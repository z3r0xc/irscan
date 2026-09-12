//! Log tampering: the gaps an intruder leaves behind.
//!
//! Everything else in this tool looks for what is *present* on a machine. This module
//! looks for what is **missing**, which is a different and often more revealing question:
//! an operator who clears the event log to cover their tracks cannot remove a record
//! without leaving a hole where it was.
//!
//! Two independent signals, both derived from data we already read:
//!
//! 1. **A gap in `RecordID`.** Windows numbers event records sequentially per channel. A
//!    missing number means records were removed selectively - not the whole log (that
//!    resets the numbering and leaves its own `104` event), but a chosen subset. Selective
//!    deletion is a deliberate act; a full clear is a blunt one.
//! 2. **A long pause in a busy channel.** A channel that normally logs continuously and
//!    then goes silent for hours is either a stopped service or a stopped service on
//!    purpose. This is weaker on its own - a quiet night is a quiet night - so it is
//!    reported at low severity and never on its own.
//!
//! The algorithm is deliberately a port of the idea used by Chainsaw (`analyse/gaps.rs`,
//! GPL-3.0) rather than a copy of its code: read `(RecordID, timestamp)` pairs, sort by
//! id, compare each pair. Small enough to reason about, which is the point - a detector
//! nobody can follow is a detector nobody should trust.

use crate::model::{Finding, Severity};
use crate::text::sanitize;

/// Cap on the records examined per channel, so a multi-gigabyte log cannot stall a scan.
pub const MAX_RECORDS: usize = 4000;

/// A pause longer than this, in a channel that otherwise logs regularly, is worth naming.
///
/// Thirty-six hours, and the number comes from a measurement rather than a guess: at a
/// six-hour threshold this machine - an ordinary desktop - produced **25** silences, every
/// one of them the gap between two working days. A signal that fires twenty-five times on a
/// clean machine is noise, and noise is what teaches a reader to skim past the section that
/// matters. At thirty-six hours the same machine produces none, while a channel that logs
/// every few minutes and then stops for two days still stands out.
pub const SILENCE_SECONDS: i64 = 36 * 60 * 60;

/// Below this many observed records a gap is not evidence: a channel with four records has
/// no baseline to be irregular against.
pub const MIN_RECORDS_FOR_GAP: usize = 20;

/// One event record, reduced to what the comparison needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub id: u64,
    /// Seconds since the Unix epoch, as reported by the event itself.
    pub time: i64,
}

/// A hole in a channel's numbering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    pub channel: String,
    /// The last record before the hole, and the first one after it.
    pub after_id: u64,
    pub before_id: u64,
    /// How many records are missing between them.
    pub missing: u64,
}

/// A stretch of silence in a channel that was otherwise logging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Silence {
    pub channel: String,
    pub from_id: u64,
    pub to_id: u64,
    pub seconds: i64,
}

/// Missing records between two consecutive ids.
///
/// `None` when the ids are consecutive or descending: event records can legitimately
/// arrive out of order in a merged view, and a descending pair means "different source
/// order", not "records were deleted".
pub fn gap_between(after_id: u64, before_id: u64) -> Option<u64> {
    if before_id <= after_id + 1 {
        return None;
    }
    Some(before_id - after_id - 1)
}

/// Find every hole in one channel's numbering.
///
/// Records are sorted by id first, so a channel delivered newest-first (which is how
/// `EvtQuery` with reverse direction returns it) needs no special handling.
pub fn find_gaps(channel: &str, records: &[Record]) -> Vec<Gap> {
    if records.len() < MIN_RECORDS_FOR_GAP {
        return Vec::new();
    }

    let mut sorted: Vec<&Record> = records.iter().collect();
    sorted.sort_by_key(|r| r.id);

    let mut gaps = Vec::new();
    for pair in sorted.windows(2) {
        if let Some(missing) = gap_between(pair[0].id, pair[1].id) {
            gaps.push(Gap {
                channel: channel.to_string(),
                after_id: pair[0].id,
                before_id: pair[1].id,
                missing,
            });
        }
    }
    gaps
}

/// Find stretches of silence in one channel.
pub fn find_silences(channel: &str, records: &[Record], threshold_seconds: i64) -> Vec<Silence> {
    if records.len() < MIN_RECORDS_FOR_GAP || threshold_seconds <= 0 {
        return Vec::new();
    }

    let mut sorted: Vec<&Record> = records.iter().collect();
    sorted.sort_by_key(|r| r.time);

    let mut silences = Vec::new();
    for pair in sorted.windows(2) {
        let seconds = pair[1].time - pair[0].time;
        if seconds >= threshold_seconds {
            silences.push(Silence {
                channel: channel.to_string(),
                from_id: pair[0].id,
                to_id: pair[1].id,
                seconds,
            });
        }
    }
    silences
}

/// Render a threshold for human reading. Public because the report must state the
/// threshold it actually applied, not a copy of the number.
pub fn human_duration(seconds: i64) -> String {
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m")
    }
}

/// Turn the gaps in one channel into a finding.
///
/// A single missing record is not reported: record ids can be absent for mundane reasons
/// (a service restarted mid-write). A *run* of missing records, or several separate holes,
/// is what selective deletion looks like.
pub fn gaps_finding(channel: &str, gaps: &[Gap]) -> Option<Finding> {
    if gaps.is_empty() {
        return None;
    }

    let total: u64 = gaps.iter().map(|g| g.missing).sum();
    let separate = gaps.len();

    // One hole of one record: not worth the reader's attention.
    if separate == 1 && total <= 1 {
        return None;
    }

    let severity = if total >= 5 || separate >= 3 {
        Severity::High
    } else {
        Severity::Med
    };

    let mut finding = Finding::new(
        severity,
        "log-tampering",
        format!(
            "Event log '{channel}' has {} missing record(s) in {separate} place(s)",
            total
        ),
    )
    .evidence(format!(
        "channel : {channel}  ({} records examined)",
        gaps.len()
    ))
    .evidence(
        "Windows numbers event records sequentially, so a missing number means a record \
         was removed without clearing the log: clearing restarts the numbering and records \
         its own event 1102, and emptying the file records 104.",
    )
    .remediation(
        "Look for event 1102 (the log was cleared) or 104 (the log was emptied) on this \
         channel. If neither is present, treat the missing records as deliberate removal: \
         the machine has been used by someone who did not want to be seen.",
    );

    for gap in gaps.iter().take(6) {
        finding = finding.evidence(format!(
            "missing {} between record {} and {}",
            gap.missing, gap.after_id, gap.before_id
        ));
    }
    if separate > 6 {
        finding = finding.evidence(format!("... and {} more hole(s)", separate - 6));
    }

    Some(finding)
}

/// Turn a silence into a finding. Deliberately low severity: this is a question, not a
/// conclusion.
pub fn silence_finding(channel: &str, silences: &[Silence]) -> Option<Finding> {
    let longest = silences.iter().max_by_key(|s| s.seconds)?;
    let mut finding = Finding::new(
        Severity::Info,
        "log-tampering",
        format!(
            "Event log '{channel}' went quiet for {}",
            human_duration(longest.seconds)
        ),
    )
    .evidence(format!(
        "channel : {channel}  (silence between record {} and {})",
        longest.from_id, longest.to_id
    ))
    .evidence(format!(
        "The channel was logging regularly and then stopped for {}.",
        human_duration(longest.seconds)
    ))
    .remediation(
        "Usually innocent: a machine that was switched off, or a service that was \
         restarting. It is only interesting together with something else in this report - \
         a new service, or a logon from an address you do not recognise.",
    );

    if silences.len() > 1 {
        finding = finding.evidence(format!(
            "{} stretches of silence of {} or more in this channel",
            silences.len(),
            human_duration(SILENCE_SECONDS)
        ));
    }
    finding = finding.evidence(format!(
        "threshold: {} of silence in a channel that otherwise logs",
        human_duration(SILENCE_SECONDS)
    ));
    let _ = sanitize(channel, 128);
    Some(finding)
}

#[test]
fn a_threshold_is_rendered_from_the_value_that_was_applied() {
    // The report used to print the literal "6h" while the audit applied 36h, so the
    // reader reasoned about gaps the check had never looked for. The label is now
    // derived, and this pins the two values that matter.
    assert_eq!(human_duration(SILENCE_SECONDS), "36h 0m");
    assert_eq!(human_duration(6 * 3600), "6h 0m");
    assert_eq!(human_duration(90 * 60), "1h 30m");
    assert_eq!(human_duration(45 * 60), "45m");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: u64, time: i64) -> Record {
        Record { id, time }
    }

    fn consecutive(count: u64) -> Vec<Record> {
        (1..=count)
            .map(|i| rec(100 + i, 1_700_000_000 + i as i64 * 60))
            .collect()
    }

    #[test]
    fn records_with_no_holes_produce_no_finding() {
        let gaps = find_gaps("System", &consecutive(100));
        assert!(gaps.is_empty());
        assert!(gaps_finding("System", &gaps).is_none());
    }

    #[test]
    fn a_single_missing_record_in_a_run_is_a_hole() {
        // The fixture has to be longer than MIN_RECORDS_FOR_GAP, or the module
        // correctly refuses to judge a channel with no baseline.
        let mut records = consecutive(100);
        records.retain(|r| r.id != 104);
        let gaps = find_gaps("Security", &records);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].missing, 1);
        assert_eq!(gaps[0].after_id, 103);
        assert_eq!(gaps[0].before_id, 105);
    }

    #[test]
    fn a_run_of_missing_records_is_high_severity() {
        // A plausible clear: everything between 110 and 130 is gone.
        let mut records = consecutive(50);
        records.retain(|r| !(110..=130).contains(&r.id));
        let gaps = find_gaps("Security", &records);

        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].missing, 21);
        let finding = gaps_finding("Security", &gaps);
        assert!(finding.is_some());
        if let Some(finding) = finding {
            assert_eq!(finding.severity, Severity::High);
            assert!(finding.title.contains("21 missing"));
        }
    }

    #[test]
    fn several_separate_holes_are_high_severity_even_when_small() {
        let mut records = consecutive(100);
        records.retain(|r| ![110, 120, 130].contains(&r.id));
        let gaps = find_gaps("System", &records);
        assert_eq!(gaps.len(), 3);
        let finding = gaps_finding("System", &gaps).expect("a finding");
        assert_eq!(finding.severity, Severity::High, "three separate removals");
    }

    #[test]
    fn one_missing_record_alone_is_not_reported() {
        // A service restart can skip an id. Reporting a single hole would make every
        // report contain one, and a finding nobody can act on trains the reader to skim.
        let mut records = consecutive(100);
        records.retain(|r| r.id != 150);
        let gaps = find_gaps("System", &records);
        assert_eq!(gaps.len(), 1);
        assert!(gaps_finding("System", &gaps).is_none());
    }

    #[test]
    fn a_short_channel_has_no_baseline_and_is_not_judged() {
        // Four records cannot establish what "regular" means.
        let mut records = consecutive(5);
        records.retain(|r| r.id != 103);
        assert!(find_gaps("Setup", &records).is_empty());
    }

    #[test]
    fn newest_first_input_is_handled_without_special_casing() {
        // This is how our own reader gets the events, so it must work by default.
        let mut records = consecutive(100);
        records.retain(|r| r.id != 140);
        records.reverse();
        let gaps = find_gaps("System", &records);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].missing, 1);
    }

    #[test]
    fn descending_or_repeated_ids_are_not_treated_as_deletions() {
        // A merged view can interleave sources; that is not evidence of anything.
        assert_eq!(gap_between(50, 40), None);
        assert_eq!(gap_between(50, 51), None);
        assert_eq!(gap_between(50, 50), None);
        assert_eq!(gap_between(50, 52), Some(1));
        assert_eq!(gap_between(50, 60), Some(9));
    }

    #[test]
    fn a_long_silence_is_found_and_reported_quietly() {
        let mut records = consecutive(30);
        // Push everything after the tenth record forward by three days: long enough to
        // clear SILENCE_SECONDS, which is 36 hours.
        for r in records.iter_mut().skip(10) {
            r.time += 3 * 86_400;
        }
        let silences = find_silences("System", &records, SILENCE_SECONDS);
        assert_eq!(silences.len(), 1);
        // The records are one minute apart, so a one-day shift opens a 24h + 1m hole.
        assert_eq!(silences[0].seconds, 3 * 86_400 + 60);
        // The hole opens after the tenth record; the fixture numbers from 101.
        assert_eq!(silences[0].from_id, 110);
        assert_eq!(silences[0].to_id, 111);

        let finding = silence_finding("System", &silences).expect("a finding");
        assert_eq!(
            finding.severity,
            Severity::Info,
            "a question, not a conclusion"
        );
        assert!(finding.title.contains("72h"), "got {}", finding.title);
    }

    #[test]
    fn a_normal_gap_between_events_is_not_a_silence() {
        let silences = find_silences("System", &consecutive(100), SILENCE_SECONDS);
        assert!(silences.is_empty(), "one minute apart is not silence");
    }

    #[test]
    fn an_ordinary_overnight_gap_is_not_reported() {
        // Measured on a real desktop: at a six-hour threshold this machine produced
        // twenty-five "silences", all of them the gap between two working days. The
        // threshold is set above that, and this test pins the decision.
        let mut records = consecutive(100);
        for r in records.iter_mut().skip(50) {
            r.time += 12 * 3600;
        }
        assert!(
            find_silences("System", &records, SILENCE_SECONDS).is_empty(),
            "a twelve-hour overnight gap must not be reported"
        );
    }

    #[test]
    fn the_silence_threshold_is_respected() {
        let mut records = consecutive(30);
        for r in records.iter_mut().skip(10) {
            r.time += 3600;
        }
        assert!(find_silences("System", &records, SILENCE_SECONDS).is_empty());
        assert_eq!(find_silences("System", &records, 1800).len(), 1);
        assert!(
            find_silences("System", &records, 0).is_empty(),
            "no threshold, no claim"
        );
    }

    #[test]
    fn the_finding_carries_the_numbers_a_reader_needs_to_verify_it() {
        let mut records = consecutive(50);
        records.retain(|r| !(120..=129).contains(&r.id));
        let gaps = find_gaps("Security", &records);
        let finding = gaps_finding("Security", &gaps).expect("a finding");

        let text = format!("{:?}", finding.evidence);
        assert!(text.contains("Security"));
        assert!(
            text.contains("119") && text.contains("130"),
            "the hole's boundaries"
        );
        assert!(
            finding
                .evidence
                .iter()
                .chain(finding.remediation.iter())
                .any(|e| e.contains("1102")),
            "the reader is told which event would prove a deliberate clear: {:?}",
            finding.remediation
        );
    }
}
