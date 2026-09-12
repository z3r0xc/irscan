//! Event-log evidence: FR-10.
//!
//! The registry and the file system show what *is*, the event log shows what *was*:
//! a service that was installed and then deleted, a logon from an address that is
//! not in the office, a scheduled task that was registered last night. Those traces
//! outlive the artefacts that produced them, which is exactly why the person on the
//! other end clears them first - and why their absence is itself worth recording.
//!
//! Design (architecture section 5.3): [`crate::win::events`] is the only place that
//! talks to `wevtapi`, and it hands back raw `EventXml`. This module owns the single
//! parser for that markup. Keeping the parser here (pure, fixture-tested, no
//! `unsafe`) means the hostile parts of the input - an attacker-controlled
//! `ImagePath` with nested markup, a 1 MiB `Data` value, a truncated document - are
//! handled by code that runs identically on any host, rather than by C that needs a
//! Windows box to exercise.
//!
//! Two rules from the collector contract (collect/mod.rs) apply throughout:
//!
//! * An unreadable channel is a *warning*, never a silent skip. A machine where
//!   the Security log cannot be opened (the tool is not elevated) must not look
//!   like a machine with no logons - that false negative is the whole reason the
//!   warning exists.
//! * Every raw event XML is also recorded verbatim under `ctx.raw_section`, so the
//!   evidence survives even when no finding is raised from it.

use std::path::Path;

use crate::collect::{CollectError, Collector};
use crate::model::{Finding, HaystackKind, ScanContext, Severity};
use crate::text::sanitize;
use crate::win::events::{
    CHANNEL_DEFENDER, CHANNEL_SECURITY, CHANNEL_SYSTEM, CHANNEL_TASKSCHED, CHANNEL_TSTRM,
};

/// Upper bound on `<Data>` entries kept from one event.
///
/// A normal event has a handful; a hostile one can carry thousands to push the
/// interesting field past any fixed read offset. Parsing stops at the cap instead.
const MAX_DATA_FIELDS: usize = 64;

/// Upper bound on one event's text kept in a buffer while scanning.
const MAX_DATA_VALUE: usize = crate::model::MAX_STRING;

/// Failed logons below this count are background noise (a mistyped password, a
/// stale credential); at or above it the log is telling a story worth reading.
const FAILED_LOGON_THRESHOLD: usize = 20;

/// RDP interactive logon (`LogonType 10`).
const LOGON_REMOTE_INTERACTIVE: &str = "10";

/// Maximum raw event lines recorded per channel section.
const MAX_RAW_LINES: usize = 512;

/// Maximum accounts and addresses quoted for a failed-logon burst.
const MAX_BURST_ITEMS: usize = 12;

/// One structured event decoded from the `EventXml` rendering.
///
/// `Default` is implemented so a partial parse can be filled in field by field;
/// `PartialEq` exists so tests can compare whole records rather than individual
/// fields, which is what a reader actually cares about.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventFields {
    /// `EventRecordID`. Windows numbers records sequentially per channel, which is what
    /// makes a missing number meaningful: it means a record was removed. Read by
    /// `logaudit`, which is the only reason this tool can see a deleted event.
    pub record_id: u64,
    /// `TimeCreated/@SystemTime`, as seconds since the Unix epoch. `None` when the
    /// attribute is missing or unparseable, which is treated as "no time" rather than as
    /// the epoch - a wrong timestamp would invent a silence that never happened.
    pub time_epoch: Option<i64>,
    /// `<EventID>`; `0` when absent or unparseable.
    pub event_id: u32,
    /// `SystemTime` attribute of `<TimeCreated>`, verbatim.
    pub time_created: String,
    /// `<Provider Name="...">`.
    pub provider: String,
    /// `<Channel>`.
    pub channel: String,
    /// `<Computer>`.
    pub computer: String,
    /// `<Data Name="X">value</Data>` pairs, in document order. An unnamed
    /// `<Data>` is stored under the empty key.
    pub data: Vec<(String, String)>,
}

impl EventFields {
    /// Trimmed value of the first `<Data>` whose name matches `name`
    /// (case-insensitively). Convenience wrapper over [`field`].
    pub fn value(&self, name: &str) -> Option<&str> {
        field(self, name)
    }
}

/** Parse the ISO-8601 timestamp Windows writes into `TimeCreated/@SystemTime`, e.g.
 * `2026-09-12T12:12:30.9060987Z`, into seconds since the Unix epoch. UTC only: the
 * attribute always carries a `Z`, and a local-time guess would be wrong by the offset.
 *
 * Fractional seconds are ignored on purpose - the audit compares gaps of hours.
 * Returns `None` for anything it does not fully understand, so a malformed timestamp can
 * never be mistaken for a real one. */
pub fn parse_system_time(value: &str) -> Option<i64> {
    let text = value.trim();
    let (date, rest) = text.split_once('T')?;
    let rest = rest.trim_end_matches('Z');
    let time = match rest.split_once('.') {
        Some((whole, _fraction)) => whole,
        None => rest,
    };

    let mut date_parts = date.split('-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: i64 = date_parts.next()?.parse().ok()?;
    let day: i64 = date_parts.next()?.parse().ok()?;
    if date_parts.next().is_some() {
        return None;
    }

    let mut time_parts = time.split(':');
    let hour: i64 = time_parts.next()?.parse().ok()?;
    let minute: i64 = time_parts.next()?.parse().ok()?;
    let second: i64 = time_parts.next()?.parse().ok()?;
    if time_parts.next().is_some() {
        return None;
    }

    // Stated as the accepted ranges rather than as a chain of negations: the caller wants
    // to know whether this is a real timestamp, and a positive test reads that way.
    let plausible = (1..=12).contains(&month)
        && (1..=31).contains(&day)
        && (0..=23).contains(&hour)
        && (0..=59).contains(&minute)
        && (0..=60).contains(&second);
    if !plausible {
        return None;
    }

    Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second)
}

/// Days since 1970-01-01 for a proleptic Gregorian date. Howard Hinnant's algorithm.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Case-insensitive lookup of a named `<Data>` value.
///
/// Case-insensitive because providers disagree in practice: the same channel
/// emits `IpAddress` and `Ipaddress`, and a case-sensitive lookup would silently
/// miss half of them.
pub fn field<'a>(fields: &'a EventFields, name: &str) -> Option<&'a str> {
    fields
        .data
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Parse the `EventXml` rendering produced by [`crate::win::events::query`].
///
/// Returns `None` when the text does not look like an event at all (empty, no
/// `<Event>` root, or a `<`-that-never-closes document). Interior damage - a
/// missing `EventID`, a truncated tail - is not a reason to drop the event: the
/// fields that did parse are still evidence, so the partial record is returned.
///
/// Tolerant rather than strict on purpose. There is no XML crate in the shipped
/// binary on purpose (adding one adds an attack surface that runs on the hostile
/// host), and the renderer is the only producer of this text, so the grammar is
/// fixed and small. A scan of the bytes with bounded backtracking handles it
/// without the parser being coercible into deep recursion or large allocation.
pub fn parse_event_xml(xml: &str) -> Option<EventFields> {
    if !looks_like_event(xml) {
        return None;
    }

    let mut out = EventFields::default();

    // EventID: text plus optional attributes (`<EventID Qualifiers="0">7045</EventID>`).
    if let Some(raw) = element_text(xml, "EventID") {
        out.event_id = raw.trim().parse::<u32>().unwrap_or(0);
    }

    // Provider: the name is an attribute, not element text.
    if let Some(tag) = find_open_tag(xml, "Provider") {
        out.provider = tag.attribute("Name").map(unescape).unwrap_or_default();
    }

    // TimeCreated carries SystemTime as an attribute.
    if let Some(tag) = find_open_tag(xml, "TimeCreated") {
        let raw = tag
            .attribute("SystemTime")
            .map(unescape)
            .unwrap_or_default();
        out.time_epoch = parse_system_time(&raw);
        out.time_created = raw;
    }

    // EventRecordID: the sequential number that makes a missing record meaningful.
    if let Some(raw) = element_text(xml, "EventRecordID") {
        out.record_id = raw.trim().parse::<u64>().unwrap_or(0);
    }

    out.channel = element_text(xml, "Channel").unwrap_or_default();
    out.computer = element_text(xml, "Computer").unwrap_or_default();

    // EventData/Data: name comes from an attribute, value is the element text.
    // The same scan also keeps a bare `<Data>value</Data>` (no attributes at all),
    // which some providers emit for positional arguments.
    let mut data = Vec::new();
    let mut from = 0usize;
    while data.len() < MAX_DATA_FIELDS {
        let Some(tag) = next_tag(xml, from) else {
            break;
        };
        from = tag.end;
        if tag.closing || tag.local != "Data" {
            continue;
        }
        let name = tag.attribute("Name").map(unescape).unwrap_or_default();
        // The value is everything up to the matching close tag; a nested tag inside
        // a value is not expected, but if one appears the raw inner text is kept
        // rather than dropped, because losing evidence is worse than odd-looking
        // evidence.
        let value = element_inner(xml, tag.end, "Data").unwrap_or_default();
        // Entity references are decoded before the cap: `&amp;` in a path must read
        // as `&`, and a hostile value could hide a megabyte behind one reference.
        data.push((name, clamp(unescape(&value))));
    }
    out.data = data;

    Some(out)
}

/// Does this text look like an event document?
///
/// Accepts both the namespace-qualified form the renderer produces
/// (`<Event xmlns=...>`) and the bare `<Event>` form fixtures use. Only the
/// presence of a root element is required - a document whose root is not `Event`
/// (someone else's XML) is rejected, because parsing it as an event would invent
/// evidence that was never logged.
fn looks_like_event(xml: &str) -> bool {
    let Some(tag) = next_tag(xml, 0) else {
        return false;
    };
    if tag.closing {
        return false;
    }
    if tag.local != "Event" {
        return false;
    }
    // A document whose final `<` never closes was cut mid-tag by a failing render
    // or a hostile producer. There is no reliable field boundary left in it, so it
    // is rejected outright rather than scanned for whatever text happens to follow.
    match xml.rfind('<') {
        Some(pos) => !xml[pos..].find('>').is_none(),
        None => true,
    }
}

/// Read the inner text of the first `<local>` element: the value of an element,
/// with nested tags stripped and surrounding whitespace removed.
fn element_text(xml: &str, local: &str) -> Option<String> {
    let tag = find_open_tag(xml, local)?;
    let inner = element_inner(xml, tag.end, local)?;
    // Entity references are decoded here so every text-valued field (`EventID`,
    // `Channel`, `Computer`) is normalised in one place.
    Some(unescape(strip_tags(&inner).trim()))
}

/// The first `<local>` start tag at any depth, self-closing or not.
///
/// Self-closing tags are included: `Provider` and `TimeCreated` carry their payload
/// entirely in attributes (`<Provider Name="..."/>`), so skipping them would lose
/// the provider and the event time on every real event.
fn find_open_tag<'a>(xml: &'a str, local: &str) -> Option<Tag<'a>> {
    let mut from = 0usize;
    while let Some(tag) = next_tag(xml, from) {
        from = tag.end;
        if tag.closing {
            continue;
        }
        if tag.local == local {
            return Some(tag);
        }
    }
    None
}

/// Inner text of the element whose open tag ends at `content_start`, up to its
/// matching `</local>`.
///
/// Depth is tracked so a `<Data>` value containing a literal `<Data>` in its text
/// (escaped, so it should not happen, but this code assumes nothing) does not end
/// the scan early. An element that is never closed consumes the rest of the
/// document, which is the correct behaviour for a truncated event.
fn element_inner(xml: &str, content_start: usize, local: &str) -> Option<String> {
    let mut depth = 0usize;
    let mut from = content_start;
    while let Some(tag) = next_tag(xml, from) {
        from = tag.end;
        if tag.local != local {
            continue;
        }
        if tag.closing {
            if depth == 0 {
                return Some(xml[content_start..tag.start].to_string());
            }
            depth -= 1;
        } else if tag.self_closing {
            // A self-closing `<Data/>` neither opens nor closes anything.
        } else {
            depth += 1;
        }
    }
    Some(xml[content_start..].to_string())
}

/// Drop every `<...>` segment, keeping the text between them.
fn strip_tags(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for ch in s.chars() {
        if ch == '<' {
            in_tag = true;
        } else if ch == '>' {
            in_tag = false;
        } else if in_tag {
            // skipped
        } else {
            out.push(ch);
        }
    }
    out
}

/// Truncate to the string cap and sanitise control characters.
///
/// The renderer already caps an event at 1 MiB, but an individual value can still
/// be a megabyte of `A`s; every one of them must fit in a [`crate::model::MAX_STRING`]
/// field before it is echoed anywhere.
fn clamp(value: String) -> String {
    sanitize(&value, MAX_DATA_VALUE)
}

/// One XML tag, reduced to what this module needs.
struct Tag<'a> {
    /// Local name with any namespace prefix stripped (`e:Data` -> `Data`).
    local: &'a str,
    closing: bool,
    self_closing: bool,
    /// Index of the tag's `<`.
    start: usize,
    /// Index one past the tag's `>`.
    end: usize,
    /// The raw text between the name and the closing `>` (attributes), if any.
    attrs: &'a str,
}

impl<'a> Tag<'a> {
    /// Attribute value, quoted (either quote style) or bare (`Name=x`).
    ///
    /// Unquoted values are accepted because this parser also sees hand-written
    /// fixtures and provider markup that omits the quotes; a value containing
    /// whitespace must be quoted, as XML requires.
    fn attribute(&self, name: &str) -> Option<&'a str> {
        let attrs = self.attrs;
        let bytes = attrs.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() {
            // Skip whitespace and any self-closing slash between attributes.
            while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b'/') {
                i += 1;
            }
            let key_start = i;
            // An attribute name runs up to the `=`, or up to whitespace for a
            // valueless token that is not an attribute at all.
            while i < bytes.len() && bytes[i] != b'=' && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            let key = &attrs[key_start..i];
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i >= bytes.len() || bytes[i] != b'=' {
                // Not an attribute (or a lone token); keep scanning after it.
                if key.is_empty() {
                    i += 1;
                }
                continue;
            }
            i += 1; // past '='
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i >= bytes.len() {
                return None;
            }
            let value = if bytes[i] == b'"' || bytes[i] == b'\'' {
                let quote = bytes[i];
                i += 1;
                let start = i;
                while i < bytes.len() && bytes[i] != quote {
                    i += 1;
                }
                let v = &attrs[start..i];
                if i < bytes.len() {
                    i += 1; // past the closing quote
                }
                v
            } else {
                let start = i;
                // An unquoted value runs until whitespace, the self-closing
                // slash, or the tag terminator.
                while i < bytes.len()
                    && !bytes[i].is_ascii_whitespace()
                    && bytes[i] != b'/'
                    && bytes[i] != b'>'
                {
                    i += 1;
                }
                &attrs[start..i]
            };
            if key.eq_ignore_ascii_case(name) {
                return Some(value);
            }
        }
        None
    }
}

/// Scan for the next tag at or after `from`.
///
/// Returns `None` at end of input and on an unterminated tag, which is how a
/// truncated document fails without ever indexing out of bounds.
fn next_tag(xml: &str, from: usize) -> Option<Tag<'_>> {
    let bytes = xml.as_bytes();
    if from >= bytes.len() {
        return None;
    }
    let mut i = from;
    while i < bytes.len() {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        if xml[i..].starts_with("<!--") {
            {
                let k = xml[i..].find("-->")?;
                i = i + k + 3;
                continue;
            }
        }
        if xml[i..].starts_with("<?") {
            {
                let k = xml[i..].find("?>")?;
                i = i + k + 2;
                continue;
            }
        }
        if xml[i..].starts_with("<!") {
            {
                let k = xml[i..].find('>')?;
                i = i + k + 1;
                continue;
            }
        }

        let mut j = i + 1;
        let closing = j < bytes.len() && bytes[j] == b'/';
        if closing {
            j += 1;
        }
        let first = j;
        while j < bytes.len() && is_name_byte(bytes[j]) {
            j += 1;
        }
        if j == first {
            // A bare `<` that starts no tag; keep looking.
            i += 1;
            continue;
        }
        let gt = {
            let k = xml[j..].find('>')?;
            j + k
        };
        let name = &xml[first..j];
        let self_closing = xml[i + 1..gt].trim_end().ends_with('/');
        let local = match name.rfind(':') {
            Some(p) => &name[p + 1..],
            None => name,
        };
        // Attributes are the text between the name and the `>`; the self-closing
        // slash (if any) is trimmed by `attribute`'s scan.
        let attrs_end = if self_closing {
            i + 1 + xml[i + 1..gt].trim_end().len() - 1
        } else {
            gt
        };
        return Some(Tag {
            local,
            closing,
            self_closing,
            start: i,
            end: gt + 1,
            attrs: &xml[j..attrs_end.max(j)],
        });
    }
    None
}

fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.' || b == b':'
}

/// Resolve the five XML entities and numeric character references.
///
/// Handles `&#x41;` / `&#65;` as well as `&amp;`-style names. An unknown entity is
/// left as written: dropping it would silently alter a path or an account name,
/// which is the one thing this tool must never do.
fn unescape(s: &str) -> String {
    if s.contains('&') {
        let mut out = String::with_capacity(s.len());
        let mut rest = s;
        while let Some(pos) = rest.find('&') {
            out.push_str(&rest[..pos]);
            let tail = &rest[pos..];
            // A reference is short; cap the lookahead so a bare `&` cannot make
            // this scan the remainder of the document.
            let semi = tail[..tail.len().min(12)].find(';');
            let Some(rel) = semi else {
                out.push('&');
                rest = &tail[1..];
                continue;
            };
            let entity = &tail[1..rel];
            if let Some(ch) = decode_entity(entity) {
                out.push(ch);
                rest = &tail[rel + 1..];
            } else {
                out.push('&');
                rest = &tail[1..];
            }
        }
        out.push_str(rest);
        out
    } else {
        s.to_string()
    }
}

/// One entity body (without `&` or `;`) to a character, or `None` if unknown.
fn decode_entity(entity: &str) -> Option<char> {
    match entity {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        _ => {
            let body = entity.strip_prefix('#')?;
            let code = if let Some(hex) = body.strip_prefix('x').or_else(|| body.strip_prefix('X'))
            {
                u32::from_str_radix(hex, 16).ok()?
            } else {
                body.parse::<u32>().ok()?
            };
            char::from_u32(code)
        }
    }
}

// ---------------------------------------------------------------------------
// Collector
// ---------------------------------------------------------------------------

/// Reads the event channels that record persistence, remote access and protection
/// changes (FR-10).
pub struct EventsCollector;

impl Collector for EventsCollector {
    fn name(&self) -> &'static str {
        "events"
    }

    fn run(&self, ctx: &mut ScanContext) -> Result<(), CollectError> {
        service_install(ctx);
        service_install_api(ctx);
        remote_logons(ctx);
        remote_auth(ctx);
        failed_logons(ctx);
        defender_history(ctx);
        task_registration(ctx);
        audit_channels(ctx);
        Ok(())
    }
}

/// Query one channel, record its raw events, and return the parsed fields.
///
/// `None` means "nothing to read": either the channel does not exist on this
/// edition (a clean server with no Remote Desktop, Defender replaced by a
/// third-party AV), or the query failed. A failure is ALWAYS a warning, never a
/// silent skip: `channel_available` cannot tell "absent" from "exists but not
/// readable" - it probes with a `*` query - so gating on it would let an
/// unelevated Security log look like a clean one, which is exactly the false
/// negative this tool exists to avoid.
/// Render one event for the RAW DATA section, front-loading the fields that decide a finding.
///
/// Writing the raw XML looked like the honest choice - no interpretation, no risk of hiding
/// something - but the XML puts `<EventData>` after `<System>`, and the Data block is exactly
/// where `ServiceName` and `ImagePath` live for a 7045. Truncated at 512 characters, every
/// such line ended inside `<Channel>`, so the report showed service-install events with the
/// name of the installed service missing - while the finding cited that section as its
/// evidence.
///
/// The extracted fields come first now, and the XML fills whatever budget is left, so the
/// line carries the deciding value and the reader still sees the surrounding system block.
fn summarize_event_xml(xml: &str, limit: usize) -> String {
    let Some(fields) = parse_event_xml(xml) else {
        // Unparseable: the XML is all there is, so hand back as much of it as fits.
        return sanitize(xml, limit);
    };

    let mut parts: Vec<String> = Vec::new();
    if !fields.time_created.is_empty() {
        parts.push(format!("at {}", fields.time_created));
    }
    if fields.record_id > 0 {
        parts.push(format!("record {}", fields.record_id));
    }
    if fields.event_id > 0 {
        parts.push(format!("id {}", fields.event_id));
    }
    if !fields.provider.is_empty() {
        parts.push(fields.provider.clone());
    }

    // The named Data values, verbatim and in document order, are the payload.
    let joined = fields
        .data
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(" ");

    let mut head = parts.join(" | ");
    if !joined.is_empty() {
        if !head.is_empty() {
            head.push_str(" | ");
        }
        head.push_str(&joined);
    }

    if head.is_empty() {
        return sanitize(xml, limit);
    }

    // Fill the remainder with the XML, so the system block is still visible beside it.
    let used = head.chars().count();
    if used + 6 >= limit {
        return sanitize(&head, limit);
    }
    let remainder = limit.saturating_sub(used + 6);
    let tail = sanitize(xml, remainder);
    if tail.is_empty() {
        sanitize(&head, limit)
    } else {
        sanitize(&format!("{head}  ::  {tail}"), limit)
    }
}

fn collect_channel(
    ctx: &mut ScanContext,
    channel: &str,
    section: &str,
    xpath: &str,
    max: usize,
) -> Option<Vec<EventFields>> {
    let events = match crate::win::events::query(channel, xpath, max) {
        Ok(events) => events,
        Err(e) => {
            // The section is written even when the channel cannot be read, and it says so.
            // An absent or empty section is indistinguishable from "this channel was
            // checked and is clean", which is precisely the false negative to avoid: on
            // this host `Security` needs elevation, and a silent scan would have reported
            // an unread logon history as no logons at all.
            ctx.warn(format!("events: {channel} unavailable: {e}"));
            ctx.raw_section(
                section,
                vec![format!(
                    "not examined - the channel could not be read ({e}); this is not a clean result"
                )],
            );
            return None;
        }
    };

    let mut lines: Vec<String> = Vec::new();
    let mut parsed: Vec<EventFields> = Vec::new();
    let mut unparsed = 0usize;
    for event in &events {
        if lines.len() < MAX_RAW_LINES {
            lines.push(summarize_event_xml(&event.xml, MAX_DATA_VALUE));
        }
        match parse_event_xml(&event.xml) {
            Some(fields) => parsed.push(fields),
            None => unparsed += 1,
        }
    }

    if events.is_empty() {
        // Empty is a real result, and it is stated as one so it cannot be mistaken for a
        // channel that was never queried.
        lines.push(format!(
            "examined: {channel} matched nothing for the query {xpath}"
        ));
    } else {
        lines.push(format!(
            "examined {} event(s) for {xpath}; {} parsed, {} unparseable",
            events.len(),
            parsed.len(),
            unparsed
        ));
    }
    if events.len() >= max {
        lines.push(format!(
            "the query returned the limit of {max}; older events were not examined"
        ));
    }

    ctx.raw_section(section, lines);
    Some(parsed)
}

/// Read each auditable channel once and look for holes in it.
///
/// The query is deliberately wider than the other checks (all events, not one id) because
/// a gap can only be seen in a sequence: auditing `*[EventID=7045]` alone would miss a gap
/// between two records that are not 7045 at all.
fn audit_channels(ctx: &mut ScanContext) {
    // The audit reports what it examined, not only what it found. "Nothing missing" and
    // "the channel could not be read" look identical in a findings list, and conflating
    // them is the false negative this tool exists to avoid - so the section always says
    // which of the two happened.
    for channel in [CHANNEL_SECURITY, CHANNEL_SYSTEM] {
        // Per channel, not shared: a section that names `System` while showing `Security`'s
        // counts is worse than an empty one, because it looks like evidence.
        let mut report: Vec<String> = Vec::new();
        let section = format!("{channel} RECORD SEQUENCE AUDIT");
        // A message we cannot read is reported by `collect_channel` as a warning; here we
        // only need to record that the channel was skipped.
        let events = match crate::win::events::query(channel, "*", crate::logaudit::MAX_RECORDS) {
            Ok(events) => events,
            Err(e) => {
                report.push(format!(
                    "{channel}: not audited - the channel could not be read ({e})"
                ));
                ctx.warn(format!("events: {channel} not audited: {e}"));
                ctx.raw_section(section, report.clone());
                continue;
            }
        };

        let parsed: Vec<EventFields> = events
            .iter()
            .filter_map(|event| parse_event_xml(&event.xml))
            .collect();
        let with_ids = parsed.iter().filter(|f| f.record_id > 0).count();

        let records: Vec<crate::logaudit::Record> = parsed
            .iter()
            .filter(|f| f.record_id > 0)
            .map(|f| crate::logaudit::Record {
                id: f.record_id,
                time: f.time_epoch.unwrap_or(0),
            })
            .collect();

        report.push(format!(
            "{channel}: {with_ids} event(s) examined for gaps in the record numbering"
        ));

        if records.len() < crate::logaudit::MIN_RECORDS_FOR_GAP {
            report.push(format!(
                "{channel}: too few records to judge (need {})",
                crate::logaudit::MIN_RECORDS_FOR_GAP
            ));
        } else {
            let gaps = crate::logaudit::find_gaps(channel, &records);
            report.push(format!("{channel}: {} gap(s) in the numbering", gaps.len()));
            if let Some(finding) = crate::logaudit::gaps_finding(channel, &gaps) {
                ctx.add(finding);
            }

            let silences =
                crate::logaudit::find_silences(channel, &records, crate::logaudit::SILENCE_SECONDS);
            // Never a second copy of the threshold as a literal: the section used to say
            // "6h" while applying 36h, which is worse than saying nothing, because the
            // reader would then reason about gaps the check had not looked for.
            report.push(format!(
                "{channel}: {} stretch(es) of silence over {}",
                silences.len(),
                crate::logaudit::human_duration(crate::logaudit::SILENCE_SECONDS)
            ));
            if let Some(finding) = crate::logaudit::silence_finding(channel, &silences) {
                ctx.add(finding);
            }
        }

        ctx.raw_section(section, report.clone());
    }
}

/// Severity for the `ImagePath` a 7045 event recorded.
///
/// The shared location policy is the base. The one deliberate escalation is a transit
/// directory, which stays High even when the file is already gone and its signature
/// cannot be checked: the event log is then the only surviving record of the install,
/// which is exactly what it is read for.
/// Is this service name one a remote-access tool registers itself under?
///
/// Substring, case-insensitive: installers pad the name (`AnyDesk Service`,
/// `SplashtopRemoteService`), and the padded form is still the product.
pub fn is_known_remote_tool_service(name: &str) -> bool {
    let n = name.trim().to_lowercase();
    if n.len() < 3 {
        return false;
    }
    crate::remote_tools::REMOTE_TOOL_SERVICE_NAMES
        .iter()
        .any(|needle| n.contains(needle))
}

/// Does this image path name an executable a remote-access tool ships?
///
/// Matches on the file name rather than the whole path: the directory varies with the
/// version and the vendor's habits, the executable name does not.
pub fn is_known_remote_tool_image(image: &str) -> bool {
    let path = image.trim().replace('/', "\\").to_lowercase();
    // Strip a command line: `tvnserver.exe -service` names the same binary.
    let exe = match path.split(".exe").next() {
        Some(stem) => format!("{stem}.exe"),
        None => path.clone(),
    };
    if exe.len() < 5 {
        return false;
    }
    crate::remote_tools::REMOTE_TOOL_IMAGES
        .iter()
        .any(|needle| exe.contains(needle))
}

fn service_install_severity(trusted: Option<bool>, image: &str) -> Option<Severity> {
    let location = crate::rules::classify_location(image);
    if location == crate::rules::Location::Drop {
        return Some(Severity::High);
    }
    crate::rules::execution_severity(trusted, location)
}

/// FR-10: service installed via the Service Control Manager (Event 7045).
///
/// The SCM writes this event immediately before the service starts, so it survives
/// the service being removed afterwards - the single best record of "how did this
/// thing get here". An `ImagePath` in a transit directory is the headline case.
fn service_install(ctx: &mut ScanContext) {
    let xpath = "*[System[EventID=7045]]";
    let Some(events) = collect_channel(
        ctx,
        CHANNEL_SYSTEM,
        "SYSTEM EVENTS (7045 service install)",
        xpath,
        300,
    ) else {
        return;
    };

    for fields in &events {
        let name = field(fields, "ServiceName")
            .or_else(|| field(fields, "Service Name"))
            .unwrap_or_default();
        let image = field(fields, "ImagePath").unwrap_or_default();
        let expanded = crate::win::expand(image);
        let safe_name = sanitize(name, MAX_DATA_VALUE);
        let safe_image = sanitize(&expanded, MAX_DATA_VALUE);

        if safe_name.is_empty() && safe_image.is_empty() {
            continue;
        }

        ctx.note(
            HaystackKind::ServiceName,
            safe_name.clone(),
            "service install (7045)",
        );
        if !safe_image.is_empty() {
            ctx.note(
                HaystackKind::Path,
                safe_image.clone(),
                "service install (7045)",
            );
        }

        let trusted = if safe_image.is_empty() {
            None
        } else {
            crate::win::sig::is_signature_trusted(Path::new(&safe_image))
        };

        // A recognised remote-access tool is reported on the strength of its name, which is
        // the one part of the install a rename of the binary cannot change. This is checked
        // before the location policy because the two produce the same verdict for a transit
        // image but only this one catches a tool installed somewhere ordinary - which is how
        // a legitimate-looking RMM deployment arrives.
        let known_tool = if is_known_remote_tool_service(&safe_name) {
            Some("the service name matches a known remote-access tool")
        } else if is_known_remote_tool_image(&safe_image) {
            Some("the service image matches a known remote-access tool")
        } else {
            None
        };

        let severity = match known_tool {
            Some(_) => Severity::Med,
            None => match service_install_severity(trusted, &safe_image) {
                Some(s) => s,
                None => continue,
            },
        };

        let when = if fields.time_created.is_empty() {
            "an unknown time".to_string()
        } else {
            sanitize(&fields.time_created, MAX_DATA_VALUE)
        };

        let mut finding = Finding::new(
            severity,
            "service-install",
            "Service was installed and logged by the Service Control Manager",
        );
        if let Some(reason) = known_tool {
            finding = finding.evidence(format!("recognised: {reason}"));
        }
        ctx.add(
            finding
                .evidence(format!("service: {safe_name}"))
            .evidence(format!("image: {safe_image}"))
            .evidence(format!("installed: {when}"))
            .evidence(
                "Event 7045 is written by the SCM at install time, so it persists even after \
                 the service has been deleted.",
            )
            .remediation(
                "Confirm the image path belongs to software you installed. A service that runs \
                 from a user-writable directory can be replaced by any process running as that \
                 user.",
            )
            .remediation(
                "If it is not recognised, record the hash before removing it: the service \
                 itself may already be gone.",
            ),
        );
    }
}

/// FR-10: service installed through the API rather than the SCM (Event 4697).
///
/// Distinguished from 7045 deliberately: this event means `CreateService` was
/// called directly, which is what a remote administration framework does when it
/// drops a persistent agent. It is High on its own, regardless of signature,
/// because the *method* is the anomaly.
fn service_install_api(ctx: &mut ScanContext) {
    let xpath = "*[System[EventID=4697]]";
    let Some(events) = collect_channel(
        ctx,
        CHANNEL_SECURITY,
        "SECURITY EVENTS (4697 service install via API)",
        xpath,
        200,
    ) else {
        return;
    };

    for fields in &events {
        let name = field(fields, "ServiceName")
            .or_else(|| field(fields, "Service Name"))
            .unwrap_or_default();
        let image = field(fields, "ImagePath").unwrap_or_default();
        let account = field(fields, "SubjectUserName")
            .or_else(|| field(fields, "Subject User Name"))
            .unwrap_or_default();
        let safe_name = sanitize(name, MAX_DATA_VALUE);
        let safe_image = sanitize(&crate::win::expand(image), MAX_DATA_VALUE);
        let safe_account = sanitize(account, MAX_DATA_VALUE);

        if safe_name.is_empty() && safe_image.is_empty() {
            continue;
        }

        ctx.note(
            HaystackKind::ServiceName,
            safe_name.clone(),
            "service install via API (4697)",
        );
        if !safe_image.is_empty() {
            ctx.note(
                HaystackKind::Path,
                safe_image.clone(),
                "service install via API (4697)",
            );
        }

        ctx.add(
            Finding::new(
                Severity::High,
                "service-install",
                "Service installed directly through the service API",
            )
            .evidence(format!("service: {safe_name}"))
            .evidence(format!("image: {safe_image}"))
            .evidence(format!("account: {safe_account}"))
            .evidence(
                "Event 4697 records a direct CreateService call. Legitimate installers use the \
                 Service Control Manager (which logs 7045 instead), so this method is \
                 characteristic of a remote administration framework installing an agent.",
            )
            .remediation(
                "Treat the image path as untrusted: capture it and its hash before any cleanup, \
                 then remove the service.",
            ),
        );
    }
}

/// FR-10: successful RDP logons (Security 4624, LogonType 10).
///
/// Only type 10 is interesting here: types 3 and 5 fire constantly for scheduled
/// tasks and services and would drown the report. A type 10 from an address that is
/// not on the local network is the shortest path to "someone else is using this
/// machine right now".
fn remote_logons(ctx: &mut ScanContext) {
    let xpath = "*[System[EventID=4624]]";
    let Some(events) = collect_channel(
        ctx,
        CHANNEL_SECURITY,
        "SECURITY EVENTS (4624 logons, type 10 shown)",
        xpath,
        4000,
    ) else {
        return;
    };

    for fields in &events {
        let logon_type = field(fields, "LogonType").unwrap_or_default().trim();
        if logon_type != LOGON_REMOTE_INTERACTIVE {
            continue;
        }

        let account = field(fields, "TargetUserName").unwrap_or_default();
        let address = field(fields, "IpAddress").unwrap_or_default();
        let workstation = field(fields, "WorkstationName").unwrap_or_default();
        let source = if address.trim().is_empty() {
            workstation
        } else {
            address
        };
        let safe_account = sanitize(account, MAX_DATA_VALUE);
        let safe_source = sanitize(source, MAX_DATA_VALUE);
        let when = if fields.time_created.is_empty() {
            "an unknown time".to_string()
        } else {
            sanitize(&fields.time_created, MAX_DATA_VALUE)
        };

        // An address that is a *name* (not a routable literal) is the more useful
        // needle: the signature database can match an organisation domain.
        if address_looks_like_name(safe_source.as_str()) {
            ctx.note(
                HaystackKind::Domain,
                safe_source.clone(),
                "RDP source (4624 type 10)",
            );
        }

        ctx.add(
            Finding::new(
                Severity::High,
                "remote-access",
                "Interactive Remote Desktop logon",
            )
            .evidence(format!("account: {safe_account}"))
            .evidence(format!("source: {safe_source}"))
            .evidence(format!("time: {when}"))
            .evidence(
                "Logon type 10 is a full interactive Remote Desktop session: whoever held that \
                 session could see the screen and move the mouse.",
            )
            .remediation(
                "If this session is not yours, assume the account is compromised: disconnect it, \
                 change the password, and check what was installed during the session.",
            ),
        );
    }
}

/// FR-10: Remote Desktop authentication (TerminalServices 1149).
///
/// 1149 fires on *successful authentication* to the RD listener, one step before
/// the logon is accepted. It is read in addition to 4624 because it names the
/// source address directly (`Param3`) even when the logon event's fields are
/// rearranged by a remote-access product.
fn remote_auth(ctx: &mut ScanContext) {
    let xpath = "*[System[EventID=1149]]";
    let Some(events) = collect_channel(
        ctx,
        CHANNEL_TSTRM,
        "TERMINALSERVICES EVENTS (1149 RDP authentication)",
        xpath,
        100,
    ) else {
        return;
    };

    for fields in &events {
        let user = field(fields, "Param1")
            .or_else(|| field(fields, "User"))
            .unwrap_or_default();
        let domain = field(fields, "Param2")
            .or_else(|| field(fields, "Domain"))
            .unwrap_or_default();
        let address = field(fields, "Param3")
            .or_else(|| field(fields, "Address"))
            .unwrap_or_default();
        let safe_user = sanitize(user, MAX_DATA_VALUE);
        let safe_domain = sanitize(domain, MAX_DATA_VALUE);
        let safe_address = sanitize(address, MAX_DATA_VALUE);
        let when = if fields.time_created.is_empty() {
            "an unknown time".to_string()
        } else {
            sanitize(&fields.time_created, MAX_DATA_VALUE)
        };

        if address_looks_like_name(safe_address.as_str()) {
            ctx.note(
                HaystackKind::Domain,
                safe_address.clone(),
                "RDP authentication (1149)",
            );
        }

        ctx.add(
            Finding::new(
                Severity::High,
                "remote-access",
                "Remote Desktop authentication succeeded",
            )
            .evidence(format!("user: {safe_domain}\\{safe_user}"))
            .evidence(format!("source: {safe_address}"))
            .evidence(format!("time: {when}"))
            .evidence(
                "The TerminalServices listener accepted credentials for this account. This event \
                 is written before the session is fully established, so it survives sessions \
                 that were aborted.",
            )
            .remediation(
                "Confirm the account and the source address. Restrict RDP at the firewall and \
                 require a VPN if remote access is needed.",
            ),
        );
    }
}

/// FR-10: a burst of failed logons (Security 4625).
///
/// One or two are ordinary typos and are not reported as findings. Past
/// [`FAILED_LOGON_THRESHOLD`] they are an attempt, and the accounts and addresses
/// involved are quoted verbatim so the reader can tell an automated spray from a
/// person guessing.
fn failed_logons(ctx: &mut ScanContext) {
    let xpath = "*[System[EventID=4625]]";
    let Some(events) = collect_channel(
        ctx,
        CHANNEL_SECURITY,
        "SECURITY EVENTS (4625 failed logons)",
        xpath,
        500,
    ) else {
        return;
    };

    let mut accounts: Vec<String> = Vec::new();
    let mut sources: Vec<String> = Vec::new();
    let mut count = 0usize;

    for fields in &events {
        count += 1;
        let account = sanitize(
            field(fields, "TargetUserName").unwrap_or_default(),
            MAX_DATA_VALUE,
        );
        let address = field(fields, "IpAddress").unwrap_or_default();
        let workstation = field(fields, "WorkstationName").unwrap_or_default();
        let source = if address.trim().is_empty() {
            workstation
        } else {
            address
        };
        let safe_source = sanitize(source, MAX_DATA_VALUE);

        push_unique(&mut accounts, account, MAX_BURST_ITEMS);
        push_unique(&mut sources, safe_source, MAX_BURST_ITEMS);
    }

    if count < FAILED_LOGON_THRESHOLD {
        return;
    }

    ctx.add(
        Finding::new(
            Severity::Med,
            "remote-access",
            "Large burst of failed logon attempts",
        )
        .evidence(format!("failed attempts in the queried window: {count}"))
        .evidence(format!("accounts: {}", join_or_dash(&accounts)))
        .evidence(format!("sources: {}", join_or_dash(&sources)))
        .evidence(
            "Many failures in a short window are an authentication attempt rather than a \
             mistyped password, especially when the accounts or the sources vary.",
        )
        .remediation(
            "Check whether the sources are known. Repeated failures against remote-capable \
             accounts should be followed by locking the account down or blocking the source.",
        ),
    );
}

/// FR-10: Defender detections and protection-state changes (Defender channel).
///
/// Detection events (1116, 1117) name the malware; configuration events (1006,
/// 1007, 1008, 1015) mean protection was changed. Both matter, but for different
/// reasons: a detection is a payload that was seen, a configuration change is the
/// reason it may never have been.
///
/// Note that `collect/defender.rs` records the same channel's raw XML under its own
/// section; that duplication is deliberate here because this collector additionally
/// *decodes* the events into findings, and the two must not share a parser.
fn defender_history(ctx: &mut ScanContext) {
    const XPATH: &str = "*[System[(EventID=1116 or EventID=1117 or EventID=1006 or EventID=1007 \
                         or EventID=1008 or EventID=1015)]]";
    let Some(events) = collect_channel(
        ctx,
        CHANNEL_DEFENDER,
        "DEFENDER EVENTS (detections and configuration changes)",
        XPATH,
        200,
    ) else {
        return;
    };

    for fields in &events {
        match fields.event_id {
            1006 | 1007 | 1008 | 1015 => {
                let detail = defender_detail(fields);
                ctx.add(
                    Finding::new(
                        Severity::High,
                        "defender",
                        "Windows Defender protection state was changed",
                    )
                    .evidence(format!("event id: {}", fields.event_id))
                    .evidence(format!("detail: {detail}"))
                    .evidence(
                        "This event category records Defender being reconfigured or stopped. \
                         Disabling real-time protection is a standard first step before \
                         installing a persistent agent.",
                    )
                    .remediation(
                        "Check Defender's current protection status and re-enable anything that \
                         was turned off.",
                    ),
                );
            }
            1116 | 1117 => {
                let threat = field(fields, "Threat Name")
                    .or_else(|| field(fields, "ThreatName"))
                    .or_else(|| field(fields, "Name"))
                    .unwrap_or_default();
                let resource = field(fields, "Path")
                    .or_else(|| field(fields, "Resource"))
                    .or_else(|| field(fields, "Resource Name"))
                    .unwrap_or_default();
                let safe_threat = sanitize(threat, MAX_DATA_VALUE);
                let safe_resource = sanitize(resource, MAX_DATA_VALUE);

                ctx.add(
                    Finding::new(
                        Severity::Med,
                        "defender",
                        "Windows Defender recorded a malware detection",
                    )
                    .evidence(format!("threat: {safe_threat}"))
                    .evidence(format!("resource: {safe_resource}"))
                    .evidence(
                        "Defender found a file matching known malware. Depending on the action \
                         taken, the payload may still be present on disk.",
                    )
                    .remediation(
                        "Locate the named resource and remove it after capturing its hash if it \
                         matters.",
                    ),
                );
            }
            _ => {}
        }
    }
}

/// A human-readable summary of a Defender configuration event.
///
/// Different event IDs carry different field names for the same idea, so the first
/// present one is used; a missing field leaves the record empty rather than
/// inventing a value.
fn defender_detail(fields: &EventFields) -> String {
    let candidate = field(fields, "Threat Name")
        .or_else(|| field(fields, "Feature Name"))
        .or_else(|| field(fields, "Configuration"))
        .or_else(|| field(fields, "New Value"))
        .or_else(|| field(fields, "Product Name"))
        .unwrap_or_default();
    if candidate.is_empty() {
        "no detail fields present".to_string()
    } else {
        sanitize(candidate, MAX_DATA_VALUE)
    }
}

/// FR-10: scheduled task registered (TaskScheduler 106).
///
/// A task can install an agent the same way a service can, and Task Scheduler's
/// operational log records the registration with its author. The task path is
/// pushed as a haystack needle for the signature database.
fn task_registration(ctx: &mut ScanContext) {
    let xpath = "*[System[EventID=106]]";
    let Some(events) = collect_channel(
        ctx,
        CHANNEL_TASKSCHED,
        "TASKSCHEDULER EVENTS (106 task registered)",
        xpath,
        200,
    ) else {
        return;
    };

    for fields in &events {
        let path = field(fields, "TaskName")
            .or_else(|| field(fields, "Task Name"))
            .or_else(|| field(fields, "Name"))
            .unwrap_or_default();
        let author = field(fields, "UserName")
            .or_else(|| field(fields, "User Name"))
            .or_else(|| field(fields, "SubjectUserName"))
            .unwrap_or_default();
        let safe_path = sanitize(path, MAX_DATA_VALUE);
        let safe_author = sanitize(author, MAX_DATA_VALUE);

        if safe_path.is_empty() {
            continue;
        }

        ctx.note(
            HaystackKind::TaskName,
            safe_path.clone(),
            "task registered (106)",
        );

        let when = if fields.time_created.is_empty() {
            "an unknown time".to_string()
        } else {
            sanitize(&fields.time_created, MAX_DATA_VALUE)
        };

        ctx.add(
            Finding::new(
                Severity::Med,
                "scheduled-task",
                "Scheduled task was registered",
            )
            .evidence(format!("task: {safe_path}"))
            .evidence(format!("author: {safe_author}"))
            .evidence(format!("registered: {when}"))
            .evidence(
                "A newly registered task is a persistence entry. Task Scheduler shows the author \
                 and the time, which is usually enough to tell an updater from an implant.",
            )
            .remediation(
                "Inspect the task's action and confirm the author. Delete it if neither is \
                 recognised.",
            ),
        );
    }
}

/// Is this text a host name or domain rather than an IP literal?
///
/// Distinguished so the value can be pushed as a [`HaystackKind::Domain`] needle,
/// which the signature database matches against known organisation domains. An IP
/// literal (the common case) is deliberately not pushed: it is already reported as
/// the finding's source, and matching every address against a domain list would
/// produce noise. Unparseable input counts as a name, which is the conservative
/// choice - a name match is more likely to mean something than a missed one.
fn address_looks_like_name(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() {
        return false;
    }
    // The placeholder an event uses when no address applies is not a name.
    if s == "-" || s == "*" {
        return false;
    }
    // A name contains at least one letter that is not a hex digit: an IPv4 literal
    // has none, and an IPv6 literal's only letters are a-f. That single check
    // separates `office-pc` and `vpn.example.com` from `10.0.0.5` and `fe80::1`
    // without a full address parser.
    let mut has_alpha = false;
    for ch in s.chars() {
        if ch.is_ascii_alphabetic() && !ch.is_ascii_hexdigit() {
            has_alpha = true;
            break;
        }
    }
    has_alpha
}

/// Push `value` onto `items` if non-empty, not a placeholder, and not already
/// present, up to `max` entries.
fn push_unique(items: &mut Vec<String>, value: String, max: usize) {
    if value.is_empty() || value == "-" || value == "*" {
        return;
    }
    if items.len() >= max {
        return;
    }
    if items.iter().any(|existing| existing == &value) {
        return;
    }
    items.push(value);
}

/// Join with `, `, or a dash when nothing was collected.
fn join_or_dash(items: &[String]) -> String {
    if items.is_empty() {
        "-".to_string()
    } else {
        items.join(", ")
    }
}

#[test]
fn raw_event_lines_keep_the_event_data_that_is_the_evidence() {
    // The RAW section used to write `sanitize(&event.xml, 512)`. In a real event the
    // `<EventData>` block - which is where `ServiceName` and `ImagePath` live - comes
    // after `<System>`, so it was the first thing cut. The report then showed a 7045
    // event whose whole point is the name of the service installed, with the name
    // missing. Observed on this host: every 7045 line ended mid-`<Channel>`.
    //
    // A finding cites this section as its evidence, so evidence that omits the deciding
    // field is not evidence. The line is built from the extracted fields instead.
    let xml = r#"<Event xmlns='x'><System><EventID>7045</EventID></System><EventData><Data Name="ServiceName">NvModuleTracker</Data><Data Name="ImagePath">\SystemRoot\System32\drivers\nvmodule.sys</Data><Data Name="ServiceType">kernel mode driver</Data></EventData></Event>"#;
    let line = summarize_event_xml(xml, 4096);

    assert!(
        line.contains("NvModuleTracker"),
        "the service name is the evidence and must survive: {line}"
    );
    assert!(
        line.contains("nvmodule.sys"),
        "the image path is the evidence and must survive: {line}"
    );
    assert!(line.contains("7045"), "the event id must survive: {line}");

    // A short limit must still cut, and cut without splitting a character.
    let short = summarize_event_xml(xml, 40);
    assert!(short.chars().count() <= 41, "respects the limit: {short}");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic 7045 rendering: namespace-qualified root, `Qualifiers` on the
    /// EventID, `Name="..."` attributes on Provider and Data, and a service image
    /// path containing an escaped `&`.
    const SERVICE_7045: &str = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Service Control Manager" Guid="{555908d1-a6d7-4695-8e1e-26931d2012f4}"/>
    <EventID Qualifiers="16384">7045</EventID>
    <Version>0</Version>
    <Level>4</Level>
    <TimeCreated SystemTime="2026-08-14T22:03:11.1234567Z"/>
    <EventRecordID>99123</EventRecordID>
    <Channel>System</Channel>
    <Computer>WORKSTATION-7</Computer>
  </System>
  <EventData>
    <Data Name="ServiceName">AcmeAgent</Data>
    <Data Name="ImagePath">C:\Users\bob\AppData\Local\Temp\a&amp;b\agent.exe -k netsvcs</Data>
    <Data Name="ServiceType">user mode service</Data>
  </EventData>
</Event>"#;

    #[test]
    fn parse_event_xml_reads_service_install_fields() {
        let fields = parse_event_xml(SERVICE_7045).expect("fixture must parse");
        assert_eq!(fields.event_id, 7045);
        assert_eq!(fields.provider, "Service Control Manager");
        assert_eq!(fields.channel, "System");
        assert_eq!(fields.computer, "WORKSTATION-7");
        assert_eq!(fields.time_created, "2026-08-14T22:03:11.1234567Z");
        assert_eq!(field(&fields, "ServiceName"), Some("AcmeAgent"));
        // The escaped ampersand is decoded on the way in.
        assert_eq!(
            field(&fields, "ImagePath"),
            Some(r"C:\Users\bob\AppData\Local\Temp\a&b\agent.exe -k netsvcs")
        );
    }

    #[test]
    fn parse_event_xml_accepts_attributes_on_event_id() {
        // `<EventID Qualifiers="0">` must not swallow the value: a strict reader
        // that took the element text verbatim would hand back `0</EventID>`.
        let xml = r#"<Event><System><EventID Qualifiers="0">4697</EventID>
<Channel>Security</Channel></System><EventData>
<Data Name="ServiceName">x</Data></EventData></Event>"#;
        let fields = parse_event_xml(xml).expect("fixture must parse");
        assert_eq!(fields.event_id, 4697);
    }

    #[test]
    fn parse_event_xml_decodes_named_and_numeric_entities() {
        let xml = r#"<Event><System><EventID>1</EventID></System><EventData>
<Data Name="Cmd">&lt;run&gt; &#x41;&#66; &quot;quoted&quot; &apos;s&apos;</Data>
</EventData></Event>"#;
        let fields = parse_event_xml(xml).expect("fixture must parse");
        assert_eq!(field(&fields, "Cmd"), Some("<run> AB \"quoted\" 's'"));
    }

    #[test]
    fn parse_event_xml_keeps_unnamed_data_under_empty_key() {
        // TerminalServices 1149 and several providers emit positional `<Data>`
        // elements with no Name; dropping them would lose the source address.
        let xml = r#"<Event><System><EventID>1149</EventID></System><EventData>
<Data Name="Param1">bob</Data><Data>bare-value</Data>
</EventData></Event>"#;
        let fields = parse_event_xml(xml).expect("fixture must parse");
        assert_eq!(field(&fields, ""), Some("bare-value"));
        let unnamed = fields.data.iter().filter(|(k, _)| k.is_empty()).count();
        assert_eq!(unnamed, 1);
    }

    #[test]
    fn parse_event_xml_returns_none_for_truncated_document() {
        // Cut mid-tag: the scan must fail cleanly rather than index past the end.
        let truncated = "<Event><System><EventID>7045<";
        assert_eq!(parse_event_xml(truncated), None);
        assert_eq!(parse_event_xml(""), None);
        assert_eq!(parse_event_xml("<Other>not an event</Other>"), None);
    }

    #[test]
    fn parse_event_xml_caps_data_elements() {
        let mut xml = String::from("<Event><System><EventID>1</EventID></System><EventData>");
        for i in 0..1000 {
            xml.push_str(&format!("<Data Name=\"D{i}\">v{i}</Data>"));
        }
        xml.push_str("</EventData></Event>");

        let fields = parse_event_xml(&xml).expect("fixture must parse");
        assert_eq!(fields.data.len(), MAX_DATA_FIELDS);
    }

    #[test]
    fn parse_event_xml_truncates_hostile_value_to_cap() {
        // A megabyte of `A`s must arrive capped, never echoed at full length.
        let huge = "A".repeat(1024 * 1024);
        let xml = format!("<Event><System><EventID>1</EventID></System><EventData><Data Name=\"X\">{huge}</Data></EventData></Event>");
        let fields = parse_event_xml(&xml).expect("fixture must parse");
        let value = field(&fields, "X").expect("X must be present");
        assert!(value.len() <= MAX_DATA_VALUE);
    }

    #[test]
    fn the_record_id_and_the_timestamp_are_extracted() {
        // Both are properties of a genuine event, taken from this machine's System log.
        let xml = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Volsnap'/><EventID Qualifiers='16390'>33</EventID><TimeCreated SystemTime='2026-09-12T12:12:30.9060987Z'/><EventRecordID>8092</EventRecordID><Channel>System</Channel></System></Event>"#;
        let fields = parse_event_xml(xml).expect("fixture must parse");
        assert_eq!(fields.record_id, 8092);
        assert_eq!(fields.event_id, 33);
        assert_eq!(fields.time_epoch, Some(1_789_215_150));
    }

    #[test]
    fn a_malformed_timestamp_is_no_timestamp_rather_than_the_epoch() {
        // A guessed time would invent a silence of fifty years and report it as evidence.
        for bad in [
            "",
            "not a date",
            "2026-09-12",
            "2026-13-01T00:00:00Z",
            "2026-09-12T25:00:00Z",
            "2026-09-12T12:12:30+03:00",
            "T12:12:30Z",
        ] {
            assert_eq!(parse_system_time(bad), None, "accepted {bad:?}");
        }
    }

    #[test]
    fn the_timestamp_parser_handles_the_shapes_windows_writes() {
        // With and without fractional seconds, and the leap day.
        assert_eq!(parse_system_time("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_system_time("1970-01-01T00:00:01Z"), Some(1));
        assert_eq!(
            parse_system_time("2000-02-29T00:00:00.0000000Z"),
            Some(951_782_400)
        );
        assert_eq!(
            parse_system_time("2026-09-12T12:12:30Z"),
            Some(1_789_215_150)
        );
        assert_eq!(
            parse_system_time(" 2026-09-12T12:12:30.5Z "),
            Some(1_789_215_150)
        );
    }

    #[test]
    fn field_lookup_is_case_insensitive() {
        let xml = r#"<Event><System><EventID>4624</EventID></System><EventData>
<Data Name="IpAddress">203.0.113.9</Data></EventData></Event>"#;
        let fields = parse_event_xml(xml).expect("fixture must parse");
        assert_eq!(field(&fields, "ipaddress"), Some("203.0.113.9"));
        assert_eq!(field(&fields, "IPADDRESS"), Some("203.0.113.9"));
        assert_eq!(field(&fields, "WorkstationName"), None);
        // An unknown name on a field-less event is a clean `None`, not a panic.
        assert_eq!(field(&EventFields::default(), "X"), None);
    }

    #[test]
    fn parse_event_xml_keeps_unquoted_and_reordered_attributes() {
        // A hostile or hand-rolled producer may omit the quotes; the value must
        // still be found whichever order the attributes appear in.
        let xml = r#"<Event xmlns=x><System><EventID>1</EventID>
<Provider Guid="{}" Name=Acme></Provider></System><EventData>
<Data Service=x Name="Svc"></Data></EventData></Event>"#;
        let fields = parse_event_xml(xml).expect("fixture must parse");
        // `Name=Acme` (unquoted, after a quoted attribute) still decodes.
        assert_eq!(fields.provider, "Acme");
        // The Data element's Name attribute is the key; the unquoted `Service=x`
        // attribute must not have swallowed it.
        assert_eq!(field(&fields, "Svc"), Some(""));
    }

    #[test]
    fn a_known_remote_tool_service_name_is_recognised_on_its_own() {
        // Measured before this existed: 708 ProcessName needles and exactly one
        // ServiceName needle in the whole signature database. A tool that installs itself
        // as a service under a name we had never seen was therefore invisible to the 7045
        // check - despite 7045 being the single best record of how it got there.
        //
        // The name survives a rename of the binary, which is what makes this signal worth
        // having on its own.
        assert!(is_known_remote_tool_service("AnyDesk Service"));
        assert!(is_known_remote_tool_service("TeamViewer"));
        assert!(is_known_remote_tool_service("SplashtopRemoteService"));
        assert!(is_known_remote_tool_service("mesh agent"));

        // Case-insensitive, because installers are inconsistent.
        assert!(is_known_remote_tool_service("TEAMVIEWER"));
        assert!(is_known_remote_tool_service("screeNCOnnect"));

        // An ordinary machine's own services must not trip it. These are real service
        // names present on this host and in a stock Windows install.
        assert!(is_known_remote_tool_service("Spooler").eq(&false));
        assert!(is_known_remote_tool_service("WinDefend").eq(&false));
        assert!(is_known_remote_tool_service("wuauserv").eq(&false));
        assert!(is_known_remote_tool_service("Dnscache").eq(&false));
        // And an empty name is not a match.
        assert!(is_known_remote_tool_service("").eq(&false));
    }

    #[test]
    fn a_known_remote_tool_image_is_recognised() {
        assert!(is_known_remote_tool_image(
            r"C:\Program Files\AnyDesk\AnyDesk.exe"
        ));
        assert!(is_known_remote_tool_image("tvnserver.exe"));
        assert!(is_known_remote_tool_image(r"C:\x\vncserver.exe -service"));
        // Ordinary system binaries must not match.
        assert!(
            is_known_remote_tool_image(r"C:\Windows\System32\svchost.exe -k netsvcs").eq(&false)
        );
        assert!(is_known_remote_tool_image("").eq(&false));
    }

    #[test]
    fn service_install_severity_keeps_a_transit_image_high() {
        // The service file is usually gone by the time the log is read, so the
        // signature is often unknown (None); the location must still hold it at High.
        assert_eq!(
            service_install_severity(
                None,
                r"C:\Users\bob\AppData\Local\Temp\a&b\agent.exe -k netsvcs"
            ),
            Some(Severity::High)
        );
        // Per-user application data is where software legitimately installs: not High
        // on the path alone, whether or not the signature is known.
        assert_eq!(
            service_install_severity(Some(false), r"C:\ProgramData\Acme\agent.exe"),
            Some(Severity::Info)
        );
        assert_eq!(
            service_install_severity(None, r"C:\ProgramData\Acme\agent.exe"),
            None
        );
        // A signed service in a protected directory is not a finding at all; an
        // unsigned one is information, never High. The location is what carries the
        // severity - only a transit directory escalates.
        assert_eq!(
            service_install_severity(Some(true), r"C:\Program Files\Acme\svc.exe"),
            None
        );
        assert_eq!(
            service_install_severity(Some(false), r"C:\Program Files\Acme\svc.exe"),
            Some(Severity::Info)
        );
    }

    #[test]
    fn address_looks_like_name_separates_names_from_literals() {
        assert!(address_looks_like_name("office-pc"));
        assert!(address_looks_like_name("vpn.example.com"));
        assert!(address_looks_like_name("win-dc01.contoso.local"));
        assert!(!address_looks_like_name("203.0.113.9"));
        assert!(!address_looks_like_name("10.0.0.5"));
        assert!(!address_looks_like_name("fe80::1"));
        assert!(!address_looks_like_name("-"));
        assert!(!address_looks_like_name(""));
    }
}
