//! The view model handed to the front end.
//!
//! Pure data and one pure function, which is what makes the desktop surface testable
//! without a window: `build_view` takes the same `ScanContext` the command-line tool
//! renders and produces the same collapsed groups, so the two surfaces cannot disagree
//! about what was found.

use crate::monitor::DeltaView;
use irscan::model::{ScanContext, Severity, Verdict};
use irscan::report::{group_findings, HostInfo};
use serde::Serialize;

/// Facts about the machine, already formatted. The front end must not do date maths.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HostView {
    pub name: String,
    pub user: String,
    pub os: String,
    pub build: String,
    pub install_date: String,
    pub boot_time: String,
    pub elevated: bool,
    pub collected_at: String,
    pub scanned_in_ms: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VerdictView {
    pub high: usize,
    pub med: usize,
    pub info: usize,
    pub headline: String,
    pub recommendation: Vec<String>,
}

/// One rendered finding, or several findings that differ only in their evidence.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GroupView {
    /// `"high"`, `"med"` or `"info"`.
    pub severity: &'static str,
    pub category: String,
    pub title: String,
    pub instances: usize,
    pub evidence: Vec<String>,
    pub remediation: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RawView {
    pub section: String,
    pub lines: Vec<String>,
}

/// Everything the window needs to render a completed scan, and nothing it has to derive.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ScanView {
    pub host: HostView,
    pub verdict: VerdictView,
    pub groups: Vec<GroupView>,
    pub warnings: Vec<String>,
    pub raw: Vec<RawView>,
    /// What changed since the previous run on this machine, if there was one.
    pub delta: DeltaView,
    /// The sentence that stops a clean result from being read as a clean machine.
    pub not_proven: String,
    /// Opaque handle for the report on disk, so "export" does not have to re-scan.
    pub cursor: u64,
}

fn severity_label(severity: Severity) -> &'static str {
    severity.label()
}

/// Build the view model from a completed scan.
///
/// Grouping is `report::group_findings`, deliberately: the desktop view and the text
/// report must collapse identical findings the same way, or a user comparing the two
/// would see different counts and stop trusting both.
pub fn build_view(
    host: &HostInfo,
    ctx: &ScanContext,
    verdict: &Verdict,
    scanned_in_ms: u64,
    cursor: u64,
    delta: DeltaView,
) -> ScanView {
    let groups = group_findings(ctx)
        .into_iter()
        .map(|g| GroupView {
            severity: severity_label(g.severity),
            category: g.category,
            title: g.title,
            instances: g.instances,
            evidence: g.evidence,
            remediation: g.remediation,
        })
        .collect();

    ScanView {
        host: HostView {
            name: host.name.clone(),
            user: host.user.clone(),
            os: host.os.clone(),
            build: host.build.clone(),
            install_date: host.install_date.clone(),
            boot_time: host.boot_time.clone(),
            elevated: host.elevated,
            collected_at: host.collected_at.clone(),
            scanned_in_ms,
        },
        verdict: VerdictView {
            high: verdict.high,
            med: verdict.med,
            info: verdict.info,
            headline: verdict.headline.clone(),
            recommendation: verdict.recommendation.clone(),
        },
        groups,
        warnings: ctx.warnings.clone(),
        raw: ctx
            .raw
            .iter()
            .map(|(section, lines)| RawView {
                section: section.clone(),
                lines: lines.clone(),
            })
            .collect(),
        not_proven: "A clean result is not proof of a clean machine: a kernel-mode rootkit \
                     or a renamed agent with no registry trace can hide from every \
                     user-mode check this tool performs."
            .to_string(),
        delta,
        cursor,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use irscan::model::Finding;

    fn empty_delta() -> DeltaView {
        DeltaView {
            since: None,
            added: Vec::new(),
            removed: Vec::new(),
            summary: "nothing changed".to_string(),
            new_presence: false,
            first_run: true,
        }
    }

    fn host() -> HostInfo {
        HostInfo {
            name: "PC-01".into(),
            user: "bob".into(),
            os: "Windows 10 Pro".into(),
            build: "19045".into(),
            elevated: false,
            collected_at: "2026-09-11 21:00:00".into(),
            ..Default::default()
        }
    }

    fn ctx_with(severities: &[Severity]) -> ScanContext {
        let mut ctx = ScanContext::default();
        for (i, s) in severities.iter().enumerate() {
            ctx.add(
                Finding::new(*s, "process", format!("finding {i}"))
                    .evidence(format!("pid {i}"))
                    .remediation("Identify the file before acting."),
            );
        }
        ctx
    }

    #[test]
    fn severity_is_serialised_as_the_front_end_expects() {
        let ctx = ctx_with(&[Severity::High, Severity::Med, Severity::Info]);
        let verdict = irscan::rules::verdict(&ctx.findings, 0);
        let view = build_view(&host(), &ctx, &verdict, 10, 1, empty_delta());
        let labels: Vec<&str> = view.groups.iter().map(|g| g.severity).collect();
        assert_eq!(labels, vec!["high", "med", "info"]);
    }

    #[test]
    fn the_view_carries_the_same_counts_as_the_verdict() {
        let ctx = ctx_with(&[Severity::High, Severity::High, Severity::Info]);
        let verdict = irscan::rules::verdict(&ctx.findings, 0);
        let view = build_view(&host(), &ctx, &verdict, 10, 1, empty_delta());
        assert_eq!(view.verdict.high, 2);
        assert_eq!(view.verdict.med, 0);
        assert_eq!(view.verdict.info, 1);
    }

    #[test]
    fn identical_findings_are_collapsed_exactly_as_the_text_report_collapses_them() {
        let mut ctx = ScanContext::default();
        for i in 0..5 {
            ctx.add(
                Finding::new(Severity::Med, "filesystem", "unsigned executable")
                    .evidence(format!("file {i}.exe")),
            );
        }
        let verdict = irscan::rules::verdict(&ctx.findings, 0);
        let view = build_view(&host(), &ctx, &verdict, 10, 1, empty_delta());

        assert_eq!(
            view.groups.len(),
            1,
            "five identical findings are one group"
        );
        assert_eq!(view.groups[0].instances, 5);
        assert_eq!(view.groups[0].evidence.len(), 5);
    }

    #[test]
    fn warnings_and_raw_sections_are_passed_through_untouched() {
        let mut ctx = ctx_with(&[Severity::Info]);
        ctx.warn("events: Security unavailable");
        ctx.warn("events: Security unavailable");
        ctx.raw_section("SERVICES", vec!["svc a".to_string()]);
        let verdict = irscan::rules::verdict(&ctx.findings, ctx.warnings.len());
        let view = build_view(&host(), &ctx, &verdict, 42, 7, empty_delta());

        assert_eq!(view.warnings.len(), 1, "the core already deduplicates");
        assert_eq!(view.raw.len(), 1);
        assert_eq!(view.raw[0].section, "SERVICES");
        assert_eq!(view.host.scanned_in_ms, 42);
        assert_eq!(view.cursor, 7);
    }

    #[test]
    fn the_view_always_carries_the_sentence_that_limits_it() {
        let ctx = ScanContext::default();
        let verdict = irscan::rules::verdict(&[], 0);
        let view = build_view(&host(), &ctx, &verdict, 1, 1, empty_delta());
        assert!(view.not_proven.contains("not proof of a clean machine"));
        assert!(view.groups.is_empty());
    }

    #[test]
    fn a_hostile_title_survives_as_plain_data() {
        // The front end renders with textContent; this pins that the payload itself is
        // valid JSON with the markup escaped rather than stripped, so the UI receives
        // exactly what the machine reported.
        let mut ctx = ScanContext::default();
        ctx.add(Finding::new(
            Severity::High,
            "process",
            "evil</script><img src=x onerror=alert(1)>",
        ));
        let verdict = irscan::rules::verdict(&ctx.findings, 0);
        let view = build_view(&host(), &ctx, &verdict, 1, 1, empty_delta());
        let json = serde_json::to_string(&view).unwrap_or_default();

        assert!(json.contains("onerror"));
        assert!(
            json.contains("\\u003c") || json.contains("<"),
            "the payload must round-trip the markup as data"
        );
    }

    #[test]
    fn the_payload_uses_the_field_names_the_front_end_reads() {
        // The contract between the two halves is field names; a rename here is a silent
        // blank screen in the window, so it is pinned.
        let ctx = ctx_with(&[Severity::Med]);
        let verdict = irscan::rules::verdict(&ctx.findings, 0);
        let view = build_view(&host(), &ctx, &verdict, 5, 1, empty_delta());
        let json = serde_json::to_string(&view).unwrap_or_default();

        for key in [
            "\"scannedInMs\"",
            "\"installDate\"",
            "\"bootTime\"",
            "\"collectedAt\"",
            "\"notProven\"",
            "\"delta\"",
            "\"instances\"",
            "\"remediation\"",
            "\"recommendation\"",
        ] {
            assert!(json.contains(key), "missing {key} in {json}");
        }
    }
}
