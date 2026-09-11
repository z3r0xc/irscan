//! Report rendering: text for humans, JSON for diffing and CI.
//!
//! Both renderers are pure functions of the collected data, which is what makes the
//! output testable without touching a real machine. The JSON is hand-written rather
//! than pulled from a serialiser so the shipped binary keeps zero runtime
//! dependencies; the escaping rules are unit-tested instead.

use std::fmt::Write as _;

use crate::model::{ScanContext, Severity, Verdict};

/// Facts about the machine that are not findings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostInfo {
    pub name: String,
    pub user: String,
    pub os: String,
    pub build: String,
    pub install_date: String,
    pub boot_time: String,
    pub elevated: bool,
    pub collected_at: String,
}

/// Escape a string for inclusion in a JSON document.
///
/// The values come from a hostile host, so the full set of JSON-required escapes is
/// applied rather than trusting that the input is "probably fine": a raw `"` would
/// produce invalid JSON, and a raw control character would produce a document that
/// some parsers reject.
pub fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 2);
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// A JSON string literal, quotes included.
pub fn json_string(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 2);
    out.push('"');
    out.push_str(&json_escape(input));
    out.push('"');
    out
}

fn json_array(items: &[String]) -> String {
    let parts: Vec<String> = items.iter().map(|s| json_string(s)).collect();
    format!("[{}]", parts.join(", "))
}

/// Findings in a deterministic order: most severe first, then category, then title.
///
/// Two scans of an unchanged host must produce byte-identical reports, otherwise a
/// diff between runs is useless for spotting what changed.
pub fn sorted_findings(ctx: &ScanContext) -> Vec<&crate::model::Finding> {
    let mut findings: Vec<&crate::model::Finding> = ctx.findings.iter().collect();
    findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| a.category.cmp(b.category))
            .then_with(|| a.title.cmp(&b.title))
    });
    findings
}

/// How many distinct evidence lines one collapsed group carries.
///
/// A developer machine produces dozens of structurally identical findings that
/// differ only in the evidence ("unsigned binary in a user-writable location",
/// "image path could not be read"). Printing each one separately buries the single
/// finding that actually matters, so the text report collapses them; the sample has
/// to stay small enough for a human to read.
pub const MAX_GROUP_EVIDENCE: usize = 12;

/// Same idea for remediation lines, which are usually identical across a group.
pub const MAX_GROUP_REMEDIATION: usize = 3;

/// One rendered entry of the text report: a finding, or several findings that differ
/// only in their evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grouped {
    pub severity: Severity,
    pub category: String,
    pub title: String,
    /// How many raw findings collapsed into this entry. 1 means no collapsing.
    pub instances: usize,
    pub evidence: Vec<String>,
    pub remediation: Vec<String>,
}

/// Collapse structurally identical findings for the text report.
///
/// Grouping is by `(severity, category, title)`, which is exactly the sort key of
/// [`sorted_findings`], so equal findings are already adjacent and the whole pass is
/// a linear scan. The JSON report deliberately keeps every raw finding: a machine
/// consumer wants the complete list, a human wants the signal.
pub fn group_findings(ctx: &ScanContext) -> Vec<Grouped> {
    let mut out: Vec<Grouped> = Vec::new();

    for f in sorted_findings(ctx) {
        let same = match out.last() {
            Some(last) => {
                last.severity == f.severity && last.category == f.category && last.title == f.title
            }
            None => false,
        };

        if same {
            if let Some(last) = out.last_mut() {
                last.instances += 1;
                for line in &f.evidence {
                    if last.evidence.len() >= MAX_GROUP_EVIDENCE {
                        break;
                    }
                    if last.evidence.iter().any(|seen| seen == line) {
                        continue;
                    }
                    last.evidence.push(line.clone());
                }
                for line in &f.remediation {
                    if last.remediation.len() >= MAX_GROUP_REMEDIATION {
                        break;
                    }
                    if last.remediation.iter().any(|seen| seen == line) {
                        continue;
                    }
                    last.remediation.push(line.clone());
                }
            }
            continue;
        }

        out.push(Grouped {
            severity: f.severity,
            category: f.category.to_string(),
            title: f.title.clone(),
            instances: 1,
            evidence: f.evidence.clone(),
            remediation: f.remediation.clone(),
        });
    }

    out
}

/// The human-readable report: console output and the `.txt` file are the same text.
pub fn render_text(host: &HostInfo, ctx: &ScanContext, verdict: &Verdict) -> String {
    let mut out = String::with_capacity(8192);

    out.push_str("============================================================================\n");
    out.push_str(" IRScan - read-only endpoint triage for unauthorised monitoring / control\n");
    out.push_str("============================================================================\n");
    let _ = writeln!(
        out,
        " Host        : {}",
        if host.name.is_empty() {
            "unknown"
        } else {
            &host.name
        }
    );
    let _ = writeln!(
        out,
        " User        : {}",
        if host.user.is_empty() {
            "unknown"
        } else {
            &host.user
        }
    );
    let _ = writeln!(
        out,
        " Elevated    : {}",
        if host.elevated {
            "yes (full coverage)"
        } else {
            "NO - several checks cannot run; re-run as Administrator"
        }
    );
    let _ = writeln!(out, " OS          : {} build {}", host.os, host.build);
    let _ = writeln!(
        out,
        " Installed   : {}   Booted: {}",
        host.install_date, host.boot_time
    );
    let _ = writeln!(out, " Collected   : {}", host.collected_at);
    out.push('\n');

    out.push_str("----------------------------------------------------------------------------\n");
    out.push_str(" VERDICT\n");
    out.push_str("----------------------------------------------------------------------------\n");
    let _ = writeln!(
        out,
        " {} high, {} medium, {} informational finding(s)",
        verdict.high, verdict.med, verdict.info
    );
    let _ = writeln!(out, " {}", verdict.headline);
    out.push('\n');
    out.push_str(" Recommended next steps:\n");
    for (i, line) in verdict.recommendation.iter().enumerate() {
        let _ = writeln!(out, "  {}. {}", i + 1, line);
    }
    out.push('\n');

    out.push_str("----------------------------------------------------------------------------\n");
    out.push_str(" FINDINGS\n");
    out.push_str("----------------------------------------------------------------------------\n");
    let groups = group_findings(ctx);
    if groups.is_empty() {
        out.push_str(" none\n");
    }
    for g in &groups {
        // An instance count is the difference between "the report says one thing is
        // wrong" and "the report says this kind of thing is systemic here".
        let suffix = if g.instances > 1 {
            format!(
                "   ({} findings of this kind; {} shown)",
                g.instances,
                g.evidence.len()
            )
        } else {
            String::new()
        };
        let _ = writeln!(
            out,
            "[{}] {}: {}{}",
            g.severity.tag(),
            g.category,
            g.title,
            suffix
        );
        for line in &g.evidence {
            let _ = writeln!(out, "       {line}");
        }
        for line in &g.remediation {
            let _ = writeln!(out, "    -> {line}");
        }
        out.push('\n');
    }

    if ctx.warnings.is_empty() {
        // Nothing to report, and an empty section would only add noise.
    } else {
        out.push_str(
            "----------------------------------------------------------------------------\n",
        );
        out.push_str(" WARNINGS (checks that could not run - the report is incomplete)\n");
        out.push_str(
            "----------------------------------------------------------------------------\n",
        );
        let mut warnings: Vec<&String> = ctx.warnings.iter().collect();
        warnings.sort();
        for w in warnings {
            let _ = writeln!(out, " ! {w}");
        }
        out.push('\n');
    }

    out.push_str("----------------------------------------------------------------------------\n");
    out.push_str(" WHAT THIS REPORT DOES NOT PROVE\n");
    out.push_str("----------------------------------------------------------------------------\n");
    out.push_str(" A clean result is not proof that the machine is clean: a kernel-mode rootkit\n");
    out.push_str(" or a renamed agent with no registry trace can hide from every user-mode API\n");
    out.push_str(" this tool uses. Findings are heuristics backed by raw evidence - read the\n");
    out.push_str(" evidence, not just the severity tag.\n\n");

    out.push_str("----------------------------------------------------------------------------\n");
    out.push_str(" RAW DATA\n");
    out.push_str("----------------------------------------------------------------------------\n");
    for (section, lines) in &ctx.raw {
        let _ = writeln!(out, "\n## {section}");
        for line in lines {
            let _ = writeln!(out, "   {line}");
        }
    }

    out
}

/// The machine-readable report. The schema name and field names are part of the
/// contract (spec section 8.2); changes must be additive.
pub fn render_json(host: &HostInfo, ctx: &ScanContext, verdict: &Verdict) -> String {
    let mut out = String::with_capacity(16384);

    out.push_str("{\n");
    out.push_str("  \"schema\": \"irscan/v1\",\n");
    let _ = writeln!(
        out,
        "  \"host\": {{ \"name\": {}, \"user\": {}, \"os\": {}, \"build\": {}, \"admin\": {} }},",
        json_string(&host.name),
        json_string(&host.user),
        json_string(&host.os),
        json_string(&host.build),
        host.elevated
    );
    let _ = writeln!(
        out,
        "  \"verdict\": {{ \"high\": {}, \"med\": {}, \"info\": {}, \"headline\": {}, \"recommendation\": {} }},",
        verdict.high,
        verdict.med,
        verdict.info,
        json_string(&verdict.headline),
        json_array(&verdict.recommendation)
    );

    out.push_str("  \"findings\": [\n");
    let findings = sorted_findings(ctx);
    for (i, f) in findings.iter().enumerate() {
        let _ = writeln!(
            out,
            "    {{ \"severity\": {}, \"category\": {}, \"title\": {}, \"evidence\": {}, \"remediation\": {} }}{}",
            json_string(f.severity.label()),
            json_string(f.category),
            json_string(&f.title),
            json_array(&f.evidence),
            json_array(&f.remediation),
            if i + 1 == findings.len() { "" } else { "," }
        );
    }
    out.push_str("  ],\n");

    let mut warnings: Vec<String> = ctx.warnings.clone();
    warnings.sort();
    let _ = writeln!(out, "  \"warnings\": {}", json_array(&warnings));
    out.push_str("}\n");

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Finding;

    fn host() -> HostInfo {
        HostInfo {
            name: "PC-01".into(),
            user: "bob".into(),
            os: "Windows 10 Pro".into(),
            build: "19045".into(),
            elevated: true,
            ..Default::default()
        }
    }

    fn ctx_with(severities: &[Severity]) -> ScanContext {
        let mut ctx = ScanContext::default();
        for (i, s) in severities.iter().enumerate() {
            ctx.add(Finding::new(*s, "cat", format!("finding {i}")));
        }
        ctx
    }

    #[test]
    fn json_escaping_covers_the_required_characters() {
        assert_eq!(json_escape("plain"), "plain");
        assert_eq!(json_escape("a\"b"), "a\\\"b");
        assert_eq!(json_escape("a\\b"), "a\\\\b");
        assert_eq!(json_escape("a\nb\tc"), "a\\nb\\tc");
        assert_eq!(json_escape("\u{1}\u{1f}"), "\\u0001\\u001f");
        // Non-ASCII passes through as UTF-8, which JSON allows.
        assert_eq!(json_escape("Стахановец"), "Стахановец");
    }

    #[test]
    fn json_string_wraps_and_escapes() {
        assert_eq!(json_string("x"), "\"x\"");
        assert_eq!(json_string("a\"b"), "\"a\\\"b\"");
    }

    #[test]
    fn json_output_has_the_documented_shape() {
        let ctx = ctx_with(&[Severity::High]);
        let json = render_json(&host(), &ctx, &crate::rules::verdict(&ctx.findings, 0));
        assert!(json.starts_with('{'));
        assert!(json.trim_end().ends_with('}'));
        for key in [
            "\"schema\": \"irscan/v1\"",
            "\"host\":",
            "\"verdict\":",
            "\"findings\":",
            "\"warnings\":",
            "\"severity\": \"high\"",
        ] {
            assert!(json.contains(key), "missing {key} in {json}");
        }
        // Balanced delimiters: a cheap structural check that catches the classic
        // "forgot a separator" bug in a hand-written serialiser.
        assert_eq!(json.matches('{').count(), json.matches('}').count());
        assert_eq!(json.matches('[').count(), json.matches(']').count());
    }

    #[test]
    fn json_handles_a_hostile_title_without_breaking_the_document() {
        // A quote inside a system-supplied string must not terminate the JSON string
        // early and inject a field.
        let mut ctx = ScanContext::default();
        ctx.add(Finding::new(
            Severity::High,
            "process",
            "evil\"] ,\"injected\":\"yes",
        ));
        let json = render_json(&host(), &ctx, &crate::rules::verdict(&ctx.findings, 0));
        assert!(!json.contains("\"injected\""), "injection survived");
        assert!(json.contains("\\\""));
    }

    #[test]
    fn json_empty_collections_render_as_empty_arrays() {
        let ctx = ScanContext::default();
        let json = render_json(&host(), &ctx, &crate::rules::verdict(&[], 0));
        assert!(json.contains("\"warnings\": []"));
    }

    #[test]
    fn text_report_contains_the_verdict_counts_and_no_raw_escapes() {
        let ctx = ctx_with(&[Severity::High, Severity::Med]);
        let verdict = crate::rules::verdict(&ctx.findings, 0);
        let text = render_text(&host(), &ctx, &verdict);
        assert!(text.contains("1 high, 1 medium, 0 informational"));
        assert!(text.contains("PC-01"));
        // The severity tag is the machine-readable part a human greps for.
        assert!(text.contains("[HIGH] cat: finding 0"));
        assert!(!text.contains('\u{1b}'), "an escape sequence survived");
    }

    #[test]
    fn text_report_states_that_a_clean_result_proves_nothing() {
        let ctx = ScanContext::default();
        let text = render_text(&host(), &ctx, &crate::rules::verdict(&[], 0));
        assert!(text.contains("not proof that the machine is clean"));
    }

    #[test]
    fn identical_findings_collapse_into_one_entry_with_a_count() {
        let mut ctx = ScanContext::default();
        for i in 0..5 {
            ctx.add(
                Finding::new(
                    Severity::Med,
                    "process",
                    "unsigned binary in user-writable path",
                )
                .evidence(format!("pid {i}")),
            );
        }
        let groups = group_findings(&ctx);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].instances, 5);
        assert_eq!(
            groups[0].evidence.len(),
            5,
            "distinct evidence lines are kept"
        );
    }

    #[test]
    fn findings_with_different_titles_are_not_collapsed() {
        let mut ctx = ScanContext::default();
        ctx.add(Finding::new(Severity::Med, "process", "one"));
        ctx.add(Finding::new(Severity::Med, "process", "two"));
        assert_eq!(group_findings(&ctx).len(), 2);
    }

    #[test]
    fn group_evidence_is_capped_so_one_bad_category_cannot_flood_the_report() {
        let mut ctx = ScanContext::default();
        for i in 0..500 {
            ctx.add(Finding::new(Severity::Med, "process", "same").evidence(format!("pid {i}")));
        }
        let groups = group_findings(&ctx);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].instances, 500);
        assert_eq!(groups[0].evidence.len(), MAX_GROUP_EVIDENCE);
    }

    #[test]
    fn duplicate_evidence_lines_are_not_repeated_within_a_group() {
        let mut ctx = ScanContext::default();
        for _ in 0..3 {
            ctx.add(Finding::new(Severity::Med, "process", "same").evidence("identical line"));
        }
        let groups = group_findings(&ctx);
        assert_eq!(groups[0].instances, 3);
        assert_eq!(groups[0].evidence.len(), 1);
    }

    #[test]
    fn grouping_preserves_severity_order() {
        let mut ctx = ScanContext::default();
        ctx.add(Finding::new(Severity::Info, "c", "z"));
        ctx.add(Finding::new(Severity::High, "c", "a"));
        ctx.add(Finding::new(Severity::High, "c", "a"));
        let groups = group_findings(&ctx);
        assert_eq!(groups[0].severity, Severity::High);
        assert_eq!(groups[0].instances, 2);
        assert_eq!(groups[1].severity, Severity::Info);
    }

    #[test]
    fn text_report_announces_the_instance_count_and_json_keeps_every_finding() {
        let mut ctx = ScanContext::default();
        for _ in 0..4 {
            ctx.add(Finding::new(Severity::Med, "process", "repeated"));
        }
        let verdict = crate::rules::verdict(&ctx.findings, 0);
        let text = render_text(&host(), &ctx, &verdict);
        assert!(text.contains("(4 findings of this kind"));

        // The machine-readable report must stay complete: collapsing is a
        // presentation choice for humans, not a loss of data.
        let json = render_json(&host(), &ctx, &verdict);
        assert_eq!(json.matches("\"title\": \"repeated\"").count(), 4);
    }

    #[test]
    fn findings_are_ordered_by_severity_then_category_then_title() {
        let ctx = ctx_with(&[Severity::Info, Severity::High, Severity::Med]);
        let order: Vec<Severity> = sorted_findings(&ctx).iter().map(|f| f.severity).collect();
        assert_eq!(order, vec![Severity::High, Severity::Med, Severity::Info]);
    }

    #[test]
    fn report_rendering_is_deterministic() {
        // Same input, same bytes: a diff between two runs must mean the host changed.
        let ctx = ctx_with(&[Severity::Med, Severity::High]);
        let verdict = crate::rules::verdict(&ctx.findings, 1);
        assert_eq!(
            render_text(&host(), &ctx, &verdict),
            render_text(&host(), &ctx, &verdict)
        );
        assert_eq!(
            render_json(&host(), &ctx, &verdict),
            render_json(&host(), &ctx, &verdict)
        );
    }

    #[test]
    fn warnings_are_rendered_when_present_and_absent_otherwise() {
        let mut ctx = ScanContext::default();
        ctx.warn("events: access denied");
        let text = render_text(&host(), &ctx, &crate::rules::verdict(&[], 1));
        assert!(text.contains("WARNINGS"));
        assert!(text.contains("events: access denied"));

        let clean = render_text(
            &host(),
            &ScanContext::default(),
            &crate::rules::verdict(&[], 0),
        );
        assert!(!clean.contains("WARNINGS"));
    }

    #[test]
    fn raw_sections_are_included_in_the_text_report() {
        let mut ctx = ScanContext::default();
        ctx.raw_section("SERVICES", vec!["svc a".into(), "svc b".into()]);
        let text = render_text(&host(), &ctx, &crate::rules::verdict(&[], 0));
        assert!(text.contains("## SERVICES"));
        assert!(text.contains("svc a"));
    }
}
