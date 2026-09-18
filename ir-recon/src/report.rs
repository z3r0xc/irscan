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

/// `"key : value"` with the colon at a fixed column, so a column of these reads as a
/// table instead of a ragged edge.
fn kv_line(key: &str, value: &str) -> String {
    format!(" {key:<11}: {value}")
}

/// The bytes Windows' raster fonts (Consolas, Courier New, Lucida Console) draw
/// full-width: they occupy both halves of a 2-cell glyph. Everything else outside
/// ASCII is drawn two cells wide by those fonts, but only one by a modern webview.
///
/// This matters because the file is read in Notepad: a report where one column is
/// padded by character count drifts left by one cell for every Cyrillic character
/// above it. Half-width kana, and only kana, is the exception.
fn is_narrow_non_ascii(ch: char) -> bool {
    matches!(ch,
        '\u{ff61}'..='\u{ff9f}'
        | '\u{ffbf}' | '\u{ffc2}'..='\u{ffc7}' | '\u{ffca}'..='\u{ffcf}'
        | '\u{ffd2}'..='\u{ffd7}' | '\u{ffda}'..='\u{ffdc}' | '\u{ffe8}'..='\u{ffee}')
}

/// Columns a monospace cell occupies, in the sense the *file* is read in.
///
/// Deliberately *not* a general East Asian Width implementation: it is exactly the
/// width Windows' console fonts use, because that is the reader this report is
/// laid out for. A webview would disagree about three characters, and the columns
/// the report actually builds (the severity tag) are ASCII either way.
fn mono_width(text: &str) -> usize {
    text.chars()
        .map(|c| {
            if c.is_ascii() || is_narrow_non_ascii(c) {
                1
            } else {
                2
            }
        })
        .sum()
}

/// Pad to `cols` so that the *next* text starts at the same screen column.
fn mono_pad(text: &str, cols: usize) -> String {
    let w = mono_width(text);
    if w >= cols {
        text.to_string()
    } else {
        format!("{text}{}", " ".repeat(cols - w))
    }
}

/// Fit `text` into exactly `cols` monospace columns.
///
/// A Cyrillic string occupies twice the columns its character count suggests, so
/// the count-based `{:<width$}` the file used before would have produced rows that
/// drift out of alignment. Anything too long for the column is cut to the column
/// width and marked with `...`, whose position is itself column-accurate.
fn mono_fit(text: &str, cols: usize) -> String {
    let mut out = String::new();
    let mut used = 0;
    let mut clipped = false;

    for ch in text.chars() {
        let w = if ch.is_ascii() || is_narrow_non_ascii(ch) {
            1
        } else {
            2
        };
        if used + w > cols {
            clipped = true;
            break;
        }
        out.push(ch);
        used += w;
    }

    if !clipped {
        return mono_pad(&out, cols);
    }

    // Room for the marker is taken from the *text*, by dropping characters until
    // the marker fits beside them.
    while used > cols.saturating_sub(3) {
        match out.pop() {
            Some(ch) => {
                used -= if ch.is_ascii() || is_narrow_non_ascii(ch) {
                    1
                } else {
                    2
                }
            }
            None => return ".".repeat(cols),
        }
    }
    format!("{out}...{}", " ".repeat(cols - used - 3))
}

/// The human-readable report: the `.txt` file, and the same text on a plain console.
///
/// Every word this function writes itself is Russian; every value it copies out of
/// [`ScanContext`] is left verbatim. Service names, paths, event IDs, hashes and raw
/// evidence lines are evidence - a translated path cannot be searched on the machine
/// it was collected from, which makes it worthless to the person reading this.
pub fn render_text(host: &HostInfo, ctx: &ScanContext, verdict: &Verdict) -> String {
    let mut out = String::with_capacity(8192);

    out.push_str(RULE_DOUBLE);
    out.push_str(" IRScan - проверка машины только на чтение: поиск скрытого наблюдения\n");
    out.push_str("          и удалённого управления\n");
    out.push_str(RULE_DOUBLE);

    // Machine, user and OS are data: never translated, only placed.
    let dash = "-";
    let _ = writeln!(
        out,
        "{}",
        kv_line(
            "Компьютер",
            if host.name.is_empty() {
                "(не определён)"
            } else {
                &host.name
            }
        )
    );
    let _ = writeln!(
        out,
        "{}",
        kv_line(
            "Пользователь",
            if host.user.is_empty() {
                "(не определён)"
            } else {
                &host.user
            }
        )
    );
    let _ = writeln!(
        out,
        "{}",
        kv_line(
            "Права",
            if host.elevated {
                "администратор (проверено всё)"
            } else {
                "НЕ администратор - часть проверок не выполнена; запустите от имени администратора"
            }
        )
    );
    let _ = writeln!(
        out,
        "{}",
        kv_line(
            "ОС",
            &format!(
                "{}; сборка {}",
                if host.os.is_empty() { dash } else { &host.os },
                if host.build.is_empty() {
                    dash
                } else {
                    &host.build
                }
            )
        )
    );
    let _ = writeln!(
        out,
        "{}",
        kv_line(
            "Установлена",
            &format!(
                "{}     загружена: {}",
                if host.install_date.is_empty() {
                    dash
                } else {
                    &host.install_date
                },
                if host.boot_time.is_empty() {
                    dash
                } else {
                    &host.boot_time
                }
            )
        )
    );
    let _ = writeln!(
        out,
        "{}",
        kv_line(
            "Данные собраны",
            if host.collected_at.is_empty() {
                dash
            } else {
                &host.collected_at
            }
        )
    );
    let _ = writeln!(
        out,
        "{}",
        kv_line(
            "Неполнота",
            &format!(
                "{} {} не выполнено - см. раздел ВНИМАНИЕ ниже",
                ctx.warnings.len(),
                crate::text::plural_ru(ctx.warnings.len(), ("проверка", "проверки", "проверок"))
            )
        )
    );
    out.push('\n');

    out.push_str(RULE_SINGLE);
    out.push_str(" ВЫВОД\n");
    out.push_str(RULE_SINGLE);
    // One row per level, each in a fixed monospace column. `mono_fit` measures in
    // the cells a Windows console font draws, so these columns stay straight for
    // Cyrillic labels, which occupy two cells per character rather than one.
    for (label, count) in [
        ("критично:", verdict.high),
        ("средне:", verdict.med),
        ("информ.:", verdict.info),
    ] {
        let _ = writeln!(
            out,
            "  {}{}  {}",
            mono_fit(label, COLUMN_LEVEL),
            mono_fit(&count.to_string(), COLUMN_COUNT),
            level_meaning(label)
        );
    }
    let _ = writeln!(out, "{}", indent(&verdict.headline, 1));
    out.push('\n');
    out.push_str(" Что делать дальше:\n");
    for (i, line) in verdict.recommendation.iter().enumerate() {
        out.push_str(&hanging(&format!("{}. ", i + 1), line, 2));
    }
    out.push('\n');

    out.push_str(RULE_SINGLE);
    out.push_str(" НАХОДКИ\n");
    out.push_str(RULE_SINGLE);
    let groups = group_findings(ctx);
    if groups.is_empty() {
        out.push_str(" нет\n");
    }
    for g in &groups {
        // An instance count is the difference between "the report says one thing is
        // wrong" and "the report says this kind of thing is systemic here".
        let suffix = if g.instances > 1 {
            format!(
                "   ({} {} этого вида; показано {} из них)",
                g.instances,
                crate::text::plural_ru(g.instances, ("находка", "находки", "находок")),
                g.evidence.len()
            )
        } else {
            String::new()
        };
        let tag = format!("[{}] {}: ", g.severity.tag(), g.category);
        let mut head = wrap(
            &format!("{}{}", g.title.trim_end(), suffix),
            COLUMNS.saturating_sub(tag.chars().count()),
            0,
        )
        .lines()
        .enumerate()
        .map(|(i, l)| {
            if i == 0 {
                format!("{tag}{l}")
            } else {
                format!("{}{l}", " ".repeat(tag.chars().count()))
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
        head.push('\n');
        out.push_str(&head);
        for line in &g.evidence {
            let _ = writeln!(out, "{}", indent(line, 7));
        }
        if !g.remediation.is_empty() {
            out.push_str("       что делать:\n");
            for line in &g.remediation {
                out.push_str(&hanging("- ", line, 9));
            }
        }
        out.push('\n');
    }

    if ctx.warnings.is_empty() {
        // Nothing to report, and an empty section would only add noise.
    } else {
        out.push_str(RULE_SINGLE);
        out.push_str(" ВНИМАНИЕ - эти проверки не выполнились, отчёт неполный\n");
        out.push_str(RULE_SINGLE);
        let mut warnings: Vec<&String> = ctx.warnings.iter().collect();
        warnings.sort();
        for w in warnings {
            out.push_str(&hanging("! ", w, 1));
        }
        out.push('\n');
    }

    out.push_str(RULE_SINGLE);
    out.push_str(" ЧЕГО ЭТОТ ОТЧЁТ НЕ ДОКАЗЫВАЕТ\n");
    out.push_str(RULE_SINGLE);
    for line in [
        " Чистый результат не доказывает, что машина чиста: rootkit в режиме ядра или",
        " переименованный агент без следов в реестре не видны ни одному из опрошенных",
        " интерфейсов пользовательского режима. Все находки - это признаки, за которыми",
        " стоят сырые данные: читайте их, а не только метку критичности.",
    ] {
        let _ = writeln!(out, "{line}");
    }
    let _ = writeln!(out, " В отчёт заведомо не попадает:");
    for line in [
        "   - содержимое памяти процессов и драйверов;",
        "   - сетевой трафик: только установленные соединения, без полезной нагрузки;",
        "   - файлы, недоступные для чтения без прав администратора;",
        "   - всё, что перечислено выше в разделе ВНИМАНИЕ.",
    ] {
        let _ = writeln!(out, "{line}");
    }
    out.push('\n');

    out.push_str(RULE_SINGLE);
    out.push_str(" ЛЕГЕНДА\n");
    out.push_str(RULE_SINGLE);
    for line in [
        " [HIGH] критично        прямые признаки скрытого наблюдения или удалённого",
        "                        управления; проверяйте в первую очередь.",
        " [MED]  средне          требует ручной проверки; по отдельности ничего не",
        "                        доказывает.",
        " [INFO] информационно   контекст и совпадения по имени; вероятность ошибки",
        "                        велика.",
        " ->                     рекомендуемое действие к находке выше.",
        " !                      проверка не выполнилась, отчёт неполный.",
    ] {
        let _ = writeln!(out, "{line}");
    }
    out.push('\n');

    out.push_str(RULE_SINGLE);
    out.push_str(" СЫРЫЕ ДАННЫЕ\n");
    out.push_str(RULE_SINGLE);
    for (section, lines) in &ctx.raw {
        // Section names and every line under them are evidence: left verbatim.
        let _ = writeln!(out, "\n== {section} {}\n", "=".repeat(70));
        for line in lines {
            let _ = writeln!(out, "   {line}");
        }
    }

    out
}

/// Width of the level-label column in the summary, in monospace cells. Wide enough
/// for the longest label ("критично:" is 18 cells).
const COLUMN_LEVEL: usize = 18;
/// Width of the count column that follows it.
const COLUMN_COUNT: usize = 6;

/// One line per severity level, so the summary is readable without the legend: a bare
/// "информ.: 85" tells a reader nothing about what to do with it.
fn level_meaning(label: &str) -> &'static str {
    match label {
        "критично:" => "прямые признаки скрытого наблюдения или удалённого управления",
        "средне:" => "требует ручной проверки; по отдельности ничего не доказывает",
        _ => "контекст и совпадения по имени; вероятность ошибки велика",
    }
}

/// The width this report is laid out to.
///
/// 120 columns is the widest line Notepad opens without wrapping, so prose is
/// wrapped to it and the layout does not reflow depending on who opens the file.
const COLUMNS: usize = 120;

/// Two rules, a heading and a short note fit inside them at 80 columns, which is
/// the narrowest terminal worth reading.
const RULE_DOUBLE: &str =
    "==============================================================================\n";
const RULE_SINGLE: &str =
    "------------------------------------------------------------------------------\n";

/// Indent `text` to `pad` spaces, wrapping it to fit the page.
///
/// The wrap happens here rather than being left for Notepad: a 280-column sentence
/// is the same unreadable smear in every viewer, and the page width is a property of
/// the report, not of whoever opens it.
fn indent(text: &str, pad: usize) -> String {
    wrap(text, COLUMNS.saturating_sub(pad), pad)
}

/// Hard-wrap `text` to `cols` columns, prefixing every line with `pad` spaces.
///
/// Breaks on whitespace only. A word longer than the available width is left whole
/// and overflows rather than being chopped: in this report a "word" is usually a
/// path, a registry key or a hash, and a split path is worse than a wide line,
/// because it can no longer be copied and searched on the machine it came from.
fn wrap(text: &str, cols: usize, pad: usize) -> String {
    let spaces = " ".repeat(pad);
    let mut lines: Vec<String> = Vec::new();
    let mut line = String::new();

    for word in text.split_whitespace() {
        if line.is_empty() {
            line.push_str(word);
        } else if mono_width(&line) + 1 + mono_width(word) <= cols {
            line.push(' ');
            line.push_str(word);
        } else {
            lines.push(std::mem::take(&mut line));
            line.push_str(word);
        }
    }
    if !line.is_empty() {
        lines.push(line);
    }

    lines
        .into_iter()
        .map(|l| format!("{spaces}{l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// A hanging-indent list item: `lead` on the first line, the rest aligned under it.
fn hanging(lead: &str, text: &str, pad: usize) -> String {
    let body = wrap(text, COLUMNS.saturating_sub(pad + lead.chars().count()), 0);
    let mut out = body
        .lines()
        .enumerate()
        .map(|(i, l)| {
            if i == 0 {
                format!("{}{lead}{l}", " ".repeat(pad))
            } else {
                format!("{}{}{l}", " ".repeat(pad), " ".repeat(lead.chars().count()))
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    out.push('\n');
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
    fn text_report_is_russian_shows_the_counts_and_carries_no_raw_escapes() {
        let ctx = ctx_with(&[Severity::High, Severity::Med]);
        let verdict = crate::rules::verdict(&ctx.findings, 0);
        let text = render_text(&host(), &ctx, &verdict);
        assert!(text.contains("критично: 1"));
        assert!(text.contains("PC-01"));
        // The severity tag is the machine-readable part a human greps for.
        assert!(text.contains("[HIGH] cat: finding 0"));
        assert!(!text.contains('\u{1b}'), "an escape sequence survived");
    }

    #[test]
    fn text_report_states_that_a_clean_result_proves_nothing() {
        let ctx = ScanContext::default();
        let text = render_text(&host(), &ctx, &crate::rules::verdict(&[], 0));
        // Prose is wrapped to the page width, so a sentence may straddle two lines.
        let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(flat.contains("НЕ доказывает, что машина чиста"));
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
        assert!(
            text.contains("(4 находки этого вида"),
            "4 takes the paucal form: {text}"
        );

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
        assert!(text.contains("ВНИМАНИЕ"));
        assert!(text.contains("events: access denied"));

        let clean = render_text(
            &host(),
            &ScanContext::default(),
            &crate::rules::verdict(&[], 0),
        );
        assert!(!clean.contains("ВНИМАНИЕ -"));
    }

    #[test]
    fn raw_sections_are_included_in_the_text_report() {
        let mut ctx = ScanContext::default();
        ctx.raw_section("SERVICES", vec!["svc a".into(), "svc b".into()]);
        let text = render_text(&host(), &ctx, &crate::rules::verdict(&[], 0));
        assert!(text.contains("== SERVICES"));
        assert!(text.contains("svc a"));
    }
}
