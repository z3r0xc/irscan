//! Console presentation layer.
//!
//! Separated from `report` on purpose. `report` produces the evidence file: plain,
//! grep-able, diff-able, stable. This module produces the terminal view: styled,
//! wrapped to the terminal width, and pleasant to read while you are sitting in front
//! of a machine that may be hostile.
//!
//! Two rules shape every decision here:
//!
//! 1. **Monochrome by design.** The palette is black, grey and white only. Severity is
//!    therefore carried by typography and glyphs, never by hue alone: a report that
//!    only distinguishes "bad" from "worse" by colour is unreadable in a log, on a
//!    projector, or to a colour-blind reader. `--severity-colour` opts into a single
//!    red accent for HIGH, and nothing else.
//! 2. **Nothing styled leaks into the file.** Everything here can be switched off
//!    (`--plain`, `NO_COLOR`, a non-TTY stdout), and `strip_ansi` proves it.

use std::fmt::Write as _;

use crate::model::{ScanContext, Severity, Verdict};
use crate::report::{group_findings, Grouped, HostInfo};

/// Default report width when the terminal does not tell us one.
pub const DEFAULT_WIDTH: usize = 96;
/// Narrowest width worth rendering; below this the layout would wrap into porridge.
pub const MIN_WIDTH: usize = 56;

/// Grey ramp, lightest to darkest. Truecolor values, all three channels equal, which
/// is what makes the palette read as black/grey/white on any terminal.
const G_WHITE: u8 = 255;
const G_BRIGHT: u8 = 250;
const G_LIGHT: u8 = 246;
const G_MID: u8 = 242;
const G_DIM: u8 = 238;
const G_FAINT: u8 = 235;

const RESET: &str = "\u{1b}[0m";

/// How the console view should be drawn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Style {
    /// Emit ANSI sequences at all.
    pub colour: bool,
    /// Draw with box-drawing characters rather than ASCII fallbacks.
    pub unicode: bool,
    /// Wrap everything to this many columns.
    pub width: usize,
    /// Tint HIGH findings red. Off by default: the palette is monochrome.
    pub severity_colour: bool,
}

impl Default for Style {
    fn default() -> Self {
        Style {
            colour: true,
            unicode: true,
            width: DEFAULT_WIDTH,
            severity_colour: false,
        }
    }
}

impl Style {
    /// Everything off: what a file or a pipe gets.
    pub fn plain() -> Self {
        Style {
            colour: false,
            unicode: false,
            ..Style::default()
        }
    }

    fn paint(&self, grey: u8, text: &str) -> String {
        if self.colour {
            format!("\u{1b}[38;2;{grey};{grey};{grey}m{text}{RESET}")
        } else {
            text.to_string()
        }
    }

    fn bold_paint(&self, grey: u8, text: &str) -> String {
        if self.colour {
            format!("\u{1b}[1;38;2;{grey};{grey};{grey}m{text}{RESET}")
        } else {
            text.to_string()
        }
    }

    pub fn white(&self, text: &str) -> String {
        self.bold_paint(G_WHITE, text)
    }

    pub fn bright(&self, text: &str) -> String {
        self.paint(G_BRIGHT, text)
    }

    pub fn light(&self, text: &str) -> String {
        self.paint(G_LIGHT, text)
    }

    pub fn mid(&self, text: &str) -> String {
        self.paint(G_MID, text)
    }

    pub fn dim(&self, text: &str) -> String {
        self.paint(G_DIM, text)
    }

    pub fn faint(&self, text: &str) -> String {
        self.paint(G_FAINT, text)
    }

    /// The red accent, used only for HIGH when explicitly asked for.
    fn accent(&self, text: &str) -> String {
        if self.colour && self.severity_colour {
            format!("\u{1b}[1;38;2;235;90;80m{text}{RESET}")
        } else {
            self.bold_paint(G_WHITE, text)
        }
    }

    fn glyph(&self, unicode: char, ascii: char) -> char {
        if self.unicode {
            unicode
        } else {
            ascii
        }
    }

    fn rr(&self, ch: char, ascii: char, count: usize) -> String {
        let c = self.glyph(ch, ascii);
        std::iter::repeat_n(c, count).collect()
    }

    /// A full-width horizontal rule.
    pub fn rule(&self) -> String {
        self.faint(&self.rr('─', '-', self.width.saturating_sub(4)))
    }

    /// A section heading: a numbered overline plus the title, in small-caps spirit.
    pub fn heading(&self, title: &str) -> String {
        let label = format!(" {} ", title.to_uppercase());
        let used = 4 + label.chars().count();
        let tail = self.width.saturating_sub(used + 4);
        format!(
            "  {}{}{}",
            self.faint(&self.rr('─', '-', 2)),
            self.white(&label),
            self.faint(&self.rr('─', '-', tail))
        )
    }

    /// Severity marker. Filled / half / hollow reads the same in monochrome as it
    /// does in colour, which is the whole point.
    pub fn severity_marker(&self, severity: Severity) -> String {
        match severity {
            Severity::High => self.accent(&self.glyph('●', '#').to_string()),
            Severity::Med => self.bright(&self.glyph('◐', '*').to_string()),
            Severity::Info => self.faint(&self.glyph('○', '-').to_string()),
        }
    }

    /// The `[ HIGH ]` chip, padded so chips line up in a column.
    pub fn severity_chip(&self, severity: Severity) -> String {
        let text = format!("[ {} ]", severity.tag());
        match severity {
            Severity::High => self.accent(&text),
            Severity::Med => self.bright(&text),
            Severity::Info => self.mid(&text),
        }
    }
}

/// Word-wrap `text` to `width` columns, returning the lines.
///
/// Deliberately simple: break on whitespace, and break a single word that is longer
/// than the line rather than letting it overflow. No hyphenation - a mangled word in
/// an evidence line is worse than an ugly break.
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(8);
    let mut lines: Vec<String> = Vec::new();
    let mut current = String::new();

    for word in text.split_whitespace() {
        let word_len = word.chars().count();
        if current.is_empty() {
            if word_len <= width {
                current.push_str(word);
                continue;
            }
            // A single word past the width: chop it into width-sized pieces.
            let mut chunk = String::new();
            for ch in word.chars() {
                chunk.push(ch);
                if chunk.chars().count() == width {
                    lines.push(std::mem::take(&mut chunk));
                }
            }
            current = chunk;
            continue;
        }

        if current.chars().count() + 1 + word_len <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
        }
    }

    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

/// Lay text out with a gutter, wrapped to the content width.
fn gutter(style: &Style, text: &str, inner_width: usize, bar: &str, indent: usize) -> Vec<String> {
    let pad = " ".repeat(indent);
    let content = inner_width.saturating_sub(indent + bar.chars().count() + 1);
    wrap(text, content)
        .into_iter()
        .map(|line| format!("{pad}{} {line}", style.faint(bar)))
        .collect()
}

/// Remove every ANSI escape sequence. Used by tests and by `--plain` verification.
pub fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                // Consume parameter bytes then the final byte.
                for c in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&c) {
                        break;
                    }
                }
                continue;
            }
            continue;
        }
        out.push(ch);
    }
    out
}

/// Should the console be styled?
///
/// `NO_COLOR` (any non-empty value) wins over everything except an explicit request,
/// which matches the convention at <https://no-color.org>. A non-TTY stdout is never
/// styled, so redirecting to a file cannot produce a file full of escape codes.
pub fn should_style(stdout_is_tty: bool, no_color: bool, force: bool) -> bool {
    if force {
        return true;
    }
    if no_color {
        return false;
    }
    stdout_is_tty
}

/// Terminal width from the environment, clamped to something readable.
pub fn width_from_env(columns: Option<&str>) -> usize {
    match columns.and_then(|c| c.trim().parse::<usize>().ok()) {
        Some(w) if w >= MIN_WIDTH => w.min(200),
        _ => DEFAULT_WIDTH,
    }
}

/// Render the styled console view.
pub fn render_console(
    style: &Style,
    host: &HostInfo,
    ctx: &ScanContext,
    verdict: &Verdict,
) -> String {
    let mut out = String::with_capacity(16 * 1024);
    let key_width = 11;

    // ---- masthead -------------------------------------------------------
    let version = env!("CARGO_PKG_VERSION");
    let title = style.white("IRSCAN");
    let gap = style.width.saturating_sub(4 + 6 + 2 + version.len() + 2);
    let _ = writeln!(
        out,
        "  {title}{}{}",
        " ".repeat(gap.max(1)),
        style.faint(&format!("v{version}"))
    );
    let _ = writeln!(
        out,
        "  {}",
        style.dim("проверка только на чтение: скрытое наблюдение и удалённое управление")
    );
    let _ = writeln!(out, "{}", style.rule());
    out.push('\n');

    // ---- host -----------------------------------------------------------
    let mut kv = |key: &str, value: String| {
        let _ = writeln!(
            out,
            "  {}{} {}",
            style.faint(&format!("{key:<key_width$}")),
            style.faint(&style.glyph('│', '|').to_string()),
            value
        );
    };
    let who = if host.user.is_empty() {
        host.name.clone()
    } else {
        format!("{}  {}", host.name, style.faint("·"))
            .replace(&style.faint("·"), &style.faint("·").to_string())
            + &format!(" {}", host.user)
    };
    kv("ХОСТ", style.light(&who));
    kv(
        "СИСТЕМА",
        style.light(&format!("{}  сборка {}", host.os, host.build)),
    );
    let elevation = if host.elevated {
        style.light("да - проверено всё")
    } else {
        style.bright("НЕТ - часть проверок пропущена; запустите от администратора")
    };
    kv("ПРАВА", elevation);
    kv(
        "СОБРАНО",
        style.mid(&format!(
            "{}  {}  загрузка {}",
            host.collected_at,
            style.glyph('·', '-'),
            host.boot_time
        )),
    );
    out.push('\n');

    // ---- verdict --------------------------------------------------------
    let _ = writeln!(out, "{}", style.heading("вывод"));
    out.push('\n');
    let counts = format!(
        "  {:<10}{:<10}{}",
        style.accent(&format!("{} крит.", verdict.high)),
        style.bright(&format!("{} средн.", verdict.med)),
        style.mid(&format!("{} инф.", verdict.info)),
    );
    let _ = writeln!(out, "{counts}");
    out.push('\n');
    for line in gutter(
        style,
        &verdict.headline,
        style.width,
        &style.glyph('▎', '|').to_string(),
        2,
    ) {
        let _ = writeln!(out, "{line}");
    }
    out.push('\n');
    for (i, line) in verdict.recommendation.iter().enumerate() {
        let first = format!("{} {}", style.faint(&format!("{}.", i + 1)), line);
        let mut lines = wrap(&first, style.width.saturating_sub(8));
        let head = lines.first().cloned().unwrap_or_default();
        let _ = writeln!(out, "  {head}");
        lines.remove(0);
        for extra in lines {
            let _ = writeln!(out, "     {extra}");
        }
    }
    out.push('\n');

    // ---- findings -------------------------------------------------------
    let groups = group_findings(ctx);
    let _ = writeln!(out, "{}", style.heading("находки"));
    out.push('\n');
    if groups.is_empty() {
        let _ = writeln!(
            out,
            "  {}",
            style.dim("нет - и это не то же самое, что чисто; см. примечание ниже")
        );
        out.push('\n');
    }
    for g in &groups {
        let _ = writeln!(out, "{}", render_group(style, g));
    }

    // ---- warnings -------------------------------------------------------
    if !ctx.warnings.is_empty() {
        let _ = writeln!(out, "{}", style.heading("внимание"));
        out.push('\n');
        let mut warnings: Vec<&String> = ctx.warnings.iter().collect();
        warnings.sort();
        for w in warnings {
            for line in gutter(style, w, style.width, &style.glyph('│', '|').to_string(), 2) {
                let _ = writeln!(out, "{line}");
            }
        }
        let _ = writeln!(
            out,
            "\n  {}",
            style.dim("Предупреждение означает, что проверка не выполнилась. Отчёт неполный.")
        );
        out.push('\n');
    }

    // ---- footer ---------------------------------------------------------
    let _ = writeln!(out, "{}", style.rule());
    let _ = writeln!(
        out,
        "  {}",
        style.dim("Чистый результат не доказывает, что машина чиста: rootkit в режиме ядра или")
    );
    let _ = writeln!(
        out,
        "  {}",
        style.dim("переименованный агент без следов в реестре не видны ни одной проверке выше.")
    );
    let _ = writeln!(out, "{}", style.rule());

    out
}

fn render_group(style: &Style, g: &Grouped) -> String {
    let mut out = String::with_capacity(512);

    let suffix = if g.instances > 1 {
        format!(
            "  {}",
            style.dim(&format!("{} находок этого вида", g.instances))
        )
    } else {
        String::new()
    };
    let _ = writeln!(
        out,
        "  {} {}  {}{}",
        style.severity_marker(g.severity),
        style.severity_chip(g.severity),
        style.light(&g.title),
        suffix
    );
    let _ = writeln!(out, "     {}", style.mid(&g.category.to_uppercase()));

    for line in &g.evidence {
        for rendered in gutter(
            style,
            line,
            style.width,
            &style.glyph('│', '|').to_string(),
            5,
        ) {
            let _ = writeln!(out, "{rendered}");
        }
    }
    for line in &g.remediation {
        let arrow = format!(
            "{} {}",
            style.faint(&style.glyph('→', '>').to_string()),
            line
        );
        let mut lines = wrap(&arrow, style.width.saturating_sub(8));
        let head = lines.first().cloned().unwrap_or_default();
        let _ = writeln!(out, "     {head}");
        lines.remove(0);
        for extra in lines {
            let _ = writeln!(out, "       {extra}");
        }
    }
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Finding;

    fn styled() -> Style {
        Style {
            colour: true,
            unicode: true,
            width: 80,
            severity_colour: false,
        }
    }

    #[test]
    fn wrap_breaks_on_words_and_respects_the_width() {
        let lines = wrap("alpha beta gamma delta", 11);
        assert_eq!(lines, vec!["alpha beta", "gamma delta"]);
        assert!(lines.iter().all(|l| l.chars().count() <= 11));
    }

    #[test]
    fn wrap_chops_a_word_longer_than_the_line_instead_of_overflowing() {
        let lines = wrap("abcdefghijklmnop", 8);
        assert!(lines.iter().all(|l| l.chars().count() <= 8));
        assert_eq!(lines.concat(), "abcdefghijklmnop");
    }

    #[test]
    fn wrap_never_loses_text() {
        let text = "one two three four five six seven eight nine ten";
        let joined = wrap(text, 12).join(" ");
        assert_eq!(joined, text);
    }

    #[test]
    fn wrap_of_an_empty_string_yields_one_empty_line() {
        assert_eq!(wrap("", 20), vec![String::new()]);
    }

    #[test]
    fn plain_style_emits_no_escape_sequences_at_all() {
        let style = Style::plain();
        let rendered = format!(
            "{}{}{}{}",
            style.white("w"),
            style.dim("d"),
            style.rule(),
            style.severity_chip(Severity::High)
        );
        assert!(!rendered.contains('\u{1b}'));
        assert_eq!(strip_ansi(&rendered), rendered);
    }

    #[test]
    fn styled_output_strips_back_to_the_same_characters() {
        let coloured = styled().severity_chip(Severity::High);
        assert!(coloured.contains('\u{1b}'), "chip should be styled");
        assert!(strip_ansi(&coloured).contains("[ HIGH ]"));
    }

    #[test]
    fn ascii_fallbacks_keep_the_layout_rectangular() {
        // Plain style on purpose: this test is about which character is chosen, not
        // about colour, and a styled marker would carry escape sequences.
        let style = Style {
            colour: false,
            unicode: false,
            width: 80,
            severity_colour: false,
        };
        assert_eq!(style.severity_marker(Severity::High), "#");
        assert_eq!(style.severity_marker(Severity::Med), "*");
        assert_eq!(style.severity_marker(Severity::Info), "-");
        assert_eq!(style.rr('─', '-', 3), "---");
    }

    #[test]
    fn severity_markers_are_distinct_without_colour() {
        // The accessibility requirement: in a monochrome terminal the three levels
        // must still be tellable apart.
        let style = Style::plain();
        let high = style.severity_marker(Severity::High);
        let med = style.severity_marker(Severity::Med);
        let info = style.severity_marker(Severity::Info);
        assert!(!(high == med));
        assert!(!(med == info));
        assert!(!(high == info));
    }

    #[test]
    fn style_decisions_follow_the_no_color_convention() {
        assert!(should_style(true, false, false));
        assert!(!should_style(false, false, false), "a pipe is never styled");
        assert!(!should_style(true, true, false), "NO_COLOR wins");
        assert!(should_style(false, true, true), "--style forces it");
    }

    #[test]
    fn width_parsing_clamps_and_falls_back() {
        assert_eq!(width_from_env(None), DEFAULT_WIDTH);
        assert_eq!(width_from_env(Some("nonsense")), DEFAULT_WIDTH);
        assert_eq!(
            width_from_env(Some("20")),
            DEFAULT_WIDTH,
            "too narrow to use"
        );
        assert_eq!(width_from_env(Some("120")), 120);
        assert_eq!(width_from_env(Some("4000")), 200, "clamped for readability");
    }

    #[test]
    fn strip_ansi_leaves_plain_text_untouched() {
        assert_eq!(strip_ansi("no escapes here"), "no escapes here");
        assert_eq!(strip_ansi("\u{1b}[1;38;2;255;255;255mhi\u{1b}[0m"), "hi");
    }

    #[test]
    fn console_view_renders_every_section_and_stays_within_the_width() {
        let mut ctx = ScanContext::default();
        ctx.add(
            Finding::new(Severity::High, "signature", "product detected")
                .evidence("process 'agent.exe' matched process name")
                .remediation("Identify the product before deleting anything."),
        );
        ctx.warn("events: access denied");
        let host = HostInfo {
            name: "PC-01".into(),
            user: "bob".into(),
            os: "Windows 10 Pro".into(),
            build: "19045".into(),
            install_date: "2026-01-01 00:00:00".into(),
            elevated: false,
            collected_at: "2026-09-11 12:00:00".into(),
            boot_time: "2026-09-11 09:00:00".into(),
        };
        let verdict = crate::rules::verdict(&ctx.findings, ctx.warnings.len());
        let style = styled();
        let view = render_console(&style, &host, &ctx, &verdict);

        for needle in [
            "IRSCAN",
            "ХОСТ",
            "ВЫВОД",
            "НАХОДКИ",
            "ВНИМАНИЕ",
            "не доказывает, что машина чиста",
            "Предупреждение означает",
        ] {
            assert!(view.contains(needle), "missing {needle}");
        }
        assert!(view.contains("[ HIGH ]"));
        assert!(view.contains("1 крит."), "the counts row is Russian");
        // The file must never receive this; but if a user redirects, the escape codes
        // must not be able to exceed the declared width in a way that breaks a paste.
        let plain = strip_ansi(&view);
        assert!(plain.lines().all(|l| l.chars().count() <= style.width + 2));
    }

    #[test]
    fn console_view_says_none_without_claiming_cleanliness() {
        let ctx = ScanContext::default();
        let host = HostInfo::default();
        let verdict = crate::rules::verdict(&[], 0);
        let view = render_console(&Style::plain(), &host, &ctx, &verdict);
        assert!(view.contains("нет - и это не то же самое, что чисто"));
    }
}
