//! Pure text handling. Everything that touches a string from the host under test
//! passes through here first: collect, then sanitise, then report.
//!
//! Threat model for this module: a hostile program on the analysed host controls
//! registry values, service paths, task names and file names. Those strings can
//! contain ANSI escape sequences (terminal hijack, log forgery, OSC hyperlink
//! smuggling), bidirectional overrides (filename spoofing), control characters,
//! NULs and unbounded length.

/// Maximum length accepted by `sanitize` unless a caller asks for less.
pub const DEFAULT_MAX: usize = 512;

/// Make an untrusted string safe to print, log and store.
///
/// - removes complete ANSI/VT escape sequences, not just the ESC byte, so no
///   residue such as `[31m` reaches the report
/// - drops remaining control characters and DEL
/// - drops zero-width and bidirectional-override characters
/// - collapses runs of whitespace and trims
/// - truncates on a UTF-8 character boundary, never mid-character
pub fn sanitize(input: &str, max: usize) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len().min(max * 4));
    let mut last_was_space = false;
    let mut count = 0usize;
    let mut i = 0usize;

    while i < chars.len() && count < max {
        let ch = chars[i];

        if ch == ESC {
            i = skip_escape(&chars, i);
            continue;
        }

        if is_blocked(ch) {
            // A control character that separates words becomes a single space;
            // everything else simply disappears.
            if ch.is_whitespace() && !last_was_space && !out.is_empty() {
                out.push(' ');
                last_was_space = true;
                count += 1;
            }
            i += 1;
            continue;
        }

        if ch.is_whitespace() {
            if !last_was_space && !out.is_empty() {
                out.push(' ');
                last_was_space = true;
                count += 1;
            }
        } else {
            out.push(ch);
            last_was_space = false;
            count += 1;
        }
        i += 1;
    }

    while out.ends_with(' ') {
        out.pop();
    }
    out
}

const ESC: char = '\u{1b}';

/// Characters with no legitimate place in an evidence string: C0/C1 controls,
/// DEL, and the Unicode formatting block (bidi overrides, zero-width joiners).
fn is_blocked(ch: char) -> bool {
    ch.is_control()
        || ch == '\u{7f}'
        || matches!(ch,
            '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{feff}')
}

/// Consume one escape sequence starting at `esc_at` (which must hold ESC) and
/// return the index just past it.
///
/// Handles CSI (`ESC [ ... <final byte>`), OSC (`ESC ] ... BEL | ESC \`) and the
/// single-character two-byte forms. An unterminated sequence swallows the rest of
/// the string, which is the safe direction: better to lose trailing text than to
/// emit a live escape.
fn skip_escape(chars: &[char], esc_at: usize) -> usize {
    let mut i = esc_at + 1;
    if i >= chars.len() {
        return i;
    }
    match chars[i] {
        '[' => {
            i += 1;
            while i < chars.len() {
                let code = chars[i] as u32;
                i += 1;
                if (0x40..=0x7e).contains(&code) {
                    break;
                }
            }
            i
        }
        ']' => {
            i += 1;
            while i < chars.len() {
                if chars[i] == '\u{7}' {
                    i += 1;
                    break;
                }
                if chars[i] == ESC {
                    i += 1;
                    if i < chars.len() && chars[i] == '\\' {
                        i += 1;
                    }
                    break;
                }
                i += 1;
            }
            i
        }
        _ => i + 1,
    }
}

/// Truncate to `max` characters, never splitting a UTF-8 character.
pub fn truncate(input: &str, max: usize) -> String {
    if input.chars().count() <= max {
        return input.to_string();
    }
    let mut out: String = input.chars().take(max).collect();
    out.push_str("...");
    out
}

/// Last path component, tolerating both separators and quoted registry values.
pub fn basename(path: &str) -> &str {
    let trimmed = path.trim().trim_matches('"').trim();
    match trimmed.rsplit(['\\', '/']).next() {
        Some(name) => name,
        None => trimmed,
    }
}

/// Strip surrounding quotes from a registry value that holds a command line.
/// The Russian form of a noun for a count.
///
/// Russian selects between three forms, and the selection is not simply "one or many":
///
/// * **singular** for 1, 21, 31 and every number ending in 1 except 11;
/// * **paucal** for 2-4, 22-24 and every number ending in 2, 3 or 4 except the teens;
/// * **genitive plural** for everything else, *including 0 and 11-14*.
///
/// The teens are the case that reads as broken when missed: 11, 12, 13 and 14 end in the
/// digits that would otherwise select the singular or paucal, and take the genitive
/// plural instead.
///
/// `forms` is `(one, few, many)` - `("находка", "находки", "находок")`.
pub fn plural_ru<'a>(count: usize, forms: (&'a str, &'a str, &'a str)) -> &'a str {
    let (one, few, many) = forms;
    let hundreds = count % 100;
    // 11..=14 take the genitive plural whatever their last digit says.
    if (11..=14).contains(&hundreds) {
        return many;
    }
    match count % 10 {
        1 => one,
        2..=4 => few,
        _ => many,
    }
}

pub fn unquote(value: &str) -> &str {
    value.trim().trim_matches('"').trim()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_ansi_escape_sequences() {
        // The classic terminal-hijack payload: colour codes and a cursor move.
        let hostile = "\u{1b}[31mred\u{1b}[0m agent\u{1b}[2J.exe";
        assert_eq!(sanitize(hostile, 64), "red agent.exe");
    }

    #[test]
    fn strips_osc_hyperlink_sequences() {
        // OSC 8 hyperlink: the visible text says one thing, the target is another.
        let hostile = "\u{1b}]8;;http://evil.example\u{7}click me\u{1b}]8;;\u{7}";
        assert_eq!(sanitize(hostile, 64), "click me");
        // Terminated with ST (ESC \) instead of BEL must work too.
        assert_eq!(sanitize("\u{1b}]8;;http://evil\u{1b}\\ok", 64), "ok");
    }

    #[test]
    fn unterminated_escape_does_not_leak() {
        assert_eq!(sanitize("safe\u{1b}[31", 64), "safe");
    }

    #[test]
    fn strips_control_and_bidi_characters() {
        // RTL override makes "gpj.exe" render as "exe.jpg" in some terminals.
        let hostile = "gpj\u{202e}exe\u{0}\u{7}";
        assert_eq!(sanitize(hostile, 64), "gpjexe");
    }

    #[test]
    fn collapses_whitespace_and_trims() {
        assert_eq!(sanitize("  a\t\tb \r\n c  ", 64), "a b c");
    }

    #[test]
    fn truncates_on_char_boundary() {
        // Cyrillic is 2 bytes per character in UTF-8; a byte-wise cut would panic.
        let s = "Стахановец-агент-служба";
        let out = truncate(s, 5);
        assert_eq!(out, "Стаха...");
        assert!(out.is_char_boundary(out.len()));
    }

    #[test]
    fn respects_max_length() {
        let out = sanitize(&"x".repeat(1000), 10);
        assert_eq!(out.chars().count(), 10);
    }

    #[test]
    fn basename_handles_quotes_and_both_separators() {
        assert_eq!(
            basename("\"C:\\Program Files\\Acme\\agent.exe\""),
            "agent.exe"
        );
        assert_eq!(basename("C:/Windows/Temp/x.exe"), "x.exe");
        assert_eq!(basename(""), "");
    }

    #[test]
    fn unquote_trims_quotes_and_space() {
        assert_eq!(unquote("  \"C:\\a b\\c.exe\"  "), "C:\\a b\\c.exe");
    }

    #[test]
    fn empty_input_stays_empty() {
        assert_eq!(sanitize("", 64), "");
        assert_eq!(sanitize("\u{1b}[0m", 64), "");
    }

    /// Russian counts need three forms, not two.
    ///
    /// The report said "1 находок" and "3 проверок не выполнено". Both read as broken
    /// Russian to the one person this tool is written for, and it is the first line of
    /// the report - a reader who sees the tool misuse their language has a reason to
    /// doubt its findings, which is the opposite of what the report is for.
    ///
    /// The rule is the standard one: 1, and any number ending in 1 except 11, take the
    /// singular; 2-4 (except 12-14) take the paucal; everything else the genitive plural.
    /// 11-14 are the exception that catches people out, so they are tested explicitly.
    #[test]
    fn russian_plural_picks_the_form_the_language_requires() {
        let forms = ("находка", "находки", "находок");
        let pick = |n| plural_ru(n, forms);

        // Singular.
        assert_eq!(pick(1), "находка");
        assert_eq!(pick(21), "находка");
        assert_eq!(pick(101), "находка");

        // Paucal.
        assert_eq!(pick(2), "находки");
        assert_eq!(pick(3), "находки");
        assert_eq!(pick(4), "находки");
        assert_eq!(pick(22), "находки");
        assert_eq!(pick(103), "находки");

        // Genitive plural.
        assert_eq!(pick(0), "находок");
        assert_eq!(pick(5), "находок");
        assert_eq!(pick(37), "находок");
        assert_eq!(pick(100), "находок");

        // The teens are the trap: they end in 1, 2, 3, 4 but take the genitive plural.
        assert_eq!(pick(11), "находок");
        assert_eq!(pick(12), "находок");
        assert_eq!(pick(13), "находок");
        assert_eq!(pick(14), "находок");
        assert_eq!(pick(111), "находок");
        assert_eq!(pick(112), "находок");
    }

    /// The same rule applied to a different noun, so the helper is not specialised to
    /// one word by accident.
    #[test]
    fn russian_plural_works_for_any_noun() {
        let forms = ("проверка", "проверки", "проверок");
        assert_eq!(plural_ru(1, forms), "проверка");
        assert_eq!(plural_ru(3, forms), "проверки");
        assert_eq!(plural_ru(0, forms), "проверок");
        assert_eq!(plural_ru(11, forms), "проверок");
        assert_eq!(plural_ru(21, forms), "проверка");
    }

    /// A negative count cannot happen, but the helper must not panic if one arrives.
    #[test]
    fn russian_plural_handles_absurd_input_without_panicking() {
        let forms = ("а", "б", "в");
        assert_eq!(plural_ru(0, forms), "в");
        // usize cannot be negative; the guard is for the zero path, which is the one a
        // counter actually reaches when a check has not run yet.
    }
}
