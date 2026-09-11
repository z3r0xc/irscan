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
}
