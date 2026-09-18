//! Which language the window speaks, decided from the real Windows locale.
//!
//! The front end cannot answer this for itself. Tauri's WebView2 reports
//! `navigator.language` as `en-US` regardless of the system locale the user set, so a
//! machine whose `Get-Culture`, `Get-UICulture` and `Get-WinSystemLocale` all say `ru-RU`
//! still rendered the interface in English - reported exactly that way.
//! `GetUserDefaultLocaleName` asks the OS instead of the browser and returns a
//! BCP-47-ish tag such as `ru-RU`.
//!
//! The split here is deliberate and mirrors `ir-recon/src/win`: the raw call moves bytes,
//! and [`language_for`] - the part with a rule in it - is a pure function with a unit
//! test, so the mapping can be checked without Windows.

/// The only language this interface is written in besides English. A machine whose
/// locale is `uk-UA` gets English: the dictionaries are `ru` and `en`, and Ukrainian is
/// not Russian, so claiming it is would be a wrong answer rather than a helpful one.
const RUSSIAN: &str = "ru";

/// Read the user's locale tag, or an empty string when it cannot be read.
///
/// Never fails loudly: a window that cannot name its locale is still a useful window,
/// and the caller falls back to English.
pub fn user_locale() -> String {
    #[cfg(windows)]
    {
        windows_locale()
    }
    #[cfg(not(windows))]
    {
        String::new()
    }
}

/// Map a locale tag to a dictionary name.
///
/// The tag's primary subtag is compared case-insensitively and as a whole: `ru`,
/// `ru-RU`, `RU-ru` and `ru-BY` are all Russian, while `uk-UA`, `en-US` and anything
/// unreadable are English. Only the first subtag counts, so a region code that happens to
/// start with the letters is not mistaken for the language.
pub fn language_for(tag: &str) -> &'static str {
    let primary = tag.split(['-', '_']).next().unwrap_or("");
    if primary.eq_ignore_ascii_case(RUSSIAN) {
        RUSSIAN
    } else {
        "en"
    }
}

/// The user's locale, or `"en"` when it cannot be read. What `app_info` reports.
pub fn language() -> &'static str {
    language_for(&user_locale())
}

/// `GetUserDefaultLocaleName`, with a NUL-terminated buffer sized from
/// `LOCALE_NAME_MAX_LENGTH` - the value Microsoft documents as large enough for any
/// locale name, `-u-` extension forms included.
#[cfg(windows)]
fn windows_locale() -> String {
    use windows_sys::Win32::Globalization::GetUserDefaultLocaleName;
    use windows_sys::Win32::System::SystemServices::LOCALE_NAME_MAX_LENGTH;

    let mut buf = [0u16; LOCALE_NAME_MAX_LENGTH as usize];
    let cap = buf.len() as i32;
    // SAFETY: `buf` is a live, writable, NUL-terminated-capable array of exactly
    // `LOCALE_NAME_MAX_LENGTH` UTF-16 units, and `cap` states that size truthfully, which
    // is what the API requires. It writes at most `cap` units including the terminator,
    // so it cannot write past the end.
    let written = unsafe { GetUserDefaultLocaleName(buf.as_mut_ptr(), cap) };
    if written <= 0 {
        return String::new();
    }

    // The return value counts the terminator, so the name is one unit shorter; clamping
    // to the buffer keeps a buggy or hostile return from reading past the end.
    let len = ((written as usize).saturating_sub(1)).min(buf.len());
    decode_utf16(&buf[..len])
}

/// Decode UTF-16 units, stopping at the first NUL and dropping anything malformed.
///
/// `from_utf16_lossy` rather than `from_utf16`: a locale name with an unpaired surrogate
/// is not worth losing the whole answer over, and a lossy string still maps to the right
/// language or to English, which is the same failure mode as an unreadable one.
#[cfg(windows)]
fn decode_utf16(units: &[u16]) -> String {
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn russian_locales_map_to_russian() {
        assert_eq!(language_for("ru"), "ru");
        assert_eq!(language_for("ru-RU"), "ru");
    }

    #[test]
    fn a_region_code_starting_with_ru_still_maps_to_russian() {
        // The primary subtag is `ru`; the region is Belarus, not a language.
        assert_eq!(language_for("ru-BY"), "ru");
        assert_eq!(language_for("ru_UA"), "ru");
    }

    #[test]
    fn other_languages_map_to_english() {
        assert_eq!(language_for("en-US"), "en");
        // Ukrainian is not Russian, even though the two are close and the machine may
        // well be in the same region.
        assert_eq!(language_for("uk-UA"), "en");
        assert_eq!(language_for("de-DE"), "en");
    }

    #[test]
    fn unreadable_locales_map_to_english() {
        assert_eq!(language_for(""), "en");
        assert_eq!(language_for("   "), "en");
        assert_eq!(language_for("not a locale"), "en");
        assert_eq!(language_for("-RU"), "en");
        assert_eq!(language_for("$$$"), "en");
    }

    /// The defect this module exists for was never in the mapping - it was in the tag
    /// source. WebView2 reports `en-US` through `navigator.language` on a machine whose
    /// every Windows locale is `ru-RU`, so a front end that decides for itself gets
    /// English. This pins the two facts that make that failure impossible here: the
    /// mapping accepts the tag the OS actually returns, and rejects the one the browser
    /// invented.
    #[test]
    fn the_os_tag_is_accepted_where_the_browser_tag_is_not_russian() {
        // What `GetUserDefaultLocaleName` returns on this machine.
        assert_eq!(language_for("ru-RU"), "ru");
        // What WebView2 claimed, and what must NOT be read as Russian.
        assert_eq!(language_for("en-US"), "en");
    }

    #[test]
    fn case_does_not_decide_the_answer() {
        assert_eq!(language_for("RU"), "ru");
        assert_eq!(language_for("RU-ru"), "ru");
        assert_eq!(language_for("En-US"), "en");
    }

    /// The real call, on the machine the test runs on. It must answer *something* usable:
    /// a locale tag that maps to a dictionary, or the empty string that means English.
    #[test]
    fn the_local_machine_answers_with_a_mappable_language() {
        let tag = user_locale();
        assert!(
            tag.is_empty() || tag.starts_with(|c: char| c.is_ascii_alphabetic()),
            "implausible locale tag: {tag:?}"
        );
        assert!(matches!(language(), "ru" | "en"));
    }
}
