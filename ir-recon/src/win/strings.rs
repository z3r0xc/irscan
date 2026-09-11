//! UTF-16 <-> Rust string conversion.
//!
//! Every string Win32 hands back is treated as hostile input: conversions are
//! lossy (never panicking on malformed UTF-16), NUL-trimmed, and never assume the
//! buffer is well formed.

use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};

/// Encode a Rust string as a NUL-terminated UTF-16 buffer for a `*W` API.
pub fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Decode a NUL-terminated UTF-16 buffer returned by Win32.
pub fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
    OsString::from_wide(&buf[..end])
        .to_string_lossy()
        .into_owned()
}

/// Decode an explicitly sized UTF-16 buffer.
///
/// Some APIs return a character count instead of a NUL terminator; using the
/// reported length avoids reading stale bytes left in the buffer.
pub fn from_wide_len(buf: &[u16], len_chars: usize) -> String {
    let end = len_chars.min(buf.len());
    // The reported length may include the terminator, or the buffer may hold stale
    // bytes past it; either way the first NUL ends the string.
    let end = buf[..end].iter().position(|c| *c == 0).unwrap_or(end);
    OsString::from_wide(&buf[..end])
        .to_string_lossy()
        .into_owned()
}

/// Decode a little-endian UTF-16 byte buffer, as returned by the registry.
///
/// An odd trailing byte is ignored rather than treated as an error: the value has
/// already been read, and refusing the whole report would lose more than it saves.
pub fn from_utf16_bytes(buf: &[u8]) -> String {
    from_wide(&utf16_units(buf))
}

/// Decode an entire UTF-16 byte buffer WITHOUT treating the first NUL as the end.
///
/// Required for `REG_MULTI_SZ`, whose elements are NUL-separated: stopping at the
/// first terminator would silently drop every element after the first, so a key
/// such as `UpperFilters` would look like it had exactly one driver.
pub fn from_utf16_bytes_all(buf: &[u8]) -> String {
    OsString::from_wide(&utf16_units(buf))
        .to_string_lossy()
        .into_owned()
}

fn utf16_units(buf: &[u8]) -> Vec<u16> {
    let mut units: Vec<u16> = Vec::with_capacity(buf.len() / 2);
    for chunk in buf.chunks_exact(2) {
        units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    units
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_adds_exactly_one_terminator() {
        let w = wide("ab");
        assert_eq!(w, vec![0x61, 0x62, 0x00]);
    }

    #[test]
    fn round_trip_ascii_and_non_ascii() {
        for s in ["", "C:\\Program Files\\x.exe", "Стахановец"] {
            assert_eq!(from_wide(&wide(s)), s);
        }
    }

    #[test]
    fn from_wide_stops_at_the_first_nul() {
        let buf = vec![0x61, 0x00, 0x62, 0x00, 0x63, 0x00];
        assert_eq!(from_wide(&buf), "a");
    }

    #[test]
    fn from_wide_len_uses_the_reported_length() {
        let buf = vec![0x61, 0x62, 0x63, 0x00];
        assert_eq!(from_wide_len(&buf, 2), "ab");
        // A length larger than the buffer must clamp, not panic.
        assert_eq!(from_wide_len(&buf, 99), "abc");
    }

    #[test]
    fn malformed_utf16_does_not_panic() {
        // Lone high surrogate: must become the replacement character.
        let buf = vec![0xD800, 0x00];
        let out = from_wide(&buf);
        assert!(!out.is_empty());
        assert!(out.contains('\u{fffd}'));
    }

    #[test]
    fn utf16_bytes_decode_little_endian() {
        // "Hi" -> 0x48 0x00 0x69 0x00
        let bytes = [0x48u8, 0x00, 0x69, 0x00];
        assert_eq!(from_utf16_bytes(&bytes), "Hi");
    }

    #[test]
    fn utf16_bytes_ignore_a_trailing_odd_byte() {
        let bytes = [0x48u8, 0x00, 0x69];
        assert_eq!(from_utf16_bytes(&bytes), "H");
    }

    #[test]
    fn from_utf16_bytes_all_keeps_elements_after_the_first_nul() {
        // "a\0b\0" - the shape of REG_MULTI_SZ. The NUL-terminating variant returns
        // only "a", which is exactly the bug this function exists to avoid.
        let bytes = [0x61, 0, 0x00, 0x00, 0x62, 0, 0x00, 0x00];
        assert_eq!(from_utf16_bytes(&bytes), "a");
        assert_eq!(from_utf16_bytes_all(&bytes), "a\u{0}b\u{0}");
    }
}
