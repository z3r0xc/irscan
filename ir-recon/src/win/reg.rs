//! Read-only registry access.
//!
//! Only reads: no key is ever created, written or deleted. Two implementation rules
//! from docs/architecture.md section 6 apply here:
//!
//! * size-then-allocate - the required buffer size is asked for, then allocated;
//!   a second call handles the race where the value grew in between;
//! * bounded - a value larger than `MAX_REG_BYTES` is refused rather than loaded,
//!   and enumerations stop at `MAX_ENUM` entries.

use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW, RegQueryValueExW, HKEY,
    HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ, REG_DWORD,
    REG_EXPAND_SZ, REG_MULTI_SZ, REG_QWORD, REG_SZ,
};

use super::strings::{from_utf16_bytes, from_utf16_bytes_all, from_wide, from_wide_len, wide};

/// Upper bound on a single registry value (1 MiB). Values that large are already
/// pathological; refusing them keeps memory use bounded on a hostile host.
pub const MAX_REG_BYTES: u32 = 1024 * 1024;

/// Upper bound on entries returned by one enumeration.
pub const MAX_ENUM: usize = 4096;

/// Registry root key. A closed enum, so a caller cannot pass an arbitrary handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootKey {
    Hklm,
    Hkcu,
    Hkcr,
    Hku,
}

fn root_handle(root: RootKey) -> HKEY {
    match root {
        RootKey::Hklm => HKEY_LOCAL_MACHINE,
        RootKey::Hkcu => HKEY_CURRENT_USER,
        RootKey::Hkcr => HKEY_CLASSES_ROOT,
        RootKey::Hku => HKEY_USERS,
    }
}

/// RAII guard for an opened subkey.
pub struct OwnedRegKey(HKEY);

impl OwnedRegKey {
    pub fn raw(&self) -> HKEY {
        self.0
    }
}

impl Drop for OwnedRegKey {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful `RegOpenKeyExW` and is owned
        // exclusively by this guard.
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}

/// A registry value, decoded into the shapes this tool reasons about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegValue {
    /// `REG_SZ`
    Str(String),
    /// `REG_EXPAND_SZ`: the caller decides whether to expand `%VAR%`.
    ExpandStr(String),
    /// `REG_MULTI_SZ`
    MultiStr(Vec<String>),
    /// `REG_DWORD` and `REG_QWORD` share one arm: both are small integers.
    Dword(u64),
    /// Any other type; the raw bytes are deliberately not retained.
    Other,
}

impl RegValue {
    /// The value as text, whichever textual type it is. Integers are rendered in
    /// decimal, which is how `Start` and `fDenyTSConnections` are read.
    pub fn as_text(&self) -> Option<String> {
        match self {
            RegValue::Str(s) | RegValue::ExpandStr(s) => Some(s.clone()),
            RegValue::MultiStr(v) => Some(v.join(" | ")),
            RegValue::Dword(n) => Some(n.to_string()),
            RegValue::Other => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            RegValue::Dword(n) => Some(*n),
            RegValue::Str(s) | RegValue::ExpandStr(s) => s.trim().parse::<u64>().ok(),
            _ => None,
        }
    }
}

/// Open a subkey for reading. `None` means absent or inaccessible - both normal.
pub fn open(root: RootKey, subkey: &str) -> Option<OwnedRegKey> {
    let path = wide(subkey);
    let mut handle: HKEY = std::ptr::null_mut();
    // SAFETY: `root_handle` yields a predefined root key; `path` is NUL-terminated
    // and outlives the call; `handle` is a valid out-parameter slot.
    let rc = unsafe { RegOpenKeyExW(root_handle(root), path.as_ptr(), 0, KEY_READ, &mut handle) };
    if rc != ERROR_SUCCESS || handle.is_null() {
        None
    } else {
        Some(OwnedRegKey(handle))
    }
}

/// Read one value by name from an open key.
pub fn read_value(key: &OwnedRegKey, name: &str) -> Option<RegValue> {
    let wname = wide(name);
    let mut kind: u32 = 0;
    let mut size: u32 = 0;

    // SAFETY: the key is live; a NULL data pointer with a zeroed size is the
    // documented way to ask for the required size.
    let rc = unsafe {
        RegQueryValueExW(
            key.raw(),
            wname.as_ptr(),
            std::ptr::null_mut(),
            &mut kind,
            std::ptr::null_mut(),
            &mut size,
        )
    };
    if rc != ERROR_SUCCESS || size > MAX_REG_BYTES {
        return None;
    }

    let mut buf = vec![0u8; size as usize];
    let mut size2 = size;
    // SAFETY: the buffer is exactly `size` bytes as reported by the previous call;
    // `size2` is updated with the bytes actually written. A value that grew between
    // the two calls yields ERROR_MORE_DATA, which we treat as refusal rather than
    // retrying in a loop.
    let rc = unsafe {
        RegQueryValueExW(
            key.raw(),
            wname.as_ptr(),
            std::ptr::null_mut(),
            &mut kind,
            buf.as_mut_ptr(),
            &mut size2,
        )
    };
    if rc != ERROR_SUCCESS {
        return None;
    }
    buf.truncate(size2 as usize);
    Some(decode(kind, &buf))
}

/// Read an integer value leniently: a truncated buffer keeps the bytes that are
/// present and zero-fills the rest, rather than discarding the whole value.
fn decode_int(buf: &[u8]) -> u64 {
    let mut bytes = [0u8; 8];
    for (slot, byte) in bytes.iter_mut().zip(buf.iter()) {
        *slot = *byte;
    }
    u64::from_le_bytes(bytes)
}

fn decode(kind: u32, buf: &[u8]) -> RegValue {
    match kind {
        REG_SZ => RegValue::Str(from_utf16_bytes(buf)),
        REG_EXPAND_SZ => RegValue::ExpandStr(from_utf16_bytes(buf)),
        REG_MULTI_SZ => {
            // Must NOT stop at the first NUL: the elements are NUL-separated.
            let joined = from_utf16_bytes_all(buf);
            RegValue::MultiStr(
                joined
                    .split('\0')
                    .map(|s| s.to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
            )
        }
        REG_DWORD => RegValue::Dword(decode_int(buf) & 0xFFFF_FFFF),
        REG_QWORD => RegValue::Dword(decode_int(buf)),
        _ => RegValue::Other,
    }
}

/// Convenience: open and read one value.
pub fn get_value(root: RootKey, subkey: &str, name: &str) -> Option<RegValue> {
    let key = open(root, subkey)?;
    read_value(&key, name)
}

/// Convenience: read a `REG_SZ` / `REG_EXPAND_SZ` value as text, expanding `%VAR%`
/// when the value's own type asks for it.
pub fn get_string(root: RootKey, subkey: &str, name: &str) -> Option<String> {
    match get_value(root, subkey, name)? {
        RegValue::Str(s) => Some(s),
        RegValue::ExpandStr(s) => Some(super::expand(&s)),
        other => other.as_text(),
    }
}

/// Convenience: read a DWORD/QWORD value.
pub fn get_u64(root: RootKey, subkey: &str, name: &str) -> Option<u64> {
    get_value(root, subkey, name)?.as_u64()
}

/// Enumerate the values of a key, with their names.
pub fn enum_values(root: RootKey, subkey: &str) -> Vec<(String, RegValue)> {
    match open(root, subkey) {
        Some(key) => enum_values_of(&key),
        None => Vec::new(),
    }
}

/// Enumerate the values of an already-open key.
pub fn enum_values_of(key: &OwnedRegKey) -> Vec<(String, RegValue)> {
    let mut out = Vec::new();
    let mut index = 0u32;
    let mut name_buf = vec![0u16; 512];

    while out.len() < MAX_ENUM {
        let mut name_len = name_buf.len() as u32;
        let mut kind: u32 = 0;
        let mut data_len: u32 = 0;

        // SAFETY: the key is live; the name buffer is a valid out-buffer whose
        // capacity is passed in `name_len`; a NULL data pointer asks for the size.
        let rc = unsafe {
            RegEnumValueW(
                key.raw(),
                index,
                name_buf.as_mut_ptr(),
                &mut name_len,
                std::ptr::null_mut(),
                &mut kind,
                std::ptr::null_mut(),
                &mut data_len,
            )
        };

        if rc == ERROR_NO_MORE_ITEMS {
            break;
        }
        if rc != ERROR_SUCCESS && rc != ERROR_MORE_DATA {
            // Any other error: stop rather than spin on the same index.
            break;
        }

        // The API said the name did not fit: grow and retry the same index.
        if name_len as usize >= name_buf.len() {
            name_buf = vec![0u16; name_len as usize + 1];
            continue;
        }

        // The default value has an empty name, which is meaningful: an unnamed Run
        // value is a classic autostart trick, so it is kept, not skipped.
        let name = from_wide_len(&name_buf, name_len as usize);

        let value = if data_len > MAX_REG_BYTES {
            RegValue::Other
        } else {
            read_value(key, &name).unwrap_or(RegValue::Other)
        };
        out.push((name, value));
        index += 1;
    }

    out
}

/// Enumerate subkey names.
pub fn enum_subkeys(root: RootKey, subkey: &str) -> Vec<String> {
    match open(root, subkey) {
        Some(key) => enum_subkeys_of(&key),
        None => Vec::new(),
    }
}

/// Enumerate subkey names of an already-open key.
pub fn enum_subkeys_of(key: &OwnedRegKey) -> Vec<String> {
    let mut out = Vec::new();
    let mut index = 0u32;
    let mut name_buf = vec![0u16; 512];

    while out.len() < MAX_ENUM {
        let mut name_len = name_buf.len() as u32;

        // SAFETY: as above; the class and last-write-time pointers are optional and
        // documented as such, hence NULL.
        let rc = unsafe {
            RegEnumKeyExW(
                key.raw(),
                index,
                name_buf.as_mut_ptr(),
                &mut name_len,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };

        if rc == ERROR_NO_MORE_ITEMS {
            break;
        }
        if rc != ERROR_SUCCESS && rc != ERROR_MORE_DATA {
            break;
        }
        if name_len as usize >= name_buf.len() {
            name_buf = vec![0u16; name_len as usize + 1];
            continue;
        }

        out.push(from_wide(&name_buf));
        index += 1;
    }

    out
}

/// Does a subkey exist? Cheaper and clearer than matching on `open`.
pub fn key_exists(root: RootKey, subkey: &str) -> bool {
    open(root, subkey).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_stable_value_from_this_machine() {
        // Exercises the whole FFI path: open, size query, allocate, read, decode.
        // The key exists on every Windows installation.
        let name = get_string(
            RootKey::Hklm,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "ProductName",
        );
        assert!(name.is_some(), "ProductName should be readable on Windows");
        assert!(!name.unwrap_or_default().is_empty());
    }

    #[test]
    fn missing_key_and_missing_value_are_none_not_a_panic() {
        assert!(get_string(RootKey::Hklm, r"SOFTWARE\IRScan-Does-Not-Exist", "x").is_none());
        assert!(get_string(
            RootKey::Hklm,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "IRScanNoSuchValue"
        )
        .is_none());
        assert!(!key_exists(
            RootKey::Hklm,
            r"SOFTWARE\IRScan-Does-Not-Exist"
        ));
    }

    #[test]
    fn enumerates_subkeys_of_a_stable_key() {
        let subkeys = enum_subkeys(
            RootKey::Hklm,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        );
        assert!(
            subkeys
                .iter()
                .any(|s| s == "ProfileList" || s == "Winlogon"),
            "expected well-known subkeys, got {subkeys:?}"
        );
    }

    #[test]
    fn enumerates_values_with_their_types() {
        let values = enum_values(
            RootKey::Hklm,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        );
        assert!(!values.is_empty());
        let product = values.iter().find(|(n, _)| n == "ProductName");
        assert!(product.is_some(), "ProductName missing from enumeration");
        if let Some((_, v)) = product {
            assert!(v.as_text().is_some(), "REG_SZ must decode to text");
        }
    }

    #[test]
    fn enumeration_of_a_missing_key_is_empty() {
        assert!(enum_values(RootKey::Hklm, r"SOFTWARE\IRScan-Does-Not-Exist").is_empty());
        assert!(enum_subkeys(RootKey::Hklm, r"SOFTWARE\IRScan-Does-Not-Exist").is_empty());
    }

    #[test]
    fn decode_shapes_are_what_callers_expect() {
        assert_eq!(decode(REG_DWORD, &[1, 0, 0, 0]), RegValue::Dword(1));
        assert_eq!(
            decode(REG_SZ, &[0x61, 0x00, 0x00, 0x00]),
            RegValue::Str("a".into())
        );
        let multi = decode(REG_MULTI_SZ, &[0x61, 0, 0, 0, 0x62, 0, 0, 0, 0, 0]);
        assert_eq!(
            multi,
            RegValue::MultiStr(vec!["a".to_string(), "b".to_string()])
        );
        assert_eq!(decode(0xFFFF, &[1, 2, 3]), RegValue::Other);
    }

    #[test]
    fn dword_decoding_tolerates_short_buffers() {
        // Must not panic on a truncated value.
        assert_eq!(decode(REG_DWORD, &[]), RegValue::Dword(0));
        assert_eq!(decode(REG_QWORD, &[1, 0]), RegValue::Dword(1));
    }
}
