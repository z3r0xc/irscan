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
    RegCloseKey, RegDeleteValueW, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW, RegQueryValueExW,
    RegSetValueExW, HKEY, HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS,
    KEY_READ, KEY_SET_VALUE, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ, REG_QWORD, REG_SZ,
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

/// Decode a registry value name.
///
/// `RegEnumValueW` returns the name as UTF-16 units, but a key written through the ANSI API
/// can hold text whose *bytes* were stored verbatim and are then read back as units. On this
/// host `HKCU\...\Run` contains exactly that: the bytes `57 69 6e 64 6f 77 73 ...` are
/// `WindowsUpdateTask` packed two characters per unit, so the units decode as
/// `楗摮睯啳摰瑡呥獡k` - and that is what this tool used to print, search for, and match against
/// its signature database. The name is unsearchable for the operator and invisible to every
/// check keyed on a process name, which is a silent hole at the one place an autostart entry
/// lives.
///
/// The two encodings cannot be separated by the shape of the units - a UTF-16 name of even
/// length also has zero high bytes, and the packed form above does not. They are separated by
/// what decodes into readable text: the raw little-endian bytes are tried as UTF-8 first, and
/// the UTF-16 reading survives whenever that fails or yields control characters. Guessing is
/// safe in this direction because a real UTF-16 name of ASCII text decodes as UTF-8 only into
/// `W\0i\0n\0...`, which the control-character test rejects.
fn decode_value_name(buf: &[u16], len_chars: usize) -> String {
    let wide = from_wide_len(buf, len_chars);

    let units = len_chars.min(buf.len());
    let units = buf[..units].iter().position(|c| *c == 0).unwrap_or(units);
    let mut bytes: Vec<u8> = buf[..units].iter().flat_map(|u| u.to_le_bytes()).collect();
    // A packed name ends with the terminator that `from_wide_len` would have stopped at,
    // and it arrives here as a trailing zero *byte* rather than a zero unit.
    while bytes.last() == Some(&0) {
        bytes.pop();
    }

    match std::str::from_utf8(&bytes) {
        // At least one alphanumeric character and nothing unprintable: that is text, not a
        // UTF-16 read of the same bytes (which decodes into `W\0i\0n\0...`).
        Ok(text)
            if !text.is_empty()
                && text.chars().any(|c| c.is_alphanumeric())
                && text.chars().all(|c| !c.is_control()) =>
        {
            text.to_string()
        }
        _ => wide,
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

        // The first call asks for the sizes: a NULL data pointer means "tell me how big".
        // SAFETY: the key is live; the name buffer is a valid out-buffer whose capacity is
        // passed in `name_len`; `data_len` receives the required size.
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

        // Read the data in the same enumeration step rather than by looking the value up
        // again. Two reasons, and the second is a real bug this code had: the second lookup
        // has to name the value, and the name we hold is *decoded* - for a name whose stored
        // bytes are not UTF-16 the decoded form is not the key's name, so the lookup returned
        // nothing and every such value was reported empty.
        if data_len > MAX_REG_BYTES {
            out.push((
                decode_value_name(&name_buf, name_len as usize),
                RegValue::Other,
            ));
            index += 1;
            continue;
        }

        let mut data_buf = vec![0u8; data_len as usize];
        let mut kind_after: u32 = kind;
        let mut data_len_after = data_len;
        // `name_len` is an in/out parameter: on entry it must be the buffer's capacity in
        // characters, not the length the previous call reported. Passing the reported length
        // back in makes the API reject every name as too long and return
        // ERROR_MORE_DATA for good, which emptied the whole enumeration.
        let mut name_len_after = name_buf.len() as u32;
        // SAFETY: the key is live; the name buffer's capacity is passed in
        // `name_len_after`; `data_buf` is exactly `data_len` bytes as reported for this
        // index; `data_len_after` receives what was written.
        let rc = unsafe {
            RegEnumValueW(
                key.raw(),
                index,
                name_buf.as_mut_ptr(),
                &mut name_len_after,
                std::ptr::null_mut(),
                &mut kind_after,
                data_buf.as_mut_ptr(),
                &mut data_len_after,
            )
        };
        if rc != ERROR_SUCCESS {
            index += 1;
            continue;
        }
        data_buf.truncate(data_len_after as usize);
        let name_len = name_len_after;

        // The default value has an empty name, which is meaningful: an unnamed Run value is
        // a classic autostart trick, so it is kept, not skipped.
        let name = decode_value_name(&name_buf, name_len as usize);
        out.push((name, decode(kind_after, &data_buf)));
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

/// Open a subkey for writing.
///
/// Deliberately a separate function from [`open`], which asks only for `KEY_READ`. Every
/// other part of this tool reads; only the remediation path writes, and it should be
/// obvious at the call site which one is in play.
pub fn open_for_write(root: RootKey, subkey: &str) -> Option<OwnedRegKey> {
    let path = wide(subkey);
    let mut handle: HKEY = std::ptr::null_mut();
    // SAFETY: a predefined root key, a NUL-terminated path that outlives the call, and a
    // valid out-parameter slot.
    let rc = unsafe {
        RegOpenKeyExW(
            root_handle(root),
            path.as_ptr(),
            0,
            KEY_READ | KEY_SET_VALUE,
            &mut handle,
        )
    };
    if rc != ERROR_SUCCESS || handle.is_null() {
        None
    } else {
        Some(OwnedRegKey(handle))
    }
}

/// Write a `REG_DWORD`.
///
/// Returns `Err` with the Win32 message rather than a bool, because the caller is about to
/// tell the user that something on their machine was changed: a silent failure there is
/// the one outcome that must not happen.
pub fn set_u64(key: &OwnedRegKey, name: &str, value: u64) -> Result<(), String> {
    let wname = wide(name);
    let bytes = (value as u32).to_le_bytes();
    // SAFETY: the key is open for writing, the name is NUL-terminated, and the buffer is
    // exactly the four bytes the type declares.
    let rc = unsafe {
        RegSetValueExW(
            key.raw(),
            wname.as_ptr(),
            0,
            REG_DWORD,
            bytes.as_ptr(),
            bytes.len() as u32,
        )
    };
    if rc == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(format!("RegSetValueExW failed with code {rc}"))
    }
}

/// Delete one value. Used only by a removal the user explicitly confirmed.
pub fn delete_value(key: &OwnedRegKey, name: &str) -> Result<(), String> {
    let wname = wide(name);
    // SAFETY: the key is open for writing and the name is NUL-terminated.
    let rc = unsafe { RegDeleteValueW(key.raw(), wname.as_ptr()) };
    if rc == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(format!("RegDeleteValueW failed with code {rc}"))
    }
}

/// Create a key. Test-only: the shipped tool never creates a key, and this exists so the
/// write path can be exercised against a real registry rather than a mock.
#[cfg(test)]
pub fn reg_create_for_test(root: RootKey, subkey: &str) -> bool {
    use windows_sys::Win32::System::Registry::{RegCreateKeyExW, REG_OPTION_NON_VOLATILE};
    let path = wide(subkey);
    let mut handle: HKEY = std::ptr::null_mut();
    let mut disposition: u32 = 0;
    // SAFETY: a predefined root, a NUL-terminated path, and valid out-parameters.
    let rc = unsafe {
        RegCreateKeyExW(
            root_handle(root),
            path.as_ptr(),
            0,
            std::ptr::null_mut(),
            REG_OPTION_NON_VOLATILE,
            KEY_READ | KEY_SET_VALUE,
            std::ptr::null_mut(),
            &mut handle,
            &mut disposition,
        )
    };
    if rc == ERROR_SUCCESS && !handle.is_null() {
        // SAFETY: the handle came from a successful create and is not used afterwards.
        unsafe {
            let _ = RegCloseKey(handle);
        }
        true
    } else {
        false
    }
}

/// Delete a key. Test-only, and only ever used on a key this test created.
#[cfg(test)]
pub fn reg_delete_for_test(root: RootKey, subkey: &str) -> bool {
    use windows_sys::Win32::System::Registry::RegDeleteKeyW;
    let path = wide(subkey);
    // SAFETY: a predefined root and a NUL-terminated path.
    let rc = unsafe { RegDeleteKeyW(root_handle(root), path.as_ptr()) };
    rc == ERROR_SUCCESS
}

/// Does a subkey exist? Cheaper and clearer than matching on `open`.
pub fn key_exists(root: RootKey, subkey: &str) -> bool {
    open(root, subkey).is_some()
}

#[cfg(test)]
mod tests {

    #[test]
    fn a_value_name_whose_bytes_pair_up_into_units_is_recovered() {
        // The real case, from this host's own `HKCU\...\Run`. Verified with .NET that the
        // stored name bytes are `57 69 6e 64 6f 77 73 ...` - the ASCII of "WindowsUpdateTask"
        // packed two characters per UTF-16 unit, which is what reading a UTF-8 name back in
        // wide form produces. Decoded as UTF-16 it is `楗摮睯啳摰瑡呥獡k`.
        let name = "WindowsUpdateTask";
        let mut bytes = name.as_bytes().to_vec();
        if bytes.len() % 2 == 1 {
            bytes.push(0);
        }
        let as_units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from(c[0]) | (u16::from(c[1]) << 8))
            .collect();

        let recovered = decode_value_name(&as_units, as_units.len());
        assert_eq!(recovered, name, "the packed name must be recovered in full");

        // An ordinary UTF-16 name stays intact: the recovery must not corrupt the case the
        // API documents.
        let ordinary: Vec<u16> = "OneDrive".encode_utf16().collect();
        assert_eq!(decode_value_name(&ordinary, ordinary.len()), "OneDrive");

        // Non-ASCII UTF-16 is still UTF-16.
        let cyrillic: Vec<u16> = "Обновление".encode_utf16().collect();
        assert_eq!(decode_value_name(&cyrillic, cyrillic.len()), "Обновление");

        // The default value's empty name stays empty.
        assert_eq!(decode_value_name(&[], 0), "");
    }

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
    fn a_dword_can_be_written_and_read_back_under_hkcu() {
        // The remediation path is the only writer in this tool, so it gets a real test on
        // a real key rather than a mock. HKCU\Software is used because a test must not
        // need administrator rights and must clean up after itself.
        let path = r"Software\IRScanSelfTest";
        let created = reg_create_for_test(RootKey::Hkcu, path);
        assert!(created, "could not create the test key");

        if let Some(key) = open_for_write(RootKey::Hkcu, path) {
            assert!(set_u64(&key, "Start", 4).is_ok());
        }
        assert_eq!(get_u64(RootKey::Hkcu, path, "Start"), Some(4));

        if let Some(key) = open_for_write(RootKey::Hkcu, path) {
            assert!(delete_value(&key, "Start").is_ok());
        }
        assert_eq!(get_u64(RootKey::Hkcu, path, "Start"), None);

        let _ = reg_delete_for_test(RootKey::Hkcu, path);
    }

    #[test]
    fn deleting_a_value_that_is_absent_is_an_error_not_a_silent_success() {
        let path = r"Software\IRScanSelfTest";
        let _ = reg_create_for_test(RootKey::Hkcu, path);
        let result = match open_for_write(RootKey::Hkcu, path) {
            Some(key) => delete_value(&key, "IRScanNoSuchValue"),
            None => Err("key unavailable".to_string()),
        };
        assert!(
            result.is_err(),
            "an absent value must be reported, not assumed gone"
        );
        let _ = reg_delete_for_test(RootKey::Hkcu, path);
    }

    #[test]
    fn dword_decoding_tolerates_short_buffers() {
        // Must not panic on a truncated value.
        assert_eq!(decode(REG_DWORD, &[]), RegValue::Dword(0));
        assert_eq!(decode(REG_QWORD, &[1, 0]), RegValue::Dword(1));
    }
}
