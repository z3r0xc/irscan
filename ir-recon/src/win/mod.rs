//! The only module in the crate allowed to contain `unsafe`.
//!
//! Everything here is a thin, boring shim over Win32: no business rules, no
//! severity decisions, no printing. The rules live in `crate::rules`, so that the
//! interesting logic can be unit-tested without Windows (spec SR-6).
//!
//! FFI safety rules (docs/architecture.md section 6) applied throughout:
//! every return value is checked, buffers are sized from the length the API
//! reports, and every handle is released through an RAII guard.

pub mod console;
pub mod elevate;
pub mod events;
pub mod hash;
pub mod net;
pub mod reg;
pub mod services;
pub mod sig;
pub mod strings;

pub use strings::{from_utf16_bytes, from_wide, from_wide_len, wide};

pub mod accounts;
pub mod wmi;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};

/// RAII guard: closes a kernel handle on every path, including early returns and
/// panics. Constructed only from a handle an API has already validated, so there is
/// no "did we open it?" bookkeeping to get wrong.
pub struct OwnedHandle(HANDLE);

impl OwnedHandle {
    /// Wrap a handle returned by a Win32 API. Returns `None` for `NULL` and for
    /// `INVALID_HANDLE_VALUE`, both of which mean "no handle to close".
    pub fn new(handle: HANDLE) -> Option<Self> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            None
        } else {
            Some(OwnedHandle(handle))
        }
    }

    pub fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: the handle was returned by a Win32 call that succeeded and has not
        // been closed elsewhere; `OwnedHandle` is its unique owner for its lifetime.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// Is the current process running with an elevated token?
///
/// Used to warn the user that some collectors will come back empty, not to gate
/// behaviour: a partial report is still valuable.
pub fn is_elevated() -> bool {
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle that needs no closing;
    // `token` is a valid out-parameter slot for `OpenProcessToken`.
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if opened == 0 {
        return false;
    }
    let Some(token) = OwnedHandle::new(token) else {
        return false;
    };

    // SAFETY: `TOKEN_ELEVATION` is plain-old-data for which an all-zero bit pattern
    // is valid, and `size_of` matches what the API expects.
    let mut elevation: TOKEN_ELEVATION = unsafe { std::mem::zeroed() };
    let mut returned = 0u32;
    // SAFETY: the token is live; the output buffer is exactly `size_of::<T>()` bytes
    // as the API requires; `returned` is a valid out-parameter.
    let ok = unsafe {
        GetTokenInformation(
            token.raw(),
            TokenElevation,
            &mut elevation as *mut _ as *mut core::ffi::c_void,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    };
    ok != 0 && elevation.TokenIsElevated != 0
}

/// `%SystemRoot%`, falling back to the conventional value for the rare process whose
/// environment block has been stripped.
pub fn system_root() -> String {
    std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string())
}

/// The `%VAR%` set used to expand paths found in the registry.
///
/// Deliberately a fixed list rather than "everything in the environment": a hostile
/// service path containing `%SOMETHING%` must not be resolved into an unrelated
/// value that changes what the report claims.
pub fn system_vars() -> Vec<(String, String)> {
    const NAMES: &[&str] = &[
        "SystemRoot",
        "windir",
        "SystemDrive",
        "ProgramData",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "AppData",
        "LocalAppData",
        "UserProfile",
        "Public",
        "Temp",
        "Tmp",
        "System32",
    ];
    let mut out = Vec::new();
    for name in NAMES {
        if let Ok(value) = std::env::var(name) {
            out.push((name.to_string(), value));
        }
    }
    out
}

/// Expand `%VAR%` references in a string collected from the host.
pub fn expand(path: &str) -> String {
    let vars = system_vars();
    let refs: Vec<(&str, &str)> = vars.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    crate::rules::expand_env(path, &refs)
}

/// `FILE_ATTRIBUTE_REPARSE_POINT`. Directory walks must skip these, otherwise a
/// junction planted in a drop location can lead the walk out of its root (SR-3).
pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

/// Is this file or directory a reparse point (symlink, junction, mount point)?
pub fn is_reparse_point(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// Current local time as `YYYY-MM-DD HH:MM:SS`.
///
/// Taken from the OS rather than computed, so the report carries the same local
/// time the user sees and no timezone arithmetic is invented here.
pub fn local_time_string() -> String {
    use windows_sys::Win32::Foundation::SYSTEMTIME;
    use windows_sys::Win32::System::SystemInformation::GetLocalTime;
    // SAFETY: SYSTEMTIME is plain-old-data; an all-zero bit pattern is valid.
    let mut st: SYSTEMTIME = unsafe { std::mem::zeroed() };
    // SAFETY: GetLocalTime fills a caller-provided SYSTEMTIME and cannot fail.
    unsafe { GetLocalTime(&mut st) };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond
    )
}

/// Seconds since the machine booted.
pub fn uptime_seconds() -> u64 {
    use windows_sys::Win32::System::SystemInformation::GetTickCount64;
    // SAFETY: GetTickCount64 takes no arguments and cannot fail.
    unsafe { GetTickCount64() / 1000 }
}

/// Human-readable text for the last Win32 error.
pub fn last_error() -> String {
    std::io::Error::last_os_error().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_root_is_absolute() {
        let root = system_root();
        assert!(root.len() >= 3, "system root looks wrong: {root}");
        assert!(
            root.contains(':'),
            "system root must be a drive path: {root}"
        );
    }

    #[test]
    fn system_vars_never_contain_nul_or_empty_names() {
        for (k, v) in system_vars() {
            assert!(!k.is_empty());
            assert!(!k.contains('\0'));
            assert!(!v.contains('\0'));
        }
    }

    #[test]
    fn expand_resolves_a_real_variable() {
        let root = system_root();
        let expanded = expand(r"%SystemRoot%\System32");
        assert!(expanded
            .to_lowercase()
            .starts_with(&root.to_lowercase()[..2]));
        assert!(!expanded.contains('%'), "unexpanded variable left behind");
    }

    #[test]
    fn expand_preserves_unknown_variables() {
        assert_eq!(expand("%IRSCAN_NO_SUCH_VAR%\\x"), "%IRSCAN_NO_SUCH_VAR%\\x");
    }

    #[test]
    fn local_time_is_a_sortable_stamp() {
        let t = local_time_string();
        assert_eq!(t.len(), 19, "unexpected stamp: {t}");
        assert_eq!(t.chars().nth(4), Some('-'));
        assert_eq!(t.chars().nth(7), Some('-'));
        assert_eq!(t.chars().nth(10), Some(' '));
    }

    #[test]
    fn uptime_is_plausible() {
        // A running machine has been up for at least a second and does not have a
        // negative (wrapped) uptime.
        assert!(uptime_seconds() > 0);
        assert!(uptime_seconds() < u64::MAX / 2);
    }

    #[test]
    fn owned_handle_rejects_null_and_invalid() {
        assert!(OwnedHandle::new(std::ptr::null_mut()).is_none());
        assert!(OwnedHandle::new(INVALID_HANDLE_VALUE).is_none());
    }
}
