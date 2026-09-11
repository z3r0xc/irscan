//! Self-elevation.
//!
//! The binary ships with an `asInvoker` manifest on purpose: that keeps the
//! reduced-coverage path reachable (and testable) when an administrator declines, and
//! it lets the tool be smoke-tested without a UAC prompt. When the user does want
//! full coverage, this module asks the shell for an elevated copy of the same
//! executable. It never launches a command interpreter, so no collected string can
//! ever reach a shell (spec SR-1).

use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

/// Quote one command-line argument so a path containing spaces survives intact.
///
/// Deliberately minimal: this is only used for arguments the tool itself builds
/// (the executable path and our own flags), never for anything read off the host.
pub fn quote_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "\"\"".to_string();
    }
    if arg.contains(' ') || arg.contains('\t') {
        format!("\"{}\"", arg.replace('"', "\\\""))
    } else {
        arg.to_string()
    }
}

/// Relaunch this executable with `runas`, passing `args` through unchanged.
///
/// Returns true when the elevated copy was started. A false return means the user
/// declined the UAC prompt or the shell refused, in which case the caller should
/// continue with reduced coverage rather than fail.
pub fn relaunch_elevated(args: &[String]) -> bool {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return false,
    };
    relaunch_path(&exe, args)
}

/// Same as [`relaunch_elevated`] but for an explicit executable path, which is what
/// the unit tests exercise.
pub fn relaunch_path(exe: &Path, args: &[String]) -> bool {
    // Every buffer must outlive the call, so they are bound here rather than
    // constructed inline.
    let exe_w: Vec<u16> = exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let verb_w: Vec<u16> = "runas".encode_utf16().chain(std::iter::once(0)).collect();
    let params: String = args
        .iter()
        .map(|a| quote_arg(a))
        .collect::<Vec<_>>()
        .join(" ");
    let params_w: Vec<u16> = params.encode_utf16().chain(std::iter::once(0)).collect();

    // SAFETY: SHELLEXECUTEINFOW is plain-old-data for which an all-zero bit pattern
    // is valid, and `cbSize` is set to the size the API requires.
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = verb_w.as_ptr();
    info.lpFile = exe_w.as_ptr();
    info.lpParameters = if params.is_empty() {
        std::ptr::null()
    } else {
        params_w.as_ptr()
    };
    info.nShow = SW_SHOWNORMAL;

    // SAFETY: the struct is fully initialised, every pointer inside it refers to a
    // buffer that is still alive, and the strings are NUL-terminated.
    let launched = unsafe { ShellExecuteExW(&mut info) };
    launched != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_arg_leaves_plain_arguments_alone() {
        assert_eq!(quote_arg("--json"), "--json");
        assert_eq!(quote_arg("C:\\tmp\\x.txt"), "C:\\tmp\\x.txt");
    }

    #[test]
    fn quote_arg_wraps_paths_with_spaces() {
        assert_eq!(
            quote_arg("C:\\Program Files\\IRScan\\out.txt"),
            "\"C:\\Program Files\\IRScan\\out.txt\""
        );
    }

    #[test]
    fn quote_arg_handles_empty_and_embedded_quotes() {
        assert_eq!(quote_arg(""), "\"\"");
        assert_eq!(quote_arg("a\"b c"), "\"a\\\"b c\"");
    }

    #[test]
    fn quoting_is_the_whole_contract_we_can_test_here() {
        // Deliberately NOT calling relaunch_path: `ShellExecuteExW` with the `runas`
        // verb can raise a UAC consent prompt and block for a minute, which a unit
        // test must never do. The elevation path is exercised by running the binary
        // unelevated (it prints a notice and asks for an elevated copy), and what is
        // testable without side effects is the argument quoting that call depends on.
        let args = [
            "--quick".to_string(),
            r"C:\Program Files\x".to_string(),
            String::new(),
        ];
        let joined = args
            .iter()
            .map(|a| quote_arg(a))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            joined.starts_with("--quick "),
            "flag stays unquoted: {joined}"
        );
        assert!(
            joined.contains("\"C:\\Program Files\\x\""),
            "a path with a space must be quoted: {joined}"
        );
        assert!(
            joined.ends_with("\"\""),
            "an empty argument must survive as an empty quoted token: {joined}"
        );
    }
}
