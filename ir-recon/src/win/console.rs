//! Console preparation.
//!
//! Windows terminals need to be told to interpret ANSI escape sequences. Windows 10
//! supports them from build 10586 onwards, but only after
//! `ENABLE_VIRTUAL_TERMINAL_PROCESSING` is set on the standard output handle - a
//! process cannot assume it inherited that mode.
//!
//! This lives in `win` because it is one of the few places the tool talks to the
//! console through FFI rather than through `std::io`. Failure is not an error: a
//! terminal without VT support simply gets the plain rendering.
//!
//! Note on style: every comparison in this file is written in the positive form
//! (`== 0`, `> 0`) rather than with a negation. That is deliberate - a leading
//! exclamation mark before an identifier has been observed to be rewritten by the
//! development toolchain in this project, so the code avoids the pattern entirely
//! rather than relying on it surviving a round trip through a text pipeline.

use windows_sys::Win32::System::Console::{
    GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
    STD_OUTPUT_HANDLE,
};

/// Ask the console to interpret ANSI escape sequences.
///
/// Returns true when the mode is in force (either it was already set, or this call
/// set it). A false return means the caller must fall back to unstyled rendering -
/// never a reason to fail a scan.
pub fn enable_virtual_terminal() -> bool {
    // SAFETY: `GetStdHandle` takes a constant selector and returns a handle this
    // process already owns; it must not be closed.
    let handle = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    if handle.is_null() {
        return false;
    }

    let mut mode: u32 = 0;
    // SAFETY: `handle` came from `GetStdHandle` above and `mode` is a valid out-slot.
    let got = unsafe { GetConsoleMode(handle, &mut mode) };
    if got == 0 {
        // Not a console: a pipe, a file, or an MSYS pseudo-terminal. Nothing to do.
        return false;
    }

    if mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING == ENABLE_VIRTUAL_TERMINAL_PROCESSING {
        return true;
    }

    // SAFETY: same live handle; the value is the mode just read, with one documented
    // flag added.
    let set = unsafe { SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) };
    set > 0
}

/// Is the standard output attached to a console rather than a pipe or a file?
///
/// `std::io::IsTerminal` answers the same question portably and is what callers
/// should use; this exists so that every console probe lives in one file.
pub fn stdout_is_console() -> bool {
    // SAFETY: a constant selector and a borrowed pseudo-handle.
    let handle = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    if handle.is_null() {
        return false;
    }
    let mut mode: u32 = 0;
    // SAFETY: as above.
    let got = unsafe { GetConsoleMode(handle, &mut mode) };
    got > 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probing_the_console_never_panics() {
        // Under `cargo test` stdout is usually a pipe, so the likely answer is false.
        // What this pins is that neither call aborts on a non-console handle.
        let _ = enable_virtual_terminal();
        let _ = stdout_is_console();
    }

    #[test]
    fn enabling_twice_is_idempotent() {
        // The second call must take the early-return path, reporting the same state,
        // rather than toggling the flag back off.
        let first = enable_virtual_terminal();
        let second = enable_virtual_terminal();
        assert_eq!(first, second);
    }
}
