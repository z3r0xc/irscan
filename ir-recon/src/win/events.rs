//! Thin `wevtapi.dll` shim: channel queries rendered to raw event XML.
//!
//! This file deliberately contains **no parsing and no rules** (FR-10). It hands
//! back the exact XML `EvtRender` emitted, so the interesting work - pulling
//! EventID, ImagePath, account names and remote addresses out of hostile markup -
//! lives in a pure, fixture-testable parser in `collect/events.rs`. Nothing here
//! decides severity, prints, or sanitises; sanitisation happens at the boundary
//! where the text enters a `Finding`.
//!
//! FFI safety rules applied (docs/architecture.md section 6):
//!
//! * `EvtQuery` with `EvtQueryReverseDirection`, so the newest events arrive first
//!   and the scan can stop after the handful it cares about instead of walking a
//!   multi-gigabyte log forwards;
//! * `EvtNext` in fixed-size batches, bounded by the caller's `max` and by
//!   `MAX_EVENTS_HARD_CAP`, so a hostile or huge channel cannot be pulled into
//!   memory;
//! * size-then-allocate `EvtRender` (the first call legitimately fails with
//!   `ERROR_INSUFFICIENT_BUFFER`), with a second call covering the race where the
//!   event grew in between;
//! * every `EVT_HANDLE` travels in an [`OwnedEvt`] guard, so resultsets, the query
//!   handle and each individual event are closed on every path, error paths
//!   included.

use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS};
use windows_sys::Win32::System::EventLog::{
    EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection, EvtRender,
    EvtRenderEventXml, EVT_HANDLE,
};

use super::strings::{from_wide, wide};

/// Standard channels this tool reads.
///
/// Named here so a channel rename happens in one place rather than in every
/// collector that queries the log.
pub const CHANNEL_SYSTEM: &str = "System";
pub const CHANNEL_SECURITY: &str = "Security";
pub const CHANNEL_DEFENDER: &str = "Microsoft-Windows-Windows Defender/Operational";
pub const CHANNEL_TASKSCHED: &str = "Microsoft-Windows-TaskScheduler/Operational";
pub const CHANNEL_TSTRM: &str =
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";

/// Absolute ceiling on events returned by a single `query`, whatever the caller
/// asks for. A caller-supplied `usize::MAX` must not turn into an unbounded loop
/// over the Security log (reliability tactic, architecture section 5.2).
pub const MAX_EVENTS_HARD_CAP: usize = 20_000;

/// Events pulled from the resultset per `EvtNext` call. Batched rather than one
/// at a time: each `EvtNext` is a syscall, and each returned handle must be closed.
const EVT_BATCH: usize = 32;

/// Upper bound on a rendered event (1 MiB). Real events are a few KiB; a larger
/// one is rejected rather than retried into an unbounded allocation.
const MAX_EVENT_XML_BYTES: u32 = 1024 * 1024;
/// Upper bound on the debug-formatted Win32 error text embedded in `Err`.
const MAX_ERROR_TEXT: usize = 512;

/// One rendered event, exactly as `EvtRender` produced it.
///
/// Parsed, not interpreted: the `EventXml` representation preserves every field
/// and namespace the collector may need.
pub struct RawEvent {
    pub xml: String,
}

/// RAII guard for an `EVT_HANDLE`, mirroring `win::OwnedHandle` and `win::reg::OwnedRegKey`.
///
/// Handles come from the three `wevtapi` functions that create them, each of which
/// returns a null pointer on failure. Construction is gated on "non-null", and the
/// only other value the guard can hold - `EVT_HANDLE::default()`, i.e. 0 - is a
/// no-op for `EvtClose`, so dropping an empty guard is harmless.
///
/// The one rule callers must follow: never return a handle out of a loop alive.
/// [`EvtIter`] rebuilds its batch every call and drops the previous batch first,
/// which is what keeps "at most `EVT_BATCH` handles open" true.
struct OwnedEvt(EVT_HANDLE);

impl OwnedEvt {
    /// Wrap a handle, or `None` if the API reported failure with a null handle.
    fn new(handle: EVT_HANDLE) -> Option<Self> {
        if handle == 0 {
            None
        } else {
            Some(Self(handle))
        }
    }

    fn raw(&self) -> EVT_HANDLE {
        self.0
    }
}

impl Drop for OwnedEvt {
    fn drop(&mut self) {
        // SAFETY: an `OwnedEvt` is only ever built around a non-null handle that
        // `wevtapi` returned, and it owns that handle exclusively until here.
        unsafe {
            let _ = EvtClose(self.0);
        }
    }
}

/// Incremental cursor over an `EvtQuery` resultset.
///
/// Holds the resultset handle and the current batch of event handles. `next_batch`
/// drops the previous batch before `EvtNext` refills it, so the live-handle count
/// is `1 + EVT_BATCH` regardless of how many events are consumed.
struct EvtIter {
    resultset: OwnedEvt,
    batch: Vec<OwnedEvt>,
}

impl EvtIter {
    /// Pull the next batch of event handles. `Err` carries the raw Win32 code, so
    /// the caller can tell "end of results" from a real failure.
    fn next_batch(&mut self) -> Result<(), u32> {
        // Release the previous batch first; its handles are fully consumed.
        self.batch.clear();
        let mut handles: [EVT_HANDLE; EVT_BATCH] = [0; EVT_BATCH];
        let mut returned: u32 = 0;

        // SAFETY: the resultset is live and owned by `self`; `handles` is a valid
        // out-buffer of exactly `eventssize` elements and `returned` a valid slot.
        // `EvtNext` writes at most `EVT_BATCH` handles, so `returned` indexes are
        // clamped to the array length below before any read.
        let ok = unsafe {
            EvtNext(
                self.resultset.raw(),
                EVT_BATCH as u32,
                handles.as_mut_ptr(),
                u32::MAX,
                0,
                &mut returned,
            )
        };

        if ok == 0 {
            return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32);
        }

        let count = (returned as usize).min(EVT_BATCH);
        for h in handles.iter().take(count) {
            // A null handle cannot be closed and carries no event; skip it rather
            // than accumulating a poisoned guard.
            if let Some(ev) = OwnedEvt::new(*h) {
                self.batch.push(ev);
            }
        }
        // A success with zero handles returned would make `next_event` loop
        // forever on the same empty batch; treat it as the end of the resultset.
        if self.batch.is_empty() {
            return Err(ERROR_NO_MORE_ITEMS);
        }
        Ok(())
    }

    /// The next event, or `None` at the end of the resultset.
    ///
    /// Returns the **owned guard**, not a bare handle, and that is the whole point: the
    /// caller renders the event after this function returns, and the next call to
    /// `next_batch` closes every handle in the batch before refilling it. Handing out a
    /// bare handle would leave the caller rendering a handle that had just been closed,
    /// which fails with `ERROR_INVALID_HANDLE` (6) and - because the caller skips an
    /// event it cannot render - silently reports an empty channel. That was a real
    /// false negative across four checks, so the type now makes the lifetime explicit:
    /// the guard travels to the caller and is dropped only when the caller is done.
    ///
    /// `ERROR_NO_MORE_ITEMS` is a clean end and is mapped to `None`; every other failure
    /// is reported as an error rather than silently truncating the scan.
    fn next_event(&mut self) -> Result<Option<OwnedEvt>, String> {
        loop {
            if let Some(ev) = self.batch.pop() {
                return Ok(Some(ev));
            }
            match self.next_batch() {
                Ok(()) => {}
                Err(code) if code == ERROR_NO_MORE_ITEMS => return Ok(None),
                Err(code) => return Err(win_err("EvtNext", code)),
            }
        }
    }
}

/// Render one event as its `EventXml` string.
///
/// Two-call protocol: a zero-size call is *expected* to fail with
/// `ERROR_INSUFFICIENT_BUFFER` and reports the required byte length; the second
/// call fills the buffer. If the event grew in between, the second call fails the
/// same way and the event is retried once with the freshly reported size - bounded
/// so a pathological event cannot spin.
fn render_event_xml(event: EVT_HANDLE) -> Result<String, String> {
    // `used` is documented as a character count, but the buffer is a `Vec<u8>`,
    // so every offset below converts to bytes and clamps to the allocation. An
    // out-of-range offset is treated as the string ending there, never as a panic.
    let mut used: u32 = 0;
    let mut props: u32 = 0;

    // SAFETY: the event handle is live; a null buffer with size 0 is the
    // documented size-probe form, and both out-parameters are valid slots.
    let ok = unsafe {
        EvtRender(
            0,
            event,
            EvtRenderEventXml,
            0,
            std::ptr::null_mut(),
            &mut used,
            &mut props,
        )
    };
    if ok == 0 {
        let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32;
        // Any other error on the probe means the event cannot be rendered at all.
        if code != ERROR_INSUFFICIENT_BUFFER {
            return Err(win_err("EvtRender", code));
        }
    }

    let mut needed = used;
    for _ in 0..2 {
        if needed == 0 || needed > MAX_EVENT_XML_BYTES {
            return Err(format!(
                "event XML of {needed} bytes exceeds the {MAX_EVENT_XML_BYTES} byte cap"
            ));
        }
        let mut buf: Vec<u8> = vec![0; needed as usize];
        let mut written: u32 = 0;
        let mut props: u32 = 0;

        // SAFETY: the event handle is live and `buf` is a valid allocation of
        // `needed` bytes, the exact size `EvtRender` asked for.
        let ok = unsafe {
            EvtRender(
                0,
                event,
                EvtRenderEventXml,
                needed,
                buf.as_mut_ptr().cast(),
                &mut written,
                &mut props,
            )
        };
        if ok != 0 {
            return Ok(decode_event_xml(&buf, written));
        }

        let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32;
        if code != ERROR_INSUFFICIENT_BUFFER {
            return Err(win_err("EvtRender", code));
        }
        // The event grew between the probe and the render: retry once, larger.
        needed = written;
    }

    Err("EvtRender kept reporting a growing buffer".to_string())
}

/// Decode the UTF-16 payload `EvtRender` wrote into `buf`.
///
/// The API reports a character count; the odd trailing byte of an unaligned
/// buffer is dropped, and a count larger than the allocation is clamped. Both are
/// cases the string helpers already handle, and neither may abort the scan.
fn decode_event_xml(buf: &[u8], used_bytes: u32) -> String {
    // `EvtRender` reports the used buffer size in BYTES, not characters. Treating it
    // as a character count silently halved the text.
    let clamped = (used_bytes as usize).min(buf.len());
    let mut units: Vec<u16> = Vec::with_capacity(clamped / 2);
    for chunk in buf[..clamped].chunks_exact(2) {
        units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    // `EvtRender` emits a NUL-terminated UTF-16 string, so the terminator ends the
    // text even when the reported length runs past it.
    from_wide(&units)
}

/// Query a channel and return up to `max` events, NEWEST FIRST, rendered as XML.
///
/// `xpath` is a full XPath query, e.g. `*[System[EventID=7045]]`.
/// `Err(text)` when the channel does not exist, is unreadable (not elevated), or
/// the query is malformed.
pub fn query(channel: &str, xpath: &str, max: usize) -> Result<Vec<RawEvent>, String> {
    if channel.is_empty() {
        return Err("empty channel name".to_string());
    }
    let want = max.min(MAX_EVENTS_HARD_CAP);
    if want == 0 {
        return Ok(Vec::new());
    }

    let path = wide(channel);
    let q = wide(xpath);
    let flags = EvtQueryChannelPath | EvtQueryReverseDirection;

    // SAFETY: a null session means "local machine". Both wide buffers are
    // NUL-terminated and outlive the call. A failed query returns a null handle,
    // which `OwnedEvt::new` turns into `None` before this function returns.
    let raw = unsafe { EvtQuery(0, path.as_ptr(), q.as_ptr(), flags) };
    let resultset = match OwnedEvt::new(raw) {
        Some(h) => h,
        None => {
            let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32;
            return Err(format!(
                "{}: {}",
                win_err("EvtQuery", code),
                "channel missing, not readable, or the query is malformed"
            ));
        }
    };

    let mut iter = EvtIter {
        resultset,
        batch: Vec::new(),
    };
    let mut out: Vec<RawEvent> = Vec::new();

    while out.len() < want {
        match iter.next_event()? {
            // The guard owns the handle for as long as it is alive here, so the render
            // below cannot outlive it. Nothing leaks: it is dropped at the end of this
            // arm, and the batch that produced it is refilled only on the next call.
            Some(event_handle) => {
                let xml = match render_event_xml(event_handle.raw()) {
                    Ok(x) => x,
                    // One unrenderable event must not discard the events already
                    // collected: skip it and keep going.
                    Err(_) => continue,
                };
                out.push(RawEvent { xml });
            }
            None => break,
        }
    }

    Ok(out)
}

/// Whether a channel exists and is readable.
///
/// Used to skip channels absent on this edition of Windows instead of recording a
/// spurious warning. A query that matches nothing is still a success: the empty
/// XPath matches every event the caller may read, so the only way this fails is a
/// genuine channel/permission problem.
pub fn channel_available(channel: &str) -> bool {
    query(channel, "*", 1).is_ok()
}

/// Format a Win32 failure with the module it came from, bounded and lossy.
fn win_err(api: &str, code: u32) -> String {
    let mut text = format!("{api} failed with Win32 error {code}");
    if text.len() > MAX_ERROR_TEXT {
        text.truncate(MAX_ERROR_TEXT);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_xpath_is_an_error_not_a_panic() {
        // A dangling bracket: the query parser rejects it. The important part is
        // that this returns `Err` rather than aborting the scan.
        let r = query(CHANNEL_SYSTEM, "*[System[EventID=", 5);
        assert!(r.is_err(), "malformed XPath must be reported as Err");
    }

    #[test]
    fn another_malformed_xpath_is_an_error() {
        assert!(query(CHANNEL_SYSTEM, "this is not xpath", 5).is_err());
    }

    #[test]
    fn non_existent_channel_is_an_error() {
        let r = query("IRScan-Channel-That-Does-Not-Exist/Operational", "*", 5);
        assert!(r.is_err(), "unknown channel must be reported as Err");
    }

    #[test]
    fn empty_channel_and_zero_max_are_handled() {
        assert!(query("", "*", 1).is_err());
        // Asking for nothing must not even open the channel.
        match query(CHANNEL_SYSTEM, "*", 0) {
            Ok(events) => assert!(events.is_empty()),
            Err(_) => panic!("a zero-event query should succeed with an empty vector"),
        }
    }

    #[test]
    fn system_channel_is_available() {
        assert!(
            channel_available(CHANNEL_SYSTEM),
            "the System channel exists on every Windows installation"
        );
    }

    #[test]
    fn made_up_channel_is_not_available() {
        assert!(!channel_available(
            "Microsoft-Windows-IRScan-No-Such-Provider/Operational"
        ));
    }

    #[test]
    fn query_returns_at_most_the_requested_max() {
        // Environment-independent: the assertion is about the cap, not contents.
        // An unreadable System channel is still not a test failure: the assertion is
        // about the cap, not about what happens to be in the log.
        if let Ok(events) = query(CHANNEL_SYSTEM, "*", 3) {
            assert!(events.len() <= 3, "max must be honoured");
        }
    }

    #[test]
    fn decode_treats_the_count_as_bytes_and_clamps_it() {
        // "Hi" is 0x48 0x00 0x69 0x00, plus one stray byte. The count is a BYTE
        // count, so 5 bytes is two characters and a leftover.
        let buf = [0x48u8, 0x00, 0x69, 0x00, 0xFF];
        assert_eq!(decode_event_xml(&buf, 5), "Hi");
        // A byte count larger than the buffer must clamp, not panic.
        assert_eq!(decode_event_xml(&buf, 99), "Hi");
        // A half character at the end is dropped rather than guessed at.
        assert_eq!(decode_event_xml(&buf, 3), "H");
        // The rendered XML is NUL-terminated, so decoding stops at the terminator
        // even when the reported length runs past it.
        let terminated = [0x48u8, 0x00, 0x00, 0x00, 0x69, 0x00];
        assert_eq!(decode_event_xml(&terminated, 6), "H");
        assert_eq!(decode_event_xml(&[], 0), "");
    }

    #[test]
    fn the_event_iterator_hands_out_an_owned_guard_not_a_bare_handle() {
        // This is the regression test for a silent false negative that emptied four
        // checks at once: the iterator used to return `ev.raw()`, and the next batch
        // refill dropped every guard - including the one whose handle the caller was
        // still rendering. `EvtRender` then failed with ERROR_INVALID_HANDLE and the
        // caller skipped the event, so a channel with events looked empty.
        //
        // The fix is a type, so the test asserts the type's presence in the signature:
        // `next_event` must not be able to produce a bare handle.
        let source = include_str!("events.rs");
        let signature_line = source
            .lines()
            .find(|l| l.contains("fn next_event("))
            .unwrap_or("");
        assert!(
            signature_line.contains("Option<OwnedEvt>"),
            "next_event must return the guard, not EVT_HANDLE: {signature_line}"
        );
        assert!(
            !signature_line.contains("EVT_HANDLE"),
            "a bare handle here is the defect: {signature_line}"
        );

        // And the caller must render through the guard rather than the raw value.
        assert!(
            source.contains("render_event_xml(event_handle.raw())"),
            "the render must go through the guard"
        );
    }

    #[test]
    fn zero_handle_is_not_wrapped() {
        assert!(OwnedEvt::new(0).is_none());
    }
}
