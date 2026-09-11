//! Service and kernel-driver enumeration through the Service Control Manager.
//!
//! WMI (`Win32_Service`) is deliberately avoided: it needs a COM apartment, it is
//! slow, and — the deciding reason — an attacker who knows the tool exists can
//! break it from user mode. `EnumServicesStatusExW` is the same source the Service
//! Control Manager itself uses, so anything the SCM will start, this sees (FR-3).
//!
//! The record is built for triage, not for completeness: `image_path`, `account`
//! and `start_mode` come from the service's own registry key, because the input
//! filter check (FR-12) and the user-writable-path check (FR-13) both need the real
//! on-disk path, and `SERVICE_STATUS_PROCESS` does not carry a start type at all.
//!
//! FFI rules applied here (docs/architecture.md section 6): size-then-allocate with
//! a bounded retry for `ERROR_MORE_DATA`, every return code checked, and the SCM
//! handle released through a guard on every path — including the early returns.

use windows_sys::Win32::Foundation::ERROR_MORE_DATA;
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, ENUM_SERVICE_STATUS_PROCESSW,
    SC_ENUM_PROCESS_INFO, SC_HANDLE, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_DRIVER,
    SERVICE_STATE_ALL, SERVICE_WIN32,
};

use super::reg::{self, RootKey};
use crate::model::{ServiceRecord, MAX_STRING};
use crate::text::sanitize;

/// Hard cap on services+drivers returned. A Windows 10 workstation has a few
/// hundred; a value four orders of magnitude larger than reality still bounds the
/// allocation on a host that is deliberately lying about its service count (FR-3).
pub const MAX_SERVICES: usize = 8192;

/// First buffer guess in bytes. Big enough for most hosts so the common case takes
/// one call plus one grow, rather than repeatedly re-querying.
const INITIAL_BUFFER: u32 = 64 * 1024;

/// Bytes allowed when the SCM keeps reporting a larger size between calls. Four
/// retries of at least doubling from 64 KiB reaches well past a fully populated
/// 8192-entry answer, so anything beyond this bound is pathological.
const GROW_ATTEMPTS: usize = 4;

/// RAII guard for the SCM handle. `CloseServiceHandle` must run on the error paths
/// too, and a guard is the only way to make that unconditional.
struct OwnedScManager(SC_HANDLE);

impl Drop for OwnedScManager {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful `OpenSCManagerW`, has not been
        // closed elsewhere, and this guard is its unique owner. Closing the SCM
        // handle does not stop or alter any service.
        unsafe {
            let _ = CloseServiceHandle(self.0);
        }
    }
}

/// Service state code (`dwCurrentState`) -> stable lowercase token for the report.
///
/// Pure so the mapping is unit-testable without a live host. Matched on the numeric
/// codes (stopped=1, start-pending=2, stop-pending=3, running=4, continue-pending=5,
/// pause-pending=6, paused=7) so the table is self-contained; the trailing arm keeps
/// an undefined code from silently becoming a known state.
pub fn map_state(dw: u32) -> &'static str {
    match dw {
        1 => "stopped",
        2 => "starting",
        3 => "stopping",
        4 => "running",
        5 => "continue-pending",
        6 => "pause-pending",
        7 => "paused",
        _ => "unknown",
    }
}

/// Service start type -> stable lowercase token used by the report.
///
/// The input is the `Start` registry value (`REG_DWORD`), not a field of the SCM
/// answer: `SERVICE_STATUS_PROCESS` has no start type, and asking the SCM for one
/// with `QueryServiceConfigW` would cost an extra round trip per service for data
/// the same key we already open holds. Codes: boot=0, system=1, auto=2, manual=3,
/// disabled=4. Boot (0) and disabled (4) mean opposite things but differ by one
/// nibble, so a typo would invert a finding's meaning and the table has its own test.
pub fn map_start_type(dw: u32) -> &'static str {
    match dw {
        0 => "boot",
        1 => "system",
        2 => "auto",
        3 => "manual",
        4 => "disabled",
        _ => "unknown",
    }
}

/// Render a state/start-type code the tables above do not know.
///
/// Separate from `map_state` so "unknown value" still carries the raw code: the hex
/// form is what tells an analyst whether the host is running something the SDK does
/// not describe, which is exactly the case worth looking at.
fn hex_code(dw: u32) -> String {
    format!("0x{dw:x}")
}

/// One decoded entry, before the registry lookups turn it into a full record.
#[derive(Debug, PartialEq, Eq)]
struct RawEntry {
    name: String,
    display_name: String,
    state: String,
    is_driver: bool,
}

/// The registry key every service stores its configuration under.
fn service_key(name: &str) -> String {
    format!(r"SYSTEM\CurrentControlSet\Services\{name}")
}

/// The `ImagePath` a service actually runs, expanded.
///
/// The registry is the second source here on purpose: the SCM answer carries no
/// path, and a missing value is normal (`None` becomes an empty string so the record
/// shape stays uniform rather than losing the entry).
fn image_path(name: &str) -> String {
    match reg::get_string(RootKey::Hklm, &service_key(name), "ImagePath") {
        // `get_string` already expanded a REG_EXPAND_SZ; a plain REG_SZ can carry a
        // literal `%SystemRoot%` from a sloppy installer, so expand once more. A
        // second pass over an already-expanded path is harmless.
        Some(raw) => sanitize(&super::expand(&raw), MAX_STRING),
        None => String::new(),
    }
}

/// The account a service runs as, from its own registry key (`ObjectName`).
///
/// Read here rather than from the SCM because the batch enum does not carry it; an
/// absent value (`LocalSystem` is only implied by omission) becomes an empty string.
fn account_of(name: &str) -> String {
    reg::get_string(RootKey::Hklm, &service_key(name), "ObjectName")
        .map(|s| sanitize(&s, MAX_STRING))
        .unwrap_or_default()
}

/// The configured start type, from the service key's `Start` DWORD.
///
/// This is the second half of the answer the SCM cannot give: `SERVICE_STATUS_PROCESS`
/// carries the *current state* but not the start type, and the start type is what
/// tells an analyst whether a driver boots with the kernel or was configured by hand.
fn start_mode_of(name: &str) -> String {
    match reg::get_u64(RootKey::Hklm, &service_key(name), "Start") {
        Some(code) => {
            let code = code as u32;
            match map_start_type(code) {
                "unknown" => sanitize(&hex_code(code), MAX_STRING),
                known => known.to_string(),
            }
        }
        None => String::new(),
    }
}

/// Decode one NUL-terminated UTF-16 string out of the enumeration buffer.
///
/// The SCM hands back pointers into the same buffer we own; the slice is bounded by
/// the buffer end, so a missing terminator (hostile or truncated answer) stops at
/// the end instead of running off into unrelated memory.
///
/// SAFETY (all calls): `ptr` must either be null or point somewhere inside `buf`'s
/// allocation; the scan is clamped to `buf`'s end regardless.
unsafe fn read_wide(buf: &[u8], ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let start = ptr as *const u8;
    let base = buf.as_ptr();
    let end = base.wrapping_add(buf.len());
    // Pointer comparison within the same allocation: equal to or past the end means
    // there is nothing to read, and a pointer below the base does not belong to this
    // buffer at all.
    if start < base || start >= end {
        return String::new();
    }
    let avail = (end as usize - start as usize) / 2;
    // SAFETY: `start` is inside the buffer and `start + avail * 2 <= end`, so `avail`
    // UTF-16 units are addressable from `ptr`. The slice never escapes this function.
    let units: &[u16] = unsafe { std::slice::from_raw_parts(ptr, avail) };
    let len = units.iter().position(|c| *c == 0).unwrap_or(units.len());
    super::from_wide_len(units, len)
}

/// Walk a filled buffer as an array of `ENUM_SERVICE_STATUS_PROCESSW`.
///
/// Pure apart from the pointer reads, so the fixtures in this module can drive it
/// without a live SCM. `returned` is trusted only up to what the buffer can hold: a
/// host that claims more entries than it sent gets clamped, not read past (SR-4).
fn parse_buffer(buf: &[u8], returned: u32, cap: usize) -> Vec<RawEntry> {
    let stride = std::mem::size_of::<ENUM_SERVICE_STATUS_PROCESSW>();
    if stride == 0 {
        return Vec::new();
    }
    let want = (returned as usize).min(cap).min(buf.len() / stride);
    let mut out = Vec::with_capacity(want);
    for index in 0..want {
        let offset = index * stride;
        let Some(chunk) = buf.get(offset..offset + stride) else {
            break;
        };
        // SAFETY: the buffer was filled by `EnumServicesStatusExW` (or by the test
        // fixtures) and `chunk` is exactly one entry's worth of bytes at an entry
        // boundary. `read_unaligned` is required because a `Vec<u8>` allocation
        // carries no `align_of::<ENUM_SERVICE_STATUS_PROCESSW>()` guarantee.
        let entry: ENUM_SERVICE_STATUS_PROCESSW = unsafe {
            chunk
                .as_ptr()
                .cast::<ENUM_SERVICE_STATUS_PROCESSW>()
                .read_unaligned()
        };
        // SAFETY: both pointers came out of the same API answer; `read_wide` bounds
        // every read at the buffer end even if they point at nonsense.
        let name = unsafe { read_wide(buf, entry.lpServiceName) };
        // SAFETY: same invariant as `lpServiceName` above.
        let display_name = unsafe { read_wide(buf, entry.lpDisplayName) };

        // `SERVICE_STATUS_PROCESS` carries the current state but no start type;
        // the start type is read from the registry in `to_record`.
        let status = entry.ServiceStatusProcess;
        let state_code = status.dwCurrentState;

        out.push(RawEntry {
            name: sanitize(&name, MAX_STRING),
            display_name: sanitize(&display_name, MAX_STRING),
            state: match map_state(state_code) {
                "unknown" => sanitize(&hex_code(state_code), MAX_STRING),
                known => known.to_string(),
            },
            // A single query asks for `SERVICE_WIN32 | SERVICE_DRIVER`, so the two
            // halves are told apart by the entry's own type mask (FR-3).
            is_driver: status.dwServiceType & SERVICE_DRIVER != 0,
        });
    }
    out
}

/// Turn one decoded entry into the record the report carries.
///
/// The two registry reads live here rather than in `parse_buffer` so the byte-level
/// decode stays testable without any host access.
fn to_record(raw: RawEntry) -> ServiceRecord {
    let image_path = image_path(&raw.name);
    let account = account_of(&raw.name);
    let start_mode = start_mode_of(&raw.name);
    ServiceRecord {
        name: raw.name,
        display_name: raw.display_name,
        state: raw.state,
        start_mode,
        account,
        image_path,
        is_driver: raw.is_driver,
    }
}

/// Every service and kernel driver the SCM knows about.
///
/// `Err(text)` only when the SCM itself cannot be opened (typically: not elevated).
/// An individual service whose registry key is unreadable is still reported, with
/// an empty `image_path` — dropping it would hide exactly the kind of entry an
/// attacker would prefer the tool not to show.
pub fn enum_services() -> Result<Vec<ServiceRecord>, String> {
    // SAFETY: a null machine name means the local SCM; the database name is likewise
    // null (the active database); `SC_MANAGER_ENUMERATE_SERVICE` is the read-only
    // access right `EnumServicesStatusExW` needs.
    let raw = unsafe {
        OpenSCManagerW(
            std::ptr::null(),
            std::ptr::null(),
            SC_MANAGER_ENUMERATE_SERVICE,
        )
    };
    if raw.is_null() {
        return Err(format!(
            "OpenSCManagerW failed: {}. Run elevated for a complete report.",
            super::last_error()
        ));
    }
    let scm = OwnedScManager(raw);

    // Start from a guess; the first call reports the real size in `needed` and the
    // loop below grows to it. Starting non-empty means a host that answers
    // `ERROR_MORE_DATA` without a size still has somewhere to write.
    let mut buffer = vec![0u8; INITIAL_BUFFER as usize];
    let mut needed: u32 = 0;
    let mut returned: u32 = 0;
    let mut resume: u32 = 0;

    let mut attempt = 0usize;
    loop {
        // SAFETY: `scm` owns a live SCM handle; the query type is fixed at the only
        // shape this module understands (`SC_ENUM_PROCESS_INFO`, which makes the
        // entries carry `SERVICE_STATUS_PROCESS`); both masks are valid; `buffer` is
        // a live `Vec<u8>` of exactly `len()` bytes, and the three out-parameters
        // are valid stack slots.
        let ok = unsafe {
            EnumServicesStatusExW(
                scm.0,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32 | SERVICE_DRIVER,
                SERVICE_STATE_ALL,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                &mut needed,
                &mut returned,
                &mut resume,
                std::ptr::null(),
            )
        };

        if ok != 0 {
            break;
        }
        let err = std::io::Error::last_os_error();
        // `ERROR_MORE_DATA` is the documented "buffer too small, here is the size"
        // answer; anything else is a genuine failure.
        if err.raw_os_error() != Some(ERROR_MORE_DATA as i32) || attempt >= GROW_ATTEMPTS {
            return Err(format!("EnumServicesStatusExW failed: {err}"));
        }
        attempt += 1;
        // Grow to the larger of the reported need and what we already hold, so a
        // host that reports the same size twice still makes progress and the loop
        // terminates at `GROW_ATTEMPTS`.
        buffer = vec![0u8; needed.max(buffer.len() as u32) as usize];
    }

    let entries = parse_buffer(&buffer, returned, MAX_SERVICES);
    Ok(entries
        .into_iter()
        .take(MAX_SERVICES)
        .map(to_record)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_the_states_the_report_names() {
        // Numeric codes, because `map_state` owns its table rather than depending on
        // SDK constants the compiler would then flag as unused.
        assert_eq!(map_state(4), "running");
        assert_eq!(map_state(1), "stopped");
        assert_eq!(map_state(2), "starting");
        assert_eq!(map_state(3), "stopping");
        assert_eq!(map_state(7), "paused");
    }

    #[test]
    fn maps_every_start_type() {
        // The registry `Start` codes, in order.
        assert_eq!(map_start_type(0), "boot");
        assert_eq!(map_start_type(1), "system");
        assert_eq!(map_start_type(2), "auto");
        assert_eq!(map_start_type(3), "manual");
        assert_eq!(map_start_type(4), "disabled");
    }

    #[test]
    fn unknown_codes_fall_back_to_hex_not_a_panic() {
        // 0xEEEE is not a documented state and is not a start type; both must render
        // as data, because an undocumented value is itself the finding.
        assert_eq!(map_state(0xEEEE), "unknown");
        assert_eq!(map_start_type(0xEEEE), "unknown");
        assert_eq!(hex_code(0xEEEE), "0xeeee");
        assert_eq!(hex_code(0), "0x0");
    }

    #[test]
    fn start_type_zero_is_boot_not_disabled() {
        // The one pair in this file where a table typo inverts the meaning.
        assert_ne!(map_start_type(0), "disabled");
        assert_eq!(map_start_type(0), "boot");
        assert_eq!(map_start_type(4), "disabled");
    }

    #[test]
    fn parse_uses_hex_when_a_code_is_undefined() {
        let raw = parse_one_entry(SERVICE_WIN32, 0x7FFF);
        assert_eq!(raw.state, "0x7fff");
    }

    /// Build a one-entry answer, then decode it through `parse_buffer`.
    ///
    /// The buffer holds the entry at byte 0 followed by a UTF-16 pool; the entry's
    /// string pointers are absolute, so they are patched in after the pool's final
    /// address is known.
    fn parse_one_entry(service_type: u32, state: u32) -> RawEntry {
        let stride = std::mem::size_of::<ENUM_SERVICE_STATUS_PROCESSW>();
        let mut strings: Vec<u16> = Vec::new();
        strings.extend("Spooler".encode_utf16());
        strings.push(0);
        let display_off = strings.len();
        strings.extend("Print Spooler".encode_utf16());
        strings.push(0);
        let pool_bytes = strings.len() * 2;

        let mut buf = vec![0u8; stride + pool_bytes];
        let base = buf.as_ptr() as usize;
        let pool = stride;
        for (i, unit) in strings.iter().enumerate() {
            let bytes = unit.to_le_bytes();
            buf[pool + i * 2] = bytes[0];
            buf[pool + i * 2 + 1] = bytes[1];
        }

        let entry = ENUM_SERVICE_STATUS_PROCESSW {
            lpServiceName: (base + pool) as *mut u16,
            lpDisplayName: (base + pool + display_off * 2) as *mut u16,
            ServiceStatusProcess: windows_sys::Win32::System::Services::SERVICE_STATUS_PROCESS {
                dwServiceType: service_type,
                dwCurrentState: state,
                dwProcessId: 1234,
                ..Default::default()
            },
        };
        // SAFETY: `entry` is a plain-old-data value whose byte image is `stride`
        // bytes long, which is exactly the room the buffer reserves.
        let image =
            unsafe { std::slice::from_raw_parts(std::ptr::addr_of!(entry) as *const u8, stride) };
        buf[..stride].copy_from_slice(image);

        let mut parsed = parse_buffer(&buf, 1, MAX_SERVICES);
        assert_eq!(parsed.len(), 1, "the single entry must decode");
        parsed.pop().unwrap_or(RawEntry {
            name: String::new(),
            display_name: String::new(),
            state: String::new(),
            is_driver: false,
        })
    }

    #[test]
    fn parses_a_win32_service_entry() {
        let raw = parse_one_entry(SERVICE_WIN32, 4);
        assert_eq!(raw.name, "Spooler");
        assert_eq!(raw.display_name, "Print Spooler");
        assert_eq!(raw.state, "running");
        assert!(
            !raw.is_driver,
            "SERVICE_WIN32 must not be flagged as a driver"
        );
    }

    #[test]
    fn parses_a_kernel_driver_entry() {
        // A driver entry is told apart by its type mask (FR-3). The start type is not
        // part of the SCM answer, so only the driver flag is asserted from the parse.
        let raw = parse_one_entry(
            windows_sys::Win32::System::Services::SERVICE_KERNEL_DRIVER,
            4,
        );
        assert!(
            raw.is_driver,
            "SERVICE_KERNEL_DRIVER must be flagged as a driver"
        );
    }

    #[test]
    fn a_buffer_claiming_more_entries_than_it_holds_is_clamped() {
        // A hostile or buggy host can report a larger count than the buffer holds.
        // The walk must stop at the buffer, not read past it.
        let buf = vec![0u8; std::mem::size_of::<ENUM_SERVICE_STATUS_PROCESSW>() * 2];
        let parsed = parse_buffer(&buf, u32::MAX, MAX_SERVICES);
        assert_eq!(parsed.len(), 2);
        // Null string pointers must not produce garbage names, and the all-zero
        // StatusProcess decodes as state 0, which is *not* a documented state and so
        // must surface as hex rather than being guessed at.
        assert_eq!(parsed[0].name, "");
        assert_eq!(parsed[0].state, "0x0");
    }

    #[test]
    fn empty_and_truncated_buffers_are_safe() {
        assert!(parse_buffer(&[], 0, MAX_SERVICES).is_empty());
        // A buffer too short for even one entry must not panic or invent one.
        assert!(parse_buffer(&[0u8; 4], 5, MAX_SERVICES).is_empty());
    }

    #[test]
    fn the_live_host_has_a_service_list() {
        // Proves the buffer walk works against a real SCM answer, not just a fixture
        // (FR-3). SERVICE_WIN32 alone is always dozens of entries on Windows, so a
        // failure here means the enumeration regressed.
        match enum_services() {
            Ok(list) => {
                assert!(
                    list.len() > 10,
                    "only {} services enumerated - the buffer walk is wrong",
                    list.len()
                );
                assert!(
                    list.iter().any(|s| !s.name.is_empty()),
                    "service names came back empty"
                );
                assert!(
                    list.iter().any(|s| !s.start_mode.is_empty()),
                    "no service reported a start mode - the registry read is broken"
                );
            }
            Err(text) => {
                // Only "the SCM could not be opened" is acceptable, and it must name
                // the API so the warning is actionable.
                assert!(text.contains("OpenSCManagerW"), "unexpected error: {text}");
            }
        }
    }
}
