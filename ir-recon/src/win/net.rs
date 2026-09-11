//! Owning-PID endpoint tables: who is talking to (or listening for) the network.
//!
//! The value of listing TCP/UDP endpoints with their owning PID is that a host
//! running an agent that "screenshots and uploads" will, while active, hold an
//! outbound TCP connection or a UDP socket whose PID can be cross-referenced back
//! to the process table. `GetExtendedTcpTable`/`GetExtendedUdpTable` with the
//! dedicated owner classes give us that association with one call each (FR-7).
//!
//! Every byte-order subtlety is confined to `format_v4` and `map_tcp_state`, which
//! are pure; the FFI below them only moves bytes. `ERROR_INSUFFICIENT_BUFFER` on the
//! probe call is the *expected* flow, not an error (SR-4).

use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCPROW_OWNER_PID, MIB_UDPROW_OWNER_PID,
    TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::AF_INET;

use crate::model::ConnectionRecord;

/// Hard cap on endpoint rows offered to the report at once. A busy Windows
/// workstation rarely holds more than a few thousand; anything past this cap is cut
/// off, because half a million rows is noise, not triage (SR-4).
pub const MAX_CONNECTIONS: u32 = 65536;

/// First buffer guess in bytes. The probe call below normally replaces it with the
/// exact figure, so this only matters for the rare API version that does not answer
/// `ERROR_INSUFFICIENT_BUFFER`.
const INITIAL_BUFFER: u32 = 64 * 1024;

/// How many times to grow and retry when the table races ahead of the buffer.
/// Doubling from the probe size reaches megabytes within a handful of tries; past
/// that the host is hostile or the API is being misused, and an empty table is the
/// honest answer.
const GROW_ATTEMPTS: usize = 6;

/// Byte offset of the first row in either table: both open with a `u32` count.
const TABLE_HEADER: usize = 4;

/// Decode a 32-bit host-order IPv4 address into its four octets.
///
/// Windows returns addresses as host-order DWORDs, so `127.0.0.1` arrives as
/// `0x0100007F`. `to_le_bytes` yields the bytes in the order they appear in a dotted
/// quad — and pinning it to `to_le_bytes` rather than `to_ne_bytes` keeps the result
/// the same on a big-endian build host instead of silently reversing it.
fn v4_octets(addr_le: u32) -> [u8; 4] {
    addr_le.to_le_bytes()
}

/// Format a host-order IPv4 address and a network-order port as `"a.b.c.d:port"`.
///
/// The address is host order (see `v4_octets`); the port is not — the API writes the
/// 16-bit port in **network** byte order into the low half of a `u32`, so on this
/// little-endian host port 443 arrives as `0xBB01` and `to_be` recovers the 443. The
/// two opposite conventions inside one struct are why this is a tested function
/// rather than an inline `format!`.
pub fn format_v4(addr_le: u32, port_be: u16) -> String {
    let [a, b, c, d] = v4_octets(addr_le);
    format!("{a}.{b}.{c}.{d}:{}", port_be.to_be())
}

/// Map a `MIB_TCP_STATE` code to the lowercase token the report uses.
///
/// Matched on explicit numeric arms because the SDK constants are `i32`: a `const`
/// pattern would drag in the uninhabited negative gap. An unrecognised code renders
/// as hex, because a state the SDK does not describe is itself worth seeing spelled
/// out rather than folded into a known value.
fn map_tcp_state(dw: u32) -> String {
    match dw {
        1 => "closed".to_string(),
        2 => "listening".to_string(),
        3 => "syn-sent".to_string(),
        4 => "syn-received".to_string(),
        5 => "established".to_string(),
        6 => "fin-wait1".to_string(),
        7 => "fin-wait2".to_string(),
        8 => "close-wait".to_string(),
        9 => "closing".to_string(),
        10 => "last-ack".to_string(),
        11 => "time-wait".to_string(),
        12 => "delete-tcb".to_string(),
        other => format!("0x{other:x}"),
    }
}

/// Render one TCP row.
fn tcp_record(row: &MIB_TCPROW_OWNER_PID) -> ConnectionRecord {
    ConnectionRecord {
        protocol: "TCP",
        // The port fields are `u32` in the SDK but hold a 16-bit network-order
        // value; the cast is lossless for every value the API actually writes.
        local: format_v4(row.dwLocalAddr, row.dwLocalPort as u16),
        remote: format_v4(row.dwRemoteAddr, row.dwRemotePort as u16),
        state: map_tcp_state(row.dwState),
        pid: row.dwOwningPid,
    }
}

/// Render one UDP row.
///
/// UDP has no remote endpoint in this table shape, so the report uses the `*:*`
/// convention `netstat` itself adopts and a fixed literal state.
fn udp_record(row: &MIB_UDPROW_OWNER_PID) -> ConnectionRecord {
    ConnectionRecord {
        protocol: "UDP",
        local: format_v4(row.dwLocalAddr, row.dwLocalPort as u16),
        remote: "*:*".to_string(),
        state: "udp".to_string(),
        pid: row.dwOwningPid,
    }
}

/// Decode `n` rows of `T` out of a raw byte buffer, after the leading count.
///
/// Pure apart from one `read_unaligned`, and separate from both public functions so
/// the byte-walk is tested directly: the fixtures below feed it a hand-built table
/// and it never touches iphlpapi. A `Vec<u8>` carries no alignment guarantee, hence
/// `read_unaligned`.
fn rows_from_bytes<T: Copy>(
    buffer: &[u8],
    n: u32,
    make: impl Fn(&T) -> ConnectionRecord,
) -> Vec<ConnectionRecord> {
    let stride = std::mem::size_of::<T>();
    if stride == 0 {
        return Vec::new();
    }
    let want = (n as usize).min(MAX_CONNECTIONS as usize);
    let mut out = Vec::with_capacity(want);
    for index in 0..want {
        let Some(start) = TABLE_HEADER.checked_add(index.saturating_mul(stride)) else {
            break;
        };
        let Some(end) = start.checked_add(stride) else {
            break;
        };
        if end > buffer.len() {
            break;
        }
        // SAFETY: `start..end` was just proven to lie inside `buffer`, and `T` is a
        // plain-old-data struct whose size is `stride`. `read_unaligned` is required
        // because the buffer's alignment is whatever `Vec<u8>` chose.
        let row: T = unsafe { buffer.as_ptr().add(start).cast::<T>().read_unaligned() };
        out.push(make(&row));
    }
    out
}

/// Read the `dwNumEntries` count that opens either table.
fn entry_count(buffer: &[u8]) -> u32 {
    let Some(first) = buffer.get(0..4) else {
        return 0;
    };
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(first);
    u32::from_ne_bytes(bytes)
}

/// Active TCP connections with the owning PID (`TCP_TABLE_OWNER_PID_ALL`).
pub fn tcp_connections() -> Vec<ConnectionRecord> {
    let buffer = fetch_tcp_table(AF_INET as u32, TCP_TABLE_OWNER_PID_ALL as u32);
    rows_from_bytes::<MIB_TCPROW_OWNER_PID>(&buffer, entry_count(&buffer), tcp_record)
}

/// Active UDP endpoints with the owning PID (`UDP_TABLE_OWNER_PID`).
pub fn udp_endpoints() -> Vec<ConnectionRecord> {
    let buffer = fetch_udp_table(AF_INET as u32, UDP_TABLE_OWNER_PID as u32);
    rows_from_bytes::<MIB_UDPROW_OWNER_PID>(&buffer, entry_count(&buffer), udp_record)
}

/// Obtain a buffer holding one complete `GetExtendedTcpTable` answer.
///
/// Probe with a null buffer to learn the size, allocate, then fetch — retrying with
/// a larger buffer while the table keeps growing under us. An empty `Vec` is a valid
/// answer: a machine can legitimately have no TCP connections.
fn fetch_tcp_table(family: u32, class: u32) -> Vec<u8> {
    let mut size: u32 = 0;
    // SAFETY: a null table pointer with a valid size slot is the documented size
    // probe; nothing is written through the null pointer.
    let probe =
        unsafe { GetExtendedTcpTable(std::ptr::null_mut(), &mut size, 0, family, class as _, 0) };
    let mut buffer = initial_buffer(probe, size);
    let mut attempts = 0usize;
    loop {
        // SAFETY: `buffer` is a live `Vec<u8>` and its `len()` is the byte count the
        // API may write; `size` is a valid out-parameter updated on both outcomes.
        let rc = unsafe {
            GetExtendedTcpTable(
                buffer.as_mut_ptr().cast(),
                &mut size,
                0,
                family,
                class as _,
                0,
            )
        };
        if rc == 0 {
            // On success the row count inside the buffer is what bounds the walk
            // (`entry_count`), so the returned buffer needs no further trimming.
            return buffer;
        }
        if rc != ERROR_INSUFFICIENT_BUFFER {
            return Vec::new();
        }
        attempts += 1;
        if attempts >= GROW_ATTEMPTS {
            return Vec::new();
        }
        buffer.resize(size.max(buffer.len() as u32) as usize, 0u8);
    }
}

/// Obtain a buffer holding one complete `GetExtendedUdpTable` answer.
///
/// Same two-call shape as the TCP version; kept separate so a protocol-specific
/// class constant cannot be swapped by accident.
fn fetch_udp_table(family: u32, class: u32) -> Vec<u8> {
    let mut size: u32 = 0;
    // SAFETY: as for the TCP probe — null table plus a valid size slot.
    let probe =
        unsafe { GetExtendedUdpTable(std::ptr::null_mut(), &mut size, 0, family, class as _, 0) };
    let mut buffer = initial_buffer(probe, size);
    let mut attempts = 0usize;
    loop {
        // SAFETY: as for the TCP fetch — `buffer` is live for `len()` bytes.
        let rc = unsafe {
            GetExtendedUdpTable(
                buffer.as_mut_ptr().cast(),
                &mut size,
                0,
                family,
                class as _,
                0,
            )
        };
        if rc == 0 {
            return buffer;
        }
        if rc != ERROR_INSUFFICIENT_BUFFER {
            return Vec::new();
        }
        attempts += 1;
        if attempts >= GROW_ATTEMPTS {
            return Vec::new();
        }
        buffer.resize(size.max(buffer.len() as u32) as usize, 0u8);
    }
}

/// Size the working buffer from a probe result.
///
/// `ERROR_INSUFFICIENT_BUFFER` plus a populated `size` is the normal path; anything
/// else (including an API that answers zero) falls back to the initial guess so the
/// second call is not handed a zero-length buffer.
fn initial_buffer(probe: u32, size: u32) -> Vec<u8> {
    let chosen = if probe == ERROR_INSUFFICIENT_BUFFER && size > 0 {
        size
    } else {
        INITIAL_BUFFER
    };
    vec![0u8; chosen as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_address_formats_in_memory_order() {
        // 127.0.0.1 is stored as the DWORD 0x0100007F; its bytes spell 127,0,0,1.
        assert_eq!(format_v4(0x0100_007F, 0), "127.0.0.1:0");
    }

    #[test]
    fn any_address_formats_as_zeroes() {
        assert_eq!(format_v4(0, 0), "0.0.0.0:0");
    }

    #[test]
    fn private_range_formats_correctly() {
        // 192.168.1.5 -> host-order DWORD 0x0501A8C0.
        assert_eq!(format_v4(0x0501_A8C0, 0), "192.168.1.5:0");
    }

    #[test]
    fn port_is_byte_swapped_from_network_order() {
        // On the wire 443 is the bytes 0x01 0xBB; the API stores them straight into
        // the low half of the DWORD, so on this little-endian host the `u32` reads
        // 0xBB01 (and the DWORD's high half is zero). `to_be` recovers 443.
        assert_eq!(format_v4(0, 0xBB01), "0.0.0.0:443");
        // 47873 is the mirror image and must not collapse to the same string, or the
        // byte swap would be invisible.
        assert_eq!(format_v4(0, 0x01BB), "0.0.0.0:47873");
    }

    #[test]
    fn unknown_tcp_state_renders_hex_not_a_panic() {
        let row = MIB_TCPROW_OWNER_PID {
            dwState: 0xFFFF,
            dwLocalAddr: 0x0100_007F,
            dwLocalPort: 0xBB01, // 443 in network order, as the API stores it
            dwRemoteAddr: 0,
            dwRemotePort: 0,
            dwOwningPid: 42,
        };
        let rec = tcp_record(&row);
        assert_eq!(rec.state, "0xffff");
        assert_eq!(rec.local, "127.0.0.1:443");
        assert_eq!(rec.pid, 42);
    }

    #[test]
    fn known_states_map_to_tokens() {
        for (code, expected) in [
            (2u32, "listening"),
            (5u32, "established"),
            (11u32, "time-wait"),
            (12u32, "delete-tcb"),
        ] {
            let row = MIB_TCPROW_OWNER_PID {
                dwState: code,
                dwLocalAddr: 0,
                dwLocalPort: 0,
                dwRemoteAddr: 0,
                dwRemotePort: 0,
                dwOwningPid: 0,
            };
            assert_eq!(tcp_record(&row).state, expected, "state code {code}");
        }
    }

    #[test]
    fn udp_rows_are_owner_bound_datagrams() {
        let row = MIB_UDPROW_OWNER_PID {
            dwLocalAddr: 0x0100_007F,
            // 13090 is 0x3322 on the wire, so the DWORD's low half reads 0x2233.
            dwLocalPort: 0x2233,
            dwOwningPid: 7,
        };
        let rec = udp_record(&row);
        assert_eq!(rec.protocol, "UDP");
        assert_eq!(rec.local, "127.0.0.1:13090");
        assert_eq!(rec.remote, "*:*");
        assert_eq!(rec.state, "udp");
        assert_eq!(rec.pid, 7);
    }

    /// Build a table the way the API does: a `u32` count, then packed rows.
    fn table_bytes<T: Copy>(rows: &[T]) -> Vec<u8> {
        let stride = std::mem::size_of::<T>();
        let mut buf = vec![0u8; TABLE_HEADER + std::mem::size_of_val(rows)];
        buf[..4].copy_from_slice(&(rows.len() as u32).to_ne_bytes());
        for (i, row) in rows.iter().enumerate() {
            // SAFETY: `row` is a plain-old-data value of `stride` readable bytes.
            let bytes =
                unsafe { std::slice::from_raw_parts((row as *const T).cast::<u8>(), stride) };
            buf[TABLE_HEADER + i * stride..TABLE_HEADER + (i + 1) * stride].copy_from_slice(bytes);
        }
        buf
    }

    #[test]
    fn walks_a_hand_built_table_starting_after_the_header() {
        let rows = [
            MIB_TCPROW_OWNER_PID {
                dwState: 5,
                dwLocalAddr: 0x0100_007F,
                dwLocalPort: 0xBB01, // 443
                dwRemoteAddr: 0x0101_A8C0,
                dwRemotePort: 0x5000, // 80
                dwOwningPid: 100,
            },
            MIB_TCPROW_OWNER_PID {
                dwState: 2,
                dwLocalAddr: 0,
                dwLocalPort: 0,
                dwRemoteAddr: 0,
                dwRemotePort: 0,
                dwOwningPid: 4,
            },
        ];
        let buf = table_bytes(&rows);
        let parsed = rows_from_bytes::<MIB_TCPROW_OWNER_PID>(&buf, entry_count(&buf), tcp_record);
        assert_eq!(parsed.len(), 2, "both rows must be decoded");
        // Row 0 must not be the header reinterpreted as a row: the header count is
        // 2, which would surface as state "listening" / pid 0 if the offset were wrong.
        assert_eq!(parsed[0].state, "established");
        assert_eq!(parsed[0].pid, 100);
        assert_eq!(parsed[0].remote, "192.168.1.1:80");
        assert_eq!(parsed[1].state, "listening");
        assert_eq!(parsed[1].pid, 4);
    }

    #[test]
    fn a_count_larger_than_the_buffer_is_clamped() {
        // A hostile host can claim more rows than it sent; the walk must stop at
        // the buffer rather than reading past it.
        let rows = [MIB_UDPROW_OWNER_PID {
            dwLocalAddr: 0,
            dwLocalPort: 0,
            dwOwningPid: 9,
        }];
        let buf = table_bytes(&rows);
        let parsed = rows_from_bytes::<MIB_UDPROW_OWNER_PID>(&buf, u32::MAX, udp_record);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].pid, 9);
    }

    #[test]
    fn empty_and_truncated_buffers_are_safe() {
        assert!(rows_from_bytes::<MIB_TCPROW_OWNER_PID>(&[], 5, tcp_record).is_empty());
        assert_eq!(entry_count(&[]), 0);
        // A header with no room for a row yet must not panic or invent a row.
        let short = vec![3u8, 0, 0, 0, 1, 2, 3];
        assert!(
            rows_from_bytes::<MIB_TCPROW_OWNER_PID>(&short, entry_count(&short), tcp_record)
                .is_empty()
        );
    }
}
