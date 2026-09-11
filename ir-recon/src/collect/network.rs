//! Network endpoint triage (FR-7, FR-13).
//!
//! The tables come from [`crate::win::net`]; this module turns each row into a
//! finding, a haystack or a raw line. This is the collector that answers the
//! question the user actually asked: *is something on this machine talking to the
//! internet right now*. A monitoring agent that screenshots and uploads has, while
//! active, an `ESTABLISHED` connection with an owning PID, and that PID joins back
//! to the process table the process collector populated (which is why `processes`
//! runs first in the fixed collector order).
//!
//! Three rules, all deliberately narrow:
//!
//! * an **established connection to a public address whose owner is weakly
//!   provenance'd** - the binary lives somewhere a standard user can write, or is
//!   unsigned, or the process has already exited (a socket outliving its owner is
//!   itself evidence);
//! * a **listener on a distinctive remote-control port**, which means this machine
//!   accepts inbound remote sessions;
//! * a **public connection to a privileged port from a user-writable binary**,
//!   which is the shape of an agent reaching a C2 on a well-known port.
//!
//! Both tables are read once and recorded in full: absence of findings is not
//! absence of connections, and the raw appendix is what lets a human check the
//! negative. Nothing here opens a socket, resolves a name or sends a packet.

use crate::collect::{CollectError, Collector};
use crate::model::{ConnectionRecord, Finding, HaystackKind, ScanContext, Severity};
use crate::rules::{is_private_ip, is_user_writable, port_label};
use crate::text::sanitize;
use crate::win::net::{tcp_connections, udp_endpoints};

/// Cap on connections classified. `win::net` already caps its own tables; this is
/// the second, cheaper bound so a hostile host cannot make the classify loop the
/// slowest part of the scan.
pub const MAX_CLASSIFIED: usize = 65536;

/// Ports at or below this are privileged on every operating system. An outbound
/// connection to one from a writable binary is unusual enough to report: legitimate
/// software almost always uses 443/80/8080 or a product-specific high port.
pub const PRIVILEGED_PORT_MAX: u16 = 1024;

/// Split an `address:port` endpoint into its two halves.
///
/// Handles the three shapes the tables produce: `1.2.3.4:443`, the bracketed IPv6
/// form `[::1]:80` (the brackets exist precisely so the colons inside the address
/// are not mistaken for the separator), and `0.0.0.0:0`. A host with no colon is not
/// an endpoint either.
///
/// The bracket form is *required* rather than inferred for IPv6: an unbracketed
/// `2001:db8::1:443` cannot be split without guessing where the address ends, and a
/// guess here would attribute the connection to the wrong port.
pub fn split_endpoint(endpoint: &str) -> Option<(String, u16)> {
    let s = endpoint.trim();
    if s.is_empty() {
        return None;
    }
    // `rfind` because an IPv6 address contains colons; the separator is the last one.
    let idx = s.rfind(':')?;
    // A colon at index 0 is not a separator (`:80` has no host), and a trailing colon
    // (`1.2.3.4:`) has no port.
    if idx == 0 || idx == s.len() - 1 {
        return None;
    }
    let host = s[..idx].trim();
    let port_text = s[idx + 1..].trim();
    if host.is_empty() {
        return None;
    }
    if host == "*" {
        return None;
    }
    if host.contains(':') && !host.starts_with('[') {
        // Unbracketed IPv6: ambiguous, so refuse rather than mis-attribute the port.
        return None;
    }
    let host = host.trim_matches(['[', ']']).trim();
    if host.is_empty() {
        return None;
    }
    let port = match port_text.parse::<u16>() {
        Ok(p) => p,
        Err(_) => return None,
    };
    Some((host.to_string(), port))
}

/// Port of a remote endpoint, or 0 when there is none (`*:*` on a UDP row).
pub fn port_of(remote: &str) -> u16 {
    match split_endpoint(remote) {
        Some((_, port)) => port,
        None => 0,
    }
}

/// Is `remote` an address on the public internet?
///
/// Everything that cannot be a public destination is `false`: an empty string, the
/// wildcards, and anything [`crate::rules::is_private_ip`] classifies as private -
/// which already covers loopback, link-local, the RFC1918 ranges and unparseable
/// junk. Delegating to `rules` keeps one definition of "private" in the crate.
///
/// The address is unwrapped by [`split_endpoint`] first, because `is_private_ip`
/// would mis-read a bracketed IPv6 literal such as `[::1]`.
pub fn is_public_remote(remote: &str) -> bool {
    let trimmed = remote.trim();
    // A wildcard endpoint (`*:*`) is not a destination at all, so it is refused
    // before the split and the raw string never reaches the address classifier.
    if trimmed.is_empty() || trimmed.contains('*') {
        return false;
    }
    let address = match split_endpoint(trimmed) {
        Some((host, _)) => host,
        // Not an endpoint shape: classify the raw text instead of dropping it, so a
        // bare address still gets an answer.
        None => trimmed.to_string(),
    };
    let address = address.trim();
    if address.is_empty() || address == "*" {
        return false;
    }
    if address == "::1" || address.eq_ignore_ascii_case("localhost") {
        return false;
    }
    !is_private_ip(address)
}

/// Severity for one connection row.
///
/// `public` is "the remote end is on the public internet" and `suspicious_owner` is
/// "the owning process is weakly provenance'd" (user-writable, unsigned, or gone).
/// Both are required: a public connection from a signed binary in `System32` is
/// ordinary software, and a local connection from a writable binary is ordinary IPC.
///
/// The state gate is what separates a live session from an attempt: `ESTABLISHED`
/// is `High`, a `SYN_SENT` from the same process is `Med`. Listener states return
/// `None` because inbound listeners belong to the port rule, not this one.
pub fn connection_severity(state: &str, public: bool, suspicious_owner: bool) -> Option<Severity> {
    if !suspicious_owner || !public {
        return None;
    }
    match state.to_ascii_uppercase().as_str() {
        "ESTABLISHED" => Some(Severity::High),
        "LISTEN" | "LISTENING" | "BOUND" => None,
        // Anything else that is public and weakly owned gets a look: `win::net`
        // renders unknown state codes as hex, and an unrecognised state is exactly
        // when a human should read the row.
        _ => Some(Severity::Med),
    }
}

/// One stable, readable line per endpoint for the RAW DATA appendix.
///
/// Fixed column widths so the table is scannable in a monospace report and diffs
/// cleanly between two scans of an unchanged host.
pub fn describe(r: &ConnectionRecord) -> String {
    format!(
        "{:<4} {:<24} -> {:<24} {:<12} pid {}",
        r.protocol, r.local, r.remote, r.state, r.pid
    )
}

/// The owner's name and image path, as the finding prints them.
///
/// A pid with no entry in the process table means the socket outlived its owner.
/// That is evidence, not a lookup failure, so it is labelled rather than rendered as
/// an empty field that would read like "no owner".
fn owner_lines(ctx: &ScanContext, pid: u32) -> (String, String) {
    let Some(p) = ctx.processes.get(&pid) else {
        return (
            "<process has exited>".to_string(),
            "<unavailable: the owning process is gone>".to_string(),
        );
    };
    let name = if p.name.is_empty() {
        "<unnamed>".to_string()
    } else {
        p.name.clone()
    };
    let path = match p.path.as_deref() {
        Some(v) if !v.as_os_str().is_empty() => {
            sanitize(&v.to_string_lossy(), crate::model::MAX_STRING)
        }
        _ => String::new(),
    };
    let path = if path.is_empty() {
        "<none reported>".to_string()
    } else {
        path
    };
    (name, path)
}

/// Is this connection's owning process weakly provenance'd?
///
/// A process absent from the table counts as suspicious: the socket survived its
/// owner, which is how a short-lived beacon looks between runs, and it also means
/// nothing about the binary was verified. A user-writable image path or an explicit
/// untrusted signature counts for the same reasons the process collector reports
/// them.
fn suspicious_owner(ctx: &ScanContext, pid: u32) -> bool {
    let Some(p) = ctx.processes.get(&pid) else {
        return true;
    };
    if p.signature_trusted == Some(false) {
        return true;
    }
    match p.path.as_deref().and_then(|v| v.to_str()) {
        Some(path) => is_user_writable(path),
        None => false,
    }
}

/// Enumerates TCP and UDP endpoints into the context and classifies them.
pub struct NetworkCollector;

impl Collector for NetworkCollector {
    fn name(&self) -> &'static str {
        "network"
    }

    fn run(&self, ctx: &mut ScanContext) -> Result<(), CollectError> {
        let mut table: Vec<String> = Vec::new();
        let mut rows: Vec<ConnectionRecord> = Vec::new();

        // Neither call can fail: `win::net` reports an unavailable table as an empty
        // one. That trade is deliberate - a host with no reachable TCP/IP stack still
        // produces a complete report, with this section empty and a warning.
        rows.extend(tcp_connections());
        rows.extend(udp_endpoints());

        if rows.is_empty() {
            ctx.warn("network enumeration returned no endpoints (is the TCP/IP stack up?)");
        }
        if rows.len() > MAX_CLASSIFIED {
            ctx.warn(format!(
                "network: {} endpoints found; only the first {} were examined",
                rows.len(),
                MAX_CLASSIFIED
            ));
        }

        for r in rows.into_iter().take(MAX_CLASSIFIED) {
            let port = port_of(&r.remote);
            // A labelled port is worth recording as a haystack in its own right: it is
            // the one place the port number appears next to a human-readable product
            // class, and the report reads the port table from the same source.
            if let Some(label) = port_label(port) {
                ctx.note(
                    HaystackKind::Port,
                    format!("{label}:{port}"),
                    format!("endpoint pid {}", r.pid),
                );
            }

            classify(ctx, &r);
            table.push(describe(&r));
            ctx.connections.push(r);
        }

        // Sorted, because the kernel does not promise to return its tables in the same
        // order twice and the report has to diff cleanly between runs.
        table.sort();
        ctx.raw_section("NETWORK ENDPOINTS", table);
        Ok(())
    }
}

/// Apply the FR-7 / FR-13 policy to one endpoint and push anything it warrants.
///
/// The three rules are independent rather than else-if: a listener on 3389 and a
/// user-writable binary connecting to port 443 are different problems, and a rule
/// ordering that suppressed one of them would hide half the picture.
fn classify(ctx: &mut ScanContext, r: &ConnectionRecord) {
    let (name, path) = owner_lines(ctx, r.pid);
    let suspicious = suspicious_owner(ctx, r.pid);
    let public = is_public_remote(&r.remote);
    let port = port_of(&r.remote);

    // Rule 1: a live connection to the public internet from a process we cannot
    // vouch for. This is the finding the reported symptom is about.
    if let Some(sev) = connection_severity(&r.state, public, suspicious) {
        let state_label = if r.state.trim().is_empty() {
            "connection".to_string()
        } else {
            r.state.to_uppercase()
        };
        ctx.add(
            Finding::new(
                sev,
                "network",
                format!(
                    "{state_label} to {} held by {} (pid {})",
                    r.remote, name, r.pid
                ),
            )
            .evidence(format!("protocol: {}", r.protocol))
            .evidence(format!("local endpoint: {}", r.local))
            .evidence(format!("remote endpoint: {}", r.remote))
            .evidence(format!("state: {}", r.state))
            .evidence(format!("owning process: {name} (pid {})", r.pid))
            .evidence(format!("image path: {path}"))
            .evidence(
                "the owning process is weakly provenance'd: it runs from a user-writable path, \
                 is unsigned, or has already exited while its socket survived",
            )
            .remediation(
                "Identify the remote address and port before closing anything; a live upload \
                 session is the strongest evidence this scan can produce.",
            )
            .remediation(
                "Disconnect the machine from the network to stop the session, then work from the \
                 report - the socket is gone once the process exits.",
            ),
        );
    }

    // Rule 2: a listener on a port only remote-control software uses. Med, not High:
    // an open port means the machine *accepts* remote sessions, which is a
    // configuration fact, not proof that a session happened.
    if r.state.to_ascii_uppercase().contains("LISTEN") {
        if let Some(label) = port_label(port) {
            ctx.add(
                Finding::new(
                    Severity::Med,
                    "network",
                    format!(
                        "{label} is listening on port {port} (pid {}, {name})",
                        r.pid
                    ),
                )
                .evidence(format!("local endpoint: {}", r.local))
                .evidence(format!("protocol: {}", r.protocol))
                .evidence(format!("owning process: {name} (pid {})", r.pid))
                .evidence(format!("image path: {path}"))
                .evidence(format!(
                    "port {port} is labelled {label} by the port table this scan uses"
                ))
                .remediation(
                    "If you did not install this product, close the port and remove the software: \
                     an open remote-control port is an inbound path into this machine.",
                ),
            );
        }
    }

    // Rule 3: a public destination on a privileged port, reached from a binary a
    // standard user can replace. Reported in addition to rule 1 because the port is
    // what a reader scans for: a C2 on 443 blends into HTTPS traffic, one on 22 or 53
    // does not.
    if public && port > 0 && port <= PRIVILEGED_PORT_MAX && suspicious {
        let user_writable = ctx
            .processes
            .get(&r.pid)
            .and_then(|p| p.path.as_deref())
            .and_then(|v| v.to_str())
            .map(is_user_writable)
            .unwrap_or(false);
        if user_writable {
            ctx.add(
                Finding::new(
                    Severity::High,
                    "network",
                    format!(
                        "{} (pid {}) from a user-writable location connects to privileged port \
                         {port} at {}",
                        name, r.pid, r.remote
                    ),
                )
                .evidence(format!("remote endpoint: {}", r.remote))
                .evidence(format!(
                    "port: {port} (privileged range 1-{PRIVILEGED_PORT_MAX})"
                ))
                .evidence(format!("state: {}", r.state))
                .evidence(format!("owning process: {name} (pid {})", r.pid))
                .evidence(format!("image path: {path}"))
                .remediation(
                    "A user-writable binary talking to a privileged remote port is not normal \
                     software behaviour; capture the process image and its hash, and treat the \
                     host as compromised.",
                ),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ProcessRecord;
    use std::path::PathBuf;

    fn proc(pid: u32, name: &str, path: &str, trusted: Option<bool>) -> ProcessRecord {
        ProcessRecord {
            pid,
            ppid: 4,
            name: name.to_string(),
            path: Some(PathBuf::from(path)),
            cmdline: String::new(),
            owner: String::new(),
            started: None,
            signature_trusted: trusted,
            company: None,
        }
    }

    fn conn(protocol: &'static str, remote: &str, state: &str, pid: u32) -> ConnectionRecord {
        ConnectionRecord {
            protocol,
            local: "0.0.0.0:50000".to_string(),
            remote: remote.to_string(),
            state: state.to_string(),
            pid,
        }
    }

    #[test]
    fn split_endpoint_handles_ipv4_and_bracketed_ipv6() {
        assert_eq!(
            split_endpoint("1.2.3.4:443"),
            Some(("1.2.3.4".to_string(), 443))
        );
        assert_eq!(split_endpoint("[::1]:80"), Some(("::1".to_string(), 80)));
        assert_eq!(
            split_endpoint("[fe80::1]:1900"),
            Some(("fe80::1".to_string(), 1900))
        );
        // A port with leading zeros is still a port.
        assert_eq!(
            split_endpoint("10.0.0.1:00443"),
            Some(("10.0.0.1".to_string(), 443))
        );
    }

    #[test]
    fn split_endpoint_rejects_everything_it_cannot_read() {
        // The wildcard forms the UDP table produces.
        assert_eq!(split_endpoint("*:*"), None);
        assert_eq!(
            split_endpoint("0.0.0.0:0"),
            Some(("0.0.0.0".to_string(), 0))
        );
        // No port, no host, no value.
        assert_eq!(split_endpoint("1.2.3.4"), None);
        assert_eq!(split_endpoint(""), None);
        assert_eq!(split_endpoint("   "), None);
        assert_eq!(split_endpoint(":443"), None);
        assert_eq!(split_endpoint("1.2.3.4:"), None);
        // Out-of-range and non-numeric ports.
        assert_eq!(split_endpoint("1.2.3.4:99999"), None);
        assert_eq!(split_endpoint("1.2.3.4:http"), None);
        // Unbracketed IPv6 is ambiguous, so it is refused rather than mis-split.
        assert_eq!(split_endpoint("2001:db8::1:443"), None);
    }

    #[test]
    fn public_remote_excludes_private_loopback_and_wildcards() {
        assert!(is_public_remote("8.8.8.8:443"));
        assert!(is_public_remote("1.1.1.1:53"));
        assert!(!is_public_remote("192.168.1.1:445"));
        assert!(!is_public_remote("127.0.0.1:8080"));
        assert!(!is_public_remote("[::1]:80"));
        assert!(!is_public_remote("0.0.0.0:0"));
        assert!(!is_public_remote("*:*"));
        assert!(!is_public_remote(""));
        // Link-local and the 172.16/12 block are private too.
        assert!(!is_public_remote("169.254.10.10:53"));
        assert!(!is_public_remote("172.20.5.5:443"));
        // A bare address with no port still gets classified.
        assert!(is_public_remote("8.8.8.8"));
        assert!(!is_public_remote("localhost"));
    }

    #[test]
    fn connection_severity_branches() {
        assert_eq!(
            connection_severity("ESTABLISHED", true, true),
            Some(Severity::High)
        );
        // Public but the owner is trustworthy: nothing to report.
        assert_eq!(connection_severity("ESTABLISHED", true, false), None);
        // Suspicious owner but the peer is local: nothing to report.
        assert_eq!(connection_severity("ESTABLISHED", false, true), None);
        // A listener is the port rule's job, not this one.
        assert_eq!(connection_severity("LISTENING", true, true), None);
        assert_eq!(connection_severity("BOUND", true, true), None);
        // A public attempt from a weakly provenance'd process is Med, not High.
        assert_eq!(
            connection_severity("SYN_SENT", true, true),
            Some(Severity::Med)
        );
        // An unrecognised state code is not silently dropped when the peer is public.
        assert_eq!(
            connection_severity("0x1234", true, true),
            Some(Severity::Med)
        );
        // State comparison ignores case.
        assert_eq!(
            connection_severity("established", true, true),
            Some(Severity::High)
        );
    }

    #[test]
    fn owner_lines_distinguish_a_vanished_process_from_an_unnamed_one() {
        let mut ctx = ScanContext::default();
        ctx.processes.insert(
            7,
            proc(7, "agent.exe", r"C:\ProgramData\Agent\agent.exe", None),
        );
        assert_eq!(
            owner_lines(&ctx, 7),
            (
                "agent.exe".to_string(),
                r"C:\ProgramData\Agent\agent.exe".to_string()
            )
        );
        // A pid absent from the table means the process exited; that is evidence, so it
        // must be labelled rather than rendered as an empty field.
        let (name, path) = owner_lines(&ctx, 999);
        assert_eq!(name, "<process has exited>");
        assert!(
            path.contains("gone"),
            "explains why the path is missing: {path}"
        );
    }

    #[test]
    fn suspicious_owner_treats_a_missing_process_as_suspicious() {
        let mut ctx = ScanContext::default();
        // Absent from the table: a socket that outlived its owner.
        assert!(suspicious_owner(&ctx, 42));
        // Present, signed, in a protected location: not suspicious.
        ctx.processes.insert(
            1,
            proc(
                1,
                "svchost.exe",
                r"C:\Windows\System32\svchost.exe",
                Some(true),
            ),
        );
        assert!(!suspicious_owner(&ctx, 1));
        // Same kind of path, but the signature did not verify.
        ctx.processes.insert(
            2,
            proc(2, "x.exe", r"C:\Windows\System32\x.exe", Some(false)),
        );
        assert!(suspicious_owner(&ctx, 2));
        // User-writable path, verification never attempted.
        ctx.processes.insert(
            3,
            proc(3, "y.exe", r"C:\Users\bob\AppData\Local\Temp\y.exe", None),
        );
        assert!(suspicious_owner(&ctx, 3));
        // No path at all and no failed signature: nothing says it is suspicious.
        let mut bare = proc(4, "z.exe", r"C:\Windows\z.exe", None);
        bare.path = None;
        ctx.processes.insert(4, bare);
        assert!(!suspicious_owner(&ctx, 4));
    }

    #[test]
    fn port_of_is_zero_when_there_is_no_port() {
        assert_eq!(port_of("1.2.3.4:3389"), 3389);
        assert_eq!(port_of("*:*"), 0);
        assert_eq!(port_of("1.2.3.4"), 0);
        assert_eq!(port_of(""), 0);
    }

    #[test]
    fn describe_is_stable_and_readable() {
        let line = describe(&conn("TCP", "8.8.8.8:443", "established", 1234));
        assert!(line.contains("8.8.8.8:443"), "remote is visible: {line}");
        assert!(line.contains("1234"), "pid is visible: {line}");
        assert!(line.starts_with("TCP"), "protocol column first: {line}");
    }
}
