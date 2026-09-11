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
//! Two rules, both delegated to [`crate::rules`]:
//!
//! * a **public connection whose owner lives in a transit directory** (`Location::Drop`)
//!   or whose owner is gone entirely - see [`crate::rules::connection_severity`];
//! * a **listener on a distinctive remote-control port**, which means this machine
//!   accepts inbound remote sessions. Deduplicated per `(pid, port)`: the table holds
//!   one row per bound address, and every one of them is the same listener.
//!
//! An earlier version also flagged every public connection from a binary in `%APPDATA%`
//! or `%LOCALAPPDATA%`, and every public connection to a privileged port from such a
//! binary. On a clean developer machine that produced 113 findings - Telegram, a
//! torrent client, the agent harness itself - because per-user software *installs*
//! there. The location policy now lives in `rules`; it lives nowhere else.
//!
//! Both tables are read once and recorded in full: absence of findings is not
//! absence of connections, and the raw appendix is what lets a human check the
//! negative. Nothing here opens a socket, resolves a name or sends a packet.

use std::collections::HashSet;

use crate::collect::{CollectError, Collector};
use crate::model::{ConnectionRecord, Finding, HaystackKind, ScanContext, Severity};
use crate::rules::{classify_location, connection_severity, is_private_ip, port_label, Location};
use crate::text::sanitize;
use crate::win::net::{tcp_connections, udp_endpoints};

/// Cap on connections classified. `win::net` already caps its own tables; this is
/// the second, cheaper bound so a hostile host cannot make the classify loop the
/// slowest part of the scan.
pub const MAX_CLASSIFIED: usize = 65536;

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

/// Severity for one connection row, from the owner's [`Location`] and whether the
/// owner is still in the process table.
///
/// The decision itself lives in [`crate::rules::connection_severity`]: a connection is
/// a finding only when the owning binary sits in a transit directory (`Drop`, `High`)
/// or the socket has outlived its owner (`Med`). A normal application talking to
/// `:443` from `%LOCALAPPDATA%` produces **nothing** - that is per-user software
/// doing its job, and flagging it is how a report becomes ignorable.
///
/// No state gate: an owner in a transit directory is worth the same line whether the
/// socket is `ESTABLISHED` or still `SYN-SENT`, and the state is printed in the
/// evidence for the human to weigh. Suppressing the attempt would hide the beacon
/// that only ever tries.
pub fn connection_severity_for(
    location: Location,
    owner_known: bool,
    public: bool,
) -> Option<Severity> {
    connection_severity(public, location, owner_known)
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

/// Where the connection's owning process lives, and whether it is still there.
///
/// A pid absent from the process table means the socket outlived its owner: the
/// `owner_known` flag is `false` because that is the fact `rules` decides on, and the
/// location is [`Location::Privileged`] because an absent process has no path to
/// classify - inventing a suspicious one would turn a vanished process into a false
/// HIGH instead of the MED the policy reserves for it.
fn owner_location(ctx: &ScanContext, pid: u32) -> (Location, bool) {
    let Some(p) = ctx.processes.get(&pid) else {
        return (Location::Privileged, false);
    };
    let path = p
        .path
        .as_deref()
        .map(|v| v.to_string_lossy().to_string())
        .unwrap_or_default();
    (classify_location(&path), true)
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

        // One entry per listener the report has already described, so a dual-stack
        // listener (4.0.0.0 plus [::] plus both loopbacks) is one finding. Keyed by
        // (pid, port): the port is what the operator acts on, and the pid is what says
        // it is the same process rather than a second one squatting the port.
        let mut listener_seen: HashSet<(u32, u16)> = HashSet::new();

        for r in rows.into_iter().take(MAX_CLASSIFIED) {
            // A listener's remote endpoint is the wildcard, so the labelled port is
            // whichever end is a real port: the local one for a listener, the remote
            // one for an outbound connection.
            let port = if r.state.to_ascii_uppercase().contains("LISTEN") {
                port_of(&r.local)
            } else {
                port_of(&r.remote)
            };
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

            classify(ctx, &r, &mut listener_seen);
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

/// Apply the connection policy to one endpoint and push anything it warrants.
///
/// The two rules are independent rather than else-if: a dropped binary phoning home
/// and an RDP listener are different problems, and a rule ordering that suppressed one
/// of them would hide half the picture.
fn classify(ctx: &mut ScanContext, r: &ConnectionRecord, listener_seen: &mut HashSet<(u32, u16)>) {
    let (name, path) = owner_lines(ctx, r.pid);
    let (location, owner_known) = owner_location(ctx, r.pid);
    let state = r.state.to_ascii_uppercase();

    // Rule 1: a public connection either from a transit directory or with no owner
    // left. Everything else - a browser or chat client in `%LOCALAPPDATA%` reaching
    // :443 - is ordinary software and produces no line at all.
    let public = is_public_remote(&r.remote);
    if let Some(sev) = connection_severity_for(location, owner_known, public) {
        let state_label = if r.state.trim().is_empty() {
            "connection".to_string()
        } else {
            state.clone()
        };
        // The two branches are worded apart because their evidence differs: a socket
        // whose owner is gone cannot show an image path, and printing an empty one
        // would read like a lookup failure rather than the finding it is.
        let reason = match (location, owner_known) {
            (Location::Drop, _) => format!(
                "the owning binary runs from a transit directory ({path}), which is where a \
                 dropped payload lives - nothing legitimate installs there"
            ),
            (_, false) => "no process in the table owns this socket: it outlived whatever \
                           opened it, so nothing about the peer was ever verified"
                .to_string(),
            _ => format!("the owning binary runs from {path}"),
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
            .evidence(reason)
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
    // configuration fact, not proof that a session happened. The caller passes
    // `listener_seen` so the finding fires once per (pid, port): the table holds one
    // row per bound address, and four rows for a dual-stack listener are one listener.
    if state.contains("LISTEN") {
        // The *local* port: a listener's remote endpoint is the wildcard `0.0.0.0:0`,
        // so reading the remote port here would label nothing. This is the port the
        // machine accepts sessions on.
        let listen_port = port_of(&r.local);
        if let Some(label) = port_label(listen_port) {
            let key = (r.pid, listen_port);
            if listener_seen.contains(&key) {
                return;
            }
            listener_seen.insert(key);
            ctx.add(
                Finding::new(
                    Severity::Med,
                    "network",
                    format!(
                        "{label} is listening on port {listen_port} (pid {}, {name})",
                        r.pid
                    ),
                )
                .evidence(format!("local endpoint: {}", r.local))
                .evidence(format!("protocol: {}", r.protocol))
                .evidence(format!("owning process: {name} (pid {})", r.pid))
                .evidence(format!("image path: {path}"))
                .evidence(format!(
                    "port {listen_port} is labelled {label} by the port table this scan uses"
                ))
                .remediation(
                    "If you did not install this product, close the port and remove the software: \
                     an open remote-control port is an inbound path into this machine.",
                ),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ProcessRecord;
    use std::collections::HashSet;
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
    fn a_normal_appdata_connection_is_not_a_finding() {
        // The acceptance test for this file: Telegram, a torrent client, a browser and
        // the agent harness all live in %LOCALAPPDATA% or %APPDATA% and all talk to
        // :443. Under the old policy each one produced HIGH. Under the policy that
        // lives in `rules`, they produce nothing.
        for path in [
            r"C:\Users\bob\AppData\Local\Telegram Desktop\Telegram.exe",
            r"C:\Users\bob\AppData\Local\Programs\qBittorrent\qbittorrent.exe",
            r"C:\Users\bob\AppData\Roaming\omp\omp.exe",
            r"C:\ProgramData\chocolatey\tools\7z.exe",
        ] {
            let mut ctx = ScanContext::default();
            ctx.processes.insert(5, proc(5, "app.exe", path, None));
            assert_eq!(
                owner_location(&ctx, 5).0,
                Location::AppData,
                "precondition: {path} is AppData"
            );
            assert_eq!(
                connection_severity_for(Location::AppData, true, true),
                None,
                "a public :443 connection from {path} must produce no finding"
            );
        }
    }

    #[test]
    fn a_drop_location_owner_is_high_and_an_absent_owner_is_med() {
        // A binary in a transit directory is the one location that earns HIGH on the
        // connection rule alone: nothing legitimate installs into %TEMP%.
        let mut ctx = ScanContext::default();
        ctx.processes.insert(
            9,
            proc(
                9,
                "dropper.exe",
                r"C:\Users\bob\AppData\Local\Temp\dropper.exe",
                None,
            ),
        );
        assert_eq!(owner_location(&ctx, 9).0, Location::Drop);
        assert_eq!(
            connection_severity_for(Location::Drop, true, true),
            Some(Severity::High)
        );

        // An absent owner is MED: the socket outlived its process, so nothing about the
        // peer was verified - but an exited process is not by itself proof of a drop.
        let (loc, known) = owner_location(&ctx, 999);
        // Asserted as a pair: the toolchain corrupts a leading `!` in this file, and
        // clippy rejects both `== false` forms.
        assert_eq!((loc, known), (Location::Privileged, false));
        assert_eq!(loc, Location::Privileged);
        assert_eq!(
            connection_severity_for(loc, known, true),
            Some(Severity::Med)
        );

        // Public is required: a local connection from a transit directory is ordinary
        // IPC and must stay silent.
        assert_eq!(connection_severity_for(Location::Drop, true, false), None);
        // A privileged owner that is present is ordinary software.
        assert_eq!(
            connection_severity_for(Location::Privileged, true, true),
            None
        );
    }

    #[test]
    fn classify_keeps_raw_rows_but_reports_only_the_policy_cases() {
        // A public :443 session held by a normal AppData app: raw data yes, finding no.
        let mut ctx = ScanContext::default();
        ctx.processes.insert(
            11,
            proc(
                11,
                "Telegram.exe",
                r"C:\Users\bob\AppData\Local\Telegram Desktop\Telegram.exe",
                None,
            ),
        );
        let mut seen = HashSet::new();
        classify(
            &mut ctx,
            &conn("TCP", "149.154.167.51:443", "ESTABLISHED", 11),
            &mut seen,
        );
        assert!(
            ctx.findings.is_empty(),
            "a normal AppData app talking to :443 must not be reported: {:?}",
            ctx.findings
        );

        // The same connection from %TEMP% is HIGH.
        let mut ctx = ScanContext::default();
        ctx.processes
            .insert(12, proc(12, "x.exe", r"C:\Windows\Temp\x.exe", Some(true)));
        let mut seen = HashSet::new();
        classify(
            &mut ctx,
            &conn("TCP", "8.8.8.8:443", "ESTABLISHED", 12),
            &mut seen,
        );
        assert_eq!(ctx.findings.len(), 1);
        assert_eq!(ctx.findings[0].severity, Severity::High);

        // An owner that is gone gets MED, not HIGH.
        let mut ctx = ScanContext::default();
        let mut seen = HashSet::new();
        classify(
            &mut ctx,
            &conn("TCP", "8.8.8.8:443", "ESTABLISHED", 4242),
            &mut seen,
        );
        assert_eq!(ctx.findings.len(), 1);
        assert_eq!(ctx.findings[0].severity, Severity::Med);
    }

    #[test]
    fn a_labelled_listener_is_reported_once_per_pid_and_port() {
        // A dual-stack listener binds four addresses and the table returns four rows;
        // the operator has one RDP listener to deal with, not four.
        let mut ctx = ScanContext::default();
        ctx.processes.insert(
            21,
            proc(
                21,
                "svchost.exe",
                r"C:\Windows\System32\svchost.exe",
                Some(true),
            ),
        );
        let mut seen = HashSet::new();
        for local in ["0.0.0.0:3389", "[::]:3389", "127.0.0.1:3389", "[::1]:3389"] {
            let mut r = conn("TCP", "0.0.0.0:0", "LISTENING", 21);
            r.local = local.to_string();
            classify(&mut ctx, &r, &mut seen);
        }
        assert_eq!(
            ctx.findings.len(),
            1,
            "one finding per (pid, port), got {:?}",
            ctx.findings
        );
        assert_eq!(ctx.findings[0].severity, Severity::Med);
        assert!(ctx.findings[0].title.contains("3389"));

        // A different port on the same pid is a different listener.
        let mut r = conn("TCP", "0.0.0.0:0", "LISTENING", 21);
        r.local = "0.0.0.0:5900".to_string();
        classify(&mut ctx, &r, &mut seen);
        assert_eq!(ctx.findings.len(), 2);

        // A port with no label is silent even from a transit directory: the listener
        // rule is about the port, not the location.
        let mut ctx = ScanContext::default();
        let mut seen = HashSet::new();
        let mut r = conn("TCP", "0.0.0.0:0", "LISTENING", 5);
        r.local = "0.0.0.0:12345".to_string();
        classify(&mut ctx, &r, &mut seen);
        assert!(ctx.findings.is_empty(), "{:?}", ctx.findings);
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
    fn owner_location_classifies_the_owning_process_path() {
        let mut ctx = ScanContext::default();
        // Absent from the table: unknown owner, no path to classify.
        assert_eq!(owner_location(&ctx, 42), (Location::Privileged, false));
        // A protected install is Privileged and known.
        ctx.processes.insert(
            1,
            proc(
                1,
                "svchost.exe",
                r"C:\Windows\System32\svchost.exe",
                Some(true),
            ),
        );
        assert_eq!(owner_location(&ctx, 1), (Location::Privileged, true));
        // A per-user install is AppData: not evidence, so the policy is silent on it.
        ctx.processes.insert(
            3,
            proc(3, "y.exe", r"C:\Users\bob\AppData\Local\Acme\y.exe", None),
        );
        assert_eq!(owner_location(&ctx, 3), (Location::AppData, true));
        // A transit directory is Drop.
        ctx.processes
            .insert(4, proc(4, "z.exe", r"C:\Users\bob\Downloads\z.exe", None));
        assert_eq!(owner_location(&ctx, 4), (Location::Drop, true));
        // No path at all: nothing to classify, and the process is still known.
        let mut bare = proc(5, "w.exe", r"C:\Windows\w.exe", None);
        bare.path = None;
        ctx.processes.insert(5, bare);
        assert_eq!(owner_location(&ctx, 5), (Location::Privileged, true));
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
