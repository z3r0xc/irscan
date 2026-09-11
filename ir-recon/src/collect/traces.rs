//! Product evidence-file collector (FR-16).
//!
//! Remote-control and employee-monitoring products keep logs on the machine they
//! run on. Those logs are the highest-value artefact this tool can produce, because
//! they often name the *remote party*: an address, a peer id, a session start and
//! stop time. A log that is present and non-empty is proof the product was not just
//! installed but used, which a binary signature alone never shows.
//!
//! Only paths that can be justified are listed. Every entry carries a
//! [`Confidence`] and, where the path is not documented by the vendor, a comment
//! saying so - a guessed path is worse than no path, because its absence would be
//! mistaken for evidence of absence.
//!
//! Reads are capped at [`MAX_TRACE_BYTES`]; nothing here writes, executes or
//! connects anywhere.

use std::path::{Path, PathBuf};

use crate::collect::{CollectError, Collector};
use crate::model::{Finding, HaystackKind, ScanContext, Severity, MAX_STRING};
use crate::text::sanitize;

/// Never read more than this from an evidence file. Logs are small; a hostile file
/// sized to fill memory must not be able to slow the scan down.
pub const MAX_TRACE_BYTES: u64 = 64 * 1024;
/// Cap on endpoints extracted from one file.
const MAX_ENDPOINTS: usize = 64;
/// Cap on connection lines copied into a finding.
const MAX_CONNECTION_LINES: usize = 5;
/// Cap on endpoints copied into a finding's evidence.
const MAX_ENDPOINT_EVIDENCE: usize = 8;
/// Cap on directory entries examined for a wildcard template.
const MAX_GLOB_ENTRIES: usize = 64;
/// Sanitised length of one log line kept as evidence.
const MAX_LINE_LEN: usize = 200;

/// How much the path itself can be trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// Documented by the vendor or by its own support guidance.
    Confirmed,
    /// Seen in practice / follows the product's documented install layout, but not
    /// named in public documentation.
    Likely,
    /// Plausible but unverified. Kept deliberately, and labelled in the report.
    Unverified,
}

impl Confidence {
    pub fn label(self) -> &'static str {
        match self {
            Confidence::Confirmed => "confirmed path",
            Confidence::Likely => "likely path",
            Confidence::Unverified => "unverified path",
        }
    }
}

/// One evidence file a product is known to write.
#[derive(Debug, Clone, Copy)]
pub struct TraceArtifact {
    pub product: &'static str,
    /// Path template; `%VAR%` segments are expanded by the collector, and a single
    /// trailing `*` matches a whole directory-name segment.
    pub template: &'static str,
    /// What finding this file supports - copied verbatim into the evidence.
    pub what_it_proves: &'static str,
    pub confidence: Confidence,
}

/// Evidence files for the remote-control and monitoring products this tool targets.
pub const ARTIFACTS: &[TraceArtifact] = &[
    // --- AnyDesk ---------------------------------------------------------------
    // AnyDesk's own support guidance points at these two files (machine-wide
    // service install and per-user install respectively).
    TraceArtifact {
        product: "AnyDesk",
        template: r"%ProgramData%\AnyDesk\connection_trace.txt",
        what_it_proves:
            "one line per session: AnyDesk ID, remote address and session start/stop time",
        confidence: Confidence::Confirmed,
    },
    TraceArtifact {
        product: "AnyDesk",
        template: r"%APPDATA%\AnyDesk\connection_trace.txt",
        what_it_proves:
            "one line per session: AnyDesk ID, remote address and session start/stop time",
        confidence: Confidence::Confirmed,
    },
    // `ad_svc.trace` sits next to the connection trace in service installs; the
    // file name is observable in an AnyDesk directory but is not in public docs.
    TraceArtifact {
        product: "AnyDesk",
        template: r"%ProgramData%\AnyDesk\ad_svc.trace",
        what_it_proves: "AnyDesk service trace: service start/stop and connection attempts",
        confidence: Confidence::Likely,
    },
    // --- TeamViewer ------------------------------------------------------------
    // TeamViewer documents `Connections_incoming.txt` as the record of incoming
    // sessions, in the install directory (machine-wide) and per user.
    TraceArtifact {
        product: "TeamViewer",
        template: r"%ProgramFiles%\TeamViewer\Connections_incoming.txt",
        what_it_proves: "every incoming TeamViewer session with the remote peer id and address",
        confidence: Confidence::Confirmed,
    },
    TraceArtifact {
        product: "TeamViewer",
        template: r"%PROGRAMFILES(X86)%\TeamViewer\Connections_incoming.txt",
        what_it_proves: "every incoming TeamViewer session with the remote peer id and address",
        confidence: Confidence::Confirmed,
    },
    // QuickSupport / Host write the same file under the user profile.
    TraceArtifact {
        product: "TeamViewer",
        template: r"%APPDATA%\TeamViewer\Connections_incoming.txt",
        what_it_proves: "incoming session log for a per-user (QuickSupport / Host) install",
        confidence: Confidence::Likely,
    },
    // --- RustDesk --------------------------------------------------------------
    // RustDesk keeps its configuration (rendezvous/relay server, peer id) under
    // %APPDATA%\RustDesk\config.
    TraceArtifact {
        product: "RustDesk",
        template: r"%APPDATA%\RustDesk\config\",
        what_it_proves: "RustDesk.toml holds the rendezvous/relay server and the device peer id",
        confidence: Confidence::Confirmed,
    },
    // --- ScreenConnect / ConnectWise Control -----------------------------------
    // The client installs into a per-instance folder under Program Files (x86);
    // the folder name carries the instance id, hence the wildcard segment.
    TraceArtifact {
        product: "ScreenConnect / ConnectWise Control",
        template: r"%PROGRAMFILES(X86)%\ScreenConnect Client *\",
        what_it_proves: "ScreenConnect client install directory; the name contains the instance id",
        confidence: Confidence::Confirmed,
    },
    // --- Supremo ---------------------------------------------------------------
    // Supremo's default install root is the Program Files (x86) folder below; the
    // exact log file name inside it is not documented, so only the directory is
    // listed. (Unverified log names are deliberately not invented.)
    TraceArtifact {
        product: "Supremo",
        template: r"%PROGRAMFILES(X86)%\Supremo\",
        what_it_proves: "Supremo install directory (log file names inside are not confirmed)",
        confidence: Confidence::Likely,
    },
    // --- LiteManager -----------------------------------------------------------
    TraceArtifact {
        product: "LiteManager",
        template: r"%ProgramFiles%\LiteManager\",
        what_it_proves: "LiteManager server install directory",
        confidence: Confidence::Likely,
    },
    TraceArtifact {
        product: "LiteManager",
        template: r"%PROGRAMFILES(X86)%\LiteManager\",
        what_it_proves: "LiteManager server install directory (32-bit install)",
        confidence: Confidence::Likely,
    },
    // --- Remote Utilities ------------------------------------------------------
    // The host component is installed as "Remote Utilities - Host".
    TraceArtifact {
        product: "Remote Utilities",
        template: r"%PROGRAMFILES(X86)%\Remote Utilities - Host\",
        what_it_proves: "Remote Utilities host install directory (RUTserv.exe)",
        confidence: Confidence::Likely,
    },
    TraceArtifact {
        product: "Remote Utilities",
        template: r"%ProgramFiles%\Remote Utilities - Host\",
        what_it_proves: "Remote Utilities host install directory (RUTserv.exe)",
        confidence: Confidence::Likely,
    },
    // --- AeroAdmin -------------------------------------------------------------
    // UNCONFIRMED. AeroAdmin is normally run as a portable executable and writes
    // beside itself; this path is plausible but is not documented. It is listed so
    // that an operator who knows the product can confirm it - the report labels it
    // "unverified path" so a miss here is never read as absence.
    TraceArtifact {
        product: "AeroAdmin",
        template: r"%APPDATA%\AeroAdmin\",
        what_it_proves: "possible AeroAdmin settings/log directory (path unverified)",
        confidence: Confidence::Unverified,
    },
    // --- Ammyy Admin -----------------------------------------------------------
    // UNCONFIRMED. Ammyy Admin stores most of its state in the registry and runs
    // portable; no per-user directory is documented. Listed and labelled only so
    // the report names the product if the directory does exist.
    TraceArtifact {
        product: "Ammyy Admin",
        template: r"%APPDATA%\Ammyy\",
        what_it_proves: "possible Ammyy Admin directory (path unverified; state is registry-based)",
        confidence: Confidence::Unverified,
    },
];

/// Reads the evidence files listed in [`ARTIFACTS`].
pub struct TracesCollector;

impl Collector for TracesCollector {
    fn name(&self) -> &'static str {
        "traces"
    }

    fn run(&self, ctx: &mut ScanContext) -> Result<(), CollectError> {
        let mut raw_lines: Vec<String> = Vec::new();
        for artifact in ARTIFACTS {
            for path in artifact_paths(artifact.template) {
                if !path.exists() {
                    continue;
                }
                examine(ctx, artifact, &path, &mut raw_lines);
            }
        }
        ctx.raw_section("PRODUCT EVIDENCE FILES", raw_lines);
        Ok(())
    }
}

/// Evaluate one existing evidence path.
fn examine(ctx: &mut ScanContext, artifact: &TraceArtifact, path: &Path, raw: &mut Vec<String>) {
    let safe_path = sanitize(&path.display().to_string(), MAX_STRING);
    ctx.note(
        HaystackKind::Path,
        safe_path.clone(),
        format!("{} evidence file", artifact.product),
    );
    raw.push(format!(
        "{} [{}] {}",
        artifact.product,
        artifact.confidence.label(),
        safe_path
    ));

    // A directory is evidence of installation, not of use: there is nothing to read.
    if path.is_dir() {
        raw.push(format!("  directory present: {}", artifact.what_it_proves));
        ctx.add(
            Finding::new(
                Severity::Med,
                "trace",
                format!("{} installation found: {}", artifact.product, safe_path),
            )
            .evidence(format!("directory: {safe_path}"))
            .evidence(artifact.what_it_proves)
            .evidence(format!("path confidence: {}", artifact.confidence.label()))
            .remediation(
                "The product is installed. If it was not installed deliberately, treat the \
                 machine as remotely controllable until it is removed.",
            ),
        );
        return;
    }

    let content = match read_capped(path, MAX_TRACE_BYTES) {
        Some(text) => text,
        None => {
            ctx.warn(format!("traces: could not read {}", safe_path));
            String::new()
        }
    };

    let endpoints = extract_remote_endpoints(&content);
    let connections = connection_lines(&content, MAX_CONNECTION_LINES);

    let mut finding = Finding::new(
        Severity::Med,
        "trace",
        format!("{} evidence file present: {}", artifact.product, safe_path),
    )
    .evidence(format!("path: {safe_path}"))
    .evidence(artifact.what_it_proves)
    .evidence(format!("path confidence: {}", artifact.confidence.label()));

    if content.trim().is_empty() {
        finding = finding.evidence("file is empty");
    }
    for endpoint in endpoints.iter().take(MAX_ENDPOINT_EVIDENCE) {
        finding = finding.evidence(format!("endpoint: {endpoint}"));
    }
    for line in &connections {
        finding = finding.evidence(format!("connection: {line}"));
    }

    // Every hostname goes into the haystack so the signature database can name the
    // product even when the file name alone does not.
    for endpoint in &endpoints {
        let host = endpoint_host(endpoint);
        if !host.is_empty() && host.parse::<std::net::IpAddr>().is_err() {
            ctx.note(HaystackKind::Domain, host.to_string(), artifact.product);
        }
    }

    if has_public_endpoint(&endpoints) {
        finding.severity = Severity::High;
        finding.title = format!(
            "{} was used to reach a public address: {}",
            artifact.product, safe_path
        );
        finding = finding.evidence(
            "at least one recorded endpoint is a public (routable) address, so control came \
             from outside the local network",
        );
    }

    finding = finding.remediation(
        "Preserve this file before removing anything: it is the record of who connected.",
    );
    ctx.add(finding);
}

// ---------------------------------------------------------------------------
// Pure helpers (unit-tested without Windows)
// ---------------------------------------------------------------------------

/// Expand a path template with the machine's environment (FR-16).
pub fn expand_template(template: &str) -> String {
    crate::win::expand(template)
}

/// Split an expanded `dir\prefix*` template into its parent directory and the
/// literal prefix of the wildcard segment.
///
/// Only a single `*` that covers the whole tail of a path segment is supported
/// (that covers `ScreenConnect Client *`). Anything else returns `None` so the
/// caller reports nothing rather than matching the wrong directory.
pub fn split_glob(expanded: &str) -> Option<(String, String)> {
    let star = expanded.find('*')?;
    let slash = expanded[..star].rfind('\\')?;
    let seg_end = match expanded[star..].find('\\') {
        Some(i) => star + i,
        None => expanded.len(),
    };
    if !expanded[star + 1..seg_end].is_empty() {
        return None;
    }

    // The parent is returned WITHOUT a trailing separator, so the value reads the way
    // a user would write the path. Two cases keep one: a bare drive ("C:" means the
    // current directory on C:, not its root) and a root-relative template.
    let raw_parent = &expanded[..slash];
    let parent = if raw_parent.len() == 2 && raw_parent.ends_with(':') {
        format!("{raw_parent}\\")
    } else if raw_parent.is_empty() {
        "\\".to_string()
    } else {
        raw_parent.to_string()
    };

    Some((parent, expanded[slash + 1..star].to_string()))
}

/// Resolve a template to the paths that exist (or could): a literal path, or every
/// directory matching the wildcard segment.
pub fn artifact_paths(template: &str) -> Vec<PathBuf> {
    let expanded = expand_template(template);
    let Some((parent, prefix)) = split_glob(&expanded) else {
        return vec![PathBuf::from(expanded)];
    };
    let Ok(entries) = std::fs::read_dir(&parent) else {
        return Vec::new();
    };
    let prefix = prefix.to_ascii_lowercase();
    let mut out: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten() {
        if out.len() >= MAX_GLOB_ENTRIES {
            break;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.to_ascii_lowercase().starts_with(&prefix) {
            out.push(entry.path());
        }
    }
    out.sort();
    out
}

/// IPv4/IPv6 literals and host:port pairs found in a log line set.
///
/// A four-part dotted number must parse as an actual IPv4 address, so a version
/// such as `2.1.3` or `10.0.19045.3803` is never mistaken for a peer.
pub fn extract_remote_endpoints(content: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in content.lines() {
        for token in line.split_whitespace() {
            let token = trim_endpoint_token(token);
            if token.is_empty() {
                continue;
            }
            let Some(endpoint) = classify_endpoint(token) else {
                continue;
            };
            if out.len() >= MAX_ENDPOINTS {
                return out;
            }
            if !out.contains(&endpoint) {
                out.push(endpoint);
            }
        }
    }
    out
}

/// The last `max` lines that look like connection records, newest last.
///
/// Everything that is not blank and not a `#` comment counts as a record: dropping
/// a line because it looked unusual would hide the one address that matters. Most
/// products append, so the tail of the file is its newest content; TeamViewer's
/// incoming-session log is ordered newest-first instead, which is why the raw
/// section of the report keeps the file's own order too.
pub fn connection_lines(content: &str, max: usize) -> Vec<String> {
    if max == 0 {
        return Vec::new();
    }
    let mut out: Vec<String> = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        out.push(sanitize(trimmed, MAX_LINE_LEN));
    }
    let start = out.len().saturating_sub(max);
    out.split_off(start)
}

/// The host part of an endpoint, with any port and IPv6 brackets removed.
pub fn endpoint_host(endpoint: &str) -> &str {
    if let Some(rest) = endpoint.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return &rest[..end];
        }
        return endpoint;
    }
    // More than one colon means a bare IPv6 literal, not host:port.
    if endpoint.matches(':').count() > 1 {
        return endpoint;
    }
    match endpoint.split_once(':') {
        Some((host, _)) => host,
        None => endpoint,
    }
}

/// Does any endpoint reach a routable address? Only loopback and LAN peers means
/// the product was installed but no remote party from outside the network is
/// recorded.
pub fn has_public_endpoint(endpoints: &[String]) -> bool {
    endpoints
        .iter()
        .any(|e| !crate::rules::is_private_ip(endpoint_host(e)))
}

/// Strip punctuation that can only be adjacent to an endpoint, never part of one.
fn trim_endpoint_token(token: &str) -> &str {
    token.trim_matches(|c: char| {
        !(c.is_ascii_alphanumeric()
            || c == '.'
            || c == ':'
            || c == '-'
            || c == '_'
            || c == '['
            || c == ']'
            || c == '%')
    })
}

/// Classify one whitespace-delimited token as an endpoint.
fn classify_endpoint(token: &str) -> Option<String> {
    let (host, _port) = split_host_port(token)?;
    if host.is_empty() {
        return None;
    }
    if host.parse::<std::net::Ipv4Addr>().is_ok() || host.parse::<std::net::Ipv6Addr>().is_ok() {
        return Some(token.to_string());
    }
    if is_hostname(host) {
        return Some(token.to_string());
    }
    None
}

/// Split `host[:port]`, `[ipv6][:port]` or a bare IPv6 literal.
///
/// `None` when a port is present but malformed, which is the safe direction: a
/// token like `a.exe:notaport` is not a peer.
fn split_host_port(token: &str) -> Option<(&str, Option<u16>)> {
    if let Some(rest) = token.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let after = &rest[end + 1..];
        if after.is_empty() {
            return Some((host, None));
        }
        let port = after.strip_prefix(':')?.parse::<u16>().ok()?;
        if port == 0 {
            return None;
        }
        return Some((host, Some(port)));
    }
    match token.matches(':').count() {
        0 => Some((token, None)),
        1 => {
            let (host, port) = token.split_once(':')?;
            let port = port.parse::<u16>().ok()?;
            if port == 0 {
                return None;
            }
            Some((host, Some(port)))
        }
        // Bare IPv6 literal (grouped colon form).
        _ => Some((token, None)),
    }
}

/// A DNS-style hostname: at least two labels, an alphabetic top-level label.
fn is_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || !host.contains('.') || host.contains(':') {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }
    let Some(tld) = labels.last() else {
        return false;
    };
    tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic())
}

// ---------------------------------------------------------------------------
// Host access
// ---------------------------------------------------------------------------

/// Read at most `max` bytes of a text file, decoding UTF-16 BOMs.
fn read_capped(path: &Path, max: u64) -> Option<String> {
    use std::io::Read;
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let file = std::fs::File::open(path).ok()?;
    let mut buf: Vec<u8> = Vec::with_capacity(meta.len().min(max) as usize);
    if file.take(max).read_to_end(&mut buf).is_err() {
        return None;
    }
    Some(decode_text(&buf))
}

/// Decode a log file: UTF-16LE with a BOM (a few products write these) or UTF-8,
/// lossily in both cases so malformed bytes never cost the whole scan.
fn decode_text(bytes: &[u8]) -> String {
    match bytes.strip_prefix(&[0xFF, 0xFE]) {
        Some(body) => crate::win::from_utf16_bytes(body),
        None => String::from_utf8_lossy(bytes).into_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_remote_endpoints_finds_addresses_and_hostnames() {
        let content = "# AnyDesk connection trace\n\
             2026-01-01 10:00:00 12.34.56.78:443 connected\n\
             2026-01-01 10:01:00 127.0.0.1:5 loopback session\n\
             2026-01-01 10:02:00 desk.example.com connected\n\
             2026-01-01 10:03:00 12.34.56.78:443 duplicate\n\
             version 2.1.3 build 7\n";

        let endpoints = extract_remote_endpoints(content);
        assert!(endpoints.contains(&"12.34.56.78:443".to_string()));
        assert!(endpoints.contains(&"127.0.0.1:5".to_string()));
        assert!(endpoints.contains(&"desk.example.com".to_string()));
        assert_eq!(
            endpoints.iter().filter(|e| *e == "12.34.56.78:443").count(),
            1,
            "endpoints are de-duplicated"
        );
    }

    #[test]
    fn version_numbers_are_never_endpoints() {
        assert!(extract_remote_endpoints("build 2.1.3").is_empty());
        assert!(extract_remote_endpoints("OS 10.0.19045.3803").is_empty());
        assert!(extract_remote_endpoints("2026-01-01T10:00:00Z").is_empty());
    }

    #[test]
    fn connection_lines_respects_cap_and_skips_noise() {
        let content = "# header\n\nfirst\nsecond\nthird\n";
        assert_eq!(
            connection_lines(content, 2),
            vec!["second".to_string(), "third".to_string()]
        );
        assert!(connection_lines(content, 0).is_empty());
        assert_eq!(connection_lines("# only comments\n\n", 5).len(), 0);
    }

    #[test]
    fn expand_template_expands_known_and_preserves_unknown() {
        let expanded = expand_template(r"%ProgramData%\AnyDesk\connection_trace.txt");
        assert!(!expanded.contains('%'), "expanded: {expanded}");
        assert!(expanded.ends_with("connection_trace.txt"));
        assert_eq!(
            expand_template(r"%IRSCAN_NO_SUCH_VAR%\x"),
            r"%IRSCAN_NO_SUCH_VAR%\x"
        );
    }

    #[test]
    fn split_glob_finds_parent_and_prefix() {
        assert_eq!(
            split_glob(r"C:\Program Files (x86)\ScreenConnect Client *"),
            Some((
                r"C:\Program Files (x86)".to_string(),
                "ScreenConnect Client ".to_string()
            ))
        );
        assert_eq!(split_glob(r"C:\x\plain\"), None);
        assert_eq!(split_glob(r"C:\x\abc*def"), None);
    }

    #[test]
    fn split_glob_keeps_the_separator_only_where_it_carries_meaning() {
        // A bare drive is not its own root: "C:" means the current directory on C:,
        // so the separator has to stay for the listing to mean the right thing.
        assert_eq!(
            split_glob(r"C:\ScreenConnect Client*"),
            Some((r"C:\".to_string(), "ScreenConnect Client".to_string()))
        );
        // A UNC share keeps its server and share, and loses the trailing separator.
        assert_eq!(
            split_glob(r"\\srv\share\Acme Agent*"),
            Some((r"\\srv\share".to_string(), "Acme Agent".to_string()))
        );
        // A root-relative template is the one case that is nothing but a separator.
        assert_eq!(
            split_glob(r"\Acme Agent*"),
            Some(("\\".to_string(), "Acme Agent".to_string()))
        );
    }

    #[test]
    fn endpoint_host_strips_ports_and_brackets() {
        assert_eq!(endpoint_host("12.34.56.78:443"), "12.34.56.78");
        assert_eq!(endpoint_host("[fe80::1]:5"), "fe80::1");
        assert_eq!(endpoint_host("fe80::1"), "fe80::1");
        assert_eq!(endpoint_host("desk.example.com"), "desk.example.com");
    }

    #[test]
    fn public_endpoints_raise_the_severity_signal() {
        assert!(has_public_endpoint(&["12.34.56.78:443".to_string()]));
        assert!(has_public_endpoint(&["desk.example.com".to_string()]));
        assert!(!has_public_endpoint(&[
            "127.0.0.1:5".to_string(),
            "192.168.1.10".to_string()
        ]));
        assert!(!has_public_endpoint(&[]));
    }
}
