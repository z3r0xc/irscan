//! Drop-location and prefetch collector (FR-13, FR-14, FR-21).
//!
//! The question this collector answers is "what executable appeared on this machine
//! recently, and where?". A covert monitoring agent has to write its binary
//! somewhere, and the places a user-mode process can write without elevation are
//! exactly the ones legitimate software avoids: `%TEMP%`, `%APPDATA%`,
//! `%ProgramData%` and `C:\Users\Public`.
//!
//! Evidence survives deletion: prefetch entries name binaries that ran even if the
//! file is gone. That listing is raw evidence rather than a finding, because a
//! prefetch entry alone proves execution, not intent.
//!
//! Everything is bounded - depth, files visited, results, signature checks, hashes -
//! so a hostile directory tree cannot turn triage into an outage (FR-21).

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::collect::{CollectError, Collector};
use crate::model::{Finding, HaystackKind, ScanContext, Severity, MAX_STRING};
use crate::text::sanitize;

/// Walk depth below each root.
pub const MAX_DEPTH: usize = 3;
/// Hard cap on directory entries visited in one scan.
pub const MAX_FILES: usize = 20000;
/// Hard cap on reported recent executables.
pub const MAX_RESULTS: usize = 300;
/// Hard cap on prefetch entries listed.
pub const MAX_PREFETCH: usize = 300;
/// Maximum prefetch entries examined before sorting (a `Prefetch` folder holds
/// roughly that many, and reading more would only cost I/O).
const PREFETCH_SCAN_CAP: usize = 5000;
/// "Recently written", in seconds: 90 days.
pub const RECENT_WINDOW_SECS: u64 = 90 * 24 * 60 * 60;
/// Only this many binaries are signature-checked: `WinVerifyTrust` is slow and the
/// report does not need hundreds of signature verdicts.
pub const MAX_SIGNATURE_CHECKS: usize = 50;
/// Only this many files are hashed, and only suspicious ones, so the report stays
/// small enough to read.
pub const MAX_HASHES: usize = 10;
/// Upper bound passed to the hasher (8 MiB), so a sparse multi-gigabyte file cannot
/// stall the scan.
pub const HASH_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Locations worth walking: the standard per-user and machine-wide data
/// directories, which are exactly the places a user-mode drop can write to.
const ROOTS: &[&str] = &[
    "%ProgramData%",
    "%LOCALAPPDATA%",
    "%APPDATA%",
    "%TEMP%",
    r"C:\Users\Public",
    r"%SystemRoot%\Temp",
];

/// Walk the standard drop locations for recently written executables, plus the
/// prefetch directory.
///
/// `quick` is `irscan --quick`: it skips both walks and records that it did, so the
/// report never looks silently empty (spec section 4).
#[derive(Debug, Clone, Copy)]
pub struct FilesystemCollector {
    pub quick: bool,
}

impl FilesystemCollector {
    pub fn new(quick: bool) -> Self {
        Self { quick }
    }
}

impl Collector for FilesystemCollector {
    fn name(&self) -> &'static str {
        "filesystem"
    }

    fn run(&self, ctx: &mut ScanContext) -> Result<(), CollectError> {
        if !should_walk(self.quick) {
            ctx.warn(
                "filesystem: --quick skipped the drop-location walk and the prefetch listing; \
                 recently written executables and prefetch evidence are NOT in this report",
            );
            return Ok(());
        }

        let hits = self.collect_hits(ctx);
        self.report_hits(ctx, &hits);
        self.prefetch(ctx);
        Ok(())
    }
}

impl FilesystemCollector {
    /// Walk every existing root and return the recent executable candidates sorted
    /// by path (a fixed order keeps two scans of an unchanged host comparable).
    fn collect_hits(&self, ctx: &mut ScanContext) -> Vec<FileHit> {
        let now = SystemTime::now();
        let mut seen = 0usize;
        let mut hits: Vec<FileHit> = Vec::new();

        for template in ROOTS {
            let root = PathBuf::from(crate::win::expand(template));
            if root.as_os_str().is_empty() || !root.is_dir() {
                continue;
            }
            walk_dir(&root, 0, now, &mut seen, &mut hits);
            if !within_scan_limits(seen, hits.len()) {
                break;
            }
        }

        if seen >= MAX_FILES {
            ctx.warn(format!(
                "filesystem: stopped after {} directory entries",
                MAX_FILES
            ));
        }
        if hits.len() >= MAX_RESULTS {
            ctx.warn(format!(
                "filesystem: list truncated at {} recent executables",
                MAX_RESULTS
            ));
        }

        hits.sort_by(|a, b| a.path.cmp(&b.path));
        hits
    }

    /// Turn the candidates into findings, hashing at most [`MAX_HASHES`] of them.
    fn report_hits(&self, ctx: &mut ScanContext, hits: &[FileHit]) {
        let mut lines: Vec<String> = Vec::new();
        let mut findings: Vec<Finding> = Vec::new();
        let mut signature_checks = 0usize;
        let mut hashes = 0usize;

        for hit in hits {
            let safe_path = sanitize(&hit.path.display().to_string(), MAX_STRING);
            let safe_name = sanitize(crate::text::basename(&safe_path), MAX_STRING);
            ctx.note(HaystackKind::Path, safe_path.clone(), "recent executable");
            lines.push(format!(
                "{} | {} days old",
                safe_path,
                hit.age_secs / 86_400
            ));

            // Signature verification is the expensive step, so it runs only where it
            // can change the verdict, and only a bounded number of times.
            let trust =
                if is_suspicious_data_dir(&safe_path) && signature_checks < MAX_SIGNATURE_CHECKS {
                    signature_checks += 1;
                    crate::win::sig::is_signature_trusted(&hit.path)
                } else {
                    None
                };

            let classified = if is_impersonating(&safe_name) {
                Some((
                    Severity::High,
                    format!("Executable impersonating a Windows component: {safe_name}"),
                ))
            } else if trust == Some(false) && is_suspicious_data_dir(&safe_path) {
                Some((
                    Severity::High,
                    format!("Unsigned executable in a user data directory: {safe_name}"),
                ))
            } else if crate::rules::is_user_writable(&safe_path) {
                Some((
                    Severity::Med,
                    format!("Recent executable in a user-writable location: {safe_name}"),
                ))
            } else {
                None
            };

            let Some((severity, title)) = classified else {
                continue;
            };

            let mut finding = Finding::new(severity, "filesystem", title)
                .evidence(format!("path: {safe_path}"))
                .evidence(format!("modified: {} days ago", hit.age_secs / 86_400))
                .remediation(
                    "Identify the file before acting: this tool reports a location and a date, \
                     not a verdict on the program.",
                );
            if let Some(trusted) = trust {
                finding = finding.evidence(format!("signature trusted: {trusted}"));
            }

            if hashes < MAX_HASHES {
                hashes += 1;
                match crate::win::hash::sha256_file(&hit.path, HASH_MAX_BYTES) {
                    Some(digest) => finding = finding.evidence(format!("sha256: {digest}")),
                    None => finding = finding.evidence("sha256: could not be computed"),
                }
            }

            findings.push(finding);
        }

        for finding in findings {
            ctx.add(finding);
        }
        ctx.raw_section("RECENT EXECUTABLES", lines);
    }

    /// List prefetch entries, newest first, as raw evidence.
    fn prefetch(&self, ctx: &mut ScanContext) {
        let dir = PathBuf::from(crate::win::expand(r"%SystemRoot%\Prefetch"));
        let Ok(entries) = std::fs::read_dir(&dir) else {
            ctx.warn(format!(
                "filesystem: prefetch directory unavailable: {}",
                dir.display()
            ));
            return;
        };

        let mut files: Vec<(SystemTime, String)> = Vec::new();
        for entry in entries.flatten() {
            if files.len() >= PREFETCH_SCAN_CAP {
                break;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.to_ascii_lowercase().ends_with(".pf") {
                continue;
            }
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if !meta.is_file() || crate::win::is_reparse_point(&meta) {
                continue;
            }
            if let Ok(modified) = meta.modified() {
                files.push((modified, sanitize(&name, MAX_STRING)));
            }
        }

        files.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        files.truncate(MAX_PREFETCH);

        if files.is_empty() {
            ctx.warn(
                "filesystem: no prefetch entries found; prefetch may be disabled on this host",
            );
        }
        let lines: Vec<String> = files
            .into_iter()
            .map(|(modified, name)| format!("{} | {}", epoch_secs(modified), name))
            .collect();
        ctx.raw_section("PREFETCH", lines);
    }
}

// ---------------------------------------------------------------------------
// Pure policy (unit-tested without Windows)
// ---------------------------------------------------------------------------

/// Should the drop-location walk run? `--quick` turns it off; the collector records
/// that as a warning rather than reporting an empty section.
pub fn should_walk(quick: bool) -> bool {
    !quick
}

/// Depth guard: a directory at `depth` may be entered only while still below
/// [`MAX_DEPTH`], so the walk visits at most that many levels below each root.
pub fn should_descend(depth: usize) -> bool {
    depth < MAX_DEPTH
}

/// Visit guard: stop when either the visited-entry cap or the result cap is hit.
pub fn within_scan_limits(files_seen: usize, results: usize) -> bool {
    files_seen < MAX_FILES && results < MAX_RESULTS
}

/// Is this file age (in seconds) inside the "written recently" window? The boundary
/// is inclusive, so a file written exactly 90 days ago still counts.
pub fn is_recent(age_secs: u64) -> bool {
    age_secs <= RECENT_WINDOW_SECS
}

/// Executable-ish extensions worth collecting.
pub fn is_interesting_extension(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [".exe", ".dll", ".sys"].iter().any(|e| lower.ends_with(e))
}

/// Does the file name impersonate a Windows component (FR-14)?
pub fn is_impersonating(name: &str) -> bool {
    crate::rules::SYSTEM_PROCESS_NAMES.contains(&name.to_ascii_lowercase().as_str())
}

/// Directories where an unsigned binary is a High finding: the per-user and
/// machine-wide data directories a dropped payload can write to.
pub fn is_suspicious_data_dir(path: &str) -> bool {
    let lower = path.replace('/', "\\").to_ascii_lowercase();
    lower.contains("\\appdata\\") || lower.contains("\\programdata\\") || lower.contains("\\temp\\")
}

// ---------------------------------------------------------------------------
// Host access
// ---------------------------------------------------------------------------

/// A recently modified executable candidate.
#[derive(Debug, Clone)]
struct FileHit {
    path: PathBuf,
    age_secs: u64,
}

/// Recursively collect recent executables. Reparse points are skipped so a junction
/// planted in a drop location cannot lead the walk out of its root (FR-21 / SR-3).
fn walk_dir(dir: &Path, depth: usize, now: SystemTime, seen: &mut usize, hits: &mut Vec<FileHit>) {
    if !should_descend(depth) || !within_scan_limits(*seen, hits.len()) {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if !within_scan_limits(*seen, hits.len()) {
            return;
        }
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if crate::win::is_reparse_point(&meta) {
            continue;
        }
        let path = entry.path();
        if meta.is_dir() {
            walk_dir(&path, depth + 1, now, seen, hits);
            continue;
        }
        if !meta.is_file() {
            continue;
        }
        *seen += 1;

        let name = entry.file_name().to_string_lossy().into_owned();
        if !is_interesting_extension(&name) {
            continue;
        }
        let Some(modified) = meta.modified().ok() else {
            continue;
        };
        // A timestamp in the future (clock skew, or a hostile file) counts as recent.
        let age_secs = now
            .duration_since(modified)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if !is_recent(age_secs) {
            continue;
        }
        hits.push(FileHit { path, age_secs });
    }
}

/// Seconds since the Unix epoch; 0 for a timestamp the platform cannot express.
fn epoch_secs(t: SystemTime) -> u64 {
    t.duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quick_flag_suppresses_the_walks() {
        assert!(should_walk(false));
        assert!(!should_walk(true));
    }

    #[test]
    fn depth_cap_stops_at_max_depth() {
        assert!(should_descend(0));
        assert!(should_descend(MAX_DEPTH - 1));
        assert!(!should_descend(MAX_DEPTH));
        assert!(!should_descend(MAX_DEPTH + 1));
    }

    #[test]
    fn scan_limits_bound_the_walk() {
        assert!(within_scan_limits(0, 0));
        assert!(!within_scan_limits(MAX_FILES, 0));
        assert!(!within_scan_limits(0, MAX_RESULTS));
    }

    #[test]
    fn recent_predicate_is_inclusive_at_the_boundary() {
        assert!(is_recent(0));
        assert!(is_recent(RECENT_WINDOW_SECS));
        assert!(!is_recent(RECENT_WINDOW_SECS + 1));
    }

    #[test]
    fn interesting_extensions_match_case_insensitively() {
        assert!(is_interesting_extension("a.exe"));
        assert!(is_interesting_extension("A.DLL"));
        assert!(is_interesting_extension("drv.SYS"));
        assert!(!is_interesting_extension("readme.txt"));
        assert!(!is_interesting_extension("exe"));
    }

    #[test]
    fn impersonation_matches_system_names_only() {
        assert!(is_impersonating("Svchost.exe"));
        assert!(is_impersonating("lsass.exe"));
        assert!(!is_impersonating("agent.exe"));
        assert!(!is_impersonating("svchost.dll"));
    }

    #[test]
    fn suspicious_data_dir_covers_appdata_programdata_and_temp() {
        assert!(is_suspicious_data_dir(
            r"C:\Users\bob\AppData\Roaming\a.exe"
        ));
        assert!(is_suspicious_data_dir("C:/ProgramData/Acme/a.exe"));
        assert!(is_suspicious_data_dir(r"C:\Windows\Temp\a.exe"));
        assert!(!is_suspicious_data_dir(r"C:\Program Files\Vendor\a.exe"));
        // "Temperature" must not be mistaken for "\temp\".
        assert!(!is_suspicious_data_dir(
            r"C:\Program Files\Temperature\a.exe"
        ));
    }
}
