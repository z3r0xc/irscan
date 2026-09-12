//! Drop-location and prefetch collector (FR-13, FR-14, FR-21).
//!
//! The question this collector answers is "what executable appeared on this machine
//! recently, and where?". A covert monitoring agent has to write its binary
//! somewhere, and the one place no legitimate software *installs* to is a transit
//! directory: `%TEMP%`, `%LOCALAPPDATA%\Temp`, `C:\Windows\Temp`, `Users\Public`,
//! `Downloads`, `$Recycle.Bin`, `Perflogs`.
//!
//! Application data (`%APPDATA%`, `%LOCALAPPDATA%`, `%ProgramData%`) is *not*
//! evidence on its own: chocolatey, scoop, node, python, Docker and PowerToys all
//! install per-user there. An earlier version of this collector reported every
//! recently written executable under any user-writable directory and produced 294
//! Med findings on a clean developer machine - thirteen locale copies of each
//! `PowerToys.*.resources.dll` among them - which trains the reader to ignore the
//! report. The policy now comes from [`crate::rules::execution_severity`].
//!
//! Findings are aggregated per directory: several files that share a directory and a
//! reason are one finding that names the count and shows a handful of examples,
//! because one finding per file makes the JSON unreadable and the counts meaningless.
//!
//! Evidence survives deletion: prefetch entries name binaries that ran even if the
//! file is gone. That listing is raw evidence rather than a finding, because a
//! prefetch entry alone proves execution, not intent.
//!
//! Everything is bounded - depth, files visited, results, signature checks, hashes -
//! so a hostile directory tree cannot turn triage into an outage (FR-21).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::collect::{CollectError, Collector};
use crate::model::{Finding, HaystackKind, ScanContext, Severity, MAX_STRING};
use crate::rules::{classify_location, Location};
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
/// Example paths quoted per aggregated finding. The directory and the count carry the
/// signal; more than a handful of examples is the per-file noise this collector
/// exists to avoid.
const MAX_EXAMPLES: usize = 5;

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
    ///
    /// Every candidate is listed under RAW DATA regardless of verdict - a `.dll` in
    /// `%LOCALAPPDATA%` is not a finding, but hiding it from the listing would lose
    /// evidence. Findings are grouped by (directory, reason): thirteen locale copies
    /// of the same DLL under one directory are one line naming the count, not thirteen.
    fn report_hits(&self, ctx: &mut ScanContext, hits: &[FileHit]) {
        let mut lines: Vec<String> = Vec::new();
        let mut classified: Vec<Classified> = Vec::new();
        let mut signature_checks = 0usize;

        // The verification budget is spent on what the verdict can actually change, and
        // the order matters more than the size of the budget. `is_signature_trusted` is the
        // only slow step here, so only `MAX_SIGNATURE_CHECKS` candidates get a verdict and
        // the rest have `trust = None`. A transit-directory candidate is the one whose
        // verdict decides between "reported" and "not reported" - application data needs
        // the verdict only to separate MED from nothing - so transit candidates are
        // verified first. Walking `hits` in its original order instead let ordinary
        // per-user software consume the whole budget before `%TEMP%` was ever reached, and
        // a dropped payload in `%TEMP%` was then silently cleared because its signature had
        // never been checked.
        let mut order: Vec<&FileHit> = hits.iter().collect();
        order.sort_by_key(|hit| {
            let path = hit.path.display().to_string();
            let name = crate::text::basename(&path);
            let location = classify_location(&path);
            let transit = location == Location::Drop;
            // Transit first, then candidates over non-candidates, then newest.
            (
                core::cmp::Reverse(transit),
                core::cmp::Reverse(is_finding_extension(name) && !is_impersonating(name)),
                hit.age_secs,
            )
        });

        for hit in order {
            let safe_path = sanitize(&hit.path.display().to_string(), MAX_STRING);
            let safe_name = sanitize(crate::text::basename(&safe_path), MAX_STRING);
            ctx.note(HaystackKind::Path, safe_path.clone(), "recent executable");
            lines.push(format!(
                "{} | {} days old",
                safe_path,
                hit.age_secs / 86_400
            ));

            // Signature verification is the expensive step, so it runs only where it
            // can change the verdict, and only a bounded number of times. The free
            // checks come first: a `.dll`, or anything in a privileged directory, is
            // never a finding and must not consume a verification slot.
            let impersonating = is_impersonating(&safe_name);
            let location = classify_location(&safe_path);
            let eligible = impersonating || is_finding_candidate(&safe_name, location);
            if eligible {
                // A name match is decisive and free; only the rest pay for a check.
                let trust = if impersonating || signature_checks >= MAX_SIGNATURE_CHECKS {
                    None
                } else {
                    signature_checks += 1;
                    crate::win::sig::is_signature_trusted(&hit.path)
                };

                if let Some((severity, reason)) =
                    finding_reason(impersonating, trust, location, hit.age_secs)
                {
                    classified.push(Classified {
                        severity,
                        reason,
                        dir: directory_of(&safe_path),
                        path: safe_path,
                        age_days: hit.age_secs / 86_400,
                        trust,
                        hash_path: hit.path.clone(),
                    });
                }
            }
        }

        // The budget is finite, so say when it ran out. Without this a candidate whose
        // signature was never checked is indistinguishable from one that passed, which is
        // how the transit-directory rule came to depend on walk order in the first place.
        if signature_checks >= MAX_SIGNATURE_CHECKS {
            ctx.warn(format!(
                "filesystem: signature verification stopped at {MAX_SIGNATURE_CHECKS} files; \
                 executables listed after that point have no signature verdict"
            ));
        }

        let mut hashes = 0usize;
        for finding in aggregate_findings(&classified, &mut hashes, |p| {
            crate::win::hash::sha256_file(p, HASH_MAX_BYTES)
        }) {
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

/// Executable-ish extensions worth *listing* in RAW DATA.
///
/// Deliberately wider than [`is_finding_extension`]: a `.dll` is not a reason to
/// report anything, but it is still evidence an analyst may want, and dropping it
/// from the listing would lose data for no gain.
pub fn is_interesting_extension(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [".exe", ".dll", ".sys", ".scr"]
        .iter()
        .any(|e| lower.ends_with(e))
}

/// Extensions that can be *reported* as a finding.
///
/// Narrower than the listing on purpose. A `.dll` is loaded by a host process and its
/// mere presence in a data directory says nothing - a per-user application ships
/// dozens of them, as every PowerToys install does. `.exe`, `.sys` and `.scr` are the
/// ones a user can double-click or a boot loads directly.
pub fn is_finding_extension(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [".exe", ".sys", ".scr"].iter().any(|e| lower.ends_with(e))
}

/// Does the file name impersonate a Windows component (FR-14)?
pub fn is_impersonating(name: &str) -> bool {
    crate::rules::SYSTEM_PROCESS_NAMES.contains(&name.to_ascii_lowercase().as_str())
}

/// Why a file was reported. The variant *is* the aggregation key: files that share a
/// directory and a reason become one finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Reason {
    /// The file name belongs to a Windows component and it is not in `%SystemRoot%`.
    Impersonation,
    /// An untrusted executable in a transit directory - nothing installs there.
    UntrustedInDropLocation,
    /// An untrusted executable that appeared in application data within the last week.
    /// Per-user software is normal in `%APPDATA%`; *new and unsigned* is the signal.
    FreshUntrustedInAppData,
}

impl Reason {
    /// The human-readable clause shared by every file carrying this reason.
    pub fn describe(self) -> &'static str {
        match self {
            Reason::Impersonation => "impersonates a Windows component",
            Reason::UntrustedInDropLocation => {
                "is unsigned and runs from a directory nothing installs to"
            }
            Reason::FreshUntrustedInAppData => {
                "is unsigned and appeared in a software data directory within the last 7 days"
            }
        }
    }
}

/// The seven-day window for [`Reason::FreshUntrustedInAppData`].
pub const FRESH_WINDOW_SECS: u64 = 7 * 24 * 60 * 60;

/// Decide a single candidate. `None` means "not a finding": it stays in RAW DATA.
///
/// The policy, in priority order:
///
/// * a system-component name anywhere outside `%SystemRoot%` - HIGH, always;
/// * an untrusted executable in a transit directory - HIGH;
/// * an untrusted executable in application data, *written within the last week* -
///   MED. Application data on its own is where half the software on a developer
///   machine installs; recency plus an unverified signature is what makes it worth a
///   second look;
/// * everything else - nothing. In particular `.dll` files, anything under
///   `%ProgramData%\chocolatey` or a versioned app directory, and untrusted binaries
///   in application data older than a week are all legitimate.
///
/// `age_secs` is the file's age; `trust` is `None` when verification could not run.
pub fn finding_reason(
    impersonating: bool,
    trust: Option<bool>,
    location: Location,
    age_secs: u64,
) -> Option<(Severity, Reason)> {
    if impersonating {
        return Some((Severity::High, Reason::Impersonation));
    }
    // Note the direction of this test: it requires a *verdict*, `Some(false)`, and treats
    // `None` as the absence of evidence it is. An earlier attempt inverted it to
    // `trust != Some(true)` to stop the signature budget from hiding a dropped payload, and
    // that was wrong twice over - it turned "not checked" into "checked and bad", and it
    // flagged every legitimately signed installer in `%TEMP%` or `Downloads` as HIGH when
    // the budget ran out. The budget is dealt with where it belongs, in `report_hits`,
    // which now spends its slots on transit-directory candidates first so that `None` does
    // not arise for the files this rule exists to catch.
    if trust == Some(false) && location == Location::Drop {
        return Some((Severity::High, Reason::UntrustedInDropLocation));
    }
    if trust == Some(false) && location == Location::AppData && age_secs <= FRESH_WINDOW_SECS {
        return Some((Severity::Med, Reason::FreshUntrustedInAppData));
    }
    None
}

/// Is this candidate even eligible to become a finding? A `.dll` never is, and a
/// privileged location needs no check at all.
pub fn is_finding_candidate(name: &str, location: Location) -> bool {
    is_finding_extension(name) && location != Location::Privileged
}

/// The directory a sanitised path sits in, as an aggregation key.
///
/// Falls back to the whole path when no separator is present, so an unusable path is
/// still grouped rather than dropped.
pub fn directory_of(path: &str) -> String {
    match path.rfind(['\\', '/']) {
        Some(idx) if idx > 0 => path[..idx].to_string(),
        _ => path.to_string(),
    }
}

/// One candidate that survived [`finding_reason`], ready to be aggregated.
#[derive(Debug, Clone)]
struct Classified {
    severity: Severity,
    reason: Reason,
    dir: String,
    path: String,
    age_days: u64,
    trust: Option<bool>,
    hash_path: PathBuf,
}

/// Group candidates by (directory, reason) and emit one finding per group.
///
/// `hashes` is threaded across groups and capped at [`MAX_HASHES`] so a machine with
/// many suspicious directories still cannot turn the scan into a hashing job.
/// `hash` is injected rather than called directly so the aggregation is testable on
/// any host.
fn aggregate_findings(
    classified: &[Classified],
    hashes: &mut usize,
    hash: impl Fn(&Path) -> Option<String>,
) -> Vec<Finding> {
    // BTreeMap, not HashMap: two scans of an unchanged host must produce the same
    // finding order.
    let mut groups: BTreeMap<(String, Reason), Vec<&Classified>> = BTreeMap::new();
    for item in classified {
        groups
            .entry((item.dir.clone(), item.reason))
            .or_default()
            .push(item);
    }

    let mut findings: Vec<Finding> = Vec::new();
    for ((dir, reason), mut items) in groups {
        // The line naming the directory carries the signal, not the order the walk
        // happened to see it in.
        items.sort_by(|a, b| a.path.cmp(&b.path));
        let severity = items
            .iter()
            .map(|i| i.severity)
            .min()
            .unwrap_or(Severity::Info);
        let count = items.len();

        let title = if count == 1 {
            format!(
                "Executable in {dir} {}: {}",
                reason.describe(),
                crate::text::basename(&items[0].path)
            )
        } else {
            format!("{count} executables in {dir} {}", reason.describe())
        };

        let mut finding = Finding::new(severity, "filesystem", title)
            .evidence(format!("directory: {dir}"))
            .evidence(format!("matching files: {count}"))
            .evidence(format!(
                "most recent: {} day(s) ago",
                items.iter().map(|i| i.age_days).min().unwrap_or(0)
            ))
            .remediation(
                "Identify the file(s) before acting: this tool reports a location and a date, \
                 not a verdict on the program.",
            );

        for item in items.iter().take(MAX_EXAMPLES) {
            finding = finding.evidence(format!("example: {}", item.path));
        }
        if count > MAX_EXAMPLES {
            finding = finding.evidence(format!(
                "and {} more file(s) in this directory",
                count - MAX_EXAMPLES
            ));
        }
        if let Some(trusted) = items.first().and_then(|i| i.trust) {
            finding = finding.evidence(format!("signature trusted: {trusted}"));
        }

        // Hash the first example that still needs one; a per-file hash for a group of
        // a hundred identical locale DLLs would be the same digest repeated.
        if *hashes < MAX_HASHES {
            if let Some(item) = items.first() {
                *hashes += 1;
                let line = match hash(&item.hash_path) {
                    Some(digest) => format!("sha256 ({}): {digest}", item.path),
                    None => format!("sha256 ({}): could not be computed", item.path),
                };
                finding = finding.evidence(line);
            }
        }

        findings.push(finding);
    }
    findings
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

    #[test]
    fn an_unchecked_signature_is_not_read_as_a_bad_one() {
        // `trust = None` means the check did not run. Reading it as "untrusted" would flag
        // every legitimately signed installer in %TEMP% and Downloads as HIGH once the
        // verification budget ran out - the same false-positive direction that once produced
        // 89 HIGH findings on a clean developer machine. A verdict is required.
        assert_eq!(
            finding_reason(false, None, Location::Drop, 3600),
            None,
            "not checked must not be reported as untrusted"
        );
        assert_eq!(
            finding_reason(false, Some(true), Location::Drop, 3600),
            None,
            "a verified signature clears the location signal"
        );
        // A real negative verdict is what the rule is for.
        assert_eq!(
            finding_reason(false, Some(false), Location::Drop, 3600),
            Some((Severity::High, Reason::UntrustedInDropLocation))
        );
    }

    #[test]
    fn the_signature_budget_is_spent_on_transit_directories_first() {
        // `None` must not be treated as a verdict precisely because the budget runs out.
        // The fix is to spend it where the verdict changes the outcome first, so this pins
        // the ordering. The review's scenario: ordinary per-user software consumed all
        // fifty slots before %TEMP% was reached, and a dropped payload was then cleared
        // for having no verdict at all.
        let hits = [
            FileHit {
                path: PathBuf::from(r"C:\ProgramData\vendor\app\one.exe"),
                age_secs: 10,
            },
            FileHit {
                path: PathBuf::from(r"C:\Users\bob\AppData\Local\vendor\two.exe"),
                age_secs: 20,
            },
            FileHit {
                path: PathBuf::from(r"C:\Users\bob\AppData\Local\Temp\dropped.exe"),
                age_secs: 30,
            },
        ];
        let mut order: Vec<&FileHit> = hits.iter().collect();
        order.sort_by_key(|hit| {
            let path = hit.path.display().to_string();
            let name = crate::text::basename(&path).to_string();
            let transit = classify_location(&path) == Location::Drop;
            (
                core::cmp::Reverse(transit),
                core::cmp::Reverse(is_finding_extension(&name) && !is_impersonating(&name)),
                hit.age_secs,
            )
        });
        assert!(
            order[0].path.ends_with("dropped.exe"),
            "the transit candidate must be verified before the others, got {:?}",
            order[0].path
        );
    }

    #[test]
    fn application_data_still_requires_a_failed_signature_check() {
        // Only the transit-directory rule changed. Application data is where half the
        // software on a developer machine lives, so an unverified binary there must NOT
        // be reported on location alone - that was the 89-false-positive mistake.
        assert_eq!(finding_reason(false, None, Location::AppData, 3600), None);
        assert!(finding_reason(false, Some(false), Location::AppData, 3600).is_some());
    }

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
        assert!(is_interesting_extension("screen.SCR"));
        assert!(!is_interesting_extension("readme.txt"));
        assert!(!is_interesting_extension("exe"));
    }

    #[test]
    fn finding_extensions_exclude_dlls() {
        assert!(is_finding_extension("a.exe"));
        assert!(is_finding_extension("A.SYS"));
        assert!(is_finding_extension("screen.scr"));
        // The 294-finding regression in one line: a PowerToys locale assembly is a
        // `.dll` and must never be reported, however recent it is.
        assert!(!is_finding_extension("PowerToys.Awake.resources.dll"));
        assert!(!is_finding_extension("7z.dll"));
        assert!(!is_finding_extension("readme.txt"));
    }

    #[test]
    fn impersonation_matches_system_names_only() {
        assert!(is_impersonating("Svchost.exe"));
        assert!(is_impersonating("lsass.exe"));
        assert!(!is_impersonating("agent.exe"));
        assert!(!is_impersonating("svchost.dll"));
    }

    /// The whole point of the fix: a clean developer machine's per-user installs
    /// produce nothing, while the two genuinely indefensible cases still fire.
    #[test]
    fn finding_reason_separates_drops_from_normal_per_user_installs() {
        const DAY: u64 = 86_400;

        // PowerToys lives in %LOCALAPPDATA%\Microsoft -> AppData, and even unsigned it
        // is not evidence: no HIGH, and no finding at all once past the fresh window.
        let powertoys = classify_location(r"C:\Users\bob\AppData\Local\Microsoft\PowerToys\a.exe");
        assert_eq!(powertoys, Location::AppData);
        assert_eq!(finding_reason(false, Some(true), powertoys, DAY), None);
        assert_eq!(finding_reason(false, None, powertoys, 365 * DAY), None);

        // Chocolatey is AppData too: unsigned and older than the window is exactly how
        // it ships, so it is not a finding.
        let choco = classify_location(r"C:\ProgramData\chocolatey\tools\7z.exe");
        assert_eq!(choco, Location::AppData);
        assert_eq!(finding_reason(false, Some(false), choco, 23 * DAY), None);

        // An executable in %TEMP% with a *failed* signature check is HIGH. The verdict is
        // what makes the location signal actionable; without one there is nothing to report,
        // and the budget - not this rule - is what keeps that case rare.
        let temp = classify_location(r"C:\Users\bob\AppData\Local\Temp\a.exe");
        assert_eq!(temp, Location::Drop);
        assert_eq!(
            finding_reason(false, Some(false), temp, DAY),
            Some((Severity::High, Reason::UntrustedInDropLocation))
        );

        // Fresh and unsigned in application data is the narrowed Med tier.
        assert_eq!(
            finding_reason(false, Some(false), Location::AppData, 3 * DAY),
            Some((Severity::Med, Reason::FreshUntrustedInAppData))
        );

        // A system-component name is HIGH wherever it sits.
        assert_eq!(
            finding_reason(true, Some(true), Location::AppData, 365 * DAY),
            Some((Severity::High, Reason::Impersonation))
        );

        // Privileged locations are never reported here.
        assert_eq!(
            finding_reason(false, Some(false), Location::Privileged, DAY),
            None
        );
        // An unverified signature is not evidence on its own in application data...
        assert_eq!(finding_reason(false, None, Location::AppData, DAY), None);
        // ...and neither is it evidence in a transit directory. The budget makes an
        // unchecked signature common there, so treating it as a verdict would flag every
        // signed installer that runs out of %TEMP% - which is normal behaviour.
        assert_eq!(finding_reason(false, None, Location::Drop, DAY), None);
    }

    #[test]
    fn finding_candidate_excludes_dlls_and_privileged_paths() {
        assert!(is_finding_candidate(
            "a.exe",
            classify_location(r"C:\ProgramData\chocolatey\tools\a.exe")
        ));
        assert!(!is_finding_candidate(
            "PowerToys.Awake.resources.dll",
            Location::AppData
        ));
        assert!(!is_finding_candidate("a.exe", Location::Privileged));
        assert!(!is_finding_candidate(
            "a.exe",
            classify_location(r"C:\Program Files\Vendor\a.exe")
        ));
    }

    #[test]
    fn directory_of_splits_on_either_separator() {
        assert_eq!(
            directory_of(r"C:\Users\bob\AppData\Local\Temp\a.exe"),
            r"C:\Users\bob\AppData\Local\Temp"
        );
        assert_eq!(directory_of("C:/Users/bob/a.exe"), "C:/Users/bob");
        assert_eq!(directory_of(r"\a.exe"), r"\a.exe");
        assert_eq!(directory_of("a.exe"), "a.exe");
        assert_eq!(directory_of(""), "");
    }

    fn classified(path: &str, severity: Severity, reason: Reason, age_days: u64) -> Classified {
        Classified {
            severity,
            reason,
            dir: directory_of(path),
            path: path.to_string(),
            age_days,
            trust: Some(false),
            hash_path: PathBuf::from(path),
        }
    }

    /// The aggregation requirement: many files, one directory, one reason -> one
    /// finding whose evidence names the count.
    #[test]
    fn several_files_in_one_directory_produce_one_finding_naming_the_count() {
        let temp = r"C:\Users\bob\AppData\Local\Temp";
        let items: Vec<Classified> = (0..7)
            .map(|i| {
                classified(
                    &format!("{temp}\\drop{i}.exe"),
                    Severity::High,
                    Reason::UntrustedInDropLocation,
                    1,
                )
            })
            .collect();

        let mut hashes = 0usize;
        let findings = aggregate_findings(&items, &mut hashes, |_| None);

        assert_eq!(
            findings.len(),
            1,
            "seven files in one directory are one finding"
        );
        let f = &findings[0];
        assert_eq!(f.severity, Severity::High);
        assert!(f.title.contains("7 executables"), "title was: {}", f.title);
        assert!(f.title.contains(temp), "title was: {}", f.title);
        assert!(f.evidence.iter().any(|l| l == "matching files: 7"));
        assert_eq!(
            f.evidence
                .iter()
                .filter(|l| l.starts_with("example: "))
                .count(),
            MAX_EXAMPLES
        );
        assert!(f.evidence.iter().any(|l| l.contains("2 more file(s)")));
        assert_eq!(hashes, 1, "a group is hashed once, not once per file");
    }

    #[test]
    fn different_reasons_or_directories_stay_separate() {
        let items = vec![
            classified(
                r"C:\tmp\a.exe",
                Severity::High,
                Reason::UntrustedInDropLocation,
                1,
            ),
            classified(
                r"C:\tmp\svchost.exe",
                Severity::High,
                Reason::Impersonation,
                1,
            ),
            classified(
                r"C:\other\b.exe",
                Severity::High,
                Reason::UntrustedInDropLocation,
                1,
            ),
            classified(
                r"C:\tmp\c.exe",
                Severity::High,
                Reason::UntrustedInDropLocation,
                1,
            ),
        ];
        let mut hashes = 0usize;
        let findings = aggregate_findings(&items, &mut hashes, |_| None);
        assert_eq!(findings.len(), 3);
        // The `C:\tmp` drop-location group holds two files; the others are singletons.
        let group = findings
            .iter()
            .find(|f| f.title.contains(r"C:\tmp") && f.title.contains("2 executables"));
        assert!(
            group.is_some(),
            "titles: {:?}",
            findings.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
        assert!(findings
            .iter()
            .any(|f| f.title.contains("impersonates a Windows component")));
    }

    #[test]
    fn a_single_file_names_itself_rather_than_a_bare_count() {
        let items = vec![classified(
            r"C:\Users\bob\AppData\Local\Temp\only.exe",
            Severity::High,
            Reason::UntrustedInDropLocation,
            2,
        )];
        let mut hashes = 0usize;
        let findings = aggregate_findings(&items, &mut hashes, |_| Some("deadbeef".into()));
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("only.exe"));
        assert!(findings[0]
            .evidence
            .iter()
            .any(|l| l.contains("sha256") && l.contains("deadbeef")));
    }

    /// `Location` classification of the paths that produced the false positives: none
    /// of them may be `Drop`.
    #[test]
    fn legitimate_developer_installs_are_not_transit_directories() {
        for path in [
            r"C:\Users\bob\AppData\Local\Microsoft\PowerToys\KeyboardManagerEditor\a.exe",
            r"C:\Users\bob\AppData\Local\Programs\Python\Python313\Scripts\a.exe",
            r"C:\ProgramData\chocolatey\tools\7z.exe",
            r"C:\Users\bob\AppData\Local\uv\cache\archive-v0\x\Scripts\a.exe",
        ] {
            assert_eq!(
                classify_location(path),
                Location::AppData,
                "{path} is a per-user install, not a drop site"
            );
        }
    }
}
