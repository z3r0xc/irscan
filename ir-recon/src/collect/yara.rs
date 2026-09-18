//! YARA-based content scanning.
//!
//! The rest of the tool reasons about *where* something lives: a path, a service
//! name, a registry key, a publisher. This collector reasons about *what is inside*
//! the file, which is the only axis that still works when an agent is renamed and
//! relocated.
//!
//! It is deliberately narrow, because scanning a whole disk would take longer than
//! the investigation:
//!
//! * only files irscan already has a reason to look at - process images, service
//!   images, scheduled-task actions, autostart commands - plus a bounded walk of the
//!   drop locations, so nothing is scanned merely because it exists;
//! * an executable-ish extension filter, a per-file size cap and a file-count cap;
//! * a per-file scan timeout, so a crafted file cannot stall the run.
//!
//! Every rule is packaged separately, and a rule that fails to compile is a warning
//! rather than a fatal error: a single bad line in an externally supplied rule file
//! (see `--yara-rules`) must not cost the user the whole scan.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use yara_x::{Compiler, MetaValue, Rules, Scanner};

use crate::collect::services::service_executable;
use crate::collect::{CollectError, Collector};
use crate::model::{Finding, HaystackKind, ScanContext, Severity};
use crate::text::sanitize;

/// Upper bound on files scanned in one run.
pub const MAX_FILES: usize = 512;
/// Upper bound on the size of a single scanned file (32 MiB). Anything larger is
/// almost certainly an installer or a game asset, and scanning it would dominate the
/// run for no benefit.
pub const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;
/// Per-file scan budget. YARA can be made slow by a crafted file; a scan that
/// exceeds this is abandoned and reported.
pub const SCAN_TIMEOUT_MS: u64 = 20_000;
/// Matches retained per pattern, to bound memory on a file full of repeats.
pub const MAX_MATCHES_PER_PATTERN: usize = 4;
/// Upper bound on externally supplied rule files.
pub const MAX_RULE_FILES: usize = 32;
/// Upper bound on the size of one externally supplied rule file.
pub const MAX_RULE_BYTES: u64 = 8 * 1024 * 1024;

/// Extensions worth scanning. Scripts are included: a scheduled task that launches a
/// `.ps1` or `.vbs` is a perfectly ordinary way to hide persistence.
const SCANNABLE_EXTENSIONS: &[&str] = &[
    "exe", "dll", "sys", "scr", "ocx", "cpl", "com", "ps1", "vbs", "js", "bat", "cmd", "hta", "jar",
];

/// Rules compiled into the binary.
pub const BUNDLED_RULES: &str = include_str!("../../rules/irscan.yar");

/// Map a rule's `severity` metadata onto our scale.
///
/// An unrecognised or absent severity is `Medium`: the rule matched something the
/// author thought worth reporting, so it should not be silently dropped to Info, and
/// it should not shout either.
pub fn severity_from_meta(pairs: &[(String, String)]) -> Severity {
    for (key, value) in pairs {
        if key.eq_ignore_ascii_case("severity") {
            let v = value.to_ascii_lowercase();
            if v == "critical" || v == "high" {
                return Severity::High;
            }
            if v == "low" || v == "info" || v == "informational" {
                return Severity::Info;
            }
            return Severity::Med;
        }
    }
    Severity::Med
}

/// Pull the keys we care about out of rule metadata.
pub fn meta_value(pairs: &[(String, String)], key: &str) -> Option<String> {
    pairs
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.clone())
        .filter(|v| !v.is_empty())
}

/// Is this a file whose contents are worth scanning?
pub fn is_scannable_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    match lower.rsplit_once('.') {
        Some((_, ext)) => SCANNABLE_EXTENSIONS.contains(&ext),
        None => false,
    }
}

/// Is the file small enough to scan within the budget?
pub fn within_scan_budget(size: u64, max_bytes: u64) -> bool {
    if size == 0 {
        return false;
    }
    size <= max_bytes
}

fn stringify(value: &MetaValue) -> String {
    match value {
        MetaValue::Integer(i) => i.to_string(),
        MetaValue::Float(f) => f.to_string(),
        MetaValue::Bool(b) => b.to_string(),
        MetaValue::String(s) => s.to_string(),
        _ => String::new(),
    }
}

/// Compile every source, isolating failures.
///
/// Returns the compiled rules plus one message per source that failed. Compilation
/// continues after a failure so that one broken external rule file costs the user
/// only that file.
pub fn compile_sources(sources: &[(String, String)]) -> (Rules, Vec<String>) {
    let mut compiler = Compiler::new();
    let mut errors: Vec<String> = Vec::new();
    for (name, source) in sources {
        // SAFETY-free: this is the safe yara-x API. A source that fails to compile
        // returns Err and is recorded, leaving the other sources in place.
        if let Err(e) = compiler.add_source(source.as_str()) {
            errors.push(format!("{name}: {e}"));
        }
    }
    (compiler.build(), errors)
}

fn load_rule_sources(extra: &[PathBuf], warnings: &mut Vec<String>) -> Vec<(String, String)> {
    let mut sources = vec![("bundled".to_string(), BUNDLED_RULES.to_string())];
    for path in extra.iter().take(MAX_RULE_FILES) {
        match std::fs::metadata(path) {
            Ok(meta) if meta.len() <= MAX_RULE_BYTES => {}
            Ok(_) => {
                warnings.push(format!(
                    "yara: файл правил {} больше предела в {} байт; пропущен",
                    path.display(),
                    MAX_RULE_BYTES
                ));
                continue;
            }
            Err(e) => {
                warnings.push(format!(
                    "yara: не удалось прочитать {}: {e}",
                    path.display()
                ));
                continue;
            }
        }
        match std::fs::read_to_string(path) {
            Ok(text) => sources.push((path.display().to_string(), text)),
            Err(e) => warnings.push(format!(
                "yara: не удалось прочитать {}: {e}",
                path.display()
            )),
        }
    }
    sources
}

/// Collect the files worth scanning from what the other collectors already found.
///
/// The tool's own artifacts are excluded. A scanner must not report itself: its
/// binaries contain the very strings the bundled rules look for (a rule that matches
/// `HiddenDesktop` matches the code that hunts for it), so a self-match would sit at
/// the top of every report as a permanent false positive.
///
/// `current_exe()` alone is not enough. The engine ships as two binaries - the console
/// `irscan.exe` and the windowed `irscan-desktop.exe` - and running either one scans
/// the other, because only the *running* image was excluded. On the author's host that
/// produced eight findings naming the tool's own build tree, including two HIGH ones
/// (the tool reporting itself for containing a keylogger's API set, which is the
/// string list it uses to find keyloggers). Every process and service image that
/// belongs to this program is therefore excluded, console or windowed.
fn targets(ctx: &ScanContext) -> Vec<PathBuf> {
    let mut set: BTreeSet<PathBuf> = BTreeSet::new();
    let ours = own_images();

    for record in ctx.processes.values() {
        if let Some(path) = &record.path {
            set.insert(path.clone());
        }
    }
    for service in &ctx.services {
        if let Some(exe) = service_executable(&service.image_path) {
            set.insert(PathBuf::from(exe));
        }
    }
    for task in &ctx.tasks {
        if let Some(exe) = service_executable(&task.action) {
            set.insert(PathBuf::from(exe));
        }
    }
    for autorun in &ctx.autoruns {
        if let Some(exe) = service_executable(&autorun.command) {
            set.insert(PathBuf::from(exe));
        }
    }

    set.into_iter()
        .filter(|p| is_scannable_path(&p.to_string_lossy()))
        .filter(|p| !is_own_image_name(p) && !ours.contains(&normalized(p)))
        .take(MAX_FILES)
        .collect()
}

/// The file names this program's own binaries carry.
///
/// Both spellings are listed rather than only the running one, because the two can be
/// installed side by side and either may be the one running the check.
const OWN_IMAGE_NAMES: &[&str] = &["irscan.exe", "irscan-desktop.exe"];

/// Canonical paths of every copy of this program that the scan could otherwise reach.
///
/// The running executable is resolved through the filesystem so a differently spelled
/// path (`\?\D:\...`, a symlinked directory, a differing letter case) still matches
/// the process table entry. The sibling binary is looked for next to it; a copy in
/// another directory is caught by the file-name check below, which is coarse but
/// cannot miss, and a coarse exclusion that only ever hides the scanner is safer than
/// a precise one that occasionally reports it.
fn own_images() -> BTreeSet<PathBuf> {
    let mut out = BTreeSet::new();
    if let Ok(exe) = std::env::current_exe() {
        out.insert(normalized(&exe));
        if let Some(dir) = exe.parent() {
            for name in OWN_IMAGE_NAMES {
                let sibling = dir.join(name);
                if sibling.try_exists().unwrap_or(false) {
                    out.insert(normalized(&sibling));
                }
            }
        }
    }
    out
}

/// A path in the form two spellings of the same file can be compared in.
///
/// `canonicalize` resolves case, short names and links; when the file cannot be
/// resolved (it is gone, or access is denied) the raw path is lowercased as a fallback,
/// which is still correct on Windows because its paths are case-insensitive.
fn normalized(path: &Path) -> PathBuf {
    match path.canonicalize() {
        Ok(p) => p,
        Err(_) => PathBuf::from(path.to_string_lossy().to_lowercase()),
    }
}

/// Is this file name one of the scanner's own binaries?
fn is_own_image_name(path: &Path) -> bool {
    path.file_name()
        .and_then(|s| s.to_str())
        .map(|n| {
            OWN_IMAGE_NAMES
                .iter()
                .any(|own| n.eq_ignore_ascii_case(own))
        })
        .unwrap_or(false)
}

/// Scan the collected targets with the shipped rules.
pub struct YaraCollector {
    extra_rules: Vec<PathBuf>,
}

impl YaraCollector {
    pub fn new(extra_rules: Vec<PathBuf>) -> Self {
        YaraCollector { extra_rules }
    }
}

impl Collector for YaraCollector {
    fn name(&self) -> &'static str {
        "yara"
    }

    fn run(&self, ctx: &mut ScanContext) -> Result<(), CollectError> {
        let mut warnings: Vec<String> = Vec::new();
        let sources = load_rule_sources(&self.extra_rules, &mut warnings);
        let (rules, compile_errors) = compile_sources(&sources);

        for w in warnings.iter().chain(compile_errors.iter()) {
            ctx.warn(w.to_string());
        }

        let rule_count = rules.iter().count();
        if rule_count == 0 {
            ctx.warn(
                "yara: ни одного правила не скомпилировано, проверка содержимого \
                 полностью пропущена"
                    .to_string(),
            );
            return Ok(());
        }

        let files = targets(ctx);
        let mut scanner = Scanner::new(&rules);
        scanner.set_timeout(Duration::from_millis(SCAN_TIMEOUT_MS));
        scanner.max_matches_per_pattern(MAX_MATCHES_PER_PATTERN);

        let mut lines: Vec<String> = Vec::with_capacity(files.len() + 4);
        lines.push(format!(
            "скомпилировано правил: {rule_count} из {} источник(ов); файлов-кандидатов: {}",
            sources.len(),
            files.len()
        ));

        let mut scanned = 0usize;
        let mut skipped = 0usize;
        let mut scan_errors = 0usize;

        for path in &files {
            let size = match std::fs::metadata(path) {
                Ok(meta) => meta.len(),
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            };
            if !within_scan_budget(size, MAX_FILE_BYTES) {
                skipped += 1;
                continue;
            }

            match scanner.scan_file(path) {
                Ok(results) => {
                    scanned += 1;
                    let mut matched_any = false;
                    for rule in results.matching_rules() {
                        matched_any = true;
                        let mut meta: Vec<(String, String)> = Vec::new();
                        for (key, value) in rule.metadata() {
                            meta.push((key.to_string(), stringify(&value)));
                        }
                        let severity = severity_from_meta(&meta);
                        let description = meta_value(&meta, "description").unwrap_or_else(|| {
                            "правило обнаружения из встроенного набора".to_string()
                        });

                        let mut finding = Finding::new(
                            severity,
                            "yara",
                            format!(
                                "Содержимое файла совпало с правилом YARA '{}'",
                                rule.identifier()
                            ),
                        )
                        .evidence(format!("файл    : {} ({} байт)", path.display(), size))
                        .evidence(format!("правило : {}", rule.identifier()))
                        .evidence(format!("описание правила: {description}"));
                        // The namespace groups rules by origin (bundled vs an
                        // externally supplied rule file), which is what a reader needs
                        // in order to judge how much to trust the match. yara-x also
                        // exposes tags through a wrapper type with no text accessor, so
                        // the namespace is the useful, documented field here.
                        finding = finding.evidence(format!(
                            "набор правил: {} (namespace)",
                            sanitize(rule.namespace(), 64)
                        ));
                        finding = finding
                            .evidence(
                                "Совпадение с правилом YARA — это зацепка, а не приговор. \
                                 Подтвердите его путём к файлу, подписью и сетевыми данными из \
                                 этого отчёта.",
                            )
                            .remediation(
                                "Проверьте файл: если вы или ваш ИТ-отдел его не устанавливали, \
                                 считайте машину скомпрометированной и переустановите систему с \
                                 чистого носителя, а не удаляйте один этот файл.",
                            );
                        ctx.add(finding);

                        ctx.note(
                            HaystackKind::Path,
                            path.to_string_lossy().to_string(),
                            "yara",
                        );
                    }
                    if matched_any {
                        lines.push(format!("СОВПАДЕНИЕ {} :: {:?}", path.display(), rule_count));
                    }
                }
                Err(e) => {
                    scan_errors += 1;
                    lines.push(format!("ОШИБКА {} :: {e}", path.display()));
                }
            }
        }

        lines.push(format!(
            "просканировано={scanned} пропущено={skipped} ошибок={scan_errors}"
        ));
        ctx.raw_section("ПРОВЕРКА СОДЕРЖИМОГО YARA", lines);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn severity_metadata_maps_onto_our_scale() {
        assert_eq!(
            severity_from_meta(&meta(&[("severity", "critical")])),
            Severity::High
        );
        assert_eq!(
            severity_from_meta(&meta(&[("severity", "HIGH")])),
            Severity::High
        );
        assert_eq!(
            severity_from_meta(&meta(&[("severity", "medium")])),
            Severity::Med
        );
        assert_eq!(
            severity_from_meta(&meta(&[("severity", "low")])),
            Severity::Info
        );
        assert_eq!(
            severity_from_meta(&meta(&[("severity", "informational")])),
            Severity::Info
        );
        // An unknown value and a missing key both land on Med, never silently on Info.
        assert_eq!(
            severity_from_meta(&meta(&[("severity", "banana")])),
            Severity::Med
        );
        assert_eq!(severity_from_meta(&meta(&[("author", "x")])), Severity::Med);
        assert_eq!(severity_from_meta(&[]), Severity::Med);
    }

    #[test]
    fn meta_lookup_is_case_insensitive_and_ignores_empty() {
        let pairs = meta(&[("Description", "does a thing"), ("empty", "")]);
        assert_eq!(
            meta_value(&pairs, "description").as_deref(),
            Some("does a thing")
        );
        assert_eq!(meta_value(&pairs, "empty"), None);
        assert_eq!(meta_value(&pairs, "absent"), None);
    }

    #[test]
    fn scannable_extension_filter_is_case_insensitive_and_strict() {
        assert!(is_scannable_path(r"C:\x\agent.exe"));
        assert!(is_scannable_path(r"C:\x\AGENT.EXE"));
        assert!(is_scannable_path(r"C:\x\hook.dll"));
        assert!(is_scannable_path(r"C:\x\task.ps1"));
        assert!(is_scannable_path(r"C:\x\boot.sys"));
        // Logs, config and text are not scanned: rules match code, and scanning
        // everything would blow the time budget.
        assert!(!is_scannable_path(r"C:\x\ad_svc.trace"));
        assert!(!is_scannable_path(r"C:\x\notes.txt"));
        assert!(!is_scannable_path(r"C:\x\noext"));
        assert!(!is_scannable_path(""));
    }

    #[test]
    fn scan_budget_refuses_empty_and_oversized_files() {
        assert!(within_scan_budget(1, MAX_FILE_BYTES));
        assert!(within_scan_budget(MAX_FILE_BYTES, MAX_FILE_BYTES));
        assert!(!within_scan_budget(MAX_FILE_BYTES + 1, MAX_FILE_BYTES));
        assert!(!within_scan_budget(0, MAX_FILE_BYTES));
    }

    #[test]
    fn the_bundled_rule_file_compiles_and_contains_rules() {
        // This is the test that protects the shipped content: a syntax error in
        // rules/irscan.yar would otherwise only show up as a warning at runtime.
        let sources = vec![("bundled".to_string(), BUNDLED_RULES.to_string())];
        let (rules, errors) = compile_sources(&sources);
        assert_eq!(errors, Vec::<String>::new(), "bundled rules must compile");
        assert!(
            rules.iter().count() >= 5,
            "expected the shipped rule set, found {}",
            rules.iter().count()
        );
    }

    /// The hidden-desktop rule must not fire on a stock Windows binary.
    ///
    /// Measured defect: the rule listed `CreateDesktopW` and `SwitchDesktop` among its
    /// strings and required two of them. Those are ordinary `user32` imports - they sit
    /// in the import table as plain text in every process that touches a window station -
    /// so `C:\Windows\System32\winlogon.exe` supplied both and the scanner put a HIGH
    /// "hidden desktop technique" finding on the core of Windows itself.
    ///
    /// The rule now matches only an explicit name for the technique, so a real Windows
    /// image must produce no match. `winlogon.exe` is the specimen rather than a
    /// synthetic buffer because the defect was only visible against the real file.
    #[test]
    fn the_hidden_desktop_rule_does_not_fire_on_a_windows_binary() {
        let path = Path::new(r"C:\Windows\System32\winlogon.exe");
        if !path.try_exists().unwrap_or(false) {
            return; // not running on Windows, or a layout without winlogon
        }
        let data = std::fs::read(path).expect("read winlogon.exe");
        let sources = vec![("bundled".to_string(), BUNDLED_RULES.to_string())];
        let (rules, errors) = compile_sources(&sources);
        assert_eq!(errors, Vec::<String>::new());

        let mut scanner = Scanner::new(&rules);
        let matched: Vec<String> = scanner
            .scan(&data)
            .expect("scan")
            .matching_rules()
            .map(|r| r.identifier().to_string())
            .collect();

        assert!(
            !matched.iter().any(|r| r == "irscan_hidden_desktop_marker"),
            "winlogon.exe must not match the hidden-desktop rule, matched: {matched:?}"
        );
    }

    #[test]
    fn a_broken_source_is_isolated_and_the_good_one_survives() {
        let sources = vec![
            (
                "good".to_string(),
                "rule irscan_test_ok { strings: $a = \"irscan-test-needle\" condition: $a }"
                    .to_string(),
            ),
            (
                "bad".to_string(),
                "rule irscan_test_broken { strings: $a = condition: $a }".to_string(),
            ),
        ];
        let (rules, errors) = compile_sources(&sources);
        assert_eq!(errors.len(), 1, "exactly one source should fail");
        assert!(errors[0].starts_with("bad:"), "got {errors:?}");
        assert_eq!(rules.iter().count(), 1, "the good rule must survive");
    }

    #[test]
    fn a_rule_actually_matches_its_needle() {
        // End-to-end through the engine, without touching the filesystem.
        let sources = vec![(
            "test".to_string(),
            "rule irscan_test_match { strings: $a = \"irscan-needle-xyz\" condition: $a }"
                .to_string(),
        )];
        let (rules, errors) = compile_sources(&sources);
        assert_eq!(errors.len(), 0);
        let mut scanner = Scanner::new(&rules);
        let data = b"prefix irscan-needle-xyz suffix";
        let results = scanner
            .scan(data)
            .unwrap_or_else(|e| panic!("scan failed: {e}"));
        let names: Vec<&str> = results.matching_rules().map(|r| r.identifier()).collect();
        assert_eq!(names, vec!["irscan_test_match"]);

        let clean = scanner.scan(b"nothing interesting here");
        if let Ok(res) = clean {
            assert_eq!(res.matching_rules().count(), 0);
        }
    }

    #[test]
    fn target_selection_runs_over_collected_records() {
        // Empty context: nothing to scan, and no panic.
        let ctx = ScanContext::default();
        assert!(targets(&ctx).is_empty());
    }

    #[test]
    fn the_scanner_never_targets_its_own_image() {
        // The binary contains the strings the rules match, so scanning itself would
        // produce two permanent HIGH findings in every report.
        let own = std::env::current_exe().unwrap_or_default();
        let mut ctx = ScanContext::default();
        ctx.processes.insert(
            1,
            crate::model::ProcessRecord {
                pid: 1,
                ppid: 0,
                name: "irscan.exe".to_string(),
                path: Some(own.clone()),
                cmdline: String::new(),
                owner: String::new(),
                started: None,
                signature_trusted: None,
                company: None,
            },
        );
        assert!(
            !targets(&ctx).contains(&own),
            "the running executable must be excluded from the scan"
        );
    }

    /// Both spellings of this program are excluded, not only the running one.
    ///
    /// Measured on the author's host: running the console `irscan.exe` scanned the
    /// windowed `irscan-desktop.exe` sitting beside it, because only `current_exe()`
    /// was excluded. The result was eight findings naming the tool's own build tree,
    /// including two HIGH ones - the scanner reporting itself as containing a
    /// keylogger's API set, which is the string list it uses to *find* keyloggers.
    #[test]
    fn neither_binary_of_this_program_is_scanned() {
        assert!(is_own_image_name(Path::new(r"D:\build\irscan.exe")));
        assert!(is_own_image_name(Path::new(r"D:\build\irscan-desktop.exe")));
        assert!(is_own_image_name(Path::new(r"D:\build\IRSCAN-DESKTOP.EXE")));
        // A different program whose name merely starts the same way is not ours.
        assert!(!is_own_image_name(Path::new(r"D:\build\irscan-helper.exe")));
        assert!(!is_own_image_name(Path::new(r"D:\build\not-irscan.exe")));
    }

    /// A copy that cannot be resolved to a canonical path is still matched by name,
    /// which is what makes the exclusion hold for a build tree the scan can only see
    /// through the process table.
    #[test]
    fn an_unresolvable_path_still_normalizes_to_something_comparable() {
        let missing = Path::new(r"D:\does\not\exist\IRScan-Desktop.exe");
        assert!(!normalized(missing).as_os_str().is_empty());
        assert_eq!(
            normalized(missing),
            normalized(Path::new(r"d:\DOES\NOT\EXIST\irscan-desktop.exe")),
            "case must not decide whether two spellings of one path compare equal"
        );
    }
}
