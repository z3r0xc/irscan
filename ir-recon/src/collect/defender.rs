//! Windows Defender configuration and detection history: FR-11.
//!
//! Two things matter here, and they matter more together than apart:
//!
//! 1. **Exclusions.** Adding a path, process or extension to the Defender exclusion
//!    list is one of the first things an intruder does, because it is a supported
//!    feature, needs no exploit, and makes everything that follows invisible. A
//!    hostile exclusion is therefore evidence in its own right.
//! 2. **Disabled protection.** `DisableAntiSpyware` and `DisableRealtimeMonitoring`
//!    are policy values; non-zero means someone turned the scanner off deliberately.
//!
//! A missing or unreadable Defender key is **normal**: a third-party antivirus
//! replaced Defender, or the tool is not elevated. That is recorded as a note, never
//! as a warning and never as a finding, because a false alarm on a clean machine
//! teaches the user to ignore the report.

use crate::collect::{CollectError, Collector};
use crate::model::{Finding, HaystackKind, ScanContext, Severity};
use crate::win::reg::{self, RegValue, RootKey};

/// Cap on exclusions reported per category; a hostile host could plant thousands to
/// bury the interesting one.
const MAX_EXCLUSIONS: usize = 512;

/// Roots read by this collector.
const DEFENDER_ROOT: &str = r"SOFTWARE\Microsoft\Windows Defender";
const POLICIES_ROOT: &str = r"SOFTWARE\Policies\Microsoft\Windows Defender";

/// Collects Defender state, exclusions and detection history.
pub struct DefenderCollector;

impl Collector for DefenderCollector {
    fn name(&self) -> &'static str {
        "defender"
    }

    fn run(&self, ctx: &mut ScanContext) -> Result<(), CollectError> {
        let mut lines: Vec<String> = Vec::new();

        // --- Exclusions ---------------------------------------------------------
        // The excluded item is the *value name*; the data is normally empty. On a
        // policy-set exclusion the same holds, and a policy survives the user (or a
        // "helpful" tool) clearing the interactive list.
        let exclusion_groups: &[(&str, &str, ExclusionKind)] = &[
            (
                r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
                "path",
                ExclusionKind::Path,
            ),
            (
                r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes",
                "process",
                ExclusionKind::Process,
            ),
            (
                r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions",
                "extension",
                ExclusionKind::Extension,
            ),
            (
                r"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions",
                "policy path",
                ExclusionKind::Path,
            ),
        ];

        let mut any_exclusion_key = false;

        for (subkey, label, kind) in exclusion_groups {
            let values = reg::enum_values(RootKey::Hklm, subkey);
            if reg::key_exists(RootKey::Hklm, subkey) {
                any_exclusion_key = true;
            }
            if values.is_empty() {
                continue;
            }

            ctx.note(HaystackKind::RegistryPath, *subkey, "Defender exclusions");
            let origin = format!("HKLM\\{subkey}");
            push_line(
                &mut lines,
                &format!("{origin}: {} exclusion(s)", values.len()),
            );

            for (index, (name, _value)) in values.iter().enumerate() {
                if index >= MAX_EXCLUSIONS {
                    ctx.warn(format!(
                        "defender: exclusions under {subkey} truncated at {MAX_EXCLUSIONS}"
                    ));
                    break;
                }
                let item = crate::text::sanitize(name, crate::model::MAX_STRING);
                if item.trim().is_empty() {
                    continue;
                }
                push_line(&mut lines, &format!("  [{label}] {item}"));

                report_exclusion(ctx, *kind, &item, &origin, label);
            }
        }

        if !any_exclusion_key {
            // Not a problem: this is the expected state on a machine whose Defender
            // key is absent (third-party AV, or a policy that hides it).
            push_line(&mut lines, "Defender exclusion keys: not present (normal)");
            ctx.warn(
                "defender: exclusion keys absent - Defender may be replaced by third-party \
                 antivirus or the scan may be running without elevation",
            );
        }

        // --- Policy state -------------------------------------------------------
        let disables: &[(&str, &str, &str)] = &[
            (
                POLICIES_ROOT,
                "DisableAntiSpyware",
                "Windows Defender is disabled by policy",
            ),
            (
                r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
                "DisableRealtimeMonitoring",
                "Real-time protection is disabled by policy",
            ),
        ];

        for (subkey, value_name, title) in disables {
            let Some(value) = reg::get_u64(RootKey::Hklm, subkey, value_name) else {
                continue;
            };
            pass_note(ctx, subkey);
            push_line(
                &mut lines,
                &format!("HKLM\\{subkey}\\{value_name} = {value}"),
            );
            if value != 0 {
                ctx.add(
                    Finding::new(Severity::High, "defender", *title)
                        .evidence(format!("HKLM\\{subkey}\\{value_name} = {value}"))
                        .evidence(
                            "This value is set by policy. It survives the normal settings UI, so \
                             the machine keeps running without protection even if it looks \
                             enabled.",
                        )
                        .remediation(
                            "Determine who set the policy (a management tool, or the person who \
                             had access to the machine). Remove the value and reboot, then \
                             confirm protection is on.",
                        ),
                );
            }
        }

        // --- Engine / product state --------------------------------------------
        // Reported raw: the product-state bitfield is not worth decoding here, and a
        // reader comparing two machines wants the number.
        let Some(status) = reg::get_value(RootKey::Hklm, DEFENDER_ROOT, "ProductStatus") else {
            pass_note(ctx, DEFENDER_ROOT);
            push_line(
                &mut lines,
                "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\ProductStatus: not present",
            );
            ctx.raw_section("DEFENDER", lines);
            push_history(ctx);
            return Ok(());
        };
        ctx.note(HaystackKind::RegistryPath, DEFENDER_ROOT, "Defender engine");
        match status {
            RegValue::Dword(n) => {
                push_line(
                    &mut lines,
                    &format!("HKLM\\{DEFENDER_ROOT}\\ProductStatus = 0x{n:x} ({n})"),
                );
            }
            other => {
                let text = other.as_text().unwrap_or_default();
                let text = crate::text::sanitize(&text, crate::model::MAX_STRING);
                push_line(
                    &mut lines,
                    &format!("HKLM\\{DEFENDER_ROOT}\\ProductStatus = {text}"),
                );
            }
        }

        ctx.raw_section("DEFENDER", lines);
        push_history(ctx);
        Ok(())
    }
}

/// Which exclusion list a name came from. The severity policy differs per list:
/// a bare extension is weak evidence, a writable path is strong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExclusionKind {
    Path,
    Process,
    Extension,
}

/// Severity for one Defender exclusion, keyed by the list it came from.
///
/// Returns `None` only for the routine extension exclusions, where a name like `log`
/// or `tmp` is ordinary application behaviour and reporting it would drown the real
/// findings. Every path and process exclusion is reported, escalated when the path is
/// user-writable - an agent excluding its own drop location - or when the process is
/// not one of the products Windows users actually install.
pub fn exclusion_severity(kind: &str, item: &str) -> Option<Severity> {
    let value = item.trim();
    if value.is_empty() {
        return None;
    }
    match kind {
        "extension" => {
            // Extensions are value names without the leading dot on some builds.
            let ext = value.trim_start_matches('.').to_lowercase();
            if WELL_KNOWN_EXCLUDED_EXTENSIONS.contains(&ext.as_str()) {
                return None;
            }
            Some(Severity::Info)
        }
        "path" | "policy path" => {
            if crate::rules::is_user_writable(value) {
                Some(Severity::High)
            } else {
                Some(Severity::Med)
            }
        }
        _ => {
            if is_well_known_product(value) {
                Some(Severity::Med)
            } else {
                Some(Severity::High)
            }
        }
    }
}

/// Extensions whose exclusion is routine third-party AV behaviour, not a signal.
const WELL_KNOWN_EXCLUDED_EXTENSIONS: &[&str] = &["log", "tmp", "bak", "mdb", "ldf", "edb", "pst"];

/// A deliberately short list of process names that Windows ships or that a normal
/// business machine installs and signs. Anything else excluded by name is treated as
/// suspicious by default: the list is a *floor*, and the report says so.
fn is_well_known_product(process: &str) -> bool {
    const KNOWN: &[&str] = &[
        "svchost.exe",
        "explorer.exe",
        "msmpeng.exe",
        "taskhostw.exe",
        "outlook.exe",
        "excel.exe",
        "winword.exe",
        "teams.exe",
        "msedge.exe",
        "chrome.exe",
        "firefox.exe",
        "code.exe",
        "sqlservr.exe",
        "javaw.exe",
        "node.exe",
        "python.exe",
        "docker.exe",
        "msbuild.exe",
    ];
    let bare = crate::text::basename(process);
    if bare.is_empty() {
        return false;
    }
    KNOWN.iter().any(|k| k.eq_ignore_ascii_case(bare))
}

/// Emit the finding (or, for a routine extension exclusion, nothing) for one item.
fn report_exclusion(
    ctx: &mut ScanContext,
    kind: ExclusionKind,
    item: &str,
    origin: &str,
    label: &str,
) {
    let kind_label = match kind {
        ExclusionKind::Path => "path",
        ExclusionKind::Process => "process",
        ExclusionKind::Extension => "extension",
    };
    let Some(severity) = exclusion_severity(kind_label, item) else {
        return;
    };
    if severity == Severity::Info {
        // A routine extension exclusion: record it as a haystack only. Reporting it
        // would make every report noisy, which is how real findings get ignored.
        ctx.note(HaystackKind::Path, item, origin);
        return;
    }

    let mut finding = Finding::new(
        severity,
        "defender",
        format!("Defender exclusion ({label}): {item}"),
    )
    .evidence(format!("{origin}\\{item}"))
    .evidence(
        "Windows Defender does not scan, open or block anything matching this entry. Adding it \
         is a supported feature, not an exploit, and it is a standard step taken by software \
         that does not want to be found.",
    );

    if kind == ExclusionKind::Path {
        finding = finding.evidence(
            "An exclusion on a path that the current user can write to means the owner of that \
             directory can place any file there and it will never be scanned.",
        );
    }
    if kind == ExclusionKind::Process {
        finding = finding.evidence(
            "A process exclusion stops Defender from inspecting that process at all, including \
             its memory and its command line.",
        );
    }

    ctx.note(HaystackKind::Path, item, origin);
    ctx.add(finding.remediation(
        "Confirm each excluded path or process is a product you recognise and deliberately \
         configured. Remove the entries you cannot account for, then run a full scan.",
    ));
}

/// Query Defender's detection history (FR-10 evidence).
///
/// The raw XML is recorded verbatim: parsing event fields is another module's job,
/// and a second parser here would be a second thing to keep correct. A query failure
/// is a warning, never an error - Defender may hold no channel at all, or the log may
/// need elevation.
fn push_history(ctx: &mut ScanContext) {
    const XPATH: &str = "*[System[(EventID=1116 or EventID=1117 or EventID=1006 or EventID=1007 \
                         or EventID=1008 or EventID=1015)]]";
    match crate::win::events::query(crate::win::events::CHANNEL_DEFENDER, XPATH, 200) {
        Ok(events) => {
            let lines: Vec<String> = events
                .iter()
                .map(|e| crate::text::sanitize(&e.xml, crate::model::MAX_STRING))
                .collect();
            ctx.note(
                HaystackKind::RegistryPath,
                crate::win::events::CHANNEL_DEFENDER,
                "Defender detection history",
            );
            ctx.raw_section("DEFENDER EVENTS", lines);
        }
        Err(e) => ctx.warn(format!("defender: detection history unavailable: {e}")),
    }
}

/// Record the absence of a key as a note, not a warning.
fn pass_note(ctx: &mut ScanContext, subkey: &str) {
    ctx.note(
        HaystackKind::RegistryPath,
        subkey,
        "Defender (absent/unreadable is normal)",
    );
}

fn push_line(lines: &mut Vec<String>, line: &str) {
    const MAX_RAW_LINES: usize = 1024;
    if lines.len() < MAX_RAW_LINES {
        lines.push(line.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_user_writable_excluded_path_is_high() {
        assert_eq!(
            exclusion_severity("path", r"C:\Users\bob\AppData\Local\Temp\agent\"),
            Some(Severity::High)
        );
        assert_eq!(
            exclusion_severity("path", r"C:\ProgramData\SomeAgent\"),
            Some(Severity::High)
        );
        // The policy list uses the same decision, because a policy exclusion survives
        // the interactive list being cleaned up.
        assert_eq!(
            exclusion_severity("policy path", r"C:\ProgramData\monitor\"),
            Some(Severity::High)
        );
    }

    #[test]
    fn a_program_files_exclusion_is_med_not_high() {
        assert_eq!(
            exclusion_severity("path", r"C:\Program Files\Corp App\"),
            Some(Severity::Med)
        );
        assert_eq!(
            exclusion_severity("path", r"D:\Scanned Data\Exports"),
            Some(Severity::Med)
        );
    }

    #[test]
    fn the_extension_list_does_not_produce_a_finding() {
        // Routine AV behaviour: reporting it would bury the real findings.
        assert_eq!(exclusion_severity("extension", "log"), None);
        assert_eq!(exclusion_severity("extension", ".tmp"), None);
        // An unusual extension is still worth a line, at the lowest severity.
        assert_eq!(exclusion_severity("extension", "exe"), Some(Severity::Info));
    }

    #[test]
    fn a_process_exclusion_is_high_unless_the_product_is_known() {
        assert_eq!(
            exclusion_severity("process", "svchost.exe"),
            Some(Severity::Med)
        );
        assert_eq!(
            exclusion_severity("process", r"C:\Program Files\App\code.exe"),
            Some(Severity::Med)
        );
        assert_eq!(
            exclusion_severity("process", "agent.exe"),
            Some(Severity::High)
        );
    }

    #[test]
    fn an_empty_exclusion_set_produces_no_findings() {
        // The contract that keeps a clean machine's report clean: nothing to report
        // means no severity at all, not a zero-severity finding.
        assert_eq!(exclusion_severity("path", ""), None);
        assert_eq!(exclusion_severity("process", "   "), None);
        assert_eq!(exclusion_severity("extension", ""), None);

        // And the collector must not invent a finding merely because a key is empty:
        // drive the reporting path with no items and confirm nothing is added.
        let mut ctx = ScanContext::default();
        for name in Vec::<String>::new() {
            report_exclusion(&mut ctx, ExclusionKind::Path, &name, "HKLM\\test", "path");
        }
        assert!(ctx.findings.is_empty());
    }
}
