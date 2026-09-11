//! Autostart (autorun) enumeration: FR-5.
//!
//! The registry is where the overwhelming majority of persistent, user-mode agents
//! live, because it survives reboots and needs no service install (no elevation, no
//! event 7045). This collector walks the classic autostart locations documented by
//! Microsoft and by the Autoruns tool, records each one as an [`AutorunRecord`], and
//! raises a finding only where the location itself is a known hijack point or the
//! command executes from a user-writable path.
//!
//! The rule that keeps this module honest: a value is **never** reported just for
//! existing. `HKCU\...\Run` is normal software behaviour. What is reported is
//! (a) a location whose *documented default value* has changed, and (b) a command
//! whose executable lives somewhere a non-elevated writer can reach.
//!
//! All strings that come from the registry are expanded (`REG_EXPAND_SZ` is the norm
//! here) and sanitised before they reach a record, a finding or the raw section.

use crate::collect::{CollectError, Collector};
use crate::model::{Finding, HaystackKind, ScanContext, Severity};
use crate::win::reg::{self, RegValue, RootKey};

/// Cap on subkeys walked under Image File Execution Options. IFEO holds a few
/// hundred entries on a normal machine; a hostile host could plant thousands.
const MAX_IFEO_SUBKEYS: usize = 512;

/// Cap on lines pushed into the raw AUTORUNS section.
const MAX_RAW_LINES: usize = 2048;

/// The Winlogon values whose defaults are documented and worth comparing against.
/// `Shell` and `Userinit` are the two that actually start the user's session; a
/// change to either is the classic "logon persistence" trick. `Taskman` is read but
/// has no default on modern Windows; `AppSetup` has never had one.
const WINLOGON_DEFAULTS: &[(&str, &str)] = &[
    ("Shell", "explorer.exe"),
    ("Userinit", r"C:\Windows\system32\userinit.exe,"),
    ("Taskman", ""),
    ("AppSetup", ""),
];

/// `BootExecute` default. Anything else runs a native program *before* Windows
/// starts, which is both rare and high-impact.
const BOOT_EXECUTE_DEFAULT: &[&str] = &["autocheck autochk *"];

/// Collects autostart entries from the registry.
pub struct AutorunsCollector;

impl Collector for AutorunsCollector {
    fn name(&self) -> &'static str {
        "autoruns"
    }

    fn run(&self, ctx: &mut ScanContext) -> Result<(), CollectError> {
        let mut lines: Vec<String> = Vec::new();

        // --- Run / RunOnce, HKLM + HKCU + the WOW6432Node mirror -----------------
        // A 32-bit Run key is read by 32-bit processes; a hostile agent can hide
        // exclusively there, so both views must be enumerated.
        let run_locations: &[(RootKey, &str)] = &[
            (
                RootKey::Hklm,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            ),
            (
                RootKey::Hklm,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            ),
            (
                RootKey::Hkcu,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            ),
            (
                RootKey::Hkcu,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            ),
            (
                RootKey::Hklm,
                r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
            ),
            (
                RootKey::Hklm,
                r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
            ),
        ];

        for (root, subkey) in run_locations {
            let (origin, label) = describe(*root, subkey);
            ctx.note(HaystackKind::RegistryPath, *subkey, origin.clone());

            let entries = reg::enum_values(*root, subkey);
            push_line(
                &mut lines,
                &format!("{origin} ({label}): {} value(s)", entries.len()),
            );

            for (name, value) in &entries {
                let raw = value.as_text().unwrap_or_default();
                let command = crate::win::expand(&raw);
                let command = crate::text::sanitize(&command, crate::model::MAX_STRING);

                ctx.autoruns.push(crate::model::AutorunRecord {
                    location: origin.clone(),
                    name: crate::text::sanitize(name, crate::model::MAX_STRING),
                    command: command.clone(),
                });
                push_line(&mut lines, &format!("{origin}\\{name} = {command}"));

                ctx.note(HaystackKind::RegistryPath, origin.clone(), origin.clone());
                ctx.note(HaystackKind::Path, command.clone(), origin.clone());
                if !name.is_empty() {
                    ctx.note(HaystackKind::ServiceName, name.clone(), origin.clone());
                }

                // A Run value with an empty *name* is legal in the registry but is
                // not something legitimate software does: it exists to be hard to
                // find and to be attributed to nothing.
                if name.trim().is_empty() && !command.trim().is_empty() {
                    ctx.add(
                        Finding::new(
                            Severity::Med,
                            "persistence",
                            "Unnamed Run autostart value",
                        )
                        .evidence(format!(
                            "{origin} contains a value with an empty name running: {command}"
                        ))
                        .evidence(
                            "Legitimate installers always name their Run values; an empty name \
                             is used to make the entry hard to find in Regedit.",
                        )
                        .remediation(format!(
                            "Inspect {origin}; if the command is not recognised, export the key \
                             for evidence and then delete the unnamed value."
                        )),
                    );
                }

                report_command(ctx, &command, &origin, name);
            }
        }

        // --- Winlogon -----------------------------------------------------------
        let winlogon = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
        ctx.note(HaystackKind::RegistryPath, winlogon, "HKLM Winlogon");
        for (value_name, expected) in WINLOGON_DEFAULTS {
            let Some(value) = reg::get_value(RootKey::Hklm, winlogon, value_name) else {
                continue;
            };
            let raw = value.as_text().unwrap_or_default();
            let actual = crate::win::expand(&raw);
            let actual = crate::text::sanitize(&actual, crate::model::MAX_STRING);
            push_line(
                &mut lines,
                &format!("HKLM\\{winlogon}\\{value_name} = {actual}"),
            );
            ctx.note(HaystackKind::Path, actual.clone(), "HKLM Winlogon");

            if !is_default_winlogon_value(value_name, &actual, expected) {
                ctx.add(
                    Finding::new(
                        Severity::High,
                        "persistence",
                        format!("Winlogon {value_name} deviates from the default"),
                    )
                    .evidence(format!("HKLM\\{winlogon}\\{value_name} = {actual}"))
                    .evidence(format!("Documented default: {expected}"))
                    .evidence(
                        "Winlogon runs this value in every interactive session, so a changed \
                         value starts the attacker's program at every logon.",
                    )
                    .remediation(
                        "Restore the documented default, but only after saving the current \
                         value: it names what is running as the logged-on user.",
                    ),
                );
            }
        }

        // --- AppInit_DLLs -------------------------------------------------------
        // Present on modern Windows only for compatibility; a non-empty value injects
        // a DLL into every process that loads user32.dll.
        for subkey in [
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
            r"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
        ] {
            ctx.note(HaystackKind::RegistryPath, subkey, "HKLM AppInit_DLLs");
            let Some(value) = reg::get_value(RootKey::Hklm, subkey, "AppInit_DLLs") else {
                continue;
            };
            let raw = value.as_text().unwrap_or_default();
            // The value is often a REG_SZ of semicolon- or space- separated DLL paths.
            let dlls = crate::win::expand(&raw);
            let dlls = crate::text::sanitize(&dlls, crate::model::MAX_STRING);
            if dlls.trim().is_empty() {
                push_line(
                    &mut lines,
                    &format!("HKLM\\{subkey}\\AppInit_DLLs = (empty)"),
                );
                continue;
            }
            push_line(
                &mut lines,
                &format!("HKLM\\{subkey}\\AppInit_DLLs = {dlls}"),
            );
            ctx.note(HaystackKind::Path, dlls.clone(), "AppInit_DLLs");

            ctx.add(
                Finding::new(
                    Severity::High,
                    "persistence",
                    "AppInit_DLLs is set (DLL injection into every GUI process)",
                )
                .evidence(format!("HKLM\\{subkey}\\AppInit_DLLs = {dlls}"))
                .evidence(
                    "AppInit_DLLs injects the named DLL into every process that loads user32.dll. \
                     Microsoft ships this feature off and empty on Windows 10; software that \
                     needs it is rare outside of malware and old accessibility tools.",
                )
                .remediation(
                    "Identify each DLL listed here. Unless it is a product you deliberately \
                     installed and can name, clear AppInit_DLLs and re-check for the file.",
                ),
            );
        }

        // --- Image File Execution Options: "Debugger" hijack --------------------
        // IFEO\\<image>\\Debugger replaces the named binary with whatever the value
        // points at, for every launch of that binary, for every user.
        let ifeo_root =
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
        ctx.note(HaystackKind::RegistryPath, ifeo_root, "HKLM IFEO");
        let subkeys = reg::enum_subkeys(RootKey::Hklm, ifeo_root);
        push_line(
            &mut lines,
            &format!("HKLM\\{ifeo_root}: {} subkey(s)", subkeys.len()),
        );
        for (index, image) in subkeys.iter().enumerate() {
            if index >= MAX_IFEO_SUBKEYS {
                ctx.warn(format!(
                    "autoruns: image file execution options truncated at {MAX_IFEO_SUBKEYS} subkeys"
                ));
                break;
            }
            let sub = format!("{ifeo_root}\\{image}");
            let Some(value) = reg::get_value(RootKey::Hklm, &sub, "Debugger") else {
                continue;
            };
            let raw = value.as_text().unwrap_or_default();
            let debugger = crate::win::expand(&raw);
            let debugger = crate::text::sanitize(&debugger, crate::model::MAX_STRING);
            if debugger.trim().is_empty() {
                continue;
            }
            push_line(&mut lines, &format!("HKLM\\{sub}\\Debugger = {debugger}"));
            ctx.autoruns.push(crate::model::AutorunRecord {
                location: format!("HKLM\\{sub}"),
                name: crate::text::sanitize(image, crate::model::MAX_STRING),
                command: debugger.clone(),
            });
            ctx.note(HaystackKind::Path, debugger.clone(), "HKLM IFEO Debugger");
            ctx.note(
                HaystackKind::ServiceName,
                image.clone(),
                "HKLM IFEO Debugger",
            );

            ctx.add(
                Finding::new(
                    Severity::High,
                    "persistence",
                    format!("Image File Execution Options Debugger set for {image}"),
                )
                .evidence(format!("HKLM\\{sub}\\Debugger = {debugger}"))
                .evidence(
                    "A Debugger value silently redirects every launch of this image to the named \
                     program. It is the standard way to run code in place of a trusted binary.",
                )
                .remediation(
                    "Delete the Debugger value unless it belongs to a debugger you are actively \
                     using. Then verify the original image is the one Microsoft shipped.",
                ),
            );
        }

        // --- Session Manager: BootExecute ---------------------------------------
        let session_manager = r"SYSTEM\CurrentControlSet\Control\Session Manager";
        ctx.note(
            HaystackKind::RegistryPath,
            session_manager,
            "HKLM Session Manager",
        );
        if let Some(value) = reg::get_value(RootKey::Hklm, session_manager, "BootExecute") {
            let entries: Vec<String> = match &value {
                RegValue::MultiStr(v) => v.clone(),
                other => other.as_text().into_iter().collect(),
            };
            let entries: Vec<String> = entries
                .into_iter()
                .map(|e| crate::win::expand(&e))
                .map(|e| crate::text::sanitize(&e, crate::model::MAX_STRING))
                .filter(|e| !e.trim().is_empty())
                .collect();
            push_line(
                &mut lines,
                &format!(
                    "HKLM\\{session_manager}\\BootExecute = {}",
                    entries.join(" | ")
                ),
            );
            for entry in &entries {
                ctx.note(HaystackKind::Path, entry.clone(), "BootExecute");
            }
            if !is_default_boot_execute(&entries) {
                ctx.add(
                    Finding::new(
                        Severity::Med,
                        "persistence",
                        "BootExecute is not the default",
                    )
                    .evidence(format!(
                        "HKLM\\{session_manager}\\BootExecute = {}",
                        entries.join(" | ")
                    ))
                    .evidence("Default on Windows 10: autocheck autochk *")
                    .evidence(
                        "BootExecute runs natively before the Win32 subsystem starts, so it is \
                         invisible to most monitoring and cannot be removed while the system runs.",
                    )
                    .remediation(
                        "Restore the default value (`autocheck autochk *`) after recording what \
                         was there. A native executable named here must be treated as a rootkit \
                         until identified.",
                    ),
                );
            }
        }

        truncate_lines(&mut lines);
        ctx.raw_section("AUTORUNS", lines);
        Ok(())
    }
}

/// Names of the roots, for evidence lines and record labels.
fn describe(root: RootKey, subkey: &str) -> (String, &'static str) {
    let prefix = match root {
        RootKey::Hklm => "HKLM",
        RootKey::Hkcu => "HKCU",
        RootKey::Hkcr => "HKCR",
        RootKey::Hku => "HKU",
    };
    let label = if subkey.contains("Wow6432Node") {
        "32-bit view"
    } else if subkey.ends_with("RunOnce") {
        "runs once"
    } else {
        "runs at logon"
    };
    (format!("{prefix}\\{subkey}"), label)
}

/// Build the per-command finding: does this execute from a place a non-elevated
/// writer can reach?
fn report_command(ctx: &mut ScanContext, command: &str, location: &str, name: &str) {
    let exe = extract_executable(command);
    if exe.is_empty() {
        return;
    }
    if !crate::rules::is_user_writable(&exe) {
        return;
    }
    let trusted = signature_trust(&exe);
    let Some(severity) = crate::rules::execution_severity(trusted, true) else {
        return;
    };
    let trust_line = match trusted {
        Some(true) => "signature: valid".to_string(),
        Some(false) => "signature: NOT valid".to_string(),
        None => "signature: could not be verified".to_string(),
    };
    ctx.add(
        Finding::new(
            severity,
            "persistence",
            format!("Autostart entry runs from a user-writable path: {name}"),
        )
        .evidence(format!("{location}\\{name} = {command}"))
        .evidence(format!("Executable: {exe}"))
        .evidence(trust_line)
        .evidence(
            "A user-writable path can be modified by any process running as this user, so an \
             autostart entry there executes whatever replaces the file, with no prompt.",
        )
        .remediation(
            "If this is not software you installed, move the file to external media for \
             analysis and disable the autostart entry.",
        ),
    );
}

/// Signature trust for a path, or `None` when the file is absent or the check
/// cannot run. Missing files are common here (an uninstaller that left its Run value
/// behind) and must never abort the collector.
fn signature_trust(path: &str) -> Option<bool> {
    if path.is_empty() {
        return None;
    }
    let p = std::path::Path::new(path);
    if !p.is_file() {
        return None;
    }
    // `is_signature_trusted` itself yields `None` for a missing/inaccessible file,
    // so the fast path above is an optimisation, not the safety guarantee.
    crate::win::sig::is_signature_trusted(p)
}

/// Extract the executable path from an autostart command line.
///
/// Rules, in order: strip the surrounding quotes the registry convention uses;
/// if the result is quoted, take up to the closing quote (the quoted part is the
/// executable and everything after it is arguments); otherwise take up to the first
/// space *only when the token ends in an executable extension*, so that
/// `C:\Program Files\App\App.exe -run` is not cut at `C:\Program`.
///
/// Pure: takes the already-expanded, already-sanitised command string.
pub fn extract_executable(command: &str) -> String {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    // Case 1: the value is `"C:\path with spaces\app.exe" args...` - the first
    // closing quote delimits the executable.
    if let Some(rest) = trimmed.strip_prefix('"') {
        if let Some(end) = rest.find('"') {
            return crate::text::unquote(&rest[..end]).to_string();
        }
        // Unterminated quote: treat the remainder as the path rather than guessing.
        return crate::text::unquote(rest).to_string();
    }

    // Case 2: no quotes. A path with spaces and arguments is ambiguous at the text
    // level; prefer the interpretation that yields an executable, i.e. cut at the
    // end of the first token that carries an .exe/.com/.bat/.cmd/.scr/.dll suffix.
    let lower = trimmed.to_lowercase();
    for ext in [".exe", ".com", ".bat", ".cmd", ".scr", ".dll", ".sys"] {
        if let Some(pos) = lower.find(ext) {
            let end = pos + ext.len();
            // Only accept the split when the next character really ends the token.
            let next = lower[end..].chars().next();
            if next.is_none() || next == Some(' ') || next == Some('\t') {
                return crate::text::unquote(&trimmed[..end]).to_string();
            }
        }
    }

    // No recognisable executable token: the value may be a bare path, a URI or a
    // script command. Return the first whitespace-free token.
    let token = trimmed.split_whitespace().next().unwrap_or("");
    crate::text::unquote(token).to_string()
}

/// Is the Winlogon value at its documented default? Comparison is case-insensitive
/// and whitespace-tolerant for the comma form of `Userinit`.
pub fn is_default_winlogon_value(value_name: &str, actual: &str, expected: &str) -> bool {
    let name = value_name.to_lowercase();
    let expected_norm = normalize_default(expected);
    let Some(actual_norm) = normalize_actual(value_name, actual) else {
        // An absent or unreadable value is not a deviation that can be proven.
        return true;
    };
    let _ = name;
    actual_norm == expected_norm
}

fn normalize_default(expected: &str) -> String {
    expected.trim().trim_end_matches(',').to_lowercase()
}

fn normalize_actual(value_name: &str, actual: &str) -> Option<String> {
    let mut s = crate::text::unquote(actual).trim().to_string();
    if s.is_empty() {
        return None;
    }
    // `Userinit` is documented with a trailing comma to allow a second program;
    // a value that ends in the default path plus anything else is a deviation, but
    // the trailing comma itself is part of the default and must not count.
    if value_name.eq_ignore_ascii_case("Userinit") {
        s = s.trim_end_matches(',').trim().to_string();
    }
    Some(s.to_lowercase())
}

/// Does `BootExecute` hold only the documented default entry?
pub fn is_default_boot_execute(entries: &[String]) -> bool {
    let mut meaningful = entries.iter().filter(|e| !e.trim().is_empty());
    let Some(first) = meaningful.next() else {
        // An empty BootExecute is unusual but is not a *deviation* this check claims
        // to detect; report it as-is rather than flagging a missing value.
        return true;
    };
    if meaningful.next().is_some() {
        return false;
    }
    let value = first.trim().trim_end_matches('\0').trim().to_lowercase();
    BOOT_EXECUTE_DEFAULT
        .iter()
        .any(|d| d.trim().to_lowercase() == value)
}

/// Push a line into the raw section, respecting the cap.
fn push_line(lines: &mut Vec<String>, line: &str) {
    if lines.len() < MAX_RAW_LINES {
        lines.push(line.to_string());
    }
}

/// Drop the tail of an over-long raw section, recording the truncation in the
/// section itself rather than losing lines silently.
fn truncate_lines(lines: &mut Vec<String>) {
    if lines.len() > MAX_RAW_LINES {
        lines.truncate(MAX_RAW_LINES);
        lines.push(format!("(truncated at {MAX_RAW_LINES} lines)"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_exe_from_a_quoted_command_with_arguments() {
        let cmd = r#""C:\Program Files\Some Agent\agent.exe" --service --quiet"#;
        assert_eq!(
            extract_executable(cmd),
            r"C:\Program Files\Some Agent\agent.exe"
        );
    }

    #[test]
    fn extracts_exe_from_a_quoted_command_with_an_env_var() {
        // The caller expands %VAR% before this helper runs, but the helper must not
        // choke on a value that still contains one (an unknown variable is left
        // untouched by rules::expand_env).
        let cmd = r#""%LocalAppData%\App\app.exe" /run"#;
        assert_eq!(extract_executable(cmd), r"%LocalAppData%\App\app.exe");
    }

    #[test]
    fn extracts_exe_from_an_unquoted_path_with_spaces_and_arguments() {
        // The hard case: no quotes, spaces, and arguments. Cutting at the first space
        // would yield `C:\Program`, which is wrong and would hide the real path.
        let cmd = r"C:\Program Files\App\App.exe -run";
        assert_eq!(extract_executable(cmd), r"C:\Program Files\App\App.exe");
    }

    #[test]
    fn handles_a_bare_unquoted_path_and_malformed_input() {
        assert_eq!(
            extract_executable(r"C:\Windows\system32\cmd.exe"),
            r"C:\Windows\system32\cmd.exe"
        );
        // Unterminated quote: never panic, never drop the whole value.
        assert_eq!(extract_executable(r#""C:\odd\app.exe"#), r"C:\odd\app.exe");
        // Empty and whitespace-only inputs collapse to an empty result.
        assert_eq!(extract_executable(""), "");
        assert_eq!(extract_executable("   "), "");
    }

    #[test]
    fn winlogon_default_is_recognised_despite_case_and_the_trailing_comma() {
        assert!(is_default_winlogon_value(
            "Shell",
            "explorer.exe",
            "explorer.exe"
        ));
        assert!(is_default_winlogon_value(
            "Shell",
            "Explorer.EXE",
            "explorer.exe"
        ));
        assert!(is_default_winlogon_value(
            "Userinit",
            r"C:\Windows\system32\userinit.exe,",
            r"C:\Windows\system32\userinit.exe,"
        ));
        assert!(is_default_winlogon_value(
            "Userinit",
            r"C:\WINDOWS\System32\UserInit.exe",
            r"C:\Windows\system32\userinit.exe,"
        ));
    }

    #[test]
    fn winlogon_deviation_is_detected() {
        // A second program appended after the comma: the classic Userinit hijack.
        assert!(!is_default_winlogon_value(
            "Userinit",
            r"C:\Windows\system32\userinit.exe,C:\Temp\payload.exe",
            r"C:\Windows\system32\userinit.exe,"
        ));
        // A different shell altogether.
        assert!(!is_default_winlogon_value(
            "Shell",
            r"C:\Temp\shell.exe",
            "explorer.exe"
        ));
        // Taskman has no default; any value is a deviation.
        assert!(is_default_winlogon_value("Taskman", "", ""));
        assert!(!is_default_winlogon_value("Taskman", "C:\\Temp\\t.exe", ""));
    }

    #[test]
    fn boot_execute_default_is_accepted_and_an_extra_entry_is_not() {
        assert!(is_default_boot_execute(
            &["autocheck autochk *".to_string()]
        ));
        assert!(is_default_boot_execute(
            &["Autocheck Autochk *".to_string()]
        ));
        assert!(is_default_boot_execute(&[]));
        assert!(!is_default_boot_execute(&[
            "autocheck autochk *".to_string(),
            r"\SystemRoot\System32\evil.sys".to_string(),
        ]));
        assert!(!is_default_boot_execute(&[
            r"\??\C:\Windows\Temp\boot.exe".to_string()
        ]));
    }
}
