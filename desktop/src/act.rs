//! Applying a removal, one typed action at a time.
//!
//! Three rules govern everything here, and they exist because this is the only part of
//! the tool that changes the machine:
//!
//! 1. **The action is a type, never a string.** It arrives from the interface as a
//!    tagged value and is re-validated against the live machine before anything happens.
//!    No command line is ever assembled from data that came off the machine under
//!    investigation, so there is nothing here to inject into.
//! 2. **Nothing is deleted.** Every action stops, disables or detaches, and records what
//!    would put it back. The undo record is written before the change is made, so a
//!    crash halfway through cannot leave a change with no record of how to reverse it.
//! 3. **Nothing happens without an explicit confirmation from the user**, which is why
//!    the interface asks before calling this at all.
//!
//! What it can do is deliberately narrow: a service, a scheduled task, an autostart
//! value, a WMI consumer, and ending a process. Those are the actions that are both
//! useful and safe to automate. Anything else - editing the registry freely, deleting
//! files, uninstalling software - is left to the person, because a tool that offers a
//! general-purpose "run this" button has handed the machine back to whoever tricked it.

use std::path::{Path, PathBuf};

use irscan::remediate::Action;
use irscan::win::reg::{self, RootKey};

/// What actually happened, for the report and the interface.
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Applied {
    pub key: String,
    pub description: String,
    pub outcome: String,
    pub reversible: bool,
}

/// Where the undo record is written. Beside the report, so a removal and its reversal
/// instructions travel together.
///
/// Returns `None` when there is no report path. The record must sit next to the report -
/// that is the whole point, so the two travel together - and with no report there is no
/// "next to it" to compute. The previous behaviour produced `-undo.txt` and wrote it into
/// whatever the process's working directory happened to be, which on this product is the
/// folder the tool was run from **on the suspect machine**. A containment action would
/// then create a file in an unpredictable place on a machine the operator does not
/// control, which is the one thing this tool must never do.
///
/// The caller refuses the action instead. An action that cannot be recorded is an action
/// that must not be taken.
pub fn undo_path(next_to: &Path) -> Option<PathBuf> {
    // Whitespace-only counts as empty: a path of spaces is not a place to write, and
    // `Path::with_file_name` would turn it into a file named "-undo.txt" beside nothing.
    //
    // `file_stem` on an empty path yields an empty name, which is why this check is
    // here and not left to `with_file_name`.
    let raw = next_to.to_string_lossy();
    if raw.trim().is_empty() {
        return None;
    }

    let mut name = next_to
        .file_stem()
        .map(|s| s.to_os_string())
        .unwrap_or_default();
    name.push("-undo.txt");
    Some(next_to.with_file_name(name))
}

/// Disable a service.
///
/// The previous start type is *not* a parameter. It was one — accepted and then ignored
/// — which let the caller pass a placeholder that looked like the value the undo line
/// would use. The value comes from `prepare`, which reads it before anything changes and
/// puts it in the `Action` the undo record is written from.
fn apply_service(name: &str) -> Result<String, String> {
    let key = format!(r"SYSTEM\CurrentControlSet\Services\{name}");
    if !reg::key_exists(RootKey::Hklm, &key) {
        return Err(format!("no service named '{name}' exists on this machine"));
    }

    let current = reg::get_u64(RootKey::Hklm, &key, "Start").unwrap_or(2);
    if current == 4 {
        return Ok("already disabled".to_string());
    }

    // Written directly rather than through `sc.exe`, so no process is spawned and no
    // string from the machine reaches a command line.
    let hklm =
        reg::open(RootKey::Hklm, &key).ok_or_else(|| format!("cannot open {key} for writing"))?;
    irscan::win::reg::set_u64(&hklm, "Start", 4)
        .map_err(|e| format!("cannot set the service start type: {e}"))?;

    Ok(format!(
        "start type changed from {current} to 4 (disabled); the service is stopped at the next boot and its image is untouched"
    ))
}

/// Disable a scheduled task by renaming its file, which is reversible and needs no shell.
fn apply_task(_name: &str) -> Result<String, String> {
    Err(
        "disabling a scheduled task is not implemented yet; use schtasks /Change /DISABLE, \
         and the report's evidence names the exact task"
            .to_string(),
    )
}

/// Remove one autostart value, returning its previous contents for the undo record.
fn apply_autostart(hive: &str, key: &str, value: &str) -> Result<(String, String), String> {
    let root = match hive.to_ascii_uppercase().as_str() {
        "HKLM" | "HKEY_LOCAL_MACHINE" => RootKey::Hklm,
        "HKCU" | "HKEY_CURRENT_USER" => RootKey::Hkcu,
        other => return Err(format!("unsupported registry hive '{other}'")),
    };

    let previous = reg::get_value(root, key, value)
        .ok_or_else(|| format!("no value '{value}' under {hive}\\{key}"))?;
    let text = previous.as_text().unwrap_or_default();

    let hk = reg::open(root, key).ok_or_else(|| format!("cannot open {hive}\\{key}"))?;
    irscan::win::reg::delete_value(&hk, value)
        .map_err(|e| format!("cannot remove the autostart value: {e}"))?;

    Ok((
        text.clone(),
        format!("value removed; it pointed at {text} and can be restored from the undo record"),
    ))
}

/// Read the current state of what an action targets, and return the action with the
/// real previous value filled in — **without changing anything**.
///
/// This is the first half of a two-phase apply, and the split is the fix for a real
/// defect: the commands used to call `apply` and only then `write_undo_record`, so a
/// failure to write the record (its directory missing, the volume read-only) left the
/// registry modified with no instructions for reversing it, while the module doc
/// promised the opposite. `prepare` touches nothing, so the caller can write the undo
/// record from what it returns and know that the change it describes has not happened
/// yet.
///
/// It also fixes the value the undo line records. `apply_service` read the service's
/// real `Start` value but the caller passed a hardcoded `previous_start: 2`, so the undo
/// line restored a start type the machine may never have had; `apply_autostart` read the
/// value's contents and the caller passed `String::new()`, so the record said to restore
/// an empty string. Both now come from here.
pub fn prepare(action: &Action) -> Result<Action, String> {
    match action {
        Action::DisableService { name, .. } => {
            let key = format!(r"SYSTEM\CurrentControlSet\Services\{name}");
            if !reg::key_exists(RootKey::Hklm, &key) {
                return Err(format!("no service named '{name}' exists on this machine"));
            }
            // A service `Start` value is a DWORD in a documented 0..=4 range. The wider
            // read is clamped rather than cast, so a malformed value cannot wrap into a
            // plausible-looking start type in the undo line.
            let current = reg::get_u64(RootKey::Hklm, &key, "Start")
                .unwrap_or(2)
                .min(4) as u32;
            if current == 4 {
                return Err(format!("the service '{name}' is already disabled"));
            }
            Ok(with_previous_start(action, current))
        }
        Action::RemoveAutostart {
            hive, key, value, ..
        } => {
            let text = read_autostart(hive, key, value)?;
            Ok(Action::RemoveAutostart {
                hive: hive.clone(),
                key: key.clone(),
                value: value.clone(),
                previous_data: text,
            })
        }
        // The remaining kinds are not automated; `apply` says so, and `prepare` has
        // nothing to read for them.
        other => Ok(other.clone()),
    }
}

/// The same action with `previous_start` replaced by the value that was found.
fn with_previous_start(action: &Action, start: u32) -> Action {
    match action {
        Action::DisableService { name, .. } => Action::DisableService {
            name: name.clone(),
            previous_start: start,
        },
        other => other.clone(),
    }
}

/// Read an autostart value's contents, refusing an unknown hive.
fn read_autostart(hive: &str, key: &str, value: &str) -> Result<String, String> {
    let root = match hive.to_ascii_uppercase().as_str() {
        "HKLM" | "HKEY_LOCAL_MACHINE" => RootKey::Hklm,
        "HKCU" | "HKEY_CURRENT_USER" => RootKey::Hkcu,
        other => return Err(format!("unsupported registry hive '{other}'")),
    };
    let previous = reg::get_value(root, key, value)
        .ok_or_else(|| format!("no value '{value}' under {hive}\\{key}"))?;
    Ok(previous.as_text().unwrap_or_default())
}

/// Carry out one action and return what happened.
pub fn apply(action: &Action) -> Result<Applied, String> {
    match action {
        Action::DisableService { name, .. } => {
            let outcome = apply_service(name)?;
            Ok(Applied {
                key: action.key(),
                description: action.describe(),
                outcome,
                reversible: true,
            })
        }
        Action::DisableTask { name } => {
            let outcome = apply_task(name)?;
            Ok(Applied {
                key: action.key(),
                description: action.describe(),
                outcome,
                reversible: true,
            })
        }
        Action::RemoveAutostart {
            hive, key, value, ..
        } => {
            let (_, outcome) = apply_autostart(hive, key, value)?;
            Ok(Applied {
                key: action.key(),
                description: action.describe(),
                outcome,
                reversible: true,
            })
        }
        Action::RemoveWmiConsumer { .. } => Err(
            "removing a WMI consumer is not implemented yet: its definition is in the report, \
             and it is the one artefact where a mistake is hard to notice, so it is left to \
             the person reading the evidence"
                .to_string(),
        ),
        Action::EndProcess { pid, name } => Err(format!(
            "ending '{name}' (pid {pid}) is not implemented yet: the window shows the pid so it \
             can be ended from Task Manager, where you can see what else it is holding"
        )),
    }
}

/// Write the undo record. Called before the first change so a crash cannot leave a change
/// without instructions for reversing it.
pub fn write_undo_record(path: &Path, actions: &[Action], taken_at: &str) -> Result<(), String> {
    let script = irscan::remediate::undo_script(actions, taken_at);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    std::fs::write(path, script).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_undo_record_sits_beside_the_report() {
        let report = PathBuf::from(r"C:\Users\x\report.txt");
        assert_eq!(
            undo_path(&report),
            Some(PathBuf::from(r"C:\Users\x\report-undo.txt"))
        );
    }

    /// No report path means no undo record, and the caller must refuse the action.
    ///
    /// This used to yield `-undo.txt` in the working directory, which on this product is
    /// the folder the tool was launched from on the suspect machine.
    #[test]
    fn no_undo_record_is_written_without_a_report_path() {
        assert_eq!(undo_path(Path::new("")), None);
        assert_eq!(undo_path(Path::new("   ")), None);
    }

    #[test]
    fn an_unsupported_hive_is_refused_rather_than_guessed_at() {
        let result = apply_autostart("HKCR", r"Software\Run", "x");
        assert!(result.is_err());
        if let Err(message) = result {
            assert!(message.contains("unsupported registry hive"));
        }
    }

    #[test]
    fn a_service_that_does_not_exist_is_refused() {
        // The interface may hold a stale action; the machine is the authority, and an
        // action naming something absent is an error rather than a no-op that pretends
        // to have worked.
        let result = apply_service("irscan-no-such-service-7ab2");
        assert!(result.is_err());
    }

    /// The previous state has to travel out of `prepare`, because the undo record is
    /// written from it *before* the machine is touched.
    ///
    /// The defect this pins: the commands used to call `apply` and then
    /// `write_undo_record`, so a failure to write the record left a modified registry
    /// with no instructions for reversing it — and `Action::DisableService` carried a
    /// hardcoded `previous_start: 2` while `apply_service` read the real value and threw
    /// it away, so the undo line restored the wrong start type even when it was written.
    #[test]
    fn prepare_returns_the_previous_state_without_changing_anything() {
        // No such service: prepare must fail without touching the registry.
        let action = Action::DisableService {
            name: "irscan-no-such-service-7ab2".to_string(),
            previous_start: 0,
        };
        let err = prepare(&action).unwrap_err();
        assert!(err.contains("no service named"), "unexpected error: {err}");

        // An unsupported hive is refused for the same reason.
        let action = Action::RemoveAutostart {
            hive: "HKCR".to_string(),
            key: r"Software\Run".to_string(),
            value: "x".to_string(),
            previous_data: String::new(),
        };
        let err = prepare(&action).unwrap_err();
        assert!(
            err.contains("unsupported registry hive"),
            "unexpected: {err}"
        );
    }

    /// `prepare` carries the start type that is actually on the machine.
    ///
    /// This reads a real service rather than calling the helper directly, because the
    /// helper being correct is not the claim — the claim is that the *record* gets the
    /// machine's value. An earlier version of this test called `with_previous_start`
    /// itself and passed even when `prepare` was broken to return a hardcoded 0.
    #[test]
    fn prepare_carries_the_start_type_that_is_on_the_machine() {
        // Spooler is present on every Windows install and is not disabled by default.
        const SERVICE: &str = "Spooler";
        let key = format!(r"SYSTEM\CurrentControlSet\Services\{SERVICE}");
        let on_the_machine =
            irscan::win::reg::get_u64(irscan::win::reg::RootKey::Hklm, &key, "Start");
        let Some(real) = on_the_machine else {
            return; // not a Windows host, or the service is absent
        };
        if real == 4 {
            return; // already disabled on this machine; nothing to compare
        }

        let prepared = prepare(&irscan::remediate::Action::DisableService {
            name: SERVICE.to_string(),
            previous_start: 99,
        })
        .expect("preparing an enabled service must succeed");

        match prepared {
            irscan::remediate::Action::DisableService { previous_start, .. } => {
                assert_ne!(
                    previous_start, 99,
                    "the caller's placeholder must be overwritten"
                );
                assert_eq!(
                    previous_start as u64, real,
                    "the undo line must restore the start type that is actually set"
                );
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn unimplemented_actions_say_so_instead_of_pretending_to_succeed() {
        // Deliberate: three action kinds are modelled, recorded and shown, and applying
        // them is not automated yet. Reporting success would be a lie about the machine.
        let task = Action::DisableTask {
            name: "X".to_string(),
        };
        assert!(apply(&task).is_err());
        let process = Action::EndProcess {
            pid: 1,
            name: "x.exe".to_string(),
        };
        assert!(apply(&process).is_err());
    }
}
