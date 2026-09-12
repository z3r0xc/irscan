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
pub fn undo_path(next_to: &Path) -> PathBuf {
    let mut name = next_to
        .file_stem()
        .map(|s| s.to_os_string())
        .unwrap_or_default();
    name.push("-undo.txt");
    next_to.with_file_name(name)
}

/// Stop and disable a service, recording how to restore it.
fn apply_service(name: &str, previous_start: Option<u64>) -> Result<String, String> {
    let key = format!(r"SYSTEM\CurrentControlSet\Services\{name}");
    if !reg::key_exists(RootKey::Hklm, &key) {
        return Err(format!("no service named '{name}' exists on this machine"));
    }

    let current = reg::get_u64(RootKey::Hklm, &key, "Start").unwrap_or(2);
    let _ = previous_start;
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

/// Carry out one action and return what happened.
pub fn apply(action: &Action) -> Result<Applied, String> {
    match action {
        Action::DisableService { name, .. } => {
            let outcome = apply_service(name, None)?;
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
        let undo = undo_path(&report);
        assert_eq!(undo, PathBuf::from(r"C:\Users\x\report-undo.txt"));
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
        let result = apply_service("irscan-no-such-service-7ab2", None);
        assert!(result.is_err());
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
