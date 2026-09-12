//! Removal: what can be undone, and what cannot.
//!
//! This module exists because "delete it" is the wrong answer to almost every finding
//! this tool produces, and a tool that offers only that teaches its user to press the
//! button that destroys evidence. So the actions here are:
//!
//! * **typed** - a fixed set of operations, never a command line built from a string
//!   that came off a possibly hostile machine;
//! * **reversible by construction** - every action records the value that restores it;
//! * **inert** - building an action performs no I/O and needs no privileges, so the plan
//!   can be computed, shown, reviewed and tested without touching anything.
//!
//! The decisive question, and the one the report already answers, is whether removing one
//! artefact is even meaningful. Against a real RAT with a watchdog, a driver or several
//! persistence mechanisms, a hand cleanup is theatre: the thing comes back, and all that
//! has been achieved is the destruction of the evidence that would have proved what it
//! was. [`strategy`] is where that judgement lives, and it is deliberately blunt.

use crate::model::Severity;
use crate::text::sanitize;

/// One reversible operation, with everything needed to undo it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Stop a service and set its start type to disabled, keeping the previous value.
    ///
    /// Nothing is deleted: the image, the key and the configuration all stay where they
    /// are, so the change is a two-second reversal and the artefact is still there to be
    /// examined.
    DisableService { name: String, previous_start: u32 },
    /// Disable a scheduled task, remembering that it was enabled.
    DisableTask { name: String },
    /// Remove an autostart value, keeping its contents.
    RemoveAutostart {
        hive: String,
        key: String,
        value: String,
        previous_data: String,
    },
    /// Remove a WMI event consumer, keeping its definition.
    RemoveWmiConsumer { name: String, definition: String },
    /// Terminate a process tree.
    ///
    /// The only irreversible action here, and it is safe in the sense that matters: a
    /// running process is not evidence that disappears, because the tool has already
    /// recorded its identity, path, signature and sockets.
    EndProcess { pid: u32, name: String },
}

impl Action {
    /// A stable key, used to deduplicate a plan and to name the undo record.
    pub fn key(&self) -> String {
        match self {
            Action::DisableService { name, .. } => format!("service:{name}"),
            Action::DisableTask { name } => format!("task:{name}"),
            Action::RemoveAutostart { key, value, .. } => format!("autostart:{key}\\{value}"),
            Action::RemoveWmiConsumer { name, .. } => format!("wmi:{name}"),
            Action::EndProcess { pid, .. } => format!("process:{pid}"),
        }
    }

    /// What the user is about to do, in one line, for the confirmation prompt.
    pub fn describe(&self) -> String {
        match self {
            Action::DisableService { name, .. } => {
                format!("stop and disable the service '{name}' (not deleted - reversible)")
            }
            Action::DisableTask { name } => {
                format!("disable the scheduled task '{name}' (not deleted - reversible)")
            }
            Action::RemoveAutostart { value, .. } => format!(
                "remove the autostart entry '{value}' (its content is saved and can be restored)"
            ),
            Action::RemoveWmiConsumer { name, .. } => format!(
                "remove the WMI event consumer '{name}' (its definition is saved and can be restored)"
            ),
            Action::EndProcess { pid, name } => {
                format!("end the process tree '{name}' (pid {pid}) - this one cannot be undone")
            }
        }
    }

    /// Whether undo can restore the previous state exactly.
    pub fn is_reversible(&self) -> bool {
        !matches!(self, Action::EndProcess { .. })
    }

    /// The line written to the undo record. Kept as text so the record is readable
    /// without this program, which is the only property an undo record really needs.
    pub fn undo_line(&self) -> String {
        match self {
            Action::DisableService { name, previous_start } => format!(
                "sc.exe config \"{name}\" start= {previous_start}    # then: sc.exe start \"{name}\""
            ),
            Action::DisableTask { name } => {
                format!("schtasks.exe /Change /TN \"{name}\" /ENABLE")
            }
            Action::RemoveAutostart {
                hive,
                key,
                value,
                previous_data,
            } => format!(
                "reg.exe add \"{hive}\\{key}\" /v \"{value}\" /t REG_EXPAND_SZ /d \"{previous_data}\" /f"
            ),
            Action::RemoveWmiConsumer { name, definition } => format!(
                "re-create the consumer '{name}' from: {definition}"
            ),
            Action::EndProcess { pid, name } => {
                format!("nothing to undo: '{name}' (pid {pid}) was ended, not removed")
            }
        }
    }
}

/// What a scan implies about removal, given how bad it looks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing high-severity. Reversible containment is proportionate, and a reinstall
    /// would be an over-reaction.
    Contain,
    /// Something is hostile *and* the machine cannot be trusted to have only one
    /// foothold. Hand cleanup does not work here, and pretending otherwise is the
    /// harmful part.
    Reinstall,
}

/// Decide what removal should look like, from evidence rather than from taste.
///
/// The rule is intentionally simple and intentionally conservative:
///
/// * a high-severity finding is not, by itself, proof of an intrusion - it is a reason
///   to look. Containment and a second opinion are the proportionate response.
/// * **two independent high-severity mechanisms in different categories** is a different
///   claim: persistence that survives a reboot *and* something talking to the network,
///   or a driver *and* an autostart entry. At that point the honest advice is a clean
///   reinstall, because a hand cleanup cannot be verified.
pub fn strategy(findings: &[(Severity, &'static str)]) -> Verdict {
    let mut categories: Vec<&'static str> = Vec::new();
    for (severity, category) in findings {
        if *severity == Severity::High && !categories.contains(category) {
            categories.push(category);
        }
    }

    let persistence = [
        "service",
        "persistence",
        "tasks",
        "autoruns",
        "wmi-persistence",
    ];
    let has_persistence = categories.iter().any(|c| persistence.contains(c));
    let has_other = categories
        .iter()
        .any(|c| !persistence.contains(c) && *c != "yara");

    if categories.len() >= 2 && has_persistence && has_other {
        Verdict::Reinstall
    } else {
        Verdict::Contain
    }
}

/// Build the plan for one group of findings.
///
/// Order matters and is not arbitrary: network activity is stopped first, then the
/// persistence that would bring everything back, then the process itself. Doing it the
/// other way around gives a watchdog time to restart what was just killed.
pub fn plan_for(actions: Vec<Action>) -> Vec<Action> {
    let mut ordered: Vec<Action> = Vec::with_capacity(actions.len());
    for action in actions {
        if !ordered.iter().any(|seen| seen.key() == action.key()) {
            ordered.push(action);
        }
    }
    ordered.sort_by_key(|action| match action {
        Action::EndProcess { .. } => 3,
        Action::RemoveWmiConsumer { .. } => 2,
        Action::RemoveAutostart { .. } => 2,
        Action::DisableTask { .. } => 1,
        Action::DisableService { .. } => 0,
    });
    ordered
}

/// The exact, complete undo script for a plan.
///
/// Written as a file next to the report so that a removal the user regrets is a
/// double-click to reverse, and so the claim "reversible" is checkable rather than
/// rhetorical.
pub fn undo_script(actions: &[Action], taken_at: &str) -> String {
    let mut out = String::new();
    out.push_str("# irscan undo record\n");
    out.push_str(&format!("# taken at: {}\n", sanitize(taken_at, 64)));
    out.push_str("#\n# Run the lines below in an elevated prompt to put the machine back as it\n");
    out.push_str("# was. Nothing was deleted, so nothing has to be recovered.\n\n");

    let mut any_irreversible = false;
    for action in actions {
        out.push_str(&format!("# {}\n", action.describe()));
        out.push_str(&action.undo_line());
        out.push_str("\n\n");
        if !action.is_reversible() {
            any_irreversible = true;
        }
    }

    if any_irreversible {
        out.push_str(
            "# One or more actions ended a process. A process is not a file: restarting the\n\
             # program, or rebooting, restores it.\n",
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_service_action_records_how_to_put_it_back() {
        let action = Action::DisableService {
            name: "AcmeAgent".to_string(),
            previous_start: 2,
        };
        assert!(action.is_reversible());
        assert!(action.undo_line().contains("start= 2"));
        assert!(action.describe().contains("not deleted"));
    }

    #[test]
    fn ending_a_process_is_marked_as_the_one_thing_that_cannot_be_undone() {
        let action = Action::EndProcess {
            pid: 42,
            name: "agent.exe".to_string(),
        };
        assert!(!action.is_reversible());
        assert!(action.undo_line().contains("nothing to undo"));
    }

    #[test]
    fn the_plan_contains_no_second_copy_of_the_same_action() {
        let plan = plan_for(vec![
            Action::DisableTask {
                name: "X".to_string(),
            },
            Action::DisableTask {
                name: "X".to_string(),
            },
        ]);
        assert_eq!(plan.len(), 1);
    }

    #[test]
    fn the_plan_stops_the_service_before_ending_the_process() {
        // The order is the whole point: a watchdog restarts what was killed a moment
        // ago, so the persistence that would revive it goes first.
        let plan = plan_for(vec![
            Action::EndProcess {
                pid: 1,
                name: "agent.exe".to_string(),
            },
            Action::DisableService {
                name: "AcmeAgent".to_string(),
                previous_start: 2,
            },
            Action::RemoveWmiConsumer {
                name: "C".to_string(),
                definition: "cmd /c x".to_string(),
            },
        ]);
        assert!(matches!(plan[0], Action::DisableService { .. }));
        assert!(matches!(plan[1], Action::RemoveWmiConsumer { .. }));
        assert!(matches!(plan[2], Action::EndProcess { .. }));
    }

    #[test]
    fn containment_is_the_answer_to_a_single_high_finding() {
        assert_eq!(
            strategy(&[(Severity::High, "inputfilters")]),
            Verdict::Contain
        );
        assert_eq!(strategy(&[(Severity::Med, "signature")]), Verdict::Contain);
    }

    #[test]
    fn a_reinstall_is_advised_only_for_two_independent_footholds() {
        // Persistence alone: still containable.
        assert_eq!(strategy(&[(Severity::High, "service")]), Verdict::Contain);
        assert_eq!(
            strategy(&[(Severity::High, "service"), (Severity::High, "yara")]),
            Verdict::Contain,
            "a content match on its own is a lead, not a second foothold"
        );
        // Persistence plus something else that is independently serious.
        assert_eq!(
            strategy(&[(Severity::High, "service"), (Severity::High, "network")]),
            Verdict::Reinstall
        );
        assert_eq!(
            strategy(&[(Severity::High, "tasks"), (Severity::High, "inputfilters")]),
            Verdict::Reinstall
        );
    }

    #[test]
    fn the_undo_record_names_every_action_and_the_time() {
        let script = undo_script(
            &[
                Action::DisableService {
                    name: "AcmeAgent".to_string(),
                    previous_start: 2,
                },
                Action::RemoveAutostart {
                    hive: "HKCU".to_string(),
                    key: r"Software\Microsoft\Windows\CurrentVersion\Run".to_string(),
                    value: "Updater".to_string(),
                    previous_data: r"C:\x\updater.exe".to_string(),
                },
            ],
            "2026-09-11 22:30:00",
        );
        assert!(script.contains("2026-09-11 22:30:00"));
        assert!(script.contains("sc.exe config"));
        assert!(script.contains("reg.exe add"));
        assert!(!script.contains("One or more actions ended a process"));
    }

    #[test]
    fn the_undo_record_warns_that_a_process_cannot_be_restored() {
        let script = undo_script(
            &[Action::EndProcess {
                pid: 7,
                name: "agent.exe".to_string(),
            }],
            "t",
        );
        assert!(script.contains("cannot be undone") || script.contains("nothing to undo"));
    }
}
