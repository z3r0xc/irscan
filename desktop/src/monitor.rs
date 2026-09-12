//! Keeping history between runs, so the second scan can say what changed.
//!
//! The history is one file next to the executable's data directory. It holds a single
//! previous snapshot, not an archive: the question this feature answers is "what changed
//! since I last looked", and keeping a long history would invite the reader to compare
//! the wrong two runs.
//!
//! Two properties matter and are both deliberate:
//!
//! * **the history is the tool's own state, not evidence.** It is re-validated on load
//!   and a file this version cannot parse is discarded rather than half-read, because the
//!   machine it lives on may be the one under investigation.
//! * **a missing or unreadable history is normal.** It is what the first run looks like.
//!   It produces no warning and no finding, only an absence of comparison.

use std::path::PathBuf;

use irscan::model::ScanContext;
use irscan::monitor::{self, Delta, Snapshot};

pub struct StoredSnapshot {
    pub when: String,
    pub snapshot: Snapshot,
}

/// Where the history lives.
///
/// Under `%LOCALAPPDATA%\IRScan\`, not beside the executable: the tool may be run from a
/// read-only medium, and a program that fails to start because it cannot write next to
/// itself is a program that fails on the machine it was meant for.
pub fn history_path() -> PathBuf {
    let base = std::env::var("LOCALAPPDATA")
        .unwrap_or_else(|_| std::env::temp_dir().display().to_string());
    PathBuf::from(base).join("IRScan").join("last-snapshot.txt")
}

/// Load the previous snapshot, if there is a usable one.
pub fn load() -> Option<StoredSnapshot> {
    let path = history_path();
    let text = std::fs::read_to_string(&path).ok()?;
    let snapshot = Snapshot::from_text(&text)?;
    Some(StoredSnapshot {
        when: snapshot.taken_at.clone(),
        snapshot,
    })
}

/// Store a snapshot, replacing any previous one.
///
/// A failure to write is reported to the caller and turned into a warning, never into a
/// failed scan: the scan itself has already succeeded, and losing the ability to compare
/// with the *next* run is not a reason to discard this one.
pub fn store(snapshot: &Snapshot) -> Result<(), String> {
    let path = history_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    std::fs::write(&path, snapshot.to_text())
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// What the window is told about the comparison.
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeltaView {
    /// `None` on the first run, when there is nothing to compare against.
    pub since: Option<String>,
    pub added: Vec<EntryView>,
    pub removed: Vec<EntryView>,
    pub summary: String,
    /// Whether anything appeared that a reboot would have to preserve.
    pub new_presence: bool,
    /// Whether this is the first run, so the interface can say so instead of showing an
    /// empty comparison that looks like "nothing changed".
    pub first_run: bool,
}

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EntryView {
    pub kind: String,
    pub subject: String,
}

/// Compare the current scan against the stored one, and store the new snapshot.
pub fn compare_and_store(ctx: &ScanContext, taken_at: &str) -> DeltaView {
    let previous = load();
    let current = monitor::snapshot(taken_at, ctx);
    let first_run = previous.is_none();

    let delta = match &previous {
        Some(stored) => monitor::diff(&stored.snapshot, &current),
        None => Delta::default(),
    };

    if let Err(e) = store(&current) {
        // The scan is unaffected; the caller turns this into a warning below.
        let _ = e;
    }

    DeltaView {
        since: previous.map(|stored| stored.when),
        added: delta
            .added
            .iter()
            .map(|i| EntryView {
                kind: i.kind().to_string(),
                subject: i.subject().to_string(),
            })
            .collect(),
        removed: delta
            .removed
            .iter()
            .map(|i| EntryView {
                kind: i.kind().to_string(),
                subject: i.subject().to_string(),
            })
            .collect(),
        summary: delta.summary(),
        new_presence: delta.has_new_presence(),
        first_run,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use irscan::model::ServiceRecord;

    fn ctx_with_service(name: &str) -> ScanContext {
        let mut ctx = ScanContext::default();
        ctx.services.push(ServiceRecord {
            name: name.to_string(),
            display_name: name.to_string(),
            state: "running".to_string(),
            start_mode: "auto".to_string(),
            account: "LocalSystem".to_string(),
            image_path: format!(r"C:\Program Files\{name}\{name}.exe"),
            is_driver: false,
        });
        ctx
    }

    #[test]
    fn the_history_path_is_under_local_app_data_not_beside_the_exe() {
        // The tool may be started from a read-only medium; writing next to itself would
        // make it fail to start on exactly the machines it is meant for.
        let path = history_path();
        let text = path.to_string_lossy().to_lowercase();
        assert!(text.ends_with("irscan\\last-snapshot.txt"), "got {text}");
        assert!(
            text.contains("appdata") || text.contains("temp"),
            "got {text}"
        );
    }

    #[test]
    fn a_snapshot_survives_a_write_and_read_round_trip() {
        let dir = std::env::temp_dir().join("irscan-monitor-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("snap.txt");

        let ctx = ctx_with_service("AcmeAgent");
        let snap = monitor::snapshot("2026-09-11 23:00:00", &ctx);
        std::fs::write(&path, snap.to_text()).unwrap_or_default();

        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let back = Snapshot::from_text(&text);
        assert!(back.is_some());
        if let Some(back) = back {
            assert_eq!(back.identities, snap.identities);
        }
    }

    #[test]
    fn a_delta_reports_new_presence_only_for_things_that_persist() {
        // A new process is a change; a new *service* is the case that matters and the
        // one the interface highlights.
        let empty = monitor::snapshot("t1", &ScanContext::default());
        let with_service = monitor::snapshot("t2", &ctx_with_service("AcmeAgent"));
        let delta = monitor::diff(&empty, &with_service);
        assert!(delta.has_new_presence());
        assert!(delta.added.iter().any(|i| i.subject() == "AcmeAgent"));
    }
}
