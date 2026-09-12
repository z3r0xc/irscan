//! Change detection: what appeared, and what went away, since the previous look.
//!
//! A single scan answers "what is on this machine". A sequence of scans answers a more
//! useful question - "what changed" - which is how an agent installed while you were
//! watching, or a beacon that started phoning home at 03:00, gets caught.
//!
//! The whole design rests on one decision: what makes two observations "the same thing".
//! Get it wrong and the feature is worse than useless, because every scan looks like a
//! wave of changes:
//!
//! * a **process** is identified by its image name, never by its pid. A pid changes on
//!   every restart, so pid-based identity would report the whole process table as new on
//!   every cycle;
//! * a **connection** is identified by its remote endpoint, not by its local port. "This
//!   machine started talking to a new address" is the signal; which ephemeral port it
//!   uses is noise;
//! * a **service, task, autostart entry, account or WMI subscription** is identified by
//!   its name or path, which is exactly what a persistence mechanism has to preserve to
//!   survive a reboot.
//!
//! Identity strings are sanitised before they are stored or serialised, because every one
//! of them originated on the machine under analysis.

use std::collections::BTreeSet;

use crate::model::{ScanContext, Severity};
use crate::text::sanitize;

/// The format version of the serialised snapshot. A stored snapshot from an older
/// version is refused rather than misread.
pub const SNAPSHOT_VERSION: &str = "irscan-snapshot/1";

/// Upper bound on the identities a snapshot keeps, and on the differences one delta
/// reports. A machine with a hostile or instrumented process table must not be able to
/// grow the history file without limit.
pub const MAX_IDENTITIES: usize = 20_000;
pub const MAX_DELTA: usize = 500;

/// One thing worth tracking across scans, as an opaque, comparable string.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Identity(String);

impl Identity {
    /// Build an identity. Returns `None` for anything that would be meaningless: an
    /// empty label, or a label that sanitising empties out.
    pub fn new(kind: &str, value: &str) -> Option<Identity> {
        let cleaned = sanitize(value, 512);
        if cleaned.is_empty() {
            return None;
        }
        Some(Identity(format!("{kind}:{cleaned}")))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The kind prefix, for grouping a delta in the interface.
    pub fn kind(&self) -> &str {
        match self.0.split_once(':') {
            Some((kind, _)) => kind,
            None => "unknown",
        }
    }

    /// What is shown to a person: the identity without its machine prefix.
    pub fn subject(&self) -> &str {
        match self.0.split_once(':') {
            Some((_, subject)) => subject,
            None => &self.0,
        }
    }
}

/// Everything one scan saw, reduced to stable identities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// When the snapshot was taken, as the machine's local time.
    pub taken_at: String,
    pub identities: BTreeSet<Identity>,
}

impl Snapshot {
    pub fn len(&self) -> usize {
        self.identities.len()
    }

    pub fn is_empty(&self) -> bool {
        self.identities.is_empty()
    }

    /// Serialise to a line-based text format.
    ///
    /// Deliberately not JSON: the library has no serialiser, and a format of one
    /// sanitised identity per line cannot be corrupted by a value containing a quote or a
    /// brace. The version line is written first so an incompatible file can be refused
    /// instead of half-read.
    pub fn to_text(&self) -> String {
        let mut out = String::with_capacity(self.identities.len() * 48 + 64);
        out.push_str(SNAPSHOT_VERSION);
        out.push('\n');
        out.push_str(&sanitize(&self.taken_at, 64));
        out.push('\n');
        for identity in &self.identities {
            out.push_str(identity.as_str());
            out.push('\n');
        }
        out
    }

    /// Parse a stored snapshot. `None` means "not a snapshot this version understands",
    /// and the caller starts a fresh history rather than guessing.
    pub fn from_text(text: &str) -> Option<Snapshot> {
        let mut lines = text.lines();
        if lines.next()? != SNAPSHOT_VERSION {
            return None;
        }
        let taken_at = lines.next()?.to_string();

        let mut identities = BTreeSet::new();
        for line in lines {
            if line.trim().is_empty() {
                continue;
            }
            if identities.len() >= MAX_IDENTITIES {
                break;
            }
            // Re-validate rather than trust: the file could have been edited, and this
            // is the tool's own history, not evidence.
            if let Some((kind, subject)) = line.split_once(':') {
                if let Some(identity) = Identity::new(kind, subject) {
                    identities.insert(identity);
                }
            }
        }

        Some(Snapshot {
            taken_at,
            identities,
        })
    }
}

/// What changed between two snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Delta {
    pub added: Vec<Identity>,
    pub removed: Vec<Identity>,
}

impl Delta {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }

    pub fn total(&self) -> usize {
        self.added.len() + self.removed.len()
    }

    /// Whether anything *appeared*, which is the direction that matters for an intrusion.
    pub fn has_new_presence(&self) -> bool {
        self.identities_of_kind_are_new("service")
            || self.identities_of_kind_are_new("task")
            || self.identities_of_kind_are_new("autorun")
            || self.identities_of_kind_are_new("wmi")
            || self.identities_of_kind_are_new("connection")
            || self.identities_of_kind_are_new("account")
    }

    fn identities_of_kind_are_new(&self, kind: &str) -> bool {
        self.added.iter().any(|i| i.kind() == kind)
    }

    /// A one-line summary for the interface.
    pub fn summary(&self) -> String {
        if self.is_empty() {
            return "nothing changed".to_string();
        }
        format!("{} new, {} gone", self.added.len(), self.removed.len())
    }
}

/// Reduce one scan to the set of things worth tracking.
pub fn snapshot(taken_at: impl Into<String>, ctx: &ScanContext) -> Snapshot {
    let mut identities: BTreeSet<Identity> = BTreeSet::new();
    let mut push = |kind: &str, value: &str| {
        if identities.len() >= MAX_IDENTITIES {
            return;
        }
        if let Some(identity) = Identity::new(kind, value) {
            identities.insert(identity);
        }
    };

    // Persistent artefacts: identified by what a reboot has to preserve.
    for service in &ctx.services {
        push("service", &service.name);
        push("service-image", &service.image_path);
    }
    for task in &ctx.tasks {
        push("task", &task.name);
    }
    for autorun in &ctx.autoruns {
        push("autorun", &format!("{}|{}", autorun.location, autorun.name));
    }
    for account in &ctx.haystack {
        // Accounts arrive as haystacks rather than records; the kind is what makes the
        // identity meaningful, so it is used verbatim rather than guessed at.
        if account.kind == crate::model::HaystackKind::ProductName
            && account.origin.starts_with("accounts")
        {
            push("account", &account.value);
        }
    }

    // Running state: image names, never pids.
    for process in ctx.processes.values() {
        push("process", &process.name);
        if let Some(path) = &process.path {
            push("process-path", &path.to_string_lossy());
        }
    }

    // Network: the remote endpoint, never the local port.
    for connection in &ctx.connections {
        if crate::rules::is_private_ip(endpoint_address(&connection.remote)) {
            continue;
        }
        push("connection", &connection.remote);
    }

    // Findings that are not about volatile state, so that a new detection is itself a
    // change worth reporting.
    for finding in &ctx.findings {
        if matches!(finding.severity, Severity::High | Severity::Med) {
            push(
                "finding",
                &format!("{}|{}", finding.category, finding.title),
            );
        }
    }

    Snapshot {
        taken_at: taken_at.into(),
        identities,
    }
}

/// Address part of an `ip:port` endpoint, tolerating bracketed IPv6.
fn endpoint_address(endpoint: &str) -> &str {
    match endpoint.rfind(':') {
        Some(index) if index > 0 => endpoint[..index].trim_matches(['[', ']']),
        _ => endpoint,
    }
}

/// What is in `current` and was not in `previous`, and the reverse.
pub fn diff(previous: &Snapshot, current: &Snapshot) -> Delta {
    let added = current
        .identities
        .difference(&previous.identities)
        .take(MAX_DELTA)
        .cloned()
        .collect();
    let removed = previous
        .identities
        .difference(&current.identities)
        .take(MAX_DELTA)
        .cloned()
        .collect();
    Delta { added, removed }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ConnectionRecord, ProcessRecord, ServiceRecord};

    fn ctx_with_process(name: &str, pid: u32) -> ScanContext {
        let mut ctx = ScanContext::default();
        ctx.processes.insert(
            pid,
            ProcessRecord {
                pid,
                ppid: 0,
                name: name.to_string(),
                path: Some(std::path::PathBuf::from(format!(r"C:\x\{name}"))),
                cmdline: String::new(),
                owner: String::new(),
                started: None,
                signature_trusted: None,
                company: None,
            },
        );
        ctx
    }

    fn service(name: &str) -> ServiceRecord {
        ServiceRecord {
            name: name.to_string(),
            display_name: name.to_string(),
            state: "running".to_string(),
            start_mode: "auto".to_string(),
            account: "LocalSystem".to_string(),
            image_path: format!(r"C:\Program Files\{name}\{name}.exe"),
            is_driver: false,
        }
    }

    #[test]
    fn a_restarted_process_is_not_a_change() {
        // The reason identity is the image name and not the pid: a browser, an updater
        // or a chat client restarts constantly, and a pid-based identity would report
        // the whole process table as new every cycle.
        let before = snapshot("t1", &ctx_with_process("telegram.exe", 100));
        let after = snapshot("t2", &ctx_with_process("telegram.exe", 999));
        assert!(diff(&before, &after).is_empty());
    }

    #[test]
    fn a_new_image_name_is_a_change() {
        let before = snapshot("t1", &ctx_with_process("telegram.exe", 100));
        let mut after_ctx = ctx_with_process("telegram.exe", 100);
        after_ctx.processes.insert(
            101,
            ProcessRecord {
                pid: 101,
                ppid: 0,
                name: "agent.exe".to_string(),
                path: None,
                cmdline: String::new(),
                owner: String::new(),
                started: None,
                signature_trusted: None,
                company: None,
            },
        );
        let delta = diff(&before, &snapshot("t2", &after_ctx));
        assert_eq!(delta.added.len(), 1);
        assert_eq!(delta.added[0].kind(), "process");
        assert_eq!(delta.added[0].subject(), "agent.exe");
    }

    #[test]
    fn a_service_that_appeared_is_reported_as_new_presence() {
        let before = snapshot("t1", &ScanContext::default());
        let mut after_ctx = ScanContext::default();
        after_ctx.services.push(service("AcmeAgent"));
        let delta = diff(&before, &snapshot("t2", &after_ctx));

        assert!(
            delta.has_new_presence(),
            "a new service is the headline case"
        );
        assert!(delta.added.iter().any(|i| i.subject() == "AcmeAgent"));
        assert_eq!(delta.summary(), "2 new, 0 gone", "name and image path");
    }

    #[test]
    fn a_service_that_vanished_is_reported_as_gone() {
        let mut before_ctx = ScanContext::default();
        before_ctx.services.push(service("AcmeAgent"));
        let delta = diff(
            &snapshot("t1", &before_ctx),
            &snapshot("t2", &ScanContext::default()),
        );

        assert_eq!(delta.added.len(), 0);
        assert_eq!(delta.removed.len(), 2, "name and image path");
        assert!(!delta.has_new_presence());
    }

    #[test]
    fn a_new_remote_endpoint_is_a_change_but_a_private_one_is_not_tracked() {
        let mut after_ctx = ScanContext::default();
        after_ctx.connections.push(ConnectionRecord {
            protocol: "TCP",
            local: "10.0.0.5:5555".to_string(),
            remote: "203.0.113.9:443".to_string(),
            state: "established".to_string(),
            pid: 1,
        });
        let delta = diff(
            &snapshot("t1", &ScanContext::default()),
            &snapshot("t2", &after_ctx),
        );
        assert_eq!(delta.added.len(), 1);
        assert!(delta.added[0].subject().starts_with("203.0.113.9"));

        // Private addresses are not identity: a machine talks to its own LAN constantly
        // and tracking that would bury the one address that matters.
        let mut lan_ctx = ScanContext::default();
        lan_ctx.connections.push(ConnectionRecord {
            protocol: "TCP",
            local: "10.0.0.5:5555".to_string(),
            remote: "192.168.1.10:445".to_string(),
            state: "established".to_string(),
            pid: 1,
        });
        assert!(diff(
            &snapshot("t1", &ScanContext::default()),
            &snapshot("t2", &lan_ctx)
        )
        .is_empty());
    }

    #[test]
    fn a_local_port_change_is_not_a_change() {
        // Two messages say: one thing must not be reported as a change merely because
        // the socket was re-established on a different ephemeral port.
        let mut first = ScanContext::default();
        first.connections.push(ConnectionRecord {
            protocol: "TCP",
            local: "10.0.0.5:40000".to_string(),
            remote: "203.0.113.9:443".to_string(),
            state: "established".to_string(),
            pid: 1,
        });
        let mut second = ScanContext::default();
        second.connections.push(ConnectionRecord {
            protocol: "TCP",
            local: "10.0.0.5:51234".to_string(),
            remote: "203.0.113.9:443".to_string(),
            state: "established".to_string(),
            pid: 1,
        });
        assert!(diff(&snapshot("t1", &first), &snapshot("t2", &second)).is_empty());
    }

    #[test]
    fn snapshots_round_trip_through_the_stored_format() {
        let mut ctx = ScanContext::default();
        ctx.services.push(service("AcmeAgent"));
        let original = snapshot("2026-09-11 22:00:00", &ctx);

        let text = original.to_text();
        let parsed = Snapshot::from_text(&text);
        assert!(parsed.is_some());
        if let Some(parsed) = parsed {
            assert_eq!(parsed.taken_at, original.taken_at);
            assert_eq!(parsed.identities, original.identities);
            assert!(
                diff(&original, &parsed).is_empty(),
                "a stored snapshot must be identical"
            );
        }
    }

    #[test]
    fn a_snapshot_from_another_version_is_refused_rather_than_misread() {
        assert!(Snapshot::from_text("irscan-snapshot/0\n2026-01-01\nservice:x\n").is_none());
        assert!(Snapshot::from_text("").is_none());
        assert!(Snapshot::from_text("not a snapshot at all").is_none());
    }

    #[test]
    fn a_hostile_identity_cannot_forge_an_extra_entry() {
        // An identity carrying a newline would otherwise be read back as two identities,
        // letting a hostile service name invent history.
        let mut ctx = ScanContext::default();
        let mut evil = service("evil");
        evil.name = "evil\nservice:injected".to_string();
        ctx.services.push(evil);

        let text = snapshot("t1", &ctx).to_text();
        let parsed = match Snapshot::from_text(&text) {
            Some(parsed) => parsed,
            None => Snapshot {
                taken_at: String::new(),
                identities: BTreeSet::new(),
            },
        };
        assert!(
            parsed
                .identities
                .iter()
                .all(|i| !i.subject().contains('\n')),
            "the newline must not survive into a stored identity"
        );
        assert_eq!(
            parsed
                .identities
                .iter()
                .filter(|i| i.subject() == "injected")
                .count(),
            0,
            "a forged entry must not appear"
        );
    }

    #[test]
    fn empty_labels_are_dropped_rather_than_tracked() {
        assert!(Identity::new("service", "").is_none());
        assert!(Identity::new("service", "   ").is_none());
        assert!(
            Identity::new("", "x").is_some(),
            "the kind prefix is the caller's job"
        );
    }

    #[test]
    fn a_snapshot_of_nothing_is_empty_and_says_so() {
        let empty = snapshot("t1", &ScanContext::default());
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert_eq!(diff(&empty, &empty).summary(), "nothing changed");
    }
}
