//! Core data model: pure data, no OS access, no I/O.

use std::collections::HashMap;
use std::path::PathBuf;

/// Hard cap applied to every string that originates from the host under test.
/// Prevents a hostile service path or task name from bloating the report.
pub const MAX_STRING: usize = 512;

/// Severity of a finding.
///
/// The variant order is deliberate: `High < Med < Info`, so a plain ascending
/// `sort()` places the most interesting findings first. `severity_sorts_high_first`
/// pins that invariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    High,
    Med,
    Info,
}

impl Severity {
    pub fn tag(self) -> &'static str {
        match self {
            Severity::High => "HIGH",
            Severity::Med => "MED",
            Severity::Info => "INFO",
        }
    }

    /// Lower-case name used in the JSON report.
    pub fn label(self) -> &'static str {
        match self {
            Severity::High => "high",
            Severity::Med => "med",
            Severity::Info => "info",
        }
    }
}

/// A single reported observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub category: &'static str,
    pub title: String,
    pub evidence: Vec<String>,
    pub remediation: Vec<String>,
}

impl Finding {
    pub fn new(severity: Severity, category: &'static str, title: impl Into<String>) -> Self {
        Finding {
            severity,
            category,
            title: title.into(),
            evidence: Vec::new(),
            remediation: Vec::new(),
        }
    }

    pub fn evidence(mut self, line: impl Into<String>) -> Self {
        self.evidence.push(line.into());
        self
    }

    pub fn remediation(mut self, line: impl Into<String>) -> Self {
        self.remediation.push(line.into());
        self
    }
}

/// How a collected string should be compared against the signature database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HaystackKind {
    ProcessName,
    Path,
    ServiceName,
    ServiceDisplayName,
    RegistryPath,
    TaskName,
    Domain,
    Port,
    CommandLine,
    ProductName,
}

impl HaystackKind {
    pub fn label(self) -> &'static str {
        match self {
            HaystackKind::ProcessName => "process",
            HaystackKind::Path => "path",
            HaystackKind::ServiceName => "service",
            HaystackKind::ServiceDisplayName => "service-display",
            HaystackKind::RegistryPath => "registry",
            HaystackKind::TaskName => "task",
            HaystackKind::Domain => "domain",
            HaystackKind::Port => "port",
            HaystackKind::CommandLine => "cmdline",
            HaystackKind::ProductName => "product",
        }
    }
}

/// A string collected from the host, tagged with what it is and where it came from.
///
/// Collectors never look at the signature database: they push haystacks, and a
/// single matcher pass turns needles into findings. That keeps every collector
/// ignorant of detection policy and makes the policy testable on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Haystack {
    pub kind: HaystackKind,
    pub value: String,
    pub origin: String,
}

impl Haystack {
    pub fn new(kind: HaystackKind, value: impl Into<String>, origin: impl Into<String>) -> Self {
        Haystack {
            kind,
            value: value.into(),
            origin: origin.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessRecord {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub path: Option<PathBuf>,
    pub cmdline: String,
    pub owner: String,
    /// Seconds since the Unix epoch, when the API exposes it.
    pub started: Option<u64>,
    /// `None` when signature verification could not be attempted.
    pub signature_trusted: Option<bool>,
    pub company: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRecord {
    pub name: String,
    pub display_name: String,
    pub state: String,
    pub start_mode: String,
    pub account: String,
    pub image_path: String,
    pub is_driver: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRecord {
    pub name: String,
    pub path: String,
    pub state: String,
    pub author: String,
    pub action: String,
    pub hidden: bool,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutorunRecord {
    pub location: String,
    pub name: String,
    pub command: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionRecord {
    pub protocol: &'static str,
    pub local: String,
    pub remote: String,
    pub state: String,
    pub pid: u32,
}

/// Aggregated result, computed once at the end (see `rules::verdict`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub high: usize,
    pub med: usize,
    pub info: usize,
    pub headline: String,
    pub recommendation: Vec<String>,
}

/// Everything a scan accumulates. Collectors push; rules and report read.
#[derive(Debug, Default)]
pub struct ScanContext {
    pub findings: Vec<Finding>,
    pub warnings: Vec<String>,
    pub haystack: Vec<Haystack>,
    pub processes: HashMap<u32, ProcessRecord>,
    pub services: Vec<ServiceRecord>,
    pub tasks: Vec<TaskRecord>,
    pub autoruns: Vec<AutorunRecord>,
    pub connections: Vec<ConnectionRecord>,
    /// Free-form sections rendered verbatim under RAW DATA, in insertion order.
    pub raw: Vec<(String, Vec<String>)>,
}

impl ScanContext {
    pub fn add(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    /// Record a non-fatal problem. A collector must never abort the scan.
    ///
    /// An exact duplicate is dropped: several collectors query the same subsystem
    /// once per event ID, so an unreadable Security log would otherwise appear three
    /// times and make the WARNINGS section harder to read than the problem it
    /// describes. Distinct messages are always kept.
    pub fn warn(&mut self, message: impl Into<String>) {
        let m = crate::text::sanitize(&message.into(), MAX_STRING);
        if m.is_empty() || self.warnings.iter().any(|seen| seen == &m) {
            return;
        }
        self.warnings.push(m);
    }

    pub fn note(
        &mut self,
        kind: HaystackKind,
        value: impl Into<String>,
        origin: impl Into<String>,
    ) {
        let v = crate::text::sanitize(&value.into(), MAX_STRING);
        if v.is_empty() {
            return;
        }
        self.haystack.push(Haystack::new(
            kind,
            v,
            crate::text::sanitize(&origin.into(), MAX_STRING),
        ));
    }

    pub fn raw_section(&mut self, section: impl Into<String>, lines: Vec<String>) {
        self.raw.push((
            section.into(),
            lines
                .into_iter()
                .map(|l| crate::text::sanitize(&l, MAX_STRING))
                .collect(),
        ));
    }

    pub fn process_name(&self, pid: u32) -> Option<&str> {
        self.processes.get(&pid).map(|p| p.name.as_str())
    }

    pub fn counts(&self) -> (usize, usize, usize) {
        let mut high = 0;
        let mut med = 0;
        let mut info = 0;
        for f in &self.findings {
            match f.severity {
                Severity::High => high += 1,
                Severity::Med => med += 1,
                Severity::Info => info += 1,
            }
        }
        (high, med, info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_sorts_high_first() {
        let mut v = vec![Severity::Info, Severity::High, Severity::Med];
        v.sort();
        assert_eq!(v, vec![Severity::High, Severity::Med, Severity::Info]);
    }

    #[test]
    fn note_sanitizes_and_drops_empty_values() {
        let mut ctx = ScanContext::default();
        ctx.note(HaystackKind::ProcessName, "  ", "origin");
        ctx.note(HaystackKind::ProcessName, "agent.exe\u{1b}[31m", "origin");
        assert_eq!(ctx.haystack.len(), 1, "blank haystacks are dropped");
        assert_eq!(ctx.haystack[0].value, "agent.exe");
    }

    #[test]
    fn warnings_are_deduplicated_but_not_swallowed() {
        let mut ctx = ScanContext::default();
        ctx.warn("events: Security unavailable");
        ctx.warn("events: Security unavailable");
        ctx.warn("events: System unavailable");
        ctx.warn("");
        assert_eq!(ctx.warnings.len(), 2, "got {:?}", ctx.warnings);
        assert_eq!(ctx.warnings[0], "events: Security unavailable");
        assert_eq!(ctx.warnings[1], "events: System unavailable");
    }

    #[test]
    fn counts_match_severities() {
        let mut ctx = ScanContext::default();
        ctx.add(Finding::new(Severity::High, "c", "t"));
        ctx.add(Finding::new(Severity::Med, "c", "t"));
        ctx.add(Finding::new(Severity::Med, "c", "t"));
        assert_eq!(ctx.counts(), (1, 2, 0));
    }
}
