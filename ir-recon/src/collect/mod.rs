//! Collectors: the only place that observes the operating system.
//!
//! Contract (see docs/architecture.md section 3):
//!
//! * A collector **observes** and records. It never prints, never decides severity
//!   beyond calling into `rules`, and never looks at the signature database - it
//!   pushes [`crate::model::Haystack`] values instead.
//! * A collector returns `Err` only when it cannot run at all. Partial success is
//!   `Ok` plus a warning: one broken collector must never abort a scan, because the
//!   machine under analysis is assumed hostile and part of the point is to find out
//!   which of its subsystems is lying.
//! * Collectors run in a fixed order so that two scans of an unchanged host produce
//!   identical reports.

pub mod autoruns;
pub mod defender;
pub mod filesystem;
pub mod inputfilters;
pub mod processes;
pub mod tasks;
pub mod traces;
pub mod yara;

pub mod accounts;
pub mod events;
pub mod network;
pub mod remote_access;
pub mod services;
pub mod wmi;
use crate::model::ScanContext;

/// Why a collector could not run at all.
#[derive(Debug)]
pub struct CollectError {
    pub collector: &'static str,
    pub message: String,
}

impl CollectError {
    pub fn new(collector: &'static str, message: impl std::fmt::Display) -> Self {
        CollectError {
            collector,
            message: message.to_string(),
        }
    }
}

impl std::fmt::Display for CollectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.collector, self.message)
    }
}

impl std::error::Error for CollectError {}

/// A single observation pass over one subsystem.
pub trait Collector {
    /// Stable identifier used in warnings and in the report.
    fn name(&self) -> &'static str;

    /// Observe and record. Must not print and must not panic.
    fn run(&self, ctx: &mut ScanContext) -> Result<(), CollectError>;
}

/// What one collector did, reported as soon as it finishes.
///
/// This exists so the caller can show progress: a scan takes long enough that a
/// silent window looks like a hang, and knowing which check is slow is itself useful
/// information when triaging an unfamiliar machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Progress {
    pub collector: &'static str,
    pub elapsed_ms: u128,
    pub findings_added: usize,
    /// `Some` when the collector could not run at all. The scan carried on.
    pub error: Option<String>,
}

/// Run every collector in order, isolating failures and reporting progress.
///
/// Returns the number of collectors that failed; each failure is recorded as a
/// warning on the context rather than propagated.
pub fn run_all_with<F>(
    collectors: &[Box<dyn Collector>],
    ctx: &mut ScanContext,
    mut on_progress: F,
) -> usize
where
    F: FnMut(&Progress),
{
    let mut failures = 0usize;
    for collector in collectors {
        let before = ctx.findings.len();
        let started = std::time::Instant::now();
        let outcome = collector.run(ctx);

        let mut error = None;
        if let Err(e) = outcome {
            let message = e.to_string();
            ctx.warn(format!("collector failed: {message}"));
            error = Some(message);
            failures += 1;
        }

        on_progress(&Progress {
            collector: collector.name(),
            elapsed_ms: started.elapsed().as_millis(),
            findings_added: ctx.findings.len().saturating_sub(before),
            error,
        });
    }
    failures
}

/// The collector set and its execution order.
///
/// This lives in the library rather than in each front end on purpose: two surfaces that
/// each assembled their own list would drift, and the desktop application must run
/// exactly the checks the command-line tool runs.
///
/// The order is fixed rather than parallel so that two scans of an unchanged host
/// produce byte-identical reports - a diff between runs should mean the host changed.
/// Two orderings are load-bearing: `processes` runs before `network` (which labels
/// sockets with process names), and `yara` runs last (it consumes what the other
/// collectors found instead of walking the disk itself).
pub fn default_set(
    quick: bool,
    extra_rule_files: Vec<std::path::PathBuf>,
) -> Vec<Box<dyn Collector>> {
    let mut collectors: Vec<Box<dyn Collector>> = vec![
        Box::new(crate::collect::accounts::AccountsCollector),
        Box::new(crate::collect::remote_access::RemoteAccessCollector),
        Box::new(crate::collect::services::ServicesCollector),
        Box::new(crate::collect::tasks::TasksCollector),
        Box::new(crate::collect::autoruns::AutorunsCollector),
        Box::new(crate::collect::wmi::WmiCollector),
        Box::new(crate::collect::inputfilters::InputFiltersCollector),
        Box::new(crate::collect::defender::DefenderCollector),
        Box::new(crate::collect::processes::ProcessesCollector),
        Box::new(crate::collect::network::NetworkCollector),
        Box::new(crate::collect::traces::TracesCollector),
        Box::new(crate::collect::filesystem::FilesystemCollector::new(quick)),
        Box::new(crate::collect::events::EventsCollector),
    ];
    collectors.push(Box::new(crate::collect::yara::YaraCollector::new(
        extra_rule_files,
    )));
    collectors
}

/// Run every collector, ignoring progress. Equivalent to `run_all_with` with a
/// no-op observer.
pub fn run_all(collectors: &[Box<dyn Collector>], ctx: &mut ScanContext) -> usize {
    run_all_with(collectors, ctx, |_| {})
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysOk;

    impl Collector for AlwaysOk {
        fn name(&self) -> &'static str {
            "ok"
        }
        fn run(&self, _ctx: &mut ScanContext) -> Result<(), CollectError> {
            Ok(())
        }
    }

    struct AlwaysFails;

    impl Collector for AlwaysFails {
        fn name(&self) -> &'static str {
            "boom"
        }
        fn run(&self, _ctx: &mut ScanContext) -> Result<(), CollectError> {
            Err(CollectError::new("boom", "synthetic failure"))
        }
    }

    #[test]
    fn a_failing_collector_does_not_stop_the_others() {
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(AlwaysFails), Box::new(AlwaysOk)];
        let mut ctx = ScanContext::default();
        let failures = run_all(&collectors, &mut ctx);

        assert_eq!(failures, 1);
        assert_eq!(
            ctx.warnings.len(),
            1,
            "the failure is recorded as a warning"
        );
        assert!(ctx.warnings[0].contains("boom"));
    }

    #[test]
    fn progress_is_reported_for_every_collector_including_a_failing_one() {
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(AlwaysFails), Box::new(AlwaysOk)];
        let mut ctx = ScanContext::default();
        let mut seen: Vec<&'static str> = Vec::new();
        let mut errors = 0usize;

        let failures = run_all_with(&collectors, &mut ctx, |p| {
            seen.push(p.collector);
            if p.error.is_some() {
                errors += 1;
            }
        });

        assert_eq!(seen, vec!["boom", "ok"]);
        assert_eq!(failures, 1);
        assert_eq!(errors, 1, "the failure must be visible to the observer too");
        assert_eq!(ctx.warnings.len(), 1);
    }

    #[test]
    fn collect_error_display_is_the_contract_for_report_warnings() {
        let e = CollectError::new("services", "access denied");
        assert_eq!(e.to_string(), "services: access denied");
    }
}
