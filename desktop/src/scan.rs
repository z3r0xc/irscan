//! Running a scan inside the application, with progress.
//!
//! This is the only place in the desktop crate that does real work, and even here the
//! work is borrowed: `collect::default_set`, `signatures::match_all` and
//! `rules::verdict` are the same calls the command-line tool makes, in the same order.
//! Nothing about what is suspicious is decided in this crate.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use irscan::collect::{self, Progress};
use irscan::model::ScanContext;
use irscan::report;
use irscan::{rules, signatures};
use serde::Serialize;
use tauri::{AppHandle, Emitter};

use crate::host;
use crate::monitor;
use crate::view::{build_view, ScanView};

/// One progress line, emitted as `scan://progress` while the scan runs.
///
/// `error` is `None` when the collector ran and `Some` when it could not - a fact about
/// this machine's privileges rather than a crash, and the window shows it as a warning.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressView {
    pub collector: String,
    pub elapsed_ms: u64,
    pub findings_added: usize,
    pub error: Option<String>,
}

/// Counts the scans this process has performed. The value doubles as the cursor the
/// front end hands back, so the report on disk and the view in the window can never
/// refer to different scans.
#[derive(Default)]
pub struct AppState {
    pub scans: AtomicU64,
}

/// The rendered report of the most recent scan.
///
/// The exact bytes the command-line tool would have written are kept, so exporting
/// cannot drift from the CLI and costs nothing, because nothing is recomputed.
#[derive(Default)]
pub struct LastScan {
    pub inner: Mutex<Option<LastScanData>>,
}

pub struct LastScanData {
    /// The scan this report belongs to. `export_report` compares it against the view the
    /// window is showing, so a slow export can never write the report of a *previous*
    /// scan over the results of the current one.
    pub cursor: u64,
    pub text: String,
    pub json: String,
}

/// The result of one scan: what the window renders, plus what it can export.
pub struct ScanOutcome {
    pub view: ScanView,
    pub text: String,
    pub json: String,
    pub cursor: u64,
}

/// Run the full scan.
///
/// Blocking on purpose. Tauri runs a command on a worker thread, so the window stays
/// responsive while this executes, and returning one complete payload avoids a
/// half-rendered list that grows as collectors finish.
pub fn run_scan(app: &AppHandle, state: &AppState, quick: bool) -> ScanOutcome {
    let started = Instant::now();
    let mut ctx = ScanContext::default();

    let collectors = collect::default_set(quick, Vec::new());
    let failures = collect::run_all_with(&collectors, &mut ctx, |p: &Progress| {
        // A failed emit is not worth surfacing: the window closing mid-scan is the only
        // way it happens, and the report is written regardless.
        let _ = app.emit(
            "scan://progress",
            ProgressView {
                collector: p.collector.to_string(),
                elapsed_ms: p.elapsed_ms.min(u64::MAX as u128) as u64,
                findings_added: p.findings_added,
                error: p.error.clone(),
            },
        );
    });

    for finding in signatures::match_all(&ctx.haystack) {
        ctx.add(finding);
    }

    let verdict = rules::verdict(&ctx.findings, failures);
    let host = host::collect();
    let cursor = state.scans.fetch_add(1, Ordering::SeqCst) + 1;
    let scanned_in_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;

    // Rendered with the library's own renderers rather than a second implementation:
    // the file exported from the window is byte-identical to the one the CLI writes.
    let text = report::render_text(&host, &ctx, &verdict);
    let json = report::render_json(&host, &ctx, &verdict);

    // Compared against the previous run and stored for the next one. A failure to write
    // the history is a warning, never a failed scan: this scan has already succeeded, and
    // losing the ability to compare with the *next* one is not a reason to discard it.
    let delta = monitor::compare_and_store(&ctx, &host.collected_at);
    if !delta.first_run && delta.added.is_empty() && delta.removed.is_empty() {
        // Nothing to say, and saying it would be noise.
    }

    ScanOutcome {
        view: build_view(&host, &ctx, &verdict, scanned_in_ms, cursor, delta),
        text,
        json,
        cursor,
    }
}

/// Refuse to export a report that does not belong to the scan on screen.
///
/// The cursor makes this check possible; the alternative - exporting whatever happens to
/// be in memory - would silently write one scan's results under another scan's heading.
pub fn may_export(data: &LastScanData, cursor: u64) -> Result<(), String> {
    if data.cursor == cursor {
        return Ok(());
    }
    Err(format!(
        "the report on screen belongs to scan {cursor}, but the stored report is from \
         scan {} - run the scan again",
        data.cursor
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pathological_elapsed_value_saturates_instead_of_wrapping() {
        // A collector could in principle report a duration beyond u64::MAX
        // milliseconds. The cast must saturate: wrapping would render a slow check as
        // instantaneous, which is a lie inside a report.
        let huge: u128 = u128::MAX;
        assert_eq!(huge.min(u64::MAX as u128) as u64, u64::MAX);
    }

    #[test]
    fn the_state_numbers_scans_from_one() {
        let state = AppState::default();
        assert_eq!(state.scans.fetch_add(1, Ordering::SeqCst) + 1, 1);
        assert_eq!(state.scans.fetch_add(1, Ordering::SeqCst) + 1, 2);
    }

    #[test]
    fn an_export_for_a_different_scan_is_refused() {
        // The guard that gives `cursor` its purpose: a report must be exported for the
        // scan the window is showing, never for an older one.
        let data = LastScanData {
            cursor: 6,
            text: "text".to_string(),
            json: "{}".to_string(),
        };
        assert!(may_export(&data, 6).is_ok());
        assert!(may_export(&data, 5).is_err());
        assert!(may_export(&data, 7).is_err());
    }
}
