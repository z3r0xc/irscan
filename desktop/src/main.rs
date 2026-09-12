//! IRScan desktop - the same read-only triage, in a window.
//!
//! The window exists so a report can be read comfortably on the machine it was taken
//! from. It is not an alternative implementation: every finding, count and warning comes
//! from the `irscan` library, which is also what the command-line tool runs (FR-31).
//!
//! Security posture, stated so a reviewer can check it rather than trust it:
//! * no network access - no http plugin is installed and the CSP forbids it;
//! * no shell and no general filesystem access: the file commands here take an exact path,
//!   and the only path the interface produces comes from the user's own save dialog;
//! * the removal commands take a typed identifier, never a command line, so no string read
//!   off the machine can reach an interpreter;
//! * a strict CSP, and the front end renders only through `textContent`.

// Test code uses panic!, unwrap and expect as its assertion mechanism; production code
// keeps the strict lints - the same policy as the library crate.
#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used, clippy::expect_used))]

mod act;
mod host;
mod monitor;
mod scan;
mod view;

use std::path::PathBuf;

use serde::Serialize;
use tauri::Manager;

use scan::{AppState, LastScan, LastScanData};
use view::ScanView;

/// Run the collectors and return everything the window renders.
#[tauri::command]
async fn scan(app: tauri::AppHandle, quick: bool) -> Result<ScanView, String> {
    let handle = app.clone();
    let outcome = tauri::async_runtime::spawn_blocking(move || {
        let state = handle.state::<AppState>();
        let last = handle.state::<LastScan>();
        let outcome = scan::run_scan(&handle, state.inner(), quick);

        if let Ok(mut guard) = last.inner.lock() {
            *guard = Some(LastScanData {
                cursor: outcome.cursor,
                text: outcome.text.clone(),
                json: outcome.json.clone(),
            });
        }

        outcome
    })
    .await;

    match outcome {
        Ok(outcome) => Ok(outcome.view),
        Err(e) => Err(format!("the scan could not be started: {e}")),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AppInfo {
    version: &'static str,
    needles: usize,
    yara_rules: usize,
    collectors: usize,
    elevated: bool,
    history_path: String,
}

#[tauri::command]
fn app_info() -> AppInfo {
    let (rules, _) = irscan::collect::yara::compile_sources(&[(
        "bundled".to_string(),
        irscan::collect::yara::BUNDLED_RULES.to_string(),
    )]);
    AppInfo {
        version: env!("CARGO_PKG_VERSION"),
        needles: irscan::signatures::SIGNATURES.len(),
        yara_rules: rules.iter().count(),
        collectors: irscan::collect::default_set(false, Vec::new()).len(),
        elevated: irscan::win::is_elevated(),
        history_path: monitor::history_path().display().to_string(),
    }
}

/// Write the report of the scan the window is showing.
///
/// The `cursor` must match. Without that check a slow export could write an older scan's
/// report over the one on screen, and the user would have no way to notice.
#[tauri::command]
fn export_report(
    state: tauri::State<'_, LastScan>,
    format: String,
    path: String,
    cursor: u64,
) -> Result<String, String> {
    let target = PathBuf::from(path.trim());
    if target.as_os_str().is_empty() {
        return Err("no path was given".to_string());
    }
    if target.is_dir() {
        return Err(format!("{} is a directory, not a file", target.display()));
    }

    let guard = state
        .inner
        .lock()
        .map_err(|_| "the last scan is unavailable".to_string())?;
    let data = guard
        .as_ref()
        .ok_or_else(|| "there is no completed scan to export".to_string())?;

    scan::may_export(data, cursor)?;

    let body = match format.as_str() {
        "text" => &data.text,
        "json" => &data.json,
        other => return Err(format!("unsupported format '{other}'")),
    };

    std::fs::write(&target, body).map_err(|e| format!("cannot write {}: {e}", target.display()))?;
    Ok(target.display().to_string())
}

/// What a containment action produced, plus where its undo record went.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Containment {
    description: String,
    outcome: String,
    undo_path: String,
}

/// Stop and disable a service, and write the record that reverses it.
///
/// The service name is validated against the machine before anything is touched, so a
/// stale value in the interface fails loudly instead of silently doing nothing.
#[tauri::command]
fn disable_service(name: String, report_path: String) -> Result<Containment, String> {
    let action = irscan::remediate::Action::DisableService {
        name: name.trim().to_string(),
        previous_start: 2,
    };
    let applied = act::apply(&action)?;

    let undo = act::undo_path(&PathBuf::from(report_path.trim()));
    act::write_undo_record(
        &undo,
        std::slice::from_ref(&action),
        &irscan::win::local_time_string(),
    )?;

    Ok(Containment {
        description: applied.description,
        outcome: applied.outcome,
        undo_path: undo.display().to_string(),
    })
}

/// Remove one autostart value, and write the record that restores it.
#[tauri::command]
fn remove_autostart(
    hive: String,
    key: String,
    value: String,
    report_path: String,
) -> Result<Containment, String> {
    let action = irscan::remediate::Action::RemoveAutostart {
        hive: hive.trim().to_string(),
        key: key.trim().to_string(),
        value: value.trim().to_string(),
        previous_data: String::new(),
    };
    let applied = act::apply(&action)?;

    let undo = act::undo_path(&PathBuf::from(report_path.trim()));
    act::write_undo_record(
        &undo,
        std::slice::from_ref(&action),
        &irscan::win::local_time_string(),
    )?;

    Ok(Containment {
        description: applied.description,
        outcome: applied.outcome,
        undo_path: undo.display().to_string(),
    })
}

fn main() {
    // `expect` is denied crate-wide, so the fallible `run` is handled explicitly. The
    // only realistic failure is a missing WebView2 runtime, and saying that plainly beats
    // a window that opens blank and looks like a bug in the tool.
    if let Err(e) = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .manage(LastScan::default())
        .invoke_handler(tauri::generate_handler![
            scan,
            app_info,
            export_report,
            disable_service,
            remove_autostart
        ])
        .run(tauri::generate_context!())
    {
        eprintln!(
            "irscan-desktop could not start: {e}\n\
             This is usually a missing WebView2 runtime. It ships with Windows 11 and \
             arrives on Windows 10 through Windows Update; the installer is \
             \"WebView2 Runtime\" from Microsoft."
        );
        std::process::exit(1);
    }
}
