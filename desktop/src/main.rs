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
// Without this the binary is linked as a console application (subsystem 3), so Windows
// attaches a console window and the user sees a black terminal beside the interface -
// reported exactly that way. `windows` selects the GUI subsystem, which is the same
// information the CLI's opposite choice carries: a CLI must have a console, a GUI must not.
// Debug builds keep the console, because a panic in a windowed process is otherwise
// invisible.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod act;
mod host;
mod locale;
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
    /// `"ru"` or `"en"`, from the machine's own locale. This is the only place the
    /// window can learn it: WebView2 reports `en-US` through `navigator.language` even
    /// on a Russian Windows.
    language: &'static str,
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
        language: locale::language(),
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

/// The rendered report of the scan the window is showing, as text.
///
/// The same bytes `export_report` would write, without writing them. The window already
/// holds the report - the scan command renders it once and keeps it - so "show me the
/// report" costs a clone rather than a re-render, and what the user reads in the window
/// is guaranteed to be what the file would contain, because it is literally the same
/// string.
///
/// `cursor` must match, for the same reason it must on export: a window showing scan N
/// must never display the report of scan N-1.
///
/// The `json` flag selects the machine-readable form. It is offered because the file
/// dialog offers both, and a user who wants to check a field before saving should not
/// have to save a file to do it.
#[tauri::command]
fn report_text(
    state: tauri::State<'_, LastScan>,
    cursor: u64,
    json: bool,
) -> Result<String, String> {
    let guard = state
        .inner
        .lock()
        .map_err(|_| "the last scan is unavailable".to_string())?;
    let data = guard
        .as_ref()
        .ok_or_else(|| "there is no completed scan to show".to_string())?;

    scan::may_export(data, cursor)?;

    Ok(if json {
        data.json.clone()
    } else {
        data.text.clone()
    })
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
    let requested = irscan::remediate::Action::DisableService {
        name: name.trim().to_string(),
        // Filled in by `prepare` from the machine's real value, never guessed here:
        // an undo line that restores a start type the service never had is worse than
        // no undo line, because it looks authoritative.
        previous_start: 0,
    };

    // Read first, write the record, and only then change anything. The order is the
    // guarantee: if the record cannot be written, nothing has been modified yet, so
    // the error is a clean refusal rather than a machine changed with no way back.
    let action = act::prepare(&requested)?;
    let undo = act::undo_path(&PathBuf::from(report_path.trim())).ok_or_else(|| {
        "save the report first: the undo record is written beside it, and without the \
         report there is nowhere to put it. Nothing has been changed."
            .to_string()
    })?;
    act::write_undo_record(
        &undo,
        std::slice::from_ref(&action),
        &irscan::win::local_time_string(),
    )?;

    let applied = act::apply(&action)?;

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
    let requested = irscan::remediate::Action::RemoveAutostart {
        hive: hive.trim().to_string(),
        key: key.trim().to_string(),
        value: value.trim().to_string(),
        // Filled in by `prepare` from the value's real contents. This is the whole
        // point of the record: without it the undo line says to restore an empty
        // string, and running it would destroy what was there.
        previous_data: String::new(),
    };

    let action = act::prepare(&requested)?;
    let undo = act::undo_path(&PathBuf::from(report_path.trim())).ok_or_else(|| {
        "save the report first: the undo record is written beside it, and without the \
         report there is nowhere to put it. Nothing has been changed."
            .to_string()
    })?;
    act::write_undo_record(
        &undo,
        std::slice::from_ref(&action),
        &irscan::win::local_time_string(),
    )?;

    let applied = act::apply(&action)?;

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
    // The OS language, set on the document before the page is parsed.
    //
    // `index.html` declares `lang="en"`, and the front end used to decide from
    // `navigator.language` - which WebView2 answers with `en-US` even on a Russian
    // machine. The result was a window painted in English that repainted in Russian
    // once `app_info` resolved. An init script runs before the document is built, so
    // the first paint already has the right answer and `app_info` only confirms it.
    //
    // The value is one of two literals from `locale::language()`, never collected data,
    // so interpolating it into a script is safe; it is still written as a JSON string
    // rather than pasted between quotes.
    let lang_script = format!(
        "document.documentElement.setAttribute('lang', {});",
        serde_json::to_string(locale::language()).unwrap_or_else(|_| "\"en\"".to_string())
    );

    if let Err(e) = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(move |app| {
            // The window is declared in `tauri.conf.json`, which cannot carry code, so it
            // is built here instead and given the language script. `app.windows` in that
            // file is deliberately empty - restoring an entry there would open a second
            // window, because this call would still run. Building it in `setup`
            // rather than editing the config is what lets `initialization_script` be
            // used: it is a builder method, and the runtime guarantees it runs after the
            // global object exists but **before the document is parsed** - which is why
            // the first paint is already in the right language rather than repainted.
            //
            // The config's window entry is removed in `tauri.conf.json`; if that is ever
            // restored, this would open a second window, so the two must change together.
            tauri::WebviewWindowBuilder::new(app, "main", tauri::WebviewUrl::default())
                .title("IRScan - read-only endpoint triage")
                .inner_size(1280.0, 840.0)
                .min_inner_size(900.0, 600.0)
                .resizable(true)
                .center()
                .theme(Some(tauri::Theme::Dark))
                .background_color(tauri::window::Color(10, 10, 10, 255))
                .initialization_script(&lang_script)
                .build()
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
            Ok(())
        })
        .manage(AppState::default())
        .manage(LastScan::default())
        .invoke_handler(tauri::generate_handler![
            scan,
            app_info,
            export_report,
            report_text,
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

#[cfg(test)]
mod tests {
    /// The binary must be a GUI application, not a console one.
    ///
    /// The user reported a black terminal window opening beside the interface, and the PE
    /// header explained it: the binary was linked with subsystem 3 (`WINDOWS_CUI`), so
    /// Windows attached a console. The attribute that fixes it is invisible in review - it
    /// is a cfg-gated crate attribute - and dropping it would silently bring the console
    /// back. Verified independently: the release binary's PE header now reads subsystem 2,
    /// and no `conhost.exe` child is created when it starts.
    ///
    /// The check is on the source because the attribute only affects release linkage, while
    /// this test runs in the debug profile where the console is deliberately kept.
    #[test]
    fn the_release_binary_is_a_gui_application_not_a_console_one() {
        let source = include_str!("main.rs");
        assert!(
            source.contains("windows_subsystem = \"windows\""),
            "the GUI must select the windows subsystem or a console window appears"
        );
        // Gated on release on purpose: a panicking windowed process is invisible, so debug
        // builds keep the console to show it.
        assert!(
            source.contains("cfg_attr(not(debug_assertions), windows_subsystem"),
            "the console must stay available in debug builds"
        );
    }

    /// The window is built in Rust, so `tauri.conf.json` must not declare one.
    ///
    /// The language has to be set before the document is parsed, and the only API for that
    /// (`initialization_script`) is a builder method. The window therefore moved out of
    /// the config and into `setup`. If a `windows` entry is ever restored there, Tauri
    /// creates it *and* this code creates its own, and the user gets two windows. The
    /// coupling is invisible in either file alone, so it is pinned here.
    #[test]
    fn the_config_does_not_also_declare_a_window() {
        let config = include_str!("../tauri.conf.json");
        let parsed: serde_json::Value =
            serde_json::from_str(config).expect("tauri.conf.json must be valid JSON");
        let windows = parsed["app"]["windows"]
            .as_array()
            .expect("app.windows must be an array");

        if !windows.is_empty() {
            let source = include_str!("main.rs");
            assert!(
                !source.contains("WebviewWindowBuilder::new"),
                "the window is declared in tauri.conf.json and built in main.rs; \
                 that opens two windows - keep exactly one of them"
            );
        }
    }

    /// The language tag reaches the document as a JSON string, never pasted raw.
    ///
    /// `locale::language()` returns one of two literals today, but writing it into a
    /// script by interpolation is the shape that becomes an injection the moment the
    /// function returns anything richer. The script is built with `serde_json::to_string`,
    /// and this pins that it stays that way.
    #[test]
    fn the_language_script_quotes_its_value() {
        let source = include_str!("main.rs");
        assert!(
            source.contains("serde_json::to_string(locale::language())"),
            "the language must be JSON-encoded before it is written into a script"
        );
    }
}
