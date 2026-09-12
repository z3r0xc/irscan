//! IRScan command-line entry point.
//!
//! Responsibilities, in order: parse arguments, offer an elevated copy of itself when
//! the user wants full coverage, run every collector, run the signature pass exactly
//! once, compute the verdict, then present the result two ways - a styled console view
//! for the person sitting in front of the machine, and a plain text file that keeps
//! its bytes stable so two runs can be diffed.
//!
//! All observation lives in `collect`, all judgement in `rules`, all presentation in
//! `ui` and `report`; this file only wires them together.

// The crate-wide lints above target production code. In test code, `panic!`,
// `unwrap` and `expect` ARE the assertion mechanism, so they are lifted for the
// test configuration only - never for a shipped binary.
#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used, clippy::expect_used))]

use std::collections::HashSet;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use irscan::collect::{self, Collector};
use irscan::model::ScanContext;
use irscan::report::{self, HostInfo};
use irscan::ui::{self, Style};
use irscan::{rules, signatures, win};

/// Exit code used when the tool itself could not run as asked.
const EXIT_USAGE: u8 = 2;
/// Exit code used when `--self-test` found a collector that failed.
const EXIT_SELF_TEST_FAILED: u8 = 1;

/// Parsed command line. Pure data, so `Options::parse` is unit tested.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct Options {
    quick: bool,
    json_path: Option<String>,
    out_dir: Option<String>,
    watch_seconds: u64,
    self_test: bool,
    help: bool,
    no_elevate: bool,
    /// Force plain output even on a terminal.
    plain: bool,
    /// Force styled output even when stdout is a pipe.
    force_style: bool,
    /// Use ASCII instead of box-drawing characters.
    ascii: bool,
    /// Tint HIGH findings red. Off by default: the palette is monochrome.
    severity_colour: bool,
    /// Override the wrap width.
    width: Option<usize>,
    /// Do not run the YARA content scan.
    no_yara: bool,
    /// Additional YARA rule files or directories.
    yara_rules: Vec<PathBuf>,
    /// Hide the per-collector progress lines.
    quiet: bool,
}

impl Options {
    fn parse(args: &[String]) -> Result<Options, String> {
        let mut opts = Options::default();
        let mut i = 0usize;
        while i < args.len() {
            let arg = args[i].as_str();
            match arg {
                "--quick" => opts.quick = true,
                "--self-test" => opts.self_test = true,
                "--help" | "-h" => opts.help = true,
                "--no-elevate" => opts.no_elevate = true,
                "--plain" => opts.plain = true,
                "--style" | "--force-style" => opts.force_style = true,
                "--ascii" => opts.ascii = true,
                "--severity-colour" | "--severity-color" => opts.severity_colour = true,
                "--no-yara" => opts.no_yara = true,
                "--quiet" => opts.quiet = true,
                "--width" => {
                    i += 1;
                    let raw = args
                        .get(i)
                        .ok_or_else(|| "--width needs a column count".to_string())?;
                    let n = raw
                        .parse::<usize>()
                        .map_err(|_| format!("--width expects a number, got '{raw}'"))?;
                    opts.width = Some(n);
                }
                "--json" => {
                    i += 1;
                    opts.json_path = Some(
                        args.get(i)
                            .ok_or_else(|| "--json needs a file path".to_string())?
                            .clone(),
                    );
                }
                "--out" => {
                    i += 1;
                    opts.out_dir = Some(
                        args.get(i)
                            .ok_or_else(|| "--out needs a directory".to_string())?
                            .clone(),
                    );
                }
                "--watch" => {
                    i += 1;
                    let raw = args
                        .get(i)
                        .ok_or_else(|| "--watch needs a number of seconds".to_string())?;
                    opts.watch_seconds = raw
                        .parse::<u64>()
                        .map_err(|_| format!("--watch expects seconds, got '{raw}'"))?;
                }
                "--yara-rules" => {
                    i += 1;
                    let raw = args
                        .get(i)
                        .ok_or_else(|| "--yara-rules needs a path".to_string())?;
                    // A comma-separated list keeps the common case to one flag.
                    for part in raw.split(',') {
                        let trimmed = part.trim();
                        if !trimmed.is_empty() {
                            opts.yara_rules.push(PathBuf::from(trimmed));
                        }
                    }
                }
                other => return Err(format!("unknown argument: {other}")),
            }
            i += 1;
        }
        Ok(opts)
    }

    /// The arguments an elevated relaunch should receive. `--no-elevate` is dropped so
    /// the child cannot inherit the instruction that suppressed elevation, and
    /// `--quiet` is kept so a relaunched run does not print progress twice.
    fn relaunch_args(args: &[String]) -> Vec<String> {
        let mut out: Vec<String> = args.to_vec();
        out.retain(|a| a != "--no-elevate");
        out
    }

    /// Expand any directories in `--yara-rules` into the rule files they contain.
    fn rule_files(&self) -> Vec<PathBuf> {
        let mut out: Vec<PathBuf> = Vec::new();
        for path in &self.yara_rules {
            if path.is_dir() {
                if let Ok(entries) = std::fs::read_dir(path) {
                    for entry in entries.flatten() {
                        let candidate = entry.path();
                        let name = candidate.to_string_lossy().to_ascii_lowercase();
                        if name.ends_with(".yar") || name.ends_with(".yara") {
                            out.push(candidate);
                        }
                    }
                }
            } else {
                out.push(path.clone());
            }
        }
        out.sort();
        out.dedup();
        out
    }
}

fn usage() -> String {
    [
        "IRScan - read-only Windows endpoint triage",
        "",
        "USAGE:",
        "  irscan.exe                        full scan: console report + .txt file",
        "  irscan.exe --json out.json        also write a machine-readable report",
        "  irscan.exe --quick                skip the slow collectors (prefetch, disk walk)",
        "  irscan.exe --watch 120            after the scan, watch new outbound connections",
        "  irscan.exe --out DIR              where to write the report (default: current dir)",
        "  irscan.exe --self-test            run every collector once and report failures",
        "  irscan.exe --no-elevate           stay unelevated on purpose",
        "",
        "PRESENTATION:",
        "  --plain             never emit ANSI sequences (also implied by NO_COLOR or a pipe)",
        "  --style             force styled output even when stdout is redirected",
        "  --ascii             use ASCII instead of box-drawing characters",
        "  --severity-colour   tint HIGH findings red (default is strictly monochrome)",
        "  --width N           wrap the console view to N columns",
        "  --quiet             hide the per-collector progress lines",
        "",
        "CONTENT SCANNING:",
        "  --yara-rules PATH   extra YARA rule file or directory (comma-separated)",
        "  --no-yara           skip the content scan entirely",
        "",
        "The tool never modifies the system and never contacts the network.",
        "It writes exactly one report file.",
    ]
    .join("\n")
}

/// Convert Unix epoch seconds to a UTC `YYYY-MM-DD HH:MM:SS` stamp.
///
/// Implemented here instead of pulling in a date crate: civil-from-days is about
/// twenty lines and is pinned by unit tests, which is a better trade than a
/// dependency for the two timestamps the report needs.
fn epoch_to_datetime(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    // Howard Hinnant's civil_from_days, epoch shifted to 0000-03-01.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 {
        year += 1;
    }

    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}")
}

fn now_epoch_secs() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => 0,
    }
}

fn host_info() -> HostInfo {
    let ver = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let os_name = win::reg::get_string(win::reg::RootKey::Hklm, ver, "ProductName")
        .unwrap_or_else(|| "Windows".to_string());
    let build_number = win::reg::get_string(win::reg::RootKey::Hklm, ver, "CurrentBuildNumber")
        .unwrap_or_default();
    let revision = win::reg::get_string(win::reg::RootKey::Hklm, ver, "UBR").unwrap_or_default();
    let install_epoch = win::reg::get_u64(win::reg::RootKey::Hklm, ver, "InstallDate");

    let build = if revision.is_empty() {
        build_number
    } else {
        format!("{build_number}.{revision}")
    };
    let install_date = match install_epoch {
        Some(secs) => epoch_to_datetime(secs),
        None => "unknown".to_string(),
    };
    let boot_epoch = now_epoch_secs().saturating_sub(win::uptime_seconds());

    HostInfo {
        name: std::env::var("COMPUTERNAME").unwrap_or_default(),
        user: std::env::var("USERNAME").unwrap_or_default(),
        os: os_name,
        build,
        install_date,
        boot_time: epoch_to_datetime(boot_epoch),
        elevated: win::is_elevated(),
        collected_at: win::local_time_string(),
    }
}

/// The collector set and its execution order, taken from the library.
///
/// The list itself lives in `collect::default_set` so that the desktop application
/// runs exactly the same checks; all this function decides is whether the content
/// scan is wanted at all.
fn build_collectors(opts: &Options) -> Vec<Box<dyn Collector>> {
    let mut collectors = collect::default_set(opts.quick, opts.rule_files());
    if opts.no_yara {
        collectors.retain(|c| c.name() != "yara");
    }
    collectors
}

/// Resolve the presentation settings from the flags and the environment.
fn resolve_style(opts: &Options) -> Style {
    let is_tty = std::io::stdout().is_terminal();
    let no_color = match std::env::var("NO_COLOR") {
        Ok(v) => !v.is_empty(),
        Err(_) => false,
    };
    let force = opts.force_style && !opts.plain;
    let colour = ui::should_style(is_tty, no_color || opts.plain, force);

    let width = match opts.width {
        Some(w) => w.clamp(ui::MIN_WIDTH, 200),
        None => match std::env::var("COLUMNS") {
            Ok(columns) => ui::width_from_env(Some(columns.as_str())),
            Err(_) => ui::width_from_env(None),
        },
    };

    Style {
        colour,
        unicode: !opts.ascii,
        width,
        severity_colour: opts.severity_colour,
    }
}

/// Run every collector, then the signature pass, reporting progress as it goes.
///
/// Progress goes to stderr so that `irscan > report.txt` still yields a clean file.
fn scan(opts: &Options, style: &Style) -> (ScanContext, usize) {
    let mut ctx = ScanContext::default();
    let show_progress = !opts.quiet && style.colour;
    let collectors = build_collectors(opts);

    let failures = collect::run_all_with(&collectors, &mut ctx, |p| {
        if !show_progress {
            return;
        }
        let status = match &p.error {
            Some(message) => format!("failed: {message}"),
            None => format!("{} finding(s)", p.findings_added),
        };
        eprintln!(
            "  {} {:<14} {:>6} ms  {}",
            style.dim("*"),
            p.collector,
            p.elapsed_ms,
            style.dim(&status)
        );
    });

    for finding in signatures::match_all(&ctx.haystack) {
        ctx.add(finding);
    }
    (ctx, failures)
}

/// Watch new outbound connections. This is how a periodic beacon - a screenshot
/// upload every N seconds - is caught in the act rather than inferred.
fn watch_connections(seconds: u64, ctx: &ScanContext, style: &Style) {
    println!();
    println!(
        "{}",
        style.bright(&format!(
            "Watching new outbound connections for {seconds}s (Ctrl+C to stop)"
        ))
    );

    let mut seen: HashSet<(u32, String)> = HashSet::new();
    for c in &ctx.connections {
        seen.insert((c.pid, c.remote.clone()));
    }

    let deadline = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_secs(2));
        for c in win::net::tcp_connections() {
            let key = (c.pid, c.remote.clone());
            if seen.contains(&key) {
                continue;
            }
            if rules::is_private_ip(endpoint_address(&c.remote)) {
                continue;
            }
            seen.insert(key);
            let name = ctx.process_name(c.pid).unwrap_or("<already exited>");
            println!(
                "  {} pid {:<6} {:<26} -> {}  ({})",
                style.bright("NEW"),
                c.pid,
                name,
                c.remote,
                style.dim(&c.state)
            );
        }
    }
    println!("{}", style.dim("Watch finished."));
}

/// Address part of an `ip:port` endpoint, tolerating bracketed IPv6.
fn endpoint_address(endpoint: &str) -> &str {
    match endpoint.rfind(':') {
        Some(idx) if idx > 0 => endpoint[..idx].trim_matches(['[', ']']),
        _ => endpoint,
    }
}

/// Should the process wait for a key before exiting?
///
/// True only in the double-click case: no arguments at all and a real console. A
/// console application that exits instantly takes the report with it, so the user
/// double-clicks, sees a flash, and has nothing to read. An explicit run with flags -
/// including every scripted or piped run - never waits.
fn should_pause(args_were_empty: bool, stdout_is_terminal: bool) -> bool {
    args_were_empty && stdout_is_terminal
}

fn pause_before_exit() {
    println!();
    println!("Press Enter to close this window...");
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
}

fn report_stem(host: &HostInfo) -> String {
    let name = if host.name.is_empty() {
        "host"
    } else {
        host.name.as_str()
    };
    let stamp = host.collected_at.replace(' ', "_").replace(':', "-");
    format!("irscan-{name}-{stamp}")
}

fn write_outputs(
    opts: &Options,
    host: &HostInfo,
    text: &str,
    json: &str,
) -> Result<Option<PathBuf>, String> {
    let dir = match &opts.out_dir {
        Some(d) => PathBuf::from(d),
        None => {
            std::env::current_dir().map_err(|e| format!("cannot read current directory: {e}"))?
        }
    };
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return Err(format!("cannot create {}: {e}", dir.display()));
    }
    let txt_path = dir.join(format!("{}.txt", report_stem(host)));
    std::fs::write(&txt_path, text)
        .map_err(|e| format!("cannot write {}: {e}", txt_path.display()))?;

    if let Some(path) = &opts.json_path {
        let json_path = PathBuf::from(path);
        if let Some(parent) = json_path.parent() {
            if !parent.as_os_str().is_empty() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    return Err(format!("cannot create {}: {e}", parent.display()));
                }
            }
        }
        std::fs::write(&json_path, json)
            .map_err(|e| format!("cannot write {}: {e}", json_path.display()))?;
    }

    Ok(Some(txt_path))
}

fn self_test(opts: &Options, style: &Style) -> u8 {
    println!("{}", style.white("IRSCAN SELF-TEST"));
    println!(
        "{}",
        style.dim("running every collector once; this is the same code path as a scan and changes nothing")
    );
    println!();

    let mut ctx = ScanContext::default();
    let collectors = build_collectors(opts);
    let mut failed = 0usize;

    for collector in &collectors {
        let before = ctx.findings.len();
        let started = Instant::now();
        match collector.run(&mut ctx) {
            Ok(()) => {
                let added = ctx.findings.len() - before;
                println!(
                    "  {} {:<14} {:>6} ms  {} finding(s)",
                    style.bright("ok  "),
                    collector.name(),
                    started.elapsed().as_millis(),
                    added
                );
            }
            Err(e) => {
                failed += 1;
                println!("  {} {:<14} {}", style.white("FAIL"), collector.name(), e);
            }
        }
    }

    let (bundled_rules, rule_errors) = collect::yara::compile_sources(&[(
        "bundled".to_string(),
        collect::yara::BUNDLED_RULES.to_string(),
    )]);
    for problem in &rule_errors {
        println!("  bundled rule problem: {problem}");
    }

    println!();
    println!(
        "{} collector(s) ran, {} failed, {} signature needle(s), {} compiled YARA rule(s)",
        collectors.len(),
        failed,
        signatures::SIGNATURES.len(),
        bundled_rules.iter().count()
    );

    if failed == 0 {
        0
    } else {
        EXIT_SELF_TEST_FAILED
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let opts = match Options::parse(&args) {
        Ok(o) => o,
        Err(message) => {
            eprintln!("irscan: {message}");
            eprintln!();
            eprintln!("{}", usage());
            return ExitCode::from(EXIT_USAGE);
        }
    };

    if opts.help {
        println!("{}", usage());
        return ExitCode::SUCCESS;
    }

    // Windows terminals need to be told before any ANSI is emitted.
    if !win::console::enable_virtual_terminal() {
        // Not a console, or VT is unavailable. The style resolver already refuses to
        // style a non-TTY, so nothing else is needed here.
    }

    let style = resolve_style(&opts);

    if !win::is_elevated() && !opts.no_elevate {
        println!(
            "{}",
            style.bright("Not running as Administrator: the Security log, Prefetch and")
        );
        println!(
            "{}",
            style.bright("some service metadata will be missing from the report.")
        );
        println!("Requesting an elevated copy - confirm the UAC prompt.");
        if win::elevate::relaunch_elevated(&Options::relaunch_args(&args)) {
            return ExitCode::SUCCESS;
        }
        println!("Elevation was refused; continuing with reduced coverage.");
        println!();
    }

    if opts.self_test {
        return ExitCode::from(self_test(&opts, &style));
    }

    let started = Instant::now();
    let (ctx, collector_failures) = scan(&opts, &style);
    let verdict = rules::verdict(&ctx.findings, ctx.warnings.len());
    let host = host_info();

    let view = ui::render_console(&style, &host, &ctx, &verdict);
    print!("{view}");
    println!(
        "  {}",
        style.dim(&format!(
            "scan completed in {} ms",
            started.elapsed().as_millis()
        ))
    );

    // The file is always plain: it is the artefact that gets copied, hashed, diffed
    // and pasted into a ticket, so it must not depend on a terminal.
    let text = report::render_text(&host, &ctx, &verdict);
    let json = report::render_json(&host, &ctx, &verdict);

    match write_outputs(&opts, &host, &text, &json) {
        Ok(path) => {
            if let Some(path) = path {
                println!();
                println!(
                    "{}",
                    style.bright(&format!("Report written to: {}", path.display()))
                );
                println!(
                    "{}",
                    style
                        .dim("Copy it to external media before changing anything on this machine.")
                );
            }
            if collector_failures > 0 {
                println!(
                    "{}",
                    style.bright(&format!(
                        "NOTE: {collector_failures} collector(s) failed. The report lists them \
                         under WARNINGS, and it is incomplete."
                    ))
                );
            }
        }
        Err(e) => {
            eprintln!("irscan: {e}");
            return ExitCode::from(1);
        }
    }

    if opts.watch_seconds > 0 {
        watch_connections(opts.watch_seconds, &ctx, &style);
    }

    if should_pause(args.is_empty(), std::io::stdout().is_terminal()) {
        pause_before_exit();
    }

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_defaults_to_a_full_interactive_scan() {
        let o = Options::parse(&args(&[])).unwrap_or_default();
        assert!(!o.quick);
        assert!(!o.self_test);
        assert_eq!(o.watch_seconds, 0);
        assert_eq!(o.json_path, None);
        assert!(!o.no_yara);
        assert!(!o.plain);
        assert!(!o.severity_colour);
    }

    #[test]
    fn parse_reads_every_documented_flag() {
        let o = Options::parse(&args(&[
            "--quick",
            "--self-test",
            "--no-elevate",
            "--plain",
            "--ascii",
            "--severity-colour",
            "--quiet",
            "--no-yara",
            "--width",
            "120",
            "--out",
            "D:\\tmp",
            "--json",
            "D:\\tmp\\r.json",
            "--watch",
            "90",
        ]))
        .unwrap_or_default();
        assert!(o.quick);
        assert!(o.self_test);
        assert!(o.no_elevate);
        assert!(o.plain);
        assert!(o.ascii);
        assert!(o.severity_colour);
        assert!(o.quiet);
        assert!(o.no_yara);
        assert_eq!(o.width, Some(120));
        assert_eq!(o.out_dir.as_deref(), Some("D:\\tmp"));
        assert_eq!(o.json_path.as_deref(), Some("D:\\tmp\\r.json"));
        assert_eq!(o.watch_seconds, 90);
    }

    #[test]
    fn parse_splits_a_comma_separated_rule_list_and_ignores_empty_parts() {
        let o =
            Options::parse(&args(&["--yara-rules", "a.yar, b.yar ,, c.yar"])).unwrap_or_default();
        let names: Vec<String> = o
            .yara_rules
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        assert_eq!(names, vec!["a.yar", "b.yar", "c.yar"]);
    }

    #[test]
    fn parse_rejects_unknown_flags_and_missing_values() {
        assert!(Options::parse(&args(&["--nope"])).is_err());
        assert!(Options::parse(&args(&["--json"])).is_err());
        assert!(Options::parse(&args(&["--out"])).is_err());
        assert!(Options::parse(&args(&["--watch"])).is_err());
        assert!(Options::parse(&args(&["--watch", "soon"])).is_err());
        assert!(Options::parse(&args(&["--width"])).is_err());
        assert!(Options::parse(&args(&["--width", "wide"])).is_err());
        assert!(Options::parse(&args(&["--yara-rules"])).is_err());
    }

    #[test]
    fn relaunch_args_drop_no_elevate_so_the_child_does_not_loop() {
        let with = args(&["--quick", "--no-elevate", "--json", "x.json"]);
        let out = Options::relaunch_args(&with);
        assert!(!out.iter().any(|a| a == "--no-elevate"));
        assert!(out.contains(&"--quick".to_string()));
        assert!(out.contains(&"x.json".to_string()));
    }

    #[test]
    fn plain_beats_style_when_both_are_given() {
        let opts = Options {
            plain: true,
            force_style: true,
            ..Options::default()
        };
        assert!(!resolve_style(&opts).colour);
    }

    #[test]
    fn width_override_is_clamped_to_something_readable() {
        let narrow = Options {
            width: Some(10),
            ..Options::default()
        };
        assert_eq!(resolve_style(&narrow).width, ui::MIN_WIDTH);
        let wide = Options {
            width: Some(10_000),
            ..Options::default()
        };
        assert_eq!(resolve_style(&wide).width, 200);
    }

    #[test]
    fn ascii_flag_switches_the_glyph_set() {
        let opts = Options {
            ascii: true,
            ..Options::default()
        };
        assert!(!resolve_style(&opts).unicode);
    }

    #[test]
    fn epoch_conversion_matches_published_values() {
        assert_eq!(epoch_to_datetime(0), "1970-01-01 00:00:00");
        assert_eq!(epoch_to_datetime(1), "1970-01-01 00:00:01");
        assert_eq!(epoch_to_datetime(86_399), "1970-01-01 23:59:59");
        assert_eq!(epoch_to_datetime(946_684_800), "2000-01-01 00:00:00");
        assert_eq!(epoch_to_datetime(1_000_000_000), "2001-09-09 01:46:40");
        // A leap day, which is where naive implementations break.
        assert_eq!(epoch_to_datetime(951_782_400), "2000-02-29 00:00:00");
    }

    #[test]
    fn endpoint_address_handles_ipv4_ipv6_and_junk() {
        assert_eq!(endpoint_address("1.2.3.4:443"), "1.2.3.4");
        assert_eq!(endpoint_address("[::1]:3389"), "::1");
        assert_eq!(endpoint_address("*:*"), "*");
        assert_eq!(endpoint_address(""), "");
        assert_eq!(endpoint_address("noport"), "noport");
    }

    #[test]
    fn the_pause_happens_only_for_a_double_click() {
        // Double-click: no arguments, a console. The report must not vanish with the
        // window.
        assert!(should_pause(true, true));
        // An explicit run with flags never waits, so scripts and pipes keep working.
        assert!(!should_pause(false, true));
        // Redirected output is not a human watching a window.
        assert!(!should_pause(true, false));
        assert!(!should_pause(false, false));
    }

    #[test]
    fn report_stem_is_a_safe_filename() {
        let host = HostInfo {
            name: "PC-01".into(),
            collected_at: "2026-09-11 12:34:56".into(),
            ..Default::default()
        };
        let stem = report_stem(&host);
        assert_eq!(stem, "irscan-PC-01-2026-09-11_12-34-56");
        assert!(!stem.contains(':'));
        assert!(!stem.contains(' '));
    }

    #[test]
    fn report_stem_survives_an_unknown_hostname() {
        assert!(report_stem(&HostInfo::default()).starts_with("irscan-host-"));
    }

    #[test]
    fn every_collector_name_is_unique() {
        // Duplicate names would make the self-test output ambiguous and the WARNINGS
        // section unable to say which check failed.
        let collectors = build_collectors(&Options::default());
        let mut names: Vec<&str> = collectors.iter().map(|c| c.name()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "duplicate collector name in {names:?}");
        assert!(
            before >= 14,
            "expected the full collector set, got {before}"
        );
    }

    #[test]
    fn disabling_the_content_scan_removes_exactly_one_collector() {
        let with = build_collectors(&Options::default());
        let without = build_collectors(&Options {
            no_yara: true,
            ..Options::default()
        });
        assert_eq!(without.len() + 1, with.len());
        assert!(!without.iter().any(|c| c.name() == "yara"));
        assert!(with.iter().any(|c| c.name() == "yara"));
    }

    #[test]
    fn quick_flag_reaches_the_filesystem_collector_without_changing_names() {
        let quick = build_collectors(&Options {
            quick: true,
            ..Options::default()
        });
        let slow = build_collectors(&Options::default());
        let a: Vec<&str> = quick.iter().map(|c| c.name()).collect();
        let b: Vec<&str> = slow.iter().map(|c| c.name()).collect();
        assert_eq!(a, b);
    }

    #[test]
    fn yara_runs_last_because_it_consumes_what_the_others_found() {
        let collectors = build_collectors(&Options::default());
        assert_eq!(collectors.last().map(|c| c.name()), Some("yara"));
    }
}
