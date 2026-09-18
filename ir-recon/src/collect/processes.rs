//! Process enumeration: the baseline observation of the whole scan.
//!
//! FR-2 requires the process table (pid, parent, image path, command line, owner,
//! start time, signature trust). FR-13 and FR-14 classify it: execution from a
//! user-writable location, an unsigned image, a masquerading system-binary name, or
//! a fresh image inside `System32` where Windows Update does not drop new files.
//!
//! The table is also the join key for every later collector: a TCP endpoint carries
//! a pid, and a pid is only useful once a name, owner and image path hang off it.
//! That is why the records go into [`crate::model::ScanContext::processes`] even
//! when nothing about them is suspicious.
//!
//! Enumeration is done with `sysinfo` (pure Rust, no FFI, per SR-6). The Win32
//! signature and company lookups live behind `crate::win::sig`, which is the only
//! place allowed to touch `unsafe`. Everything this module emits is sanitised and
//! length-capped, because every string here originates from the host under test and
//! is therefore untrusted (SR-2).

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sysinfo::{System, Users};

use crate::collect::services::location_label;
use crate::collect::{CollectError, Collector};
use crate::model::{Finding, HaystackKind, ProcessRecord, ScanContext, Severity, MAX_STRING};
use crate::rules::{classify_location, execution_severity, looks_masquerading, Location};
use crate::text::sanitize;
use crate::win::sig::{company_name, is_signature_trusted};

/// Hard cap on the process table. A hostile or instrumented host can expose an
/// absurd pid count; the report has to stay bounded and diffable.
pub const MAX_PROCESSES: usize = 8192;

/// Command lines are the longest per-process string and the least interesting
/// beyond their head; cap separately so one runaway argv cannot bloat the report.
const MAX_CMDLINE: usize = MAX_STRING;

/// A freshly created image is the signature of a drop. 90 days is deliberately
/// generous: the point is to catch "this binary appeared around the time the
/// symptoms started", not to date a patch.
const RECENT_DAYS: u64 = 90;

const SECS_PER_DAY: u64 = 86_400;

/// Names that the Windows kernel exposes as processes but that have no image on
/// disk. Finding one of these with no image path is normal and must not be
/// reported; anything else with no image path is hiding.
const KERNEL_PSEUDO_PROCESSES: &[&str] = &[
    "[System Process]",
    "System",
    "Registry",
    "Memory Compression",
    "Secure System",
    "Idle",
];

/// How a signature state reads in English. Written out rather than as a boolean so
/// a human reading the report can tell "unsigned" from "signed by <vendor>".
pub fn trust_label(trusted: Option<bool>) -> &'static str {
    match trusted {
        Some(true) => "подписан доверенным издателем",
        Some(false) => "неподписанный или недоверенная подпись",
        None => "подпись не проверена",
    }
}

/// Is this one of the kernel's pseudo-processes, which legitimately have no image?
pub fn is_kernel_pseudo_process(name: &str) -> bool {
    let name = name.trim();
    KERNEL_PSEUDO_PROCESSES
        .iter()
        .any(|k| name.eq_ignore_ascii_case(k))
}

/// Was `created_secs_since_epoch` within the last `within_days`?
///
/// `None` (the API exposed no creation time, or the file could not be stat'ed) is
/// **not** recent: absence of evidence must not become a finding. A timestamp in
/// the future is clock skew or a forged timestamp, and is likewise not treated as
/// recent rather than blowing up on the subtraction.
pub fn is_recently_created(
    created_secs_since_epoch: Option<u64>,
    now_secs: u64,
    within_days: u64,
) -> bool {
    let Some(created) = created_secs_since_epoch else {
        return false;
    };
    if created > now_secs {
        return false;
    }
    let Some(window) = within_days.checked_mul(SECS_PER_DAY) else {
        return false;
    };
    now_secs - created <= window
}

/// Does `path` sit under `<system_root>\System32`?
///
/// Used for the "fresh binary inside System32" rule. The trailing separator in the
/// prefix matters: without it `C:\Windows\System32evil` would match.
pub fn is_under_system32(path: &str, system_root: &str) -> bool {
    if path.trim().is_empty() || system_root.trim().is_empty() {
        return false;
    }
    let p = path.replace('/', "\\").to_lowercase();
    let root = system_root.replace('/', "\\").to_lowercase();
    let prefix = format!("{}\\system32\\", root.trim_end_matches('\\'));
    p.starts_with(&prefix)
}

/// One stable, readable line per process for the RAW DATA appendix.
///
/// Stable field order and `<none>` placeholders (rather than omitting fields) so
/// two scans of an unchanged host diff cleanly.
pub fn describe(p: &ProcessRecord) -> String {
    let name = if p.name.is_empty() {
        "<none>"
    } else {
        p.name.as_str()
    };
    let path = match p.path.as_deref() {
        Some(v) if !v.as_os_str().is_empty() => v.to_string_lossy().into_owned(),
        _ => "<none>".to_string(),
    };
    let cmd = if p.cmdline.is_empty() {
        "<none>"
    } else {
        p.cmdline.as_str()
    };
    let owner = if p.owner.is_empty() {
        "<unknown>"
    } else {
        p.owner.as_str()
    };
    let started = match p.started {
        Some(s) => s.to_string(),
        None => "<unknown>".to_string(),
    };
    let company = p.company.as_deref().unwrap_or("<unknown>");
    format!(
        "pid={} ppid={} name={} path={} cmd={} owner={} started={} signature={} company={}",
        p.pid,
        p.ppid,
        name,
        path,
        cmd,
        owner,
        started,
        trust_label(p.signature_trusted),
        company
    )
}

/// The evidence block attached to any process finding.
///
/// `trusted` and `location` are passed in rather than read from `p` so the caller
/// can hand over the values it actually used in the rule decision, and so the
/// function is testable without a Windows host.
pub fn evidence_lines(p: &ProcessRecord, trusted: Option<bool>, location: Location) -> Vec<String> {
    let name = if p.name.is_empty() {
        "<none>"
    } else {
        p.name.as_str()
    };
    let path = match p.path.as_deref() {
        Some(v) if !v.as_os_str().is_empty() => v.to_string_lossy().into_owned(),
        _ => "<не указан>".to_string(),
    };
    let owner = if p.owner.is_empty() {
        "<unknown>"
    } else {
        p.owner.as_str()
    };
    let started = match p.started {
        Some(s) => s.to_string(),
        None => "<unknown>".to_string(),
    };
    let cmd = if p.cmdline.is_empty() {
        "<empty>"
    } else {
        p.cmdline.as_str()
    };
    let company = p.company.as_deref().unwrap_or("<unknown>");
    vec![
        format!(
            "идентификатор процесса: {} ({}) родительский процесс: {}",
            p.pid, name, p.ppid
        ),
        format!("путь к файлу: {}", path),
        format!("подпись: {}", trust_label(trusted)),
        format!("издатель: {}", company),
        format!("расположение: {}", location_label(location)),
        format!("учётная запись: {}", owner),
        format!("запущен (секунды эпохи): {}", started),
        format!("командная строка: {}", cmd),
    ]
}

/// Enumerates running processes into the context.
pub struct ProcessesCollector;

impl Collector for ProcessesCollector {
    fn name(&self) -> &'static str {
        "processes"
    }

    fn run(&self, ctx: &mut ScanContext) -> Result<(), CollectError> {
        let sys = System::new_all();
        let users = Users::new_with_refreshed_list();
        let system_root = crate::win::system_root();
        let now = now_secs();
        // Whether this scan can read a protected process at all. An unreadable image
        // path on a non-elevated scan is a privilege limit, not evidence; the same
        // path on an *elevated* scan is the process actively withholding it.
        let elevated = crate::win::is_elevated();

        // Sort by pid so an unchanged host produces a byte-identical RAW DATA
        // section; HashMap iteration order is not stable across runs.
        let mut entries: Vec<&sysinfo::Process> = sys.processes().values().collect();
        entries.sort_by_key(|p| p.pid().as_u32());

        if entries.is_empty() {
            ctx.warn("перечисление процессов не вернуло ни одного процесса");
            return Ok(());
        }
        if entries.len() > MAX_PROCESSES {
            ctx.warn(format!(
                "перечисление процессов вернуло {} записей; проверены только первые {}",
                entries.len(),
                MAX_PROCESSES
            ));
        }

        let mut table: Vec<String> = Vec::with_capacity(entries.len().min(MAX_PROCESSES));
        let mut owners_unresolved: usize = 0;
        // Processes whose image path could not be read. Collected here so the whole
        // set becomes ONE finding at the end rather than one finding per process -
        // on a stock non-elevated host this is ~180 rows of the same observation.
        let mut unreadable: Vec<Unreadable> = Vec::new();

        for process in entries.iter().take(MAX_PROCESSES) {
            let pid = process.pid().as_u32();
            let ppid = process.parent().map(|p| p.as_u32()).unwrap_or(0);
            let name = sanitize(&process.name().to_string_lossy(), MAX_STRING);
            // Keep the raw path for the Win32 calls (stat / WinVerifyTrust must see
            // the real bytes); store only the sanitised form in the record.
            let raw_path = process.exe().map(|e| e.to_string_lossy().into_owned());
            let path = raw_path.as_deref().map(|p| sanitize(p, MAX_STRING));
            let cmdline = sanitize(&command_line(process), MAX_CMDLINE);
            let owner = match process.user_id() {
                Some(uid) => {
                    let name = owner_name(&users, uid);
                    if name == "<не определена>" {
                        owners_unresolved += 1;
                    }
                    name
                }
                None => String::new(),
            };
            // 0 means "unknown" for sysinfo's start time, not 1970.
            let started = match process.start_time() {
                0 => None,
                s => Some(s),
            };
            let (trusted, company) = match raw_path.as_deref() {
                Some(p) => {
                    let p = Path::new(p);
                    (is_signature_trusted(p), company_name(p))
                }
                None => (None, None),
            };

            let record = ProcessRecord {
                pid,
                ppid,
                name: name.clone(),
                path: path.clone().map(PathBuf::from),
                cmdline: cmdline.clone(),
                owner: owner.clone(),
                started,
                signature_trusted: trusted,
                company: company.clone(),
            };

            let origin = format!("process {} (pid {})", display_name(&name), pid);
            ctx.note(HaystackKind::ProcessName, name.clone(), origin.clone());
            if let Some(p) = path.as_deref() {
                ctx.note(HaystackKind::Path, p, origin.clone());
            }
            ctx.note(HaystackKind::CommandLine, cmdline.clone(), origin);

            let created = raw_path
                .as_deref()
                .and_then(|p| creation_secs(Path::new(p)));
            let recent = is_recently_created(created, now, RECENT_DAYS);

            if let Some(entry) = classify(
                ctx,
                &record,
                path.as_deref().unwrap_or(""),
                path.is_some(),
                &system_root,
                recent,
                created,
            ) {
                unreadable.push(entry);
            }

            table.push(describe(&record));
            ctx.processes.insert(pid, record);
        }

        report_unreadable_paths(ctx, &unreadable, elevated);

        if owners_unresolved > 0 {
            ctx.warn(format!(
                "не удалось определить учётную запись-владельца для {owners_unresolved} процесс(ов)"
            ));
        }

        ctx.raw_section("PROCESSES", table);
        Ok(())
    }
}

/// One process whose image path could not be read.
#[derive(Debug, Clone)]
struct Unreadable {
    pid: u32,
    name: String,
    owner: String,
}

/// Emit the single aggregated finding for unreadable image paths.
///
/// On a non-elevated scan an unreadable path is an artefact of privilege, so the
/// finding is **Info** and says so in its own evidence. When the scan *is* elevated
/// the process still refused to name its image, which is concealment rather than a
/// permission limit, and it stays **Med** - the one case where this observation is
/// worth an analyst's attention.
fn report_unreadable_paths(ctx: &mut ScanContext, unreadable: &[Unreadable], elevated: bool) {
    if unreadable.is_empty() {
        return;
    }
    let count = unreadable.len();

    // Distinct names, in order, so the evidence reads as a list of processes rather
    // than a wall of pid rows. Bounded to keep the line readable.
    let mut names: Vec<&str> = Vec::new();
    for entry in unreadable {
        let name = display_name(&entry.name);
        if names.contains(&name) {
            continue;
        }
        names.push(name);
    }
    let shown = names.len().min(20);
    let mut name_list = names[..shown].join(", ");
    if names.len() > shown {
        name_list.push_str(&format!(", и ещё {}", names.len() - shown));
    }

    let (severity, title, note) = if elevated {
        (
            Severity::Med,
            format!(
                "Не читается путь к файлу у {count} процесс(ов), хотя проверка выполняется с \
                 правами администратора"
            ),
            "Проверка выполняется с правами администратора и всё равно не может открыть эти \
             файлы, поэтому доступ запрещает сам файл, а не недостаток прав.",
        )
    } else {
        (
            Severity::Info,
            format!(
                "Не читается путь к файлу у {count} процесс(ов) \
                 (проверка без прав администратора)"
            ),
            "Это ограничение прав, а не попытка скрыться: защищённые процессы и процессы \
             SYSTEM не отдают путь к файлу тому, кто читает их без прав администратора. \
             Запустите проверку с правами администратора, чтобы это выяснить.",
        )
    };

    let mut finding = Finding::new(severity, "process", title)
        .evidence(format!("затронуто процессов: {count}"))
        .evidence(format!("имена: {name_list}"))
        .evidence(format!(
            "учётная запись: {}",
            if unreadable[0].owner.is_empty() {
                "<неизвестно>"
            } else {
                unreadable[0].owner.as_str()
            }
        ))
        .evidence(format!(
            "идентификатор процесса (первый): {}",
            unreadable[0].pid
        ))
        .evidence(format!("проверка с правами администратора: {elevated}"))
        .evidence(format!("примечание: {note}"))
        .remediation(
            "Запустите проверку с правами администратора: большинство из них окажутся \
             штатными системными файлами, как только у программы появится доступ к ним.",
        );
    if elevated {
        finding = finding.remediation(
            "Если путь остаётся скрытым и при проверке с правами администратора, считайте \
             файл подозрительным: штатный двоичный файл Windows не скрывает собственный \
             путь от администратора.",
        );
    }
    ctx.add(finding);
}

/// Apply the FR-13 / FR-14 policy to one process and push anything it warrants.
///
/// Kept separate from the enumeration loop so the rule block is readable and so
/// severity always comes from [`crate::rules`] rather than being picked here.
///
/// `path_observed` is `false` when the image path could not be read at all - which
/// is the normal case for protected (PPL) and SYSTEM processes when the scan is not
/// elevated, and applies to roughly a fifth of the process table on a stock Windows
/// host. That distinction is load-bearing: an *unreadable* path is missing data, and
/// missing data must never become a High finding. Concretely, `svchost.exe` with no
/// readable path is the real `System32\svchost.exe`, so treating "no path" as
/// masquerading would flag every core Windows process as a RAT and make the report
/// worthless. Only a path that was actually read and lies outside `%SystemRoot%`
/// is evidence of masquerading.
///
/// Returns the process's [`Unreadable`] entry when its path could not be read, for
/// the caller to aggregate; everything else is pushed directly. Nothing but an
/// aggregate is emitted for the unreadable case, because one finding per process
/// turned 183 of them loose on a clean host.
fn classify(
    ctx: &mut ScanContext,
    p: &ProcessRecord,
    path: &str,
    path_observed: bool,
    system_root: &str,
    recent: bool,
    created: Option<u64>,
) -> Option<Unreadable> {
    let trusted = p.signature_trusted;
    // `Location`, not the coarse boolean: a binary in application data is where
    // per-user software lives, so it must not carry the same weight as one in a
    // transit directory. `rules::execution_severity` owns the resulting severity.
    let location = classify_location(path);
    let user_writable = location != crate::rules::Location::Privileged;
    let masquerading = path_observed && looks_masquerading(&p.name, path, system_root);
    let name_disp = display_name(&p.name);

    // FR-13: weak provenance. `rules::execution_severity` owns the base severity;
    // the escalation below is the spec's "drop window" signal on top of it. It
    // requires a *transit* directory: an unsigned binary that appeared last week
    // under `%LOCALAPPDATA%` is a normal per-user install, and treating it as a drop
    // produced 21 false Highs on a clean developer machine.
    let escalated = trusted == Some(false) && location == crate::rules::Location::Drop && recent;
    // A *fresh, unsigned* image inside System32 is the classic hand-placed payload.
    // Freshness alone is not evidence: Windows Update rewrites System32 binaries on
    // every cumulative patch, so a legitimately signed `svchost.exe` with a recent
    // creation time is a patch artefact, not a drop. Requiring `trusted == Some(false)`
    // is what separates the two; without it this rule flags ~90 stock Windows processes
    // on a freshly patched host.
    let system32_recent = recent && is_under_system32(path, system_root) && trusted == Some(false);

    let mut severity = execution_severity(trusted, location);
    if escalated || system32_recent {
        severity = Some(Severity::High);
    }

    if let Some(sev) = severity {
        let title = if escalated {
            format!(
                "Процесс {} (pid {}) не подписан и недавно создан в каталоге для временных файлов",
                name_disp, p.pid
            )
        } else if system32_recent {
            format!(
                "Процесс {} (pid {}) — неподписанный, недавно созданный образ внутри System32",
                name_disp, p.pid
            )
        } else if user_writable && trusted == Some(false) {
            format!(
                "Процесс {} (pid {}) не подписан и запущен из каталога данных приложений",
                name_disp, p.pid
            )
        } else if user_writable {
            format!(
                "Процесс {} (pid {}) запущен из каталога данных приложений",
                name_disp, p.pid
            )
        } else {
            format!(
                "Процесс {} (pid {}) не имеет действительной подписи",
                name_disp, p.pid
            )
        };

        let mut finding = Finding::new(sev, "process", title);
        for line in evidence_lines(p, trusted, location) {
            finding = finding.evidence(line);
        }
        if let Some(c) = created {
            finding = finding.evidence(format!(
                "файл образа создан в момент эпохи {} ({} сут. назад)",
                c,
                now_secs().saturating_sub(c) / SECS_PER_DAY
            ));
        }
        ctx.add(
            finding
                .remediation(
                    "Снимите хеш файла (SHA-256) и запишите путь; не запускайте его, чтобы \
                     'проверить'.",
                )
                .remediation(
                    "Если это не установленное вами программное обеспечение, удалите его и \
                     переустановите систему с внешнего носителя.",
                ),
        );
    }

    // FR-14: a system-binary name outside %SystemRoot%, or with the path hidden,
    // has no legitimate use. Returns early so this process is not *also* counted as
    // an unreadable path - the masquerade is the stronger, more specific statement.
    if masquerading {
        ctx.add(
            Finding::new(
                Severity::High,
                "process",
                format!(
                    "Процесс {} (pid {}) выдаёт себя за системный процесс Windows",
                    name_disp, p.pid
                ),
            )
            .evidence(format!(
                "путь к файлу: {}",
                if path.is_empty() {
                    "<не указан>"
                } else {
                    path
                }
            ))
            .evidence(format!("подпись: {}", trust_label(trusted)))
            .evidence(format!(
                "издатель: {}",
                p.company.as_deref().unwrap_or("<неизвестно>")
            ))
            .evidence(format!(
                "ожидаемое расположение: {}\\System32\\{}",
                system_root.trim_end_matches('\\'),
                p.name
            ))
            .remediation(
                "Имя системного процесса вне %SystemRoot% не бывает законным; считайте файл \
                 враждебным.",
            )
            .remediation(
                "Сохраните сам файл и его хеш до удаления, затем переустановите систему с \
                 внешнего носителя.",
            ),
        );
        return None;
    }

    // An image path that could not be read cannot be verified either way, and is
    // reported by the caller as ONE aggregate rather than one finding per process.
    // The kernel pseudo-processes have no image by design and are excluded here.
    let observed = path_observed || is_kernel_pseudo_process(&p.name);
    if observed {
        return None;
    }
    Some(Unreadable {
        pid: p.pid,
        name: p.name.clone(),
        owner: p.owner.clone(),
    })
}

/// Account name that owns `uid`, resolved against the loaded user list.
///
/// `Users::get_user_by_id` compares `Uid` values, and on Windows `Uid` wraps
/// `sysinfo`'s SID type, whose `PartialEq` is derived over the raw SID bytes
/// (`sysinfo::common::xid!` -> `#[derive(PartialEq, Eq, Hash)]` over
/// `windows::Sid { sid: Vec<u8> }`). `Users` builds its SIDs from `NetUserGetInfo`
/// level 23 while `Process::user_id` comes from the process token, and the two
/// paths can produce byte-different SIDs for the same account - so the built-in
/// lookup silently fails and the report loses the owner, which is exactly the
/// field that tells "a service is doing this" from "a user is doing this".
///
/// The reliable key is the account name each `User` already carries. Formatted
/// SIDs are the fallback only when no name matches; they never *override* a name.
fn owner_name(users: &Users, uid: &sysinfo::Uid) -> String {
    if let Some(u) = users.list().iter().find(|u| u.id() == uid) {
        let name = u.name().trim();
        if !name.is_empty() {
            return sanitize(name, MAX_STRING);
        }
    }
    // A failure to resolve an owner is a real gap in the evidence: say so rather
    // than emitting an empty field that reads like "no owner".
    String::from("<не определена>")
}

/// Join an argv without lossy-allocating per argument more than once.
fn command_line(p: &sysinfo::Process) -> String {
    let mut out = String::new();
    for arg in p.cmd() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&arg.to_string_lossy());
    }
    out
}

/// Display placeholder for an empty image name, used in finding titles.
fn display_name(name: &str) -> &str {
    if name.is_empty() {
        "<без имени>"
    } else {
        name
    }
}

/// Creation time of the image, in seconds since the Unix epoch, when available.
fn creation_secs(path: &Path) -> Option<u64> {
    let meta = std::fs::metadata(path).ok()?;
    meta.created()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(pid: u32, name: &str, path: Option<&str>) -> ProcessRecord {
        ProcessRecord {
            pid,
            ppid: 4,
            name: name.to_string(),
            path: path.map(PathBuf::from),
            cmdline: String::new(),
            owner: String::new(),
            started: None,
            signature_trusted: None,
            company: None,
        }
    }

    #[test]
    fn kernel_pseudo_process_truth_table() {
        assert!(is_kernel_pseudo_process("System"));
        assert!(is_kernel_pseudo_process("Registry"));
        assert!(is_kernel_pseudo_process("Memory Compression"));
        assert!(is_kernel_pseudo_process("Secure System"));
        assert!(is_kernel_pseudo_process("Idle"));
        // Case and surrounding whitespace must not defeat the exclusion.
        assert!(is_kernel_pseudo_process("  SYSTEM "));
        assert!(is_kernel_pseudo_process("memory compression"));
        // Negatives: a lookalike is not the real pseudo-process.
        assert!(!is_kernel_pseudo_process("System Idle Process"));
        assert!(!is_kernel_pseudo_process("svchost.exe"));
        assert!(!is_kernel_pseudo_process(""));
        assert!(!is_kernel_pseudo_process("registrys"));
    }

    #[test]
    fn recently_created_window_boundaries() {
        const DAY: u64 = 86_400;
        // Exactly 90 days old is still inside the window; one second older is not.
        assert!(is_recently_created(Some(1_000), 1_000 + 90 * DAY, 90));
        assert!(!is_recently_created(Some(1_000), 1_000 + 90 * DAY + 1, 90));
        // Created one second ago is recent.
        assert!(is_recently_created(Some(1_000), 1_001, 90));
        // No timestamp (or unreadable file) is never recent.
        assert!(!is_recently_created(None, 1_000 + DAY, 90));
        // A timestamp in the future is clock skew, not a drop.
        assert!(!is_recently_created(Some(2_000_000), 1_000, 90));
        // Absurd input must not panic (overflowing day window).
        assert!(!is_recently_created(Some(0), u64::MAX, u64::MAX));
        // A zero-day window only matches exactly now.
        assert!(is_recently_created(Some(1_000), 1_000, 0));
        assert!(!is_recently_created(Some(999), 1_000, 0));
    }

    #[test]
    fn system32_prefix_requires_a_separator() {
        assert!(is_under_system32(
            r"C:\Windows\System32\evil.exe",
            r"C:\Windows"
        ));
        assert!(is_under_system32(
            r"C:\Windows\System32\drivers\evil.sys",
            r"C:\Windows"
        ));
        assert!(is_under_system32(
            "c:/windows/system32/Evil.exe",
            "C:\\Windows"
        ));
        assert!(!is_under_system32(
            r"C:\Windows\System32evil\evil.exe",
            r"C:\Windows"
        ));
        assert!(!is_under_system32(
            r"C:\Windows\SysWOW64\evil.dll",
            r"C:\Windows"
        ));
        assert!(!is_under_system32(r"C:\Windows\System32", r"C:\Windows"));
        assert!(!is_under_system32("", r"C:\Windows"));
        assert!(!is_under_system32(r"C:\Windows\System32\evil.exe", ""));
    }

    #[test]
    fn describe_is_stable_and_identifies_the_process() {
        let mut p = rec(
            4321,
            "agent.exe",
            Some(r"C:\Users\bob\AppData\Local\agent.exe"),
        );
        p.cmdline = "--install".to_string();
        p.owner = "HOST\\bob".to_string();
        p.started = Some(1_700_000_000);
        p.signature_trusted = Some(false);
        p.company = Some("Unknown Vendor".to_string());

        let d = describe(&p);
        assert_eq!(d, describe(&p), "describe must be deterministic");
        assert!(d.contains("pid=4321"));
        assert!(d.contains("name=agent.exe"));
        assert!(d.contains("agent.exe"));
        assert!(d.contains("--install"));
        // Long/missing content must still render a line rather than vanish.
        let empty = describe(&rec(0, "", None));
        assert!(empty.contains("pid=0"));
        assert!(empty.contains("name=<none>"));
        assert!(empty.contains("path=<none>"));
    }

    #[test]
    fn evidence_lines_states_trust_in_words() {
        let p = rec(900, "tool.exe", Some(r"C:\Users\bob\tool.exe"));

        let unsigned = evidence_lines(&p, Some(false), Location::AppData);
        assert!(unsigned.iter().any(|l| l.contains("недоверенная подпись")));
        assert!(unsigned
            .iter()
            .any(|l| l.contains("каталог данных приложений")));

        let signed = evidence_lines(&p, Some(true), Location::Privileged);
        assert!(signed
            .iter()
            .any(|l| l.contains("подписан доверенным издателем")));
        assert!(!signed.iter().any(|l| l.contains("недоверенная")));

        let unknown = evidence_lines(&p, None, Location::Privileged);
        assert!(unknown.iter().any(|l| l.contains("подпись не проверена")));
        assert!(unknown.iter().any(|l| l.contains("tool.exe")));
    }

    /// The regression that matters most: on a non-elevated Windows host about a
    /// fifth of processes report no image path, including the genuine
    /// `System32\svchost.exe` and every other protected system binary. Treating an
    /// unreadable path as masquerading would emit a High finding for each one, so the
    /// collector must only classify masquerading when the path was actually read.
    #[test]
    fn unreadable_path_is_not_evidence_of_masquerading() {
        // rules::looks_masquerading deliberately treats an empty path as a match -
        // that is the module's contract, and it is exactly why the collector must not
        // call it on a path it never observed.
        assert!(looks_masquerading("svchost.exe", "", r"C:\Windows"));

        // The gate the collector applies: an unobserved path disables the branch
        // regardless of what the rule function would have said.
        let p = rec(996, "svchost.exe", None);
        let observed_path = p
            .path
            .as_deref()
            .map(|v| v.to_string_lossy().into_owned())
            .unwrap_or_default();
        let path_observed = p.path.is_some();
        let would_masquerade =
            path_observed && looks_masquerading(&p.name, &observed_path, r"C:\Windows");
        assert!(
            !would_masquerade,
            "an unreadable path must never be flagged as masquerading"
        );

        // A path that WAS read and lies outside SystemRoot is the real masquerade.
        let fake = rec(1234, "svchost.exe", Some(r"C:\Users\bob\svchost.exe"));
        assert!(looks_masquerading(
            &fake.name,
            &fake
                .path
                .as_deref()
                .map(|v| v.to_string_lossy().into_owned())
                .unwrap_or_default(),
            r"C:\Windows"
        ));
    }

    /// A fresh file inside System32 is a *patch*, not a drop, unless it is unsigned.
    /// Windows Update rewrites these binaries every cumulative update, so freshness
    /// alone flagged ~90 stock Windows processes on a patched host - all false.
    #[test]
    fn recent_system32_binary_is_only_suspicious_when_unsigned() {
        let signed_patch = rec(
            1496,
            "svchost.exe",
            Some(r"C:\Windows\System32\svchost.exe"),
        );
        let unsigned_drop = rec(
            6666,
            "payload.exe",
            Some(r"C:\Windows\System32\payload.exe"),
        );

        // The predicate the collector uses, isolated from signature verification so it
        // can be exercised on any host.
        let suspicious = |p: &ProcessRecord, trusted: Option<bool>, recent: bool| {
            recent
                && is_under_system32(
                    &p.path
                        .as_deref()
                        .map(|v| v.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    r"C:\Windows",
                )
                && trusted == Some(false)
        };

        assert!(
            !suspicious(&signed_patch, Some(true), true),
            "a signed, freshly patched System32 binary must not be reported"
        );
        assert!(
            suspicious(&unsigned_drop, Some(false), true),
            "an unsigned fresh binary inside System32 is the real signal"
        );
        // Unverifiable signature is not enough to accuse either.
        assert!(!suspicious(&unsigned_drop, None, true));
        // An old unsigned binary in System32 is not a drop either.
        assert!(!suspicious(&unsigned_drop, Some(false), false));
    }

    #[test]
    fn kernel_pseudo_processes_cover_pid_zero() {
        // sysinfo reports the kernel's pid-0 row under this bracketed name; it has no
        // image by design and must not be reported as hiding one.
        assert!(is_kernel_pseudo_process("[System Process]"));
        assert!(!is_kernel_pseudo_process("[system process"));
    }

    #[test]
    fn malformed_records_do_not_panic() {
        // Empty everything, including the pid-0 style row sysinfo reports.
        let blank = rec(0, "", None);
        assert!(describe(&blank).contains("pid=0"));
        let lines = evidence_lines(&blank, None, Location::Privileged);
        assert!(!lines.is_empty());
        assert!(lines.iter().any(|l| l.contains("<не указан>")));

        // An empty path string is treated as "reported nothing", and a system-binary
        // name with no path is the masquerade case rules::looks_masquerading owns.
        assert!(looks_masquerading("svchost.exe", "", r"C:\Windows"));
        assert!(!is_kernel_pseudo_process(""));
        assert_eq!(trust_label(None), "подпись не проверена");

        // Paths that are pure noise must classify, not panic.
        assert!(!crate::rules::is_user_writable(""));
        assert!(!is_under_system32("\\\\?\\", ""));
    }

    /// The rule that generated 21 false Highs: an unsigned binary in application
    /// data is a normal per-user install. Execution severity must key off
    /// `Location`, not the coarse "is it user-writable" boolean.
    #[test]
    fn unsigned_binary_severity_follows_the_location_not_user_writability() {
        // Six agents' worth of dev tooling on this very machine.
        let appdata = r"C:\Users\bob\AppData\Local\uv\cache\archive\Scripts\a.exe";
        let choco = r"C:\ProgramData\chocolatey\tools\a.exe";
        let temp = r"C:\Users\bob\AppData\Local\Temp\a.exe";

        let appdata_loc = classify_location(appdata);
        let choco_loc = classify_location(choco);
        let temp_loc = classify_location(temp);

        // All three report as "user-writable", which is why the boolean was the bug.
        assert!(crate::rules::is_user_writable(appdata));
        assert!(crate::rules::is_user_writable(choco));
        assert!(crate::rules::is_user_writable(temp));

        // But only the transit directory is High.
        assert_eq!(
            execution_severity(Some(false), temp_loc),
            Some(Severity::High)
        );
        // Application data is at most Info - never Med, never High.
        assert_eq!(
            execution_severity(Some(false), appdata_loc),
            Some(Severity::Info)
        );
        assert_eq!(
            execution_severity(Some(false), choco_loc),
            Some(Severity::Info)
        );
        // Signed or unverifiable in application data is nothing at all.
        assert_eq!(execution_severity(Some(true), appdata_loc), None);
        assert_eq!(execution_severity(None, choco_loc), None);
    }

    /// The "drop window" escalation is only allowed in a transit directory. An
    /// unsigned binary that appeared last week under %LOCALAPPDATA% must not be
    /// promoted to High.
    #[test]
    fn recent_and_unsigned_only_escalates_in_a_transit_directory() {
        let escalated = |path: &str, trusted: Option<bool>, recent: bool| {
            trusted == Some(false)
                && classify_location(path) == crate::rules::Location::Drop
                && recent
        };
        assert!(escalated(
            r"C:\Users\bob\AppData\Local\Temp\a.exe",
            Some(false),
            true
        ));
        assert!(!escalated(
            r"C:\Users\bob\AppData\Local\omp\omp.exe",
            Some(false),
            true
        ));
        assert!(!escalated(
            r"C:\ProgramData\chocolatey\tools\a.exe",
            Some(false),
            true
        ));
        // Not recent, not unsigned: no escalation either way.
        assert!(!escalated(
            r"C:\Users\bob\AppData\Local\Temp\a.exe",
            Some(false),
            false
        ));
        assert!(!escalated(
            r"C:\Users\bob\AppData\Local\Temp\a.exe",
            None,
            true
        ));
    }

    /// The 183-finding regression: many unreadable paths become ONE finding. On a
    /// non-elevated scan that finding is Info, because a privilege limit is not
    /// evidence; on an elevated scan concealment stays Med.
    #[test]
    fn unreadable_paths_are_one_aggregate_finding() {
        let mut ctx = ScanContext::default();
        let entries = vec![
            Unreadable {
                pid: 996,
                name: "svchost.exe".into(),
                owner: "SYSTEM".into(),
            },
            Unreadable {
                pid: 1300,
                name: "winlogon.exe".into(),
                owner: "SYSTEM".into(),
            },
            Unreadable {
                pid: 996,
                name: "svchost.exe".into(),
                owner: "SYSTEM".into(),
            },
        ];

        report_unreadable_paths(&mut ctx, &entries, false);
        assert_eq!(ctx.findings.len(), 1, "one finding, not one per process");
        let f = &ctx.findings[0];
        assert_eq!(f.severity, Severity::Info);
        assert!(f.title.contains('3'), "title was: {}", f.title);
        assert!(f.evidence.iter().any(|l| l == "затронуто процессов: 3"));
        // Distinct names in evidence, not a pid-per-line wall.
        let names = f
            .evidence
            .iter()
            .find(|l| l.starts_with("имена: "))
            .cloned()
            .unwrap_or_default();
        assert!(names.contains("svchost.exe"), "names was: {names}");
        assert!(names.contains("winlogon.exe"), "names was: {names}");

        // Elevated: the same observation is concealment, so it stays Med.
        let mut elevated_ctx = ScanContext::default();
        report_unreadable_paths(&mut elevated_ctx, &entries, true);
        assert_eq!(elevated_ctx.findings.len(), 1);
        assert_eq!(elevated_ctx.findings[0].severity, Severity::Med);

        // Nothing to report when nothing was unreadable.
        let mut empty = ScanContext::default();
        report_unreadable_paths(&mut empty, &[], false);
        assert!(empty.findings.is_empty());
    }
}
