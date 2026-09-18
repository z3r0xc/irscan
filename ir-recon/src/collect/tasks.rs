//! Scheduled-task persistence collector (FR-4, FR-13, FR-14).
//!
//! `%SystemRoot%\System32\Tasks` is a directory tree that mirrors the Task
//! Scheduler namespace: one XML file per task, one subdirectory per task folder.
//! The files are read directly instead of through the Task Scheduler API because a
//! task whose `Hidden` element is true is invisible in the GUI - which is exactly
//! the case this collector exists to surface.
//!
//! The parser is a string scanner, not an XML parser: no XML crate is available in
//! the shipped binary, and the input is attacker-influenced, so a tolerant scanner
//! that returns `None` on junk beats a strict parser that could be coerced into
//! allocating or recursing. All scanning is bounded by the input string itself, so
//! a hostile file cannot stall the scan.

use std::ops::Not;
use std::path::{Path, PathBuf};

use crate::collect::{CollectError, Collector};
use crate::model::{Finding, HaystackKind, ScanContext, Severity, TaskRecord, MAX_STRING};
use crate::text::sanitize;

/// Deepest task-folder nesting followed below `...\System32\Tasks`.
pub const MAX_TASK_DEPTH: usize = 8;
/// Hard cap on the number of task definitions read in one scan.
pub const MAX_TASKS: usize = 8000;
/// Largest file still considered a task definition; real ones are a few KiB.
pub const MAX_TASK_XML_BYTES: u64 = 256 * 1024;

/// Extensions that mean "this action runs a program", used to find the end of an
/// unquoted executable path.
const EXECUTABLE_EXTENSIONS: &[&str] = &[
    ".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".scr", ".msi",
];

/// Reads `%SystemRoot%\System32\Tasks` and reports what it finds.
///
/// Findings are emitted per task, not per problem, so a single task cannot flood
/// the report with four near-identical lines: the most decisive condition wins.
pub struct TasksCollector;

impl Collector for TasksCollector {
    fn name(&self) -> &'static str {
        "tasks"
    }

    fn run(&self, ctx: &mut ScanContext) -> Result<(), CollectError> {
        let root = PathBuf::from(format!("{}\\System32\\Tasks", crate::win::system_root()));
        if !root.is_dir() {
            return Err(CollectError::new(
                "tasks",
                format!("хранилище задач не найдено: {}", root.display()),
            ));
        }

        let mut files: Vec<(String, PathBuf)> = Vec::new();
        walk_tasks(&root, "", 0, &mut files, ctx);
        if files.len() >= MAX_TASKS {
            ctx.warn(format!(
                "задачи: перебор остановлен после {} определений задач",
                MAX_TASKS
            ));
        }

        let mut lines: Vec<String> = Vec::new();
        for (name, file) in files {
            let Some(xml) = read_task_file(&file) else {
                ctx.warn(format!(
                    "задачи: определение не читается или слишком велико: {}",
                    file.display()
                ));
                continue;
            };
            let Some(mut record) = parse_task_xml(&name, &xml) else {
                ctx.warn(format!(
                    "задачи: это не определение задачи: {}",
                    file.display()
                ));
                continue;
            };
            record.path = sanitize(&file.display().to_string(), MAX_STRING);

            lines.push(describe_task(&record));
            ctx.note(
                HaystackKind::TaskName,
                record.name.clone(),
                "задача планировщика",
            );
            for action in record.action.split(" ;; ") {
                if let Some(exe) = task_action_executable(action) {
                    ctx.note(
                        HaystackKind::Path,
                        exe,
                        format!("команда задачи: {}", record.name),
                    );
                }
            }
            if let Some(finding) = classify_task(&record) {
                ctx.add(finding);
            }
            ctx.tasks.push(record);
        }

        if lines.is_empty() {
            // The store exists but nothing was read from it, which is what happens without
            // elevation. Saying so here keeps "no tasks" and "could not look" apart.
            lines.push(
                "ни одно определение задачи не прочитано; без повышенных прав хранилище \
                 задач недоступно, так что это не доказывает отсутствие задач"
                    .to_string(),
            );
        }
        ctx.raw_section("SCHEDULED TASKS", lines);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Pure parsing (unit-tested without Windows)
// ---------------------------------------------------------------------------

/// Parse a Task Scheduler XML definition. `task_name` is the full task path with a
/// leading backslash. Returns None only when the document is not a task definition.
///
/// `TaskRecord::path` is left empty here: it is the on-disk XML file path, which
/// only the collector can know. Everything else in the record comes from the XML.
pub fn parse_task_xml(task_name: &str, xml: &str) -> Option<crate::model::TaskRecord> {
    if !looks_like_task_document(xml) {
        return None;
    }

    // Author lives in RegistrationInfo; Hidden and Enabled live in Settings.
    // Scoping is deliberate: `Enabled` also appears inside every trigger, and the
    // first one in document order is not the task's own enable flag.
    let registration = element_blocks(xml, "RegistrationInfo")
        .into_iter()
        .next()
        .unwrap_or(xml);
    let settings = element_blocks(xml, "Settings")
        .into_iter()
        .next()
        .unwrap_or(xml);

    let author = element_text(registration, "Author").unwrap_or_default();
    let hidden = element_text(settings, "Hidden")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    // Absent means enabled; only an explicit `false` disables.
    let enabled = element_text(settings, "Enabled")
        .map(|v| !v.eq_ignore_ascii_case("false"))
        .unwrap_or(true);
    let action = extract_actions(xml);

    Some(TaskRecord {
        name: sanitize(task_name, MAX_STRING),
        path: String::new(),
        state: if enabled {
            "Enabled".to_string()
        } else {
            "Disabled".to_string()
        },
        author: sanitize(&author, MAX_STRING),
        action: sanitize(&action, MAX_STRING),
        hidden,
        enabled,
    })
}

/// A task is hidden when its `Hidden` element is true. Task Scheduler's own UI does
/// not show such a task, which is precisely why the report calls it out.
///
/// Windows hides a large number of its own tasks this way - `.NET Framework NGEN`,
/// the AppX deployment cleanup, `UsbCeip`, the Data Integrity scans, well over fifty on
/// a stock install - and every one of them is ordinary. Reporting them lifts the count
/// of a healthy machine into the nineties, which is the failure mode this whole report
/// exists to avoid: a reader who sees sixty "hidden task" lines stops reading them, and
/// the one hidden task that *was* planted goes past with the rest.
///
/// A task under `\Microsoft\` is Microsoft's own namespace. Windows installs and
/// owns it; a third party writing a persistence entry there is not the shape of the
/// threat - the shape is a hidden task in a neutral or vendor path, which is what this
/// now reports. The Microsoft tasks are still collected and still listed under RAW
/// DATA, so nothing is hidden from the operator, only unalarmed.
pub fn is_hidden_task(record: &TaskRecord) -> bool {
    record.hidden && !is_microsoft_namespace(&record.name)
}

/// Does the task's path sit in Microsoft's own namespace?
///
/// `\Microsoft\...` and a bare `\Microsoft` are both Microsoft's. The check is on
/// the leading component only, so a task named `\MicrosoftFake\x` - which would be
/// the whole point of picking a lookalike name - is NOT treated as Microsoft's.
fn is_microsoft_namespace(name: &str) -> bool {
    let trimmed = name.strip_prefix('\\').unwrap_or(name);
    match trimmed.split_once('\\') {
        Some((first, _)) => first.eq_ignore_ascii_case("Microsoft"),
        None => trimmed.eq_ignore_ascii_case("Microsoft"),
    }
}

/// The executable a task action runs, with any argument tail removed.
///
/// Actions are free-form command lines: `"C:\Program Files\A\a.exe" -x` and
/// `C:\a.exe /y` are both valid. Nothing here is executed, only classified, so the
/// cost of a wrong guess is a mis-classified file name, never an execution.
pub fn task_action_executable(action: &str) -> Option<String> {
    let trimmed = action.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(rest) = trimmed.strip_prefix('"') {
        // Quoted: the closing quote is the end of the path, spaces included.
        let end = rest.find('"')?;
        let exe = rest[..end].trim();
        return if exe.is_empty() {
            None
        } else {
            Some(exe.to_string())
        };
    }

    // Unquoted: Windows allows a path with spaces, so take the shortest
    // whitespace-delimited prefix that ends in a program extension.
    for (idx, ch) in trimmed.char_indices() {
        if ch.is_whitespace() {
            let candidate = &trimmed[..idx];
            if has_executable_extension(candidate) {
                return Some(candidate.to_string());
            }
        }
    }
    if has_executable_extension(trimmed) {
        return Some(trimmed.to_string());
    }
    // Nothing looked like a program; return the leading token so a bare command
    // name is still classified rather than silently dropped.
    trimmed.split_whitespace().next().map(str::to_string)
}

/// A fully qualified drive path (`C:\...`).
///
/// Used to decide whether "the executable is missing" is meaningful: a path that
/// still contains an unexpanded `%VAR%`, or that is only a bare file name, has not
/// been resolved yet and must not be reported as a deleted payload.
pub fn is_drive_path(path: &str) -> bool {
    let b = path.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')
}

fn has_executable_extension(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    EXECUTABLE_EXTENSIONS.iter().any(|e| lower.ends_with(e))
}

/// Join every `<Command>` (plus its `<Arguments>`) from the `<Actions>` section.
///
/// Multiple `Exec` actions become one string separated by `" ;; "`, which is
/// unusual enough that it cannot collide with a real command line.
fn extract_actions(xml: &str) -> String {
    let actions = element_blocks(xml, "Actions");
    let scope = actions.into_iter().next().unwrap_or(xml);
    let execs = element_blocks(scope, "Exec");
    let sources: Vec<&str> = if execs.is_empty() { vec![scope] } else { execs };

    let mut parts: Vec<String> = Vec::new();
    for source in sources {
        let Some(command) = element_text(source, "Command") else {
            continue;
        };
        let mut line = command.trim().to_string();
        if let Some(args) = element_text(source, "Arguments") {
            let args = args.trim();
            if !args.is_empty() {
                line.push(' ');
                line.push_str(args);
            }
        }
        if !line.is_empty() {
            parts.push(line);
        }
    }
    parts.join(" ;; ")
}

/// A document is a task definition when its root element is `<Task>` and a matching
/// `</Task>` exists. Truncated files - a half-written drop, or a deliberately
/// broken one - fail here and are rejected rather than reported with a partial
/// action.
fn looks_like_task_document(xml: &str) -> bool {
    let Some(root) = next_tag(xml, 0) else {
        return false;
    };
    if root.local != "Task" || root.closing || root.self_closing {
        return false;
    }
    let mut from = root.end;
    while let Some(tag) = next_tag(xml, from) {
        from = tag.end;
        if tag.closing && tag.local == "Task" {
            return true;
        }
    }
    false
}

/// Inner text of the first `<local>` element, with nested tags stripped.
fn element_text(xml: &str, local: &str) -> Option<String> {
    let block = element_blocks(xml, local).into_iter().next()?;
    let text = strip_tags(block);
    let text = text.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

/// Inner content of every `<local>` element, in document order.
fn element_blocks<'a>(xml: &'a str, local: &str) -> Vec<&'a str> {
    let mut out: Vec<&str> = Vec::new();
    let mut from = 0usize;
    while let Some(tag) = next_tag(xml, from) {
        from = tag.end;
        if tag.closing || tag.self_closing || tag.local != local {
            continue;
        }
        let content_start = tag.end;
        let mut scan = content_start;
        let mut content_end = None;
        while let Some(inner) = next_tag(xml, scan) {
            scan = inner.end;
            if inner.closing && inner.local == local {
                content_end = Some(inner.start);
                break;
            }
        }
        let Some(content_end) = content_end else {
            // Unterminated element: stop rather than treat the rest of the document
            // as its content.
            break;
        };
        out.push(&xml[content_start..content_end]);
        from = scan;
    }
    out
}

/// Drop every `<...>` segment, keeping the text between them.
fn strip_tags(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for ch in s.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            c if !in_tag => out.push(c),
            _ => {}
        }
    }
    out
}

/// One XML tag, reduced to what this module needs.
struct Tag<'a> {
    /// Local name with any namespace prefix stripped (`task:Command` -> `Command`).
    local: &'a str,
    closing: bool,
    self_closing: bool,
    /// Index of the tag's `<`.
    start: usize,
    /// Index one past the tag's `>`.
    end: usize,
}

/// Scan for the next tag at or after `from`.
///
/// Returns `None` at end of input and on an unterminated tag, which is how a
/// truncated document fails without ever indexing out of bounds.
fn next_tag(xml: &str, from: usize) -> Option<Tag<'_>> {
    let bytes = xml.as_bytes();
    let mut i = from;
    while i < bytes.len() {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        if xml[i..].starts_with("<!--") {
            {
                let k = xml[i..].find("-->")?;
                i = i + k + 3;
                continue;
            }
        }
        if xml[i..].starts_with("<?") {
            {
                let k = xml[i..].find("?>")?;
                i = i + k + 2;
                continue;
            }
        }
        if xml[i..].starts_with("<!") {
            {
                let k = xml[i..].find('>')?;
                i = i + k + 1;
                continue;
            }
        }

        let mut j = i + 1;
        let closing = j < bytes.len() && bytes[j] == b'/';
        if closing {
            j += 1;
        }
        let first = j;
        while j < bytes.len() && is_name_byte(bytes[j]) {
            j += 1;
        }
        if j == first {
            // A bare `<` that starts no tag; keep looking.
            i += 1;
            continue;
        }
        let gt = {
            let k = xml[j..].find('>')?;
            j + k
        };
        let name = &xml[first..j];
        let self_closing = xml[i + 1..gt].trim_end().ends_with('/');
        let local = match name.rfind(':') {
            Some(p) => &name[p + 1..],
            None => name,
        };
        return Some(Tag {
            local,
            closing,
            self_closing,
            start: i,
            end: gt + 1,
        });
    }
    None
}

fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.' || b == b':'
}

// ---------------------------------------------------------------------------
// Host access
// ---------------------------------------------------------------------------

/// Walk the task store, producing `(task name, file path)` pairs.
///
/// Reparse points are skipped so a junction planted in a task folder cannot lead
/// the walk out of its root (FR-21 / SR-3).
fn walk_tasks(
    dir: &Path,
    rel: &str,
    depth: usize,
    out: &mut Vec<(String, PathBuf)>,
    ctx: &mut ScanContext,
) {
    if depth >= MAX_TASK_DEPTH || out.len() >= MAX_TASKS {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        ctx.warn(format!("задачи: не удалось прочитать {}", dir.display()));
        return;
    };
    for entry in entries.flatten() {
        if out.len() >= MAX_TASKS {
            return;
        }
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if crate::win::is_reparse_point(&meta) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let child_rel = if rel.is_empty() {
            name
        } else {
            format!("{rel}\\{name}")
        };
        if meta.is_dir() {
            walk_tasks(&entry.path(), &child_rel, depth + 1, out, ctx);
        } else if meta.is_file() {
            out.push((format!("\\{child_rel}"), entry.path()));
        }
    }
}

/// Read a task definition, refusing anything too large to be one.
fn read_task_file(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_TASK_XML_BYTES {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    Some(decode_task_xml(&bytes))
}

/// Decode a task definition.
///
/// Task Scheduler writes them as UTF-16LE with a BOM; hand-written or third-party
/// files may be UTF-8. Both are decoded lossily - never panicking - because a
/// malformed byte must not cost the whole scan.
pub fn decode_task_xml(bytes: &[u8]) -> String {
    if let Some(body) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        crate::win::from_utf16_bytes(body)
    } else if let Some(body) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        let mut units: Vec<u16> = Vec::with_capacity(body.len() / 2);
        for chunk in body.chunks_exact(2) {
            units.push(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        crate::win::from_wide(&units)
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

/// Severity for one task action, from its location and signature.
///
/// The shared location policy is the base, with one deliberate escalation: an action
/// in a transit directory stays High even when the file is gone or its signature looks
/// valid. The task is what re-runs a dropped payload, and `%TEMP%`, `Downloads` and
/// `Users\Public` are directories nothing installs to. `trusted` is `None` when the
/// file is absent and the signature check cannot run.
fn task_action_severity(trusted: Option<bool>, exe: &str) -> Option<Severity> {
    let location = crate::rules::classify_location(exe);
    if location == crate::rules::Location::Drop {
        return Some(Severity::High);
    }
    crate::rules::execution_severity(trusted, location)
}

/// Is this a fully qualified drive path whose file is gone?
///
/// Only then does "the payload was deleted" mean anything: a path that still contains
/// an unexpanded `%VAR%`, or a bare file name, has not been resolved yet and must not
/// be reported as a deleted payload.
///
/// A path whose own directory names a superseded build is excluded too. Product
/// updaters that install into a versioned directory - OneDrive is the common one -
/// leave their scheduled task pointing at the build they were running when it was
/// written, and the next update deletes that directory. The task then outlives its
/// file for a reason that has nothing to do with an intruder, and reporting it as
/// "the payload deleted itself" puts a HIGH finding on an ordinary update. It is
/// still reported, at its location and signature, by the caller.
fn missing_drive_payload(exe: &str) -> bool {
    if !is_drive_path(exe) || superseded_by_versioned_install(exe) {
        return false;
    }
    match Path::new(exe).try_exists() {
        Ok(present) => present.not(),
        // Unreadable (permissions, a disconnected drive): report nothing, because
        // "cannot tell" must not be presented as "deleted".
        Err(_) => false,
    }
}

/// Does the file sit in a `...\<name>\<version>\file.exe` directory whose version
/// component is a dotted number, and does a sibling directory of the same product
/// hold the same file name under a different version?
///
/// The check has to see the replacement, not just the shape: a dropped payload in
/// `%LOCALAPPDATA%\SomeAgent\1.2.3\agent.exe` has the same shape as an updated
/// OneDrive, and only the presence of a newer sibling tells them apart. Requiring
/// three numeric components keeps `...\1.2\x.exe` - a far more plausible drop path -
/// out of it.
fn superseded_by_versioned_install(exe: &str) -> bool {
    let path = Path::new(exe);
    let Some(version_dir) = path.parent() else {
        return false;
    };
    let (Some(vendor_dir), Some(version), Some(file)) = (
        version_dir.parent(),
        version_dir.file_name().and_then(|s| s.to_str()),
        path.file_name(),
    ) else {
        return false;
    };
    if !is_dotted_version(version) {
        return false;
    }
    let Ok(siblings) = std::fs::read_dir(vendor_dir) else {
        return false;
    };
    siblings.flatten().any(|entry| {
        entry.file_name() != version_dir.file_name().unwrap_or_default()
            && entry.path().join(file).try_exists().unwrap_or(false)
    })
}

/// A version directory such as `26.129.0706.0004`: at least three dot-separated parts,
/// every one of them digits.
fn is_dotted_version(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() >= 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// Decide the single finding (if any) a task deserves, strongest condition first.
fn classify_task(record: &TaskRecord) -> Option<Finding> {
    let exe = task_action_executable(&record.action).unwrap_or_default();
    let exe_expanded = crate::win::expand(&exe);
    let safe_exe = sanitize(&exe_expanded, MAX_STRING);
    let safe_action = sanitize(&crate::win::expand(&record.action), MAX_STRING);

    // Most decisive first: the persistence entry outliving its payload is the
    // shape of an agent that deleted itself after use. Only a fully qualified drive
    // path is checked; an unexpanded `%VAR%` has not been resolved yet.
    //
    // Microsoft's own tasks are exempt from this one too. `\Microsoft\Windows\
    // UpdateOrchestrator\USO_UxBroker` points at `MusNotification.exe`, which a
    // Windows component-removal or an update can delete while the task stays behind;
    // measured on the author's host, that put a HIGH "the executable no longer
    // exists" finding on a stock Windows task. The file's absence is real, its
    // meaning is not: a task Microsoft installed and Microsoft left dangling is not
    // evidence of an intruder, and a HIGH finding that a reader learns to ignore
    // costs more than the finding is worth. It stays visible under RAW DATA.
    if !is_microsoft_namespace(&record.name) && missing_drive_payload(&exe_expanded) {
        return Some(
            Finding::new(
                Severity::High,
                "scheduled-task",
                "Задача планировщика указывает на исполняемый файл, которого больше нет",
            )
            .evidence(format!("задача: {}", record.name))
            .evidence(format!("ожидаемый файл: {safe_exe}"))
            .evidence(format!("команда: {}", record.action))
            .remediation(
                "Задача, чей файл уже удалён, — обычный признак самоочистки: запись \
                 автозапуска переживает двоичный файл, который выполнял работу.",
            )
            .remediation("Проверьте журнал этой задачи и удалите её, если она не ваша."),
        );
    }

    // The location - and the signature, when there is a file to check - decide,
    // through the shared policy. A task pointing at a path that is gone because it
    // deleted itself is still classified for its location, with the signature unknown.
    let location = crate::rules::classify_location(&safe_exe);
    let trusted = if Path::new(&safe_exe).is_file() {
        crate::win::sig::is_signature_trusted(Path::new(&safe_exe))
    } else {
        None
    };
    if let Some(severity) = task_action_severity(trusted, &safe_exe) {
        let label = crate::collect::services::location_label(location);
        let title = format!("Задача планировщика запускается из {label}");
        return Some(
            Finding::new(severity, "scheduled-task", title)
                .evidence(format!("задача: {}", record.name))
                .evidence(format!("команда: {safe_action}"))
                .evidence(format!("путь к файлу: {safe_exe}"))
                .remediation(
                    "Задачу, запускающую файл из каталога для временных файлов или из каталога, \
                     куда может писать пользователь, может подменить любой процесс этого \
                     пользователя (FR-13).",
                )
                .remediation("Проверьте подпись и издателя файла, прежде чем доверять задаче."),
        );
    }

    if is_hidden_task(record) {
        return Some(
            Finding::new(
                Severity::Med,
                "scheduled-task",
                "Скрытая задача планировщика",
            )
            .evidence(format!("задача: {}", record.name))
            .evidence(format!("команда: {safe_action}"))
            .evidence(format!("автор: {}", record.author))
            .remediation(
                "Скрытые задачи не показывает интерфейс планировщика. Ими пользуются \
                     некоторые легальные средства обновления, но и агенты слежения, \
                     которые хотят остаться незамеченными.",
            )
            .remediation("Удалите задачу, если ни её команда, ни её автор вам не знакомы."),
        );
    }

    None
}

fn describe_task(r: &TaskRecord) -> String {
    format!(
        "{} | {} | hidden={} | author={} | action={}",
        r.name, r.state, r.hidden, r.author, r.action
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic definition: namespace, attributes on the root and on `Actions`,
    /// a trigger-level `<Enabled>` that must NOT be mistaken for the task's own,
    /// and a quoted command with arguments.
    const TASK_XML: &str = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2025-01-02T03:04:05</Date>
    <Author>CONTOSO\bob</Author>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>false</Enabled>
    </LogonTrigger>
  </Triggers>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <Hidden>true</Hidden>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>"C:\ProgramData\Acme\agent.exe"</Command>
      <Arguments>--quiet --server 12.34.56.78:443</Arguments>
    </Exec>
  </Actions>
</Task>"#;

    const PLAIN_XML: &str = r#"<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>NT AUTHORITY\SYSTEM</Author></RegistrationInfo>
  <Actions><Exec><Command>C:\Windows\System32\cmd.exe</Command><Arguments>/c echo hi</Arguments></Exec></Actions>
</Task>"#;

    const NS_XML: &str = r#"<t:Task xmlns:t="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <t:RegistrationInfo><t:Author>CONTOSO\bob</t:Author></t:RegistrationInfo>
  <t:Settings><t:Hidden>true</t:Hidden><t:Enabled>false</t:Enabled></t:Settings>
  <t:Actions Context="Author"><t:Exec><t:Command>C:\x\a.exe</t:Command></t:Exec></t:Actions>
</t:Task>"#;

    #[test]
    fn realistic_definition_parses_author_hidden_and_command() {
        let record = parse_task_xml("\\Acme Agent", TASK_XML);
        assert_eq!(
            record.as_ref().map(|r| r.author.as_str()),
            Some("CONTOSO\\bob")
        );
        assert_eq!(record.as_ref().map(is_hidden_task), Some(true));
        assert_eq!(record.as_ref().map(|r| r.enabled), Some(true));
        assert_eq!(
            record.as_ref().map(|r| r.action.as_str()),
            Some("\"C:\\ProgramData\\Acme\\agent.exe\" --quiet --server 12.34.56.78:443")
        );
        assert_eq!(
            record.as_ref().map(|r| r.name.as_str()),
            Some("\\Acme Agent")
        );
    }

    #[test]
    fn missing_hidden_element_means_not_hidden_and_enabled() {
        let record = parse_task_xml("\\Plain", PLAIN_XML);
        assert_eq!(record.as_ref().map(|r| r.hidden), Some(false));
        assert_eq!(record.as_ref().map(|r| r.enabled), Some(true));
        assert_eq!(
            record.as_ref().map(|r| r.action.as_str()),
            Some("C:\\Windows\\System32\\cmd.exe /c echo hi")
        );
    }

    #[test]
    fn namespaced_document_parses_identically_to_unprefixed() {
        let prefixed = parse_task_xml("\\X", NS_XML);
        let plain = parse_task_xml("\\X", &NS_XML.replace("t:", ""));
        assert!(prefixed.is_some());
        assert_eq!(prefixed, plain);
        assert_eq!(prefixed.as_ref().map(|r| r.enabled), Some(false));
    }

    #[test]
    fn multiple_exec_actions_are_joined() {
        const MULTI: &str = "<Task><Actions>\
            <Exec><Command>C:\\a.exe</Command><Arguments>-1</Arguments></Exec>\
            <Exec><Command>C:\\b.exe</Command></Exec>\
            </Actions></Task>";
        assert_eq!(
            parse_task_xml("\\M", MULTI)
                .as_ref()
                .map(|r| r.action.as_str()),
            Some("C:\\a.exe -1 ;; C:\\b.exe")
        );
    }

    #[test]
    fn truncated_or_malformed_documents_return_none() {
        // Truncated mid-element: no closing </Task>.
        assert_eq!(
            parse_task_xml("\\T", "<Task version=\"1.2\"><RegistrationInfo><Author>a"),
            None
        );
        assert_eq!(parse_task_xml("\\T", "<Task><Actions><Exec>"), None);
        assert_eq!(parse_task_xml("\\T", "<<<>>>"), None);
        assert_eq!(parse_task_xml("\\T", ""), None);
        assert_eq!(parse_task_xml("\\T", "<NotATask></NotATask>"), None);
    }

    #[test]
    fn task_action_executable_strips_quotes_and_arguments() {
        assert_eq!(
            task_action_executable("\"C:\\Program Files\\A\\a.exe\" -x").as_deref(),
            Some("C:\\Program Files\\A\\a.exe")
        );
        assert_eq!(
            task_action_executable("C:\\Windows\\System32\\cmd.exe /c echo hi").as_deref(),
            Some("C:\\Windows\\System32\\cmd.exe")
        );
        // Unterminated quote yields nothing rather than a guess.
        assert_eq!(task_action_executable("\"C:\\broken"), None);
        assert_eq!(task_action_executable("   "), None);
    }

    /// A task whose file was removed by a product update is not "a payload that deleted
    /// itself".
    ///
    /// Measured on the author's host: OneDrive's startup task pointed at
    /// `...\Microsoft OneDrive\26.129.0706.0004\OneDriveLauncher.exe` while the
    /// installed builds were 26.153 and 26.158, so the named directory was gone and the
    /// task became a HIGH finding reading "the executable no longer exists". The rule
    /// has to see the *replacement* to fire, otherwise it also whitelists a genuine drop
    /// in a versioned directory.
    #[test]
    fn a_versioned_install_replaced_by_a_newer_one_is_not_a_deleted_payload() {
        let root = std::env::temp_dir().join("irscan-versioned-install-test");
        let vendor = root.join("Microsoft OneDrive");
        let old_dir = vendor.join("26.129.0706.0004");
        let new_dir = vendor.join("26.153.0809.0004");
        std::fs::create_dir_all(&old_dir).expect("old dir");
        std::fs::create_dir_all(&new_dir).expect("new dir");
        // The new build carries the file; the old one's copy is gone, as it is after an update.
        std::fs::write(new_dir.join("OneDriveLauncher.exe"), b"MZ").expect("new build file");

        let gone = old_dir
            .join("OneDriveLauncher.exe")
            .to_string_lossy()
            .into_owned();
        assert!(
            !missing_drive_payload(&gone),
            "a path superseded by a newer build of the same product must not read as deleted"
        );

        // The naming has to be the *same product*, so a versioned directory under a
        // vendor that has no replacement is still reported. This is the shape the rule
        // must not excuse: a drop in `%LOCALAPPDATA%\Vendor\1.2.3\agent.exe` with no
        // second version beside it.
        let lonely_root = root.join("Lonely Vendor");
        let lonely_dir = lonely_root.join("1.2.3");
        std::fs::create_dir_all(&lonely_dir).expect("lonely dir");
        let lonely = lonely_dir.join("agent.exe").to_string_lossy().into_owned();
        assert!(
            missing_drive_payload(&lonely),
            "a versioned path with no replacement must still be reported"
        );

        std::fs::remove_dir_all(&root).ok();
    }

    /// Only a dotted numeric directory counts as a version, so a plausible drop path
    /// such as `...\1.2\payload.exe` is not silently excused.
    /// Windows hides dozens of its own tasks; a report that flags them is unreadable.
    ///
    /// Measured on the author's host: 59 findings, every one a `\\Microsoft\\Windows\\...`
    /// task that Windows itself marks `<Hidden>true</Hidden>` - `.NET Framework NGEN`,
    /// the AppX cleanup, `UsbCeip`, the Data Integrity scans. They are ordinary, and a
    /// reader who sees sixty of them stops reading the list, which is where a planted
    /// one would hide.
    #[test]
    fn windows_own_hidden_tasks_are_not_reported_as_hidden() {
        let task = |name: &str| TaskRecord {
            name: name.to_string(),
            state: String::new(),
            hidden: true,
            enabled: true,
            author: String::new(),
            action: String::new(),
            path: String::new(),
        };

        assert!(!is_hidden_task(&task(
            r"\Microsoft\Windows\.NET Framework\NGEN"
        )));
        assert!(!is_hidden_task(&task(
            r"\Microsoft\Windows\AppxDeploymentClient\UCPD velocity"
        )));
        assert!(!is_hidden_task(&task(r"\Microsoft")));
        assert!(!is_hidden_task(&task(r"\microsoft\anything")));

        // A hidden task anywhere else is exactly what the finding is for.
        assert!(is_hidden_task(&task(r"\SystemUpdate\svc")));
        assert!(is_hidden_task(&task(r"\OneDrive Startup Task")));
        // A lookalike namespace is not Microsoft's - that is the whole point of it.
        assert!(is_hidden_task(&task(r"\MicrosoftFake\x")));
        assert!(is_hidden_task(&task(r"\Microsoft Windows\x")));
    }

    /// A Microsoft task whose payload was removed is not a HIGH finding.
    ///
    /// Measured on the author's host: `\\Microsoft\\Windows\\UpdateOrchestrator\\USO_UxBroker`
    /// points at `MusNotification.exe`, which a Windows component removal had deleted
    /// while the task stayed behind. The file really is gone - the finding was not
    /// wrong about that - but it is a stock Windows task, and a HIGH "the executable
    /// no longer exists" on stock Windows teaches the reader to skip the line that
    /// matters.
    #[test]
    fn a_microsoft_task_with_a_missing_payload_is_not_high() {
        let missing = r"C:\definitely\not\here\payload.exe";
        let record = |name: &str| TaskRecord {
            name: name.to_string(),
            state: "Enabled".to_string(),
            hidden: false,
            enabled: true,
            author: "Microsoft".to_string(),
            action: missing.to_string(),
            path: String::new(),
        };

        let ms = classify_task(&record(
            r"\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker",
        ));
        assert!(
            !matches!(ms, Some(ref f) if f.severity == Severity::High),
            "a Microsoft task must not be reported HIGH for a missing payload, got {ms:?}"
        );

        // The same task outside Microsoft's namespace is exactly the shape the rule
        // exists for, and must stay HIGH.
        let other = classify_task(&record(r"\SystemUpdate\svc"));
        assert!(
            matches!(other, Some(ref f) if f.severity == Severity::High),
            "an identical task outside Microsoft's namespace must still be HIGH"
        );
    }

    #[test]
    fn only_dotted_numeric_directories_are_treated_as_versions() {
        assert!(is_dotted_version("26.129.0706.0004"));
        assert!(is_dotted_version("1.2.3"));
        assert!(
            !is_dotted_version("26.129"),
            "two parts is not enough to be a build dir"
        );
        assert!(!is_dotted_version("1.2"));
        assert!(!is_dotted_version("v1.2.3"));
        assert!(!is_dotted_version("26.129.0706.0004-beta"));
        assert!(!is_dotted_version(""));
        assert!(!is_dotted_version(".."));
    }

    #[test]
    fn drive_path_recognition() {
        assert!(is_drive_path(r"C:\a.exe"));
        assert!(!is_drive_path(r"%TEMP%\a.exe"));
        assert!(!is_drive_path("a.exe"));
    }

    #[test]
    fn task_action_severity_is_high_only_where_nothing_installs() {
        // %TEMP%: the task is what re-runs the dropped payload, so it stays High even
        // when the signature could not be checked.
        assert_eq!(
            task_action_severity(None, r"C:\Users\bob\AppData\Local\Temp\setup.exe"),
            Some(Severity::High)
        );
        assert_eq!(
            task_action_severity(Some(true), r"C:\Users\bob\AppData\Local\Temp\setup.exe"),
            Some(Severity::High)
        );
        // A per-user install directory is where software legitimately lands.
        assert_eq!(
            task_action_severity(Some(false), r"C:\ProgramData\Acme\agent.exe"),
            Some(Severity::Info)
        );
        assert_eq!(
            task_action_severity(None, r"C:\ProgramData\Acme\agent.exe"),
            None
        );
        // Program Files: an unsigned image is worth recording, but no more than that.
        assert_eq!(
            task_action_severity(Some(true), r"C:\Program Files\Vendor\svc.exe"),
            None
        );
        assert_eq!(
            task_action_severity(Some(false), r"C:\Program Files\Vendor\svc.exe"),
            Some(Severity::Info)
        );
    }

    #[test]
    fn a_task_in_a_transit_directory_is_high_even_when_the_image_is_gone() {
        // The file is absent, so no signature can be taken; the location alone must
        // still carry the finding: %TEMP% is a directory nothing installs to.
        let gone_in_temp = parse_task_xml(
            "\\Cleanup",
            "<Task><Actions><Exec><Command>%TEMP%\\t-9999\\agent.exe</Command>\
             </Exec></Actions></Task>",
        )
        .expect("fixture must parse");
        let temp = classify_task(&gone_in_temp).expect("a task in %TEMP% must be reported");
        assert_eq!(temp.severity, Severity::High);
    }

    #[test]
    fn a_task_running_from_application_data_is_not_high() {
        // A present executable under AppData with no signature is at most INFO; a
        // clean machine must not show a High just because per-user software lives
        // there. See `task_action_severity` for the signed and absent combinations.
        // through a path that is present: the report must not carry a High for a
        // per-user install directory, only the Info that says "unsigned, look". The
        // file is staged under %LOCALAPPDATA% (never %TEMP%, which is a transit
        // directory and *is* worth a High).
        let base = std::env::var("LOCALAPPDATA").unwrap_or_default();
        let dir = Path::new(&base).join("irscan-policy-test");
        let exe = dir.join("app.exe");
        std::fs::create_dir_all(&dir).ok();
        std::fs::write(&exe, b"stub").ok();
        let appdata = parse_task_xml(
            "\\Updater",
            &format!(
                "<Task><Actions><Exec><Command>{}</Command></Exec></Actions></Task>",
                exe.display()
            ),
        )
        .expect("fixture must parse");
        let severity = classify_task(&appdata).map(|f| f.severity);
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(severity, Some(Severity::Info));
    }

    #[test]
    fn utf16_definitions_are_decoded() {
        let mut bytes = vec![0xFFu8, 0xFE];
        for unit in "<Task></Task>".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(decode_task_xml(&bytes), "<Task></Task>");
        assert_eq!(decode_task_xml(b"<Task></Task>"), "<Task></Task>");
    }
}
