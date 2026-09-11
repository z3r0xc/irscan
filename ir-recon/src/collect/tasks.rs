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

/// Action directories malware uses to drop payloads (FR-13). A scheduled task that
/// runs from here is worth a High finding even when the binary is not obviously bad.
const SUSPICIOUS_ACTION_MARKERS: &[&str] = &["\\temp\\", "\\appdata\\", "\\programdata\\"];

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
                format!("task store not found: {}", root.display()),
            ));
        }

        let mut files: Vec<(String, PathBuf)> = Vec::new();
        walk_tasks(&root, "", 0, &mut files, ctx);
        if files.len() >= MAX_TASKS {
            ctx.warn(format!(
                "tasks: stopped after {} task definitions",
                MAX_TASKS
            ));
        }

        let mut lines: Vec<String> = Vec::new();
        for (name, file) in files {
            let Some(xml) = read_task_file(&file) else {
                ctx.warn(format!(
                    "tasks: unreadable or oversized definition: {}",
                    file.display()
                ));
                continue;
            };
            let Some(mut record) = parse_task_xml(&name, &xml) else {
                ctx.warn(format!("tasks: not a task definition: {}", file.display()));
                continue;
            };
            record.path = sanitize(&file.display().to_string(), MAX_STRING);

            lines.push(describe_task(&record));
            ctx.note(
                HaystackKind::TaskName,
                record.name.clone(),
                "scheduled task",
            );
            for action in record.action.split(" ;; ") {
                if let Some(exe) = task_action_executable(action) {
                    ctx.note(
                        HaystackKind::Path,
                        exe,
                        format!("task action: {}", record.name),
                    );
                }
            }
            if let Some(finding) = classify_task(&record) {
                ctx.add(finding);
            }
            ctx.tasks.push(record);
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
pub fn is_hidden_task(record: &TaskRecord) -> bool {
    record.hidden
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

/// Does this task action run from a temporary or per-user data directory?
pub fn action_is_suspicious(action: &str) -> bool {
    let lower = action.replace('/', "\\").to_ascii_lowercase();
    SUSPICIOUS_ACTION_MARKERS.iter().any(|m| lower.contains(m))
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
        ctx.warn(format!("tasks: cannot read {}", dir.display()));
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

/// Decide the single finding (if any) a task deserves, strongest condition first.
fn classify_task(record: &TaskRecord) -> Option<Finding> {
    let exe = task_action_executable(&record.action).unwrap_or_default();
    let exe_expanded = crate::win::expand(&exe);
    let safe_exe = sanitize(&exe_expanded, MAX_STRING);
    let safe_action = sanitize(&crate::win::expand(&record.action), MAX_STRING);

    // Most decisive first: the persistence entry outliving its payload is the
    // shape of an agent that deleted itself after use.
    if is_drive_path(&exe_expanded) && !Path::new(&exe_expanded).exists() {
        return Some(
            Finding::new(
                Severity::High,
                "scheduled-task",
                "Scheduled task points at an executable that no longer exists",
            )
            .evidence(format!("task: {}", record.name))
            .evidence(format!("expected image: {safe_exe}"))
            .evidence(format!("action: {}", record.action))
            .remediation(
                "A task whose payload has been deleted is a common self-cleaning pattern: \
                 the persistence entry survives the binary that did the work.",
            )
            .remediation("Check the task's history and delete it if it is not yours."),
        );
    }

    if action_is_suspicious(&crate::win::expand(&record.action)) {
        return Some(
            Finding::new(
                Severity::High,
                "scheduled-task",
                "Scheduled task runs from %TEMP%, AppData or ProgramData",
            )
            .evidence(format!("task: {}", record.name))
            .evidence(format!("action: {safe_action}"))
            .remediation(
                "Legitimate software installs into Program Files; per-user data directories \
                 are where dropped payloads live.",
            )
            .remediation("Inspect the file and the task's author before deleting the task."),
        );
    }

    if crate::rules::is_user_writable(&safe_exe) {
        return Some(
            Finding::new(
                Severity::High,
                "scheduled-task",
                "Scheduled task executes from a user-writable location",
            )
            .evidence(format!("task: {}", record.name))
            .evidence(format!("image: {safe_exe}"))
            .remediation(
                "A task that runs an executable from a user-writable directory can be \
                 replaced by any process running as that user (FR-13).",
            )
            .remediation("Verify the file's signature and publisher before trusting the task."),
        );
    }

    if is_hidden_task(record) {
        return Some(
            Finding::new(Severity::Med, "scheduled-task", "Hidden scheduled task")
                .evidence(format!("task: {}", record.name))
                .evidence(format!("action: {safe_action}"))
                .remediation(
                    "Hidden tasks are not shown by Task Scheduler's UI. They are used by some \
                 legitimate updaters, but also by monitoring agents that want to stay unseen.",
                )
                .remediation("Delete the task if neither the action nor the author is recognised."),
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

    #[test]
    fn suspicious_action_locations_are_flagged() {
        assert!(action_is_suspicious(
            r"C:\Users\bob\AppData\Local\Temp\a.exe"
        ));
        assert!(action_is_suspicious(r"C:\ProgramData\Acme\a.exe"));
        assert!(!action_is_suspicious(r"C:\Program Files\Vendor\svc.exe"));
        // An unexpanded %TEMP% is not a path yet and must not be assumed.
        assert!(!action_is_suspicious(r"%TEMP%\a.exe"));
        assert!(is_drive_path(r"C:\a.exe"));
        assert!(!is_drive_path(r"%TEMP%\a.exe"));
        assert!(!is_drive_path("a.exe"));
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
