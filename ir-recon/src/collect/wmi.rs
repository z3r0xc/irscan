//! WMI event-subscription persistence: FR-6.
//!
//! This is the collector for the one persistence mechanism that leaves **no file,
//! no service and no scheduled task** behind. A permanent WMI subscription is three
//! objects in the `ROOT\SUBSCRIPTION` repository:
//!
//! * a `__EventFilter` - the trigger, e.g. "at system startup" or "when process X
//!   starts";
//! * a `CommandLineEventConsumer` or `ActiveScriptEventConsumer` - the payload,
//!   held as a command line or as a script body inside the repository itself;
//! * a `__FilterToConsumerBinding` - the wire between the two.
//!
//! Because the payload is stored in the WMI repository, a scan that only walks the
//! filesystem, the service database and the task folder sees nothing at all. That is
//! why this module exists and why a `__EventFilter` alone is already worth reporting.
//!
//! The severity policy is the readable part:
//!
//! * any consumer - `CommandLineEventConsumer` or `ActiveScriptEventConsumer` - is
//!   **High**. A consumer *executes*: at every boot, or on every matching event. On a
//!   home machine there is no benign reason for one, and the payload text is carried
//!   in the evidence so the user can see exactly what would run.
//! * a `__EventFilter` with no consumer wired to it is **Med**: a dormant trigger,
//!   suspicious but not yet an execution path.
//! * a binding is **Info**: it is evidence of what is wired to what, and its severity
//!   derives from the objects it names, which are reported separately.
//!
//! A query that fails produces a warning, never silence. "WMI could not be checked"
//! and "WMI was checked and is clean" are different statements, and a report that
//! conflates them is worse than no report (spec section 9, honesty).

use crate::collect::{CollectError, Collector};
use crate::model::{Finding, HaystackKind, ScanContext, Severity};
use crate::text::{truncate, unquote};
use crate::win::wmi::{self, WmiInstance};

/// The repository that holds event subscriptions, not the default `ROOT\CIMV2`.
const NAMESPACE: &str = r"ROOT\SUBSCRIPTION";

/// Category string used on every finding from this module.
const CATEGORY: &str = "wmi-persistence";

/// Cap on instances pulled per class. A hostile host could plant thousands of
/// filters to bury the one consumer that matters; 256 is far above a real machine.
const MAX_PER_CLASS: usize = 256;

/// A consumer's script body can legitimately run to thousands of characters, but the
/// evidence line must stay readable. The full text is not needed to act on it.
const MAX_SCRIPT_EVIDENCE: usize = 1024;

/// A command line is bounded harder: a real one is short, and anything longer is
/// padding designed to push the interesting prefix out of view.
const MAX_COMMAND_EVIDENCE: usize = 512;

/// WMI classes this collector reads, exposed for the raw-data section and for tests.
pub const CLASSES: &[&str] = &[
    "__EventFilter",
    "CommandLineEventConsumer",
    "ActiveScriptEventConsumer",
    "__FilterToConsumerBinding",
];

/// Query every class, push findings and haystacks, and warn on any class that could
/// not be read.
pub struct WmiCollector;

impl Collector for WmiCollector {
    fn name(&self) -> &'static str {
        "wmi"
    }

    fn run(&self, ctx: &mut ScanContext) -> Result<(), CollectError> {
        // A class that cannot be read is recorded as a warning, not an error: the
        // other three classes may still be readable, and "WMI could not be checked"
        // must be stated rather than implied.
        let filters = query_class(ctx, "__EventFilter");
        let command_consumers = query_class(ctx, "CommandLineEventConsumer");
        let script_consumers = query_class(ctx, "ActiveScriptEventConsumer");
        let bindings = query_class(ctx, "__FilterToConsumerBinding");

        for instance in &filters {
            report_filter(ctx, instance);
        }
        for instance in &command_consumers {
            report_command_consumer(ctx, instance);
        }
        for instance in &script_consumers {
            report_script_consumer(ctx, instance);
        }
        for instance in &bindings {
            report_binding(ctx, instance);
        }

        push_raw(ctx, "__EventFilter", &filters);
        push_raw(ctx, "CommandLineEventConsumer", &command_consumers);
        push_raw(ctx, "ActiveScriptEventConsumer", &script_consumers);
        push_raw(ctx, "__FilterToConsumerBinding", &bindings);

        Ok(())
    }
}

/// What a class of object means for severity.
///
/// Factored out of the reporting functions so the policy is testable on a string
/// rather than on a live WMI instance: the rule is "does this class execute?", and
/// that question has nothing to do with the host.
pub fn class_severity(class: &str) -> Severity {
    match class {
        "CommandLineEventConsumer" | "ActiveScriptEventConsumer" => Severity::High,
        "__EventFilter" => Severity::Med,
        // A binding is inert on its own; what it points at carries the weight.
        _ => Severity::Info,
    }
}

/// Extract the executable path from a consumer command line, if any.
///
/// WMI's `CommandLineTemplate` is a command line, not a path: it may be quoted, may
/// carry arguments, and may be a bare program name to be resolved on `PATH`. The
/// first token is returned exactly as found - the collector pushes it to the
/// signature matcher, which compares paths itself, so normalising here would only
/// lose information a rule might need.
///
/// An empty or whitespace-only command line yields `None` rather than an empty path,
/// which is what an `ActiveScriptEventConsumer` (no command line at all) provides.
pub fn consumer_executable(command_line: &str) -> Option<String> {
    let trimmed = command_line.trim();
    if trimmed.is_empty() {
        return None;
    }

    // A leading quote means the whole path is quoted, which is how a path with
    // spaces is expressed. Everything before the closing quote is the path.
    if let Some(rest) = trimmed.strip_prefix('"') {
        let end = rest.find('"').unwrap_or(rest.len());
        return non_empty(&rest[..end]);
    }

    // Unquoted: split at the first whitespace, which is where arguments begin. A
    // Windows path cannot contain a space unquoted, so this is unambiguous.
    let end = trimmed.find(char::is_whitespace).unwrap_or(trimmed.len());
    non_empty(&trimmed[..end])
}

/// `Some(cleaned)` unless the candidate is empty after stripping quotes and
/// whitespace - an empty path would match nothing and still read as a finding.
fn non_empty(candidate: &str) -> Option<String> {
    let cleaned = unquote(candidate);
    if cleaned.is_empty() {
        return None;
    }
    Some(cleaned.to_string())
}

/// Run `SELECT * FROM <class>` and warn when it fails.
///
/// The warning names the class and the reason, so the report says *which* part of
/// WMI could not be checked. An empty result is a success: it means the class was
/// read and held nothing.
fn query_class(ctx: &mut ScanContext, class: &str) -> Vec<WmiInstance> {
    let wql = format!("SELECT * FROM {class}");
    match wmi::query(NAMESPACE, &wql, MAX_PER_CLASS) {
        Ok(instances) => instances,
        Err(message) => {
            ctx.warn(format!(
                "WMI query {wql} in {NAMESPACE} failed: {message} - WMI persistence was NOT checked"
            ));
            Vec::new()
        }
    }
}

/// A `__EventFilter` is the trigger. Alone it is Med: dormant, but it is the half of
/// the mechanism a consumer must be bound to, and its presence on a home machine has
/// no benign explanation.
fn report_filter(ctx: &mut ScanContext, instance: &WmiInstance) {
    let name = field(instance, "Name");
    let query = field(instance, "Query");
    let event_namespace = field(instance, "EventNamespace");

    let title = format!("WMI event filter '{}'", display_name(&name));
    let finding = Finding::new(class_severity("__EventFilter"), CATEGORY, title)
        .evidence(format!("filter name: {}", display_name(&name)))
        .evidence(format!("event namespace: {event_namespace}"))
        .evidence(format!("WQL trigger: {query}"))
        .remediation(
            "Inspect this filter with Get-WmiObject -Namespace root\\subscription -Class __EventFilter; \
             a filter with no legitimate software behind it should be removed.",
        );

    ctx.add(finding);

    // The WQL body names the event source and often an executable or a path; it
    // belongs in the haystack exactly as a service path does.
    ctx.note(HaystackKind::CommandLine, query, "WMI __EventFilter Query");
    ctx.note(HaystackKind::TaskName, name, "WMI __EventFilter");
}

/// A `CommandLineEventConsumer` runs a command line. Always High.
fn report_command_consumer(ctx: &mut ScanContext, instance: &WmiInstance) {
    let name = field(instance, "Name");
    let template = field(instance, "CommandLineTemplate");
    let executable = field(instance, "ExecutablePath");

    let title = format!("WMI command-line consumer '{}'", display_name(&name));
    let mut finding = Finding::new(class_severity("CommandLineEventConsumer"), CATEGORY, title)
        .evidence(format!("consumer name: {}", display_name(&name)))
        .evidence(format!(
            "command line: {}",
            truncate(&template, MAX_COMMAND_EVIDENCE)
        ));

    if let Some(text) = non_empty(&executable) {
        finding = finding.evidence(format!(
            "executable: {}",
            truncate(&text, MAX_COMMAND_EVIDENCE)
        ));
    }

    let finding = finding.remediation(
        "This runs a command whenever its filter fires. Enumerate the binding \
         (Get-WmiObject -Namespace root\\subscription -Class __FilterToConsumerBinding) and remove the \
         consumer, the filter and the binding together.",
    );
    ctx.add(finding);

    // The command line is matched as a command line, and the executable it starts as
    // a path - the same treatment a service or autorun entry gets.
    ctx.note(
        HaystackKind::CommandLine,
        template.clone(),
        "WMI CommandLineEventConsumer",
    );
    ctx.note(
        HaystackKind::Path,
        executable,
        "WMI CommandLineEventConsumer ExecutablePath",
    );
    if let Some(path) = consumer_executable(&template) {
        ctx.note(
            HaystackKind::Path,
            path,
            "WMI CommandLineEventConsumer command line",
        );
    }
}

/// An `ActiveScriptEventConsumer` runs a script body. Always High - and the script
/// text *is* the payload, so it goes into the evidence (truncated hard).
fn report_script_consumer(ctx: &mut ScanContext, instance: &WmiInstance) {
    let name = field(instance, "Name");
    let engine = field(instance, "ScriptingEngine");
    let text = field(instance, "ScriptText");
    let file_name = field(instance, "ScriptFileName");

    let title = format!("WMI active-script consumer '{}'", display_name(&name));
    let mut finding = Finding::new(class_severity("ActiveScriptEventConsumer"), CATEGORY, title)
        .evidence(format!("consumer name: {}", display_name(&name)))
        .evidence(format!(
            "script engine: {}",
            truncate(&engine, MAX_COMMAND_EVIDENCE)
        ))
        .evidence(format!(
            "script text: {}",
            truncate(&text, MAX_SCRIPT_EVIDENCE)
        ));

    if let Some(text) = non_empty(&file_name) {
        finding = finding.evidence(format!(
            "script file: {}",
            truncate(&text, MAX_COMMAND_EVIDENCE)
        ));
    }

    let finding = finding.remediation(
        "The script body above is stored in the WMI repository, not on disk. Remove the consumer, its \
         filter and the binding together, then re-check the repository for further subscriptions.",
    );
    ctx.add(finding);

    ctx.note(
        HaystackKind::CommandLine,
        text,
        "WMI ActiveScriptEventConsumer ScriptText",
    );
    ctx.note(
        HaystackKind::TaskName,
        name,
        "WMI ActiveScriptEventConsumer",
    );
    ctx.note(
        HaystackKind::Path,
        file_name,
        "WMI ActiveScriptEventConsumer ScriptFileName",
    );
}

/// A `__FilterToConsumerBinding` records what is wired to what. Info severity: the
/// dangerous objects it names are reported under their own classes, and repeating
/// their severity here would double-count the same fact in the verdict.
fn report_binding(ctx: &mut ScanContext, instance: &WmiInstance) {
    let consumer = field(instance, "Consumer");
    let filter = field(instance, "Filter");

    let title = format!(
        "WMI filter-to-consumer binding: {} -> {}",
        short_ref(&filter),
        short_ref(&consumer)
    );
    let finding = Finding::new(class_severity("__FilterToConsumerBinding"), CATEGORY, title)
        .evidence(format!("filter: {filter}"))
        .evidence(format!("consumer: {consumer}"))
        .remediation(
            "A binding is inert by itself; act on the consumer it names, then delete the binding.",
        );
    ctx.add(finding);

    // The consumer path carries the class and instance name, which is worth matching
    // against the product database.
    ctx.note(
        HaystackKind::CommandLine,
        consumer,
        "WMI __FilterToConsumerBinding Consumer",
    );
}

/// A field's text, sanitised for the report. `WmiInstance::text` already returns `""`
/// for an absent property; sanitising here is what makes the value safe to print,
/// because a WMI string is attacker-controlled like any other (SR-2).
fn field(instance: &WmiInstance, name: &str) -> String {
    crate::text::sanitize(&instance.text(name), crate::model::MAX_STRING)
}

/// A name to put in a title: the sanitised value, or a placeholder when the provider
/// omitted it. A blank title would make two filters indistinguishable in the report.
fn display_name(name: &str) -> String {
    if name.trim().is_empty() {
        "(unnamed)".to_string()
    } else {
        name.to_string()
    }
}

/// The instance-name part of a WMI reference, for a readable title.
///
/// A binding stores its reference as `__EventFilter.Name="BootFilter"` (dot form) or
/// `\\.\root\subscription:__EventFilter.Name="BootFilter"` (colon form). Both are
/// reduced to the `Name="..."` tail: the class ahead of it is already in the finding
/// title, and the full path is carried in the evidence unchanged.
fn short_ref(object_path: &str) -> String {
    // Colon form first: everything after the last ':' is the class-qualified name.
    let after_colon = object_path.rsplit(':').next().unwrap_or(object_path);
    // Then the dot form: drop the class name that precedes the '.'.
    let tail = after_colon.rsplit('.').next().unwrap_or(after_colon);
    let tail = tail.trim();
    if tail.is_empty() {
        "(unnamed)".to_string()
    } else {
        tail.to_string()
    }
}

/// Record the instances of one class verbatim under RAW DATA, so the report carries
/// the evidence behind every finding and a human can overrule the reading.
fn push_raw(ctx: &mut ScanContext, class: &str, instances: &[WmiInstance]) {
    if instances.is_empty() {
        return;
    }

    let lines = instances
        .iter()
        .map(|instance| {
            let mut pairs: Vec<String> = instance
                .values
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            pairs.sort();
            format!("{class}: {}", pairs.join(" | "))
        })
        .collect();

    ctx.raw_section(format!("WMI {class} ({NAMESPACE})"), lines);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ScanContext;

    #[test]
    fn collector_name_is_stable() {
        assert_eq!(WmiCollector.name(), "wmi");
    }

    // --- consumer_executable ------------------------------------------------

    #[test]
    fn quoted_path_with_arguments() {
        let exe = consumer_executable(r#""C:\Program Files\Thing\agent.exe" --silent --run"#);
        assert_eq!(exe.as_deref(), Some(r"C:\Program Files\Thing\agent.exe"));
    }

    #[test]
    fn bare_path_with_no_arguments() {
        assert_eq!(
            consumer_executable(r"C:\Windows\System32\cmd.exe").as_deref(),
            Some(r"C:\Windows\System32\cmd.exe")
        );
    }

    #[test]
    fn powershell_encoded_command_yields_the_interpreter() {
        // The interesting part of a `-enc` line is which interpreter runs it; the
        // base64 blob is the payload and belongs in the command-line haystack.
        let exe =
            consumer_executable("powershell.exe -NoProfile -WindowStyle Hidden -enc SQBFAFgA");
        assert_eq!(exe.as_deref(), Some("powershell.exe"));
    }

    #[test]
    fn empty_command_line_is_none_not_empty_string() {
        assert_eq!(consumer_executable(""), None);
        assert_eq!(consumer_executable("   \t "), None);
    }

    #[test]
    fn malformed_quoting_does_not_panic_or_invent_a_path() {
        // An unterminated quote: everything after the quote is the candidate, so
        // the whole remainder is the path. The point is that this returns without
        // panicking and without inventing a truncated path.
        assert_eq!(
            consumer_executable("\"C:\\Tools\\half").as_deref(),
            Some("C:\\Tools\\half")
        );
        // A lone quote has nothing behind it.
        assert_eq!(consumer_executable("\""), None);
        assert_eq!(consumer_executable("\"   \""), None);
    }

    // --- class_severity -----------------------------------------------------

    #[test]
    fn a_consumer_is_high_and_a_filter_alone_is_med() {
        assert_eq!(class_severity("CommandLineEventConsumer"), Severity::High);
        assert_eq!(class_severity("ActiveScriptEventConsumer"), Severity::High);
        assert_eq!(class_severity("__EventFilter"), Severity::Med);
        assert_eq!(class_severity("__FilterToConsumerBinding"), Severity::Info);
    }

    #[test]
    fn unknown_class_is_info_not_high() {
        assert_eq!(class_severity("SomethingElse"), Severity::Info);
    }

    // --- reporting ----------------------------------------------------------

    /// A command-line consumer must produce a High finding whose evidence carries
    /// the full command line - that text is the whole reason the finding exists.
    #[test]
    fn command_consumer_reports_high_with_its_command_line() {
        let instance = WmiInstance {
            class: "CommandLineEventConsumer".to_string(),
            values: vec![
                ("Name".to_string(), "Updater".to_string()),
                (
                    "CommandLineTemplate".to_string(),
                    r"C:\Users\bob\AppData\Roaming\svc.exe -install".to_string(),
                ),
                (
                    "ExecutablePath".to_string(),
                    r"C:\Users\bob\AppData\Roaming\svc.exe".to_string(),
                ),
            ],
        };

        let mut ctx = ScanContext::default();
        report_command_consumer(&mut ctx, &instance);

        assert_eq!(ctx.findings.len(), 1);
        let finding = &ctx.findings[0];
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.category, CATEGORY);
        assert!(
            finding
                .evidence
                .iter()
                .any(|e| e.contains("svc.exe -install")),
            "the command line must be in the evidence"
        );

        // The executable path must reach the signature matcher as a path.
        assert!(ctx
            .haystack
            .iter()
            .any(|h| h.kind == HaystackKind::Path && h.value.contains("svc.exe")));
    }

    /// A script consumer must report High and put the script body in the evidence.
    #[test]
    fn script_consumer_reports_high_with_its_script_text() {
        let instance = WmiInstance {
            class: "ActiveScriptEventConsumer".to_string(),
            values: vec![
                ("Name".to_string(), "Persist".to_string()),
                ("ScriptingEngine".to_string(), "VBScript".to_string()),
                (
                    "ScriptText".to_string(),
                    "CreateObject(\"WScript.Shell\").Run \"calc.exe\"".to_string(),
                ),
            ],
        };

        let mut ctx = ScanContext::default();
        report_script_consumer(&mut ctx, &instance);

        assert_eq!(ctx.findings.len(), 1);
        assert_eq!(ctx.findings[0].severity, Severity::High);
        assert!(ctx.findings[0]
            .evidence
            .iter()
            .any(|e| e.contains("WScript.Shell")));
    }

    /// A filter alone is Med, never High: it does not execute anything until a
    /// consumer is bound to it.
    #[test]
    fn filter_alone_is_med() {
        let instance = WmiInstance {
            class: "__EventFilter".to_string(),
            values: vec![
                ("Name".to_string(), "BootFilter".to_string()),
                (
                    "Query".to_string(),
                    "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'".to_string(),
                ),
                ("EventNamespace".to_string(), "root\\cimv2".to_string()),
            ],
        };

        let mut ctx = ScanContext::default();
        report_filter(&mut ctx, &instance);

        assert_eq!(ctx.findings.len(), 1);
        assert_eq!(ctx.findings[0].severity, Severity::Med);
        assert!(ctx.findings[0]
            .evidence
            .iter()
            .any(|e| e.contains("root\\cimv2")));
    }

    /// An instance whose properties are all missing must still report, with a
    /// placeholder rather than a panic or an empty title.
    #[test]
    fn empty_instance_is_handled_without_panicking() {
        let mut ctx = ScanContext::default();
        report_filter(&mut ctx, &WmiInstance::default());
        report_command_consumer(&mut ctx, &WmiInstance::default());
        report_script_consumer(&mut ctx, &WmiInstance::default());
        report_binding(&mut ctx, &WmiInstance::default());

        assert_eq!(ctx.findings.len(), 4);
        for finding in &ctx.findings {
            assert!(finding.title.contains("unnamed") || finding.title.contains("WMI"));
        }
    }

    /// A property value carrying an ANSI escape must be sanitised before it reaches
    /// the report (SR-2) - a hostile consumer name is attacker-controlled input.
    #[test]
    fn hostile_property_text_is_sanitised() {
        let instance = WmiInstance {
            class: "CommandLineEventConsumer".to_string(),
            values: vec![(
                "CommandLineTemplate".to_string(),
                "evil\u{1b}[31mred\u{7}name.exe".to_string(),
            )],
        };

        let mut ctx = ScanContext::default();
        report_command_consumer(&mut ctx, &instance);

        let joined = ctx.findings[0].evidence.join(" ");
        // Positive form: the escape and the bell were removed by `sanitize`.
        assert!(joined.chars().all(|c| c != '\u{1b}' && c != '\u{7}'));
    }

    /// A long script must be truncated in the evidence, not dumped in full.
    #[test]
    fn long_script_text_is_truncated_in_evidence() {
        let instance = WmiInstance {
            class: "ActiveScriptEventConsumer".to_string(),
            values: vec![("ScriptText".to_string(), "A".repeat(8_000))],
        };

        let mut ctx = ScanContext::default();
        report_script_consumer(&mut ctx, &instance);

        let line = ctx.findings[0]
            .evidence
            .iter()
            .find(|e| e.starts_with("script text:"))
            .cloned()
            .unwrap_or_default();
        assert!(
            !line.is_empty(),
            "the evidence line must carry the script text"
        );
        assert!(line.len() <= MAX_SCRIPT_EVIDENCE + 64);
    }

    // --- short_ref ----------------------------------------------------------

    #[test]
    fn binding_reference_is_shortened_to_the_instance_name() {
        assert_eq!(
            short_ref("__EventFilter.Name=\"BootFilter\""),
            "Name=\"BootFilter\""
        );
        assert_eq!(short_ref(""), "(unnamed)");
    }
}
