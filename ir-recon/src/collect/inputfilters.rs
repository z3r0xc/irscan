//! Device-class filter drivers: FR-12.
//!
//! A `UpperFilters` / `LowerFilters` value on a device class is the documented,
//! supported way to attach a driver to *every device of that class* - and it is
//! exactly where input-interception and screen-capture products register. A filter
//! on the keyboard or mouse class sees every keystroke and every pointer move before
//! the application does; a filter on the display/monitor class sees every frame.
//!
//! For a report about a mouse that moved by itself, this is the most directly
//! relevant registry location in the whole scan, which is why it is its own
//! collector rather than a footnote in the services list.
//!
//! The check is a comparison against the small, documented set of class drivers
//! Microsoft ships in these classes. Anything else is reported - a false positive
//! here costs a line of review; a false negative hides the exact component capable
//! of moving the cursor.

use crate::collect::{CollectError, Collector};
use crate::model::{Finding, HaystackKind, ScanContext, Severity};
use crate::win::reg::{self, RegValue, RootKey};

/// The device class GUIDs whose filter stacks matter for this investigation.
/// Class GUIDs are defined by Microsoft and are stable across Windows versions.
const DEVICE_CLASSES: &[(&str, &str)] = &[
    ("{4d36e96b-e325-11ce-bfc1-08002be10318}", "Keyboard"),
    ("{4d36e96f-e325-11ce-bfc1-08002be10318}", "Mouse"),
    ("{4d36e968-e325-11ce-bfc1-08002be10318}", "Display"),
    ("{4d36e96e-e325-11ce-bfc1-08002be10318}", "Monitor"),
];

/// Drivers that Microsoft ships in these classes. A filter present here is the
/// expected stack, not a finding. Compared case-insensitively.
///
/// `monitor` and `display` are the in-box class names for the monitor/display
/// classes; `usbccgp` is the USB composite-device parent that every USB keyboard,
/// mouse and webcam sits behind.
pub const KNOWN_CLASS_DRIVERS: &[&str] = &[
    "kbdclass", "mouclass", "kbdhid", "mouhid", "i8042prt", "usbccgp", "hidusb", "hidclass",
    "monitor", "display",
];

/// The ScanCode Map value lives outside the Class key: it is a direct remapping of
/// physical scan codes to other keys, applied before any driver sees the input.
const KEYBOARD_LAYOUT: &str = r"SYSTEM\CurrentControlSet\Control\Keyboard Layout";
const CLASS_ROOT: &str = r"SYSTEM\CurrentControlSet\Control\Class";

/// Collects device-class filter drivers and the keyboard scan-code map.
pub struct InputFiltersCollector;

impl Collector for InputFiltersCollector {
    fn name(&self) -> &'static str {
        "inputfilters"
    }

    fn run(&self, ctx: &mut ScanContext) -> Result<(), CollectError> {
        let mut lines: Vec<String> = Vec::new();

        for (guid, label) in DEVICE_CLASSES {
            let key_path = format!("{CLASS_ROOT}\\{guid}");
            let origin = format!("HKLM\\{key_path}");
            ctx.note(HaystackKind::RegistryPath, key_path.clone(), origin.clone());
            push_line(&mut lines, &format!("{origin} ({label})"));

            let mut saw_filters = false;
            for value_name in ["UpperFilters", "LowerFilters"] {
                let Some(value) = reg::get_value(RootKey::Hklm, &key_path, value_name) else {
                    continue;
                };
                let filters = flatten_multi(&value);
                if filters.is_empty() {
                    continue;
                }
                saw_filters = true;
                push_line(
                    &mut lines,
                    &format!("  {value_name} = {}", filters.join(", ")),
                );

                // `flatten_multi` already sanitised every name, so these are safe
                // to note and to quote in evidence as-is.
                for filter in &filters {
                    ctx.note(HaystackKind::ServiceName, filter.clone(), origin.clone());
                }

                report_filters(ctx, label, guid, value_name, &filters, &origin);
            }

            if !saw_filters {
                push_line(&mut lines, "  (фильтры не зарегистрированы)");
            }
        }

        // --- Keyboard scan-code remapping ---------------------------------------
        // A Scancode Map rewrites physical keys to other keys in the kernel, below
        // any driver. Its legitimate use is swapping Ctrl/CapsLock; its abuse is a
        // keylogger that never touches a file the user can see.
        ctx.note(
            HaystackKind::RegistryPath,
            KEYBOARD_LAYOUT,
            "HKLM Keyboard Layout",
        );
        let scancode_map = read_scancode_map();
        if let Some(description) = scancode_map {
            push_line(
                &mut lines,
                &format!("HKLM\\{KEYBOARD_LAYOUT}\\Scancode Map = {description}"),
            );
            ctx.add(
                Finding::new(
                    Severity::Med,
                    "input",
                    format!(
                        "HKLM\\{KEYBOARD_LAYOUT}\\Scancode Map ({description}) — эта запись \
                         переопределяет физические скан-коды клавиш"
                    ),
                )
                .evidence(format!(
                    "HKLM\\{KEYBOARD_LAYOUT}\\Scancode Map задан: {description}"
                ))
                .evidence(
                    "Эта запись переопределяет физические скан-коды в ядре, до того как \
                     нажатие увидит любой драйвер. Windows её не создаёт; она существует \
                     только потому, что её записал кто-то другой.",
                )
                .remediation(
                    "Проверьте в настройках клавиатуры Windows раскладку, добавленную вами \
                     или администратором. Если её никто не узнаёт, экспортируйте значение \
                     как доказательство и удалите его, затем перезагрузите компьютер.",
                ),
            );
        } else {
            push_line(
                &mut lines,
                "HKLM\\Keyboard Layout\\Scancode Map = (не задан)",
            );
        }

        ctx.raw_section("INPUT FILTERS", lines);
        Ok(())
    }
}

/// Decide whether a class's filters are ordinary and report the ones that are not.
fn report_filters(
    ctx: &mut ScanContext,
    class_label: &str,
    guid: &str,
    value_name: &str,
    filters: &[String],
    origin: &str,
) {
    let unusual: Vec<&String> = filters
        .iter()
        .filter(|f| !is_known_class_driver(f))
        .collect();
    if unusual.is_empty() {
        return;
    }

    let is_input_class = class_label == "Keyboard" || class_label == "Mouse";

    for filter in unusual {
        // Already sanitised by `flatten_multi`.
        let name = filter.as_str();
        if name.trim().is_empty() {
            continue;
        }

        // Keyboard and mouse are the classes that can watch and *drive* input, so an
        // unknown filter there is escalated; on display/monitor it stays Med.
        let severity = if is_input_class {
            Severity::High
        } else {
            Severity::Med
        };

        let mut finding = Finding::new(
            severity,
            "input",
            format!("Фильтр {name} неизвестен в классе устройств «{class_label}»: файл {origin}"),
        )
        .evidence(format!("имя фильтра: {name}"))
        .evidence(format!("каталог класса: {origin}"))
        .evidence(format!(
            "зарегистрирован как {value_name} в классе устройств {class_label} {guid}"
        ));

        if is_input_class {
            finding = finding.evidence(
                "Этот драйвер загружается поверх каждого устройства класса «клавиатура» и/или \
                 «мышь», поэтому он видит каждое нажатие и каждое движение указателя, а также \
                 может отправлять собственные события. Именно так фильтр становится механизмом, \
                 с помощью которого средство удалённого управления двигает курсор.",
            );
        } else {
            finding = finding.evidence(
                "Фильтр этого класса обрабатывает поток данных устройства. В классах «дисплей» \
                 и «монитор» это означает, что он может снимать содержимое экрана.",
            );
        }

        ctx.add(finding.remediation(
            "Определите продукт, которому принадлежит этот драйвер (его имени обычно достаточно, \
             чтобы найти сайт производителя). Удаляйте продукт его собственным деинсталлятором: \
             не удаляйте один файл драйвера, запись фильтра останется и заблокирует устройство.",
        ));
    }
}

/// Is this filter one of the drivers Microsoft ships in these classes?
///
/// The check is case-insensitive because the registry preserves the installer's
/// casing (`MouClass` and `mouclass` are the same driver). A filter may be written
/// with a path or a `.sys` suffix, so the comparison is done on the bare name.
pub fn is_known_class_driver(filter: &str) -> bool {
    let bare = crate::text::basename(filter);
    let lower = bare.trim().to_lowercase();
    let bare = lower.strip_suffix(".sys").unwrap_or(&lower);
    if bare.is_empty() {
        return true; // an empty entry is malformed, not an unknown driver
    }
    KNOWN_CLASS_DRIVERS
        .iter()
        .any(|known| known.eq_ignore_ascii_case(bare))
}

/// Flatten a `REG_MULTI_SZ` filter value into its individual names.
///
/// A plain `REG_SZ` holding a space-separated list is also accepted, because some
/// installers write filters that way and dropping them would miss the driver this
/// collector exists to find.
///
/// Sanitisation happens here, at the single point where a registry string becomes a
/// filter name, so every consumer - the raw section, a haystack note, a finding's
/// evidence lines - is clean by construction (SR-2). Doing it at each call site
/// would be three separate places to forget.
pub fn flatten_multi(value: &RegValue) -> Vec<String> {
    let parts: Vec<String> = match value {
        RegValue::MultiStr(parts) => parts
            .iter()
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect(),
        RegValue::Str(s) | RegValue::ExpandStr(s) => s
            .split_whitespace()
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect(),
        _ => Vec::new(),
    };
    parts
        .into_iter()
        .map(|p| crate::text::sanitize(&p, crate::model::MAX_STRING))
        .filter(|p| !p.trim().is_empty())
        .collect()
}

/// Read the `Scancode Map` binary value and describe it without decoding it.
///
/// The value is a `REG_BINARY` blob, which `win::reg` reports as [`RegValue::Other`].
/// This collector proves *presence*, which is the actionable fact; decoding the
/// individual mappings is deliberately out of scope until the report needs it.
fn read_scancode_map() -> Option<String> {
    let value = reg::get_value(RootKey::Hklm, KEYBOARD_LAYOUT, "Scancode Map")?;
    match value {
        RegValue::Other => Some("binary value present".to_string()),
        RegValue::Str(s) | RegValue::ExpandStr(s) if !s.trim().is_empty() => {
            Some(format!("present ({s})"))
        }
        RegValue::MultiStr(v) if !v.is_empty() => Some("present".to_string()),
        RegValue::Dword(n) if n != 0 => Some(format!("present (0x{n:x})")),
        _ => None,
    }
}

fn push_line(lines: &mut Vec<String>, line: &str) {
    const MAX_RAW_LINES: usize = 512;
    if lines.len() < MAX_RAW_LINES {
        lines.push(line.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_shipped_class_driver_is_not_flagged() {
        for name in [
            "kbdclass", "mouclass", "kbdhid", "mouhid", "i8042prt", "usbccgp",
        ] {
            assert!(
                is_known_class_driver(name),
                "{name} is an in-box driver and must not be reported"
            );
        }
    }

    #[test]
    fn a_made_up_driver_is_flagged() {
        assert!(!is_known_class_driver("stealthhook"));
        assert!(!is_known_class_driver("ScreenCaptureFlt"));
        assert!(!is_known_class_driver("remotecontrol"));
    }

    #[test]
    fn the_allowlist_comparison_is_case_insensitive_and_tolerates_paths_and_suffixes() {
        assert!(is_known_class_driver("MouClass"));
        assert!(is_known_class_driver("KBDHID"));
        assert!(is_known_class_driver("mouclass.sys"));
        assert!(is_known_class_driver(
            r"C:\Windows\System32\drivers\kbdclass.sys"
        ));
        // ...and the same normalisation must not turn an unknown driver into a known one.
        assert!(!is_known_class_driver("fakeclass.sys"));
    }

    #[test]
    fn multistr_values_flatten_with_blanks_removed() {
        let value = RegValue::MultiStr(vec![
            "kbdclass".to_string(),
            String::new(),
            " SomeFilter ".to_string(),
        ]);
        assert_eq!(flatten_multi(&value), vec!["kbdclass", "SomeFilter"]);

        // A REG_SZ holding a whitespace-separated list is accepted too.
        let value = RegValue::Str("mouclass  mouhid".to_string());
        assert_eq!(flatten_multi(&value), vec!["mouclass", "mouhid"]);

        // A value type that cannot hold a filter name yields nothing to report.
        assert!(flatten_multi(&RegValue::Dword(1)).is_empty());
        assert!(flatten_multi(&RegValue::Other).is_empty());
    }

    #[test]
    fn an_empty_multistr_produces_no_filters() {
        let value = RegValue::MultiStr(vec![]);
        assert!(flatten_multi(&value).is_empty());
        // An empty entry is malformed input, not an unknown driver.
        assert!(is_known_class_driver(""));
    }
}
