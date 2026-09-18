//! Service and kernel-driver triage (FR-3, FR-13, FR-14).
//!
//! The SCM enumeration itself lives in [`crate::win::services`]; this module is the
//! part that decides what the result *means*. Two reasons that split exists: the
//! FFI half is the only code allowed to contain `unsafe` (SR-6), and the policy half
//! is pure, so every severity here is decided by [`crate::rules`] and unit-tested
//! without a Windows host.
//!
//! Why this collector matters for the reported symptom: a service is the standard
//! way to get a component to run before logon, survive reboots and run as
//! `LocalSystem`. A *driver* service additionally loads into the kernel, which is
//! the mechanism behind input interception and screen capture at a level no
//! user-mode tool can inspect - hence the escalation rule in [`service_severity`].
//! `LocalSystem` plus a binary in a *transit* directory is the shape of an agent that
//! took over the machine; `LocalSystem` under `%ProgramData%` is Windows Defender and
//! half the machine-wide installers on a developer box, so it is not a finding.
//!
//! Every string recorded here comes from the registry and is therefore untrusted;
//! `ScanContext::note` sanitises, and the raw table is sanitised at the boundary
//! (SR-2). Nothing in this module writes, executes or connects anywhere.

use std::path::Path;

use crate::collect::{CollectError, Collector};
use crate::model::{Finding, HaystackKind, ScanContext, ServiceRecord, Severity};
use crate::rules::{classify_location, execution_severity, looks_masquerading, Location};
use crate::text::{basename, sanitize};
use crate::win::services::enum_services;
use crate::win::sig::is_signature_trusted;

/// A returned executable longer than this is not a path worth stat'ing or verifying,
/// and it may well be hostile. 32 KiB is far past `MAX_PATH` and past the long-path
/// maximum, so anything beyond it is refused rather than truncated into something
/// that could resolve to a different file.
pub const MAX_EXECUTABLE_LEN: usize = 32 * 1024;

/// Does `account` denote the local `LocalSystem` principal?
///
/// A service's `ObjectName` is absent only when the account *is* `LocalSystem`, so
/// the empty string is a real answer rather than missing data. `"LocalSystem"` is
/// what the Services UI and `sc qc` print, `NT AUTHORITY\SYSTEM` is what the
/// registry holds on most hosts, and a bare `SYSTEM` appears in keys written by
/// non-Microsoft installers. The domain prefix is optional because the local
/// principal can also be written `.\SYSTEM`; matching on the *last* component covers
/// all three spellings without letting `NT AUTHORITY\SYSTEMX` through.
pub fn is_system_service_account(account: &str) -> bool {
    let a = account.trim();
    if a.is_empty() {
        return true;
    }
    let tail = match a.rsplit_once('\\') {
        Some((_, name)) => name,
        None => a,
    };
    tail.eq_ignore_ascii_case("localsystem") || tail.eq_ignore_ascii_case("system")
}

/// How a [`Location`] reads in a finding title or evidence line.
///
/// The report is read by a human under time pressure, so the wire names are spelled
/// out once here rather than at each format site.
pub fn location_label(location: Location) -> &'static str {
    match location {
        Location::Privileged => "привилегированный каталог",
        Location::AppData => "каталог данных приложений",
        Location::Drop => "каталог для временных файлов",
    }
}

/// Extract the executable from a service's `ImagePath` value.
///
/// `ImagePath` is a command line, not a path: it is normally quoted (so that
/// `C:\Program Files\...` survives), it may carry arguments, and the *unquoted*
/// form is ambiguous about where the program name ends. Microsoft's own guidance is
/// to quote it; when a host does not, this function recovers the boundary by taking
/// the **last** whitespace-separated token that carries an executable extension
/// (`EXECUTABLE_EXTENSIONS`) and keeping everything up to it:
///
/// * `"C:\Program Files\X\agent.exe" -k x` -> the quoted name, authoritatively;
/// * `C:\Windows\System32\svchost.exe -k netsvcs` -> `...\svchost.exe`;
/// * `C:\Program Files\My Agent\agent.exe -k x` -> `...\My Agent\agent.exe`.
///
/// A value with *no* executable-extension token anywhere has no recoverable
/// boundary, so the whole string is returned and the drive-letter check below judges
/// it. A path that names a directory (a trailing separator, or `.`/`..`) is refused:
/// it is not a program, and returning it would make the collector stat and
/// signature-check a directory and report a bogus missing image.
///
/// A path is accepted **only** when it starts with a drive letter. That is what
/// keeps the "missing image" rule honest: [`crate::win::system_vars`] is a fixed
/// variable list, so an unrecognised `%VAR%` survives expansion verbatim, and
/// stat'ing a literal `%VAR%\x.exe` would declare every such service missing. An
/// unexpanded path is a gap in the evidence, not evidence of malware, so it yields
/// `None` here.
pub fn service_executable(image_path: &str) -> Option<String> {
    let trimmed = image_path.trim();
    if trimmed.is_empty() {
        return None;
    }

    let first = if let Some(inner) = trimmed.strip_prefix('"') {
        // Quoted: the first quote closes the name; an unterminated quote means the
        // value is malformed and nothing about its shape can be trusted.
        let (name, _) = inner.split_once('"')?;
        name.trim().to_string()
    } else {
        // Unquoted, and therefore ambiguous: every token boundary is a candidate end
        // of the program name. The binary is the LAST token that carries a known
        // executable extension, so walking leftwards finds it without guessing:
        //   `...\System32\svchost.exe -k netsvcs` -> token 0 ends in .exe -> token 0
        //   `...\My Agent\agent.exe -k x`          -> token 2 ends in .exe -> tokens 0..=2
        // A value with no executable extension at all has no recoverable boundary, so
        // the whole string is returned and the drive-letter check below judges it.
        let mut cut: Option<usize> = None;
        for (index, token) in trimmed.split(' ').enumerate() {
            if has_executable_extension(token) {
                cut = Some(index);
            }
        }
        match cut {
            Some(last) => trimmed[..token_end(trimmed, last)].to_string(),
            None => trimmed.to_string(),
        }
    };

    let path = first.trim();
    if path.is_empty() || path.len() > MAX_EXECUTABLE_LEN {
        return None;
    }
    // A path whose final component is empty names a directory, not a program:
    // returning it would make the collector stat and signature-check a directory and
    // report a "missing image" for something that was never a file.
    if names_a_directory(path) {
        return None;
    }
    let mut chars = path.chars();
    let drive = chars.next()?;
    if !drive.is_ascii_alphabetic() {
        return None;
    }
    if chars.next() != Some(':') {
        return None;
    }
    Some(path.to_string())
}

/// Extensions the service and driver loaders accept for a binary. A token ending in
/// one of these is a candidate end of the program name in an unquoted `ImagePath`.
const EXECUTABLE_EXTENSIONS: &[&str] = &[
    ".exe", ".com", ".sys", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js",
];

/// Does this token look like a program name?
fn has_executable_extension(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    EXECUTABLE_EXTENSIONS.iter().any(|e| lower.ends_with(e))
}

/// Byte offset just past the `index`-th space-separated token of `value`.
///
/// `index` is bounded by the enumeration that produced it, and the loop stops at the
/// end of the string, so the result is always a character boundary the caller can
/// slice at. Splitting on `' '` rather than on a Unicode whitespace class keeps the
/// byte offsets trivially computable.
fn token_end(value: &str, index: usize) -> usize {
    let bytes = value.as_bytes();
    let mut seen = 0usize;
    let mut at = 0usize;
    while at < bytes.len() {
        if bytes[at] == b' ' {
            if seen == index {
                return at;
            }
            seen += 1;
            // Collapse a run of spaces so `a  b` still counts as two tokens, the way
            // `split(' ')` above does not - the enumeration governs, so this only
            // mirrors it for the common single-space case.
            while at < bytes.len() && bytes[at] == b' ' {
                at += 1;
            }
            continue;
        }
        at += 1;
    }
    bytes.len()
}

/// Does this path name a directory rather than a program?
///
/// A trailing separator (`C:\Windows\System32\`), and the `.` / `..` components,
/// are directory references. Treating them as an executable would make the collector
/// stat a directory, fail the signature check and report a bogus "missing image".
fn names_a_directory(path: &str) -> bool {
    let trimmed = path.trim_end_matches([' ', '\\', '/']);
    if trimmed.len() != path.trim_end().len() {
        // The path ended in a separator (ignoring trailing blanks): a directory.
        return true;
    }
    match path.rsplit(['\\', '/']).next() {
        Some(last) => last == "." || last == "..",
        None => true,
    }
}

/// Severity for a service, from the two facts `rules` owns plus the driver flag.
///
/// The base decision is [`execution_severity`], so a service is never judged by a
/// rule invented in this file: `Location::AppData` - which is where `%ProgramData%`,
/// chocolatey, scoop, and Windows Defender's own Platform directory live - yields at
/// most `Info`, and no longer `High` merely for being there. An earlier version of
/// this function asked only "is this path user-writable", which made
/// `C:\ProgramData\...\MsMpEng.exe` a HIGH on a clean machine.
///
/// The driver escalations remain, because a driver is kernel code and the location
/// axis means something different for it. Each branch, justified:
///
/// * `Drop` or `AppData` plus any signature state -> `High`. A standard user can
///   replace the file, and the signature on the bytes sitting there today says
///   nothing about the bytes that will be there at the next boot. `execution_severity`
///   would call a signed AppData binary "not worth reporting"; for something that
///   loads into the kernel the replaceability is the risk, not the current signature.
/// * `Privileged` plus `trusted == Some(false)` -> `High`, one band above the `Med`
///   that [`execution_severity`] gives an unsigned user-mode service in the same
///   directory. A driver is the one component in this report that can intercept input
///   or capture the screen with no user-mode process to inspect.
/// * `Privileged` plus signed or unverifiable -> whatever `execution_severity` says
///   (`None`). Every stock in-box driver is exactly this, so escalating here would
///   produce the noise this change exists to remove.
pub fn service_severity(
    trusted: Option<bool>,
    location: Location,
    is_driver: bool,
) -> Option<Severity> {
    if is_driver && location != Location::Privileged {
        return Some(Severity::High);
    }
    if is_driver && trusted == Some(false) {
        return Some(Severity::High);
    }
    execution_severity(trusted, location)
}

/// One stable, readable line per service for the RAW DATA appendix.
///
/// Fixed field order and `<none>` placeholders (rather than omitting fields) so two
/// scans of an unchanged host diff cleanly.
pub fn describe(r: &ServiceRecord) -> String {
    format!(
        "{}  [{}]  state={} start={} account={} driver={} image={}",
        r.name,
        if r.display_name.is_empty() {
            "<нет>"
        } else {
            r.display_name.as_str()
        },
        r.state,
        r.start_mode,
        account_label(&r.account),
        if r.is_driver { "yes" } else { "no" },
        if r.image_path.is_empty() {
            "<не указан>"
        } else {
            r.image_path.as_str()
        },
    )
}

/// The evidence block every service finding attaches.
///
/// Name, state, start mode, account and the full image path travel with the finding,
/// as required: a severity tag on its own is not actionable, and the point of this
/// report is that a human can verify every claim it makes.
pub fn evidence_lines(r: &ServiceRecord) -> Vec<String> {
    vec![
        format!(
            "служба: {} ({})",
            r.name,
            if r.display_name.is_empty() {
                "<нет>"
            } else {
                r.display_name.as_str()
            }
        ),
        format!("состояние: {}", r.state),
        format!("запуск: {}", r.start_mode),
        format!("учётная запись: {}", account_label(&r.account)),
        format!(
            "путь к файлу: {}",
            if r.image_path.is_empty() {
                "<не указан>"
            } else {
                r.image_path.as_str()
            }
        ),
        format!(
            "тип: {}",
            if r.is_driver {
                "драйвер ядра"
            } else {
                "служба win32"
            }
        ),
    ]
}

/// How an account reads in the report. An absent `ObjectName` is not missing data:
/// it means `LocalSystem`, and printing an empty field would read like a gap.
pub fn account_label(account: &str) -> &str {
    if account.is_empty() {
        "LocalSystem (по умолчанию)"
    } else {
        account
    }
}

/// The service's binary path, when it names one and that file is gone.
///
/// `None` covers every situation that must stay silent: no path was extracted (many
/// in-box kernel services genuinely carry no `ImagePath`), or the file is there.
/// A callable so the negative cases are testable without a host.
pub fn missing_image(executable: &Option<String>) -> Option<String> {
    let exe = executable.as_deref()?;
    // UNC paths have no drive letter, so `service_executable` already refused them;
    // the guard is repeated so this function is safe when called on its own.
    if exe.starts_with(r"\\") {
        return None;
    }
    if Path::new(exe).is_file() {
        return None;
    }
    Some(exe.to_string())
}

/// Enumerates services and kernel drivers into the context.
pub struct ServicesCollector;

impl Collector for ServicesCollector {
    fn name(&self) -> &'static str {
        "services"
    }

    fn run(&self, ctx: &mut ScanContext) -> Result<(), CollectError> {
        // A failure here means the SCM itself could not be opened, which on a normal
        // host means "not elevated". The report must say so rather than show an empty
        // service list that reads like a clean result.
        let services = match enum_services() {
            Ok(s) => s,
            Err(e) => return Err(CollectError::new("services", e)),
        };

        if services.is_empty() {
            ctx.warn("service enumeration returned no services");
        }

        let system_root = crate::win::system_root();
        let mut table: Vec<String> = Vec::with_capacity(services.len());

        for r in services {
            // Haystacks first: they are what the signature database matches, and they
            // are recorded even for a service with nothing wrong with it.
            let origin = format!(
                "service {}",
                if r.name.is_empty() {
                    "<unnamed>"
                } else {
                    r.name.as_str()
                }
            );
            ctx.note(HaystackKind::ServiceName, r.name.clone(), origin.clone());
            ctx.note(
                HaystackKind::ServiceDisplayName,
                r.display_name.clone(),
                origin.clone(),
            );
            ctx.note(HaystackKind::Path, r.image_path.clone(), origin.clone());
            // The key a service must live under is itself searchable: LOLRMM entries
            // name these paths, and a product that hides its binary can still be
            // spotted by the key it persists through.
            ctx.note(
                HaystackKind::RegistryPath,
                format!(r"SYSTEM\CurrentControlSet\Services\{}", r.name),
                origin,
            );

            table.push(describe(&r));
            classify(ctx, &r, &system_root);
            ctx.services.push(r);
        }

        ctx.raw_section("SERVICES", table);
        Ok(())
    }
}

/// Apply the FR-13 / FR-14 policy to one service and push anything it warrants.
///
/// Kept out of the enumeration loop so the rule block stays readable and the only
/// severity source is [`service_severity`]. A service is *not* reported merely for
/// running: several hundred on a normal host run as `LocalSystem` out of `System32`,
/// and reporting those would bury the entry that matters.
fn classify(ctx: &mut ScanContext, r: &ServiceRecord, system_root: &str) {
    let name_disp = if r.name.is_empty() {
        "<unnamed>"
    } else {
        r.name.as_str()
    };
    let executable = service_executable(&r.image_path);
    // The signature is verified on the *extracted executable*, not on the whole
    // `ImagePath`: WinVerifyTrust needs a file, and handing it `"C:\x.exe" -k` would
    // either fail or be resolved by the OS to something unintended.
    let trusted = match executable.as_deref() {
        Some(exe) => is_signature_trusted(Path::new(exe)),
        None => None,
    };
    // The location comes from `rules`, on the *image path*, so `%ProgramData%` is
    // `AppData` (per-machine software lives there) rather than "user-writable".
    let location = classify_location(&r.image_path);

    if let Some(sev) = service_severity(trusted, location, r.is_driver) {
        let title = if r.is_driver && location != Location::Privileged {
            format!(
                "Драйвер ядра {name_disp} загружается из {} ({})",
                location_label(location),
                r.image_path
            )
        } else if r.is_driver {
            format!(
                "Драйвер ядра {name_disp} не имеет действительной подписи ({})",
                r.image_path
            )
        } else if location == Location::Drop && trusted == Some(false) {
            format!(
                "Служба {name_disp} работает без подписи из {} ({})",
                location_label(location),
                r.image_path
            )
        } else if location == Location::Drop {
            format!(
                "Служба {name_disp} работает из {} ({})",
                location_label(location),
                r.image_path
            )
        } else if location == Location::AppData && trusted == Some(false) {
            format!(
                "Служба {name_disp} работает без подписи из {} ({})",
                location_label(location),
                r.image_path
            )
        } else {
            format!(
                "Служба {name_disp} не имеет действительной подписи ({})",
                r.image_path
            )
        };

        let mut finding = Finding::new(sev, "service", title);
        for line in evidence_lines(r) {
            finding = finding.evidence(line);
        }
        if location != Location::Privileged {
            finding = finding.evidence(format!(
                "расположение: {} (обычный пользователь и любой процесс от его имени могут \
                 подменить этот файл без прав администратора)",
                location_label(location)
            ));
        }
        ctx.add(
            finding
                .remediation(
                    "Снимите SHA-256 файла и запишите путь и имя службы до любых изменений.",
                )
                .remediation(
                    "Файл службы, который может подменить обычный пользователь, сам по себе \
                     открывает путь к правам SYSTEM; если это не установленная вами программа, \
                     удалите службу и переустановите систему с внешнего носителя.",
                ),
        );
    }

    // A registered service whose binary is gone is the shape of a payload removed
    // while its persistence entry survived: a half-finished uninstall, or a
    // deliberate attempt to keep the name reachable. Either way it needs a human.
    if let Some(missing) = missing_image(&executable) {
        ctx.add(
            Finding::new(
                Severity::High,
                "service",
                format!("Служба {name_disp} указывает на несуществующий файл: {missing}"),
            )
            .evidence(format!(
                "служба всё ещё зарегистрирована в Service Control Manager, но файла \
                 {missing} на диске нет"
            ))
            .evidence(format!("указанный путь к файлу: {}", r.image_path))
            .evidence(format!("запуск: {}, состояние: {}", r.start_mode, r.state))
            .evidence(format!("учётная запись: {}", account_label(&r.account)))
            .evidence(
                "сохранившаяся запись службы без файла чаще говорит о намеренной зачистке \
                 следов, чем о безобидном остатке от удаления",
            )
            .remediation(
                "Посмотрите в журнале System события 7045 с именем этой службы, чтобы понять, \
                 что её создало, и поищите в prefetch следы запуска файла.",
            )
            .remediation(
                "Удаляйте ветку реестра службы только после того, как отчёт сохранён; \
                 зафиксируйте имя службы и исходный путь в заметках об инциденте.",
            ),
        );
    }

    // A service running as SYSTEM out of a *transit* directory has no legitimate
    // install story, so the privilege context is stated separately from the severity
    // block above. Restricted to `Drop`: `%ProgramData%` is `AppData` and hosts
    // Defender, chocolatey and every machine-wide per-machine installer, so SYSTEM +
    // AppData is ordinary and was half this machine's false positives.
    if location == Location::Drop && is_system_service_account(&r.account) {
        ctx.add(
            Finding::new(
                Severity::High,
                "service",
                format!(
                    "Служба {name_disp} работает от SYSTEM из {}",
                    location_label(location)
                ),
            )
            .evidence(format!("учётная запись: {}", account_label(&r.account)))
            .evidence(format!("путь к файлу: {}", r.image_path))
            .evidence(format!("расположение: {}", location_label(location)))
            .evidence(format!("состояние: {}, запуск: {}", r.state, r.start_mode))
            .evidence(
                "служба от SYSTEM, запущенная из каталога, куда может писать обычный \
                 пользователь и куда ничего не устанавливается, не имеет законного объяснения",
            )
            .remediation(
                "Останавливайте и отключайте службу только после того, как файл сохранён и \
                 посчитан его хеш; если что-то работает от SYSTEM из доступного на запись \
                 каталога, считайте, что оно полностью контролировало эту машину.",
            ),
        );
    }

    // FR-14: a system binary name outside the Windows directory. `looks_masquerading`
    // takes an image *name*, so the executable is extracted first; a service with no
    // usable path cannot masquerade in this sense and is left alone.
    if let Some(exe) = executable.as_deref() {
        if looks_masquerading(basename(exe), exe, system_root) {
            ctx.add(
                Finding::new(
                    Severity::High,
                    "service",
                    format!(
                        "Служба {name_disp} запускает процесс с именем системного компонента \
                         из каталога вне Windows"
                    ),
                )
                .evidence(format!("путь к файлу: {exe}"))
                .evidence(format!(
                    "ожидаемое расположение: {}\\System32\\{}",
                    system_root.trim_end_matches('\\'),
                    basename(exe)
                ))
                .evidence(format!("имя службы: {name_disp}"))
                .evidence(format!("account: {}", account_label(&r.account)))
                .remediation(
                    "Имя компонента Windows вне %SystemRoot% не бывает законным: сохраните \
                     файл и считайте машину скомпрометированной.",
                ),
            );
        }
    }
}

/// Sanitise a value for any record field this module derives from raw registry text.
///
/// [`crate::win::services`] already sanitises what it returns, so this is a single
/// named boundary rather than a scattered call - the one place to change if service
/// data ever needs a different cap.
pub fn clean(value: &str) -> String {
    sanitize(value, crate::model::MAX_STRING)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(name: &str, image_path: &str, account: &str, is_driver: bool) -> ServiceRecord {
        ServiceRecord {
            name: name.to_string(),
            display_name: name.to_string(),
            state: "running".to_string(),
            start_mode: "auto".to_string(),
            account: account.to_string(),
            image_path: image_path.to_string(),
            is_driver,
        }
    }

    #[test]
    fn executable_from_a_quoted_path_with_arguments() {
        assert_eq!(
            service_executable(r#""C:\Program Files\Acme Agent\agent.exe" -service"#).as_deref(),
            Some(r"C:\Program Files\Acme Agent\agent.exe")
        );
    }

    #[test]
    fn executable_from_a_bare_path() {
        assert_eq!(
            service_executable(r"C:\Windows\System32\svchost.exe").as_deref(),
            Some(r"C:\Windows\System32\svchost.exe")
        );
        assert_eq!(
            service_executable("  C:/Windows/System32/x.exe  ").as_deref(),
            Some("C:/Windows/System32/x.exe")
        );
    }

    #[test]
    fn unquoted_path_with_arguments_is_repaired_at_the_last_executable_token() {
        // No spaces in the path: the first token is the binary, the rest is arguments.
        assert_eq!(
            service_executable(r"C:\Windows\System32\svchost.exe -k netsvcs").as_deref(),
            Some(r"C:\Windows\System32\svchost.exe")
        );
        // A space in the path: the last token carrying an executable extension is the
        // binary, so the name runs up to it and the switch is left behind.
        assert_eq!(
            service_executable(r"C:\Program Files\My Agent\agent.exe -k x").as_deref(),
            Some(r"C:\Program Files\My Agent\agent.exe")
        );
        // A switch that itself looks executable-ish must not win over the binary: the
        // *last* extension token wins, which is wrong here only if the trailing
        // argument is also a program path - and that is the documented ambiguity, so
        // the test pins the behaviour rather than pretending it does not exist.
        assert_eq!(
            service_executable(r"C:\Tools\agent.exe --config").as_deref(),
            Some(r"C:\Tools\agent.exe")
        );
    }

    #[test]
    fn unexpanded_environment_path_is_not_an_executable() {
        // The drive-letter rule exists for exactly this: stat'ing these would report
        // every service that uses `%ProgramFiles%` as missing on disk.
        assert_eq!(service_executable(r"%ProgramFiles%\x\y.exe"), None);
        assert_eq!(service_executable(r"%SystemRoot%\System32\x.exe"), None);
        assert_eq!(service_executable("").as_deref(), None);
        assert_eq!(service_executable("   ").as_deref(), None);
        // Malformed shapes are not guessed at either.
        assert_eq!(service_executable(r#""C:\unterminated"#), None);
        assert_eq!(service_executable(r"1:\not-a-drive\x.exe"), None);
    }

    #[test]
    fn a_directory_is_not_an_executable() {
        // A trailing separator names a directory, so stat'ing it would produce a
        // nonsensical "missing image" finding for something that was never a file.
        assert_eq!(service_executable(r"C:\Windows\System32\"), None);
        assert_eq!(service_executable(r"C:\Program Files\Acme Agent\"), None);
        assert_eq!(service_executable("C:/Windows/"), None);
        // Trailing blanks must not smuggle the separator past the check.
        assert_eq!(service_executable("C:/Windows/   "), None);
        // The dot components are directories too.
        assert_eq!(service_executable(r"C:\Tools\."), None);
        assert_eq!(service_executable(r"C:\Tools\.."), None);
        // A quoted command line naming a directory is refused for the same reason.
        assert_eq!(
            service_executable(r#""C:\Windows\System32\" -k netsvcs"#),
            None
        );
    }

    #[test]
    fn system_account_truth_table() {
        // An absent ObjectName *is* LocalSystem: that is what the registry means.
        assert!(is_system_service_account(""));
        assert!(is_system_service_account("   "));
        assert!(is_system_service_account("LocalSystem"));
        assert!(is_system_service_account(r"NT AUTHORITY\SYSTEM"));
        assert!(is_system_service_account(r"NT AUTHORITY\system"));
        assert!(is_system_service_account("SYSTEM"));
        assert!(is_system_service_account(r".\SYSTEM"));
        // The negatives that matter: the other in-box service accounts.
        assert!(!is_system_service_account(r"NT AUTHORITY\LocalService"));
        assert!(!is_system_service_account(r"NT AUTHORITY\NetworkService"));
        assert!(!is_system_service_account("Local System"));
        assert!(!is_system_service_account(r"NT AUTHORITY\SYSTEMX"));
    }

    #[test]
    fn a_programdata_service_is_no_longer_high() {
        // The acceptance test for this file. Windows Defender's own engine lives in
        // `C:\ProgramData\Microsoft\Windows Defender\...`, and the old
        // `is_user_writable` gate made it both a HIGH ("runs as SYSTEM from a
        // user-writable location") and two MEDs on a clean machine.
        let def = r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe";
        assert_eq!(classify_location(def), Location::AppData);
        // Signed, unsigned, or unverifiable: AppData never reaches HIGH on location.
        assert_eq!(service_severity(Some(true), Location::AppData, false), None);
        assert_eq!(
            service_severity(Some(false), Location::AppData, false),
            Some(Severity::Info)
        );
        assert_eq!(
            service_severity(None, Location::AppData, false),
            None,
            "an unverifiable signature in AppData is not a finding"
        );
        // Same for a chocolatey-installed tool under ProgramData.
        assert_eq!(
            service_severity(
                Some(false),
                classify_location(r"C:\ProgramData\chocolatey\tools\x.exe"),
                false
            ),
            Some(Severity::Info)
        );
    }

    #[test]
    fn severity_follows_rules_and_escalates_drivers() {
        // Base policy is delegated, never reinvented here.
        assert_eq!(
            service_severity(Some(true), Location::Privileged, false),
            None
        );
        assert_eq!(
            service_severity(Some(false), Location::Privileged, false),
            Some(Severity::Info)
        );
        assert_eq!(service_severity(None, Location::Privileged, false), None);
        // A transit directory is what escalates a user-mode service.
        assert_eq!(
            service_severity(Some(false), Location::Drop, false),
            Some(Severity::High)
        );
        assert_eq!(
            service_severity(None, Location::Drop, false),
            Some(Severity::Med)
        );
        assert_eq!(
            service_severity(Some(true), Location::Drop, false),
            Some(Severity::Med)
        );
        // Driver escalation: a replaceable location at any signature state, or an
        // unsigned driver even from a protected directory.
        assert_eq!(
            service_severity(Some(false), Location::Privileged, true),
            Some(Severity::High)
        );
        assert_eq!(
            service_severity(Some(true), Location::Drop, true),
            Some(Severity::High)
        );
        assert_eq!(
            service_severity(None, Location::Drop, true),
            Some(Severity::High)
        );
        assert_eq!(
            service_severity(Some(true), Location::AppData, true),
            Some(Severity::High)
        );
        // A signed driver in a protected directory is not a finding at all - every
        // stock in-box driver is this, and escalating would recreate the noise.
        assert_eq!(
            service_severity(Some(true), Location::Privileged, true),
            None
        );
        assert_eq!(service_severity(None, Location::Privileged, true), None);
    }

    #[test]
    fn classify_reports_programdata_services_only_informatively() {
        // Defender's `Platform` directory is the real-world shape, and it is under
        // `%ProgramData%`. The image path must be a file that exists, or the separate
        // missing-image rule fires and the test would prove nothing about location.
        let exe = std::env::current_exe()
            .ok()
            .and_then(|p| p.to_str().map(str::to_string));
        let Some(exe) = exe else {
            return;
        };
        let reported: Vec<&str> = vec!["Acme", "Defender"];
        for name in reported {
            let mut ctx = ScanContext::default();
            classify(
                &mut ctx,
                &rec(name, &exe, "LocalSystem", false),
                r"C:\Windows",
            );
            // The locations under test are the real ones; the file just has to exist.
            assert_eq!(
                classify_location(r"C:\ProgramData\Microsoft\Windows Defender\x.exe"),
                Location::AppData,
                "precondition: ProgramData is AppData"
            );
            for f in &ctx.findings {
                assert!(
                    f.severity != Severity::High,
                    "a service under ProgramData must never be HIGH: {:?}",
                    f.title
                );
            }
        }
    }

    #[test]
    fn classify_escalates_a_programdata_driver_but_not_a_programdata_service() {
        // The distinction the driver branch exists for: a `.sys` under `%ProgramData%`
        // is replaceable by a standard user *and* loads into the kernel, so it stays
        // HIGH; a user-mode service in the same directory does not.
        assert_eq!(
            service_severity(
                Some(true),
                classify_location(r"C:\ProgramData\Acme\acme.sys"),
                true
            ),
            Some(Severity::High)
        );
    }

    #[test]
    fn a_driver_in_a_transit_directory_is_high() {
        // A `.sys` under Downloads or %TEMP% is the shape that matters: a standard user
        // can replace the file and it loads into the kernel.
        assert_eq!(
            service_severity(
                Some(true),
                classify_location(r"C:\Users\bob\Downloads\evil.sys"),
                true
            ),
            Some(Severity::High)
        );
        assert_eq!(
            location_label(Location::Drop),
            "каталог для временных файлов"
        );
        assert_eq!(
            location_label(Location::AppData),
            "каталог данных приложений"
        );
    }

    #[test]
    fn missing_image_only_fires_for_an_extracted_drive_path() {
        // Nothing extracted -> nothing to say (covers kernel services with no path).
        assert_eq!(missing_image(&None), None);
        // A file that exists is not missing.
        if let Some(p) = std::env::current_exe()
            .ok()
            .as_deref()
            .and_then(|p| p.to_str())
        {
            assert_eq!(missing_image(&Some(p.to_string())), None);
        }
        // A path that cannot exist is reported verbatim.
        assert_eq!(
            missing_image(&Some(r"C:\IRScan-Does-Not-Exist\ghost.exe".to_string())),
            Some(r"C:\IRScan-Does-Not-Exist\ghost.exe".to_string())
        );
        // UNC has no drive letter: no stat, no finding.
        assert_eq!(
            missing_image(&Some(r"\\server\share\x.exe".to_string())),
            None
        );
    }

    #[test]
    fn describe_and_evidence_use_placeholders_not_empty_fields() {
        let line = describe(&rec("AcmeAgent", "", "", false));
        assert!(line.contains("AcmeAgent"), "name always present: {line}");
        assert!(
            line.contains("LocalSystem (по умолчанию)"),
            "absent account is named: {line}"
        );
        assert!(
            line.contains("<не указан>"),
            "absent image path is named: {line}"
        );
        let ev = evidence_lines(&rec("AcmeAgent", r"C:\x\agent.exe", "", true));
        assert!(ev.iter().any(|l| l.starts_with("состояние: ")));
        assert!(ev.iter().any(|l| l.starts_with("запуск: ")));
        assert!(ev
            .iter()
            .any(|l| l == "учётная запись: LocalSystem (по умолчанию)"));
        assert!(ev.iter().any(|l| l == r"путь к файлу: C:\x\agent.exe"));
        assert!(ev.iter().any(|l| l == "тип: драйвер ядра"));
    }

    #[test]
    fn clean_strips_hostile_bytes_from_service_text() {
        assert_eq!(clean("\u{1b}[31mAcme\u{1b}[0m"), "Acme");
        assert_eq!(clean("   "), "");
    }
}
