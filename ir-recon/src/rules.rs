//! Pure classification and severity policy.
//!
//! This is the **single place** where severity is decided. Collectors describe what
//! they saw; they never get to pick a severity by feel, otherwise the policy becomes
//! untestable and drifts between modules.
//!
//! Nothing here touches the operating system, so the whole module is unit-tested
//! on any host, including Linux CI.

use crate::model::{Finding, Severity, Verdict};

/// Directory markers that indicate a location a normal user (or user-mode malware
/// running as that user) can write to without elevation.
///
/// Legitimate *services* install into `Program Files` or the Windows directory. A
/// service or autostart entry whose image lives under one of these markers is worth
/// reporting even when it is validly signed - per-user installs do exist, but they
/// are unusual and directly relevant here.
/// Locations that are pure transit: nothing legitimate *installs* into them. A binary
/// that lives here got here by being dropped, which is what makes it worth reporting.
const DROP_MARKERS: &[&str] = &[
    "\\temp\\",
    "\\windows\\temp\\",
    "\\users\\public\\",
    "\\downloads\\",
    "\\$recycle.bin\\",
    "\\perflogs\\",
    "\\appdata\\local\\temp\\",
];

/// Application data directories. Legitimate software installs here constantly -
/// per-user installers, package managers, every Electron and Rust and Python tool a
/// developer has - so a binary in one of these is *not* evidence on its own. An
/// earlier version of this tool treated the whole set as suspicious and produced 89
/// high-severity findings on a clean developer machine, which is worse than no report.
const APPDATA_MARKERS: &[&str] = &["\\appdata\\", "\\programdata\\"];

/// Names that belong to core Windows components. Finding one of these outside the
/// Windows directory (or with no image path at all) is a classic masquerading signal.
/// Names a user recognises, which is exactly why they are worth wearing.
///
/// Every entry must be a binary that legitimately lives in `%SystemRoot%`, because the check
/// is "this name, but not from where it belongs". `taskmgr.exe` is the sharpest case: it is
/// the tool someone opens to look for an intruder, so a second copy of it elsewhere is not a
/// coincidence. `rundll32`, `dllhost` and `conhost` are the standard hosts Windows itself
/// uses to run code, which is what makes them attractive to hide behind - and also why a copy
/// outside `%SystemRoot%` has no innocent explanation.
pub const SYSTEM_PROCESS_NAMES: &[&str] = &[
    "svchost.exe",
    "lsass.exe",
    "services.exe",
    "winlogon.exe",
    "csrss.exe",
    "smss.exe",
    "wininit.exe",
    "explorer.exe",
    "taskhostw.exe",
    "dwm.exe",
    "runtimebroker.exe",
    "spoolsv.exe",
    "sihost.exe",
    "ctfmon.exe",
    "fontdrvhost.exe",
    // Four added from kudu's SUSPICIOUS_FILENAMES (MIT) - see the test below.
    "taskmgr.exe",
    "rundll32.exe",
    "dllhost.exe",
    "conhost.exe",
    "taskhost.exe",
];

/// Ports strongly associated with remote-control software, used to label listeners
/// and outbound connections. Deliberately small: a generic port list would drown the
/// report in noise.
pub fn port_label(port: u16) -> Option<&'static str> {
    match port {
        3389 => Some("RDP"),
        5800 | 5900 | 5901 | 5500 => Some("VNC"),
        4899 => Some("Radmin"),
        5938 => Some("TeamViewer"),
        6568 | 7070 => Some("AnyDesk"),
        8040 | 8041 => Some("Ammyy Admin"),
        6129 => Some("DameWare"),
        4000 => Some("NetSupport"),
        4782 => Some("AeroAdmin"),
        _ => None,
    }
}

/// Where a file lives, from a detection standpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Location {
    /// A location only a privileged install writes to: `Program Files`, `Windows`.
    Privileged,
    /// A per-user or per-machine application data directory.
    AppData,
    /// A transit location such as `%TEMP%`, `Downloads` or `Users\Public`.
    Drop,
}

/// Classify a path. An empty or unrecognised path is `Privileged`: the absence of a
/// suspicious location must not itself become the finding.
pub fn classify_location(path: &str) -> Location {
    if path.is_empty() {
        return Location::Privileged;
    }
    let mut lower = path.replace('/', "\\").to_lowercase();
    if !lower.starts_with('\\') {
        lower.insert(0, '\\');
    }

    // Drop is checked first: `%LOCALAPPDATA%\Temp` matches both lists, and the more
    // specific answer is the honest one.
    if DROP_MARKERS.iter().any(|m| lower.contains(m)) {
        return Location::Drop;
    }
    if APPDATA_MARKERS.iter().any(|m| lower.contains(m)) {
        return Location::AppData;
    }
    Location::Privileged
}

/// Does this path sit somewhere that does not require elevation to write to?
///
/// The coarse form of [`classify_location`], kept because a few callers only need the
/// binary question.
pub fn is_user_writable(path: &str) -> bool {
    classify_location(path) != Location::Privileged
}

/// Does a process impersonate a Windows component?
///
/// Returns true when the image name is a known system binary but the image path is
/// empty (the process hides it) or lies outside the Windows directory.
pub fn looks_masquerading(name: &str, path: &str, system_root: &str) -> bool {
    let n = name.to_lowercase();
    if !SYSTEM_PROCESS_NAMES.contains(&n.as_str()) {
        return false;
    }
    if path.trim().is_empty() {
        return true;
    }
    let p = path.replace('/', "\\").to_lowercase();
    let root = system_root.replace('/', "\\").to_lowercase();
    if root.is_empty() {
        return false;
    }
    !p.starts_with(&root)
}

/// Severity for something that executes (a service, a scheduled task, an autostart
/// entry). `trusted` is `None` when signature verification could not be attempted.
///
/// Returns `None` when the location and signature give no reason to report it.
pub fn execution_severity(trusted: Option<bool>, location: Location) -> Option<Severity> {
    match (location, trusted) {
        // There is no innocent explanation for an unsigned binary executing out of a
        // transit directory. This is the one combination that earns HIGH on a single
        // signal.
        (Location::Drop, Some(false)) => Some(Severity::High),
        // Could not verify, and it is in a place nothing installs to: worth a look.
        (Location::Drop, None) => Some(Severity::Med),
        // Signed but running from a transit directory is still unusual.
        (Location::Drop, Some(true)) => Some(Severity::Med),

        // Application data is where per-user software installs. Reporting it as HIGH
        // is how a tool becomes noise, so it is informational unless something else
        // in the report corroborates it.
        (Location::AppData, Some(false)) => Some(Severity::Info),
        (Location::AppData, _) => None,

        // Unsigned in a privileged location is common and not actionable: an msys64
        // tree, an in-house tool and a game installed under Program Files all look
        // like this. It stays in the report as information - an earlier version called
        // it MEDIUM and produced 42 of them on a clean developer machine - because
        // "unsigned" alone is not evidence, and a reader who learns to skip a MEDIUM
        // section will skip a real one.
        (Location::Privileged, Some(false)) => Some(Severity::Info),
        (Location::Privileged, _) => None,
    }
}

/// Severity for an active outbound connection.
///
/// Deliberately narrow. An earlier version flagged every public connection from a
/// user-writable process and produced 113 findings on a normal machine - Telegram,
/// a torrent client and the agent harness itself - which buried everything that
/// mattered. A connection is only a finding when the *location* is wrong or the owner
/// is gone:
///
/// * a transit directory (High - a dropped binary phoning home),
/// * no owning process at all (Med - a socket held by something that has exited).
pub fn connection_severity(
    public: bool,
    location: Location,
    owner_known: bool,
) -> Option<Severity> {
    if !public {
        return None;
    }
    if location == Location::Drop {
        return Some(Severity::High);
    }
    if !owner_known {
        return Some(Severity::Med);
    }
    None
}

/// Private / non-routable address, including loopback, link-local and documentation
/// ranges. Unparseable input is reported as public: better a noisy line than a silent
/// miss of the one address that matters.
pub fn is_private_ip(ip: &str) -> bool {
    let ip = ip.trim();
    if ip.is_empty() || ip == "-" || ip == "*" {
        return true;
    }
    let ip = ip.strip_prefix("::ffff:").unwrap_or(ip);

    if ip.contains(':') {
        let l = ip.to_lowercase();
        return l == "::1"
            || l.starts_with("fe80")
            || l.starts_with("fc")
            || l.starts_with("fd")
            || l.starts_with("2001:db8")
            || l.starts_with("::");
    }

    let mut o = [0u8; 4];
    let mut n = 0usize;
    for part in ip.split('.') {
        match part.parse::<u8>() {
            Ok(v) if n < 4 => {
                o[n] = v;
                n += 1;
            }
            _ => return false,
        }
    }
    if n != 4 {
        return false;
    }

    o[0] == 10
        || o[0] == 127
        || (o[0] == 169 && o[1] == 254)
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || o[0] == 0
}

/// Expand `%VAR%` references using a caller-supplied, case-insensitive variable set.
///
/// Pure on purpose: the real environment is supplied by `win`, so this stays testable.
/// An unknown `%VAR%` is left untouched - never silently deleted, because a deleted
/// segment would make a path look like something it is not.
pub fn expand_env(input: &str, vars: &[(&str, &str)]) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;

    while i < chars.len() {
        if chars[i] == '%' {
            if let Some(offset) = chars[i + 1..].iter().position(|c| *c == '%') {
                let key: String = chars[i + 1..i + 1 + offset].iter().collect();
                if let Some((_, value)) = vars.iter().find(|(k, _)| k.eq_ignore_ascii_case(&key)) {
                    out.push_str(value);
                    i = i + offset + 2;
                    continue;
                }
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Aggregate finding counts into a verdict plus the honest remediation playbook.
pub fn verdict(findings: &[Finding], warnings: usize) -> Verdict {
    let mut high = 0usize;
    let mut med = 0usize;
    let mut info = 0usize;
    for f in findings {
        match f.severity {
            Severity::High => high += 1,
            Severity::Med => med += 1,
            Severity::Info => info += 1,
        }
    }

    let headline = if high > 0 {
        format!(
            "{high} находок уровня \"критично\": это прямые признаки скрытого наблюдения \
             или удалённого управления."
        )
    } else if med > 0 {
        format!(
            "{med} находок требуют ручной проверки; по отдельности ни одна из них \
             ничего не доказывает."
        )
    } else {
        "Ничего подозрительного этими проверками не найдено. Это НЕ доказывает, что машина \
         чиста: rootkit в режиме ядра или переименованный агент без следов в реестре не \
         видны ни одному из опрошенных интерфейсов пользовательского режима."
            .to_string()
    };

    let mut headline = headline;
    if warnings > 0 {
        headline.push_str(&format!(
            " ({warnings} проверок не выполнилось - часть данных отсутствует, см. отчёт.)"
        ));
    }

    let recommendation = vec![
        "Сначала отключите машину от сети: это сразу остановит выгрузку экрана и удалённое \
         управление и при этом не уничтожит ни одного локального следа."
            .to_string(),
        "Пока ничего не удаляйте. Скопируйте отчёт вместе со строками доказательств на \
         внешний носитель."
            .to_string(),
        "Если опознан известный продукт наблюдения или удалённого доступа, удаляйте его \
         штатным деинсталлятором этого продукта (некоторые требуют пароль удаления от \
         того, кто их устанавливал)."
            .to_string(),
        "Если найден неизвестный агент - в первую очередь неподписанный файл в доступной \
         на запись папке с активным исходящим соединением - считайте машину полностью \
         скомпрометированной. Надёжно убрать современный RAT позволяет только чистая \
         переустановка системы с внешнего носителя."
            .to_string(),
        "Смените все пароли с ДРУГОГО, заведомо чистого устройства, начиная с почты: \
         именно почта служит каналом сброса для всего остального. Включите двухфакторную \
         аутентификацию и отзовите активные сессии и токены."
            .to_string(),
        "Проверьте роутер (пароль администратора, прошивку, проброс портов) и все \
         остальные устройства в сети."
            .to_string(),
        "После устранения запустите проверку заново и сравните отчёты: те же находки \
         снова означают, что механизм закрепления уцелел."
            .to_string(),
    ];

    Verdict {
        high,
        med,
        info,
        headline,
        recommendation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Finding;

    #[test]
    fn drop_locations_are_recognised() {
        assert_eq!(
            classify_location(r"C:\Users\bob\AppData\Local\Temp\x.exe"),
            Location::Drop
        );
        assert_eq!(
            classify_location(r"C:\Windows\Temp\svc.exe"),
            Location::Drop
        );
        assert_eq!(
            classify_location("c:/users/bob/downloads/payload.exe"),
            Location::Drop
        );
        assert_eq!(classify_location(r"C:\Users\Public\a.exe"), Location::Drop);
        // More specific than AppData: LocalAppData\Temp is both, and Drop wins.
        assert_eq!(
            classify_location(r"C:\Users\bob\AppData\Local\Temp\deep\x"),
            Location::Drop
        );
    }

    #[test]
    fn application_data_is_not_treated_as_suspicious() {
        // The distinction that removed 89 false HIGH findings: this is where per-user
        // software legitimately installs.
        assert_eq!(
            classify_location(r"C:\Users\bob\AppData\Local\Programs\x\app.exe"),
            Location::AppData
        );
        assert_eq!(
            classify_location(r"C:\ProgramData\chocolatey\tools\7z.exe"),
            Location::AppData
        );
        assert_eq!(
            classify_location(r"C:\ProgramData\Agent\agent.exe"),
            Location::AppData
        );
    }

    #[test]
    fn privileged_locations_are_the_default() {
        assert_eq!(
            classify_location(r"C:\Program Files\Vendor\svc.exe"),
            Location::Privileged
        );
        assert_eq!(
            classify_location(r"C:\Windows\System32\svchost.exe"),
            Location::Privileged
        );
        assert_eq!(classify_location(""), Location::Privileged);
        // "Temperature" must not be mistaken for "\temp\".
        assert_eq!(
            classify_location(r"C:\Program Files\Temperature\app.exe"),
            Location::Privileged
        );
    }

    #[test]
    fn execution_policy_needs_the_right_location_to_raise_high() {
        // Only a transit directory earns High without corroboration.
        assert_eq!(
            execution_severity(Some(false), Location::Drop),
            Some(Severity::High)
        );
        assert_eq!(
            execution_severity(None, Location::Drop),
            Some(Severity::Med)
        );
        assert_eq!(
            execution_severity(Some(true), Location::Drop),
            Some(Severity::Med)
        );
        // Application data is informational at most - the lesson from the 89.
        assert_eq!(
            execution_severity(Some(false), Location::AppData),
            Some(Severity::Info)
        );
        assert_eq!(execution_severity(Some(true), Location::AppData), None);
        assert_eq!(execution_severity(None, Location::AppData), None);
        // Privileged: unsigned is information, not a warning.
        assert_eq!(
            execution_severity(Some(false), Location::Privileged),
            Some(Severity::Info)
        );
        assert_eq!(execution_severity(Some(true), Location::Privileged), None);
    }

    #[test]
    fn connection_policy_reports_only_a_wrong_location_or_a_missing_owner() {
        // A normal application talking to the internet is not a finding.
        assert_eq!(connection_severity(true, Location::AppData, true), None);
        assert_eq!(connection_severity(true, Location::Privileged, true), None);
        // Private addresses are never findings.
        assert_eq!(connection_severity(false, Location::Drop, true), None);
        // A dropped binary phoning home is the case worth shouting about.
        assert_eq!(
            connection_severity(true, Location::Drop, true),
            Some(Severity::High)
        );
        // A socket whose owner has exited is worth a note.
        assert_eq!(
            connection_severity(true, Location::AppData, false),
            Some(Severity::Med)
        );
    }

    #[test]
    fn masquerade_covers_the_names_malware_hides_behind() {
        // The list started from the processes a user sees in Task Manager and was extended
        // from kudu's SUSPICIOUS_FILENAMES table (MIT), which collects the same idea
        // independently. The four added were missing and matter in practice:
        // `taskmgr.exe` because it is the very tool someone opens to hunt an intruder,
        // and `rundll32.exe`, `dllhost.exe` and `conhost.exe` because all three are
        // legitimate System32 binaries that are also standard hosts for a hostile payload,
        // so a copy of any of them outside `%SystemRoot%` has no innocent reading.
        const HOSTILE: &str = r"C:\Users\bob\AppData\Local\Temp\x.exe";

        for name in [
            "taskmgr.exe",
            "rundll32.exe",
            "dllhost.exe",
            "conhost.exe",
            "taskhost.exe",
        ] {
            // Outside %SystemRoot%: a finding.
            assert!(
                looks_masquerading(name, HOSTILE, r"C:\Windows"),
                "{name} outside %SystemRoot% must be treated as masquerading"
            );

            // In its real home: not a finding. These are system binaries that run from
            // System32 on every machine, and reporting them would be pure noise.
            let real = format!(r"C:\Windows\System32\{name}");
            assert!(
                looks_masquerading(name, &real, r"C:\Windows").eq(&false),
                "{name} in System32 must not be reported"
            );
        }
    }

    #[test]
    fn masquerade_flags_system_names_outside_windows() {
        assert!(looks_masquerading(
            "svchost.exe",
            r"C:\Users\bob\AppData\Roaming\svchost.exe",
            r"C:\Windows"
        ));
        assert!(looks_masquerading("lsass.exe", "", r"C:\Windows"));
        assert!(!looks_masquerading(
            "svchost.exe",
            r"C:\Windows\System32\svchost.exe",
            r"C:\Windows"
        ));
        assert!(!looks_masquerading(
            "chrome.exe",
            r"C:\Users\bob\AppData\Local\Google\chrome.exe",
            r"C:\Windows"
        ));
    }

    #[test]
    fn private_ip_classification() {
        assert!(is_private_ip("10.0.0.5"));
        assert!(is_private_ip("192.168.1.10"));
        assert!(is_private_ip("172.20.3.4"));
        assert!(is_private_ip("127.0.0.1"));
        assert!(is_private_ip("169.254.1.1"));
        assert!(is_private_ip("::1"));
        assert!(is_private_ip("::ffff:192.168.0.1"));
        assert!(is_private_ip(""));
        assert!(!is_private_ip("8.8.8.8"));
        assert!(!is_private_ip("172.32.0.1"));
        assert!(!is_private_ip("203.0.113.7"));
        // Unparseable input is treated as public so it still gets reported.
        assert!(!is_private_ip("not-an-ip"));
    }

    #[test]
    fn expand_env_is_case_insensitive_and_preserves_unknown_vars() {
        let vars = [
            ("ProgramData", r"C:\ProgramData"),
            ("APPDATA", r"C:\Users\b\AppData"),
        ];
        assert_eq!(
            expand_env(r"%programdata%\AnyDesk\ad_svc.trace", &vars),
            r"C:\ProgramData\AnyDesk\ad_svc.trace"
        );
        assert_eq!(
            expand_env(r"%AppData%\AnyDesk\ad.trace", &vars),
            r"C:\Users\b\AppData\AnyDesk\ad.trace"
        );
        assert_eq!(expand_env(r"%NOPE%\x", &vars), r"%NOPE%\x");
        assert_eq!(expand_env("plain", &vars), "plain");
    }

    #[test]
    fn port_labels_cover_the_classic_remote_control_ports() {
        assert_eq!(port_label(3389), Some("RDP"));
        assert_eq!(port_label(5938), Some("TeamViewer"));
        assert_eq!(port_label(6568), Some("AnyDesk"));
        assert_eq!(port_label(443), None);
        assert_eq!(port_label(80), None);
    }

    #[test]
    fn verdict_counts_and_headline() {
        let findings = vec![
            Finding::new(Severity::High, "cat", "a"),
            Finding::new(Severity::Med, "cat", "b"),
            Finding::new(Severity::Info, "cat", "c"),
        ];
        let v = verdict(&findings, 0);
        assert_eq!((v.high, v.med, v.info), (1, 1, 1));
        assert!(v.headline.contains("критично"));
        assert!(v.recommendation.len() >= 5);
    }

    #[test]
    fn verdict_without_high_does_not_alarm() {
        let v = verdict(&[Finding::new(Severity::Med, "cat", "b")], 0);
        assert!(v.headline.contains("ручной проверки"));
        assert!(!v.headline.contains("критично"));
    }

    #[test]
    fn clean_verdict_states_its_own_limits() {
        let v = verdict(&[], 0);
        assert!(
            v.headline.contains("НЕ доказывает"),
            "must not claim the host is clean"
        );
        assert_eq!((v.high, v.med, v.info), (0, 0, 0));
    }

    #[test]
    fn warnings_are_surfaced_in_the_headline() {
        let v = verdict(&[], 2);
        assert!(v.headline.contains("2 проверок не выполнилось"));
    }
}
