//! Remote-access configuration - the ways into this machine (FR-9).
//!
//! This collector reports **configuration, not activity**. The question it answers
//! is "does this host offer a way in?", which is what separates a locked-down
//! workstation from one an operator can return to at will. Activity (the 4624 type
//! 10 logons, the TerminalServices 1149 events) is the events collector's job; the
//! two are read together.
//!
//! The checks, deliberately all read-only registry and service state:
//!
//! * `fDenyTSConnections = 0` - Remote Desktop accepts connections;
//! * `fAllowToGetHelp` non-zero - Remote Assistance is on, which lets another person
//!   drive the session;
//! * a WinRM basic-auth policy or an existing WinRM listener configuration;
//! * anything **listening on 3389** - the concrete proof that RDP is live, not just
//!   permitted, named with its owning process;
//! * `sshd` and `RemoteRegistry` **running** - both are unusual on a home machine and
//!   both are ways in;
//! * the state of `TermService`, `WinRM`, `sshd` and `RemoteRegistry`, so a reader can
//!   see the full picture even when nothing is wrong.
//!
//! A missing registry value is `None`, never an error: on a machine where the key does
//! not exist, the feature does not exist either.

use std::ops::Not;

use crate::collect::{CollectError, Collector};
use crate::model::{ConnectionRecord, Finding, HaystackKind, ScanContext, Severity};
use crate::win::reg::{self, RootKey};

/// Terminal Server configuration key.
const TERMINAL_SERVER: &str = r"SYSTEM\CurrentControlSet\Control\Terminal Server";
/// Remote Assistance configuration key.
const REMOTE_ASSISTANCE: &str = r"SYSTEM\CurrentControlSet\Control\Remote Assistance";
/// WinRM service policy key (where `AllowBasic` lives).
const WINRM_POLICY: &str = r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service";
/// WinRM listener configuration - present once WinRM has been set up.
const WSMAN_SERVICE: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service";

/// The RDP listener port. Distinctive enough to name directly (FR-9).
const RDP_PORT: u16 = 3389;

/// Services whose state is always reported.
const REPORTED_SERVICES: &[&str] = &["TermService", "WinRM", "sshd", "RemoteRegistry"];

/// Severity for the `fDenyTSConnections` value.
///
/// `Some(Med)` only for `0`, which explicitly *permits* Remote Desktop. Absent means
/// the feature was never configured, and any non-zero value denies connections - both
/// return `None`. `Some(1)` must stay quiet or every Windows machine would be flagged.
pub fn rdp_enabled(f_deny_ts_connections: Option<u64>) -> Option<Severity> {
    match f_deny_ts_connections {
        Some(0) => Some(Severity::Med),
        _ => None,
    }
}

/// Severity for the `fAllowToGetHelp` value: any non-zero value enables Remote
/// Assistance. Absent or `0` is quiet.
pub fn remote_assistance_severity(value: Option<u64>) -> Option<Severity> {
    match value {
        Some(v) if v > 0 => Some(Severity::Med),
        _ => None,
    }
}

/// Is this connection a listener on `port`?
///
/// The endpoint is compared by its trailing `:port`, colon-anchored, so
/// `0.0.0.0:3389`, `[::]:3389` and `127.0.0.1:3389` all match while `:13389` and a
/// bare `3389` cannot slip in.
fn is_listener_on(connection: &ConnectionRecord, port: u16) -> bool {
    if connection.state.eq_ignore_ascii_case("listening").not() {
        return false;
    }
    connection.local.ends_with(&format!(":{port}"))
}

/// Describe every connection listening on `port`, as `"<local> (pid <pid>)"`.
///
/// Pure, so the matching rules are testable without a host. Duplicates are collapsed:
/// a dual-stack listener reports the same PID on IPv4 and IPv6, and two identical
/// lines add nothing.
pub fn listening_on(connections: &[ConnectionRecord], port: u16) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for connection in connections {
        if is_listener_on(connection, port).not() {
            continue;
        }
        let line = format!("{} (pid {})", connection.local, connection.pid);
        if out.contains(&line).not() {
            out.push(line);
        }
    }
    out
}

/// Services that have no business running on an ordinary workstation.
///
/// Running `sshd` means a remote shell can be opened; running `RemoteRegistry` lets a
/// remote user read this machine's registry. Neither is a default, so their being
/// **running** is the signal - installed-and-stopped is not.
fn is_unusual_running_service(name: &str) -> bool {
    name.eq_ignore_ascii_case("sshd") || name.eq_ignore_ascii_case("RemoteRegistry")
}

/// Report remote-access configuration.
pub struct RemoteAccessCollector;

impl Collector for RemoteAccessCollector {
    fn name(&self) -> &'static str {
        "remote_access"
    }

    fn run(&self, ctx: &mut ScanContext) -> Result<(), CollectError> {
        let mut lines: Vec<String> = Vec::new();

        // --- Remote Desktop -----------------------------------------------------
        let deny = reg::get_u64(RootKey::Hklm, TERMINAL_SERVER, "fDenyTSConnections");
        ctx.note(HaystackKind::RegistryPath, TERMINAL_SERVER, "remote access");
        lines.push(format!(
            "HKLM\\{TERMINAL_SERVER}\\fDenyTSConnections = {}",
            describe(deny)
        ));
        if let Some(severity) = rdp_enabled(deny) {
            ctx.add(
                Finding::new(severity, "remote_access", "Включён удалённый рабочий стол")
                    .evidence(format!(
                        "HKLM\\{TERMINAL_SERVER}\\fDenyTSConnections = 0: машина принимает \
                         подключения по удалённому рабочему столу."
                    ))
                    .remediation(
                        "Если удалённый рабочий стол на этой машине никому не нужен, отключите \
                         его: Параметры > Система > Удалённый рабочий стол, либо задайте \
                         fDenyTSConnections = 1. Если он нужен, проверьте все учётные записи, \
                         которым разрешён вход через него.",
                    ),
            );
        } else if deny.is_none() {
            lines.push(
                "  (значение отсутствует: удалённый рабочий стол не настраивался)".to_string(),
            );
        }

        // --- Remote Assistance --------------------------------------------------
        let help = reg::get_u64(RootKey::Hklm, REMOTE_ASSISTANCE, "fAllowToGetHelp");
        ctx.note(
            HaystackKind::RegistryPath,
            REMOTE_ASSISTANCE,
            "remote access",
        );
        lines.push(format!(
            "HKLM\\{REMOTE_ASSISTANCE}\\fAllowToGetHelp = {}",
            describe(help)
        ));
        if let Some(severity) = remote_assistance_severity(help) {
            ctx.add(
                Finding::new(severity, "remote_access", "Включён удалённый помощник")
                    .evidence(format!(
                        "HKLM\\{REMOTE_ASSISTANCE}\\fAllowToGetHelp = {}: кто-то может \
                         предложить просмотр или управление этим сеансом.",
                        describe(help)
                    ))
                    .remediation(
                        "Если эту машину так не поддерживают постоянно, отключите удалённого \
                         помощника в разделе «Свойства системы» > «Удалённые сеансы».",
                    ),
            );
        }

        // --- WinRM --------------------------------------------------------------
        let allow_basic = reg::get_u64(RootKey::Hklm, WINRM_POLICY, "AllowBasic");
        let wsman_present = reg::key_exists(RootKey::Hklm, WSMAN_SERVICE);
        ctx.note(HaystackKind::RegistryPath, WINRM_POLICY, "remote access");
        if wsman_present {
            ctx.note(HaystackKind::RegistryPath, WSMAN_SERVICE, "remote access");
        }
        lines.push(format!(
            "HKLM\\{WINRM_POLICY}\\AllowBasic = {}",
            describe(allow_basic)
        ));
        lines.push(format!(
            "HKLM\\{WSMAN_SERVICE}: {}",
            if wsman_present {
                "присутствует"
            } else {
                "отсутствует"
            }
        ));
        let basic_allowed = matches!(allow_basic, Some(value) if value > 0);
        if basic_allowed || wsman_present {
            ctx.add(
                Finding::new(
                    Severity::Med,
                    "remote_access",
                    "Настроено удалённое управление через WinRM",
                )
                .evidence(format!(
                    "AllowBasic = {}; конфигурация прослушивателя WinRM {}",
                    describe(allow_basic),
                    if wsman_present {
                        "присутствует"
                    } else {
                        "отсутствует"
                    }
                ))
                .evidence(
                    "WinRM (Windows Remote Management) позволяет другой машине выполнять здесь \
                     команды по HTTP(S).",
                )
                .remediation(
                    "Если WinRM не используется для управления, остановите и отключите службу \
                     WinRM и удалите прослушиватель (winrm delete winrm/config/Listener). \
                     Отключение одной только обычной проверки подлинности доступ не убирает.",
                ),
            );
        }

        // --- Listening 3389 -----------------------------------------------------
        // Prefer the connection table the connection collector already built; fall
        // back to asking iphlpapi directly, because this collector must not depend on
        // another collector's ordering.
        let fetched;
        let connections: &[ConnectionRecord] = if ctx.connections.is_empty() {
            fetched = crate::win::net::tcp_connections();
            fetched.as_slice()
        } else {
            ctx.connections.as_slice()
        };

        let listeners = listening_on(connections, RDP_PORT);
        if listeners.is_empty() {
            lines.push(format!("нет прослушивателя на порту {RDP_PORT}"));
        } else {
            for listener in &listeners {
                lines.push(format!("прослушивается {RDP_PORT}: {listener}"));
            }
            let mut evidence: Vec<String> = Vec::new();
            for connection in connections {
                if is_listener_on(connection, RDP_PORT) {
                    let process = ctx
                        .process_name(connection.pid)
                        .unwrap_or("неизвестный процесс");
                    evidence.push(format!(
                        "{} прослушивается, владелец pid {} ({})",
                        connection.local, connection.pid, process
                    ));
                }
            }
            evidence.dedup();
            let mut finding = Finding::new(
                Severity::Med,
                "remote_access",
                format!("Порт {RDP_PORT} прослушивается (удалённый рабочий стол)"),
            );
            for line in evidence {
                finding = finding.evidence(line);
            }
            ctx.add(finding.remediation(
                "Удалённый рабочий стол не просто разрешён, он работает. Убедитесь, что процесс \
                 — это svchost/TermService, и, если RDP не нужен, остановите прослушиватель и \
                 задайте fDenyTSConnections = 1.",
            ));
        }

        // --- Service state ------------------------------------------------------
        match crate::win::services::enum_services() {
            Ok(services) => {
                for wanted in REPORTED_SERVICES {
                    let found = services
                        .iter()
                        .find(|service| service.name.eq_ignore_ascii_case(wanted));
                    let Some(service) = found else {
                        lines.push(format!("служба {wanted}: отсутствует"));
                        continue;
                    };
                    ctx.note(
                        HaystackKind::ServiceName,
                        service.name.clone(),
                        "remote-access service",
                    );
                    lines.push(format!(
                        "служба {:<16} state={:<10} start={:<10} {}",
                        service.name, service.state, service.start_mode, service.image_path
                    ));
                    if service.state.eq_ignore_ascii_case("running")
                        && is_unusual_running_service(wanted)
                    {
                        ctx.add(
                            Finding::new(
                                Severity::Med,
                                "remote_access",
                                format!("Служба {} запущена", service.name),
                            )
                            .evidence(format!(
                                "служба {} ({}), состояние={}, запуск={}",
                                service.display_name,
                                service.name,
                                service.state,
                                service.start_mode
                            ))
                            .evidence(
                                "Эта служба не работает на обычной рабочей станции Windows, \
                                 а sshd и RemoteRegistry — это способы попасть внутрь.",
                            )
                            .remediation(
                                "Если удалённый доступ не нужен, остановите и отключите службу \
                                 и уточните у владельца машины, кто её установил.",
                            ),
                        );
                    }
                }
            }
            Err(e) => ctx.warn(format!("remote_access: не удалось перечислить службы: {e}")),
        }

        ctx.raw_section("REMOTE ACCESS", lines);
        Ok(())
    }
}

/// Render an optional registry number for the raw table: the number, or "absent".
fn describe(value: Option<u64>) -> String {
    match value {
        Some(n) => n.to_string(),
        None => "отсутствует".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connection(local: &str, state: &str, pid: u32) -> ConnectionRecord {
        ConnectionRecord {
            protocol: "tcp",
            local: local.to_string(),
            remote: "*:*".to_string(),
            state: state.to_string(),
            pid,
        }
    }

    #[test]
    fn rdp_enabled_only_for_zero() {
        assert_eq!(rdp_enabled(None), None, "absent feature is not enabled");
        assert_eq!(rdp_enabled(Some(0)), Some(Severity::Med));
        assert_eq!(rdp_enabled(Some(1)), None, "1 denies connections");
        assert_eq!(rdp_enabled(Some(2)), None, "any other value stays quiet");
    }

    #[test]
    fn remote_assistance_nonzero_is_med() {
        assert_eq!(remote_assistance_severity(None), None);
        assert_eq!(remote_assistance_severity(Some(0)), None);
        assert_eq!(remote_assistance_severity(Some(1)), Some(Severity::Med));
    }

    #[test]
    fn listening_on_matches_only_the_listening_port() {
        let connections = vec![
            connection("0.0.0.0:3389", "listening", 4),
            connection("[::]:3389", "listening", 4),
            connection("10.0.0.5:3389", "established", 1234),
            connection("0.0.0.0:13389", "listening", 77),
            connection("0.0.0.0:22", "listening", 900),
            connection("3389", "listening", 5),
        ];
        let listeners = listening_on(&connections, 3389);
        assert_eq!(
            listeners,
            vec![
                "0.0.0.0:3389 (pid 4)".to_string(),
                "[::]:3389 (pid 4)".to_string()
            ]
        );
    }

    #[test]
    fn listening_on_is_case_insensitive_and_deduplicates() {
        let connections = vec![
            connection("0.0.0.0:3389", "LISTENING", 7),
            connection("0.0.0.0:3389", "listening", 7),
        ];
        assert_eq!(
            listening_on(&connections, 3389),
            vec!["0.0.0.0:3389 (pid 7)".to_string()]
        );
    }

    #[test]
    fn listening_on_handles_empty_input() {
        assert!(listening_on(&[], 3389).is_empty());
    }

    #[test]
    fn describe_absent_is_not_zero() {
        assert_eq!(describe(None), "отсутствует");
        assert_eq!(describe(Some(0)), "0");
    }
}
