//! Local-account policy and findings: the interpretation half of FR-8.
//!
//! The raw enumeration lives in [`crate::win::accounts`]; this module decides what
//! is worth reporting and why. The signals, in descending order of confidence:
//!
//! * an **enabled** built-in Guest or DefaultAccount (RID 501 / 503) - High. Both ship disabled, so an
//!   enabled one was switched on deliberately, and a guest session needs no password
//!   and leaves almost no trace;
//! * an account whose password is explicitly **not required** - High. This is the
//!   single most reliable "someone made a way in" flag in the SAM database;
//! * an **administrator with no descriptive fields** - Med. A newly created backdoor
//!   account is usually bare, but most admin accounts are not, so this is only Med:
//!   reporting it loudly would teach the user to ignore the report;
//! * an enabled administrator that has **never logged on** - Med. An account created
//!   for later use.
//!
//! Every account name is pushed as a [`HaystackKind::ProductName`] so the signature
//! pass can match a vendor-managed account (a remote-support product creating
//! `AnyDesk-User` is exactly the case FR-15 exists for).

use std::ops::Not;

use crate::collect::{CollectError, Collector};
use crate::model::{Finding, HaystackKind, ScanContext, Severity};
use crate::win::accounts::{
    local_accounts, used_level_2_fallback, LocalAccount, RID_DEFAULT_ACCOUNT, RID_GUEST,
};

/// Enabled, and either the Guest account or the (normally disabled) DefaultAccount.
///
/// This is the top-priority condition: it is a deliberate change to a shipped-with-
/// Windows account, not an application's installer choosing a name.
///
/// Identity comes from the **RID** (501 Guest, 503 DefaultAccount), never from the
/// name, because Windows localises those names - on a Russian install the built-in
/// Guest is `Гость` and an English-only check would miss exactly the account this
/// rule exists to catch. The name check remains only as a fallback for an account
/// whose SID could not be read.
pub fn is_enabled_builtin_guest(account: &LocalAccount) -> bool {
    if account.enabled.not() {
        return false;
    }
    if account.is_guest {
        return true;
    }
    match account.rid {
        Some(rid) => rid == RID_GUEST || rid == RID_DEFAULT_ACCOUNT,
        // No SID: fall back to the English spelling, which is the only name available.
        None => account.name.eq_ignore_ascii_case("DefaultAccount"),
    }
}

/// An enabled administrator that has never logged on.
///
/// `None` last logon on an admin account is worth a look; on a brand-new machine the
/// built-in Administrator also matches, which is why this is Med and not High.
///
/// Caveat worth stating in the report rather than hiding: `NetUserEnum`'s
/// `last_logon` is only updated by *network* logons, so an interactive-only account
/// reads as "never" on a machine it is used every day. The finding says "this
/// account has no recorded network logon", which is exactly what the field means,
/// and the evidence prints the raw value rather than asserting more than that.
pub fn never_logged_on_admin(account: &LocalAccount) -> bool {
    account.enabled && account.is_admin && account.last_logon_days.is_none()
}

/// An enabled administrator carrying neither a description nor a full name.
///
/// Both fields must be empty. Windows' built-in Administrator always has a
/// description, so requiring both keeps this signal pointed at accounts that were
/// **created**, while the alias accounts ordinary software makes usually carry at
/// least a comment. That is the difference between a signal and crying wolf.
pub fn should_flag_admin_without_description(account: &LocalAccount) -> bool {
    account.enabled
        && account.is_admin
        && account.comment.trim().is_empty()
        && account.full_name.trim().is_empty()
}

/// An enabled account that can be used without a password.
///
/// `enabled` is part of the condition on purpose. Windows ships `DefaultAccount` and
/// the built-in `Guest` **disabled** and with `UF_PASSWD_NOTREQD` set, so a check that
/// ignored `enabled` would report both on every clean machine as an open door - the
/// exact "cry wolf" failure that teaches a user to ignore the report. A disabled
/// account is not a way in.
pub fn is_passwordless_and_enabled(account: &LocalAccount) -> bool {
    account.enabled && account.password_required.not()
}

/// The single severity decision for one account, or `None` when nothing is wrong.
///
/// Disabled accounts are quiet unless they are a built-in that should not exist in
/// that state; an enabled account is reported for the High signals first, then Med.
pub fn account_severity(account: &LocalAccount) -> Option<Severity> {
    if is_enabled_builtin_guest(account) {
        return Some(Severity::High);
    }
    if is_passwordless_and_enabled(account) {
        return Some(Severity::High);
    }
    if should_flag_admin_without_description(account) {
        return Some(Severity::Med);
    }
    if never_logged_on_admin(account) {
        return Some(Severity::Med);
    }
    None
}

/// Human label for a "days ago" figure. `None` is "never", never "0 days ago".
pub fn days_to_label(days: Option<u32>) -> String {
    match days {
        None => "never".to_string(),
        Some(0) => "today".to_string(),
        Some(1) => "1 day ago".to_string(),
        Some(n) => format!("{n} days ago"),
    }
}

/// Enumerate local accounts and report the ones that are ways in or ways to stay in.
pub struct AccountsCollector;

impl Collector for AccountsCollector {
    fn name(&self) -> &'static str {
        "accounts"
    }

    fn run(&self, ctx: &mut ScanContext) -> Result<(), CollectError> {
        let accounts = local_accounts().map_err(|e| CollectError::new("accounts", e))?;
        if used_level_2_fallback() {
            // Not a failure: the account list is complete, but without the SID the
            // built-in-account check can only match the English (and Russian) names,
            // so a localised install could hide an enabled Guest from this run.
            ctx.warn(
                "accounts: USER_INFO_4 was unavailable, so account SIDs could not be read;                  built-in accounts are matched by name only",
            );
        }

        let mut lines: Vec<String> = Vec::new();
        lines.push(format!(
            "{:<24} {:<8} {:<6} {:<6} {:<14} {:<8}",
            "name", "enabled", "admin", "guest", "last logon", "password"
        ));
        lines.push(format!("{} local account(s)", accounts.len()));

        for account in &accounts {
            // Names are haystacks, not findings: the signature pass owns the
            // decision of whether a name is a known product (FR-15).
            ctx.note(
                HaystackKind::ProductName,
                account.name.clone(),
                "local account name",
            );
            if account.full_name.is_empty().not() {
                ctx.note(
                    HaystackKind::ProductName,
                    account.full_name.clone(),
                    "local account full name",
                );
            }

            lines.push(format!(
                "{:<24} {:<8} {:<6} {:<6} {:<14} {:<8}",
                account.name,
                account.enabled,
                account.is_admin,
                account.is_guest,
                days_to_label(account.last_logon_days),
                account.password_required,
            ));

            let Some(severity) = account_severity(account) else {
                continue;
            };

            let mut reasons: Vec<String> = Vec::new();
            if is_enabled_builtin_guest(account) {
                reasons.push("the account is enabled but ships disabled on Windows".to_string());
            }
            if is_passwordless_and_enabled(account) {
                reasons.push("a password is not required to use it".to_string());
            }
            if should_flag_admin_without_description(account) {
                reasons.push("it is an administrator with no description or full name".to_string());
            }
            if never_logged_on_admin(account) {
                reasons.push(
                    "it is an enabled administrator with no recorded logon (NetAPI updates this \
                     field on network logons only, so an interactively-used account also \
                     reads as never)"
                        .to_string(),
                );
            }

            let detail = if account.comment.is_empty() {
                String::new()
            } else {
                format!(" - {}", account.comment)
            };

            let mut finding = Finding::new(
                severity,
                "accounts",
                format!("Local account: {}{}", account.name, detail),
            )
            .evidence(format!(
                "enabled={} admin={} guest={} last logon={} password required={}",
                account.enabled,
                account.is_admin,
                account.is_guest,
                days_to_label(account.last_logon_days),
                account.password_required,
            ))
            .evidence(format!(
                "sid RID: {}",
                match account.rid {
                    Some(rid) => rid.to_string(),
                    None => "not read".to_string(),
                }
            ))
            .evidence(format!(
                "password age: {}",
                days_to_label(account.password_age_days)
            ));
            for reason in &reasons {
                finding = finding.evidence(reason.clone());
            }
            ctx.add(
                finding
                    .remediation(
                        "Confirm this account with the machine's owner. If it was not created \
                         deliberately, disable it, set a password, and check the Security event \
                         log for logons (4624) and account changes (4720/4722/4732) around the \
                         time it appeared.",
                    )
                    .remediation(
                        "An account that can be used without a password is an open door: set \
                         UF_PASSWD_REQUIRED (net user <name> /passwordreq:yes) or delete it.",
                    ),
            );
        }

        ctx.raw_section("ACCOUNTS", lines);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(name: &str) -> LocalAccount {
        LocalAccount {
            name: name.to_string(),
            full_name: format!("{name} Full"),
            comment: format!("{name} comment"),
            enabled: true,
            password_required: true,
            password_age_days: Some(10),
            last_logon_days: Some(3),
            is_admin: false,
            is_guest: false,
            rid: Some(1001),
        }
    }

    #[test]
    fn enabled_guest_is_high() {
        let mut guest = account("Guest");
        guest.is_guest = true;
        guest.last_logon_days = None;
        assert_eq!(account_severity(&guest), Some(Severity::High));
    }

    #[test]
    fn localized_default_account_is_high_by_rid() {
        // A Russian install calls it something else entirely; only the RID is stable.
        let mut localized = account("Гость");
        localized.rid = Some(RID_GUEST);
        localized.is_guest = true;
        assert_eq!(account_severity(&localized), Some(Severity::High));
    }

    #[test]
    fn disabled_guest_is_not_flagged() {
        let mut guest = account("Guest");
        guest.is_guest = true;
        guest.enabled = false;
        assert_eq!(account_severity(&guest), None);
    }

    #[test]
    fn password_not_required_on_an_enabled_account_is_high() {
        let mut weak = account("helpdesk");
        weak.password_required = false;
        assert_eq!(account_severity(&weak), Some(Severity::High));
    }

    #[test]
    fn disabled_passwordless_builtin_is_not_flagged() {
        // Windows ships DefaultAccount and Guest disabled AND with UF_PASSWD_NOTREQD.
        // Both must stay quiet or every clean machine reports two false High findings;
        // this regression is what the live host run caught.
        let mut default_account = account("DefaultAccount");
        default_account.rid = Some(RID_DEFAULT_ACCOUNT);
        default_account.enabled = false;
        default_account.password_required = false;
        assert_eq!(account_severity(&default_account), None);

        let mut guest = account("Гость");
        guest.is_guest = true;
        guest.rid = Some(RID_GUEST);
        guest.enabled = false;
        guest.password_required = false;
        assert_eq!(account_severity(&guest), None);
    }

    #[test]
    fn enabled_passwordless_guest_is_high_by_rid() {
        // The dangerous combination the rule exists for: enabled, passwordless, and
        // recognised by RID so it works on a non-English install.
        let mut guest = account("Гость");
        guest.is_guest = true;
        guest.rid = Some(RID_GUEST);
        guest.enabled = true;
        guest.password_required = false;
        assert_eq!(account_severity(&guest), Some(Severity::High));
    }

    #[test]
    fn admin_without_description_is_med() {
        let mut bare = account("backdoor");
        bare.is_admin = true;
        bare.comment = "  ".to_string();
        bare.full_name = String::new();
        assert_eq!(account_severity(&bare), Some(Severity::Med));
    }

    #[test]
    fn admin_with_description_and_a_logon_is_clean() {
        let mut admin = account("alice");
        admin.is_admin = true;
        assert_eq!(account_severity(&admin), None);
    }

    #[test]
    fn never_logged_on_admin_is_med() {
        let mut admin = account("dormant");
        admin.is_admin = true;
        admin.last_logon_days = None;
        assert_eq!(account_severity(&admin), Some(Severity::Med));
    }

    #[test]
    fn should_flag_admin_without_description_truth_table() {
        let mut a = account("a");
        a.is_admin = true;
        a.comment = String::new();
        a.full_name = String::new();
        assert!(should_flag_admin_without_description(&a), "bare admin");

        a.comment = "has a description".to_string();
        assert!(
            should_flag_admin_without_description(&a).not(),
            "a described admin is not flagged"
        );

        a.comment = String::new();
        a.full_name = "Has Name".to_string();
        assert!(
            should_flag_admin_without_description(&a).not(),
            "a named admin is not flagged"
        );

        a.full_name = String::new();
        a.enabled = false;
        assert!(
            should_flag_admin_without_description(&a).not(),
            "a disabled account is not flagged"
        );

        a.enabled = true;
        a.is_admin = false;
        assert!(
            should_flag_admin_without_description(&a).not(),
            "a non-administrator is not flagged"
        );
    }

    #[test]
    fn days_to_label_never_and_pluralisation() {
        assert_eq!(days_to_label(None), "never");
        assert_eq!(days_to_label(Some(0)), "today");
        assert_eq!(days_to_label(Some(1)), "1 day ago");
        assert_eq!(days_to_label(Some(45)), "45 days ago");
    }
}
