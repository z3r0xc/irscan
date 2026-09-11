//! Local-account enumeration through the Win32 NetAPI (FR-8).
//!
//! `NetUserEnum` is the same source `lusrmgr.msc` reads, so an account the SAM
//! database knows about but the settings UI hides is still visible here.
//!
//! **Level 4 (`USER_INFO_4`), with a documented fall back to level 2.** Levels 1-3
//! hand back only names, and the names of the built-in accounts are *localised*: on a
//! Russian Windows the built-in Guest is `Гость` and the built-in Administrator is
//! `Администратор`. Any check written against the English strings silently misses the
//! accounts this tool most needs to see. `USER_INFO_4` adds `usri4_user_sid`, so
//! identity is derived from the **relative identifier (RID)**, which Windows fixes
//! regardless of display language:
//!
//! * RID 501 - the built-in Guest;
//! * RID 500 - the built-in Administrator;
//! * RID 503 - the DefaultAccount.
//!
//! Level 4 is, however, not universally callable: on some Windows builds it answers
//! `NERR_... (124)` for a non-elevated token while levels 0-3 succeed. Refusing the
//! whole enumeration over that would lose the account list on exactly the machines
//! where the tool matters, so `USER_INFO_2` is used as a fallback. The fallback has no
//! SID, so `rid` stays `None` and the caller falls back to name matching - degraded,
//! and said so in a warning rather than silently.
//!
//! Buffer discipline (docs/architecture.md section 6): every block the NetAPI
//! allocates is released with `NetApiBufferFree` on every path, including the path
//! where the call failed and the pointer is null. `MAX_PREFERRED_LENGTH` lets the
//! API size the block itself, and the resume-handle loop is bounded by `MAX_ROUNDS`
//! and `MAX_ACCOUNTS`, so a host that keeps answering `ERROR_MORE_DATA` cannot spin
//! forever. Structures are pulled out with `read_unaligned`, because a `Vec<u8>`
//! carries no alignment promise.
//!
//! If the SID of an account cannot be decoded, its `rid` is `None` and the collector
//! falls back to name matching; a missing RID never invents a finding.

use std::mem::size_of;
use std::ptr;

use windows_sys::Win32::Foundation::ERROR_MORE_DATA;
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NERR_Success, NetApiBufferFree, NetLocalGroupGetMembers, NetUserEnum, FILTER_NORMAL_ACCOUNT,
    LOCALGROUP_MEMBERS_INFO_1, MAX_PREFERRED_LENGTH, UF_ACCOUNTDISABLE, UF_PASSWD_NOTREQD,
    USER_INFO_2, USER_INFO_4,
};

use super::strings::{from_wide_len, wide};

/// Hard cap on local accounts returned. A workstation has a handful; anything near
/// this bound is a host deliberately flooding the enumerator.
pub const MAX_ACCOUNTS: usize = 1024;

/// Hard cap on Administrators members decoded. Prevents a hostile group from making
/// the membership list unbounded.
const MAX_GROUP_MEMBERS: usize = 4096;

/// Cap on the UTF-16 code units decoded from one account string. A name longer than
/// this is not a name, it is a hostile buffer; stopping is safer than growing.
const MAX_NAME_UNITS: usize = 1024;

/// Upper bound on enumeration rounds for either NetAPI call. With
/// `MAX_PREFERRED_LENGTH` a healthy host answers in one round.
const MAX_ROUNDS: usize = 64;

/// Seconds in a day, for the `*_password_age` / `*_last_logon` fields.
const SECONDS_PER_DAY: u32 = 86_400;

/// Well-known relative identifiers. These are language-independent, unlike the names.
/// <https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids>
pub const RID_GUEST: u32 = 501;
pub const RID_ADMINISTRATOR: u32 = 500;
/// The `DefaultAccount`, present (and disabled) from Windows 10 1803 onward.
pub const RID_DEFAULT_ACCOUNT: u32 = 503;

/// The local BUILTIN domain is authority 5 with a leading sub-authority of 32; a
/// domain SID shares authority 5 but must not be mistaken for a local account.
const BUILTIN_SUB_AUTHORITY: u8 = 32;

/// `sizeof(SID)` for a SID with 15 sub-authorities - the maximum Windows allows.
const MAX_SID_BYTES: usize = 68;

/// One local account, decoded and sanitised at this boundary.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalAccount {
    pub name: String,
    pub full_name: String,
    /// The description shown in `lusrmgr`.
    pub comment: String,
    pub enabled: bool,
    pub password_required: bool,
    /// `None` means "never set" - the field is zero or the sentinel all-ones value.
    pub password_age_days: Option<u32>,
    /// `None` means "never logged on".
    pub last_logon_days: Option<u32>,
    pub is_admin: bool,
    pub is_guest: bool,
    /// The account's relative identifier, decoded from its SID. `None` when the SID
    /// could not be read; this is the language-independent way to recognise built-ins.
    pub rid: Option<u32>,
}

/// Split `USER_ACCOUNT_FLAGS` into the two booleans the report reasons about.
///
/// Pure so the flag semantics are pinned without a live host: `UF_ACCOUNTDISABLE`
/// and `UF_PASSWD_NOTREQD` are both *negative* flags, and inverting one silently
/// would turn a healthy machine into a wall of false findings.
fn interpret_flags(flags: u32) -> (bool, bool) {
    let enabled = flags & UF_ACCOUNTDISABLE == 0;
    let password_required = flags & UF_PASSWD_NOTREQD == 0;
    (enabled, password_required)
}

/// Convert a NetAPI seconds field into whole days.
///
/// `0` and `u32::MAX` both mean "never"/"unknown" on this interface, and reporting
/// either as "0 days ago" would invent activity that did not happen.
fn seconds_to_days(seconds: u32) -> Option<u32> {
    if seconds == 0 || seconds == u32::MAX {
        return None;
    }
    Some(seconds / SECONDS_PER_DAY)
}

/// Extract the RID from a `SID` byte image, or `None` when it is not a local
/// (`S-1-5-32-x`) account.
///
/// Pure and testable on hand-built bytes: a SID is
/// `[revision, sub_authority_count, authority(6 bytes, big-endian), sub_authorities(4 each)]`,
/// with the RID in the last `u32`. Anything malformed (short buffer, wrong revision,
/// authority other than NT, a leading sub-authority other than BUILTIN, or a
/// sub-authority count that does not match the bytes present) yields `None` rather
/// than a number read past the end of the buffer.
fn rid_from_sid(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < 12 {
        return None;
    }
    if bytes[0] != 1 {
        return None;
    }
    // Identifier authority 5 = NT. The 6-byte authority is big-endian, so the value
    // lives in the last byte for every authority Windows actually uses.
    if bytes[7] != 5 {
        return None;
    }
    let sub_count = bytes[1] as usize;
    if sub_count == 0 {
        return None;
    }
    if bytes[8] != BUILTIN_SUB_AUTHORITY {
        return None;
    }
    let needed = 8usize.checked_add(sub_count.checked_mul(4)?)?;
    if bytes.len() < needed {
        return None;
    }
    let rid_at = needed - 4;
    let rid = u32::from_le_bytes([
        *bytes.get(rid_at)?,
        *bytes.get(rid_at + 1)?,
        *bytes.get(rid_at + 2)?,
        *bytes.get(rid_at + 3)?,
    ]);
    Some(rid)
}

/// Decode one NUL-terminated UTF-16 string that points into a NetAPI buffer.
///
/// The scan is bounded by `MAX_NAME_UNITS`: a string with no terminator (a truncated
/// or hostile answer) stops at the cap instead of running off into memory the caller
/// does not own.
///
/// SAFETY (all callers): `ptr` must be null or point at a NUL-terminated UTF-16
/// string that stays valid for the duration of the call.
unsafe fn utf16_field(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut units: Vec<u16> = Vec::with_capacity(32);
    // SAFETY: the caller guarantees the pointer, and the loop cannot exceed the cap.
    unsafe {
        for index in 0..MAX_NAME_UNITS {
            let unit = ptr.add(index).read_unaligned();
            if unit == 0 {
                break;
            }
            units.push(unit);
        }
    }
    from_wide_len(&units, units.len())
}

/// Release a NetAPI buffer, tolerating a null pointer.
///
/// SAFETY: `buffer` must be null or a pointer returned by a NetAPI enumeration that
/// has not already been freed.
unsafe fn free_buffer(buffer: *mut u8) {
    if buffer.is_null() {
        return;
    }
    // SAFETY: upheld by the caller; every NetAPI allocation is freed exactly once.
    unsafe {
        NetApiBufferFree(buffer as *const core::ffi::c_void);
    }
}

/// Copy a SID out of a NetAPI buffer into bounded bytes.
///
/// A SID carries no length field a caller may trust before the pointer is known to be
/// valid, so the copy is bounded by the SID's own `sub_authority_count` byte and, at
/// worst, by `MAX_SID_BYTES`. Parsing then decides whether it is plausible.
///
/// SAFETY: `sid` must be null or point at a valid SID inside a live NetAPI buffer.
unsafe fn sid_bytes(sid: *mut core::ffi::c_void) -> Vec<u8> {
    if sid.is_null() {
        return Vec::new();
    }
    let ptr = sid as *const u8;
    // SAFETY: the caller guarantees `sid` points at a valid SID inside a NetAPI
    // allocation, so the fixed 2-byte header is readable.
    let header = unsafe { [ptr.read_unaligned(), ptr.add(1).read_unaligned()] };
    // `sub_authority_count` fixes the real length: 8 header bytes plus 4 per
    // sub-authority. A count that would exceed the largest legal SID (15
    // sub-authorities) is treated as the cap rather than trusted.
    let count = (header[1] as usize).min(15);
    let wanted = 8 + count * 4;

    let mut out: Vec<u8> = Vec::with_capacity(wanted);
    // SAFETY: as above; the copy is clamped to `wanted <= MAX_SID_BYTES`, so a
    // malformed count cannot make this read past the allocation's plausible size.
    unsafe {
        for index in 0..wanted.min(MAX_SID_BYTES) {
            out.push(ptr.add(index).read_unaligned());
        }
    }
    out
}

/// Record that the level-4 answer was unavailable, so the caller can warn.
///
/// A process-global flag is the honest shape here: the FFI layer is called from one
/// collector on one thread, and threading a "which level succeeded" value through
/// every signature would complicate the API for a diagnostic.
static LEVEL4_UNAVAILABLE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Did the enumeration have to fall back to `USER_INFO_2`?
///
/// The collector turns this into a warning: the account list is still complete, but
/// `rid` is empty, so the built-in-account check degrades to name matching.
pub fn used_level_2_fallback() -> bool {
    LEVEL4_UNAVAILABLE.load(std::sync::atomic::Ordering::Relaxed)
}

/// Decode `count` `USER_INFO_2` records; the level-4 fallback.
///
/// `rid` is left `None`: level 2 has no SID. Everything else - description, flags,
/// password age, last logon - is present and identical in meaning.
///
/// SAFETY: `base` must point at `count` contiguous `USER_INFO_2` records written by
/// `NetUserEnum`, and the strings they reference must live in the same allocation.
unsafe fn decode_accounts_v2(
    base: *const u8,
    count: u32,
    admin_names: &[String],
    out: &mut Vec<LocalAccount>,
) {
    let stride = size_of::<USER_INFO_2>();
    let take = (count as usize).min(MAX_ACCOUNTS.saturating_sub(out.len()));
    for index in 0..take {
        // SAFETY: index < count, so the record lies inside the API-owned buffer;
        // read_unaligned because the buffer makes no alignment promise.
        let info = unsafe { ptr::read_unaligned(base.add(index * stride) as *const USER_INFO_2) };
        // SAFETY: the string pointers belong to the same live allocation.
        let name = unsafe { utf16_field(info.usri2_name) };
        if name.is_empty() {
            continue;
        }
        // SAFETY: as above.
        let full_name = unsafe { utf16_field(info.usri2_full_name) };
        // SAFETY: as above.
        let comment = unsafe { utf16_field(info.usri2_comment) };

        let (enabled, password_required) = interpret_flags(info.usri2_flags);
        let key = name.to_lowercase();
        out.push(LocalAccount {
            name: crate::text::sanitize(&name, crate::model::MAX_STRING),
            full_name: crate::text::sanitize(&full_name, crate::model::MAX_STRING),
            comment: crate::text::sanitize(&comment, crate::model::MAX_STRING),
            enabled,
            password_required,
            password_age_days: seconds_to_days(info.usri2_password_age),
            last_logon_days: seconds_to_days(info.usri2_last_logon),
            is_admin: admin_names.contains(&key),
            // No SID at this level, so no RID-based guest detection; the caller
            // falls back to the name and the collector warns about it.
            is_guest: name.eq_ignore_ascii_case("Guest") || name.eq_ignore_ascii_case("Гость"),
            rid: None,
        });
    }
}

/// Decode `count` `USER_INFO_4` records out of a buffer `NetUserEnum` filled.
///
/// SAFETY: `base` must point at `count` contiguous `USER_INFO_4` records written by
/// `NetUserEnum`, and the strings they reference must live in the same allocation.
unsafe fn decode_accounts(
    base: *const u8,
    count: u32,
    admin_names: &[String],
    out: &mut Vec<LocalAccount>,
) {
    let stride = size_of::<USER_INFO_4>();
    let take = (count as usize).min(MAX_ACCOUNTS.saturating_sub(out.len()));
    for index in 0..take {
        // SAFETY: index < count, so the record lies inside the API-owned buffer;
        // read_unaligned because the buffer makes no alignment promise.
        let info = unsafe { ptr::read_unaligned(base.add(index * stride) as *const USER_INFO_4) };
        // SAFETY: the string pointers belong to the same live allocation.
        let name = unsafe { utf16_field(info.usri4_name) };
        if name.is_empty() {
            continue;
        }
        // SAFETY: as above.
        let full_name = unsafe { utf16_field(info.usri4_full_name) };
        // SAFETY: as above.
        let comment = unsafe { utf16_field(info.usri4_comment) };
        // SAFETY: `usri4_user_sid` points into the same live allocation.
        let sid = unsafe { sid_bytes(info.usri4_user_sid) };
        let rid = rid_from_sid(&sid);

        let (enabled, password_required) = interpret_flags(info.usri4_flags);
        let key = name.to_lowercase();
        out.push(LocalAccount {
            name: crate::text::sanitize(&name, crate::model::MAX_STRING),
            full_name: crate::text::sanitize(&full_name, crate::model::MAX_STRING),
            comment: crate::text::sanitize(&comment, crate::model::MAX_STRING),
            enabled,
            password_required,
            password_age_days: seconds_to_days(info.usri4_password_age),
            last_logon_days: seconds_to_days(info.usri4_last_logon),
            is_admin: admin_names.contains(&key),
            // RID 501 is the built-in Guest whatever it is called in this language.
            is_guest: rid == Some(RID_GUEST),
            rid,
        });
    }
}

/// Decode `count` `LOCALGROUP_MEMBERS_INFO_1` records into lower-cased names.
///
/// SAFETY: `base` must point at `count` contiguous `LOCALGROUP_MEMBERS_INFO_1`
/// records written by `NetLocalGroupGetMembers`, with their strings in the same
/// allocation.
unsafe fn decode_members(base: *const u8, count: u32, out: &mut Vec<String>) {
    let stride = size_of::<LOCALGROUP_MEMBERS_INFO_1>();
    let take = (count as usize).min(MAX_GROUP_MEMBERS.saturating_sub(out.len()));
    for index in 0..take {
        // SAFETY: index < count; read_unaligned as for the account records.
        let info = unsafe {
            ptr::read_unaligned(base.add(index * stride) as *const LOCALGROUP_MEMBERS_INFO_1)
        };
        // SAFETY: lgrmi1_name points into the same live allocation.
        let name = unsafe { utf16_field(info.lgrmi1_name) };
        if name.is_empty() {
            continue;
        }
        // Lower-cased here so the comparison against `usri4_name` is case-insensitive
        // without allocating again per account.
        out.push(name.to_lowercase());
    }
}

/// Names a machine may accept for the built-in Administrators group (RID 544).
///
/// The group name is localised (`Администраторы`, `Administratoren`, ...), so it is
/// looked up rather than assumed. The English name is first because an English
/// install is the common case; the rest cover the languages this tool is likely to
/// run under. A miss is safe: `is_admin` stays false, which errs toward silence
/// rather than toward a false accusation.
const ADMIN_GROUP_NAMES: &[&str] = &[
    "Administrators",
    "Администраторы",
    "Administratoren",
    "Administrateurs",
    "Administradores",
    "Administratori",
];

/// Members of a local group by name, lower-cased.
///
/// `None` when the group does not exist or cannot be read; `Some` with an empty list
/// is a real answer (a group with no members). The two are kept distinct so an
/// unresolvable group is not mistaken for an empty one.
fn group_members(group_name: &str) -> Option<Vec<String>> {
    let group = wide(group_name);
    let mut out: Vec<String> = Vec::new();
    let mut resume: usize = 0;
    let mut rounds = 0usize;
    let mut success = false;

    while rounds < MAX_ROUNDS && out.len() < MAX_GROUP_MEMBERS {
        rounds += 1;
        let mut buffer: *mut u8 = ptr::null_mut();
        let mut read: u32 = 0;
        let mut total: u32 = 0;
        // SAFETY: every pointer is either null (the API allocates) or a valid local;
        // `resume` starts at zero and is maintained by the API across calls.
        let status = unsafe {
            NetLocalGroupGetMembers(
                ptr::null(),
                group.as_ptr(),
                1,
                &mut buffer,
                MAX_PREFERRED_LENGTH,
                &mut read,
                &mut total,
                &mut resume,
            )
        };

        if status == NERR_Success || status == ERROR_MORE_DATA {
            // SAFETY: a successful/partial call filled `buffer` with `read` records.
            unsafe { decode_members(buffer, read, &mut out) };
        }
        // SAFETY: free whatever the call allocated, including on the error path.
        unsafe { free_buffer(buffer) };

        if status == NERR_Success {
            success = true;
            break;
        }
        if status != ERROR_MORE_DATA || read == 0 {
            break;
        }
    }

    if success {
        Some(out)
    } else {
        None
    }
}

/// Names of the members of the local Administrators group (lower-cased).
///
/// Best effort: an unresolvable group yields an empty list rather than an error, so
/// the account list is still reported.
fn admin_members() -> Vec<String> {
    for candidate in ADMIN_GROUP_NAMES {
        if let Some(members) = group_members(candidate) {
            return members;
        }
    }
    Vec::new()
}

/// Enumerate every normal (non-computer, non-service) local account.
///
/// `Err` only when the NetAPI refuses the enumeration outright - typically when the
/// process is not elevated. The message carries the raw NERR code, because the code
/// is what tells an analyst whether the SAM database was unreadable or empty.
pub fn local_accounts() -> Result<Vec<LocalAccount>, String> {
    let admins = admin_members();
    // Level 4 gives the SID, which is the language-independent way to recognise the
    // built-in accounts; level 2 is the fallback for builds that refuse level 4.
    let mut out = enumerate(4, &admins);
    if out.is_err() {
        LEVEL4_UNAVAILABLE.store(true, std::sync::atomic::Ordering::Relaxed);
        out = enumerate(2, &admins);
    }
    out
}

/// Enumerate every normal local account at one `USER_INFO_*` level.
///
/// `Err` only when the NetAPI refuses the enumeration outright. The message carries
/// the raw NERR code, because the code is what tells an analyst whether the SAM
/// database was unreadable or empty.
fn enumerate(level: u32, admins: &[String]) -> Result<Vec<LocalAccount>, String> {
    let mut out: Vec<LocalAccount> = Vec::new();
    let mut resume: u32 = 0;
    let mut rounds = 0usize;
    let mut failure: Option<u32> = None;

    while rounds < MAX_ROUNDS && out.len() < MAX_ACCOUNTS {
        rounds += 1;
        let mut buffer: *mut u8 = ptr::null_mut();
        let mut read: u32 = 0;
        let mut total: u32 = 0;
        // SAFETY: null server name means "this machine"; the output pointers are
        // valid locals, and the API writes only through them.
        let status = unsafe {
            NetUserEnum(
                ptr::null(),
                level,
                FILTER_NORMAL_ACCOUNT,
                &mut buffer,
                MAX_PREFERRED_LENGTH,
                &mut read,
                &mut total,
                &mut resume,
            )
        };

        if status == NERR_Success || status == ERROR_MORE_DATA {
            // SAFETY: the call filled `buffer` with `read` records of this level.
            unsafe {
                if level == 4 {
                    decode_accounts(buffer, read, admins, &mut out);
                } else {
                    decode_accounts_v2(buffer, read, admins, &mut out);
                }
            }
        }
        // SAFETY: free the block on every path, including a failed call.
        unsafe { free_buffer(buffer) };

        if status == NERR_Success {
            break;
        }
        if status != ERROR_MORE_DATA {
            if out.is_empty() {
                failure = Some(status);
            }
            break;
        }
        if read == 0 {
            break;
        }
    }

    match failure {
        // Only a total failure is an error: with no records the collector has nothing
        // to report, whereas a failure after the first round still leaves useful data.
        Some(code) => Err(format!(
            "NetUserEnum level {level} failed with NERR code {code}"
        )),
        None => Ok(out),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::Not;

    #[test]
    fn flags_map_to_enabled_and_password_required() {
        assert_eq!(interpret_flags(0), (true, true));
        assert_eq!(interpret_flags(UF_ACCOUNTDISABLE), (false, true));
        assert_eq!(interpret_flags(UF_PASSWD_NOTREQD), (true, false));
        assert_eq!(
            interpret_flags(UF_ACCOUNTDISABLE | UF_PASSWD_NOTREQD),
            (false, false)
        );
    }

    #[test]
    fn seconds_to_days_treats_zero_and_max_as_never() {
        assert_eq!(seconds_to_days(0), None, "0 means never");
        assert_eq!(seconds_to_days(u32::MAX), None, "all-ones means unknown");
        assert_eq!(seconds_to_days(86_399), Some(0), "just under a day");
        assert_eq!(seconds_to_days(86_400), Some(1));
        assert_eq!(seconds_to_days(86_400 * 30), Some(30));
    }

    #[test]
    fn rid_from_sid_decodes_builtin_accounts() {
        // The real Guest SID, S-1-5-32-501: revision 1, TWO sub-authorities (32 =
        // BUILTIN, then 501 little-endian), NT authority 5. The RID is the last one,
        // which is why the parser reads from the end rather than a fixed offset.
        #[rustfmt::skip]
        let guest = [
            1u8, 2, 0, 0, 0, 0, 0, 5,
            32, 0, 0, 0,
            245, 1, 0, 0,
        ];
        assert_eq!(guest.len(), 16);
        assert_eq!(rid_from_sid(&guest), Some(RID_GUEST));

        // S-1-5-32-500, the built-in Administrator.
        #[rustfmt::skip]
        let admin = [
            1u8, 2, 0, 0, 0, 0, 0, 5,
            32, 0, 0, 0,
            244, 1, 0, 0,
        ];
        assert_eq!(rid_from_sid(&admin), Some(RID_ADMINISTRATOR));

        // S-1-5-32 with one sub-authority: the RID is 32 and must still decode.
        let builtin = [1u8, 1, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0];
        assert_eq!(rid_from_sid(&builtin), Some(32));
    }

    #[test]
    fn rid_from_sid_rejects_malformed_input() {
        assert_eq!(rid_from_sid(&[]), None, "empty");
        assert_eq!(rid_from_sid(&[1, 1, 0, 0]), None, "too short");
        // A domain SID (authority 5, but sub-authority 21 = domain) must not be read
        // as a local RID: a domain account is not a local account.
        let domain = [1u8, 1, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 2, 0, 0];
        assert_eq!(rid_from_sid(&domain), None, "domain SID is not local");
        // Claims two sub-authorities but only one is present: the RID must not be
        // fabricated from the tail of the truncated buffer.
        let truncated = [1u8, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0];
        assert_eq!(rid_from_sid(&truncated), None, "sub-authorities truncated");
        // Wrong revision byte.
        let bad_rev = [2u8, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 245, 1, 0, 0];
        assert_eq!(rid_from_sid(&bad_rev), None, "revision must be 1");
        // Zero sub-authorities cannot carry a RID.
        let none = [1u8, 0, 0, 0, 0, 0, 0, 5];
        assert_eq!(rid_from_sid(&none), None, "no sub-authorities");
    }

    #[test]
    fn sid_bytes_reads_exactly_the_sid_length() {
        // A SID with two sub-authorities is 8 + 8 = 16 bytes; the copy must stop there
        // rather than walking the 68-byte cap into unrelated memory.
        // S-1-5-32-545 (Users): sub-authorities 32 then 545 -> 8 + 2*4 = 16 bytes.
        let raw = [
            1u8, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x21, 0x02, 0, 0, 0, 0, 0, 0,
        ];
        let copied = unsafe { sid_bytes(raw.as_ptr() as *mut core::ffi::c_void) };
        assert_eq!(copied.len(), 16, "8 header bytes + 2 sub-authorities");
        assert_eq!(rid_from_sid(&copied), Some(545));
        // A malformed count byte must not make the copy run to the 68-byte cap.
        let bogus = [1u8, 250, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0];
        let copied2 = unsafe { sid_bytes(bogus.as_ptr() as *mut core::ffi::c_void) };
        assert_eq!(
            copied2.len(),
            68,
            "an absurd count is clamped to the SID cap"
        );
    }

    #[test]
    fn free_buffer_accepts_null() {
        // A failed NetAPI call leaves the pointer null; freeing it must be a no-op
        // rather than a crash, because that is a common error path.
        let buffer: *mut u8 = ptr::null_mut();
        unsafe { free_buffer(buffer) };
    }

    #[test]
    fn local_accounts_lists_a_builtin_account_or_fails_cleanly() {
        match local_accounts() {
            Ok(accounts) => {
                assert!(
                    accounts.is_empty().not(),
                    "a Windows machine always has local accounts"
                );
                // Recognised by RID, so this holds on any display language - the whole
                // point of asking for USER_INFO_4 instead of USER_INFO_2.
                let has_builtin = accounts.iter().any(|a| {
                    a.is_guest
                        || a.rid == Some(RID_ADMINISTRATOR)
                        || a.rid == Some(RID_DEFAULT_ACCOUNT)
                });
                assert!(
                    has_builtin,
                    "expected a built-in account by RID: {:?}",
                    accounts
                        .iter()
                        .map(|a| (a.name.as_str(), a.rid))
                        .collect::<Vec<_>>()
                );
            }
            // A non-elevated process, or a CI runner with the SAM database locked,
            // must produce a typed error and never a panic.
            Err(message) => assert!(message.contains("NetUserEnum"), "{message}"),
        }
    }
}
