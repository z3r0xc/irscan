//! Authenticode trust and publisher identity: the two independent axes this tool
//! uses to judge whether a file is the legitimate product it claims to be.
//!
//! They are deliberately **not** combined here. Trust comes from `WinVerifyTrust`
//! (the OS validates the signature chain); publisher string comes from the PE
//! version resource, which any binary can forge with a text editor and a resource
//! compiler. Handing a caller a single "is this good" boolean would throw that
//! distinction away, so callers in `crate::rules` weigh `is_signature_trusted` and
//! `company_name` together and a mismatch between the two is itself the finding
//! (FR-13, FR-14).
//!
//! # Two kinds of signature, both of them "trusted by the OS"
//!
//! Windows trusts an executable through either of two mechanisms:
//!
//! 1. an **embedded** Authenticode signature in the PE image itself, and
//! 2. a **catalog** signature: the file's hash is listed in a `.cat` file that is
//!    itself signed, and Windows verifies the hash against the catalog.
//!
//! Most of `%SystemRoot%\System32` is catalog-signed, not embedded-signed. A tool
//! that only asked `WinVerifyTrust` about embedded signatures reported 38 of 56
//! sampled System32 executables as untrusted - including Microsoft's own
//! `notepad.exe` and `cmd.exe`. Feeding that into `rules::execution_severity`
//! turned a clean host into a page of MEDIUM findings, which is worse than no
//! report at all. So [`is_signature_trusted`] tries embedded first and falls back
//! to the catalog, and only answers `Some(false)` when both mechanisms say no.
//!
//! The fallback must not manufacture accusations: when the catalog lookup itself
//! cannot run (no catalog admin context, access denied), the answer is `None`
//! ("could not check"), never `Some(false)`. A file we could not verify is a
//! question, not a finding.
//!
//! Everything in this module is `unsafe` FFI and belongs here, not in the
//! collectors (spec SR-6). Rules followed (docs/architecture.md section 6):
//! every return value is checked, every store/message/context/catalog handle is
//! released on every path, and every returned string is sanitised before it
//! leaves the module, because a version resource is attacker-controlled text
//! (SR-2).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::{Mutex, OnceLock};

use windows_sys::Win32::Foundation::{LocalFree, HANDLE, HWND};
use windows_sys::Win32::Security::Cryptography::Catalog::{
    CryptCATAdminAcquireContext, CryptCATAdminCalcHashFromFileHandle,
    CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
};
use windows_sys::Win32::Security::Cryptography::{
    CertCloseStore, CryptMsgClose, CryptQueryObject, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
    CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE, HCERTSTORE,
};
use windows_sys::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA,
    WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE,
    WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};
use windows_sys::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
};

use super::wide;
use crate::model::MAX_STRING;
use crate::text::sanitize;

/// Upper bound on a PE version resource we are willing to load (1 MiB).
///
/// A genuine `VS_VERSIONINFO` is a few kilobytes. Anything past this is either
/// pathological or planted to make the scan allocate hard, so it is refused
/// rather than read (architecture section 6 rule 2).
pub const MAX_VERSION_BYTES: u32 = 1024 * 1024;

/// Upper bound on the characters kept from a publisher/product string *before*
/// sanitisation. A version resource is attacker-controlled and can be megabytes
/// long with no NUL in sight; `sanitize` then clamps to `MAX_STRING`.
pub const MAX_IDENTITY_CHARS: usize = 4096;

/// Upper bound on language/codepage pairs probed for a version resource. Small
/// and fixed on purpose: an unbounded probe would turn one hostile binary into
/// minutes of I/O.
pub const MAX_TRANSLATION_PROBES: usize = 8;

/// Upper bound on the catalog hash `CryptCATAdminCalcHashFromFileHandle` can
/// report. The real value is 20 bytes (SHA-1) or 32 (SHA-256); 64 leaves room
/// without letting a hostile return size drive the allocation.
pub const MAX_CATALOG_HASH_BYTES: usize = 64;

/// Upper bound on cached trust answers. The cache exists so the process and
/// service collectors (which both ask about the same handful of binaries) do not
/// each pay a full-file catalog hash; it is a scan-local memo, not a database.
pub const MAX_TRUST_CACHE: usize = 4096;

/// The language/codepage pairs to try when the translation table is unusable.
/// `040904b0` (US English, Unicode) is what virtually every Windows toolchain
/// emits; the rest are the localised codepages that show up on non-English hosts.
const FALLBACK_TRANSLATIONS: [(u16, u16); 4] = [
    (0x0409, 0x04b0),
    (0x0409, 0x04e4),
    (0x0000, 0x04b0),
    (0x0407, 0x04b0),
];

/// Is this file validly signed *and* trusted by the operating system?
///
/// * `None` - the question could not be asked: the file is missing, is a
///   directory, or could not be opened. Reported as "unavailable", never as
///   "unsigned".
/// * `Some(true)` - the OS accepted the Authenticode signature and its chain.
/// * `Some(false)` - the file is unsigned, its signature is broken, or its chain
///   is not trusted. A broken signature on an otherwise legitimate-looking binary
///   is worth reporting on its own.
///
/// UI is suppressed and revocation lookups are cache-only, so the call cannot
/// block on the network or pop a dialog on the suspect machine (spec: the tool
/// never contacts the network).
pub fn is_signature_trusted(path: &Path) -> Option<bool> {
    // A directory has no signature, but that is not a finding either - the caller
    // asked about a file. Both cases collapse to "could not attempt".
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }

    // Normalise before consulting the cache: two paths that differ only in case or
    // in `\?\` prefixing are the same file, and the cache key must say so.
    let key = match std::fs::canonicalize(path) {
        Ok(canonical) => canonical,
        // Falling back to the raw path is correct: it only loses cache sharing,
        // never correctness.
        Err(_) => PathBuf::from(path),
    };

    if let Some(hit) = trust_cache().lock().ok().and_then(|c| c.get(&key).copied()) {
        return hit;
    }

    let answer = verify_trust(path);

    if let Ok(mut cache) = trust_cache().lock() {
        if cache.len() < MAX_TRUST_CACHE {
            cache.insert(key, answer);
        }
    }

    answer
}

/// Verify a file's signature, embedded first, then catalog. Split out from the
/// public entry point so the cache wrapper stays trivial.
fn verify_trust(path: &Path) -> Option<bool> {
    let embedded = verify_embedded(path);

    // An embedded signature the OS accepts settles it; no catalog lookup (and no
    // full-file hash) needed. This is the common case for third-party software and
    // the expensive one to skip, so it goes first.
    if embedded == Some(true) {
        return Some(true);
    }

    // Otherwise, the file may still be catalog-signed. This is the normal case for
    // Windows' own binaries.
    match verify_catalog(path) {
        Some(true) => Some(true),
        // The catalog ran and found no trusted entry for this hash, so the file is
        // not covered by either mechanism. If the embedded probe also ran and said
        // no, the answer is a definite "unsigned". If the embedded probe could not
        // run, the file was never checked at all, so the answer stays `None`.
        Some(false) => embedded,
        // The catalog could not be consulted (no admin context, unreadable file).
        // A file we could not fully check is a question, not a finding: `None`,
        // even when the embedded probe said no. Reporting `Some(false)` here would
        // accuse a file on the strength of half a check.
        None => None,
    }
}

/// Verify through a **catalog** signature: hash the file, ask the catalog store
/// whether that hash is listed, and if so let `WinVerifyTrust` validate the
/// catalog's own signature against the listed hash.
///
/// * `Some(true)` - a catalog covered this file and the OS accepted it.
/// * `Some(false)` - the catalog machinery ran and has no trusted entry for this
///   hash. The file is not covered by any catalog we can see.
/// * `None` - the check could not be attempted (no catalog admin context, the file
///   could not be opened, a size/read failure). Never `Some(false)`: an
///   environmental failure must not read as "unsigned".
///
/// The admin context is acquired per call rather than cached: it is cheap next to
/// the file hash, and a cached `isize` would have to be released at process exit
/// anyway, which this read-only tool has no clean hook for.
fn verify_catalog(path: &Path) -> Option<bool> {
    // SAFETY: a null subsystem GUID asks for the default catalog subsystem and is
    // documented as valid. The out-parameter points at a live local initialised to
    // 0; on success the guard below owns the context and releases it exactly once.
    let mut catalog_admin: isize = 0;
    let acquired = unsafe { CryptCATAdminAcquireContext(&mut catalog_admin, ptr::null(), 0) };
    if acquired == 0 || catalog_admin == 0 {
        return None;
    }
    // From here on every exit path must release the context.
    let result = catalog_lookup(catalog_admin, path);
    // SAFETY: `catalog_admin` was returned by a successful acquire above and is
    // released exactly once here, on both the success and failure paths.
    unsafe {
        let _ = CryptCATAdminReleaseContext(catalog_admin, 0);
    }
    result
}

/// The body of the catalog check, separated so the context release above cannot be
/// skipped by an early return.
fn catalog_lookup(catalog_admin: isize, path: &Path) -> Option<bool> {
    let mut file = std::fs::File::open(path).ok()?;
    let handle = file_handle(&mut file)?;

    // Hash the file through the catalog admin so the hash algorithm matches the
    // one the catalog uses (SHA-1 on older builds, SHA-256 on newer ones).
    let mut hash_len: u32 = 0;
    // SAFETY: `handle` is a live file handle owned by `file`; a null hash buffer
    // with a zeroed size is the documented sizing call.
    let sized =
        unsafe { CryptCATAdminCalcHashFromFileHandle(handle, &mut hash_len, ptr::null_mut(), 0) };
    if sized == 0 || hash_len == 0 || hash_len as usize > MAX_CATALOG_HASH_BYTES {
        return None;
    }

    let mut hash = vec![0u8; hash_len as usize];
    let mut hash_len2 = hash_len;
    // SAFETY: `hash` is exactly `hash_len` bytes as just reported; `file` is back
    // at its start; the API rewinds the handle itself.
    let hashed = unsafe {
        CryptCATAdminCalcHashFromFileHandle(handle, &mut hash_len2, hash.as_mut_ptr(), 0)
    };
    if hashed == 0 {
        return None;
    }
    hash.truncate(hash_len2 as usize);
    if hash.is_empty() {
        return None;
    }

    // Walk the catalog entries for this hash; `phPrevCatInfo` must start at 0.
    let mut previous: isize = 0;
    // SAFETY: `catalog_admin` is live for the whole call chain; `hash` is a valid
    // buffer of the length passed; `previous` starts at the documented 0.
    let cat_info = unsafe {
        CryptCATAdminEnumCatalogFromHash(
            catalog_admin,
            hash.as_ptr(),
            hash.len() as u32,
            0,
            &mut previous,
        )
    };
    if cat_info == 0 {
        // No catalog entry for this hash: the lookup itself succeeded, so this is
        // a real (negative) answer, not an environmental failure.
        return Some(false);
    }

    // Convert the enumeration handle into a catalog path, then verify against it.
    let mut info = CATALOG_INFO {
        cbStruct: std::mem::size_of::<CATALOG_INFO>() as u32,
        wszCatalogFile: [0u16; 260],
    };
    // SAFETY: `cat_info` was returned by the enum call above; `info` is a live,
    // correctly sized out-parameter (cbStruct set).
    let got_info = unsafe { CryptCATCatalogInfoFromContext(cat_info, &mut info, 0) };

    let verdict = if got_info == 0 {
        // The handle was valid but the path could not be read back. We cannot name
        // a catalog to verify against, so the file stays unverifiable.
        None
    } else {
        verify_against_catalog(&info.wszCatalogFile, &hash, catalog_admin)
    };

    // SAFETY: `catalog_admin` is live and `cat_info` was returned by the enum call
    // above; it is released exactly once here, on both paths.
    unsafe {
        let _ = CryptCATAdminReleaseCatalogContext(catalog_admin, cat_info, 0);
    }

    verdict
}

/// Ask `WinVerifyTrust` to validate a catalog's signature and confirm the catalog
/// lists `hash` for `path`.
fn verify_against_catalog(catalog_file: &[u16], hash: &[u8], catalog_admin: isize) -> Option<bool> {
    // The catalog path is a fixed buffer; it may or may not be NUL-terminated
    // within its own length, so terminate a copy explicitly.
    let mut catalog_path: Vec<u16> = catalog_file
        .iter()
        .copied()
        .take_while(|c| *c != 0)
        .collect();
    if catalog_path.is_empty() {
        return None;
    }
    catalog_path.push(0);

    let mut catalog_info = WINTRUST_CATALOG_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
        dwCatalogVersion: 0,
        pcwszCatalogFilePath: catalog_path.as_ptr(),
        // A null member tag asks WinVerifyTrust to locate the member by hash, which
        // is exactly the question we are asking.
        pcwszMemberTag: ptr::null(),
        // The member file path is not needed for a hash-based lookup.
        pcwszMemberFilePath: ptr::null(),
        hMemberFile: ptr::null_mut(),
        pbCalculatedFileHash: hash.as_ptr() as *mut u8,
        cbCalculatedFileHash: hash.len() as u32,
        pcCatalogContext: ptr::null_mut(),
        hCatAdmin: catalog_admin,
    };

    // SAFETY: every pointer field points at a live local (`catalog_path`) or a
    // live borrowed slice (`hash`), or is null per the API's contract for a
    // hash-only lookup. `Anonymous.pCatalog` is the arm selected by
    // `dwUnionChoice = WTD_CHOICE_CATALOG`.
    let mut trust_data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: ptr::null_mut(),
        pSIPClientData: ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_CATALOG,
        Anonymous: windows_sys::Win32::Security::WinTrust::WINTRUST_DATA_0 {
            pCatalog: &mut catalog_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: ptr::null_mut(),
        pwszURLReference: ptr::null_mut(),
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        dwUIContext: 0,
        pSignatureSettings: ptr::null_mut(),
    };

    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    // SAFETY: `action`, `trust_data` and `catalog_info` are live, correctly sized
    // and exclusively owned here; the null window handle plus WTD_UI_NONE means no
    // UI can be reached. The return is a LONG trust status, interpreted below.
    let status = unsafe {
        WinVerifyTrust(
            ptr::null_mut::<core::ffi::c_void>() as HWND,
            &mut action,
            &mut trust_data as *mut WINTRUST_DATA as *mut core::ffi::c_void,
        )
    };

    // Release the cached trust state, exactly as in the embedded path.
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: same live, exclusively owned structures; only the state action
    // changed. The return is deliberately ignored.
    unsafe {
        let _ = WinVerifyTrust(
            ptr::null_mut::<core::ffi::c_void>() as HWND,
            &mut action,
            &mut trust_data as *mut WINTRUST_DATA as *mut core::ffi::c_void,
        );
    }

    // A catalog entry existed but the OS rejected it (bad signature over the
    // catalog, revoked signer): a real negative answer.
    Some(status == 0)
}

/// The raw `HANDLE` behind an open `File`, for the FFI calls that need one.
fn file_handle(file: &mut std::fs::File) -> Option<HANDLE> {
    use std::os::windows::io::AsRawHandle;
    let raw = file.as_raw_handle();
    if raw.is_null() {
        None
    } else {
        Some(raw as HANDLE)
    }
}

fn trust_cache() -> &'static Mutex<HashMap<PathBuf, Option<bool>>> {
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, Option<bool>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Embedded Authenticode only: `WinVerifyTrust` over `WINTRUST_FILE_INFO`.
fn verify_embedded(path: &Path) -> Option<bool> {
    let wide_path = wide(&path.to_string_lossy());

    // SAFETY: `wide_path` is NUL-terminated and outlives both calls. The file
    // info is read-only for the duration of the call; `hFile` is left null, which
    // makes WinVerifyTrust open the path itself.
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wide_path.as_ptr(),
        hFile: ptr::null_mut(),
        pgKnownSubject: ptr::null_mut(),
    };

    // SAFETY: every pointer field either points at `file_info`, which is live for
    // the whole call, or is null. `Anonymous.pFile` is the union arm selected by
    // `dwUnionChoice = WTD_CHOICE_FILE`, so reading it as a file info is correct.
    let mut trust_data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: ptr::null_mut(),
        pSIPClientData: ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: windows_sys::Win32::Security::WinTrust::WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: ptr::null_mut(),
        pwszURLReference: ptr::null_mut(),
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        dwUIContext: 0,
        pSignatureSettings: ptr::null_mut(),
    };

    // `WinVerifyTrust` takes the action GUID by mutable pointer but never writes
    // through it; a local copy keeps the shared constant untouched.
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    // SAFETY: `action` and `trust_data` are live, correctly sized (`cbStruct` is
    // set) and exclusively owned here; the null window handle plus WTD_UI_NONE
    // means no UI can be reached. The return is a LONG trust status, not an
    // HRESULT failure code - it is interpreted, not checked for != 0.
    let status = unsafe {
        WinVerifyTrust(
            ptr::null_mut::<core::ffi::c_void>() as HWND,
            &mut action,
            &mut trust_data as *mut WINTRUST_DATA as *mut core::ffi::c_void,
        )
    };

    // Release the state WinVerifyTrust cached for this data block. Best-effort:
    // a failure here does not invalidate the answer we already have. `dwStateAction`
    // MUST be switched before the second call, and the trust data must not be
    // mutated by the caller in between.
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: same live, exclusively owned structures as above; only the state
    // action changed. The return is ignored deliberately - the trust answer has
    // already been captured.
    unsafe {
        let _ = WinVerifyTrust(
            ptr::null_mut::<core::ffi::c_void>() as HWND,
            &mut action,
            &mut trust_data as *mut WINTRUST_DATA as *mut core::ffi::c_void,
        );
    }

    // Anything that is not success is "not trusted". The one status worth
    // distinguishing is deliberately collapsed: both an unsigned file and an
    // invalid one are `Some(false)`, because the report says which in its own
    // evidence line using `has_embedded_signature`.
    Some(status == 0)
}

/// `CompanyName` from the file's version resource, if present.
///
/// **Untrusted.** Any binary can declare any company; this is an attribute of the
/// file's claims, not evidence about its origin. Callers must weigh it together
/// with `is_signature_trusted` (spec: a forged publisher string on an unsigned
/// binary is exactly the pattern a monitoring agent would present).
pub fn company_name(path: &Path) -> Option<String> {
    version_string(path, "CompanyName")
}

/// `ProductName` from the file's version resource, if present. Untrusted in the
/// same sense as [`company_name`]; used to spot vendor strings such as a product
/// name that matches a known monitoring agent.
pub fn product_name(path: &Path) -> Option<String> {
    version_string(path, "ProductName")
}

/// Does the file carry an embedded Authenticode signature at all, regardless of
/// whether it is trusted?
///
/// Distinct from [`is_signature_trusted`]: a file can carry a signature whose
/// chain does not validate (expired, revoked, self-signed). That state is itself
/// worth reporting, so the collector needs to tell "no signature" from "signature
/// that failed".
///
/// `false` also covers "could not tell" (missing file, unreadable): the certainty
/// only ever goes one way, so a false negative here never turns into a false
/// accusation.
pub fn has_embedded_signature(path: &Path) -> bool {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return false,
    };
    if !meta.is_file() {
        return false;
    }

    let wide_path = wide(&path.to_string_lossy());
    let mut encoding_type: u32 = 0;
    let mut content_type: u32 = 0;
    let mut format_type: u32 = 0;
    let mut store: HCERTSTORE = ptr::null_mut();
    let mut message: *mut core::ffi::c_void = ptr::null_mut();
    let mut context: *mut core::ffi::c_void = ptr::null_mut();

    // SAFETY: `wide_path` is NUL-terminated and outlives the call; every
    // out-parameter below points at a live local; requesting exactly the embedded
    // PKCS#7 signed content in binary form means the function allocates a message
    // store/context we own and must free.
    let ok = unsafe {
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wide_path.as_ptr() as *const core::ffi::c_void,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            &mut encoding_type,
            &mut content_type,
            &mut format_type,
            &mut store,
            &mut message,
            &mut context,
        )
    };

    // The query failed: no embedded signature we can see. Nothing was allocated
    // on a failure path, but the handles are still released defensively below.
    let found = ok != 0 && !store.is_null();

    // Release in reverse order of acquisition. `LocalFree` is correct for the
    // message and context: `CryptQueryObject` documents both as locally allocated
    // blobs, not as objects with their own free API.
    //
    // SAFETY: each handle is either null (skipped) or was returned by the
    // successful `CryptQueryObject` above and is freed exactly once here.
    unsafe {
        if !message.is_null() {
            let _ = CryptMsgClose(message);
        }
        if !context.is_null() {
            let _ = LocalFree(context);
        }
        if !store.is_null() {
            let _ = CertCloseStore(store, 0);
        }
    }

    found
}

/// Read one string field out of a PE version resource.
///
/// Returns `None` whenever the resource is absent, unreadable, oversized, or does
/// not contain the requested field; none of those is an error worth surfacing
/// individually, the absence is the information. The result is sanitised here so
/// no caller has to remember to (SR-2).
fn version_string(path: &Path, field: &str) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }

    let wide_path = wide(&path.to_string_lossy());

    // Size-then-allocate: ask how big the version resource is before allocating.
    // A zero return means the file has no version resource at all, which is the
    // norm for a plain executable and not an error.
    //
    // SAFETY: `wide_path` is NUL-terminated; the handle out-parameter receives an
    // opaque value we never use (the API sets a dummy 0 for file paths).
    let size = unsafe { GetFileVersionInfoSizeW(wide_path.as_ptr(), ptr::null_mut()) };
    if size == 0 || size > MAX_VERSION_BYTES {
        return None;
    }

    let mut buf = vec![0u8; size as usize];
    // SAFETY: `buf` is exactly `size` bytes as just reported; the length passed in
    // matches; a false return means the resource could not be read and the buffer
    // contents are unspecified, so the result is discarded.
    let ok = unsafe {
        GetFileVersionInfoW(
            wide_path.as_ptr(),
            0,
            size,
            buf.as_mut_ptr() as *mut core::ffi::c_void,
        )
    };
    if ok == 0 {
        return None;
    }

    for (language, codepage) in translations(&buf) {
        let sub_block = format!(r"\StringFileInfo\{language:04x}{codepage:04x}\{field}");
        if let Some(value) = query_string(&buf, &sub_block) {
            return Some(value);
        }
    }

    None
}

/// The `\VarFileInfo\Translation` table: (language, codepage) pairs, in order.
///
/// Falls back to the conventional pairs when the table is missing or empty, which
/// happens in resources produced by older or non-Microsoft toolchains.
fn translations(block: &[u8]) -> Vec<(u16, u16)> {
    let mut out = Vec::new();

    if let Some(value) = query_raw(block, r"\VarFileInfo\Translation", Unit::Bytes) {
        // The table is an array of 4-byte DWORDs: low word = language, high word
        // = codepage, both little-endian. A trailing partial entry is ignored
        // rather than misread.
        for chunk in value.as_bytes().chunks_exact(4) {
            let language = u16::from_le_bytes([chunk[0], chunk[1]]);
            let codepage = u16::from_le_bytes([chunk[2], chunk[3]]);
            out.push((language, codepage));
            if out.len() >= MAX_TRANSLATION_PROBES {
                break;
            }
        }
    }

    if out.is_empty() {
        out.extend_from_slice(&FALLBACK_TRANSLATIONS);
    }

    out
}

/// Look up one string sub-block and sanitise the result.
fn query_string(block: &[u8], sub_block: &str) -> Option<String> {
    let raw = query_raw(block, sub_block, Unit::Chars)?;
    let text = decode_utf16(raw.as_bytes());
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(sanitize(trimmed, MAX_STRING))
}

/// The raw bytes `VerQueryValueW` reports for a sub-block.
///
/// `VerQueryValueW` returns a pointer *into* the version block, so the bytes are
/// copied out immediately and never outlive the borrow of `block`.
///
/// `VerQueryValueW` walks the block as a `VS_VERSIONINFO` tree without validating
/// it, so it must only ever be handed a buffer that came straight from
/// `GetFileVersionInfoW`. The size floor below is the cheap half of that invariant:
/// a buffer too small to even hold the root header is refused before the API can
/// dereference a header that is not there.
///
/// `unit` is not decoration: the API reports the length in *bytes* for the binary
/// `\VarFileInfo\Translation` table but in *characters* (including the NUL) for a
/// `\StringFileInfo` string. Getting this wrong silently halves every publisher
/// name, which is exactly the sort of quiet corruption a report must not contain.
fn query_raw(block: &[u8], sub_block: &str, unit: Unit) -> Option<RawValue> {
    // Root VS_VERSIONINFO header at minimum. Real resources are 1 KiB+, so nothing
    // legitimate hits this floor.
    const MIN_BLOCK_BYTES: usize = 6;
    if block.len() < MIN_BLOCK_BYTES {
        return None;
    }

    let wide_sub = wide(sub_block);
    let mut value_ptr: *mut core::ffi::c_void = ptr::null_mut();
    let mut value_len: u32 = 0;

    // SAFETY: `block` is the buffer filled by `GetFileVersionInfoW` and is still
    // borrowed here; `wide_sub` is NUL-terminated. On success the out-parameters
    // describe a region inside `block`, which is copied before this function
    // returns, so the pointer is never used after the borrow ends.
    let ok = unsafe {
        VerQueryValueW(
            block.as_ptr() as *const core::ffi::c_void,
            wide_sub.as_ptr(),
            &mut value_ptr,
            &mut value_len,
        )
    };
    if ok == 0 || value_ptr.is_null() {
        return None;
    }

    // Convert the reported length into bytes: strings count 2 bytes per character.
    // Saturating, because a hostile resource can report a huge count.
    let reported_bytes = match unit {
        Unit::Bytes => value_len as usize,
        Unit::Chars => (value_len as usize).saturating_mul(2),
    };

    // The reported length is the API's own claim, but it is still clamped to the
    // block: a hostile resource must not be able to make us read past the buffer
    // we allocated (SR-4).
    let offset = (value_ptr as usize).checked_sub(block.as_ptr() as usize)?;
    if offset > block.len() {
        return None;
    }
    let len = reported_bytes.min(block.len() - offset);
    let bytes = block.get(offset..offset + len)?;

    Some(RawValue(bytes.to_vec()))
}

/// How `VerQueryValueW` counts the length it reports for a sub-block.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Unit {
    /// The `\VarFileInfo\Translation` table: the count is in bytes.
    Bytes,
    /// A `\StringFileInfo\...` string: the count is in UTF-16 characters,
    /// including the terminating NUL.
    Chars,
}

/// Bytes copied out of a version block. A newtype so a caller cannot accidentally
/// treat the pointer-into-block region as ordinary owned data.
struct RawValue(Vec<u8>);

impl RawValue {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Decode a NUL-terminated UTF-16 buffer, stopping at the first NUL and capping
/// the length so a missing terminator cannot make us walk the whole resource.
fn decode_utf16(bytes: &[u8]) -> String {
    let mut units: Vec<u16> = Vec::new();
    for chunk in bytes.chunks_exact(2) {
        let unit = u16::from_le_bytes([chunk[0], chunk[1]]);
        if unit == 0 {
            break;
        }
        units.push(unit);
        if units.len() >= MAX_IDENTITY_CHARS {
            break;
        }
    }
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp(tag: &str, data: &[u8]) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("irscan_sig_{tag}_{}.bin", std::process::id()));
        if let Ok(mut f) = std::fs::File::create(&path) {
            let _ = f.write_all(data);
            let _ = f.flush();
        }
        path
    }

    #[test]
    fn unsigned_file_is_reported_as_untrusted_not_unavailable() {
        // A file we just wrote a handful of arbitrary bytes into cannot carry a
        // valid Authenticode signature and cannot be in any catalog, so the trust
        // answer is Some(false): the question was answerable, the answer is "no".
        let path = write_temp("unsigned", b"this is not a signed PE image");
        assert_eq!(is_signature_trusted(&path), Some(false));
        assert!(!has_embedded_signature(&path));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_catalog_signed_system_binary_is_trusted() {
        // Regression pin. Embedded-only verification reported 38 of 56 sampled
        // System32 executables as untrusted, because Windows trusts most of them
        // through a catalog rather than an embedded signature. The truth of the
        // fix is observable: a genuine System32 executable the OS vouches for must
        // come back Some(true).
        //
        // No specific path is asserted: whichever binary exists on this host is
        // used, so the test travels across Windows versions and installs.
        let candidates = [
            r"System32\notepad.exe",
            r"System32\cmd.exe",
            r"System32\svchost.exe",
            r"System32\kernel32.dll",
        ];
        let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());

        let mut checked = 0;
        for candidate in candidates {
            let path = std::path::Path::new(&system_root).join(candidate);
            if !path.is_file() {
                continue;
            }
            checked += 1;
            assert_eq!(
                is_signature_trusted(&path),
                Some(true),
                "a genuine {candidate} must be trusted by the OS (catalog or embedded)"
            );
            if checked >= 2 {
                break;
            }
        }
        // If the host has none of these, the test cannot prove the fix either way
        // and says so rather than passing vacuously.
        assert!(checked > 0, "no System32 sample binary found on this host");
    }

    #[test]
    fn a_tampered_copy_of_a_signed_binary_is_untrusted() {
        // The dangerous failure mode of the catalog fix would be trusting any file
        // with a recognisable name. Corrupting the body of a signed System32 binary
        // changes its hash, so the catalog no longer covers it and the answer must
        // flip to Some(false).
        let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let source = std::path::Path::new(&system_root).join(r"System32\notepad.exe");
        let Ok(bytes) = std::fs::read(&source) else {
            return; // no sample on this host: nothing to tamper with
        };
        if bytes.len() < 4096 {
            return;
        }

        let mut damaged = bytes;
        let mid = damaged.len() / 2;
        if let Some(byte) = damaged.get_mut(mid) {
            *byte ^= 0xFF;
        }

        let mut path = std::env::temp_dir();
        path.push(format!("irscan_tampered_{}.exe", std::process::id()));
        if std::fs::write(&path, &damaged).is_err() {
            return;
        }

        assert_eq!(
            is_signature_trusted(&path),
            Some(false),
            "a byte-flipped copy must not inherit the original's trust"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn non_existent_path_is_none_and_false_not_a_panic() {
        let mut missing = std::env::temp_dir();
        missing.push("irscan_sig_definitely_absent_7ab2.exe");
        assert_eq!(is_signature_trusted(&missing), None);
        assert!(!has_embedded_signature(&missing));
        assert_eq!(company_name(&missing), None);
        assert_eq!(product_name(&missing), None);
    }

    #[test]
    fn a_directory_is_not_an_executable() {
        assert_eq!(is_signature_trusted(&std::env::temp_dir()), None);
        assert_eq!(company_name(&std::env::temp_dir()), None);
    }

    #[test]
    fn unsigned_image_has_no_publisher_strings() {
        // A non-PE file has no version resource, so both identity fields must be
        // absent rather than an empty string.
        let path = write_temp("nores", b"MZ but not a real PE");
        assert_eq!(company_name(&path), None);
        assert_eq!(product_name(&path), None);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn utf16_decoding_stops_at_nul_and_survives_malformed_input() {
        // "Hi\0" then junk: the NUL must terminate the string, not the junk.
        let bytes = [b'H', 0, b'i', 0, 0, 0, b'X', 0];
        assert_eq!(decode_utf16(&bytes), "Hi");
        // An odd trailing byte is ignored rather than panicking.
        assert_eq!(decode_utf16(&[b'A', 0, b'B']), "A");
        // A lone high surrogate becomes the replacement character, not a panic.
        assert!(decode_utf16(&[0x00, 0xD8]).contains('\u{fffd}'));
        // Over-long input is capped rather than unbounded.
        let long = vec![b'A'; MAX_IDENTITY_CHARS * 4];
        assert!(decode_utf16(&long).chars().count() <= MAX_IDENTITY_CHARS);
    }

    #[test]
    fn a_block_too_small_to_be_a_version_resource_is_refused() {
        // `VerQueryValueW` walks the block as a VS_VERSIONINFO tree without
        // validating it, so the wrapper must not hand it a buffer that cannot even
        // hold the root header - that would dereference unmapped memory. This is a
        // guard test: the previous version of this code passed `&[]` straight
        // through and took the process down with it.
        assert!(query_raw(&[], r"\VarFileInfo\Translation", Unit::Bytes).is_none());
        assert!(query_raw(
            &[0u8; 4],
            r"\StringFileInfo\040904b0\CompanyName",
            Unit::Chars
        )
        .is_none());
        assert!(query_string(&[0u8; 2], r"\StringFileInfo\040904b0\CompanyName").is_none());
    }

    #[test]
    fn the_translation_fallback_is_a_fixed_non_empty_set() {
        // The fallback list is what keeps a resource with an odd/missing
        // translation table from silently yielding no publisher at all.
        assert!(!FALLBACK_TRANSLATIONS.is_empty());
        assert!(FALLBACK_TRANSLATIONS.len() <= MAX_TRANSLATION_PROBES);
        assert!(FALLBACK_TRANSLATIONS.iter().all(|(_, cp)| *cp != 0));
        // The conventional US-English pair must be first: it is what almost every
        // Windows binary actually uses.
        assert_eq!(FALLBACK_TRANSLATIONS[0], (0x0409, 0x04b0));
    }

    #[test]
    fn repeated_queries_return_the_same_answer() {
        // The per-path cache is invisible to callers, so its only observable
        // contract is stability: asking twice about the same file must not change
        // the verdict (e.g. a release of a per-call context that broke the second
        // lookup).
        let path = write_temp("cached", b"still not signed, still not catalogued");
        let first = is_signature_trusted(&path);
        let second = is_signature_trusted(&path);
        assert_eq!(first, second);
        assert_eq!(first, Some(false));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_version_resource_cap_is_bounded() {
        // A hostile or corrupted file must not make the scanner allocate without
        // limit; the cap is a constant contract, not an incidental value. Checked at
        // compile time so the assertion cannot be edited away unnoticed.
        const _: () = assert!(MAX_VERSION_BYTES > 0);
        const _: () = assert!(MAX_VERSION_BYTES <= 16 * 1024 * 1024);
    }
}
