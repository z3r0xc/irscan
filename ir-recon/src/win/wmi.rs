//! Minimal read-only WMI client over raw COM: FR-6.
//!
//! WMI permanent event subscriptions are the classic **fileless** persistence
//! mechanism: a `__EventFilter` (the trigger) plus a `CommandLineEventConsumer` or
//! `ActiveScriptEventConsumer` (the payload) and a `__FilterToConsumerBinding` (the
//! wiring) live entirely in the `ROOT\SUBSCRIPTION` repository. Nothing lands on
//! disk, no service is registered, no scheduled task exists - so a scan that does
//! not query WMI cannot see it at all.
//!
//! This file is a **shim**: it connects, runs a WQL query and flattens each
//! resulting instance into `(property name, value as text)` pairs. It contains no
//! class knowledge and no rules; the collector decides what any of it means. That
//! split keeps the interesting logic unit-testable while the raw FFI stays small
//! enough to audit (docs/architecture.md section 6).
//!
//! Why hand-rolled COM rather than a crate:
//!
//! * `windows-sys` deliberately exposes **no** `IWbemLocator` / `IWbemServices` /
//!   `IEnumWbemClassObject` / `IWbemClassObject` vtables - the crate ships the MI
//!   (modern provider) API and the Wbem *GUIDs* only. The `WbemLocator` and
//!   `WbemLevel1Login` CLSIDs needed to reach `ROOT\SUBSCRIPTION` are present, so
//!   the vtables are declared here.
//! * A wrapper crate would be a new dependency on the machine under suspicion; this
//!   tool deliberately depends on nothing it did not ship with (spec section 8).
//!
//! FFI safety rules applied (docs/architecture.md section 6):
//!
//! * every interface pointer travels in an RAII guard ([`ComPtr`]), released exactly
//!   once on every path, error paths and panics included;
//! * [`Apartment`] pairs every successful `CoInitializeEx` with exactly one
//!   `CoUninitialize`, and treats "already initialised" (`S_FALSE`) and a
//!   conflicting apartment model (`RPC_E_CHANGED_MODE`) as survivable;
//! * every `HRESULT` is checked before the output parameter behind it is read;
//! * the instance count is capped by the caller's `max` and by
//!   [`MAX_WMI_INSTANCES_HARD_CAP`]; property values are bounded by
//!   `MAX_WMI_STRING` and `MAX_WMI_PROPERTIES`;
//! * `ExecQuery` is semisynchronous, forward-only, with a finite per-`Next` timeout,
//!   so no callback runs on a WMI thread and a stalled provider cannot hang the scan.

use std::ffi::c_void;

use windows_sys::core::{BSTR, GUID, HRESULT, PCWSTR};
use windows_sys::Win32::Foundation::{SysStringLen, RPC_E_CHANGED_MODE};
use windows_sys::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows_sys::Win32::System::Ole::{
    SafeArrayAccessData, SafeArrayGetLBound, SafeArrayGetUBound, SafeArrayGetVartype,
    SafeArrayUnaccessData,
};
use windows_sys::Win32::System::Variant::{
    VariantClear, VariantInit, VARIANT, VT_BOOL, VT_BSTR, VT_I2, VT_I4, VT_NULL, VT_UI2, VT_UI4,
};
use windows_sys::Win32::System::Wmi::WbemLocator;

use super::strings::{from_wide_len, wide};

/// COM apartment was already initialised by someone else: success, not failure.
const S_FALSE: HRESULT = 1;

/// `VARIANT` tag for BYREF, tested because a provider may hand one back.
const VT_BYREF: u16 = 0x4000;

/// `CIM_FLAG_ARRAY` as it appears in the `CIMTYPE` an `IWbemClassObject::Get`
/// reports. A WMI array property is *not* a `VARIANT` array, so `VariantClear`
/// will not release it - the `SAFEARRAY` branch below handles it, and this flag is
/// how that branch is chosen.
const CIM_FLAG_ARRAY: i32 = 8192;

/// Absolute ceiling on instances returned by one [`query`], whatever the caller
/// asks for. A hostile provider that ignores `max` must not become an unbounded
/// allocation (reliability tactic, architecture section 5.2).
pub const MAX_WMI_INSTANCES_HARD_CAP: usize = 4096;

/// Upper bound on one property value, in characters. A consumer's script text can
/// be long, but a megabyte of it is a hostile provider, not a finding.
const MAX_WMI_STRING: usize = 32 * 1024;

/// Upper bound on properties kept per instance: real WMI classes carry a few dozen.
const MAX_WMI_PROPERTIES: usize = 256;

/// Per-`Next` timeout in milliseconds. Replaces `WBEM_INFINITE`: a provider that
/// never answers must fail the query, not hang the scan.
const NEXT_TIMEOUT_MS: i32 = 5_000;

/// One WMI instance, flattened to text.
///
/// Property values are already strings: the collector compares them rather than
/// re-parsing them, so keeping the original type would only be another thing to get
/// wrong. Order follows the provider's own property order, which keeps two runs on
/// an unchanged host byte-identical.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WmiInstance {
    pub class: String,
    pub values: Vec<(String, String)>,
}

impl WmiInstance {
    /// First value whose property name matches `name`, case-insensitively.
    ///
    /// WMI property names are case-insensitive, and a hostile provider will happily
    /// emit `commandlinetemplate` where the SDK documents `CommandLineTemplate`.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.values
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// A property value, or `""` when the provider omitted it.
    pub fn text(&self, name: &str) -> String {
        self.get(name).unwrap_or_default().to_string()
    }
}

// ---------------------------------------------------------------------------
// Interface declarations
//
// `windows-sys` ships the Wbem GUIDs but not these vtables, so they are spelled
// out here. The layouts are the ones in `wbemidl.h`. Each vtable is copied from
// the SDK in declaration order because slots are reached by offset: a reordered or
// omitted entry silently calls the wrong function at runtime, which is the one
// failure mode this module cannot catch for you. Only `IWbemServices` and
// `IEnumWbemClassObject` carry method-typed slots; the rest are `*const c_void`
// because this tool never calls them and a function-pointer type it cannot verify
// would be a lie.
// ---------------------------------------------------------------------------

/// `IUnknown` prologue shared by every COM vtable.
#[repr(C)]
struct IUnknownVtbl {
    query_interface:
        unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> HRESULT,
    add_ref: unsafe extern "system" fn(*mut c_void) -> u32,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
}

/// `IWbemLocator`, whose only method this tool calls is `ConnectServer`.
#[repr(C)]
struct IWbemLocatorVtbl {
    base: IUnknownVtbl,
    /// `ConnectServer(sPath, user, password, locale, level, ctx, authority, ppNamespace)`.
    connect_server: unsafe extern "system" fn(
        *mut c_void,
        PCWSTR,
        PCWSTR,
        PCWSTR,
        PCWSTR,
        i32,
        PCWSTR,
        *mut c_void,
        *mut *mut c_void,
    ) -> HRESULT,
}

/// `IWbemServices` through `ExecQuery`, in the exact order of the SDK's
/// `IWbemServicesVtbl` (`wbemcli.h`).
///
/// The order matters more than anything else in this file: methods are reached by
/// vtable offset, and `ExecQuery` is **slot 20**, not slot 5 - an earlier draft of
/// this struct placed it after `CancelAsyncCall`, which silently called
/// `QueryObjectSink` and returned `WBEM_E_INVALID_PARAMETER` for every query. The
/// unused slots are kept as placeholders rather than omitted so the offset of
/// `exec_query` is fixed by the declaration itself, and a future reader cannot
/// "tidy" one away without moving it.
#[repr(C)]
struct IWbemServicesVtbl {
    base: IUnknownVtbl,
    open_namespace: *const c_void,             //  3
    cancel_async_call: *const c_void,          //  4
    query_object_sink: *const c_void,          //  5
    get_object: *const c_void,                 //  6
    get_object_async: *const c_void,           //  7
    put_class: *const c_void,                  //  8
    put_class_async: *const c_void,            //  9
    delete_class: *const c_void,               // 10
    delete_class_async: *const c_void,         // 11
    create_class_enum: *const c_void,          // 12
    create_class_enum_async: *const c_void,    // 13
    put_instance: *const c_void,               // 14
    put_instance_async: *const c_void,         // 15
    delete_instance: *const c_void,            // 16
    delete_instance_async: *const c_void,      // 17
    create_instance_enum: *const c_void,       // 18
    create_instance_enum_async: *const c_void, // 19
    /// 20: `ExecQuery(strQueryLanguage, strQuery, lFlags, pCtx, ppEnum)`.
    exec_query: unsafe extern "system" fn(
        *mut c_void,
        PCWSTR,
        PCWSTR,
        i32,
        *mut c_void,
        *mut *mut c_void,
    ) -> HRESULT,
}

/// `IEnumWbemClassObject` through `Next`, in the exact order of the SDK's
/// `IEnumWbemClassObjectVtbl` (`wbemcli.h`): `Reset` (3), `Next` (4).
#[repr(C)]
struct IEnumWbemClassObjectVtbl {
    base: IUnknownVtbl,
    reset: *const c_void, // 3
    /// 4: `Next(lTimeout, uCount, apObjects, puReturned)`. Returns `WBEM_S_FALSE`
    /// (0x00040004) when the enumerator is exhausted before `uCount` is reached.
    next: unsafe extern "system" fn(*mut c_void, i32, u32, *mut *mut c_void, *mut u32) -> HRESULT,
}

/// `IWbemClassObject` through `EndEnumeration`, in the exact order of the SDK's
/// `IWbemClassObjectVtbl` (`wbemcli.h`): `GetQualifierSet` (3), `Get` (4),
/// `Put` (5), `Delete` (6), `GetNames` (7), `BeginEnumeration` (8), `Next` (9),
/// `EndEnumeration` (10).
///
/// `GetQualifierSet` is the slot an earlier draft of this struct mistook for `Get`,
/// and the property walk uses this object's own `Next` - **not** an `IEnumVARIANT`,
/// which `BeginEnumeration` does not return.
#[repr(C)]
struct IWbemClassObjectVtbl {
    base: IUnknownVtbl,
    get_qualifier_set: *const c_void, // 3
    /// 4: `Get(strName, lFlags, pVal, pType, plFlavor)`.
    get: unsafe extern "system" fn(
        *mut c_void,
        PCWSTR,
        i32,
        *mut VARIANT,
        *mut i32,
        *mut i32,
    ) -> HRESULT,
    put: *const c_void,       // 5
    delete: *const c_void,    // 6
    get_names: *const c_void, // 7
    /// 8: `BeginEnumeration(lEnumFlags)` - starts a property walk on this object.
    begin_enumeration: unsafe extern "system" fn(*mut c_void, i32) -> HRESULT,
    /// 9: `Next(lFlags, strName, pVal, pType, plFlavor)` - one property per call.
    next: unsafe extern "system" fn(
        *mut c_void,
        i32,
        *mut BSTR,
        *mut VARIANT,
        *mut i32,
        *mut i32,
    ) -> HRESULT,
    /// 10: `EndEnumeration()`.
    end_enumeration: unsafe extern "system" fn(*mut c_void) -> HRESULT,
}

/// The vtable pointer of a COM interface: the first word of the object.
///
/// `None` for a null interface pointer. The `'static` is a fiction confined to this
/// module: every caller holds the interface alive in a `ComPtr` for at least as
/// long as it uses the returned reference.
fn vtable<T>(ptr: *mut c_void) -> Option<&'static T> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: a live COM interface pointer starts with a pointer to its own vtable,
    // and `T` is a `#[repr(C)]` mirror of the beginning of that vtable.
    unsafe { (*(ptr as *const *const T)).as_ref() }
}

/// A COM interface pointer, released exactly once when the guard drops.
///
/// The release goes through the interface's own vtable rather than through
/// `IUnknown`, so a provider that overrides `Release` behaves as it wants to;
/// taking the pointer out before calling makes a double drop impossible even if a
/// hostile `Release` re-enters this code.
struct ComPtr {
    ptr: Option<*mut c_void>,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
}

impl ComPtr {
    fn raw(&self) -> *mut c_void {
        self.ptr.unwrap_or(std::ptr::null_mut())
    }
}

impl Drop for ComPtr {
    fn drop(&mut self) {
        if let Some(p) = self.ptr.take() {
            // SAFETY: `p` came from a successful COM call, is exclusive to this
            // guard and has not yet been released; `release` is that same object's
            // vtable slot, so the ABI matches the object exactly.
            unsafe { (self.release)(p) };
        }
    }
}

/// Wrap a freshly obtained interface pointer, or `None` when it is null.
///
/// The caller has already checked the `HRESULT`; the null check is the last line of
/// defence against an in-proc server that succeeds and returns nothing.
fn guard(
    ptr: *mut c_void,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
) -> Option<ComPtr> {
    if ptr.is_null() {
        None
    } else {
        Some(ComPtr {
            ptr: Some(ptr),
            release,
        })
    }
}

/// A COM apartment, one `CoUninitialize` per successful `CoInitializeEx`.
///
/// `uninit: false` covers the two "somebody else already did this" outcomes:
/// `S_FALSE` (same model, already initialised) and `RPC_E_CHANGED_MODE` (a
/// different model is in place). Neither is fatal - COM is usable either way - but
/// calling `CoUninitialize` for either would unbalance the *other* owner's
/// reference count, so the guard simply does not.
struct Apartment {
    uninit: bool,
}

impl Apartment {
    /// Enter a multithreaded apartment.
    ///
    /// `Err` only when COM genuinely cannot be used at all.
    fn mta() -> Result<Self, String> {
        // SAFETY: a null reserved pointer is the documented "no OLE1 DDE" argument
        // for `CoInitializeEx`, and the call has no effect on the process beyond
        // apartment membership.
        let hr = unsafe { CoInitializeEx(std::ptr::null(), COINIT_MULTITHREADED as u32) };

        if hr >= 0 {
            return Ok(Self {
                uninit: hr != S_FALSE,
            });
        }

        if hr == RPC_E_CHANGED_MODE {
            // A different apartment model is already active. The calls below still
            // dispatch through it, so the query is worth attempting; the collector
            // reports anything that then fails.
            return Ok(Self { uninit: false });
        }

        Err(format!("CoInitializeEx failed ({})", hresult_hex(hr)))
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        if self.uninit {
            // SAFETY: this runs at most once, only after a `CoInitializeEx` this
            // guard owns returned success.
            unsafe { CoUninitialize() };
        }
    }
}

/// Hex form of an `HRESULT`, for an error message.
fn hresult_hex(hr: HRESULT) -> String {
    format!("0x{:08X}", hr as u32)
}

/// `IID_IWbemLocator`, from `wbemidl.h`.
const IID_IWBEM_LOCATOR: GUID = GUID::from_u128(0xdc12a687_737f_11cf_884d_00aa004b2e24);

/// Query `namespace` with `wql`, returning up to `max` instances.
///
/// `max` is clamped to [`MAX_WMI_INSTANCES_HARD_CAP`]; `max == 0` returns nothing
/// without touching WMI at all. `Err` carries a bounded, human-readable reason - a
/// broken or hostile provider must produce an error, never a panic and never a hang.
pub fn query(namespace: &str, wql: &str, max: usize) -> Result<Vec<WmiInstance>, String> {
    let limit = max.min(MAX_WMI_INSTANCES_HARD_CAP);
    if limit == 0 {
        return Ok(Vec::new());
    }

    let _apartment = Apartment::mta()?;
    let locator = create_locator()?;
    let services = connect_server(&locator, namespace)?;
    // The locator has done its job; release it now rather than holding a pointer
    // open for the duration of the enumeration.
    drop(locator);

    let enumerator = exec_query(&services, wql)?;
    collect_instances(&enumerator, limit)
}

/// `CoCreateInstance(WbemLocator, IID_IWbemLocator)`.
fn create_locator() -> Result<ComPtr, String> {
    let mut raw: *mut c_void = std::ptr::null_mut();

    // SAFETY: `WbemLocator` is a valid CLSID and `IID_IWBEM_LOCATOR` its IID; the
    // out-pointer is a valid slot; the class is in-process so
    // `CLSCTX_INPROC_SERVER` is the narrowest context that works. On failure the
    // out-pointer keeps the null it started as, which `guard` rejects.
    let hr = unsafe {
        CoCreateInstance(
            &WbemLocator,
            std::ptr::null_mut(),
            CLSCTX_INPROC_SERVER,
            &IID_IWBEM_LOCATOR,
            &mut raw,
        )
    };

    if hr < 0 {
        return Err(format!(
            "CoCreateInstance(WbemLocator) failed ({})",
            hresult_hex(hr)
        ));
    }

    // SAFETY: `raw` is a live `IWbemLocator`; its first word is the vtable pointer.
    match vtable::<IWbemLocatorVtbl>(raw).map(|vt| vt.base.release) {
        Some(r) => guard(raw, r).ok_or_else(|| "WbemLocator returned a null interface".to_string()),
        None => Err("WbemLocator returned a null vtable".to_string()),
    }
}

/// `IWbemLocator::ConnectServer` for `namespace`, with the current credentials.
fn connect_server(locator: &ComPtr, namespace: &str) -> Result<ComPtr, String> {
    let Some(vt) = vtable::<IWbemLocatorVtbl>(locator.raw()) else {
        return Err("IWbemLocator vtable is null".to_string());
    };

    let path = wide(namespace);
    let mut raw: *mut c_void = std::ptr::null_mut();

    // SAFETY: `locator.raw()` is live and exclusively owned by the guard; `path` is
    // NUL-terminated and outlives the call; every optional parameter is null/zero,
    // which OLE for WMI documents as "current identity, current locale, default
    // authority"; `raw` is a valid out-slot.
    let hr = unsafe {
        (vt.connect_server)(
            locator.raw(),
            path.as_ptr() as PCWSTR,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            std::ptr::null(),
            std::ptr::null_mut(),
            &mut raw,
        )
    };

    if hr < 0 {
        return Err(format!(
            "ConnectServer({namespace}) failed ({})",
            hresult_hex(hr)
        ));
    }

    // SAFETY: `raw` is a live `IWbemServices`.
    match vtable::<IWbemServicesVtbl>(raw).map(|v| v.base.release) {
        Some(r) => {
            guard(raw, r).ok_or_else(|| "ConnectServer returned a null interface".to_string())
        }
        None => Err("ConnectServer returned a null vtable".to_string()),
    }
}

/// `IWbemServices::ExecQuery`, semisynchronous and forward-only.
fn exec_query(services: &ComPtr, wql: &str) -> Result<ComPtr, String> {
    let Some(vt) = vtable::<IWbemServicesVtbl>(services.raw()) else {
        return Err("IWbemServices vtable is null".to_string());
    };

    let language = wide("WQL");
    let text = wide(wql);
    let mut raw: *mut c_void = std::ptr::null_mut();

    // `WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY` = 0x20 | 0x10.
    // Forward-only is what makes `Next` cheap, and return-immediately hands back an
    // enumerator instead of blocking inside the call.
    let flags: i32 = 0x30;

    // SAFETY: `services.raw()` is live; both strings are NUL-terminated and outlive
    // the call; the flags are a valid `WBEM_GENERIC_FLAG_TYPE` combination; a null
    // context is the documented "default"; `raw` is a valid out-slot.
    let hr = unsafe {
        (vt.exec_query)(
            services.raw(),
            language.as_ptr() as PCWSTR,
            text.as_ptr() as PCWSTR,
            flags,
            std::ptr::null_mut(),
            &mut raw,
        )
    };

    // Broken WQL fails here with `WBEM_E_INVALID_QUERY`, which is exactly the
    // "malformed query returns Err" contract the tests pin.
    if hr < 0 {
        return Err(format!("ExecQuery failed ({})", hresult_hex(hr)));
    }

    // SAFETY: `raw` is a live `IEnumWbemClassObject`.
    match vtable::<IEnumWbemClassObjectVtbl>(raw).map(|v| v.base.release) {
        Some(r) => guard(raw, r).ok_or_else(|| "ExecQuery returned a null enumerator".to_string()),
        None => Err("ExecQuery returned a null vtable".to_string()),
    }
}

/// Pull instances out of an enumerator, bounded by `limit`.
fn collect_instances(enumerator: &ComPtr, limit: usize) -> Result<Vec<WmiInstance>, String> {
    let Some(vt) = vtable::<IEnumWbemClassObjectVtbl>(enumerator.raw()) else {
        return Err("IEnumWbemClassObject vtable is null".to_string());
    };

    let mut out: Vec<WmiInstance> = Vec::new();

    while out.len() < limit {
        // One object per call: batching would need the same bounds on a larger
        // scratch array, and the cap above already stops a runaway enumeration.
        let mut raw: *mut c_void = std::ptr::null_mut();
        let mut returned: u32 = 0;

        // SAFETY: `enumerator.raw()` is live and exclusively owned here; `raw` and
        // `returned` are valid out-slots; `uCount` is 1, so at most one pointer is
        // written. The timeout is finite, so a stalled provider fails rather than
        // hanging the scan.
        let hr = unsafe {
            (vt.next)(
                enumerator.raw(),
                NEXT_TIMEOUT_MS,
                1,
                &mut raw,
                &mut returned,
            )
        };

        if hr < 0 {
            return Err(format!(
                "IEnumWbemClassObject::Next failed ({})",
                hresult_hex(hr)
            ));
        }

        // A zero count (or the `WBEM_S_FALSE` end marker) means "no more objects".
        if returned == 0 || raw.is_null() {
            break;
        }

        // SAFETY: `raw` is a live `IWbemClassObject`.
        let Some(release) = vtable::<IWbemClassObjectVtbl>(raw).map(|v| v.base.release) else {
            return Err("Next returned an object with a null vtable".to_string());
        };
        let Some(object) = guard(raw, release) else {
            return Err("Next returned a null interface".to_string());
        };

        out.push(read_instance(&object));
    }

    Ok(out)
}

/// Flatten one instance into its class name and property pairs.
///
/// Never fails. A provider that refuses property enumeration still yields the
/// instance's class, and that alone is worth reporting; returning `Err` here would
/// throw away what was already learned.
///
/// The walk is `BeginEnumeration` / `Next` / `EndEnumeration` on the object itself -
/// the SDK's property iteration, which hands back one name and value per call. This
/// is deliberately *not* an `IEnumVARIANT`: `BeginEnumeration` takes only a flags
/// argument and returns no enumerator, so borrowing one would be a layout lie.
fn read_instance(object: &ComPtr) -> WmiInstance {
    let mut values: Vec<(String, String)> = Vec::new();

    let Some(vt) = vtable::<IWbemClassObjectVtbl>(object.raw()) else {
        return WmiInstance {
            class: String::new(),
            values,
        };
    };

    // `__CLASS` is the instance's own class name. Read it directly first: it is the
    // one property guaranteed to be present, and it survives a provider that refuses
    // the enumeration walk.
    let mut class = read_class_name(object, vt).unwrap_or_default();

    // SAFETY: `object.raw()` is live. `lEnumFlags = 0` (`WBEM_FLAG_ALWAYS`) asks for
    // every property, not only the non-default ones.
    let hr = unsafe { (vt.begin_enumeration)(object.raw(), 0) };
    if hr < 0 {
        return WmiInstance { class, values };
    }

    // A provider that never signals "no more properties" is hostile. The bound is
    // twice the per-instance cap so skipped properties still cannot spin here.
    let mut probes = 0usize;
    while values.len() < MAX_WMI_PROPERTIES && probes < MAX_WMI_PROPERTIES * 2 {
        probes += 1;

        let mut name: BSTR = std::ptr::null();
        let mut value: VARIANT = VARIANT::default();
        // SAFETY: `value` is a valid, aligned `VARIANT`.
        unsafe { VariantInit(&mut value) };
        let mut cim_type: i32 = 0;
        let mut flavor: i32 = 0;

        // SAFETY: `object.raw()` is live; every out-parameter is a valid slot. The
        // function writes the name into `name`, which the API allocated and which is
        // released with `SysFreeString` below.
        let hr = unsafe {
            (vt.next)(
                object.raw(),
                0,
                &mut name,
                &mut value,
                &mut cim_type,
                &mut flavor,
            )
        };

        // `WBEM_S_NO_MORE_DATA` is a success code that means the walk is done.
        if hr < 0 || name.is_null() {
            clear_variant(&mut value);
            free_bstr(name);
            break;
        }

        let key = decode_bstr(name);
        free_bstr(name);

        if key.is_empty() {
            clear_variant(&mut value);
            continue;
        }

        let is_array = (cim_type & CIM_FLAG_ARRAY) != 0;
        let decoded = decode_variant(&value, is_array);
        clear_variant(&mut value);

        if let Some(text) = decoded {
            let text = crate::text::truncate(&text, MAX_WMI_STRING);
            if key.eq_ignore_ascii_case("__CLASS") {
                // Prefer the enumerator's own view if the direct read failed.
                if class.is_empty() {
                    class = text;
                }
            } else if key.starts_with("__") {
                // `__PATH`, `__RELPATH`, `__DERIVATION` and friends are WMI
                // metadata, not properties of the object the collector asked for.
            } else {
                values.push((key, text));
            }
        }
    }

    // SAFETY: the enumeration was started above and has not been ended.
    unsafe { (vt.end_enumeration)(object.raw()) };

    WmiInstance { class, values }
}

/// Read `__CLASS` from an instance, or `None` when the provider will not say.
fn read_class_name(object: &ComPtr, vt: &IWbemClassObjectVtbl) -> Option<String> {
    let key = wide("__CLASS");
    let mut value: VARIANT = VARIANT::default();
    // SAFETY: `value` is a valid, aligned `VARIANT`.
    unsafe { VariantInit(&mut value) };
    let mut cim_type: i32 = 0;
    let mut flavor: i32 = 0;

    // SAFETY: `object.raw()` is live; `key` outlives the call; the out-parameters
    // are valid slots.
    let hr = unsafe {
        (vt.get)(
            object.raw(),
            key.as_ptr() as PCWSTR,
            0,
            &mut value,
            &mut cim_type,
            &mut flavor,
        )
    };

    if hr < 0 {
        clear_variant(&mut value);
        return None;
    }

    let text = decode_variant(&value, false);
    clear_variant(&mut value);
    let text = text?;
    Some(crate::text::truncate(&text, MAX_WMI_STRING))
}

/// Free a `BSTR` the API handed us, tolerating null.
///
/// `Next` allocates the name with `SysAllocString`, so the caller owns it; a null
/// pointer (the "no more data" case) must not reach `SysFreeString` unguarded.
fn free_bstr(bstr: BSTR) {
    if bstr.is_null() {
        return;
    }
    // SAFETY: `bstr` came from `SysAllocString` inside the provider and has not been
    // freed; it is not retained anywhere after this call.
    unsafe { windows_sys::Win32::Foundation::SysFreeString(bstr) };
}

/// `VariantClear` without the double-clear hazard.
///
/// Clears in place and leaves the variant as `VT_EMPTY`, so a second call on the
/// same slot is a no-op rather than a double free - which matters because the
/// caller clears on both the normal and the early-exit path.
fn clear_variant(value: &mut VARIANT) {
    // SAFETY: `value` is an initialised `VARIANT` owned by the caller, which does
    // not use it again after this call. `VariantClear` sets it to `VT_EMPTY`.
    unsafe { VariantClear(value) };
}

/// `VT_ARRAY` tag bit, ORed with the element type in a `VARIANT`'s `vt`.
const VT_ARRAY_TAG: u16 = 0x2000;

/// `VT_VARIANT` - an array whose elements are themselves variants.
const VT_VARIANT_TAG: u16 = 12;

/// `VT_EMPTY` - a variant the provider never filled in.
const VT_EMPTY_TAG: u16 = 0;

/// Decode a `VARIANT` leniently.
///
/// Anything unrecognised becomes a readable placeholder rather than an error: a
/// property this tool cannot parse is still evidence that the instance exists, and
/// dropping the whole query over it would hide exactly the kind of unusual provider
/// worth seeing.
fn decode_variant(value: &VARIANT, is_array: bool) -> Option<String> {
    // SAFETY: `value` is an initialised `VARIANT`, so reading `vt` and then the
    // union member that `vt` selects is the documented access pattern.
    unsafe {
        let inner = &value.Anonymous.Anonymous;
        let vt = inner.vt;

        // A WMI array property arrives as `SAFEARRAY | <element type>`. Checked
        // before the scalar match because the tag carries both bits.
        if is_array || (vt & VT_ARRAY_TAG) != 0 {
            return Some(decode_string_array(inner.Anonymous.parray));
        }

        match vt {
            VT_BSTR => Some(decode_bstr(inner.Anonymous.bstrVal)),
            VT_NULL | VT_EMPTY_TAG => None,
            VT_I4 => Some(inner.Anonymous.lVal.to_string()),
            VT_UI4 => Some(inner.Anonymous.ulVal.to_string()),
            VT_I2 => Some(inner.Anonymous.iVal.to_string()),
            VT_UI2 => Some(inner.Anonymous.uiVal.to_string()),
            VT_BOOL => {
                let raw = inner.Anonymous.boolVal;
                Some(if raw == 0 { "false" } else { "true" }.to_string())
            }
            // A BYREF value is not followed: dereferencing an arbitrary pointer a
            // provider supplied is exactly the read this tool will not do.
            other if (other & VT_BYREF) != 0 => None,
            other => Some(format!("<variant 0x{other:04X}>")),
        }
    }
}

/// Read a `BSTR` as text, bounded and lossy. A null `BSTR` is the empty string.
fn decode_bstr(bstr: BSTR) -> String {
    if bstr.is_null() {
        return String::new();
    }

    // SAFETY: `bstr` is a live BSTR owned by the variant, which the caller clears
    // only after this returns. `SysStringLen` is the documented way to ask a BSTR
    // for its character count - the length comes from the allocation header, never
    // from a guess (SR-4).
    let len = unsafe { SysStringLen(bstr as *mut u16) } as usize;
    let chars = unsafe { std::slice::from_raw_parts(bstr, len) };
    from_wide_len(chars, len)
}

/// Render a `SAFEARRAY` of BSTRs as a comma-separated list, bounded.
///
/// Only reached for an array whose element type is `VT_BSTR` or `VT_VARIANT`. That
/// guard is load-bearing: `CreatorSID` on a `__EventFilter` is `VT_ARRAY | VT_UI1`,
/// and reading its buffer as `BSTR` pointers would dereference arbitrary bytes. A
/// non-string array is reported by its element type instead.
///
/// `SafeArrayAccessData` is used rather than per-element `SafeArrayGetElement`
/// because the elements must not be freed individually: the array owns them, and
/// double-freeing a BSTR handed over by a hostile provider is exactly the bug the
/// guard structure here exists to prevent.
fn decode_string_array(array: *mut windows_sys::Win32::System::Com::SAFEARRAY) -> String {
    if array.is_null() {
        return String::new();
    }

    // `SafeArrayGetVartype` reports the element type without the `VT_ARRAY` bit.
    let mut element_type: u16 = 0;
    // SAFETY: `array` is non-null and live; `element_type` is a valid out-slot.
    let type_hr = unsafe { SafeArrayGetVartype(array, &mut element_type) };
    if type_hr < 0 || (element_type != VT_BSTR && element_type != VT_VARIANT_TAG) {
        return format!("<array of variant 0x{element_type:04X}>");
    }

    let mut data: *mut c_void = std::ptr::null_mut();

    // SAFETY: `array` is non-null and live; `data` is a valid out-slot.
    let hr = unsafe { SafeArrayAccessData(array, &mut data) };
    if hr < 0 || data.is_null() {
        return String::new();
    }

    let mut parts: Vec<String> = Vec::new();

    // SAFETY: the array is locked, so its bounds and its element buffer are stable
    // for as long as `data` is held. Every element read is inside the bounds the
    // API itself reported.
    unsafe {
        let mut lower: i32 = 0;
        let mut upper: i32 = -1;
        let bounds_ok = SafeArrayGetLBound(array, 1, &mut lower) >= 0
            && SafeArrayGetUBound(array, 1, &mut upper) >= 0;

        if bounds_ok && upper >= lower {
            let count = ((upper - lower) as usize + 1).min(MAX_WMI_PROPERTIES);
            let elements = data as *const BSTR;
            for i in 0..count {
                parts.push(decode_bstr(elements.add(i).read()));
            }
        }
    }

    // SAFETY: the pointer came from a successful `SafeArrayAccessData` on this same
    // array and is released exactly once; the BSTRs stay owned by the array.
    unsafe { SafeArrayUnaccessData(array) };

    parts.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The namespace the WMI collector reads (FR-6). Named here so a test and the
    /// collector cannot disagree about it.
    const NAMESPACE: &str = r"ROOT\SUBSCRIPTION";

    /// Upper bound on an error message, mirroring the module's own discipline.
    const MAX_ERROR_TEXT_IN_TEST: usize = 1024;

    /// The point of this test is not "WMI returns the right thing" - that is a host
    /// property, not a code property. It is that a real `__EventFilter` query on a
    /// real machine neither panics nor hangs, whichever way the provider answers: a
    /// stopped `Winmgmt`, a denied `ROOT\SUBSCRIPTION` and a genuine empty set are
    /// all acceptable; a crash is not.
    #[test]
    fn event_filter_query_is_survivable() {
        match query(NAMESPACE, "SELECT * FROM __EventFilter", 16) {
            Ok(instances) => {
                // Whatever came back must respect the cap and be internally whole.
                assert!(instances.len() <= 16);
                for instance in &instances {
                    assert!(
                        instance.values.len() <= MAX_WMI_PROPERTIES,
                        "property cap not enforced"
                    );
                }
            }
            Err(message) => {
                // The error must be a real, diagnosable message - not an empty
                // string, and not a panicked thread.
                assert!(
                    !message.trim().is_empty(),
                    "error must say something: got {message:?}"
                );
                assert!(message.len() <= MAX_ERROR_TEXT_IN_TEST);
            }
        }
    }

    /// Syntactically broken WQL must come back as `Err`, not as a panic and not as a
    /// silent empty result that would read as "the host is clean".
    #[test]
    fn malformed_wql_returns_err() {
        let result = query(NAMESPACE, "SELECT * FROMM __EventFilter WHERE", 4);
        assert!(result.is_err(), "broken WQL must not report success");
    }

    /// A zero cap is honoured before COM is touched, so a caller can disable the
    /// query without paying for a connection.
    #[test]
    fn zero_max_returns_nothing() {
        assert_eq!(
            query(NAMESPACE, "SELECT * FROM __EventFilter", 0),
            Ok(Vec::new())
        );
    }

    #[test]
    fn instance_lookup_is_case_insensitive() {
        let instance = WmiInstance {
            class: "CommandLineEventConsumer".to_string(),
            values: vec![("CommandLineTemplate".to_string(), "calc.exe".to_string())],
        };
        assert_eq!(instance.get("commandlinetemplate"), Some("calc.exe"));
        assert_eq!(instance.get("COMMANDLINETEMPLATE"), Some("calc.exe"));
        assert_eq!(instance.get("ExecutablePath"), None);
    }

    #[test]
    fn missing_property_reads_as_empty_not_panic() {
        let instance = WmiInstance::default();
        assert_eq!(instance.text("Name"), "");
        assert_eq!(instance.get("Name"), None);
    }

    /// A null interface pointer must be rejected rather than dereferenced. This is
    /// the guard that stops a provider which "succeeds" with a null out-pointer
    /// from turning into a null-pointer read.
    #[test]
    fn null_interface_is_rejected() {
        // An `extern "system"` fn item, matching the release slot exactly; the
        // null pointer means it never runs.
        unsafe extern "system" fn release(_: *mut c_void) -> u32 {
            0
        }
        assert!(guard(std::ptr::null_mut(), release).is_none());
        assert!(vtable::<IUnknownVtbl>(std::ptr::null_mut()).is_none());
    }

    /// A non-null pointer with a plausible vtable round-trips through the guard and
    /// releases exactly the pointer it was given.
    #[test]
    fn guard_releases_only_the_pointer_it_wraps() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static RELEASED: AtomicUsize = AtomicUsize::new(0);

        unsafe extern "system" fn release(ptr: *mut c_void) -> u32 {
            RELEASED.store(ptr as usize, Ordering::SeqCst);
            0
        }

        let sentinel = 0x1234usize as *mut c_void;
        {
            let wrapped = guard(sentinel, release);
            assert!(wrapped.is_some(), "a non-null interface must be wrapped");
        }
        assert_eq!(RELEASED.load(Ordering::SeqCst), sentinel as usize);
    }

    /// Error text must be the hex form of the code, so a report reader can look it
    /// up without guessing its provenance.
    #[test]
    fn hresult_format_is_stable() {
        assert_eq!(hresult_hex(0x80041010u32 as HRESULT), "0x80041010");
        assert_eq!(hresult_hex(0), "0x00000000");
    }

    /// Unrecognised variant tags must degrade to a readable placeholder instead of
    /// being silently dropped - a provider emitting an unusual type should still be
    /// visible in the report.
    #[test]
    fn unknown_variant_tag_still_yields_text() {
        let mut value: VARIANT = VARIANT::default();
        // SAFETY: `value` is a valid, aligned `VARIANT`; setting `vt` to a tag with
        // no associated pointer is safe because no union member is read for a tag
        // that matches no known case.
        value.Anonymous.Anonymous.vt = 0x0042;
        let decoded = decode_variant(&value, false).unwrap_or_default();
        assert!(decoded.contains("0x0042"));
    }

    /// A null array must read as empty text, not as a dereference.
    #[test]
    fn null_safearray_decodes_empty() {
        assert_eq!(decode_string_array(std::ptr::null_mut()), "");
    }

    /// A null BSTR is the empty string, which is how a provider spells "present but
    /// not set".
    #[test]
    fn null_bstr_decodes_empty() {
        assert_eq!(decode_bstr(std::ptr::null()), "");
    }
}
