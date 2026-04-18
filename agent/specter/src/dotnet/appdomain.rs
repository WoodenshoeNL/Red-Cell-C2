//! AppDomain isolation: creation, QueryInterface, and teardown helpers.
//!
//! Teardown (domain unload + runtime stop) is handled automatically by
//! [`super::runtime::ClrSession`]'s [`Drop`] implementation.  This module
//! exposes the creation side.

#![allow(unsafe_code)]

use std::ffi::c_void;
use tracing::{debug, error};

use super::runtime::{
    APP_DOMAIN_LOAD_3, ASSEMBLY_ENTRY_POINT, COR_HOST_CREATE_DOMAIN, IID_APP_DOMAIN,
    IUNKNOWN_QUERY_INTERFACE, METHOD_INFO_INVOKE_3, S_OK, vtable_fn,
};

/// Create a new AppDomain and QueryInterface it to `_AppDomain`.
///
/// On success, writes the raw `ICorRuntimeHost` domain thunk to
/// `*app_domain_thunk_out` and the `_AppDomain` interface pointer to
/// `*app_domain_out`.
///
/// # Safety
///
/// `cor_runtime_host` must be a valid `ICorRuntimeHost` COM pointer.
/// `domain_name_wide` must be a null-terminated UTF-16 slice.
/// Both output pointers must be non-null and point to null-initialised slots.
pub(super) unsafe fn create_appdomain(
    cor_runtime_host: *mut c_void,
    domain_name_wide: &[u16],
    app_domain_thunk_out: &mut *mut c_void,
    app_domain_out: &mut *mut c_void,
) -> Result<(), String> {
    // ICorRuntimeHost::CreateDomain
    // Signature: CreateDomain(this, friendlyName, identityArray, appDomain)
    let create_domain: unsafe extern "system" fn(
        *mut c_void,
        *const u16,
        *mut c_void,
        *mut *mut c_void,
    ) -> i32 = std::mem::transmute(vtable_fn(cor_runtime_host, COR_HOST_CREATE_DOMAIN));
    let hr = create_domain(
        cor_runtime_host,
        domain_name_wide.as_ptr(),
        std::ptr::null_mut(),
        app_domain_thunk_out,
    );
    if hr != S_OK {
        error!("CreateDomain failed: HRESULT 0x{hr:08X}");
        return Err(format!("CreateDomain HRESULT 0x{hr:08X}"));
    }
    debug!("AppDomain created");

    // IUnknown::QueryInterface to get the typed _AppDomain pointer.
    let qi: unsafe extern "system" fn(
        *mut c_void,
        *const super::runtime::Guid,
        *mut *mut c_void,
    ) -> i32 = std::mem::transmute(vtable_fn(*app_domain_thunk_out, IUNKNOWN_QUERY_INTERFACE));
    let hr = qi(*app_domain_thunk_out, &IID_APP_DOMAIN, app_domain_out);
    if hr != S_OK {
        error!("QueryInterface(_AppDomain) failed: HRESULT 0x{hr:08X}");
        return Err(format!("QI AppDomain HRESULT 0x{hr:08X}"));
    }

    Ok(())
}

/// Load a raw assembly byte array into an AppDomain via `_AppDomain::Load_3`.
///
/// On success writes the `_Assembly` COM pointer to `*assembly_out`.
///
/// # Safety
///
/// `app_domain` must be a valid `_AppDomain` COM pointer.
/// `safe_array` must be a `SAFEARRAY(VT_UI1)` holding the assembly bytes.
pub(super) unsafe fn load_assembly_into_domain(
    app_domain: *mut c_void,
    safe_array: *mut c_void,
    assembly_out: &mut *mut c_void,
) -> Result<(), String> {
    // _AppDomain::Load_3(this, rawAssembly: *mut SAFEARRAY, pRetVal: *mut *mut Assembly)
    let load_3: unsafe extern "system" fn(*mut c_void, *mut c_void, *mut *mut c_void) -> i32 =
        std::mem::transmute(vtable_fn(app_domain, APP_DOMAIN_LOAD_3));
    let hr = load_3(app_domain, safe_array, assembly_out);
    if hr != S_OK {
        error!("_AppDomain::Load_3 failed: HRESULT 0x{hr:08X}");
        return Err(format!("Load_3 HRESULT 0x{hr:08X}"));
    }
    Ok(())
}

/// Resolve the entry point of a loaded `_Assembly` via `_Assembly::EntryPoint`.
///
/// On success writes the `_MethodInfo` COM pointer to `*method_info_out`.
///
/// # Safety
///
/// `assembly` must be a valid `_Assembly` COM pointer.
pub(super) unsafe fn resolve_entry_point(
    assembly: *mut c_void,
    method_info_out: &mut *mut c_void,
) -> Result<(), String> {
    // _Assembly::EntryPoint(this, pRetVal: *mut *mut _MethodInfo)
    let entry_point: unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> i32 =
        std::mem::transmute(vtable_fn(assembly, ASSEMBLY_ENTRY_POINT));
    let hr = entry_point(assembly, method_info_out);
    if hr != S_OK {
        error!("_Assembly::EntryPoint failed: HRESULT 0x{hr:08X}");
        return Err(format!("EntryPoint HRESULT 0x{hr:08X}"));
    }
    Ok(())
}

/// Invoke the resolved `_MethodInfo` entry point via `_MethodInfo::Invoke_3`.
///
/// Returns the raw HRESULT so the caller can decide whether to treat it as
/// success or failure (and emit the appropriate [`super::DotnetCallback`]).
///
/// # Safety
///
/// `method_info` must be a valid `_MethodInfo` COM pointer.
/// `obj` is the `this` VARIANT (pass `Variant::empty()` for a static `Main`).
/// `method_args` must be a `SAFEARRAY(VARIANT)` or null.
pub(super) unsafe fn invoke_entry_point(
    method_info: *mut c_void,
    obj: super::runtime::Variant,
    method_args: *mut c_void,
) -> i32 {
    use super::runtime::Variant;

    let mut ret = Variant::empty();
    // _MethodInfo::Invoke_3(this, obj: VARIANT, parameters: *mut SAFEARRAY, ret: *mut VARIANT)
    let invoke_3: unsafe extern "system" fn(
        *mut c_void,
        Variant,
        *mut c_void,
        *mut Variant,
    ) -> i32 = std::mem::transmute(vtable_fn(method_info, METHOD_INFO_INVOKE_3));
    invoke_3(method_info, obj, method_args, &mut ret)
}
