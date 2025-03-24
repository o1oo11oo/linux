// SPDX-License-Identifier: GPL-2.0

//! Bindings for Rust DABAC LSM.
//!
//! Implements the bare necessities to implement an LSM in Rust and register it,
//! using the bindings to C. Long term this should move to the kernel crate, but
//! for now this is easier here.
//!
//! Also implemented here are small glue functions that are called from the C
//! implementation of the dabac_rs securityfs, which was easier to do there than
//! getting started with all the Rust bindings for it. Long term that should be
//! replaced with a pure Rust implementation.

use kernel::{
    bindings, c_str,
    ffi::*,
    fs::LocalFile,
    prelude::*,
    str::CString,
    types::Opaque,
    uaccess::{UserPtr, UserSlice},
};

use crate::{pap, pdp};

/// The name the LSM gets registered under.
const NAME: &CStr = c_str!("dabac_rs");

/// The amount of hooks that get registered by this LSM.
///
/// This could be automatically calculated from the length of the array, but
/// would then still need to manually be adjusted there. Having it as a separate
/// constant simplifies access for calling [`security_add_hooks`]
/// though.
///
/// This is [`i32`] because that's what [`security_add_hooks`] expects. To use
/// it for the array length it is cast to usize, since that can hold larger
/// values on all relevant architectures.
///
/// [`security_add_hooks`]: bindings::security_add_hooks
const SECURITY_HOOK_LIST_LEN: i32 = 1;

/// Wrapper to be able to use `lsm_id` in a static context.
#[repr(transparent)]
struct LsmId(Opaque<bindings::lsm_id>);

// SAFETY: There is only a static instance and in that one the pointer field
// points to an immutable C string.
unsafe impl Sync for LsmId {}

/// Wrapper to be able to use `lsm_info` in a static context.
// Needs to be aligned to `size_of::<kernel::ffi::c_ulong>()`, but Rust
// attributes cannot express this and even statically setting it to 8 cannot be
// combined with `repr(transparent)`.
#[repr(transparent)]
struct LsmInfo(Opaque<bindings::lsm_info>);

// SAFETY: There is only a static instance and in that one the pointer fields
// point to an immutable C string and the init function defined here.
unsafe impl Sync for LsmInfo {}

/// Wrapper to be able to use `security_hook_list` in a static context.
#[repr(transparent)]
struct SecurityHookList(Opaque<[bindings::security_hook_list; SECURITY_HOOK_LIST_LEN as _]>);

// SAFETY: There is only a static instance, which is only modified from C during
// LSM initialization using the interior mutability of `Opaque`
unsafe impl Sync for SecurityHookList {}

/// Static information about the LSM.
static DABAC_RS_LSMID: LsmId = LsmId(Opaque::new(bindings::lsm_id {
    name: NAME.as_char_ptr(),
    id: bindings::LSM_ID_DABAC_RS as _,
}));

/// Registers the LSM in the kernel by placing it in the `.lsm_info.init` linker
/// section.
#[used]
#[link_section = ".lsm_info.init"]
static DABAC_RS_LSMINFO: LsmInfo = LsmInfo(Opaque::new(bindings::lsm_info {
    name: NAME.as_char_ptr(),
    init: Some(init),
    order: bindings::lsm_order_LSM_ORDER_MUTABLE,
    flags: 0,
    enabled: core::ptr::null_mut(),
    blobs: core::ptr::null_mut(),
}));

/// Init function for the LSM, gets called from C through the pointer stored in
/// `lsm_info`.
///
/// # Safety
///
/// This function must only be called once from the C LSM initialization code.
#[link_section = ".init.text"]
unsafe extern "C" fn init() -> c_int {
    pr_info!("Rust DABAC LSM is starting...\n");

    // Register the hooks
    // SAFETY: FFI call to register the hooks for the LSM. All pointers point to
    // statics which are only accessed from this init and are therefore valid
    // for the call. The hook list is modified using the interior mutability of
    // `Opaque`.
    unsafe {
        bindings::security_add_hooks(
            DABAC_RS_HOOKS.0.get().cast(),
            SECURITY_HOOK_LIST_LEN,
            DABAC_RS_LSMID.0.get(),
        );
    }

    // Call the normal init function for further component initialization
    if let Err(e) = super::init() {
        return e.to_errno();
    }

    pr_info!("Rust DABAC LSM is initialized!\n");

    0
}

/// List of hooks to register callbacks for.
///
/// The data stored here is updated by the LSM code during LSM initialization
/// using the interior mutability of [`Opaque`].
#[used]
#[link_section = ".data..ro_after_init"]
static DABAC_RS_HOOKS: SecurityHookList =
    SecurityHookList(Opaque::new([bindings::security_hook_list {
        // SAFETY: Creates an unaligned pointer to the mutable static since the
        // `static_calls_table` is `repr(packed)`. The pointers are only used
        // from C code.
        scalls: unsafe { &raw mut bindings::static_calls_table.file_permission as _ },
        hook: bindings::security_list_options {
            file_permission: Some(file_permission),
        },
        lsmid: DABAC_RS_LSMID.0.get(),
    }]));

/// Callback for the `file_permission` hook, gets called every time a file is
/// read or written.
///
/// # Safety
///
/// May only be called by the LSM framework as `file_permission` hook with a
/// file pointer valid for the duration of the call.
unsafe extern "C" fn file_permission(file: *mut bindings::file, mask: c_int) -> c_int {
    // SAFETY: `file` is valid for the duration of this call
    let file = unsafe { LocalFile::from_raw_file(file) };

    match pdp::file_permission(file, mask) {
        Ok(true) => 0,
        Ok(false) => EPERM.to_errno(),
        Err(e) => e.to_errno(),
    }
}

/// Read the currently set user attributes
///
/// Called from the C implementation of the dabac_rs securityfs. Small glue
/// function that gets the data from the PAP and then copies it to userspace.
///
/// # Safety
///
/// May only be used as `read` function pointer in `struct file_operations`
#[no_mangle]
unsafe extern "C" fn dabac_rs_read_user_attr(
    _file: *mut bindings::file,
    ptr: UserPtr,
    count: c_ulong,
    offset: *mut c_longlong,
) -> c_int {
    read_str(pap::read_user_attr, ptr, count, offset)
}

/// Update the user attributes
///
/// Called from the C implementation of the dabac_rs securityfs. Small glue
/// function that copies the data from userspace before delegating to the actual
/// function in the PAP.
///
/// # Safety
///
/// May only be used as `write` function pointer in `struct file_operations`
#[no_mangle]
unsafe extern "C" fn dabac_rs_update_user_attr(
    _file: *mut bindings::file,
    ptr: UserPtr,
    length: c_ulong,
    _offset: *mut c_longlong,
) -> c_int {
    update_policy_or_attrs(pap::update_user_attr, ptr, length)
}

/// Read the currently set object attributes
///
/// Called from the C implementation of the dabac_rs securityfs. Small glue
/// function that gets the data from the PAP and then copies it to userspace.
///
/// # Safety
///
/// May only be used as `read` function pointer in `struct file_operations`
#[no_mangle]
unsafe extern "C" fn dabac_rs_read_object_attr(
    _file: *mut bindings::file,
    ptr: UserPtr,
    count: c_ulong,
    offset: *mut c_longlong,
) -> c_int {
    read_str(pap::read_object_attr, ptr, count, offset)
}

/// Update the object attributes
///
/// Called from the C implementation of the dabac_rs securityfs. Small glue
/// function that copies the data from userspace before delegating to the actual
/// function in the PAP.
///
/// # Safety
///
/// May only be used as `write` function pointer in `struct file_operations`
#[no_mangle]
unsafe extern "C" fn dabac_rs_update_object_attr(
    _file: *mut bindings::file,
    ptr: UserPtr,
    length: c_ulong,
    _offset: *mut c_longlong,
) -> c_int {
    update_policy_or_attrs(pap::update_object_attr, ptr, length)
}

/// Read the currently set environmental attributes
///
/// Called from the C implementation of the dabac_rs securityfs. Small glue
/// function that gets the data from the PAP and then copies it to userspace.
///
/// # Safety
///
/// May only be used as `read` function pointer in `struct file_operations`
#[no_mangle]
unsafe extern "C" fn dabac_rs_read_env_attr(
    _file: *mut bindings::file,
    ptr: UserPtr,
    count: c_ulong,
    offset: *mut c_longlong,
) -> c_int {
    read_str(pap::read_env_attr, ptr, count, offset)
}

/// Update the environmental attributes
///
/// Called from the C implementation of the dabac_rs securityfs. Small glue
/// function that copies the data from userspace before delegating to the actual
/// function in the PAP.
///
/// # Safety
///
/// May only be used as `write` function pointer in `struct file_operations`
#[no_mangle]
unsafe extern "C" fn dabac_rs_update_env_attr(
    _file: *mut bindings::file,
    ptr: UserPtr,
    length: c_ulong,
    _offset: *mut c_longlong,
) -> c_int {
    update_policy_or_attrs(pap::update_env_attr, ptr, length)
}

/// Read the currently configured policy
///
/// Called from the C implementation of the dabac_rs securityfs. Small glue
/// function that gets the data from the PAP and then copies it to userspace.
///
/// # Safety
///
/// May only be used as `read` function pointer in `struct file_operations`
#[no_mangle]
unsafe extern "C" fn dabac_rs_read_policy(
    _file: *mut bindings::file,
    ptr: UserPtr,
    count: c_ulong,
    offset: *mut c_longlong,
) -> c_int {
    read_str(pap::read_policy, ptr, count, offset)
}

/// Update the policy
///
/// Called from the C implementation of the dabac_rs securityfs. Small glue
/// function that copies the data from userspace before delegating to the actual
/// function in the PAP.
///
/// # Safety
///
/// May only be used as `write` function pointer in `struct file_operations`
#[no_mangle]
unsafe extern "C" fn dabac_rs_update_policy(
    _file: *mut bindings::file,
    ptr: UserPtr,
    length: c_ulong,
    _offset: *mut c_longlong,
) -> c_int {
    update_policy_or_attrs(pap::update_policy, ptr, length)
}

/// Read a CString from user space
///
/// Implemented as helper function because they all do the same.
fn read_str(
    target: fn() -> Result<CString>,
    ptr: UserPtr,
    count: c_ulong,
    offset: *mut c_longlong,
) -> c_int {
    // Get the position requested
    // SAFETY: this function is called from C with a valid pointer for the offset
    let pos: usize = match unsafe { *offset }.try_into() {
        Ok(pos) => pos,
        Err(e) => return Into::<Error>::into(e).to_errno(),
    };

    // Get the data supposed to be sent to userspace
    let str = match target() {
        Ok(str) => str,
        Err(e) => return e.to_errno(),
    };
    let bytes = str.as_bytes();

    // Only continue if there are still bytes to read
    if pos >= bytes.len() || count == 0 {
        return 0;
    }

    // Limit the count to the remaining length of the bytes starting from pos
    let count = core::cmp::min(count, bytes.len().saturating_sub(pos));

    // Write to userspace
    let mut writer = UserSlice::new(ptr, count).writer();
    if let Err(e) = writer.write_slice(&bytes[pos..pos + count]) {
        return e.to_errno();
    }

    let count: i64 = match count.try_into() {
        Ok(count) => count,
        Err(e) => return Into::<Error>::into(e).to_errno(),
    };

    // SAFETY: this function is called from C with a valid pointer for the offset
    unsafe { *offset += count };

    count as _
}

/// Update stored policy or attributes
///
/// Implemented as helper function because they all do the same.
///
/// The unsafety of these functions is somewhat hidden by the linker, in C the
/// function definitions contain a pointer argument, while the same argument is
/// represented as UserPtr (usize) in Rust. Since there is no unsafe function to
/// create a UserPtr from an actual pointer, this is probably not the worst, but
/// still a bit shady.
fn update_policy_or_attrs(target: fn(&[u8]) -> Result, ptr: UserPtr, length: c_ulong) -> c_int {
    let mut buf = KVec::new();

    if let Err(e) = UserSlice::new(ptr, length).read_all(&mut buf, GFP_KERNEL) {
        return e.to_errno();
    }

    if let Err(e) = target(&buf) {
        return e.to_errno();
    }

    length as _
}
