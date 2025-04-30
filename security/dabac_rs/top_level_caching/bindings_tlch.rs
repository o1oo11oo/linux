// SPDX-License-Identifier: GPL-2.0

//! Variant-dependant bindings for Rust DABAC LSM (TLCH).
//!
//! Variant: top level caching with hashing (TLCH)

use kernel::{bindings, ffi::*, uaccess::UserPtr};

use crate::{
    bindings::{read_str, update_policy_or_attrs},
    pap,
};

extern "C" {
    fn dabac_rs_tlch_init_done();
}

/// Signal the securityfs that the LSM was initialized
///
/// # Safety
///
/// Must only be called during init after the LSM was successfully initialized.
pub(crate) unsafe fn init_done() {
    // SAFETY: only called during init, no other requirements for FFI call
    unsafe {
        dabac_rs_tlch_init_done();
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
unsafe extern "C" fn dabac_rs_tlch_read_user_attr(
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
unsafe extern "C" fn dabac_rs_tlch_update_user_attr(
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
unsafe extern "C" fn dabac_rs_tlch_read_object_attr(
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
unsafe extern "C" fn dabac_rs_tlch_update_object_attr(
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
unsafe extern "C" fn dabac_rs_tlch_read_env_attr(
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
unsafe extern "C" fn dabac_rs_tlch_update_env_attr(
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
unsafe extern "C" fn dabac_rs_tlch_read_policy(
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
unsafe extern "C" fn dabac_rs_tlch_update_policy(
    _file: *mut bindings::file,
    ptr: UserPtr,
    length: c_ulong,
    _offset: *mut c_longlong,
) -> c_int {
    update_policy_or_attrs(pap::update_policy, ptr, length)
}
