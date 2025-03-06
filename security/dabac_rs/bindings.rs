// SPDX-License-Identifier: GPL-2.0

//! Bindings for Rust DABAC LSM.
//!
//! Implements the bare necessities to implement an LSM in Rust and register it,
//! using the bindings to C. Long term this should move to the kernel crate, but
//! for now this is easier here.

use kernel::{
    bindings::{
        lsm_id, lsm_info, lsm_order_LSM_ORDER_MUTABLE, security_add_hooks, security_hook_list,
        security_list_options, static_calls_table, LSM_ID_DABAC_RS,
    },
    c_str,
    prelude::*,
    types::Opaque,
};

use crate::pdp;

/// The name the LSM gets registered under.
const NAME: &CStr = c_str!("dabac_rs");

/// The amount of hooks that get registered. Easier to just define this here
/// than getting it from the array.
const SECURITY_HOOK_LIST_LEN: usize = 1;

/// Wrapper to be able to use `lsm_id` in a static context.
#[repr(transparent)]
struct LsmId(Opaque<lsm_id>);
unsafe impl Sync for LsmId {}

/// Wrapper to be able to use `lsm_info` in a static context.
// Needs to be aligned to size_of::<kernel::ffi::c_ulong>(), but Rust attributes
// cannot express this and even statically setting it to 8 cannot be combined
// with repr(transparent).
#[repr(transparent)]
struct LsmInfo(Opaque<lsm_info>);
unsafe impl Sync for LsmInfo {}

/// Wrapper to be able to use `security_hook_list` in a static context.
#[repr(transparent)]
struct SecurityHookList(Opaque<[security_hook_list; SECURITY_HOOK_LIST_LEN]>);
unsafe impl Sync for SecurityHookList {}

/// Static information about the LSM.
static DABAC_RS_LSMID: LsmId = LsmId(Opaque::new(lsm_id {
    name: NAME.as_char_ptr(),
    id: LSM_ID_DABAC_RS as _,
}));

/// Registers the LSM in the kernel by placing it in the `.lsm_info.init` linker
/// section.
#[used]
#[link_section = ".lsm_info.init"]
static DABAC_RS_LSMINFO: LsmInfo = LsmInfo(Opaque::new(lsm_info {
    name: NAME.as_char_ptr(),
    init: Some(dabac_rs_init),
    order: lsm_order_LSM_ORDER_MUTABLE,
    flags: 0,
    enabled: core::ptr::null_mut(),
    blobs: core::ptr::null_mut(),
}));

/// Init function for the LSM, gets called from C through the pointer stored in
/// `lsm_info`.
#[no_mangle]
#[link_section = ".init.text"]
pub extern "C" fn dabac_rs_init() -> kernel::ffi::c_int {
    pr_info!("Rust DABAC LSM is starting...\n");

    // Register hooks
    unsafe {
        security_add_hooks(
            &raw mut DABAC_RS_HOOKS.0 as _,
            SECURITY_HOOK_LIST_LEN as _,
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

/// List of hooks to register callbacks for. Length must match
/// `SECURITY_HOOK_LIST_LEN`.
#[used]
#[link_section = ".data..ro_after_init"]
static mut DABAC_RS_HOOKS: SecurityHookList = SecurityHookList(Opaque::new([security_hook_list {
    scalls: unsafe { &raw mut static_calls_table.file_permission as _ },
    hook: security_list_options {
        file_permission: Some(dabac_rs_file_permission),
    },
    lsmid: DABAC_RS_LSMID.0.get(),
}]));

/// Callback for the `file_permission` hook, gets called every time a file is
/// read or written.
#[no_mangle]
pub extern "C" fn dabac_rs_file_permission(
    file: *mut kernel::bindings::file,
    mask: kernel::ffi::c_int,
) -> kernel::ffi::c_int {
    let file = unsafe { kernel::fs::File::from_raw_file(file) };

    match pdp::file_permission(file, mask) {
        Ok(allowed) => {
            if allowed {
                0
            } else {
                EPERM.to_errno()
            }
        }
        Err(e) => e.to_errno(),
    }
}
