// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM PDP.
//!
//! Policy Decision Point for Rust-based DABAC LSM.

use kernel::{c_str, fs::File, pr_info, prelude::*, task::Kuid};

use crate::{helpers, pip};

const PROTECTED_PATH: &CStr = c_str!("/home/dabac_rs/");

/// TODO doc comment
pub(crate) fn file_permission(file: &File, _mask: i32) -> Result<bool> {
    let full_name = helpers::file_get_full_name(file)?;

    // Allow everything unprotected/out of scope
    if !is_protected(&full_name) {
        return Ok(true);
    }

    let uid = Kuid::current_euid().into_uid_in_current_ns();
    let u_attr = pip::get_user_attributes(uid);
    let f_attr = pip::get_object_attributes(&full_name);
    pr_info!("User {uid} (attr: {u_attr:?}) ist trying to access {full_name:?} (attr: {f_attr:?})");

    // Also allow everything else for now :D
    Ok(true)
}

fn is_protected(name: &CStr) -> bool {
    name.starts_with(&PROTECTED_PATH)
}
