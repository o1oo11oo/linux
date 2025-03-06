// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM PDP.
//!
//! Policy Decision Point for Rust-based DABAC LSM.

use kernel::{c_str, fs::File, pr_info, prelude::*, task::Kuid};

use crate::{helpers, pip, AVP};

const PROTECTED_PATH: &CStr = c_str!("/home/dabac_rs/");

type Rule = (UserAVP, ObjectAVP);
type UserAVP = AVP;
type ObjectAVP = AVP;

const POLICY: [Rule; 3] = [
    (
        (c_str!("role"), c_str!("admin")),
        (c_str!("protection"), c_str!("secret")),
    ),
    (
        (c_str!("role"), c_str!("admin")),
        (c_str!("protection"), c_str!("open")),
    ),
    (
        (c_str!("role"), c_str!("user")),
        (c_str!("protection"), c_str!("open")),
    ),
];

/// Rust implementation of the file_permission hook.
///
/// Gets called everytime a file gets read or written. Returns Ok(true) when the
/// access should be allowed, Ok(false) otherwise. Errors most commonly occur on
/// allocation failures.
pub(crate) fn file_permission(file: &File, _mask: i32) -> Result<bool> {
    let full_name = helpers::file_get_full_name(file)?;

    // Allow everything unprotected/out of scope
    if !is_protected(&full_name) {
        return Ok(true);
    }

    let uid = Kuid::current_euid().into_uid_in_current_ns();
    let u_attr = pip::get_user_attributes(uid);
    let o_attr = pip::get_object_attributes(&full_name);
    pr_info!("User {uid} (attr: {u_attr:?}) ist trying to access {full_name:?} (attr: {o_attr:?})");

    // Check policy for protected files
    let resolution = resolve(u_attr, o_attr);

    if resolution {
        pr_info!("Access granted");
        Ok(true)
    } else {
        pr_info!("Access denied");
        Ok(false)
    }
}

fn resolve(u_attr: &[AVP], o_attr: &[AVP]) -> bool {
    POLICY
        .iter()
        .any(|(u, o)| u_attr.contains(u) && o_attr.contains(o))
}

fn is_protected(name: &CStr) -> bool {
    name.starts_with(&PROTECTED_PATH)
}
