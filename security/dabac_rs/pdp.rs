// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM PDP.
//!
//! Policy Decision Point for Rust-based DABAC LSM.

use kernel::{c_str, fs::File, kvec, pr_info, prelude::*, sync::global_lock, task::Kuid};

use crate::{helpers, pip, AVP};

const PROTECTED_PATH: &CStr = c_str!("/home/dabac_rs/");

global_lock! {
    // SAFETY: Initialized in module initializer before first use.
    unsafe(uninit) static POLICY: Mutex<Policy> = Policy {rules: KVec::new()};
}

struct Policy {
    rules: KVec<Rule>,
}

struct Rule {
    user_attr: KVec<AVP>,
    object_attr: KVec<AVP>,
}

/// Initialize the PDP during LSM initialization
pub(crate) fn init() -> Result<()> {
    // SAFETY: Called exactly once.
    unsafe { POLICY.init() };

    let mut guard = POLICY.lock();
    guard.rules.reserve(3, GFP_KERNEL)?;
    guard.rules.push(
        Rule {
            user_attr: kvec![(c_str!("role"), c_str!("admin"))]?,
            object_attr: kvec![(c_str!("protection"), c_str!("secret"))]?,
        },
        GFP_KERNEL,
    )?;
    guard.rules.push(
        Rule {
            user_attr: kvec![(c_str!("role"), c_str!("admin"))]?,
            object_attr: kvec![(c_str!("protection"), c_str!("open"))]?,
        },
        GFP_KERNEL,
    )?;
    guard.rules.push(
        Rule {
            user_attr: kvec![(c_str!("role"), c_str!("user"))]?,
            object_attr: kvec![(c_str!("protection"), c_str!("open"))]?,
        },
        GFP_KERNEL,
    )?;

    Ok(())
}

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
    let u_attr = pip::get_user_attributes(uid)?;
    let o_attr = pip::get_object_attributes(&full_name)?;
    pr_info!("User {uid} (attr: {u_attr:?}) ist trying to access {full_name:?} (attr: {o_attr:?})");

    // Check policy for protected files
    let resolution = resolve(&u_attr, &o_attr);

    if resolution {
        pr_info!("Access granted");
        Ok(true)
    } else {
        pr_info!("Access denied");
        Ok(false)
    }
}

/// Policy resolution function.
///
/// At least one rule needs to be fulfilled, which means
/// the user   needs to have at least the user   AVPs required by the rule and
/// the object needs to have at least the object AVPs required by the rule.
/// The values of the attributes need to be equal.
fn resolve(u_attr: &[AVP], o_attr: &[AVP]) -> bool {
    POLICY.lock().rules.iter().any(|r| {
        r.user_attr.iter().all(|u| u_attr.contains(u))
            && r.object_attr.iter().all(|o| o_attr.contains(o))
    })
}

fn is_protected(name: &CStr) -> bool {
    name.starts_with(&PROTECTED_PATH)
}
