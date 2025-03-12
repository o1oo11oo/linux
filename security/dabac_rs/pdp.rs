// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM PDP.
//!
//! Policy Decision Point for Rust-based DABAC LSM.

use core::ops::Deref;

use kernel::{
    c_str,
    fs::File,
    pr_info,
    prelude::*,
    sync::{
        global_lock,
        rcu::{self, Rcu},
        ProjectableGlobalLockedBy,
    },
    task::Kuid,
};

use crate::{
    epp, helpers, pip,
    policy::{Attributions, Policy},
};

const PROTECTED_PATH: &CStr = c_str!("/home/dabac_rs/");

global_lock! {
    // SAFETY: Initialized in module initializer before first use.
    unsafe(uninit) static POLICY_WRITE_GUARD: Mutex<()> = ();
}

static POLICY: ProjectableGlobalLockedBy<Rcu<KBox<Policy>>, POLICY_WRITE_GUARD> =
    ProjectableGlobalLockedBy::new(Rcu::null());

/// Initialize the PDP during LSM initialization
pub(crate) fn init() -> Result<()> {
    // SAFETY: Called exactly once.
    unsafe { POLICY_WRITE_GUARD.init() };

    // The attributes are encoded because it is simpler to work with
    // (implementing Copy means they use no lifetimes) and can be used for
    // formula evaluation in a simpler way. Attribute identifiers as usize also
    // allow (ab-)using Vecs as HashMaps. See PIP for an int => string mapping.

    let policy = "u0=c0 & o0=c0 => -o /home/dabac_rs/a: 0=0, +o /home/dabac_rs/a: 0=1;
        u0=c0 & o0=c1 => +u 1000: 0=0, -u 1000: 0=0;
        u0=c1 & o0=c1"
        .parse()?;
    set_policy(policy)?;

    Ok(())
}

pub(crate) fn set_policy(policy: Policy) -> Result<()> {
    let mut guard = POLICY_WRITE_GUARD.lock();
    let mut policy_writer = POLICY.as_mut(&mut guard);
    let policy = KBox::new(policy, GFP_KERNEL)?;
    policy_writer.as_mut().read_copy_update(|_| Some(policy));

    Ok(())
}

/// Rust implementation of the file_permission hook.
///
/// Gets called everytime a file gets read or written. Returns Ok(true) when the
/// access should be allowed, Ok(false) otherwise. Errors most commonly occur on
/// allocation failures.
pub(crate) fn file_permission(file: &File, _mask: i32) -> Result<bool> {
    let full_name = helpers::file_get_full_name(file)?;
    let inode = helpers::file_get_inode_number(file);

    // Allow everything unprotected/out of scope
    if !is_protected(&full_name) {
        return Ok(true);
    }

    let uid = Kuid::current_euid().into_uid_in_current_ns();
    let user_attr = pip::get_user_attributes(uid)?;
    let object_attr = pip::get_object_attributes(&full_name)?;
    pr_info!("User {uid} (attr: {user_attr:?}) ist trying to access {full_name:?} (inode: {inode}) (attr: {object_attr:?})");

    // Check policy for protected files
    let resolution = resolve(&user_attr, &object_attr)?;

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
///
/// If a rule matches, its post-condition is executed by the EPP, if one exists.
fn resolve(user_attr: &Attributions, object_attr: &Attributions) -> Result<bool> {
    let policy = POLICY.deref();
    let rcu_guard = rcu::read_lock();
    let Some(policy) = policy.dereference(&rcu_guard) else {
        // No policy defined => default deny
        return Ok(false);
    };

    for rule in &policy.rules {
        if rule.pre.formula.evaluate(user_attr, object_attr)? {
            if !rule.post.changes.is_empty() {
                epp::execute_postcondition(&rule.post)?;
            }

            return Ok(true);
        }
    }

    return Ok(false);
}

fn is_protected(name: &CStr) -> bool {
    name.starts_with(&PROTECTED_PATH)
}
