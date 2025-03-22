// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM PDP.
//!
//! Policy Decision Point for Rust-based DABAC LSM.

use kernel::{
    bindings, c_str,
    fs::File,
    hash::HashMap,
    prelude::*,
    str::CString,
    sync::{
        global_lock,
        rcu::{self, Rcu},
        ProjectableGlobalLockedBy,
    },
};

use crate::{
    epp, helpers, pip,
    policy::{self, Policy},
};

const PROTECTED_PATH: &CStr = c_str!("/home/dabac_rs/");

global_lock! {
    // SAFETY: Initialized in module initializer before first use.
    unsafe(uninit) static POLICY_WRITE_GUARD: Mutex<()> = ();
}

global_lock! {
    // SAFETY: Initialized in module initializer before first use.
    unsafe(uninit) static CACHE: Mutex<HashMap<(usize, usize, usize), bool>> = unsafe { HashMap::new_uninitialized() };
}

static POLICY: ProjectableGlobalLockedBy<Rcu<KBox<Policy>>, POLICY_WRITE_GUARD> =
    ProjectableGlobalLockedBy::new(Rcu::null());

/// Initialize the PDP during LSM initialization
pub(crate) fn init() -> Result<()> {
    // SAFETY: All initializers are called exactly once.
    unsafe {
        POLICY_WRITE_GUARD.init();
        CACHE.init();
    };

    // Properly initialize the HashMap by resetting it
    CACHE.lock().reset();

    // The attributes are encoded because it is simpler to work with
    // (implementing Copy means they use no lifetimes) and can be used for
    // formula evaluation in a simpler way. Attribute identifiers as usize also
    // allow (ab-)using Vecs as HashMaps. See PIP for an int => string mapping.

    // Operations:
    // - 0: file read
    // - 1: file write

    let policy = "0:= u0=c1 & o0=c1;
        1:= u0=c1 & o0=c1 => +o 1048581: 0=2;
        0:= u0=c1 & o0=c2 | u0=c2 & o0=c2;
        1:= u0=c1 & o0=c2 | u0=c2 & o0=c2;
        0:= o0=c3 & e0>c16;
        1:= o0=c3 & e0>c16"
        .parse()?;
    set_policy(policy)?;
    pr_info!("Policy initialized");

    Ok(())
}

pub(crate) fn get_serialized_policy() -> Result<CString> {
    let rcu_guard = rcu::read_lock();
    if let Some(policy) = POLICY.dereference(&rcu_guard) {
        CString::try_from_fmt(fmt!("{}", policy))
    } else {
        CString::new()
    }
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
pub(crate) fn file_permission(file: &File, mask: i32) -> Result<bool> {
    let full_name = helpers::file_get_full_name(file)?;

    // Allow everything unprotected/out of scope
    if !is_protected(&full_name) {
        return Ok(true);
    }

    // Get entity identifiers for the involved subjects and objects
    let operation = get_op_from_mask(mask)?;
    let uid = helpers::get_current_euid();
    let inode = helpers::file_get_inode_number(file);

    // Check policy for protected files
    let resolution = resolve(operation, uid, inode)?;

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
fn resolve(operation: usize, uid: usize, object: usize) -> Result<bool> {
    // Check the cache for quick policy resolution first, keep it locked because
    // of post-conditions
    let mut cache_guard = CACHE.lock();
    let cache = &mut *cache_guard;
    pr_info!("Current cache: {cache:?}");
    if let Some(&resolution) = cache.get(&(operation, uid, object)) {
        pr_info!("Resolving request using cached resolution: {resolution}");
        return Ok(resolution);
    }

    // Get locks for the attribute stores before entering RCU read critical
    // section as to not block during it
    let mut user_attr_guard = pip::USER_ATTRIBUTES.lock();
    let mut object_attr_guard = pip::OBJECT_ATTRIBUTES.lock();

    // Enter RCU read critical section for policy and env attributes
    // This means we are not allowed to block anymore, so we use GFP_NOWAIT for
    // all allocations during this section. Under memory pressure this could
    // fail, but an access getting denied is an acceptable consequence
    let rcu_guard = rcu::read_lock();

    // Get a reference to the RCU protected policy
    let Some(policy) = POLICY.dereference(&rcu_guard) else {
        // No policy defined => default deny
        return Ok(false);
    };

    // Get a reference to the RCU protected environmental attributes
    // Get a default if none are set, which makes the other code/checks easier
    let env_attr = pip::ENV_ATTRIBUTES
        .dereference(&rcu_guard)
        .unwrap_or(&policy::EMPTY_ATTRIBUTIONS);

    // Get the attributes relevant for this decision
    let user_attr = user_attr_guard.get(uid);
    let object_attr = object_attr_guard.get(object);

    // Collect post-conditions so that they can be executed after all the
    // pre-conditions have been checked
    let mut post_conditions = KVec::new();

    pr_info!(
        "Operation {operation}: user {uid} (attr: {user_attr:?}) is trying to access {object:?} (attr: {object_attr:?})"
    );

    // Get the rules for this operation, if it is a valid one
    let rules = policy.get(operation).ok_or(EINVAL)?;
    let mut resolution = false;

    // Check all rules if they allow access and collect all post-conditions for
    // the ones evaluating to true to execute them after all rules were checked
    for rule in rules {
        if rule.pre.evaluate(user_attr, object_attr, env_attr) {
            resolution = true;
            if !rule.post.changes.is_empty() {
                post_conditions.push(&rule.post, GFP_NOWAIT)?;
            }
        }
    }

    // Execute all the post-conditions if there are any
    for post in &post_conditions {
        epp::execute_postcondition(
            post,
            &mut user_attr_guard,
            &mut object_attr_guard,
            GFP_NOWAIT,
        )?;
    }

    // If post-conditions were executed we need to reset the cache
    if !post_conditions.is_empty() {
        cache.reset();
        pr_info!("Resetting cache because post-conditions were executed");
    }

    // Add this resolution to the cache
    cache.insert_resize_if_needed((operation, uid, object), resolution, GFP_NOWAIT)?;

    Ok(resolution)
}

fn is_protected(name: &CStr) -> bool {
    name.starts_with(&PROTECTED_PATH)
}

fn get_op_from_mask(mask: i32) -> Result<usize> {
    match mask.try_into()? {
        bindings::MAY_APPEND | bindings::MAY_WRITE => Ok(1),
        bindings::MAY_READ => Ok(0),
        _ => Err(EINVAL),
    }
}
