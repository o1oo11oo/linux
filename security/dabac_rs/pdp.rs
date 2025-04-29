// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM PDP.
//!
//! Policy Decision Point for Rust-based DABAC LSM.

use kernel::{
    alloc::arrayvec::ArrayVec,
    bindings,
    fs::LocalFile,
    lru::LRUCache,
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
    policy::{self, Attributions, Policy},
    CACHE_SIZE, MAX_POST_CONDITIONS, PROTECTED_PATH,
};

global_lock! {
    // SAFETY: Initialized in module initializer before first use.
    unsafe(uninit) static POLICY_WRITE_GUARD: Mutex<()> = ();
}

static POLICY: ProjectableGlobalLockedBy<Rcu<KBox<Policy>>, POLICY_WRITE_GUARD> =
    ProjectableGlobalLockedBy::new(Rcu::null());

global_lock! {
    // SAFETY: Initialized in module initializer before first use.
    unsafe(uninit) static CACHE: Mutex<LRUCache<CacheEntry, {CACHE_SIZE}>> = LRUCache::new();
}

struct CacheEntry {
    key: CacheKey,
    value: CacheValue,
}

struct CacheKey {
    operation: usize,
    uid: usize,
    object: usize,
    // TODO: add Arc
    env_attr: Attributions,
}

struct CacheValue {
    resolution: bool,
    post_condition_indices: ArrayVec<usize, { MAX_POST_CONDITIONS }>,
}

/// Initialize the PDP during LSM initialization
pub(crate) fn init() -> Result {
    // SAFETY: All initializers are called exactly once.
    unsafe {
        POLICY_WRITE_GUARD.init();
        CACHE.init();
    };

    // The attributes are encoded because it is simpler to work with
    // (implementing Copy means they use no lifetimes) and can be used for
    // formula evaluation in a simpler way. Attribute identifiers as usize also
    // allow (ab-)using Vecs as HashMaps. See PIP for an int => string mapping.

    // Operations:
    // - 0: policy read
    // - 1: policy write
    // - 2: file read
    // - 3: file write

    let policy = "0:= u0=c1 | u0=c2;
        1:= u0=c1;
        2:= u0=c1 & o0=c1;
        3:= u0=c1 & o0=c1 => +o 1048581: 0=2;
        2:= u0=c1 & o0=c2 | u0=c2 & o0=c2;
        3:= u0=c1 & o0=c2 | u0=c2 & o0=c2;
        2:= o0=c3 & e0>c16;
        3:= o0=c3 & e0>c16"
        .parse()?;
    set_policy(policy)?;
    pr_info!("Policy initialized");

    Ok(())
}

pub(crate) fn get_max_attribute_id() -> usize {
    let rcu_guard = rcu::read_lock();
    match POLICY.dereference(&rcu_guard) {
        Some(p) => p.get_max_attribute_id(),
        None => 0,
    }
}

pub(crate) fn get_serialized_policy() -> Result<CString> {
    let rcu_guard = rcu::read_lock();
    if let Some(policy) = POLICY.dereference(&rcu_guard) {
        CString::try_from_fmt(fmt!("{}", policy))
    } else {
        CString::new()
    }
}

pub(crate) fn set_policy(policy: Policy) -> Result {
    let policy = KBox::new(policy, GFP_KERNEL)?;
    let mut guard = POLICY_WRITE_GUARD.lock();
    let mut policy_writer = POLICY.as_mut(&mut guard);
    policy_writer.as_mut().replace(policy);

    Ok(())
}

/// Rust implementation of the file_permission hook.
///
/// Gets called everytime a file gets read or written. Returns Ok(true) when the
/// access should be allowed, Ok(false) otherwise. Errors most commonly occur on
/// allocation failures.
pub(crate) fn file_permission(file: &LocalFile, mask: i32) -> Result<bool> {
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
/// At least one rule for the operation needs to be fulfilled, which means the current attributions
/// for the user trying to access the object and the current environmental attributions need to
/// satisfy the pre-condition formula of at least on rule for access to be granted.
///
/// If a rule matches, its post-condition is executed by the EPP, if one exists. Since multiple
/// rules could allow an access, all of them are checked and all associated post-conditions are
/// executed.
pub(crate) fn resolve(operation: usize, uid: usize, object: usize) -> Result<bool> {
    // Get locks for the attribute stores and for the cache before entering RCU read critical
    // section as to not block during it
    let mut user_attr_guard = pip::USER_ATTRIBUTES.lock();
    let mut object_attr_guard = pip::OBJECT_ATTRIBUTES.lock();
    let mut cache = CACHE.lock();

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

    // Collect post-conditions so that they can be executed after all the pre-conditions have been
    // checked and stored in the cache
    let mut post_condition_indices = ArrayVec::<_, { MAX_POST_CONDITIONS }>::new();
    let mut post_conditions = ArrayVec::<_, { MAX_POST_CONDITIONS }>::new();

    pr_info!(
        "Operation {operation}: user {uid} (attr: {user_attr:?}) is trying to access {object:?} (attr: {object_attr:?})"
    );

    // Get the rules for this operation, if it is a valid one
    let rules = policy.get(operation).ok_or(EINVAL)?;
    let mut resolution = false;
    let mut cached;

    // Check the cache for previous resolutions
    if let Some(entry) = cache.find(|e| {
        e.key.operation == operation
            && e.key.uid == uid
            && e.key.object == object
            && e.key.env_attr == *env_attr
    }) {
        // We found a cache entry, retrieve resolutions and post-conditions from there
        cached = true;
        resolution = entry.value.resolution;
        for (idx, post) in entry
            .value
            .post_condition_indices
            .iter()
            .filter_map(|&idx| rules.get(idx).map(|r| (idx, &r.post)))
        {
            post_condition_indices.try_push(idx)?;
            post_conditions.try_push(post)?;
        }
        pr_info!(
            "Cache hit, resolution: {}, will execute post-conditions: {}",
            resolution,
            !post_condition_indices.is_empty()
        );
    } else {
        // There was no cache entry matching this access, so check all rules if they allow access
        // and collect all post-conditions for the ones evaluating to true to execute them after
        // all rules were checked
        cached = false;
        for (idx, rule) in rules.iter().enumerate() {
            if rule.pre.evaluate(user_attr, object_attr, env_attr) {
                resolution = true;
                if !rule.post.changes.is_empty() {
                    post_condition_indices.try_push(idx)?;
                    post_conditions.try_push(&rule.post)?;
                }
            }
        }
        pr_info!(
            "Cache miss, resolution: {}, will execute post-conditions: {}",
            resolution,
            !post_condition_indices.is_empty()
        );
    }

    // Execute all the post-conditions if there are any. This might allocate in some cases, but the
    // normal happy path should be allocation-free, because the attributions are pre-allocated.
    for post in &post_conditions {
        epp::execute_postcondition(
            post,
            &mut user_attr_guard,
            &mut object_attr_guard,
            GFP_NOWAIT,
        )?;
    }

    // If we executed any post-conditions we need to reset the cache
    if !post_condition_indices.is_empty() {
        cache.clear();
        pr_info!("Cache has been reset");

        // The cache has been reset, so we need to re-add the current entry
        cached = false;
    }

    // Store the current resolution for later, but only if it is not already present in the cache.
    // Since the cache is not hash-based, it does not detect duplicates
    if !cached {
        cache.insert(CacheEntry {
            key: CacheKey {
                operation,
                uid,
                object,
                env_attr: env_attr.clone(GFP_NOWAIT)?,
            },
            value: CacheValue {
                resolution,
                post_condition_indices,
            },
        });
    }

    Ok(resolution)
}

fn is_protected(name: &CStr) -> bool {
    name.starts_with(PROTECTED_PATH)
}

fn get_op_from_mask(mask: i32) -> Result<usize> {
    match mask.try_into()? {
        bindings::MAY_APPEND | bindings::MAY_WRITE => Ok(3),
        bindings::MAY_READ => Ok(2),
        _ => Err(EINVAL),
    }
}
