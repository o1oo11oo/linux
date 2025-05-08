// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM (TLCH) PDP.
//!
//! Policy Decision Point for Rust-based DABAC LSM.
//!
//! Variant: top level caching with hashing (TLCH)

use kernel::{
    alloc::{allocator::KVmalloc, arrayvec::ArrayVec},
    bindings, c_str,
    crypto::hash::{Shash, ShashDesc},
    fs::LocalFile,
    lru::LRUCache,
    prelude::*,
    str::CString,
    sync::{
        rcu::{self, Rcu},
        GlobalGuard, ProjectableGlobalLockedBy,
    },
};

use crate::{
    epp,
    evaluation::*,
    helpers::{self, vendored_global_lock},
    pip,
    policy::{self, Policy},
    CACHE_SIZE, MAX_POST_CONDITIONS, PROTECTED_PATH,
};

vendored_global_lock! {
    // SAFETY: Initialized in module initializer before first use.
    unsafe(uninit) static POLICY_WRITE_GUARD: Lock<()> = ();
}

static POLICY: ProjectableGlobalLockedBy<Rcu<KBox<Policy>>, POLICY_WRITE_GUARD> =
    ProjectableGlobalLockedBy::new(Rcu::null());

vendored_global_lock! {
    // SAFETY: Initialized in module initializer before first use.
    pub(crate) unsafe(uninit) static CACHE: Lock<LRUCache<CacheEntry, {CACHE_SIZE}>> = LRUCache::new();
}

pub(crate) struct CacheEntry {
    key: CacheKey,
    value: CacheValue,
}

struct CacheKey {
    hash: [u8; 32],
}

struct CacheValue {
    resolution: bool,
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

pub(crate) fn get_serialized_policy() -> Result<CString<KVmalloc>> {
    let rcu_guard = rcu::read_lock();
    if let Some(policy) = POLICY.dereference(&rcu_guard) {
        CString::try_from_fmt(fmt!("{}", policy))
    } else {
        CString::new()
    }
}

pub(crate) fn set_policy(policy: Policy) -> Result {
    // This function has the same semantic requirements as `pip::set_env_attributes`, see its
    // lengthy explanation, but a bit simpler because we can directly access the cache.

    // Defined before `guard` to drop after releasing spinlock in spinlock variants.
    let _old;
    let policy = KBox::new(policy, GFP_KERNEL)?;
    let mut guard = POLICY_WRITE_GUARD.lock();

    // Lock the cache and reset it when the policy is updated
    let mut cache = CACHE.lock();
    cache.clear();
    pr_info!("Policy update, cache has been reset.");

    let mut policy_writer = POLICY.as_mut(&mut guard);
    _old = policy_writer.as_mut().replace(policy);

    Ok(())
}

pub(crate) fn notify_attrs_changed() {
    CACHE.lock().clear();
    pr_info!("Attribution update, cache has been reset.");
}

// Return the guard to hold the lock until the attributions are updated
pub(crate) fn notify_env_attrs_changed() -> GlobalGuard<CACHE> {
    let mut cache = CACHE.lock();
    cache.clear();
    pr_info!("Environmental attribution update, cache has been reset.");

    cache
}

/// Rust implementation of the file_permission hook.
///
/// Gets called everytime a file gets read or written. Returns Ok(true) when the
/// access should be allowed, Ok(false) otherwise. Errors most commonly occur on
/// allocation failures.
pub(crate) fn file_permission(file: &LocalFile, mask: i32) -> Result<bool> {
    // Store the cycle counts for this request for performance measurement
    let mut cycle_counts = [0; CYCLE_COUNTS_LEN];

    let full_name = helpers::file_get_full_name(file)?;

    // Allow everything unprotected/out of scope
    if !is_protected(&full_name) {
        return Ok(true);
    }

    // Start performance measurements after making sure the request actually concerns us
    save_tsc_start(&mut cycle_counts);

    // Get entity identifiers for the involved subjects and objects
    let operation = get_op_from_mask(mask)?;
    let uid = helpers::get_current_euid();
    let inode = helpers::file_get_inode_number(file);

    save_tsc(&mut cycle_counts, AFTER_IDENTIFIERS);

    // Check policy for protected files
    let resolution = resolve(operation, uid, inode, &mut cycle_counts)?;

    // Stop the performance measurement
    save_tsc_stop(cycle_counts, uid);

    if resolution {
        #[cfg(not(CONFIG_SECURITY_PERFORMANCE))]
        pr_info!("Access granted");
        Ok(true)
    } else {
        #[cfg(not(CONFIG_SECURITY_PERFORMANCE))]
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
pub(crate) fn resolve(
    operation: usize,
    uid: usize,
    object: usize,
    cycle_counts: &mut [u64; CYCLE_COUNTS_LEN],
) -> Result<bool> {
    save_tsc(cycle_counts, IN_RESOLVE);

    // Initialize hasher before entering critical sections
    let hash = Shash::new(c_str!("sha256"), 0, 0)?;
    let mut hash_state = ShashDesc::new(&hash, GFP_KERNEL)?;
    let mut buf = [0u8; 32];

    save_tsc(cycle_counts, AFTER_HASH_INIT);

    // Get locks for the attribute stores and for the cache before entering RCU read critical
    // section as to not block during it
    let mut user_attr_guard = pip::USER_ATTRIBUTES.lock();
    let mut object_attr_guard = pip::OBJECT_ATTRIBUTES.lock();
    let mut cache = CACHE.lock();

    save_tsc(cycle_counts, AFTER_LOCKS);

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

    save_tsc(cycle_counts, AFTER_RCU);

    // Get the attributes relevant for this decision
    let user_attr = user_attr_guard.get(uid);
    let object_attr = object_attr_guard.get(object);

    save_tsc(cycle_counts, AFTER_GET_ATTRS);

    // Collect post-conditions to execute them after all the pre-conditions have been checked
    let mut post_conditions = ArrayVec::<_, { MAX_POST_CONDITIONS }>::new();

    #[cfg(not(CONFIG_SECURITY_PERFORMANCE))]
    pr_info!(
        "Operation {operation}: user {uid} (attr: {user_attr:?}) is trying to access {object:?} (attr: {object_attr:?}) under env {env_attr:?}"
    );

    // Get the rules for this operation, if it is a valid one
    let rules = policy.get(operation).ok_or(EINVAL)?;
    let mut resolution = false;

    save_tsc(cycle_counts, AFTER_GET_POLICY);

    // Calculate cache key
    hash_state.update(&operation.to_ne_bytes())?;
    hash_state.update(&uid.to_ne_bytes())?;
    hash_state.update(&object.to_ne_bytes())?;
    hash_state.update(env_attr.as_bytes())?;
    hash_state.finalize(&mut buf)?;

    save_tsc(cycle_counts, AFTER_CALC_HASH);

    // Check the cache for previous resolutions
    if let Some(entry) = cache.find(|e| e.key.hash == buf) {
        // We found a cache entry, retrieve resolution from there
        // Since it was stored in the cache, it cannot have any post-conditions
        save_tsc(cycle_counts, AFTER_CHECK_CACHE);
        resolution = entry.value.resolution;

        #[cfg(not(CONFIG_SECURITY_PERFORMANCE))]
        pr_info!("Cache hit, resolution: {resolution}, will execute post-conditions: false");
    } else {
        // There was no cache entry matching this access, so check all rules if they allow access
        // and collect all post-conditions for the ones evaluating to true to execute them after
        // all rules were checked
        save_tsc(cycle_counts, AFTER_CHECK_CACHE);

        for rule in rules.iter() {
            if rule.pre.evaluate(user_attr, object_attr, env_attr) {
                resolution = true;
                if !rule.post.changes.is_empty() {
                    post_conditions.try_push(&rule.post)?;
                }
            }
        }

        save_tsc(cycle_counts, AFTER_PRE_CONDITIONS);

        // Since there was no cache entry for this, store the resolution, but only if there are no
        // post-conditions to execute, otherwise the cache gets reset anyway. This means we can
        // never store an entry that would execute post-conditions.
        if post_conditions.is_empty() {
            cache.insert(CacheEntry {
                key: CacheKey { hash: buf },
                value: CacheValue { resolution },
            });
        }

        save_tsc(cycle_counts, AFTER_UPDATE_CACHE);

        #[cfg(not(CONFIG_SECURITY_PERFORMANCE))]
        pr_info!(
            "Cache miss, resolution: {}, will execute post-conditions: {}",
            resolution,
            !post_conditions.is_empty()
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

    save_post_condition_count(cycle_counts, post_conditions.len());
    save_tsc(cycle_counts, AFTER_POST_CONDITIONS);

    // If we executed any post-conditions we need to reset the cache
    if !post_conditions.is_empty() {
        cache.clear();
        #[cfg(not(CONFIG_SECURITY_PERFORMANCE))]
        pr_info!("Cache has been reset");
    }

    save_tsc(cycle_counts, AFTER_CLEAR_CACHE);

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
