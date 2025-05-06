// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM PDP.
//!
//! Policy Information Point for Rust-based DABAC LSM.

use core::num::NonZeroU32;

use kernel::{
    alloc::Flags,
    prelude::*,
    str::CString,
    sync::{
        rcu::{self, Rcu},
        ProjectableGlobalLockedBy,
    },
};

use crate::{
    helpers::vendored_global_lock,
    pdp,
    policy::{Attributions, ObjectAttributes, UserAttributes},
};

vendored_global_lock! {
    // SAFETY: Initialized in LSM initializer before first use.
    pub(crate) unsafe(uninit) static USER_ATTRIBUTES: Lock<UserAttributes> = UserAttributes::new();
}

vendored_global_lock! {
    // SAFETY: Initialized in LSM initializer before first use.
    pub(crate) unsafe(uninit) static OBJECT_ATTRIBUTES: Lock<ObjectAttributes> = unsafe { ObjectAttributes::new() };
}

vendored_global_lock! {
    // SAFETY: Initialized in LSM initializer before first use.
    pub(crate) unsafe(uninit) static ENV_ATTR_WRITE_GUARD: Lock<()> = ();
}

pub(crate) static ENV_ATTRIBUTES: ProjectableGlobalLockedBy<
    Rcu<KBox<Attributions>>,
    ENV_ATTR_WRITE_GUARD,
> = ProjectableGlobalLockedBy::new(Rcu::null());

/// Initialize the PDP during LSM initialization
pub(crate) fn init() -> Result {
    // SAFETY: All initializers are called exactly once.
    unsafe {
        USER_ATTRIBUTES.init();
        OBJECT_ATTRIBUTES.init();
        ENV_ATTR_WRITE_GUARD.init();
    }

    // Initialize the HashMap as required
    OBJECT_ATTRIBUTES.lock().initialize();

    // The attributes are encoded because it is simpler to work with
    // (implementing Copy means they use no lifetimes) and can be used for
    // formula evaluation in a simpler way. Attribute identifiers as usize also
    // allow (ab-)using Vecs as HashMaps.

    // User attribute identifiers:
    // - 0 => "role"
    // - 1 => "group"

    // User attribute values:
    // - 1 => "admin"
    // - 2 => "user"
    // - 3 => "software"
    // - 4 => "sales"

    // Object attribute identifiers:
    // - 0 => "protection"
    // - 1 => "type"

    // Object attribute values:
    // - 1 => "secret"
    // - 2 => "open"
    // - 3 => "open iff hour of day > 16"
    // - 4 => "pdf"
    // - 5 => "doc"

    // Env attribute identifiers:
    // - 0 => hour of day
    // - 1 => day of week

    // Env attribute values:
    // - hour of day: 1-24 (1-indexed because 0 is used for the Option niche)
    // - day of week: 1-7

    let attrs = "0: 0=1 & 1=3, 1000: 0=2 & 1=4".parse()?;
    set_user_attributes(attrs)?;
    pr_info!("User attributes initialized");

    let attrs = "1048581: 0=1 & 1=3,
        1048582: 0=2 & 1=5,
        1048588: 0=3 & 1=5,
        1048589: 0=3 & 1=5"
        .parse()?;
    set_object_attributes(attrs)?;
    pr_info!("Object attributes initialized");

    let attrs = "0=1 & 1=1".parse()?;
    set_env_attributes(attrs)?;
    pr_info!("Environmental attributes initialized");

    Ok(())
}

pub(crate) fn get_serialized_user_attrs() -> Result<CString> {
    let guard = USER_ATTRIBUTES.lock();
    CString::try_from_fmt(fmt!("{}", &*guard))
}

pub(crate) fn set_user_attributes(mut attrs: UserAttributes) -> Result {
    // Make sure the attributions are pre-allocated for all possible accesses
    let max_id = pdp::get_max_attribute_id();
    attrs.ensure_attribution_length(max_id, GFP_KERNEL)?;

    // Store the new attributions
    let mut guard = USER_ATTRIBUTES.lock();
    *guard = attrs;

    // Notify the PDP that the attributions changed, in case the cache needs to be reset
    // Do this after acquiring the lock for the attributions to prevent deadlocks
    pdp::notify_attrs_changed();

    Ok(())
}

pub(crate) fn get_serialized_object_attrs() -> Result<CString> {
    let guard = OBJECT_ATTRIBUTES.lock();
    CString::try_from_fmt(fmt!("{}", &*guard))
}

pub(crate) fn set_object_attributes(mut attrs: ObjectAttributes) -> Result {
    // Make sure the attributions are pre-allocated for all possible accesses
    let max_id = pdp::get_max_attribute_id();
    attrs.ensure_attribution_length(max_id, GFP_KERNEL)?;

    // Store the new attributions
    let mut guard = OBJECT_ATTRIBUTES.lock();
    *guard = attrs;

    // Notify the PDP that the attributions changed, in case the cache needs to be reset
    // Do this after acquiring the lock for the attributions to prevent deadlocks
    pdp::notify_attrs_changed();

    Ok(())
}

pub(crate) fn get_serialized_env_attrs() -> Result<CString> {
    let rcu_guard = rcu::read_lock();
    if let Some(attrs) = ENV_ATTRIBUTES.dereference(&rcu_guard) {
        CString::try_from_fmt(fmt!("{}", attrs))
    } else {
        CString::new()
    }
}

// In the no-caching variant the notify function returns (), which we pass to Some(...) directly.
#[allow(clippy::unit_arg)]
pub(crate) fn set_env_attributes(attrs: Attributions) -> Result {
    // This function has somewhat intricate locking/synchronization semantics, which is why the
    // `old` and `_cache_guard` variables are defined first in this order, to get the correct drop
    // order, resulting in the required unlock order.
    //
    // Before the attributes stored in RCU are changed, the PDP needs to be notified that they do
    // change, because that might reset a cache in one of the variants. Because environmental
    // attributes are updated regularly, this should only happen if there is an actual change,
    // otherwise cache efficiency decreases. To compare to the current state, an RCU read-side
    // critical section is needed.
    //
    // As soon as the PDP clears the cache, new cache entries or policy resolutions using the still
    // unchanged environmental attributes must not be created, as they would remain in the cache.
    // Resetting the cache also cannot wait till after the attributes are updated, as otherwise
    // requests could be resolved with a now wrong resolution.
    //
    // Because of this, the cache needs to stay locked until the RCU protected data is updated when
    // `replace` is called at the end of this function. To ensure this, the notify function in
    // caching variants returns the lock guard for their cache, which is stored as `_cache_guard`.
    //
    // To actually update the value stored in RCU, the `ENV_ATTR_WRITE_GUARD` global lock needs to
    // be held, to ensure only one thread can update the data stored in the static variable. This is
    // also dropped at the end of the function, which unlocks it.
    //
    // In variants using spinlocks instead of mutexes as backends of the global lock providing the
    // `ENV_ATTR_WRITE_GUARD`, the spinlock is also held till the end of the function. Changing a
    // value in RCU and dropping the old value requires waiting for other threads until they leave
    // their read-side critical sections. The `synchronize_rcu()` call responsible for that involves
    // sleeping though, which is not permitted while holding a spinlock.
    //
    // To ensure both locks (the one for the cache and the RCU write guard) are unlocked before
    // `synchronize_rcu()` is called, we define the variable for the old RCU data up here, so that
    // it gets dropped last, after the locks have already been unlocked in their earlier
    // destructors, when its drop impl can safely call `synchronize_rcu()`.

    // Defined before `guard` to drop after releasing spinlock in spinlock variants.
    let _old;
    let _cache_guard;
    let attrs = KBox::new(attrs, GFP_KERNEL)?;

    // Check if the attributions actually changed to see if the PDP needs to be notified. If they
    // did change or if they were not set before, notify it. Then also store the guard until the
    // environmental attributions are updated to make sure this happens atomically.
    let rcu_guard = rcu::read_lock();
    if let Some(old_attrs) = ENV_ATTRIBUTES.dereference(&rcu_guard) {
        if *attrs != *old_attrs {
            _cache_guard = Some(pdp::notify_env_attrs_changed());
        }
    } else {
        // Nothing set yet, also notify for changes
        _cache_guard = Some(pdp::notify_env_attrs_changed());
    }
    drop(rcu_guard);

    let mut guard = ENV_ATTR_WRITE_GUARD.lock();
    let mut env_attr_writer = ENV_ATTRIBUTES.as_mut(&mut guard);
    _old = env_attr_writer.as_mut().replace(attrs);

    Ok(())
}

pub(crate) fn ensure_attribution_length(index: usize) -> Result {
    USER_ATTRIBUTES
        .lock()
        .ensure_attribution_length(index, GFP_KERNEL)?;
    OBJECT_ATTRIBUTES
        .lock()
        .ensure_attribution_length(index, GFP_KERNEL)
}

pub(crate) fn add_user_attribution(
    user_attr: &mut UserAttributes,
    uid: usize,
    identifier: usize,
    value: NonZeroU32,
    flags: Flags,
) -> Result {
    let entry = user_attr.get_mut(uid, flags)?;
    entry.add(identifier, value, flags)
}

pub(crate) fn remove_user_attribution(
    user_attr: &mut UserAttributes,
    uid: usize,
    identifier: usize,
    flags: Flags,
) -> Result {
    let entry = user_attr.get_mut(uid, flags)?;
    entry.remove(identifier, flags)
}

pub(crate) fn add_object_attribution(
    object_attr: &mut ObjectAttributes,
    inode: usize,
    identifier: usize,
    value: NonZeroU32,
    flags: Flags,
) -> Result {
    let entry = object_attr.get_mut(inode, flags)?;
    entry.add(identifier, value, flags)
}

pub(crate) fn remove_object_attribution(
    object_attr: &mut ObjectAttributes,
    inode: usize,
    identifier: usize,
    flags: Flags,
) -> Result {
    let entry = object_attr.get_mut(inode, flags)?;
    entry.remove(identifier, flags)
}
