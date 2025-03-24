// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM PDP.
//!
//! Policy Information Point for Rust-based DABAC LSM.

use core::num::NonZeroU32;

use kernel::{
    alloc::Flags,
    global_lock,
    prelude::*,
    str::CString,
    sync::{
        rcu::{self, Rcu},
        ProjectableGlobalLockedBy,
    },
};

use crate::policy::{Attributions, ObjectAttributes, UserAttributes};

global_lock! {
    // SAFETY: Initialized in LSM initializer before first use.
    pub(crate) unsafe(uninit) static USER_ATTRIBUTES: Mutex<UserAttributes> = UserAttributes::new();
}

global_lock! {
    // SAFETY: Initialized in LSM initializer before first use.
    pub(crate) unsafe(uninit) static OBJECT_ATTRIBUTES: Mutex<ObjectAttributes> = ObjectAttributes::new();
}

global_lock! {
    // SAFETY: Initialized in LSM initializer before first use.
    pub(crate) unsafe(uninit) static ENV_ATTR_WRITE_GUARD: Mutex<()> = ();
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
    set_user_attributes(attrs);
    pr_info!("User attributes initialized");

    let attrs = "1048581: 0=1 & 1=3,
        1048582: 0=2 & 1=5,
        1048588: 0=3 & 1=5,
        1048589: 0=3 & 1=5"
        .parse()?;
    set_object_attributes(attrs);
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

pub(crate) fn set_user_attributes(attrs: UserAttributes) {
    let mut guard = USER_ATTRIBUTES.lock();
    *guard = attrs;
}

pub(crate) fn get_serialized_object_attrs() -> Result<CString> {
    let guard = OBJECT_ATTRIBUTES.lock();
    CString::try_from_fmt(fmt!("{}", &*guard))
}

pub(crate) fn set_object_attributes(attrs: ObjectAttributes) {
    let mut guard = OBJECT_ATTRIBUTES.lock();
    *guard = attrs;
}

pub(crate) fn get_serialized_env_attrs() -> Result<CString> {
    let rcu_guard = rcu::read_lock();
    if let Some(attrs) = ENV_ATTRIBUTES.dereference(&rcu_guard) {
        CString::try_from_fmt(fmt!("{}", attrs))
    } else {
        CString::new()
    }
}

pub(crate) fn set_env_attributes(attrs: Attributions) -> Result {
    let mut guard = ENV_ATTR_WRITE_GUARD.lock();
    let mut env_attr_writer = ENV_ATTRIBUTES.as_mut(&mut guard);
    let attrs = KBox::new(attrs, GFP_KERNEL)?;
    env_attr_writer.as_mut().read_copy_update(|_| Some(attrs));

    Ok(())
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
