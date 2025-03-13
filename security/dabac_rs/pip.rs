// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM PDP.
//!
//! Policy Information Point for Rust-based DABAC LSM.

use core::num::NonZeroU32;

use kernel::{global_lock, prelude::*};

use crate::policy::{ObjectAttributes, UserAttributes};

global_lock! {
    // SAFETY: Initialized in LSM initializer before first use.
    pub(crate) unsafe(uninit) static USER_ATTRIBUTES: Mutex<UserAttributes> = UserAttributes::new();
}

global_lock! {
    // SAFETY: Initialized in LSM initializer before first use.
    pub(crate) unsafe(uninit) static OBJECT_ATTRIBUTES: Mutex<ObjectAttributes> = ObjectAttributes::new();
}

/// Initialize the PDP during LSM initialization
pub(crate) fn init() -> Result<()> {
    // SAFETY: Called exactly once.
    unsafe { USER_ATTRIBUTES.init() };
    // SAFETY: Called exactly once.
    unsafe { OBJECT_ATTRIBUTES.init() };

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
    // - 3 => "pdf"
    // - 4 => "doc"

    let attrs = "0: 0=1 & 1=3, 1000: 0=2 & 1=4".parse()?;
    set_user_attributes(attrs);

    let attrs = "1048581: 0=1 & 1=3, 1048582: 0=2 & 1=4".parse()?;
    set_object_attributes(attrs);

    Ok(())
}

pub(crate) fn set_user_attributes(attrs: UserAttributes) {
    let mut guard = USER_ATTRIBUTES.lock();
    *guard = attrs;
}

pub(crate) fn set_object_attributes(attrs: ObjectAttributes) {
    let mut guard = OBJECT_ATTRIBUTES.lock();
    *guard = attrs;
}

pub(crate) fn add_user_attribution(
    user_attr: &mut UserAttributes,
    uid: usize,
    identifier: usize,
    value: NonZeroU32,
) -> Result<()> {
    let entry = user_attr.get_mut(uid)?;
    entry.add(identifier, value)
}

pub(crate) fn remove_user_attribution(
    user_attr: &mut UserAttributes,
    uid: usize,
    identifier: usize,
) -> Result<()> {
    let entry = user_attr.get_mut(uid)?;
    entry.remove(identifier)
}

pub(crate) fn add_object_attribution(
    object_attr: &mut ObjectAttributes,
    inode: usize,
    identifier: usize,
    value: NonZeroU32,
) -> Result<()> {
    let entry = object_attr.get_mut(inode)?;
    entry.add(identifier, value)
}

pub(crate) fn remove_object_attribution(
    object_attr: &mut ObjectAttributes,
    inode: usize,
    identifier: usize,
) -> Result<()> {
    let entry = object_attr.get_mut(inode)?;
    entry.remove(identifier)
}
