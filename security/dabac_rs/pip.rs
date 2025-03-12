// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM PDP.
//!
//! Policy Information Point for Rust-based DABAC LSM.

use kernel::{bindings, global_lock, kvec, prelude::*, str::CStr};

use crate::{
    helpers::vec_clone,
    policy::{
        Attributions, ObjectAttributes, ObjectAttribution, PolicyChange, UserAttributes,
        UserAttribution,
    },
};

global_lock! {
    // SAFETY: Initialized in LSM initializer before first use.
    unsafe(uninit) static USER_ATTRIBUTES: Mutex<UserAttributes> = UserAttributes { attr: KVec::new() };
}

global_lock! {
    // SAFETY: Initialized in LSM initializer before first use.
    unsafe(uninit) static OBJECT_ATTRIBUTES: Mutex<ObjectAttributes> = ObjectAttributes { attr: KVec::new() };
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

    let attrs = "/home/dabac_rs/a: 0=1 & 1=3, /home/dabac_rs/b: 0=2 & 1=4".parse()?;
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

/// Retrieve the Attributions for a specific user
pub(crate) fn get_user_attributes(uid: bindings::uid_t) -> Result<Attributions> {
    let guard = USER_ATTRIBUTES.lock();
    let avps = guard
        .attr
        .iter()
        .find_map(|u| (u.user == uid).then_some(u.attr.inner.as_ref()))
        .unwrap_or_default();

    Ok(Attributions {
        inner: vec_clone(avps, GFP_KERNEL)?,
    })
}

/// Retrieve the Attributions for a specific object
pub(crate) fn get_object_attributes(path: &CStr) -> Result<Attributions> {
    let guard = OBJECT_ATTRIBUTES.lock();
    let avps = guard
        .attr
        .iter()
        .find_map(|o| (*o.object == *path).then_some(o.attr.inner.as_ref()))
        .unwrap_or_default();

    Ok(Attributions {
        inner: vec_clone(avps, GFP_KERNEL)?,
    })
}

/// Add new AVPs from post-conditions, called by EPP.
///
/// This updates both types of attributes in one function and locks both mutexes
/// at the same time to guarantee atomic policy updates.
pub(crate) fn execute_postcondition(changes: &[PolicyChange]) -> Result<()> {
    let mut user_attr = USER_ATTRIBUTES.lock();
    let mut object_attr = OBJECT_ATTRIBUTES.lock();

    for change in changes {
        match change {
            PolicyChange::AddUserAttribution(addition) => {
                add_user_attribution(&mut *user_attr, addition)?
            }
            PolicyChange::RemoveUserAttribution(removal) => {
                remove_user_attribution(&mut *user_attr, removal)?
            }
            PolicyChange::AddObjectAttribution(addition) => {
                add_object_attribution(&mut *object_attr, addition)?
            }
            PolicyChange::RemoveObjectAttribution(removal) => {
                remove_object_attribution(&mut *object_attr, removal)?
            }
        }
    }

    Ok(())
}

fn add_user_attribution(user_attr: &mut UserAttributes, addition: &UserAttribution) -> Result<()> {
    if let Some(entry) = user_attr.attr.iter_mut().find(|u| u.user == addition.user) {
        entry
            .attr
            .inner
            .extend_from_slice(&addition.attr.inner, GFP_KERNEL)?
    } else {
        user_attr.attr.push(
            UserAttribution {
                user: addition.user,
                attr: Attributions {
                    inner: vec_clone(&addition.attr.inner, GFP_KERNEL)?,
                },
            },
            GFP_KERNEL,
        )?
    }

    Ok(())
}

fn remove_user_attribution(
    user_attr: &mut UserAttributes,
    removal: &UserAttribution,
) -> Result<()> {
    if let Some(entry) = user_attr.attr.iter_mut().find(|u| u.user == removal.user) {
        // kernel::Vec has no retain(), so this is a bit less efficient
        // filter to only keep the items not contained in the removal collection
        let mut replacement = kvec![];
        core::mem::swap(&mut entry.attr.inner, &mut replacement);
        for item in replacement
            .into_iter()
            .filter(|a| !removal.attr.inner.contains(a))
        {
            entry.attr.inner.push(item, GFP_KERNEL)?;
        }
    }

    Ok(())
}

fn add_object_attribution(
    object_attr: &mut ObjectAttributes,
    addition: &ObjectAttribution,
) -> Result<()> {
    if let Some(entry) = object_attr
        .attr
        .iter_mut()
        .find(|o| o.object == addition.object)
    {
        entry
            .attr
            .inner
            .extend_from_slice(&addition.attr.inner, GFP_KERNEL)?
    } else {
        object_attr.attr.push(
            ObjectAttribution {
                object: (*addition.object).try_into()?,
                attr: Attributions {
                    inner: vec_clone(&addition.attr.inner, GFP_KERNEL)?,
                },
            },
            GFP_KERNEL,
        )?
    }

    Ok(())
}

fn remove_object_attribution(
    object_attr: &mut ObjectAttributes,
    removal: &ObjectAttribution,
) -> Result<()> {
    if let Some(entry) = object_attr
        .attr
        .iter_mut()
        .find(|u| u.object == removal.object)
    {
        // kernel::Vec has no retain(), so this is a bit less efficient
        // filter to only keep the items not contained in the removal collection
        let mut replacement = kvec![];
        core::mem::swap(&mut entry.attr.inner, &mut replacement);
        for item in replacement
            .into_iter()
            .filter(|a| !removal.attr.inner.contains(a))
        {
            entry.attr.inner.push(item, GFP_KERNEL)?;
        }
    }

    Ok(())
}
