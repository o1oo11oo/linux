// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM PDP.
//!
//! Policy Information Point for Rust-based DABAC LSM.

use constants::*;
use kernel::{bindings::uid_t, c_str, global_lock, kvec, prelude::*, str::CStr};

use crate::{epp::PolicyChange, helpers::vec_clone};

global_lock! {
    // SAFETY: Initialized in LSM initializer before first use.
    unsafe(uninit) static USER_ATTRIBUTES: Mutex<KVec<UserAttribution>> = KVec::new();
}

global_lock! {
    // SAFETY: Initialized in LSM initializer before first use.
    unsafe(uninit) static OBJECT_ATTRIBUTES: Mutex<KVec<ObjectAttribution>> = KVec::new();
}

/// An Attribute-Value Pair (AVP) combines an attribute "name" and its value.
///
/// For simplicity the name is encoded as an identifier and values only allow
/// integers, which are easier to work with in equations.
type AVP = (usize, i32);

#[derive(Debug)]
pub(crate) struct UserAttribution {
    pub(crate) user: uid_t,
    pub(crate) attr: Attributions,
}

#[derive(Debug)]
pub(crate) struct ObjectAttribution {
    pub(crate) object: &'static CStr,
    pub(crate) attr: Attributions,
}

#[derive(Debug)]
pub(crate) struct Attributions {
    pub(crate) inner: KVec<AVP>,
}

impl Attributions {
    pub(crate) fn get(&self, identifier: usize) -> Option<i32> {
        self.inner
            .iter()
            .find_map(|&(i, v)| (i == identifier).then_some(v))
    }
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

    let mut guard = USER_ATTRIBUTES.lock();
    guard.push(
        UserAttribution {
            user: 0,
            attr: Attributions {
                inner: kvec![(ATTR_ROLE, VALUE_ADMIN), (ATTR_GROUP, VALUE_SOFTWARE)]?,
            },
        },
        GFP_KERNEL,
    )?;
    guard.push(
        UserAttribution {
            user: 1000,
            attr: Attributions {
                inner: kvec![(ATTR_ROLE, VALUE_USER), (ATTR_GROUP, VALUE_SALES)]?,
            },
        },
        GFP_KERNEL,
    )?;

    let mut guard = OBJECT_ATTRIBUTES.lock();
    guard.push(
        ObjectAttribution {
            object: c_str!("/home/dabac_rs/a"),
            attr: Attributions {
                inner: kvec![(ATTR_PROTECTION, VALUE_SECRET), (ATTR_TYPE, VALUE_PDF)]?,
            },
        },
        GFP_KERNEL,
    )?;
    guard.push(
        ObjectAttribution {
            object: c_str!("/home/dabac_rs/b"),
            attr: Attributions {
                inner: kvec![(ATTR_PROTECTION, VALUE_OPEN), (ATTR_TYPE, VALUE_DOC)]?,
            },
        },
        GFP_KERNEL,
    )?;

    Ok(())
}

/// Retrieve the Attributions for a specific user
pub(crate) fn get_user_attributes(uid: uid_t) -> Result<Attributions> {
    let guard = USER_ATTRIBUTES.lock();
    let avps = guard
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
        .iter()
        .find_map(|o| (o.object == path).then_some(o.attr.inner.as_ref()))
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

fn add_user_attribution(
    user_attr: &mut KVec<UserAttribution>,
    addition: &UserAttribution,
) -> Result<()> {
    if let Some(entry) = user_attr.iter_mut().find(|u| u.user == addition.user) {
        entry
            .attr
            .inner
            .extend_from_slice(&addition.attr.inner, GFP_KERNEL)?
    } else {
        user_attr.push(
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
    user_attr: &mut [UserAttribution],
    removal: &UserAttribution,
) -> Result<()> {
    if let Some(entry) = user_attr.iter_mut().find(|u| u.user == removal.user) {
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
    object_attr: &mut KVec<ObjectAttribution>,
    addition: &ObjectAttribution,
) -> Result<()> {
    if let Some(entry) = object_attr.iter_mut().find(|o| o.object == addition.object) {
        entry
            .attr
            .inner
            .extend_from_slice(&addition.attr.inner, GFP_KERNEL)?
    } else {
        object_attr.push(
            ObjectAttribution {
                object: addition.object,
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
    object_attr: &mut [ObjectAttribution],
    removal: &ObjectAttribution,
) -> Result<()> {
    if let Some(entry) = object_attr.iter_mut().find(|u| u.object == removal.object) {
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

/// Temporary place to store encoded attribute and value identifiers
pub(crate) mod constants {
    // User attribute identifiers:
    // - 0 => "role"
    // - 1 => "group"
    pub(crate) const ATTR_ROLE: usize = 0;
    pub(crate) const ATTR_GROUP: usize = 1;

    // User attribute values:
    // - 0 => "admin"
    // - 1 => "user"
    // - 2 => "software"
    // - 3 => "sales"
    pub(crate) const VALUE_ADMIN: i32 = 0;
    pub(crate) const VALUE_USER: i32 = 1;
    pub(crate) const VALUE_SOFTWARE: i32 = 2;
    pub(crate) const VALUE_SALES: i32 = 3;

    // Object attribute identifiers:
    // - 0 => "protection"
    // - 1 => "type"
    pub(crate) const ATTR_PROTECTION: usize = 0;
    pub(crate) const ATTR_TYPE: usize = 1;

    // Object attribute values:
    // - 0 => "secret"
    // - 1 => "open"
    // - 2 => "pdf"
    // - 3 => "doc"
    pub(crate) const VALUE_SECRET: i32 = 0;
    pub(crate) const VALUE_OPEN: i32 = 1;
    pub(crate) const VALUE_PDF: i32 = 2;
    pub(crate) const VALUE_DOC: i32 = 3;
}
