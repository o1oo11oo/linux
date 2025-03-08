// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM PDP.
//!
//! Policy Information Point for Rust-based DABAC LSM.

use core::str::FromStr;

use kernel::{
    bindings::uid_t,
    global_lock, kvec,
    prelude::*,
    str::{CStr, CString},
};

use crate::{epp::PolicyChange, helpers::vec_clone};

global_lock! {
    // SAFETY: Initialized in LSM initializer before first use.
    unsafe(uninit) static USER_ATTRIBUTES: Mutex<UserAttributes> = UserAttributes { attr: KVec::new() };
}

global_lock! {
    // SAFETY: Initialized in LSM initializer before first use.
    unsafe(uninit) static OBJECT_ATTRIBUTES: Mutex<ObjectAttributes> = ObjectAttributes { attr: KVec::new() };
}

/// An Attribute-Value Pair (AVP) combines an attribute "name" and its value.
///
/// For simplicity the name is encoded as an identifier and values only allow
/// integers, which are easier to work with in equations.
type AVP = (usize, i32);

#[derive(Debug)]
pub(crate) struct UserAttributes {
    pub(crate) attr: KVec<UserAttribution>,
}

impl FromStr for UserAttributes {
    type Err = Error;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() {
            return Ok(Self { attr: kvec![] });
        }

        let mut attrs = kvec![];
        for attr in s.split(',') {
            attrs.push(attr.parse()?, GFP_KERNEL)?;
        }

        Ok(Self { attr: attrs })
    }
}

#[derive(Debug)]
pub(crate) struct UserAttribution {
    pub(crate) user: uid_t,
    pub(crate) attr: Attributions,
}

impl FromStr for UserAttribution {
    type Err = Error;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        match s.trim().split_once(':') {
            None => Err(EINVAL),
            Some((uid, attr)) => Ok(Self {
                user: uid.parse()?,
                attr: attr.parse()?,
            }),
        }
    }
}

#[derive(Debug)]
pub(crate) struct ObjectAttributes {
    pub(crate) attr: KVec<ObjectAttribution>,
}

impl FromStr for ObjectAttributes {
    type Err = Error;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() {
            return Ok(Self { attr: kvec![] });
        }

        let mut attrs = kvec![];
        for attr in s.split(',') {
            attrs.push(attr.parse()?, GFP_KERNEL)?;
        }

        Ok(Self { attr: attrs })
    }
}

#[derive(Debug)]
pub(crate) struct ObjectAttribution {
    pub(crate) object: CString,
    pub(crate) attr: Attributions,
}

impl FromStr for ObjectAttribution {
    type Err = Error;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        match s.trim().split_once(':') {
            None => Err(EINVAL),
            Some((object, attr)) => Ok(Self {
                object: object.try_into()?,
                attr: attr.parse()?,
            }),
        }
    }
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

impl FromStr for Attributions {
    type Err = Error;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() {
            return Ok(Self { inner: kvec![] });
        }

        let mut attrs = kvec![];
        for attr in s.split('&') {
            let (i, v) = attr.trim().split_once('=').ok_or(EINVAL)?;
            attrs.push((i.trim().parse()?, v.trim().parse()?), GFP_KERNEL)?;
        }

        Ok(Self { inner: attrs })
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

    // User attribute identifiers:
    // - 0 => "role"
    // - 1 => "group"

    // User attribute values:
    // - 0 => "admin"
    // - 1 => "user"
    // - 2 => "software"
    // - 3 => "sales"

    // Object attribute identifiers:
    // - 0 => "protection"
    // - 1 => "type"

    // Object attribute values:
    // - 0 => "secret"
    // - 1 => "open"
    // - 2 => "pdf"
    // - 3 => "doc"

    let attrs = "0: 0=0 & 1=2, 1000: 0=1 & 1=3".parse()?;
    set_user_attributes(attrs);

    let attrs = "/home/dabac_rs/a: 0=0 & 1=2, /home/dabac_rs/b: 0=1 & 1=3".parse()?;
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
pub(crate) fn get_user_attributes(uid: uid_t) -> Result<Attributions> {
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
