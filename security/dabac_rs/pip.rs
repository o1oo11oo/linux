// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM PDP.
//!
//! Policy Information Point for Rust-based DABAC LSM.

use kernel::{bindings::uid_t, c_str, global_lock, kvec, prelude::*, str::CStr};

use crate::{helpers::vec_clone, AVP};

global_lock! {
    // SAFETY: Initialized in LSM initializer before first use.
    unsafe(uninit) static USER_ATTRIBUTES: Mutex<KVec<UserAttribution>> = KVec::new();
}

global_lock! {
    // SAFETY: Initialized in LSM initializer before first use.
    unsafe(uninit) static OBJECT_ATTRIBUTES: Mutex<KVec<ObjectAttribution>> = KVec::new();
}

#[derive(Debug)]
pub(crate) struct UserAttribution {
    pub(crate) user: uid_t,
    pub(crate) attr: KVec<AVP>,
}

#[derive(Debug)]
pub(crate) struct ObjectAttribution {
    pub(crate) object: &'static CStr,
    pub(crate) attr: KVec<AVP>,
}

/// Initialize the PDP during LSM initialization
pub(crate) fn init() -> Result<()> {
    // SAFETY: Called exactly once.
    unsafe { USER_ATTRIBUTES.init() };
    // SAFETY: Called exactly once.
    unsafe { OBJECT_ATTRIBUTES.init() };

    {
        let mut guard = USER_ATTRIBUTES.lock();
        guard.reserve(2, GFP_KERNEL)?;
        guard.push(
            UserAttribution {
                user: 0,
                attr: kvec![
                    (c_str!("role"), c_str!("admin")),
                    (c_str!("group"), c_str!("software"))
                ]?,
            },
            GFP_KERNEL,
        )?;
        guard.push(
            UserAttribution {
                user: 1000,
                attr: kvec![
                    (c_str!("role"), c_str!("user")),
                    (c_str!("group"), c_str!("sales"))
                ]?,
            },
            GFP_KERNEL,
        )?;
    }

    {
        let mut guard = OBJECT_ATTRIBUTES.lock();
        guard.reserve(2, GFP_KERNEL)?;
        guard.push(
            ObjectAttribution {
                object: c_str!("/home/dabac_rs/a"),
                attr: kvec![
                    (c_str!("protection"), c_str!("secret")),
                    (c_str!("type"), c_str!("pdf"))
                ]?,
            },
            GFP_KERNEL,
        )?;
        guard.push(
            ObjectAttribution {
                object: c_str!("/home/dabac_rs/b"),
                attr: kvec![
                    (c_str!("protection"), c_str!("open")),
                    (c_str!("type"), c_str!("doc"))
                ]?,
            },
            GFP_KERNEL,
        )?;
    }

    Ok(())
}

/// Retrieve the AVPs for a specific user
pub(crate) fn get_user_attributes(uid: uid_t) -> Result<KVec<AVP>> {
    let mut buf = kvec![];
    buf.extend_from_slice(
        USER_ATTRIBUTES
            .lock()
            .iter()
            .find_map(|u| (u.user == uid).then(|| u.attr.as_ref()))
            .unwrap_or_default(),
        GFP_KERNEL,
    )?;
    Ok(buf)
}

/// Retrieve the AVPs for a specific object
pub(crate) fn get_object_attributes(path: &CStr) -> Result<KVec<AVP>> {
    let mut buf = kvec![];
    buf.extend_from_slice(
        OBJECT_ATTRIBUTES
            .lock()
            .iter()
            .find_map(|o| (o.object == path).then(|| o.attr.as_ref()))
            .unwrap_or_default(),
        GFP_KERNEL,
    )?;
    Ok(buf)
}

/// Add new AVPs from post-conditions, called by EPP.
///
/// This updates both types of attributes in one function and locks both mutexes
/// at the same time to guarantee atomic policy updates.
pub(crate) fn add_attributes(
    user_additions: &[UserAttribution],
    object_additions: &[ObjectAttribution],
) -> Result<()> {
    let mut user_attr = USER_ATTRIBUTES.lock();
    let mut object_attr = OBJECT_ATTRIBUTES.lock();

    for addition in user_additions {
        if let Some(entry) = user_attr.iter_mut().find(|u| u.user == addition.user) {
            entry.attr.extend_from_slice(&addition.attr, GFP_KERNEL)?;
        } else {
            user_attr.push(
                UserAttribution {
                    user: addition.user,
                    attr: vec_clone(&addition.attr, GFP_KERNEL)?,
                },
                GFP_KERNEL,
            )?;
        }
    }

    for addition in object_additions {
        if let Some(entry) = object_attr.iter_mut().find(|o| o.object == addition.object) {
            entry.attr.extend_from_slice(&addition.attr, GFP_KERNEL)?;
        } else {
            object_attr.push(
                ObjectAttribution {
                    object: addition.object,
                    attr: vec_clone(&addition.attr, GFP_KERNEL)?,
                },
                GFP_KERNEL,
            )?;
        }
    }

    Ok(())
}
