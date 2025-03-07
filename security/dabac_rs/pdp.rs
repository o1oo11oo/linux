// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM PDP.
//!
//! Policy Decision Point for Rust-based DABAC LSM.

use kernel::{c_str, fs::File, kvec, pr_info, prelude::*, sync::global_lock, task::Kuid};

use crate::{
    epp::{self, PolicyChange},
    helpers,
    pip::{self, constants::*, ObjectAttribution, UserAttribution},
    AVP,
};

const PROTECTED_PATH: &CStr = c_str!("/home/dabac_rs/");

global_lock! {
    // SAFETY: Initialized in module initializer before first use.
    unsafe(uninit) static POLICY: Mutex<Policy> = Policy {rules: KVec::new()};
}

#[derive(Debug)]
struct Policy {
    rules: KVec<Rule>,
}

#[derive(Debug)]
struct Rule {
    pre: PreCondition,
    post: PostCondition,
}

#[derive(Debug)]
struct PreCondition {
    user_attr: KVec<AVP>,
    object_attr: KVec<AVP>,
}

#[derive(Debug)]
pub(crate) struct PostCondition {
    pub(crate) changes: KVec<PolicyChange>,
}

/// Initialize the PDP during LSM initialization
pub(crate) fn init() -> Result<()> {
    // SAFETY: Called exactly once.
    unsafe { POLICY.init() };

    // The attributes are encoded because it is simpler to work with
    // (implementing Copy means they use no lifetimes) and can be used for
    // formula evaluation in a simpler way. Attribute identifiers as usize also
    // allow (ab-)using Vecs as HashMaps. See PIP for an int => string mapping.

    let mut guard = POLICY.lock();
    guard.rules.push(
        Rule {
            pre: PreCondition {
                user_attr: kvec![(ATTR_ROLE, VALUE_ADMIN)]?,
                object_attr: kvec![(ATTR_PROTECTION, VALUE_SECRET)]?,
            },
            post: PostCondition {
                changes: kvec![
                    PolicyChange::RemoveObjectAttribution(ObjectAttribution {
                        object: c_str!("/home/dabac_rs/a"),
                        attr: kvec![(ATTR_PROTECTION, VALUE_SECRET)]?,
                    }),
                    PolicyChange::AddObjectAttribution(ObjectAttribution {
                        object: c_str!("/home/dabac_rs/a"),
                        attr: kvec![(ATTR_PROTECTION, VALUE_OPEN)]?,
                    }),
                ]?,
            },
        },
        GFP_KERNEL,
    )?;
    guard.rules.push(
        Rule {
            pre: PreCondition {
                user_attr: kvec![(ATTR_ROLE, VALUE_ADMIN)]?,
                object_attr: kvec![(ATTR_PROTECTION, VALUE_OPEN)]?,
            },
            post: PostCondition {
                changes: kvec![
                    PolicyChange::AddUserAttribution(UserAttribution {
                        user: 1000,
                        attr: kvec![(ATTR_ROLE, VALUE_ADMIN)]?,
                    }),
                    PolicyChange::RemoveUserAttribution(UserAttribution {
                        user: 1000,
                        attr: kvec![(ATTR_ROLE, VALUE_ADMIN)]?,
                    }),
                ]?,
            },
        },
        GFP_KERNEL,
    )?;
    guard.rules.push(
        Rule {
            pre: PreCondition {
                user_attr: kvec![(ATTR_ROLE, VALUE_USER)]?,
                object_attr: kvec![(ATTR_PROTECTION, VALUE_OPEN)]?,
            },
            post: PostCondition { changes: kvec![] },
        },
        GFP_KERNEL,
    )?;

    Ok(())
}

/// Rust implementation of the file_permission hook.
///
/// Gets called everytime a file gets read or written. Returns Ok(true) when the
/// access should be allowed, Ok(false) otherwise. Errors most commonly occur on
/// allocation failures.
pub(crate) fn file_permission(file: &File, _mask: i32) -> Result<bool> {
    let full_name = helpers::file_get_full_name(file)?;

    // Allow everything unprotected/out of scope
    if !is_protected(&full_name) {
        return Ok(true);
    }

    let uid = Kuid::current_euid().into_uid_in_current_ns();
    let u_attr = pip::get_user_attributes(uid)?;
    let o_attr = pip::get_object_attributes(&full_name)?;
    pr_info!("User {uid} (attr: {u_attr:?}) ist trying to access {full_name:?} (attr: {o_attr:?})");

    // Check policy for protected files
    let resolution = resolve(&u_attr, &o_attr)?;

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
fn resolve(u_attr: &[AVP], o_attr: &[AVP]) -> Result<bool> {
    if let Some(rule) = POLICY.lock().rules.iter().find(|&r| {
        r.pre.user_attr.iter().all(|u| u_attr.contains(u))
            && r.pre.object_attr.iter().all(|o| o_attr.contains(o))
    }) {
        if !rule.post.changes.is_empty() {
            epp::execute_postcondition(&rule.post)?;
        }

        return Ok(true);
    }

    return Ok(false);
}

fn is_protected(name: &CStr) -> bool {
    name.starts_with(&PROTECTED_PATH)
}
