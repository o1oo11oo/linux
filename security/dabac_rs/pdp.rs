// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM PDP.
//!
//! Policy Decision Point for Rust-based DABAC LSM.

use core::str::FromStr;

use kernel::{c_str, fs::File, kvec, pr_info, prelude::*, sync::global_lock, task::Kuid};

use crate::{
    epp::{self, PolicyChange},
    expr::Expression,
    helpers,
    pip::{self, Attributions},
};

const PROTECTED_PATH: &CStr = c_str!("/home/dabac_rs/");

global_lock! {
    // SAFETY: Initialized in module initializer before first use.
    unsafe(uninit) static POLICY: Mutex<Policy> = Policy {rules: KVec::new()};
}

#[derive(Debug)]
pub(crate) struct Policy {
    rules: KVec<Rule>,
}

impl FromStr for Policy {
    type Err = Error;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() {
            return Ok(Self { rules: kvec![] });
        }

        let mut rules = kvec![];
        for rule in s.split(';') {
            rules.push(rule.parse()?, GFP_KERNEL)?;
        }
        Ok(Self { rules })
    }
}

#[derive(Debug)]
struct Rule {
    pre: PreCondition,
    post: PostCondition,
}

impl FromStr for Rule {
    type Err = Error;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        match s.trim().split_once("=>") {
            None => Ok(Self {
                pre: s.parse()?,
                post: PostCondition { changes: kvec![] },
            }),
            Some((pre, post)) => Ok(Self {
                pre: pre.parse()?,
                post: post.parse()?,
            }),
        }
    }
}

#[derive(Debug)]
struct PreCondition {
    formula: Expression,
}

impl FromStr for PreCondition {
    type Err = Error;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        Ok(Self {
            formula: s.trim().parse()?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct PostCondition {
    pub(crate) changes: KVec<PolicyChange>,
}

impl FromStr for PostCondition {
    type Err = Error;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() {
            return Ok(Self { changes: kvec![] });
        }

        let mut changes = kvec![];
        for change in s.split(',') {
            changes.push(change.parse()?, GFP_KERNEL)?;
        }
        Ok(Self { changes })
    }
}

/// Initialize the PDP during LSM initialization
pub(crate) fn init() -> Result<()> {
    // SAFETY: Called exactly once.
    unsafe { POLICY.init() };

    // The attributes are encoded because it is simpler to work with
    // (implementing Copy means they use no lifetimes) and can be used for
    // formula evaluation in a simpler way. Attribute identifiers as usize also
    // allow (ab-)using Vecs as HashMaps. See PIP for an int => string mapping.

    let policy = "u0=c0 & o0=c0 => -o /home/dabac_rs/a: 0=0, +o /home/dabac_rs/a: 0=1;
        u0=c0 & o0=c1 => +u 1000: 0=0, -u 1000: 0=0;
        u0=c1 & o0=c1 =>"
        .parse()?;
    set_policy(policy);

    Ok(())
}

pub(crate) fn set_policy(policy: Policy) {
    let mut guard = POLICY.lock();
    *guard = policy;
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
    let user_attr = pip::get_user_attributes(uid)?;
    let object_attr = pip::get_object_attributes(&full_name)?;
    pr_info!("User {uid} (attr: {user_attr:?}) ist trying to access {full_name:?} (attr: {object_attr:?})");

    // Check policy for protected files
    let resolution = resolve(&user_attr, &object_attr)?;

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
fn resolve(user_attr: &Attributions, object_attr: &Attributions) -> Result<bool> {
    for rule in &POLICY.lock().rules {
        if rule.pre.formula.evaluate(user_attr, object_attr)? {
            if !rule.post.changes.is_empty() {
                epp::execute_postcondition(&rule.post)?;
            }

            return Ok(true);
        }
    }

    return Ok(false);
}

fn is_protected(name: &CStr) -> bool {
    name.starts_with(&PROTECTED_PATH)
}
