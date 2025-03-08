// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM EPP.
//!
//! Event Processing Point for Rust-based DABAC LSM.

use core::str::FromStr;

use kernel::prelude::*;

use crate::{pdp::PostCondition, pip};

#[derive(Debug)]
pub(crate) enum PolicyChange {
    AddUserAttribution(pip::UserAttribution),
    RemoveUserAttribution(pip::UserAttribution),
    AddObjectAttribution(pip::ObjectAttribution),
    RemoveObjectAttribution(pip::ObjectAttribution),
}

impl FromStr for PolicyChange {
    type Err = Error;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        use PolicyChange::*;

        match s.trim().split_at_checked(2) {
            None => Err(EINVAL),
            Some(("+u", s)) => Ok(AddUserAttribution(s.parse()?)),
            Some(("-u", s)) => Ok(RemoveUserAttribution(s.parse()?)),
            Some(("+o", s)) => Ok(AddObjectAttribution(s.parse()?)),
            Some(("-o", s)) => Ok(RemoveObjectAttribution(s.parse()?)),
            Some(_) => Err(EINVAL),
        }
    }
}

/// Coordinate post-condition execution.
///
/// This requires the attribute mutexes to be unlocked, otherwise this will
/// deadlock.
pub(crate) fn execute_postcondition(post: &PostCondition) -> Result<()> {
    pr_info!("Executing post-condition: {post:?}");
    pip::execute_postcondition(&post.changes)
}
