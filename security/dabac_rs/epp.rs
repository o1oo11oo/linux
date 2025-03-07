// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM EPP.
//!
//! Event Processing Point for Rust-based DABAC LSM.

use kernel::prelude::*;

use crate::{pdp::PostCondition, pip};

/// Coordinate post-condition execution.
///
/// This requires the attribute mutexes to be unlocked, otherwise this will
/// deadlock.
pub(crate) fn execute_postcondition(post: &PostCondition) -> Result<()> {
    pr_info!("Executing post-condition: {post:?}");
    pip::add_attributes(&post.user_attr, &post.object_attr)
}
