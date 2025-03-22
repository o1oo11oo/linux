// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM EPP.
//!
//! Event Processing Point for Rust-based DABAC LSM.

use kernel::{alloc::Flags, prelude::*};

use crate::{
    pip,
    policy::{ObjectAttributes, PolicyChange, PostCondition, UserAttributes},
};

/// Coordinate post-condition execution.
pub(crate) fn execute_postcondition(
    post: &PostCondition,
    user_attr: &mut UserAttributes,
    object_attr: &mut ObjectAttributes,
    flags: Flags,
) -> Result<()> {
    pr_info!("Executing post-condition: {post:?}");

    for change in &post.changes {
        match change {
            PolicyChange::AddToUser(addition) => pip::add_user_attribution(
                user_attr,
                addition.entity,
                addition.identifier,
                addition.value,
                flags,
            )?,
            PolicyChange::RemoveFromUser(removal) => {
                pip::remove_user_attribution(user_attr, removal.entity, removal.identifier, flags)?
            }
            PolicyChange::AddToObject(addition) => pip::add_object_attribution(
                object_attr,
                addition.entity,
                addition.identifier,
                addition.value,
                flags,
            )?,
            PolicyChange::RemoveFromObject(removal) => pip::remove_object_attribution(
                object_attr,
                removal.entity,
                removal.identifier,
                flags,
            )?,
        }
    }

    Ok(())
}
