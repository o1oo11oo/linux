// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM EPP.
//!
//! Event Processing Point for Rust-based DABAC LSM.

use kernel::prelude::*;

use crate::{
    pip,
    policy::{ObjectAttributes, PolicyChange, PostCondition, UserAttributes},
};

/// Coordinate post-condition execution.
pub(crate) fn execute_postcondition(
    post: &PostCondition,
    user_attr: &mut UserAttributes,
    object_attr: &mut ObjectAttributes,
) -> Result<()> {
    pr_info!("Executing post-condition: {post:?}");

    for change in &post.changes {
        match change {
            PolicyChange::AddUserAttribution(addition) => pip::add_user_attribution(
                user_attr,
                addition.entity,
                addition.identifier,
                addition.value,
            )?,
            PolicyChange::RemoveUserAttribution(removal) => {
                pip::remove_user_attribution(user_attr, removal.entity, removal.identifier)?
            }
            PolicyChange::AddObjectAttribution(addition) => pip::add_object_attribution(
                object_attr,
                addition.entity,
                addition.identifier,
                addition.value,
            )?,
            PolicyChange::RemoveObjectAttribution(removal) => {
                pip::remove_object_attribution(object_attr, removal.entity, removal.identifier)?
            }
        }
    }

    Ok(())
}
