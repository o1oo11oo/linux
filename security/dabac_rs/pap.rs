// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM PAP.
//!
//! Policy Administration Point for Rust-based DABAC LSM.

use core::str;

use kernel::{prelude::*, str::CString};

use crate::{helpers, pdp, pip};

fn check_access(operation: usize) -> Result {
    // There is no file to access, but the current policy semantics cannot handle that
    let uid = helpers::get_current_euid();
    let inode = 0;

    match pdp::resolve(operation, uid, inode) {
        Ok(true) => Ok(()),
        Ok(false) => Err(EPERM),
        Err(e) => Err(e),
    }
}

pub(crate) fn read_user_attr() -> Result<CString> {
    // Get an AC decision before reading the attributes
    check_access(0)?;

    // Read the attributes from the PIP
    pip::get_serialized_user_attrs()
}

pub(crate) fn update_user_attr(attrs: &[u8]) -> Result {
    // Get an AC decision before editing the attributes
    check_access(1)?;

    // Read and parse the attributes and update them in the PIP
    let attrs = str::from_utf8(attrs)?.parse()?;
    pr_info!("Updating user attributes to: {attrs:?}");
    pip::set_user_attributes(attrs);

    Ok(())
}

pub(crate) fn read_object_attr() -> Result<CString> {
    // Get an AC decision before reading the attributes
    check_access(0)?;

    // Read the attributes from the PIP
    pip::get_serialized_object_attrs()
}

pub(crate) fn update_object_attr(attrs: &[u8]) -> Result {
    // Get an AC decision before editing the attributes
    check_access(1)?;

    // Read and parse the attributes and update them in the PIP
    let attrs = str::from_utf8(attrs)?.parse()?;
    pr_info!("Updating object attributes to: {attrs:?}");
    pip::set_object_attributes(attrs);

    Ok(())
}

pub(crate) fn read_env_attr() -> Result<CString> {
    // Get an AC decision before reading the attributes
    check_access(0)?;

    // Read the attributes from the PIP
    pip::get_serialized_env_attrs()
}

pub(crate) fn update_env_attr(attrs: &[u8]) -> Result {
    // Get an AC decision before editing the attributes
    check_access(1)?;

    // Read and parse the attributes and update them in the PIP
    let attrs = str::from_utf8(attrs)?.parse()?;
    pr_info!("Updating environmental attributes to: {attrs:?}");
    pip::set_env_attributes(attrs)?;

    Ok(())
}

pub(crate) fn read_policy() -> Result<CString> {
    // Get an AC decision before reading the policy
    check_access(0)?;

    // Read the policy from the PDP
    pdp::get_serialized_policy()
}

pub(crate) fn update_policy(policy: &[u8]) -> Result {
    // Get an AC decision before editing the policy
    check_access(1)?;

    // Read and parse the policy and update it in the PDP
    let policy = str::from_utf8(policy)?.parse()?;
    pr_info!("Updating policy to: {policy:?}");
    pdp::set_policy(policy)?;

    Ok(())
}
