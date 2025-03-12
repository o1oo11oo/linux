// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM PAP.
//!
//! Policy Administration Point for Rust-based DABAC LSM.

use core::str;

use kernel::prelude::*;

use crate::{pdp, pip};

pub(crate) fn update_user_attr(attrs: &[u8]) -> Result<()> {
    let attrs = str::from_utf8(attrs)?.parse()?;
    pr_info!("Updating user attributes to: {attrs:?}");
    pip::set_user_attributes(attrs);

    Ok(())
}

pub(crate) fn update_object_attr(attrs: &[u8]) -> Result<()> {
    let attrs = str::from_utf8(attrs)?.parse()?;
    pr_info!("Updating object attributes to: {attrs:?}");
    pip::set_object_attributes(attrs);

    Ok(())
}

pub(crate) fn update_policy(policy: &[u8]) -> Result<()> {
    // TODO: check for policy replacement permissions
    let policy = str::from_utf8(policy)?.parse()?;
    pr_info!("Updating policy to: {policy:?}");
    pdp::set_policy(policy)?;

    Ok(())
}
