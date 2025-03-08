// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM PAP.
//!
//! Policy Administration Point for Rust-based DABAC LSM.

use core::str;

use kernel::prelude::*;

use crate::pdp;

pub(crate) fn update_user_attr(_attrs: &[u8]) -> Result<()> {
    pr_err!("Not implemented!");
    Err(ENOTSUPP)
}

pub(crate) fn update_object_attr(_attrs: &[u8]) -> Result<()> {
    pr_err!("Not implemented!");
    Err(ENOTSUPP)
}

pub(crate) fn update_policy(policy: &[u8]) -> Result<()> {
    // TODO: check for policy replacement permissions
    let policy = str::from_utf8(policy)?.parse()?;
    pr_info!("Updating policy to: {policy:?}");
    pdp::set_policy(policy);

    Ok(())
}
