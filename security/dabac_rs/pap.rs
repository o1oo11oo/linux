// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM PAP.
//!
//! Policy Administration Point for Rust-based DABAC LSM.

use core::str;

use kernel::{prelude::*, str::CString};

use crate::{evaluation::CYCLE_COUNTS_LEN, helpers, pdp, pip, policy::Policy};

fn check_access(operation: usize) -> Result {
    // There is no file to access, but the current policy semantics cannot handle that
    let uid = helpers::get_current_euid();
    let inode = 0;

    // Not relevant for the evaluation, but the function expects the parameter, so we need to
    // provide it with correct length
    let mut cycle_counts = [0; CYCLE_COUNTS_LEN];

    match pdp::resolve(operation, uid, inode, &mut cycle_counts) {
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
    pip::set_user_attributes(attrs)
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
    pip::set_object_attributes(attrs)
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
    pip::set_env_attributes(attrs)
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
    let policy: Policy = str::from_utf8(policy)?.parse()?;
    let max_id = policy.get_max_attribute_id();
    pr_info!("Updating policy to: {policy:?}");
    pdp::set_policy(policy)?;

    // Update attribution allocations just in case we have new maximum identifiers
    pip::ensure_attribution_length(max_id)
}

pub(crate) fn read_perf() -> Result<CString> {
    // No need for AC decisions for eval
    // Read the perf results from the PDP
    pdp::get_perf_results()
}

pub(crate) fn register_or_start_perf(input: &[u8]) -> Result {
    // No need for AC decisions for eval

    // Trim the input to be able to more easily work with it (and parsing requires it)
    let input = str::from_utf8(input)?.trim();

    // Check which action this is
    match input {
        "start" => {
            pr_info!("Starting perf run, storing results from now on");
            pdp::start_perf_run();

            Ok(())
        }
        "clear" | "reset" => {
            pr_info!("Resetting all perf data");
            pdp::clear_perf_data();

            Ok(())
        }
        _ => {
            // This is another runner registering itself
            // Get the uid and read and parse the amount of requests and send them to the PDP
            let uid = helpers::get_current_euid();
            let amount: usize = input.parse()?;
            pr_info!("Registering perf runner {uid} with {amount} requests");
            pdp::register_perf(uid, amount)
        }
    }
}
