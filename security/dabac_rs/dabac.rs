// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM.
//!
//! Rust-based LSM that implements a dynamic ABAC policy.

mod bindings;
mod epp;
mod expr;
mod helpers;
mod pap;
mod pdp;
mod pip;
mod policy;

use kernel::prelude::*;

/// Prefix to appear before log messages printed from within this crate.
const __LOG_PREFIX: &[u8] = b"dabac_rs\0";

fn init() -> Result<()> {
    pdp::init()?;
    pip::init()
}
