// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM.
//!
//! Rust-based LSM that implements a dynamic ABAC policy.

mod bindings;
mod epp;
mod helpers;
mod pdp;
mod pip;

// Export functions which are called by C, even though that's probably unnecessary
pub use bindings::{dabac_rs_file_permission, dabac_rs_init};
use kernel::prelude::*;

/// Prefix to appear before log messages printed from within this crate.
const __LOG_PREFIX: &[u8] = b"dabac_rs\0";

/// An Attribute-Value Pair (AVP) combines an attribute "name" and its value.
///
/// For simplicity the name is encoded as an identifier and values only allow
/// integers, which are easier to work with in equations.
type AVP = (usize, i32);

fn init() -> Result<()> {
    pdp::init()?;
    pip::init()?;

    Ok(())
}
