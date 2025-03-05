// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM.
//!
//! Rust-based LSM that implements a dynamic ABAC policy.

mod bindings;
mod helpers;
mod pdp;

// Export functions which are called by C, even though that's probably unnecessary
pub use bindings::{dabac_rs_file_permission, dabac_rs_init};

/// Prefix to appear before log messages printed from within this crate.
const __LOG_PREFIX: &[u8] = b"dabac_rs\0";
