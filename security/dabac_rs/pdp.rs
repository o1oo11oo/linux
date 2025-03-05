// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM PDP.
//!
//! Policy Decision Point for Rust-based DABAC LSM.

use kernel::{fs::File, prelude::*};

/// TODO doc comment
pub(crate) fn file_permission(file: &File, _mask: i32) -> Result<bool> {
    // Allow everything for now
    Ok(true)
}
