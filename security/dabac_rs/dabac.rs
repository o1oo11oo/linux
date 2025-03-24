// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM.
//!
//! Rust-based LSM that implements a dynamic ABAC policy.

// `slice_ptr_len` and `split_at_checked` have only been stable since Rust
// 1.79.0 and 1.80.0 respectively, but the kernel currently uses 1.78.0. Since I
// use latest stable ignore this for now. Setting the feature gates instead
// would be nicer, but this does not work because of a clippy bug, see
// https://github.com/rust-lang/rust-clippy/issues/14425
#![allow(clippy::incompatible_msrv)]

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

fn init() -> Result {
    pdp::init()?;
    pip::init()
}
