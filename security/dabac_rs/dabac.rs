// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM.
//!
//! Rust-based LSM that implements a dynamic ABAC policy.

// `split_at_checked` has only been stable since Rust 1.80.0, but the kernel
// currently uses 1.78.0. Since I use latest stable ignore this for now. Setting
// the feature gates instead would be nicer, but this does not work because of a
// clippy bug, see https://github.com/rust-lang/rust-clippy/issues/14425
#![allow(clippy::incompatible_msrv)]

mod bindings;
mod epp;
mod expr;
mod helpers;
mod pap;
mod pdp;
mod pip;
mod policy;

use kernel::{c_str, prelude::*};

/// Prefix to appear before log messages printed from within this crate.
const __LOG_PREFIX: &[u8] = b"dabac_rs\0";

/// The path under which the LSM provides access decisions for file reads/writes.
const PROTECTED_PATH: &CStr = c_str!("/home/dabac_rs/");

/// The maximum amount of post-conditions that can be executed for one operation.
const MAX_POST_CONDITIONS: usize = 32;

/// The number of entries the cache can hold, same as SELinux's AVC.
const CACHE_SIZE: usize = 512;

fn init() -> Result {
    // The PDP needs to be initialized first so that the initial policy is available for the PIP to
    // load its initial attributions and expand the allocation to limit allocations during policy
    // resolution. Otherwise uninitialized locks might get accessed.
    pdp::init()?;
    pip::init()
}
