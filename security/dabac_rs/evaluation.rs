// SPDX-License-Identifier: GPL-2.0

//! Performance evaluation code for the Rust DABAC LSM.
//!
//! Contains the code for the in-kernel part of the performance measurement for the thesis.

// Not all position identifiers or functions are used in all variants
#![allow(dead_code)]

use core::arch::x86_64::{__rdtscp, _mm_lfence};

use kernel::prelude::*;

/// Amount of cycle counts to store for intermediate measurements
#[cfg(CONFIG_SECURITY_PERFORMANCE_KERNEL_PRECISE)]
pub(crate) const CYCLE_COUNTS_LEN: usize = 15;

/// Amount of cycle counts to store for start to end measurement
#[cfg(all(
    CONFIG_SECURITY_PERFORMANCE_KERNEL,
    not(CONFIG_SECURITY_PERFORMANCE_KERNEL_PRECISE)
))]
pub(crate) const CYCLE_COUNTS_LEN: usize = 2;

/// Force the cycle counts array to be zero sized when it is not needed
#[cfg(not(CONFIG_SECURITY_PERFORMANCE_KERNEL))]
pub(crate) const CYCLE_COUNTS_LEN: usize = 0;

pub(crate) const START: usize = 0;
pub(crate) const AFTER_IDENTIFIERS: usize = 1;
pub(crate) const IN_RESOLVE: usize = 2;
pub(crate) const AFTER_HASH_INIT: usize = 3;
pub(crate) const AFTER_LOCKS: usize = 4;
pub(crate) const AFTER_RCU: usize = 5;
pub(crate) const AFTER_GET_ATTRS: usize = 6;
pub(crate) const AFTER_GET_POLICY: usize = 7;
pub(crate) const AFTER_CALC_HASH: usize = 8;
pub(crate) const AFTER_CHECK_CACHE: usize = 9;
pub(crate) const AFTER_PRE_CONDITIONS: usize = 10;
pub(crate) const AFTER_UPDATE_CACHE: usize = 11;
pub(crate) const AFTER_POST_CONDITIONS: usize = 12;
pub(crate) const AFTER_CLEAR_CACHE: usize = 13;
pub(crate) const STOP: usize = CYCLE_COUNTS_LEN.saturating_sub(1);

/// Read and return the current cycle count
#[inline]
pub(crate) fn rdtscp() -> u64 {
    let mut aux = 0;
    // SAFETY: FFI/ASM call without any requirements
    unsafe { __rdtscp(&mut aux) }
}

/// Serialize and read the current cycle count
#[inline]
pub(crate) fn rdtscp_sync() -> u64 {
    let mut aux = 0;
    // SAFETY: FFI/ASM calls without any requirements
    unsafe {
        _mm_lfence();
        __rdtscp(&mut aux)
    }
}

/// Store the current cycle count in the fist slot of the provided array
#[inline]
#[cfg_attr(not(CONFIG_SECURITY_PERFORMANCE_KERNEL), allow(unused_variables))]
pub(crate) fn save_tsc_start(cycle_counts: &mut [u64; CYCLE_COUNTS_LEN]) {
    #[cfg(CONFIG_SECURITY_PERFORMANCE_KERNEL)]
    {
        cycle_counts[START] = rdtscp_sync();
    }
}

/// Store the current cycle count in the last slot of the provided array and immediately print the
/// results to be collected from user space
#[inline]
#[cfg_attr(not(CONFIG_SECURITY_PERFORMANCE_KERNEL), allow(unused_variables))]
pub(crate) fn save_tsc_stop(cycle_counts: &mut [u64; CYCLE_COUNTS_LEN]) {
    #[cfg(CONFIG_SECURITY_PERFORMANCE_KERNEL)]
    {
        cycle_counts[STOP] = rdtscp();
        pr_info!("cycle_counts: {cycle_counts:?}");
    }
}

/// Store the current cycle count in the provided array
///
/// No-op unless precise measurements are configured, use [`save_tsc_start`] and [`save_tsc_stop`]
/// for the first and last measurement.
#[inline]
#[cfg_attr(
    not(CONFIG_SECURITY_PERFORMANCE_KERNEL_PRECISE),
    allow(unused_variables)
)]
pub(crate) fn save_tsc(cycle_counts: &mut [u64; CYCLE_COUNTS_LEN], index: usize) {
    #[cfg(CONFIG_SECURITY_PERFORMANCE_KERNEL_PRECISE)]
    {
        cycle_counts[index] = rdtscp();
    }
}
