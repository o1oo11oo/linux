// SPDX-License-Identifier: GPL-2.0

//! Performance evaluation code for the Rust DABAC LSM.
//!
//! Contains the code for the in-kernel part of the performance measurement for the thesis.

// Not all position identifiers or functions are used in all variants
#![allow(dead_code)]

use core::arch::x86_64::{__rdtscp, _mm_lfence};

use kernel::{global_lock, prelude::*, str::CString};

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

global_lock! {
    // SAFETY: Initialized in module initializer before first use.
    unsafe(uninit) static PERF_RESULTS: SpinLock<PerfResults> = PerfResults::new();
}

/// Initialize the evaluation code during LSM initialization
pub(crate) fn init() -> Result {
    // SAFETY: All initializers are called exactly once.
    unsafe {
        PERF_RESULTS.init();
    };

    Ok(())
}

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
pub(crate) fn save_tsc_stop(mut cycle_counts: [u64; CYCLE_COUNTS_LEN], uid: usize) {
    #[cfg(CONFIG_SECURITY_PERFORMANCE_KERNEL)]
    {
        cycle_counts[STOP] = rdtscp();

        // Lock the results store and add the current ones
        PERF_RESULTS.lock().push(uid, cycle_counts);
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

pub(crate) fn register_perf(uid: usize, amount: usize) -> Result {
    let mut guard = PERF_RESULTS.lock();
    guard.register_runner(uid, amount)
}

pub(crate) fn start_perf_run() {
    let mut guard = PERF_RESULTS.lock();
    guard.start_recording();
}

pub(crate) fn get_perf_results() -> Result<CString> {
    let mut guard = PERF_RESULTS.lock();
    guard.stop_recording();
    CString::try_from_fmt(fmt!("{}", &*guard))
}

pub(crate) fn clear_perf_data() {
    let mut guard = PERF_RESULTS.lock();
    guard.clear_all();
}

#[derive(Debug)]
pub(crate) struct PerfResults {
    record: bool,
    list: KVec<KVVec<[u64; CYCLE_COUNTS_LEN]>>,
}

impl PerfResults {
    pub(crate) const fn new() -> Self {
        Self {
            record: false,
            list: KVec::new(),
        }
    }

    pub(crate) fn start_recording(&mut self) {
        // Delete entries from previous runs in case they were not removed
        self.clear_entries();
        self.record = true;
    }

    pub(crate) fn stop_recording(&mut self) {
        self.record = false;
    }

    pub(crate) fn clear_all(&mut self) {
        self.list.clear();
    }

    pub(crate) fn clear_entries(&mut self) {
        self.list.iter_mut().for_each(|v| v.clear());
    }

    pub(crate) fn register_runner(&mut self, uid: usize, amount: usize) -> Result {
        // All processes run under uids starting from 1000
        let index = uid.saturating_sub(1000);
        // Add 10 requests for some slack to make sure we don't crash because of this
        let amount = amount + 10;
        for _ in self.list.len()..=index {
            self.list
                .push(KVVec::with_capacity(amount, GFP_KERNEL)?, GFP_KERNEL)?
        }

        Ok(())
    }

    pub(crate) fn push(&mut self, uid: usize, cycle_counts: [u64; CYCLE_COUNTS_LEN]) {
        // Only store entries if we are recording
        if !self.record {
            return;
        }

        // All processes run under uids starting from 1000
        let index = uid.saturating_sub(1000);

        // SAFETY: according to the invariants the runner has registered itself beforehand and
        // provided the maximum amount of requests it will make during evaluation
        unsafe {
            let runner_entry = self.list.get_unchecked_mut(index);
            runner_entry.push_within_capacity_unchecked(cycle_counts);
        };
    }
}

impl core::fmt::Display for PerfResults {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[")?;
        let Some(results) = self.list.first() else {
            write!(f, "]")?;
            return Ok(());
        };

        write!(f, "{{\"1000\": {:?}}}", results)?;

        for (index, results) in self.list.iter().enumerate().skip(1) {
            write!(f, ",{{\"{}\": {:?}}}", index + 1000, results)?;
        }
        write!(f, "]")?;

        Ok(())
    }
}
