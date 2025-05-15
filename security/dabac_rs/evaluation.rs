// SPDX-License-Identifier: GPL-2.0

//! Performance evaluation code for the Rust DABAC LSM.
//!
//! Contains the code for the in-kernel part of the performance measurement for the thesis.

// Not all position identifiers or functions are used in all variants
#![allow(dead_code)]

use core::arch::x86_64::{__rdtscp, _mm_lfence};

use kernel::{alloc::allocator::KVmalloc, global_lock, prelude::*, str::CString};

/// Amount of additional data to store after the timestamps
pub(crate) const EXTRA_STATS_AMOUNT: usize = 3;

/// Amount of cycle counts to store for intermediate measurements
#[cfg(CONFIG_SECURITY_PERFORMANCE_KERNEL_PRECISE)]
pub(crate) const CYCLE_COUNTS_LEN: usize = EXTRA_STATS_AMOUNT + 15;

/// Amount of cycle counts to store for start to end measurement
#[cfg(all(
    CONFIG_SECURITY_PERFORMANCE_KERNEL,
    not(CONFIG_SECURITY_PERFORMANCE_KERNEL_PRECISE)
))]
pub(crate) const CYCLE_COUNTS_LEN: usize = EXTRA_STATS_AMOUNT + 2;

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
pub(crate) const STOP: usize = CYCLE_COUNTS_LEN.saturating_sub(EXTRA_STATS_AMOUNT + 1);
pub(crate) const EXTRA_STATS_INDEX: usize = CYCLE_COUNTS_LEN.saturating_sub(EXTRA_STATS_AMOUNT);

/// Storage for the performance results.
///
/// Not protected by a global lock to not slow down the evaluation. The synchronization comes from
/// the fact that each runner can only send one request at a time, and each runner has their own
/// entry into this data structure. To ensure that no two mutable references to the same static mut
/// exist at the same time, only pointers are used until the Vec for one runner is reached. This
/// feels similar to how `split_at_mut` works internally to me, mutable references are ok as long as
/// they do not overlap. I am very far from certain though and I cannot easily check this under
/// miri. So far the results I am getting make sense and it looks like nothing has stomped all over
/// my memory yet.
///
/// The runner registration is synchronized using the [`PERF_REGISTRATION`] global lock. Cleanup is
/// only triggered by the orchestrator and can therefore not happen in parallel. But to quote the
/// Rustonomicon: "the guardrails here are dental floss".
static mut PERF_RESULTS: PerfResults = PerfResults::new();

global_lock! {
    // SAFETY: Initialized in module initializer before first use.
    unsafe(uninit) static PERF_REGISTRATION: SpinLock<()> = ();
}

/// Initialize the evaluation code during LSM initialization
pub(crate) fn init() -> Result {
    // SAFETY: All initializers are called exactly once.
    unsafe {
        PERF_REGISTRATION.init();
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
    let ret;
    // SAFETY: FFI/ASM calls without any requirements
    unsafe {
        ret = __rdtscp(&mut aux);
        _mm_lfence();
    };
    ret
}

/// Totally serialize and read the current cycle count
#[inline]
pub(crate) fn rdtscp_full_sync() -> u64 {
    let mut aux = 0;
    let ret;
    // SAFETY: FFI/ASM calls without any requirements
    unsafe {
        _mm_lfence();
        ret = __rdtscp(&mut aux);
        _mm_lfence();
    };
    ret
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

/// Store the current cycle count in the last TSC slot of the provided array, stop the measurement
/// and immediately store the whole results in the buffer to be fetched later
#[inline]
#[cfg_attr(
    not(CONFIG_SECURITY_PERFORMANCE_KERNEL),
    allow(unused_variables, unused_mut)
)]
pub(crate) fn save_tsc_stop(mut cycle_counts: [u64; CYCLE_COUNTS_LEN], uid: usize) {
    #[cfg(CONFIG_SECURITY_PERFORMANCE_KERNEL)]
    {
        cycle_counts[STOP] = rdtscp();

        // Because all runners have their own entry into the Vec, add entries without locking it.
        // This requires no mutable references to be created until the Vec for each runner is
        // reached, as otherwise this is UB.
        // SAFETY: This is during performance evaluation and the orechestrator is waiting for the
        // runners, so the conditions of the call are fulfilled.
        unsafe { PerfResults::push(uid, cycle_counts) }
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

/// Store additional data about the request.
///
/// Currently contains the amount of post-conditions that were executed and the cache hits and
/// misses.
#[inline]
#[cfg_attr(not(CONFIG_SECURITY_PERFORMANCE_KERNEL), allow(unused_variables))]
pub(crate) fn save_extra_stats(
    cycle_counts: &mut [u64; CYCLE_COUNTS_LEN],
    stats: [u64; EXTRA_STATS_AMOUNT],
) {
    #[cfg(CONFIG_SECURITY_PERFORMANCE_KERNEL)]
    {
        cycle_counts[EXTRA_STATS_INDEX..EXTRA_STATS_INDEX + EXTRA_STATS_AMOUNT]
            .copy_from_slice(&stats);
    }
}

pub(crate) fn register_perf(uid: usize, amount: usize) -> Result {
    let _guard = PERF_REGISTRATION.lock();
    // SAFETY: actually decent as long as nothing is getting decisions from the LSM, which could
    // access the PERF_RESULTS in parallel
    unsafe { PERF_RESULTS.register_runner(uid, amount) }
}

pub(crate) fn start_perf_run() {
    let _guard = PERF_REGISTRATION.lock();
    // SAFETY: actually decent as long as nothing is getting decisions from the LSM, which could
    // access the PERF_RESULTS in parallel
    unsafe { PERF_RESULTS.start_recording() }
}

pub(crate) fn get_perf_results() -> Result<CString<KVmalloc>> {
    let _guard = PERF_REGISTRATION.lock();
    // SAFETY: actually decent as long as nothing is getting decisions from the LSM, which could
    // access the PERF_RESULTS in parallel
    unsafe {
        PERF_RESULTS.stop_recording();
        CString::try_from_fmt(fmt!("{}", &PERF_RESULTS))
    }
}

pub(crate) fn clear_perf_data() {
    let _guard = PERF_REGISTRATION.lock();
    // SAFETY: actually decent as long as nothing is getting decisions from the LSM, which could
    // access the PERF_RESULTS in parallel
    unsafe { PERF_RESULTS.clear() }
}

pub(crate) fn reset_perf_data() {
    let _guard = PERF_REGISTRATION.lock();
    // SAFETY: actually decent as long as nothing is getting decisions from the LSM, which could
    // access the PERF_RESULTS in parallel
    unsafe { PERF_RESULTS.reset() }
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
        self.clear();
        self.record = true;
    }

    pub(crate) fn stop_recording(&mut self) {
        self.record = false;
    }

    pub(crate) fn reset(&mut self) {
        self.list.clear();
    }

    pub(crate) fn clear(&mut self) {
        self.list.iter_mut().for_each(|v| v.clear());
    }

    pub(crate) fn register_runner(&mut self, uid: usize, amount: usize) -> Result {
        // All processes run under uids starting from 1000
        let index = uid.saturating_sub(1000);
        // Add 10 requests for some slack to make sure we don't crash because of this
        let amount = amount + 10;

        // Make sure the Vec contains the required entry
        for _ in self.list.len()..=index {
            self.list.push(KVVec::new(), GFP_KERNEL)?
        }

        // Update the required entry to its correct amount
        if let Some(entry) = self.list.get_mut(index) {
            *entry = KVVec::with_capacity(amount, GFP_KERNEL)?
        }

        Ok(())
    }

    /// # Safety
    ///
    /// May only be called during performance evaluation after all runners were set up and while the
    /// perf store is not modified in any other way concurrently.
    pub(crate) unsafe fn push(uid: usize, cycle_counts: [u64; CYCLE_COUNTS_LEN]) {
        let ptr = &raw mut PERF_RESULTS;

        // Only store entries if we are recording
        // SAFETY: The pointer is valid because it comes from the static instance
        if unsafe { !(*ptr).record } {
            return;
        }

        // All processes run under uids starting from 1000
        let index = uid.saturating_sub(1000);

        // SAFETY: The pointer is valid because it comes from the static instance.
        let list = unsafe { (*ptr).list.ptr.as_ptr() };

        // SAFETY: The runner must have been registered before as per the safety requirement of this
        // function, so we can get it its entry.
        let runner_ptr = unsafe { list.add(index) };

        // SAFETY: The runner only sends one request at a time, so this is the only mutable
        // reference to its Vec.
        let runner_vec = unsafe { &mut *runner_ptr };

        // SAFETY: according to the invariants the runner has registered itself beforehand and
        // provided the maximum amount of requests it will make during evaluation
        unsafe { runner_vec.push_within_capacity_unchecked(cycle_counts) };
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
