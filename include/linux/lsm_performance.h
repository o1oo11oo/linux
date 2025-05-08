/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Linux Security Module performance measurements for thesis
 *
 * This file provides routines to aid performance microbenchmarks for the ABAC
 * LSM and for SELinux, which are evaluated as part of the thesis. The dabac_rs
 * variants, implemented in Rust, use their own Rust eval code.
 */

#ifndef _LSM_PERFORMANCE_H
#define _LSM_PERFORMANCE_H

#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/types.h>

#if IS_ENABLED(CONFIG_SECURITY_PERFORMANCE_KERNEL_PRECISE)
#define CYCLE_COUNTS_LEN 14
#elif IS_ENABLED(CONFIG_SECURITY_PERFORMANCE_KERNEL)
#define CYCLE_COUNTS_LEN 2
// Cannot be zero sized as C does not allow that. Advantage for Rust I guess?
// Cannot use globals because of parallelism
#else
#define CYCLE_COUNTS_LEN 1
#endif

#define UID_OFFSET 1000

#define TSC_START 0
#define AFTER_GET_OP 1
#define AFTER_GET_USER_ATTR 2
#define AFTER_GET_OBJ 3
#define IN_RESOLVE 4
#define AFTER_NULL_CHECKS 5
#define LOOP_START 6

// abac_rules and abac_trees differ here
#define ABAC_RULES_AFTER_GET_RULE 7
#define ABAC_RULES_AFTER_CHECK_OP 8
#define ABAC_RULES_AFTER_CHECK_USER_ATTR 9
#define ABAC_RULES_AFTER_CHECK_ENV_ATTR 10

#define ABAC_TREES_BEFORE_GET_CHILD 7
#define ABAC_TREES_AFTER_CHECK_USER_ATTR 8
#define ABAC_TREES_AFTER_CHECK_ENV_ATTR 9
#define ABAC_TREES_AFTER_GET_CHILD 10
#define ABAC_TREES_AFTER_CHECK_CHILD 11
#define ABAC_TREES_AFTER_CHECK_OP 12

#define TSC_STOP (CYCLE_COUNTS_LEN-1)

struct perf_result_entry {
	u64 *entries; // Flattened array: count * CYCLE_COUNTS_LEN
	size_t count;
	size_t capacity;
};

struct perf_results {
	struct perf_result_entry *runners;
	size_t num_runners;
	spinlock_t lock;
	bool record;
};

// API
int perf_results_init(struct perf_results *store);
void perf_results_start_recording(struct perf_results *store);
void perf_results_stop_recording(struct perf_results *store);
void perf_results_clear_entries(struct perf_results *store);
int perf_results_register_runner(struct perf_results *store, uid_t uid, size_t amount);
void perf_results_push(struct perf_results *store, uid_t uid, const u64 values[CYCLE_COUNTS_LEN]);
void perf_results_free(struct perf_results *store);
void perf_results_serialize_to_json(struct perf_results *results, char *buf, size_t buf_size);

/**
 * Read the current cycle count
 *
 * Use this instead of the one provided by <asm/msr.h> as I am not sure the
 * variant selection gets compiled away. The CPU I am testing on provides
 * rdtscp, so it can be statically used directly.
 *
 * Adapted from kvm selftests
 */
static __always_inline uint64_t rdtscp(void)
{
	uint32_t eax, edx;
	uint32_t aux;

	__asm__ __volatile__("rdtscp" : "=a"(eax), "=d"(edx), "=c"(aux));
	return ((uint64_t)edx) << 32 | eax;
}

/**
 * Serialize and read the current cycle count
 */
static __always_inline uint64_t rdtscp_sync(void)
{
	uint32_t eax, edx;
	uint32_t aux;

	__asm__ __volatile__("rdtscp; lfence"
		: "=a"(eax), "=d"(edx), "=c"(aux)
		:: "memory"
	);

	return ((uint64_t)edx) << 32 | eax;
}

/**
 * Store the current cycle count in the first slot of the provided array
 */
static __always_inline void save_tsc_start(uint64_t *cycle_counts)
{
	#if IS_ENABLED(CONFIG_SECURITY_PERFORMANCE_KERNEL)
	cycle_counts[TSC_START] = rdtscp_sync();
	#endif
}

/**
 * Store the current cycle count in the last slot of the provided array and
 * print the results
 */
static __always_inline int save_tsc_stop(uint64_t *cycle_counts, uid_t uid, struct perf_results *store)
{
	#if IS_ENABLED(CONFIG_SECURITY_PERFORMANCE_KERNEL)
	cycle_counts[TSC_STOP] = rdtscp();

	perf_results_push(store, uid, cycle_counts);
	#endif

	return 0;
}

/**
 * Store the current cycle count in a provided array
 */
static __always_inline void save_tsc(uint64_t *cycle_counts, uint64_t index)
{
	#if IS_ENABLED(CONFIG_SECURITY_PERFORMANCE_KERNEL_PRECISE)
	cycle_counts[index] = rdtscp();
	#endif
}

static inline size_t uid_index(uid_t uid)
{
	return (uid >= UID_OFFSET) ? (uid - UID_OFFSET) : 0;
}

#endif
