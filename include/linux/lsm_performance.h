/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Linux Security Module performance measurements for thesis
 *
 * This file provides routines to aid performance microbenchmarks for the ABAC
 * LSM and for SELinux, which are evaluated as part of the thesis. The dabac_rs
 * variants, implemented in Rust, use their own Rust eval code.
 */

#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

// Define this here as fall back to silence IDE warnings
#ifndef LSM_NAME
#define LSM_NAME "unknown"
#endif

#if IS_ENABLED(CONFIG_SECURITY_PERFORMANCE_KERNEL_PRECISE)
#define CYCLE_COUNTS_LEN 14
#elif IS_ENABLED(CONFIG_SECURITY_PERFORMANCE_KERNEL)
#define CYCLE_COUNTS_LEN 2
// Cannot be zero sized as C does not allow that. Advantage for Rust I guess?
// Cannot use globals because of parallelism
#else CYCLE_COUNTS_LEN 1
#endif

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

static char *join_uint64_array(uint64_t *array, size_t length, const char *delimiter);

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

	__asm__ __volatile__("lfence; rdtscp"
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
static __always_inline int save_tsc_stop(uint64_t *cycle_counts)
{
	#if IS_ENABLED(CONFIG_SECURITY_PERFORMANCE_KERNEL)
	cycle_counts[TSC_STOP] = rdtscp();

	char *joined_cycle_counts = join_uint64_array(cycle_counts, CYCLE_COUNTS_LEN, ", ");

	if (IS_ERR(joined_cycle_counts))
		return PTR_ERR(joined_cycle_counts);

	pr_info("%s: cycle_counts: [%s]", LSM_NAME, joined_cycle_counts);
	kfree(joined_cycle_counts);
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

/*
 * Generate a string representation from a uint64_t array
 *
 * AI generated, with little touchups for checkpatch, can't be bothered to
 * implement something like this by hand just to communicate some values to user
 * space. The joy of C programming.
 */
static char *join_uint64_array(uint64_t *array, size_t length, const char *delimiter)
{
	size_t delimiter_len = strlen(delimiter);
	size_t total_length = 0;
	size_t i;
	char *result;
	char *ptr;

	// Calculate the total length needed for the result string
	for (i = 0; i < length; i++) {
		total_length += 20; // Max length for a uint64_t is 20 characters
		if (i < length - 1)
			total_length += delimiter_len;
	}
	total_length += 1; // For the null terminator

	// Allocate memory for the result string
	result = kmalloc(total_length, GFP_KERNEL);
	if (!result)
		return ERR_PTR(-ENOMEM);

	ptr = result;

	// Convert each uint64_t to a string and concatenate with the delimiter
	for (i = 0; i < length; i++) {
		ptr += sprintf(ptr, "%llu", (unsigned long long)array[i]);
		if (i < length - 1) {
			strcpy(ptr, delimiter);
			ptr += delimiter_len;
		}
	}

	return result;
}
