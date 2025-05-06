// SPDX-License-Identifier: GPL-2.0

#include <linux/lsm_performance.h>

int perf_results_init(struct perf_results *store)
{
	spin_lock_init(&store->lock);
	store->runners = NULL;
	store->num_runners = 0;
	store->record = false;
	return 0;
}

void perf_results_start_recording(struct perf_results *store)
{
	spin_lock(&store->lock);
	store->record = true;
	for (size_t i = 0; i < store->num_runners; ++i)
		store->runners[i].count = 0;
	spin_unlock(&store->lock);
}

void perf_results_stop_recording(struct perf_results *store)
{
	spin_lock(&store->lock);
	store->record = false;
	spin_unlock(&store->lock);
}

void perf_results_clear_entries(struct perf_results *store)
{
	spin_lock(&store->lock);
	for (size_t i = 0; i < store->num_runners; ++i)
		store->runners[i].count = 0;
	spin_unlock(&store->lock);
}

void perf_results_free(struct perf_results *store)
{
	spin_lock(&store->lock);
	for (size_t i = 0; i < store->num_runners; ++i) {
		kfree(store->runners[i].entries);
		store->runners[i].entries = NULL;
		store->runners[i].count = 0;
		store->runners[i].capacity = 0;
	}
	kfree(store->runners);
	store->runners = NULL;
	store->num_runners = 0;
	spin_unlock(&store->lock);
}

int perf_results_register_runner(struct perf_results *store, uid_t uid, size_t amount)
{
	size_t index = uid_index(uid);
	size_t new_size = index + 1;

	spin_lock(&store->lock);

	if (new_size > store->num_runners) {
		struct perf_result_entry *new_runners;

		new_runners = krealloc(store->runners, new_size * sizeof(*store->runners), GFP_KERNEL);
		if (!new_runners) {
			spin_unlock(&store->lock);
			return -ENOMEM;
		}

		// Zero newly added slots
		for (size_t i = store->num_runners; i < new_size; ++i) {
			new_runners[i].entries = NULL;
			new_runners[i].count = 0;
			new_runners[i].capacity = 0;
		}

		store->runners = new_runners;
		store->num_runners = new_size;
	}

	struct perf_result_entry *runner = &store->runners[index];

	if (!runner->entries) {
		runner->capacity = amount + 10;
		runner->count = 0;
		runner->entries = kmalloc_array(runner->capacity * CYCLE_COUNTS_LEN, sizeof(u64), GFP_KERNEL);
		if (!runner->entries) {
			spin_unlock(&store->lock);
			return -ENOMEM;
		}
	}

	spin_unlock(&store->lock);
	return 0;
}

void perf_results_push(struct perf_results *store, uid_t uid, const u64 values[CYCLE_COUNTS_LEN])
{
	size_t index = uid_index(uid);

	spin_lock(&store->lock);

	// Only store entries if we are recording
	if (!store->record) {
		spin_unlock(&store->lock);
		return;
	}

	struct perf_result_entry *runner = &store->runners[index];
	u64 *dst = &runner->entries[runner->count * CYCLE_COUNTS_LEN];

	memcpy(dst, values, sizeof(u64) * CYCLE_COUNTS_LEN);
	runner->count++;

	spin_unlock(&store->lock);
}
