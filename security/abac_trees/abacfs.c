#include "abacfs.h"
#include "cache.h"
#include <linux/init.h>
#include <linux/security.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/lsm_performance.h>

extern struct perf_results abac_trees_perf_store;

const size_t ABAC_TREES_MAX_FILE_SIZE = 8388608; // 8MB

struct dentry *abac_trees_abacfs;
struct dentry *abac_trees_user_attr_file;
struct dentry *abac_trees_obj_attr_file;
struct dentry *abac_trees_env_attr_file;
struct dentry *abac_trees_perf_file;

struct dentry *abac_trees_generic_abacfs;
struct dentry *abac_trees_generic_user_attr_file;
struct dentry *abac_trees_generic_obj_attr_file;
struct dentry *abac_trees_generic_env_attr_file;
struct dentry *abac_trees_generic_perf_file;

char *abac_trees_user_attr_buf = NULL;
char *abac_trees_obj_attr_buf = NULL;
char *abac_trees_env_attr_buf = NULL;
char abac_trees_perf_buf[64];
int abac_trees_recording = 0;
u64 abac_trees_prev_access_time = 0;

avp *abac_trees_env_attr = NULL;

// method for opening policy file
static int abac_open(struct inode *i, struct file *f)
{
	// TODO: Add a check to let only the root access the policy file
	return 0;
}

// method for writing to user_attrs file
static ssize_t user_attr_write(struct file *filp, const char __user *buffer,
			       size_t len, loff_t *off)
{
	if (len >= ABAC_TREES_MAX_FILE_SIZE) {
		printk(KERN_INFO
		       "Write failed. Buffer too large %zu. Maximum file size is %zu\n",
		       len, ABAC_TREES_MAX_FILE_SIZE);
		return -EFAULT;
	}
	if (abac_trees_user_attr_buf) {
		abac_trees_clear_user_attrs();
		kfree(abac_trees_user_attr_buf);
	}
	abac_trees_user_attr_buf = kmalloc(len + 1, GFP_KERNEL);
	if (!abac_trees_user_attr_buf) {
		printk(KERN_INFO
		       "Write failed. Failed to allocate memory for user attributes buffer\n");
		return -EFAULT;
	}
	if (copy_from_user(abac_trees_user_attr_buf, buffer, len + 1)) {
		printk(KERN_INFO "Write to user_attrs failed\n");
		return -EFAULT;
	}
	abac_trees_user_attr_buf[len] = '\0';
	printk("User attributes written to buffer. Attempting to parse...");
	abac_trees_parse_user_attr(abac_trees_user_attr_buf);
	//abac_trees_print_user_attrs();
	printk("User attributes loaded");
	//clear_cache();
	return len;
}

// method for writing to obj_attrs file
static ssize_t obj_attr_write(struct file *filp, const char __user *buffer, size_t len, loff_t *off)
{
	if (len >= ABAC_TREES_MAX_FILE_SIZE) {
		printk(KERN_INFO "Write failed. Buffer too large %zu. Maximum file size is %zu\n", len, ABAC_TREES_MAX_FILE_SIZE);
		return -EFAULT;
	}
	if (abac_trees_obj_attr_buf) {
		abac_trees_clear_obj_attrs();
		kfree(abac_trees_obj_attr_buf);
	}
	abac_trees_obj_attr_buf = kmalloc(len + 1, GFP_KERNEL);
	if (!abac_trees_obj_attr_buf) {
		printk(KERN_INFO "Write failed. Failed to allocate memory for object attributes buffer\n");
		return -EFAULT;
	}
	if (copy_from_user(abac_trees_obj_attr_buf, buffer, len + 1)) {
		printk(KERN_INFO "Write to obj_attrs failed\n");
		return -EFAULT;
	}
	abac_trees_obj_attr_buf[len] = '\0';
	printk("Object attributes written to buffer. Attempting to parse...");
	abac_trees_parse_obj_attr(abac_trees_obj_attr_buf);
	//abac_trees_print_obj_attrs();
	printk("Object attributes loaded");
	//clear_cache();
	return len;
}

// method for writing to env_attrs file
static ssize_t env_attr_write(struct file *filp, const char __user *buffer,
			      size_t len, loff_t *off)
{
	if (len >= ABAC_TREES_MAX_FILE_SIZE) {
		printk(KERN_INFO
		       "Write failed. Buffer too large %zu. Maximum file size is %zu\n",
		       len, ABAC_TREES_MAX_FILE_SIZE);
		return -EFAULT;
	}
	if (abac_trees_env_attr_buf) {
		abac_trees_clear_avp_list(abac_trees_env_attr);
		kfree(abac_trees_env_attr_buf);
	}
	abac_trees_env_attr_buf = kmalloc(len + 1, GFP_KERNEL);
	if (!abac_trees_env_attr_buf) {
		printk(KERN_INFO
		       "Write failed. Failed to allocate memory for environment "
		       "attributes buffer\n");
		return -EFAULT;
	}
	if (copy_from_user(abac_trees_env_attr_buf, buffer, len + 1)) {
		printk(KERN_INFO "Write to env_attrs failed\n");
		return -EFAULT;
	}
	abac_trees_env_attr_buf[len] = '\0';
	printk("Environment attributes written to buffer. Attempting to parse...");
	abac_trees_env_attr = abac_trees_parse_env_attr(abac_trees_env_attr_buf);
	//abac_trees_print_env_attrs(abac_trees_env_attr);
	printk("Environment attributes loaded");
	//clear_cache();
	return len;
}

static ssize_t perf_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	char *kbuf;
	ssize_t ret;

	// Stop recording when reading
	perf_results_stop_recording(&abac_trees_perf_store);

	// Allocate buffer
	kbuf = kvmalloc(ABAC_TREES_MAX_FILE_SIZE, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	// Fill with JSON output
	perf_results_serialize_to_json(&abac_trees_perf_store, kbuf, ABAC_TREES_MAX_FILE_SIZE);

	// Use simple_read_from_buffer to handle ppos and copy to userspace
	ret = simple_read_from_buffer(buf, count, ppos, kbuf, strlen(kbuf));
	kvfree(kbuf);
	return ret;
}

static ssize_t perf_write(struct file *file, const char __user *ubuf, size_t len, loff_t *ppos)
{
	char kbuf[32];
	size_t to_copy = min(len, sizeof(kbuf) - 1);
	uid_t uid = current_euid().val;
	int ret, parsed;

	if (copy_from_user(kbuf, ubuf, to_copy))
		return -EFAULT;

	kbuf[to_copy] = '\0';
	strim(kbuf); // remove trailing whitespace

	if (strcmp(kbuf, "start") == 0) {
		pr_info("Starting perf run\n");
		perf_results_start_recording(&abac_trees_perf_store);
	} else if (strcmp(kbuf, "clear") == 0) {
		pr_info("Clearing perf data\n");
		perf_results_clear_entries(&abac_trees_perf_store);
	} else if (strcmp(kbuf, "reset") == 0) {
		pr_info("Resetting perf data storage\n");
		perf_results_free(&abac_trees_perf_store);
	} else {
		ret = kstrtoint(kbuf, 10, &parsed);
		if (ret)
			return ret;
		pr_info("Registering perf runner %d with %d entries\n", uid, parsed);
		perf_results_register_runner(&abac_trees_perf_store, uid, parsed);
	}

	return len;
}

static const struct file_operations user_attr_fops = {
	.open = abac_open,
	.write = user_attr_write,
};

static const struct file_operations obj_attr_fops = {
	.open = abac_open,
	.write = obj_attr_write,
};

static const struct file_operations env_attr_fops = {
	.open = abac_open,
	.write = env_attr_write,
};

static const struct file_operations perf_fops = {
	.read = perf_read,
	.write = perf_write,
};

static void destroy_abac_fs(void)
{
	if (!IS_ERR_OR_NULL(abac_trees_user_attr_file)) {
		securityfs_remove(abac_trees_user_attr_file);
	}
	if (!IS_ERR_OR_NULL(abac_trees_obj_attr_file)) {
		securityfs_remove(abac_trees_obj_attr_file);
	}
	if (!IS_ERR_OR_NULL(abac_trees_env_attr_file)) {
		securityfs_remove(abac_trees_env_attr_file);
	}
	if (!IS_ERR_OR_NULL(abac_trees_perf_file)) {
		securityfs_remove(abac_trees_perf_file);
	}
	if (!IS_ERR_OR_NULL(abac_trees_abacfs)) {
		securityfs_remove(abac_trees_abacfs);
	}
	if (!IS_ERR_OR_NULL(abac_trees_generic_user_attr_file)) {
		securityfs_remove(abac_trees_generic_user_attr_file);
	}
	if (!IS_ERR_OR_NULL(abac_trees_generic_obj_attr_file)) {
		securityfs_remove(abac_trees_generic_obj_attr_file);
	}
	if (!IS_ERR_OR_NULL(abac_trees_generic_env_attr_file)) {
		securityfs_remove(abac_trees_generic_env_attr_file);
	}
	if (!IS_ERR_OR_NULL(abac_trees_generic_perf_file)) {
		securityfs_remove(abac_trees_generic_perf_file);
	}
	if (!IS_ERR_OR_NULL(abac_trees_generic_abacfs)) {
		securityfs_remove(abac_trees_generic_abacfs);
	}
}

static struct dentry *create_file(struct dentry *parent, const char *parentname, const char *filename, const struct file_operations *fops) {
	struct dentry *f;
	f = securityfs_create_file(filename, 0666, parent, NULL, fops);
	if (IS_ERR(f)) {
		printk(KERN_ERR "ABAC LSM (Trees): Failed to create file /sys/kernel/security/%s/%s", parentname, filename);
		destroy_abac_fs();
		return f;
	}
	printk(KERN_INFO "ABAC LSM (Trees): Created file /sys/kernel/security/%s/%s", parentname, filename);
	return f;
}

/* create the abac filesystem */
static int abac_create_fs(void)
{
	const char *parentname = "abac_trees";

	if (!abac_trees_initialized) {
		pr_info("ABAC LSM (Trees): LSM was not initialized, not loading securityfs");
		return 0;
	}

	// create the root 'abac' directory
	abac_trees_abacfs = securityfs_create_dir(parentname, NULL);
	if (IS_ERR(abac_trees_abacfs)) {
		printk(KERN_ERR "ABAC LSM (Trees): Failed to create abac securityfs at /sys/kernel/security/%s/", parentname);
		destroy_abac_fs();
		return PTR_ERR(abac_trees_abacfs);
	}

	abac_trees_user_attr_file = create_file(abac_trees_abacfs, parentname, "user_attr", &user_attr_fops);
	if (IS_ERR(abac_trees_user_attr_file)) {
		destroy_abac_fs();
		return PTR_ERR(abac_trees_user_attr_file);
	}
	abac_trees_obj_attr_file = create_file(abac_trees_abacfs, parentname, "obj_attr", &obj_attr_fops);
	if (IS_ERR(abac_trees_obj_attr_file)) {
		destroy_abac_fs();
		return PTR_ERR(abac_trees_obj_attr_file);
	}
	abac_trees_env_attr_file = create_file(abac_trees_abacfs, parentname, "env_attr", &env_attr_fops);
	if (IS_ERR(abac_trees_env_attr_file)) {
		destroy_abac_fs();
		return PTR_ERR(abac_trees_env_attr_file);
	}

	// Performance evaluation file
	abac_trees_perf_file = create_file(abac_trees_abacfs, parentname, "perf", &perf_fops);
	if (IS_ERR(abac_trees_perf_file)) {
		destroy_abac_fs();
		return PTR_ERR(abac_trees_perf_file);
	}

	printk(KERN_INFO "ABAC LSM (Trees): Securityfs Initialized");
	return 0;
}

/* create the abac filesystem */
static int abac_create_generic_fs(void)
{
	const char *parentname = "abac";

	if (!abac_trees_initialized) {
		pr_info("ABAC LSM (Trees): LSM was not initialized, not loading generic securityfs");
		return 0;
	}

	if (abac_rules_initialized || abac_rules_enc_initialized || abac_trees_enc_initialized) {
		pr_info("ABAC LSM (Trees): We are not the only ABAC LSM, not using generic paths");
		return 0;
	}

	pr_info("ABAC LSM (Trees): We are the only ABAC LSM, using generic paths additionally");

	// create the root 'abac' directory
	abac_trees_generic_abacfs = securityfs_create_dir(parentname, NULL);
	if (IS_ERR(abac_trees_generic_abacfs)) {
		printk(KERN_ERR "ABAC LSM (Trees): Failed to create abac securityfs at /sys/kernel/security/%s/", parentname);
		destroy_abac_fs();
		return PTR_ERR(abac_trees_generic_abacfs);
	}

	abac_trees_generic_user_attr_file = create_file(abac_trees_generic_abacfs, parentname, "user_attr", &user_attr_fops);
	if (IS_ERR(abac_trees_generic_user_attr_file)) {
		destroy_abac_fs();
		return PTR_ERR(abac_trees_generic_user_attr_file);
	}
	abac_trees_generic_obj_attr_file = create_file(abac_trees_generic_abacfs, parentname, "obj_attr", &obj_attr_fops);
	if (IS_ERR(abac_trees_generic_obj_attr_file)) {
		destroy_abac_fs();
		return PTR_ERR(abac_trees_generic_obj_attr_file);
	}
	abac_trees_generic_env_attr_file = create_file(abac_trees_generic_abacfs, parentname, "env_attr", &env_attr_fops);
	if (IS_ERR(abac_trees_generic_env_attr_file)) {
		destroy_abac_fs();
		return PTR_ERR(abac_trees_generic_env_attr_file);
	}

	// Performance evaluation file
	abac_trees_generic_perf_file = create_file(abac_trees_generic_abacfs, parentname, "perf", &perf_fops);
	if (IS_ERR(abac_trees_generic_perf_file)) {
		destroy_abac_fs();
		return PTR_ERR(abac_trees_generic_perf_file);
	}

	printk(KERN_INFO "ABAC LSM (Trees): Generic Securityfs Initialized");
	return 0;
}

fs_initcall(abac_create_fs);
fs_initcall(abac_create_generic_fs);
