// SPDX-License-Identifier: GPL-2.0

// PAP bindings for Rust DABAC LSM
// Variant: spinlocks, top level caching with hashing (SL-TLCH)

// This code is based on the ABAC LSM securityfs implementation

#include <linux/security.h>

struct dentry *dabac_rs_sl_tlch_fs;
struct dentry *dabac_rs_sl_tlch_user_attr_file;
struct dentry *dabac_rs_sl_tlch_obj_attr_file;
struct dentry *dabac_rs_sl_tlch_env_attr_file;
struct dentry *dabac_rs_sl_tlch_policy_file;

// The unsafety of these functions is somewhat hidden by the linker, in C the
// function definitions contain a pointer argument, while the same argument is
// represented as UserPtr (usize) in Rust. Since there is no unsafe function to
// create a UserPtr from an actual pointer, this is probably not the worst, but
// still a bit shady.
extern ssize_t dabac_rs_sl_tlch_read_user_attr(struct file *filp, char __user *buffer, size_t count, loff_t *off);
extern ssize_t dabac_rs_sl_tlch_update_user_attr(struct file *filp, const char __user *buffer, size_t len, loff_t *off);
extern ssize_t dabac_rs_sl_tlch_read_object_attr(struct file *filp, char __user *buffer, size_t count, loff_t *off);
extern ssize_t dabac_rs_sl_tlch_update_object_attr(struct file *filp, const char __user *buffer, size_t len, loff_t *off);
extern ssize_t dabac_rs_sl_tlch_read_env_attr(struct file *filp, char __user *buffer, size_t count, loff_t *off);
extern ssize_t dabac_rs_sl_tlch_update_env_attr(struct file *filp, const char __user *buffer, size_t len, loff_t *off);
extern ssize_t dabac_rs_sl_tlch_read_policy(struct file *filp, char __user *buffer, size_t count, loff_t *off);
extern ssize_t dabac_rs_sl_tlch_update_policy(struct file *filp, const char __user *buffer, size_t len, loff_t *off);

int dabac_rs_sl_tlch_initialized;

void dabac_rs_sl_tlch_init_done(void);
void dabac_rs_sl_tlch_init_done(void)
{
	dabac_rs_sl_tlch_initialized = 1;
}

static int dabac_rs_sl_tlch_open(struct inode *i, struct file *f)
{
	// No check here, POSIX permissions limit access to root
	return 0;
}

static const struct file_operations user_attr_fops = {
	.open = dabac_rs_sl_tlch_open,
	.read = dabac_rs_sl_tlch_read_user_attr,
	.write = dabac_rs_sl_tlch_update_user_attr,
};

static const struct file_operations obj_attr_fops = {
	.open = dabac_rs_sl_tlch_open,
	.read = dabac_rs_sl_tlch_read_object_attr,
	.write = dabac_rs_sl_tlch_update_object_attr,
};

static const struct file_operations env_attr_fops = {
	.open = dabac_rs_sl_tlch_open,
	.read = dabac_rs_sl_tlch_read_env_attr,
	.write = dabac_rs_sl_tlch_update_env_attr,
};

static const struct file_operations policy_fops = {
	.open = dabac_rs_sl_tlch_open,
	.read = dabac_rs_sl_tlch_read_policy,
	.write = dabac_rs_sl_tlch_update_policy,
};

static void dabac_rs_sl_tlch_destroy_fs(void)
{
	if (dabac_rs_sl_tlch_user_attr_file)
		securityfs_remove(dabac_rs_sl_tlch_user_attr_file);
	if (dabac_rs_sl_tlch_obj_attr_file)
		securityfs_remove(dabac_rs_sl_tlch_obj_attr_file);
	if (dabac_rs_sl_tlch_env_attr_file)
		securityfs_remove(dabac_rs_sl_tlch_env_attr_file);
	if (dabac_rs_sl_tlch_policy_file)
		securityfs_remove(dabac_rs_sl_tlch_policy_file);
	if (dabac_rs_sl_tlch_fs)
		securityfs_remove(dabac_rs_sl_tlch_fs);
}

static struct dentry *dabac_rs_sl_tlch_create_file(const char *filename, const struct file_operations *fops)
{
	struct dentry *f;

	// File is writable by everyone because the PAP checks each access with the PDP
	f = securityfs_create_file(filename, 0666, dabac_rs_sl_tlch_fs, NULL, fops);
	if (!f) {
		pr_err("dabac_rs_sl_tlch: Failed to create file /sys/kernel/security/dabac_rs/%s", filename);
		dabac_rs_sl_tlch_destroy_fs();
		return NULL;
	}
	pr_info("dabac_rs_sl_tlch: Created file /sys/kernel/security/dabac_rs/%s", filename);
	return f;
}

static int dabac_rs_sl_tlch_create_fs(void)
{
	if (!dabac_rs_sl_tlch_initialized) {
		pr_info("dabac_rs_sl_tlch: LSM was not initialized, not loading securityfs");
		return 0;
	}

	if (dabac_rs_sl_tlch_fs) {
		pr_err("dabac_rs_sl_tlch: securityfs already exists, did you load multiple dabac_rs variants?");
		return -EEXIST;
	}

	// create the root 'dabac_rs' directory
	dabac_rs_sl_tlch_fs = securityfs_create_dir("dabac_rs", NULL);
	if (!dabac_rs_sl_tlch_fs) {
		pr_err("dabac_rs_sl_tlch: Failed to create dabac_rs securityfs at /sys/kernel/security/dabac_rs/");
		dabac_rs_sl_tlch_destroy_fs();
		return -1;
	}

	dabac_rs_sl_tlch_user_attr_file = dabac_rs_sl_tlch_create_file("user_attr", &user_attr_fops);
	if (!dabac_rs_sl_tlch_user_attr_file) {
		dabac_rs_sl_tlch_destroy_fs();
		return -1;
	}
	dabac_rs_sl_tlch_obj_attr_file = dabac_rs_sl_tlch_create_file("obj_attr", &obj_attr_fops);
	if (!dabac_rs_sl_tlch_obj_attr_file) {
		dabac_rs_sl_tlch_destroy_fs();
		return -1;
	}
	dabac_rs_sl_tlch_env_attr_file = dabac_rs_sl_tlch_create_file("env_attr", &env_attr_fops);
	if (!dabac_rs_sl_tlch_env_attr_file) {
		dabac_rs_sl_tlch_destroy_fs();
		return -1;
	}
	dabac_rs_sl_tlch_policy_file = dabac_rs_sl_tlch_create_file("policy", &policy_fops);
	if (!dabac_rs_sl_tlch_policy_file) {
		dabac_rs_sl_tlch_destroy_fs();
		return -1;
	}

	return 0;
}

fs_initcall(dabac_rs_sl_tlch_create_fs);
