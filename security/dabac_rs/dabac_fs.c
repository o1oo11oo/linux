// SPDX-License-Identifier: GPL-2.0

// This code is based on the ABAC LSM securityfs implementation

#include <linux/security.h>

struct dentry *dabacfs;
struct dentry *dabac_rs_user_attr_file;
struct dentry *dabac_rs_obj_attr_file;
struct dentry *dabac_rs_env_attr_file;
struct dentry *dabac_rs_policy_file;

// The unsafety of these functions is somewhat hidden by the linker, in C the
// function definitions contain a pointer argument, while the same argument is
// represented as UserPtr (usize) in Rust. Since there is no unsafe function to
// create a UserPtr from an actual pointer, this is probably not the worst, but
// still a bit shady.
extern ssize_t dabac_rs_update_user_attr(struct file *filp, const char __user *buffer, size_t len, loff_t *off);
extern ssize_t dabac_rs_update_object_attr(struct file *filp, const char __user *buffer, size_t len, loff_t *off);
extern ssize_t dabac_rs_update_env_attr(struct file *filp, const char __user *buffer, size_t len, loff_t *off);
extern ssize_t dabac_rs_update_policy(struct file *filp, const char __user *buffer, size_t len, loff_t *off);

static int dabac_rs_open(struct inode *i, struct file *f)
{
	// No check here, POSIX permissions limit access to root
	return 0;
}

static const struct file_operations user_attr_fops = {
	.open = dabac_rs_open,
	.write = dabac_rs_update_user_attr,
};

static const struct file_operations obj_attr_fops = {
	.open = dabac_rs_open,
	.write = dabac_rs_update_object_attr,
};

static const struct file_operations env_attr_fops = {
	.open = dabac_rs_open,
	.write = dabac_rs_update_env_attr,
};

static const struct file_operations policy_fops = {
	.open = dabac_rs_open,
	.write = dabac_rs_update_policy,
};

static void dabac_rs_destroy_fs(void)
{
	if (dabac_rs_user_attr_file)
		securityfs_remove(dabac_rs_user_attr_file);
	if (dabac_rs_obj_attr_file)
		securityfs_remove(dabac_rs_obj_attr_file);
	if (dabac_rs_env_attr_file)
		securityfs_remove(dabac_rs_env_attr_file);
	if (dabac_rs_policy_file)
		securityfs_remove(dabac_rs_policy_file);
	if (dabacfs)
		securityfs_remove(dabacfs);
}

static struct dentry *dabac_rs_create_file(const char *filename, const struct file_operations *fops)
{
	struct dentry *f;

	f = securityfs_create_file(filename, 0600, dabacfs, NULL, fops);
	if (!f) {
		pr_err("dabac_rs: Failed to create file /sys/kernel/security/dabac_rs/%s", filename);
		dabac_rs_destroy_fs();
		return NULL;
	}
	pr_info("dabac_rs: Created file /sys/kernel/security/dabac_rs/%s", filename);
	return f;
}

static int dabac_rs_create_fs(void)
{
	// create the root 'dabac_rs' directory
	dabacfs = securityfs_create_dir("dabac_rs", NULL);
	if (!dabacfs) {
		pr_err("dabac_rs: Failed to create dabac_rs securityfs at /sys/kernel/security/dabac_rs/");
		dabac_rs_destroy_fs();
		return -1;
	}

	dabac_rs_user_attr_file = dabac_rs_create_file("user_attr", &user_attr_fops);
	if (!dabac_rs_user_attr_file) {
		dabac_rs_destroy_fs();
		return -1;
	}
	dabac_rs_obj_attr_file = dabac_rs_create_file("obj_attr", &obj_attr_fops);
	if (!dabac_rs_obj_attr_file) {
		dabac_rs_destroy_fs();
		return -1;
	}
	dabac_rs_env_attr_file = dabac_rs_create_file("env_attr", &env_attr_fops);
	if (!dabac_rs_env_attr_file) {
		dabac_rs_destroy_fs();
		return -1;
	}
	dabac_rs_policy_file = dabac_rs_create_file("policy", &policy_fops);
	if (!dabac_rs_policy_file) {
		dabac_rs_destroy_fs();
		return -1;
	}

	return 0;
}

fs_initcall(dabac_rs_create_fs);
