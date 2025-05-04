// SPDX-License-Identifier: GPL-2.0

// PAP bindings for Rust DABAC LSM
// Variant: mutexes, formula level caching with hashing (MX-FLCH)

// This code is based on the ABAC LSM securityfs implementation

#include <linux/security.h>

struct dentry *dabac_rs_mx_flch_fs;
struct dentry *dabac_rs_mx_flch_user_attr_file;
struct dentry *dabac_rs_mx_flch_obj_attr_file;
struct dentry *dabac_rs_mx_flch_env_attr_file;
struct dentry *dabac_rs_mx_flch_policy_file;
struct dentry *dabac_rs_mx_flch_perf_file;

struct dentry *dabac_rs_mx_flch_generic_fs;
struct dentry *dabac_rs_mx_flch_generic_user_attr_file;
struct dentry *dabac_rs_mx_flch_generic_obj_attr_file;
struct dentry *dabac_rs_mx_flch_generic_env_attr_file;
struct dentry *dabac_rs_mx_flch_generic_policy_file;
struct dentry *dabac_rs_mx_flch_generic_perf_file;

// The unsafety of these functions is somewhat hidden by the linker, in C the
// function definitions contain a pointer argument, while the same argument is
// represented as UserPtr (usize) in Rust. Since there is no unsafe function to
// create a UserPtr from an actual pointer, this is probably not the worst, but
// still a bit shady.
extern ssize_t dabac_rs_mx_flch_read_user_attr(struct file *filp, char __user *buffer, size_t count, loff_t *off);
extern ssize_t dabac_rs_mx_flch_update_user_attr(struct file *filp, const char __user *buffer, size_t len, loff_t *off);
extern ssize_t dabac_rs_mx_flch_read_object_attr(struct file *filp, char __user *buffer, size_t count, loff_t *off);
extern ssize_t dabac_rs_mx_flch_update_object_attr(struct file *filp, const char __user *buffer, size_t len, loff_t *off);
extern ssize_t dabac_rs_mx_flch_read_env_attr(struct file *filp, char __user *buffer, size_t count, loff_t *off);
extern ssize_t dabac_rs_mx_flch_update_env_attr(struct file *filp, const char __user *buffer, size_t len, loff_t *off);
extern ssize_t dabac_rs_mx_flch_read_policy(struct file *filp, char __user *buffer, size_t count, loff_t *off);
extern ssize_t dabac_rs_mx_flch_update_policy(struct file *filp, const char __user *buffer, size_t len, loff_t *off);
extern ssize_t dabac_rs_mx_flch_read_perf(struct file *filp, char __user *buffer, size_t count, loff_t *off);
extern ssize_t dabac_rs_mx_flch_register_perf(struct file *filp, const char __user *buffer, size_t len, loff_t *off);

extern int dabac_rs_mx_nc_initialized;
extern int dabac_rs_sl_nc_initialized;
extern int dabac_rs_mx_tlc_initialized;
extern int dabac_rs_sl_tlc_initialized;
extern int dabac_rs_mx_tlch_initialized;
extern int dabac_rs_sl_tlch_initialized;
extern int dabac_rs_mx_flc_initialized;
extern int dabac_rs_sl_flc_initialized;
int dabac_rs_mx_flch_initialized;
extern int dabac_rs_sl_flch_initialized;

void dabac_rs_mx_flch_init_done(void);
void dabac_rs_mx_flch_init_done(void)
{
	dabac_rs_mx_flch_initialized = 1;
}

static int dabac_rs_mx_flch_open(struct inode *i, struct file *f)
{
	// No check here, POSIX permissions limit access to root
	return 0;
}

static const struct file_operations user_attr_fops = {
	.open = dabac_rs_mx_flch_open,
	.read = dabac_rs_mx_flch_read_user_attr,
	.write = dabac_rs_mx_flch_update_user_attr,
};

static const struct file_operations obj_attr_fops = {
	.open = dabac_rs_mx_flch_open,
	.read = dabac_rs_mx_flch_read_object_attr,
	.write = dabac_rs_mx_flch_update_object_attr,
};

static const struct file_operations env_attr_fops = {
	.open = dabac_rs_mx_flch_open,
	.read = dabac_rs_mx_flch_read_env_attr,
	.write = dabac_rs_mx_flch_update_env_attr,
};

static const struct file_operations policy_fops = {
	.open = dabac_rs_mx_flch_open,
	.read = dabac_rs_mx_flch_read_policy,
	.write = dabac_rs_mx_flch_update_policy,
};

static const struct file_operations perf_fops = {
	.open = dabac_rs_mx_flch_open,
	.read = dabac_rs_mx_flch_read_perf,
	.write = dabac_rs_mx_flch_register_perf,
};

static void dabac_rs_mx_flch_destroy_fs(void)
{
	if (!IS_ERR_OR_NULL(dabac_rs_mx_flch_user_attr_file))
		securityfs_remove(dabac_rs_mx_flch_user_attr_file);
	if (!IS_ERR_OR_NULL(dabac_rs_mx_flch_obj_attr_file))
		securityfs_remove(dabac_rs_mx_flch_obj_attr_file);
	if (!IS_ERR_OR_NULL(dabac_rs_mx_flch_env_attr_file))
		securityfs_remove(dabac_rs_mx_flch_env_attr_file);
	if (!IS_ERR_OR_NULL(dabac_rs_mx_flch_policy_file))
		securityfs_remove(dabac_rs_mx_flch_policy_file);
	if (!IS_ERR_OR_NULL(dabac_rs_mx_flch_perf_file))
		securityfs_remove(dabac_rs_mx_flch_perf_file);
	if (!IS_ERR_OR_NULL(dabac_rs_mx_flch_fs))
		securityfs_remove(dabac_rs_mx_flch_fs);
	if (!IS_ERR_OR_NULL(dabac_rs_mx_flch_generic_user_attr_file))
		securityfs_remove(dabac_rs_mx_flch_generic_user_attr_file);
	if (!IS_ERR_OR_NULL(dabac_rs_mx_flch_generic_obj_attr_file))
		securityfs_remove(dabac_rs_mx_flch_generic_obj_attr_file);
	if (!IS_ERR_OR_NULL(dabac_rs_mx_flch_generic_env_attr_file))
		securityfs_remove(dabac_rs_mx_flch_generic_env_attr_file);
	if (!IS_ERR_OR_NULL(dabac_rs_mx_flch_generic_policy_file))
		securityfs_remove(dabac_rs_mx_flch_generic_policy_file);
	if (!IS_ERR_OR_NULL(dabac_rs_mx_flch_generic_perf_file))
		securityfs_remove(dabac_rs_mx_flch_generic_perf_file);
	if (!IS_ERR_OR_NULL(dabac_rs_mx_flch_generic_fs))
		securityfs_remove(dabac_rs_mx_flch_generic_fs);
}

static struct dentry *dabac_rs_mx_flch_create_file(struct dentry *parent, const char *parentname, const char *filename, const struct file_operations *fops)
{
	struct dentry *f;

	// File is writable by everyone because the PAP checks each access with the PDP
	f = securityfs_create_file(filename, 0666, parent, NULL, fops);
	if (IS_ERR(f)) {
		pr_err("dabac_rs_mx_flch: Failed to create file /sys/kernel/security/%s/%s", parentname, filename);
		dabac_rs_mx_flch_destroy_fs();
		return f;
	}
	pr_info("dabac_rs_mx_flch: Created file /sys/kernel/security/%s/%s", parentname, filename);
	return f;
}

static int dabac_rs_mx_flch_create_fs(void)
{
	const char *parentname = "dabac_rs_mx_flch";

	if (!dabac_rs_mx_flch_initialized) {
		pr_info("dabac_rs_mx_flch: LSM was not initialized, not loading securityfs");
		return 0;
	}

	// create the root 'dabac_rs' directory
	dabac_rs_mx_flch_fs = securityfs_create_dir(parentname, NULL);
	if (IS_ERR(dabac_rs_mx_flch_fs)) {
		pr_err("dabac_rs_mx_flch: Failed to create dabac_rs securityfs at /sys/kernel/security/%s/", parentname);
		dabac_rs_mx_flch_destroy_fs();
		return PTR_ERR(dabac_rs_mx_flch_fs);
	}

	dabac_rs_mx_flch_user_attr_file = dabac_rs_mx_flch_create_file(dabac_rs_mx_flch_fs, parentname, "user_attr", &user_attr_fops);
	if (IS_ERR(dabac_rs_mx_flch_user_attr_file)) {
		dabac_rs_mx_flch_destroy_fs();
		return PTR_ERR(dabac_rs_mx_flch_user_attr_file);
	}
	dabac_rs_mx_flch_obj_attr_file = dabac_rs_mx_flch_create_file(dabac_rs_mx_flch_fs, parentname, "obj_attr", &obj_attr_fops);
	if (IS_ERR(dabac_rs_mx_flch_obj_attr_file)) {
		dabac_rs_mx_flch_destroy_fs();
		return PTR_ERR(dabac_rs_mx_flch_obj_attr_file);
	}
	dabac_rs_mx_flch_env_attr_file = dabac_rs_mx_flch_create_file(dabac_rs_mx_flch_fs, parentname, "env_attr", &env_attr_fops);
	if (IS_ERR(dabac_rs_mx_flch_env_attr_file)) {
		dabac_rs_mx_flch_destroy_fs();
		return PTR_ERR(dabac_rs_mx_flch_env_attr_file);
	}
	dabac_rs_mx_flch_policy_file = dabac_rs_mx_flch_create_file(dabac_rs_mx_flch_fs, parentname, "policy", &policy_fops);
	if (IS_ERR(dabac_rs_mx_flch_policy_file)) {
		dabac_rs_mx_flch_destroy_fs();
		return PTR_ERR(dabac_rs_mx_flch_policy_file);
	}
	dabac_rs_mx_flch_perf_file = dabac_rs_mx_flch_create_file(dabac_rs_mx_flch_fs, parentname, "perf", &perf_fops);
	if (IS_ERR(dabac_rs_mx_flch_perf_file)) {
		dabac_rs_mx_flch_destroy_fs();
		return PTR_ERR(dabac_rs_mx_flch_perf_file);
	}

	pr_info("dabac_rs_mx_flch: securityfs initialized");
	return 0;
}

static int dabac_rs_mx_flch_create_generic_fs(void)
{
	const char *parentname = "dabac_rs";

	if (!dabac_rs_mx_flch_initialized) {
		pr_info("dabac_rs_mx_flch: LSM was not initialized, not loading securityfs");
		return 0;
	}

	if (dabac_rs_mx_nc_initialized
	    || dabac_rs_sl_nc_initialized
	    || dabac_rs_mx_tlc_initialized
	    || dabac_rs_sl_tlc_initialized
	    || dabac_rs_mx_tlch_initialized
	    || dabac_rs_sl_tlch_initialized
	    || dabac_rs_mx_flc_initialized
	    || dabac_rs_sl_flc_initialized
	    || dabac_rs_sl_flch_initialized) {
		pr_info("dabac_rs_mx_flch: We are not the only dabac_rs LSM, not using generic paths");
		return 0;
	}

	pr_info("dabac_rs_mx_flch: We are the only dabac_rs LSM, using generic paths additionally");

	// create the root 'dabac_rs' directory
	dabac_rs_mx_flch_generic_fs = securityfs_create_dir(parentname, NULL);
	if (IS_ERR(dabac_rs_mx_flch_generic_fs)) {
		pr_err("dabac_rs_mx_flch: Failed to create dabac_rs securityfs at /sys/kernel/security/%s/", parentname);
		dabac_rs_mx_flch_destroy_fs();
		return PTR_ERR(dabac_rs_mx_flch_generic_fs);
	}

	dabac_rs_mx_flch_generic_user_attr_file = dabac_rs_mx_flch_create_file(dabac_rs_mx_flch_generic_fs, parentname, "user_attr", &user_attr_fops);
	if (IS_ERR(dabac_rs_mx_flch_generic_user_attr_file)) {
		dabac_rs_mx_flch_destroy_fs();
		return PTR_ERR(dabac_rs_mx_flch_generic_user_attr_file);
	}
	dabac_rs_mx_flch_generic_obj_attr_file = dabac_rs_mx_flch_create_file(dabac_rs_mx_flch_generic_fs, parentname, "obj_attr", &obj_attr_fops);
	if (IS_ERR(dabac_rs_mx_flch_generic_obj_attr_file)) {
		dabac_rs_mx_flch_destroy_fs();
		return PTR_ERR(dabac_rs_mx_flch_generic_obj_attr_file);
	}
	dabac_rs_mx_flch_generic_env_attr_file = dabac_rs_mx_flch_create_file(dabac_rs_mx_flch_generic_fs, parentname, "env_attr", &env_attr_fops);
	if (IS_ERR(dabac_rs_mx_flch_generic_env_attr_file)) {
		dabac_rs_mx_flch_destroy_fs();
		return PTR_ERR(dabac_rs_mx_flch_generic_env_attr_file);
	}
	dabac_rs_mx_flch_generic_policy_file = dabac_rs_mx_flch_create_file(dabac_rs_mx_flch_generic_fs, parentname, "policy", &policy_fops);
	if (IS_ERR(dabac_rs_mx_flch_generic_policy_file)) {
		dabac_rs_mx_flch_destroy_fs();
		return PTR_ERR(dabac_rs_mx_flch_generic_policy_file);
	}
	dabac_rs_mx_flch_generic_perf_file = dabac_rs_mx_flch_create_file(dabac_rs_mx_flch_generic_fs, parentname, "perf", &perf_fops);
	if (IS_ERR(dabac_rs_mx_flch_generic_perf_file)) {
		dabac_rs_mx_flch_destroy_fs();
		return PTR_ERR(dabac_rs_mx_flch_generic_perf_file);
	}

	pr_info("dabac_rs_mx_flch: generic securityfs initialized");
	return 0;
}

fs_initcall(dabac_rs_mx_flch_create_fs);
fs_initcall(dabac_rs_mx_flch_create_generic_fs);
