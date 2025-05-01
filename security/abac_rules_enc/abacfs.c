#include "abacfs.h"
#include <linux/init.h>
#include <linux/security.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

const size_t ABAC_RULES_ENC_MAX_FILE_SIZE = 8388608; // 8MB

struct dentry *abac_rules_enc_abacfs;
struct dentry *abac_rules_enc_user_attr_file;
struct dentry *abac_rules_enc_obj_rules_file;
struct dentry *abac_rules_enc_env_attr_file;
struct dentry *abac_rules_enc_policy_file;
struct dentry *abac_rules_enc_action_file;
struct dentry *abac_rules_enc_perf_file;

struct dentry *abac_rules_enc_generic_abacfs;
struct dentry *abac_rules_enc_generic_user_attr_file;
struct dentry *abac_rules_enc_generic_obj_rules_file;
struct dentry *abac_rules_enc_generic_env_attr_file;
struct dentry *abac_rules_enc_generic_policy_file;
struct dentry *abac_rules_enc_generic_action_file;
struct dentry *abac_rules_enc_generic_perf_file;

char *abac_rules_enc_user_attr_buf = NULL;
char *abac_rules_enc_obj_rules_buf = NULL;
char *abac_rules_enc_env_attr_buf = NULL;
char *abac_rules_enc_policy_buf = NULL;
char abac_rules_enc_perf_buf[64];
int abac_rules_enc_recording = 0;
u64 abac_rules_enc_prev_access_time = 0;

avp *abac_rules_enc_env_attr = NULL;

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
	if (len >= ABAC_RULES_ENC_MAX_FILE_SIZE) {
		printk(KERN_INFO
		       "Write failed. Buffer too large %zu. Maximum file size is %zu\n",
		       len, ABAC_RULES_ENC_MAX_FILE_SIZE);
		return -EFAULT;
	}
	if (abac_rules_enc_user_attr_buf) {
		abac_rules_enc_clear_user_attrs();
		kfree(abac_rules_enc_user_attr_buf);
	}
	abac_rules_enc_user_attr_buf = kmalloc(len + 1, GFP_KERNEL);
	if (!abac_rules_enc_user_attr_buf) {
		printk(KERN_INFO
		       "Write failed. Failed to allocate memory for user attributes buffer\n");
		return -EFAULT;
	}
	if (copy_from_user(abac_rules_enc_user_attr_buf, buffer, len + 1)) {
		printk(KERN_INFO "Write to user_attrs failed\n");
		return -EFAULT;
	}
	abac_rules_enc_user_attr_buf[len] = '\0';
	printk("User attributes written to buffer. Attempting to parse...");
	abac_rules_enc_parse_user_attr(abac_rules_enc_user_attr_buf);
	//abac_rules_enc_print_user_attrs();
	printk("User attributes loaded");
	return len;
}

// method for writing to obj_rules file
static ssize_t obj_rules_write(struct file *filp, const char __user *buffer, size_t len, loff_t *off)
{
	if (len >= ABAC_RULES_ENC_MAX_FILE_SIZE) {
		printk(KERN_INFO "Write failed. Buffer too large %zu. Maximum file size is %zu\n", len, ABAC_RULES_ENC_MAX_FILE_SIZE);
		return -EFAULT;
	}
	if (abac_rules_enc_obj_rules_buf) {
		abac_rules_enc_clear_obj_rule_map();
		kfree(abac_rules_enc_obj_rules_buf);
	}
	abac_rules_enc_obj_rules_buf = kmalloc(len + 1, GFP_KERNEL);
	if (!abac_rules_enc_obj_rules_buf) {
		printk(KERN_INFO "Write failed. Failed to allocate memory for object rules buffer\n");
		return -EFAULT;
	}
	if (copy_from_user(abac_rules_enc_obj_rules_buf, buffer, len + 1)) {
		printk(KERN_INFO "Write to obj_rules failed\n");
		return -EFAULT;
	}
	abac_rules_enc_obj_rules_buf[len] = '\0';
	printk("Object rules written to buffer. Attempting to parse...");
	abac_rules_enc_parse_obj_rule_map(abac_rules_enc_obj_rules_buf);
	//abac_rules_enc_print_obj_rule_map();
	printk("Object rules loaded");
	return len;
}

// method for writing to env_attrs file
static ssize_t env_attr_write(struct file *filp, const char __user *buffer,
			      size_t len, loff_t *off)
{
	if (len >= ABAC_RULES_ENC_MAX_FILE_SIZE) {
		printk(KERN_INFO
		       "Write failed. Buffer too large %zu. Maximum file size is %zu\n",
		       len, ABAC_RULES_ENC_MAX_FILE_SIZE);
		return -EFAULT;
	}
	if (abac_rules_enc_env_attr_buf) {
		abac_rules_enc_clear_avp_list(abac_rules_enc_env_attr);
		kfree(abac_rules_enc_env_attr_buf);
	}
	abac_rules_enc_env_attr_buf = kmalloc(len + 1, GFP_KERNEL);
	if (!abac_rules_enc_env_attr_buf) {
		printk(KERN_INFO
		       "Write failed. Failed to allocate memory for environment "
		       "attributes buffer\n");
		return -EFAULT;
	}
	if (copy_from_user(abac_rules_enc_env_attr_buf, buffer, len + 1)) {
		printk(KERN_INFO "Write to env_attrs failed\n");
		return -EFAULT;
	}
	abac_rules_enc_env_attr_buf[len] = '\0';
	printk("Environment attributes written to buffer. Attempting to parse...");
	abac_rules_enc_env_attr = abac_rules_enc_parse_env_attr(abac_rules_enc_env_attr_buf);
	//abac_rules_enc_print_env_attrs(abac_rules_enc_env_attr);
	printk("Environment attributes loaded");
	return len;
}

// method for writing to policy file
static ssize_t policy_write(struct file *filp, const char __user *buffer, size_t len, loff_t *off)
{
	if (len >= ABAC_RULES_ENC_MAX_FILE_SIZE) {
		printk(KERN_INFO "Write failed. Buffer too large %zu. Maximum file size is %zu\n", len, ABAC_RULES_ENC_MAX_FILE_SIZE);
		return -EFAULT;
	}
	if (abac_rules_enc_policy_buf) {
		abac_rules_enc_clear_policy();
		kfree(abac_rules_enc_policy_buf);
	}
	abac_rules_enc_policy_buf = kmalloc(len + 1, GFP_KERNEL);
	if (!abac_rules_enc_policy_buf) {
		printk(KERN_INFO "Write failed. Failed to allocate memory for policy buffer\n");
		return -EFAULT;
	}
	if (copy_from_user(abac_rules_enc_policy_buf, buffer, len + 1)) {
		printk(KERN_INFO "Write to policy failed\n");
		return -EFAULT;
	}
	abac_rules_enc_policy_buf[len] = '\0';
	printk("Policy written to buffer. Attempting to parse...");
	abac_rules_enc_parse_policy(abac_rules_enc_policy_buf);
	//abac_rules_enc_print_policy();
	printk("Policy loaded");
	return len;
}

// method for writing to action file
static ssize_t action_write(struct file *filp, const char __user *buffer,
			      size_t len, loff_t *off)
{
	char *action_buf;
	if (len >= ABAC_RULES_ENC_MAX_FILE_SIZE) {
		printk(KERN_INFO
		       "Write failed. Buffer too large %zu. Maximum file size is %zu\n",
		       len, ABAC_RULES_ENC_MAX_FILE_SIZE);
		return -EFAULT;
	}
	action_buf = kmalloc(len + 1, GFP_KERNEL);
	if (!action_buf) {
		printk(KERN_INFO
		       "Write failed. Failed to allocate memory for action buffer\n");
		return -EFAULT;
	}
	if (copy_from_user(action_buf, buffer, len + 1)) {
		printk(KERN_INFO "Write to action failed\n");
		return -EFAULT;
	}
	action_buf[len] = '\0';
	if (strcmp(action_buf, "RECORD") == 0) {
		//printk("Recording started...");
		abac_rules_enc_prev_access_time = 0;
		abac_rules_enc_recording = 1;
	} else if (strcmp(action_buf, "STOP") == 0) {
		//printk("Recording stopped...");
		abac_rules_enc_recording = 0;
		//snprintf(abac_rules_enc_perf_buf, 64, "%llu\n", abac_rules_enc_prev_access_time);
		//printk("Time taken written to /sys/kernel/security/abac/perf");
		abac_rules_enc_prev_access_time = 0;
	} else {
		printk("Invalid action...");
	}
	kfree(action_buf);
	return len;
}

static ssize_t perf_read(struct file *file, char __user *buf, size_t count, loff_t *off)
{
    loff_t pos = *off;
    loff_t len = strlen(abac_rules_enc_perf_buf);

    if (pos >= len || !count)
        return 0;

    len -= pos;
    if (count < len)
        len = count;

    if (copy_to_user(buf, abac_rules_enc_perf_buf, len))
        return -EFAULT;
    *off += len;
    return len;
}

static const struct file_operations user_attr_fops = {
	.open = abac_open,
	.write = user_attr_write,
};

static const struct file_operations obj_rules_fops = {
	.open = abac_open,
	.write = obj_rules_write,
};

static const struct file_operations env_attr_fops = {
	.open = abac_open,
	.write = env_attr_write,
};

static const struct file_operations policy_fops = {
	.open = abac_open,
	.write = policy_write,
};

static const struct file_operations action_fops = {
	.open = abac_open,
	.write = action_write,
};

static const struct file_operations perf_fops = {
	.open = abac_open,
	.read = perf_read,
};


static void destroy_abac_fs(void)
{
	if (!IS_ERR_OR_NULL(abac_rules_enc_user_attr_file)) {
		securityfs_remove(abac_rules_enc_user_attr_file);
	}
	if (!IS_ERR_OR_NULL(abac_rules_enc_obj_rules_file)) {
		securityfs_remove(abac_rules_enc_obj_rules_file);
	}
	if (!IS_ERR_OR_NULL(abac_rules_enc_env_attr_file)) {
		securityfs_remove(abac_rules_enc_env_attr_file);
	}
	if (!IS_ERR_OR_NULL(abac_rules_enc_policy_file)) {
		securityfs_remove(abac_rules_enc_policy_file);
	}
	if (!IS_ERR_OR_NULL(abac_rules_enc_action_file)) {
		securityfs_remove(abac_rules_enc_action_file);
	}
	if (!IS_ERR_OR_NULL(abac_rules_enc_perf_file)) {
		securityfs_remove(abac_rules_enc_perf_file);
	}
	if (!IS_ERR_OR_NULL(abac_rules_enc_abacfs)) {
		securityfs_remove(abac_rules_enc_abacfs);
	}
	if (!IS_ERR_OR_NULL(abac_rules_enc_generic_user_attr_file)) {
		securityfs_remove(abac_rules_enc_generic_user_attr_file);
	}
	if (!IS_ERR_OR_NULL(abac_rules_enc_generic_obj_rules_file)) {
		securityfs_remove(abac_rules_enc_generic_obj_rules_file);
	}
	if (!IS_ERR_OR_NULL(abac_rules_enc_generic_env_attr_file)) {
		securityfs_remove(abac_rules_enc_generic_env_attr_file);
	}
	if (!IS_ERR_OR_NULL(abac_rules_enc_generic_policy_file)) {
		securityfs_remove(abac_rules_enc_generic_policy_file);
	}
	if (!IS_ERR_OR_NULL(abac_rules_enc_generic_action_file)) {
		securityfs_remove(abac_rules_enc_generic_action_file);
	}
	if (!IS_ERR_OR_NULL(abac_rules_enc_generic_perf_file)) {
		securityfs_remove(abac_rules_enc_generic_perf_file);
	}
	if (!IS_ERR_OR_NULL(abac_rules_enc_generic_abacfs)) {
		securityfs_remove(abac_rules_enc_generic_abacfs);
	}
}

static struct dentry *create_file(struct dentry *parent, const char *parentname, const char *filename, const struct file_operations *fops) {
	struct dentry *f;
	f = securityfs_create_file(filename, 0666, parent, NULL, fops);
	if (IS_ERR(f)) {
		printk(KERN_ERR "ABAC LSM (Rules ENC): Failed to create file /sys/kernel/security/%s/%s", parentname, filename);
		destroy_abac_fs();
		return f;
	}
	printk(KERN_INFO "ABAC LSM (Rules ENC): Created file /sys/kernel/security/%s/%s", parentname, filename);
	return f;
}

/* create the abac filesystem */
static int abac_create_fs(void)
{
	const char *parentname = "abac_rules_enc";

	if (!abac_rules_enc_initialized) {
		pr_info("ABAC LSM (Rules ENC): LSM was not initialized, not loading securityfs");
		return 0;
	}

	// create the root 'abac' directory
	abac_rules_enc_abacfs = securityfs_create_dir(parentname, NULL);
	if (IS_ERR(abac_rules_enc_abacfs)) {
		printk(KERN_ERR "ABAC LSM (Rules ENC): Failed to create abac securityfs at /sys/kernel/security/%s/", parentname);
		destroy_abac_fs();
		return PTR_ERR(abac_rules_enc_abacfs);
	}

	abac_rules_enc_user_attr_file = create_file(abac_rules_enc_abacfs, parentname, "user_attr", &user_attr_fops);
	if (IS_ERR(abac_rules_enc_user_attr_file)) {
		destroy_abac_fs();
		return PTR_ERR(abac_rules_enc_user_attr_file);
	}
	abac_rules_enc_obj_rules_file = create_file(abac_rules_enc_abacfs, parentname, "obj_rules", &obj_rules_fops);
	if (IS_ERR(abac_rules_enc_obj_rules_file)) {
		destroy_abac_fs();
		return PTR_ERR(abac_rules_enc_obj_rules_file);
	}
	abac_rules_enc_env_attr_file = create_file(abac_rules_enc_abacfs, parentname, "env_attr", &env_attr_fops);
	if (IS_ERR(abac_rules_enc_env_attr_file)) {
		destroy_abac_fs();
		return PTR_ERR(abac_rules_enc_env_attr_file);
	}
	abac_rules_enc_policy_file = create_file(abac_rules_enc_abacfs, parentname, "policy", &policy_fops);
	if (IS_ERR(abac_rules_enc_policy_file)) {
		destroy_abac_fs();
		return PTR_ERR(abac_rules_enc_policy_file);
	}

	// Performance evaluation files
	abac_rules_enc_action_file = create_file(abac_rules_enc_abacfs, parentname, "action", &action_fops);
	if (IS_ERR(abac_rules_enc_action_file)) {
		destroy_abac_fs();
		return PTR_ERR(abac_rules_enc_action_file);
	}
	abac_rules_enc_perf_file = create_file(abac_rules_enc_abacfs, parentname, "perf", &perf_fops);
	if (IS_ERR(abac_rules_enc_perf_file)) {
		destroy_abac_fs();
		return PTR_ERR(abac_rules_enc_perf_file);
	}

	printk(KERN_INFO "ABAC LSM (Rules ENC): Securityfs Initialized");
	return 0;
}

/* create the generic abac filesystem */
static int abac_create_generic_fs(void)
{
	const char *parentname = "abac";

	if (!abac_rules_enc_initialized) {
		pr_info("ABAC LSM (Rules ENC): LSM was not initialized, not loading generic securityfs");
		return 0;
	}

	if (abac_rules_initialized || abac_trees_initialized || abac_trees_enc_initialized) {
		pr_info("ABAC LSM (Rules ENC): We are not the only ABAC LSM, not using generic paths");
		return 0;
	}

	pr_info("ABAC LSM (Rules ENC): We are the only ABAC LSM, using generic paths additionally");

	// create the root 'abac' directory
	abac_rules_enc_generic_abacfs = securityfs_create_dir(parentname, NULL);
	if (IS_ERR(abac_rules_enc_generic_abacfs)) {
		printk(KERN_ERR "ABAC LSM (Rules ENC): Failed to create abac securityfs at /sys/kernel/security/%s/", parentname);
		destroy_abac_fs();
		return PTR_ERR(abac_rules_enc_generic_abacfs);
	}

	abac_rules_enc_generic_user_attr_file = create_file(abac_rules_enc_generic_abacfs, parentname, "user_attr", &user_attr_fops);
	if (IS_ERR(abac_rules_enc_generic_user_attr_file)) {
		destroy_abac_fs();
		return PTR_ERR(abac_rules_enc_generic_user_attr_file);
	}
	abac_rules_enc_generic_obj_rules_file = create_file(abac_rules_enc_generic_abacfs, parentname, "obj_rules", &obj_rules_fops);
	if (IS_ERR(abac_rules_enc_generic_obj_rules_file)) {
		destroy_abac_fs();
		return PTR_ERR(abac_rules_enc_generic_obj_rules_file);
	}
	abac_rules_enc_generic_env_attr_file = create_file(abac_rules_enc_generic_abacfs, parentname, "env_attr", &env_attr_fops);
	if (IS_ERR(abac_rules_enc_generic_env_attr_file)) {
		destroy_abac_fs();
		return PTR_ERR(abac_rules_enc_generic_env_attr_file);
	}
	abac_rules_enc_generic_policy_file = create_file(abac_rules_enc_generic_abacfs, parentname, "policy", &policy_fops);
	if (IS_ERR(abac_rules_enc_generic_policy_file)) {
		destroy_abac_fs();
		return PTR_ERR(abac_rules_enc_generic_policy_file);
	}

	// Performance evaluation files
	abac_rules_enc_generic_action_file = create_file(abac_rules_enc_generic_abacfs, parentname, "action", &action_fops);
	if (IS_ERR(abac_rules_enc_generic_action_file)) {
		destroy_abac_fs();
		return PTR_ERR(abac_rules_enc_generic_action_file);
	}
	abac_rules_enc_generic_perf_file = create_file(abac_rules_enc_generic_abacfs, parentname, "perf", &perf_fops);
	if (IS_ERR(abac_rules_enc_generic_perf_file)) {
		destroy_abac_fs();
		return PTR_ERR(abac_rules_enc_generic_perf_file);
	}

	printk(KERN_INFO "ABAC LSM (Rules ENC): Generic Securityfs Initialized");
	return 0;
}

fs_initcall(abac_create_fs);
fs_initcall(abac_create_generic_fs);
