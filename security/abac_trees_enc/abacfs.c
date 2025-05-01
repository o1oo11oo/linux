#include "abacfs.h"
#include <linux/init.h>
#include <linux/security.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

const size_t ABAC_TREES_ENC_MAX_FILE_SIZE = 8388608; // 8MB

struct dentry *abac_trees_enc_abacfs;
struct dentry *abac_trees_enc_user_attr_file;
struct dentry *abac_trees_enc_obj_attr_file;
struct dentry *abac_trees_enc_env_attr_file;
struct dentry *abac_trees_enc_action_file;
struct dentry *abac_trees_enc_perf_file;

char *abac_trees_enc_user_attr_buf = NULL;
char *abac_trees_enc_obj_attr_buf = NULL;
char *abac_trees_enc_env_attr_buf = NULL;
char abac_trees_enc_perf_buf[64];
int abac_trees_enc_recording = 0;
u64 abac_trees_enc_prev_access_time = 0;

avp *abac_trees_enc_env_attr = NULL;

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
	if (len >= ABAC_TREES_ENC_MAX_FILE_SIZE) {
		printk(KERN_INFO
		       "Write failed. Buffer too large %zu. Maximum file size is %zu\n",
		       len, ABAC_TREES_ENC_MAX_FILE_SIZE);
		return -EFAULT;
	}
	if (abac_trees_enc_user_attr_buf) {
		abac_trees_enc_clear_user_attrs();
		kfree(abac_trees_enc_user_attr_buf);
	}
	abac_trees_enc_user_attr_buf = kmalloc(len + 1, GFP_KERNEL);
	if (!abac_trees_enc_user_attr_buf) {
		printk(KERN_INFO
		       "Write failed. Failed to allocate memory for user attributes buffer\n");
		return -EFAULT;
	}
	if (copy_from_user(abac_trees_enc_user_attr_buf, buffer, len + 1)) {
		printk(KERN_INFO "Write to user_attrs failed\n");
		return -EFAULT;
	}
	abac_trees_enc_user_attr_buf[len] = '\0';
	printk("User attributes written to buffer. Attempting to parse...");
	abac_trees_enc_parse_user_attr(abac_trees_enc_user_attr_buf);
	//abac_trees_enc_print_user_attrs();
	printk("User attributes loaded");
	return len;
}

// method for writing to obj_attrs file
static ssize_t obj_attr_write(struct file *filp, const char __user *buffer, size_t len, loff_t *off)
{
	if (len >= ABAC_TREES_ENC_MAX_FILE_SIZE) {
		printk(KERN_INFO "Write failed. Buffer too large %zu. Maximum file size is %zu\n", len, ABAC_TREES_ENC_MAX_FILE_SIZE);
		return -EFAULT;
	}
	if (abac_trees_enc_obj_attr_buf) {
		abac_trees_enc_clear_obj_attrs();
		kfree(abac_trees_enc_obj_attr_buf);
	}
	abac_trees_enc_obj_attr_buf = kmalloc(len + 1, GFP_KERNEL);
	if (!abac_trees_enc_obj_attr_buf) {
		printk(KERN_INFO "Write failed. Failed to allocate memory for object attributes buffer\n");
		return -EFAULT;
	}
	if (copy_from_user(abac_trees_enc_obj_attr_buf, buffer, len + 1)) {
		printk(KERN_INFO "Write to obj_attrs failed\n");
		return -EFAULT;
	}
	abac_trees_enc_obj_attr_buf[len] = '\0';
	printk("Object attributes written to buffer. Attempting to parse...");
	abac_trees_enc_parse_obj_attr(abac_trees_enc_obj_attr_buf);
	//abac_trees_enc_print_obj_attrs();
	printk("Object attributes loaded");
	return len;
}

// method for writing to env_attrs file
static ssize_t env_attr_write(struct file *filp, const char __user *buffer,
			      size_t len, loff_t *off)
{
	if (len >= ABAC_TREES_ENC_MAX_FILE_SIZE) {
		printk(KERN_INFO
		       "Write failed. Buffer too large %zu. Maximum file size is %zu\n",
		       len, ABAC_TREES_ENC_MAX_FILE_SIZE);
		return -EFAULT;
	}
	if (abac_trees_enc_env_attr_buf) {
		abac_trees_enc_clear_avp_list(abac_trees_enc_env_attr);
		kfree(abac_trees_enc_env_attr_buf);
	}
	abac_trees_enc_env_attr_buf = kmalloc(len + 1, GFP_KERNEL);
	if (!abac_trees_enc_env_attr_buf) {
		printk(KERN_INFO
		       "Write failed. Failed to allocate memory for environment "
		       "attributes buffer\n");
		return -EFAULT;
	}
	if (copy_from_user(abac_trees_enc_env_attr_buf, buffer, len + 1)) {
		printk(KERN_INFO "Write to env_attrs failed\n");
		return -EFAULT;
	}
	abac_trees_enc_env_attr_buf[len] = '\0';
	printk("Environment attributes written to buffer. Attempting to parse...");
	abac_trees_enc_env_attr = abac_trees_enc_parse_env_attr(abac_trees_enc_env_attr_buf);
	//abac_trees_enc_print_env_attrs(abac_trees_enc_env_attr);
	printk("Environment attributes loaded");
	return len;
}

// method for writing to action file
static ssize_t action_write(struct file *filp, const char __user *buffer,
			      size_t len, loff_t *off)
{
	char *action_buf;
	if (len >= ABAC_TREES_ENC_MAX_FILE_SIZE) {
		printk(KERN_INFO
		       "Write failed. Buffer too large %zu. Maximum file size is %zu\n",
		       len, ABAC_TREES_ENC_MAX_FILE_SIZE);
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
		printk("Recording started...");
		abac_trees_enc_prev_access_time = 0;
		abac_trees_enc_recording = 1;
	} else if (strcmp(action_buf, "STOP") == 0) {
		printk("Recording stopped...");
		abac_trees_enc_recording = 0;
		//snprintf(abac_trees_enc_perf_buf, 64, "%llu\n", abac_trees_enc_prev_access_time);
		//printk("Time taken written to /sys/kernel/security/abac/perf");
		abac_trees_enc_prev_access_time = 0;
	} else {
		printk("Invalid action...");
	}
	kfree(action_buf);
	return len;
}

static ssize_t perf_read(struct file *file, char __user *buf, size_t count, loff_t *off)
{
    loff_t pos = *off;
    loff_t len = strlen(abac_trees_enc_perf_buf);

    if (pos >= len || !count)
        return 0;

    len -= pos;
    if (count < len)
        len = count;

    if (copy_to_user(buf, abac_trees_enc_perf_buf, len))
        return -EFAULT;
    *off += len;
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
	if (abac_trees_enc_user_attr_file) {
		securityfs_remove(abac_trees_enc_user_attr_file);
	}
	if (abac_trees_enc_obj_attr_file) {
		securityfs_remove(abac_trees_enc_obj_attr_file);
	}
	if (abac_trees_enc_env_attr_file) {
		securityfs_remove(abac_trees_enc_env_attr_file);
	}
	if (abac_trees_enc_action_file) {
		securityfs_remove(abac_trees_enc_action_file);
	}
	if (abac_trees_enc_perf_file) {
		securityfs_remove(abac_trees_enc_perf_file);
	}
	if (abac_trees_enc_abacfs) {
		securityfs_remove(abac_trees_enc_abacfs);
	}
}

static struct dentry *create_file(const char *filename, const struct file_operations *fops) {
	struct dentry *f;
	//f = securityfs_create_file(filename, 0666, abac_trees_enc_abacfs, NULL, fops);
	f = securityfs_create_file(filename, 0777, abac_trees_enc_abacfs, NULL, fops);
	if (!f) {
		printk(KERN_ERR "ABAC LSM: Failed to create file /sys/kernel/security/abac/%s", filename);
		destroy_abac_fs();
		return NULL;
	}
	printk(KERN_INFO "ABAC LSM: Created file /sys/kernel/security/abac/%s", filename);
	return f;
}

/* create the abac filesystem */
static int abac_create_fs(void)
{
	// create the root 'abac' directory
	abac_trees_enc_abacfs = securityfs_create_dir("abac", NULL);
	if (!abac_trees_enc_abacfs) {
		printk(KERN_ERR "ABAC LSM: Failed to create abac securityfs at /sys/kernel/security/abac/");
		destroy_abac_fs();
		return -1;
	}

	abac_trees_enc_user_attr_file = create_file("user_attr", &user_attr_fops);
	if (!abac_trees_enc_user_attr_file) {
		destroy_abac_fs();
		return -1;
	}
	abac_trees_enc_obj_attr_file = create_file("obj_attr", &obj_attr_fops);
	if (!abac_trees_enc_obj_attr_file) {
		destroy_abac_fs();
		return -1;
	}
	abac_trees_enc_env_attr_file = create_file("env_attr", &env_attr_fops);
	if (!abac_trees_enc_env_attr_file) {
		destroy_abac_fs();
		return -1;
	}

	// Performance evaluation files
	abac_trees_enc_action_file = create_file("action", &action_fops);
	if (!abac_trees_enc_action_file) {
		destroy_abac_fs();
		return -1;
	}
	abac_trees_enc_perf_file = create_file("perf", &perf_fops);
	if (!abac_trees_enc_perf_file) {
		destroy_abac_fs();
		return -1;
	}
	printk(KERN_INFO "ABAC LSM: Securityfs Initialized");
	return 0;
}

fs_initcall(abac_create_fs);
