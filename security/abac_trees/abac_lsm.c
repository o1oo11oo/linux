#include "abacfs.h"
#include "cache.h"
#include <linux/limits.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/lsm_hooks.h>
#include <linux/lsm_performance.h>
#include <linux/timekeeping.h>
#include <linux/dcache.h>
#include <linux/cred.h>

static const char* secured_dir = "/home/secured/";
static const int secured_dir_len = 14;

// Track if the LSM was loaded and finished initializing
int abac_trees_initialized;

// Track cycle counts
struct perf_results abac_trees_perf_store;

// Check if path is secured
static int is_secured(char *accessed_path)
{
	if (strncmp(secured_dir, accessed_path, secured_dir_len) == 0) {
		return 1;
	}
	return 0;
}

// get full filename
// char *get_full_name(struct file *file, char *buf, int buflen)
// {
// 	struct dentry *dentry = file->f_path.dentry;
// 	char *ret = dentry_path_raw(dentry, buf, buflen);
// 	return ret;
// }

static struct abac_trees_node *get_child(avp *user_attrs, struct abac_trees_node *n, uint64_t *cycle_counts) {
	/*
	 * Find the child node corresponding to the value of user or environmental attribute
	 */
	struct avp *u, *e;
	branch *b; 
	u = user_attrs;
	e = abac_trees_env_attr;
	while (u != NULL) {
		if (strcmp(u->name, n->attr) == 0) {
			/* If the node's attribute is found in user attributes,
			 * look for corresponding branch in the node */
			b = n->head;
			while (b != NULL) {
				if (strcmp(u->value, b->value) == 0) {
					save_tsc(cycle_counts, ABAC_TREES_AFTER_CHECK_USER_ATTR);
					//printk("Found child: %s for attr: %s", b->value, n->attr);
					return b->child;
				}
				b = b->next;
			}
		}
		u = u->next;
	}
	/* Check environmental attributes (similar to checking user attributes) */
	while (e != NULL) {
		if (strcmp(e->name, n->attr) == 0) {
			b = n->head;
			while (b != NULL) {
				if (strcmp(e->value, b->value) == 0) {
					save_tsc(cycle_counts, ABAC_TREES_AFTER_CHECK_ENV_ATTR);
					//printk("Found child: %s for attr: %s", e->value, n->attr);
					return b->child;
				}
				b = b->next;
			}
		}
		e = e->next;
	}

	save_tsc(cycle_counts, ABAC_TREES_AFTER_CHECK_ENV_ATTR);

	// branch not found
	return NULL;
}

static int resolve_r(avp *user_attr, struct abac_trees_node *n, enum operation op, uint64_t *cycle_counts) {
	struct abac_trees_node *child;

	save_tsc(cycle_counts, LOOP_START);

	/* Recursive helper method for resolve() */
	if (strlen(n->attr) == 0) {
		/* n is a leaf, so check only operation */
		if(n->op == op) {
			//printk("matched op");
			save_tsc(cycle_counts, ABAC_TREES_AFTER_CHECK_OP);

			return 0;
		} else if (n->op == ABAC_MODIFY && op == ABAC_READ) {
			/* If the rule says MODIFY, then the user also has READ rights */
			save_tsc(cycle_counts, ABAC_TREES_AFTER_CHECK_OP);

			//printk("subsumed op");
			return 0;
		}

		save_tsc(cycle_counts, ABAC_TREES_AFTER_CHECK_OP);

		//printk("wrong op");
		return 1;
	}

	save_tsc(cycle_counts, ABAC_TREES_BEFORE_GET_CHILD);

	child = get_child(user_attr, n, cycle_counts);

	save_tsc(cycle_counts, ABAC_TREES_AFTER_GET_CHILD);

	if (!child) {
		/* Corresponding child not found in n */
		save_tsc(cycle_counts, ABAC_TREES_AFTER_CHECK_OP);

		//printk("Child not found");
		return 1;
	}

	save_tsc(cycle_counts, ABAC_TREES_AFTER_CHECK_CHILD);

	//printk("Child found");
	return resolve_r(user_attr, child, op, cycle_counts);
}

static int resolve(avp *user_attr, struct abac_trees_node *obj_root, enum operation op, uint64_t *cycle_counts){
	/* Resolve access request using 
	 * 1. User attributes (*user_attr)
	 * 2. Root of the object attribute tree (struct abac_trees_node *obj_root)
	 * 3. Current environmental attributes (avp *abac_trees_env_attr -> from abacfs)
	 * 4. Access operation (READ or MODIFY)
	 *
	 * Returns 0 if decision is allowed, 1 otherwise
	 */

	save_tsc(cycle_counts, IN_RESOLVE);

	if (user_attr == NULL) {
		/* If the user doesn't have any attributes, access is DENIED */
		return 1;
	}
	if (obj_root == NULL) {
		/* If the object doesn't have any attribute, access is DENIED */
		return 1;
	}
	if (op == ABAC_IGNORE) {
		/* If not a relevant operation, allow it */
		return 0;
	}

	save_tsc(cycle_counts, AFTER_NULL_CHECKS);

	return resolve_r(user_attr, obj_root, op, cycle_counts);
}

static enum operation get_op(int mask) {
	/* Conver access bit mask into valid abac operation */
	//printk("Mask: %d", mask);
	switch (mask) {
		case MAY_WRITE:
		case MAY_APPEND:
			return ABAC_MODIFY;
		case MAY_READ:
		//case MAY_OPEN:
		//case MAY_ACCESS:
			return ABAC_READ;
	}
	return ABAC_IGNORE;
}

// File read/write hook
static int abac_file_permission(struct file *file, int mask)
{
	//u64 start, end, diff;
	unsigned int uid;
	char *path, *buff;
	struct dentry *dentry;
	struct abac_trees_node *root;
	avp *user_attr;
	int decision;
	enum operation op;

	// Cannot use a global as multiple requests might happen in parallel
	uint64_t cycle_counts[CYCLE_COUNTS_LEN];

	/*if (abac_trees_recording) {
		//start = ktime_get_real_ns();
		start = ktime_get_ns();
	}*/
	uid = current_uid().val;
	if (uid < 1000) {
		return 0;
	}
	path = NULL;
	dentry = file->f_path.dentry;
	buff = kmalloc(PATH_MAX, GFP_KERNEL);
	path = dentry_path_raw(dentry, buff, PATH_MAX);
	if (!is_secured(path)){
		kfree(buff);
		return 0;
	}

	// Start performance measurements after making sure the request actually
	// concerns us
	save_tsc_start(cycle_counts);

	op = get_op(mask);

	//printk("ABAC LSM (Trees): %d accessing %s\n", uid, path);
	// operation
	/*
	if (op == ABAC_READ) {
		printk("ABAC READ");
	} else if (op == ABAC_MODIFY) {
		printk("ABAC MODIFY");
	} else {
		printk("ABAC IGNORE");
	}
	*/

	save_tsc(cycle_counts, AFTER_GET_OP);

	// Check cache
	/*
	cached_decision = search_cache(uid, path);
	if (cached_decision != -1) {
		return cached_decision == 0 ? 0 : -EPERM;
	}
	*/

	// Print user attributes
	user_attr = abac_trees_get_user_attrs(uid);
	//printk("User attributes");
	//abac_trees_print_avp(user_attr);
	//printk("-----------------------------------");

	// Print env attributes
	//printk("Environmental attributes");
	//abac_trees_print_avp(abac_trees_env_attr);
	//printk("-----------------------------------");

	save_tsc(cycle_counts, AFTER_GET_USER_ATTR);

	// Print object tree
	//printk("Object attribute tree");
	root = abac_trees_get_obj_tree(path);
	//abac_trees_print_attr_tree(root);
	//printk("-----------------------------------");

	save_tsc(cycle_counts, AFTER_GET_OBJ);

	decision = resolve(user_attr, root, op, cycle_counts);

	// Stop the performance measurement and store the results
	save_tsc_stop(cycle_counts, uid, &abac_trees_perf_store);

	/* insert decision into cache */
	//insert_cache(uid, path, decision);

	//printk("decision: %s\n", decision == 0 ? "ALLOWED" : "DENIED");
	/*if (abac_trees_recording) {
		//end = ktime_get_real_ns();
		end = ktime_get_ns();
		diff = end - start;
		abac_trees_prev_access_time = diff;
		snprintf(abac_trees_perf_buf, 64, "%llu\n", abac_trees_prev_access_time);
	}*/

	kfree(buff);
	return decision == 0 ? 0 : -EPERM;
}

extern char *abac_trees_user_attr_buf;
extern char *abac_trees_obj_attr_buf;
extern char *abac_trees_env_attr_buf;
static int load_initial_policy(void)
{
	const char *initial_user_attr = "1000:ua_0=ua_0_v_0\n1001:ua_0=ua_0_v_1";
	const char *initial_obj_attr = "/home/secured/a:3|0 - - ea_0|1 0 ea_0_v_0 ua_0|2 1 ua_0_v_0 MODIFY\n/home/secured/b:4|0 - - ea_0|1 0 ea_0_v_0 ua_0|2 1 ua_0_v_0 READ|2 1 ua_0_v_1 READ";
	const char *initial_env_attr = "ea_0=ea_0_v_0\nea_1=ea_1_v_0";

	abac_trees_user_attr_buf = kmalloc(strlen(initial_user_attr), GFP_KERNEL);
	if (!abac_trees_user_attr_buf)
		return -ENOMEM;

	abac_trees_obj_attr_buf = kmalloc(strlen(initial_obj_attr), GFP_KERNEL);
	if (!abac_trees_obj_attr_buf)
		return -ENOMEM;

	abac_trees_env_attr_buf = kmalloc(strlen(initial_env_attr), GFP_KERNEL);
	if (!abac_trees_env_attr_buf)
		return -ENOMEM;

	strscpy(abac_trees_user_attr_buf, initial_user_attr, strlen(initial_user_attr));
	abac_trees_parse_user_attr(abac_trees_user_attr_buf);
	strscpy(abac_trees_obj_attr_buf, initial_obj_attr, strlen(initial_obj_attr));
	abac_trees_parse_obj_attr(abac_trees_obj_attr_buf);
	strscpy(abac_trees_env_attr_buf, initial_env_attr, strlen(initial_env_attr));
	abac_trees_env_attr = abac_trees_parse_env_attr(abac_trees_env_attr_buf);

	return 0;
}

// The hooks we wish to be installed.
static struct security_hook_list abac_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(file_permission, abac_file_permission),
};

static const struct lsm_id abac_lsmid = {
	.name = "abac_trees",
	.id = LSM_ID_ABAC_TREES,
};

// Initialize our module.
static int __init abac_init(void)
{
	security_add_hooks(abac_hooks, ARRAY_SIZE(abac_hooks), &abac_lsmid);
	int err = load_initial_policy();

	if (err)
		return err;

	printk(KERN_INFO "ABAC LSM (Trees): Initialized.\n Files in %s are protected by ABAC policy\n", secured_dir);
	abac_trees_initialized = 1;
	return 0;
}

DEFINE_LSM(abac_trees) = {
	.init = abac_init,
	.name = "abac_trees",
};
