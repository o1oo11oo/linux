#include <linux/string.h>
#include <linux/slab.h>
#include "policy.h"

/* Array of rules and its size */
struct abac_rule **abac_rules_enc_policy = NULL;
unsigned int abac_rules_enc_count = 0;

static struct abac_rule *parse_line(char *line) {
	/* Parse a single line in the file */
	struct abac_rule *r;
	char *id_str;
	char *section;
	int rc;

	r = kcalloc(1, sizeof(struct abac_rule), GFP_KERNEL);
	r->op = ABAC_IGNORE;
	id_str = strsep(&line, ":");
	rc = kstrtoint(id_str, 10, &(r->id));
	// User attributes
	section = strsep(&line, "|");
	r->user = abac_rules_enc_parse_avp(section);
	// Environmental attributes
	section = strsep(&line, "|");
	r->env = abac_rules_enc_parse_avp(section);
	// Operation
	if (strcmp(line, "MODIFY") == 0) {
		r->op = ABAC_MODIFY;
	} else if (strcmp(line, "READ") == 0){
		r->op = ABAC_MODIFY;
	}
	return r;
}

void abac_rules_enc_parse_policy(char *data) {
	/*
	 * Parses ABAC policy written to 'policy' file in securityfs
	 * Rules are parsed and stored in an array
	 * File Format:
	 * <rule_count>
	 * <rule_id>:u_attr1=u_val1,u_attr2=u_val2|e_attr=e_val|op=MODIFY
	 * <rule_id>:u_attr2=u_val2|e_attr=e_val|op=READ
	 * ...
	 */
	struct abac_rule *r;
	char *line, *count_str;
	int abac_rules_enc_count;
	int rc;

	count_str = strsep(&data, "\n");
	rc = kstrtouint(count_str, 10, &abac_rules_enc_count);
	//policy = kmalloc(sizeof(struct abac_rule *), GFP_KERNEL);
	abac_rules_enc_policy = kmalloc(sizeof(struct abac_rule *) * abac_rules_enc_count, GFP_KERNEL);
	printk("Policy has %d rules", abac_rules_enc_count);

	while((line = strsep(&data, "\n")) != NULL) {
		/* Ignore empty lines */
		if (strlen(line) < 2) {
			break;
		}
		r = parse_line(line);
		abac_rules_enc_policy[r->id] = r;
		printk("Added rule %u to array", r->id);
	}
}

abac_rule *abac_rules_enc_get_rule(unsigned int id) {
	/* Get rule to a ID */
	return abac_rules_enc_policy[id];
}

void abac_rules_enc_clear_policy(void) {
	// Clear the rules in policy array
	int i;
	printk("clearing policy array...");
	for (i = 0; i < abac_rules_enc_count; i++) {
		abac_rules_enc_clear_avp_list(abac_rules_enc_policy[i]->user);
		abac_rules_enc_clear_avp_list(abac_rules_enc_policy[i]->env);
	}
	abac_rules_enc_count = 0;
	kfree(abac_rules_enc_policy);
}

void abac_rules_enc_print_policy(void) {
	int i;
	printk("Printing policy array...");
	printk("Contains %d rules", abac_rules_enc_count);
	for (i = 0; i < abac_rules_enc_count; i++){
		printk("ID = %u", abac_rules_enc_policy[i]->id);
		printk("User attributes");
		abac_rules_enc_print_avp(abac_rules_enc_policy[i]->user);
		printk("Environmental attributes");
		abac_rules_enc_print_avp(abac_rules_enc_policy[i]->env);
		printk("Operation");
		if (abac_rules_enc_policy[i]->op == ABAC_MODIFY) printk("MODIFY");
		else if (abac_rules_enc_policy[i]->op == ABAC_READ) printk("READ");
		else printk("IGNORE");
	}
}
