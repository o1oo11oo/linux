#include <linux/string.h>
#include <linux/slab.h>
#include "avp.h"

void abac_rules_enc_clear_avp_list(avp *head) 
{
	// Free the avp linked list given by head
	avp* cursor = head;
	avp* to_free = NULL;
	while (cursor != NULL) {
		to_free = cursor;
		cursor = cursor->next;
		kfree(to_free);
	}
}

avp *abac_rules_enc_parse_avp(char *avp_str) {
	/* Parse a collection of name=value pairs separated by commas */
	avp *head, *temp;
	char *pair, *name;
	int rc;
	head = NULL;
	while((pair = strsep(&avp_str, ",")) != NULL) {
		name = strsep(&pair, "=");
		temp = kcalloc(1, sizeof(avp), GFP_KERNEL);
		temp->next = NULL;
		rc = kstrtoint(name, 10, &(temp->name));
		rc = kstrtoint(pair, 10, &(temp->value));
		if (head) {
			temp->next = head;
		}
		head = temp;
	}
	return head;
}

void abac_rules_enc_print_avp(avp *head) {
	avp *cursor;
	cursor = head;
	while (cursor != NULL) {
		printk("%d=%d", cursor->name, cursor->value);
		cursor = cursor->next;
	}
}
