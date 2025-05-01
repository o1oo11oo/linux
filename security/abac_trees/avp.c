#include <linux/string.h>
#include <linux/slab.h>
#include "avp.h"

void abac_trees_clear_avp_list(avp *head) 
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

avp *abac_trees_parse_avp(char *avp_str) {
	/* Parse a collection of name=value pairs separated by commas */
	avp *head, *temp;
	char *pair, *name;
	head = NULL;
	while((pair = strsep(&avp_str, ",")) != NULL) {
		name = strsep(&pair, "=");
		temp = kcalloc(1, sizeof(avp), GFP_KERNEL);
		temp->next = NULL;
		strcpy(temp->name, name);
		strcpy(temp->value, pair);
		if (head) {
			temp->next = head;
		}
		head = temp;
	}
	return head;
}

void abac_trees_print_avp(avp *head) {
	avp *cursor;
	cursor = head;
	while (cursor != NULL) {
		printk("%s=%s", cursor->name, cursor->value);
		cursor = cursor->next;
	}
}
