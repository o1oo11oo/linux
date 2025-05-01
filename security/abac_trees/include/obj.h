#include "avp.h"

enum operation {ABAC_MODIFY, ABAC_READ, ABAC_IGNORE};

// predefinition of node to make its pointer available for definition
//struct abac_trees_node;

// struct representing a branch in a node
struct branch {
	char value[MAX_STR];
	struct abac_trees_node *child;
	struct branch *next;
};
typedef struct branch branch;

// struct representing a node in the tree
// Branches are stored as linked lists
struct abac_trees_node {
	char attr[MAX_STR];
	enum operation op;
	struct branch *head;
};

// struct representing the contents of a parsed node
struct node_cont {
	int nid;
	int pid;
	char attr[MAX_STR];
	char value[MAX_STR];
};
typedef struct node_cont node_cont;

void abac_trees_parse_obj_attr(char *);
struct abac_trees_node *abac_trees_get_obj_tree(char *);
void abac_trees_clear_obj_attrs(void);
void abac_trees_print_obj_attrs(void);
void abac_trees_print_attr_tree(struct abac_trees_node *);
