#ifndef _ABAC_USER_H
#define _ABAC_USER_H

#include "avp.h"

void abac_trees_parse_user_attr(char *);
avp *abac_trees_get_user_attrs(unsigned int);
void abac_trees_print_user_attrs(void);
void abac_trees_clear_user_attrs(void);

#endif /* _ABAC_USER_H */
