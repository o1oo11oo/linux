#ifndef _ABAC_ENV_H
#define _ABAC_ENV_H
#include "avp.h"

avp *abac_trees_parse_env_attr(char *);
void abac_trees_print_env_attrs(avp *);

#endif /* _ABAC_ENV_H */
