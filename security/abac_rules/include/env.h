#ifndef _ABAC_ENV_H
#define _ABAC_ENV_H
#include "avp.h"

avp *abac_rules_parse_env_attr(char *);
void abac_rules_print_env_attrs(avp *);

#endif /* _ABAC_ENV_H */
