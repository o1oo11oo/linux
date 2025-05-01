#ifndef _ABAC_POLICY_H
#define _ABAC_POLICY_H

#include "avp.h"

typedef struct abac_rule abac_rule;
struct abac_rule {
	unsigned int id;
	avp *user;
	avp *env;
	enum operation op;
};

void abac_rules_parse_policy(char *);
abac_rule *abac_rules_get_rule(unsigned int );
void abac_rules_print_policy(void);
void abac_rules_clear_policy(void);

#endif /* _ABAC_POLICY_H */
