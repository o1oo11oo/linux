#ifndef _ABAC_USER_H
#define _ABAC_USER_H

#include "avp.h"

void abac_rules_enc_parse_user_attr(char *);
avp *abac_rules_enc_get_user_attrs(unsigned int);
void abac_rules_enc_print_user_attrs(void);
void abac_rules_enc_clear_user_attrs(void);

#endif /* _ABAC_USER_H */
