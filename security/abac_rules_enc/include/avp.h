#ifndef _ABAC_AVP_H
#define _ABAC_AVP_H

#define MAX_STR 32

enum operation {ABAC_MODIFY, ABAC_READ, ABAC_IGNORE};

typedef struct avp avp;
struct avp {
    int name;
    int value;
    avp *next;
};

avp *abac_rules_enc_parse_avp(char *);
void abac_rules_enc_print_avp(avp *);
void abac_rules_enc_clear_avp_list(avp *);

#endif /* _ABAC_AVP_H */
