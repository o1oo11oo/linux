#ifndef _ABAC_AVP_H
#define _ABAC_AVP_H

#define MAX_STR 64

typedef struct avp avp;
struct avp {
	int name;
	int value;
    avp *next;
};

avp *abac_trees_enc_parse_avp(char *);
void abac_trees_enc_print_avp(avp *);
void abac_trees_enc_clear_avp_list(avp *);

#endif /* _ABAC_AVP_H */
