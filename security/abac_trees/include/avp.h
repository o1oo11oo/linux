#ifndef _ABAC_AVP_H
#define _ABAC_AVP_H

#define MAX_STR 64

typedef struct avp avp;
struct avp {
    char name[MAX_STR];
    char value[MAX_STR];
    avp *next;
};

avp *abac_trees_parse_avp(char *);
void abac_trees_print_avp(avp *);
void abac_trees_clear_avp_list(avp *);

#endif /* _ABAC_AVP_H */
