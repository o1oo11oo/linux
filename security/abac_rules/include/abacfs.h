#ifndef _ABAC_FS_H_
#define _ABAC_FS_H_

#include "linux/time.h"
#include "avp.h"
#include "env.h"
#include "user.h"
#include "obj.h"
#include "policy.h"

/* Check whether the LSM was initialized successfully */
extern int abac_rules_initialized;

/* Pointer to the environment attribute list. Initialized in abacfs */
extern avp *abac_rules_env_attr;

/* Recording performance variables. Initialized in abacfs */
extern int abac_rules_recording;
extern char abac_rules_perf_buf[64];
extern u64 abac_rules_prev_access_time;

#endif /* _ABAC_FS_H */
