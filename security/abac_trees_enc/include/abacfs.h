#ifndef _ABAC_FS_H_
#define _ABAC_FS_H_

#include "linux/time.h"
#include "avp.h"
#include "env.h"
#include "user.h"
#include "obj.h"

/* Check whether the LSM was initialized successfully */
extern int abac_trees_enc_initialized;

/* Pointer to the environment attribute list. Initialized in abacfs */
extern avp *abac_trees_enc_env_attr;

/* Recording performance variables. Initialized in abacfs */
extern int abac_trees_enc_recording;
extern char abac_trees_enc_perf_buf[64];
extern u64 abac_trees_enc_prev_access_time;

#endif /* _ABAC_FS_H */
