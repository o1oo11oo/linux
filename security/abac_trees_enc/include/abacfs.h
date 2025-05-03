#ifndef _ABAC_FS_H_
#define _ABAC_FS_H_

#include "linux/time.h"
#include "avp.h"
#include "env.h"
#include "user.h"
#include "obj.h"

/* Check whether this and other ABAC LSMs were initialized successfully */

#if IS_ENABLED(CONFIG_SECURITY_ABAC_RULES)
extern int abac_rules_initialized;
#else
static int abac_rules_initialized;
#endif

#if IS_ENABLED(CONFIG_SECURITY_ABAC_RULES_ENC)
extern int abac_rules_enc_initialized;
#else
static int abac_rules_enc_initialized;
#endif

#if IS_ENABLED(CONFIG_SECURITY_ABAC_TREES)
extern int abac_trees_initialized;
#else
static int abac_trees_initialized;
#endif

#if IS_ENABLED(CONFIG_SECURITY_ABAC_TREES_ENC)
extern int abac_trees_enc_initialized;
#else
static int abac_trees_enc_initialized;
#endif

/* Pointer to the environment attribute list. Initialized in abacfs */
extern avp *abac_trees_enc_env_attr;

/* Recording performance variables. Initialized in abacfs */
extern int abac_trees_enc_recording;
extern char abac_trees_enc_perf_buf[64];
extern u64 abac_trees_enc_prev_access_time;

#endif /* _ABAC_FS_H */
