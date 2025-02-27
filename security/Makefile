# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the kernel security code
#

obj-$(CONFIG_KEYS)			+= keys/

# always enable default capabilities
obj-y					+= commoncap.o
obj-$(CONFIG_SECURITY) 			+= lsm_syscalls.o
obj-$(CONFIG_MMU)			+= min_addr.o

# Object file lists
obj-$(CONFIG_SECURITY)			+= security.o
obj-$(CONFIG_SECURITYFS)		+= inode.o
obj-$(CONFIG_SECURITY_SELINUX)		+= selinux/
obj-$(CONFIG_SECURITY_SMACK)		+= smack/
obj-$(CONFIG_HAS_SECURITY_AUDIT)	+= lsm_audit.o
obj-$(CONFIG_SECURITY_TOMOYO)		+= tomoyo/
obj-$(CONFIG_SECURITY_APPARMOR)		+= apparmor/
obj-$(CONFIG_SECURITY_YAMA)		+= yama/
obj-$(CONFIG_SECURITY_ABAC_TREES)	+= abac_trees/
obj-$(CONFIG_SECURITY_ABAC_TREES_ENC)	+= abac_trees_enc/
obj-$(CONFIG_SECURITY_ABAC_RULES)	+= abac_rules/
obj-$(CONFIG_SECURITY_ABAC_RULES_ENC)	+= abac_rules_enc/
obj-$(CONFIG_SECURITY_LOADPIN)		+= loadpin/
obj-$(CONFIG_SECURITY_SAFESETID)       += safesetid/
obj-$(CONFIG_SECURITY_LOCKDOWN_LSM)	+= lockdown/
obj-$(CONFIG_CGROUPS)			+= device_cgroup.o
obj-$(CONFIG_BPF_LSM)			+= bpf/
obj-$(CONFIG_SECURITY_LANDLOCK)		+= landlock/
obj-$(CONFIG_SECURITY_IPE)		+= ipe/
obj-$(CONFIG_SECURITY_DABAC_RS)		+= dabac_rs/

# Object integrity file lists
obj-$(CONFIG_INTEGRITY)			+= integrity/
