# SPDX-License-Identifier: GPL-2.0
ccflags-y += -I$(src)			# needed for trace events

obj-$(CONFIG_SECURITY_DABAC_RS)		+= dabac_tlch_lsm.o

dabac_tlch_lsm-y := dabac_tlch.o top_level_caching_hashing/dabac_fs.o
