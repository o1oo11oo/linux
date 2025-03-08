# SPDX-License-Identifier: GPL-2.0
ccflags-y += -I$(src)			# needed for trace events

obj-$(CONFIG_SECURITY_DABAC_RS)		+= dabac_lsm.o

dabac_lsm-y := dabac.o dabac_fs.o
