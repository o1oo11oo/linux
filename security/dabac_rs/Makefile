# SPDX-License-Identifier: GPL-2.0
ccflags-y += -I$(src)			# needed for trace events

obj-$(CONFIG_SECURITY_DABAC_RS) += dabac_nc_lsm.o \
	dabac_tlc_lsm.o dabac_tlch_lsm.o \
	dabac_flc_lsm.o dabac_flch_lsm.o

dabac_nc_lsm-y := dabac_nc.o no_caching/dabac_nc_fs.o
dabac_tlc_lsm-y := dabac_tlc.o top_level_caching/dabac_tlc_fs.o
dabac_tlch_lsm-y := dabac_tlch.o top_level_caching/dabac_tlch_fs.o
dabac_flc_lsm-y := dabac_flc.o formula_level_caching/dabac_flc_fs.o
dabac_flch_lsm-y := dabac_flch.o formula_level_caching/dabac_flch_fs.o
