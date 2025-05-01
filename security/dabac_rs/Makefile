# SPDX-License-Identifier: GPL-2.0
ccflags-y += -I$(src)			# needed for trace events

obj-$(CONFIG_SECURITY_DABAC_RS) += dabac_mx_nc_lsm.o dabac_sl_nc_lsm.o \
	dabac_mx_tlc_lsm.o dabac_sl_tlc_lsm.o \
	dabac_mx_tlch_lsm.o dabac_sl_tlch_lsm.o \
	dabac_mx_flc_lsm.o dabac_sl_flc_lsm.o \
	dabac_mx_flch_lsm.o dabac_sl_flch_lsm.o

dabac_mx_nc_lsm-y := dabac_mx_nc.o no_caching/dabac_mx_nc_fs.o
dabac_sl_nc_lsm-y := dabac_sl_nc.o no_caching/dabac_sl_nc_fs.o
dabac_mx_tlc_lsm-y := dabac_mx_tlc.o top_level_caching/dabac_mx_tlc_fs.o
dabac_sl_tlc_lsm-y := dabac_sl_tlc.o top_level_caching/dabac_sl_tlc_fs.o
dabac_mx_tlch_lsm-y := dabac_mx_tlch.o top_level_caching/dabac_mx_tlch_fs.o
dabac_sl_tlch_lsm-y := dabac_sl_tlch.o top_level_caching/dabac_sl_tlch_fs.o
dabac_mx_flc_lsm-y := dabac_mx_flc.o formula_level_caching/dabac_mx_flc_fs.o
dabac_sl_flc_lsm-y := dabac_sl_flc.o formula_level_caching/dabac_sl_flc_fs.o
dabac_mx_flch_lsm-y := dabac_mx_flch.o formula_level_caching/dabac_mx_flch_fs.o
dabac_sl_flch_lsm-y := dabac_sl_flch.o formula_level_caching/dabac_sl_flch_fs.o
