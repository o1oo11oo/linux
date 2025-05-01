/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (C) 2023 Google LLC.
 */

#ifndef __UNROLL_H
#define __UNROLL_H

#include <linux/args.h>

#define UNROLL(N, MACRO, args...) CONCATENATE(__UNROLL_, N)(MACRO, args)

#define __UNROLL_0(MACRO, args...)
#define __UNROLL_1(MACRO, args...)  __UNROLL_0(MACRO, args)  MACRO(0, args)
#define __UNROLL_2(MACRO, args...)  __UNROLL_1(MACRO, args)  MACRO(1, args)
#define __UNROLL_3(MACRO, args...)  __UNROLL_2(MACRO, args)  MACRO(2, args)
#define __UNROLL_4(MACRO, args...)  __UNROLL_3(MACRO, args)  MACRO(3, args)
#define __UNROLL_5(MACRO, args...)  __UNROLL_4(MACRO, args)  MACRO(4, args)
#define __UNROLL_6(MACRO, args...)  __UNROLL_5(MACRO, args)  MACRO(5, args)
#define __UNROLL_7(MACRO, args...)  __UNROLL_6(MACRO, args)  MACRO(6, args)
#define __UNROLL_8(MACRO, args...)  __UNROLL_7(MACRO, args)  MACRO(7, args)
#define __UNROLL_9(MACRO, args...)  __UNROLL_8(MACRO, args)  MACRO(8, args)
#define __UNROLL_10(MACRO, args...) __UNROLL_9(MACRO, args)  MACRO(9, args)
#define __UNROLL_11(MACRO, args...) __UNROLL_10(MACRO, args) MACRO(10, args)
#define __UNROLL_12(MACRO, args...) __UNROLL_11(MACRO, args) MACRO(11, args)
#define __UNROLL_13(MACRO, args...) __UNROLL_12(MACRO, args) MACRO(12, args)
#define __UNROLL_14(MACRO, args...) __UNROLL_13(MACRO, args) MACRO(13, args)
#define __UNROLL_15(MACRO, args...) __UNROLL_14(MACRO, args) MACRO(14, args)
#define __UNROLL_16(MACRO, args...) __UNROLL_15(MACRO, args) MACRO(15, args)
#define __UNROLL_17(MACRO, args...) __UNROLL_16(MACRO, args) MACRO(16, args)
#define __UNROLL_18(MACRO, args...) __UNROLL_17(MACRO, args) MACRO(17, args)
#define __UNROLL_19(MACRO, args...) __UNROLL_18(MACRO, args) MACRO(18, args)
#define __UNROLL_20(MACRO, args...) __UNROLL_19(MACRO, args) MACRO(19, args)
#define __UNROLL_21(MACRO, args...) __UNROLL_20(MACRO, args) MACRO(20, args)
#define __UNROLL_22(MACRO, args...) __UNROLL_21(MACRO, args) MACRO(21, args)
#define __UNROLL_23(MACRO, args...) __UNROLL_22(MACRO, args) MACRO(22, args)
#define __UNROLL_24(MACRO, args...) __UNROLL_23(MACRO, args) MACRO(23, args)
#define __UNROLL_25(MACRO, args...) __UNROLL_24(MACRO, args) MACRO(24, args)
#define __UNROLL_26(MACRO, args...) __UNROLL_25(MACRO, args) MACRO(25, args)
#define __UNROLL_27(MACRO, args...) __UNROLL_26(MACRO, args) MACRO(26, args)
#define __UNROLL_28(MACRO, args...) __UNROLL_27(MACRO, args) MACRO(27, args)
#define __UNROLL_29(MACRO, args...) __UNROLL_28(MACRO, args) MACRO(28, args)
#define __UNROLL_30(MACRO, args...) __UNROLL_29(MACRO, args) MACRO(29, args)

#endif /* __UNROLL_H */
