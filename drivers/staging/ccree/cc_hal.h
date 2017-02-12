/****************************************************************************
* The confidential and proprietary information contained in this file may    *
* only be used by a person authorised under and to the extent permitted      *
* by a subsisting licensing agreement from ARM Limited or its affiliates.    *
* 	(C) COPYRIGHT [2001-2016] ARM Limited or its affiliates.	     *
*	    ALL RIGHTS RESERVED						     *
* This entire notice must be reproduced on all copies of this file           *
* and copies of this file may only be made by a person if such person is     *
* permitted to do so under the terms of a subsisting license agreement       *
* from ARM Limited or its affiliates.					     *
*****************************************************************************/

/* pseudo cc_hal.h for cc7x_perf_test_driver (to be able to include code from CC drivers) */

#ifndef __CC_HAL_H__
#define __CC_HAL_H__

#include <linux/io.h>

#if defined(CONFIG_ARM) || defined(CONFIG_ARM64)
/* CC registers are always 32 bit wide (even on 64 bit platforms) */
#define READ_REGISTER(_addr) ioread32((_addr))
#define WRITE_REGISTER(_addr, _data)  iowrite32((_data), (_addr))
#else
#error Unsupported platform
#endif

#define CC_HAL_WRITE_REGISTER(offset, val) WRITE_REGISTER(cc_base + offset, val)
#define CC_HAL_READ_REGISTER(offset) READ_REGISTER(cc_base + offset)

#endif
