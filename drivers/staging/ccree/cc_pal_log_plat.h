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

/* Dummy pal_log_plat for test driver in kernel */

#ifndef _SSI_PAL_LOG_PLAT_H_
#define _SSI_PAL_LOG_PLAT_H_

#if defined(DEBUG)

#define __CC_PAL_LOG_PLAT(level, format, ...) printk(level "cc7x_test::" format , ##__VA_ARGS__)

#else /* Disable all prints */

#define __CC_PAL_LOG_PLAT(...)  do {} while (0)

#endif

#endif /*_SASI_PAL_LOG_PLAT_H_*/

