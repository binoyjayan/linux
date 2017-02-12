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

/* \file ssi_config.h
   Definitions for ARM CryptoCell Linux Crypto Driver
 */

#ifndef __SSI_CONFIG_H__
#define __SSI_CONFIG_H__

#include <linux/version.h>

#define DISABLE_COHERENT_DMA_OPS
//#define FLUSH_CACHE_ALL
//#define COMPLETION_DELAY
//#define DX_DUMP_DESCS
// #define DX_DUMP_BYTES
// #define CC_DEBUG
#define ENABLE_CC_SYSFS		/* Enable sysfs interface for debugging REE driver */
//#define ENABLE_CC_CYCLE_COUNT
//#define DX_IRQ_DELAY 100000
#define DMA_BIT_MASK_LEN	48	/* was 32 bit, but for juno's sake it was enlarged to 48 bit */

#if defined ENABLE_CC_CYCLE_COUNT && defined ENABLE_CC_SYSFS
#define CC_CYCLE_COUNT
#endif


#if defined (CONFIG_ARM64)	// TODO currently only this mode was test on Juno (which is ARM64), need to enable coherent also.
#define DISABLE_COHERENT_DMA_OPS
#endif

/* Define the CryptoCell DMA cache coherency signals configuration */
#if defined (DISABLE_COHERENT_DMA_OPS)
	/* Software Controlled Cache Coherency (SCCC) */ 
	#define SSI_CACHE_PARAMS (0x000)
	/* CC attached to NONE-ACP such as HPP/ACE/AMBA4.
	 * The customer is responsible to enable/disable this feature
	 * according to his platform type. */
	#define DX_HAS_ACP 0
#else
	#define SSI_CACHE_PARAMS (0xEEE)
	/* CC attached to ACP */
	#define DX_HAS_ACP 1
#endif

#endif /*__DX_CONFIG_H__*/

