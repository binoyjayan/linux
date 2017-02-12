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

/* \file ssi_sysfs.h
   ARM CryptoCell sysfs APIs
 */

#ifndef __SSI_SYSFS_H__
#define __SSI_SYSFS_H__

#include <asm/timex.h>

/* forward declaration */
struct ssi_drvdata;

enum stat_phase {
	STAT_PHASE_0 = 0,
	STAT_PHASE_1,
	STAT_PHASE_2,
	STAT_PHASE_3,
	STAT_PHASE_4,
	STAT_PHASE_5,
	STAT_PHASE_6,
	MAX_STAT_PHASES,
};
enum stat_op {
	STAT_OP_TYPE_NULL = 0,
	STAT_OP_TYPE_ENCODE,
	STAT_OP_TYPE_DECODE,
	STAT_OP_TYPE_SETKEY,
	STAT_OP_TYPE_GENERIC,
	MAX_STAT_OP_TYPES,
};

int ssi_sysfs_init(struct kobject *sys_dev_obj, struct ssi_drvdata *drvdata);
void ssi_sysfs_fini(void);
void update_host_stat(unsigned int op_type, unsigned int phase, cycles_t result);
void update_cc_stat(unsigned int op_type, unsigned int phase, unsigned int elapsed_cycles);
void display_all_stat_db(void);

#endif /*__SSI_SYSFS_H__*/
