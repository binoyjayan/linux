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

#ifndef __HW_QUEUE_DEFS_PLAT_H__
#define __HW_QUEUE_DEFS_PLAT_H__


/*****************************/
/* Descriptor packing macros */
/*****************************/

#define HW_QUEUE_FREE_SLOTS_GET() (CC_HAL_READ_REGISTER(CC_REG_OFFSET(CRY_KERNEL, DSCRPTR_QUEUE_CONTENT)) & HW_QUEUE_SLOTS_MAX)

#define HW_QUEUE_POLL_QUEUE_UNTIL_FREE_SLOTS(seqLen)						\
	do {											\
	} while (HW_QUEUE_FREE_SLOTS_GET() < (seqLen))

#define HW_DESC_PUSH_TO_QUEUE(pDesc) do {        				  \
	LOG_HW_DESC(pDesc);							  \
	HW_DESC_DUMP(pDesc);							  \
	CC_HAL_WRITE_REGISTER(GET_HW_Q_DESC_WORD_IDX(0), (pDesc)->word[0]); \
	CC_HAL_WRITE_REGISTER(GET_HW_Q_DESC_WORD_IDX(1), (pDesc)->word[1]); \
	CC_HAL_WRITE_REGISTER(GET_HW_Q_DESC_WORD_IDX(2), (pDesc)->word[2]); \
	CC_HAL_WRITE_REGISTER(GET_HW_Q_DESC_WORD_IDX(3), (pDesc)->word[3]); \
	CC_HAL_WRITE_REGISTER(GET_HW_Q_DESC_WORD_IDX(4), (pDesc)->word[4]); \
	wmb();									   \
	CC_HAL_WRITE_REGISTER(GET_HW_Q_DESC_WORD_IDX(5), (pDesc)->word[5]); \
} while (0)

#endif /*__HW_QUEUE_DEFS_PLAT_H__*/
