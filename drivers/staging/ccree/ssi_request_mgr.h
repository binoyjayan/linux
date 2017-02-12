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

/* \file request_mgr.h
   Request Manager
 */

#ifndef __REQUEST_MGR_H__
#define __REQUEST_MGR_H__

#include "cc_hw_queue_defs.h"

int request_mgr_init(struct ssi_drvdata *drvdata);

/*!
 * Enqueue caller request to crypto hardware.
 * 
 * \param drvdata 
 * \param ssi_req The request to enqueue
 * \param desc The crypto sequence
 * \param len The crypto sequence length
 * \param is_dout If "true": completion is handled by the caller 
 *      	  If "false": this function adds a dummy descriptor completion
 *      	  and waits upon completion signal.
 * 
 * \return int Returns -EINPROGRESS if "is_dout=ture"; "0" if "is_dout=false"
 */
int send_request(
	struct ssi_drvdata *drvdata, struct ssi_crypto_req *ssi_req,
	HwDesc_s *desc, unsigned int len, bool is_dout);

int send_request_init(
	struct ssi_drvdata *drvdata, HwDesc_s *desc, unsigned int len);

void complete_request(struct ssi_drvdata *drvdata);

void request_mgr_fini(struct ssi_drvdata *drvdata);

#if defined (CONFIG_PM_RUNTIME) || defined (CONFIG_PM_SLEEP)
int ssi_request_mgr_runtime_resume_queue(struct ssi_drvdata *drvdata);

int ssi_request_mgr_runtime_suspend_queue(struct ssi_drvdata *drvdata);

bool ssi_request_mgr_is_queue_runtime_suspend(struct ssi_drvdata *drvdata);
#endif

#endif /*__REQUEST_MGR_H__*/
