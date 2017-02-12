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

/* \file ssi_pm.h
    */

#ifndef __SSI_POWER_MGR_H__
#define __SSI_POWER_MGR_H__


#include "ssi_config.h"
#include "ssi_driver.h"


#define SSI_SUSPEND_TIMEOUT 3000


int ssi_power_mgr_init(struct ssi_drvdata *drvdata);

void ssi_power_mgr_fini(struct ssi_drvdata *drvdata);

#if defined (CONFIG_PM_RUNTIME) || defined (CONFIG_PM_SLEEP)
int ssi_power_mgr_runtime_suspend(struct device *dev);

int ssi_power_mgr_runtime_resume(struct device *dev);

int ssi_power_mgr_runtime_get(struct device *dev);

int ssi_power_mgr_runtime_put_suspend(struct device *dev);
#endif

#endif /*__POWER_MGR_H__*/

