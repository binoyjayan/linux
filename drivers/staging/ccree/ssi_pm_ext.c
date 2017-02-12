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


#include "ssi_config.h"
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/interrupt.h>
#include <crypto/ctr.h>
#include <linux/pm_runtime.h>
#include "ssi_driver.h"
#include "ssi_sram_mgr.h"
#include "ssi_pm_ext.h"

/*
This function should suspend the HW (if possiable), It should be implemented by 
the driver user. 
The reference code clears the internal SRAM to imitate lose of state. 
*/
void ssi_pm_ext_hw_suspend(struct device *dev)
{
	struct ssi_drvdata *drvdata =
		(struct ssi_drvdata *)dev_get_drvdata(dev);
	unsigned int val;
	void __iomem *cc_base = drvdata->cc_base;
	unsigned int  sram_addr = 0;

	CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, SRAM_ADDR), sram_addr);

	for (;sram_addr < SSI_CC_SRAM_SIZE ; sram_addr+=4) {
		CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, SRAM_DATA), 0x0);

		do {
			val = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, SRAM_DATA_READY));
		} while (!(val &0x1));
	}
}

/*
This function should resume the HW (if possiable).It should be implemented by 
the driver user. 
*/
void ssi_pm_ext_hw_resume(struct device *dev)
{
	return;
}

