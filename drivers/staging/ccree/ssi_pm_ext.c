/*
 * Copyright (C) 2012-2016 ARM Limited or its affiliates.
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */


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

