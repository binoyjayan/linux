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
