/*
 * include/media/ti-scbl.h
 *
 * Copyright (C) 2015 Texas Instruments
 *
 * Contact: Daniel Jeong <gshark.jeong@gmail.com>
 *			Ldd-Mlp <ldd-mlp@list.ti.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 */

#ifndef __TI_SCBL_H
#define __TI_SCBL_H

#define LM36923_NAME "lm36923"
#define LM36923_I2C_ADDR	(0x36)

#define TI_SINGLE_CONTROL_BL_NAME	"ti_sc_backlight"

#define SCBL_FAULT_OVER_VOLTAGE 0x01
#define SCBL_FAULT_OVER_CURRENT 0x02
#define SCBL_FAULT_THERMAL_SHDN 0x04
#define SCBL_FAULT_LED_SHORT    0x08
#define SCBL_FAULT_LED_OPEN     0x10
#define SCBL_FAULT_MAX 5

#define SCBL_LED_MAX 8
#define SCBL_REG_MAX 0xff

int scbl_set_brightness(int bl_level);

#endif /* __TI_SCBL_H */
