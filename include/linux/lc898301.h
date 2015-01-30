/*---------------------------------------------------------------
 * lc898301.h
 * LICENSE      GPL 2.0
 * Copyright (C) 2013 Smartisan Tech Co., Ltd. 2013
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 *--------------------------------------------------------------*/
#include <linux/device.h>

#ifndef	_lc898301_
#define	_lc898301_


enum power_state {
	POWER_ON,
	POWER_OFF,
	POWER_WHATEVER_ELSE
};

enum teardown_state {
	LC898301_SHUTDOWN,
	LC898301_FAILPROBE,
	LC898301_I2CERROR
};

#define	LC898301_REG_SIZE		10

#define	LC898301_FREQ_FWD_SIZE		2
#define	LC898301_FREQ_REV_SIZE		2

struct lc898301pwm_freq_tbl {
	unsigned long duty_ns;		/* nsec */
	unsigned long period_ns;	/* nsec */
	int output_time;		/* msec */
};

struct lc898301board_info {
	int (*platform_init)(struct device *dev, int stat);
	int (*platform_reset)(struct device *dev, int stat);
	int (*platform_power)(struct device *dev, enum power_state);
	int (*platform_enable)(struct device *dev, int stat);
	int (*platform_teardown)(struct device *dev,
						enum teardown_state stat);

	int max_timeout_ms;
	char reg_data[LC898301_REG_SIZE];
	char *devname;
	struct lc898301pwm_freq_tbl pwmfqtbl_fwd[LC898301_FREQ_FWD_SIZE];
	struct lc898301pwm_freq_tbl pwmfqtbl_fwdrpt;
	struct lc898301pwm_freq_tbl pwmfqtbl_rev[LC898301_FREQ_REV_SIZE];
};

#endif
