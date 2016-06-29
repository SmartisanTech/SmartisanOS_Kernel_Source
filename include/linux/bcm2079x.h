/*
 * Copyright (C) 2012 Broadcom Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _BCM2079X_H
#define _BCM2079X_H

#define BCMNFC_MAGIC	0xFA

/*
 * BCMNFC power control via ioctl
 * BCMNFC_POWER_CTL(0): power off
 * BCMNFC_POWER_CTL(1): power on
 * BCMNFC_WAKE_CTL(0): wake off
 * BCMNFC_WAKE_CTL(1): wake on
 */
#define BCMNFC_POWER_CTL		_IO(BCMNFC_MAGIC, 0x01)
#define BCMNFC_CHANGE_ADDR		_IO(BCMNFC_MAGIC, 0x02)
#define BCMNFC_READ_FULL_PACKET		_IO(BCMNFC_MAGIC, 0x03)
#define BCMNFC_SET_WAKE_ACTIVE_STATE	_IO(BCMNFC_MAGIC, 0x04)
#define BCMNFC_WAKE_CTL			_IO(BCMNFC_MAGIC, 0x05)
#define BCMNFC_READ_MULTI_PACKETS	_IO(BCMNFC_MAGIC, 0x06)

/* This structure keeps information per regulator */
struct bcm_nfc_reg_data {
	/* voltage regulator handle */
	struct regulator *reg;
	/* regulator name */
	const char *name;
	/* voltage level to be set */
	unsigned int low_vol_level;
	unsigned int high_vol_level;
	/* Load values for low power and high power mode */
	unsigned int lpm_uA;
	unsigned int hpm_uA;
	/*
	 * is set voltage supported for this regulator?
	 * false => set voltage is not supported
	 * true  => set voltage is supported
	 *
	 * Some regulators (like gpio-regulators, LVS (low voltage swtiches)
	 * PMIC regulators) dont have the capability to call
	 * regulator_set_voltage or regulator_set_optimum_mode
	 * Use this variable to indicate if its a such regulator or not
	 */
	bool set_voltage_sup;
	/* is this regulator enabled? */
	bool is_enabled;
	/* is this regulator needs to be always on? */
	bool always_on;
	/* is low power mode setting required for this regulator? */
	bool lpm_sup;
	/*
	 * Use to indicate if the regulator should be reset at boot time.
	 * Its needed only when sd card's vdd regulator is always on
	 * since always on regulators dont get reset at boot time.
	 *
	 * It is needed for sd 3.0 card to be detected as a sd 3.0 card
	 * on device reboot.
	 */
	bool reset_at_init;
};



struct bcm2079x_platform_data {
	unsigned int irq_gpio;
	unsigned int en_gpio;
	unsigned int wake_gpio;
	unsigned int reg;
	const char *clk_src;
	unsigned int clk_src_gpio;
	struct bcm_nfc_reg_data *vcc_data; /* keeps VDD/VCC regulator info */
};

extern int poweroff_charging;
#endif
