/*
 *
 * Copyright (C) 2014 Smartisan Technology (Beijing) Co.Ltd
 * Author: dangpenghui<dangpenghui@smartisan.com>
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
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/i2c.h>
#include <linux/io.h>
#include <linux/platform_device.h>
#include <linux/i2c-dev.h>
#include <linux/device.h>
#include <linux/delay.h>
#include <linux/gpio.h>
#include <linux/jiffies.h>
#include <asm/uaccess.h>

#define DRIVER_VERSION "1.0.1"
#define DEV_NAME "tfa9890"
#define I2C_ADDR 0x34
#define ENABLE_MI2S_CLK 0x0709
#define GET_CURRENT_SPK_ID 0x0710
#define TFA9890_RST_GPIO 930        //GPIO52
#define SPEAKER_ID_GPIO 917         //GPIO39

struct class *tfa9890_class;
static int speaker_id = 0;

extern int msm8994_pri_mi2s_clk_enable(bool enable);

long tfa9890_i2c_ioctl(struct file *fp, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case ENABLE_MI2S_CLK: {
		if (arg == 1) {
			msm8994_pri_mi2s_clk_enable(true);
		} else {
			msm8994_pri_mi2s_clk_enable(false);
		}
		break;
	}
	case GET_CURRENT_SPK_ID: {
		if (copy_to_user((void *)arg, &speaker_id, sizeof(speaker_id))) {
			pr_err("%s: copy_to_user for GET_CURRENT_SPK_ID failed\n",
				__func__);
			return -EFAULT;
		}
		break;
	}
	default:
		pr_err("%s: cmd 0x%x is not supported\n", __func__, cmd);
	}

	return 0;
}

int tfa9890_i2c_open(struct inode *node, struct file *fp)
{
	pr_debug("%s: line %d\n", __func__, __LINE__);
	return 0;
}

ssize_t tfa9890_i2c_read(struct file *fp, char __user *buff, size_t count, loff_t *offset)
{
	return 0;
}

ssize_t tfa9890_i2c_write(struct file *fp, const char __user *buff, size_t count, loff_t *offset)
{
	return count;
}

static const struct file_operations tfa9890_i2c_fops = {
	.owner = THIS_MODULE,
	.open = tfa9890_i2c_open,
	.read = tfa9890_i2c_read,
	.write = tfa9890_i2c_write,
#ifdef CONFIG_COMPAT
	.compat_ioctl = tfa9890_i2c_ioctl,
#endif
};

static int __init tfa9890_dev_init(void)
{
	int ret;
	struct device *dev;
	int major;

	major = register_chrdev(0, DEV_NAME, &tfa9890_i2c_fops);
	if (!major) {
		pr_err("%s:register_chardev fail! major = %d\n", __func__, major);
		return ret;
	}

	tfa9890_class = class_create(THIS_MODULE, "my_class");
	if (IS_ERR(tfa9890_class)) {
		pr_err("%s: failed in creating class.\n", __func__);
		return -1;
	}

	dev = device_create(tfa9890_class, NULL, MKDEV(major, 0), NULL, DEV_NAME);
	if (IS_ERR(dev)) {
		pr_err("%s: device_creat error!\n", __func__);
		return -1;
	}

	ret = gpio_request(TFA9890_RST_GPIO, "TFA98XX_RESET");
	if (ret) {
		pr_err("%s: failed to request gpio %d, ret = %d\n", __func__,
		       TFA9890_RST_GPIO, ret);
		return ret;
	}
	gpio_direction_output(TFA9890_RST_GPIO, 1);
	msleep(20);
	gpio_direction_output(TFA9890_RST_GPIO, 0);
	msleep(20);

	speaker_id = gpio_get_value_cansleep(SPEAKER_ID_GPIO);

	return ret;
}

module_init(tfa9890_dev_init);

static void __exit tfa9890_dev_exit(void)
{
	pr_err("%s:Unloading tfa9890 i2c driver\n", __func__);
}

module_exit(tfa9890_dev_exit);

MODULE_AUTHOR("dangpenghui <dangpenghui@smartisan.com>");
MODULE_DESCRIPTION("tfa9890 i2c driver");
MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL v2");
