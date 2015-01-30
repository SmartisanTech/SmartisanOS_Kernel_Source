/*
 * Cirrus Logic 192kHz Multi-Bit DAC driver
 *
 * Copyright (C) 2013 Smartisan Technology (Beijing) Co.Ltd
 * Author: Chris Wang <wangjunkang@smartisan.cn>
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
#include <linux/irq.h>
#include <linux/jiffies.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/platform_device.h>
#include <linux/gpio.h>
#include <linux/poll.h>
#include <linux/miscdevice.h>
#include <linux/spinlock.h>
#include <linux/regulator/consumer.h>
#include <linux/of_gpio.h>

#define DRIVER_VERSION "1.0.1"

/* register 8 */
#define CS4398_CPEN		0x40
#define CS4398_PDN		0x80

#define CS4398_ANA_VTG_UV	5000000
//#define CS4398_DIG_VTG_UV	3300000
//#define CS4398_CTL_VTG_UV	1800000
//#define CS4398_SER_VTG_UV	1800000
#define CS4398_ANA_LOAD_UA	25000
#define CS4398_DIG_LOAD_UA	18000
#define CS4398_CTL_LOAD_UA	2
#define CS4398_SER_LOAD_UA	80

struct cs4398dac_data {
	struct i2c_client *client;
	struct regulator *vcc_ana;
	struct regulator *vcc_dig;
	struct regulator *vcc_ctl;
	struct regulator *vcc_ser;
};

static int reset_gpio = 0;


static int cs4398dac_suspend(struct i2c_client *client, pm_message_t mesg)
{
	return 0;
}

static int cs4398dac_resume(struct i2c_client *client)
{
	return 0;
}

/*
#ifdef CONFIG_OF
static int cs4398dac_parse_dt(struct device *dev,
				struct cs4398dac_i2c_platform_data *cs4398_pdata)
{
	struct device_node *np = dev->of_node;
	return 0;
}
#else
static inline int cs4398dac_parse_dt(struct device *dev,
				struct cs4398dac_i2c_platform_data *cs4398_pdata)
{
	return 0;
}
#endif
*/
static int reg_set_optimum_mode_check(struct regulator *reg, int load_uA)
{
	return (regulator_count_voltages(reg) > 0) ?
		regulator_set_optimum_mode(reg, load_uA) : 0;
}

static int cs4398dac_power_on(struct cs4398dac_data *data, bool on)
{
	int ret;

	if (on == false)
		goto power_off;

	ret = reg_set_optimum_mode_check(data->vcc_ana, CS4398_ANA_LOAD_UA);
	if (ret < 0) {
		dev_err(&data->client->dev,
			"Regulator vcc_ana set_opt failed ret=%d\n", ret);
		return ret;
	}

	ret = regulator_enable(data->vcc_ana);
	if (ret) {
		dev_err(&data->client->dev,
			"Regulator vcc_ana enable failed ret=%d\n", ret);
		goto error_reg_en_vcc_ana;
	}

	if (regulator_is_enabled(data->vcc_dig)) {
		ret = reg_set_optimum_mode_check(data->vcc_dig, CS4398_DIG_LOAD_UA);
		if (ret < 0) {
			dev_err(&data->client->dev,
				"Regulator vcc_dig set_opt failed ret=%d\n", ret);
			goto error_reg_opt_vcc_dig;
		}
	} else {
		dev_err(&data->client->dev,
			"Regulator vcc_dig should be enabled already by cs8422");
		goto error_reg_opt_vcc_dig;
	}

	if (regulator_is_enabled(data->vcc_ctl)) {
		ret = reg_set_optimum_mode_check(data->vcc_ctl, CS4398_CTL_LOAD_UA);
		if (ret < 0) {
			dev_err(&data->client->dev,
				"Regulator vcc_ctl set_opt failed ret=%d\n", ret);
			goto error_reg_opt_vcc_ctl;
		}
	} else {
		dev_err(&data->client->dev,
			"Regulator vcc_ctl should be enabled already by cs8422");
		goto error_reg_opt_vcc_ctl;
	}

	if (regulator_is_enabled(data->vcc_ser)) {
		ret = reg_set_optimum_mode_check(data->vcc_ser, CS4398_SER_LOAD_UA);
		if (ret < 0) {
			dev_err(&data->client->dev,
				"Regulator vcc_ser set_opt failed ret=%d\n", ret);
			goto error_reg_opt_vcc_ser;
		}
	} else {
		dev_err(&data->client->dev,
			"Regulator vcc_ser should be enabled already by cs8422");
		goto error_reg_opt_vcc_ser;
	}

/*
	ret = regulator_enable(data->vcc_dig);
	if (ret) {
		dev_err(&data->client->dev,
			"Regulator vcc_dig enable failed ret=%d\n", ret);
		goto error_reg_en_vcc_dig;
	}

	ret = regulator_enable(data->vcc_ctl);
	if (ret) {
		dev_err(&data->client->dev,
			"Regulator vcc_ctl enable failed ret=%d\n", ret);
		goto error_reg_en_vcc_ctl;
	}

	ret = regulator_enable(data->vcc_ser);
	if (ret) {
		dev_err(&data->client->dev,
			"Regulator vcc_ser enable failed ret=%d\n", ret);
		goto error_reg_en_vcc_ser;
	}
*/

	msleep(50);

	return 0;

error_reg_opt_vcc_ser:
	reg_set_optimum_mode_check(data->vcc_ctl, 0);
error_reg_opt_vcc_ctl:
	reg_set_optimum_mode_check(data->vcc_dig, 0);
error_reg_opt_vcc_dig:
	regulator_disable(data->vcc_ana);
error_reg_en_vcc_ana:
	reg_set_optimum_mode_check(data->vcc_ana, 0);
	return ret;

power_off:
	reg_set_optimum_mode_check(data->vcc_ana, 0);
	regulator_disable(data->vcc_ana);
	reg_set_optimum_mode_check(data->vcc_dig, 0);
	reg_set_optimum_mode_check(data->vcc_ctl, 0);
	reg_set_optimum_mode_check(data->vcc_ser, 0);

	msleep(50);
	return 0;
}

static int cs4398dac_regulator_configure(struct cs4398dac_data *data, bool on)
{
	int ret;

	if (on == false)
		goto hw_shutdown;

	data->vcc_ana = regulator_get(&data->client->dev, "vdd_ana");
	if (IS_ERR(data->vcc_ana)) {
		ret = PTR_ERR(data->vcc_ana);
		dev_err(&data->client->dev,
			"Regulator get failed vcc_ana ret=%d\n", ret);
		return ret;
	}

	if (regulator_count_voltages(data->vcc_ana) > 0) {
		ret = regulator_set_voltage(data->vcc_ana, CS4398_ANA_VTG_UV,
							CS4398_ANA_VTG_UV);
		if (ret) {
			dev_err(&data->client->dev,
				"regulator set_vtg failed ret=%d\n", ret);
			goto error_set_vtg_vcc_ana;
		}
	}

	data->vcc_dig = regulator_get(&data->client->dev, "vdd_dig");
	if (IS_ERR(data->vcc_dig)) {
		ret = PTR_ERR(data->vcc_dig);
		dev_err(&data->client->dev,
			"Regulator get failed vcc_dig ret=%d\n", ret);
		goto error_get_vtg_vcc_dig;
	}

	data->vcc_ctl = regulator_get(&data->client->dev, "vdd_ctl");
	if (IS_ERR(data->vcc_ctl)) {
		ret = PTR_ERR(data->vcc_ctl);
		dev_err(&data->client->dev,
			"Regulator get failed vcc_ctl ret=%d\n", ret);
		goto error_get_vtg_vcc_ctl;
	}

	data->vcc_ser = regulator_get(&data->client->dev, "vdd_ser");
	if (IS_ERR(data->vcc_ser)) {
		ret = PTR_ERR(data->vcc_ser);
		dev_err(&data->client->dev,
			"Regulator get failed vcc_ser ret=%d\n", ret);
		goto error_get_vtg_vcc_ser;
	}

/*
	if (regulator_count_voltages(data->vcc_dig) > 0) {
		ret = regulator_set_voltage(data->vcc_dig, CS4398_DIG_VTG_UV,
							CS4398_DIG_VTG_UV);
		if (ret) {
			dev_err(&data->client->dev,
				"regulator set_vtg failed ret=%d\n", ret);
			goto error_set_vtg_vcc_dig;
		}
	}

	if (regulator_count_voltages(data->vcc_ctl) > 0) {
		ret = regulator_set_voltage(data->vcc_ctl, CS4398_CTL_VTG_UV,
							CS4398_CTL_VTG_UV);
		if (ret) {
			dev_err(&data->client->dev,
				"regulator set_vtg failed ret=%d\n", ret);
			goto error_set_vtg_vcc_ctl;
		}
	}

	if (regulator_count_voltages(data->vcc_ser) > 0) {
		ret = regulator_set_voltage(data->vcc_ser, CS4398_SER_VTG_UV,
							CS4398_SER_VTG_UV);
		if (ret) {
			dev_err(&data->client->dev,
				"regulator set_vtg failed ret=%d\n", ret);
			goto error_set_vtg_vcc_ser;
		}
	}
*/

	return 0;

error_get_vtg_vcc_ser:
	regulator_put(data->vcc_ctl);
error_get_vtg_vcc_ctl:
	regulator_put(data->vcc_dig);
error_get_vtg_vcc_dig:
	if (regulator_count_voltages(data->vcc_ana) > 0)
		regulator_set_voltage(data->vcc_ana, 0, CS4398_ANA_VTG_UV);
error_set_vtg_vcc_ana:
	regulator_put(data->vcc_ana);
	return ret;

hw_shutdown:
	if (regulator_count_voltages(data->vcc_ana) > 0)
		regulator_set_voltage(data->vcc_ana, 0, CS4398_ANA_VTG_UV);
	regulator_put(data->vcc_ana);
	regulator_put(data->vcc_dig);
	regulator_put(data->vcc_ctl);
	regulator_put(data->vcc_ser);
	return 0;
}

static int __devinit cs4398dac_probe(struct i2c_client *client,
			 const struct i2c_device_id *id)
{
	int ret;

	u8 buffer[2];
	struct cs4398dac_data *data;
/*
	if (client->dev.of_node) {
		platform_data = devm_kzalloc(&client->dev,
			sizeof(*platform_data), GFP_KERNEL);
                if (!platform_data) {
                        dev_err(&client->dev, "Failed to allocate memory\n");
                        return -ENOMEM;
                }

		ret = cs4398dac_parse_dt(&client->dev, platform_data);
                if (ret)
                        return ret;
	} else {
		platform_data = client->dev.platform_data;
	}

	pr_debug("%s : clientptr %p\n", __func__, client);

	if (platform_data == NULL) {
		pr_err("%s : cs4398dac probe fail\n", __func__);
		return -ENODEV;
	}
*/
	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		pr_err("%s : need I2C_FUNC_I2C\n", __func__);
		return -ENODEV;
	}

	data = kzalloc(sizeof(struct cs4398dac_data), GFP_KERNEL);
	if (!data) {
		dev_err(&client->dev, "Failed to allocate memory\n");
		ret = -ENOMEM;
		goto err_free_mem;
	}

	data->client = client;
	i2c_set_clientdata(client, data);

	ret = cs4398dac_regulator_configure(data, true);
	if (ret) {
		dev_err(&client->dev, "Failed to intialize regulator\n");
		goto err_free_mem;
	}

	if (client->dev.of_node) {
		reset_gpio = of_get_named_gpio_flags(client->dev.of_node,
						"cirrus,dac-reset-gpio", 0, NULL);
	}

	ret = cs4398dac_power_on(data, true);
	if (ret) {
		dev_err(&client->dev, "Failed to power on hardware\n");
		goto err_regulator_on;
	}

	if (gpio_is_valid(reset_gpio)) {
		ret = gpio_request(reset_gpio, "cs4398dac_reset");
		if (ret) {
			dev_err(&client->dev,
				"unable to request gpio [%d]\n",
				reset_gpio);
			goto err_power_on;
		}

		ret = gpio_direction_output(reset_gpio, 1);
		if (ret) {
			dev_err(&client->dev,
				"unable to set direction for gpio [%d]\n",
				reset_gpio);
				goto err_reset_gpio_req;
		}
	} else {
		dev_err(&client->dev, "reset gpio not provided\n");
		goto err_power_on;
	}

	buffer[0] = 0x08;			//Misc. Control - register addr:0x08
	buffer[1] = CS4398_PDN | CS4398_CPEN;	//enable Control Port but keep power down - PDN:1, CPEN:1
	ret = i2c_master_send(client, buffer, 2);
	if (ret != 2) {
		ret = -EIO;
		goto err_reset_gpio_req;
	}

	msleep(10);

	buffer[0] = 0x08;			//Misc. Control - register addr:08h
	buffer[1] = CS4398_CPEN;		//Clear PDN for normal operation - PDN:0, CPEN:1
	ret = i2c_master_send(client, buffer, 2);
	if (ret != 2) {
		ret = -EIO;
		goto err_reset_gpio_req;
	}

	msleep(50);

	return 0;

err_reset_gpio_req:
	if (gpio_is_valid(reset_gpio))
		gpio_free(reset_gpio);
err_power_on:
	cs4398dac_power_on(data, false);
err_regulator_on:
	cs4398dac_regulator_configure(data, false);
err_free_mem:
	kfree(data);
	return ret;
}

static int __devexit cs4398dac_remove(struct i2c_client *client)
{
	struct cs4398dac_data *data = i2c_get_clientdata(client);

	cs4398dac_power_on(data, false);
	cs4398dac_regulator_configure(data, false);

	if (gpio_is_valid(reset_gpio))
		gpio_free(reset_gpio);

	kfree(data);

	return 0;
}

static const struct i2c_device_id cs4398dac_id[] = {
	{ "cs4398dac", 0 },
	{ }
};
MODULE_DEVICE_TABLE(i2c, cs4398dac_id);
#ifdef CONFIG_OF
static struct of_device_id cs4398dac_match_table[] = {
        { .compatible = "cirrus,cs4398dac", },
        { },
};
#else
#define cs4398dac_match_table NULL
#endif

static struct i2c_driver cs4398dac_driver = {
	.driver = {
		.name	= "cs4398dac",
		.owner	= THIS_MODULE,
		.of_match_table = cs4398dac_match_table,
	},
	.probe		= cs4398dac_probe,
	.remove		= __devexit_p(cs4398dac_remove),
	.suspend	= cs4398dac_suspend,
	.resume		= cs4398dac_resume,
	.id_table	= cs4398dac_id,
};

/*
 * module load/unload record keeping
 */

static int __init cs4398dac_dev_init(void)
{
	pr_debug("Loading cs4398 dac driver\n");
	return i2c_add_driver(&cs4398dac_driver);
}

module_init(cs4398dac_dev_init);

static void __exit cs4398dac_dev_exit(void)
{
	pr_debug("Unloading cs4398 dac driver\n");
	i2c_del_driver(&cs4398dac_driver);
}

module_exit(cs4398dac_dev_exit);

MODULE_AUTHOR("Chris Wang <wangjunkang@smartisan.cn>");
MODULE_DESCRIPTION("Cirrus Logic Multi-Bit DAC driver");
MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL");
