/*
 * Cirrus Logic Asynchronous Sample Rate Converter driver
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

#define CS8422_ANA_VTG_UV	3300000
#define CS8422_LOG_VTG_UV	1800000
#define CS8422_ANA_LOAD_UA	18900
#define CS8422_LOG_LOAD_UA	3100

struct cs8422src_data {
	struct i2c_client *client;
	struct regulator *vcc_ana;
	struct regulator *vcc_log1;
	struct regulator *vcc_log2;
};

static int src_reset_gpio = 0;
static int dac_reset_gpio = 0;


static int cs8422src_suspend(struct i2c_client *client, pm_message_t mesg)
{
	return 0;
}

static int cs8422src_resume(struct i2c_client *client)
{
	return 0;
}

/*
#ifdef CONFIG_OF
static int cs8422src_parse_dt(struct device *dev,
				struct cs8422src_i2c_platform_data *cs8422_pdata)
{
	struct device_node *np = dev->of_node;
	return 0;
}
#else
static inline int cs8422src_parse_dt(struct device *dev,
				struct cs8422src_i2c_platform_data *cs8422_pdata)
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

static int cs8422src_power_on(struct cs8422src_data *data, bool on)
{
	int ret;

	if (on == false)
		goto power_off;

	ret = reg_set_optimum_mode_check(data->vcc_ana, CS8422_ANA_LOAD_UA);
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

	ret = reg_set_optimum_mode_check(data->vcc_log1, CS8422_LOG_LOAD_UA);
	if (ret < 0) {
		dev_err(&data->client->dev,
			"Regulator vcc_log set_opt failed ret=%d\n", ret);
		goto error_reg_opt_vcc_log1;
	}

	ret = regulator_enable(data->vcc_log1);
	if (ret) {
		dev_err(&data->client->dev,
			"Regulator vcc_log enable failed ret=%d\n", ret);
		goto error_reg_en_vcc_log1;
	}

	ret = reg_set_optimum_mode_check(data->vcc_log2, CS8422_LOG_LOAD_UA);
	if (ret < 0) {
		dev_err(&data->client->dev,
			"Regulator vcc_log set_opt failed ret=%d\n", ret);
		goto error_reg_opt_vcc_log2;
	}

	ret = regulator_enable(data->vcc_log2);
	if (ret) {
		dev_err(&data->client->dev,
			"Regulator vcc_log enable failed ret=%d\n", ret);
		goto error_reg_en_vcc_log2;
	}

	msleep(100);

	return 0;

error_reg_en_vcc_log2:
	reg_set_optimum_mode_check(data->vcc_log2, 0);
error_reg_opt_vcc_log2:
	regulator_disable(data->vcc_log1);
error_reg_en_vcc_log1:
	reg_set_optimum_mode_check(data->vcc_log1, 0);
error_reg_opt_vcc_log1:
	regulator_disable(data->vcc_ana);
error_reg_en_vcc_ana:
	reg_set_optimum_mode_check(data->vcc_ana, 0);
	return ret;

power_off:
	reg_set_optimum_mode_check(data->vcc_ana, 0);
	regulator_disable(data->vcc_ana);
	reg_set_optimum_mode_check(data->vcc_log1, 0);
	regulator_disable(data->vcc_log1);
	reg_set_optimum_mode_check(data->vcc_log2, 0);
	regulator_disable(data->vcc_log2);

	msleep(50);
	return 0;
}

static int cs8422src_regulator_configure(struct cs8422src_data *data, bool on)
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
		ret = regulator_set_voltage(data->vcc_ana, CS8422_ANA_VTG_UV,
							CS8422_ANA_VTG_UV);
		if (ret) {
			dev_err(&data->client->dev,
				"regulator set_vtg failed ret=%d\n", ret);
			goto error_set_vtg_vcc_ana;
		}
	}

	data->vcc_log1 = regulator_get(&data->client->dev, "vdd_log1");
	if (IS_ERR(data->vcc_log1)) {
		ret = PTR_ERR(data->vcc_log1);
		dev_err(&data->client->dev,
			"Regulator get failed vcc_log1 ret=%d\n", ret);
		goto error_get_vtg_vcc_log1;
	}

	if (regulator_count_voltages(data->vcc_log1) > 0) {
		ret = regulator_set_voltage(data->vcc_log1, CS8422_LOG_VTG_UV,
							CS8422_LOG_VTG_UV);
		if (ret) {
			dev_err(&data->client->dev,
				"regulator set_vtg failed ret=%d\n", ret);
			goto error_set_vtg_vcc_log1;
		}
	}

	data->vcc_log2 = regulator_get(&data->client->dev, "vdd_log2");
	if (IS_ERR(data->vcc_log2)) {
		ret = PTR_ERR(data->vcc_log2);
		dev_err(&data->client->dev,
			"Regulator get failed vcc_log2 ret=%d\n", ret);
		goto error_get_vtg_vcc_log2;
	}

	if (regulator_count_voltages(data->vcc_log2) > 0) {
		ret = regulator_set_voltage(data->vcc_log2, CS8422_LOG_VTG_UV,
							CS8422_LOG_VTG_UV);
		if (ret) {
			dev_err(&data->client->dev,
				"regulator set_vtg failed ret=%d\n", ret);
			goto error_set_vtg_vcc_log2;
		}
	}

	return 0;

error_set_vtg_vcc_log2:
	regulator_put(data->vcc_log2);
error_get_vtg_vcc_log2:
	if (regulator_count_voltages(data->vcc_log1) > 0)
		regulator_set_voltage(data->vcc_log1, 0, CS8422_LOG_VTG_UV);
error_set_vtg_vcc_log1:
	regulator_put(data->vcc_log1);
error_get_vtg_vcc_log1:
	if (regulator_count_voltages(data->vcc_ana) > 0)
		regulator_set_voltage(data->vcc_ana, 0, CS8422_ANA_VTG_UV);
error_set_vtg_vcc_ana:
	regulator_put(data->vcc_ana);
	return ret;

hw_shutdown:
	if (regulator_count_voltages(data->vcc_ana) > 0)
		regulator_set_voltage(data->vcc_ana, 0, CS8422_ANA_VTG_UV);
	regulator_put(data->vcc_ana);
	if (regulator_count_voltages(data->vcc_log1) > 0)
		regulator_set_voltage(data->vcc_log1, 0, CS8422_LOG_VTG_UV);
	regulator_put(data->vcc_log1);
	if (regulator_count_voltages(data->vcc_log2) > 0)
		regulator_set_voltage(data->vcc_log2, 0, CS8422_LOG_VTG_UV);
	regulator_put(data->vcc_log2);
	return 0;
}

static int __devinit cs8422src_probe(struct i2c_client *client,
			const struct i2c_device_id *id)
{
	int ret;

	struct cs8422src_data *data;
/*
	if (client->dev.of_node) {
		platform_data = devm_kzalloc(&client->dev,
			sizeof(*platform_data), GFP_KERNEL);
                if (!platform_data) {
                        dev_err(&client->dev, "Failed to allocate memory\n");
                        return -ENOMEM;
                }

		ret = cs8422src_parse_dt(&client->dev, platform_data);
                if (ret)
                        return ret;
	} else {
		platform_data = client->dev.platform_data;
	}

	pr_debug("%s : clientptr %p\n", __func__, client);

	if (platform_data == NULL) {
		pr_err("%s : cs8422src probe fail\n", __func__);
		return -ENODEV;
	}
*/
	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		pr_err("%s : need I2C_FUNC_I2C\n", __func__);
		return -ENODEV;
	}

	data = kzalloc(sizeof(struct cs8422src_data), GFP_KERNEL);
	if (!data) {
		dev_err(&client->dev, "Failed to allocate memory\n");
		ret = -ENOMEM;
		goto err_free_mem;
	}

	data->client = client;
	i2c_set_clientdata(client, data);

	ret = cs8422src_regulator_configure(data, true);
	if (ret) {
		dev_err(&client->dev, "Failed to intialize regulator\n");
		goto err_free_mem;
	}

	if (client->dev.of_node) {
		src_reset_gpio = of_get_named_gpio_flags(client->dev.of_node,
						"cirrus,src-reset-gpio", 0, NULL);
		dac_reset_gpio = of_get_named_gpio_flags(client->dev.of_node,
						"cirrus,dac-reset-gpio", 0, NULL);
	}

	if (gpio_is_valid(src_reset_gpio)) {
		ret = gpio_request(src_reset_gpio, "cs8422src_reset");
		if (ret) {
			dev_err(&client->dev,
				"unable to request gpio [%d]\n",
				src_reset_gpio);
			goto err_regulator_on;
		}
		ret = gpio_direction_output(src_reset_gpio, 0);
		if (ret) {
			dev_err(&client->dev,
				"unable to set direction for gpio [%d]\n",
				src_reset_gpio);
			goto err_src_reset_gpio_req;
		}
	} else {
		dev_err(&client->dev, "reset gpio not provided\n");
		goto err_regulator_on;
	}

	if (gpio_is_valid(dac_reset_gpio)) {
		ret = gpio_request(dac_reset_gpio, "cs4398dac_reset");
		if (ret) {
			dev_err(&client->dev,
				"unable to request gpio [%d]\n",
				dac_reset_gpio);
			goto err_src_reset_gpio_req;
		}
		ret = gpio_direction_output(dac_reset_gpio, 0);
		if (ret) {
			dev_err(&client->dev,
				"unable to set direction for gpio [%d]\n",
				dac_reset_gpio);
			goto err_dac_reset_gpio_req;
		}
		msleep(50);
	} else {
		dev_err(&client->dev, "reset gpio not provided\n");
		goto err_src_reset_gpio_req;
	}

	ret = cs8422src_power_on(data, true);
	if (ret) {
		dev_err(&client->dev, "Failed to power on hardware\n");
		goto err_dac_reset_gpio_req;
	}

	if (gpio_is_valid(src_reset_gpio)) {
		ret = gpio_direction_output(src_reset_gpio, 1);
		if (ret) {
			dev_err(&client->dev,
				"unable to set direction for gpio [%d]\n",
				src_reset_gpio);
				goto err_power_on;
		}
	} else {
		dev_err(&client->dev, "reset gpio not provided\n");
		goto err_power_on;
	}

	gpio_free(dac_reset_gpio);

	msleep(50);

	return 0;

err_power_on:
	cs8422src_power_on(data, false);
err_dac_reset_gpio_req:
	if (gpio_is_valid(dac_reset_gpio))
		gpio_free(dac_reset_gpio);
err_src_reset_gpio_req:
	if (gpio_is_valid(src_reset_gpio))
		gpio_free(src_reset_gpio);
err_regulator_on:
	cs8422src_regulator_configure(data, false);
err_free_mem:
	kfree(data);
	return ret;
}

static int __devexit cs8422src_remove(struct i2c_client *client)
{
	struct cs8422src_data *data = i2c_get_clientdata(client);

	cs8422src_power_on(data, false);
	cs8422src_regulator_configure(data, false);

	if (gpio_is_valid(src_reset_gpio))
		gpio_free(src_reset_gpio);

	kfree(data);

	return 0;
}

static const struct i2c_device_id cs8422src_id[] = {
	{ "cs8422src", 0 },
	{ }
};
MODULE_DEVICE_TABLE(i2c, cs8422src_id);
#ifdef CONFIG_OF
static struct of_device_id cs8422src_match_table[] = {
        { .compatible = "cirrus,cs8422src", },
        { },
};
#else
#define cs8422src_match_table NULL
#endif

static struct i2c_driver cs8422src_driver = {
	.driver = {
		.name	= "cs8422src",
		.owner	= THIS_MODULE,
		.of_match_table = cs8422src_match_table,
	},
	.probe		= cs8422src_probe,
	.remove		= __devexit_p(cs8422src_remove),
	.suspend	= cs8422src_suspend,
	.resume		= cs8422src_resume,
	.id_table	= cs8422src_id,
};

/*
 * module load/unload record keeping
 */

static int __init cs8422src_dev_init(void)
{
	int ret;

	ret = i2c_add_driver(&cs8422src_driver);
	if (ret) {
		pr_err("i2c_add_driver cs8422 src driver failed!\n");
		return ret;
	}

	return ret;
}

module_init(cs8422src_dev_init);

static void __exit cs8422src_dev_exit(void)
{
	pr_debug("Unloading cs8422 src driver\n");
	i2c_del_driver(&cs8422src_driver);
}

module_exit(cs8422src_dev_exit);

MODULE_AUTHOR("Chris Wang <wangjunkang@smartisan.cn>");
MODULE_DESCRIPTION("Cirrus Logic ASRC driver");
MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL");
