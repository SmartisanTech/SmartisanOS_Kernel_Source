/*
 * tlv320adc3001.c  --  TLV320ADC3001 ALSA Soc Audio driver
 *
 * Copyright 2015 Cirrus Logic, Inc.
 *
 * Authors: Tim Howe <Tim.Howe@cirrus.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/of_gpio.h>
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/gpio.h>
#include <linux/gpio/consumer.h>
#include <linux/platform_device.h>
#include <linux/pm.h>
#include <linux/i2c.h>
#include <linux/of_device.h>
#include <linux/regmap.h>
#include <linux/slab.h>
#include <sound/core.h>
#include <sound/pcm.h>
#include <sound/pcm_params.h>
#include <sound/soc.h>
#include <sound/soc-dapm.h>
#include <sound/initval.h>
#include <sound/tlv.h>
//#include "tlv320adc3001.h"

//static struct clk *pll_ref_clk;

static int cs4398_va;
/* Private data for the CS4398 */
struct  tlv320adc3001_private {
	struct regmap			*regmap;
	unsigned int			mode;
	int				rate;
	int				reset_gpio;
	int				power_gpio;
};

static int tlv320adc3001_i2c_probe(struct i2c_client *client,
				      const struct i2c_device_id *id)
{
	struct tlv320adc3001_private *tlv320adc3001;
	struct device_node *np = client->dev.of_node;
	u8 buffer[2];
	int ret;

	dev_err(&client->dev, "%s: enter\n", __func__);

	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		dev_err(&client->dev, "%s: need I2C_FUNC_I2C\n", __func__);
		return -ENODEV;
	}

	tlv320adc3001 = devm_kzalloc(&client->dev, sizeof(*tlv320adc3001), GFP_KERNEL);
	if (!tlv320adc3001)
		return -ENOMEM;

//	tlv320adc3001->regmap = devm_regmap_init_i2c(client, &tlv320adc3001_regmap);
//	if (IS_ERR(tlv320adc3001->regmap)) {
//		ret = PTR_ERR(tlv320adc3001->regmap);
//		dev_err(&client->dev, "regmap_init() failed: %d\n", ret);
//		return ret;
//	}
//
	tlv320adc3001->reset_gpio = of_get_named_gpio(np, "ti,reset-gpio", 0);
	if (gpio_is_valid(tlv320adc3001->reset_gpio)) {
		ret = devm_gpio_request_one(&client->dev, tlv320adc3001->reset_gpio,
					    GPIOF_OUT_INIT_HIGH, "TLV320ADC3001_RST");
		if (ret) {
			dev_err(&client->dev, "Failed to request tlv320adc3001 reset gpio %d \n",
				tlv320adc3001->reset_gpio);
		}
	}

	cs4398_va = of_get_named_gpio(np, "cs,va-enable", 0);
	if (gpio_is_valid(cs4398_va)) {
		ret = devm_gpio_request_one(&client->dev, cs4398_va,
					    GPIOF_OUT_INIT_HIGH, "CS4398_VA");
		if (ret) {
			dev_err(&client->dev, "Failed to request cs4398 ldo-en gpio %d \n",
				cs4398_va);
		}
	}

	tlv320adc3001->power_gpio = of_get_named_gpio(np, "hifi-ldo-en", 0);
	if (gpio_is_valid(tlv320adc3001->power_gpio)) {
		ret = devm_gpio_request_one(&client->dev, tlv320adc3001->power_gpio,
					    GPIOF_OUT_INIT_HIGH, "TLV320ADC3001_PWR");
		if (ret) {
			dev_err(&client->dev, "Failed to request tlv320adc3001 ldo-en gpio %d \n",
				tlv320adc3001->power_gpio);
		}
	}

	//ret = devm_gpio_request_one(&client->dev, tlv_reset_gpio,
	//			    GPIOF_OUT_INIT_LOW, "TLV320_RST");
	//if (ret) {
	//	dev_err(&client->dev, "Failed to request tlv320 reset gpio %d \n",
	//		tlv_reset_gpio);
	//}
	gpio_set_value_cansleep(tlv320adc3001->reset_gpio, 0);

	usleep_range(10, 15);

	gpio_set_value_cansleep(tlv320adc3001->reset_gpio, 1);

	usleep_range(100, 150);

	i2c_set_clientdata(client, tlv320adc3001);

	msleep(5);

	buffer[0] = 0x04;
	buffer[1] = 0x03;
	ret = i2c_master_send(client, buffer, 2);
	if (ret != 2) {
		dev_err(&client->dev, "%s: i2c write failed at addr %d\n", __func__, buffer[0]);
		ret = -EIO;
	}

	buffer[0] = 0x05;
	buffer[1] = 0x91;
	ret = i2c_master_send(client, buffer, 2);
	if (ret != 2) {
		dev_err(&client->dev, "%s: i2c write failed at addr %d\n", __func__, buffer[0]);
		ret = -EIO;
	}

	buffer[0] = 0x06;
	buffer[1] = 0x05;
	ret = i2c_master_send(client, buffer, 2);
	if (ret != 2) {
		dev_err(&client->dev, "%s: i2c write failed at addr %d\n", __func__, buffer[0]);
		ret = -EIO;
	}

	buffer[0] = 0x07;
	buffer[1] = 0x04;
	ret = i2c_master_send(client, buffer, 2);
	if (ret != 2) {
		dev_err(&client->dev, "%s: i2c write failed at addr %d\n", __func__, buffer[0]);
		ret = -EIO;
	}

	buffer[0] = 0x08;
	buffer[1] = 0xB0;
	ret = i2c_master_send(client, buffer, 2);
	if (ret != 2) {
		dev_err(&client->dev, "%s: i2c write failed at addr %d\n", __func__, buffer[0]);
		ret = -EIO;
	}

	buffer[0] = 0x12; //reg 18
	buffer[1] = 0x88; //0x88
	ret = i2c_master_send(client, buffer, 2);
	if (ret != 2) {
		dev_err(&client->dev, "%s: i2c write failed at addr %d\n", __func__, buffer[0]);
		ret = -EIO;
	}

	buffer[0] = 0x13;  //reg 19
	buffer[1] = 0x82;
	ret = i2c_master_send(client, buffer, 2);
	if (ret != 2) {
		dev_err(&client->dev, "%s: i2c write failed at addr %d\n", __func__, buffer[0]);
		ret = -EIO;
	}

	buffer[0] = 0x14;  //reg 20
	buffer[1] = 0x80;
	ret = i2c_master_send(client, buffer, 2);
	if (ret != 2) {
		dev_err(&client->dev, "%s: i2c write failed at addr %d\n", __func__, buffer[0]);
		ret = -EIO;
	}

	buffer[0] = 0x19;  //reg 25
	buffer[1] = 0x06;
	ret = i2c_master_send(client, buffer, 2);
	if (ret != 2) {
		dev_err(&client->dev, "%s: i2c write failed at addr %d\n", __func__, buffer[0]);
		ret = -EIO;
	}

	buffer[0] = 0x1A;  //reg 26
	buffer[1] = 0x81;
	ret = i2c_master_send(client, buffer, 2);
	if (ret != 2) {
		dev_err(&client->dev, "%s: i2c write failed at addr %d\n", __func__, buffer[0]);
		ret = -EIO;
	}

	buffer[0] = 0x1B;  //reg 27
	buffer[1] = 0x3C;
	ret = i2c_master_send(client, buffer, 2);
	if (ret != 2) {
		dev_err(&client->dev, "%s: i2c write failed at addr %d\n", __func__, buffer[0]);
		ret = -EIO;
	}

	buffer[0] = 0x1D;  //reg 29
	buffer[1] = 0x06;
	ret = i2c_master_send(client, buffer, 2);
	if (ret != 2) {
		dev_err(&client->dev, "%s: i2c write failed at addr %d\n", __func__, buffer[0]);
		ret = -EIO;
	}

	buffer[0] = 0x1E;  //reg 30
	buffer[1] = 0x84;  //0x84
	ret = i2c_master_send(client, buffer, 2);
	if (ret != 2) {
		dev_err(&client->dev, "%s: i2c write failed at addr %d\n", __func__, buffer[0]);
		ret = -EIO;
	}

	buffer[0] = 0x35;  //reg 53
	buffer[1] = 0x16;
	ret = i2c_master_send(client, buffer, 2);
	if (ret != 2) {
		dev_err(&client->dev, "%s: i2c write failed at addr %d\n", __func__, buffer[0]);
		ret = -EIO;
	} else {
		ret = 0;
	}

	msleep(5);

	/*
	if (of_property_read_bool(np, "qcom,node_has_rpm_clock")) {
		pll_ref_clk = clk_get(&client->dev, "pll_ref_clk");
		if (IS_ERR(pll_ref_clk)) {
			dev_err(&client->dev, "Failed to get RPM div clk3\n");
			ret = PTR_ERR(pll_ref_clk);
		}
	}

	ret = clk_prepare_enable(pll_ref_clk);
	if (ret) {
		dev_err(&client->dev, "%s: div clk3 enable failed\n",
			__func__);
	}
	*/


//	return snd_soc_register_codec(&client->dev, &soc_codec_dev_tlv320adc3001,
//		&tlv320adc3001_dai, 1);

	return ret;
}

static int tlv320adc3001_i2c_remove(struct i2c_client *client)
{
	struct tlv320adc3001_private *tlv320adc3001 = i2c_get_clientdata(client);

//	snd_soc_unregister_codec(&client->dev);

	/* Hold down reset */
	gpio_set_value_cansleep(tlv320adc3001->reset_gpio, 0);
	/* Power down */
	gpio_set_value_cansleep(tlv320adc3001->power_gpio, 0);

	//clk_disable_unprepare(pll_ref_clk);
	//clk_put(pll_ref_clk);
	return 0;
}

static const struct of_device_id tlv320adc3001_of_match[] = {
	{ .compatible = "ti,tlv320adc3001", },
	{},
};

MODULE_DEVICE_TABLE(of, tlv320adc3001_of_match);

static const struct i2c_device_id tlv320adc3001_i2c_id[] = {
	{"tlv320adc3001", 0},
	{}
};

MODULE_DEVICE_TABLE(i2c, tlv320adc3001_i2c_id);

static struct i2c_driver tlv320adc3001_i2c_driver = {
	.driver = {
		.name = "tlv320adc3001",
		.of_match_table	= tlv320adc3001_of_match,
	},
	.id_table	= tlv320adc3001_i2c_id,
	.probe		= tlv320adc3001_i2c_probe,
	.remove		= tlv320adc3001_i2c_remove,
};

module_i2c_driver(tlv320adc3001_i2c_driver);

MODULE_AUTHOR("wangjunkang<wangjunkang@smartisan.com>");
MODULE_DESCRIPTION("ASoC TLV320ADC3001 Codec Driver");
MODULE_LICENSE("GPL");
