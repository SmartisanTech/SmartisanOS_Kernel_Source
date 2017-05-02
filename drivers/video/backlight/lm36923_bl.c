/*
 * Simple driver for multi-string single control backlight driver chips of
 * Texas Instruments.
 *
 * Copyright (C) 2015 Texas Instruments
 * Author: Daniel Jeong  <gshark.jeong@gmail.com>
 *         Ldd Mlp <ldd-mlp@list.ti.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/i2c.h>
#include <linux/backlight.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/i2c.h>
#include <linux/platform_data/ti-scbl.h>
#include <linux/regmap.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/gpio.h>

#define scbl_attr(_name, _show, _store)\
{\
	.attr = {\
		.name = _name,\
		.mode = S_IWUSR | S_IRUSR,\
	},\
	.show = _show,\
	.store = _store,\
}

int bl_en_gpio = 25;
int bl_level_curent = 0;
bool ic_state = 0;
struct scbl_chip *pchip_globle = NULL;
#define ID_SUR_LCD 50

struct scbl_reg_ctrl {
	unsigned int reg;
	unsigned int mask;
	unsigned int shift;
};

/*
 *brightness control 
 *@min : minimum brightness
 *@max : maximum brightness
 *@msb_shift : msb bit shfit
 *@lsb_mask  : lsb bit mask
 *@msb : register for the upper 8bits of the brightness code
 *@lsb : register for the lower 8bits of the brightness code
 */
struct scbl_brt_ctrl {
	unsigned int min;
	unsigned int max;
	unsigned int msb_shift;
	unsigned int lsb_mask;
	struct scbl_reg_ctrl msb;
	struct scbl_reg_ctrl lsb;
};

/*
 *fault data
 *@reg : fault register
 *@mask: mask bit of fault
 *@bl_fault : backlight fault mapped the bit
 */
struct scbl_fault {
	unsigned int reg;
	unsigned int mask;
	unsigned int bl_fault;
};

/*
 *single control backlight data
 *@name    : chip name
 *@num_led : number of led string
 *@en_chip : chip enable register
 *@en_led  : led string enable register
 *@brt     : brightness register
 *@fault   : fault register
 *@boot    : function that should be called before chip enable
 *@init    : function that should be called after chip enable
 *@reset   : reset function
 *@num_devnode   : number of device node to be created
 *@scbl_dev_attr : device node attribute
 */
struct scbl_data {
	char *name;

	int num_led;
	struct scbl_reg_ctrl en_chip;
	struct scbl_reg_ctrl en_led[SCBL_LED_MAX];

	struct scbl_brt_ctrl brt;
	struct scbl_fault fault[SCBL_FAULT_MAX];

	int (*boot)(struct regmap* regmap);
	int (*init)(struct regmap* regmap);
	int (*reset)(struct regmap* regmap);
	
	int num_devnode;
	struct device_attribute *scbl_dev_attr;
};

/*
 *chip data
 *@dev   : device
 *@regmap: register map
 *@bled  : backlight device
 *@data  : single control backlight data
 */
struct scbl_chip {
	struct device *dev;
	struct regmap *regmap;

	struct backlight_device *bled;
	const struct scbl_data *data; 
};

/* chip reset */
static ssize_t scbl_reset_store(struct device *dev,
				  struct device_attribute *attr,
				  const char *buf, size_t size)
{
	struct scbl_chip *pchip = dev_get_drvdata(dev);
	const struct scbl_data *data = pchip->data; 
	u8 input;
	int ret;

	if (kstrtou8(buf, 0, &input))
		return -EINVAL;

	if (input == 1) {
		ret = data->reset(pchip->regmap);
		if (ret<0)
			return ret;
	}
	return size;
}

/* fault status */
static ssize_t scbl_fault_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct scbl_chip *pchip = dev_get_drvdata(dev);
	const struct scbl_data *data = pchip->data; 
	unsigned int reg_val, reg = 0xfff;
	s32 fault = 0x0000;
	int ret, icnt;

	for(icnt = 0; icnt < SCBL_FAULT_MAX; icnt++) {
		if(data->fault[icnt].mask == 0x00)
			continue;
		if(data->fault[icnt].reg != reg) {
			reg = data->fault[icnt].reg;
			ret = regmap_read(pchip->regmap, reg, &reg_val);
			if (ret < 0) {
				dev_err(pchip->dev, 
						"fail : i2c access to register.\n");
				return sprintf(buf, "%d\n", ret);
			}
		}
		if (reg_val & data->fault[icnt].mask)
			fault |= data->fault[icnt].bl_fault;		
	}
	return sprintf(buf, "%d\n", fault);
}

/* chip enable control */
static ssize_t scbl_enable_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	struct scbl_chip *pchip = dev_get_drvdata(dev);
	const struct scbl_data *data = pchip->data; 
	unsigned int reg_val;
	int ret;

	ret = regmap_read(pchip->regmap, data->en_chip.reg, &reg_val);
	if (ret <0) {		
		return sprintf(buf, "%d\n", -EINVAL);
	}
	return sprintf(buf, "%d\n",
			(reg_val & data->en_chip.mask) >> data->en_chip.shift);
}

static ssize_t scbl_enable_store(struct device *dev,
				   struct device_attribute *attr,
				   const char *buf, size_t size)
{
	struct scbl_chip *pchip = dev_get_drvdata(dev);
	const struct scbl_data *data = pchip->data; 
	int ret;
	u8 input;

	if (kstrtou8(buf, 0, &input))
		return -EINVAL;

	if (input == 0)
		ret = regmap_update_bits(pchip->regmap,
					data->en_chip.reg, data->en_chip.mask, 0x00);
	else
		ret = regmap_update_bits(pchip->regmap, data->en_chip.reg,
					data->en_chip.mask, 0x01 << data->en_chip.shift);
	if(ret <0)
		return ret;

	return size;
}

/* brightness control */
#if 0
static int scbl_update_status(struct backlight_device *bl)
{
	struct scbl_chip *pchip = bl_get_data(bl);
	const struct scbl_data *data = pchip->data; 
	int ret = -EINVAL;
	int msb, lsb;

	printk("%s\n", __func__);
	if (bl->props.state & (BL_CORE_SUSPENDED | BL_CORE_FBBLANK))
		bl->props.brightness = 0;
	
	/* lsb write first */
	if(data->brt.lsb_mask != 0x00) {
		msb = bl->props.brightness >> data->brt.msb_shift ;
		lsb = bl->props.brightness & data->brt.lsb_mask ;

		ret = regmap_update_bits(pchip->regmap, data->brt.lsb.reg,
					data->brt.lsb.mask, lsb << data->brt.lsb.shift);
	} else {
		msb = bl->props.brightness;
	}

	/* msb write */
	ret = regmap_update_bits(pchip->regmap, data->brt.msb.reg,
				data->brt.msb.mask, msb << data->brt.msb.shift);

	if (ret < 0)
		dev_err(pchip->dev, "fail : i2c access to register.\n");
	else
		ret = bl->props.brightness;

	return ret;
}

static int scbl_get_brightness(struct backlight_device *bl)
{
	return bl->props.brightness;
}

static const struct backlight_ops scbl_bled_ops = {
	.options = BL_CORE_SUSPENDRESUME,
	.update_status = scbl_update_status,
	.get_brightness = scbl_get_brightness,
};
#endif

/*
 * LP36923 backlight chip data
 *  lp36923 is an ultra-compact, highly efficient, three string white-LED
 * driver.
 */
static struct device_attribute lm36923_dev_attr[] = {
	scbl_attr("fault", scbl_fault_show, NULL),
	scbl_attr("reset", NULL, scbl_reset_store),
	scbl_attr("enable", scbl_enable_show, scbl_enable_store),
};

static int scbl_lm36923_reset(struct regmap *regmap)
{
	return regmap_update_bits(regmap, 0x01, 0x01, 0x01);
}

static int scbl_lm36923_boot(struct regmap *regmap)
{
	int rval;

	rval = regmap_update_bits(regmap, 0x10, 0x0f, 0x00);
	/* 
	 * For glitch free operation, the following data should
	 * only be written while chine enable bit is 0
	 */
	/* mapping mode / brt mode / ramp / ramp rate / bl_adj polarity */
	rval |= regmap_write(regmap, 0x11, 0x41);
	/* pwm */
	rval |= regmap_write(regmap, 0x12, 0xe0);
	/* auto frequency high threshold */
	rval |= regmap_write(regmap, 0x15, 0x00);
	/* auto frequency low threshold */
	rval |= regmap_write(regmap, 0x16, 0x00);
	/* backlight adjust threshold */
	rval |= regmap_write(regmap, 0x17, 0x00);
	/* set brightness */
	rval |= regmap_write(regmap, 0x18, 0x00);
	rval |= regmap_write(regmap, 0x19, 0x00);
	/* chip and leds enable */
	rval |= regmap_update_bits(regmap, 0x10, 0x0f, 0x0f);
	return rval;
}

struct scbl_data bl_lm36923 = {
	.name = LM36923_NAME,
	.num_led = 2,
	.en_chip = {.reg = 0x10, .mask = 0x01, .shift = 0},
	.en_led = {
		[0] = {.reg = 0x10, .mask = 0x02, .shift = 1},
		[1] = {.reg = 0x10, .mask = 0x04, .shift = 2},
		//[2] = {.reg = 0x10, .mask = 0x08, .shift = 3},
	},
	.brt = {
		.min = 0x00, .max = 0x7ff,
		.msb_shift = 3, .lsb_mask = 0x07,
		.msb = {.reg = 0x19, .mask = 0xff, .shift = 0},
		.lsb = {.reg = 0x18, .mask = 0x07, .shift = 0},
	},
	.fault = {
		[0] = {
			.reg = 0x1f, .mask = 0x01, 
			.bl_fault = SCBL_FAULT_OVER_VOLTAGE
		},	
		[1] = {
			.reg = 0x1f, .mask = 0x02,
			.bl_fault = SCBL_FAULT_OVER_CURRENT
		},	
		[2] = {
			.reg = 0x1f, .mask = 0x04,
			.bl_fault = SCBL_FAULT_THERMAL_SHDN
		},	
		[3] = {
			.reg = 0x1f, .mask = 0x08,
			.bl_fault = SCBL_FAULT_LED_SHORT
		},	
		[4] = {
			.reg = 0x1f, .mask = 0x10,
			.bl_fault = SCBL_FAULT_LED_OPEN
		},	
	},
	.boot = scbl_lm36923_boot,
	.init = NULL,
	.reset = scbl_lm36923_reset,
	.num_devnode = 3,
	.scbl_dev_attr = lm36923_dev_attr,
};

int scbl_set_brightness(int bl_level)
{
	int ret = 0;
	int msb, lsb;
	static int delay_count = 0;
	int bl_diff = 0;

	pr_debug("%s: bl_level = %d\n", __func__, bl_level);
	bl_level = (bl_level * 1473 / 1024);
	pr_debug("%s: bl_level_cal = %d\n", __func__, bl_level);
	if (ic_state == false)
		return 0;

	if (bl_level == 0)
	{
		gpio_set_value(bl_en_gpio, 0);
		bl_level_curent = bl_level;
		return 0;
	}
	else if (bl_level == -1)
	{
		gpio_set_value(bl_en_gpio, 1);
		pchip_globle->data->boot(pchip_globle->regmap);
		return 0;
	}
	else if (bl_level_curent == 0)
	{
		gpio_set_value(bl_en_gpio, 1);
		pchip_globle->data->boot(pchip_globle->regmap);
		delay_count = 0;
	}

	if (delay_count < 2)
	{
		bl_diff = abs(bl_level - bl_level_curent);
		if ((delay_count == 1) && (bl_diff < 7))
		{
			bl_level = bl_level_curent + 10;
			printk("LM36923 change bl_level\n");
		}
		delay_count ++;
	}
	if (bl_level < 8)
		bl_level = 8; // avoid can't light up issue

	/* lsb write first */
	if(bl_lm36923.brt.lsb_mask != 0x00) {
		msb = bl_level >> bl_lm36923.brt.msb_shift ;
		lsb = bl_level & bl_lm36923.brt.lsb_mask ;

		ret = regmap_update_bits(pchip_globle->regmap, bl_lm36923.brt.lsb.reg,
					bl_lm36923.brt.lsb.mask, lsb << bl_lm36923.brt.lsb.shift);
	} else {
		msb = bl_level;
	}

	/* msb write */
	ret = regmap_update_bits(pchip_globle->regmap, bl_lm36923.brt.msb.reg,
				bl_lm36923.brt.msb.mask, msb << bl_lm36923.brt.msb.shift);

	if (ret < 0)
	{
		dev_err(pchip_globle->dev, "fail : i2c access to register.\n");
		gpio_set_value(bl_en_gpio, 1);
		pchip_globle->data->boot(pchip_globle->regmap);
	}
	else
		ret = bl_level;

	bl_level_curent = bl_level;
	return ret;
}

static const struct regmap_config scbl_regmap = {
	.reg_bits = 8,
	.val_bits = 8,
	.max_register = SCBL_REG_MAX,
};

static int scbl_probe(struct i2c_client *client,
			const struct i2c_device_id *devid)
{
	struct scbl_chip *pchip;
	struct backlight_properties props;
	int ret, icnt;

	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		dev_err(&client->dev, "fail : i2c functionality check.\n");
		return -EOPNOTSUPP;
	}

	pchip = devm_kzalloc(&client->dev,
			     sizeof(struct scbl_chip), GFP_KERNEL);
	if (!pchip)
		return -ENOMEM;
	pchip->dev = &client->dev;

	pchip->regmap = devm_regmap_init_i2c(client, &scbl_regmap);
	if (IS_ERR(pchip->regmap)) {
		ret = PTR_ERR(pchip->regmap);
		dev_err(pchip->dev, "fail : allocate i2c register map.\n");
		//return ret;
	}

	pchip->data = (const struct scbl_data *)devid->driver_data;
	i2c_set_clientdata(client, pchip);

	props.brightness = 0;
	props.type = BACKLIGHT_RAW;
	props.max_brightness = pchip->data->brt.max;
	pchip->bled = devm_backlight_device_register(pchip->dev,
						     pchip->data->name,
							 pchip->dev,
						     pchip, NULL,//&scbl_bled_ops,
						     &props);
	if (IS_ERR(pchip->bled)) {
		dev_err(pchip->dev, "fail : backlight register.\n");
		ret = PTR_ERR(pchip->bled);
		return ret;
	}

	for (icnt = 0; icnt < pchip->data->num_devnode; icnt++) {
		ret =
		    device_create_file(&(pchip->bled->dev),
					      &(pchip->data->scbl_dev_attr)[icnt]);
		if (ret < 0) {
			dev_err(pchip->dev, "fail : node create\n");
			goto err_out;
		}
	}
	ret = gpio_request(bl_en_gpio, "bl_en_gpio");
	if (ret) {
		printk("bl_lm36923 request bl_en_gpio failed\n");
	}
	else
	{
		gpio_set_value(bl_en_gpio, 1);
		msleep(2);
	}

	/* chip boot sequence before chip enable */
	if (0)  //Need not re-enable if lk splash enabled
	{
		if(pchip->data->boot != NULL) {
			ret = pchip->data->boot(pchip->regmap);
			if (ret < 0)
				goto err_out;
		}
		/* chip enable */
		ret = regmap_update_bits(pchip->regmap, pchip->data->en_chip.reg,
				pchip->data->en_chip.mask,
				0x01<<pchip->data->en_chip.shift);

		/* chip init sequence after chip enable */
		if(pchip->data->init != NULL) {
			ret = pchip->data->boot(pchip->regmap);
			if (ret < 0)
				goto err_out;
		}
	}
	dev_info(pchip->dev, "[%s] initialized.\n",	pchip->data->name);
	pchip_globle = pchip;
	ic_state = true;
	return 0;

err_out:
	while (--icnt >= 0)
		device_remove_file(&(pchip->bled->dev),
						      &(pchip->data->scbl_dev_attr)[icnt]);
	dev_info(pchip->dev, "[%s] init failed.\n",	pchip->data->name);
	gpio_free(bl_en_gpio);
	return ret;
}

static int scbl_remove(struct i2c_client *client)
{
	struct scbl_chip *pchip = i2c_get_clientdata(client);
	int icnt;

	for (icnt = 0; icnt < pchip->data->num_devnode; icnt++)
		device_remove_file(&(pchip->bled->dev),
						      &(pchip->data->scbl_dev_attr)[icnt]);
	gpio_free(bl_en_gpio);
	return 0;
}

static const struct i2c_device_id scbl_id[] = {
	{LM36923_NAME, (unsigned long)&bl_lm36923},
	{}
};

MODULE_DEVICE_TABLE(i2c, scbl_id);

static struct of_device_id lm36923_match_table[] = {
	{ .compatible = "lm36923"},
	{ },
};

static struct i2c_driver scbl_i2c_driver = {
	.driver = {
		.name = "lm36923",
		.owner	= THIS_MODULE,
		.of_match_table = lm36923_match_table,
	},
	.probe = scbl_probe,
	.remove = scbl_remove,
	.id_table = scbl_id,
};

//module_i2c_driver(scbl_i2c_driver);

static int __init lm36923_dev_init(void)
{
	return i2c_add_driver(&scbl_i2c_driver);
}
//module_init(lm36923_dev_init);
late_initcall(lm36923_dev_init);

static void __exit lm36923_dev_exit(void)
{
	i2c_del_driver(&scbl_i2c_driver);
}
module_exit(lm36923_dev_exit);

MODULE_DESCRIPTION("Texas Instruments Single Control Backlight Driver");
MODULE_AUTHOR("Daniel Jeong <gshark.jeong@gmail.com>");
MODULE_AUTHOR("Ldd Mlp <ldd-mlp@list.ti.com>");
MODULE_LICENSE("GPL v2");
