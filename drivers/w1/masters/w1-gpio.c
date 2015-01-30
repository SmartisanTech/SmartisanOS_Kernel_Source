/*
 * w1-gpio - GPIO w1 bus master driver
 *
 * Copyright (C) 2007 Ville Syrjala <syrjala@sci.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/w1-gpio.h>
#include <linux/gpio.h>
#include <linux/of_device.h>
#include <linux/of_gpio.h>
#include "../w1.h"
#include "../w1_int.h"


#if 0
#define GPIO_W1_PULL_ENABLE (105)

static void w1_enable_external_pullup(int enable)
{
	gpio_set_value(GPIO_W1_PULL_ENABLE, enable);
	msleep(100);
}
#endif

#ifdef CONFIG_OF
static struct w1_gpio_platform_data w1_gpio_data = {
	.pin = 49/*32 49*/,
	.is_open_drain = 0,
	.enable_external_pullup = NULL/*w1_enable_external_pullup*/,
};

static const struct of_device_id w1_gpio_match[] = {
	{.compatible = "qcom,w1-gpio", .data = &w1_gpio_data},
	{}
};
#endif

static void w1_gpio_write_bit_dir(void *data, u8 bit)
{
	struct w1_gpio_platform_data *pdata = data;

	if (bit)
		gpio_direction_input(pdata->pin);
	else
		gpio_direction_output(pdata->pin, 0);
}

static void w1_gpio_write_bit_val(void *data, u8 bit)
{
	struct w1_gpio_platform_data *pdata = data;

	gpio_set_value(pdata->pin, bit);
}

static u8 w1_gpio_read_bit(void *data)
{
	struct w1_gpio_platform_data *pdata = data;

	return gpio_get_value(pdata->pin) ? 1 : 0;
}

static int __init w1_gpio_probe(struct platform_device *pdev)
{
	struct w1_bus_master *master;
	int err;
#ifdef CONFIG_OF
	struct device_node *node = pdev->dev.of_node;
	enum of_gpio_flags flags = OF_GPIO_ACTIVE_LOW;
	const struct of_device_id *match;
    struct w1_gpio_platform_data *pdata;
	match = of_match_device(w1_gpio_match, &pdev->dev);
    pdata = match->data;
#else
	struct w1_gpio_platform_data *pdata = pdev->dev.platform_data;
#endif

	if (!pdata)
		return -ENXIO;

	master = kzalloc(sizeof(struct w1_bus_master), GFP_KERNEL);
	if (!master)
		return -ENOMEM;

	if (gpio_is_valid(pdata->pin)) {
		err = gpio_request(pdata->pin, "w1");
		if (err) {
			pr_err("w1_gpio_request: gpio_request %d failed!\n",pdata->pin);
			goto free_master;
        }
	}
	//printk("gpio_request w1 pdata->pin =%d\n",pdata->pin);

	master->data = pdata;
	master->read_bit = w1_gpio_read_bit;
#ifdef CONFIG_OF

	pdata->pin = of_get_named_gpio_flags(node, "qcom,batt_id_pin",0, &flags);
	err = of_property_read_u32(node, "qcom,is_open_drain", &pdata->is_open_drain);
	if (err) {
		pr_err("W1 Could not find qcom,is_open_drain property, err = %d\n",err);
		goto free_master;
	}

#endif
	//printk("w1_gpro probe is_open_drain:[%d]\n", pdata->is_open_drain);
	if (pdata->is_open_drain) {
		gpio_direction_output(pdata->pin, 1);
		master->write_bit = w1_gpio_write_bit_val;
	} else {
		gpio_direction_input(pdata->pin);
		master->write_bit = w1_gpio_write_bit_dir;
	}

	err = w1_add_master_device(master);
	if (err) {
               // printk("[DYC] w1_add_master_device failed!\n");
		goto free_gpio;
        }

	if (pdata->enable_external_pullup)
		pdata->enable_external_pullup(1);

	platform_set_drvdata(pdev, master);
       // printk("[DYC] w1_gpio add master successed!\n");
	return 0;

 free_gpio:
 if (gpio_is_valid(pdata->pin))
	gpio_free(pdata->pin);
 free_master:
	kfree(master);

	return err;
}

static int __exit w1_gpio_remove(struct platform_device *pdev)
{
	struct w1_bus_master *master = platform_get_drvdata(pdev);
#ifdef CONFIG_OF
	const struct of_device_id *match;
        struct w1_gpio_platform_data *pdata;
	match = of_match_device(w1_gpio_match, &pdev->dev);
	pdata = match->data;
#else
	struct w1_gpio_platform_data *pdata = pdev->dev.platform_data;
#endif

	if (pdata->enable_external_pullup)
		pdata->enable_external_pullup(0);

	w1_remove_master_device(master);
	gpio_free(pdata->pin);
	kfree(master);

	return 0;
}

#ifdef CONFIG_PM

static int w1_gpio_suspend(struct platform_device *pdev, pm_message_t state)
{
#ifdef CONFIG_OF
	const struct of_device_id *match;
        struct w1_gpio_platform_data *pdata;
	match = of_match_device(w1_gpio_match, &pdev->dev);
	pdata = match->data;
#else
	struct w1_gpio_platform_data *pdata = pdev->dev.platform_data;
#endif

	if (pdata->enable_external_pullup)
		pdata->enable_external_pullup(0);

	return 0;
}

static int w1_gpio_resume(struct platform_device *pdev)
{

#ifdef CONFIG_OF
	const struct of_device_id *match;
        struct w1_gpio_platform_data *pdata;
	match = of_match_device(w1_gpio_match, &pdev->dev);
	pdata= match->data;
#else
	struct w1_gpio_platform_data *pdata = pdev->dev.platform_data;
#endif

	if (pdata->enable_external_pullup)
		pdata->enable_external_pullup(1);

	return 0;
}

#else
#define w1_gpio_suspend	NULL
#define w1_gpio_resume	NULL
#endif

static struct platform_driver w1_gpio_driver = {
	.driver = {
		.name	= "w1-gpio",
		.owner	= THIS_MODULE,
#ifdef CONFIG_OF
		.of_match_table = w1_gpio_match,
#endif
	},
	.remove	= __exit_p(w1_gpio_remove),
	.suspend = w1_gpio_suspend,
	.resume = w1_gpio_resume,
};

static int __init w1_gpio_init(void)
{
	return platform_driver_probe(&w1_gpio_driver, w1_gpio_probe);
}

static void __exit w1_gpio_exit(void)
{
	platform_driver_unregister(&w1_gpio_driver);
}

module_init(w1_gpio_init);
module_exit(w1_gpio_exit);

MODULE_DESCRIPTION("GPIO w1 bus master driver");
MODULE_AUTHOR("Ville Syrjala <syrjala@sci.fi>");
MODULE_LICENSE("GPL");
