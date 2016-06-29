/* arch/arm/mach-msm/gpio_color.c
 *
 * version : 2.0
 *
 * Copyright (c) 2008-2010,2013 Code Aurora Forum. All rights reserved.
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
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/of_gpio.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/sched.h>
#include <asm/gpio.h>
#include <mach/board.h>
#include <linux/workqueue.h>
#include <linux/jiffies.h>

struct gpio_color_data
{
    const char *name;
    unsigned int gpio_sel1;
    unsigned int gpio_sel2;
    unsigned int gpio_sel3;
};

struct gpio_color
{
        struct device *dev;
        struct gpio_color_data *data;
        struct delayed_work work;
        unsigned int gpio_status;
		int32_t irq1;
		int32_t irq2;
		int32_t irq3;
};
static struct gpio_color *gpio_color;
static ssize_t gpio_color_status_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	if (!gpio_color)
		return -ENODEV;

	return scnprintf(buf, PAGE_SIZE, "%d\n", gpio_color->gpio_status);
}


static DEVICE_ATTR(gpio_status, S_IRUSR|S_IRGRP ,
	gpio_color_status_show, NULL);


static void gpio_color_work(struct work_struct *work)
{
        char gpio_value[120] ;
        char *envp [2];
        gpio_color = container_of((struct delayed_work *)work, struct gpio_color, work);
	    disable_irq_nosync(gpio_color->irq1);
		disable_irq_nosync(gpio_color->irq2);
		disable_irq_nosync(gpio_color->irq3);
        snprintf(gpio_value, sizeof(gpio_value), "gpio_value is %d%d%d", 
                gpio_get_value(gpio_color->data->gpio_sel1) ,
                gpio_get_value(gpio_color->data->gpio_sel2) ,
                gpio_get_value(gpio_color->data->gpio_sel3)) ;
        envp[0] = gpio_value;
        envp[1] = NULL;
        kobject_uevent_env(&gpio_color->dev->kobj, KOBJ_CHANGE, envp);
		enable_irq(gpio_color->irq3);
		enable_irq(gpio_color->irq2);
		enable_irq(gpio_color->irq1);
        gpio_color->gpio_status= gpio_get_value(gpio_color->data->gpio_sel1) +
             gpio_get_value(gpio_color->data->gpio_sel2) *2  +
              gpio_get_value(gpio_color->data->gpio_sel3) *4 ;
        pr_err("gpio_color delayed work queue handler begin %s\n",gpio_value);
}

static irqreturn_t gpio_color_isr(int irq, void *dev_id)
{
        //pr_err("gpio_color interrupt\n");
	schedule_delayed_work(&gpio_color->work,msecs_to_jiffies(3000));
	return IRQ_HANDLED;
}

struct gpio_color_data *gc_dt_to_pdata(struct platform_device *pdev)
{
	struct device_node *node = pdev->dev.of_node;
	struct gpio_color_data *pdata;
	pdata = devm_kzalloc(&pdev->dev, sizeof(*pdata), GFP_KERNEL);
	if (!pdata) {
		pr_err("unable to allocate platform data\n");
		return NULL;
	}
	pdata->gpio_sel1 = of_get_named_gpio(node,  "sim,gpio-sel1", 0);
    	pdata->gpio_sel2 = of_get_named_gpio(node,  "sim,gpio-sel2", 0);
      	pdata->gpio_sel3 = of_get_named_gpio(node,  "sim,gpio-sel3", 0);

        return pdata;
}

static int gpio_color_probe(struct platform_device *pdev)
{
        int rc,rc1,rc2,rc3 = 0;
        //int irq1,irq2,irq3;
        char gpio_value[120] ;
        char *envp [2];
        struct gpio_color_data *gc_data;
        
        printk("%s \n", __func__);
	if (pdev->dev.of_node) {
                gc_data = gc_dt_to_pdata(pdev);

	} else if (!pdev->dev.platform_data) {
		dev_err(&pdev->dev, "No platform data given. Bailing out\n");
		return -ENODEV;
        } else {
                gc_data = pdev->dev.platform_data;
        }
        //struct gpio_color *gpio_color;
        gpio_color = kzalloc(sizeof(struct gpio_color), GFP_KERNEL);

        if (!gpio_color)
                return -ENOMEM;
        gpio_color->dev = &pdev->dev;
        gpio_color->data = gc_data;
        //requset gpio address
        rc1 = gpio_request(gc_data->gpio_sel1, "color-sel1");
        rc2 = gpio_request(gc_data->gpio_sel2, "color-sel2");
        rc3 = gpio_request(gc_data->gpio_sel3, "color-sel3");
        if (rc1 || rc2 || rc3)
                goto err_gpio;
        rc1 = gpio_direction_input(gc_data->gpio_sel1);
        rc2 = gpio_direction_input(gc_data->gpio_sel2);
        rc3 = gpio_direction_input(gc_data->gpio_sel3);
        if (rc1 || rc2 || rc3)
                goto err_gpio;
        gpio_color->irq1 = gpio_to_irq(gc_data->gpio_sel1);
        gpio_color->irq2 = gpio_to_irq(gc_data->gpio_sel2);
        gpio_color->irq3 = gpio_to_irq(gc_data->gpio_sel3);

        
        rc1 = request_irq(gpio_color->irq1, gpio_color_isr, IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING, "color_sel1", NULL);
        rc2 = request_irq(gpio_color->irq2, gpio_color_isr, IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING, "color_sel2", NULL);
        rc3 = request_irq(gpio_color->irq3, gpio_color_isr, IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING, "color_sel3", NULL);
        if (rc1 || rc2 || rc3)
                goto err_gpio;

        INIT_DELAYED_WORK(&gpio_color->work, gpio_color_work);
        platform_set_drvdata(pdev, gpio_color);
        //creat file node
        rc = device_create_file(gpio_color->dev, &dev_attr_gpio_status);
	if (rc)
		return 0;
        //pr_err("creat file node succeccfully\n");
        snprintf(gpio_value, sizeof(gpio_value), "gpio_value is %d%d%d", 
                gpio_get_value(gpio_color->data->gpio_sel1) ,
                gpio_get_value(gpio_color->data->gpio_sel2) ,
                gpio_get_value(gpio_color->data->gpio_sel3)) ;
        envp[0] = gpio_value;
        envp[1] = NULL;
        kobject_uevent_env(&gpio_color->dev->kobj, KOBJ_CHANGE, envp);


        gpio_color->gpio_status= gpio_get_value(gpio_color->data->gpio_sel1) +
             gpio_get_value(gpio_color->data->gpio_sel2) *2  +
              gpio_get_value(gpio_color->data->gpio_sel3) *4 ;
        return 0;


err_gpio:
        kfree(gpio_color);
        return rc;

}

static int gpio_color_remove(struct platform_device *pdev)
{
        struct gpio_color *gc = platform_get_drvdata(pdev);
        //switch_dev_unregister(&gc->dev);
        gpio_free(gc->data->gpio_sel1);
        gpio_free(gc->data->gpio_sel2);
        gpio_free(gc->data->gpio_sel3);
        kfree(gc);
        return 0;
}

static struct of_device_id gpio_color_dt_match[] = {
	{	.compatible = "sim,gpio-color",
	},
	{}
};

static struct platform_driver gpio_color_driver =
{
        .probe      = gpio_color_probe,
        .remove     = gpio_color_remove,
        .driver     = {
                .name   = "gpio-color",
                .owner  = THIS_MODULE,
		.of_match_table = gpio_color_dt_match,
        }
};

static int __init gpio_color_init(void)
{
        return platform_driver_register(&gpio_color_driver);
}

static void __exit gpio_color_exit(void)
{
        platform_driver_unregister(&gpio_color_driver);
}

module_init(gpio_color_init);
module_exit(gpio_color_exit);

MODULE_AUTHOR(zhangjunfeng <junfeng.zhang@sim.com>);
MODULE_DESCRIPTION("GPIO detect driver");
MODULE_LICENSE("GPL v2");
