/* BTP Sensor Driver
 *
 * Copyright (c) 2016 CanvasBio Fingerprint <www.canvasbio.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License Version 2
 * as published by the Free Software Foundation.
 */

#define DEBUG
//#define CTRL_SPI_CLK

#include <linux/platform_device.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/input.h>
#include <linux/interrupt.h>
#include <linux/gpio.h>
#include <linux/delay.h>
#if defined (CTRL_SPI_CLK)
#include <linux/clk.h>
#endif
#include <linux/pinctrl/consumer.h>
#ifdef CONFIG_OF
#include <linux/of.h>
#include <linux/of_gpio.h>
#endif
#include <linux/wakelock.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("CanvasBio Fingerprint <www.canvasbio.com>");
MODULE_DESCRIPTION("BTP sensor driver.");


/* -------------------------------------------------------------------- */
/* ix driver constants                                                 */
/* -------------------------------------------------------------------- */
#define ix_DEV_NAME   "btp"
#define ix_INTERRUPT  REL_MISC

/* -------------------------------------------------------------------- */
/* ix_btp data types                                                   */
/* -------------------------------------------------------------------- */
struct ix_data{
	struct platform_device *pdev;
	struct input_dev *input;
	struct device *device;
	u32 reset_gpio;
	u32 irq_gpio;
	u32 irq;

#if defined(CONFIG_FB)
	struct notifier_block fb_notifier;
#elif defined(CONFIG_HAS_EARLYSUSPEND)
	struct early_suspend early_suspend;
#endif
	struct pinctrl  *spi_pinctrl;
#if defined (CTRL_SPI_CLK)
	/* clk info */
	bool clock_enable;
	u32 max_spi_freq_hz;
	struct clk *core_clk;
	struct clk *iface_clk;
#endif
    struct wake_lock ttw_wl;
};

/* -------------------------------------------------------------------- */
/* function prototypes                                                  */
/* -------------------------------------------------------------------- */
static int ix_init(void);
static void ix_exit(void);
static int ix_probe(struct platform_device *pdev);
static int ix_remove(struct platform_device *pdev);
static int ix_get_of_pdata(struct device *dev, struct ix_data *pdata);
static int ix_reset_init(struct ix_data *ix_btp, struct ix_data *pdata);
static int ix_irq_init(struct ix_data *ix_btp, struct ix_data *pdata);
static int ix_cleanup(struct ix_data *ix_btp);
#if defined (CTRL_SPI_CLK)
static int ix_set_clks(struct ix_data *ix_btp, bool enable);
static int ix_set_pinctrl(struct ix_data *ix_btp, bool enable);
#endif
irqreturn_t ix_btp_interrupt(int irq, void *_ix_btp);
static int ix_register_input_device(struct ix_data *ix_btp);
static int ix_btp_gpio_reset(struct ix_data *ix_btp);

/* -------------------------------------------------------------------- */
/* External interface                                                   */
/* -------------------------------------------------------------------- */
module_init(ix_init);
module_exit(ix_exit);

#ifdef CONFIG_OF
static struct of_device_id ix_of_match[] = {
  { .compatible = "ix,btp", },
  {}
};

MODULE_DEVICE_TABLE(of, ix_of_match);
#endif

static struct platform_driver ix_driver = {
	.driver = {
		.name   = ix_DEV_NAME,
        .owner  = THIS_MODULE,
#ifdef CONFIG_OF
		.of_match_table = ix_of_match,
#endif
	},
	.probe  = ix_probe,
	.remove = ix_remove,
};

#if defined (CTRL_SPI_CLK)
/* -------------------------------------------------------------------- */
static ssize_t ix_btp_store_spi_prepare(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct ix_data *ix_btp = dev_get_drvdata(dev);
	int status;
	unsigned int val;
	bool enable;
	pr_debug(KERN_DEBUG ": [DEBUG] %s:%i %s\n", __FILE__, __LINE__, __func__);
	status = kstrtouint(buf, 0, &val);
	if (status != 0)
		return count;

	enable = val == 0 ? false : true;

	if (enable != ix_btp->clock_enable) {
		ix_btp->clock_enable = enable;
		ix_set_pinctrl(ix_btp, ix_btp->clock_enable);
		ix_set_clks(ix_btp, ix_btp->clock_enable);
	}

	return count;
}

static ssize_t ix_btp_show_spi_prepare(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct ix_data *ix_btp = dev_get_drvdata(dev);
	pr_debug(KERN_DEBUG ": [DEBUG] %s:%i %s\n", __FILE__, __LINE__, __func__);
	return sprintf(buf, "%d\n", ix_btp->clock_enable ? 1 : 0);
}

static DEVICE_ATTR(clk_enable, S_IRUGO | S_IWUSR,
		ix_btp_show_spi_prepare, ix_btp_store_spi_prepare);

static struct attribute *ix_btp_attributes[] = {
	&dev_attr_clk_enable.attr,
	NULL
};

static const struct attribute_group ix_btp_attr_group = {
	.attrs = ix_btp_attributes,
};
#endif

static ssize_t ix_btp_store_job_cancel(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct ix_data *ix_btp = dev_get_drvdata(dev);
	pr_debug(KERN_DEBUG ": [DEBUG] %s:%i %s\n", __FILE__, __LINE__, __func__);

	input_report_rel(ix_btp->input, ix_INTERRUPT, 2);
	input_sync(ix_btp->input);

	return strnlen(buf, count);
}

static DEVICE_ATTR(job_cancel, S_IRUGO|S_IWUSR,
		NULL, ix_btp_store_job_cancel);

static ssize_t ix_btp_store_hw_reset(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct ix_data *ix_btp = dev_get_drvdata(dev);
	pr_debug(KERN_DEBUG ": [DEBUG] %s:%i %s\n", __FILE__, __LINE__, __func__);

	ix_btp_gpio_reset(ix_btp);
	
	return strnlen(buf, count);
}

static DEVICE_ATTR(hw_reset, S_IRUGO|S_IWUSR,
		NULL, ix_btp_store_hw_reset);

static struct attribute *ix_btp_attributes[] = {
	&dev_attr_hw_reset.attr,
	&dev_attr_job_cancel.attr,
	NULL
};

static const struct attribute_group ix_btp_attr_group = {
	.attrs = ix_btp_attributes,
};

extern char *fingerprint_id;

static int get_fingerprint_id(char *src)
{
	if (src == NULL)
		return 0;

	if (!strcmp(src, "idex"))
		fingerprint_id = "idex";
	else if (!strcmp(src, "goodix"))
		fingerprint_id = "goodix";

	pr_warn("kernel detect fingerprint_id = *%s*\n", fingerprint_id);

	return 1;
}
__setup("androidboot.fingerprint.id=", get_fingerprint_id);

/* -------------------------------------------------------------------- */
/* function definitions                                                 */
/* -------------------------------------------------------------------- */
static int ix_init(void)
{
	pr_debug(KERN_DEBUG ": [DEBUG] %s:%i %s\n", __FILE__, __LINE__, __func__);

	if (strcmp(fingerprint_id, "idex")) {
		pr_err(" %s fingerprint_id = %s \n", __func__, fingerprint_id);
		return -1;
	}

	if (platform_driver_register(&ix_driver))
		return -EINVAL;

	return 0;
}

/* -------------------------------------------------------------------- */
static void ix_exit(void)
{
	pr_debug(KERN_DEBUG ": [DEBUG] %s:%i %s\n", __FILE__, __LINE__, __func__);

	platform_driver_unregister(&ix_driver);
}

/* -------------------------------------------------------------------- */
static int ix_probe(struct platform_device *pdev)
{
	struct ix_data *ix_pdata;
	struct ix_data pdata_of;
	struct device *dev = &pdev->dev;
	struct ix_data *ix_btp = NULL;

	int error = 0;

	ix_btp = kzalloc(sizeof(*ix_btp), GFP_KERNEL);
	if (!ix_btp)
	{
		dev_err(&pdev->dev, "[ERROR] failed to allocate memory for struct ix_data\n");
		return -ENOMEM;
	}

	ix_pdata = pdev->dev.platform_data;
	if (!ix_pdata)
	{
		error = ix_get_of_pdata(dev, &pdata_of);
		ix_pdata = &pdata_of;

		if (error)
			goto err;
	}

	if (!ix_pdata)
	{
		dev_err(&ix_btp->pdev->dev, "[ERROR] pdev->dev.platform_data is NULL.\n");
		error = -EINVAL;
		goto err;
	}

	platform_set_drvdata(pdev, ix_btp);
	ix_btp->pdev = pdev;

#if defined (CTRL_SPI_CLK)
	ix_btp->max_spi_freq_hz = pdata_of.max_spi_freq_hz;
	ix_btp->clock_enable = false;
#endif
	ix_btp->reset_gpio = -EINVAL;
	ix_btp->irq_gpio = -EINVAL;
	ix_btp->irq = -EINVAL;

	error = ix_register_input_device(ix_btp);
	if (error)
	{
		dev_err(&ix_btp->pdev->dev,  "[ERROR] register input device failed.\n");
		goto err;
	}

	error = ix_reset_init(ix_btp, ix_pdata);
	if (error)
		goto err;

	error = ix_irq_init(ix_btp, ix_pdata);
	if (error)
		goto err;

	if(sysfs_create_group(&ix_btp->input->dev.kobj, &ix_btp_attr_group)) {
		 dev_err(dev, "[ERROR] sysfs_create_group failed.\n");
		 goto err;
	}

#if defined (CTRL_SPI_CLK)
	if(sysfs_create_group(&ix_btp->input->dev.kobj, &ix_btp_attr_group)) {
		 dev_err(dev, "[ERROR] sysfs_create_group failed.\n");
		 goto err;
	}

	ix_btp->iface_clk = clk_get(&pdev->dev, "iface_clk");
	if (IS_ERR(ix_btp->iface_clk)) {
		dev_err(dev, "%s: Failed to get iface_clk\n", __func__);
		error = -EINVAL;
		goto err;
	}

	ix_btp->core_clk = clk_get(&pdev->dev, "core_clk");
	if (IS_ERR(ix_btp->core_clk)) {
		dev_err(dev, "%s: Failed to get core_clk\n", __func__);
		error = -EINVAL;
		goto err;
	}

	error = clk_set_rate(ix_btp->core_clk, ix_btp->max_spi_freq_hz);
	if (error) {
		dev_err(dev, "%s: Error setting clk_rate:%d\n", __func__,  ix_btp->max_spi_freq_hz);
		goto err;
	}

	if (ix_set_pinctrl(ix_btp, false)) {
		 dev_err(dev, "[ERROR] sysfs_create_group failed.\n");
		 goto err;
	}
#endif

	ix_btp_gpio_reset(ix_btp);

	pr_debug(KERN_DEBUG ": [DEBUG] %s:%i %s probe OK...\n", __FILE__, __LINE__, __func__);

	return 0;

err:
	ix_cleanup(ix_btp);
	dev_set_drvdata(&pdev->dev, NULL);
	return error;
}

/* -------------------------------------------------------------------- */
static int ix_remove(struct platform_device *pdev)
{
	struct ix_data *ix_btp = dev_get_drvdata(&pdev->dev);

	pr_debug(KERN_DEBUG ": [DEBUG] %s:%i %s\n", __FILE__, __LINE__, __func__);

    wake_lock_destroy(&ix_btp->ttw_wl);

	input_free_device(ix_btp->input);
	input_unregister_device(ix_btp->input);

	ix_cleanup(ix_btp);
	platform_set_drvdata(pdev, NULL);

	return 0;
}

/* -------------------------------------------------------------------- */
static int ix_get_of_pdata(struct device *dev, struct ix_data *pdata)
{
	const struct device_node *node = dev->of_node;
#if defined (CTRL_SPI_CLK)
	u32 val = 0;
	int error = of_property_read_u32(dev->of_node, "spi-max-frequency", &val);
#endif
	pdata->irq_gpio  = of_get_named_gpio(dev->of_node, "ix,gpio_irq",   0);
	pdata->reset_gpio = of_get_named_gpio(dev->of_node, "ix,gpio_reset", 0);

#if defined (CTRL_SPI_CLK)
	pdata->max_spi_freq_hz = error < 0 ? 4800000 : val;
#endif

	pr_info(KERN_DEBUG ": [DEBUG] %s:%i %s\n", __FILE__, __LINE__, __func__);

	if (node == NULL) {
		dev_err(dev, "%s: Could not find OF device node\n", __func__);
		goto of_err;
	}
	if (!gpio_is_valid(pdata->irq_gpio)) {
		dev_err(dev, "Looking up %s property in node %s failed %d\n",
					"ix,gpio_irq", dev->of_node->full_name,
		pdata->irq_gpio);
		goto of_err;
	}
	if (!gpio_is_valid(pdata->reset_gpio)) {
		dev_err(dev, "Looking up %s property in node %s failed %d\n",
					"ix,gpio_reset", dev->of_node->full_name,
		pdata->reset_gpio);
		goto of_err;
	}

#if defined (CTRL_SPI_CLK)
	pr_info(KERN_INFO ": [INFO] irq : %d  reset : %d max_spi_freq_hz : %d\n", pdata->irq_gpio, pdata->reset_gpio, pdata->max_spi_freq_hz);
#else
	pr_info(KERN_INFO ": [INFO] irq : %d  reset : %d\n", pdata->irq_gpio, pdata->reset_gpio);
#endif

	return 0;

of_err:
	pdata->reset_gpio = -EINVAL;
	pdata->irq_gpio   = -EINVAL;

	return -ENODEV;
}


static int ix_register_input_device(struct ix_data *ix_btp)
{
	int error;

	/* register input device */
	ix_btp->input = input_allocate_device();
	if(!ix_btp->input) {
		dev_err(&ix_btp->pdev->dev, "input_allocate_deivce failed.");
		error = -ENOMEM;
		goto err;
	}

	ix_btp->input->name = "fingerprint";
	ix_btp->input->dev.init_name = "cb_fingerprint";

	input_set_capability(ix_btp->input, EV_REL, ix_INTERRUPT);
	input_set_drvdata(ix_btp->input, ix_btp);
	error = input_register_device(ix_btp->input);
	if(error) {
		dev_err(&ix_btp->pdev->dev, "input_register_device failed.");
		input_free_device(ix_btp->input);
		goto err;
	}
	return 0;

err:
	return -1;
}

/* -------------------------------------------------------------------- */
static int ix_reset_init(struct ix_data *ix_btp, struct ix_data *pdata)
{
	int error = -EINVAL;
	if (gpio_is_valid(pdata->reset_gpio)) {
		dev_info(&ix_btp->pdev->dev, "[INFO] Assign RST -> GPIO%d\n", pdata->reset_gpio);
		error = gpio_request(pdata->reset_gpio, "gpio_reset");
		if (error)
		{
			dev_err(&ix_btp->pdev->dev,  "[ERROR] %s, gpio_request (reset) failed.\n", __FUNCTION__);
			return error;
		}

		if (pdata->reset_gpio == -EINVAL)
		{
			dev_err(&ix_btp->pdev->dev, "[ERROR] %s, reset_gpio EINVAL.\n", __FUNCTION__);
			return -EINVAL;
		}

		ix_btp->reset_gpio = pdata->reset_gpio;

		error = gpio_direction_output(ix_btp->reset_gpio, 1);
		if (error)
		{
			dev_err(&ix_btp->pdev->dev,  "[ERROR] %s, gpio_direction_output(reset) failed.\n", __FUNCTION__);
			return error;
		}
	} else {
		dev_err(&ix_btp->pdev->dev,  "[ERROR] %s, Invalid reset gpio.\n", __FUNCTION__);
    }
	return 0;
}

/* -------------------------------------------------------------------- */
static int ix_irq_init(struct ix_data *ix_btp, struct ix_data *pdata)
{
	int error = 0;

    wake_lock_init(&ix_btp->ttw_wl, WAKE_LOCK_SUSPEND, "ix_ttw_wl");

	if (gpio_is_valid(pdata->irq_gpio)) {
		dev_info(&ix_btp->pdev->dev, "[INFO] Assign IRQ -> GPIO%d\n", pdata->irq_gpio);

		error = gpio_request(pdata->irq_gpio, "gpio_irq");
		if (error)
		{
			dev_err(&ix_btp->pdev->dev, "[ERROR] %s, gpio_request (irq) failed.\n", __FUNCTION__);
			return error;
		}

		if(pdata->irq_gpio == -EINVAL)
		{
			dev_err(&ix_btp->pdev->dev, "[ERROR] %s, irq_gpio EINVAL.\n", __FUNCTION__);
			return -EINVAL;
		}

		ix_btp->irq_gpio = pdata->irq_gpio;

		error = gpio_direction_input(ix_btp->irq_gpio);
		if (error)
		{
			dev_err(&ix_btp->pdev->dev, "[ERROR] %s, gpio_direction_input (irq) failed.\n", __FUNCTION__);
			return error;
		}

		ix_btp->irq = gpio_to_irq(ix_btp->irq_gpio);
		if (ix_btp->irq < 0)
		{
			dev_err(&ix_btp->pdev->dev, "[ERROR] %s, gpio_to_irq failed.\n", __FUNCTION__);
			error = ix_btp->irq;
			return error;
		}

		error = request_irq(ix_btp->irq, ix_btp_interrupt, IRQF_TRIGGER_RISING, "ix_btp", ix_btp);
		if (error)
		{
			dev_err(&ix_btp->pdev->dev, "[ERROR] %s, request_irq %i failed.\n", __FUNCTION__, ix_btp->irq);
			ix_btp->irq = -EINVAL;
			return error;
		}

	} else {
		dev_err(&ix_btp->pdev->dev,  "[ERROR] %s, Invalid reset gpio.\n", __FUNCTION__);
		return -EINVAL;
	}
	return error;
}

/* -------------------------------------------------------------------- */
static int ix_cleanup(struct ix_data *ix_btp)
{
	pr_debug(KERN_DEBUG ": [DEBUG] %s:%i %s\n", __FILE__, __LINE__, __func__);

	if (ix_btp->irq >= 0)
		free_irq(ix_btp->irq, ix_btp);

	if (gpio_is_valid(ix_btp->irq_gpio))
		gpio_free(ix_btp->irq_gpio);

	if (gpio_is_valid(ix_btp->reset_gpio))
		gpio_free(ix_btp->reset_gpio);

	kfree(ix_btp);

	return 0;
}

#if defined (CTRL_SPI_CLK)
static int ix_set_clks(struct ix_data *ix_btp, bool enable)
{
	int rc = 0;
	if (enable) {
		rc = clk_prepare_enable(ix_btp->core_clk);
		if (rc) {
			dev_err(&ix_btp->pdev->dev,
					"%s: Error enabling core clk: %d\n",
					__func__, rc);
			goto out;
		}

		rc = clk_prepare_enable(ix_btp->iface_clk);
		if (rc) {
			dev_err(&ix_btp->pdev->dev,
					"%s: Error enabling iface clk: %d\n",
				__func__, rc);
			clk_disable_unprepare(ix_btp->core_clk);
			goto out;
		}
	} else {
		clk_disable_unprepare(ix_btp->iface_clk);
		clk_disable_unprepare(ix_btp->core_clk);
	}

out:
	return rc;
}

static int ix_set_pinctrl(struct ix_data *ix_btp, bool enable)
{
	long rc = 0;
	ix_btp->spi_pinctrl = pinctrl_get_select(&ix_btp->pdev->dev, enable ? "spi_active" : "spi_sleep");
	rc = IS_ERR(ix_btp->spi_pinctrl);
	if (rc) {
		dev_err(&ix_btp->pdev->dev, "%s: Could not get/set pinctrl state, rc = %ld\n", __func__,  rc);
	}

	return rc;
}
#endif

/* -------------------------------------------------------------------- */
irqreturn_t ix_btp_interrupt(int irq, void *handle)
{
	struct ix_data *ix_btp = handle;
	if ( gpio_get_value(ix_btp->irq_gpio) )
	{
        wake_lock_timeout(&ix_btp->ttw_wl, msecs_to_jiffies(1000));

		input_report_rel(ix_btp->input, ix_INTERRUPT, 1);
		input_sync(ix_btp->input);
		return IRQ_HANDLED;
	}
	return IRQ_NONE;
}

/* -------------------------------------------------------------------- */
static int ix_btp_gpio_reset(struct ix_data *ix_btp)
{
	pr_debug(KERN_DEBUG ": [DEBUG] %s:%i %s\n", __FILE__, __LINE__, __func__);

	gpio_set_value(ix_btp->reset_gpio, 0);
	udelay(1000);

	gpio_set_value(ix_btp->reset_gpio, 1);
	udelay(1250);

	return 0;
}
