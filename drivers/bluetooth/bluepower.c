#define pr_fmt(fmt) "BluePower: %s: " fmt, __func__

#include <linux/err.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/gpio.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/regulator/consumer.h>
#include <linux/rfkill.h>
#include <linux/platform_device.h>
#include <linux/clk.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/wakelock.h>
#include <linux/pm_qos.h>
#include <linux/delay.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/termios.h>
#include <linux/bitops.h>
#include <linux/param.h>

#include <linux/slab.h>
#include <linux/of_gpio.h>
#include <linux/of_device.h>
#include <linux/pinctrl/consumer.h>
#include <linux/platform_data/msm_serial_hs.h>

#define BT_UPORT_ID 0

struct bluetooth_pm_data {
	int bt_reset;
	int bt_uport;
	struct rfkill *rfkill;
};

struct bluetooth_pm_device_info {
	int gpio_bt_reset;
	struct rfkill *rfk;
};

static struct bluetooth_pm_data *bpm;

static int bluetooth_pm_rfkill_set_power(void *data, bool blocked)
{
	struct bluetooth_pm_device_info *bdev = data;

	pr_info("blocked (%d)", blocked);
	
	if (gpio_get_value(bpm->bt_reset) == !blocked) {
		pr_err("Receive same status(%d)", blocked);
		return 0;
	}

	pr_info("bdev->gpio_bt_reset = %d", bdev->gpio_bt_reset);

	if (!blocked) { // BT ON
		msm_hs_set_clock(bpm->bt_uport, 1);

		gpio_direction_output(bdev->gpio_bt_reset, 1);
		mdelay(100);
		gpio_direction_output(bdev->gpio_bt_reset, 0);
		mdelay(100);
		gpio_direction_output(bdev->gpio_bt_reset, 1);
		pr_info("Bluetooth Power ON!!");
	} else {  // BT OFF
		msm_hs_set_clock(bpm->bt_uport, 0);

		gpio_direction_output(bdev->gpio_bt_reset, 0);
		pr_info("Bluetooth Power OFF!!");
	}

	return 0;
}

static const struct rfkill_ops bluetooth_pm_rfkill_ops = {
	.set_block = bluetooth_pm_rfkill_set_power,
}; 

static int bluetooth_pm_parse_dt(struct device *dev) {
	struct device_node *np = dev->of_node;

	pr_info("bluetooth_pm_parse_dt is started");

	bpm->bt_reset = of_get_named_gpio_flags(np, "gpio-bt-reset", 0, NULL);

	pr_info("bt_reset GPIO Number = %d", bpm->bt_reset);

	if(bpm->bt_reset <0)
		return -ENOMEM;

	return 0;
}

static int bluetooth_pm_probe(struct platform_device *pdev)
{
	int ret;
	bool default_state = true;  /* off */

	struct bluetooth_pm_device_info *bdev;

	pr_info("bluetooth_pm_probe is called");
	bpm = kzalloc(sizeof(struct bluetooth_pm_data), GFP_KERNEL);
	if (!bpm) {
		pr_err("bpm is null");
		return -ENOMEM;
	}

	if (pdev->dev.of_node) {
		pdev->dev.platform_data = bpm;
		ret = bluetooth_pm_parse_dt(&pdev->dev);
		if (ret < 0) {
			pr_err("failed to parse device tree");
			goto free_res;
		}
	} else {
		pr_err("No Device Node");
		goto free_res;
	}

	if(!bpm) {
		pr_err("no bluetooth_pm_data");
		return -ENODEV;
	}

	bdev = kzalloc(sizeof(struct bluetooth_pm_device_info), GFP_KERNEL);
	if (!bdev) {
		pr_err("bdev is null");
		return -ENOMEM;
	}

	bdev->gpio_bt_reset = bpm->bt_reset;

	platform_set_drvdata(pdev, bdev);

	ret = gpio_request_one(bdev->gpio_bt_reset, GPIOF_OUT_INIT_LOW, "bt_reset");
	if (ret) {
		pr_err("failed to request gpio(%d)", bdev->gpio_bt_reset);
		goto free_res;
	}

	bluetooth_pm_rfkill_set_power(bdev, default_state);

	bdev->rfk = rfkill_alloc(pdev->name, &pdev->dev, RFKILL_TYPE_BLUETOOTH,
			&bluetooth_pm_rfkill_ops, bpm);
	if(unlikely(!bdev->rfk)) {
		pr_err("failed to alloc rfkill");
		ret = -ENOMEM;
		goto free_res;
	}

	rfkill_set_states(bdev->rfk, default_state, false);

	ret = rfkill_register(bdev->rfk);

	if (unlikely(ret)) {
		pr_err("failed to register rfkill");
		rfkill_destroy(bdev->rfk);
		kfree(bdev->rfk);
		goto free_res;
	}

	bpm->rfkill = bdev->rfk;

	bpm->bt_uport = BT_UPORT_ID;

	return 0;

free_res:
	if(bpm->bt_reset)
		gpio_free(bpm->bt_reset);
	if (bpm->rfkill) {
		rfkill_unregister(bpm->rfkill);
		rfkill_destroy(bpm->rfkill);
		kfree(bpm->rfkill);
	}
	kfree(bpm);
	return ret;
}

static int bluetooth_pm_remove(struct platform_device *pdev)
{

	if (bpm->rfkill) {
		rfkill_unregister(bpm->rfkill);
		rfkill_destroy(bpm->rfkill);
		kfree(bpm->rfkill);
	}
	if (bpm->bt_reset)
		gpio_free(bpm->bt_reset);

	kfree(bpm);
	
	return 0;
}

static struct of_device_id bluetooth_pm_match_table[] = {
        { .compatible = "bcm,bcm_bluepower"  },
        { },
};

static struct platform_driver bluetooth_pm_driver = {
	.probe = bluetooth_pm_probe,
	.remove = bluetooth_pm_remove,
	.driver = {
		   .name = "bluetooth_pm",
		   .owner = THIS_MODULE,
		   .of_match_table = bluetooth_pm_match_table,
	},
};


static int __init bluetooth_pm_init(void)
{
	int ret;
	
	pr_info("Enter");
	
	ret = platform_driver_register(&bluetooth_pm_driver);
	if (ret)
		pr_err("Fail to register bluetooth_pm platform driver");

	return ret;
}


static void __exit bluetooth_pm_exit(void)
{
	platform_driver_unregister(&bluetooth_pm_driver);
}

module_init(bluetooth_pm_init);
module_exit(bluetooth_pm_exit);

MODULE_DESCRIPTION("Bluetooth Power Manager Driver");
MODULE_LICENSE("GPL");
