#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/gpio.h>
#include <linux/platform_device.h>
#include <linux/miscdevice.h>
#include <linux/power_supply.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/of_device.h>

enum plug_type {
	PLUG_IN = 1,
	PLUG_OUT = 2,
};

static char *plug_status[] = {
	"plug_unkonwn",
	"plug_in",
	"plug_out",
};

struct rf_cable_chip {
	struct device *cdev;
	int irq;
	int grfc15_gpio;
	enum plug_type plug_status;
	enum plug_type irq_st;
	wait_queue_head_t wait_q;
	struct work_struct work;
	struct mutex mutex_lock;
	struct power_supply *usb_psy;
	struct notifier_block psy_nb;
};

static struct rf_cable_chip *chip;

static ssize_t rf_cable_read(struct file *file, char __user *buf, size_t count,
		                          loff_t *ppos)
{
	char *pbuf;
	int cnt;
	static int local_plug_status = 0;
	int ret;

	if (!buf) {
		dev_err(chip->cdev, "rf_cable: bad address from user side\n");
		return -EFAULT;
	}

	mutex_lock(&chip->mutex_lock);
	ret = wait_event_interruptible(chip->wait_q, (chip->plug_status != local_plug_status));
	if (ret) {
		mutex_unlock(&chip->mutex_lock);
		return ret;
	}

	pbuf = plug_status[chip->plug_status];

	cnt = count > strlen(pbuf) ? strlen(pbuf) : count;

	dev_info(chip->cdev, "buf:%s\n", pbuf);

	if (copy_to_user(buf, pbuf, cnt)) {
		dev_err(chip->cdev, "copy to user space failed\n");
		mutex_unlock(&chip->mutex_lock);
		return -EFAULT;
	}

	local_plug_status = chip->plug_status;
	mutex_unlock(&chip->mutex_lock);

	return cnt;
}

static const struct file_operations rf_cable_fops = {
        .owner = THIS_MODULE,
        .read = rf_cable_read
};

static struct miscdevice rf_cable_misc = {
        .minor = MISC_DYNAMIC_MINOR,
        .name = "rf_cable_misc",
        .fops = &rf_cable_fops,
};

static irqreturn_t rf_cable_rising_interrupt(int irq, void *data)
{
	struct rf_cable_chip *chip = (struct rf_cable_chip *)data;

	chip->irq_st = PLUG_IN;

	schedule_work(&chip->work);

	return IRQ_HANDLED;
}

static irqreturn_t rf_cable_falling_interrupt(int irq, void *data)
{
	struct rf_cable_chip *chip = (struct rf_cable_chip *)data;

	chip->irq_st = PLUG_OUT;

	schedule_work(&chip->work);

	return IRQ_HANDLED;
}

static void rf_cable_work(struct work_struct *work)
{
	struct rf_cable_chip *chip = container_of(work, struct rf_cable_chip, work);
	int rc;

	dev_info(chip->cdev, "plug status: %d\n", chip->irq_st);

	devm_free_irq(chip->cdev, chip->irq, chip);

	if (chip->irq_st == PLUG_IN) {
		chip->plug_status = PLUG_IN;
		rc = devm_request_irq(chip->cdev, chip->irq, rf_cable_falling_interrupt,
				IRQF_TRIGGER_FALLING, "rf_cable_falling_irq", chip);
		if (rc) {
			dev_err(chip->cdev, "%s:%d failed to reqeust falling IRQ\n", __func__, __LINE__);
			return;
		}
	} else if (chip->irq_st == PLUG_OUT) {
		chip->plug_status = PLUG_OUT;
		rc = devm_request_irq(chip->cdev, chip->irq, rf_cable_rising_interrupt,
				IRQF_TRIGGER_RISING, "rf_cable_rising_irq", chip);
		if (rc)
			dev_err(chip->cdev, "%s:%d failed to reqeust rising IRQ\n", __func__, __LINE__);
	}  else {
		dev_err(chip->cdev, "%s:%d unkonwn plug status\n", __func__, __LINE__);
	}

	wake_up_interruptible(&chip->wait_q);
}

static int usbc_event_changed(struct notifier_block *nb,
				      unsigned long evt, void *ptr)
{
	int ret;
	union power_supply_propval mode;
	struct device *cdev;
	static int last_mode;

	cdev = chip->cdev;

	if ((struct power_supply *)ptr != chip->usb_psy ||
				evt != PSY_EVENT_PROP_CHANGED)
		return 0;

	ret = power_supply_get_property(chip->usb_psy,
			POWER_SUPPLY_PROP_TYPEC_MODE, &mode);

	if (ret) {
		dev_err(cdev, "%s: Unable to read USB TYPEC_MODE: %d\n",
			__func__, ret);
		return ret;
	}

	dev_dbg(cdev, "%s: USB change event received, supply mode %d\n",__func__, mode.intval);
	if (mode.intval != last_mode){
		switch (mode.intval) {
		case POWER_SUPPLY_TYPEC_SINK:
		case POWER_SUPPLY_TYPEC_SINK_POWERED_CABLE:
		case POWER_SUPPLY_TYPEC_SINK_DEBUG_ACCESSORY:
		case POWER_SUPPLY_TYPEC_SINK_AUDIO_ADAPTER:
		case POWER_SUPPLY_TYPEC_SOURCE_DEFAULT:
		case POWER_SUPPLY_TYPEC_SOURCE_MEDIUM:
		case POWER_SUPPLY_TYPEC_SOURCE_HIGH:
			if (gpio_is_valid(chip->grfc15_gpio))
				gpio_direction_output(chip->grfc15_gpio, 1);

			dev_dbg(cdev, "%s: usb connected\n", __func__);
		break;
		case POWER_SUPPLY_TYPEC_NONE:
		case POWER_SUPPLY_TYPEC_POWERED_CABLE_ONLY:
		default:
			if (gpio_is_valid(chip->grfc15_gpio))
				gpio_direction_output(chip->grfc15_gpio, 0);

			dev_dbg(cdev, "%s: usb disconnected\n", __func__);
		break;
		}
		last_mode = mode.intval;
	}

	return ret;
}

static int rf_cable_probe(struct platform_device *pdev)
{
	struct device *cdev = &pdev->dev;
	struct device_node *dev_node = cdev->of_node;
	int rc = 0;
	int int_irq;
	int default_val;

	chip = devm_kzalloc(cdev, sizeof(struct rf_cable_chip), GFP_KERNEL);
	if (!chip) {
		dev_err(cdev, "can't alloc rf_cable chip\n");
		return -ENOMEM;
	}

	chip->cdev = cdev;

	chip->grfc15_gpio = of_get_named_gpio(dev_node, "grfc15-gpio", 0);

	if (chip->grfc15_gpio < 0) {
		dev_err(cdev, "grfc15 gpio is not available\n");
	}

	int_irq = of_get_named_gpio(dev_node, "rf_cable,int-gpio", 0);
	if (int_irq < 0) {
		dev_err(cdev, "int gpio is not available\n");
		rc = int_irq;
		goto out1;
	}

	gpio_direction_input(int_irq);
	default_val = gpio_get_value(int_irq);

	chip->irq = gpio_to_irq(int_irq);
	dev_info(cdev, "chip->irq:%d default_val:%d int_irq:%d grfc15_gpio: %d\n", chip->irq, default_val, int_irq, chip->grfc15_gpio);

	mutex_init(&chip->mutex_lock);
	rc = misc_register(&rf_cable_misc);
	if (rc < 0) {
		dev_err(cdev, "register misc device failed\n");
		goto out1;
	}

	if (default_val == 0) {
		chip->plug_status = PLUG_OUT;
		rc = devm_request_irq(cdev, chip->irq, rf_cable_rising_interrupt,
					IRQF_TRIGGER_RISING, "rf_cable_rising_irq", chip);
	} else {
		chip->plug_status = PLUG_IN;
		rc = devm_request_irq(cdev, chip->irq, rf_cable_falling_interrupt,
					IRQF_TRIGGER_FALLING, "rf_cable_rising_irq", chip);
	}
	if (rc) {
		dev_err(cdev, "failed to reqeust IRQ\n");
		goto out2;
	}

	INIT_WORK(&chip->work, rf_cable_work);
	init_waitqueue_head(&chip->wait_q);

	platform_set_drvdata(pdev, chip);

	chip->usb_psy = power_supply_get_by_name("usb");
	if (!chip->usb_psy) {
		dev_err(cdev, "%s: could not get USB psy info\n", __func__);
	}

	chip->psy_nb.notifier_call = usbc_event_changed;
	rc = power_supply_reg_notifier(&chip->psy_nb);
	if (rc < 0) {
		dev_err(cdev, "%s could not register psy notifier rc=%d\n", __func__, rc);
	}

	return 0;

out2:
	misc_deregister(&rf_cable_misc);
out1:
	devm_kfree(cdev, chip);

	return rc;
}

static int rf_cable_remove(struct platform_device *pdev)
{
	struct rf_cable_chip *chip = platform_get_drvdata(pdev);
	struct device *cdev = &pdev->dev;

	devm_free_irq(cdev, chip->irq, chip);
	devm_kfree(cdev, chip);
	misc_deregister(&rf_cable_misc);

	return 0;
}


static struct of_device_id rf_cable_match_table[] = {
	{ .compatible = "rf_cable, plug_detection",},
	{ },
};

static struct platform_driver rf_cable_driver = {
	.driver = {
		.name = "rf_cable",
		.owner = THIS_MODULE,
		.of_match_table = rf_cable_match_table,
	},
	.probe 	= rf_cable_probe,
	.remove = rf_cable_remove,
};

static int __init rf_cable_init(void)
{
    return platform_driver_register(&rf_cable_driver);
}

static void __exit rf_cable_exit(void)
{
    platform_driver_unregister(&rf_cable_driver);
}

late_initcall(rf_cable_init);
module_exit(rf_cable_exit);
