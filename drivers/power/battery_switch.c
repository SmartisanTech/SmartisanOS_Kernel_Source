/*
 *  drivers/power/battery_switch.c
 *
 * Copyright (C) 2013 Smartisan, Inc.
 * Author: Du Yichun <duyichun@smartisan.cn>
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

#include <linux/err.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/switch.h>
#include <linux/workqueue.h>
#include <linux/gpio.h>
#include <linux/delay.h>
#include <linux/power_supply.h>
#include <linux/notifier.h>
#include <linux/regulator/consumer.h>
#include <linux/power/battery_common.h>
#include <linux/power/battery_switch.h>

#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/of_device.h>

/*
 * General defines
 */
struct class *batt_switch_class;
static	char last_buf[10] = "off";

enum batt_switch_state {
	BATT_SWITCH_OFF=0,	
	BATT_SWITCH_ON,    
	BATT_SWITCH_LOCKED   /* buffer is locked and cannot be written by user space */
};


/* this represents each char device 'switch' */
struct batt_switch {
	struct device *dev;
	//struct power_supply		*main_batt_psy;
	//struct power_supply		*backup_batt_psy;
	unsigned bb_lock_gpio;
	unsigned sw_ctrl_2nd_batt_gpio;
	unsigned trcc_en_gpio;
	unsigned trcc_en_2nd_gpio;
	struct regulator *vcc_switch;
	enum batt_switch_state state;   /* switch state(on/off) */
};

static struct batt_switch *gswitch;

ATOMIC_NOTIFIER_HEAD(switch_notifier_list);

EXPORT_SYMBOL(switch_notifier_list);


int get_backup_batt_switch_status(void)
{
	int val;
	
	if (!gswitch)
		return -EPERM;
	
	val = gpio_get_value_cansleep(gswitch->sw_ctrl_2nd_batt_gpio);
	
	return val;
}
EXPORT_SYMBOL_GPL(get_backup_batt_switch_status);

int set_bb_lock_switch(char *status)
{
	int rc;
	if (!gswitch)
		return -EPERM;

	if (!strncmp(status, "lock", 4)) {
		gpio_set_value_cansleep(gswitch->bb_lock_gpio, 1);
		mdelay(5);
		rc = regulator_disable(gswitch->vcc_switch);
		if (rc)
			printk("kernel disable ldo21 failed, rc: %d\n", rc);
	}
	else if (!strncmp(status, "unlock", 6))
		gpio_set_value_cansleep(gswitch->bb_lock_gpio, 0);
	else
		return -EINVAL;

	return 0;
}
EXPORT_SYMBOL_GPL(set_bb_lock_switch);

int set_sw_ctrl_2nd_batt_switch(char *status)
{
	char cur_buf[10]  = "off";

	if (!gswitch)
		return -EPERM;

	if (!strncmp(status, "on", 2))
		gpio_set_value_cansleep(gswitch->sw_ctrl_2nd_batt_gpio, 1);
	else if (!strncmp(status, "off", 3))
		gpio_set_value_cansleep(gswitch->sw_ctrl_2nd_batt_gpio, 0);
	else
		return -EINVAL;

	strcpy(cur_buf, status);
	if (strncmp(last_buf, cur_buf, 3))
		atomic_notifier_call_chain(&switch_notifier_list, 0, cur_buf);

    strcpy(last_buf, status);

	return 0;
}
EXPORT_SYMBOL_GPL(set_sw_ctrl_2nd_batt_switch);

int set_trcc_en_switch(char *status)
{
	if (!gswitch)
		return -EPERM;

	if (!strncmp(status, "on", 2))
		gpio_set_value_cansleep(gswitch->trcc_en_gpio, 1);
	else if (!strncmp(status, "off", 3))
		gpio_set_value_cansleep(gswitch->trcc_en_gpio, 0);
	else
		return -EINVAL;

	return 0;
}
EXPORT_SYMBOL_GPL(set_trcc_en_switch);

int set_trcc_en_2nd_switch(char *status)
{
	if (!gswitch)
		return -EPERM;

	if (!strncmp(status, "on", 2))
		gpio_set_value_cansleep(gswitch->trcc_en_2nd_gpio, 1);
	else if (!strncmp(status, "off", 3))
		gpio_set_value_cansleep(gswitch->trcc_en_2nd_gpio, 0);
	else
		return -EINVAL;

	return 0;
}
EXPORT_SYMBOL_GPL(set_trcc_en_2nd_switch);

int get_trcc_en_switch_status(void)
{
	int val;

    if (!gswitch)
        return -EPERM;

    val = gpio_get_value_cansleep(gswitch->trcc_en_gpio);
	
	return val;
}
EXPORT_SYMBOL_GPL(get_trcc_en_switch_status);

int get_trcc_en_2nd_switch_status(void)
{
	int val;

    if (!gswitch)
		return -EPERM;

    val = gpio_get_value_cansleep(gswitch->trcc_en_2nd_gpio);

    return val;
}
EXPORT_SYMBOL_GPL(get_trcc_en_2nd_switch_status);

#if 0
static int main_batt_vol_get(int *main_batt_vol)
{
	union power_supply_propval ret = {0,};
	
	if (!gswitch)
		return -EPERM;
	
	gswitch->main_batt_psy->get_property(gswitch->main_batt_psy,
			  POWER_SUPPLY_PROP_VOLTAGE_NOW, &ret);
	
	*main_batt_vol = ret.intval;
	
	return 0;

}

static int backup_batt_vol_get(int *back_batt_vol)
{
	union power_supply_propval ret = {0,};

	if (!gswitch)
		return -EPERM;
	
	gswitch->backup_batt_psy->get_property(gswitch->backup_batt_psy,
			  POWER_SUPPLY_PROP_VOLTAGE_NOW, &ret);

	*back_batt_vol = ret.intval;
	
	return 0;
}
#endif

static int batt_switch_hw_init(struct batt_switch *switch_data) //need to modify gpiomux.c, or it couldn't bootup
{
	int ret;
#if 0
	int main_batt_vol_now;
	int backup_batt_vol_now;
	
	if (main_batt_vol_get(&main_batt_vol_now))
		return -EINVAL;
	if (backup_batt_vol_get(&backup_batt_vol_now))
		return -EINVAL;
#endif	
	if (gpio_is_valid(switch_data->bb_lock_gpio)) {
		ret = gpio_request(switch_data->bb_lock_gpio, "bb_lock");
        if (ret < 0)
            goto err_request_bb_lock_gpio;
	}
	if (gpio_is_valid(switch_data->sw_ctrl_2nd_batt_gpio)) {
		ret = gpio_request(switch_data->sw_ctrl_2nd_batt_gpio, "sw_ctrl_2nd_batt");
        if (ret < 0)
            goto err_request_sw_ctrl_gpio;
	}
	if (gpio_is_valid(switch_data->trcc_en_gpio)) {
		ret = gpio_request(switch_data->trcc_en_gpio, "trcc_en");
        if (ret < 0)
            goto err_request_trcc_en_gpio;
	}
	if (gpio_is_valid(switch_data->trcc_en_2nd_gpio)) {
		ret = gpio_request(switch_data->trcc_en_2nd_gpio, "trcc_en_2nd");
        if (ret < 0)
            goto err_request_trcc_en_2nd_gpio;
	}
#if 0
    printk("main_batt_vol_now: %d, backup_batt_vol_now: %d\n", main_batt_vol_now, backup_batt_vol_now);
	/* Must check battery power supply voltage before bb_lock */
	if (main_batt_vol_now / 1000 >= 3500) {
		ret = gpio_direction_output(switch_data->sw_ctrl_2nd_batt_gpio, 0);
	    if (ret < 0)
			goto err_set_gpio_output;
		ret = gpio_direction_output(switch_data->bb_lock_gpio, 1);
	    if (ret < 0)
			goto err_set_gpio_output;
	} else {
		if (main_batt_vol_now  >= backup_batt_vol_now) {
			ret = gpio_direction_output(switch_data->sw_ctrl_2nd_batt_gpio, 0);
		    if (ret < 0)
				goto err_set_gpio_output;
			ret = gpio_direction_output(switch_data->bb_lock_gpio, 1);
		    if (ret < 0)
				goto err_set_gpio_output;
		} else {
		ret = gpio_direction_output(switch_data->sw_ctrl_2nd_batt_gpio, 1);
	    if (ret < 0)
			goto err_set_gpio_output;
		ret = gpio_direction_output(switch_data->bb_lock_gpio, 1);
	    if (ret < 0)
			goto err_set_gpio_output;
		}
	}
#endif
    ret = gpio_direction_output(switch_data->bb_lock_gpio, 0);
	if (ret < 0)
        goto err_set_gpio_output;
    ret = gpio_direction_output(switch_data->sw_ctrl_2nd_batt_gpio, 0);
	if (ret < 0)
        goto err_set_gpio_output;
    ret = gpio_direction_output(switch_data->trcc_en_gpio, 0);
	if (ret < 0)
        goto err_set_gpio_output;
	ret = gpio_direction_output(switch_data->trcc_en_2nd_gpio, 0);
	if (ret < 0)
        goto err_set_gpio_output;
	
	return ret;

err_set_gpio_output:
err_request_trcc_en_2nd_gpio:
	if (gpio_is_valid(switch_data->trcc_en_2nd_gpio))
		gpio_free(switch_data->trcc_en_2nd_gpio);
err_request_trcc_en_gpio:
	if (gpio_is_valid(switch_data->trcc_en_gpio))
		gpio_free(switch_data->trcc_en_gpio);
err_request_sw_ctrl_gpio:
	if (gpio_is_valid(switch_data->sw_ctrl_2nd_batt_gpio))
		gpio_free(switch_data->sw_ctrl_2nd_batt_gpio);
err_request_bb_lock_gpio:
	if (gpio_is_valid(switch_data->bb_lock_gpio))
		gpio_free(switch_data->bb_lock_gpio);
	pr_err("batt_switch: Fail to batt_switch_hw_init\n");
    return ret;
}

#if 0
static ssize_t
main_batt_vol_show(struct device *dev, struct device_attribute *attr, char *buf)
{

	int main_batt_vol_now;
	
	if (main_batt_vol_get(&main_batt_vol_now))
		return -EINVAL;


	return snprintf(buf, PAGE_SIZE, "%d\n", main_batt_vol_now / 1000);
}

static ssize_t
back_batt_vol_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	int backup_batt_vol_now;
	
	if (backup_batt_vol_get(&backup_batt_vol_now))
		return -EINVAL;


	return snprintf(buf, PAGE_SIZE, "%d\n", backup_batt_vol_now / 1000);
}
#endif
static ssize_t
bb_lock_switch_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	int val;
	
	if (!gswitch)
		return -EPERM;
	
	val = gpio_get_value_cansleep(gswitch->bb_lock_gpio);
	
	return snprintf(buf, PAGE_SIZE, "%s\n", val == BATT_SWITCH_ON ? "locked" : "unlocked");
}

#if 1
//just for debugging this store
static ssize_t
bb_lock_switch_store(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
{
	if (!gswitch)
		return -EPERM;

	if (!strncmp(buf, "lock", 4)) {
		gpio_direction_output(gswitch->bb_lock_gpio, 1);
		mdelay(5);
		regulator_disable(gswitch->vcc_switch);
	}
	else if (!strncmp(buf, "unlock", 6))
		gpio_direction_output(gswitch->bb_lock_gpio, 0);
	else
		return -EINVAL;

	return count;
}
#endif

static ssize_t
trcc_en_switch_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	int val;
	
	if (!gswitch)
		return -EPERM;
	
	val = gpio_get_value_cansleep(gswitch->trcc_en_gpio);
	
	return snprintf(buf, PAGE_SIZE, "%s\n", val == BATT_SWITCH_ON ? "on" : "off");
}

static ssize_t
trcc_en_switch_store(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
{
	if (!gswitch)
		return -EPERM;

	if (!strncmp(buf, "on", 2))
		gpio_set_value_cansleep(gswitch->trcc_en_gpio, 1);
	else if (!strncmp(buf, "off", 3))
		gpio_set_value_cansleep(gswitch->trcc_en_gpio, 0);
	else
		return -EINVAL;

	return count;
}

static ssize_t
trcc_en_2nd_switch_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	int val;

    if (!gswitch)
		return -EPERM;

    val = gpio_get_value_cansleep(gswitch->trcc_en_2nd_gpio);

    return snprintf(buf, PAGE_SIZE, "%s\n", val == BATT_SWITCH_ON ? "on" : "off");
}

static ssize_t
trcc_en_2nd_switch_store(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
{
	if (!gswitch)
		return -EPERM;

	if (!strncmp(buf, "on", 2))
		gpio_set_value_cansleep(gswitch->trcc_en_2nd_gpio, 1);
	else if (!strncmp(buf, "off", 3))
		gpio_set_value_cansleep(gswitch->trcc_en_2nd_gpio, 0);
	else
		return -EINVAL;

	return count;
}

static ssize_t
sw_ctrl_2nd_batt_switch_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	int val;
	
	val = get_backup_batt_switch_status();
	
	return snprintf(buf, PAGE_SIZE, "%s\n", val == BATT_SWITCH_ON ? "on" : "off");
}

static ssize_t
sw_ctrl_2nd_batt_switch_store(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
{	
	char cur_buf[10]  = "off";
	
	if (!gswitch)
		return -EPERM;

	if (!strncmp(buf, "on", 2))
		gpio_set_value_cansleep(gswitch->sw_ctrl_2nd_batt_gpio, 1);
	else if (!strncmp(buf, "off", 3))
		gpio_set_value_cansleep(gswitch->sw_ctrl_2nd_batt_gpio, 0);
	else
		return -EINVAL;

	strcpy(cur_buf, buf);
	if (strncmp(last_buf, cur_buf, 3))
		atomic_notifier_call_chain(&switch_notifier_list, 0, cur_buf);
		
	strcpy(last_buf, buf);
	
	return count;
}
/*
 * Battery switch device attributes
 */
static struct device_attribute batt_switch_dev_attr[] = {
//	__ATTR(main_batt_vol_now, 0444, main_batt_vol_show, NULL),
//	__ATTR(back_batt_vol_now, 0444, back_batt_vol_show, NULL),
//	__ATTR(bb_lock_switch, 0444, bb_lock_switch_show, NULL),
	__ATTR(bb_lock_switch, 0644, bb_lock_switch_show, bb_lock_switch_store),
	__ATTR(trcc_en_switch, 0644, trcc_en_switch_show, trcc_en_switch_store),
	__ATTR(trcc_en_2nd_switch, 0644, trcc_en_2nd_switch_show, trcc_en_2nd_switch_store),
	__ATTR(sw_ctrl_2nd_batt_switch, 0644, sw_ctrl_2nd_batt_switch_show, sw_ctrl_2nd_batt_switch_store),
    __ATTR_NULL,
};
#if 0
static int create_batt_switch_sysfs(struct batt_switch *switch_data)
{
	int result = 0;
	int num_attr = sizeof(batt_switch_dev_attr)/sizeof(struct device_attribute);
	int i;

	for (i = 0; i < num_attr; i++) {
		result = device_create_file(switch_data->dev, &batt_switch_dev_attr[i]);
		if (result < 0)
			return result;
	}

	return 0;
}

static void remove_batt_switch_sysfs(struct batt_switch *switch_data)
{
	int num_attr = sizeof(batt_switch_dev_attr)/sizeof(struct device_attribute);
	int i;

	for (i = 0; i < num_attr; i++)
		device_remove_file(switch_data->dev, &batt_switch_dev_attr[i]);

	return;
}
#endif
/* copy device-tree data to platfrom data struct */
static int batt_switch_dt_to_pdata(struct platform_device *pdev, struct batt_switch *switch_data)
{
	int rc = 0;
	struct device_node *node = pdev->dev.of_node;
	enum of_gpio_flags flags = OF_GPIO_ACTIVE_LOW;

	switch_data->bb_lock_gpio = of_get_named_gpio_flags(node, "qcom,bb-lock-gpio",
				0, &flags);
	switch_data->sw_ctrl_2nd_batt_gpio = of_get_named_gpio_flags(node, "qcom,sw-ctrl-2nd-batt-gpio",
				0, &flags);
	switch_data->trcc_en_gpio = of_get_named_gpio_flags(node, "qcom,trcc-en-gpio",
				0, &flags);
	switch_data->trcc_en_2nd_gpio = of_get_named_gpio_flags(node, "qcom,trcc-en-2nd-gpio",
				0, &flags);

    rc = of_property_read_u32(node, "qcom,switch-state", &switch_data->state);
	if (rc) {
		pr_err("batt_switch: Could not find switch-state property, err = %d\n", rc);
	}

    switch_data->vcc_switch = regulator_get(&pdev->dev, "vcc_switch");
	if (IS_ERR(switch_data->vcc_switch)) {
		rc = PTR_ERR(switch_data->vcc_switch);
		pr_err("Regulator get failed vcc_switch rc=%d\n", rc);
		}

    return rc;
}

static int battery_switch_probe(struct platform_device *pdev)
{
	struct batt_switch *switch_data;
	int ret = 0;

	switch_data = kzalloc(sizeof(*switch_data), GFP_KERNEL);
	if (!switch_data) {
		pr_err("Failed to alloc mem for switch_data\n");
		return -ENOMEM;
	}
	switch_data->dev = &pdev->dev;
#if 0
	switch_data->main_batt_psy = power_supply_get_by_name("main_battery");
	if (!switch_data->main_batt_psy) {
		pr_err("main_battery supply not found deferring probe\n");
		ret = -EPROBE_DEFER;
		goto fail_switch_enable;
	}
	switch_data->backup_batt_psy = power_supply_get_by_name("back_battery");
	if (!switch_data->backup_batt_psy) {
		pr_err("back_battery supply not found deferring probe\n");
		ret = -EPROBE_DEFER;
		goto fail_switch_enable;
	}
#endif
	if (pdev->dev.of_node) {
		/* get information from device tree */
		ret = batt_switch_dt_to_pdata(pdev, switch_data);
		if (ret) {
			pr_err("Unable to read all batt_switch properties, ret = %d\n", ret);
			goto  fail_switch_enable;
	      }
		} else {
		pr_err("battery_switch: Platform data not available");
		goto fail_switch_enable;
	}
	ret = regulator_enable(switch_data->vcc_switch);
	if (ret)
		goto  fail_switch_enable;

    gswitch = switch_data;
#if 0
	ret = create_batt_switch_sysfs(switch_data);
	if (ret < 0) {
		pr_err("Cannot create batt_switch sysfs\n");
        goto fail_switch_enable;
	}
#endif
	batt_switch_class = class_create(THIS_MODULE, "batt_switch");
	if (IS_ERR(batt_switch_class))
		return PTR_ERR(batt_switch_class);
	batt_switch_class->dev_attrs = batt_switch_dev_attr;
    device_create(batt_switch_class, switch_data->dev, 0, NULL, "battery_switch_dev");

    batt_switch_hw_init(switch_data);

	platform_set_drvdata(pdev, switch_data);
	
	printk("battery_switch_probe success!\n");
	return ret;

fail_switch_enable:
	kfree(switch_data);
	return ret;
}

static int __devexit battery_switch_remove(struct platform_device *pdev)
{
	gpio_free(gswitch->bb_lock_gpio);
	gpio_free(gswitch->sw_ctrl_2nd_batt_gpio);
	gpio_free(gswitch->trcc_en_gpio);
    gpio_free(gswitch->trcc_en_2nd_gpio);
    regulator_put(gswitch->vcc_switch);
#if 0
    remove_batt_switch_sysfs(gswitch);
#endif
	kfree(gswitch);
	gswitch = NULL;
	class_destroy(batt_switch_class);
	platform_set_drvdata(pdev, NULL);
	
	return 0;
}

static struct of_device_id battery_switch_match_table[] = {
	{.compatible = "qcom,battery_switch"},
	{}
};

static struct platform_driver battery_switch_driver = {
	.probe		= battery_switch_probe,
	.remove		= __devexit_p(battery_switch_remove),
	.driver		= {
		.name	= "battery_switch",
		.owner	= THIS_MODULE,
		.of_match_table = battery_switch_match_table,
	},
};

static int __init battery_switch_init(void)
{
	return platform_driver_register(&battery_switch_driver);
}

static void __exit battery_switch_exit(void)
{
	platform_driver_unregister(&battery_switch_driver);
}

module_init(battery_switch_init);
module_exit(battery_switch_exit);

MODULE_AUTHOR("Du Yichun <duyichun@smartisan.cn>");
MODULE_DESCRIPTION("Battery Switch driver");
MODULE_LICENSE("GPL v2");
