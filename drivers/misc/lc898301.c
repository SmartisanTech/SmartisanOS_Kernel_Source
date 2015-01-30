/*	#define	DESKTOP_DEBUG	*/
/*---------------------------------------------------------------
 * lc898301.c
 * LICENSE      GPL 2.0
 * Copyright (C) 2013 Smartisan Tech Co., Ltd. 2013
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
 *--------------------------------------------------------------*/
#include <linux/delay.h>
#include <linux/lc898301.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/hrtimer.h>
#include <linux/i2c.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include "../staging/android/timed_output.h"
#include <linux/of_gpio.h>
#include <linux/regulator/consumer.h>


#define LC898301_DRIVER_VERSION		"0.728"
#define LC898301_DRV_NAME		"LC898301"

/**---------------------------------------------------------------
 *	Index for BRAKE TIME
 *--------------------------------------------------------------*/
#define	BRK_OBSTIME	50			/* force brake time	*/
#define	MIN_BRAKE	5
#define	NORM_BRAKE	10

#define LC898301REG_ATBR			(1 << 6)
#define LC898301REG_BRTIME			(3 << 4)

#define LC898301_VB_LVS_VTG_UV 1800000
#define LC898301_VB_LVS_LOAD_UV 3100

/**---------------------------------------------------------------
 *	private object type definition.
 *--------------------------------------------------------------*/
enum lc898301_state {
	STOP = 0,				/* ready		*/
	SETUP = 1,				/* waiting LSI READY	*/
	WORKING = 2,				/* vibrating		*/
	BRAKING = 3				/* waiting brake finish	*/
};

/**---------------------------------------------------------------
 *	lc898301 private data
 *--------------------------------------------------------------*/
struct lc898301_private {
	const char *name;
	struct timed_output_dev tdev;
	struct i2c_client *client;
	struct work_struct exec_queue;
	struct hrtimer timer;
	struct hrtimer observer;
	enum lc898301_state state;
	int vib_time;
	int remain;
	int detect_autostop;
	unsigned int max_timeout;
	unsigned int hap_reset_gpio;
	unsigned int hap_len_gpio;
	struct regulator *vb_lvs2;
	struct regulator *vb_lvs3;
	bool vib_busy;
};

char reg_data[LC898301_REG_SIZE] = {
	0x01, 0x04, 0x0B, 0x03,
	0x18, 0x08, 0x60, 0x60,
	(0x01 << 5), 0x0
};

static int platform_init(struct lc898301_private *data, int stat)
{
	dev_info(&data->client->dev, "platform_init() - DO Nothing.\n");
	return 0;
}

static int platform_reset(struct lc898301_private *data, int stat)
{
	if(stat == true)
		stat = gpio_direction_output(data->hap_reset_gpio, 0);
	else if (data->vib_busy == false)
		stat = gpio_direction_output(data->hap_reset_gpio, 1);

	//dev_info(&data->client->dev, "Set GPIO reset to %d.\n", !stat);

	return stat;
}

static int platform_power(struct lc898301_private *data, enum power_state stat)
{
	dev_info(&data->client->dev, "platform_power() - DO Nothing. stat is %d.\n", stat);
	return 0;
}

static int platform_enable(struct lc898301_private *data, int stat)
{
	if((stat == true) && (data->vib_busy == false))
		stat = gpio_direction_output(data->hap_len_gpio, 1);
	else
		stat = gpio_direction_output(data->hap_len_gpio, 0);

	//gpio_free(data->hap_len_gpio);
	//dev_info(&data->client->dev, "Set GPIO enable to %d.\n", stat);

	return stat;
}

static int platform_teardown(struct lc898301_private *data, enum teardown_state stat)
{
	dev_err(&data->client->dev, "platform_teardown() - Something is wroing. stat is %d. \n", stat);
	return 0;
}

/*---------------------------------------------------------------
 * Timer method
 *--------------------------------------------------------------*/
static void lc898301_timer_start(struct hrtimer *timerobj, int val,
		enum hrtimer_restart (*handler)(struct hrtimer *timer))
{
	if (val > 0) {
		hrtimer_cancel(timerobj);
		hrtimer_start(timerobj,
			ktime_set(val / 1000, (val % 1000) * 1000000),
							HRTIMER_MODE_REL);
	}
}

/**---------------------------------------------------------------
 * timer handler
 *--------------------------------------------------------------*/
static enum hrtimer_restart handler_timer(struct hrtimer *timer_obj)
{
	struct lc898301_private *parent = container_of(timer_obj,
					struct lc898301_private, timer);

	schedule_work(&parent->exec_queue);
	return HRTIMER_NORESTART;
}

/**---------------------------------------------------------------
 * enable OFF operation
 *--------------------------------------------------------------*/
static void enable_off(struct lc898301_private *pdata)
{
	int ret = 0;
	char reg_brake = reg_data[4];

	int brake_time = (pdata->vib_time >= NORM_BRAKE) ? NORM_BRAKE
								: MIN_BRAKE;

	/* Unnecessary brake 13/03/19 add*/
	if ((reg_brake & LC898301REG_ATBR) == 0
	&& (reg_brake & LC898301REG_BRTIME) == 0)
		brake_time = 1;

	ret = platform_enable(pdata, false);
	if (ret)
		printk("%s: platform_enable to false fail!\n", __func__);

	lc898301_timer_start(&pdata->timer, brake_time, handler_timer);
	pdata->state = BRAKING;
}

/**---------------------------------------------------------------
 * timer handler, OBSERVING.
 *--------------------------------------------------------------*/
static enum hrtimer_restart handler_observing(struct hrtimer *timer_obj)
{
	struct lc898301_private *parent = container_of(timer_obj,
					struct lc898301_private, observer);
	hrtimer_cancel(&parent->timer);
	enable_off(parent);
	parent->remain = 0;
	parent->detect_autostop = true;

	return HRTIMER_NORESTART;
}

/*---------------------------------------------------------------
 *	lc898301 native register control.
 *--------------------------------------------------------------*/
static int lc898301_set_vibrator_mode(struct i2c_client *client,
							char *data, int len)
{
	int ret = 0;
	struct i2c_msg msg[] = {
		{client->addr, 0, len, data}
	};

	if (data == NULL)
		return -EINVAL;
	if (1 != i2c_transfer(client->adapter, msg, 1))
		ret = -EIO;

	return ret;
}

/**---------------------------------------------------------------
 * event handler
 *--------------------------------------------------------------*/
static void notify_start(struct lc898301_private *pdata)
{
	int ret = 0;

	if (pdata->detect_autostop)
		return;
	ret = platform_reset(pdata, false);
	if (ret)
		printk("%s: platform_reset to false fail!\n", __func__);

	lc898301_timer_start(&pdata->timer, 1, handler_timer);

	pdata->state = SETUP;
}

/**---------------------------------------------------------------
 * event handler
 *--------------------------------------------------------------*/
static void notify_setup(struct lc898301_private *pdata)
{
	int observing_time = pdata->max_timeout;
	int ret;

	ret = lc898301_set_vibrator_mode(pdata->client,
					reg_data,
					sizeof(reg_data));

	if (ret != 0) {
		dev_err(&pdata->client->dev, "I2C WRITE ERROR!!!!!!!!!!!!!!\n");
		platform_teardown(pdata, LC898301_I2CERROR);
		pdata->state = STOP;
		return;
	}

	ret = platform_enable(pdata, true);
	if (ret)
		printk("%s: platform_enable to true fail!\n", __func__);

	lc898301_timer_start(&pdata->timer, pdata->vib_time, handler_timer);

	if (observing_time)
		lc898301_timer_start(&pdata->observer, observing_time,
							handler_observing);
	pdata->state = WORKING;
}

/**---------------------------------------------------------------
 * event handler
 *--------------------------------------------------------------*/
static void notify_enabled(struct lc898301_private *pdata)
{
	hrtimer_cancel(&pdata->observer);
	enable_off(pdata);
	pdata->remain = 0;
}

/**---------------------------------------------------------------
 * event handler
 *--------------------------------------------------------------*/
static void notify_braked(struct lc898301_private *pdata)
{
	int ret = 0;
	ret = platform_reset(pdata, true);
	if (ret)
		printk("%s: platform_reset to true fail!\n", __func__);

	pdata->state = STOP;
}

static void (*callbacks[])(struct lc898301_private *pdata) = {
	notify_start,
	notify_setup,
	notify_enabled,
	notify_braked
};

/**---------------------------------------------------------------
 *      @override       (default platform_driver)
 *--------------------------------------------------------------*/
static ssize_t lc898301_show_version(struct device_driver *driver, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%s\n", LC898301_DRIVER_VERSION);
}

static DRIVER_ATTR(Version, S_IRUGO, lc898301_show_version, NULL);

/*---------------------------------------------------------------
 *	create driver attribute
 *--------------------------------------------------------------*/
static int lc898301_create_attr_file(struct lc898301_private *pa)
{
	int ret = 0;
	struct device_driver *driver = pa->client->dev.driver;

	ret = driver_create_file(driver, &driver_attr_Version);
	return ret;
}

/*---------------------------------------------------------------
 *	revmove driver attribute file
 *--------------------------------------------------------------*/
static void lc898301_remove_attr_file(struct lc898301_private *pa)
{
	struct device_driver *driver = pa->client->dev.driver;
	driver_remove_file(driver, &driver_attr_Version);
}

/*---------------------------------------------------------------
 *	Work queue kernel thread entry point.
 *--------------------------------------------------------------*/
static void thread_entry(struct work_struct *queue)
{
	int size = ARRAY_SIZE(callbacks);
	struct lc898301_private *private_obj =
		container_of(queue, struct lc898301_private, exec_queue);

	//printk(KERN_INFO "LC898301 thread_entry state = %d\n", private_obj->state);

	if (private_obj->state >= size)
		return;
	if (private_obj->state < 0)
		return;
	callbacks[private_obj->state](private_obj);
}

/*---------------------------------------------------------------
 *	initialize private kernel resources.
 *--------------------------------------------------------------*/
static int lc898301_init_private_object(struct i2c_client *client)
{
	struct lc898301_private *private = i2c_get_clientdata(client);

	INIT_WORK(&private->exec_queue, thread_entry);
	hrtimer_init(&private->timer, CLOCK_MONOTONIC,
				HRTIMER_MODE_REL);
	private->timer.function = handler_timer;

	hrtimer_init(&private->observer, CLOCK_MONOTONIC,
				HRTIMER_MODE_REL);
	private->observer.function = handler_observing;

	private->state = STOP;

	private->remain = 0;
	private->detect_autostop = false;

	return 0;
}

/*---------------------------------------------------------------
 *	init platform dependenceies
 *--------------------------------------------------------------*/
static int lc898301_init_platform(struct lc898301_private *pdata)
{
	int err = 0;

	err = platform_init(pdata, true);
	if (err)
		goto exit_init;

	err = gpio_is_valid(pdata->hap_len_gpio);
	if (err) {
		err = gpio_request(pdata->hap_len_gpio, "haptic_len_gpio");
		if (err) {
			dev_err(&pdata->client->dev, "%s: gpio %d request failed\n",
					__func__, pdata->hap_len_gpio);
			return -1;
		}
	} else {
		dev_err(&pdata->client->dev, "%s: Invalid gpio %d\n", __func__,
					pdata->hap_len_gpio);
		return -1;
	}

	err = platform_enable(pdata, false);
	if (err)
	{
		printk("%s: platform_enable to false fail!\n", __func__);
		goto exit_init;
	}

	err = gpio_is_valid(pdata->hap_reset_gpio);
	if (err) {
		err = gpio_request(pdata->hap_reset_gpio, "haptic_reset_gpio");
		if (err) {
			dev_err(&pdata->client->dev, "%s: gpio %d request failed\n",
					__func__, pdata->hap_reset_gpio);
			return -1;
		}
	} else {
		dev_err(&pdata->client->dev, "%s: Invalid gpio %d\n", __func__,
					pdata->hap_reset_gpio);
		return -1;
	}

	err = platform_reset(pdata, true);
	if (err)
	{
		printk("%s: platform_reset to true fail!\n", __func__);
		goto exit_init;
	}
	err = platform_power(pdata, POWER_ON);
	if (err)
		goto exit_init;
exit_init:
	return err;
}

/**---------------------------------------------------------------
 * @override
 * @return <code>int</code>     order is in msec.
 *--------------------------------------------------------------*/
static int lc898301_get_timer_remain(struct hrtimer *timer)
{
	struct lc898301_private *parent = container_of(timer,
					struct lc898301_private, timer);
	int ret_val;

	if (parent->state != WORKING)
		return parent->remain;

	if (hrtimer_active(timer)) {
		struct timeval tmm;
		ktime_t remain = hrtimer_get_remaining(timer);

		tmm = ktime_to_timeval(remain);
		ret_val = (tmm.tv_sec * 1000 + tmm.tv_usec / 1000);
		return ret_val;
	}
	return 0;
}

/**---------------------------------------------------------------
 *      @override       (timed_output_dev)
 *--------------------------------------------------------------*/
static int lc898301_get_time(struct timed_output_dev *dev)
{
	int ret;
	struct lc898301_private *private_obj =
			container_of(dev, struct lc898301_private, tdev);
	ret = lc898301_get_timer_remain(&private_obj->timer);
	return ret;
}

/**---------------------------------------------------------------
 *      @override       (timed_output_dev)
 *--------------------------------------------------------------*/
static void lc898301_enable(struct timed_output_dev *dev, int timeout)
{
	struct lc898301_private *private_obj =
			container_of(dev, struct lc898301_private, tdev);

	private_obj->vib_time = timeout;
	printk(KERN_INFO "lc898301_enable, timeout = %d \n", timeout);

	//if (timeout && private_obj->state != STOP)
	//	return;			/* prohibit subsequent enable */
	private_obj->vib_busy = false;

	if (private_obj->vib_time == 0) {
		private_obj->vib_busy = true;
		//if (private_obj->state != STOP) {
		hrtimer_cancel(&private_obj->timer);
		hrtimer_cancel(&private_obj->observer);
		notify_enabled(private_obj);
		//}
		return;
	}
	private_obj->remain = private_obj->vib_time;
	private_obj->detect_autostop = false;
	schedule_work(&private_obj->exec_queue);
}

/*---------------------------------------------------------------
 *	Work queue kernel thread entry point.
 *--------------------------------------------------------------*/
static int lc898301_setup_timedout_device(struct lc898301_private *data)
{
	int ret = 0;

	data->tdev.name = data->name;
	data->tdev.get_time = lc898301_get_time;
	data->tdev.enable = lc898301_enable;
	ret = timed_output_dev_register(&data->tdev);
	//if (ret == 0)
		//dev_set_drvdata(data->tdev.dev, data);
	return ret;
}

#ifdef CONFIG_OF
static int lc898301_parse_dt(struct device *dev,
			struct lc898301_private *data)
{
	struct device_node *np = dev->of_node;
	enum of_gpio_flags hap_reset_flags = OF_GPIO_ACTIVE_LOW;
	enum of_gpio_flags hap_len_flags = OF_GPIO_ACTIVE_LOW;
	int rc = 0;

	rc = of_property_read_string(np, "label", &data->name);
	if (rc) {
		dev_err(dev, "Unable to read device name\n");
		return rc;
	}

	dev_err(dev, "data->name read from dts is %s .\n", data->name);
	data->hap_reset_gpio = of_get_named_gpio_flags(np,
				"onsemi,hap-reset-gpio", 0, &hap_reset_flags);

	rc = gpio_is_valid(data->hap_reset_gpio);
	if (rc) {
		rc = gpio_request(data->hap_reset_gpio, "haptic_reset_gpio");
		if (rc) {
			dev_err(dev, "%s: gpio %d request failed\n",
					__func__, data->hap_reset_gpio);
			goto err_reset_gpio_req;
		}
	} else {
		dev_err(dev, "%s: Invalid gpio %d\n", __func__,
					data->hap_reset_gpio);
		goto err_reset_gpio_req;
	}
	rc = gpio_direction_output(data->hap_reset_gpio, 0);
	if (rc) {
		dev_err(dev,
				"unable to set direction for gpio " \
				"[%d]\n", data->hap_reset_gpio);
		goto err_reset_gpio_dir;
	}
	gpio_free(data->hap_reset_gpio);

	data->hap_len_gpio = of_get_named_gpio_flags(np,
				"onsemi,hap-len-gpio", 0, &hap_len_flags);

	rc = gpio_is_valid(data->hap_len_gpio);
	if (rc) {
		rc = gpio_request(data->hap_len_gpio, "haptic_len_gpio");
		if (rc) {
			dev_err(dev, "%s: gpio %d request failed\n",
					__func__, data->hap_len_gpio);
			goto err_reset_gpio_dir;
		}
	} else {
		dev_err(dev, "%s: Invalid gpio %d\n", __func__,
					data->hap_len_gpio);
		goto err_len_gpio_dir;
	}
	rc = gpio_direction_output(data->hap_len_gpio, 0);
	if (rc) {
		dev_err(dev,
				"unable to set direction for gpio " \
				"[%d]\n", data->hap_len_gpio);
		goto err_len_gpio_dir;
	}
	gpio_free(data->hap_len_gpio);

	rc = of_property_read_u32(np, "onsemi,max-timeout",
				&data->max_timeout);
	if (rc) {
		dev_err(dev, "Unable to read max timeout\n");
		goto err_len_gpio_dir;
	}


	return 0;
err_len_gpio_dir:
    if (gpio_is_valid(data->hap_len_gpio))
        gpio_free(data->hap_len_gpio);
err_reset_gpio_dir:
    if (gpio_is_valid(data->hap_reset_gpio))
        gpio_free(data->hap_reset_gpio);
err_reset_gpio_req:
    return rc;
}
#else
static int lc898301_parse_dt(struct device *dev,
		struct isa1200_platform_data *pdata)
{
	return -ENODEV;
}
#endif

/**---------------------------------------------------------------
 *	Remove timed output device
 *--------------------------------------------------------------*/
static void lc898301_remove_timedout_device(struct lc898301_private *data)
{
	timed_output_dev_unregister(&data->tdev);
}

static int lc898301_init_regulator(struct lc898301_private *data, bool on)
{
	int ret;

	if (on == false)
		goto hw_shutdown;

	data->vb_lvs2 = regulator_get(&data->client->dev, "vb_lvs2");
	if (IS_ERR(data->vb_lvs2)) {
		ret = PTR_ERR(data->vb_lvs2);
		dev_err(&data->client->dev,
			"Regulator get failed vb_lvs2 ret=%d\n", ret);
		goto error_get_vtg_vb_lvs2;
	}

	if (regulator_count_voltages(data->vb_lvs2) > 0) {
		ret = regulator_set_voltage(data->vb_lvs2, LC898301_VB_LVS_VTG_UV,
							LC898301_VB_LVS_VTG_UV);
		if (ret) {
			dev_err(&data->client->dev,
				"regulator set_vtg lvs2 failed ret=%d\n", ret);
			goto error_set_vtg_vb_lvs2;
		}
	}

	data->vb_lvs3 = regulator_get(&data->client->dev, "vb_lvs3");
	if (IS_ERR(data->vb_lvs3)) {
		ret = PTR_ERR(data->vb_lvs3);
		dev_err(&data->client->dev,
			"Regulator get failed vb_lvs3 ret=%d\n", ret);
		goto error_get_vtg_vb_lvs3;
	}

	if (regulator_count_voltages(data->vb_lvs3) > 0) {
		ret = regulator_set_voltage(data->vb_lvs3, LC898301_VB_LVS_VTG_UV,
							LC898301_VB_LVS_VTG_UV);
		if (ret) {
			dev_err(&data->client->dev,
				"regulator set_vtg lvs3 failed ret=%d\n", ret);
			goto error_set_vtg_vb_lvs3;
		}
	}

	return 0;

error_set_vtg_vb_lvs3:
	regulator_put(data->vb_lvs3);
error_get_vtg_vb_lvs3:
	if (regulator_count_voltages(data->vb_lvs2) > 0)
		regulator_set_voltage(data->vb_lvs2, 0, LC898301_VB_LVS_VTG_UV);
error_set_vtg_vb_lvs2:
	regulator_put(data->vb_lvs2);
error_get_vtg_vb_lvs2:
	return ret;

hw_shutdown:
	if (regulator_count_voltages(data->vb_lvs2) > 0)
		regulator_set_voltage(data->vb_lvs2, 0, LC898301_VB_LVS_VTG_UV);
	regulator_put(data->vb_lvs2);
	if (regulator_count_voltages(data->vb_lvs3) > 0)
		regulator_set_voltage(data->vb_lvs3, 0, LC898301_VB_LVS_VTG_UV);
	regulator_put(data->vb_lvs3);
	return 0;
}

static int reg_set_optimum_mode_check(struct regulator *reg, int load_uA)
{
	return (regulator_count_voltages(reg) > 0) ?
		regulator_set_optimum_mode(reg, load_uA) : 0;
}

static int lc898301_enable_regulator(struct lc898301_private *data, bool on)
{
	int ret;

	if (on == false)
		goto power_off;

	ret = reg_set_optimum_mode_check(data->vb_lvs2, LC898301_VB_LVS_LOAD_UV);
	if (ret < 0) {
		dev_err(&data->client->dev,
			"Regulator vb_lvs2 set_opt failed ret=%d\n", ret);
		goto error_reg_opt_vb_lvs2;
	}

	ret = regulator_enable(data->vb_lvs2);
	if (ret) {
		dev_err(&data->client->dev,
			"Regulator vb_lvs2 enable failed ret=%d\n", ret);
		goto error_reg_en_vb_lvs2;
	}

	ret = reg_set_optimum_mode_check(data->vb_lvs3, LC898301_VB_LVS_LOAD_UV);
	if (ret < 0) {
		dev_err(&data->client->dev,
			"Regulator vb_lvs3 set_opt failed ret=%d\n", ret);
		goto error_reg_opt_vb_lvs3;
	}

	ret = regulator_enable(data->vb_lvs3);
	if (ret) {
		dev_err(&data->client->dev,
			"Regulator vb_lvs3 enable failed ret=%d\n", ret);
		goto error_reg_en_vb_lvs3;
	}

	return 0;

error_reg_en_vb_lvs3:
	reg_set_optimum_mode_check(data->vb_lvs3, 0);
error_reg_opt_vb_lvs3:
	regulator_disable(data->vb_lvs2);
error_reg_en_vb_lvs2:
	reg_set_optimum_mode_check(data->vb_lvs2, 0);
error_reg_opt_vb_lvs2:
	return ret;

power_off:
	reg_set_optimum_mode_check(data->vb_lvs2, 0);
	regulator_disable(data->vb_lvs2);
	reg_set_optimum_mode_check(data->vb_lvs3, 0);
	regulator_disable(data->vb_lvs3);

	return 0;
}

/*---------------------------------------------------------------
 * I2C init/probing/exit functions
 *--------------------------------------------------------------*/
static int __devinit lc898301_probe(struct i2c_client *client,
					const struct i2c_device_id *id)
{
	struct i2c_adapter *adapter;
	struct lc898301_private *data = NULL;
	int ret = 0;

	adapter = to_i2c_adapter(client->dev.parent);

	if (!i2c_check_functionality(adapter, I2C_FUNC_SMBUS_WRITE_BYTE
		| I2C_FUNC_SMBUS_READ_BYTE_DATA)) {
		ret = -EIO;
		goto exit;
	}
	data = kzalloc(sizeof(struct lc898301_private), GFP_KERNEL);
	if (!data) {
		ret = -ENOMEM;
		goto exit;
	}
	data->client = client;
	i2c_set_clientdata(client, data);

	ret = lc898301_init_regulator(data, true);
	if (ret) {
		dev_err(&client->dev, "init regulator failed(%d)", ret);
		goto exit_kfree;
	}

	ret = lc898301_enable_regulator(data, true);
	if (ret) {
		dev_err(&client->dev, "enable regulator failed(%d)", ret);
		goto exit_kfree;
	}

	ret = lc898301_init_private_object(client);
	if (ret)
		goto exit_kfree;

	if (client->dev.of_node) {
		ret = lc898301_parse_dt(&client->dev, data);
		if (ret) {
			dev_err(&client->dev, "Parsing DT failed(%d)", ret);
			return ret;
		}
	}

	data->vib_busy = false;
	ret = lc898301_init_platform(data);
	if (ret)
		goto exit_kfree;
	ret = lc898301_create_attr_file(data);
	if (ret)
		goto exit_remove_file;
	ret = lc898301_setup_timedout_device(data);
	if (ret)
		goto exit_remove_timed_ouput;
	dev_info(&client->dev, "support ver. %s enabled\n",
					LC898301_DRIVER_VERSION);

	return 0;

exit_remove_timed_ouput:
	lc898301_remove_timedout_device(data);

exit_remove_file:
	lc898301_remove_attr_file(data);

exit_kfree:
	platform_teardown(data, LC898301_FAILPROBE);
	kfree(data);
exit:
	return ret;
}

/*---------------------------------------------------------------
 * I2C init/probing/exit functions
 *--------------------------------------------------------------*/
static int __devexit lc898301_remove(struct i2c_client *client)
{
	struct lc898301_private *private = i2c_get_clientdata(client);

	flush_scheduled_work();
	hrtimer_cancel(&private->timer);
	hrtimer_cancel(&private->observer);

	platform_power(private, POWER_OFF);
	lc898301_enable_regulator(private, false);
	lc898301_init_regulator(private, false);

	lc898301_remove_timedout_device(private);
	lc898301_remove_attr_file(private);

	kfree(private);
	return 0;
}


#ifdef CONFIG_PM
static int lc898301_suspend(struct i2c_client *client, pm_message_t mesg)
{
	struct lc898301_private *data = i2c_get_clientdata(client);
	int ret;

	hrtimer_cancel(&data->timer);
	hrtimer_cancel(&data->observer);

	/* prevent from broking device,  while breaking. */
	ret = platform_enable(data, false);
	if (ret < 0)
		printk("%s: platform_enable to false fail!\n", __func__);
	msleep(BRK_OBSTIME);            /* need breake time     */

	ret = platform_reset(data, true);
	if (ret < 0)
		printk("%s: platform_reset to true fail!\n", __func__);

	ret = platform_power(data, POWER_OFF);

	return ret;
}

static int lc898301_resume(struct i2c_client *client)
{
	struct lc898301_private *data = i2c_get_clientdata(client);
	int ret;

	data->remain = 0;
	data->state = STOP;

	ret = platform_enable(data, false);
	if (ret < 0)
		goto exit_resume;

	ret = platform_reset(data, true);
	if (ret < 0)
		goto exit_resume;

	ret = platform_power(data, POWER_ON);
exit_resume:
	return ret;
}
#else
#define lc898301_suspend		NULL
#define lc898301_resume		NULL
#endif


/**---------------------------------------------------------------
 * i2c Device/Driver setup
 *--------------------------------------------------------------*/
static const struct i2c_device_id lc898301_id[] = {
	{ "lc898301", 0 },
	{ }
};

MODULE_DEVICE_TABLE(i2c, lc898301_id);

#ifdef CONFIG_OF
static struct of_device_id lc898301_match_table[] = {
	{ .compatible = "onsemi,lc898301",},
	{ },
};
#else
#define lc898301_match_table NULL
#endif

static struct i2c_driver lc898301_driver = {
	.driver = {
		.name = LC898301_DRV_NAME,
		.of_match_table = lc898301_match_table,
		.owner = THIS_MODULE,
	},
	.probe = lc898301_probe,
	.remove = __devexit_p(lc898301_remove),
	.suspend = lc898301_suspend,
	.resume = lc898301_resume,
	.id_table = lc898301_id,
};

/**---------------------------------------------------------------
 * module entry
 *--------------------------------------------------------------*/
static int __init lc898301_init(void)
{
	return i2c_add_driver(&lc898301_driver);
}

/**---------------------------------------------------------------
 * module exit
 *--------------------------------------------------------------*/
static void __exit lc898301_exit(void)
{
	i2c_del_driver(&lc898301_driver);
}

MODULE_DESCRIPTION("lc898301 motor driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(LC898301_DRIVER_VERSION);
module_init(lc898301_init);
module_exit(lc898301_exit);

