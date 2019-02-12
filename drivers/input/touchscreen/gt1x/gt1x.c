/* drivers/input/touchscreen/gt1x.c
 *
 * 2010 - 2014 Goodix Technology.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be a reference
 * to you, when you are integrating the GOODiX's CTP IC into your system,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * Version: 1.6
 */

#include "gt1x_generic.h"
#ifdef CONFIG_GTP_TYPE_B_PROTOCOL
#include <linux/input/mt.h>
#endif
#include <linux/notifier.h>
#include <linux/fb.h>
#include <linux/msm_drm_notify.h>
//#0244395 bsp madan@smartisan.com add to support aging test begin.
#include <smartisan/hwstate.h>
//#0244395 bsp madan@smartisan.com add to support aging test end.

static struct input_dev *input_dev;
static spinlock_t irq_lock;
static int irq_disabled;
#ifndef CONFIG_GTP_INT_SEL_SYNC
#include <linux/pinctrl/consumer.h>
static struct pinctrl *default_pctrl;
#endif
#ifdef CONFIG_OF
int gt1x_rst_gpio;
int gt1x_int_gpio;
int gt1x_pwr_gpio;
#endif
extern int gtp_remove_sysfs(struct i2c_client *client);
extern int gtp_create_sysfs(struct i2c_client *client);
static int gt1x_register_powermanger(void);
static int gt1x_unregister_powermanger(void);
static void gt1x_ts_work_thread(void);

/**
 * gt1x_i2c_write - i2c write.
 * @addr: register address.
 * @buffer: data buffer.
 * @len: the bytes of data to write.
 *Return: 0: success, otherwise: failed
 */
s32 gt1x_i2c_write(u16 addr, u8 * buffer, s32 len)
{
	struct i2c_msg msg = {
		.flags = 0,
		.addr = gt1x_i2c_client->addr,
	};
	return _do_i2c_write(&msg, addr, buffer, len);
}

/**
 * gt1x_i2c_read - i2c read.
 * @addr: register address.
 * @buffer: data buffer.
 * @len: the bytes of data to write.
 *Return: 0: success, otherwise: failed
 */
s32 gt1x_i2c_read(u16 addr, u8 * buffer, s32 len)
{
	u8 addr_buf[GTP_ADDR_LENGTH] = { (addr >> 8) & 0xFF, addr & 0xFF };
	struct i2c_msg msgs[2] = {
		{
		 .addr = gt1x_i2c_client->addr,
		 .flags = 0,
		 .buf = addr_buf,
		 .len = GTP_ADDR_LENGTH},
		{
		 .addr = gt1x_i2c_client->addr,
		 .flags = I2C_M_RD}
	};
	return _do_i2c_read(msgs, addr, buffer, len);
}

/**
 * gt1x_irq_enable - enable irq function.
 *
 */
void gt1x_irq_enable(void)
{
	unsigned long irqflags = 0;

	spin_lock_irqsave(&irq_lock, irqflags);
	if (irq_disabled) {
		irq_disabled = 0;
		spin_unlock_irqrestore(&irq_lock, irqflags);
		enable_irq(gt1x_i2c_client->irq);
	} else {
		spin_unlock_irqrestore(&irq_lock, irqflags);
	}
}

/**
 * gt1x_irq_enable - disable irq function.
 *	disable irq and wait bottom half
 *	thread(gt1x_ts_work_thread)
 */
void gt1x_irq_disable(void)
{
	unsigned long irqflags;

	/* because there is an irq enable action in
	 * the bottom half thread, we need to wait until
	 * bottom half thread finished.
	 */
	//synchronize_irq(gt1x_i2c_client->irq);
	spin_lock_irqsave(&irq_lock, irqflags);
	if (!irq_disabled) {
		irq_disabled = 1;
		spin_unlock_irqrestore(&irq_lock, irqflags);
		disable_irq(gt1x_i2c_client->irq);
	} else {
		spin_unlock_irqrestore(&irq_lock, irqflags);
	}
}

#ifndef CONFIG_OF
int gt1x_power_switch(s32 state)
{
	return 0;
}
#endif

int gt1x_debug_proc(u8 * buf, int count)
{
	return -1;
}

#ifdef CONFIG_GTP_CHARGER_SWITCH
u32 gt1x_get_charger_status(void)
{
	/*
	 * Need to get charger status of
	 * your platform.
	 */
	 return 0;
}
#endif

/**
 * gt1x_ts_irq_handler - External interrupt service routine
 *		for interrupt mode.
 * @irq:  interrupt number.
 * @dev_id: private data pointer.
 * Return: Handle Result.
 *			IRQ_WAKE_THREAD: top half work finished,
 *			wake up bottom half thread to continue the rest work.
 */
static irqreturn_t gt1x_ts_irq_handler(int irq, void *dev_id)
{
	//unsigned long irqflags;

	/* irq top half, use nosync irq api to 
	 * disable irq line, if irq is enabled,
	 * then wake up bottom half thread */
	/*spin_lock_irqsave(&irq_lock, irqflags);
	if (!irq_disabled) {
		irq_disabled = 1;
		spin_unlock_irqrestore(&irq_lock, irqflags);
		disable_irq_nosync(gt1x_i2c_client->irq);
		return IRQ_WAKE_THREAD;
	} else {
		spin_unlock_irqrestore(&irq_lock, irqflags);
		return IRQ_HANDLED;
	}*/
	gt1x_ts_work_thread();
	return IRQ_HANDLED;
}

/**
 * gt1x_touch_down - Report touch point event .
 * @id: trackId
 * @x:	input x coordinate
 * @y:	input y coordinate
 * @w:	input pressure
 * Return: none.
 */
void gt1x_touch_down(s32 x, s32 y, s32 size, s32 id)
{
#ifdef CONFIG_GTP_CHANGE_X2Y
	GTP_SWAP(x, y);
#endif

	input_report_key(input_dev, BTN_TOUCH, 1);
#ifdef CONFIG_GTP_TYPE_B_PROTOCOL
	input_mt_slot(input_dev, id);
	input_mt_report_slot_state(input_dev, MT_TOOL_FINGER, true);
#else
	input_report_abs(input_dev, ABS_MT_TRACKING_ID, id);
#endif

	input_report_abs(input_dev, ABS_MT_POSITION_X, x);
	input_report_abs(input_dev, ABS_MT_POSITION_Y, y);
	input_report_abs(input_dev, ABS_MT_PRESSURE, size);
	input_report_abs(input_dev, ABS_MT_TOUCH_MAJOR, size);

#ifndef CONFIG_GTP_TYPE_B_PROTOCOL
	input_mt_sync(input_dev);
#endif
}

/**
 * gt1x_touch_up -	Report touch release event.
 * @id: trackId
 * Return: none.
 */
void gt1x_touch_up(s32 id)
{
#ifdef CONFIG_GTP_TYPE_B_PROTOCOL
	input_mt_slot(input_dev, id);
	input_mt_report_slot_state(input_dev, MT_TOOL_FINGER, false);
#else
	input_mt_sync(input_dev);
#endif
}

/**
 * gt1x_ts_work_thread - Goodix touchscreen work function.
 * @iwork: work struct of gt1x_workqueue.
 * Return: none.
 */
//static irqreturn_t gt1x_ts_work_thread(int irq, void *data)
static void gt1x_ts_work_thread(void)
{
	u8 point_data[11] = { 0 };
	u8 end_cmd = 0;
	u8 finger = 0;
	s32 ret = 0;

    if (update_info.status) {
        GTP_DEBUG("Ignore interrupts during fw update.");
        return ;
    }
    
#ifdef CONFIG_GTP_GESTURE_WAKEUP
	ret = gesture_event_handler(input_dev);
	if (ret >= 0)
		goto exit_work_func;
#endif

	if (gt1x_halt) {
		GTP_DEBUG("Ignore interrupts after suspend");
        return ;
	}

	ret = gt1x_i2c_read(GTP_READ_COOR_ADDR, point_data, sizeof(point_data));
	if (ret < 0) {
		GTP_ERROR("I2C transfer error!");
#ifndef CONFIG_GTP_ESD_PROTECT
		gt1x_power_reset();
#endif
		goto exit_work_func;
	}

	finger = point_data[0];
	if (finger == 0x00)
		gt1x_request_event_handler();

	if ((finger & 0x80) == 0) {
#ifdef CONFIG_HOTKNOT_BLOCK_RW
		if (!hotknot_paired_flag)
#endif
		{
			return;
			//goto exit_eint;
		}
	}

#ifdef CONFIG_HOTKNOT_BLOCK_RW
	ret = hotknot_event_handler(point_data);
	if (!ret)
		goto exit_work_func;
#endif

#ifdef CONFIG_GTP_PROXIMITY
	ret = gt1x_prox_event_handler(point_data);
	if (ret > 0)
		goto exit_work_func;
#endif

#ifdef CONFIG_GTP_WITH_STYLUS
	ret = gt1x_touch_event_handler(point_data, input_dev, pen_dev);
#else
	ret = gt1x_touch_event_handler(point_data, input_dev, NULL);
#endif

exit_work_func:
	if (!gt1x_rawdiff_mode && (ret >= 0 || ret == ERROR_VALUE)) {
		ret = gt1x_i2c_write(GTP_READ_COOR_ADDR, &end_cmd, 1);
		if (ret < 0)
			GTP_ERROR("I2C write end_cmd  error!");
	}
//exit_eint:
    //gt1x_irq_enable();
	//return IRQ_HANDLED;
}

/*
 * Devices Tree support,
*/
#ifdef CONFIG_OF
/**
 * gt1x_parse_dt - parse platform infomation form devices tree.
 */
static int gt1x_parse_dt(struct device *dev)
{
	struct device_node *np;

	if (!dev)
		return -ENODEV;

	np = dev->of_node;
	gt1x_int_gpio = of_get_named_gpio(np, "goodix,irq-gpio", 0);
	gt1x_rst_gpio = of_get_named_gpio(np, "goodix,reset-gpio", 0);
	gt1x_pwr_gpio = of_get_named_gpio(np, "goodix,pwr-gpio", 0);

	if (!gpio_is_valid(gt1x_int_gpio) || !gpio_is_valid(gt1x_rst_gpio) || !gpio_is_valid(gt1x_pwr_gpio)) {
		GTP_ERROR("Invalid GPIO, irq-gpio:%d, rst-gpio:%d, pwr-gpio:%d",
			gt1x_int_gpio, gt1x_rst_gpio, gt1x_pwr_gpio);
		return -EINVAL;
	}

	return 0;
}

/**
 * gt1x_power_switch - power switch .
 * @on: 1-switch on, 0-switch off.
 * return: 0-succeed, -1-faileds
 */
int gt1x_power_switch(int on)
{

	int ret = -1;
	struct i2c_client *client = gt1x_i2c_client;

	if (!client)
		return -1;

	if (on) {
		GTP_DEBUG("GTP power on.");
		ret = gpio_direction_output(GTP_PWR_PORT, 1);
	} else {
		GTP_DEBUG("GTP power off.");
		ret = gpio_direction_output(GTP_PWR_PORT, 0);
	}

	msleep(10);
	return ret;

}
#endif

static void gt1x_release_resource(void)
{
	if (gpio_is_valid(GTP_INT_PORT)) {
		gpio_direction_input(GTP_INT_PORT);
		gpio_free(GTP_INT_PORT);
	}

	if (gpio_is_valid(GTP_RST_PORT)) {
		gpio_direction_output(GTP_RST_PORT, 0);
		gpio_free(GTP_RST_PORT);
	}

	if (gpio_is_valid(GTP_PWR_PORT)) {
		gpio_direction_output(GTP_PWR_PORT, 0);
		gpio_free(GTP_PWR_PORT);
	}

#ifndef CONFIG_GTP_INT_SEL_SYNC
	if (default_pctrl) {
		pinctrl_put(default_pctrl);
		default_pctrl = NULL;
	}
#endif

	if (input_dev) {
		input_unregister_device(input_dev);
		input_dev = NULL;
	}
}

/**
 * gt1x_request_gpio - Request gpio(INT & RST) ports.
 */
static s32 gt1x_request_gpio(void)
{
	s32 ret = 0;

	ret = gpio_request(GTP_INT_PORT, "GTP_INT_IRQ");
	if (ret < 0) {
		GTP_ERROR("Failed to request GPIO:%d, ERRNO:%d", (s32) GTP_INT_PORT, ret);
		return -ENODEV;
	} else {
		GTP_GPIO_AS_INT(GTP_INT_PORT);
		gt1x_i2c_client->irq = gpio_to_irq(GTP_INT_PORT);
	}

	ret = gpio_request(GTP_RST_PORT, "GTP_RST_PORT");
	if (ret < 0) {
		GTP_ERROR("Failed to request GPIO:%d, ERRNO:%d", (s32) GTP_RST_PORT, ret);
		return -ENODEV;
	}

	ret = gpio_request(GTP_PWR_PORT, "GTP_PWR_IRQ");
	if (ret < 0) {
		GTP_ERROR("Failed to request GPIO:%d, ERRNO:%d", (s32) GTP_PWR_PORT, ret);
		return -ENODEV;
	}

	GTP_GPIO_AS_INPUT(GTP_RST_PORT);
	return ret;
}

/**
 * gt1x_request_irq - Request interrupt.
 * Return
 *		0: succeed, -1: failed.
 */
static s32 gt1x_request_irq(void)
{
	s32 ret = -1;
	const u8 irq_table[] = GTP_IRQ_TAB;

	GTP_DEBUG("INT trigger type:%x", gt1x_int_type);
	ret = request_threaded_irq(gt1x_i2c_client->irq,
			NULL,
			gt1x_ts_irq_handler,
			irq_table[gt1x_int_type] | IRQF_ONESHOT,
			gt1x_i2c_client->name,
			gt1x_i2c_client);
	if (ret) {
		GTP_ERROR("Request IRQ failed!ERRNO:%d.", ret);
		return -1;
	} else {
		gt1x_irq_disable();
		return 0;
	}
}

/**
 * gt1x_request_input_dev -  Request input device Function.
 * Return
 *		0: succeed, -1: failed.
 */
static s8 gt1x_request_input_dev(void)
{
	s8 ret = -1;
#ifdef CONFIG_GTP_HAVE_TOUCH_KEY
	u8 index = 0;
#endif

	input_dev = input_allocate_device();
	if (input_dev == NULL) {
		GTP_ERROR("Failed to allocate input device.");
		return -ENOMEM;
	}

	input_dev->evbit[0] = BIT_MASK(EV_SYN) | BIT_MASK(EV_KEY) | BIT_MASK(EV_ABS);
#ifdef CONFIG_GTP_TYPE_B_PROTOCOL
#if (LINUX_VERSION_CODE > KERNEL_VERSION(3, 7, 0))
	input_mt_init_slots(input_dev, GTP_MAX_TOUCH, INPUT_MT_DIRECT);
#else
	input_mt_init_slots(input_dev, GTP_MAX_TOUCH);
#endif
#endif
	input_dev->keybit[BIT_WORD(BTN_TOUCH)] = BIT_MASK(BTN_TOUCH);
	set_bit(INPUT_PROP_DIRECT, input_dev->propbit);

#ifdef CONFIG_GTP_HAVE_TOUCH_KEY
	for (index = 0; index < GTP_MAX_KEY_NUM; index++)
		input_set_capability(input_dev, EV_KEY, gt1x_touch_key_array[index]);
#endif

#ifdef CONFIG_GTP_GESTURE_WAKEUP
	input_set_capability(input_dev, EV_KEY, KEY_GES_REGULAR);
	input_set_capability(input_dev, EV_KEY, KEY_GES_CUSTOM);
#endif

#ifdef CONFIG_GTP_CHANGE_X2Y
	input_set_abs_params(input_dev, ABS_MT_POSITION_X, 0, gt1x_abs_y_max, 0, 0);
	input_set_abs_params(input_dev, ABS_MT_POSITION_Y, 0, gt1x_abs_x_max, 0, 0);
#else
	input_set_abs_params(input_dev, ABS_MT_POSITION_X, 0, gt1x_abs_x_max, 0, 0);
	input_set_abs_params(input_dev, ABS_MT_POSITION_Y, 0, gt1x_abs_y_max, 0, 0);
#endif
	input_set_abs_params(input_dev, ABS_MT_PRESSURE, 0, 255, 0, 0);
	input_set_abs_params(input_dev, ABS_MT_TOUCH_MAJOR, 0, 255, 0, 0);
	input_set_abs_params(input_dev, ABS_MT_TRACKING_ID, 0, 255, 0, 0);

	input_dev->name = "goodix-ts";
	input_dev->phys = "input/ts";
	input_dev->id.bustype = BUS_I2C;
	input_dev->id.vendor = 0xDEAD;
	input_dev->id.product = 0xBEEF;
	input_dev->id.version = 10427;

	ret = input_register_device(input_dev);
	if (ret) {
		GTP_ERROR("Register %s input device failed", input_dev->name);
		return -ENODEV;
	}

	return 0;
}
extern int if_use_focal_ic(void);
/**
 * gt1x_ts_probe -	 I2c probe.
 * @client: i2c device struct.
 * @id: device id.
 * Return  0: succeed, <0: failed.
 */
static int gt1x_ts_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
	int ret = -1;

	/* do NOT remove these logs */
	GTP_INFO("GTP Driver Version: %s,slave addr:%02xh",
			GTP_DRIVER_VERSION, client->addr);

	gt1x_i2c_client = client;
	spin_lock_init(&irq_lock);

	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		GTP_ERROR("I2C check functionality failed.");
		return -ENODEV;
	}

	if (false != if_use_focal_ic()) {
		GTP_INFO("not goodix ic, return");
		return -ENODEV;
	}
#ifdef CONFIG_OF	/* device tree support */
	if (client->dev.of_node) {
		ret = gt1x_parse_dt(&client->dev);
		if (ret < 0)
			return -EINVAL;
	}
#else
#error [GOODIX]only support devicetree platform
#endif

	/*
	 * Pinctrl pull-up state is required by INT gpio if
	 * your kernel has the output restriction of gpio tied
	 * to IRQ line(kernel3.13 and later version).
	 */
#ifndef CONFIG_GTP_INT_SEL_SYNC
	default_pctrl = pinctrl_get_select_default(&client->dev);
	if (IS_ERR(default_pctrl)) {
		GTP_ERROR("Please add default pinctrl state"
				"(pull-up irq-gpio)");
		return PTR_ERR(default_pctrl);
	}
#endif

	/* gpio resource */
	ret = gt1x_request_gpio();
	if (ret < 0) {
		GTP_ERROR("GTP request IO port failed.");
		goto exit_clean;
	}

	/* power on */
	ret = gt1x_power_switch(SWITCH_ON);
	if (ret) {
		GTP_ERROR("Power on failed");
		goto exit_clean;
	}

	/* reset ic & do i2c test */
	ret = gt1x_reset_guitar();
	if (ret != 0) {
		ret = gt1x_power_switch(SWITCH_OFF);
		if (ret < 0)
			goto exit_clean;
		ret = gt1x_power_switch(SWITCH_ON);
		if (ret < 0)
			goto exit_clean;
		ret = gt1x_reset_guitar(); /* retry */
		if (ret != 0) {
			GTP_ERROR("Reset guitar failed!");
			goto exit_clean;
		}
	}

	/* check firmware, initialize and send
	 * chip configuration data, initialize nodes */
	ret = gt1x_init();
	if (ret < 0)
		goto exit_clean;

	ret = gt1x_request_input_dev();
	if (ret < 0)
		goto err_input;

	ret = gt1x_request_irq();
	if (ret < 0)
		goto err_irq;

#ifdef CONFIG_GTP_ESD_PROTECT
	/* must before auto update */
	gt1x_init_esd_protect();
	gt1x_esd_switch(SWITCH_ON);
#endif

#ifdef CONFIG_GTP_AUTO_UPDATE
	do {
		struct task_struct *thread = NULL;
		thread = kthread_run(gt1x_auto_update_proc,
				(void *)NULL,
				"gt1x_auto_update");
		if (IS_ERR(thread))
			GTP_ERROR("Failed to create auto-update thread: %d.", ret);
	} while (0);
#endif

#ifdef CONFIG_GTP_SYSFS_NODE_EN
    ret = gtp_create_sysfs(client);
    if (ret) {
        GTP_ERROR("create sysfs node fail");
    }
#endif
	gt1x_register_powermanger();
	gt1x_irq_enable();

//#0244395 bsp madan@smartisan.com add to support aging test begin.
	smartisan_hwstate_set("touch", "ok");
//#0244395 bsp madan@smartisan.com add to support aging test end.

	return 0;

err_irq:
err_input:
	gt1x_deinit();
exit_clean:
	gt1x_release_resource();
	GTP_ERROR("GTP probe failed:%d", ret);
//#0244395 bsp madan@smartisan.com add to support aging test begin.
	smartisan_hwstate_set("touch", "fail");
//#0244395 bsp madan@smartisan.com add to support aging test end.

	return -ENODEV;
}

/**
 * gt1x_ts_remove -  Goodix touchscreen driver release function.
 * @client: i2c device struct.
 * Return  0: succeed, -1: failed.
 */
static int gt1x_ts_remove(struct i2c_client *client)
{
	GTP_INFO("GTP driver removing...");
	gt1x_unregister_powermanger();

	gt1x_deinit();
	gt1x_release_resource();
#ifdef CONFIG_GTP_SYSFS_NODE_EN
	gtp_remove_sysfs(client);
#endif

	return 0;
}

#if   defined(CONFIG_FB)
/* frame buffer notifier block control the suspend/resume procedure */
static struct notifier_block gt1x_fb_notifier;
struct work_struct resume_work;
struct workqueue_struct *resume_workqueue;

//#0244395 bsp madan@smartisan.com add to fix tp suspend when unplug the dp line begin.
extern bool touch_needed;
//#0244395 bsp madan@smartisan.com add to fix tp suspend when unplug the dp line end.

static int gtp_fb_notifier_callback(struct notifier_block *self,
                                unsigned long event, void *data)
{
	int *blank = NULL;
	struct msm_drm_notifier *drm_data = (struct msm_drm_notifier *)data;
	
	//#0244395 bsp madan@smartisan.com add to fix tp suspend when unplug the dp line begin.
	if (drm_data != NULL && drm_data->data != NULL && touch_needed) {
		blank = drm_data->data;
		if (*blank == MSM_DRM_BLANK_POWERDOWN) {
			cancel_work_sync(&resume_work);
			flush_workqueue(resume_workqueue);
			gt1x_suspend();
		} else if (*blank == MSM_DRM_BLANK_UNBLANK) {
			queue_work(resume_workqueue,
			  &resume_work);
		}
		touch_needed = false;
	}
	//#0244395 bsp madan@smartisan.com add to fix tp suspend when unplug the dp line end.
	return 0;

}
#elif defined(CONFIG_PM)
/**
 * gt1x_ts_suspend - i2c suspend callback function.
 * @dev: i2c device.
 * Return  0: succeed, -1: failed.
 */
static int gt1x_pm_suspend(struct device *dev)
{
	return gt1x_suspend();
}

/**
 * gt1x_ts_resume - i2c resume callback function.
 * @dev: i2c device.
 * Return  0: succeed, -1: failed.
 */
static int gt1x_pm_resume(struct device *dev)
{
	return gt1x_resume();
}

/* bus control the suspend/resume procedure */
static const struct dev_pm_ops gt1x_ts_pm_ops = {
	.suspend = gt1x_pm_suspend,
	.resume = gt1x_pm_resume,
};

#elif defined(CONFIG_HAS_EARLYSUSPEND)
/* earlysuspend module the suspend/resume procedure */
static void gt1x_ts_early_suspend(struct early_suspend *h)
{
	gt1x_suspend();
}

static void gt1x_ts_late_resume(struct early_suspend *h)
{
	gt1x_resume();
}

static struct early_suspend gt1x_early_suspend = {
	.level = EARLY_SUSPEND_LEVEL_BLANK_SCREEN + 1,
	.suspend = gt1x_ts_early_suspend,
	.resume = gt1x_ts_late_resume,
};
#endif

static void gt1x_resume_work(struct work_struct *work)
{
    gt1x_resume();
}

static int gt1x_register_powermanger(void)
{
#if defined(CONFIG_FB)
    resume_workqueue = create_singlethread_workqueue("gt1x_resume");
    INIT_WORK(&resume_work, gt1x_resume_work);

	gt1x_fb_notifier.notifier_call = gtp_fb_notifier_callback;
	msm_drm_register_client(&gt1x_fb_notifier);

#elif defined(CONFIG_HAS_EARLYSUSPEND)
	register_early_suspend(&gt1x_early_suspend);
#endif
	return 0;
}

static int gt1x_unregister_powermanger(void)
{
#if   defined(CONFIG_FB)
	fb_unregister_client(&gt1x_fb_notifier);
	destroy_workqueue(resume_workqueue);
#elif defined(CONFIG_HAS_EARLYSUSPEND)
	unregister_early_suspend(&gt1x_early_suspend);
#endif
	return 0;
}

#ifdef CONFIG_OF
static const struct of_device_id gt1x_match_table[] = {
		{.compatible = "goodix,gt1x",},
		{ },
};
#endif

static const struct i2c_device_id gt1x_ts_id[] = {
	{GTP_I2C_NAME, 0},
	{}
};

static struct i2c_driver gt1x_ts_driver = {
	.probe = gt1x_ts_probe,
	.remove = gt1x_ts_remove,
	.id_table = gt1x_ts_id,
	.driver = {
		   .name = GTP_I2C_NAME,
		   .owner = THIS_MODULE,
#ifdef CONFIG_OF
		   .of_match_table = gt1x_match_table,
#endif
#if !defined(CONFIG_FB) && defined(CONFIG_PM)
		   .pm = &gt1x_ts_pm_ops,
#endif
		   },
};

/**
 * gt1x_ts_init - Driver Install function.
 * Return	0---succeed.
 */
static int __init gt1x_ts_init(void)
{
	GTP_INFO("GTP driver installing...");
	return i2c_add_driver(&gt1x_ts_driver);
}

/**
 * gt1x_ts_exit - Driver uninstall function.
 * Return	0---succeed.
 */
static void __exit gt1x_ts_exit(void)
{
	GTP_DEBUG_FUNC();
	GTP_INFO("GTP driver exited.");
	i2c_del_driver(&gt1x_ts_driver);
}

module_init(gt1x_ts_init);
module_exit(gt1x_ts_exit);

MODULE_DESCRIPTION("GTP Series Driver");
MODULE_LICENSE("GPL v2");
