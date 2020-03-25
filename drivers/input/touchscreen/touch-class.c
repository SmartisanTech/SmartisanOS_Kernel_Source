/*
 * TouchScreen Class Interface
 *
 * Copyright (C) 2019-2022, ByteDance Inc., all rights reserved.
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

#include <linux/ctype.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/touchscreen.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

static struct class *touch_class;

/*****************************************************************************
* Glove Mode: enable: 1 disable: 0
*****************************************************************************/
static ssize_t glove_mode_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct touch_classdev *touch_cdev = dev_get_drvdata(dev);

	return sprintf(buf, "%u\n", touch_cdev->touch_mode_get(GLOVE_MODE));
}

static ssize_t glove_mode_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t size)
{

	struct touch_classdev *touch_cdev = dev_get_drvdata(dev);
	int state;

	mutex_lock(&touch_cdev->touch_mutex);

	if (kstrtoint(buf, 10, &state) < 0)
		goto unlock;

	touch_cdev->touch_mode_set(GLOVE_MODE, state);

unlock:
	mutex_unlock(&touch_cdev->touch_mutex);
	return size;
}
static DEVICE_ATTR_RW(glove_mode);

/*****************************************************************************
* Touch Major Report: enable: 1 disable: 0
*****************************************************************************/
static ssize_t touch_major_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct touch_classdev *touch_cdev = dev_get_drvdata(dev);

	return sprintf(buf, "%u\n", touch_cdev->touch_mode_get(TOUCH_MAJOR));
}

static ssize_t touch_major_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t size)
{
	struct touch_classdev *touch_cdev = dev_get_drvdata(dev);
	int state;

	mutex_lock(&touch_cdev->touch_mutex);

	if (kstrtoint(buf, 10, &state) < 0)
		goto unlock;

	touch_cdev->touch_mode_set(TOUCH_MAJOR, state);

unlock:
	mutex_unlock(&touch_cdev->touch_mutex);
	return size;
}
static DEVICE_ATTR_RW(touch_major);

/*****************************************************************************
* Touch Minor Report: enable: 1 disable: 0
*****************************************************************************/
static ssize_t touch_minor_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct touch_classdev *touch_cdev = dev_get_drvdata(dev);

	return sprintf(buf, "%u\n", touch_cdev->touch_mode_get(TOUCH_MINOR));
}

static ssize_t touch_minor_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t size)
{
	struct touch_classdev *touch_cdev = dev_get_drvdata(dev);
	int state;

	mutex_lock(&touch_cdev->touch_mutex);

	if (kstrtoint(buf, 10, &state) < 0)
		goto unlock;

	touch_cdev->touch_mode_set(TOUCH_MINOR, state);

unlock:
	mutex_unlock(&touch_cdev->touch_mutex);
	return size;
}
static DEVICE_ATTR_RW(touch_minor);

/*****************************************************************************
* Gesture Mode: enable: 1 disable: 0
*****************************************************************************/
static ssize_t gesture_mode_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct touch_classdev *touch_cdev = dev_get_drvdata(dev);

	return sprintf(buf, "%u\n", touch_cdev->touch_mode_get(GESTURE_MODE));
}

static ssize_t gesture_mode_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t size)
{
	struct touch_classdev *touch_cdev = dev_get_drvdata(dev);
	int state;

	mutex_lock(&touch_cdev->touch_mutex);

	if (kstrtoint(buf, 10, &state) < 0)
		goto unlock;

	touch_cdev->touch_mode_set(GESTURE_MODE, state);

unlock:
	mutex_unlock(&touch_cdev->touch_mutex);
	return size;
}
static DEVICE_ATTR_RW(gesture_mode);

/*****************************************************************************
* Suspend TouchScreen: enable: 1 disable: 0
*****************************************************************************/
static ssize_t suspend_touch_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct touch_classdev *touch_cdev = dev_get_drvdata(dev);

	return sprintf(buf, "%u\n", touch_cdev->touch_mode_get(SUSPEND_TOUCH));
}

static ssize_t suspend_touch_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t size)
{
	struct touch_classdev *touch_cdev = dev_get_drvdata(dev);
	int state;

	mutex_lock(&touch_cdev->touch_mutex);

	if (kstrtoint(buf, 10, &state) < 0)
		goto unlock;

	touch_cdev->touch_mode_set(SUSPEND_TOUCH, state);

unlock:
	mutex_unlock(&touch_cdev->touch_mutex);
	return size;
}
static DEVICE_ATTR_RW(suspend_touch);

static struct attribute *touchscreen_touch_attrs[] = {
	&dev_attr_glove_mode.attr,
	&dev_attr_touch_major.attr,
	&dev_attr_touch_minor.attr,
	&dev_attr_gesture_mode.attr,
	&dev_attr_suspend_touch.attr,
	NULL,
};

static const struct attribute_group touchscreen_touch_group = {
	.attrs = touchscreen_touch_attrs,
};

#ifdef CONFIG_TOUCHSCREEN_GAME_SUPPORT
static const struct attribute_group touchscreen_game_group = {
	.attrs = touchscreen_game_attrs,
};
#endif

#ifdef CONFIG_TOUCHSCREEN_TEST_SUPPORT
static const struct attribute_group touchscreen_test_group = {
	.attrs = touchscreen_test_attrs,
};
#endif

/*****************************************************************************
* touchscreen_class_register
*****************************************************************************/
int touchscreen_class_register(struct touch_classdev *touch_cdev)
{
	touch_cdev->dev_touch = device_create(touch_class, NULL, 0, touch_cdev, "touch");
	if (IS_ERR(touch_cdev->dev_touch))
		return PTR_ERR(touch_cdev->dev_touch);

	if (sysfs_create_group(&touch_cdev->dev_touch->kobj, &touchscreen_touch_group))
		return -ENODEV;

#ifdef CONFIG_TOUCHSCREEN_GAME_SUPPORT
	touch_cdev->dev_game = device_create(touch_class, NULL, 0, touch_cdev, "game");
	if (IS_ERR(touch_cdev->dev_game))
		return PTR_ERR(touch_cdev->dev_game);

	if (sysfs_create_group(&touch_cdev->dev_game->kobj, &touchscreen_game_group))
		return -ENODEV;
#endif
#ifdef CONFIG_TOUCHSCREEN_TEST_SUPPORT
	touch_cdev->dev_test = device_create(touch_class, NULL, 0, touch_cdev, "test");
	if (IS_ERR(touch_cdev->dev_test))
		return PTR_ERR(touch_cdev->dev_test);

	if (sysfs_create_group(&touch_cdev->dev_test->kobj, &touchscreen_test_group))
		return -ENODEV;
#endif
	mutex_init(&touch_cdev->touch_mutex);

	return 0;
}
EXPORT_SYMBOL(touchscreen_class_register);

/*****************************************************************************
* touchscreen_class_unregister
*****************************************************************************/
void touchscreen_class_unregister(struct touch_classdev *touch_cdev)
{
	device_destroy(touch_class, 0);

	mutex_destroy(&touch_cdev->touch_mutex);
}
EXPORT_SYMBOL(touchscreen_class_unregister);

static int __init touch_init(void)
{
	touch_class = class_create(THIS_MODULE, "touchscreen");
	if (IS_ERR(touch_class))
		return PTR_ERR(touch_class);

	return 0;
}

static void __exit touch_exit(void)
{
	class_destroy(touch_class);
}

subsys_initcall(touch_init);
module_exit(touch_exit);

MODULE_AUTHOR("Newstone Lab Driver Team");
MODULE_DESCRIPTION("Touchscreen Class Interface");
MODULE_LICENSE("GPL v2");
