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
#ifndef __LINUX_TOUCHSCREEN_H_INCLUDED
#define __LINUX_TOUCHSCREEN_H_INCLUDED

#include <linux/device.h>
#include <linux/kernfs.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/workqueue.h>

struct device;

enum touch_mode {
	GLOVE_MODE = 0,
	TOUCH_MAJOR,
	TOUCH_MINOR,
	GESTURE_MODE,
	SUSPEND_TOUCH,
};

struct touch_classdev {
	struct device           *dev;
	void	(*touch_mode_set)(enum touch_mode mode, int state);
	int	(*touch_mode_get)(enum touch_mode mode);
	struct device		*dev_touch;
#ifdef CONFIG_TOUCHSCREEN_GAME_SUPPORT
	struct device		*dev_game;
#endif
#ifdef CONFIG_TOUCHSCREEN_TEST_SUPPORT
	struct device		*dev_test
#endif
	struct mutex		touch_mutex;
};

extern int touchscreen_class_register(struct touch_classdev *touch_cdev);
extern void touchscreen_class_unregister(struct touch_classdev *touch_cdev);

#endif		/* __LINUX_TOUCHSCREEN_H_INCLUDED */
