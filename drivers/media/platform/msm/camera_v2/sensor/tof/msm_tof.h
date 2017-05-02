/* Copyright (c) 2014-2015, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#ifndef MSM_TOF_H
#define MSM_TOF_H

#include <linux/i2c.h>
#include <linux/gpio.h>
#include <linux/of_gpio.h>
#include <soc/qcom/camera2.h>
#include <media/v4l2-subdev.h>
#include <media/msmb_camera.h>
#include "msm_camera_i2c.h"
#include "msm_camera_dt_util.h"
#include "msm_camera_io_util.h"

#define DEFINE_MSM_MUTEX(mutexname) \
	static struct mutex mutexname = __MUTEX_INITIALIZER(mutexname)

#define	MSM_TOF_MAX_VREGS (10)

struct msm_tof_ctrl_t;

enum msm_tof_state_t {
	TOF_ENABLE_STATE,
	TOF_OPS_ACTIVE,
	TOF_OPS_INACTIVE,
	TOF_DISABLE_STATE,
};

struct msm_tof_vreg {
	struct camera_vreg_t *cam_vreg;
	void *data[MSM_TOF_MAX_VREGS];
	int num_vreg;
};

struct msm_tof_gpio {
	struct msm_camera_gpio_conf *cam_gconf;
	struct msm_pinctrl_info pinctrl_info;
	int num_gpio;
};

struct msm_tof_ctrl_t {
	int shared_power_flag;
	struct i2c_driver *i2c_driver;
	struct platform_driver *pdriver;
	struct platform_device *pdev;
	struct msm_camera_i2c_client i2c_client;
	enum msm_camera_device_type_t tof_device_type;
	struct msm_sd_subdev msm_sd;
	struct mutex *tof_mutex;
	enum msm_camera_i2c_data_type i2c_data_type;
	struct v4l2_subdev sdev;
	struct v4l2_subdev_ops *tof_v4l2_subdev_ops;
	void *user_data;
	uint16_t i2c_tbl_index;
	enum cci_i2c_master_t cci_master;
	uint32_t subdev_id;
	enum msm_tof_state_t tof_state;
	struct msm_tof_vreg vreg_cfg;
	struct msm_tof_gpio gpio_cfg;
	struct msm_tof_gpio shared_gpio_cfg;
	uint8_t chip_id;
	uint32_t chip_id_addr;
};

#endif
