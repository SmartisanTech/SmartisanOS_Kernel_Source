/* Copyright (c) 2014 - 2016, The Linux Foundation. All rights reserved.
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

#define pr_fmt(fmt) "%s:%d " fmt, __func__, __LINE__

#include <linux/module.h>
#include "msm_sd.h"
#include "msm_tof.h"
#include "msm_cci.h"

DEFINE_MSM_MUTEX(msm_tof_mutex);
//#define MSM_TOF_DEBUG
#undef CDBG
#ifdef MSM_TOF_DEBUG
#define CDBG(fmt, args...) pr_err(fmt, ##args)
#else
#define CDBG(fmt, args...) pr_debug(fmt, ##args)
#endif
#define CAM_SENSOR_PINCTRL_STATE_SLEEP "cam_suspend"
#define CAM_SENSOR_PINCTRL_STATE_DEFAULT "cam_default"
#define CAM_SENSOR_SHARED_PINCTRL_STATE_SLEEP "cam_shared_suspend"
#define CAM_SENSOR_SHARED_PINCTRL_STATE_DEFAULT "cam_shared_default"

static struct v4l2_file_operations msm_tof_v4l2_subdev_fops;
static int32_t msm_tof_power_up(struct msm_tof_ctrl_t *o_ctrl);
static int32_t msm_tof_power_down(struct msm_tof_ctrl_t *o_ctrl);

static struct i2c_driver msm_tof_i2c_driver;

static int32_t msm_tof_write_settings(struct msm_tof_ctrl_t *o_ctrl,
	uint16_t size, struct reg_settings_tof_t *settings)
{
	int32_t rc = -EFAULT;
	int32_t i = 0;
	struct msm_camera_i2c_seq_reg_array *reg_setting;
	CDBG("Enter\n");

	for (i = 0; i < size; i++) {
		switch (settings[i].i2c_operation) {
		case MSM_TOF_WRITE: {
			switch (settings[i].data_type) {
			case MSM_CAMERA_I2C_BYTE_DATA:
			case MSM_CAMERA_I2C_SET_BYTE_MASK:
			case MSM_CAMERA_I2C_WORD_DATA:
				rc = o_ctrl->i2c_client.i2c_func_tbl->i2c_write(
					&o_ctrl->i2c_client,
					settings[i].reg_addr,
					settings[i].reg_data,
					settings[i].data_type);
				break;
			case MSM_CAMERA_I2C_DWORD_DATA:
			reg_setting =
			kzalloc(sizeof(struct msm_camera_i2c_seq_reg_array),
				GFP_KERNEL);
				if (!reg_setting)
					return -ENOMEM;

				reg_setting->reg_addr = settings[i].reg_addr;
				reg_setting->reg_data[0] = (uint8_t)
					((settings[i].reg_data &
					0xFF000000) >> 24);
				reg_setting->reg_data[1] = (uint8_t)
					((settings[i].reg_data &
					0x00FF0000) >> 16);
				reg_setting->reg_data[2] = (uint8_t)
					((settings[i].reg_data &
					0x0000FF00) >> 8);
				reg_setting->reg_data[3] = (uint8_t)
					(settings[i].reg_data & 0x000000FF);
				reg_setting->reg_data_size = 4;
				rc = o_ctrl->i2c_client.i2c_func_tbl->
					i2c_write_seq(&o_ctrl->i2c_client,
					reg_setting->reg_addr,
					reg_setting->reg_data,
					reg_setting->reg_data_size);
				kfree(reg_setting);
				reg_setting = NULL;
				if (rc < 0)
					return rc;
				break;

			default:
				pr_err("Unsupport data type: %d\n",
					settings[i].data_type);
				break;
			}
			if (settings[i].delay > 20)
				msleep(settings[i].delay);
			else if (0 != settings[i].delay)
				usleep_range(settings[i].delay * 1000,
					(settings[i].delay * 1000) + 1000);
		}
			break;

		case MSM_TOF_POLL: {
			switch (settings[i].data_type) {
			case MSM_CAMERA_I2C_BYTE_DATA:
			case MSM_CAMERA_I2C_WORD_DATA:

				rc = o_ctrl->i2c_client.i2c_func_tbl
					->i2c_poll(&o_ctrl->i2c_client,
					settings[i].reg_addr,
					settings[i].reg_data,
					settings[i].data_type,
					settings[i].delay);
				break;

			default:
				pr_err("Unsupport data type: %d\n",
					settings[i].data_type);
				break;
			}
		}
			break;
		case MSM_TOF_READ_SEQ: {
			switch (settings[i].data_type) {
			case MSM_CAMERA_I2C_BYTE_DATA:
			case MSM_CAMERA_I2C_WORD_DATA:
				if (settings[i].reg_data_len > 0) {
					uint8_t *data_out = kzalloc ( settings[i].reg_data_len, GFP_KERNEL);
					//pr_err("[xxp] addr=%x, data_len=%d, data_addr=%d", settings[i].reg_addr, settings[i].reg_data_len, settings[i].reg_data_addr);
					rc = o_ctrl->i2c_client.i2c_func_tbl->i2c_read_seq(&o_ctrl->i2c_client,
							settings[i].reg_addr,data_out,settings[i].reg_data_len);
					rc = copy_to_user (compat_ptr(settings[i].reg_data_addr), (void *)data_out, settings[i].reg_data_len);
					kfree(data_out);	
					}
				break;
			default:
				pr_err("Unsupport data type: %d\n",
					settings[i].data_type);
				break;
			}
		}
		break;
		case MSM_TOF_WRITE_SEQ: {
				if (settings[i].reg_data_len > 0) {
					uint8_t *data_in = kzalloc ( settings[i].reg_data_len, GFP_KERNEL);
					rc = copy_from_user ((void *)data_in, compat_ptr(settings[i].reg_data_addr), settings[i].reg_data_len);
					rc = o_ctrl->i2c_client.i2c_func_tbl->
						i2c_write_seq(&o_ctrl->i2c_client,
								settings[i].reg_addr,
								data_in,
								settings[i].reg_data_len);
					kfree(data_in);
				}
		}
		break;
		case MSM_TOF_READ: {
			uint16_t data = 0;
			switch (settings[i].data_type) {
			case MSM_CAMERA_I2C_BYTE_DATA:
			case MSM_CAMERA_I2C_WORD_DATA:
				rc = o_ctrl->i2c_client.i2c_func_tbl
					->i2c_read(&o_ctrl->i2c_client,
					settings[i].reg_addr,
					&data,
					settings[i].data_type);
				break;

			default:
				pr_err("Unsupport data type: %d\n",
					settings[i].data_type);
				break;
			}
		}
		break;
		}

		if (rc < 0)
			break;
	}

	CDBG("Exit\n");
	return rc;
}

static int32_t msm_tof_vreg_control(struct msm_tof_ctrl_t *o_ctrl,
							int config)
{
	int rc = 0, i, cnt;
	struct msm_tof_vreg *vreg_cfg;

	vreg_cfg = &o_ctrl->vreg_cfg;
	cnt = vreg_cfg->num_vreg;
	if (!cnt)
		return 0;

	if (cnt >= MSM_TOF_MAX_VREGS) {
		pr_err("%s failed %d cnt %d\n", __func__, __LINE__, cnt);
		return -EINVAL;
	}

	for (i = 0; i < cnt; i++) {
		rc = msm_camera_config_single_vreg(&(o_ctrl->pdev->dev),
			&vreg_cfg->cam_vreg[i],
			(struct regulator **)&vreg_cfg->data[i],
			config);
	}
	return rc;
}

static int32_t msm_tof_power_down(struct msm_tof_ctrl_t *o_ctrl)
{
	int32_t rc = 0;
	CDBG("[] %sEnter \n", __func__);
	if (o_ctrl->tof_state != TOF_DISABLE_STATE) {

		rc = msm_tof_vreg_control(o_ctrl, 0);
		if (rc < 0) {
			pr_err("[]%s failed %d\n", __func__, __LINE__);
			return rc;
		}
		if (o_ctrl->shared_power_flag == 1) {
			rc = msm_camera_request_gpio_table(o_ctrl->shared_gpio_cfg.cam_gconf->cam_gpio_req_tbl,
				o_ctrl->shared_gpio_cfg.cam_gconf->cam_gpio_req_tbl_size, 1);
		if(rc < 0){
			pr_err("%s failed %d\n",__func__,__LINE__);
			return rc;
		}

		gpio_set_value_cansleep(o_ctrl->shared_gpio_cfg.cam_gconf->gpio_num_info->gpio_num[SENSOR_SHARED_GPIO_VDIG],0);
        			rc = pinctrl_select_state(o_ctrl->shared_gpio_cfg.pinctrl_info.pinctrl,
				o_ctrl->shared_gpio_cfg.pinctrl_info.gpio_state_suspend);
		if(rc < 0){
			pr_err("%s failed %d\n",__func__,__LINE__);
			return rc;
		}
		rc = msm_camera_request_gpio_table(o_ctrl->shared_gpio_cfg.cam_gconf->cam_gpio_req_tbl,
				o_ctrl->shared_gpio_cfg.cam_gconf->cam_gpio_req_tbl_size, 0);
		if(rc < 0){
			pr_err("%s failed %d\n",__func__,__LINE__);
			return rc;
		}

				}

		if (1) {
			rc = msm_camera_request_gpio_table(o_ctrl->gpio_cfg.cam_gconf->cam_gpio_req_tbl,
				o_ctrl->gpio_cfg.cam_gconf->cam_gpio_req_tbl_size, 1);
		if(rc < 0){
			pr_err("%s failed %d\n",__func__,__LINE__);
			return rc;
		}

		gpio_set_value_cansleep(o_ctrl->gpio_cfg.cam_gconf->gpio_num_info->gpio_num[SENSOR_GPIO_XSHUT],0);
		rc = pinctrl_select_state(o_ctrl->gpio_cfg.pinctrl_info.pinctrl,
			o_ctrl->gpio_cfg.pinctrl_info.gpio_state_suspend);
		if(rc < 0){
			pr_err("%s failed %d\n",__func__,__LINE__);
			return rc;
		}
		rc = msm_camera_request_gpio_table(o_ctrl->gpio_cfg.cam_gconf->cam_gpio_req_tbl,
				o_ctrl->gpio_cfg.cam_gconf->cam_gpio_req_tbl_size, 0);
		if(rc < 0){
			pr_err("%s failed %d\n",__func__,__LINE__);
			return rc;
		}

				}

	o_ctrl->i2c_tbl_index = 0;
        	o_ctrl->tof_state = TOF_OPS_INACTIVE;



	}
	CDBG("[]%sExit\n", __func__);
	return rc;
}

static int msm_tof_init(struct msm_tof_ctrl_t *o_ctrl)
{
	int rc = 0;
	CDBG("Enter\n");

	if (!o_ctrl) {
		pr_err("failed\n");
		return -EINVAL;
	}

	if (o_ctrl->tof_device_type == MSM_CAMERA_PLATFORM_DEVICE) {
		rc = o_ctrl->i2c_client.i2c_func_tbl->i2c_util(
			&o_ctrl->i2c_client, MSM_CCI_INIT);
		if (rc < 0)
			pr_err("cci_init failed\n");
	}
	o_ctrl->tof_state = TOF_OPS_ACTIVE;
	CDBG("Exit\n");
	return rc;
}

static int32_t msm_tof_control(struct msm_tof_ctrl_t *o_ctrl,
	struct msm_tof_set_info_t *set_info)
{
	struct reg_settings_tof_t *settings = NULL;
	int32_t rc = 0;
	struct msm_camera_cci_client *cci_client = NULL;
	CDBG("Enter\n");

	if (o_ctrl->tof_device_type == MSM_CAMERA_PLATFORM_DEVICE) {
		cci_client = o_ctrl->i2c_client.cci_client;
		cci_client->sid =
			set_info->tof_params.i2c_addr >> 1;
		cci_client->retries = 3;
		cci_client->id_map = 0;
		cci_client->cci_i2c_master = o_ctrl->cci_master;
		cci_client->i2c_freq_mode = set_info->tof_params.i2c_freq_mode;
	} else {
		o_ctrl->i2c_client.client->addr =
			set_info->tof_params.i2c_addr;
	}
	o_ctrl->i2c_client.addr_type = MSM_CAMERA_I2C_BYTE_ADDR;


	if (set_info->tof_params.setting_size > 0 &&
		set_info->tof_params.setting_size
		< MAX_TOF_REG_SETTINGS) {
		settings = kmalloc(
			sizeof(struct reg_settings_tof_t) *
			(set_info->tof_params.setting_size),
			GFP_KERNEL);
		if (settings == NULL) {
			pr_err("Error allocating memory\n");
			return -EFAULT;
		}
		if (copy_from_user(settings,
			(void *)set_info->tof_params.settings,
			set_info->tof_params.setting_size *
			sizeof(struct reg_settings_tof_t))) {
			kfree(settings);
			pr_err("Error copying\n");
			return -EFAULT;
		}

		rc = msm_tof_write_settings(o_ctrl,
			set_info->tof_params.setting_size,
			settings);
		kfree(settings);
		if (rc < 0) {
			pr_err("Error\n");
			return -EFAULT;
		}
	}

	CDBG("Exit\n");

	return rc;
}


static int32_t msm_tof_config(struct msm_tof_ctrl_t *o_ctrl,
	void __user *argp)
{
	struct msm_tof_cfg_data *cdata =
		(struct msm_tof_cfg_data *)argp;
	int32_t rc = 0;
	mutex_lock(o_ctrl->tof_mutex);
	CDBG("Enter\n");
	CDBG("%s type %d\n", __func__, cdata->cfgtype);
	switch (cdata->cfgtype) {
	case CFG_TOF_INIT:
		rc = msm_tof_init(o_ctrl);
		if (rc < 0)
			pr_err("msm_tof_init failed %d\n", rc);
		break;
	case CFG_TOF_POWERDOWN:
		o_ctrl->shared_power_flag = cdata->cfg.shared_power_flag;
		rc = msm_tof_power_down(o_ctrl);
		if (rc < 0)
			pr_err("msm_tof_power_down failed %d\n", rc);
		break;
	case CFG_TOF_POWERUP:
		o_ctrl->shared_power_flag = cdata->cfg.shared_power_flag;

		rc = msm_tof_power_up(o_ctrl);
		if (rc < 0)
			pr_err("Failed tof power up%d\n", rc);
		break;
	case CFG_TOF_CONTROL:
		rc = msm_tof_control(o_ctrl, &cdata->cfg.set_info);
		if (rc < 0)
			pr_err("Failed tof control%d\n", rc);
		break;
	case CFG_TOF_I2C_WRITE_SEQ_TABLE: {
		struct msm_camera_i2c_seq_reg_setting conf_array;
		struct msm_camera_i2c_seq_reg_array *reg_setting = NULL;

#ifdef CONFIG_COMPAT
		if (is_compat_task()) {
			memcpy(&conf_array,
				(void *)cdata->cfg.settings,
				sizeof(struct msm_camera_i2c_seq_reg_setting));
		} else
#endif
		if (copy_from_user(&conf_array,
			(void *)cdata->cfg.settings,
			sizeof(struct msm_camera_i2c_seq_reg_setting))) {
			pr_err("%s:%d failed\n", __func__, __LINE__);
			rc = -EFAULT;
			break;
		}

		if (!conf_array.size) {
			pr_err("%s:%d failed\n", __func__, __LINE__);
			rc = -EFAULT;
			break;
		}
		reg_setting = kzalloc(conf_array.size *
			(sizeof(struct msm_camera_i2c_seq_reg_array)),
			GFP_KERNEL);
		if (!reg_setting) {
			pr_err("%s:%d failed\n", __func__, __LINE__);
			rc = -ENOMEM;
			break;
		}
		if (copy_from_user(reg_setting, (void *)conf_array.reg_setting,
			conf_array.size *
			sizeof(struct msm_camera_i2c_seq_reg_array))) {
			pr_err("%s:%d failed\n", __func__, __LINE__);
			kfree(reg_setting);
			rc = -EFAULT;
			break;
		}

		conf_array.reg_setting = reg_setting;
		rc = o_ctrl->i2c_client.i2c_func_tbl->
			i2c_write_seq_table(&o_ctrl->i2c_client,
			&conf_array);
		kfree(reg_setting);
		break;
	}
	default:
		break;
	}
	mutex_unlock(o_ctrl->tof_mutex);
	CDBG("Exit\n");
	return rc;
}

static int32_t msm_tof_get_subdev_id(struct msm_tof_ctrl_t *o_ctrl,
	void *arg)
{
	uint32_t *subdev_id = (uint32_t *)arg;
	CDBG("Enter\n");
	if (!subdev_id) {
		pr_err("failed\n");
		return -EINVAL;
	}
	if (o_ctrl->tof_device_type == MSM_CAMERA_PLATFORM_DEVICE)
		*subdev_id = o_ctrl->pdev->id;
	else
		*subdev_id = o_ctrl->subdev_id;

	CDBG("subdev_id %d\n", *subdev_id);
	CDBG("Exit\n");
	return 0;
}

static struct msm_camera_i2c_fn_t msm_sensor_cci_func_tbl = {
	.i2c_read = msm_camera_cci_i2c_read,
	.i2c_read_seq = msm_camera_cci_i2c_read_seq,
	.i2c_write = msm_camera_cci_i2c_write,
	.i2c_write_table = msm_camera_cci_i2c_write_table,
	.i2c_write_seq = msm_camera_cci_i2c_write_seq,
	.i2c_write_seq_table = msm_camera_cci_i2c_write_seq_table,
	.i2c_write_table_w_microdelay =
		msm_camera_cci_i2c_write_table_w_microdelay,
	.i2c_util = msm_sensor_cci_i2c_util,
	.i2c_poll =  msm_camera_cci_i2c_poll,
};

static struct msm_camera_i2c_fn_t msm_sensor_qup_func_tbl = {
	.i2c_read = msm_camera_qup_i2c_read,
	.i2c_read_seq = msm_camera_qup_i2c_read_seq,
	.i2c_write = msm_camera_qup_i2c_write,
	.i2c_write_table = msm_camera_qup_i2c_write_table,
	.i2c_write_seq = msm_camera_qup_i2c_write_seq,
	.i2c_write_seq_table = msm_camera_qup_i2c_write_seq_table,
	.i2c_write_table_w_microdelay =
		msm_camera_qup_i2c_write_table_w_microdelay,
	.i2c_poll = msm_camera_qup_i2c_poll,
};

static int msm_tof_close(struct v4l2_subdev *sd,
	struct v4l2_subdev_fh *fh) {
	int rc = 0;
	struct msm_tof_ctrl_t *o_ctrl =  v4l2_get_subdevdata(sd);
	CDBG("Enter\n");
	if (!o_ctrl) {
		pr_err("failed\n");
		return -EINVAL;
	}
	mutex_lock(o_ctrl->tof_mutex);
	if (o_ctrl->tof_device_type == MSM_CAMERA_PLATFORM_DEVICE &&
		o_ctrl->tof_state != TOF_DISABLE_STATE) {
		rc = o_ctrl->i2c_client.i2c_func_tbl->i2c_util(
			&o_ctrl->i2c_client, MSM_CCI_RELEASE);
		if (rc < 0)
			pr_err("cci_init failed\n");
	}
	o_ctrl->tof_state = TOF_DISABLE_STATE;
	mutex_unlock(o_ctrl->tof_mutex);
	CDBG("Exit\n");
	return rc;
}

static const struct v4l2_subdev_internal_ops msm_tof_internal_ops = {
	.close = msm_tof_close,
};

static long msm_tof_subdev_ioctl(struct v4l2_subdev *sd,
			unsigned int cmd, void *arg)
{
	int rc;
	struct msm_tof_ctrl_t *o_ctrl = v4l2_get_subdevdata(sd);
	void __user *argp = (void __user *)arg;
	CDBG("Enter\n");
	CDBG("%s:%d o_ctrl %p argp %p\n", __func__, __LINE__, o_ctrl, argp);
	switch (cmd) {
	case VIDIOC_MSM_SENSOR_GET_SUBDEV_ID:
		return msm_tof_get_subdev_id(o_ctrl, argp);
	case VIDIOC_MSM_TOF_CFG:
		return msm_tof_config(o_ctrl, argp);
	case MSM_SD_SHUTDOWN:
		if (!o_ctrl->i2c_client.i2c_func_tbl) {
			pr_err("o_ctrl->i2c_client.i2c_func_tbl NULL\n");
			return -EINVAL;
		}
		rc = msm_tof_power_down(o_ctrl);
		if (rc < 0) {
			pr_err("%s:%d TOF Power down failed\n",
				__func__, __LINE__);
		}
		return msm_tof_close(sd, NULL);
	default:
		return -ENOIOCTLCMD;
	}
}


static int msm_tof_pinctrl_init(struct msm_tof_ctrl_t *ctrl)
{
	struct msm_pinctrl_info *tof_pctrl = NULL;
	struct msm_pinctrl_info *shared_tof_pctrl = NULL;
	tof_pctrl = &(ctrl->gpio_cfg.pinctrl_info);
	shared_tof_pctrl = &(ctrl->shared_gpio_cfg.pinctrl_info);
	tof_pctrl->pinctrl = devm_pinctrl_get(&(ctrl->pdev->dev));
	shared_tof_pctrl->pinctrl = devm_pinctrl_get(&(ctrl->pdev->dev));

        if (IS_ERR_OR_NULL(tof_pctrl->pinctrl)){
		pr_err("%s:%d Getting pinctrl handle failed\n",
				__func__, __LINE__);
		return -EINVAL;
	}
	pr_err(": tof_pctrl->pinctrl=%p\n",tof_pctrl->pinctrl);
	tof_pctrl->gpio_state_active =
		pinctrl_lookup_state(tof_pctrl->pinctrl,CAM_SENSOR_PINCTRL_STATE_DEFAULT);
	if (IS_ERR_OR_NULL(tof_pctrl->gpio_state_active)) {
		pr_err("%s:%d Failed to get the active state pinctrl handle\n",
				__func__, __LINE__);
		return -EINVAL;
	}
	tof_pctrl->gpio_state_suspend =
		pinctrl_lookup_state(tof_pctrl->pinctrl,CAM_SENSOR_PINCTRL_STATE_SLEEP);
	if (IS_ERR_OR_NULL(tof_pctrl->gpio_state_suspend)) {
		pr_err("%s:%d Failed to get the suspend state pinctrl handle\n",
				__func__, __LINE__);
		return -EINVAL;
	}
	if (IS_ERR_OR_NULL(shared_tof_pctrl->pinctrl)){
		pr_err("%s:%d Getting pinctrl handle failed\n",
				__func__, __LINE__);
		return -EINVAL;
	}
	pr_err(": tof_pctrl->pinctrl=%p\n",shared_tof_pctrl->pinctrl);
	shared_tof_pctrl->gpio_state_active =
		pinctrl_lookup_state(shared_tof_pctrl->pinctrl,CAM_SENSOR_SHARED_PINCTRL_STATE_DEFAULT);
	if (IS_ERR_OR_NULL(shared_tof_pctrl->gpio_state_active)) {
		pr_err("%s:%d Failed to get the active state pinctrl handle\n",
				__func__, __LINE__);
		return -EINVAL;
	}
	shared_tof_pctrl->gpio_state_suspend =
		pinctrl_lookup_state(shared_tof_pctrl->pinctrl,CAM_SENSOR_SHARED_PINCTRL_STATE_SLEEP);
	if (IS_ERR_OR_NULL(shared_tof_pctrl->gpio_state_suspend)) {
		pr_err("%s:%d Failed to get the suspend state pinctrl handle\n",
				__func__, __LINE__);
		return -EINVAL;
	}

	return 0;
}

static int32_t msm_tof_power_up(struct msm_tof_ctrl_t *o_ctrl)
{
	int rc = 0;
	struct msm_camera_i2c_client *tof_i2c_client;
	CDBG("%s called\n", __func__);
	rc = msm_tof_vreg_control(o_ctrl, 1);
	if (rc < 0) {
		pr_err("%s failed %d\n", __func__, __LINE__);
		return rc;
	}
	tof_i2c_client = &(o_ctrl->i2c_client);
	/**************************Add TOF GPIO Support**************************/
	rc = msm_tof_pinctrl_init(o_ctrl);
	if (rc < 0) {
		pr_err("msm_tof_pinctrl_init failed, non-fatal ERROR");
		rc = 0;
	}
	if (o_ctrl->shared_power_flag == 0) {
		rc = msm_camera_request_gpio_table(
			 o_ctrl->shared_gpio_cfg.cam_gconf->cam_gpio_req_tbl,
			 o_ctrl->shared_gpio_cfg.cam_gconf->cam_gpio_req_tbl_size, 1);

	if (rc < 0) {
		pr_err("msm_camera_request_gpio_table failed, non-fatal ERROR");
		return rc;
	}
	rc = pinctrl_select_state(o_ctrl->shared_gpio_cfg.pinctrl_info.pinctrl,
			o_ctrl->shared_gpio_cfg.pinctrl_info.gpio_state_active);
	if (rc < 0) {
		pr_err("pinctrl_select_state failed, non-fatal ERROR");
		rc = 0;
	}

	CDBG("%s:%d gpio set val %d 2\n", __func__, __LINE__,
	o_ctrl->shared_gpio_cfg.cam_gconf->gpio_num_info->gpio_num[SENSOR_SHARED_GPIO_VDIG]);
	gpio_set_value_cansleep(o_ctrl->shared_gpio_cfg.cam_gconf->gpio_num_info
			->gpio_num[SENSOR_SHARED_GPIO_VDIG], 2);

	rc = msm_camera_request_gpio_table(
			 o_ctrl->shared_gpio_cfg.cam_gconf->cam_gpio_req_tbl,
			 o_ctrl->shared_gpio_cfg.cam_gconf->cam_gpio_req_tbl_size, 0);

	if (rc < 0) {
		pr_err("msm_camera_request_gpio_table failed, non-fatal ERROR");
		return rc;
	}

	}
	usleep_range(100, 150);
	rc = msm_camera_request_gpio_table(
			 o_ctrl->gpio_cfg.cam_gconf->cam_gpio_req_tbl,
			 o_ctrl->gpio_cfg.cam_gconf->cam_gpio_req_tbl_size, 1);

	if (rc < 0) {
		pr_err("msm_camera_request_gpio_table failed, non-fatal ERROR");
		return rc;
	}
	rc = pinctrl_select_state(o_ctrl->gpio_cfg.pinctrl_info.pinctrl,
			o_ctrl->gpio_cfg.pinctrl_info.gpio_state_active);
	if (rc < 0) {
		pr_err("pinctrl_select_state failed, non-fatal ERROR");
		rc = 0;
	}

	CDBG("%s:%d gpio set val %d 2\n", __func__, __LINE__,
	o_ctrl->gpio_cfg.cam_gconf->gpio_num_info->gpio_num[SENSOR_GPIO_XSHUT]);

	gpio_set_value_cansleep(o_ctrl->gpio_cfg.cam_gconf->gpio_num_info
			->gpio_num[SENSOR_GPIO_XSHUT], 2);

	rc = msm_camera_request_gpio_table(
			 o_ctrl->gpio_cfg.cam_gconf->cam_gpio_req_tbl,
			 o_ctrl->gpio_cfg.cam_gconf->cam_gpio_req_tbl_size, 0);

	if (rc < 0) {
		pr_err("msm_camera_request_gpio_table failed, non-fatal ERROR");
		return rc;
	}

	/****************************Add End***************************************/

	o_ctrl->tof_state = TOF_ENABLE_STATE;
	CDBG("Exit\n");
	return rc;
}

static struct v4l2_subdev_core_ops msm_tof_subdev_core_ops = {
	.ioctl = msm_tof_subdev_ioctl,
};

static struct v4l2_subdev_ops msm_tof_subdev_ops = {
	.core = &msm_tof_subdev_core_ops,
};

static const struct i2c_device_id msm_tof_i2c_id[] = {
	{"qcom,tof", (kernel_ulong_t)NULL},
	{ }
};

static int32_t msm_tof_i2c_probe(struct i2c_client *client,
	const struct i2c_device_id *id)
{
	int rc = 0;
	struct msm_tof_ctrl_t *tof_ctrl_t = NULL;
	CDBG("Enter\n");

	if (client == NULL) {
		pr_err("msm_tof_i2c_probe: client is null\n");
		return -EINVAL;
	}

	tof_ctrl_t = kzalloc(sizeof(struct msm_tof_ctrl_t),
		GFP_KERNEL);
	if (!tof_ctrl_t) {
		pr_err("%s:%d failed no memory\n", __func__, __LINE__);
		return -ENOMEM;
	}

	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		pr_err("i2c_check_functionality failed\n");
		rc = -EINVAL;
		goto probe_failure;
	}

	CDBG("client = 0x%p\n",  client);

	rc = of_property_read_u32(client->dev.of_node, "cell-index",
		&tof_ctrl_t->subdev_id);
	CDBG("cell-index %d, rc %d\n", tof_ctrl_t->subdev_id, rc);
	if (rc < 0) {
		pr_err("failed rc %d\n", rc);
		goto probe_failure;
	}

	tof_ctrl_t->i2c_driver = &msm_tof_i2c_driver;
	tof_ctrl_t->i2c_client.client = client;
	/* Set device type as I2C */
	tof_ctrl_t->tof_device_type = MSM_CAMERA_I2C_DEVICE;
	tof_ctrl_t->i2c_client.i2c_func_tbl = &msm_sensor_qup_func_tbl;
	tof_ctrl_t->tof_v4l2_subdev_ops = &msm_tof_subdev_ops;
	tof_ctrl_t->tof_mutex = &msm_tof_mutex;

	/* Assign name for sub device */
	snprintf(tof_ctrl_t->msm_sd.sd.name, sizeof(tof_ctrl_t->msm_sd.sd.name),
		"%s", tof_ctrl_t->i2c_driver->driver.name);

	/* Initialize sub device */
	v4l2_i2c_subdev_init(&tof_ctrl_t->msm_sd.sd,
		tof_ctrl_t->i2c_client.client,
		tof_ctrl_t->tof_v4l2_subdev_ops);
	v4l2_set_subdevdata(&tof_ctrl_t->msm_sd.sd, tof_ctrl_t);
	tof_ctrl_t->msm_sd.sd.internal_ops = &msm_tof_internal_ops;
	tof_ctrl_t->msm_sd.sd.flags |= V4L2_SUBDEV_FL_HAS_DEVNODE;
	media_entity_init(&tof_ctrl_t->msm_sd.sd.entity, 0, NULL, 0);
	tof_ctrl_t->msm_sd.sd.entity.type = MEDIA_ENT_T_V4L2_SUBDEV;
	tof_ctrl_t->msm_sd.sd.entity.group_id = MSM_CAMERA_SUBDEV_TOF;
	tof_ctrl_t->msm_sd.close_seq = MSM_SD_CLOSE_2ND_CATEGORY | 0x2;
	msm_sd_register(&tof_ctrl_t->msm_sd);
	tof_ctrl_t->tof_state = TOF_DISABLE_STATE;
	pr_info("msm_tof_i2c_probe: succeeded\n");
	CDBG("Exit\n");

probe_failure:
	kfree(tof_ctrl_t);
	return rc;
}

#ifdef CONFIG_COMPAT
static long msm_tof_subdev_do_ioctl(
	struct file *file, unsigned int cmd, void *arg)
{
	long rc = 0;
	struct video_device *vdev;
	struct v4l2_subdev *sd;
	struct msm_tof_cfg_data32 *u32;
	struct msm_tof_cfg_data tof_data;
	void *parg;
	struct msm_camera_i2c_seq_reg_setting settings;
	struct msm_camera_i2c_seq_reg_setting32 settings32;
	memset((void*)&tof_data, 0, sizeof(tof_data));

	if (!file || !arg) {
		pr_err("%s:failed NULL parameter\n", __func__);
		return -EINVAL;
	}
	vdev = video_devdata(file);
	sd = vdev_to_v4l2_subdev(vdev);
	u32 = (struct msm_tof_cfg_data32 *)arg;
	parg = arg;

	tof_data.cfgtype = u32->cfgtype;

	switch (cmd) {
	case VIDIOC_MSM_TOF_CFG32:
		cmd = VIDIOC_MSM_TOF_CFG;

		switch (u32->cfgtype) {
		case CFG_TOF_POWERUP:
		case CFG_TOF_POWERDOWN:
			tof_data.cfg.shared_power_flag = u32->cfg.shared_power_flag;
			parg = &tof_data;
			break;
		case CFG_TOF_CONTROL:
			tof_data.cfg.set_info.tof_params.setting_size =
				u32->cfg.set_info.tof_params.setting_size;
			tof_data.cfg.set_info.tof_params.i2c_addr =
				u32->cfg.set_info.tof_params.i2c_addr;
			tof_data.cfg.set_info.tof_params.i2c_freq_mode =
				u32->cfg.set_info.tof_params.i2c_freq_mode;
			tof_data.cfg.set_info.tof_params.i2c_addr_type =
				u32->cfg.set_info.tof_params.i2c_addr_type;
			tof_data.cfg.set_info.tof_params.i2c_data_type =
				u32->cfg.set_info.tof_params.i2c_data_type;
			tof_data.cfg.set_info.tof_params.settings =
				compat_ptr(u32->cfg.set_info.tof_params.
				settings);
			#ifdef FAC_LASER_TEST
			tof_data.distance_data =
				compat_ptr(u32->distance_data);
			#endif
			parg = &tof_data;
			break;
		case CFG_TOF_I2C_WRITE_SEQ_TABLE:
			if (copy_from_user(&settings32,
				(void *)compat_ptr(u32->cfg.settings),
				sizeof(
				struct msm_camera_i2c_seq_reg_setting32))) {
				pr_err("copy_from_user failed\n");
				return -EFAULT;
			}

			settings.addr_type = settings32.addr_type;
			settings.delay = settings32.delay;
			settings.size = settings32.size;
			settings.reg_setting =
				compat_ptr(settings32.reg_setting);

			tof_data.cfgtype = u32->cfgtype;
			tof_data.cfg.settings = &settings;
			parg = &tof_data;
			break;
		default:
			parg = &tof_data;
			break;
		}
	}
	rc = msm_tof_subdev_ioctl(sd, cmd, parg);

	return rc;
}

static long msm_tof_subdev_fops_ioctl(struct file *file, unsigned int cmd,
	unsigned long arg)
{
	return video_usercopy(file, cmd, arg, msm_tof_subdev_do_ioctl);
}
#endif

static int32_t msm_tof_platform_probe(struct platform_device *pdev)
{
	int32_t rc = 0;
	uint8_t chip_id;
	uint32_t sid, chip_id_u32;
	struct msm_camera_cci_client *cci_client = NULL;
	struct msm_tof_ctrl_t *msm_tof_t = NULL;
	struct msm_tof_vreg *vreg_cfg;
	/****************Add gpio support for tof**********/
	int i = 0;
	struct msm_tof_gpio *gpio_cfg;
	uint16_t gpio_array_size = 0;
	uint16_t *gpio_array = NULL;
	/****************Add End**************************/
	CDBG("Enter\n");

	if (!pdev->dev.of_node) {
		pr_err("of_node NULL\n");
		return -EINVAL;
	}

	msm_tof_t = kzalloc(sizeof(struct msm_tof_ctrl_t),
		GFP_KERNEL);
	if (!msm_tof_t) {
		pr_err("%s:%d failed no memory\n", __func__, __LINE__);
		return -ENOMEM;
	}

	msm_tof_t->i2c_client.cci_client = kzalloc(sizeof(
		struct msm_camera_cci_client), GFP_KERNEL);
	if (!msm_tof_t->i2c_client.cci_client) {
		kfree(msm_tof_t->vreg_cfg.cam_vreg);
		kfree(msm_tof_t);
		pr_err("failed no memory\n");
		return -ENOMEM;
	}

	rc = of_property_read_u32((&pdev->dev)->of_node, "cell-index",
		&pdev->id);
	CDBG("cell-index %d, rc %d\n", pdev->id, rc);
	if (rc < 0) {
		kfree(msm_tof_t);
		pr_err("failed rc %d\n", rc);
		return rc;
	}

	rc = of_property_read_u32((&pdev->dev)->of_node, "qcom,cci-master",
		&msm_tof_t->cci_master);
	CDBG("qcom,cci-master %d, rc %d\n", msm_tof_t->cci_master, rc);
	if (rc < 0 || msm_tof_t->cci_master >= MASTER_MAX) {
		kfree(msm_tof_t);
		pr_err("failed rc %d\n", rc);
		return rc;
	}

	rc = of_property_read_u32((&pdev->dev)->of_node, "qcom,cci-sid",
		&sid);
	msm_tof_t->i2c_client.cci_client->sid = (uint8_t)sid;
	pr_err("qcom,cci-sid 0x%x, rc %d\n", msm_tof_t->i2c_client.cci_client->sid, rc);
	if (rc < 0) {
		kfree(msm_tof_t);
		pr_err("failed rc %d\n", rc);
		return rc;
	}

	rc = of_property_read_u32((&pdev->dev)->of_node, "qcom,chip-id",
		&chip_id_u32);
	msm_tof_t->chip_id = (uint8_t)chip_id_u32;
	pr_err("qcom,chip-id 0x%x, rc %d\n", msm_tof_t->chip_id, rc);
	if (rc < 0) {
		kfree(msm_tof_t);
		pr_err("failed rc %d\n", rc);
		return rc;
	}

	rc = of_property_read_u32((&pdev->dev)->of_node, "qcom,chip-id-addr",
		&msm_tof_t->chip_id_addr);
	pr_err("qcom,chip-id-addr 0x%x, rc %d\n", msm_tof_t->chip_id_addr, rc);
	if (rc < 0) {
		kfree(msm_tof_t);
		pr_err("failed rc %d\n", rc);
		return rc;
	}

	if (of_find_property((&pdev->dev)->of_node,
			"qcom,cam-vreg-name", NULL)) {
		vreg_cfg = &msm_tof_t->vreg_cfg;
		rc = msm_camera_get_dt_vreg_data((&pdev->dev)->of_node,
			&vreg_cfg->cam_vreg, &vreg_cfg->num_vreg);
		if (rc < 0) {
			kfree(msm_tof_t);
			pr_err("failed rc %d\n", rc);
			return rc;
		}
	}
	/**********************Add gpio support for tof***********************/
	gpio_cfg = &msm_tof_t->gpio_cfg;
	gpio_array_size = of_gpio_count((&pdev->dev)->of_node);
	if(gpio_array_size > 0)
	{
		gpio_cfg->cam_gconf = kzalloc(sizeof(struct msm_camera_gpio_conf), GFP_KERNEL);
		gpio_array = kzalloc(sizeof(uint16_t) * gpio_array_size, GFP_KERNEL);
		if(!gpio_cfg->cam_gconf || !gpio_array)
		{
			pr_err("%s:%d failed no memory\n",__func__, __LINE__);
			kfree(msm_tof_t);
			return -ENOMEM;
		}
		gpio_cfg->num_gpio = gpio_array_size;
		for(i = 0; i < gpio_array_size; i++)
		{
			gpio_array[i] = of_get_gpio((&pdev->dev)->of_node, i);
			pr_err("tof: gpio_array[%d] = %d", i, gpio_array[i]);
		}
		rc = msm_camera_get_dt_gpio_req_tbl( (&pdev->dev)->of_node, gpio_cfg->cam_gconf,
			gpio_array,gpio_array_size);
		if(rc < 0)
		{
			kfree(msm_tof_t);
			kfree(gpio_cfg->cam_gconf);
			kfree(gpio_array);
			pr_err("%s:%d: tof: get gpio req tbl error\n",__func__,__LINE__);
			return rc;
		}
		rc = msm_camera_init_gpio_pin_tbl((&pdev->dev)->of_node,
				gpio_cfg->cam_gconf, gpio_array,gpio_array_size);
		if(rc < 0)
		{
			kfree(msm_tof_t);
			kfree(gpio_cfg->cam_gconf);
			kfree(gpio_array);
			pr_err("%s:%d: tof: get gpio pin tbl error\n",__func__,__LINE__);
			return rc;
		}
	}
	/************************Add End***************************************/

	/**********************Add shared gpio support for tof***********************/
	gpio_cfg = &msm_tof_t->shared_gpio_cfg;
	gpio_array_size = of_gpio_named_count((&pdev->dev)->of_node, "shared-gpios");
	if(gpio_array_size > 0)
	{
		gpio_cfg->cam_gconf = kzalloc(sizeof(struct msm_camera_gpio_conf), GFP_KERNEL);
		gpio_array = kzalloc(sizeof(uint16_t) * gpio_array_size, GFP_KERNEL);
		if(!gpio_cfg->cam_gconf || !gpio_array)
		{
			pr_err("%s:%d failed no memory\n",__func__, __LINE__);
			kfree(msm_tof_t);
			return -ENOMEM;
		}
		gpio_cfg->num_gpio = gpio_array_size;
		for(i = 0; i < gpio_array_size; i++)
		{
			gpio_array[i] = of_get_named_gpio((&pdev->dev)->of_node, "shared-gpios", i);
			pr_err("tof: gpio_array[%d] = %d", i, gpio_array[i]);
		}
		rc = msm_camera_get_dt_shared_gpio_req_tbl( (&pdev->dev)->of_node, gpio_cfg->cam_gconf,
			gpio_array,gpio_array_size);
		if(rc < 0)
		{
			kfree(msm_tof_t);
			kfree(gpio_cfg->cam_gconf);
			kfree(gpio_array);
			pr_err("%s:%d: tof: get gpio req tbl error\n",__func__,__LINE__);
			return rc;
		}
		rc = msm_camera_init_shared_gpio_pin_tbl((&pdev->dev)->of_node,
				gpio_cfg->cam_gconf, gpio_array,gpio_array_size);
		if(rc < 0)
		{
			kfree(msm_tof_t);
			kfree(gpio_cfg->cam_gconf);
			kfree(gpio_array);
			pr_err("%s:%d: tof: get gpio pin tbl error\n",__func__,__LINE__);
			return rc;
		}
	}
	/************************Add End***************************************/

	msm_tof_t->tof_v4l2_subdev_ops = &msm_tof_subdev_ops;
	msm_tof_t->tof_mutex = &msm_tof_mutex;

	/* Set platform device handle */
	msm_tof_t->pdev = pdev;
	/* Set device type as platform device */
	msm_tof_t->tof_device_type = MSM_CAMERA_PLATFORM_DEVICE;
	msm_tof_t->i2c_client.i2c_func_tbl = &msm_sensor_cci_func_tbl;

	cci_client = msm_tof_t->i2c_client.cci_client;
	cci_client->cci_subdev = msm_cci_get_subdev();
	cci_client->cci_i2c_master = msm_tof_t->cci_master;
	msm_tof_t->shared_power_flag  = 0;
	msm_tof_power_up(msm_tof_t);
	rc = msm_tof_t->i2c_client.i2c_func_tbl->i2c_util(
		&msm_tof_t->i2c_client, MSM_CCI_INIT);
	if (rc < 0) {
		pr_err("cci_init failed\n");
		rc = -1;
		goto ERROR2;
	}

	msm_tof_t->i2c_client.cci_client->retries = 3;
	msm_tof_t->i2c_client.cci_client->id_map = 0;
	msm_tof_t->i2c_client.cci_client->cci_i2c_master = msm_tof_t->cci_master;
	msm_tof_t->i2c_client.cci_client->i2c_freq_mode = I2C_STANDARD_MODE;
	msm_tof_t->i2c_data_type = MSM_CAMERA_I2C_WORD_DATA;

	msm_tof_t->i2c_client.addr_type = MSM_CAMERA_I2C_BYTE_ADDR;
	rc = msm_tof_t->i2c_client.i2c_func_tbl->i2c_read_seq(
			&msm_tof_t->i2c_client,
			msm_tof_t->chip_id_addr,
			&chip_id, 1);
	if (rc < 0) {
		pr_err("i2c read error:%d\n", rc);
		rc = -1;
		goto ERROR1;
	}

	if (chip_id != msm_tof_t->chip_id) {
		pr_err("Chip id not match, probe error");
		rc = -1;
		goto ERROR1;
	}

	v4l2_subdev_init(&msm_tof_t->msm_sd.sd,
		msm_tof_t->tof_v4l2_subdev_ops);
	v4l2_set_subdevdata(&msm_tof_t->msm_sd.sd, msm_tof_t);
	msm_tof_t->msm_sd.sd.internal_ops = &msm_tof_internal_ops;
	msm_tof_t->msm_sd.sd.flags |= V4L2_SUBDEV_FL_HAS_DEVNODE;
	snprintf(msm_tof_t->msm_sd.sd.name,
		ARRAY_SIZE(msm_tof_t->msm_sd.sd.name), "msm_tof");
	media_entity_init(&msm_tof_t->msm_sd.sd.entity, 0, NULL, 0);
	msm_tof_t->msm_sd.sd.entity.type = MEDIA_ENT_T_V4L2_SUBDEV;
	msm_tof_t->msm_sd.sd.entity.group_id = MSM_CAMERA_SUBDEV_TOF;
	msm_tof_t->msm_sd.close_seq = MSM_SD_CLOSE_2ND_CATEGORY | 0x2;
	msm_sd_register(&msm_tof_t->msm_sd);
	msm_cam_copy_v4l2_subdev_fops(&msm_tof_v4l2_subdev_fops);
#ifdef CONFIG_COMPAT
	msm_tof_v4l2_subdev_fops.compat_ioctl32 =
		msm_tof_subdev_fops_ioctl;
#endif
	msm_tof_t->msm_sd.sd.devnode->fops =
		&msm_tof_v4l2_subdev_fops;

ERROR1:
	rc = msm_tof_t->i2c_client.i2c_func_tbl->i2c_util(
		&msm_tof_t->i2c_client, MSM_CCI_RELEASE);
	if (rc < 0)
		pr_err("cci_release failed\n");
ERROR2:
	msm_tof_t->shared_power_flag = 1;
	rc = msm_tof_power_down(msm_tof_t);
	if (rc < 0) {
		pr_err("%s failed %d\n", __func__, __LINE__);
		return rc;
	}
	msm_tof_t->tof_state = TOF_DISABLE_STATE;
	CDBG("Exit\n");
	return rc;
}

static const struct of_device_id msm_tof_i2c_dt_match[] = {
	{.compatible = "qcom,tof"},
	{}
};

MODULE_DEVICE_TABLE(of, msm_tof_i2c_dt_match);

static struct i2c_driver msm_tof_i2c_driver = {
	.id_table = msm_tof_i2c_id,
	.probe  = msm_tof_i2c_probe,
	.remove = __exit_p(msm_tof_i2c_remove),
	.driver = {
		.name = "qcom,tof",
		.owner = THIS_MODULE,
		.of_match_table = msm_tof_i2c_dt_match,
	},
};

static const struct of_device_id msm_tof_dt_match[] = {
	{.compatible = "qcom,tof", .data = NULL},
	{}
};

MODULE_DEVICE_TABLE(of, msm_tof_dt_match);

static struct platform_driver msm_tof_platform_driver = {
	.probe = msm_tof_platform_probe,
	.driver = {
		.name = "qcom,tof",
		.owner = THIS_MODULE,
		.of_match_table = msm_tof_dt_match,
	},
};

static int __init msm_tof_init_module(void)
{
	int32_t rc = 0;
	CDBG("Enter\n");
	rc = platform_driver_register(&msm_tof_platform_driver);
	if (!rc)
		return rc;
	CDBG("%s:%d rc %d\n", __func__, __LINE__, rc);
	return i2c_add_driver(&msm_tof_i2c_driver);
}

static void __exit msm_tof_exit_module(void)
{
	platform_driver_unregister(&msm_tof_platform_driver);
	i2c_del_driver(&msm_tof_i2c_driver);
	return;
}

module_init(msm_tof_init_module);
module_exit(msm_tof_exit_module);
MODULE_DESCRIPTION("MSM TOF");
MODULE_LICENSE("GPL v2");
