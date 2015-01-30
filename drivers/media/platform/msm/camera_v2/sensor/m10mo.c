/* Copyright (c) 2013-2014, Smartisan Technology Co., Ltd. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include "m10mo.h"

#define M10MO_SENSOR_NAME "m10mo"

/*#define CONFIG_MSMB_CAMERA_DEBUG*/
#undef CDBG
#ifdef CONFIG_MSMB_CAMERA_DEBUG
#define CDBG(fmt, args...) pr_err(fmt, ##args)
#else
#define CDBG(fmt, args...) do { } while (0)
#endif

#define BYTE1(a) (((a) >> 8) & (0xff))
#define BYTE0(a) ((a) & (0xff))

#define ISP_LOG_BUF_SIZE (1024 * 1024 *3)


static const char *stream_status_s[] = {
	[MONITOR] = "MONITOR",
	[UNBOOTED] = "UNBOOTED",
	[STREAM_OFF] = "STREAM_OFF",
	[POWER_DOWN] = "POWER_DOWN",
	[ZSL_CAPTURE] = "ZSL_CAPTURE",
	[POWER_DOWNING] = "POWER_DOWNING",
	[MONITOR_STOPPING] = "MONITOR_STOPPING",
	[MONITOR_VIRTUAL_OFF] = "MONITOR_VIRTUAL_OFF",
	[ZSL_CAPTURE_STARTING] = "ZSL_CAPTURE_STARTING",
	[ZSL_CAPTURE_STOPPING] = "ZSL_CAPTURE_STOPPING",
};

static const char *af_status_s[] = {
	[AF_ONGOING] = "AF_ONGOING",
	[CAF_PAUSING] = "CAF_PAUSING",
	[AF_STOPPING] = "AF_STOPPING",
	[LENS_INITED] = "LENS_INITED",
	[LENS_DEINITED] = "LENS_DEINITED",
	[AF_RANGE_SETTING] = "AF_RANGE_SETTING",
	[LENS_DEINITIALING] = "LENS_DEINITIALING",
};


static const char *af_mode_s[] = {
	[Macro_AF] = "Macro_AF",
	[Fixed_AF] = "Fixed_AF",
	[Invalid_AF] = "Invalid",
	[Normal_AF] = "Normal_AF",
	[Infinity_AF] = "Infinity_AF",
	[Continuous_AF] = "Continuous_AF",
	[Continuous_AF_applied] = "Continuous_AF_applied",
};

#ifdef CONFIG_MSMB_CAMERA_DEBUG

static const char *ae_lock_s[] = {
	[AE_LOCK_ON] = "AE_LOCK_ON",
	[AE_LOCK_OFF] = "AE_LOCK_OFF",
};

static const char *awb_lock_s[] = {
	[AWB_LOCK_ON] = "AWB_LOCK_ON",
	[AWB_LOCK_OFF] = "AWB_LOCK_OFF",
};

static const char *ae_mode_s[] = {
	[AE_OFF] = "AE_OFF",
	[ROI_Mode] = "ROI_Mode",
	[All_block_integral] = "All_block_integral",
	[Center_weighted_average1] = "Center_weighted_average1",
};

static const char *hal_af_mode_s[] = {
	[CAM_FOCUS_MODE_EDOF] = "CAM_FOCUS_MODE_EDOF",
	[CAM_FOCUS_MODE_AUTO] = "CAM_FOCUS_MODE_AUTO",
	[CAM_FOCUS_MODE_MACRO] = "CAM_FOCUS_MODE_MACRO",
	[CAM_FOCUS_MODE_FIXED] = "CAM_FOCUS_MODE_FIXED",
	[CAM_FOCUS_MODE_MAX] = "CAM_FOCUS_MODE_INVALID",
	[CAM_FOCUS_MODE_INFINITY] = "CAM_FOCUS_MODE_INFINITY",
	[CAM_FOCUS_MODE_CONTINOUS_VIDEO] = "CAM_FOCUS_MODE_CONTINOUS_VIDEO",
	[CAM_FOCUS_MODE_CONTINOUS_PICTURE] = "CAM_FOCUS_MODE_CONTINOUS_PICTURE",
};

static const char *scene_value_s[] = {
	[SCENE_NUM_Auto] = "SCENE_NUM_Auto",
	[SCENE_NUM_Macro] = "SCENE_NUM_Macro",
	[SCENE_NUM_Night] = "SCENE_NUM_Night",
	[SCENE_NUM_Backlit] = "SCENE_NUM_Backlit",
	[SCENE_NUM_Portrait] = "SCENE_NUM_Portrait",
	[SCENE_NUM_Night_Portrait] = "SCENE_NUM_Night_Portrait",
	[SCENE_NUM_Backlit_Portrait] = "SCENE_NUM_Backlit_Portrait",
};

static const char *m10mo_iso_s[] = {
	[ISO_50] = "ISO_50",
	[ISO_100] = "ISO_100",
	[ISO_200] = "ISO_200",
	[ISO_400] = "ISO_400",
	[ISO_800] = "ISO_800",
	[ISO_AUTO] = "ISO_AUTO",
	[ISO_1600] = "ISO_1600",
	[ISO_3200] = "ISO_3200",
};

static const char *m10mo_flash_mode_s[] = {
	[STROBE_EN_Auto] = "STROBE_EN_Auto",
	[STROBE_EN_Torch] = "STROBE_EN_Torch",
	[STROBE_EN_Forced_ON] = "STROBE_EN_Forced_ON",
	[STROBE_EN_Forced_OFF] = "STROBE_EN_Forced_OFF",
	[STROBE_EN_Torch_on_by_TX_pin] = "STROBE_EN_Torch_on_by_TX_pin",
};

static const char *m10mo_wb_mode_s[] = {
	[AWB_Shade] = "AWB_Shade",
	[AWB_Cloudy] = "AWB_Cloudy",
	[AWB_Horizon] = "AWB_Horizon",
	[AWB_Invalid] = "AWB_Invalid",
	[AWB_Day_light] = "AWB_Day_light",
	[AWB_User_setting] = "AWB_User_setting",
	[AWB_Incandescent_light] = "AWB_Incandescent_light",
	[AWB_Fluorescent_light1] = "AWB_Fluorescent_light1",
	[AWB_Fluorescent_light2] = "AWB_Fluorescent_light2",
};

static const char *m10mo_degree_s[] = {
	[DEGREE_0] = "DEGREE_0",
	[DEGREE_90] = "DEGREE_90",
	[DEGREE_180] = "DEGREE_180",
	[DEGREE_270] = "DEGREE_270",
};
#endif

static const char *m10mo_af_result_s[] = {
	[AF_OFF] = "AF_OFF",
	[AF_operating] = "AF_operating",
	[Focus_operation_fail] = "Focus_operation_fail",
	[Focus_operation_success] = "Focus_operation_success",
	[Focus_operation_stopped_at_edge] = "Focus_operation_stopped_at_edge",
};

DEFINE_MSM_MUTEX(m10mo_mut);
DEFINE_MSM_MUTEX(m10mo_i2c_mut);
DEFINE_MSM_MUTEX(m10mo_taf_time_mut);
DEFINE_MSM_MUTEX(m10mo_power_down_mut);

static struct m10mo_ctrl_t m10mo_s_ctrl;

static const struct i2c_device_id m10mo_i2c_id[] = {
	{M10MO_SENSOR_NAME, (kernel_ulong_t)&m10mo_s_ctrl.sensor_ctrl},
	{ }
};

static const struct of_device_id m10mo_dt_match[] = {
	{.compatible = "qcom,m10mo", .data = &m10mo_s_ctrl.sensor_ctrl},
	{}
};
static int32_t m10mo_init(struct m10mo_ctrl_t *s_ctrl);
static int32_t m10mo_monitor(struct m10mo_ctrl_t *s_ctrl);
static ssize_t functions_show(struct device *pdev, 
	struct device_attribute *attr, char *buf);

static ssize_t functions_store(struct device *pdev, 
	struct device_attribute *attr, const char *buf, size_t size);
static ssize_t m10mo_af_status_show(struct device *pdev,
	struct device_attribute *attr, char *buf);

static ssize_t m10mo_af_status_store(struct device *pdev,
	struct device_attribute *attr, const char *buf, size_t size);

static DEVICE_ATTR(functions, S_IRUGO | S_IWUSR, functions_show,
						 functions_store);
static DEVICE_ATTR(m10mo_af_status, S_IRUGO | S_IWUSR, m10mo_af_status_show,
						 m10mo_af_status_store);


static int32_t msm_m10mo_i2c_probe(struct i2c_client *client,
	const struct i2c_device_id *id);

MODULE_DEVICE_TABLE(of, m10mo_dt_match);

static struct i2c_driver m10mo_i2c_driver = {
	.id_table = m10mo_i2c_id,
	.probe  = msm_m10mo_i2c_probe,
	.driver = {
		.name = M10MO_SENSOR_NAME,
		.of_match_table = m10mo_dt_match,
	},
};

static struct msm_camera_i2c_client m10mo_sensor_i2c_client = {
	.addr_type = MSM_CAMERA_I2C_WORD_ADDR,
};

static struct platform_driver m10mo_platform_driver = {
	.driver = {
		.name = "qcom,m10mo",
		.owner = THIS_MODULE,
		.of_match_table = m10mo_dt_match,
	},
};

static struct msm_sensor_power_setting m10mo_power_setting[] = {
	{
		.seq_type = SENSOR_VREG,
		.seq_val = CAM_VDIG,
		.config_val = 0,
		.delay = 0,
	},
	{
		.seq_type = SENSOR_VREG,
		.seq_val = CAM_VANA,
		.config_val = 0,
		.delay = 0,
	},
	{
		.seq_type = SENSOR_GPIO,
		.seq_val = SENSOR_GPIO_VDIG,
		.config_val = GPIO_OUT_LOW,
		.delay = 5,
	},
	{
		.seq_type = SENSOR_GPIO,
		.seq_val = SENSOR_GPIO_VDIG,
		.config_val = GPIO_OUT_HIGH,
		.delay = 5,
	},
	{
		.seq_type = SENSOR_GPIO,
		.seq_val = SENSOR_GPIO_VIO,
		.config_val = GPIO_OUT_LOW,
		.delay = 5,
	},
	{
		.seq_type = SENSOR_GPIO,
		.seq_val = SENSOR_GPIO_VIO,
		.config_val = GPIO_OUT_HIGH,
		.delay = 0,
	},
	{
		.seq_type = SENSOR_GPIO,
		.seq_val = SENSOR_GPIO_VANA,
		.config_val = GPIO_OUT_LOW,
		.delay = 5,
	},
	{
		.seq_type = SENSOR_GPIO,
		.seq_val = SENSOR_GPIO_VANA,
		.config_val = GPIO_OUT_HIGH,
		.delay = 5,
	},
	{
		.seq_type = SENSOR_CLK,
		.seq_val = SENSOR_CAM_MCLK,
		.config_val = -1,
		.delay = 1,
	},
	{
		.seq_type = SENSOR_GPIO,
		.seq_val = SENSOR_GPIO_RESET,
		.config_val = GPIO_OUT_LOW,
		.delay = 1,
	},
	{
		.seq_type = SENSOR_GPIO,
		.seq_val = SENSOR_GPIO_RESET,
		.config_val = GPIO_OUT_HIGH,
		.delay = 10,
	},
	{
		.seq_type = SENSOR_VREG,
		.seq_val = CAM_VIO,
		.config_val = 0,
		.delay = 0,
	},
	{
		.seq_type = SENSOR_VREG,
		.seq_val = CAM_VAF,
		.config_val = 0,
		.delay = 0,
	},

	{
		.seq_type = SENSOR_I2C_MUX,
		.seq_val = 0,
		.config_val = 0,
		.delay = 0,
	},
};

static struct v4l2_subdev_info m10mo_subdev_info[] = {
	{
		.code   = V4L2_MBUS_FMT_YUYV8_2X8,
		.colorspace = V4L2_COLORSPACE_JPEG,
		.fmt    = 1,
		.order    = 0,
	},
};

static int32_t m10mo_i2c_write_seq(
	struct msm_sensor_ctrl_t *s_ctrl, struct fuji_i2c_seq *cmd,
	uint16_t delay)
{
	int i, j;
	int rc = 0;
	struct msm_camera_i2c_seq_reg_setting conf_array;
	struct msm_camera_i2c_seq_reg_data reg_setting;

	conf_array.size = 1;
	conf_array.addr_type = MSM_CAMERA_I2C_WORD_ADDR;
	conf_array.delay = delay;

	reg_setting.reg_addr = (cmd->num << 8) | cmd->cmd;

	if (cmd->cmd == 2) {

		reg_setting.reg_data[0] = cmd->cat;

		reg_setting.reg_data[1] = cmd->byte;

		for (i = 2, j = 0; j < cmd->num8;) {

			reg_setting.reg_data[i++] = cmd->data[j++];

		}

		reg_setting.reg_data_size = i;

	} else if (cmd->pdata) {

		cmd->pdata[0] = cmd->num;

		cmd->pdata[1] = cmd->cmd;

		cmd->pdata[2] = reg_setting.reg_data[0] = (cmd->addr & 0xFF000000) >> 24;
		cmd->pdata[3] = reg_setting.reg_data[1] = (cmd->addr & 0x00FF0000) >> 16;
		cmd->pdata[4] = reg_setting.reg_data[2] = (cmd->addr & 0x0000FF00) >> 8;
		cmd->pdata[5] = reg_setting.reg_data[3] = (cmd->addr & 0xFF);

		cmd->pdata[6] = reg_setting.reg_data[4] = (cmd->num16 & 0xFF00) >> 8;
		cmd->pdata[7] = reg_setting.reg_data[5] = (cmd->num16 & 0xFF);

		reg_setting.reg_data_size = cmd->num16 + 6;

		reg_setting.data = cmd->pdata;
		reg_setting.data_size = cmd->num16;
	} else {
		reg_setting.reg_data[0] = (cmd->addr & 0xFF000000) >> 24;
		reg_setting.reg_data[1] = (cmd->addr & 0x00FF0000) >> 16;
		reg_setting.reg_data[2] = (cmd->addr & 0x0000FF00) >> 8;
		reg_setting.reg_data[3] = (cmd->addr & 0xFF);

		reg_setting.reg_data[4] = (cmd->num16 & 0xFF00) >> 8;
		reg_setting.reg_data[5] = (cmd->num16 & 0xFF);

		for (i = 6, j = 0; j < cmd->num16;) {
			reg_setting.reg_data[i++] = cmd->data[j++];
		}
		reg_setting.reg_data_size = i;
	}

	conf_array.reg_setting = (struct msm_camera_i2c_seq_reg_array *) &reg_setting;
	rc = s_ctrl->sensor_i2c_client->i2c_func_tbl->
		i2c_write_seq_table(s_ctrl->sensor_i2c_client,
		&conf_array);

	return rc;
}

static int32_t m10mo_i2c_read_seq(
	struct msm_sensor_ctrl_t *s_ctrl, struct fuji_i2c_seq *cmd)
{
	int rc = 0;
	uint8_t *pd = NULL;
	uint32_t addr, addr2;
	struct msm_camera_i2c_seq_reg_array reg_setting;

	reg_setting.reg_addr = cmd->num << 8 | cmd->cmd;

	if (cmd->cmd == 1) {
		s_ctrl->sensor_i2c_client->addr_type = MSM_CAMERA_I2C_5B_ADDR;
		addr = (cmd->num << 24) | (cmd->cmd << 16) |
			(cmd->cat << 8) | cmd->byte;
		addr2 = cmd->num8 << 24;
		pd = cmd->data;
	} else {
		s_ctrl->sensor_i2c_client->addr_type = MSM_CAMERA_I2C_8B_ADDR;
		addr = (cmd->num << 24) | (cmd->cmd << 16) |
			((cmd->addr & 0xFFFF0000) >> 16);
		addr2 = ((cmd->addr & 0xFFFF) << 16) | cmd->num16;

		if (cmd->data_size <= M10MO_DATA_MAX) {
			pd = cmd->data;
		} else {
			pd = cmd->pdata;
		}
	}

	rc = s_ctrl->sensor_i2c_client->i2c_func_tbl->
		i2c_read_seq_addr(s_ctrl->sensor_i2c_client,
		addr, addr2, pd, cmd->data_size, cmd->pdata? 1 : 0);
	return rc;
}

static int32_t m10mo_i2c_write_byte(
	struct msm_sensor_ctrl_t *s_ctrl, uint8_t kind, uint8_t cat,
	uint8_t byte, uint8_t data, uint16_t delay)
{
	struct fuji_i2c_seq cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.num = 5;
	cmd.cmd = kind;
	cmd.cat = cat;
	cmd.byte = byte;
	cmd.num8 = cmd.num - 4;
	cmd.data[0] = data;
	return m10mo_i2c_write_seq(s_ctrl, &cmd, delay);
}

static int32_t m10mo_i2c_write_byte_4(
	struct msm_sensor_ctrl_t *s_ctrl, uint8_t kind, uint8_t cat,
	uint8_t byte, uint32_t data, uint16_t delay)
{
	struct fuji_i2c_seq cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.num = 8;
	cmd.cmd = kind;
	cmd.cat = cat;
	cmd.byte = byte;
	cmd.num8 = cmd.num - 4;

	cmd.data[0] = (data & 0xFF000000) >> 24;
	cmd.data[1] = (data & 0x00FF0000) >> 16;
	cmd.data[2] = (data & 0x0000FF00) >> 8;
	cmd.data[3] = (data & 0xFF);

	return m10mo_i2c_write_seq(s_ctrl, &cmd, delay);
}

static int32_t m10mo_i2c_write_bytes(
	struct msm_sensor_ctrl_t *s_ctrl, uint8_t kind, uint8_t cat,
	uint8_t byte, uint8_t *data, uint8_t size, uint16_t delay)
{
	uint8_t i;
	struct fuji_i2c_seq cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.num = size + 4;
	cmd.cmd = kind;
	cmd.cat = cat;
	cmd.byte = byte;
	cmd.num8 = size;
	for (i = 0; i < size; i++)
		cmd.data[i] = data[i];
	return m10mo_i2c_write_seq(s_ctrl, &cmd, delay);
}

static int32_t m10mo_i2c_write_bulk(
	struct msm_sensor_ctrl_t *s_ctrl, uint8_t kind, uint32_t addr,
	uint16_t num, uint8_t *data, uint16_t delay)
{
	struct fuji_i2c_seq cmd;
	memset(&cmd, 0, sizeof(cmd));
	cmd.cmd = kind;
	cmd.addr = addr;
	cmd.num16 = num;
	cmd.pdata = data;
	return m10mo_i2c_write_seq(s_ctrl, &cmd, delay);
}

static int32_t m10mo_i2c_write_bulk_1(
	struct msm_sensor_ctrl_t *s_ctrl, uint8_t kind, uint32_t addr,
	uint8_t data, uint16_t delay)
{
	struct fuji_i2c_seq cmd;
	memset(&cmd, 0, sizeof(cmd));
	cmd.cmd = kind;
	cmd.addr = addr;
	cmd.num16 = 1;
	cmd.data[0] = data;
	return m10mo_i2c_write_seq(s_ctrl, &cmd, delay);
}

static int32_t m10mo_i2c_read_bulk(
	struct msm_sensor_ctrl_t *s_ctrl, uint8_t kind, uint32_t addr,
	uint16_t num, uint8_t *data)
{
	int32_t rc;
	struct fuji_i2c_seq cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.cmd = kind;
	cmd.addr = addr;
	cmd.num16 = num;
	cmd.pdata = data;
	cmd.data_size = cmd.num16 + 3;
	rc = m10mo_i2c_read_seq(s_ctrl, &cmd);

	return rc;
}

static int32_t m10mo_i2c_read_bulk_1(
	struct msm_sensor_ctrl_t *s_ctrl, uint8_t kind, uint32_t addr,
	uint8_t *data)
{
	int32_t rc;
	struct fuji_i2c_seq cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.cmd = kind;
	cmd.addr = addr;
	cmd.num16 = 1;
	cmd.data_size = cmd.num16 + 3;
	rc = m10mo_i2c_read_seq(s_ctrl, &cmd);

	*data = cmd.data[3];
	return 0;
}

static int32_t m10mo_i2c_read_byte(
	struct msm_sensor_ctrl_t *s_ctrl, uint8_t kind, uint8_t cat,
	uint8_t byte, uint8_t *data)
{
	int32_t rc;
	struct fuji_i2c_seq cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.num = 5;
	cmd.cmd = kind;
	cmd.cat = cat;
	cmd.byte = byte;
	cmd.num8 = 1;
	cmd.data_size = cmd.num8 + 1;
	rc = m10mo_i2c_read_seq(s_ctrl, &cmd);

	*data = cmd.data[1];
	return 0;
}

static int32_t m10mo_i2c_read_byte_2(
	struct msm_sensor_ctrl_t *s_ctrl, uint8_t kind, uint8_t cat,
	uint8_t byte, uint8_t *data, uint8_t *data2)
{
	int32_t rc;
	struct fuji_i2c_seq cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.num = 5;
	cmd.cmd = kind;
	cmd.cat = cat;
	cmd.byte = byte;
	cmd.num8 = 2;
	cmd.data_size = cmd.num8 + 1;
	rc = m10mo_i2c_read_seq(s_ctrl, &cmd);

	*data = cmd.data[1];
	*data2 = cmd.data[2];
	return 0;
}

static int32_t m10mo_i2c_read_byte_4(
	struct msm_sensor_ctrl_t *s_ctrl, uint8_t kind, uint8_t cat,
	uint8_t byte, uint8_t *data, uint8_t *data2,
	uint8_t *data3, uint8_t *data4)
{
	int32_t rc;
	struct fuji_i2c_seq cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.num = 5;
	cmd.cmd = kind;
	cmd.cat = cat;
	cmd.byte = byte;
	cmd.num8 = 4;
	cmd.data_size = cmd.num8 + 1;
	rc = m10mo_i2c_read_seq(s_ctrl, &cmd);

	*data = cmd.data[1];
	*data2 = cmd.data[2];
	*data3 = cmd.data[3];
	*data4 = cmd.data[4];
	return 0;
}

static int32_t m10mo_cmd(struct m10mo_ctrl_t *s_ctrl,
	uint8_t category, uint8_t byte, uint8_t value) 
{
	uint32_t pr_err_enable = 1;
	if (test_bit(FEATURE_CMD_DUMP, &s_ctrl->feature_mask)) {
		if (CATE_0X0A == category) {
			if (GYRO_RADIAN_X == byte || GYRO_RADIAN_Y == byte ||
				GYRO_RADIAN_Z == byte || GYRO_SPEED_X == byte ||
				GYRO_SPEED_Y == byte || GYRO_SPEED_Z == byte ||
				GYRO_UPDATE == byte)
				pr_err_enable = 0;
		}
		if (CATE_0X03 == category)  {
			if (DEGREE == byte)
				pr_err_enable = 0;
		}
		if (pr_err_enable)
			pr_err("[M10MO] %s: Cate:0x%02x, byte=0x%02x, \
				value=0x%02x\n", __func__, category, byte, value);
	}

	mutex_lock(s_ctrl->m10mo_i2c_mutex);
	m10mo_i2c_write_byte(&s_ctrl->sensor_ctrl, 2, category, byte, value, 0);
	mutex_unlock(s_ctrl->m10mo_i2c_mutex);
	return 0;
}

static int32_t m10mo_cmd_w(struct m10mo_ctrl_t *s_ctrl,
	uint8_t category, uint8_t byte, uint16_t value)
{
	uint8_t value8[2];
	value8[0] = (value >> 8) & 0xff;
	value8[1] = value & 0xff;
	if (test_bit(FEATURE_CMD_DUMP, &s_ctrl->feature_mask))
		pr_err("[M10MO] %s: Cate:0x%02x, byte=0x%02x, \
			value=0x%04x\n", __func__, category, byte, value);

	mutex_lock(s_ctrl->m10mo_i2c_mutex);
	m10mo_i2c_write_bytes(&s_ctrl->sensor_ctrl, 2, category, byte, value8, 2, 0);
	mutex_unlock(s_ctrl->m10mo_i2c_mutex);
	return 0;
}

static int32_t m10mo_cmd_l(struct m10mo_ctrl_t *s_ctrl,
	uint8_t category, uint8_t byte, uint32_t value)
{
	uint8_t value8[4];
	value8[0] = (value >> 24) & 0xff;
	value8[1] = (value >> 16) & 0xff;
	value8[2] = (value >> 8) & 0xff;
	value8[3] = value & 0xff;

	if (test_bit(FEATURE_CMD_DUMP, &s_ctrl->feature_mask))
		pr_err("[M10MO] %s: Cate:0x%02x, byte=0x%02x, \
			value=0x%08x\n", __func__, category, byte, value);

	mutex_lock(s_ctrl->m10mo_i2c_mutex);
	m10mo_i2c_write_bytes(&s_ctrl->sensor_ctrl, 2, category, byte, value8, 4, 0);
	mutex_unlock(s_ctrl->m10mo_i2c_mutex);
	return 0;
}
#if 0
static int32_t m10mo_mem_write(struct m10mo_ctrl_t *s_ctrl,
	int32_t addr, uint8_t *data, int32_t size)
{
	mutex_lock(s_ctrl->m10mo_i2c_mutex);
	m10mo_i2c_write_bulk(&s_ctrl->sensor_ctrl, 4,
		addr, size, data, 0);
	mutex_unlock(s_ctrl->m10mo_i2c_mutex);
	return 0;
}
#endif
static uint8_t m10mo_read(struct m10mo_ctrl_t *s_ctrl,
	uint8_t category, uint8_t byte)
{
	uint8_t value;
	mutex_lock(s_ctrl->m10mo_i2c_mutex);
	m10mo_i2c_read_byte(&s_ctrl->sensor_ctrl, 1, category, byte, &value);
	mutex_unlock(s_ctrl->m10mo_i2c_mutex);

	if (test_bit(FEATURE_CMD_DUMP, &s_ctrl->feature_mask))
		pr_err("[M10MO] %s: Cate:0x%02x, byte=0x%02x, \
			value=0x%02x\n", __func__, category, byte, value);

	return value;
}

static uint16_t m10mo_read_w(struct m10mo_ctrl_t *s_ctrl,
	uint8_t category, uint8_t byte)
{
	uint16_t value;
	uint8_t value1, value0;

	mutex_lock(s_ctrl->m10mo_i2c_mutex);
	m10mo_i2c_read_byte_2(&s_ctrl->sensor_ctrl, 1,
		category, byte, &value1, &value0);
	mutex_unlock(s_ctrl->m10mo_i2c_mutex);

	value = (value1 << 8) + value0;

	if (test_bit(FEATURE_CMD_DUMP, &s_ctrl->feature_mask))
		pr_err("[M10MO] %s: Cate:0x%02x, byte=0x%02x, \
			value=0x%02x\n", __func__, category, byte, value);

	return value;
}


static uint32_t m10mo_read_l(struct m10mo_ctrl_t *s_ctrl,
	uint8_t category, uint8_t byte)
{
	uint32_t value;
	uint8_t value3, value2, value1, value0;
	mutex_lock(s_ctrl->m10mo_i2c_mutex);
	m10mo_i2c_read_byte_4(&s_ctrl->sensor_ctrl, 1, category,
		byte, &value3, &value2, &value1, &value0);
	mutex_unlock(s_ctrl->m10mo_i2c_mutex);
	value = (value3 << 24) + (value2 << 16) + (value1 << 8) + value0;

	if (test_bit(FEATURE_CMD_DUMP, &s_ctrl->feature_mask))
		pr_err("[M10MO] %s: Cate:0x%02x, byte=0x%02x, \
			value=0x%08x\n", __func__, category, byte, value);

	return value;
}

static int32_t m10mo_mem_read(struct m10mo_ctrl_t *s_ctrl,
	int32_t addr, uint8_t *data, int32_t size)
{
	mutex_lock(s_ctrl->m10mo_i2c_mutex);
	m10mo_i2c_read_bulk(&s_ctrl->sensor_ctrl, 3,
		addr, size, data);
	mutex_unlock(s_ctrl->m10mo_i2c_mutex);
	return 0;
}

static struct timespec diff(struct timespec start, struct timespec end)
{
	struct timespec temp;
	if ((end.tv_nsec - start.tv_nsec) < 0) {
		temp.tv_sec = end.tv_sec - start.tv_sec - 1;
		temp.tv_nsec = NSEC_PER_SEC + end.tv_nsec - start.tv_nsec;
	} else {
		temp.tv_sec = end.tv_sec - start.tv_sec;
		temp.tv_nsec = end.tv_nsec - start.tv_nsec;
	}
	return temp;
}

static int32_t m10mo_firmware_init(struct msm_sensor_ctrl_t *s_ctrl,
	int i2c)
{
	int32_t rc = 0;
	struct m10mo_ctrl_t *m10mo_ctrl = container_of(s_ctrl,
		struct m10mo_ctrl_t, sensor_ctrl);

	if (i2c)
		m10mo_cmd(m10mo_ctrl, CATE_0X0F, RAM_START, RAM_Start);

	/* Set Flash ROM address for Chip erase */
	m10mo_cmd_l(m10mo_ctrl, CATE_0X0F, FLASH_AD,
		Flash_Erase_Start_Addr);
	return rc;
}

static int32_t m10mo_firmware_wait(struct msm_sensor_ctrl_t *s_ctrl,
	uint8_t cat, uint8_t byte, uint8_t bit, int ms)
{
	int32_t rc = 0, count = 0;
	uint8_t status = FUJI_ERROR_BYTE;
	struct m10mo_ctrl_t *m10mo_ctrl = container_of(s_ctrl,
		struct m10mo_ctrl_t, sensor_ctrl);

	do {
		status = m10mo_read(m10mo_ctrl, cat, byte);
		msleep(ms);
	} while ((status == (1 << bit)) && count++ < 100);

	CDBG("[M10MO] %s : %d %d, %x, %d\n", 
		__func__, __LINE__, rc, status, count);

	if (status != 0)
		return -EFAULT;
	return rc;
}

static int32_t m10mo_firmware_fctrl(struct msm_sensor_ctrl_t *s_ctrl)
{
	int32_t rc;
	rc = m10mo_i2c_write_bulk_1(s_ctrl, 4,
			M10MO_RAM_ADDR_FLASHCTL, 0x7f, 0);
	return rc;
}

static uint16_t m10mo_firmware_check(struct m10mo_ctrl_t *s_ctrl)
{
	int32_t rc;
	int16_t flash_sum = -1;
	//uint8_t flash_ctrl = 0x7f;
	struct timespec ts_start, ts_end, ts_fw_check;
	/* Set Flash Control */

	//m10mo_mem_write(s_ctrl, M10MO_RAM_ADDR_FLASHCTL, &flash_ctrl, 1);
	m10mo_firmware_fctrl(&s_ctrl->sensor_ctrl);
	/* Not sure delay really needed or not */
	msleep(25);


	ktime_get_ts(&ts_start);

	/* Start Checksum Calculate */
	m10mo_cmd(s_ctrl, CATE_0X0F, FLASH_CHK, FLASH_CHK_16M);

	/* Check Checksum process */
	rc = m10mo_firmware_wait(&s_ctrl->sensor_ctrl, CATE_0X0F, FLASH_CHK,
		2, MSLEEP_WAIT_LONG);
	if (rc) {
		pr_err("[M10MO] %s: Firmware Checksum Calculate failed\n", __func__);
		return rc;
	}
	ktime_get_ts(&ts_end);
	ts_fw_check = diff(ts_start, ts_end);
	CDBG("[M10MO]%s: Checksum calculate time = %ld ms\n", __func__,
		ts_fw_check.tv_sec * MSEC_PER_SEC + ts_fw_check.tv_nsec / NSEC_PER_MSEC);

	/* Get Checksum */
	flash_sum = m10mo_read_w(s_ctrl, CATE_0X0F, FLASH_SUM);
	CDBG("[M10MO] %s: check sum = %x\n", __func__, flash_sum);
	return flash_sum;
}

static int32_t m10mo_firmware_test(struct msm_sensor_ctrl_t *s_ctrl)
{
	int32_t rc;
	uint8_t tmp = FUJI_ERROR_BYTE;
	rc = m10mo_i2c_read_bulk_1(s_ctrl, 3, M10MO_RAM_ADDR_FLASHCTL, &tmp);
	return rc;
}

static int32_t m10mo_firmware_start(struct m10mo_ctrl_t *m10mo_ctrl,
	uint32_t i2c)
{
	int32_t rc;
	struct msm_sensor_ctrl_t *s_ctrl = &m10mo_ctrl->sensor_ctrl;
	struct msm_camera_gpio_conf *gpio_conf = s_ctrl->sensordata->gpio_conf;
	uint16_t gpio_sio_cs = gpio_conf->gpio_num_info->gpio_num[SENSOR_GPIO_SIO_CS];
	m10mo_ctrl->fw_buf = kzalloc(FIRMWARE_SIZE, GFP_KERNEL);
	if (!m10mo_ctrl->fw_buf) {
		pr_err("[M10MO] %s: alloc fw_buf failed\n", __func__);
		return -ENOMEM;
	}

	m10mo_firmware_init(s_ctrl, i2c);

	/* Chip erase */
	m10mo_cmd(m10mo_ctrl, CATE_0X0F, FLASH_ERASE, CHIP_ERASE);
	rc = m10mo_firmware_wait(s_ctrl, CATE_0X0F, FLASH_ERASE,
		BIT_CHIP_ERASE, MSLEEP_WAIT_LONG);

	if (i2c)
		return rc;

	/* Set the PLL value */
	m10mo_cmd_l(m10mo_ctrl, CATE_0X0F, PLL1DIV_VALUE, PLL_19_2MHz);

	/* Set destination address for SIO transmission */
	m10mo_cmd_l(m10mo_ctrl, CATE_0X0F, DATA_RAM_ADDR, DATA_RAM_Addr);

	/* Set programming byte */
	m10mo_cmd_l(m10mo_ctrl, CATE_0X0F, DATA_TRANS_SIZE, DATA_TRANS_Size);

	/* Set SDRAM */
	m10mo_cmd_w(m10mo_ctrl, CATE_0X0F, SDRAM_SET, SDRAM_SET_Value);

	/* Set SIO Mode */
	m10mo_cmd(m10mo_ctrl, CATE_0X0F, SIO_RECEIVE_MODE,
		ISP_latch_data_at_rising_edge);

	/* SIO mode start */
	m10mo_cmd(m10mo_ctrl, CATE_0X0F, RAM_START, SIO_Mode);
	msleep(3);

	rc = gpio_direction_output(gpio_sio_cs, 1);
	if (rc < 0) {
		pr_err("[M10MO] %s: %d %d, \
			failed to pull up gpio[%d] to send fw\n",
			__func__, __LINE__, rc, gpio_sio_cs);
		return rc;
	}

	return rc;
}

static int32_t m10mo_firmware_addr(struct msm_sensor_ctrl_t *s_ctrl,
	uint32_t *addr)
{
	int32_t rc;
	uint8_t buf[2] = {0x20, 0};

	rc = m10mo_i2c_write_byte_4(s_ctrl, 2, 0xf, FLASH_AD, *addr, 0);

	*addr += I2C_SEQ_REG_DATA_FUJI;

	rc = m10mo_i2c_write_bytes(s_ctrl, 2, 0xf, FLASH_BYTE, buf, 2, 0);
	return rc;
}

static int32_t m10mo_firmware_write(struct m10mo_ctrl_t *m10mo_ctrl)
{
	int32_t rc;
	struct msm_sensor_ctrl_t *s_ctrl = &m10mo_ctrl->sensor_ctrl;
	if (!m10mo_ctrl->fw_buf) {
		pr_err("[M10MO] %s: fw_buf NULL\n", __func__);
		return -EINVAL;
	}
	rc = m10mo_i2c_write_bulk(s_ctrl, 4, M10MO_RAM_ADDR_TOP,
		I2C_SEQ_REG_DATA_FUJI, m10mo_ctrl->fw_buf, MSLEEP_WAIT_NORM);
	CDBG("[M10MO] %s:%d %d\n", __func__, __LINE__, rc);

	rc = m10mo_i2c_write_byte(s_ctrl, 2, 0xf, FLASH_WR, 1, MSLEEP_WAIT_NORM);
	CDBG("[M10MO] %s:%d %d\n", __func__, __LINE__, rc);

	return m10mo_firmware_wait(s_ctrl, 0xf, FLASH_WR,
		BIT_PROGRAM, MSLEEP_WAIT_NORM);
}

static int32_t m10mo_firmware_write_sio(struct m10mo_ctrl_t *m10mo_ctrl)
{
	int rc;
	struct msm_sensor_ctrl_t *s_ctrl = &m10mo_ctrl->sensor_ctrl;
	struct msm_camera_gpio_conf *gpio_conf = s_ctrl->sensordata->gpio_conf;
	uint16_t gpio_sio_cs = gpio_conf->gpio_num_info->gpio_num[SENSOR_GPIO_SIO_CS];
	if (!m10mo_ctrl->fw_buf) {
		pr_err("[M10MO] %s: fw_buf NULL\n", __func__);
		return -EINVAL;
	}

	/* Send firmware */
	rc = spi_send_data_interface(m10mo_ctrl->fw_buf, FIRMWARE_SIZE);

	rc = gpio_direction_output(gpio_sio_cs, 0);
	if (rc < 0) {
		pr_err("[M10MO] %s: %d %d, \
			failed to pull down gpio[%d] after fw sent\n",
			__func__, __LINE__, rc, gpio_sio_cs);
		return rc;
	}
	/* Set FLASH ROM address */
	m10mo_cmd_l(m10mo_ctrl, CATE_0X0F, FLASH_AD, Flash_Write_Start_Addr);
	m10mo_cmd_l(m10mo_ctrl, CATE_0X0F, DATA_TRANS_SIZE, DATA_TRANS_Size);
	m10mo_cmd(m10mo_ctrl, CATE_0X0F, FLASH_WR, PROGRAM);

	return m10mo_firmware_wait(s_ctrl, CATE_0X0F, FLASH_WR,
		BIT_PROGRAM, MSLEEP_WAIT_LONG);
}

static int32_t m10mo_firmware_boot(struct m10mo_ctrl_t *s_ctrl)
{
	long result;
	int32_t rc = 0;

	rc = m10mo_i2c_write_bulk_1(&s_ctrl->sensor_ctrl, 4,
			M10MO_RAM_ADDR_FLASHCTL, 0x7f, 0);

	m10mo_cmd(s_ctrl, CATE_0X0F, CAM_START, ENABLE);
	result = wait_for_completion_interruptible_timeout(
		&s_ctrl->cpl[CPL_BOOT], msecs_to_jiffies(BOOT_TIMEOUT));

	if (result <= 0) {
		pr_err("[M10MO] %s: Timeout\n", __func__);
		return -EIO;
	}

	atomic_set(&s_ctrl->stream_status, STREAM_OFF);
	return rc;
}

static void caf_trigger_notify(struct msm_sensor_ctrl_t *s_ctrl)
{
	struct v4l2_event event;
	struct video_device *vdev = s_ctrl->msm_sd.sd.devnode;
	memset(&event, 0, sizeof(struct v4l2_event));

	event.type = MSM_CAMERA_V4L2_EVENT_TYPE;
	event.id = MSM_CAMERA_MSM_AF_TRIGGER_NOTIFY;
	v4l2_event_queue(vdev, &event);
}

static void af_finish_notify(struct msm_sensor_ctrl_t *s_ctrl)
{
	struct v4l2_event event;
	struct video_device *vdev = s_ctrl->msm_sd.sd.devnode;
	memset(&event, 0, sizeof(struct v4l2_event));

	event.type = MSM_CAMERA_V4L2_EVENT_TYPE;
	event.id = MSM_CAMERA_MSM_AF_FINISH_NOTIFY;
	v4l2_event_queue(vdev, &event);
}

static uint16_t m10mo_vcm_dac_get(struct m10mo_ctrl_t *s_ctrl)
{
	uint16_t dac = m10mo_read_w(s_ctrl, CATE_0X0A, CURRENT_DAC);

	if (0) CDBG("[M10MO] %s: current vcm dac = %d\n", __func__, dac);
	return dac;
}

static void m10mo_caf_profiling(struct m10mo_ctrl_t *s_ctrl)
{
	long this_ms;
	long total_ms;
	struct timespec caf_this_t;
	struct timespec caf_finish_t;

	getnstimeofday(&caf_finish_t);
	caf_this_t = diff(s_ctrl->caf_trigger_t, caf_finish_t);

	s_ctrl->caf_total_t.tv_sec += caf_this_t.tv_sec;
	s_ctrl->caf_total_t.tv_nsec += caf_this_t.tv_nsec;

	if (s_ctrl->caf_total_t.tv_nsec >= NSEC_PER_SEC) {
		s_ctrl->caf_total_t.tv_sec++;
		s_ctrl->caf_total_t.tv_nsec -= NSEC_PER_SEC;
	}

	total_ms = s_ctrl->caf_total_t.tv_sec * MSEC_PER_SEC +
		s_ctrl->caf_total_t.tv_nsec / NSEC_PER_MSEC;
	this_ms = caf_this_t.tv_sec * MSEC_PER_SEC +
		caf_this_t.tv_nsec / NSEC_PER_MSEC;

	CDBG("[M10MO][caf_profiling] %s: CAF counter = %d, \
		CAF time = %ld ms, CAF average = %ld ms\n", __func__,
		s_ctrl->caf_counter, this_ms, total_ms / s_ctrl->caf_counter);

	CDBG("[M10MO][caf_profiling] %s: VCM DAC = %u",
		__func__, m10mo_vcm_dac_get(s_ctrl));
}

static void m10mo_taf_profiling(struct m10mo_ctrl_t *s_ctrl)
{
	long this_ms;
	long total_ms;
	struct timespec taf_this_t;
	struct timespec taf_finish_t;

	getnstimeofday(&taf_finish_t);
	taf_this_t = diff(s_ctrl->taf_trigger_t, taf_finish_t);

	s_ctrl->taf_total_t.tv_sec += taf_this_t.tv_sec;
	s_ctrl->taf_total_t.tv_nsec += taf_this_t.tv_nsec;

	if (s_ctrl->taf_total_t.tv_nsec >= NSEC_PER_SEC) {
		s_ctrl->taf_total_t.tv_sec++;
		s_ctrl->taf_total_t.tv_nsec -= NSEC_PER_SEC;
	}

	total_ms = s_ctrl->taf_total_t.tv_sec * MSEC_PER_SEC +
		s_ctrl->taf_total_t.tv_nsec / NSEC_PER_MSEC;
	this_ms = taf_this_t.tv_sec * MSEC_PER_SEC +
		taf_this_t.tv_nsec / NSEC_PER_MSEC;

	mutex_lock(s_ctrl->taf_time_mutex);
	s_ctrl->taf_time_last = this_ms;
	mutex_unlock(s_ctrl->taf_time_mutex);

	CDBG("[M10MO][taf_profiling] %s: TAF counter = %d, \
		TAF time = %ld ms, TAF average = %ld ms\n", __func__,
		s_ctrl->taf_counter, this_ms, total_ms / s_ctrl->taf_counter);
}

static void m10mo_irq_work(struct work_struct * work)
{
	unsigned long flags;
	uint8_t inr_status = 0;
	int32_t af_mode, af_status, stream_status;
	struct m10mo_ctrl_t *s_ctrl = &m10mo_s_ctrl;

	stream_status = atomic_read(&s_ctrl->stream_status);
	if ((POWER_DOWN == stream_status) ||
		(POWER_DOWNING == stream_status)) {
		atomic_set(&s_ctrl->irq_processed, IRQ_PROCESSED);
		wake_up(&s_ctrl->wait_q);
		return;
	}
	inr_status = m10mo_read(s_ctrl, CATE_0X00, INT_FACTOR);

	spin_lock_irqsave(&s_ctrl->irq_work_lock, flags);

	af_mode = atomic_read(&s_ctrl->af_mode);
	af_status = atomic_read(&s_ctrl->af_status);
	stream_status = atomic_read(&s_ctrl->stream_status);

	CDBG("[M10MO] %s: stream status = %s, \
		af_status = %s, af_mode = %s\n",
		__func__, stream_status_s[stream_status],
		af_status_s[af_status], af_mode_s[af_mode]);

	CDBG("[M10MO] %s: IRQ_STATUS = 0x%02x\n", __func__, inr_status);

	if (inr_status & INT_STATUS_MODE)
		CDBG("[M10MO] %s: INT_STATUS | INT_STATUS_MODE\n",
			__func__);

	if (inr_status & INT_STATUS_AF)
		CDBG("[M10MO] %s: INT_STATUS | INT_STATUS_AF\n",
			__func__);

	if (inr_status & INT_STATUS_CAPTURE)
		CDBG("[M10MO] %s: INT_STATUS | INT_STATUS_CAPTURE\n",
			__func__);

	if (inr_status & INT_STATUS_CAF_START) {
		CDBG("[M10MO] %s: INT_STATUS | INT_STATUS_CAF_START\n",
			__func__);
		if (Continuous_AF_applied == af_mode)
			CDBG("[M10MO] %s: CAF TRIGGERING__\\\n", __func__);
	}

	if (inr_status & INT_STATUS_CAF_END) {
		CDBG("[M10MO] %s: INT_STATUS | INT_STATUS_CAF_END\n",
			__func__);
		if (Continuous_AF_applied == af_mode)
			CDBG("[M10MO] %s: CAF FINISH__|\n", __func__);
	}

	spin_unlock_irqrestore(&s_ctrl->irq_work_lock, flags);

	if (inr_status & INT_STATUS_MODE) {
		if (UNBOOTED == stream_status)
			complete(&s_ctrl->cpl[CPL_BOOT]);
		else if (STREAM_OFF == stream_status)
			complete(&s_ctrl->cpl[CPL_MON_START]);
		else if (MONITOR_STOPPING == stream_status)
			complete(&s_ctrl->cpl[CPL_MON_FINISH]);
	}

	if (inr_status & INT_STATUS_AF) {
		if (AF_ONGOING == af_status) {
			if (test_bit(FEATURE_AF_PROFILING, &s_ctrl->feature_mask))
				m10mo_taf_profiling(s_ctrl);
			atomic_set(&s_ctrl->af_status, LENS_INITED);
			complete(&s_ctrl->cpl[CPL_AF_FINISH]);
			af_finish_notify(&s_ctrl->sensor_ctrl);
		} else if (LENS_DEINITIALING == af_status)
			complete(&s_ctrl->cpl[CPL_LDEINIT]);
		else if (AF_STOPPING == af_status)
			complete(&s_ctrl->cpl[CPL_AF_STOP]);
		else if ((CAF_PAUSING == af_status) &&
			(Continuous_AF_applied == af_mode))
			complete(&s_ctrl->cpl[CPL_CAF_PAUSE]);
		else if (AF_RANGE_SETTING == af_status)
			complete(&s_ctrl->cpl[CPL_AF_RANGE]);
		else
			complete(&s_ctrl->cpl[CPL_LINIT]);
	}

	if (inr_status & INT_STATUS_CAPTURE) {
		if (ZSL_CAPTURE_STARTING == stream_status)
			complete(&s_ctrl->cpl[CPL_CAP_START]);
		else if (ZSL_CAPTURE_STOPPING == stream_status) {
			atomic_set(&s_ctrl->stream_status, MONITOR);
			atomic_set(&s_ctrl->cur_res, MSM_SENSOR_RES_2);
			wake_up(&s_ctrl->wait_q);
		}
	}

	if (inr_status & INT_STATUS_CAF_START) {
		if (Continuous_AF_applied == af_mode) {
			if ((AF_STOPPING != af_status) && 
				(CAF_PAUSING != af_status))
				atomic_set(&s_ctrl->af_status, AF_ONGOING);
			if (test_bit(FEATURE_AF_PROFILING, &s_ctrl->feature_mask)) {
				s_ctrl->caf_counter++;
				getnstimeofday(&s_ctrl->caf_trigger_t);
			}
			caf_trigger_notify(&s_ctrl->sensor_ctrl);
		}
	}

	if (inr_status & INT_STATUS_CAF_END) {
		if (Continuous_AF_applied == af_mode) {
			if ((AF_STOPPING != af_status) && 
				(CAF_PAUSING != af_status))
				atomic_set(&s_ctrl->af_status, LENS_INITED);

			if (test_bit(FEATURE_AF_PROFILING, &s_ctrl->feature_mask))
				m10mo_caf_profiling(s_ctrl);

			af_finish_notify(&s_ctrl->sensor_ctrl);
		}
	}

	atomic_set(&s_ctrl->irq_processed, IRQ_PROCESSED);
	wake_up(&s_ctrl->wait_q);

}

static uint32_t m10mo_caf_start(struct m10mo_ctrl_t *s_ctrl)
{
	int32_t rc = 0, af_mode, af_status, stream_status;
	af_mode = atomic_read(&s_ctrl->af_mode);
	af_status =  atomic_read(&s_ctrl->af_status);
	stream_status = atomic_read(&s_ctrl->stream_status);

	CDBG("[M10MO] %s: BEGIN--Stream_status = %s, \
		Af_mode = %s, af_status = %s\n",
		__func__, stream_status_s[stream_status],
		af_mode_s[af_mode], af_status_s[af_status]);

	if (MONITOR != stream_status) {
		CDBG("[M10MO] %s: Operation not allowed,\
			af_mode = %s\n",
			__func__, af_mode_s[af_mode]);
		return -EINVAL;
	}

	if ((Continuous_AF) != af_mode &&
		(Continuous_AF_applied != af_mode)) {
		CDBG("[M10MO] %s: Operation not allowed,\
			af_mode = %s\n", 
			__func__, af_mode_s[af_mode]);
		return -EINVAL;
	}
	if (1 == atomic_read(&s_ctrl->manual_af ) ) {
		caf_trigger_notify(&s_ctrl->sensor_ctrl);
		af_finish_notify(&s_ctrl->sensor_ctrl);
		return rc;
	}
	m10mo_cmd(s_ctrl, CATE_0X0A, AF_MODE, Continuous_AF);
	m10mo_cmd(s_ctrl, CATE_0X0A, AF_AREA_MODE, CENTER);
	m10mo_cmd(s_ctrl, CATE_0X0A, AF_START, AF_start);
	atomic_set(&s_ctrl->af_mode, Continuous_AF_applied);
	return rc;
}

static int32_t m10mo_lens_init(struct m10mo_ctrl_t *s_ctrl)
{
	long result;
	int32_t rc = 0, af_mode, af_status, stream_status;
	af_mode = atomic_read(&s_ctrl->af_mode);
	af_status = atomic_read(&s_ctrl->af_status);
	stream_status = atomic_read(&s_ctrl->stream_status);
	CDBG("[M10MO] %s: BEGIN--Stream_status = %s, \
		Af_mode = %s, af_status = %s\n",
		__func__, stream_status_s[stream_status], 
		af_mode_s[af_mode], af_status_s[af_status]);

	if (LENS_DEINITED != af_status) {
		CDBG("[M10MO] %s: Operation not allowed, \
			af_status = %s, af_mode = %s\n", __func__,
			af_status_s[af_status], af_mode_s[af_mode]);
		return -EINVAL;
	}

	m10mo_cmd(s_ctrl, CATE_0X0A, AF_RANGE,
		Initial_DAC_position);
	result = wait_for_completion_interruptible_timeout(
		&s_ctrl->cpl[CPL_LINIT],
		msecs_to_jiffies(LENS_TIMEOUT));

	if (result <= 0) {
		pr_err("[M10MO] %s: Wait for lens init timeout, \
			af_status = %s, af_mode = %s\n", __func__,
			af_status_s[af_status], af_mode_s[af_mode]);
		return -EIO;
	}

	atomic_set(&s_ctrl->af_status, LENS_INITED);
	return rc;
}

static int32_t m10mo_af_mode_apply(struct m10mo_ctrl_t *s_ctrl)
{
	long result;
	int32_t rc = 0;
	uint8_t m10mo_af_range = 0;
	int32_t cur_mode, cur_status, stream_status;

	cur_mode = atomic_read(&s_ctrl->af_mode);
	cur_status = atomic_read(&s_ctrl->af_status);
	stream_status = atomic_read(&s_ctrl->stream_status);
	CDBG("[M10MO] %s: BEGIN--Stream_status = %s, \
		cur_AF_mode = %s, af_status = %s\n", __func__,
		stream_status_s[stream_status],
		af_mode_s[cur_mode], af_status_s[cur_status]);
	if (MONITOR != stream_status) {
		CDBG("[M10MO] %s: operation not allowed\n", __func__);
		return -EINVAL;
	}
	if (LENS_INITED != cur_status) {
		CDBG("[M10MO] %s: operation not allowed\n", __func__);
		return -EINVAL;
	}

	switch (cur_mode) {
	case Continuous_AF:
	case Continuous_AF_applied: {
		if (LENS_INITED == cur_status)
			m10mo_caf_start(s_ctrl);
		return rc;
	}
	case Fixed_AF: {
		m10mo_af_range = Normal_position;
		break;
	}
	case Macro_AF: {
		m10mo_af_range = Macro_position;
		break;
	}
	case Infinity_AF: {
		m10mo_af_range = INF_position;
		break;
	}
	default:
		return rc;
	}
	atomic_set(&s_ctrl->af_status, AF_RANGE_SETTING);
	m10mo_cmd(s_ctrl, CATE_0X0A, AF_RANGE, m10mo_af_range);
	result = wait_for_completion_interruptible_timeout(
		&s_ctrl->cpl[CPL_AF_RANGE],
		msecs_to_jiffies(LENS_TIMEOUT));
	if (result <= 0) {
		pr_err("[M10MO] %s: Wait for lens init timeout, \
			af_status = %s, af_mode = %s\n", __func__,
			af_status_s[cur_status], af_mode_s[cur_mode]);
		return -EIO;
	}

	atomic_set(&s_ctrl->af_status, LENS_INITED);
	wake_up(&s_ctrl->wait_q);
	return rc;
}

static void m10mo_ae_lock(struct m10mo_ctrl_t *s_ctrl,
	int32_t enable)
{
	uint8_t ae_lock = AE_LOCK_OFF;

	if (enable > 0)
		ae_lock = AE_LOCK_ON;

	CDBG("[M10MO] %s: ae_lock = %s\n",
		__func__, ae_lock_s[ae_lock]);

	m10mo_cmd(s_ctrl, CATE_0X03, AE_LOCK, ae_lock);
	m10mo_cmd(s_ctrl, CATE_0X03, AE_PARAM_UPDATE,
		AE_PARAM_UPDATE_Update);

	if (AE_LOCK_ON == ae_lock)
		msleep(AE_LOCK_DELAY);
}

static int32_t m10mo_af_stop(struct m10mo_ctrl_t *s_ctrl)
{
	long result;
	int32_t rc = 0;
	uint8_t af_start = 0;
	int af_mode = atomic_read(&s_ctrl->af_mode);
	int af_status = atomic_read(&s_ctrl->af_status);
	int stream_status = atomic_read(&s_ctrl->stream_status);
	CDBG("[M10MO] %s: pre-BEGIN--Stream_status = %s, \
		Af_mode = %s, af_status = %s\n",
		__func__, stream_status_s[stream_status],
		af_mode_s[af_mode], af_status_s[af_status]);

	wait_event_interruptible(s_ctrl->wait_q,
		IRQ_PROCESSED == atomic_read(&s_ctrl->irq_processed));

	af_mode = atomic_read(&s_ctrl->af_mode);
	af_status = atomic_read(&s_ctrl->af_status);
	stream_status = atomic_read(&s_ctrl->stream_status);

	CDBG("[M10MO] %s: BEGIN--Stream_status = %s, \
		Af_mode = %s, af_status = %s\n",
		__func__, stream_status_s[stream_status],
		af_mode_s[af_mode], af_status_s[af_status]);


	if ((MONITOR != stream_status) &&
		(MONITOR_VIRTUAL_OFF != stream_status)) {
		CDBG("[M10MO] %s: Operation not permitted, \
			Current stream status = %s\n",
			__func__, stream_status_s[stream_status]);
		return -EINVAL;
	}

	/* AF STOP will be invoked for following cases: 
	 * - under Normal AF Mode, if AF ongoing
	 * - under CAF Mode, before monitor switch */
	af_mode = atomic_read(&s_ctrl->af_mode);
	af_status = atomic_read(&s_ctrl->af_status);
	if (((Normal_AF == af_mode) && 
		(AF_ONGOING != af_status)) ||
		((Continuous_AF_applied != af_mode) && 
		(Normal_AF != af_mode))) {
		CDBG("[M10MO] %s: Operation not permitted, \
			Current af mode = %s, \
			Current af status = %s\n",
			__func__, af_mode_s[af_mode], 
			af_status_s[af_status]);
		return -EINVAL;
	}

	atomic_set(&s_ctrl->af_status, AF_STOPPING);
	m10mo_cmd(s_ctrl, CATE_0X0A, AF_START, AF_stop_by_force);
	result = wait_for_completion_interruptible_timeout(
		&s_ctrl->cpl[CPL_AF_STOP], msecs_to_jiffies(AF_STOP_TIMEOUT));

	if (result <= 0) {
		pr_err("[M10MO] %s: af stop timeout, Current af mode = %s, \
			Current af status = %s\n",
			__func__, af_mode_s[af_mode], af_status_s[af_status]);
		return -EIO;
	}
	/* do we really need check start result? */
	if (0) {
	af_start = m10mo_read(s_ctrl, CATE_0X0A, AF_START);
	if ((AF_stop_by_force != af_start) && (AF_done != af_start)) {
		pr_err("[M10MO] %s: af stop result error, Current af mode = %s, \
			Current af status = %s\n",
			__func__, af_mode_s[af_mode], af_status_s[af_status]);
		return -EIO;
	}}

	atomic_set(&s_ctrl->af_status, LENS_INITED);
	return rc;
}

static uint32_t m10mo_caf_exit(struct m10mo_ctrl_t *s_ctrl)
{
	int rc = 0;
	long result;
	int32_t af_mode, af_status, stream_status;
	af_mode = atomic_read(&s_ctrl->af_mode);
	af_status = atomic_read(&s_ctrl->af_status);
	stream_status = atomic_read(&s_ctrl->stream_status);
	CDBG("[M10MO] %s: BEGIN--Stream_status = %s, \
		Af_mode = %s, af_status = %s\n",
		__func__, stream_status_s[stream_status],
		af_mode_s[af_mode], af_status_s[af_status]);

	if (Continuous_AF_applied != af_mode) {
		pr_err("[M10MO] %s: Operation not allowed, af_mode=%d, \
			af_status = %s\n",__func__,
			af_mode, af_status_s[af_status]);
		return -EINVAL;
	}

	wait_event_interruptible(s_ctrl->wait_q,
		IRQ_PROCESSED == atomic_read(&s_ctrl->irq_processed));

	atomic_set(&s_ctrl->af_status, CAF_PAUSING);
	m10mo_cmd(s_ctrl, CATE_0X0A, AF_START, AF_pause);
	result = wait_for_completion_interruptible_timeout(
		&s_ctrl->cpl[CPL_CAF_PAUSE], msecs_to_jiffies(AF_STOP_TIMEOUT *2*2));

	if (result <= 0) {
		pr_err("[M10MO] %s: Timeout, failed, stream_status = %s\n",
			__func__, stream_status_s[stream_status]);
		return -EIO;
	}

	atomic_set(&s_ctrl->af_status, LENS_INITED);
	return rc;
}

static void m10mo_af_mode_set(struct m10mo_ctrl_t *s_ctrl,
	int32_t af_mode)
{
	int32_t cur_mode, cur_status, stream_status;
	cur_mode = atomic_read(&s_ctrl->af_mode);
	cur_status = atomic_read(&s_ctrl->af_status);
	stream_status = atomic_read(&s_ctrl->stream_status);
	CDBG("[M10MO] %s: BEGIN--Stream_status = %s, setting AF_mode = %s, \
		cur_AF_mode = %s, af_status = %s\n", __func__,
		stream_status_s[stream_status], hal_af_mode_s[af_mode],
		af_mode_s[cur_mode], af_status_s[cur_status]);

	if (MONITOR != stream_status ||
		MONITOR_STOP_WORK_ONGOING ==
		atomic_read(&s_ctrl->monitor_stop_working)) {
		atomic_set(&s_ctrl->af_mode_p, af_mode);
		return;
	}

	switch (af_mode) {
	case CAM_FOCUS_MODE_CONTINOUS_VIDEO:
	case CAM_FOCUS_MODE_CONTINOUS_PICTURE:
		if ((Continuous_AF != cur_mode) &&
			(Continuous_AF_applied != cur_mode))
			atomic_set(&s_ctrl->af_mode, Continuous_AF);
		s_ctrl->movie_caf = CAF_MOVIE_Disable;
		if (CAM_FOCUS_MODE_CONTINOUS_VIDEO == af_mode)
			s_ctrl->movie_caf = CAF_MOVIE_Enable;
		break;

	case CAM_FOCUS_MODE_AUTO: {
		if (Continuous_AF_applied == cur_mode) {
			if (0) m10mo_af_stop(s_ctrl);
			else m10mo_caf_exit(s_ctrl);
		}

		m10mo_cmd(s_ctrl, CATE_0X0A, AF_MODE, Normal_AF);
		atomic_set(&s_ctrl->af_mode, Normal_AF);
		break;
	}

	case CAM_FOCUS_MODE_FIXED: {
		if (AF_STOPPING != cur_status) {
			if (Continuous_AF_applied == cur_mode) {
				if (0) m10mo_af_stop(s_ctrl);
				else m10mo_caf_exit(s_ctrl);
			} else
				m10mo_af_stop(s_ctrl);
		}
		atomic_set(&s_ctrl->af_mode, Fixed_AF);
		break;
	}

	case CAM_FOCUS_MODE_MACRO: {
		if (Continuous_AF_applied == cur_mode) {
			if (0) m10mo_af_stop(s_ctrl);
			else m10mo_caf_exit(s_ctrl);
		} else
			m10mo_af_stop(s_ctrl);
		atomic_set(&s_ctrl->af_mode, Macro_AF);
		break;
	}

	case CAM_FOCUS_MODE_INFINITY: {
		if (Continuous_AF_applied == cur_mode) {
			if (0) m10mo_af_stop(s_ctrl);
			else m10mo_caf_exit(s_ctrl);
		} else
			m10mo_af_stop(s_ctrl);
		atomic_set(&s_ctrl->af_mode, Infinity_AF);
		break;
	}

	default:
		break;
	}
	m10mo_af_mode_apply(s_ctrl);

}

static void m10mo_monitor_work(struct work_struct * work)
{
	struct m10mo_ctrl_t *s_ctrl = &m10mo_s_ctrl;
	int32_t stream_status = atomic_read(&s_ctrl->stream_status);
	atomic_set(&s_ctrl->monitor_working, MONITOR_WORK_ONGOING);
	if (MONITOR != stream_status) {
		pr_err("[M10MO] %s: Operation not allowed, \
			stream_status = %s\n",
			__func__, stream_status_s[stream_status]);
		atomic_set(&s_ctrl->monitor_working, MONITOR_WORK_COMPLETED);
		wake_up(&s_ctrl->wait_q);
		return;
	}
	m10mo_lens_init(s_ctrl);
	m10mo_af_mode_set(s_ctrl, atomic_read(&s_ctrl->af_mode_p));
	atomic_set(&s_ctrl->af_mode_p, CAM_FOCUS_MODE_MAX);
	if (!test_bit(FEATURE_OB_CHECK, &s_ctrl->feature_mask)) {
		atomic_set(&s_ctrl->monitor_working, MONITOR_WORK_COMPLETED);
		wake_up(&s_ctrl->wait_q);
		return;
	}

	m10mo_cmd(s_ctrl, CATE_0X03, OB_RELATED1, OB_RELATED_V1);
	m10mo_cmd(s_ctrl, CATE_0X03, OB_RELATED2, OB_RELATED_V2);
	atomic_set(&s_ctrl->monitor_working, MONITOR_WORK_COMPLETED);
	wake_up(&s_ctrl->wait_q);
}

static int32_t m10mo_monitor_stop(struct m10mo_ctrl_t *s_ctrl)
{
	int32_t rc = 0;
	long result = 0;
	int32_t cur_mode, cur_status, stream_status;

	cur_mode = atomic_read(&s_ctrl->af_mode);
	cur_status = atomic_read(&s_ctrl->af_status);
	stream_status = atomic_read(&s_ctrl->stream_status);

	CDBG("[M10MO] %s: ENTER, Stream status = %s\n",
		__func__, stream_status_s[stream_status]);

	if ((MONITOR != stream_status) &&
		(MONITOR_VIRTUAL_OFF != stream_status)) {
		pr_err("[M10MO] %s: Operation not allowed, stream_status = %s",
			__func__, stream_status_s[stream_status]);
		return -EINVAL;
	}
	if (Normal_AF == cur_mode && AF_ONGOING == cur_status)
		m10mo_af_stop(s_ctrl);

	atomic_set(&s_ctrl->stream_status, MONITOR_STOPPING);


	m10mo_cmd(s_ctrl, CATE_0X00, M10MO_SYS_MODE,
		Parameter_setting_mode);
	result = wait_for_completion_interruptible_timeout(
		&s_ctrl->cpl[CPL_MON_FINISH],
		msecs_to_jiffies(MONITOR_TIMEOUT));

	if (result <= 0) {
		pr_err("[M10MO] %s: Timeout, stream_status = %s\n",
			 __func__, stream_status_s[stream_status]);
		return -EIO;
	}

	atomic_set(&s_ctrl->stream_status, STREAM_OFF);

	return rc;
}

static void m10mo_monitor_stop_work(struct work_struct * work)
{
	int stream_status;
	struct m10mo_ctrl_t *s_ctrl = &m10mo_s_ctrl;
	stream_status = atomic_read(&s_ctrl->stream_status);
	CDBG("[M10MO] %s: ENTER, Stream status = %s\n",
		__func__, stream_status_s[stream_status]);

	m10mo_monitor_stop(s_ctrl);
	atomic_set(&s_ctrl->monitor_stop_working,
		MONITOR_STOP_WORK_COMPLETED);
	wake_up(&s_ctrl->wait_q);
}

static irqreturn_t m10mo_irq(int irq, void *data)
{
	struct m10mo_ctrl_t *m10mo_ctrl = (struct m10mo_ctrl_t *)data;
	atomic_set(&m10mo_ctrl->irq_processed, IRQ_PROCESSING);
	CDBG("[M10MO] %s: IRQ ARRIVING\n", __func__);

	if (!m10mo_ctrl->irq_q)
		return IRQ_HANDLED;

	queue_work(m10mo_ctrl->irq_q, &m10mo_ctrl->irq_work);
	return IRQ_HANDLED;
}

static int32_t m10mo_lens_deinit(struct m10mo_ctrl_t *s_ctrl)
{
	long result;
	int32_t rc = 0, af_mode, af_status, stream_status;
	af_mode = atomic_read(&s_ctrl->af_mode);
	af_status = atomic_read(&s_ctrl->af_status);
	stream_status = atomic_read(&s_ctrl->stream_status);
	CDBG("[M10MO] %s: BEGIN--Stream_status = %s, \
		Af_mode = %s, af_status = %s\n",
		__func__,stream_status_s[stream_status],
		af_mode_s[af_mode], af_status_s[af_status]);

	m10mo_af_stop(s_ctrl);

	af_status = atomic_read(&s_ctrl->af_status);
	if (LENS_INITED != af_status) {
		CDBG("[M10MO] %s: Operation not allowed, af_status = %s\n",
			__func__, af_status_s[af_status]);
		return -EINVAL;
	}

	m10mo_cmd(s_ctrl, CATE_0X0A, AF_RANGE, Close_position);
	atomic_set(&s_ctrl->af_status, LENS_DEINITIALING);
	result =  wait_for_completion_interruptible_timeout(
		&s_ctrl->cpl[CPL_LDEINIT], msecs_to_jiffies(LENS_TIMEOUT));

	if (result <= 0) {
		pr_err("[M10MO] %s: Timeout, af_status = %s\n",
			__func__, af_status_s[af_status]);
		return -EIO;
	}

	/* reset AF MODE */
	atomic_set(&s_ctrl->af_mode, Invalid_AF);
	atomic_set(&s_ctrl->af_status, LENS_DEINITED);

	return rc;
}

static int32_t m10mo_bailout_monitor(struct m10mo_ctrl_t *s_ctrl)
{
	long result = 0;
	int af_mode, af_status, stream_status, flash_mode;
	af_mode = atomic_read(&s_ctrl->af_mode);
	af_status = atomic_read(&s_ctrl->af_status);
	flash_mode = atomic_read(&s_ctrl->flash_mode);
	stream_status = atomic_read(&s_ctrl->stream_status);

	CDBG("[M10MO] %s: BEGIN--Stream_status = %s, \
		Af_mode = %s, af_status = %s\n",
		__func__, stream_status_s[stream_status],
		af_mode_s[af_mode], af_status_s[af_status]);

	if (MONITOR_VIRTUAL_OFF == stream_status) {
		atomic_set(&s_ctrl->stream_status, MONITOR);
		return -EINVAL;
	}

	if (STREAM_OFF != stream_status) {
		/* This is a Good EINVAL, sometimes */
		CDBG("[M10MO] %s: Operation not allowed, \
			stream_status = %s\n", __func__,
			stream_status_s[stream_status]);
		return -EINVAL;
	}

	m10mo_cmd(s_ctrl, CATE_0X01, MON_SIZE, _1440x1080);
	m10mo_cmd(s_ctrl, CATE_0X0C, CAP_MODE, Zsl_Capture_type2);
	m10mo_cmd(s_ctrl, CATE_0X00, M10MO_SYS_MODE, Monitor_mode);

	result = wait_for_completion_interruptible_timeout(
		&s_ctrl->cpl[CPL_MON_START],
		msecs_to_jiffies(MONITOR_TIMEOUT));

	if (result == 0) {
		pr_err("[M10MO] %s: Timeout, failed, stream_status = %s\n",
			__func__, stream_status_s[stream_status]);
		return -EIO;
	}
	if (result < 0) {
		pr_err("[M10MO] %s: interrupted, failed, stream_status = %s\n",
			__func__, stream_status_s[stream_status]);
		return -EIO;
	}
	atomic_set(&s_ctrl->stream_status, MONITOR);
	return 0;
}

int32_t m10mo_power_down(struct m10mo_ctrl_t *s_ctrl)
{
	int32_t rc = 0;
	struct msm_sensor_ctrl_t *sensor_ctrl =
		&s_ctrl->sensor_ctrl;
	int (*power_down_func)(struct msm_sensor_ctrl_t *) =
		sensor_ctrl->func_tbl->sensor_power_down;

	wait_event_interruptible(s_ctrl->wait_q,
		MONITOR_STOP_WORK_COMPLETED ==
		atomic_read(&s_ctrl->monitor_stop_working));

	CDBG("[M10MO][profiling] %s: BEGIN\n", __func__);
	m10mo_cmd(s_ctrl, CATE_0X03, STROBE_EN, 
		STROBE_EN_Torch_on_by_TX_pin);

	m10mo_bailout_monitor(s_ctrl);
	rc = m10mo_lens_deinit(s_ctrl);

	/* if no real lens operation, 
         * msleep still needed */
	if (rc == -EINVAL)
		msleep(SAFE_I2C_DELAY);

	/* reset status */
	atomic_set(&s_ctrl->hdr_enable, OFF);
	atomic_set(&s_ctrl->af_mode, Invalid_AF);
	atomic_set(&s_ctrl->af_status, LENS_DEINITED);
	atomic_set(&s_ctrl->stream_status, POWER_DOWNING);

	if (power_down_func)
		rc = power_down_func(sensor_ctrl);
	else
		rc = -EFAULT;

	if ((test_bit(FEATURE_ISP_LOG_VIEW, 
		&s_ctrl->feature_mask)) &&
		s_ctrl->log_buf_h) {
		ion_free(s_ctrl->iclient, s_ctrl->log_buf_h);
		s_ctrl->log_buf_h = 0;
	}
	if (s_ctrl->fw_buf) {
		kfree(s_ctrl->fw_buf);
		s_ctrl->fw_buf = 0;
	}
	atomic_set(&s_ctrl->stream_status, POWER_DOWN);
	wake_up(&s_ctrl->wait_q);
	CDBG("[M10MO][profiling] %s: FINISH\n", __func__);
	return 0;
}

void m10mo_power_down_work(struct work_struct *work)
{
	struct m10mo_ctrl_t *s_ctrl = &m10mo_s_ctrl;
	m10mo_power_down(s_ctrl);
	mutex_unlock(s_ctrl->power_down_mutex);

}

uint32_t m10mo_gyro_set(struct m10mo_ctrl_t *s_ctrl)
{
	int rc = 0;
	int32_t stream_status;
	int8_t radian_x, radian_y, radian_z, acc_x, acc_y, acc_z;

	if (!test_bit(FEATURE_GYRO_UPDATE, &s_ctrl->feature_mask))
		return -EINVAL;
	stream_status = atomic_read(&s_ctrl->stream_status);
	if (MONITOR != stream_status)
		return rc;

	radian_x = s_ctrl->gyro_info.x;
	radian_y = s_ctrl->gyro_info.y;
	radian_z = s_ctrl->gyro_info.z;

	acc_x = s_ctrl->acc_info.x;
	acc_y = s_ctrl->acc_info.y;
	acc_z = s_ctrl->acc_info.z;

	m10mo_cmd(s_ctrl, CATE_0X0A, GYRO_RADIAN_X, radian_x);
	m10mo_cmd(s_ctrl, CATE_0X0A, GYRO_RADIAN_Y, radian_y);
	m10mo_cmd(s_ctrl, CATE_0X0A, GYRO_RADIAN_Z, radian_z);
	if (0) CDBG("[M10MO][gyro] %s: R_x = %d, r_y = %d, r_z = %d\n",
		__func__, radian_x, radian_y, radian_z);
	m10mo_cmd(s_ctrl, CATE_0X0A, GYRO_SPEED_X, acc_x);
	m10mo_cmd(s_ctrl, CATE_0X0A, GYRO_SPEED_Y, acc_y);
	m10mo_cmd(s_ctrl, CATE_0X0A, GYRO_SPEED_Z, acc_z);
	if (0) CDBG("[M10MO][gyro] %s: A_x = %d, a_y = %d, a_z = %d\n",
		__func__, acc_x, acc_y, acc_z);
	m10mo_cmd(s_ctrl, CATE_0X0A, GYRO_UPDATE, GYRO_UPDATE_Update);

	return rc;
}

static void m10mo_gyro_set_work(struct work_struct * work)
{
	struct m10mo_ctrl_t *s_ctrl = &m10mo_s_ctrl;
	m10mo_gyro_set(s_ctrl);
	msleep(10);
}

static void m10mo_degree_set(struct m10mo_ctrl_t *s_ctrl,
	int32_t degree)
{
	uint8_t m10mo_degree;
	static int32_t count = 0;
	int32_t stream_status;
	stream_status = atomic_read(&s_ctrl->stream_status);

	count++;
	if (!(count % 5))
		return;

	if (count > 10000)
		count = 0;
	if (MONITOR != stream_status)
		return;

	switch(degree) {
	case 0:
		m10mo_degree = DEGREE_0;
		break;

	case 90:
		m10mo_degree = DEGREE_90;
		break;

	case 180:
		m10mo_degree = DEGREE_180;
		break;

	case 270:
		m10mo_degree = DEGREE_270;
		break;

	default:
		return;
	break;
	}

	if (test_bit(FEATURE_GYRO_UPDATE, &s_ctrl->feature_mask)) {
		if (0) CDBG("[M10MO][degree] %s: Degree = %s\n",
			__func__, m10mo_degree_s[m10mo_degree]);
		m10mo_cmd(s_ctrl, CATE_0X03, DEGREE, m10mo_degree);
	}
}

static void m10mo_degree_set_work(struct work_struct * work)
{
	struct m10mo_ctrl_t *s_ctrl = &m10mo_s_ctrl;
	int32_t degree = atomic_read(&s_ctrl->degree);
	m10mo_degree_set(s_ctrl, degree);
	msleep(10);
}

static void m10mo_position_set(struct m10mo_ctrl_t *s_ctrl,
	int32_t position)
{
	int8_t lens_angle = 0;
	int32_t stream_status;
	static int32_t count = 0;
	count++;
	if (!(count % 5))
		return;

	if (count > 10000)
		count = 0;
	stream_status = atomic_read(&s_ctrl->stream_status);

	if (MONITOR != stream_status)
		return;

	if (0) CDBG("[M10MO][lens_angle] %s: Position = %d\n",
		__func__, position);
	lens_angle = (int8_t)position;
	m10mo_cmd(s_ctrl, CATE_0X0A, LENS_ANGLE_INFO, lens_angle);
}

static void m10mo_position_set_work(struct work_struct * work)
{
	struct m10mo_ctrl_t *s_ctrl = &m10mo_s_ctrl;
	int32_t position = atomic_read(&s_ctrl->position);
	m10mo_position_set(s_ctrl, position);
	msleep(10);
}

void m10mo_irq_init(struct m10mo_ctrl_t *s_ctrl)
{
	int32_t i = 0, irq_result;
	struct msm_camera_gpio_conf *gpio_conf =
		s_ctrl->sensor_ctrl.sensordata->gpio_conf;
	uint16_t gpio_int = gpio_conf->gpio_num_info->gpio_num[SENSOR_GPIO_INT];
	CDBG("[M10MO] %s: ENTER, IRQ GPIO = %d\n", __func__, gpio_int);

	s_ctrl->irq_num = gpio_to_irq(gpio_int);
	s_ctrl->irq_q = create_singlethread_workqueue("m10mo_irq_q");
	s_ctrl->power_q = create_singlethread_workqueue("m10mo_power_q");
	s_ctrl->monitor_q = create_singlethread_workqueue("m10mo_monitor_q");

	INIT_WORK(&s_ctrl->irq_work, m10mo_irq_work);
	INIT_WORK(&s_ctrl->monitor_work, m10mo_monitor_work);
	INIT_WORK(&s_ctrl->power_work, m10mo_power_down_work);
	INIT_WORK(&s_ctrl->gyro_set_work, m10mo_gyro_set_work);
	INIT_WORK(&s_ctrl->degree_set_work, m10mo_degree_set_work);
	INIT_WORK(&s_ctrl->position_set_work, m10mo_position_set_work);
	INIT_WORK(&s_ctrl->monitor_stop_work, m10mo_monitor_stop_work);

	for (i = 0; i < CPL_NUM; i++)
		init_completion(&s_ctrl->cpl[i]);

	irq_result = request_irq(s_ctrl->irq_num, m10mo_irq,
		IRQF_TRIGGER_RISING, M10MO_SENSOR_NAME, (void *)s_ctrl);
	if (irq_result < 0) {
		pr_err("[M10MO] %s: Request_irq failed, gpio %d",
			__func__, gpio_int);
	}

	return;
}

void m10mo_irq_deinit(struct m10mo_ctrl_t *s_ctrl)
{
	if (s_ctrl->irq_q) {
		destroy_workqueue(s_ctrl->irq_q);
		s_ctrl->irq_q = 0;
	}

	if (s_ctrl->power_q) {
		destroy_workqueue(s_ctrl->power_q);
		s_ctrl->power_q = 0;
	}

	if (s_ctrl->monitor_q) {
		destroy_workqueue(s_ctrl->monitor_q);
		s_ctrl->monitor_q = 0;
	}

	if (s_ctrl->irq_num) {
		free_irq(s_ctrl->irq_num, (void *)s_ctrl);
		s_ctrl->irq_num = 0;
	}

	return;
}

int32_t m10mo_power_up(struct m10mo_ctrl_t *s_ctrl)
{
	int32_t rc = 0;
	struct timespec b_time;
	struct timespec f_time;
	struct timespec p_time;
	struct msm_sensor_ctrl_t *sensor_ctrl = &s_ctrl->sensor_ctrl;
	wait_event_interruptible(s_ctrl->wait_q,
		POWER_DOWN == atomic_read(&s_ctrl->stream_status));
	getnstimeofday(&b_time);
	if (test_bit(FEATURE_ISP_LOG_VIEW,
		&s_ctrl->feature_mask)) {
		s_ctrl->log_buf_h = ion_alloc(s_ctrl->iclient,
			ISP_LOG_BUF_SIZE, SZ_4K, -1, 0);
		if (!s_ctrl->log_buf_h) {
			pr_err("[M10MO] %s: LOG_BUF alloc failed!!",__func__);
			return -ENOMEM;
		}
	}

	if (test_bit(FEATURE_AF_PROFILING, &s_ctrl->feature_mask)) {
		s_ctrl->caf_counter = 0;
		s_ctrl->caf_total_t.tv_sec = 0;
		s_ctrl->caf_total_t.tv_nsec = 0;

		s_ctrl->taf_counter = 0;
		s_ctrl->taf_total_t.tv_sec = 0;
		s_ctrl->taf_total_t.tv_nsec = 0;
	}

	m10mo_irq_deinit(s_ctrl);

	m10mo_irq_init(s_ctrl);

	if (sensor_ctrl->func_tbl->sensor_power_up)
		rc = sensor_ctrl->func_tbl->sensor_power_up(sensor_ctrl);
	else {
		pr_err("[M10MO] %s: POWER UP failed\n", __func__);
		return -EFAULT;
	}
	atomic_set(&s_ctrl->stream_status, UNBOOTED);
	getnstimeofday(&f_time);
	p_time = diff(b_time, f_time);
	CDBG("[M10MO][power_profiling] %s: POWER UP TIME = %ld ms\n", __func__,
		p_time.tv_sec * MSEC_PER_SEC + p_time.tv_nsec / NSEC_PER_MSEC);
	atomic_set(&s_ctrl->manual_af, 0);
	atomic_set(&s_ctrl->m_af_trigger, 0);
	return rc;
}

static ssize_t functions_show(struct device *pdev,
	struct device_attribute *attr, char *buf)
{
        char *buff = buf;
	uint16_t fw_sum = 0xffff;
	int32_t mod_id, serial_no, serial_no2;
	uint32_t powered_up = 0;
	struct msm_camera_gpio_conf *gpio_conf;
	uint16_t gpio_mod_id, fw_ver, serial_no16;
	uint8_t *mod_name, mod_vendor/*, tmp = FUJI_ERROR_BYTE*/;
	struct msm_sensor_ctrl_t *sensor_ctrl = &m10mo_s_ctrl.sensor_ctrl;
	mutex_lock(sensor_ctrl->msm_sensor_mutex);
	mutex_lock(m10mo_s_ctrl.power_down_mutex);
	if (POWER_DOWN == atomic_read(&m10mo_s_ctrl.stream_status)) {
		m10mo_power_up(&m10mo_s_ctrl);
		fw_sum = m10mo_firmware_check(&m10mo_s_ctrl);

		atomic_set(&m10mo_s_ctrl.stream_status, UNBOOTED);
		powered_up = 1;
	}

	if (UNBOOTED == atomic_read(&m10mo_s_ctrl.stream_status)) {
		m10mo_firmware_boot(&m10mo_s_ctrl);
		atomic_set(&m10mo_s_ctrl.stream_status, STREAM_OFF);
	}

	/*tmp = m10mo_read(&m10mo_s_ctrl, CATE_0X00, PROJECT_CODE);*/
	/*tmp = m10mo_read(&m10mo_s_ctrl, CATE_0X00, CUSTOMER_CODE);*/

	fw_ver = m10mo_read_w(&m10mo_s_ctrl, CATE_0X00, VER_FIRMWARE);
	mod_vendor = m10mo_read(&m10mo_s_ctrl, CATE_0X00, MODULE_VENDOR);
	buff += snprintf(buff, PAGE_SIZE, "%04X", fw_ver);
	*buff++ = ((Foxconn == mod_vendor) ? 'F': 'L');
	if (buff != buf)
		*buff++ = '\n';

	gpio_conf = sensor_ctrl->sensordata->gpio_conf;
	gpio_mod_id = gpio_conf->gpio_num_info->gpio_num[SENSOR_GPIO_MOD_ID];
	mod_id = gpio_get_value_cansleep(gpio_mod_id);
	mod_name = mod_id ? "FOXCONN" : "LITE_ON";
	buff += snprintf(buff, PAGE_SIZE, "%s", mod_name);
	if (buff != buf)
		*buff++ = '\n';

	if (mod_id) {
		serial_no = m10mo_read_l(&m10mo_s_ctrl, CATE_0X01, OTP_0X0A06);
		serial_no16 = m10mo_read_w(&m10mo_s_ctrl, CATE_0X01, OTP_0X0A0A);
		buff += snprintf(buff, PAGE_SIZE, "%08X%04X", serial_no, serial_no16);
	} else {
		serial_no = m10mo_read_l(&m10mo_s_ctrl, CATE_0X00, SEN_DEBUG_INFO1);
		serial_no2 = m10mo_read_l(&m10mo_s_ctrl, CATE_0X00, SEN_DEBUG_INFO5);
		buff += snprintf(buff, PAGE_SIZE, "%08X%08X", serial_no, serial_no2);
	}
	if (buff != buf)
                *buff++ = '\n';

	buff += snprintf(buff, PAGE_SIZE, "%04X", fw_sum);
	if (buff != buf)
                *buff = '\n';

	if (POWER_DOWN != atomic_read(&m10mo_s_ctrl.stream_status) && (1 == powered_up)) {
		m10mo_power_down(&m10mo_s_ctrl);
		atomic_set(&m10mo_s_ctrl.stream_status, POWER_DOWN);
		powered_up = 0;
	}

	mutex_unlock(m10mo_s_ctrl.power_down_mutex);
	mutex_unlock(sensor_ctrl->msm_sensor_mutex);
	return buff - buf + 1;
}

static ssize_t m10mo_af_status_show(struct device *pdev,
	struct device_attribute *attr, char *buf)
{
	uint16_t dac;
        char *buff = buf;
	uint8_t af_result = AF_OFF;

	af_result = m10mo_read(&m10mo_s_ctrl, CATE_0X0A, AF_RESULT);
	buff += snprintf(buff, PAGE_SIZE, "RESULT: %s", m10mo_af_result_s[af_result]);

	if (buff != buf)
                *buff++ = '\n';
	dac =  	m10mo_vcm_dac_get(&m10mo_s_ctrl);

	buff += snprintf(buff, PAGE_SIZE, "DAC: %u",dac);
	if (buff != buf)
                *buff++ = '\n';

	mutex_lock(m10mo_s_ctrl.taf_time_mutex);
	buff += snprintf(buff, PAGE_SIZE, "TIME: %d", (int32_t)m10mo_s_ctrl.taf_time_last);
	if (buff != buf)
                *buff = '\n';

	mutex_unlock(m10mo_s_ctrl.taf_time_mutex);
	return buff - buf + 1;

}

static ssize_t functions_store(struct device *pdev, 
	struct device_attribute *attr, const char *buf, size_t size)
{
	uint8_t tmp = FUJI_ERROR_BYTE;
	uint32_t reg, val, aaa, m10mo_addr = 0;
	char cmd;
	int rc;

	rc = sscanf(buf, "%c %x %x %x", &cmd, &reg, &val, &aaa);
	CDBG("[M10MO] %s:%d %c\n", __func__, __LINE__, cmd);

	switch (cmd) {
	case 'a':
		m10mo_cmd_l(&m10mo_s_ctrl, CATE_0X0F, FLASH_AD, M10MO_TEST_DATA);
		val = m10mo_read_l(&m10mo_s_ctrl, CATE_0X0F, FLASH_AD);
		break;
	case 'b':
		m10mo_firmware_boot(&m10mo_s_ctrl);
		break;
	case 'd':
		m10mo_power_down(&m10mo_s_ctrl);
		break;
	case 'f':
		m10mo_firmware_fctrl(&m10mo_s_ctrl.sensor_ctrl);
		break;
	case 'k':
		m10mo_firmware_check(&m10mo_s_ctrl);
		break;
	case 'p':
		m10mo_power_up(&m10mo_s_ctrl);
		break;
	case 'r':
		rc = m10mo_i2c_read_byte(&m10mo_s_ctrl.sensor_ctrl, 1, reg, val, &tmp);
		CDBG("[M10MO] %s:%d %d, %x, %x, %x\n", __func__, __LINE__, rc, reg, val, tmp);
		break;
	case 's':
		rc = m10mo_firmware_start(&m10mo_s_ctrl, reg);
		CDBG("[M10MO] %s:%d %d\n", __func__, __LINE__, rc);
		break;
	case 't':
		m10mo_firmware_test(&m10mo_s_ctrl.sensor_ctrl);
		break;
	case 'w':
		rc = m10mo_firmware_addr(&m10mo_s_ctrl.sensor_ctrl, &m10mo_addr);
		rc = m10mo_firmware_write(&m10mo_s_ctrl);
		CDBG("[M10MO] %s:%d %d\n", __func__, __LINE__, rc);
		break;
	case 'i':
		m10mo_firmware_write_sio(&m10mo_s_ctrl);
		break;
	case 'x':
		rc = m10mo_i2c_write_byte(&m10mo_s_ctrl.sensor_ctrl, 2, reg, val, aaa, 0);
		break;
	case 'z':
		m10mo_s_ctrl.fw_buf = kzalloc(I2C_SEQ_REG_DATA_HEAD +
				I2C_SEQ_REG_DATA_FUJI, GFP_KERNEL);
		if (!m10mo_s_ctrl.fw_buf) {

			pr_err("[M10MO] %s:%d failed\n", __func__, __LINE__);

			return -ENOMEM;
		}
		break;
	}

	return size;
}

static ssize_t m10mo_af_status_store(struct device *pdev,
	struct device_attribute *attr, const char *buf, size_t size)
{
	return 0;
}

static int32_t m10mo_log_view(struct m10mo_ctrl_t *s_ctrl, uint8_t lmode)
{
	uint16_t lsel16 = 0, llen16 = 0;
	mutex_lock(s_ctrl->sensor_ctrl.msm_sensor_mutex);
	s_ctrl->log_p = (uint8_t *)ion_map_kernel(s_ctrl->iclient, 
		s_ctrl->log_buf_h);

	m10mo_cmd(s_ctrl, CATE_0X0D, LOG_ACT, Disable_Log);
	m10mo_cmd(s_ctrl, CATE_0X0D, ADD_SHOW, Log_string_address);
	m10mo_cmd(s_ctrl, CATE_0X0D, LOG_MODE, lmode);

	while (1) {
		uint32_t  saddr32;
		uint8_t *line_buf, *dbuf;

		m10mo_cmd_w(s_ctrl, CATE_0X0D, LOG_SEL, lsel16);
		m10mo_cmd(s_ctrl, CATE_0X0D, LOG_ACT, Output_Log_string);
		llen16 = m10mo_read_w(s_ctrl, CATE_0X0D, LOG_DATA_LEN);
		if (llen16 <= 0)
			break;
		if (0xffff == llen16)
			continue;

		saddr32 = m10mo_read_l(s_ctrl, CATE_0X0D, LOG_STR_ADD);
		line_buf = kzalloc(llen16 + 3 + 1, GFP_KERNEL);
		if (0 == line_buf) {
			pr_err("[M10MO] %s: Memory alloc failed\n", __func__);
			return -ENOMEM;
		}

		m10mo_mem_read(s_ctrl, saddr32, line_buf, llen16 + 3);
		memcpy(s_ctrl->log_p, line_buf + 3, llen16);
		kfree(line_buf);
		dbuf = s_ctrl->log_p;
		s_ctrl->log_p += llen16;
		*s_ctrl->log_p++ = '\n';
		lsel16++;
	}

	m10mo_cmd(s_ctrl, CATE_0X0D, LOG_ACT, Enable_Log);
	ion_unmap_kernel(s_ctrl->iclient, s_ctrl->log_buf_h);
	mutex_unlock(s_ctrl->sensor_ctrl.msm_sensor_mutex);
	return 0;
}

static int fuji_open(struct inode *inode, struct file *file)
{
	CDBG("[M10MO] %s:%d\n", __func__, __LINE__);
	return 0;
}

static int fuji_release(struct inode *inode, struct file *file)
{
	CDBG("[M10MO] %s: %d\n", __func__, __LINE__);
	return 0;
}

static ssize_t fuji_read(struct file *file, char *buf,
         size_t count, loff_t *ppos)
{
	uint8_t *tmp;
	if (!test_bit(FEATURE_ISP_LOG_VIEW,
		&m10mo_s_ctrl.feature_mask))
		return 0;

	m10mo_log_view(&m10mo_s_ctrl, Analyze_log_mode_data_only);
	m10mo_log_view(&m10mo_s_ctrl, Analyze_log_mode_data_and_string);
	tmp = (uint8_t *)ion_map_kernel(m10mo_s_ctrl.iclient, 
		m10mo_s_ctrl.log_buf_h);
	if (copy_to_user(buf, (void *)tmp, I2C_SEQ_REG_DATA_YUYV))
		;
	ion_unmap_kernel(m10mo_s_ctrl.iclient, m10mo_s_ctrl.log_buf_h);
	CDBG("[M10MO] %s: BUFFER copy completed!!\n",__func__);
	return 0;
}

static ssize_t fuji_write(struct file *file, const char *buf,
           size_t count, loff_t *ppos)
{
	uint8_t *tmp = m10mo_s_ctrl.fw_buf;
	if (!tmp) {
		pr_err("[M10MO] %s: fw_buf = NULL\n",
			__func__);
		return 0;
	}

	CDBG("[M10MO] %s:%d, 0x%x\n", __func__, __LINE__, count);
	if (copy_from_user(tmp, buf, count)) {
	}
	return count;
}

static struct file_operations fuji_fops = {
	.owner    =   THIS_MODULE,      /* Owner */
	.open     =   fuji_open,        /* Open method */
	.release  =   fuji_release,     /* Release method */
	.read     =   fuji_read,        /* Read method */
	.write    =   fuji_write,       /* Write method */
};

static int32_t msm_m10mo_i2c_probe(struct i2c_client *client,
	const struct i2c_device_id *id)
{
	int32_t rc;
	struct device *dev;
	static dev_t dev_number;
	struct class *fuji_class;
	struct fuji_dev *fuji_devp;
	unsigned long *feature = &m10mo_s_ctrl.feature_mask;

	rc = device_create_file(&client->dev, &dev_attr_functions);
	if (rc < 0) {
		return rc;
	}

	rc = device_create_file(&client->dev, &dev_attr_m10mo_af_status);
	if (rc < 0) {
		return rc;
	}

	rc = alloc_chrdev_region(&dev_number, 0, 1, M10MO_SENSOR_NAME);
	if (rc < 0) {
		return rc;
	}

	fuji_devp = kmalloc(sizeof(struct fuji_dev), GFP_KERNEL);
	if (!fuji_devp) {
		return -ENOMEM;
	}

	fuji_class = class_create(THIS_MODULE, M10MO_SENSOR_NAME);

	fuji_devp->client = client;
	cdev_init(&fuji_devp->cdev, &fuji_fops);
	fuji_devp->cdev.owner = THIS_MODULE;

	if (cdev_add(&fuji_devp->cdev, dev_number, 1)) {
		return -EPERM;
	}

	m10mo_s_ctrl.iclient = msm_ion_client_create(-1, M10MO_SENSOR_NAME);

	*feature = 0;

	if (1) set_bit(FEATURE_REAL_EXIF, feature);
	if (1) set_bit(FEATURE_RAW_CAPTURE, feature);
	if (1) set_bit(FEATURE_GYRO_UPDATE, feature);
	if (0) set_bit(FEATURE_AF_PROFILING, feature);
	if (0) set_bit(FEATURE_ISP_LOG_VIEW, feature);
	if (0) set_bit(FEATURE_CMD_DUMP, feature);
	if (0) set_bit(FEATURE_AF_DAC_TEST, feature);
	atomic_set(&m10mo_s_ctrl.stream_status, POWER_DOWN);
	atomic_set(&m10mo_s_ctrl.irq_processed, IRQ_PROCESSED);
	atomic_set(&m10mo_s_ctrl.af_mode_p, CAM_FOCUS_MODE_MAX);

	atomic_set(&m10mo_s_ctrl.monitor_working, MONITOR_WORK_COMPLETED);
	spin_lock_init(&m10mo_s_ctrl.irq_work_lock);

	/*for later use*/
	spin_lock_init(&m10mo_s_ctrl.monitor_work_lock);

	init_waitqueue_head(&m10mo_s_ctrl.wait_q);

	dev = device_create(fuji_class, NULL, MKDEV(MAJOR(dev_number),
			MINOR(dev_number)), NULL, "fuji%d", 0);
	if (IS_ERR(dev)) {
		return -ENODEV;
	}
	return msm_sensor_i2c_probe(client, id, &m10mo_s_ctrl.sensor_ctrl);
}

static int __init m10mo_init_module(void)
{
	pr_info("%s:%d\n", __func__, __LINE__);
	return i2c_add_driver(&m10mo_i2c_driver);
}

static void __exit m10mo_exit_module(void)
{
	if (m10mo_s_ctrl.sensor_ctrl.pdev) {
		msm_sensor_free_sensor_data(&m10mo_s_ctrl.sensor_ctrl);
		platform_driver_unregister(&m10mo_platform_driver);
	} else
		i2c_del_driver(&m10mo_i2c_driver);
	return;
}

static inline int32_t roi_validate(struct roi_info_t *roi)
{
	int32_t rc = 0;
	if (!roi) {
		pr_err("[M10MO] %s: roi null\n", __func__);
		return -EINVAL;
	}

	if ((roi->left >= 0) && (roi->top >= 0) &&
		(roi->right > roi->left) && (roi->bottom > roi->top))
		return rc;

	return -EINVAL;
}

static inline int32_t top_right(struct roi_info_t *roi)
{
	uint32_t right_boundary = ZSL_MONITOR_WIDTH;
	uint32_t top_boundary = ZSL_MONITOR_HEIGHT;
	uint32_t roi_center_w = roi->right + roi->left;
	uint32_t roi_center_h = roi->top + roi->bottom;
	do_div(roi_center_w, 2);
	do_div(roi_center_h, 2);
	do_div(right_boundary, 3);
	do_div(top_boundary, 3);
	right_boundary *= 2;
	if (roi_center_w <= ZSL_MONITOR_WIDTH && roi_center_w >= right_boundary) {
		if (roi_center_h <= top_boundary && roi_center_h >= 0)
			return 1;
	}
	return 0;
}

static inline int32_t top_center(struct roi_info_t *roi)
{
	uint32_t right_boundary = ZSL_MONITOR_WIDTH;
	uint32_t left_boundary = ZSL_MONITOR_WIDTH;
	uint32_t top_boundary = ZSL_MONITOR_HEIGHT;
	uint32_t roi_center_w = roi->right + roi->left;
	uint32_t roi_center_h = roi->top + roi->bottom;
	do_div(roi_center_w, 2);
	do_div(roi_center_h, 2);
	do_div(right_boundary, 3);
	do_div(left_boundary, 3);
	do_div(top_boundary, 3);
	right_boundary *= 2;
	if (roi_center_w <= right_boundary && roi_center_w >= left_boundary) {
		if (roi_center_h <= top_boundary && roi_center_h >= 0)
			return 1;
	}
	return 0;
}

static inline int32_t top_left(struct roi_info_t *roi)
{
	uint32_t left_boundary = ZSL_MONITOR_WIDTH;
	uint32_t top_boundary = ZSL_MONITOR_HEIGHT;
	uint32_t roi_center_w = roi->right + roi->left;
	uint32_t roi_center_h = roi->top + roi->bottom;
	do_div(roi_center_w, 2);
	do_div(roi_center_h, 2);
	do_div(left_boundary, 3);
	do_div(top_boundary, 3);
	if (roi_center_w <= left_boundary && roi_center_w > 0) {
		if (roi_center_h <= top_boundary && roi_center_h > 0)
			return 1;
	}
	return 0;
}

static inline int32_t center_left(struct roi_info_t *roi)
{
	uint32_t left_boundary = ZSL_MONITOR_WIDTH;
	uint32_t top_boundary = ZSL_MONITOR_HEIGHT;
	uint32_t down_boundary = ZSL_MONITOR_HEIGHT;
	uint32_t roi_center_w = roi->right + roi->left;
	uint32_t roi_center_h = roi->top + roi->bottom;
	do_div(roi_center_w, 2);
	do_div(roi_center_h, 2);
	do_div(left_boundary, 3);
	do_div(top_boundary, 3);
	do_div(down_boundary, 3);
	down_boundary *= 2;
	if (roi_center_w <= left_boundary && roi_center_w >= 0) {
		if (roi_center_h <= down_boundary && roi_center_h >= top_boundary)
			return 1;
	}
	return 0;
}

static inline int32_t center_center(struct roi_info_t *roi)
{
	uint32_t left_boundary = ZSL_MONITOR_WIDTH;
	uint32_t right_boundary = ZSL_MONITOR_WIDTH;
	uint32_t top_boundary = ZSL_MONITOR_HEIGHT;
	uint32_t down_boundary = ZSL_MONITOR_HEIGHT;
	uint32_t roi_center_w = roi->right + roi->left;
	uint32_t roi_center_h = roi->top + roi->bottom;
	do_div(roi_center_w, 2);
	do_div(roi_center_h, 2);
	do_div(left_boundary, 3);
	do_div(right_boundary, 3);
	do_div(top_boundary, 3);
	do_div(down_boundary, 3);
	down_boundary *= 2;
	right_boundary *= 2;
	if (roi_center_w >= left_boundary && roi_center_w <= right_boundary) {
		if (roi_center_h <= down_boundary && roi_center_h >= top_boundary)
			return 1;
	}
	return 0;
}

static inline int32_t center_right(struct roi_info_t *roi)
{
	uint32_t left_boundary = ZSL_MONITOR_WIDTH;
	uint32_t right_boundary = ZSL_MONITOR_WIDTH;
	uint32_t top_boundary = ZSL_MONITOR_HEIGHT;
	uint32_t down_boundary = ZSL_MONITOR_HEIGHT;
	uint32_t roi_center_w = roi->right + roi->left;
	uint32_t roi_center_h = roi->top + roi->bottom;
	do_div(roi_center_w, 2);
	do_div(roi_center_h, 2);
	do_div(left_boundary, 3);
	do_div(right_boundary, 3);
	do_div(top_boundary, 3);
	do_div(down_boundary, 3);
	down_boundary *= 2;
	right_boundary *= 2;
	if (roi_center_w >= right_boundary && roi_center_w <= ZSL_MONITOR_WIDTH) {
		if (roi_center_h <= down_boundary && roi_center_h >= top_boundary)
			return 1;
	}
	return 0;
}

static inline int32_t bottom_right(struct roi_info_t *roi)
{
	uint32_t left_boundary = ZSL_MONITOR_WIDTH;
	uint32_t right_boundary = ZSL_MONITOR_WIDTH;
	uint32_t top_boundary = ZSL_MONITOR_HEIGHT;
	uint32_t down_boundary = ZSL_MONITOR_HEIGHT;
	uint32_t roi_center_w = roi->right + roi->left;
	uint32_t roi_center_h = roi->top + roi->bottom;
	do_div(roi_center_w, 2);
	do_div(roi_center_h, 2);
	do_div(left_boundary, 3);
	do_div(right_boundary, 3);
	do_div(top_boundary, 3);
	do_div(down_boundary, 3);
	down_boundary *= 2;
	right_boundary *= 2;
	if (roi_center_w >= right_boundary && roi_center_w <= ZSL_MONITOR_WIDTH) {
		if (roi_center_h >= down_boundary && roi_center_h <= ZSL_MONITOR_HEIGHT)
			return 1;
	}
	return 0;

}


static inline int32_t bottom_center(struct roi_info_t *roi)
{
	uint32_t left_boundary = ZSL_MONITOR_WIDTH;
	uint32_t right_boundary = ZSL_MONITOR_WIDTH;
	uint32_t top_boundary = ZSL_MONITOR_HEIGHT;
	uint32_t down_boundary = ZSL_MONITOR_HEIGHT;
	uint32_t roi_center_w = roi->right + roi->left;
	uint32_t roi_center_h = roi->top + roi->bottom;
	do_div(roi_center_w, 2);
	do_div(roi_center_h, 2);
	do_div(left_boundary, 3);
	do_div(right_boundary, 3);
	do_div(top_boundary, 3);
	do_div(down_boundary, 3);
	down_boundary *= 2;
	right_boundary *= 2;
	if (roi_center_w >= left_boundary && roi_center_w <= right_boundary) {
		if (roi_center_h >= down_boundary && roi_center_h <= ZSL_MONITOR_HEIGHT)
			return 1;
	}
	return 0;

}

static inline int32_t bottom_left(struct roi_info_t *roi)
{
	uint32_t left_boundary = ZSL_MONITOR_WIDTH;
	uint32_t right_boundary = ZSL_MONITOR_WIDTH;
	uint32_t top_boundary = ZSL_MONITOR_HEIGHT;
	uint32_t down_boundary = ZSL_MONITOR_HEIGHT;
	uint32_t roi_center_w = roi->right + roi->left;
	uint32_t roi_center_h = roi->top + roi->bottom;
	do_div(roi_center_w, 2);
	do_div(roi_center_h, 2);
	do_div(left_boundary, 3);
	do_div(right_boundary, 3);
	do_div(top_boundary, 3);
	do_div(down_boundary, 3);
	down_boundary *= 2;
	right_boundary *= 2;
	if (roi_center_w <= left_boundary && roi_center_w >= 0) {
		if (roi_center_h >= down_boundary && roi_center_h <= ZSL_MONITOR_HEIGHT)
			return 1;
	}
	return 0;

}

static int32_t m10mo_roi_update(struct m10mo_ctrl_t *s_ctrl,
	struct roi_info_t *roi) 
{
	int rc = 0;
	if (!roi) {
		pr_err("[M10MO] %s: Invalid roi\n", __func__);
		return -EINVAL;
	}
	CDBG("[M10MO] %s: BEGIN, t = %d, l = %d, r = %d, b = %d\n",
		__func__, roi->top, roi->left, roi->right, roi->bottom);
	m10mo_cmd_w(s_ctrl, CATE_0X02, ROI_TOP, roi->top);
	m10mo_cmd_w(s_ctrl, CATE_0X02, ROI_LEFT, roi->left);
	m10mo_cmd_w(s_ctrl, CATE_0X02, ROI_RIGHT, roi->right);
	m10mo_cmd_w(s_ctrl, CATE_0X02, ROI_BOTTOM, roi->bottom);

	m10mo_cmd(s_ctrl, CATE_0X02, ROI_UPDATE_TRIG, Update);

	return rc;
}

static int32_t m10mo_face_roi_update(struct m10mo_ctrl_t *s_ctrl,
	struct roi_info_t *roi)
{
	int rc = 0;
	if (!roi) {
		pr_err("[M10MO] %s: Invalid roi\n", __func__);
		return -EINVAL;
	}
	CDBG("[M10MO] %s: BEGIN, t = %d, l = %d, r = %d, b = %d\n",
		__func__, roi->top, roi->left, roi->right, roi->bottom);

	m10mo_cmd_w(s_ctrl, CATE_0X02, ROI_TOP, roi->top);
	m10mo_cmd_w(s_ctrl, CATE_0X02, ROI_LEFT, roi->left);
	m10mo_cmd_w(s_ctrl, CATE_0X02, ROI_RIGHT, roi->right);
	m10mo_cmd_w(s_ctrl, CATE_0X02, ROI_BOTTOM, roi->bottom);

	m10mo_cmd(s_ctrl, CATE_0X02, ROI_UPDATE_TRIG, Face_Update);

	return rc;
}

static uint32_t m10mo_af_roi_set(struct m10mo_ctrl_t *s_ctrl)
{
	int rc = 0;
	int32_t af_mode, af_status, stream_status;
	af_mode = atomic_read(&s_ctrl->af_mode);
	af_status = atomic_read(&s_ctrl->af_status);
	stream_status = atomic_read(&s_ctrl->stream_status);
	CDBG("[M10MO] %s: BEGIN--Stream_status = %s, Af_mode = %s, af_status = %s\n",
		__func__, stream_status_s[stream_status],
		af_mode_s[af_mode], af_status_s[af_status]);

	s_ctrl->af_area_mode = ROI;
	if (roi_validate(&s_ctrl->af_roi)) {
		s_ctrl->af_area_mode = CENTER;
		m10mo_cmd(s_ctrl, CATE_0X0A, AF_AREA_MODE,
			s_ctrl->af_area_mode);
		return rc;
	}

	m10mo_roi_update(s_ctrl, &s_ctrl->af_roi);
	m10mo_cmd(s_ctrl, CATE_0X0A, AF_AREA_MODE,
		s_ctrl->af_area_mode);

	return rc;
}

static uint32_t m10mo_af_start(struct m10mo_ctrl_t *s_ctrl)
{
	int wait_ret;
	int32_t af_mode, af_status, stream_status;
	af_mode = atomic_read(&s_ctrl->af_mode);
	af_status = atomic_read(&s_ctrl->af_status);
	stream_status = atomic_read(&s_ctrl->stream_status);
	CDBG("[M10MO] %s: BEGIN--Stream_status = %s, \
		Af_mode = %s, af_status = %s\n",
		__func__, stream_status_s[stream_status], 
		af_mode_s[af_mode], af_status_s[af_status]);

	/* first time af operation,
	 * wait for lens init */
	if (af_status == LENS_DEINITED) {
		wait_ret = wait_event_timeout(s_ctrl->wait_q,
			LENS_INITED == atomic_read(&s_ctrl->af_status),
			msecs_to_jiffies(2000));
		if (wait_ret <= 0) {
			pr_err("%s: wait for lens init timeout", __func__);
			return -EIO;
		}
	}
	af_status = atomic_read(&s_ctrl->af_status);

	if (LENS_INITED != af_status) {
		CDBG("[M10MO] %s: Operation not allowed, \
			af_status = %s, af_mode = %s\n",
			__func__, af_status_s[af_status], 
			af_mode_s[af_mode]);
		return -EINVAL;
	}

	m10mo_af_roi_set(s_ctrl);
	m10mo_cmd(s_ctrl, CATE_0X0A, AF_START, AF_start);
	atomic_set(&s_ctrl->af_status, AF_ONGOING);
	if (test_bit(FEATURE_AF_PROFILING, &s_ctrl->feature_mask)) {
		s_ctrl->taf_counter++;
		getnstimeofday(&s_ctrl->taf_trigger_t);
	}
	return 0;
}

static uint32_t m10mo_caf_lock(struct m10mo_ctrl_t *s_ctrl, int32_t lock)
{
	int rc = 0;
	long result;
	int32_t af_mode, af_status, stream_status;
	af_mode = atomic_read(&s_ctrl->af_mode);
	af_status = atomic_read(&s_ctrl->af_status);
	stream_status = atomic_read(&s_ctrl->stream_status);
	CDBG("[M10MO] %s: BEGIN--Stream_status = %s, \
		Af_mode = %s, af_status = %s, lock = %d\n",
		__func__, stream_status_s[stream_status],
		af_mode_s[af_mode], af_status_s[af_status], lock);

	if (Continuous_AF_applied != af_mode) {
		CDBG("[M10MO] %s: Operation not allowed, lock = %d, \
			af_mode = %s, af_status = %s\n",
			__func__, lock, af_mode_s[af_mode], 
			af_status_s[af_status]);
		return -EINVAL;
	}

	if (lock && (CAF_PAUSING != af_status)) {
		atomic_set(&s_ctrl->af_status, CAF_PAUSING);
		m10mo_cmd(s_ctrl, CATE_0X0A, AF_START, AF_pause);
		result = wait_for_completion_interruptible_timeout(
			&s_ctrl->cpl[CPL_CAF_PAUSE], 
			msecs_to_jiffies(LENS_TIMEOUT));
		if (result <= 0) {
			pr_err("[M10MO] %s: Timeout, failed, stream_status = %s\n",
				__func__, stream_status_s[stream_status]);
			return -EIO;
		}
		atomic_set(&s_ctrl->af_status, LENS_INITED);
		return rc;
	}

	if (!lock && (LENS_INITED == af_status)) {
		/* no need wait for AF_resume interrrupt, Jon */
		m10mo_cmd(s_ctrl, CATE_0X0A, AF_START, AF_resume);
		return rc;
	}

	CDBG("[M10MO] %s: Operation not allowed, lock = %d, \
		af_mode = %s, af_status = %s\n",
		__func__, lock, af_mode_s[af_mode], af_status_s[af_status]);
	return -EINVAL;
}

static int32_t m10mo_zsl_monitor(struct m10mo_ctrl_t *s_ctrl)
{
	int32_t rc = 0;
	long result = 0;
	int af_mode, af_status, stream_status, flash_mode;
	uint8_t led_assist_af_en = LED_ASSIST_EN_OFF;
	af_mode = atomic_read(&s_ctrl->af_mode);
	af_status = atomic_read(&s_ctrl->af_status);
	flash_mode = atomic_read(&s_ctrl->flash_mode);
	stream_status = atomic_read(&s_ctrl->stream_status);

	CDBG("[M10MO] %s: BEGIN--Stream_status = %s, \
		Af_mode = %s, af_status = %s\n",
		__func__, stream_status_s[stream_status],
		af_mode_s[af_mode], af_status_s[af_status]);

	if (MONITOR_VIRTUAL_OFF == stream_status) {
		atomic_set(&s_ctrl->stream_status, MONITOR);
		return -EINVAL;
	}

	if (STREAM_OFF != stream_status) {
		/* This is a Good EINVAL, sometimes */
		CDBG("[M10MO] %s: Operation not allowed, \
			stream_status = %s\n", __func__, 
			stream_status_s[stream_status]);
		return -EINVAL;
	}

	m10mo_cmd(s_ctrl, CATE_0X01, MON_SIZE, _1440x1080);
	m10mo_cmd(s_ctrl, CATE_0X0C, CAP_MODE, Zsl_Capture_type2);
	m10mo_cmd(s_ctrl, CATE_0X00, M10MO_SYS_MODE, Monitor_mode);

	result = wait_for_completion_interruptible_timeout(
		&s_ctrl->cpl[CPL_MON_START], 
		msecs_to_jiffies(MONITOR_TIMEOUT));

	if (result == 0) {
		pr_err("[M10MO] %s: Timeout, failed, stream_status = %s\n",
			__func__, stream_status_s[stream_status]);
		return -EIO;
	}
	if (result < 0) {
		pr_err("[M10MO] %s: interrupted, failed, stream_status = %s\n",
			__func__, stream_status_s[stream_status]);
		return -EIO;
	}
	atomic_set(&s_ctrl->stream_status, MONITOR);
	atomic_set(&s_ctrl->cur_res, MSM_SENSOR_RES_2);

	m10mo_cmd(s_ctrl, CATE_0X03, STROBE_EN, (uint8_t)flash_mode);

	if (STROBE_EN_Forced_ON == flash_mode) {
		led_assist_af_en = LED_ASSIST_EN_Auto;
		m10mo_cmd(s_ctrl, CATE_0X0A, LED_ASSIST_EN,
			led_assist_af_en);		
	}

	queue_work(s_ctrl->monitor_q, &s_ctrl->monitor_work);

	return rc;
}

static uint32_t m10mo_hdr_set(struct m10mo_ctrl_t *s_ctrl, int32_t enable)
{
	int rc = 0;
	int hdr_enable = atomic_read(&s_ctrl->hdr_enable);
	int stream_status = atomic_read(&s_ctrl->stream_status);
	CDBG("[M10MO] %s: ENABLE = %d, stream_status = %s\n",
		__func__, enable, stream_status_s[stream_status]);

	if (hdr_enable == enable)
		return -EINVAL;

	wait_event_interruptible(s_ctrl->wait_q,
		MONITOR_STOP_WORK_COMPLETED ==
		atomic_read(&s_ctrl->monitor_stop_working));

	if (STREAM_OFF == stream_status) {
		m10mo_cmd(s_ctrl, CATE_0X01, SENSOR_HDR_MODE, enable);
		atomic_set(&s_ctrl->hdr_enable, enable);
		return rc;
	}

	if ((MONITOR != stream_status) &&
		(MONITOR_VIRTUAL_OFF != stream_status))
		return -EINVAL;

	m10mo_cmd(s_ctrl, CATE_0X01, SENSOR_HDR_MODE, enable);
	atomic_set(&s_ctrl->hdr_enable, enable);
	return rc;
}

static int32_t m10mo_pano_monitor(struct m10mo_ctrl_t *s_ctrl)
{
	long result = 0;
	int32_t rc = 0;
	int stream_status;
	stream_status = atomic_read(&s_ctrl->stream_status);
	CDBG("[M10MO] %s: Enter, Stream status = %s\n",
		__func__, stream_status_s[stream_status]);

	if (STREAM_OFF != stream_status) {
		CDBG("[M10MO] %s: Operation not allowed, \
			stream_status = %s\n",
			__func__, stream_status_s[stream_status]);
		return -EINVAL;
	}

	m10mo_hdr_set(s_ctrl, OFF);
	m10mo_cmd(s_ctrl, CATE_0X01, MON_SIZE, _2560x1920);
	m10mo_cmd(s_ctrl, CATE_0X0C, CAP_MODE, Panorama);
	m10mo_cmd(s_ctrl, CATE_0X00, M10MO_SYS_MODE, Monitor_mode);

	result =  wait_for_completion_interruptible_timeout(
	 &s_ctrl->cpl[CPL_MON_START], msecs_to_jiffies(MONITOR_TIMEOUT));

	if (result <= 0) {
		pr_err("[M10MO] %s: Timeout, stream_status=%d\n",
			__func__, stream_status);
		return -EIO;
	}

	atomic_set(&s_ctrl->stream_status, MONITOR);
	atomic_set(&s_ctrl->cur_res, MSM_SENSOR_RES_3);
	m10mo_cmd(s_ctrl, CATE_0X0A, LED_ASSIST_EN, LED_ASSIST_EN_OFF);

	queue_work(s_ctrl->monitor_q, &s_ctrl->monitor_work);

	return rc;
}

static int32_t m10mo_movie_monitor(struct m10mo_ctrl_t *s_ctrl)
{
	int32_t rc = 0;
	long result = 0;
	int stream_status, flash_mode;
	stream_status = atomic_read(&s_ctrl->stream_status);
	flash_mode = atomic_read(&s_ctrl->flash_mode);
	CDBG("[M10MO] %s: ENTER, Stream status = %s\n",
		__func__, stream_status_s[stream_status]);

	if (STREAM_OFF != stream_status) {
		CDBG("[M10MO] %s: Operation not allowed, \
			stream_status = %s\n",
			__func__, stream_status_s[stream_status]);
		return -EINVAL;
	}

	m10mo_cmd(s_ctrl, CATE_0X01, MON_SIZE, _1920x1080);
	m10mo_cmd(s_ctrl, CATE_0X0C, CAP_MODE, Movie);
	m10mo_cmd(s_ctrl, CATE_0X00, M10MO_SYS_MODE, Monitor_mode);

	result =  wait_for_completion_interruptible_timeout(
	 &s_ctrl->cpl[CPL_MON_START], msecs_to_jiffies(MONITOR_TIMEOUT));

	if (result <= 0) {
		pr_err("[M10MO] %s: Timeout, stream_status = %s\n",
			__func__, stream_status_s[stream_status]);
		return -EIO;
	}

	atomic_set(&s_ctrl->stream_status, MONITOR);
	atomic_set(&s_ctrl->cur_res, MSM_SENSOR_RES_QTR);
	m10mo_cmd(s_ctrl, CATE_0X03, STROBE_EN, (uint8_t)flash_mode);
	m10mo_cmd(s_ctrl, CATE_0X0A, CAF_MOVIE_EN, s_ctrl->movie_caf);
	m10mo_cmd(s_ctrl, CATE_0X0A, LED_ASSIST_EN, LED_ASSIST_EN_OFF);
	queue_work(s_ctrl->monitor_q, &s_ctrl->monitor_work);

	return rc;
}

static int32_t m10mo_reset(struct m10mo_ctrl_t *s_ctrl)
{
	atomic_set(&s_ctrl->stream_status, STREAM_OFF);
	m10mo_power_down(s_ctrl);
	m10mo_power_up(s_ctrl);
	m10mo_init(s_ctrl);
	return 0;
}

static int32_t m10mo_monitor(struct m10mo_ctrl_t *s_ctrl)
{
	int32_t wait_ret;
	struct timespec b_time, p_time;
	int32_t new_res = atomic_read(&s_ctrl->new_res);
	int32_t stream_status = atomic_read(&s_ctrl->stream_status);
	atomic_set(&s_ctrl->capture_pending , CAPTURE_COMPLETED);
	getnstimeofday(&b_time);

	wait_event_interruptible(s_ctrl->wait_q,
		MONITOR_STOP_WORK_COMPLETED ==
		atomic_read(&s_ctrl->monitor_stop_working));

	CDBG("[M10MO] %s: Waiting for CAPTURE STOP\n", __func__);
	stream_status = atomic_read(&s_ctrl->stream_status);
	if (ZSL_CAPTURE_STOPPING == stream_status) {
		wait_ret = wait_event_timeout(s_ctrl->wait_q,
			MONITOR == atomic_read(&s_ctrl->stream_status),
			msecs_to_jiffies(CAPTURE_STOP_TIMEOUT));
		if (wait_ret <= 0) {
			pr_err("[M10MO] %s: wait for capture stop timeout\n", __func__);
			m10mo_reset(s_ctrl);
		} else {
			CDBG("[M10MO] %s: wait_rec = %d\n", __func__, jiffies_to_msecs(wait_ret));
			if (wait_ret < msecs_to_jiffies(CAPTURE_STOP_TIMEOUT))
				msleep(100);
		}
	}
	CDBG("[M10MO] %s: CAPTURE STOPPED\n", __func__);

	stream_status = atomic_read(&s_ctrl->stream_status);
	if (MONITOR == stream_status) {
		if (atomic_read(&s_ctrl->cur_res) ==
			new_res) {
			CDBG("[M10MO] %s: Operation not allowed, \
				stream_status = %s\n",
				__func__, stream_status_s[stream_status]);
			getnstimeofday(&s_ctrl->monitor_f_t);
			return -EINVAL;
		} else
			m10mo_monitor_stop(s_ctrl);
	}

	getnstimeofday(&s_ctrl->monitor_f_t);
	p_time = diff(b_time, s_ctrl->monitor_f_t);
	CDBG("[M10MO][profiling] %s: POWER UP TIME = %ld ms\n", __func__,
		p_time.tv_sec * MSEC_PER_SEC + p_time.tv_nsec / NSEC_PER_MSEC);

	if (MSM_SENSOR_RES_QTR == new_res)
		m10mo_movie_monitor(s_ctrl);
	else if (MSM_SENSOR_RES_2 == new_res)
		m10mo_zsl_monitor(s_ctrl);
	else if (MSM_SENSOR_RES_3 == new_res)
		m10mo_pano_monitor(s_ctrl);
	else
		m10mo_zsl_monitor(s_ctrl);
	return 0;
}

static int32_t m10mo_zsl_capture(struct m10mo_ctrl_t *s_ctrl)
{

	int32_t rc = 0;
	long  result = 0;
	int32_t interval = 0;
	struct timespec d_time;
	int stream_status = atomic_read(&s_ctrl->stream_status);
	CDBG("[M10MO] %s: ENTER, Stream status = %s\n",
		__func__, stream_status_s[stream_status]);

	getnstimeofday(&s_ctrl->capture_s_t);
	d_time = diff(s_ctrl->monitor_f_t, s_ctrl->capture_s_t);
	interval = d_time.tv_sec * MSEC_PER_SEC + d_time.tv_nsec / NSEC_PER_MSEC;
	CDBG("[M10MO] %s: interval = %d\n", __func__, interval);
	if (interval < MONITOR_MINIMUM_TIME && interval > 0)
		msleep(MONITOR_MINIMUM_TIME - interval);
	else if (interval <= 0) {
		pr_err("[M10MO] %s: interval = %d\n", __func__, interval);
		msleep(MONITOR_MINIMUM_TIME);
	}

	if (MONITOR_STOP_WORK_ONGOING ==
		atomic_read(&s_ctrl->monitor_stop_working)) {
		wait_event_interruptible(s_ctrl->wait_q,
			MONITOR_STOP_WORK_COMPLETED ==
			atomic_read(&s_ctrl->monitor_stop_working));
	}

	if (STREAM_OFF == atomic_read(&s_ctrl->stream_status))
		m10mo_zsl_monitor(s_ctrl);
	else if (MONITOR_VIRTUAL_OFF != stream_status) {
		CDBG("[M10MO] %s: Operation not allowed, stream_status = %s\n",
			__func__, stream_status_s[stream_status]);
		return -EINVAL;
	}

	atomic_set(&s_ctrl->stream_status, ZSL_CAPTURE_STARTING);
	m10mo_cmd(s_ctrl, CATE_0X0C, START_CAP, Start_burst_shot);
	result = wait_for_completion_interruptible_timeout(
		&s_ctrl->cpl[CPL_CAP_START],
		msecs_to_jiffies(CAPTURE_TIMEOUT));

	if (result <= 0) {
		pr_err("[M10MO] %s: Timeout, stream_status = %s\n",
			__func__, stream_status_s[stream_status]);
		return -EIO;
	}

	atomic_set(&s_ctrl->stream_status, ZSL_CAPTURE);
	atomic_set(&s_ctrl->cur_res, MSM_SENSOR_RES_FULL);

	return rc;
}


static int32_t m10mo_zsl_1shot(struct m10mo_ctrl_t *s_ctrl)
{
	int wait_ret;
	long result = 0;
	struct timespec d_time;
	int32_t rc = 0, interval = 0;
	int af_status = atomic_read(&s_ctrl->af_status);
	int stream_status = atomic_read(&s_ctrl->stream_status);

	getnstimeofday(&s_ctrl->capture_s_t);
	d_time = diff(s_ctrl->monitor_f_t, s_ctrl->capture_s_t);
	interval = d_time.tv_sec * MSEC_PER_SEC + d_time.tv_nsec / NSEC_PER_MSEC;
	CDBG("[M10MO] %s: interval = %d\n", __func__, interval);
	if (interval < MONITOR_MINIMUM_TIME && interval > 0)
		msleep(MONITOR_MINIMUM_TIME - interval);
	else if (interval <= 0) {
		pr_err("[M10MO] %s: interval = %d\n", __func__, interval);
		msleep(MONITOR_MINIMUM_TIME);
	}

	if (LENS_DEINITED == af_status) {
		wait_ret = wait_event_timeout(s_ctrl->wait_q,
			LENS_INITED == atomic_read(&s_ctrl->af_status),
			msecs_to_jiffies(2000));
		if (wait_ret <= 0) {
			pr_err("%s: wait for lens init timeout", __func__);
			return -EIO;
		}
	}
	CDBG("[M10MO] %s: ENTER, Stream status = %s\n",
		__func__, stream_status_s[stream_status]);
	if (MONITOR_STOP_WORK_ONGOING ==
		atomic_read(&s_ctrl->monitor_stop_working)) {
		wait_event_interruptible(s_ctrl->wait_q,
			MONITOR_STOP_WORK_COMPLETED ==
			atomic_read(&s_ctrl->monitor_stop_working));
	}

	if (STREAM_OFF == atomic_read(&s_ctrl->stream_status))
		m10mo_zsl_monitor(s_ctrl);
	else if (MONITOR_VIRTUAL_OFF != stream_status) {
		CDBG("[M10MO] %s: Operation not allowed, stream_status = %s\n",
			__func__, stream_status_s[stream_status]);
		return -EINVAL;
	}

	atomic_set(&s_ctrl->stream_status, ZSL_CAPTURE_STARTING);
	m10mo_cmd(s_ctrl, CATE_0X0C, START_CAP,
		Start_burst_shot_debug_Output_1_frame);

	/* 1 shot may flash enabled,
	 * pre flash need long time wait */
	result = wait_for_completion_interruptible_timeout(
		&s_ctrl->cpl[CPL_CAP_START], 
		msecs_to_jiffies(_1SHOT_TIMEOUT));

	if (result <= 0) {
		pr_err("[M10MO] %s: Timeout, stream_status = %s\n",
			__func__, stream_status_s[stream_status]);
		return -EIO;
	}

	atomic_set(&s_ctrl->stream_status, ZSL_CAPTURE);
	atomic_set(&s_ctrl->cur_res, MSM_SENSOR_RES_FULL);

	return rc;
}


static int32_t m10mo_zsl_raw(struct m10mo_ctrl_t *s_ctrl)
{
	int32_t rc = 0;
	long  result = 0;
	int stream_status = atomic_read(&s_ctrl->stream_status);

	if (MONITOR_VIRTUAL_OFF != stream_status) {
		CDBG("[M10MO] %s: Operation not allowd, \
			stream_status = %s\n", __func__, 
			stream_status_s[stream_status]);
		return -EINVAL;
	}

	atomic_set(&s_ctrl->stream_status, ZSL_CAPTURE_STARTING);
	m10mo_cmd(s_ctrl, CATE_0X0C, START_CAP, Start_Raw_Main_Debug);
	result = wait_for_completion_interruptible_timeout(
		&s_ctrl->cpl[CPL_CAP_START], 
		msecs_to_jiffies(CAPTURE_TIMEOUT));

	if (result <= 0) {
		pr_err("[M10MO] %s: Timeout, stream_status = %s\n",
			__func__, stream_status_s[stream_status]);
		return -EIO;
	}

	atomic_set(&s_ctrl->stream_status, ZSL_CAPTURE);
	atomic_set(&s_ctrl->cur_res, MSM_SENSOR_RES_FULL);

	return rc;
}

static int32_t m10mo_capture_stop(struct m10mo_ctrl_t *s_ctrl)
{
	int32_t rc = 0, interval = 0;
	struct timespec f_time, d_time;
	int stream_status = atomic_read(&s_ctrl->stream_status);
	CDBG("[M10MO] %s: Enter, Stream status = %s\n",
		__func__, stream_status_s[stream_status]);
	getnstimeofday(&f_time);
	d_time = diff(s_ctrl->capture_s_t, f_time);
	interval = d_time.tv_sec * MSEC_PER_SEC + d_time.tv_nsec / NSEC_PER_MSEC;
	CDBG("[M10MO] %s: interval = %d\n", __func__, interval);
	if (interval < 100 && interval > 0)
		msleep(100 - interval);
	else if (interval <= 0) {
		pr_err("[M10MO] %s: interval = %d\n", __func__, interval);
		msleep(100);
	}

	if (ZSL_CAPTURE != stream_status) {
		CDBG("[M10MO] %s: Operation not allowed, \
			stream_status = %s\n", __func__, 
			stream_status_s[stream_status]);
		return -EINVAL;
	}

	atomic_set(&s_ctrl->stream_status, ZSL_CAPTURE_STOPPING);
	m10mo_cmd(s_ctrl, CATE_0X0C, START_CAP, Stop_burst_shot);
	/*
	result = wait_for_completion_interruptible_timeout(
	 &s_ctrl->cpl[CPL_CAP_STOP], msecs_to_jiffies(CAPTURE_TIMEOUT));

	if (result <= 0) {
		pr_err("[M10MO] %s: Timeout, stream_status = %s\n",
			__func__, stream_status_s[stream_status]);
		return -EIO;
	}
	atomic_set(&s_ctrl->stream_status, MONITOR);
	*/
	CDBG("[M10MO] %s: Exit, Stream status = %s\n",
		__func__, stream_status_s[stream_status]);


	return rc;
}

static int32_t m10mo_ae_mode_set(struct m10mo_ctrl_t *s_ctrl, 
	int32_t ae_mode)
{
	uint8_t ae_value = All_block_integral;

	if (test_bit(FEATURE_OB_CHECK, &s_ctrl->feature_mask))
		return 0;

	switch(ae_mode) {
	case CAMERA_AEC_FRAME_AVERAGE:
		ae_value = All_block_integral;
		break;

	case CAMERA_AEC_CENTER_WEIGHTED:
		ae_value = Center_weighted_average1;
		break;

	case CAMERA_AEC_SPOT_METERING:
		ae_value = ROI_Mode;
		break;

	default:
		break;
	}

	s_ctrl->ae_mode = ae_value;
	CDBG("[M10MO] %s: m10mo_ae_mode = %s\n",
		__func__, ae_mode_s[ae_value]);
	m10mo_cmd(s_ctrl, CATE_0X03, AE_MODE, ae_value);
	m10mo_cmd(s_ctrl, CATE_0X03, AE_PARAM_UPDATE,
		AE_PARAM_UPDATE_Update);

	return 0;
}

static int32_t m10mo_ae_set(struct m10mo_ctrl_t *s_ctrl)
{
	int rc = 0;
	CDBG("[M10MO] %s: BEGIN, AE MODE = %s\n",
		__func__, ae_mode_s[s_ctrl->ae_mode]);
	if (test_bit(FEATURE_OB_CHECK, &s_ctrl->feature_mask)) {
		CDBG("[M10MO] %s: AE MODE = %s\n",__func__,
			ae_mode_s[s_ctrl->ae_mode]);
		return -EINVAL;
	}

	m10mo_cmd(s_ctrl, CATE_0X03, AE_MODE, s_ctrl->ae_mode);
	m10mo_cmd(s_ctrl, CATE_0X03, AE_PARAM_UPDATE,
		AE_PARAM_UPDATE_Update);
	return rc;
}

static int32_t m10mo_ae_roi_set(struct m10mo_ctrl_t *s_ctrl, 
	struct cam_rect_t *ae_roi)
{
	int rc = 0;
	struct roi_info_t roi_info, *roi;
	CDBG("[M10MO] %s: BEGIN\n", __func__);
	roi_info.left = ae_roi->left;
	roi_info.top = ae_roi->top;
	roi_info.right = ae_roi->left + ae_roi->width;
	roi_info.bottom = ae_roi->top + ae_roi->height;
	s_ctrl->ae_mode = ROI_Mode;

	roi = &roi_info;
	if (roi_validate(roi)) {
		s_ctrl->ae_mode = Center_weighted_average1;
		return rc;
	}

	m10mo_roi_update(s_ctrl, roi);

	return 0;
}

static int32_t m10mo_ae_face_roi_set(struct m10mo_ctrl_t *s_ctrl,
	struct cam_rect_t *ae_roi)
{
	int rc = 0;
	struct roi_info_t roi_info, *roi;
	CDBG("[M10MO] %s: BEGIN\n", __func__);
	roi_info.left = ae_roi->left;
	roi_info.top = ae_roi->top;
	roi_info.right = ae_roi->left + ae_roi->width;
	roi_info.bottom = ae_roi->top + ae_roi->height;
	s_ctrl->ae_mode = ROI_Mode;

	roi = &roi_info;
	if (roi_validate(roi)) {
		s_ctrl->ae_mode = Center_weighted_average1;
		return rc;
	}

	m10mo_face_roi_update(s_ctrl, roi);

	return 0;
}

static uint16_t m10mo_zoom_set(struct m10mo_ctrl_t *s_ctrl, 
	int32_t zoom_level)
{
	int32_t rc = 0;
	CDBG("[M10MO] %s: Zoom level = %d\n", __func__, zoom_level);

	/* userspace zoom level is ratio table index,
	 * m10mo zoom level set from 1 */
	zoom_level++;
	if ((zoom_level < MIN_ZOOM_LEVEL)
		|| (zoom_level > MAX_ZOOM_LEVEL)) {
		pr_err("[M10MO] %s: Invalid zoom level, zoom_level=%d\n",
			__func__, zoom_level);
		return -EINVAL;
	}

	m10mo_cmd(s_ctrl, CATE_0X02, ZOOM, zoom_level);

	return rc;
}

static uint16_t m10mo_iso_set(struct m10mo_ctrl_t *s_ctrl, 
	enum cam_iso_mode_type iso_mode)
{
	uint8_t m10mo_iso;

	switch (iso_mode) {
	case CAM_ISO_MODE_AUTO: {
		m10mo_iso = ISO_AUTO;
		break;
	}

	case CAM_ISO_MODE_50: {
		m10mo_iso = ISO_50;
		break;
	}

	case CAM_ISO_MODE_DEBLUR: {
		m10mo_iso = ISO_AUTO;
		break;
	}

	case CAM_ISO_MODE_100: {
		m10mo_iso = ISO_100;
		break;
	}

	case CAM_ISO_MODE_200: {
		m10mo_iso = ISO_200;
		break;
	}

	case CAM_ISO_MODE_400: {
		m10mo_iso = ISO_400;
		break;
	}

	case CAM_ISO_MODE_800: {
		m10mo_iso = ISO_800;
		break;
	}

	case CAM_ISO_MODE_1600: {
		m10mo_iso = ISO_1600;
		break;
	}

	case CAM_ISO_MODE_3200: {
		m10mo_iso = ISO_3200;
		break;
	}

	default:
		break;
	}
	CDBG("[M10MO] %s: m10mo_iso = %s\n", 
		__func__, m10mo_iso_s[m10mo_iso]);
	m10mo_cmd(s_ctrl, CATE_0X03, ISOSEL, m10mo_iso);
	m10mo_cmd(s_ctrl, CATE_0X03, AE_PARAM_UPDATE, 
		AE_PARAM_UPDATE_Update);

	return 0;
}

static uint16_t m10mo_iso_get(struct m10mo_ctrl_t *s_ctrl)
{
	uint32_t i, size;
	uint16_t iso, mid, step[] =
		{50, 64, 80, 100, 125, 160, 200, 250, 320, 400, 500, 
		640, 800, 1000, 1250, 1600, 2000, 2500, 3200};

	int32_t stream_status = atomic_read(&s_ctrl->stream_status);
	size = ARRAY_SIZE(step);
	if ((ZSL_CAPTURE != stream_status) &&
		(MONITOR != stream_status)) {
		return -EINVAL;
	}

	if (!test_bit(FEATURE_REAL_EXIF, &s_ctrl->feature_mask)) {
		iso = 0;
		return -EINVAL;
	}

	if (MONITOR == stream_status) {
		/* not real ISO, only dB value,
		 * left calculation in userspace */
		iso = m10mo_read_w(s_ctrl, CATE_0X03, NOW_GAIN);
		return iso;
	} else
		iso = m10mo_read_w(s_ctrl, CATE_0X07, INFO_ISO);

	CDBG("[M10MO] %s: original ISO = %d\n", __func__, iso);

	for (i = 0; i < size; i++) {
		if (i >= (size - 1)) {
			iso = (iso >= step[i]) ? step[i] : step[0];
			break;
		}

		if (iso >= step[i] && iso <= step[i + 1]) {
			mid = (step[i] + step[i + 1]) / 2;
			iso = (iso >= mid) ? step[i + 1] : step[i];
			break;
		}
	}
	CDBG("[M10MO] %s: adjusted ISO = %d\n", __func__, iso);
	return iso;
}

static int64_t m10mo_exptime_get(struct m10mo_ctrl_t *s_ctrl)
{
	int64_t exp = 0;
	uint32_t i, size;
	uint64_t nume, deno;
	int stream_status = atomic_read(&s_ctrl->stream_status);
	int32_t step[] = {25, 30, 40, 50, 60, 80, 100, 125, 160, 200,
		250, 320, 400, 500, 640, 800, 1000, 1250, 1600, 2000,
		2500, 3200, 4000};
	size = ARRAY_SIZE(step);

	if (ZSL_CAPTURE == stream_status) {
		nume = (uint64_t)m10mo_read_l(s_ctrl, CATE_0X07, INFO_EXPTIME7);
		deno = (uint64_t)m10mo_read_l(s_ctrl, CATE_0X07, INFO_EXPTIME3);
		if (deno <= 0)
			return -EIO;

		exp = nume * USEC_PER_SEC;
		do_div(exp, deno);
		CDBG("[M10MO] %s: exptime = %lld us\n", __func__, exp);
	} else if (MONITOR == stream_status) {
		exp = (int64_t)m10mo_read_w(s_ctrl, CATE_0X03, NOW_EXPOSURE);
		exp = exp * USEC_PER_SEC;
		do_div(exp, 20000);
		/*CDBG("[M10MO][monitor_exposure] %s: exptime = %lld us\n", 
			__func__, exp);*/
	}
	for (i = 0; i < size; i++) {
		int64_t exp1, exp_mid, exp2;
		if (i >= (size - 1)) {
			exp1 = USEC_PER_SEC;
			do_div(exp1, step[i]);
			exp2 = USEC_PER_SEC;
			do_div(exp2, step[0]);
			exp = (exp <= exp1) ? exp1 : exp2;
			break;
		}
		exp1 = USEC_PER_SEC;
		exp2 = USEC_PER_SEC;
		do_div(exp1, step[i]);
		do_div(exp2, step[i + 1]);
		if (exp >= exp2 && exp <= exp1) {
			exp_mid = (exp1 + exp2) / 2;
			exp = (exp >= exp_mid) ? exp1 : exp2;
			break;
		}
	}

	/*CDBG("[M10MO] %s: Adjusted exptime = %lld us\n",
		__func__, exp);*/

	return exp;
}

static int32_t m10mo_ev_set(struct m10mo_ctrl_t *s_ctrl, 
	int32_t exp_index)
{
	uint8_t ev_bias;
	int32_t max_exp_index = MAX_EV_BIAS / EV_STEP;
	int32_t min_exp_index = MIN_EV_BIAS / EV_STEP;
	if ((exp_index > max_exp_index) ||
		(exp_index < min_exp_index)) {
		pr_err("[M10MO] %s: Invalid evbias, exp_index = %d\n",
			__func__, exp_index);
		return -EINVAL;
	}

	ev_bias = 0x1E + (exp_index * 0xA) / 3;
	CDBG("[M10MO] %s: exp_index = %d\n", __func__, exp_index);
	m10mo_cmd(s_ctrl, CATE_0X03, EV_BIAS, ev_bias);
	m10mo_cmd(s_ctrl, CATE_0X03, AE_PARAM_UPDATE, 
		AE_PARAM_UPDATE_Update);
	return 0;
}

static int32_t m10mo_shutter_speed_set(struct m10mo_ctrl_t *s_ctrl,
	int32_t shutter_speed)
{
	uint8_t m10mo_shutter = ZSL_FAST_SPEED_CAPTURE_Off;

	CDBG("[M10MO] %s: shutter_speed = %d\n",
		__func__, shutter_speed);

	if (shutter_speed > 0)
		m10mo_shutter = ZSL_FAST_SPEED_CAPTURE_On;

	m10mo_cmd(s_ctrl, CATE_0X03,
		ZSL_FAST_SPEED_CAPTURE, m10mo_shutter);
	return 0;
}

static int32_t m10mo_flash_set(struct m10mo_ctrl_t *s_ctrl, 
	int32_t flash_mode)
{
	uint8_t strobe_en = STROBE_EN_Forced_OFF, 
		led_assist_af_en = LED_ASSIST_EN_OFF;
	int32_t stream_status = atomic_read(&s_ctrl->stream_status);

	switch (flash_mode) {
	case LED_MODE_OFF:
		strobe_en = STROBE_EN_Forced_OFF;
		break;

	case LED_MODE_ON:
		strobe_en = STROBE_EN_Forced_ON;
		break;

	case LED_MODE_AUTO:
		strobe_en = STROBE_EN_Auto;
		break;
	case LED_MODE_TORCH:
		strobe_en = STROBE_EN_Torch;
		break;

	default:
		break;
	}

	CDBG("[M10MO] %s: m10mo_flash_mode = %s\n",
		__func__, m10mo_flash_mode_s[strobe_en]);

	if (MONITOR == stream_status)
		m10mo_cmd(s_ctrl, CATE_0X03, STROBE_EN, strobe_en);
	atomic_set(&s_ctrl->flash_mode, strobe_en);

	if (STROBE_EN_Forced_ON == atomic_read(&s_ctrl->flash_mode))
		led_assist_af_en = LED_ASSIST_EN_Auto;
	m10mo_cmd(s_ctrl, CATE_0X0A, LED_ASSIST_EN, led_assist_af_en);
	return 0;
}

static int32_t m10mo_scene_set(struct m10mo_ctrl_t *s_ctrl, 
	int32_t scene_mode)
{
	uint8_t scene_value = 0;

	switch(scene_mode) {
	case CAM_SCENE_MODE_AUTO:
	case CAM_SCENE_MODE_OFF:
		scene_value = SCENE_NUM_Auto;
		break;

	case CAM_SCENE_MODE_NIGHT:
		scene_value = SCENE_NUM_Night;
		break;

	case CAM_SCENE_MODE_PORTRAIT:
		scene_value = SCENE_NUM_Portrait;
		break;

	case CAM_SCENE_MODE_BACKLIGHT:
		scene_value = SCENE_NUM_Backlit;
		break;

	case CAM_SCENE_MODE_NIGHT_PORTRAIT:
		scene_value = SCENE_NUM_Night_Portrait;
		break;

	case CAM_SCENE_MODE_BACKLIGHT_PORTRAIT:
		scene_value = SCENE_NUM_Backlit_Portrait;
		break;

	case CAM_SCENE_MODE_MACRO:
		scene_value = SCENE_NUM_Macro;
		break;

	case CAM_SCENE_MODE_HDR:
		m10mo_hdr_set(s_ctrl, ON);
		return 0;

	default:
		return -1;
	}

	if(atomic_read(&s_ctrl->hdr_enable) == 1){
		m10mo_hdr_set(s_ctrl, OFF);
	}

	CDBG("[M10MO] %s: scene_value = %s\n",
		__func__, scene_value_s[scene_value]);
	m10mo_cmd(s_ctrl, CATE_0X02, SCENE_NUM, scene_value);
	return 0;
}

static void m10mo_awb_lock(struct m10mo_ctrl_t *s_ctrl, 
	int32_t enable)
{
	uint8_t awb_lock = AWB_LOCK_OFF;

	if (enable > 0)
		awb_lock = AWB_LOCK_ON;

	CDBG("[M10MO] %s: awb_lock = %s\n",
		__func__, awb_lock_s[awb_lock]);

	m10mo_cmd(s_ctrl, CATE_0X06, AWB_LOCK, awb_lock);
	m10mo_cmd(s_ctrl, CATE_0X06, AWB_PARAM_UPDATE, 
		AWB_PARAM_UPDATE_Update);
}

static void m10mo_wb_set(struct m10mo_ctrl_t *s_ctrl, 
	int32_t wb_mode)
{
	uint8_t m10mo_wb_mode = AWB_Invalid;

	switch (wb_mode) {
	case CAM_WB_MODE_AUTO:
		m10mo_cmd(s_ctrl, CATE_0X06, AWB_MODE, AWB_Auto);
		break;

	case CAM_WB_MODE_CUSTOM:
		m10mo_wb_mode = AWB_User_setting;
		break;

	case CAM_WB_MODE_INCANDESCENT:
		m10mo_wb_mode = AWB_Incandescent_light;
		break;

	case CAM_WB_MODE_FLUORESCENT:
		m10mo_wb_mode = AWB_Fluorescent_light1;
		break;

	case CAM_WB_MODE_WARM_FLUORESCENT:
		m10mo_wb_mode = AWB_Fluorescent_light2;
		break;

	case CAM_WB_MODE_DAYLIGHT:
		m10mo_wb_mode = AWB_Day_light;
		break;

	case CAM_WB_MODE_CLOUDY_DAYLIGHT:
		m10mo_wb_mode = AWB_Cloudy;
		break;

	case CAM_WB_MODE_TWILIGHT:
		m10mo_wb_mode = AWB_Horizon;
		break;

	case CAM_WB_MODE_SHADE:
		m10mo_wb_mode = AWB_Shade;
		break;

	default:
		break;
	}

	CDBG("[M10MO] %s: WB mode = %s\n", __func__, 
		m10mo_wb_mode_s[m10mo_wb_mode]);

	if (AWB_Invalid != m10mo_wb_mode) {
		m10mo_cmd(s_ctrl, CATE_0X06, AWB_MODE, Manual_WB);
		m10mo_cmd(s_ctrl, CATE_0X06, AWB_MANUAL, m10mo_wb_mode);
	}

	m10mo_cmd(s_ctrl, CATE_0X06, AWB_PARAM_UPDATE, 
		AWB_PARAM_UPDATE_Update);

}

int32_t m10mo_init(struct m10mo_ctrl_t *s_ctrl)
{
	int32_t mod_id;
	uint8_t int_mask, *mod_name;
	uint16_t gpio_mod_id, fw_ver;
	struct msm_camera_gpio_conf *gpio_conf;
	struct msm_sensor_ctrl_t *sensor_ctrl = &s_ctrl->sensor_ctrl;

	m10mo_firmware_boot(s_ctrl);

	/* force torch off when camera open */
	m10mo_cmd(s_ctrl, CATE_0X03, STROBE_EN, STROBE_EN_Forced_OFF);

	fw_ver = m10mo_read_w(s_ctrl, CATE_0X00, VER_FIRMWARE);

	CDBG("[M10MO] %s: FW VERSION = 0x%04x\n", __func__, fw_ver);

	gpio_conf = sensor_ctrl->sensordata->gpio_conf;
	gpio_mod_id = gpio_conf->gpio_num_info->gpio_num[SENSOR_GPIO_MOD_ID];
	mod_id = gpio_get_value_cansleep(gpio_mod_id);
	mod_name = mod_id ? "FOXCONN" : "LITE_ON";
	CDBG("[M10MO] %s: CAMERA module from %s", __func__, mod_name);

	/*int_mask = INT_EN_MODE | INT_EN_AF | INT_EN_CAPTURE | INT_EN_CAF;*/

	/*subscribe all interrupts*/
	int_mask = 0xff;
	m10mo_cmd(s_ctrl, CATE_0X00, INT_ENABLE, int_mask);

	m10mo_cmd(s_ctrl, CATE_0X02, REVERSE, REVERSE_ON);
	m10mo_cmd(s_ctrl, CATE_0X02, MIRROR, MIRROR_ON);

	if (test_bit(FEATURE_OB_CHECK, &s_ctrl->feature_mask))
		m10mo_cmd(s_ctrl, CATE_0X03, AE_MODE, AE_OFF);

	return 0;
}

int32_t m10mo_stream_start(struct m10mo_ctrl_t *s_ctrl,
	struct sensor_stream_start_info * start_info)
{
	int32_t num_burst;
	enum cam_stream_type_t stream_type;
	num_burst = start_info->num_burst;
	stream_type = start_info->stream_type;

	if ((CAM_STREAM_TYPE_SNAPSHOT == stream_type) ||
		(CAM_STREAM_TYPE_POSTVIEW == stream_type) ||
		(CAM_STREAM_TYPE_RAW == stream_type)) {
		if (test_bit(FEATURE_RAW_CAPTURE, &s_ctrl->feature_mask)
			&& ('R' == num_burst))
			m10mo_zsl_raw(s_ctrl);
		else if (1 == num_burst)
			m10mo_zsl_1shot(s_ctrl);
		else
			m10mo_zsl_capture(s_ctrl);
	} else if (CAM_STREAM_TYPE_PREVIEW == stream_type)
		m10mo_monitor(s_ctrl);
	return 0;
}

int32_t m10mo_face_af(struct m10mo_ctrl_t *s_ctrl)
{
	int32_t rc = 0;
	int32_t af_mode, af_status, stream_status;
	af_mode = atomic_read(&s_ctrl->af_mode);
	af_status = atomic_read(&s_ctrl->af_status);
	stream_status = atomic_read(&s_ctrl->stream_status);

	CDBG("[M10MO] %s: BEGIN--Stream_status = %s, Af_mode = %s, af_status = %s\n",
		__func__, stream_status_s[stream_status],
		af_mode_s[af_mode], af_status_s[af_status]);

	if (Continuous_AF_applied != af_mode) {
		pr_err("[M10MO] %s: Operation not allowed, af_mode=%d\n",
			__func__, af_mode);
		return -EINVAL;
	}

	if (roi_validate(&s_ctrl->af_roi)) {
		pr_err("[M10MO] %s: Invalid FACE AF ROI", __func__);
		return -EINVAL;
	}

	m10mo_face_roi_update(s_ctrl, &s_ctrl->af_roi);
	m10mo_cmd(s_ctrl, CATE_0X0A, AF_AREA_MODE, ROI);
	return rc;
}

int32_t m10mo_sensor_config(struct msm_sensor_ctrl_t *s_ctrl,
	void __user *argp)
{
	int32_t rc = 0, i = 0;

	struct sensorb_cfg_data *cdata = (struct sensorb_cfg_data *)argp;

	struct m10mo_ctrl_t *m10mo_ctrl = container_of(s_ctrl, 
		struct m10mo_ctrl_t, sensor_ctrl);

	mutex_lock(s_ctrl->msm_sensor_mutex);

	switch (cdata->cfgtype) {
	case CFG_GET_SENSOR_INFO: {
		memcpy(cdata->cfg.sensor_info.sensor_name,
			s_ctrl->sensordata->sensor_name,
			sizeof(cdata->cfg.sensor_info.sensor_name));
		cdata->cfg.sensor_info.session_id =
			s_ctrl->sensordata->sensor_info->session_id;
		for (i = 0; i < SUB_MODULE_MAX; i++)
			cdata->cfg.sensor_info.subdev_id[i] =
				s_ctrl->sensordata->sensor_info->subdev_id[i];
		break;
	}

	case CFG_SET_INIT_SETTING: {
		m10mo_init(m10mo_ctrl);
		break;
	}

	case CFG_SET_RESOLUTION: {
		int32_t res;
		if (copy_from_user(&res,
			(void *)cdata->cfg.setting, sizeof(int32_t))) {
			pr_err("[M10MO] %s:%d failed\n", __func__, __LINE__);
			rc = -EFAULT;
			break;
		}
		CDBG("[M10MO] %s: resolution set to %d\n", __func__, res);
		atomic_set(&m10mo_ctrl->new_res, res);
		break;
	}

	case CFG_SET_STOP_STREAM: {

		enum cam_stream_type_t stream_type;
		int32_t stream_status = atomic_read(&m10mo_ctrl->stream_status);
		if (copy_from_user(&stream_type,
			(void *)cdata->cfg.setting, sizeof(enum cam_stream_type_t))) {
			pr_err("[M10MO] %s:%d failed\n", __func__, __LINE__);
			rc = -EFAULT;
			break;
		}

		if (ZSL_CAPTURE == stream_status)
			m10mo_capture_stop(m10mo_ctrl);
		else if (MONITOR == stream_status) {
			if (CAPTURE_PENDING ==
				atomic_read(&m10mo_ctrl->capture_pending)) {
				wait_event_interruptible(m10mo_ctrl->wait_q,
					MONITOR_WORK_COMPLETED ==
					atomic_read(&m10mo_ctrl->monitor_working));

				atomic_set(&m10mo_ctrl->stream_status,
					MONITOR_VIRTUAL_OFF);
			} else {
				wait_event_interruptible(m10mo_ctrl->wait_q,
					MONITOR_WORK_COMPLETED ==
					atomic_read(&m10mo_ctrl->monitor_working));

				atomic_set(&m10mo_ctrl->monitor_stop_working,
					MONITOR_STOP_WORK_ONGOING);
				queue_work(m10mo_ctrl->monitor_q,
					&m10mo_ctrl->monitor_stop_work);
			}
		}

		break;

	}
	case CFG_SET_START_STREAM: {
		struct sensor_stream_start_info start_info;

		if (copy_from_user(&start_info,
			(void *)cdata->cfg.setting, 
			sizeof(struct sensor_stream_start_info))) {
			pr_err("[M10MO] %s:%d failed\n", __func__, __LINE__);
			rc = -EFAULT;
			break;
		}
		m10mo_stream_start(m10mo_ctrl, &start_info);
		break;
	}

	case CFG_GET_SENSOR_INIT_PARAMS: {
		cdata->cfg.sensor_init_params =
			*s_ctrl->sensordata->sensor_init_params;
		break;

	}

	case CFG_POWER_UP: {
		m10mo_power_up(m10mo_ctrl);
		break;
	}

	case CFG_POWER_DOWN: {
		mutex_lock(m10mo_ctrl->power_down_mutex);
		queue_work(m10mo_ctrl->power_q,
			&m10mo_ctrl->power_work);
		break;
	}

	case CFG_SET_AE_LOCK: {
		int32_t lock_enable;

		if (copy_from_user(&lock_enable,
			(void *)cdata->cfg.setting,
			sizeof(int32_t))) {
			rc = -EFAULT;
			break;
		}
		m10mo_ae_lock(m10mo_ctrl, lock_enable);
		break;
	}

	case CFG_SET_AE_MODE: {
		int32_t ae_mode;

		if (copy_from_user(&ae_mode,
			(void *)cdata->cfg.setting,
			sizeof(int32_t))) {
			rc = -EFAULT;
			break;
		}
		m10mo_ae_mode_set(m10mo_ctrl, ae_mode);
		break;
	}
	case CFG_SET_AE_ROI: {
		struct cam_rect_t ae_roi;

		if (copy_from_user(&ae_roi,
			(void *)cdata->cfg.setting,
			sizeof(struct cam_rect_t))) {
			rc = -EFAULT;
			break;
		}
		m10mo_ae_roi_set(m10mo_ctrl, &ae_roi);
		/* set AE when setting AE roi*/
		m10mo_ae_set(m10mo_ctrl);
		break;
	}

	case CFG_SET_AE_FACE_ROI: {
		struct cam_rect_t ae_roi;

		if (copy_from_user(&ae_roi,
			(void *)cdata->cfg.setting,
			sizeof(struct cam_rect_t))) {
			rc = -EFAULT;
			break;
		}
		m10mo_ae_face_roi_set(m10mo_ctrl, &ae_roi);
		/* set AE when setting AE roi*/
		m10mo_ae_set(m10mo_ctrl);
		break;
	}

	case CFG_SET_SCENE: {
		int32_t scene_mode;

		if (copy_from_user(&scene_mode,
			(void *)cdata->cfg.setting,
			sizeof(int32_t))) {
			rc = -EFAULT;
			break;
		}
		m10mo_scene_set(m10mo_ctrl, scene_mode);
		break;
	}

	case CFG_SET_ISO: {
		enum cam_iso_mode_type iso_mode;

		if (copy_from_user(&iso_mode,
			(void *)cdata->cfg.setting,
			sizeof(enum cam_iso_mode_type))) {
			rc = -EFAULT;
			break;
		}
		m10mo_iso_set(m10mo_ctrl, iso_mode);
		break;
	}

	case CFG_SET_ZOOM: {
		int32_t zoom_level;

		if (copy_from_user(&zoom_level,
			(void *)cdata->cfg.setting,
			sizeof(int32_t))) {
			rc = -EFAULT;
			break;
		}
		m10mo_zoom_set(m10mo_ctrl, zoom_level);
		break;
	}

	case CFG_SET_WHITE_BALANCE: {
		enum cam_wb_mode_type wb_mode;

		if (copy_from_user(&wb_mode,
			(void *)cdata->cfg.setting,
			sizeof(enum cam_wb_mode_type))) {
			rc = -EFAULT;
			break;
		}
		m10mo_wb_set(m10mo_ctrl, wb_mode);

		break;
	}
	case CFG_SET_AWB_LOCK: {
		int32_t lock_enable;

		if (copy_from_user(&lock_enable,
			(void *)cdata->cfg.setting,
			sizeof(int32_t))) {
			rc = -EFAULT;
			break;
		}
		m10mo_awb_lock(m10mo_ctrl, lock_enable);
		break;
	}

	case CFG_SET_AF_ROI: {
		if (copy_from_user(&m10mo_ctrl->af_roi,
			(void *)cdata->cfg.setting,
			sizeof(struct roi_info_t))) {
			rc = -EFAULT;
			break;
		}
		if (top_left(&m10mo_ctrl->af_roi)) {
			CDBG("[M10MO] %s: top left m_af_trigger = %d\n", __func__, atomic_read(&m10mo_ctrl->m_af_trigger));
			if (0 == atomic_read(&m10mo_ctrl->m_af_trigger)) {
				atomic_set(&m10mo_ctrl->m_af_trigger, 1);
				CDBG("[M10MO] %s: m_af_trigger = %d\n", __func__, atomic_read(&m10mo_ctrl->m_af_trigger));
			} else
				atomic_set(&m10mo_ctrl->m_af_trigger, 0);
		}
		if (top_center(&m10mo_ctrl->af_roi)) {
			if (1 == atomic_read(&m10mo_ctrl->m_af_trigger)) {
				atomic_set(&m10mo_ctrl->m_af_trigger, 2);
				CDBG("[M10MO] %s: m_af_trigger = %d\n", __func__, atomic_read(&m10mo_ctrl->m_af_trigger));
			} else
				atomic_set(&m10mo_ctrl->m_af_trigger, 0);
		}
		if (top_right(&m10mo_ctrl->af_roi)) {
			if (2 == atomic_read(&m10mo_ctrl->m_af_trigger)) {
				atomic_set(&m10mo_ctrl->m_af_trigger, 3);
				CDBG("[M10MO] %s: m_af_trigger = %d\n", __func__, atomic_read(&m10mo_ctrl->m_af_trigger));
			} else
				atomic_set(&m10mo_ctrl->m_af_trigger, 0);
		}
		if (center_right(&m10mo_ctrl->af_roi)) {
			if (3 == atomic_read(&m10mo_ctrl->m_af_trigger)) {
				atomic_set(&m10mo_ctrl->m_af_trigger, 4);
				CDBG("[M10MO] %s: m_af_trigger = %d\n", __func__, atomic_read(&m10mo_ctrl->m_af_trigger));
			} else
				atomic_set(&m10mo_ctrl->m_af_trigger, 0);
		}
		if (center_center(&m10mo_ctrl->af_roi)) {
			if (4 == atomic_read(&m10mo_ctrl->m_af_trigger)) {
				atomic_set(&m10mo_ctrl->m_af_trigger, 5);
				CDBG("[M10MO] %s: m_af_trigger = %d\n", __func__, atomic_read(&m10mo_ctrl->m_af_trigger));
			} else
				atomic_set(&m10mo_ctrl->m_af_trigger, 0);
		}
		if (center_left(&m10mo_ctrl->af_roi)) {
			if (5 == atomic_read(&m10mo_ctrl->m_af_trigger)) {
				atomic_set(&m10mo_ctrl->m_af_trigger, 6);
				CDBG("[M10MO] %s: m_af_trigger = %d\n", __func__, atomic_read(&m10mo_ctrl->m_af_trigger));
			} else
				atomic_set(&m10mo_ctrl->m_af_trigger, 0);
		}

		if (bottom_left(&m10mo_ctrl->af_roi)) {
			if (6 == atomic_read(&m10mo_ctrl->m_af_trigger)) {
				atomic_set(&m10mo_ctrl->m_af_trigger, 7);
				CDBG("[M10MO] %s: m_af_trigger = %d\n", __func__, atomic_read(&m10mo_ctrl->m_af_trigger));
			} else
				atomic_set(&m10mo_ctrl->m_af_trigger, 0);
		}

		if (bottom_center(&m10mo_ctrl->af_roi)) {
			if (7 == atomic_read(&m10mo_ctrl->m_af_trigger)) {
				atomic_set(&m10mo_ctrl->m_af_trigger, 8);
				CDBG("[M10MO] %s: m_af_trigger = %d\n", __func__, atomic_read(&m10mo_ctrl->m_af_trigger));
			} else
				atomic_set(&m10mo_ctrl->m_af_trigger, 0);
		}

		if (bottom_right(&m10mo_ctrl->af_roi)) {
			if (8 == atomic_read(&m10mo_ctrl->m_af_trigger)) {
				atomic_set(&m10mo_ctrl->m_af_trigger, 9);
				CDBG("[M10MO] %s: m_af_trigger = %d\n", __func__, atomic_read(&m10mo_ctrl->m_af_trigger));
				m10mo_ev_set(m10mo_ctrl, -9);
				msleep(500);
				m10mo_ev_set(m10mo_ctrl, 9);
				msleep(500);
				m10mo_ev_set(m10mo_ctrl, 0);
				atomic_set(&m10mo_ctrl->manual_af, 1);
			} else
				atomic_set(&m10mo_ctrl->m_af_trigger, 0);
		}

		if (roi_validate(&m10mo_ctrl->af_roi))
			m10mo_cmd(m10mo_ctrl, CATE_0X0A, AF_AREA_MODE, CENTER);

		break;
	}
	case CFG_SET_AF_FACE_ROI: {
		if (copy_from_user(&m10mo_ctrl->af_roi,
			(void *)cdata->cfg.setting,
			sizeof(struct roi_info_t))) {
			rc = -EFAULT;
			break;
		}
		m10mo_face_af(m10mo_ctrl);
		break;
	}

	case CFG_GET_EXPOSURE_TIME: {
		int64_t exp = m10mo_exptime_get(m10mo_ctrl);
		*(int64_t *)cdata->cfg.setting = exp;
		break;
	}

	case CFG_GET_VCM_DAC: {
		uint16_t dac = m10mo_vcm_dac_get(m10mo_ctrl);

		if (cdata && cdata->cfg.setting)
			*(uint16_t *)cdata->cfg.setting	= dac;

		break;
	}

	case CFG_GET_ISO: {
		uint16_t iso = m10mo_iso_get(m10mo_ctrl);

		if (cdata && cdata->cfg.setting)
			*(uint16_t *)cdata->cfg.setting	= iso;

		break;
	}

	case CFG_SET_HDR: {
		break;
	}
	case CFG_SET_EXPOSURE_COMPENSATION: {
		int32_t exp_index;
		if (copy_from_user(&exp_index,
			(void *)cdata->cfg.setting,
			sizeof(int32_t))) {
			rc = -EFAULT;
			break;
		}
		m10mo_ev_set(m10mo_ctrl, exp_index);
		break;
	}

	case CFG_SET_GYRO: {
		if (copy_from_user(&m10mo_ctrl->gyro_info,
			(void *)cdata->cfg.setting,
			sizeof(struct gyro_info_t))) {
			rc = -EFAULT;
			break;
		}
		break;
	}

	case CFG_SET_DEGREE: {
		int32_t degree;
		if (copy_from_user(&degree,
			(void *)cdata->cfg.setting,
			sizeof(int32_t))) {
			rc = -EFAULT;
			break;
		}
		atomic_set(&m10mo_ctrl->degree, degree);
		queue_work(m10mo_ctrl->monitor_q,
			&m10mo_ctrl->degree_set_work);
		break;
	}

	case CFG_SET_LENS_ANGLE: {
		int32_t position;
		if (copy_from_user(&position,
			(void *)cdata->cfg.setting,
			sizeof(int32_t))) {
			rc = -EFAULT;
			break;
		}
		atomic_set(&m10mo_ctrl->position, position);
		queue_work(m10mo_ctrl->monitor_q,
			&m10mo_ctrl->position_set_work);
		break;
	}
	case CFG_SET_ACC: {
		if (copy_from_user(&m10mo_ctrl->acc_info,
			(void *)cdata->cfg.setting,
			sizeof(struct acc_info_t))) {
			rc = -EFAULT;
			break;
		}
		queue_work(m10mo_ctrl->monitor_q,
			&m10mo_ctrl->gyro_set_work);
		break;
	}

	case CFG_SET_AF_MODE: {

		int32_t af_mode;
		int32_t stream_status;

		if (copy_from_user(&af_mode,
			(void *)cdata->cfg.setting,
			sizeof(int32_t))) {
			rc = -EFAULT;
			break;
		}
		wait_event_interruptible(m10mo_ctrl->wait_q,
			MONITOR_WORK_COMPLETED ==
			atomic_read(&m10mo_ctrl->monitor_working));

		stream_status = atomic_read(&m10mo_ctrl->stream_status);
		if (ZSL_CAPTURE_STOPPING == stream_status)
			wait_event_interruptible(m10mo_ctrl->wait_q,
				MONITOR == atomic_read(&m10mo_ctrl->stream_status));

		m10mo_af_mode_set(m10mo_ctrl, af_mode);
		break;
	}

	case CFG_SET_AUTOFOCUS: {
		int32_t af_mode = 0;
		wait_event_interruptible(m10mo_ctrl->wait_q,
			MONITOR_WORK_COMPLETED ==
			atomic_read(&m10mo_ctrl->monitor_working));

		af_mode = atomic_read(&m10mo_ctrl->af_mode);
		if (Normal_AF == af_mode) {
			if (1 == atomic_read(&m10mo_ctrl->manual_af)) {
				if (top_right(&m10mo_ctrl->af_roi)) {
					m10mo_cmd(m10mo_ctrl, CATE_0X0A, AF_START, AF_stop_by_force);
					msleep(50);
					m10mo_cmd(m10mo_ctrl, CATE_0X0A, MANUAL_LENS_DAC, plus_1DAC);
					msleep(100);
					af_finish_notify(s_ctrl);
				} else if (bottom_right(&m10mo_ctrl->af_roi)) {
					m10mo_cmd(m10mo_ctrl, CATE_0X0A, AF_START, AF_stop_by_force);
					msleep(50);
					m10mo_cmd(m10mo_ctrl, CATE_0X0A, MANUAL_LENS_DAC, minus_1DAC);
					msleep(100);

					af_finish_notify(s_ctrl);
				} else if (top_left(&m10mo_ctrl->af_roi)) {
					m10mo_cmd(m10mo_ctrl, CATE_0X0A, AF_START, AF_stop_by_force);
					msleep(50);
					m10mo_cmd(m10mo_ctrl, CATE_0X0A, MANUAL_LENS_DAC, plus_127DAC);
					msleep(100);

					af_finish_notify(s_ctrl);
				} else if (bottom_left(&m10mo_ctrl->af_roi)) {
					m10mo_cmd(m10mo_ctrl, CATE_0X0A, AF_START, AF_stop_by_force);
					msleep(50);
					m10mo_cmd(m10mo_ctrl, CATE_0X0A, MANUAL_LENS_DAC, minus_128DAC);
					msleep(100);

					af_finish_notify(s_ctrl);
				} else if (top_center(&m10mo_ctrl->af_roi)) {
					m10mo_cmd(m10mo_ctrl, CATE_0X0A, AF_START, AF_stop_by_force);
					msleep(50);
					m10mo_cmd(m10mo_ctrl, CATE_0X0A, MANUAL_LENS_DAC, plus_10DAC);
					msleep(100);

					af_finish_notify(s_ctrl);
				} else if (bottom_center(&m10mo_ctrl->af_roi)) {
					m10mo_cmd(m10mo_ctrl, CATE_0X0A, AF_START, AF_stop_by_force);
					msleep(50);
					m10mo_cmd(m10mo_ctrl, CATE_0X0A, MANUAL_LENS_DAC, minus_10DAC);
					msleep(100);

					af_finish_notify(s_ctrl);


				} else
					af_finish_notify(s_ctrl);
			} else
				m10mo_af_start(m10mo_ctrl);
		} else if (Macro_AF == af_mode)
			af_finish_notify(s_ctrl);
		break;
	}

	case CFG_SET_AF_LOCK: {
		int32_t lock_caf;

		if (copy_from_user(&lock_caf,
			(void *)cdata->cfg.setting,
			sizeof(int32_t))) {
			rc = -EFAULT;
			break;
		}
		m10mo_caf_lock(m10mo_ctrl, lock_caf);
		break;
	}
	case CFG_SET_BESTSHOT_MODE: {
		int32_t scene_mode ;
		if (copy_from_user(&scene_mode,
			(void *)cdata->cfg.setting,
			sizeof(int32_t))) {
			rc = -EFAULT;
			break;
		}

		m10mo_scene_set(m10mo_ctrl, scene_mode);
		break;
	}
	case CFG_SET_FLASH: {
		int32_t flash_mode;
		if (copy_from_user(&flash_mode,
			(void *)cdata->cfg.setting,
			sizeof(int32_t))) {
			rc = -EFAULT;
			break;
		}
		m10mo_flash_set(m10mo_ctrl, flash_mode);
		break;
	}

	case CFG_SET_PREPARE_SNAPSHOT: {
		int32_t enable;
		if (copy_from_user(&enable,
			(void *)cdata->cfg.setting,
			sizeof(int32_t))) {
			rc = -EFAULT;
			break;
		}
		CDBG("[M10MO] %s: capture pending set to 1\n", __func__);
		atomic_set(&m10mo_ctrl->capture_pending , CAPTURE_PENDING);
		break;
	}

	case CFG_SET_SHUTTER_SPEED: {
		int32_t shutter_speed;
		if (copy_from_user(&shutter_speed,
			(void *)cdata->cfg.setting,
			sizeof(int32_t))) {
			rc = -EFAULT;
			break;
		}
		m10mo_shutter_speed_set(m10mo_ctrl, shutter_speed);
		break;
	}

	case CFG_CANCEL_AUTOFOCUS: {
		int32_t af_mode = atomic_read(&m10mo_ctrl->af_mode);
		if (Normal_AF == af_mode)
			m10mo_af_stop(m10mo_ctrl);
		break;
	}

	default:
		rc = 0;
		break;
	}

	mutex_unlock(s_ctrl->msm_sensor_mutex);

	return rc;
}

int32_t m10mo_sensor_match_id(struct msm_sensor_ctrl_t *s_ctrl)
{
	return 0;
}

static int32_t m10mo_af_status_get(struct msm_sensor_ctrl_t *s_ctrl,
	void __user *argp)
{
	int rc = 0;
	uint8_t result = Focus_operation_fail;
	struct m10mo_ctrl_t *m10mo_ctrl = 
		container_of(s_ctrl, struct m10mo_ctrl_t, sensor_ctrl);
	struct af_result_t *af_result  = (struct af_result_t *)argp;
	int32_t af_status = atomic_read(&m10mo_ctrl->af_status);
	int32_t af_mode = atomic_read(&m10mo_ctrl->af_mode);
	if (Macro_AF == af_mode) {
		af_result->af_status = SENSOR_AF_FOCUSSED;
		return rc;
	}

	mutex_lock(s_ctrl->msm_sensor_mutex);
	if (LENS_INITED != af_status) {
		CDBG("[M10MO] %s: Operation not allowed, af_status = %s\n",
			__func__, af_status_s[af_status]);
		mutex_unlock(s_ctrl->msm_sensor_mutex);
		return -EINVAL;
	}
	
	result = m10mo_read(m10mo_ctrl, CATE_0X0A, AF_RESULT);

	CDBG("[M10MO] %s: m10mo af result = %s, \n",
		__func__, m10mo_af_result_s[result]);

	af_result->af_status = SENSOR_AF_NOT_FOCUSSED;
	if (Focus_operation_success == result)
		af_result->af_status = SENSOR_AF_FOCUSSED;
	mutex_unlock(s_ctrl->msm_sensor_mutex);
	if (AF_OFF == result || AF_operating == result) {
		pr_err("[M10MO] %s: Invalid result, result=%d\n",
			__func__, result);
		return -EINVAL;
	}

	return rc;
}

static int32_t m10mo_af_distance_get(struct msm_sensor_ctrl_t *s_ctrl,
	void __user *argp)
{
	int rc = 0;
	int32_t *af_distance  = (int32_t *)argp;
	struct m10mo_ctrl_t *m10mo_ctrl =
		container_of(s_ctrl, struct m10mo_ctrl_t, sensor_ctrl);
	int32_t af_status = atomic_read(&m10mo_ctrl->af_status);

	mutex_lock(s_ctrl->msm_sensor_mutex);
	if (LENS_INITED != af_status) {
		CDBG("[M10MO] %s: Operation not allowed, af_status = %s\n",
			__func__, af_status_s[af_status]);
		mutex_unlock(s_ctrl->msm_sensor_mutex);
		return -EINVAL;
	}

	*af_distance = (int32_t)m10mo_read_w(m10mo_ctrl, CATE_0X0A, AF_DISTANCE);
	CDBG("[M10MO] %s: target distance = %d cm\n",
		__func__, *af_distance);

	mutex_unlock(s_ctrl->msm_sensor_mutex);

	return rc;
}

static struct msm_sensor_fn_t m10mo_sensor_func_tbl = {
	.sensor_config = m10mo_sensor_config,
	.sensor_power_up = msm_sensor_power_up,
	.sensor_match_id = m10mo_sensor_match_id,
	.sensor_power_down = msm_sensor_power_down,
	.sensor_get_af_status = m10mo_af_status_get,
	.sensor_get_af_distance = m10mo_af_distance_get,
};

static struct m10mo_ctrl_t m10mo_s_ctrl = {
	.sensor_ctrl = {
		.msm_sensor_mutex = &m10mo_mut,
		.func_tbl = &m10mo_sensor_func_tbl,
		.sensor_v4l2_subdev_info = m10mo_subdev_info,
		.sensor_i2c_client = &m10mo_sensor_i2c_client,
		.power_setting_array.power_setting = m10mo_power_setting,
		.power_setting_array.size = ARRAY_SIZE(m10mo_power_setting),
		.sensor_v4l2_subdev_info_size = ARRAY_SIZE(m10mo_subdev_info),
	},

	.irq_q = 0,
	.irq_num = 0,
	.power_q = 0,
	.monitor_q = 0,

	.m10mo_i2c_mutex = &m10mo_i2c_mut,
	.taf_time_mutex = &m10mo_taf_time_mut,
	.power_down_mutex = &m10mo_power_down_mut,
};

module_init(m10mo_init_module);
module_exit(m10mo_exit_module);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Fujitsu ISP M10MO driver");
MODULE_AUTHOR("Ethan Yang yangyi@smartisan.com");
MODULE_AUTHOR("Poter Xu xuxiaopeng@smartisan.com");
