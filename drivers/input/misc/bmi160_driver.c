/*!
 * @section LICENSE
 * (C) Copyright 2011~2015 Bosch Sensortec GmbH All Rights Reserved
 *
 * This software program is licensed subject to the GNU General
 * Public License (GPL).Version 2,June 1991,
 * available at http://www.fsf.org/copyleft/gpl.html
 *
 * @filename bmi160_driver.c
 * @date     2014/11/25 14:40
 * @id       "b3ccb9e"
 * @version  1.2
 *
 * @brief
 * The core code of BMI160 device driver
 *
 * @detail
 * This file implements the core code of BMI160 device driver,
 * which includes hardware related functions, input device register,
 * device attribute files, etc.
*/

#include "bmi160.h"
#include "bmi160_driver.h"
#include <linux/device.h>
#include <linux/gpio.h>
#include <linux/of_gpio.h>
#include <linux/of_irq.h>

#define BMI160_VDD_MIN_UV	2700000
#define BMI160_VDD_MAX_UV	3300000
#define BMI160_VI2C_MIN_UV	1750000
#define BMI160_VI2C_MAX_UV	1950000

#define I2C_BURST_READ_MAX_LEN      (256)
#define BMI160_STORE_COUNT  (6000)
#define LMADA     (1)
uint64_t g_current_apts_us;
static unsigned char g_fifo_data_arr[2048];/*1024 + 12*4*/

enum BMI_SENSOR_INT_T {
	/* Interrupt enable0*/
	BMI_ANYMO_X_INT = 0,
	BMI_ANYMO_Y_INT,
	BMI_ANYMO_Z_INT,
	BMI_D_TAP_INT,
	BMI_S_TAP_INT,
	BMI_ORIENT_INT,
	BMI_FLAT_INT,
	/* Interrupt enable1*/
	BMI_HIGH_X_INT,
	BMI_HIGH_Y_INT,
	BMI_HIGH_Z_INT,
	BMI_LOW_INT,
	BMI_DRDY_INT,
	BMI_FFULL_INT,
	BMI_FWM_INT,
	/* Interrupt enable2 */
	BMI_NOMOTION_X_INT,
	BMI_NOMOTION_Y_INT,
	BMI_NOMOTION_Z_INT,
	INT_TYPE_MAX
};

/*bmi fifo sensor type combination*/
enum BMI_SENSOR_FIFO_COMBINATION {
	BMI_FIFO_A = 0,
	BMI_FIFO_G,
	BMI_FIFO_M,
	BMI_FIFO_G_A,
	BMI_FIFO_M_A,
	BMI_FIFO_M_G,
	BMI_FIFO_M_G_A,
	BMI_FIFO_COM_MAX
};

/*bmi fifo analyse return err status*/
enum BMI_FIFO_ANALYSE_RETURN_T {
	FIFO_OVER_READ_RETURN = -10,
	FIFO_SENSORTIME_RETURN = -9,
	FIFO_SKIP_OVER_LEN = -8,
	FIFO_M_G_A_OVER_LEN = -7,
	FIFO_M_G_OVER_LEN = -6,
	FIFO_M_A_OVER_LEN = -5,
	FIFO_G_A_OVER_LEN = -4,
	FIFO_M_OVER_LEN = -3,
	FIFO_G_OVER_LEN = -2,
	FIFO_A_OVER_LEN = -1
};

/*!bmi sensor generic power mode enum */
enum BMI_DEV_OP_MODE {
	SENSOR_PM_NORMAL = 0,
	SENSOR_PM_LP1,
	SENSOR_PM_SUSPEND,
	SENSOR_PM_LP2
};

/*! bmi acc sensor power mode enum */
enum BMI_ACC_PM_TYPE {
	BMI_ACC_PM_NORMAL = 0,
	BMI_ACC_PM_LP1,
	BMI_ACC_PM_SUSPEND,
	BMI_ACC_PM_LP2,
	BMI_ACC_PM_MAX
};

/*! bmi gyro sensor power mode enum */
enum BMI_GYRO_PM_TYPE {
	BMI_GYRO_PM_NORMAL = 0,
	BMI_GYRO_PM_FAST_START,
	BMI_GYRO_PM_SUSPEND,
	BMI_GYRO_PM_MAX
};

/*! bmi mag sensor power mode enum */
enum BMI_MAG_PM_TYPE {
	BMI_MAG_PM_NORMAL = 0,
	BMI_MAG_PM_LP1,
	BMI_MAG_PM_SUSPEND,
	BMI_MAG_PM_LP2,
	BMI_MAG_PM_MAX
};


/*! bmi sensor support type*/
enum BMI_SENSOR_TYPE {
	BMI_ACC_SENSOR,
	BMI_GYRO_SENSOR,
	BMI_MAG_SENSOR,
	BMI_SENSOR_TYPE_MAX
};

/*!bmi sensor generic power mode enum */
enum BMI_AXIS_TYPE {
	X_AXIS = 0,
	Y_AXIS,
	Z_AXIS,
	AXIS_MAX
};

/*!bmi sensor generic intterrupt enum */
enum BMI_INT_TYPE {
	BMI160_INT0 = 0,
	BMI160_INT1,
	BMI160_INT_MAX
};

/*! bmi sensor time resolution definition*/
enum BMI_SENSOR_TIME_RS_TYPE {
	TS_0_78_HZ = 1,/*0.78HZ*/
	TS_1_56_HZ,/*1.56HZ*/
	TS_3_125_HZ,/*3.125HZ*/
	TS_6_25_HZ,/*6.25HZ*/
	TS_12_5_HZ,/*12.5HZ*/
	TS_25_HZ,/*25HZ, odr=6*/
	TS_50_HZ,/*50HZ*/
	TS_100_HZ,/*100HZ*/
	TS_200_HZ,/*200HZ*/
	TS_400_HZ,/*400HZ*/
	TS_800_HZ,/*800HZ*/
	TS_1600_HZ,/*1600HZ*/
	TS_MAX_HZ
};

/*! bmi sensor interface mode */
enum BMI_SENSOR_IF_MODE_TYPE {
	/*primary interface:autoconfig/secondary interface off*/
	P_AUTO_S_OFF = 0,
	/*primary interface:I2C/secondary interface:OIS*/
	P_I2C_S_OIS,
	/*primary interface:autoconfig/secondary interface:Magnetometer*/
	P_AUTO_S_MAG,
	/*interface mode reseved*/
	IF_MODE_RESEVED

};

unsigned int reg_op_addr;

static const int bmi_pmu_cmd_acc_arr[BMI_ACC_PM_MAX] = {
	/*!bmi pmu for acc normal, low power1,
	 * suspend, low power2 mode command */
	CMD_PMU_ACC_NORMAL,
	CMD_PMU_ACC_LP1,
	CMD_PMU_ACC_SUSPEND,
	CMD_PMU_ACC_LP2
};

static const int bmi_pmu_cmd_gyro_arr[BMI_GYRO_PM_MAX] = {
	/*!bmi pmu for gyro normal, fast startup,
	 * suspend mode command */
	CMD_PMU_GYRO_NORMAL,
	CMD_PMU_GYRO_FASTSTART,
	CMD_PMU_GYRO_SUSPEND
};

static const int bmi_pmu_cmd_mag_arr[BMI_MAG_PM_MAX] = {
	/*!bmi pmu for mag normal, low power1,
	 * suspend, low power2 mode command */
	CMD_PMU_MAG_NORMAL,
	CMD_PMU_MAG_LP1,
	CMD_PMU_MAG_SUSPEND,
	CMD_PMU_MAG_LP2
};

static const char *bmi_axis_name[AXIS_MAX] = {"x", "y", "z"};

static const int bmi_interrupt_type[] = {
	/*!bmi interrupt type */
	/* Interrupt enable0 */
	BMI160_ANYMO_X_EN,
	BMI160_ANYMO_Y_EN,
	BMI160_ANYMO_Z_EN,
	BMI160_D_TAP_EN,
	BMI160_S_TAP_EN,
	BMI160_ORIENT_EN,
	BMI160_FLAT_EN,
	/* Interrupt enable1*/
	BMI160_HIGH_X_EN,
	BMI160_HIGH_Y_EN,
	BMI160_HIGH_Z_EN,
	BMI160_LOW_EN,
	BMI160_DRDY_EN,
	BMI160_FFULL_EN,
	BMI160_FWM_EN,
	/* Interrupt enable2 */
	BMI160_NOMOTION_X_EN,
	BMI160_NOMOTION_Y_EN,
	BMI160_NOMOTION_Z_EN
};

/*! bmi sensor time depend on ODR*/
struct bmi_sensor_time_odr_tbl {
	u32 ts_duration_lsb;
	u32 ts_duration_us;
	u32 ts_delat;/*sub current delat fifo_time*/
};

struct bmi160_axis_data_t {
	s16 x;
	s16 y;
	s16 z;
};
static struct sensors_classdev bmi160_gyro_cdev = {
	.name = "bmi160-gyro",
	.vendor = "bosch",
	.version = 1,
	.handle = SENSORS_GYROSCOPE_HANDLE,
	.type = SENSOR_TYPE_GYROSCOPE,
	.max_range = "35.0",
	.resolution = "1.0",
	.sensor_power = "0.2",
	.min_delay = 1000,
	.fifo_reserved_event_count = 0,
	.fifo_max_event_count = 0,
	.enabled = 0,
	.delay_msec = 100,
	.sensors_enable = NULL,
	.sensors_poll_delay = NULL,
	.sensors_self_test = NULL,

};

static struct sensors_classdev bmi160_acc_cdev = {
	.name = "bmi160-accel",
	.vendor = "bosch",
	.version = 1,
	.handle = SENSORS_ACCELERATION_HANDLE,
	.type = SENSOR_TYPE_ACCELEROMETER,
	.max_range = "156.8",	/* 16g */
	.resolution = "0.156",	/* 15.63mg */
	.sensor_power = "0.13",	/* typical value */
	.min_delay = 1000, /* in microseconds */
	.fifo_reserved_event_count = 0,
	.fifo_max_event_count = 0,
	.enabled = 0,
	.delay_msec = 100, /* in millisecond */
	.sensors_enable = NULL,
	.sensors_poll_delay = NULL,
	.sensors_self_test = NULL,
};
struct bmi160_type_mapping_type {

	/*! bmi16x sensor chip id */
	uint16_t chip_id;

	/*! bmi16x chip revision code */
	uint16_t revision_id;

	/*! bma2x2 sensor name */
	const char *sensor_name;
};

struct bmi160_store_info_t {
	uint8_t current_frm_cnt;
	uint64_t current_apts_us[2];
	uint8_t fifo_ts_total_frmcnt;
	uint64_t fifo_time;
};

uint64_t get_current_timestamp(void)
{
	uint64_t ts;
	struct timeval tv;

	do_gettimeofday(&tv);
	ts = (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;

	return ts;
}


/*! sensor support type map */
static const struct bmi160_type_mapping_type sensor_type_map[] = {

	{SENSOR_CHIP_ID_BMI, SENSOR_CHIP_REV_ID_BMI, "BMI160/162AB"},
	{SENSOR_CHIP_ID_BMI_C2, SENSOR_CHIP_REV_ID_BMI, "BMI160C2"},
	{SENSOR_CHIP_ID_BMI_C3, SENSOR_CHIP_REV_ID_BMI, "BMI160C3"},

};

/*!bmi160 sensor time depends on ODR */
static const struct bmi_sensor_time_odr_tbl
		sensortime_duration_tbl[TS_MAX_HZ] = {
	{0x010000, 2560000, 0x00ffff},/*2560ms, 0.39hz, odr=resver*/
	{0x008000, 1280000, 0x007fff},/*1280ms, 0.78hz, odr_acc=1*/
	{0x004000, 640000, 0x003fff},/*640ms, 1.56hz, odr_acc=2*/
	{0x002000, 320000, 0x001fff},/*320ms, 3.125hz, odr_acc=3*/
	{0x001000, 160000, 0x000fff},/*160ms, 6.25hz, odr_acc=4*/
	{0x000800, 80000,  0x0007ff},/*80ms, 12.5hz*/
	{0x000400, 40000, 0x0003ff},/*40ms, 25hz, odr_acc = odr_gyro =6*/
	{0x000200, 20000, 0x0001ff},/*20ms, 50hz, odr = 7*/
	{0x000100, 10000, 0x0000ff},/*10ms, 100hz, odr=8*/
	{0x000080, 5000, 0x00007f},/*5ms, 200hz, odr=9*/
	{0x000040, 2500, 0x00003f},/*2.5ms, 400hz, odr=10*/
	{0x000020, 1250, 0x00001f},/*1.25ms, 800hz, odr=11*/
	{0x000010, 625, 0x00000f},/*0.625ms, 1600hz, odr=12*/

};

static void bmi_dump_reg(struct bmi_client_data *client_data)
{
	#define REG_MAX0 0x24
	#define REG_MAX1 0x56
	int i;
	u8 dbg_buf0[REG_MAX0];
	u8 dbg_buf1[REG_MAX1];
	u8 dbg_buf_str0[REG_MAX0 * 3 + 1] = "";
	u8 dbg_buf_str1[REG_MAX1 * 3 + 1] = "";

	dev_notice(client_data->dev, "0x00:\n");

	client_data->device.bus_read(client_data->device.dev_addr,
			BMI_REG_NAME(USER_CHIP_ID), dbg_buf0, REG_MAX0);
	for (i = 0; i < REG_MAX0; i++) {
		sprintf(dbg_buf_str0 + i * 3, "%02x%c", dbg_buf0[i],
				(((i + 1) % BYTES_PER_LINE == 0) ? '\n' : ' '));

	dev_notice(client_data->dev, "%s\n", dbg_buf_str0);

	client_data->device.bus_read(client_data->device.dev_addr,
			BMI160_USER_ACC_CONF_ADDR, dbg_buf1, REG_MAX1);
	dev_notice(client_data->dev, "\n0x40:\n");
	for (i = 0; i < REG_MAX1; i++) {
		sprintf(dbg_buf_str1 + i * 3, "%02x%c", dbg_buf1[i],
				(((i + 1) % BYTES_PER_LINE == 0) ? '\n' : ' '));
	}
	dev_notice(client_data->dev, "%s\n", dbg_buf_str1);
	}
}

/*!
* BMG160 sensor remapping function
* need to give some parameter in BSP files first.
*/
static const struct bosch_sensor_axis_remap
	bst_axis_remap_tab_dft[MAX_AXIS_REMAP_TAB_SZ] = {
	/* src_x src_y src_z  sign_x  sign_y  sign_z */
	{  0,	 1,    2,	  1,	  1,	  1 }, /* P0 */
	{  1,	 0,    2,	  1,	 -1,	  1 }, /* P1 */
	{  0,	 1,    2,	 -1,	 -1,	  1 }, /* P2 */
	{  1,	 0,    2,	 -1,	  1,	  1 }, /* P3 */

	{  0,	 1,    2,	 -1,	  1,	 -1 }, /* P4 */
	{  1,	 0,    2,	 -1,	 -1,	 -1 }, /* P5 */
	{  0,	 1,    2,	  1,	 -1,	 -1 }, /* P6 */
	{  1,	 0,    2,	  1,	  1,	 -1 }, /* P7 */
};

static void bst_remap_sensor_data(struct bosch_sensor_data *data,
			const struct bosch_sensor_axis_remap *remap)
{
	struct bosch_sensor_data tmp;

	tmp.x = data->v[remap->src_x] * remap->sign_x;
	tmp.y = data->v[remap->src_y] * remap->sign_y;
	tmp.z = data->v[remap->src_z] * remap->sign_z;

	memcpy(data, &tmp, sizeof(*data));
}

static void bst_remap_sensor_data_dft_tab(struct bosch_sensor_data *data,
			int place)
{
/* sensor with place 0 needs not to be remapped */
	if ((place <= 0) || (place >= MAX_AXIS_REMAP_TAB_SZ))
		return;
	bst_remap_sensor_data(data, &bst_axis_remap_tab_dft[place]);
}

static void bmi_remap_sensor_data(struct bmi160_axis_data_t *val,
		struct bmi_client_data *client_data)
{
	struct bosch_sensor_data bsd;

	if ((NULL == client_data->bst_pd) ||
			(BOSCH_SENSOR_PLACE_UNKNOWN
			 == client_data->bst_pd->place))
		return;

	bsd.x = val->x;
	bsd.y = val->y;
	bsd.z = val->z;

	bst_remap_sensor_data_dft_tab(&bsd,
			client_data->bst_pd->place);

	val->x = bsd.x;
	val->y = bsd.y;
	val->z = bsd.z;

}

static void bmi_remap_data_acc(struct bmi_client_data *client_data,
				struct bmi160acc_t *acc_frame)
{
	struct bosch_sensor_data bsd;
	if ((NULL == client_data->bst_pd) ||
			(BOSCH_SENSOR_PLACE_UNKNOWN
			 == client_data->bst_pd->place))
		return;

	bsd.x = acc_frame->x;
	bsd.y = acc_frame->y;
	bsd.z = acc_frame->z;

	bst_remap_sensor_data_dft_tab(&bsd,
			client_data->bst_pd->place);

	acc_frame->x = bsd.x;
	acc_frame->y = bsd.y;
	acc_frame->z = bsd.z;


}

static void bmi_remap_data_gyro(struct bmi_client_data *client_data,
					struct bmi160gyro_t *gyro_frame)
{
	struct bosch_sensor_data bsd;

	if ((NULL == client_data->bst_pd) ||
			(BOSCH_SENSOR_PLACE_UNKNOWN
			 == client_data->bst_pd->place))
		return;

	bsd.x = gyro_frame->x;
	bsd.y = gyro_frame->y;
	bsd.z = gyro_frame->z;

	bst_remap_sensor_data_dft_tab(&bsd,
			client_data->bst_pd->place);

	gyro_frame->x = bsd.x;
	gyro_frame->y = bsd.y;
	gyro_frame->z = bsd.z;


}

static void bmi_fifo_frame_bytes_extend_calc(
	struct bmi_client_data *client_data,
	unsigned int *fifo_frmbytes_extend)
{
	switch (client_data->fifo_data_sel) {
	case BMI_FIFO_A_SEL:
	case BMI_FIFO_G_SEL:
		*fifo_frmbytes_extend = 7;
		break;
	case BMI_FIFO_G_A_SEL:
		*fifo_frmbytes_extend = 13;
		break;
	case BMI_FIFO_M_SEL:
		*fifo_frmbytes_extend = 9;
		break;
	case BMI_FIFO_M_A_SEL:
	case BMI_FIFO_M_G_SEL:
		/*8(mag) + 6(gyro or acc) +1(head) = 15*/
		*fifo_frmbytes_extend = 15;
		break;
	case BMI_FIFO_M_G_A_SEL:
		/*8(mag) + 6(gyro or acc) + 6 + 1 = 21*/
		*fifo_frmbytes_extend = 21;
		break;
	default:
		*fifo_frmbytes_extend = 0;
		break;

	};

}

static int bmi_input_init(struct bmi_client_data *client_data)
{
	struct input_dev *dev;
	int err = 0;

	dev = input_allocate_device();
	if (NULL == dev)
		return -ENOMEM;

	dev->name = SENSOR_NAME;
	dev->id.bustype = BUS_I2C;

	input_set_capability(dev, EV_ABS, ABS_MISC);
	input_set_capability(dev, EV_MSC, INPUT_EVENT_SGM);
	input_set_capability(dev, EV_MSC, INPUT_EVENT_STEP_DETECTOR);
	input_set_drvdata(dev, client_data);

	err = input_register_device(dev);
	if (err < 0) {
		input_free_device(dev);
		dev_notice(client_data->dev, "bmi160 input free!\n");
		return err;
	}
	client_data->input = dev;
	dev_notice(client_data->dev,
		"bmi160 input register successfully, %s!\n",
		client_data->input->name);
	return err;
}


static void bmi_input_destroy(struct bmi_client_data *client_data)
{
	struct input_dev *dev = client_data->input;

	input_unregister_device(dev);
	input_free_device(dev);
}

static int bmi_check_chip_id(struct bmi_client_data *client_data)
{
	int8_t err = 0;
	int8_t i = 0;
	uint8_t chip_id = 0;
	uint8_t read_count = 0;
	u8 bmi_sensor_cnt = sizeof(sensor_type_map)
				/ sizeof(struct bmi160_type_mapping_type);
	/* read and check chip id */
	while (read_count++ < CHECK_CHIP_ID_TIME_MAX) {
		if (client_data->device.bus_read(client_data->device.dev_addr,
				BMI_REG_NAME(USER_CHIP_ID), &chip_id, 1) < 0) {

			dev_err(client_data->dev,
					"Bosch Sensortec Device not found"
						"read chip_id:%d\n", chip_id);
			continue;
		} else {
			for (i = 0; i < bmi_sensor_cnt; i++) {
				if (sensor_type_map[i].chip_id == chip_id) {
					client_data->chip_id = chip_id;
					dev_notice(client_data->dev,
					"Bosch Sensortec Device detected, "
			"HW IC name: %s\n", sensor_type_map[i].sensor_name);
					break;
				}
			}
			if (i < bmi_sensor_cnt)
				break;
			else {
				if (read_count == CHECK_CHIP_ID_TIME_MAX) {
					dev_err(client_data->dev,
				"Failed!Bosch Sensortec Device not found"
					" mismatch chip_id:%d\n", chip_id);
					err = -ENODEV;
					return err;
				}
			}
			mdelay(1);
		}
	}
	return err;

}

static int bmi_pmu_set_suspend(struct bmi_client_data *client_data)
{
	int err = 0;
	if (client_data == NULL)
		return -EINVAL;
	else {
		err += BMI_CALL_API(set_command_register)
				(bmi_pmu_cmd_acc_arr[SENSOR_PM_SUSPEND]);
		err += BMI_CALL_API(set_command_register)
				(bmi_pmu_cmd_gyro_arr[SENSOR_PM_SUSPEND]);
		err += BMI_CALL_API(set_command_register)
				(bmi_pmu_cmd_mag_arr[SENSOR_PM_SUSPEND]);
		client_data->pw.acc_pm = BMI_ACC_PM_SUSPEND;
		client_data->pw.gyro_pm = BMI_GYRO_PM_SUSPEND;
		client_data->pw.mag_pm = BMI_MAG_PM_SUSPEND;
	}
	return err;
}

static int bmi_get_err_status(struct bmi_client_data *client_data)
{
	int err = 0;
	err = BMI_CALL_API(get_error_status)(&client_data->err_st.fatal_err,
		&client_data->err_st.err_code, &client_data->err_st.i2c_fail,
	&client_data->err_st.drop_cmd, &client_data->err_st.mag_drdy_err);
	return err;
}

static void bmi_work_func(struct work_struct *work)
{
	struct bmi_client_data *client_data =
		container_of((struct delayed_work *)work,
			struct bmi_client_data, work);
	unsigned long delay =
		msecs_to_jiffies(atomic_read(&client_data->delay));

	/* TODO */
	/*report current frame via input event*/
	/*input_sync(client_data->input);*/
	schedule_delayed_work(&client_data->work, delay);
}

static ssize_t bmi160_chip_id_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);
	return sprintf(buf, "0x%x\n", client_data->chip_id);
}

static ssize_t bmi160_err_st_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);
	int err = 0;
	
	unsigned char err_st_all = 0xff;
	err = bmi_get_err_status(client_data);
	if (err)
		return err;
	else {
		err_st_all = client_data->err_st.err_st_all;
		return sprintf(buf, "0x%x\n", err_st_all);
	}
}

static ssize_t bmi160_sensor_time_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int err = 0;
	u32 sensor_time;
	err = BMI_CALL_API(get_sensor_time)(&sensor_time);
	if (err)
		return err;
	else
		return sprintf(buf, "0x%x\n", (unsigned int)sensor_time);
}

static ssize_t bmi160_fifo_full_stop_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	u8 data = 0;
	BMI_CALL_API(get_fifo_stop_on_full)(&data);
	return sprintf(buf, "%d\n", data);

}

static ssize_t bmi160_fifo_full_stop_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	int err;
	unsigned long data;
	err = kstrtoul(buf, 10, &data);
	if (err)
		return err;
	err = BMI_CALL_API(set_fifo_stop_on_full)(data);
	if (err)
		return err;

	return count;
}

static ssize_t bmi160_fifo_flush_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	int err;
	unsigned long enable;
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);
	err = kstrtoul(buf, 10, &enable);
	if (err)
		return err;
	if (enable)
		err = BMI_CALL_API(set_command_register)(CMD_CLR_FIFO_DATA);

	if (err)
		dev_err(client_data->dev, "fifo flush failed!\n");

	return count;

}


static ssize_t bmi160_fifo_bytecount_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int err;
	unsigned int fifo_bytecount = 0;
	BMI_CALL_API(fifo_length)(&fifo_bytecount);
	err = sprintf(buf, "%u\n", fifo_bytecount);
	return err;
}

static ssize_t bmi160_fifo_bytecount_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);
	int err;
	unsigned long data;
	err = kstrtoul(buf, 10, &data);
	if (err)
		return err;
	client_data->fifo_bytecount = (unsigned int) data;

	return count;
}

int bmi160_fifo_data_sel_get(struct bmi_client_data *client_data)
{
	int err = 0;
	unsigned char fifo_acc_en, fifo_gyro_en, fifo_mag_en;
	unsigned char fifo_datasel;
	err += BMI_CALL_API(get_fifo_acc_en)(&fifo_acc_en);
	err += BMI_CALL_API(get_fifo_gyro_en)(&fifo_gyro_en);
	err += BMI_CALL_API(get_fifo_mag_en)(&fifo_mag_en);

	if (err)
		return err;

	fifo_datasel = (fifo_acc_en << BMI_ACC_SENSOR) |
			(fifo_gyro_en << BMI_GYRO_SENSOR) |
				(fifo_mag_en << BMI_MAG_SENSOR);

	client_data->fifo_data_sel = fifo_datasel;

	return err;


}

static ssize_t bmi160_fifo_data_sel_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int err = 0;
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);
	err = bmi160_fifo_data_sel_get(client_data);
	if (err)
		return -EINVAL;
	return sprintf(buf, "%d\n", client_data->fifo_data_sel);
}

/* write any value to clear all the fifo data. */
static ssize_t bmi160_fifo_data_sel_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);
	int err;
	unsigned long data;
	unsigned char fifo_datasel;
	err = kstrtoul(buf, 10, &data);
	if (err)
		return err;
	/* data format: aimed 0b0000 0x(m)x(g)x(a), x:1 enable, 0:disable*/
	if (data > 7)
		return -EINVAL;


	fifo_datasel = (unsigned char)data;


	err += BMI_CALL_API(set_fifo_acc_en)
			((fifo_datasel & (1 << BMI_ACC_SENSOR)) ? 1 :  0);
	err += BMI_CALL_API(set_fifo_gyro_en)
			(fifo_datasel & (1 << BMI_GYRO_SENSOR) ? 1 : 0);
	err += BMI_CALL_API(set_fifo_mag_en)
			((fifo_datasel & (1 << BMI_MAG_SENSOR)) ? 1 : 0);

	/*err += BMI_CALL_API(set_command_register)(CMD_CLR_FIFO_DATA);*/
	if (err)
		return -EIO;
	else {
		dev_notice(client_data->dev, "FIFO A_en:%d, G_en:%d, M_en:%d\n",
			(fifo_datasel & (1 << BMI_ACC_SENSOR)) ? 1 :  0,
			(fifo_datasel & (1 << BMI_GYRO_SENSOR) ? 1 : 0),
			((fifo_datasel & (1 << BMI_MAG_SENSOR)) ? 1 : 0));
		client_data->fifo_data_sel = fifo_datasel;
	}

	return count;
}

static int bmi_fifo_analysis_handle(struct bmi_client_data *client_data,
				u8 *fifo_data, u16 fifo_length, char *buf)
{
	u8 frame_head = 0;/* every frame head*/
	int len = 0;

	/*u8 skip_frame_cnt = 0;*/
	u8 acc_frm_cnt = 0;/*0~146*/
	u8 gyro_frm_cnt = 0;
	u8 mag_frm_cnt = 0;
	u8 tmp_frm_cnt = 0;
	/*u8 tmp_odr = 0;*/
	/*uint64_t current_apts_us = 0;*/
	/*fifo data last frame start_index A G M*/
	u64 fifo_time = 0;
	static u32 current_frm_ts;
	u16 fifo_index = 0;/* fifo data buff index*/
	u16 fifo_index_tmp = 0;
	u16 i = 0;
	s8 last_return_st = 0;
	int err = 0;
	unsigned int frame_bytes = 0;
	struct bmi160mag_t mag;
	struct bmi160_mag_xyz mag_comp_xyz;
	struct bmi160acc_t acc_frame_arr[FIFO_FRAME_CNT];
	struct bmi160gyro_t gyro_frame_arr[FIFO_FRAME_CNT];
	struct bmi160mag_t mag_frame_arr[FIFO_FRAME_CNT];

	struct odr_t odr;
	memset(&odr, 0, sizeof(odr));
	memset(&mag, 0, sizeof(mag));
	memset(&mag_comp_xyz, 0, sizeof(mag_comp_xyz));
	for (i = 0; i < FIFO_FRAME_CNT; i++) {
		memset(&mag_frame_arr[i], 0, sizeof(struct bmi160mag_t));
		memset(&acc_frame_arr[i], 0, sizeof(struct bmi160acc_t));
		memset(&gyro_frame_arr[i], 0, sizeof(struct bmi160gyro_t));
	}
	/*current_apts_us = get_current_timestamp();*/
	/* no fifo select for bmi sensor*/
	if (!client_data->fifo_data_sel) {
		dev_err(client_data->dev,
				"No select any sensor FIFO for BMI16x\n");
		return -EINVAL;
	}
	/*driver need read acc_odr/gyro_odr/mag_odr*/
	if ((client_data->fifo_data_sel) & (1 << BMI_ACC_SENSOR))
		odr.acc_odr = client_data->odr.acc_odr;
	if ((client_data->fifo_data_sel) & (1 << BMI_GYRO_SENSOR))
		odr.gyro_odr = client_data->odr.gyro_odr;
	if ((client_data->fifo_data_sel) & (1 << BMI_MAG_SENSOR))
		odr.mag_odr = client_data->odr.mag_odr;
	bmi_fifo_frame_bytes_extend_calc(client_data, &frame_bytes);
/* search sensor time sub function firstly */
	for (fifo_index = 0; fifo_index < fifo_length;) {
		/* conside limited HW i2c burst reading issue,
		need to re-calc index 256 512 768 1024...*/
		if ((fifo_index_tmp >> 8) != (fifo_index >> 8)) {
			if (fifo_data[fifo_index_tmp] ==
				fifo_data[(fifo_index >> 8)<<8]) {
				fifo_index = (fifo_index >> 8) << 8;
				fifo_length +=
					(fifo_index - fifo_index_tmp + 1);
			}
		}
		fifo_index_tmp = fifo_index;
		/* compare index with 256/512/ before doing parsing*/
		if (((fifo_index + frame_bytes) >> 8) != (fifo_index >> 8)) {
			fifo_index = ((fifo_index + frame_bytes) >> 8) << 8;
			continue;
		}

		frame_head = fifo_data[fifo_index];

		switch (frame_head) {
			/*skip frame 0x40 22 0x84*/
		case FIFO_HEAD_SKIP_FRAME:
		/*fifo data frame index + 1*/
			fifo_index = fifo_index + 1;
			if (fifo_index + 1 > fifo_length) {
				last_return_st = FIFO_SKIP_OVER_LEN;
				break;
			}
			/*skip_frame_cnt = fifo_data[fifo_index];*/
			fifo_index = fifo_index + 1;
		break;

			/*M & G & A*/
		case FIFO_HEAD_M_G_A:
		{/*fifo data frame index + 1*/
			fifo_index = fifo_index + 1;
			if (fifo_index + MGA_BYTES_FRM > fifo_length) {
				last_return_st = FIFO_M_G_A_OVER_LEN;
				break;
			}

			/* mag frm index = gyro */
			mag_frm_cnt = gyro_frm_cnt;
			mag_frame_arr[mag_frm_cnt].x =
				fifo_data[fifo_index + 1] << 8 |
					fifo_data[fifo_index + 0];
			mag_frame_arr[mag_frm_cnt].y =
				fifo_data[fifo_index + 3] << 8 |
					fifo_data[fifo_index + 2];
			mag_frame_arr[mag_frm_cnt].z =
				fifo_data[fifo_index + 5] << 8 |
					fifo_data[fifo_index + 4];
			mag_frame_arr[mag_frm_cnt].r =
				fifo_data[fifo_index + 7] << 8 |
					fifo_data[fifo_index + 6];

			gyro_frame_arr[gyro_frm_cnt].x =
				fifo_data[fifo_index + 9] << 8 |
					fifo_data[fifo_index + 8];
			gyro_frame_arr[gyro_frm_cnt].y =
				fifo_data[fifo_index + 11] << 8 |
					fifo_data[fifo_index + 10];
			gyro_frame_arr[gyro_frm_cnt].z =
				fifo_data[fifo_index + 13] << 8 |
					fifo_data[fifo_index + 12];

			acc_frame_arr[acc_frm_cnt].x =
				fifo_data[fifo_index + 15] << 8 |
					fifo_data[fifo_index + 14];
			acc_frame_arr[acc_frm_cnt].y =
				fifo_data[fifo_index + 17] << 8 |
					fifo_data[fifo_index + 16];
			acc_frame_arr[acc_frm_cnt].z =
				fifo_data[fifo_index + 19] << 8 |
					fifo_data[fifo_index + 18];

			mag_frm_cnt++;/* M fram_cnt++ */
			gyro_frm_cnt++;/* G fram_cnt++ */
			acc_frm_cnt++;/* A fram_cnt++ */

			fifo_index = fifo_index + MGA_BYTES_FRM;
			break;
		}

		case FIFO_HEAD_M_A:
		{/*fifo data frame index + 1*/
			fifo_index = fifo_index + 1;
			if (fifo_index + MA_BYTES_FRM > fifo_length) {
				last_return_st = FIFO_M_A_OVER_LEN;
				break;
			}

			mag_frm_cnt = acc_frm_cnt;

			mag_frame_arr[mag_frm_cnt].x =
				fifo_data[fifo_index + 1] << 8 |
					fifo_data[fifo_index + 0];
			mag_frame_arr[mag_frm_cnt].y =
				fifo_data[fifo_index + 3] << 8 |
					fifo_data[fifo_index + 2];
			mag_frame_arr[mag_frm_cnt].z =
				fifo_data[fifo_index + 5] << 8 |
					fifo_data[fifo_index + 4];
			mag_frame_arr[mag_frm_cnt].r =
				fifo_data[fifo_index + 7] << 8 |
					fifo_data[fifo_index + 6];

			acc_frame_arr[acc_frm_cnt].x =
				fifo_data[fifo_index + 9] << 8 |
					fifo_data[fifo_index + 8];
			acc_frame_arr[acc_frm_cnt].y =
				fifo_data[fifo_index + 11] << 8 |
					fifo_data[fifo_index + 10];
			acc_frame_arr[acc_frm_cnt].z =
				fifo_data[fifo_index + 13] << 8 |
					fifo_data[fifo_index + 12];

			mag_frm_cnt++;/* M fram_cnt++ */
			acc_frm_cnt++;/* A fram_cnt++ */

			fifo_index = fifo_index + MA_BYTES_FRM;
			break;
		}

		case FIFO_HEAD_M_G:
		{/*fifo data frame index + 1*/
			fifo_index = fifo_index + 1;
			if (fifo_index + MG_BYTES_FRM > fifo_length) {
				last_return_st = FIFO_M_G_OVER_LEN;
				break;
			}

			mag_frm_cnt = gyro_frm_cnt;
			mag_frame_arr[mag_frm_cnt].x =
				fifo_data[fifo_index + 1] << 8 |
					fifo_data[fifo_index + 0];
			mag_frame_arr[mag_frm_cnt].y =
				fifo_data[fifo_index + 3] << 8 |
					fifo_data[fifo_index + 2];
			mag_frame_arr[mag_frm_cnt].z =
				fifo_data[fifo_index + 5] << 8 |
					fifo_data[fifo_index + 4];
			mag_frame_arr[mag_frm_cnt].r =
				fifo_data[fifo_index + 7] << 8 |
					fifo_data[fifo_index + 6];

			gyro_frame_arr[gyro_frm_cnt].x =
				fifo_data[fifo_index + 9] << 8 |
					fifo_data[fifo_index + 8];
			gyro_frame_arr[gyro_frm_cnt].y =
				fifo_data[fifo_index + 11] << 8 |
					fifo_data[fifo_index + 10];
			gyro_frame_arr[gyro_frm_cnt].z =
				fifo_data[fifo_index + 13] << 8 |
					fifo_data[fifo_index + 12];

			mag_frm_cnt++;/* M fram_cnt++ */
			gyro_frm_cnt++;/* G fram_cnt++ */
			fifo_index = fifo_index + MG_BYTES_FRM;
		break;
		}

		case FIFO_HEAD_G_A:
		{	/*fifo data frame index + 1*/
			fifo_index = fifo_index + 1;
			if (fifo_index + GA_BYTES_FRM > fifo_length) {
				last_return_st = FIFO_G_A_OVER_LEN;
				break;
			}
			gyro_frame_arr[gyro_frm_cnt].x =
				fifo_data[fifo_index + 1] << 8 |
					fifo_data[fifo_index + 0];
			gyro_frame_arr[gyro_frm_cnt].y =
				fifo_data[fifo_index + 3] << 8 |
					fifo_data[fifo_index + 2];
			gyro_frame_arr[gyro_frm_cnt].z =
				fifo_data[fifo_index + 5] << 8 |
					fifo_data[fifo_index + 4];

			acc_frame_arr[acc_frm_cnt].x =
				fifo_data[fifo_index + 7] << 8 |
					fifo_data[fifo_index + 6];
			acc_frame_arr[acc_frm_cnt].y =
				fifo_data[fifo_index + 9] << 8 |
					fifo_data[fifo_index + 8];
			acc_frame_arr[acc_frm_cnt].z =
				fifo_data[fifo_index + 11] << 8 |
					fifo_data[fifo_index + 10];

			bmi_remap_data_gyro(client_data,
				&gyro_frame_arr[gyro_frm_cnt]);
			bmi_remap_data_acc(client_data,
				&acc_frame_arr[acc_frm_cnt]);

			gyro_frm_cnt++;
			acc_frm_cnt++;
			fifo_index = fifo_index + GA_BYTES_FRM;

			break;
		}
		case FIFO_HEAD_A:
		{	/*fifo data frame index + 1*/
			fifo_index = fifo_index + 1;
			if (fifo_index + A_BYTES_FRM > fifo_length) {
				last_return_st = FIFO_A_OVER_LEN;
				break;
			}

			acc_frame_arr[acc_frm_cnt].x =
				fifo_data[fifo_index + 1] << 8 |
					fifo_data[fifo_index + 0];
			acc_frame_arr[acc_frm_cnt].y =
				fifo_data[fifo_index + 3] << 8 |
					fifo_data[fifo_index + 2];
			acc_frame_arr[acc_frm_cnt].z =
				fifo_data[fifo_index + 5] << 8 |
					fifo_data[fifo_index + 4];

			bmi_remap_data_acc(client_data,
				&acc_frame_arr[acc_frm_cnt]);

			acc_frm_cnt++;/*acc_frm_cnt*/
			fifo_index = fifo_index + A_BYTES_FRM;
			break;
		}
		case FIFO_HEAD_G:
		{	/*fifo data frame index + 1*/
			fifo_index = fifo_index + 1;
			if (fifo_index + G_BYTES_FRM > fifo_length) {
				last_return_st = FIFO_G_OVER_LEN;
				break;
			}

			gyro_frame_arr[gyro_frm_cnt].x =
				fifo_data[fifo_index + 1] << 8 |
					fifo_data[fifo_index + 0];
			gyro_frame_arr[gyro_frm_cnt].y =
				fifo_data[fifo_index + 3] << 8 |
					fifo_data[fifo_index + 2];
			gyro_frame_arr[gyro_frm_cnt].z =
				fifo_data[fifo_index + 5] << 8 |
					fifo_data[fifo_index + 4];

			bmi_remap_data_gyro(client_data,
				&gyro_frame_arr[gyro_frm_cnt]);

			gyro_frm_cnt++;/*gyro_frm_cnt*/

			fifo_index = fifo_index + G_BYTES_FRM;
			break;
		}
		case FIFO_HEAD_M:
		{	/*fifo data frame index + 1*/
			fifo_index = fifo_index + 1;
			if (fifo_index + A_BYTES_FRM > fifo_length) {
				last_return_st = FIFO_M_OVER_LEN;
				break;
			}

			mag_frame_arr[mag_frm_cnt].x =
				fifo_data[fifo_index + 1] << 8 |
					fifo_data[fifo_index + 0];
			mag_frame_arr[mag_frm_cnt].y =
				fifo_data[fifo_index + 3] << 8 |
					fifo_data[fifo_index + 2];
			mag_frame_arr[mag_frm_cnt].z =
				fifo_data[fifo_index + 5] << 8 |
					fifo_data[fifo_index + 4];
			mag_frame_arr[mag_frm_cnt].r =
				fifo_data[fifo_index + 7] << 8 |
					fifo_data[fifo_index + 6];

			mag_frm_cnt++;/* M fram_cnt++ */

			fifo_index = fifo_index + A_BYTES_FRM;
			break;
		}

		/* sensor time frame*/
		case FIFO_HEAD_SENSOR_TIME:
		{
			/*fifo data frame index + 1*/
			fifo_index = fifo_index + 1;

			if (fifo_index + 3 > fifo_length) {
				last_return_st = FIFO_SENSORTIME_RETURN;
				break;
			}
			fifo_time =
				fifo_data[fifo_index + 2] << 16 |
				fifo_data[fifo_index + 1] << 8 |
				fifo_data[fifo_index + 0];

			client_data->fifo_time = fifo_time;
			/*fifo sensor time frame index + 3*/
			fifo_index = fifo_index + 3;
			break;
		}
		case FIFO_HEAD_OVER_READ_LSB:
			/*fifo data frame index + 1*/
			fifo_index = fifo_index + 1;

			if (fifo_index + 1 > fifo_length) {
				last_return_st = FIFO_OVER_READ_RETURN;
				break;
			}
			if (fifo_data[fifo_index] ==
					FIFO_HEAD_OVER_READ_MSB) {
				/*fifo over read frame index + 1*/
				fifo_index = fifo_index + 1;
				break;
			} else {
				last_return_st = FIFO_OVER_READ_RETURN;
				break;
			}

		default:
			last_return_st = 1;
			break;

			}
			if (last_return_st)
				break;
		}
	fifo_time = 0;
/*current_frm_ts = current_apts_us -
((fifo_time & (sensortime_duration_tbl[odr.acc_odr].ts_delat)) +
(sensortime_duration_tbl[odr.acc_odr].ts_duration_lsb
*(acc_frm_cnt - i - 1)))*625/16;*/
/*Acc Only*/
	if (client_data->fifo_data_sel == BMI_FIFO_A_SEL) {
		for (i = 0; i < acc_frm_cnt; i++) {
			/*current_frm_ts += 256;*/
			current_frm_ts +=
		sensortime_duration_tbl[odr.acc_odr].ts_duration_us*LMADA;

			len = sprintf(buf, "%s %d %d %d %d ",
					ACC_FIFO_HEAD,
					acc_frame_arr[i].x,
					acc_frame_arr[i].y,
					acc_frame_arr[i].z,
					current_frm_ts);
			buf += len;
			err += len;
		}
	}


	/*only for G*/
	if (client_data->fifo_data_sel == BMI_FIFO_G_SEL) {
		for (i = 0; i < gyro_frm_cnt; i++) {
			/*current_frm_ts += 256;*/
			current_frm_ts +=
		sensortime_duration_tbl[odr.gyro_odr].ts_duration_us*LMADA;

			len = sprintf(buf, "%s %d %d %d %d ",
						GYRO_FIFO_HEAD,
						gyro_frame_arr[i].x,
						gyro_frame_arr[i].y,
						gyro_frame_arr[i].z,
						current_frm_ts
					);
			buf += len;
			err += len;
		}
	}

	/*only for M*/
	/*remove the related process of mag for avoid crash*/
	if(0)
	{
		if (client_data->fifo_data_sel == BMI_FIFO_M_SEL) {
			for (i = 0; i < mag_frm_cnt; i++) {
				/*current_frm_ts += 256;*/
				current_frm_ts +=
			sensortime_duration_tbl[odr.mag_odr].ts_duration_us*LMADA;

				mag.x = mag_frame_arr[i].x >> 3;
				mag.y = mag_frame_arr[i].y >> 3;
				mag.z = mag_frame_arr[i].z >> 1;
				mag.r = mag_frame_arr[i].r >> 2;
				bmi160_mag_compensate_xyz_raw(&mag_comp_xyz, mag);
				len = sprintf(buf, "%s %d %d %d %d ",
							MAG_FIFO_HEAD,
							mag_comp_xyz.x,
							mag_comp_xyz.y,
							mag_comp_xyz.z,
							current_frm_ts
						);

				buf += len;
				err += len;
			}

		}
	}

/*only for A G && A M G*/
if ((client_data->fifo_data_sel == BMI_FIFO_G_A_SEL) ||
		(client_data->fifo_data_sel == BMI_FIFO_M_G_A_SEL)) {

	for (i = 0; i < gyro_frm_cnt; i++) {
		/*sensor timeLSB*/
		/*dia(sensor_time) = fifo_time & (0xff), uint:LSB, 39.0625us*/
		/*AP tinmestamp 390625/10000 = 625 /16 */
		current_frm_ts +=
		sensortime_duration_tbl[odr.gyro_odr].ts_duration_us*LMADA;

		if (0) {
				mag.x = mag_frame_arr[i].x >> 3;
				mag.y = mag_frame_arr[i].y >> 3;
				mag.z = mag_frame_arr[i].z >> 1;
				mag.r = mag_frame_arr[i].r >> 2;
			bmi160_mag_compensate_xyz_raw(&mag_comp_xyz, mag);
				len = sprintf(buf,
			"%s %d %d %d %d %s %d %d %d %d %s %d %d %d %d ",
					GYRO_FIFO_HEAD,
					gyro_frame_arr[i].x,
					gyro_frame_arr[i].y,
					gyro_frame_arr[i].z,
					current_frm_ts,
					ACC_FIFO_HEAD,
					acc_frame_arr[i].x,
					acc_frame_arr[i].y,
					acc_frame_arr[i].z,
					current_frm_ts,
					MAG_FIFO_HEAD,
					mag_comp_xyz.x,
					mag_comp_xyz.y,
					mag_comp_xyz.z,
					current_frm_ts);
				buf += len;
				err += len;
		} else {
				len = sprintf(buf,
			"%s %d %d %d %d %s %d %d %d %d ",
					GYRO_FIFO_HEAD,
					gyro_frame_arr[i].x,
					gyro_frame_arr[i].y,
					gyro_frame_arr[i].z,
					current_frm_ts,
					ACC_FIFO_HEAD,
					acc_frame_arr[i].x,
					acc_frame_arr[i].y,
					acc_frame_arr[i].z,
					current_frm_ts
					);

				buf += len;
				err += len;
		}
	}

}

/*only for A M */
if (client_data->fifo_data_sel == BMI_FIFO_M_A_SEL) {
	for (i = 0; i < acc_frm_cnt; i++) {
		/*sensor timeLSB*/
		/*dia(sensor_time) = fifo_time & (0xff), uint:LSB, 39.0625us*/
		/*AP tinmestamp 390625/10000 = 625 /16 */
		/*current_frm_ts += 256;*/
		current_frm_ts +=
		sensortime_duration_tbl[odr.acc_odr].ts_duration_us*LMADA;

		if (0) {
				mag.x = mag_frame_arr[i].x >> 3;
				mag.y = mag_frame_arr[i].y >> 3;
				mag.z = mag_frame_arr[i].z >> 1;
				mag.r = mag_frame_arr[i].r >> 2;
			bmi160_mag_compensate_xyz_raw(&mag_comp_xyz, mag);
				len = sprintf(buf,
			"%s %d %d %d %d %s %d %d %d %d ",
					ACC_FIFO_HEAD,
					acc_frame_arr[i].x,
					acc_frame_arr[i].y,
					acc_frame_arr[i].z,
					current_frm_ts,
					MAG_FIFO_HEAD,
					mag_comp_xyz.x,
					mag_comp_xyz.y,
					mag_comp_xyz.z,
					current_frm_ts);
				buf += len;
				err += len;
		} else {
			len = sprintf(buf, "%s %d %d %d %d ",
					ACC_FIFO_HEAD,
					acc_frame_arr[i].x,
					acc_frame_arr[i].y,
					acc_frame_arr[i].z,
					current_frm_ts
					);

				buf += len;
				err += len;
		}
	}
}

/*only forG M*/
if (client_data->fifo_data_sel == BMI_FIFO_M_G_SEL) {
	if (gyro_frm_cnt) {
		tmp_frm_cnt = gyro_frm_cnt;
		/*tmp_odr = odr.gyro_odr;*/
	}

	for (i = 0; i < tmp_frm_cnt; i++) {
		current_frm_ts +=
		sensortime_duration_tbl[odr.gyro_odr].ts_duration_us*LMADA;
		if (0) {
			mag.x = mag_frame_arr[i].x >> 3;
			mag.y = mag_frame_arr[i].y >> 3;
			mag.z = mag_frame_arr[i].z >> 1;
			mag.r = mag_frame_arr[i].r >> 2;
			bmi160_mag_compensate_xyz_raw(&mag_comp_xyz, mag);
			len = sprintf(buf,
		"%s %d %d %d %d %s %d %d %d %d ",
				GYRO_FIFO_HEAD,
				gyro_frame_arr[i].x,
				gyro_frame_arr[i].y,
				gyro_frame_arr[i].z,
				current_frm_ts,
				MAG_FIFO_HEAD,
				mag_comp_xyz.x,
				mag_comp_xyz.y,
				mag_comp_xyz.z,
				current_frm_ts);
			buf += len;
			err += len;
		} else {

			len = sprintf(buf, "%s %d %d %d %d ",
				GYRO_FIFO_HEAD,
				gyro_frame_arr[i].x,
				gyro_frame_arr[i].y,
				gyro_frame_arr[i].z,
				current_frm_ts
				);

				buf += len;
				err += len;
		}
	}
}


	return err;


}


static ssize_t bmi160_fifo_data_out_frame_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);
	int err = 0;
	unsigned int fifo_bytecount_tmp;
	if (NULL == g_fifo_data_arr) {
			dev_err(client_data->dev,
				"no memory available in fifo_data_frame\n");
			return -ENOMEM;
	}
	if (client_data->pw.acc_pm == 2 && client_data->pw.gyro_pm == 2
					&& client_data->pw.mag_pm == 2) {
		dev_err(client_data->dev, "pw_acc: %d, pw_gyro: %d, pw_mag:%d\n",
			client_data->pw.acc_pm, client_data->pw.gyro_pm,
				client_data->pw.mag_pm);
		return -EINVAL;
	}
	if (!client_data->fifo_data_sel)
		return sprintf(buf,
			"no selsect sensor fifo, fifo_data_sel:%d\n",
						client_data->fifo_data_sel);

	if (client_data->fifo_bytecount == 0)
		return -EINVAL;

	g_current_apts_us = get_current_timestamp();

	BMI_CALL_API(fifo_length)(&fifo_bytecount_tmp);
	if (fifo_bytecount_tmp > client_data->fifo_bytecount)
		client_data->fifo_bytecount = fifo_bytecount_tmp;
	if (client_data->fifo_bytecount > 210) {
		err += BMI_CALL_API(set_command_register)(CMD_CLR_FIFO_DATA);
		client_data->fifo_bytecount = 210;
	}
	if (!err) {
		memset(g_fifo_data_arr, 0, 2048);
		err = bmi_burst_read_wrapper(client_data->device.dev_addr,
			BMI160_USER_FIFO_DATA__REG, g_fifo_data_arr,
						client_data->fifo_bytecount);
	} else
		dev_err(client_data->dev, "read fifo leght err");
	if (err) {
		dev_err(client_data->dev, "brust read fifo err\n");
		return err;
	}
		err = bmi_fifo_analysis_handle(client_data, g_fifo_data_arr,
			client_data->fifo_bytecount, buf);


	return err;
}

static ssize_t bmi160_fifo_watermark_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int err;
	unsigned char data = 0xff;
	err = BMI_CALL_API(get_fifo_watermark)(&data);

	if (err)
		return err;
	return sprintf(buf, "%d\n", data);
}

static ssize_t bmi160_fifo_watermark_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	int err;
	unsigned long data;
	unsigned char fifo_watermark;

	err = kstrtoul(buf, 10, &data);
	if (err)
		return err;

	fifo_watermark = (unsigned char)data;
	err = BMI_CALL_API(set_fifo_watermark)(fifo_watermark);
	if (err)
		return -EIO;

	return count;
}


static ssize_t bmi160_fifo_header_en_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int err;
	unsigned char data = 0xff;
	err = BMI_CALL_API(get_fifo_header_en)(&data);

	if (err)
		return err;
	return sprintf(buf, "%d\n", data);
}

static ssize_t bmi160_fifo_header_en_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);
	int err;
	unsigned long data;
	unsigned char fifo_header_en;
	err = kstrtoul(buf, 10, &data);
	if (err)
		return err;
	if (data > 1)
		return -ENOENT;

	fifo_header_en = (unsigned char)data;
	err = BMI_CALL_API(set_fifo_header_en)(fifo_header_en);
	if (err)
		return -EIO;

	client_data->fifo_head_en = fifo_header_en;

	return count;
}

static ssize_t bmi160_fifo_time_en_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int err;
	unsigned char data = 0;
	err = BMI_CALL_API(get_fifo_time_en)(&data);

	if (!err)
		err = sprintf(buf, "%d\n", data);

	return err;
}

static ssize_t bmi160_fifo_time_en_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	int err;
	unsigned long data;
	unsigned char fifo_ts_en;

	err = kstrtoul(buf, 10, &data);
	if (err)
		return err;
	fifo_ts_en = (unsigned char)data;

	err = BMI_CALL_API(set_fifo_time_en)(fifo_ts_en);
	if (err)
		return -EIO;

	return count;
}

static ssize_t bmi160_fifo_int_tag_en_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int err = 0;
	unsigned char fifo_tag_int1 = 0;
	unsigned char fifo_tag_int2 = 0;
	unsigned char fifo_tag_int;
	err += BMI_CALL_API(get_fifo_tag_int1_en)(&fifo_tag_int1);
	err += BMI_CALL_API(get_fifo_tag_int1_en)(&fifo_tag_int2);

	fifo_tag_int = (fifo_tag_int1 << BMI160_INT0) |
			(fifo_tag_int2 << BMI160_INT1);

	if (!err)
		err = sprintf(buf, "%d\n", fifo_tag_int);

	return err;
}

static ssize_t bmi160_fifo_int_tag_en_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);
	int err;
	unsigned long data;
	unsigned char fifo_tag_int_en;

	err = kstrtoul(buf, 10, &data);
	if (err)
		return err;
	if (data > 3)
		return -EINVAL;
	fifo_tag_int_en = (unsigned char)data;

	err += BMI_CALL_API(set_fifo_tag_int1_en)
			((fifo_tag_int_en & (1 << BMI160_INT0)) ? 1 :  0);
	err += BMI_CALL_API(set_fifo_tag_int1_en)
			((fifo_tag_int_en & (1 << BMI160_INT1)) ? 1 :  0);

	if (err) {
		dev_err(client_data->dev, "fifo int tag en err:%d\n", err);
		return -EIO;
	}
	client_data->fifo_int_tag_en = fifo_tag_int_en;

	return count;
}

static int bmi160_set_acc_op_mode(struct bmi_client_data *client_data,
							unsigned long op_mode)
{
	int err = 0;
	unsigned char stc_enable;
	mutex_lock(&client_data->mutex_op_mode);

	if (op_mode < BMI_ACC_PM_MAX) {
		switch (op_mode) {
		case BMI_ACC_PM_NORMAL:
			err = BMI_CALL_API(set_command_register)
			(bmi_pmu_cmd_acc_arr[BMI_ACC_PM_NORMAL]);
			client_data->pw.acc_pm = BMI_ACC_PM_NORMAL;
			client_data->sensor_status.acc_status = BMI_ACC_PM_NORMAL;
			mdelay(10);
			break;
		case BMI_ACC_PM_LP1:
			err = BMI_CALL_API(set_command_register)
			(bmi_pmu_cmd_acc_arr[BMI_ACC_PM_LP1]);
			client_data->pw.acc_pm = BMI_ACC_PM_LP1;
			client_data->sensor_status.acc_status = BMI_ACC_PM_LP1;
			mdelay(3);
			break;
		case BMI_ACC_PM_SUSPEND:
			BMI_CALL_API(get_step_counter_enable)(&stc_enable);
			if (stc_enable == 0) {
				err = BMI_CALL_API(set_command_register)
				(bmi_pmu_cmd_acc_arr[BMI_ACC_PM_SUSPEND]);
				client_data->pw.acc_pm = BMI_ACC_PM_SUSPEND;
				client_data->sensor_status.acc_status = BMI_ACC_PM_SUSPEND;
				mdelay(10);
			}
			break;
		case BMI_ACC_PM_LP2:
			err = BMI_CALL_API(set_command_register)
			(bmi_pmu_cmd_acc_arr[BMI_ACC_PM_LP2]);
			client_data->pw.acc_pm = BMI_ACC_PM_LP2;
			client_data->sensor_status.acc_status = BMI_ACC_PM_LP2;
			mdelay(3);
			break;
		default:
			mutex_unlock(&client_data->mutex_op_mode);
			return -EINVAL;
		}
	} else {
		mutex_unlock(&client_data->mutex_op_mode);
		return -EINVAL;
	}

	mutex_unlock(&client_data->mutex_op_mode);

	return err;


}

static ssize_t bmi160_temperature_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int err;
	s16 temp = 0xff;
	err = BMI_CALL_API(get_temperature)(&temp);

	if (!err)
		err = sprintf(buf, "0x%x\n", temp);

	return err;
}

static ssize_t bmi160_place_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);
	int place = BOSCH_SENSOR_PLACE_UNKNOWN;

	if (NULL != client_data->bst_pd)
		place = client_data->bst_pd->place;

	return sprintf(buf, "%d\n", place);
}

static ssize_t bmi160_delay_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);
	return sprintf(buf, "%d\n", atomic_read(&client_data->delay));

}

static ssize_t bmi160_delay_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);
	int err;
	unsigned long data;
	err = kstrtoul(buf, 10, &data);
	if (err)
		return err;

	if (data == 0) {
		err = -EINVAL;
		return err;
	}

	if (data < BMI_DELAY_MIN)
		data = BMI_DELAY_MIN;

	atomic_set(&client_data->delay, (unsigned int)data);

	return count;
}

static ssize_t bmi160_enable_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);
	return sprintf(buf, "%d\n", atomic_read(&client_data->wkqueue_en));

}

static ssize_t bmi160_enable_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);
	int err;
	unsigned long enable;
	int pre_enable = atomic_read(&client_data->wkqueue_en);
	err = kstrtoul(buf, 10, &enable);
	if (err)
		return err;

	enable = enable ? 1 : 0;
	mutex_lock(&client_data->mutex_enable);
	if (enable) {
		if (pre_enable == 0) {
			bmi160_set_acc_op_mode(client_data,
							BMI_ACC_PM_NORMAL);
			schedule_delayed_work(&client_data->work,
			msecs_to_jiffies(atomic_read(&client_data->delay)));
			atomic_set(&client_data->wkqueue_en, 1);
		}

	} else {
		if (pre_enable == 1) {
			bmi160_set_acc_op_mode(client_data,
							BMI_ACC_PM_SUSPEND);

			cancel_delayed_work_sync(&client_data->work);
			atomic_set(&client_data->wkqueue_en, 0);
		}
	}

	mutex_unlock(&client_data->mutex_enable);

	return count;
}

#if defined(BMI160_ENABLE_INT1) || defined(BMI160_ENABLE_INT2)
/* accel sensor part */
static ssize_t bmi160_anymot_duration_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int err;
	unsigned char data;
	err = BMI_CALL_API(get_int_anymotion_duration)(&data);

	if (err < 0)
		return err;
	return sprintf(buf, "%d\n", data);
}

static ssize_t bmi160_anymot_duration_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	unsigned long data;
	int err;
	err = kstrtoul(buf, 10, &data);
	if (err)
		return err;

	err = BMI_CALL_API(set_int_anymotion_duration)((unsigned char)data);
	if (err < 0)
		return -EIO;

	return count;
}

static ssize_t bmi160_anymot_threshold_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	unsigned char data;
	int err;

	err = BMI_CALL_API(get_int_anymotion_threshold)(&data);

	if (err < 0)
		return err;
	return sprintf(buf, "%d\n", data);
}

static ssize_t bmi160_anymot_threshold_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	unsigned long data;
	int err;
	err = kstrtoul(buf, 10, &data);
	if (err)
		return err;

	err = BMI_CALL_API(set_int_anymotion_threshold)((unsigned char)data);

	if (err < 0)
		return -EIO;
	return count;
}

static ssize_t bmi160_step_detector_status_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	u8 data = 0;
	u8 step_det;
	int err;
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);
	err = BMI_CALL_API(get_stepdetector_enable)(&step_det);
	/*bmi160_get_status0_step_int*/
	if (err < 0)
		return err;
/*client_data->std will be updated in bmi_stepdetector_interrupt_handle */
	if ((step_det == 1) && (client_data->std == 1)) {
		data = 1;
		client_data->std = 0;
		}
	else {
		data = 0;
		}
	return snprintf(buf, 16, "%d\n", data);
}

static ssize_t bmi160_step_detector_enable_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	unsigned char data;
	int err;
	err = BMI_CALL_API(get_stepdetector_enable)(&data);

	if (err < 0)
		return err;
	return sprintf(buf, "%d\n", data);
}

static ssize_t bmi160_step_detector_enable_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	unsigned long data;
	int err;

	err = kstrtoul(buf, 10, &data);
	if (err)
		return err;
	err = BMI_CALL_API(set_stepdetector_enable)((unsigned char)data);

	if (err < 0)
		return -EIO;
	return count;
}


static int sigmotion_enable_interrupts(u8 sig_map_int_pin)
{
	int ret = 0;
/*0x60  */
	ret += bmi160_set_int_anymotion_threshold(0x1e);
/* 0x62(bit 3~2)	0=1.5s */
	ret += bmi160_set_int_significant_motion_skip(0);
/*0x62(bit 5~4)	1=0.5s*/
	ret += bmi160_set_int_significant_motion_proof(1);
/*0x50 (bit 0, 1, 2)  INT_EN_0 anymo x y z*/
	ret += bmi160_map_significant_motion_interrupt(sig_map_int_pin);
/*0x62 (bit 1) INT_MOTION_3	int_sig_mot_sel*/
	ret += bmi160_set_int_significant_motion_select(1);
	if (ret)
		printk(KERN_ERR "bmi160 sig motion failed setting,%d!\n", ret);
	return ret;

}
#endif

static ssize_t bmi160_acc_range_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int err;
	unsigned char range;
	err = BMI_CALL_API(get_acc_range)(&range);
	if (err)
		return err;
	return sprintf(buf, "%d\n", range);
}

static ssize_t bmi160_acc_range_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	int err;
	unsigned long range;
	err = kstrtoul(buf, 10, &range);
	if (err)
		return err;

	err = BMI_CALL_API(set_acc_range)(range);
	if (err)
		return -EIO;

	return count;
}

static ssize_t bmi160_acc_odr_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int err;
	unsigned char acc_odr;
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);
	err = BMI_CALL_API(get_acc_outputdatarate)(&acc_odr);
	if (err)
		return err;

	client_data->odr.acc_odr = acc_odr;
	return sprintf(buf, "%d\n", acc_odr);
}

static ssize_t bmi160_acc_odr_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	int err;
	unsigned long acc_odr;
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);
	err = kstrtoul(buf, 10, &acc_odr);
	if (err)
		return err;

	if (acc_odr < 1 || acc_odr > 12)
		return -EIO;

	if (acc_odr < 5)
		err = BMI_CALL_API(set_accel_undersampling_parameter)(1);
	else
		err = BMI_CALL_API(set_accel_undersampling_parameter)(0);

	if (err)
		return err;

	err = BMI_CALL_API(set_acc_outputdatarate)(acc_odr);
	if (err)
		return -EIO;
	client_data->odr.acc_odr = acc_odr;
	return count;
}

static ssize_t bmi160_acc_op_mode_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);
	return sprintf(buf, "%d\n", client_data->pw.acc_pm);
}

static ssize_t bmi160_acc_op_mode_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);
	int err;
	unsigned long op_mode;
	err = kstrtoul(buf, 10, &op_mode);
	if (err)
		return err;

	err = bmi160_set_acc_op_mode(client_data, op_mode);
	if (err)
		return err;
	else
		return count;

}

static ssize_t bmi160_acc_value_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);
	struct bmi160acc_t data;
	struct bmi160_axis_data_t bmi160_udata;
	int err;
	err = BMI_CALL_API(read_acc_xyz)(&data);
	if (err < 0)
		return err;

	bmi160_udata.x = data.x;
	bmi160_udata.y = data.y;
	bmi160_udata.z = data.z;

	bmi_remap_sensor_data(&bmi160_udata, client_data);
	return sprintf(buf, "%hd %hd %hd\n",
			bmi160_udata.x, bmi160_udata.y, bmi160_udata.z);
}

static ssize_t bmi160_acc_fast_calibration_x_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	unsigned char data;
	int err;
	err = BMI_CALL_API(get_foc_acc_x)(&data);

	if (err < 0)
		return err;
	return sprintf(buf, "%d\n", data);
}

static ssize_t bmi160_acc_fast_calibration_x_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	unsigned long data;
	int err;
	s8 accel_offset_x = 0;
	err = kstrtoul(buf, 10, &data);
	if (err)
		return err;
	/* 0: disable, 1: +1g, 2: -1g, 3: 0g */
	if (data > 3)
		return -EINVAL;

	err = BMI_CALL_API(set_accel_foc_trigger)(X_AXIS,
					data, &accel_offset_x);
	if (err)
		return -EIO;
	return count;
}

static ssize_t bmi160_acc_fast_calibration_y_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	unsigned char data;
	int err;

	err = BMI_CALL_API(get_foc_acc_y)(&data);

	if (err < 0)
		return err;
	return sprintf(buf, "%d\n", data);
}

static ssize_t bmi160_acc_fast_calibration_y_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	unsigned long data;
	int err;
	s8 accel_offset_y = 0;

	err = kstrtoul(buf, 10, &data);
	if (err)
		return err;
	/* 0: disable, 1: +1g, 2: -1g, 3: 0g */
	if (data > 3)
		return -EINVAL;

	err = BMI_CALL_API(set_accel_foc_trigger)(Y_AXIS,
				data, &accel_offset_y);
	if (err)
		return -EIO;

	return count;
}

static ssize_t bmi160_acc_fast_calibration_z_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	unsigned char data;
	int err;

	err = BMI_CALL_API(get_foc_acc_z)(&data);

	if (err < 0)
		return err;
	return sprintf(buf, "%d\n", data);
}

static ssize_t bmi160_acc_fast_calibration_z_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	unsigned long data;
	int err;
	s8 accel_offset_z = 0;

	err = kstrtoul(buf, 10, &data);
	if (err)
		return err;
	/* 0: disable, 1: +1g, 2: -1g, 3: 0g */
	if (data > 3)
		return -EINVAL;

	err = BMI_CALL_API(set_accel_foc_trigger)(Z_AXIS,
			data, &accel_offset_z);
	if (err)
		return -EIO;

	return count;
}

static ssize_t bmi160_acc_offset_x_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	unsigned char data;
	int err;

	err = BMI_CALL_API(get_acc_off_comp_xaxis)(&data);

	if (err < 0)
		return err;
	return sprintf(buf, "%d\n", data);
}


static ssize_t bmi160_acc_offset_x_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	unsigned long data;
	int err;

	err = kstrtoul(buf, 10, &data);
	if (err)
		return err;

	err = BMI_CALL_API(set_accel_offset_compensation_xaxis)
						((unsigned char)data);

	if (err < 0)
		return -EIO;
	return count;
}

static ssize_t bmi160_acc_offset_y_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	unsigned char data;
	int err;

	err = BMI_CALL_API(get_acc_off_comp_yaxis)(&data);

	if (err < 0)
		return err;
	return sprintf(buf, "%d\n", data);
}

static ssize_t bmi160_acc_offset_y_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	unsigned long data;
	int err;

	err = kstrtoul(buf, 10, &data);
	if (err)
		return err;

	err = BMI_CALL_API(set_accel_offset_compensation_yaxis)
						((unsigned char)data);

	if (err < 0)
		return -EIO;
	return count;
}

static ssize_t bmi160_acc_offset_z_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	unsigned char data;
	int err;

	err = BMI_CALL_API(get_acc_off_comp_zaxis)(&data);

	if (err < 0)
		return err;
	return sprintf(buf, "%d\n", data);
}

static ssize_t bmi160_acc_offset_z_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	unsigned long data;
	int err;

	err = kstrtoul(buf, 10, &data);
	if (err)
		return err;

	err = BMI_CALL_API(set_accel_offset_compensation_zaxis)
						((unsigned char)data);

	if (err < 0)
		return -EIO;
	return count;
}

static ssize_t bmi160_test_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);
	u8 raw_data[15] = {0};
	unsigned int sensor_time = 0;

	int err;
	memset(raw_data, 0, sizeof(raw_data));

	err = client_data->device.bus_read(client_data->device.dev_addr,
			BMI160_USER_DATA_8_GYR_X_LSB__REG, raw_data, 15);
	if (err)
		return err;

	udelay(10);
	sensor_time = (u32)(raw_data[14] << 16 | raw_data[13] << 8
						| raw_data[12]);

	return sprintf(buf, "%d %d %d %d %d %d %u",
					(s16)(raw_data[1] << 8 | raw_data[0]),
				(s16)(raw_data[3] << 8 | raw_data[2]),
				(s16)(raw_data[5] << 8 | raw_data[4]),
				(s16)(raw_data[7] << 8 | raw_data[6]),
				(s16)(raw_data[9] << 8 | raw_data[8]),
				(s16)(raw_data[11] << 8 | raw_data[10]),
				sensor_time);

}

static ssize_t bmi160_step_counter_enable_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	unsigned char data;
	int err;
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);

	err = BMI_CALL_API(get_step_counter_enable)(&data);

	client_data->stc_enable = data;

	if (err < 0)
		return err;
	return sprintf(buf, "%d\n", data);
}

static ssize_t bmi160_step_counter_enable_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	unsigned long data;
	int err;
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);

	err = kstrtoul(buf, 10, &data);
	if (err)
		return err;

	err = BMI_CALL_API(set_step_counter_enable)((unsigned char)data);

	client_data->stc_enable = data;

	if (err < 0)
		return -EIO;
	return count;
}


static ssize_t bmi160_step_counter_mode_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	unsigned long data;
	int err;

	err = kstrtoul(buf, 10, &data);
	if (err)
		return err;

	err = BMI_CALL_API(set_step_mode)((unsigned char)data);

	if (err < 0)
		return -EIO;
	return count;
}

static ssize_t bmi160_step_counter_clc_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	unsigned long data;
	int err;

	err = kstrtoul(buf, 10, &data);
	if (err)
		return err;

	err = bmi160_clear_step_counter();

	if (err < 0)
		return -EIO;
	return count;
}

static ssize_t bmi160_step_counter_value_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	s16 data;
	int err;

	err = BMI_CALL_API(read_step_count)(&data);

	if (err < 0)
		return err;
	return sprintf(buf, "%d\n", data);
}

static ssize_t bmi160_bmi_value_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);
	u8 raw_data[12] = {0};

	int err;
	memset(raw_data, 0, sizeof(raw_data));

	err = client_data->device.bus_read(client_data->device.dev_addr,
			BMI160_USER_DATA_8_GYR_X_LSB__REG, raw_data, 12);
	if (err)
		return err;
	/*output:gyro x y z acc x y z*/
	return sprintf(buf, "%hd %d %hd %hd %hd %hd\n",
					(s16)(raw_data[1] << 8 | raw_data[0]),
				(s16)(raw_data[3] << 8 | raw_data[2]),
				(s16)(raw_data[5] << 8 | raw_data[4]),
				(s16)(raw_data[7] << 8 | raw_data[6]),
				(s16)(raw_data[9] << 8 | raw_data[8]),
				(s16)(raw_data[11] << 8 | raw_data[10]));

}


static ssize_t bmi160_selftest_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);

	return sprintf(buf, "0x%x\n",
				atomic_read(&client_data->selftest_result));
}

/*!
 * @brief store selftest result which make up of acc and gyro
 * format: 0b 0000 xxxx  x:1 failed, 0 success
 * bit3:     gyro_self
 * bit2..0: acc_self z y x
 */
static ssize_t bmi160_selftest_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);
	int err = 0;
	int i = 0;

	u8 acc_selftest = 0;
	u8 gyro_selftest = 0;
	u8 bmi_selftest = 0;
	s16 axis_p_value, axis_n_value;
	u16 diff_axis[3] = {0xff, 0xff, 0xff};
	u8 acc_odr, range, acc_selftest_amp, acc_selftest_sign;

	dev_notice(client_data->dev, "Selftest for BMI16x starting.\n");

	/*soft reset*/
	err = BMI_CALL_API(set_command_register)(CMD_RESET_USER_REG);
	msleep(70);
	err += BMI_CALL_API(set_command_register)
				(bmi_pmu_cmd_acc_arr[BMI_ACC_PM_NORMAL]);
	err += BMI_CALL_API(set_command_register)
				(bmi_pmu_cmd_gyro_arr[BMI_GYRO_PM_NORMAL]);
	err += BMI_CALL_API(set_accel_undersampling_parameter)(0);
	err += BMI_CALL_API(set_acc_outputdatarate)(BMI160_ACCEL_ODR_1600HZ);

	/* set to 8G range*/
	err += BMI_CALL_API(set_acc_range)(BMI160_ACCEL_RANGE_8G);
	/* set to self amp high */
	err += BMI_CALL_API(set_acc_selftest_amp)(BMI_SELFTEST_AMP_HIGH);


	err += BMI_CALL_API(get_acc_bandwidth)(&acc_odr);
	err += BMI_CALL_API(get_acc_range)(&range);
	err += BMI_CALL_API(get_acc_selftest_amp)(&acc_selftest_amp);
	err += BMI_CALL_API(read_acc_x)(&axis_n_value);

	dev_info(client_data->dev,
			"acc_odr:%d, acc_range:%d, acc_selftest_amp:%d, acc_x:%d\n",
				acc_odr, range, acc_selftest_amp, axis_n_value);

	for (i = X_AXIS; i < AXIS_MAX; i++) {
		axis_n_value = 0;
		axis_p_value = 0;
		/* set every selftest axis */
		/*set_acc_selftest_axis(param),param x:1, y:2, z:3
		* but X_AXIS:0, Y_AXIS:1, Z_AXIS:2
		* so we need to +1*/
		err += BMI_CALL_API(set_acc_selftest_axis)(i + 1);
		msleep(50);
		switch (i) {
		case X_AXIS:
			/* set negative sign */
			err += BMI_CALL_API(set_acc_selftest_sign)(0);
			err +=
			BMI_CALL_API(get_acc_selftest_sign)(&acc_selftest_sign);

			msleep(60);
			err += BMI_CALL_API(read_acc_x)(&axis_n_value);
			dev_info(client_data->dev,
			"acc_x_selftest_sign:%d, axis_n_value:%d\n",
			acc_selftest_sign, axis_n_value);

			/* set postive sign */
			err += BMI_CALL_API(set_acc_selftest_sign)(1);
			err +=
			BMI_CALL_API(get_acc_selftest_sign)(&acc_selftest_sign);

			msleep(60);
			err += BMI_CALL_API(read_acc_x)(&axis_p_value);
			dev_info(client_data->dev,
			"acc_x_selftest_sign:%d, axis_p_value:%d\n",
			acc_selftest_sign, axis_p_value);
			diff_axis[i] = abs(axis_p_value - axis_n_value);
			break;

		case Y_AXIS:
			/* set negative sign */
			err += BMI_CALL_API(set_acc_selftest_sign)(0);
			msleep(60);
			err += BMI_CALL_API(read_acc_y)(&axis_n_value);
			/* set postive sign */
			err += BMI_CALL_API(set_acc_selftest_sign)(1);
			msleep(60);
			err += BMI_CALL_API(read_acc_y)(&axis_p_value);
			diff_axis[i] = abs(axis_p_value - axis_n_value);
			break;

		case Z_AXIS:
			/* set negative sign */
			err += BMI_CALL_API(set_acc_selftest_sign)(0);
			msleep(60);
			err += BMI_CALL_API(read_acc_z)(&axis_n_value);
			/* set postive sign */
			err += BMI_CALL_API(set_acc_selftest_sign)(1);
			msleep(60);
			err += BMI_CALL_API(read_acc_z)(&axis_p_value);
			/* also start gyro self test */
			err += BMI_CALL_API(set_gyr_self_test_start)(1);
			msleep(60);
			err += BMI_CALL_API(get_gyr_self_test)(&gyro_selftest);

			err += BMI_CALL_API(read_acc_z)(&axis_p_value);
			diff_axis[i] = abs(axis_p_value - axis_n_value);
			break;
		default:
			err += -EINVAL;
			break;
		}
		if (err) {
			dev_err(client_data->dev,
				"Failed selftest axis:%s, p_val=%d, n_val=%d\n",
				bmi_axis_name[i], axis_p_value, axis_n_value);
			return -EINVAL;
		}

		/*400mg for acc z axis*/
		if (Z_AXIS == i) {
			if (diff_axis[i] < 1639) {
				acc_selftest |= 1 << i;
				dev_err(client_data->dev,
					"Over selftest minimum for "
					"axis:%s,diff=%d,p_val=%d, n_val=%d\n",
					bmi_axis_name[i], diff_axis[i],
						axis_p_value, axis_n_value);
			}
		} else {
			/*800mg for x or y axis*/
			if (diff_axis[i] < 3277) {
				acc_selftest |= 1 << i;

				if (bmi_get_err_status(client_data) < 0)
					return err;
				dev_err(client_data->dev,
					"Over selftest minimum for "
					"axis:%s,diff=%d, p_val=%d, n_val=%d\n",
					bmi_axis_name[i], diff_axis[i],
						axis_p_value, axis_n_value);
				dev_err(client_data->dev, "err_st:0x%x\n",
						client_data->err_st.err_st_all);

			}
		}

	}
	/* gyro_selftest==1,gyro selftest successfully,
	* but bmi_result bit4 0 is successful, 1 is failed*/
	bmi_selftest = (acc_selftest & 0x0f) | ((!gyro_selftest) << AXIS_MAX);
	atomic_set(&client_data->selftest_result, bmi_selftest);
	/*soft reset*/
	err = BMI_CALL_API(set_command_register)(CMD_RESET_USER_REG);
	if (err)
		return err;
	msleep(50);
	dev_notice(client_data->dev, "Selftest for BMI16x finished\n");
	return count;
}

/* gyro sensor part */
static ssize_t bmi160_gyro_op_mode_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);
	return sprintf(buf, "%d\n", client_data->pw.gyro_pm);
}

static ssize_t bmi160_gyro_op_mode_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);
	unsigned long op_mode;
	int err;

	err = kstrtoul(buf, 10, &op_mode);
	if (err)
		return err;
	mutex_lock(&client_data->mutex_op_mode);

	if (op_mode < BMI_GYRO_PM_MAX) {
		switch (op_mode) {
		case BMI_GYRO_PM_NORMAL:
			err = BMI_CALL_API(set_command_register)
				(bmi_pmu_cmd_gyro_arr[BMI_GYRO_PM_NORMAL]);
			client_data->pw.gyro_pm = BMI_GYRO_PM_NORMAL;
			client_data->sensor_status.gyro_status= BMI_GYRO_PM_NORMAL;
			mdelay(3);
			break;
		case BMI_GYRO_PM_FAST_START:
			err = BMI_CALL_API(set_command_register)
				(bmi_pmu_cmd_gyro_arr[BMI_GYRO_PM_FAST_START]);
			client_data->pw.gyro_pm = BMI_GYRO_PM_FAST_START;
			client_data->sensor_status.gyro_status= BMI_GYRO_PM_FAST_START;
			mdelay(3);
			break;
		case BMI_GYRO_PM_SUSPEND:
			err = BMI_CALL_API(set_command_register)
				(bmi_pmu_cmd_gyro_arr[BMI_GYRO_PM_SUSPEND]);
			client_data->pw.gyro_pm = BMI_GYRO_PM_SUSPEND;
			client_data->sensor_status.gyro_status= BMI_GYRO_PM_SUSPEND;
			mdelay(3);
			break;
		default:
			mutex_unlock(&client_data->mutex_op_mode);
			return -EINVAL;
		}
	} else {
		mutex_unlock(&client_data->mutex_op_mode);
		return -EINVAL;
	}

	mutex_unlock(&client_data->mutex_op_mode);

	if (err)
		return err;
	else
		return count;

}

static ssize_t bmi160_gyro_value_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);
	struct bmi160gyro_t data;
	struct bmi160_axis_data_t bmi160_udata;
	int err;
	err = BMI_CALL_API(read_gyro_xyz)(&data);
	if (err < 0)
		return err;

	bmi160_udata.x = data.x;
	bmi160_udata.y = data.y;
	bmi160_udata.z = data.z;

	bmi_remap_sensor_data(&bmi160_udata, client_data);

	return sprintf(buf, "%hd %hd %hd\n", bmi160_udata.x,
				bmi160_udata.y, bmi160_udata.z);
}

static ssize_t bmi160_gyro_range_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int err;
	unsigned char range;
	err = BMI_CALL_API(get_gyr_range)(&range);
	if (err)
		return err;
	return sprintf(buf, "%d\n", range);
}

static ssize_t bmi160_gyro_range_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	int err;
	unsigned long range;
	err = kstrtoul(buf, 10, &range);
	if (err)
		return err;
	err = BMI_CALL_API(set_gyr_range)(range);
	if (err)
		return -EIO;

	return count;
}

static ssize_t bmi160_gyro_odr_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int err;
	unsigned char gyro_odr;
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);

	err = BMI_CALL_API(get_gyro_outputdatarate)(&gyro_odr);
	if (err)
		return err;

	client_data->odr.gyro_odr = gyro_odr;
	return sprintf(buf, "%d\n", gyro_odr);
}

static ssize_t bmi160_gyro_odr_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	int err;
	unsigned long gyro_odr;
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);

	err = kstrtoul(buf, 10, &gyro_odr);
	if (err)
		return err;
	if (gyro_odr < 6 || gyro_odr > 13)
		return -EIO;

	err = BMI_CALL_API(set_gyro_outputdatarate)(gyro_odr);
	if (err)
		return -EIO;

	client_data->odr.gyro_odr = gyro_odr;
	return count;
}

static ssize_t bmi160_gyro_fast_calibration_en_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	unsigned char data;
	int err;

	err = BMI_CALL_API(get_foc_gyr_en)(&data);
	if (err < 0)
		return err;
	return sprintf(buf, "%d\n", data);
}

static ssize_t bmi160_gyro_fast_calibration_en_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	unsigned long enable;
	s8 err;
	s16 gyr_off_x;
	s16 gyr_off_y;
	s16 gyr_off_z;

	err = kstrtoul(buf, 10, &enable);
	if (err)
		return err;
	err = BMI_CALL_API(set_foc_gyr_en)((u8)enable,
				&gyr_off_x, &gyr_off_y, &gyr_off_z);

	if (err < 0)
		return -EIO;
	return count;
}

static ssize_t bmi160_gyro_offset_x_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	s16 data = 0;
	s8 err = 0;

	err = BMI_CALL_API(get_gyro_off_comp_xaxis)(&data);
	if (err < 0)
		return err;
	return sprintf(buf, "%d\n", data);
}

static ssize_t bmi160_gyro_offset_x_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	unsigned long data;
	s8 err;

	err = kstrtoul(buf, 10, &data);
	if (err)
		return err;
	err = BMI_CALL_API(set_gyro_offset_compensation_xaxis)((s16)data);

	if (err < 0)
		return -EIO;
	return count;
}

static ssize_t bmi160_gyro_offset_y_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	s16 data = 0;
	s8 err = 0;

	err = BMI_CALL_API(get_gyro_off_comp_yaxis)(&data);

	if (err < 0)
		return err;
	return sprintf(buf, "%d\n", data);
}

static ssize_t bmi160_gyro_offset_y_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	unsigned long data;
	s8 err;

	err = kstrtoul(buf, 10, &data);
	if (err)
		return err;

	err = BMI_CALL_API(set_gyro_offset_compensation_yaxis)((s16)data);

	if (err < 0)
		return -EIO;
	return count;
}

static ssize_t bmi160_gyro_offset_z_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	s16 data = 0;
	int err = 0;

	err = BMI_CALL_API(get_gyro_off_comp_zaxis)(&data);

	if (err < 0)
		return err;
	return sprintf(buf, "%d\n", data);
}

static ssize_t bmi160_gyro_offset_z_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	unsigned long data;
	int err;

	err = kstrtoul(buf, 10, &data);
	if (err)
		return err;

	err = BMI_CALL_API(set_gyro_offset_compensation_zaxis)((s16)data);

	if (err < 0)
		return -EIO;
	return count;
}


/* mag sensor part */
#ifdef BMI160_MAG_INTERFACE_SUPPORT

static ssize_t bmi160_mag_op_mode_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);
	u8 mag_op_mode;
	s8 err;
	err = bmi160_get_mag_pmu_status(&mag_op_mode);
	if (err) {
		dev_err(client_data->dev,
			"Failed to get BMI160 mag power mode:%d\n", err);
		return err;
	} else
		return sprintf(buf, "%d, reg:%d\n",
					client_data->pw.mag_pm, mag_op_mode);
}

static ssize_t bmi160_mag_op_mode_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);
	unsigned long op_mode;
	int err;
	err = kstrtoul(buf, 10, &op_mode);
	if (err)
		return err;

	if (op_mode == client_data->pw.mag_pm)
		return count;

	mutex_lock(&client_data->mutex_op_mode);


	if (op_mode < BMI_MAG_PM_MAX) {
		switch (op_mode) {
		case BMI_MAG_PM_NORMAL:
			/* need to modify as mag sensor connected,
			 * set write address to 0x4c and triggers
			 * write operation
			 * 0x4c(op mode control reg)
			 * enables normal mode in magnetometer */
			err = bmi160_set_mag_and_secondary_if_powermode
						(BMI160_MAG_FORCE_MODE);
			client_data->pw.mag_pm = BMI_MAG_PM_NORMAL;
			break;
		case BMI_MAG_PM_LP1:
			/* need to modify as mag sensor connected,
			 * set write address to 0x4 band triggers
			 * write operation
			 * 0x4b(bmm150, power control reg, bit0)
			 * enables power in magnetometer*/
			err = bmi160_set_mag_and_secondary_if_powermode
						(BMI160_MAG_FORCE_MODE);
			client_data->pw.mag_pm = BMI_MAG_PM_LP1;
			break;
		case BMI_MAG_PM_SUSPEND:
		case BMI_MAG_PM_LP2:
			err = bmi160_set_mag_and_secondary_if_powermode
						(BMI160_MAG_SUSPEND_MODE);
			client_data->pw.mag_pm = op_mode;
			break;
		default:
			mutex_unlock(&client_data->mutex_op_mode);
			return -EINVAL;
		}
	} else {
		mutex_unlock(&client_data->mutex_op_mode);
		return -EINVAL;
	}

	mutex_unlock(&client_data->mutex_op_mode);

	if (err) {
		dev_err(client_data->dev,
			"Failed to switch BMI160 mag power mode:%d\n",
			client_data->pw.mag_pm);
		return err;
	} else
		return count;

}

static ssize_t bmi160_mag_odr_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int err = 0;
	unsigned char mag_odr = 0;
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);
	err = BMI_CALL_API(get_mag_outputdatarate)(&mag_odr);
	if (err)
		return err;

	client_data->odr.mag_odr = mag_odr;
	return sprintf(buf, "%d\n", mag_odr);
}

static ssize_t bmi160_mag_odr_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	int err;
	unsigned long mag_odr;
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);

	err = kstrtoul(buf, 10, &mag_odr);
	if (err)
		return err;
	/*1~25/32hz,..6(25hz),7(50hz),...9(200hz) */
	err = BMI_CALL_API(set_mag_outputdatarate)(mag_odr);
	if (err)
		return -EIO;

	client_data->odr.mag_odr = mag_odr;
	return count;
}

static ssize_t bmi160_mag_i2c_address_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	u8 data;
	s8 err;

	err = BMI_CALL_API(set_mag_manual_en)(1);
	err += BMI_CALL_API(get_i2c_device_addr)(&data);
	err += BMI_CALL_API(set_mag_manual_en)(0);
	if (err < 0)
		return err;
	return sprintf(buf, "0x%x\n", data);
}

static ssize_t bmi160_mag_i2c_address_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	unsigned long data;
	int err;
	err = kstrtoul(buf, 10, &data);
	if (err)
		return err;

	err += BMI_CALL_API(set_mag_manual_en)(1);
	if (!err)
		err += BMI_CALL_API(set_i2c_device_addr)((unsigned char)data);
	err += BMI_CALL_API(set_mag_manual_en)(0);

	if (err < 0)
		return -EIO;
	return count;
}

static ssize_t bmi160_mag_value_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);
	struct bmi160_mag_xyz data;

	struct bmi160_axis_data_t bmi160_udata;
	int err;
	/* raw data with compensation */
	err = bmi160_mag_compensate_xyz(&data);

	if (err < 0) {
		memset(&data, 0, sizeof(data));
		dev_err(client_data->dev, "mag not ready!\n");
	}
	bmi160_udata.x = data.x;
	bmi160_udata.y = data.y;
	bmi160_udata.z = data.z;

	bmi_remap_sensor_data(&bmi160_udata, client_data);
	return sprintf(buf, "%hd %hd %hd\n", bmi160_udata.x,
					bmi160_udata.y, bmi160_udata.z);
}

static ssize_t bmi160_mag_offset_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int err = 0;
	unsigned char mag_offset;
	err = BMI_CALL_API(get_mag_offset)(&mag_offset);
	if (err)
		return err;

	return sprintf(buf, "%d\n", mag_offset);

}

static ssize_t bmi160_mag_offset_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	unsigned long data;
	int err;
	err = kstrtoul(buf, 10, &data);
	if (err)
		return err;

	err += BMI_CALL_API(set_mag_manual_en)(1);
	if (err == 0)
		err += BMI_CALL_API(set_mag_offset)((unsigned char)data);
	err += BMI_CALL_API(set_mag_manual_en)(0);

	if (err < 0)
		return -EIO;
	return count;
}

static ssize_t bmi160_mag_chip_id_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	s8 err = 0;
	u8 mag_chipid;

	err = bmi160_set_mag_manual_en(0x01);
	/* read mag chip_id value */
	err += bmi160_set_mag_read_addr(BMM050_CHIP_ID);
	/* 0x04 is mag_x lsb register */
	err += bmi160_read_reg(BMI160_USER_DATA_0_MAG_X_LSB__REG,
							&mag_chipid, 1);

	/* Must add this commands to re-set data register addr of mag sensor */
	/* 0x42 is  bmm150 data register address */
	err += bmi160_set_mag_read_addr(0x42);
	err += bmi160_set_mag_manual_en(0x00);

	if (err)
		return err;

	return sprintf(buf, "chip_id:0x%x\n", mag_chipid);

}

#endif

#if defined(BMI160_ENABLE_INT1) || defined(BMI160_ENABLE_INT2)
static ssize_t bmi_enable_int_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	int interrupt_type, value;

	sscanf(buf, "%3d %3d", &interrupt_type, &value);

	if (interrupt_type < 0 || interrupt_type > 16)
		return -EINVAL;

	if (interrupt_type <= BMI_FLAT_INT) {
		if (BMI_CALL_API(set_int_en_0)
				(bmi_interrupt_type[interrupt_type], value) < 0)
			return -EINVAL;
	} else if (interrupt_type <= BMI_FWM_INT) {
		if (BMI_CALL_API(set_int_en_1)
			(bmi_interrupt_type[interrupt_type], value) < 0)
			return -EINVAL;
	} else {
		if (BMI_CALL_API(set_int_en_2)
			(bmi_interrupt_type[interrupt_type], value) < 0)
			return -EINVAL;
	}

	return count;
}

#endif

static ssize_t bmi_register_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);

	bmi_dump_reg(client_data);

	return sprintf(buf, "Dump OK\n");
}

static ssize_t bmi_register_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	int err;
	int reg_addr = 0;
	int data;
	u8 write_reg_add = 0;
	u8 write_data = 0;
	struct input_dev *input = to_input_dev(dev);
	struct bmi_client_data *client_data = input_get_drvdata(input);

	err = sscanf(buf, "%3d %3d", &reg_addr, &data);
	if (err < 2)
		return err;

	if (data > 0xff)
		return -EINVAL;

	write_reg_add = (u8)reg_addr;
	write_data = (u8)data;
	err += BMI_CALL_API(write_reg)(write_reg_add, &write_data, 1);

	if (!err) {
		dev_info(client_data->dev, "write reg 0x%2x, value= 0x%2x\n",
			reg_addr, data);
	} else {
		dev_err(client_data->dev, "write reg fail\n");
		return err;
	}
	return count;
}

static DEVICE_ATTR(chip_id, S_IRUGO,
		bmi160_chip_id_show, NULL);
static DEVICE_ATTR(err_st, S_IRUGO,
		bmi160_err_st_show, NULL);
static DEVICE_ATTR(sensor_time, S_IRUGO,
		bmi160_sensor_time_show, NULL);

static DEVICE_ATTR(selftest, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
		bmi160_selftest_show, bmi160_selftest_store);

static DEVICE_ATTR(fifo_full_stop, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
		bmi160_fifo_full_stop_show, bmi160_fifo_full_stop_store);
static DEVICE_ATTR(fifo_flush, S_IWUSR|S_IWGRP|S_IWOTH,
		NULL, bmi160_fifo_flush_store);
static DEVICE_ATTR(fifo_bytecount, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
		bmi160_fifo_bytecount_show, bmi160_fifo_bytecount_store);
static DEVICE_ATTR(fifo_data_sel, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
		bmi160_fifo_data_sel_show, bmi160_fifo_data_sel_store);
static DEVICE_ATTR(fifo_data_frame, S_IRUGO,
		bmi160_fifo_data_out_frame_show, NULL);

static DEVICE_ATTR(fifo_watermark, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
		bmi160_fifo_watermark_show, bmi160_fifo_watermark_store);

static DEVICE_ATTR(fifo_header_en, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
		bmi160_fifo_header_en_show, bmi160_fifo_header_en_store);
static DEVICE_ATTR(fifo_time_en, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
		bmi160_fifo_time_en_show, bmi160_fifo_time_en_store);
static DEVICE_ATTR(fifo_int_tag_en, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
		bmi160_fifo_int_tag_en_show, bmi160_fifo_int_tag_en_store);

static DEVICE_ATTR(temperature, S_IRUGO,
		bmi160_temperature_show, NULL);
static DEVICE_ATTR(place, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
		bmi160_place_show, NULL);
static DEVICE_ATTR(delay, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
		bmi160_delay_show, bmi160_delay_store);
static DEVICE_ATTR(enable, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
		bmi160_enable_show, bmi160_enable_store);
static DEVICE_ATTR(acc_range, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
		bmi160_acc_range_show, bmi160_acc_range_store);
static DEVICE_ATTR(acc_odr, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
		bmi160_acc_odr_show, bmi160_acc_odr_store);
static DEVICE_ATTR(acc_op_mode, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
		bmi160_acc_op_mode_show, bmi160_acc_op_mode_store);
static DEVICE_ATTR(acc_value, S_IRUGO,
		bmi160_acc_value_show, NULL);
static DEVICE_ATTR(acc_fast_calibration_x, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
		bmi160_acc_fast_calibration_x_show,
		bmi160_acc_fast_calibration_x_store);
static DEVICE_ATTR(acc_fast_calibration_y, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
		bmi160_acc_fast_calibration_y_show,
		bmi160_acc_fast_calibration_y_store);
static DEVICE_ATTR(acc_fast_calibration_z, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
		bmi160_acc_fast_calibration_z_show,
		bmi160_acc_fast_calibration_z_store);
static DEVICE_ATTR(acc_offset_x, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
		bmi160_acc_offset_x_show,
		bmi160_acc_offset_x_store);
static DEVICE_ATTR(acc_offset_y, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
		bmi160_acc_offset_y_show,
		bmi160_acc_offset_y_store);
static DEVICE_ATTR(acc_offset_z, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
		bmi160_acc_offset_z_show,
		bmi160_acc_offset_z_store);
static DEVICE_ATTR(test, S_IRUGO,
		bmi160_test_show, NULL);
static DEVICE_ATTR(stc_enable, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
		bmi160_step_counter_enable_show,
		bmi160_step_counter_enable_store);
static DEVICE_ATTR(stc_mode, S_IWUSR|S_IWGRP|S_IWOTH,
		NULL, bmi160_step_counter_mode_store);
static DEVICE_ATTR(stc_clc, S_IWUSR|S_IWGRP|S_IWOTH,
		NULL, bmi160_step_counter_clc_store);
static DEVICE_ATTR(stc_value, S_IRUGO,
		bmi160_step_counter_value_show, NULL);


/* gyro part */
static DEVICE_ATTR(gyro_op_mode, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
		bmi160_gyro_op_mode_show, bmi160_gyro_op_mode_store);
static DEVICE_ATTR(gyro_value, S_IRUGO,
		bmi160_gyro_value_show, NULL);
static DEVICE_ATTR(gyro_range, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
		bmi160_gyro_range_show, bmi160_gyro_range_store);
static DEVICE_ATTR(gyro_odr, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
		bmi160_gyro_odr_show, bmi160_gyro_odr_store);
static DEVICE_ATTR(gyro_fast_calibration_en, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
bmi160_gyro_fast_calibration_en_show, bmi160_gyro_fast_calibration_en_store);
static DEVICE_ATTR(gyro_offset_x, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
bmi160_gyro_offset_x_show, bmi160_gyro_offset_x_store);
static DEVICE_ATTR(gyro_offset_y, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
bmi160_gyro_offset_y_show, bmi160_gyro_offset_y_store);
static DEVICE_ATTR(gyro_offset_z, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
bmi160_gyro_offset_z_show, bmi160_gyro_offset_z_store);

#ifdef BMI160_MAG_INTERFACE_SUPPORT
static DEVICE_ATTR(mag_op_mode, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
		bmi160_mag_op_mode_show, bmi160_mag_op_mode_store);
static DEVICE_ATTR(mag_odr, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
		bmi160_mag_odr_show, bmi160_mag_odr_store);
static DEVICE_ATTR(mag_i2c_addr, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
		bmi160_mag_i2c_address_show, bmi160_mag_i2c_address_store);
static DEVICE_ATTR(mag_value, S_IRUGO,
		bmi160_mag_value_show, NULL);
static DEVICE_ATTR(mag_offset, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
		bmi160_mag_offset_show, bmi160_mag_offset_store);

static DEVICE_ATTR(mag_chip_id, S_IRUGO,
		bmi160_mag_chip_id_show, NULL);

#endif


#if defined(BMI160_ENABLE_INT1) || defined(BMI160_ENABLE_INT2)
static DEVICE_ATTR(enable_int, S_IWUSR|S_IWGRP|S_IWOTH,
		NULL, bmi_enable_int_store);
static DEVICE_ATTR(anymot_duration, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
		bmi160_anymot_duration_show, bmi160_anymot_duration_store);
static DEVICE_ATTR(anymot_threshold, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
		bmi160_anymot_threshold_show, bmi160_anymot_threshold_store);
static DEVICE_ATTR(std_stu, S_IRUGO,
		bmi160_step_detector_status_show, NULL);
static DEVICE_ATTR(std_en, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
		bmi160_step_detector_enable_show,
		bmi160_step_detector_enable_store);


#endif

static DEVICE_ATTR(register, S_IRUGO|S_IWUSR|S_IWGRP|S_IWOTH,
		bmi_register_show, bmi_register_store);

static DEVICE_ATTR(bmi_value, S_IRUGO,
		bmi160_bmi_value_show, NULL);


static struct attribute *bmi160_attributes[] = {
	&dev_attr_chip_id.attr,
	&dev_attr_err_st.attr,
	&dev_attr_sensor_time.attr,
	&dev_attr_selftest.attr,

	&dev_attr_test.attr,
	&dev_attr_fifo_full_stop.attr,
	&dev_attr_fifo_flush.attr,
	&dev_attr_fifo_header_en.attr,
	&dev_attr_fifo_time_en.attr,
	&dev_attr_fifo_int_tag_en.attr,
	&dev_attr_fifo_bytecount.attr,
	&dev_attr_fifo_data_sel.attr,
	&dev_attr_fifo_data_frame.attr,

	&dev_attr_fifo_watermark.attr,

	&dev_attr_enable.attr,
	&dev_attr_delay.attr,
	&dev_attr_temperature.attr,
	&dev_attr_place.attr,

	&dev_attr_acc_range.attr,
	&dev_attr_acc_odr.attr,
	&dev_attr_acc_op_mode.attr,
	&dev_attr_acc_value.attr,

	&dev_attr_acc_fast_calibration_x.attr,
	&dev_attr_acc_fast_calibration_y.attr,
	&dev_attr_acc_fast_calibration_z.attr,
	&dev_attr_acc_offset_x.attr,
	&dev_attr_acc_offset_y.attr,
	&dev_attr_acc_offset_z.attr,

	&dev_attr_stc_enable.attr,
	&dev_attr_stc_mode.attr,
	&dev_attr_stc_clc.attr,
	&dev_attr_stc_value.attr,

	&dev_attr_gyro_op_mode.attr,
	&dev_attr_gyro_value.attr,
	&dev_attr_gyro_range.attr,
	&dev_attr_gyro_odr.attr,
	&dev_attr_gyro_fast_calibration_en.attr,
	&dev_attr_gyro_offset_x.attr,
	&dev_attr_gyro_offset_y.attr,
	&dev_attr_gyro_offset_z.attr,

#ifdef BMI160_MAG_INTERFACE_SUPPORT
	&dev_attr_mag_chip_id.attr,
	&dev_attr_mag_op_mode.attr,
	&dev_attr_mag_odr.attr,
	&dev_attr_mag_i2c_addr.attr,
	&dev_attr_mag_value.attr,
	&dev_attr_mag_offset.attr,

#endif

#if defined(BMI160_ENABLE_INT1) || defined(BMI160_ENABLE_INT2)
	&dev_attr_enable_int.attr,

	&dev_attr_anymot_duration.attr,
	&dev_attr_anymot_threshold.attr,
	&dev_attr_std_stu.attr,
	&dev_attr_std_en.attr,

#endif
	&dev_attr_register.attr,
	&dev_attr_bmi_value.attr,
	NULL
};

static struct attribute_group bmi160_attribute_group = {
	.attrs = bmi160_attributes
};

static void bmi_delay(u32 msec)
{
	mdelay(msec);
}

#if defined(BMI160_ENABLE_INT1) || defined(BMI160_ENABLE_INT2)
static void bmi_slope_interrupt_handle(struct bmi_client_data *client_data)
{
	/* anym_first[0..2]: x, y, z */
	u8 anym_first[3] = {0};
	u8 status2;
	u8 anym_sign;
	u8 i = 0;

	client_data->device.bus_read(client_data->device.dev_addr,
				BMI160_USER_INT_STATUS_2_ADDR, &status2, 1);
	anym_first[0] = BMI160_GET_BITSLICE(status2,
				BMI160_USER_INT_STATUS_2_ANYM_FIRST_X);
	anym_first[1] = BMI160_GET_BITSLICE(status2,
				BMI160_USER_INT_STATUS_2_ANYM_FIRST_Y);
	anym_first[2] = BMI160_GET_BITSLICE(status2,
				BMI160_USER_INT_STATUS_2_ANYM_FIRST_Z);
	anym_sign = BMI160_GET_BITSLICE(status2,
				BMI160_USER_INT_STATUS_2_ANYM_SIGN);

	for (i = 0; i < 3; i++) {
		if (anym_first[i]) {
			/*1: negative*/
			if (anym_sign)
				dev_notice(client_data->dev,
				"Anymotion interrupt happend!"
				"%s axis, negative sign\n", bmi_axis_name[i]);
			else
				dev_notice(client_data->dev,
				"Anymotion interrupt happend!"
				"%s axis, postive sign\n", bmi_axis_name[i]);
		}
	}


}



static void bmi_fifo_watermark_interrupt_handle
				(struct bmi_client_data *client_data)
{
	int err = 0;
	unsigned int fifo_len0 = 0;
	unsigned int  fifo_frmbytes_ext = 0;
	unsigned char *fifo_data = NULL;
	fifo_data = kzalloc(FIFO_DATA_BUFSIZE, GFP_KERNEL);
	/*TO DO*/
	if (NULL == fifo_data) {
			dev_err(client_data->dev, "no memory available");
			err = -ENOMEM;
	}
	bmi_fifo_frame_bytes_extend_calc(client_data, &fifo_frmbytes_ext);

	if (client_data->pw.acc_pm == 2 && client_data->pw.gyro_pm == 2
					&& client_data->pw.mag_pm == 2)
		printk(KERN_INFO "pw_acc: %d, pw_gyro: %d\n",
			client_data->pw.acc_pm, client_data->pw.gyro_pm);
	if (!client_data->fifo_data_sel)
		printk(KERN_INFO "no selsect sensor fifo, fifo_data_sel:%d\n",
						client_data->fifo_data_sel);

	err = BMI_CALL_API(fifo_length)(&fifo_len0);
	client_data->fifo_bytecount = fifo_len0;

	if (client_data->fifo_bytecount == 0 || err)
		return ;

	if (client_data->fifo_bytecount + fifo_frmbytes_ext > FIFO_DATA_BUFSIZE)
		client_data->fifo_bytecount = FIFO_DATA_BUFSIZE;
	/* need give attention for the time of burst read*/
	if (!err) {
		err = bmi_burst_read_wrapper(client_data->device.dev_addr,
			BMI160_USER_FIFO_DATA__REG, fifo_data,
			client_data->fifo_bytecount + fifo_frmbytes_ext);
	} else
		dev_err(client_data->dev, "read fifo leght err");

	if (err)
		dev_err(client_data->dev, "brust read fifo err\n");
	/*err = bmi_fifo_analysis_handle(client_data, fifo_data,
			client_data->fifo_bytecount + 20, fifo_out_data);*/
	if (fifo_data != NULL) {
		kfree(fifo_data);
		fifo_data = NULL;
	}

}

static void bmi_signification_motion_interrupt_handle(
		struct bmi_client_data *client_data)
{
	printk(KERN_INFO "bmi_signification_motion_interrupt_handle\n");
	input_event(client_data->input, EV_MSC, INPUT_EVENT_SGM, 1);
/*input_report_rel(client_data->input,INPUT_EVENT_SGM,1);*/
	input_sync(client_data->input);
	bmi160_set_command_register(CMD_RESET_INT_ENGINE);

}
static void bmi_stepdetector_interrupt_handle(
	struct bmi_client_data *client_data)
{
	printk(KERN_INFO "bmi_stepdetector_interrupt_handle\n");
/*
	input_report_rel(client_data->input,INPUT_EVENT_STEP_DETECTOR,1);
	input_sync(client_data->input);
*/
	client_data->std = 1;
}

static void bmi_irq_work_func(struct work_struct *work)
{
	struct bmi_client_data *client_data =
		container_of((struct work_struct *)work,
			struct bmi_client_data, irq_work);

	unsigned char int_status[4] = {0, 0, 0, 0};
	client_data->device.bus_read(client_data->device.dev_addr,
				BMI160_USER_INT_STATUS_0_ADDR, int_status, 4);

	if (BMI160_GET_BITSLICE(int_status[0],
					BMI160_USER_INT_STATUS_0_ANYM))
		bmi_slope_interrupt_handle(client_data);

	if (BMI160_GET_BITSLICE(int_status[0],
			BMI160_USER_INT_STATUS_0_STEP_INT))
		bmi_stepdetector_interrupt_handle(client_data);
	if (BMI160_GET_BITSLICE(int_status[1],
			BMI160_USER_INT_STATUS_1_FWM_INT))
		bmi_fifo_watermark_interrupt_handle(client_data);

	/* Clear ALL inputerrupt status after handler sig mition*/
	/* Put this commads intot the last one*/
	if (BMI160_GET_BITSLICE(int_status[0],
		BMI160_USER_INT_STATUS_0_SIGMOT_INT))
		bmi_signification_motion_interrupt_handle(client_data);

}

static irqreturn_t bmi_irq_handler(int irq, void *handle)
{
	struct bmi_client_data *client_data = handle;

	if (client_data == NULL)
		return IRQ_HANDLED;
	if (client_data->dev == NULL)
		return IRQ_HANDLED;
	schedule_work(&client_data->irq_work);
	return IRQ_HANDLED;
}
#endif /* defined(BMI_ENABLE_INT1)||defined(BMI_ENABLE_INT2) */

static int bmi160_accel_calibration_xyz(struct sensors_classdev *sensors_cdev)
{
	int err;
	s8 accel_offset_x = 0;
	s8 accel_offset_y = 0;
	s8 accel_offset_z = 0;
	struct bmi_client_data *client_data = container_of(sensors_cdev,
			struct bmi_client_data, accel_cdev);
	err = bmi160_set_acc_op_mode(client_data,BMI_ACC_PM_NORMAL);
	err = BMI_CALL_API(set_accel_foc_trigger)(X_AXIS, 3, &accel_offset_x);
	err = BMI_CALL_API(set_accel_foc_trigger)(Y_AXIS, 3, &accel_offset_y);
	err = BMI_CALL_API(set_accel_foc_trigger)(Z_AXIS, 2, &accel_offset_z);
	if (err)
		return -EIO;
			
	return 0;
}

static int bmi160_gyro_calibration_xyz(struct sensors_classdev *sensors_cdev)
{
	s8 err;
	s16 gyr_off_x;
	s16 gyr_off_y;
	s16 gyr_off_z;
	
	err = BMI_CALL_API(set_command_register)
				(bmi_pmu_cmd_gyro_arr[BMI_GYRO_PM_FAST_START]);
	err = BMI_CALL_API(set_foc_gyr_en)(1,&gyr_off_x, &gyr_off_y, &gyr_off_z);
	if (err < 0)
		return -EIO;			
	return 0;
}
/*bmi power init*/
static int bmi_power_init(struct bmi_client_data *client_data)
{
	int err = 0;
	 
	client_data->bmi_vdd = regulator_get(client_data->dev, "vdd");
	if (IS_ERR(client_data->bmi_vdd)) {
		err = PTR_ERR(client_data->bmi_vdd);
		pr_err("Regulator get failed vdd rc=%d\n", err);
		return err;
	}

	client_data->bmi_vio = regulator_get(client_data->dev, "vio");
	if (IS_ERR(client_data->bmi_vio)) {
		err = PTR_ERR(client_data->bmi_vio);
		pr_err("Regulator get failed vdd rc=%d\n", err);
		return err;
	}

			 
	err = regulator_set_voltage(client_data->bmi_vdd, BMI160_VDD_MIN_UV, BMI160_VDD_MAX_UV);
	if (err) {
	        pr_err("set voltage err \n");
		 return err;
	 }

	err = regulator_set_voltage(client_data->bmi_vio, BMI160_VI2C_MIN_UV, BMI160_VI2C_MAX_UV);
	if (err) {
	         pr_err("set voltage err \n");
		  return err;
	}		 	

	return err;
}
/*bmi power control*/
static int bmi_power_control(struct bmi_client_data *client_data,bool on)
{
	 int err = 0;
	 
	 if(on)
	 {
	         err = regulator_enable(client_data->bmi_vdd);
		  if (err) {
	            pr_err("regulator enable err \n");
		     return err;
	         }

	         err = regulator_enable(client_data->bmi_vio);
		  if (err) {
	            pr_err("regulator enable err \n");
		     return err;
	         }		 	
	 }
	 else
	 {
		err = regulator_disable(client_data->bmi_vdd);
	       if (err) {
		      pr_err("regulator enable err \n");
		      return err;
		}

		err = regulator_disable(client_data->bmi_vio);
	       if (err) {
		      pr_err("regulator enable err \n");
		      return err;
		}
	 }
	 return err;
}
int bmi_probe(struct bmi_client_data *client_data, struct device *dev)
{
	int err = 0;
	u8 mag_dev_addr;
#ifdef BMI160_MAG_INTERFACE_SUPPORT
	u8 mag_urst_len;
#endif
    struct i2c_client *client = container_of(dev,struct i2c_client, dev);
	/* check chip id */
	err = bmi_check_chip_id(client_data);
	if (err)
		goto exit_err_clean;

	dev_set_drvdata(dev, client_data);
	client_data->dev = dev;

	mutex_init(&client_data->mutex_enable);
	mutex_init(&client_data->mutex_op_mode);

	err = bmi_power_init(client_data);
	if (err < 0)
		return err;
	err = bmi_power_control(client_data,true);
	if (err < 0)
		return err;
	client_data->bmi_pm_status = BMI_PM_ON;

	/* input device init */
	err = bmi_input_init(client_data);
	if (err < 0)
		goto exit_err_clean;

	/* sysfs node creation */
	err = sysfs_create_group(&client_data->input->dev.kobj,
			&bmi160_attribute_group);
	if (err < 0)
		goto exit_err_sysfs;
		
	err = sysfs_create_group(&client->dev.kobj,
			&bmi160_attribute_group);
	if (err < 0)
		goto exit_err_sysfs;

	if (NULL != dev->platform_data) {
		client_data->bst_pd = kzalloc(sizeof(*client_data->bst_pd),
				GFP_KERNEL);
		//client_data->bst_pd->place = 6;
		if (NULL != client_data->bst_pd) {
			memcpy(client_data->bst_pd, dev->platform_data,
					sizeof(*client_data->bst_pd));
			client_data->bst_pd->place = 7;
			printk(KERN_ERR "KAISADADI0");
			dev_notice(dev, "%s sensor driver set place: p%d\n",
					client_data->bst_pd->name,
					client_data->bst_pd->place);
		}
	}
	
	if (NULL != client_data->bst_pd) {
			memcpy(client_data->bst_pd, dev->platform_data,
					sizeof(*client_data->bst_pd));
			client_data->bst_pd->place = 7;
			printk(KERN_ERR "KAISADADI1");
			dev_notice(dev, "%s sensor driver set place: p%d\n",
					client_data->bst_pd->name,
					client_data->bst_pd->place);
		}

	
	/* workqueue init */
	INIT_DELAYED_WORK(&client_data->work, bmi_work_func);
	atomic_set(&client_data->delay, BMI_DELAY_DEFAULT);
	atomic_set(&client_data->wkqueue_en, 0);

	/* h/w init */
	client_data->device.delay_msec = bmi_delay;
	err = BMI_CALL_API(init)(&client_data->device);

	bmi_dump_reg(client_data);

	/*power on detected*/
	/*or softrest(cmd 0xB6) */
	/*fatal err check*/
	/*soft reset*/
	err += BMI_CALL_API(set_command_register)(CMD_RESET_USER_REG);
	mdelay(3);
	if (err)
		dev_err(dev, "Failed soft reset, er=%d", err);
	/*usr data config page*/
	err += BMI_CALL_API(set_target_page)(USER_DAT_CFG_PAGE);
	if (err)
		dev_err(dev, "Failed cffg page, er=%d", err);
	err += bmi_get_err_status(client_data);
	if (err) {
		dev_err(dev, "Failed to bmi16x init!err_st=0x%x\n",
				client_data->err_st.err_st_all);
		goto exit_err_sysfs;
	}

	err += BMI_CALL_API(get_i2c_device_addr)(&mag_dev_addr);

	
    client_data->accel_cdev = bmi160_acc_cdev;
	client_data->accel_cdev.sensors_self_test = bmi160_accel_calibration_xyz;
	err = sensors_classdev_register(&client->dev, &client_data->accel_cdev);
	client_data->gyro_cdev = bmi160_gyro_cdev;
	client_data->gyro_cdev.sensors_self_test = bmi160_gyro_calibration_xyz;
	err = sensors_classdev_register(&client->dev, &client_data->gyro_cdev);




#ifdef BMI160_MAG_INTERFACE_SUPPORT
		err += BMI_CALL_API(set_i2c_device_addr)(mag_dev_addr);
		err += bmi160_magnetometer_interface_init();
		err += bmi160_set_mag_burst(3);
		err += bmi160_get_mag_burst(&mag_urst_len);
		dev_info(client_data->dev,
			"BMI160 mag_urst_len:%d, mag_add:0x%x\n",
			mag_urst_len, mag_dev_addr);
#endif
	if (err < 0)
		goto exit_err_sysfs;


#if defined(BMI160_ENABLE_INT1) || defined(BMI160_ENABLE_INT2)
		client_data->gpio_pin = of_get_named_gpio_flags(dev->of_node,
					"bmi,gpio_irq", 0, NULL);
		dev_info(client_data->dev, "BMI160 qpio number:%d\n",
					client_data->gpio_pin);
		err += gpio_request_one(client_data->gpio_pin,
					GPIOF_IN, "bmi160_int");
		err += gpio_direction_input(client_data->gpio_pin);
		client_data->IRQ = gpio_to_irq(client_data->gpio_pin);
		if (err) {
			dev_err(client_data->dev,
				"can not request gpio to irq number\n");
			client_data->gpio_pin = 0;
		}


#ifdef BMI160_ENABLE_INT1
		/* maps interrupt to INT1/InT2 pin */
		BMI_CALL_API(set_int_anymo)(BMI_INT0, ENABLE);
		BMI_CALL_API(set_int_fwm)(BMI_INT0, ENABLE);
		/*BMI_CALL_API(set_int_drdy)(BMI_INT0, ENABLE);*/

		/*Set interrupt trige level way */
		BMI_CALL_API(set_int_edge_ctrl)(BMI_INT0, BMI_INT_LEVEL);
		bmi160_set_int_lvl(BMI_INT0, 1);
		/*set interrupt latch temporary, 5 ms*/
		/*bmi160_set_latch_int(5);*/

		BMI_CALL_API(set_output_en)(BMI160_INT1_OUTPUT_EN, ENABLE);
		sigmotion_enable_interrupts(BMI160_MAP_INT1);
	/*BMI_CALL_API(map_significant_motion_interrupt)(BMI160_MAP_INT1);*/
		BMI_CALL_API(map_step_detector_interrupt)(BMI160_MAP_INT1);
#endif

#ifdef BMI160_ENABLE_INT2
		/* maps interrupt to INT1/InT2 pin */
		BMI_CALL_API(set_int_anymo)(BMI_INT1, ENABLE);
		BMI_CALL_API(set_int_fwm)(BMI_INT1, ENABLE);
		BMI_CALL_API(set_int_drdy)(BMI_INT1, ENABLE);

		/*Set interrupt trige level way */
		BMI_CALL_API(set_int_edge_ctrl)(BMI_INT1, BMI_INT_LEVEL);
		bmi160_set_int_lvl(BMI_INT1, 1);
		/*set interrupt latch temporary, 5 ms*/
		/*bmi160_set_latch_int(5);*/

		BMI_CALL_API(set_output_en)(BMI160_INT2_OUTPUT_EN, ENABLE);
		sigmotion_enable_interrupts(BMI160_MAP_INT2);
	/*BMI_CALL_API(map_significant_motion_interrupt)(BMI160_MAP_INT2);*/
		BMI_CALL_API(map_step_detector_interrupt)(BMI160_MAP_INT2);
#endif
		err = request_irq(client_data->IRQ, bmi_irq_handler,
				IRQF_TRIGGER_RISING, "bmi160", client_data);
		if (err)
			dev_err(client_data->dev, "could not request irq\n");

		INIT_WORK(&client_data->irq_work, bmi_irq_work_func);
#endif


	client_data->fifo_data_sel = 0;
	BMI_CALL_API(get_acc_outputdatarate)(&client_data->odr.acc_odr);
	BMI_CALL_API(get_gyro_outputdatarate)(&client_data->odr.gyro_odr);
	BMI_CALL_API(get_mag_outputdatarate)(&client_data->odr.mag_odr);
	BMI_CALL_API(set_fifo_time_en)(1);
	/* now it's power on which is considered as resuming from suspend */

	/* set sensor PMU into suspend power mode for all */
	if (bmi_pmu_set_suspend(client_data) < 0) {
		dev_err(dev, "Failed to set BMI160 to suspend power mode\n");
		goto exit_err_sysfs;
	}

	dev_notice(dev, "sensor_time:%d, %d",
		sensortime_duration_tbl[0].ts_delat,
		sensortime_duration_tbl[0].ts_duration_lsb);
	dev_notice(dev, "sensor %s probed successfully", SENSOR_NAME);

	return 0;

exit_err_sysfs:
	if (err)
		bmi_input_destroy(client_data);

exit_err_clean:
	if (err) {
		if (client_data != NULL) {
			if (NULL != client_data->bst_pd) {
				kfree(client_data->bst_pd);
				client_data->bst_pd = NULL;
			}
		}
	}

	return err;
}
EXPORT_SYMBOL(bmi_probe);

/*!
 * @brief remove bmi client
 *
 * @param dev the pointer of device
 *
 * @return zero
 * @retval zero
*/
int bmi_remove(struct device *dev)
{
	int err = 0;
	struct bmi_client_data *client_data = dev_get_drvdata(dev);

	if (NULL != client_data) {
#ifdef CONFIG_HAS_EARLYSUSPEND
		unregister_early_suspend(&client_data->early_suspend_handler);
#endif
		mutex_lock(&client_data->mutex_enable);
		if (BMI_ACC_PM_NORMAL == client_data->pw.acc_pm ||
			BMI_GYRO_PM_NORMAL == client_data->pw.gyro_pm ||
				BMI_MAG_PM_NORMAL == client_data->pw.mag_pm) {
			cancel_delayed_work_sync(&client_data->work);
		}
		mutex_unlock(&client_data->mutex_enable);

		err = bmi_pmu_set_suspend(client_data);

		mdelay(5);

		sysfs_remove_group(&client_data->input->dev.kobj,
				&bmi160_attribute_group);
		bmi_input_destroy(client_data);

		if (NULL != client_data->bst_pd) {
			kfree(client_data->bst_pd);
			client_data->bst_pd = NULL;
		}
		kfree(client_data);
	}

	return err;
}
EXPORT_SYMBOL(bmi_remove);

static int bmi_post_resume(struct bmi_client_data *client_data)
{
	int err = 0;
	mutex_lock(&client_data->mutex_enable);

	if (atomic_read(&client_data->wkqueue_en) == 1) {
		bmi160_set_acc_op_mode(client_data, BMI_ACC_PM_NORMAL);
		schedule_delayed_work(&client_data->work,
				msecs_to_jiffies(
					atomic_read(&client_data->delay)));
	}
	if (client_data->sensor_status.acc_status ==BMI_ACC_PM_NORMAL ) {
		err += BMI_CALL_API(set_command_register)
				(bmi_pmu_cmd_acc_arr[BMI_ACC_PM_NORMAL]);
		client_data->pw.acc_pm = BMI_ACC_PM_NORMAL;
		mdelay(3);
	}
	if (client_data->sensor_status.gyro_status== BMI_GYRO_PM_NORMAL) {
		err += BMI_CALL_API(set_command_register)
				(bmi_pmu_cmd_gyro_arr[BMI_GYRO_PM_NORMAL]);
		client_data->pw.gyro_pm = BMI_GYRO_PM_NORMAL;
		mdelay(3);
	}

	if (client_data->sensor_status.mag_status== BMI_MAG_PM_NORMAL) {
		bmi160_set_mag_and_secondary_if_powermode
					(BMI_MAG_PM_NORMAL);
		client_data->pw.mag_pm= BMI_MAG_PM_NORMAL;
		mdelay(3);
	}
	mutex_unlock(&client_data->mutex_enable);

	return err;
}


int bmi_suspend(struct device *dev)
{
	int err = 0;
	struct bmi_client_data *client_data = dev_get_drvdata(dev);
	unsigned char stc_enable;
	dev_err(client_data->dev, "bmi suspend function entrance");
	if(client_data->bmi_pm_status != BMI_PM_ON)
	{
		err = bmi_power_control(client_data,true);
		if(err<0)
		{
			dev_err(client_data->dev, "BMI160 bmi_i2c_suspend: i2c power up  err!");
		}
		client_data->bmi_pm_status = BMI_PM_ON;
	}

	if (atomic_read(&client_data->wkqueue_en) == 1) {
		bmi160_set_acc_op_mode(client_data, BMI_ACC_PM_SUSPEND);
		cancel_delayed_work_sync(&client_data->work);
	}
	BMI_CALL_API(get_step_counter_enable)(&stc_enable);

	if (client_data->pw.acc_pm != BMI_ACC_PM_SUSPEND && (stc_enable != 1)) {
		err += BMI_CALL_API(set_command_register)
				(bmi_pmu_cmd_acc_arr[BMI_ACC_PM_SUSPEND]);
		client_data->pw.acc_pm = BMI_ACC_PM_SUSPEND;
		mdelay(3);
	}
	if (client_data->pw.gyro_pm != BMI_GYRO_PM_SUSPEND) {
		err += BMI_CALL_API(set_command_register)
				(bmi_pmu_cmd_gyro_arr[BMI_GYRO_PM_SUSPEND]);
		client_data->pw.gyro_pm = BMI_GYRO_PM_SUSPEND;
		mdelay(3);
	}

	if (client_data->pw.mag_pm != BMI_MAG_PM_SUSPEND) {
		bmi160_set_mag_and_secondary_if_powermode
					(BMI160_MAG_SUSPEND_MODE);
		client_data->pw.mag_pm = BMI160_MAG_SUSPEND_MODE;
		mdelay(3);
	}

	err = bmi_power_control(client_data,false);
	if(err<0)
	{
		dev_err(client_data->dev, "BMI160 bmi_i2c_suspend: i2c power off  err!");
		return err;
	}
	client_data->bmi_pm_status = BMI_PM_OFF;

	return err;
}
EXPORT_SYMBOL(bmi_suspend);

int bmi_resume(struct device *dev)
{
	int err = 0;
	struct bmi_client_data *client_data = dev_get_drvdata(dev);

	err = bmi_power_control(client_data,true);
	if(err<0)
	{
		dev_err(client_data->dev, "BMI160 bmi_i2c_resume: i2c power up  err!");
		return err;
	}
	client_data->bmi_pm_status = BMI_PM_ON;
	/* post resume operation */
	err = bmi_post_resume(client_data);

	return err;
}
EXPORT_SYMBOL(bmi_resume);

