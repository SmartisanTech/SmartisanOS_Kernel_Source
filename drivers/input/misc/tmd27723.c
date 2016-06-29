/*************************************************
 *Description : TMD27723 L/P-Sensor Driver
 *Author      : Wangruoming<ruoming.wang@sim.com>
 *************************************************/

#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/i2c.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/input.h>
#include <linux/ioctl.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/regulator/consumer.h>
#include <linux/of_gpio.h>
#include <linux/sensors.h>
#include <linux/delay.h>
#if defined(CONFIG_FB)
#include <linux/notifier.h>
#include <linux/fb.h>
#endif

#define TMD27723_DRV_NAME       "tmd27723"

#define ALS_POLLING_ENABLED
//#define SENSOR_DEBUG

/*Register*/
#define TMD27723_ENABLE_REG     0x00
#define TMD27723_ATIME_REG      0x01
#define TMD27723_PTIME_REG      0x02
#define TMD27723_WTIME_REG      0x03
#define TMD27723_AILTL_REG      0x04
#define TMD27723_AILTH_REG      0x05
#define TMD27723_AIHTL_REG      0x06
#define TMD27723_AIHTH_REG      0x07
#define TMD27723_PILTL_REG      0x08
#define TMD27723_PILTH_REG      0x09
#define TMD27723_PIHTL_REG      0x0A
#define TMD27723_PIHTH_REG      0x0B
#define TMD27723_PERS_REG       0x0C
#define TMD27723_CONFIG_REG     0x0D
#define TMD27723_PPCOUNT_REG    0x0E
#define TMD27723_CONTROL_REG    0x0F
#define TMD27723_REV_REG        0x11
#define TMD27723_ID_REG         0x12
#define TMD27723_STATUS_REG     0x13
#define TMD27723_CH0DATAL_REG   0x14
#define TMD27723_CH0DATAH_REG   0x15
#define TMD27723_CH1DATAL_REG   0x16
#define TMD27723_CH1DATAH_REG   0x17
#define TMD27723_PDATAL_REG     0x18
#define TMD27723_PDATAH_REG     0x19
#define TMD27723_POFFSET_REG    0x1E

#define CMD_BYTE                0x80
#define CMD_WORD                0xA0
#define CMD_SPECIAL             0xE0

/*Calibration*/
#define DEFAULT_CROSS_TALK      400

/*Chip ID*/
#define TMD27723_ID             0x39
#define TMD27721_ID             0x30

/*Configure */
#define TMD27723_PDRVIE_100MA   0x00 /*PS 100mA LED drive*/
#define TMD27723_PRX_IR_DIOD    0x20/*Proximity uses CH1 diode*/

#define ALS_MAX_RANGE           60000

/*TMD27723 power supply VDD 1.62V-3.6V VIO 1.2-3.6V */
#define TMD27723_VDD_MIN_UV       2000000
#define TMD27723_VDD_MAX_UV       3400000
#define TMD27723_VIO_MIN_UV       1500000
#define TMD27723_VIO_MAX_UV       3400000

#define TMD27723_ALS_REDUCE     0x04

/*Function state*/
static int tmd27723_init_device(struct i2c_client *client);


/*P-Sensor tuning value*/
static int tmd27723_ps_detection_threshold  = 0;
static int tmd27723_ps_hsyteresis_threshold = 0;
static int tmd27723_ps_pulse_number = 0;
static int tmd27723_ps_pgain = 0;

static int psensor_last_report_near = 0;
static int psensor_last_report_far = 1;
static int psensor_first_enable = 0;
/*L-Sensor tuning value*/
static int tmd27723_ga    = 0;
static int tmd27723_coe_b = 0;
static int tmd27723_coe_c = 0;
static int tmd27723_coe_d = 0;

/*calibration*/
static int tmd27723_cross_talk_val = 0;

struct tmd27723_data {
        struct i2c_client *client;
        struct input_dev *input_dev_als;
        struct input_dev *input_dev_ps;
        struct sensors_classdev als_cdev;
        struct sensors_classdev ps_cdev;

        /*Control sensor from HAL*/
        unsigned int enable_ps_sensor;
        unsigned int enable_als_sensor;

        /* PS parameters */
        unsigned int ps_threshold;
        unsigned int ps_hysteresis_threshold;
        unsigned int ps_detection;
        unsigned int ps_data;
        int ps_offset;

        /* ALS parameters */
        unsigned int als_threshold_l;
        unsigned int als_threshold_h;
        unsigned int als_data;

        unsigned int als_gain;
        unsigned int als_poll_delay;
        unsigned int als_atime_index;
        unsigned int als_again_index;
        unsigned int als_reduce;
        int als_prev_lux;

        /*huci lock*/
        struct mutex enable_lock;
        struct mutex op_lock;
        struct mutex update_lock;
        struct mutex ps_lock;
        struct mutex als_lock;

        /*work queue*/
        struct delayed_work     ps_work;     /*P-Sensor*/
        struct delayed_work     als_work; /*L-Sensor*/
	 struct delayed_work    	 ps_calibrate_work;     /*P-Sensor offset*/

        /*register configuration*/
        unsigned int enable;
        unsigned int atime;
        unsigned int ptime;
        unsigned int wtime;
        unsigned int ailt;
        unsigned int pilt;
        unsigned int aiht;
        unsigned int piht;
        unsigned int pers;
        unsigned int config;
        unsigned int ppcount;
        unsigned int control;
#if  1
        atomic_t ps_citvalue;
        atomic_t ps_3_cal_value;
        atomic_t ps_5_cal_value;
        unsigned int als_suspend_state;
        unsigned int ps_suspend_state;
        unsigned int suspend_state;
#if defined(CONFIG_FB)
        struct notifier_block fb_notif;
#endif
#endif
        /*calibration*/
        unsigned int cross_talk;

        /*regulator*/
        struct regulator *vdd;
        struct regulator *vio;

};
static struct tmd27723_data *globle_data;
static int last_data;
static struct sensors_classdev sensors_light_cdev = {
        .name = "light",
        .vendor = "Taos",
        .version = 1,
        .handle = SENSORS_LIGHT_HANDLE,
        .type = SENSOR_TYPE_LIGHT,
        .max_range = "60000",
        .resolution = "0.0125",
        .sensor_power = "0.20",
        .min_delay = 0,
        .fifo_reserved_event_count = 0,
        .fifo_max_event_count = 0,
        .enabled = 0,
        .delay_msec = 100,
        .sensors_enable = NULL,
        .sensors_poll_delay = NULL,
};

static struct sensors_classdev sensors_proximity_cdev = {
        .name = "proximity",
        .vendor = "Taos",
        .version = 1,
        .handle = SENSORS_PROXIMITY_HANDLE,
        .type = SENSOR_TYPE_PROXIMITY,
        .max_range = "5",
        .resolution = "5.0",
        .sensor_power = "3",
        .min_delay = 0,
        .fifo_reserved_event_count = 0,
        .fifo_max_event_count = 0,
        .enabled = 0,
        .delay_msec = 100,
        .sensors_enable = NULL,
        .sensors_poll_delay = NULL,
};
//static int tmd27723_ps_calibrate (struct tmd27723_data *data);
static int tmd27723_set_enable(struct i2c_client *client, int enable);


static int tmd27723_enable_als_sensor(struct i2c_client *client, int val)
{
        struct tmd27723_data *data = i2c_get_clientdata(client);
//        int rc;
        int pre_enable = data->enable_als_sensor;

        mutex_lock(&data->op_lock);
        if (pre_enable == 0)
        {
                if (val == 1)
                {
#if 0
                        rc = tmd27723_init_device(client);
                        if (rc)
                        {
                                printk ("Failed to init tmd27723\n");
                                mutex_unlock(&data->op_lock);
                                return rc;
                        }
#endif 
                        schedule_delayed_work(&data->als_work,msecs_to_jiffies(100));
                        data->enable_als_sensor = 1;
                }
        }
        else
        {
                if (val == 0)
                {
                        cancel_delayed_work_sync(&data->als_work);
                        data->enable_als_sensor = 0;
                }
        }
        mutex_unlock(&data->op_lock);
        return 0;
}

static int tmd27723_als_set_enable(struct sensors_classdev *sensors_cdev,
                                   unsigned int enable)
{
        struct tmd27723_data *data = container_of(sensors_cdev,
                                                  struct tmd27723_data,
                                                  als_cdev);
        if ((enable != 0)&&(enable !=1))
        {
                printk("%s:L-Sensor invalid value(%d)\n", __func__, enable);
                return -EINVAL;
        }

        return tmd27723_enable_als_sensor(data->client, enable);
}


static int tmd27723_enable_ps_sensor(struct i2c_client *client, int val)
{
        struct tmd27723_data *data = i2c_get_clientdata(client);
//        int rc;
        int pre_enable = data->enable_ps_sensor;

        mutex_lock(&data->op_lock);
        if (pre_enable == 0)
        {
                if (val == 1)
                {
#if 0
                        rc = tmd27723_init_device(client);
                        if (rc)
                        {
                                printk ("Failed to init tmd27723\n");
                                mutex_unlock(&data->op_lock);
                                return rc;
                        }
#endif
#if 0
                        if (!data->suspend_state){
                                input_report_abs(data->input_dev_ps, ABS_DISTANCE, 1); 
                                input_sync (data->input_dev_ps);
                        }
#endif
                        psensor_first_enable = 1;
                        schedule_delayed_work(&data->ps_work,msecs_to_jiffies(20));
                        data->enable_ps_sensor = 1;
                }
        }
        else
        {
                if (val == 0)
                {
                        cancel_delayed_work_sync(&data->ps_work);
						//fix bug :p-sensor always work
						tmd27723_set_enable(client, 0);
                        data->enable_ps_sensor = 0;
                }
        }
        mutex_unlock(&data->op_lock);
        return 0;
}


static int tmd27723_ps_set_enable(struct sensors_classdev *sensors_cdev,
                                   unsigned int enable)
{
        struct tmd27723_data *data = container_of(sensors_cdev,
                                                  struct tmd27723_data,
                                                  ps_cdev);
        if ((enable != 0)&&(enable !=1))
        {
                pr_err("%s:P-Sensor invalid value(%d)\n", __func__, enable);
                return -EINVAL;
        }
		printk("tmd27723_ps_set_enable : %d",enable);
        return tmd27723_enable_ps_sensor(data->client, enable);
}

/*
 *Set Pers
 */
static int tmd27723_set_pers(struct i2c_client *client, int pers)
{
        struct tmd27723_data *data = i2c_get_clientdata(client);
        int ret;

        mutex_lock(&data->update_lock);
        ret = i2c_smbus_write_byte_data(client,CMD_BYTE|TMD27723_PERS_REG,pers);
        mutex_unlock(&data->update_lock);

        data->pers = pers;

        return ret;
}

/*
 *Set Aiht
 */
static int tmd27723_set_aiht(struct i2c_client *client, int threshold)
{
        struct tmd27723_data *data = i2c_get_clientdata(client);
        int ret;

        mutex_lock(&data->update_lock);
        ret = i2c_smbus_write_word_data(client,CMD_BYTE|TMD27723_AIHTL_REG,threshold);
        mutex_unlock(&data->update_lock);

        data->aiht = threshold;

        return ret;
}

/*
 *Set Ailt
 */
static int tmd27723_set_ailt(struct i2c_client *client, int threshold)
{
        struct tmd27723_data *data = i2c_get_clientdata(client);
        int ret;

        mutex_lock(&data->update_lock);
        ret = i2c_smbus_write_word_data(client,CMD_BYTE|TMD27723_AILTL_REG,threshold);
        mutex_unlock(&data->update_lock);

        data->ailt = threshold;

        return ret;
}

static void tmd27723_set_ps_threshold_adding_cross_talk (struct i2c_client *client,
                                                         int cal_data)
{
        struct tmd27723_data *data = i2c_get_clientdata(client);

        if (cal_data > 770)
                cal_data = 770;
        if (cal_data < 0)
                cal_data = 0;

        if (cal_data == 0)
        {
                data->ps_threshold = tmd27723_ps_detection_threshold;
                data->ps_hysteresis_threshold = data->ps_threshold - 100;
        }
        else
        {
                data->cross_talk = cal_data;
                data->ps_threshold = 300 + data->cross_talk;
                data->ps_hysteresis_threshold = data->ps_threshold - 100;
        }
}

/*
 *Set Piht
 */
static int tmd27723_set_piht(struct i2c_client *client, int threshold)
{
        struct tmd27723_data *data = i2c_get_clientdata(client);
        int ret ;

        mutex_lock(&data->update_lock);
        ret = i2c_smbus_write_word_data(client,
                                        CMD_BYTE|TMD27723_PIHTL_REG,
                                        threshold);
        mutex_unlock(&data->update_lock);

        data->piht = threshold;

        return ret;
}
/*
 *Set Pilt
 */
static int tmd27723_set_pilt(struct i2c_client *client, int threshold)
{
        struct tmd27723_data *data = i2c_get_clientdata(client);
        int ret;

        mutex_lock(&data->update_lock);
        ret = i2c_smbus_write_word_data(client,
                                        CMD_BYTE|TMD27723_PILTL_REG,
                                        threshold);
        mutex_unlock(&data->update_lock);

        data->pilt = threshold;

        return ret;
}
/*
 *Set Control
 */
static int tmd27723_set_control(struct i2c_client *client, int control)
{
        struct tmd27723_data *data = i2c_get_clientdata(client);
        int ret;

        mutex_lock(&data->update_lock);
        ret = i2c_smbus_write_byte_data(client,
                                        CMD_BYTE|TMD27723_CONTROL_REG,
                                        control);
        mutex_unlock(&data->update_lock);

        data->control = control;

        return ret;
}
static int tmd27723_set_config(struct i2c_client *client, int config)
{
        struct tmd27723_data *data = i2c_get_clientdata(client);
        int ret;

        mutex_lock(&data->update_lock);
        ret = i2c_smbus_write_byte_data(client,
                                        CMD_BYTE|TMD27723_CONFIG_REG,
                                        config);
        mutex_unlock(&data->update_lock);

        data->config = config;
        return ret;
}
/*
 *Set PPcount
 */
static int tmd27723_set_ppcount(struct i2c_client *client, int ppcount)
{
        struct tmd27723_data *data = i2c_get_clientdata(client);
        int ret;

        mutex_lock(&data->update_lock);
        ret = i2c_smbus_write_byte_data(client,
                                        CMD_BYTE|TMD27723_PPCOUNT_REG,
                                        ppcount);
        mutex_unlock(&data->update_lock);

        data->ppcount = ppcount;

        return ret;
}
/*
 *Set Wtime
 */
static int tmd27723_set_wtime(struct i2c_client *client, int wtime)
{
        struct tmd27723_data *data = i2c_get_clientdata(client);
        int ret;

        mutex_lock(&data->update_lock);
        ret = i2c_smbus_write_byte_data(client,
                                        CMD_BYTE|TMD27723_WTIME_REG,
                                        wtime);
        mutex_unlock(&data->update_lock);

        data->wtime = wtime;

        return ret;
}

/*
 *Set Ptime
 */
static int tmd27723_set_ptime(struct i2c_client *client, int ptime)
{
        struct tmd27723_data *data = i2c_get_clientdata(client);
        int ret;

        mutex_lock(&data->update_lock);
        ret = i2c_smbus_write_byte_data(client,
                                        CMD_BYTE|TMD27723_PTIME_REG,
                                        ptime);
        mutex_unlock(&data->update_lock);

        data->ptime = ptime;

        return ret;
}
/*
 *Set Atime
 */
static int tmd27723_set_atime(struct i2c_client *client, int atime)
{
        struct tmd27723_data *data = i2c_get_clientdata(client);
        int ret;

        mutex_lock(&data->update_lock);
        ret = i2c_smbus_write_byte_data(client,
                                        CMD_BYTE|TMD27723_ATIME_REG,
                                        atime);
        mutex_unlock(&data->update_lock);

        data->atime = atime;

        return ret;
}


/***************************
 *Set Chip Enable or Disable
 ***************************/
static int tmd27723_set_enable(struct i2c_client *client, int enable)
{
        struct tmd27723_data *data = i2c_get_clientdata(client);
        int ret;

        mutex_lock (&data->enable_lock);
        ret = i2c_smbus_write_byte_data(client,
                                        CMD_BYTE|TMD27723_ENABLE_REG,
                                        enable);
        mutex_unlock (&data->enable_lock);

        data->enable = enable;

        return ret;
}

/*****************************
 *Initialization Chip Function
 *****************************/
static int tmd27723_init_device(struct i2c_client *client)
{
        struct tmd27723_data *data = i2c_get_clientdata(client);
        int err;

        err = tmd27723_set_enable(client, 1);
        if (err < 0)
                return err;

        /*100.64ms ALS integration time*/
        err = tmd27723_set_atime(client,0xDB);
        if (err < 0)
                return err;

        /*2.72ms Prox integration time*/
        err = tmd27723_set_ptime(client, 0xFF);
        if (err < 0)
                return err;

        /*2.72ms Wait time*/
        err = tmd27723_set_wtime(client, 0xFF);
        if (err < 0)
                return err;

	err = tmd27723_set_ppcount(client, 6);
		//err = tmd27723_set_ppcount(client, tmd27723_ps_pulse_number);
        if (err < 0)
                return err;

        err = tmd27723_set_config(client, 0);
        if (err < 0)
                return err;

        err = tmd27723_set_control(client,
                                   TMD27723_PDRVIE_100MA|
                                   TMD27723_PRX_IR_DIOD|
                                   tmd27723_ps_pgain|
                                   0x01);
        if (err < 0)
                return err;

	i2c_smbus_write_byte_data(client,CMD_BYTE|TMD27723_POFFSET_REG, 0);
	
#if 1
        /*init threshold for proximity*/
        err = tmd27723_set_pilt(client, 0);
        if (err < 0)
                return err;

        err = tmd27723_set_piht(client, tmd27723_ps_detection_threshold);
        if (err < 0)
                return err;

        /*calibration*/
        tmd27723_set_ps_threshold_adding_cross_talk(client, data->cross_talk);
        data->ps_detection = 0;

        /* force first ALS interrupt to get the environment reading */
        err = tmd27723_set_ailt(client, 0xFFFF);
        if (err < 0)
                return err;

        err = tmd27723_set_aiht(client, 0);
        if (err < 0)
                return err;

        /* 2 consecutive Interrupt persistence */
        err = tmd27723_set_pers(client, 0x20|0x02);
        if (err < 0)
                return err;

        /*sensor is in disabled mode but all the configurations are preset*/
        return 0;

#endif
msleep(25);
}

/**********************
 *Read Chip ID Function
 ***********************/
static int tmd27723_check_chip_id (struct i2c_client *client, int *id)
{
        *id = i2c_smbus_read_byte_data(client, CMD_BYTE|TMD27723_ID_REG);

        switch (*id)
        {
                case TMD27723_ID:
                        printk ("L/P-Sensor is TMD27723!\n");
                        break;
                case TMD27721_ID:
                        printk ("L/P-Sensor is TMD27721!\n");
                        break;
                default:
                        return -ENODEV;
        }
        return 0;
}
static void tmd27723_ps_work_func (struct work_struct *work)
{
        struct tmd27723_data *data = container_of((struct delayed_work *)work,
                                                   struct tmd27723_data,
                                                   ps_work);
        struct i2c_client *client = data->client;
        int status;
        int enable;
        uint8_t wen,pen,aen,pon,ppcount;
        wen = 8;
        pen = 4;
        aen = 2;
        pon = 1;
        ppcount = 6;
        //i2c_smbus_write_byte_data(client,CMD_BYTE|0x0e,ppcount);
        i2c_smbus_write_byte_data(client,CMD_BYTE|TMD27723_ENABLE_REG,wen|pen|aen|pon);
        msleep(10);   //for optimize sleep out time from 50->10

        status = i2c_smbus_read_byte_data(client, CMD_BYTE|TMD27723_STATUS_REG);
        enable = i2c_smbus_read_byte_data(client, CMD_BYTE|TMD27723_ENABLE_REG);
#if 0
        /*Enable P-Sensor*/
        i2c_smbus_write_byte_data(client,
                                  CMD_BYTE|TMD27723_ENABLE_REG,
                                  1);
#endif
        data->ps_data = i2c_smbus_read_word_data(client,CMD_WORD|TMD27723_PDATAL_REG);
#ifdef SENSOR_DEBUG
        printk ("ps_data = %d\n",data->ps_data);
/*				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_ENABLE_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_ENABLE_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_ATIME_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_ATIME_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_PTIME_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_PTIME_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_WTIME_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_WTIME_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_AILTL_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_AILTL_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_AILTH_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_AILTH_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_AIHTL_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_AIHTL_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_AIHTH_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_AIHTH_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_PILTL_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_PILTL_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_PILTH_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_PILTH_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_PIHTL_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_PIHTL_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_PIHTH_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_PIHTH_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_PERS_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_PERS_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_CONFIG_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_CONFIG_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_PPCOUNT_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_PPCOUNT_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_CONTROL_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_CONTROL_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_REV_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_REV_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_ID_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_ID_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_STATUS_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_STATUS_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_CH0DATAL_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_CH0DATAL_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_CH0DATAH_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_CH0DATAH_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_CH1DATAL_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_CH1DATAL_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_CH1DATAH_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_CH1DATAH_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_PDATAL_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_PDATAL_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_PDATAH_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_PDATAH_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_POFFSET_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_POFFSET_REG));

*/
#endif
        //globle_data->ps_cur_data.counter = data->ps_data;
        atomic_set(&globle_data->ps_citvalue,data->ps_data);
        mutex_lock (&data->ps_lock);

        //if (globle_data->ps_citvalue.counter >= globle_data->ps_5_cal_value.counter)
        if (globle_data->ps_citvalue.counter >= 450)
        {
                data->ps_data = 0;
               if ( psensor_first_enable  == 1)
               {
                        psensor_last_report_near+=2;
                        if (psensor_last_report_near==98)
                                psensor_last_report_near = 0;
                        input_report_abs(data->input_dev_ps, ABS_DISTANCE,psensor_last_report_near);
                        input_sync(data->input_dev_ps);
                        psensor_first_enable = 0;
                }else 
                {
                        if (last_data!= data->ps_data)
                        {
                                psensor_last_report_near+=2;
                                if (psensor_last_report_near==98)
                                psensor_last_report_near = 0;
                                input_report_abs(data->input_dev_ps, ABS_DISTANCE,psensor_last_report_near);
                                input_sync(data->input_dev_ps);
                        }
                }
                
                last_data = 0;
        }
         //if (globle_data->ps_citvalue.counter >= globle_data->ps_5_cal_value.counter)
        if (globle_data->ps_citvalue.counter >= 300 && globle_data->ps_citvalue.counter < 450)
        {
           if(last_data == 0){
           	 data->ps_data = 0;
               if ( psensor_first_enable  == 1)
               {
                        psensor_last_report_near+=2;
                        if (psensor_last_report_near==98)
                                psensor_last_report_near = 0;
                        input_report_abs(data->input_dev_ps, ABS_DISTANCE,psensor_last_report_near);
                        input_sync(data->input_dev_ps);
                        psensor_first_enable = 0;
                }else 
                {
                        if (last_data!= data->ps_data)
                        {
                                psensor_last_report_near+=2;
                                if (psensor_last_report_near==98)
                                psensor_last_report_near = 0;
                                input_report_abs(data->input_dev_ps, ABS_DISTANCE,psensor_last_report_near);
                                input_sync(data->input_dev_ps);
                        }
                }
                
                last_data = 0;
       		 }
       		 
       		 else {
                data->ps_data = 1;
                if (psensor_first_enable == 1)
                {
                        psensor_last_report_far+=2;
                        if (psensor_last_report_far==99)
                                psensor_last_report_far = 1;
                        input_report_abs(data->input_dev_ps, ABS_DISTANCE, psensor_last_report_far);
                        input_sync(data->input_dev_ps);
                        psensor_first_enable = 0;
                }else 
                {
                        if (last_data!= data->ps_data)
                        {
                        psensor_last_report_far+=2;
                        if (psensor_last_report_far==99)
                                psensor_last_report_far = 1;
                        input_report_abs(data->input_dev_ps, ABS_DISTANCE, psensor_last_report_far);
                        input_sync(data->input_dev_ps);
                        }
                 }
                last_data = 1;
         	 }
       		 
      	}
        //else if (globle_data->ps_citvalue.counter < globle_data->ps_5_cal_value.counter)
        else if (globle_data->ps_citvalue.counter < 300)
        {
                data->ps_data = 1;
                if (psensor_first_enable == 1)
                {
                        psensor_last_report_far+=2;
                        if (psensor_last_report_far==99)
                                psensor_last_report_far = 1;
                        input_report_abs(data->input_dev_ps, ABS_DISTANCE, psensor_last_report_far);
                        input_sync(data->input_dev_ps);
                        psensor_first_enable = 0;
                }else 
                {
                        if (last_data!= data->ps_data)
                        {
                        psensor_last_report_far+=2;
                        if (psensor_last_report_far==99)
                                psensor_last_report_far = 1;
                        input_report_abs(data->input_dev_ps, ABS_DISTANCE, psensor_last_report_far);
                        input_sync(data->input_dev_ps);
                        }
                 }
                last_data = 1;
         }

        mutex_unlock(&data->ps_lock);

        schedule_delayed_work(&data->ps_work,msecs_to_jiffies(20));
}

static int LuxCalculation(struct i2c_client *client, int ch0data, int ch1data)
{
        struct tmd27723_data *data = i2c_get_clientdata(client);
        int luxValue = 0;
        int IAC1 = 0;
        int IAC2 = 0;
        int IAC  = 0;

        if ((ch0data >= 37888)||(ch1data >=37888))
        {
                luxValue = data->als_prev_lux;
                return luxValue;
        }
        /* re-adjust COE_B to avoid 2 decimal point */
        IAC1 = (ch0data - (186 * ch1data) / 100);
        /* re-adjust COE_C and COE_D to void 2 decimal point */
        IAC2 = ((75 * ch0data) / 100 -(129 * ch1data) / 100);

        if (IAC1 > IAC2)
                IAC = IAC1;
        else if (IAC1 <= IAC2)
                IAC = IAC2;
        else
                IAC = 0;
        if (IAC1 < 0 && IAC2 < 0)
        {
                IAC = 0;
                return -1;
        }

        if (data->als_reduce)
        {
                luxValue = ((IAC * 560 * 52) / 100) * 65 / 10 /
                            ((5168 / 100) * 8);
        }
        else
        {
                luxValue = ((IAC * 560 * 52) /100) /
                           ((5168 / 100) * 8);
        }

        return luxValue;
}



static void tmd27723_als_work_func (struct work_struct *work)
{
        struct tmd27723_data *data = container_of ((struct delayed_work *)work,
                                                   struct tmd27723_data,
                                                   als_work);
        struct i2c_client *client=data->client;
        int ch0data, ch1data;
	int v1, v2;
        int luxValue;
        unsigned char lux_is_valid=1;
        uint8_t atime,ptime,wtime,ppcount;
        uint8_t pdrive,pdiode,pgain;
	int again;
        uint8_t wen,pen,aen,pon;
        atime = 183;//0xDB;
        wtime = 0xff;
        ptime = 0xff;
        ppcount = 1;

        pdrive = 0;
        pdiode = 0x20;
        pgain = 0;

        wen = 8;
        pen = 4;
        aen = 2;
        pon = 1;
        atime = i2c_smbus_read_byte_data(client,CMD_BYTE|0x01);
        i2c_smbus_write_byte_data(client,CMD_BYTE|0x00,0);
        i2c_smbus_write_byte_data(client,CMD_BYTE|0x01,183);
        i2c_smbus_write_byte_data(client,CMD_BYTE|0x02,ptime);
        i2c_smbus_write_byte_data(client,CMD_BYTE|0x03,wtime);
        //i2c_smbus_write_byte_data(client,CMD_BYTE|TMD27723_CONTROL_REG,pdrive|pdiode|pgain|again);
	again = i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_CONTROL_REG) & 3;
        //atime = i2c_smbus_read_byte_data(client,CMD_BYTE|0x01);

        i2c_smbus_write_byte_data(client,CMD_BYTE|TMD27723_ENABLE_REG,wen|pen|aen|pon);
        msleep(50);

        ch0data = i2c_smbus_read_word_data(client,CMD_WORD|TMD27723_CH0DATAL_REG);
        ch1data = i2c_smbus_read_word_data(client,CMD_WORD|TMD27723_CH1DATAL_REG);
#if 0 
        printk ("ch0data =%d\n",ch0data);
        printk ("ch1data =%d\n",ch1data);
#endif
	if (ch0data > 18000) {
		i2c_smbus_write_byte_data(client,CMD_BYTE|TMD27723_CONTROL_REG,pdrive|pdiode|pgain|0x00);
		goto next;
        	//i2c_smbus_write_byte_data(client,CMD_BYTE|TMD27723_ENABLE_REG,wen|pen|aen|pon);
        	//msleep(50);

        	//ch0data = i2c_smbus_read_word_data(client,CMD_WORD|TMD27723_CH0DATAL_REG);
        	//ch1data = i2c_smbus_read_word_data(client,CMD_WORD|TMD27723_CH1DATAL_REG);
	}
	else {
		i2c_smbus_write_byte_data(client,CMD_BYTE|TMD27723_CONTROL_REG,pdrive|pdiode|pgain|0x01);
	}

        luxValue = LuxCalculation(client, ch0data, ch1data);
	again = again ? 8 : 1;
#if 1 


	//v1 = 9198 * (10 * (int64_t)ch0data - 22 * (int64_t)ch1data) / (10 * (int64_t)again * 200);

	v1 = (10 * ch0data - 22 * ch1data);
	v1 = 11360 / again * v1 / 200 / 10;
	//v2 = 322 * (100 * (int64_t)ch0data - 167 * (int64_t)ch1data) / (100 * (int64_t)again * 200);
	v2 = 322 * (100 * ch0data - 167 * ch1data) / (100 * again * 200);
	luxValue = (int)(v1 > v2 ? v1 : v2);

#endif

        if (luxValue >= 0)
        {
                luxValue = (luxValue < ALS_MAX_RANGE)?luxValue:ALS_MAX_RANGE;
                data->als_prev_lux = luxValue;
        }
        else
        {
                /* don't report, the lux is invalid value */
                lux_is_valid = 0;
                luxValue = data->als_prev_lux;
                /* report anyway since this is the lowest gain */
                if (data->als_reduce)
                        lux_is_valid = 1;
        }
        mutex_lock (&data->als_lock);
        if (lux_is_valid)
        {
                input_report_abs(data->input_dev_als, ABS_MISC, luxValue);
                input_sync(data->input_dev_als);
        }
        mutex_unlock (&data->als_lock);
next:
        schedule_delayed_work(&data->als_work,msecs_to_jiffies(400));
}

#if 1
static int tmd27723_power_control(struct tmd27723_data *data,bool on)
{
        int rc = 0;

        if (!on)
        {
                rc = regulator_disable(data->vdd);
                if (rc)
                {
                        printk ("tmd27723 Regulator vdd disable failed \n");
                        return rc;
                }
                rc = regulator_disable(data->vio);
                if (rc)
                {
                        printk ("tmd27723 Regulator vio disable failed \n");
                        rc = regulator_enable(data->vdd);
                        if (!rc)
                        {
                                rc = -EBUSY;
                                goto enable_delay;
                        }
                }
                return rc;
        }
        else
        {
                rc = regulator_enable(data->vdd);
                if (rc)
                {
                        printk ("tmd27723 Regulator vdd enable failed\n");
                        return rc;
                }

                rc = regulator_enable(data->vio);
                if (rc)
                {
                        printk ("Regulator vio enable failed\n");
                        regulator_disable(data->vdd);
                        return rc;
                }
        }

        return 0;
enable_delay:
        msleep(130);
        printk ("Sensor regulator power on\n");

        return rc;
}

static int tmd27723_power_init (struct tmd27723_data *data)
{
        int ret;

        data->vdd = regulator_get(&data->client->dev, "vdd");
        if (IS_ERR(data->vdd))
        {
                ret = PTR_ERR(data->vdd);
                printk ("tmd27723 Regulator get failed vdd\n");
                return ret;
        }

        if (regulator_count_voltages(data->vdd) > 0)
        {
                ret = regulator_set_voltage(data->vdd,
                                            TMD27723_VDD_MIN_UV,
                                            TMD27723_VDD_MAX_UV);
                if (ret)
                {
                        printk ("tmd27723 Regulator set failed vdd\n");
                        goto reg_vdd_put;
                }
        }

        data->vio = regulator_get(&data->client->dev, "vio");
        if (IS_ERR(data->vio))
        {
                ret = PTR_ERR(data->vio);
                printk ("tmd27723 Regulator get failed vio\n");
                goto reg_vdd_set;
        }

        if (regulator_count_voltages(data->vio) > 0)
        {
                ret = regulator_set_voltage(data->vio,
                                            TMD27723_VIO_MIN_UV,
                                            TMD27723_VIO_MAX_UV);
                if (ret)
                {
                        printk ("tmd27723 Regulator set failed vio\n");
                        goto reg_vio_put;
                }
        }

        return 0;
reg_vio_put:
        regulator_put(data->vio);
reg_vdd_set:
        if (regulator_count_voltages(data->vdd) > 0)
                regulator_set_voltage(data->vdd, 0, TMD27723_VDD_MAX_UV);
reg_vdd_put:
        regulator_put(data->vdd);
        return ret;

}

static int tmd27723_power_deinit(struct tmd27723_data *data)
{
        if (regulator_count_voltages(data->vdd) > 0)
        {
                regulator_set_voltage(data->vdd,0,TMD27723_VDD_MAX_UV);
        }
        regulator_put(data->vdd);

        if (regulator_count_voltages(data->vio) > 0)
        {
                regulator_set_voltage(data->vio,0,TMD27723_VIO_MAX_UV);
        }
        regulator_put(data->vio);
        return 0;
}


#endif
static ssize_t ps_citvalue_show(struct device *dev, struct device_attribute *attr, char *buf)
{
        return snprintf(buf,PAGE_SIZE,"%d\n",atomic_read(&globle_data->ps_citvalue));
}
static DEVICE_ATTR(ps_citvalue,0444,ps_citvalue_show,NULL);

static ssize_t ps_control_reg_show (struct device *dev,
				    struct device_attribute *attr,
				    char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	int control;
	control = i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_CONTROL_REG);
		printk(".............................control-0x0f=%d\n",control);
		
	return snprintf (buf,PAGE_SIZE,"%d\n",control);
}


static ssize_t ps_control_reg_store(struct device *dev,
				    struct device_attribute *attr,
				    const char *buf,
				    size_t count)
{
	struct i2c_client *client = to_i2c_client(dev);
	unsigned long ps_control_value;

	if (kstrtoul(buf, 10, &ps_control_value))
	{
		return -EINVAL;
	}

	i2c_smbus_write_byte_data(client,CMD_BYTE|TMD27723_CONTROL_REG, ps_control_value);
	printk("............ps_control_value=%lu",ps_control_value);
	return count;
}
static DEVICE_ATTR(ps_control_reg,0664,ps_control_reg_show,ps_control_reg_store);

static ssize_t ps_config_reg_show (struct device *dev,
				    struct device_attribute *attr,
				    char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	int config;
	config = i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_CONFIG_REG);
	printk(".............................config-0x0d=%d\n",config);
		
	return snprintf (buf,PAGE_SIZE,"%d\n",config);
}


static ssize_t ps_config_reg_store(struct device *dev,
				    struct device_attribute *attr,
				    const char *buf,
				    size_t count)
{
	struct i2c_client *client = to_i2c_client(dev);
	unsigned long ps_config_value;

	if (kstrtoul(buf, 10, &ps_config_value))
	{
		return -EINVAL;
	}

	i2c_smbus_write_byte_data(client,CMD_BYTE|TMD27723_CONFIG_REG, ps_config_value);
	printk("............ps_config_value=%lu",ps_config_value);
	return count;
}
static DEVICE_ATTR(ps_config_reg,0664,ps_config_reg_show,ps_config_reg_store);

static ssize_t ps_ppcount_reg_show (struct device *dev,
				    struct device_attribute *attr,
				    char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	int ppcount;
	ppcount = i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_PPCOUNT_REG);
	printk(".............................ppcount-0x0e=%d\n",ppcount);
		
	return snprintf (buf,PAGE_SIZE,"%d\n",ppcount);
}


static ssize_t ps_ppcount_reg_store(struct device *dev,
				    struct device_attribute *attr,
				    const char *buf,
				    size_t count)
{
	struct i2c_client *client = to_i2c_client(dev);
	unsigned long ps_ppcount_value;

	if (kstrtoul(buf, 10, &ps_ppcount_value))
	{
		return -EINVAL;
	}

	i2c_smbus_write_byte_data(client,CMD_BYTE|TMD27723_PPCOUNT_REG, ps_ppcount_value);
	printk("............ps_ppcount_value=%lu",ps_ppcount_value);
	return count;
}
static DEVICE_ATTR(ps_ppcount_reg,0664,ps_ppcount_reg_show,ps_ppcount_reg_store);

static ssize_t ps_3_cal_value_show (struct device *dev,
				    struct device_attribute *attr,
				    char *buf)
{
	return snprintf (buf,PAGE_SIZE,"%d\n",atomic_read(&globle_data->ps_3_cal_value));
}


static ssize_t ps_3_cal_value_store(struct device *dev,
				    struct device_attribute *attr,
				    const char *buf,
				    size_t count)
{
	unsigned long cal_value;

	if (kstrtoul(buf, 10, &cal_value))
	{
		return -EINVAL;
	}
	atomic_set(&globle_data->ps_3_cal_value, (unsigned int)cal_value);
	return count;
}
static DEVICE_ATTR(ps_3_cal_value,0664,ps_3_cal_value_show,ps_3_cal_value_store);
static ssize_t ps_5_cal_value_show (struct device *dev,
				    struct device_attribute *attr,
				    char *buf)
{
	return snprintf (buf,PAGE_SIZE,"%d\n",atomic_read(&globle_data->ps_5_cal_value));
}

static ssize_t ps_5_cal_value_store(struct device *dev,
				    struct device_attribute *attr,
				    const char *buf,
				    size_t count)
{
	unsigned long cal_value;

	if (kstrtoul(buf, 10, &cal_value))
	{
		return -EINVAL;
	}
	atomic_set(&globle_data->ps_5_cal_value, (unsigned int)cal_value);
	return count;
}
static DEVICE_ATTR(ps_5_cal_value,0664,ps_5_cal_value_show,ps_5_cal_value_store);


static ssize_t ps_offset_level_show (struct device *dev,
				    struct device_attribute *attr,
				    char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	int ps_offset_value;
		
	ps_offset_value=i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_POFFSET_REG);
	printk("............ps_offset_value=%d\n",ps_offset_value);

	return snprintf (buf,PAGE_SIZE,"%d\n",ps_offset_value);
}


static ssize_t ps_offset_level_store(struct device *dev,
				    struct device_attribute *attr,
				    const char *buf,
				    size_t count)
{
	struct i2c_client *client = to_i2c_client(dev);
	unsigned long ps_offset_value;

	if (kstrtoul(buf, 10, &ps_offset_value))
	{
		return -EINVAL;
	}

	i2c_smbus_write_byte_data(client,CMD_BYTE|TMD27723_POFFSET_REG, ps_offset_value);
	printk("............ps_offset_value=%lu",ps_offset_value);
	return count;
}
static DEVICE_ATTR(ps_offset_level,0664,ps_offset_level_show,ps_offset_level_store);

static ssize_t ps_calibrate_prox_show (struct device *dev,
				    struct device_attribute *attr,
				    char *buf)
{
	return snprintf (buf,PAGE_SIZE,"%d\n",atomic_read(&globle_data->ps_5_cal_value));
}


static ssize_t ps_calibrate_prox_store(struct device *dev,
				    struct device_attribute *attr,
				    const char *buf,
				    size_t count)
{

	struct i2c_client *client = to_i2c_client(dev);
        struct tmd27723_data *data = i2c_get_clientdata(client);
    
//struct mpu6050_sensor *sensor = dev_get_drvdata(dev);
	//struct tmd27723_data *data =dev_get_drvdata(dev);
	//struct tmd27723_data *data = dev_get_drvdata(dev);
//	unsigned long on;
	//int reg = 0;
	
//	if (kstrtoul(buf, 10, &on))
//	{
//		return -EINVAL;
//	}
printk("\n................calibrate...........................\n");
 	//printk("............on=%d",buf);
//	if(on){

//		 schedule_delayed_work(&data->ps_offset_work,msecs_to_jiffies(20));
//		 printk("............on=%lu",on);
//		 on=0;
//		 printk("............on=%lu",on);
		 
	schedule_delayed_work(&data->ps_calibrate_work,msecs_to_jiffies(20));
        	//reg=tmd27723_ps_calibrate (data);
        	//if (reg){
            	//   	  printk ("Failed to set ps_calibrate_prox\n");
            // 		 return 1; 
       		//}
	return count;
}
static DEVICE_ATTR(ps_calibrate_prox,0664,ps_calibrate_prox_show,ps_calibrate_prox_store);



#if defined(CONFIG_FB)
static int fb_notifier_callback(struct notifier_block *self,
                                  unsigned long event, void *e_data);
#endif

static void tmd27723_ps_calibrate_func (struct work_struct *work){

/*	struct tmd27723_data *data = container_of((struct delayed_work *)work,
                                                   struct tmd27723_data,
                                                   ps_offset_work);
                                                   */
//printk("000.............................pdata=%d\n",data->ps_data);
//struct i2c_client *client = data->client;
 struct tmd27723_data *data = container_of((struct delayed_work *)work,
                                                   struct tmd27723_data,
                                                   ps_calibrate_work);
      	struct i2c_client *client = data->client;
	int status;
       int enable;
       uint8_t wen,pen,aen,pon,ppcount;
	uint8_t byteVal;
	uint8_t direction;
	uint16_t first_ps_data;
	int offset;
	int i ,reg;
       wen = 8;
       pen = 4;
       aen = 2;
       pon = 1;
       ppcount = 6;
	direction = 0;
	byteVal = 0;
	offset = 0;
	//printk("001.............................pdata=%d\n",data->ps_data);
	// i2c_smbus_write_byte_data(client,CMD_BYTE|0x0e,6);
	
        i2c_smbus_write_byte_data(client,CMD_BYTE|TMD27723_ENABLE_REG,wen|pen|aen|pon);
        msleep(10);   //for optimize sleep out time from 50->10

	 status = i2c_smbus_read_byte_data(client, CMD_BYTE|TMD27723_STATUS_REG);
        enable = i2c_smbus_read_byte_data(client, CMD_BYTE|TMD27723_ENABLE_REG);

	data->ps_data =  i2c_smbus_read_word_data(client,CMD_WORD|TMD27723_PDATAL_REG);
		printk(".............................data->ps_data=%d\n",data->ps_data);
		
		reg=i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_POFFSET_REG);
		printk ("1................... POFFSET_REG=%d\n",reg);
		//if(reg!=0&&data->ps_data>globle_data->ps_5_cal_value.counter){
		//if(reg!=0&&data->ps_data>600){
		//return 2;
		//}
	//i2c_smbus_write_byte_data(client,CMD_BYTE|TMD27723_POFFSET_REG, byteVal);
	msleep(25);
	
		//printk ("2................... POFFSET_REG=%d\n",i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_POFFSET_REG));

	//data->ps_data =  i2c_smbus_read_word_data(client,CMD_WORD|TMD27723_PDATAL_REG);
	
		printk(".............................pdata=%d\n",data->ps_data);
	 
		printk ("................. status =%d\n",status);
		printk ("................. enable =%d\n",enable);
	//offset =i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_POFFSET_REG);
	//printk("*.............................offset=%d\n",offset);
	//	if (offset>127)
	//	offset=128-offset;
	//printk("*.............................offset=%d\n",offset);
	//data->ps_data=0;
	i2c_smbus_write_byte_data(client,CMD_BYTE|TMD27723_POFFSET_REG, byteVal);
	msleep(25);
		printk("........................offset=%d\n",offset);
		
	first_ps_data =  i2c_smbus_read_word_data(client,CMD_WORD|TMD27723_PDATAL_REG);
		printk(".............................first_ps_data=%d\n",first_ps_data);
		
	for (i = 0; i < 128; i++)
	{
	first_ps_data =  i2c_smbus_read_word_data(client,CMD_WORD|TMD27723_PDATAL_REG);
	//data->ps_data =  i2c_smbus_read_word_data(client,CMD_WORD|TMD27723_PDATAL_REG);
		//for(j=0;j<10;j++){
		//	ps_data =  i2c_smbus_read_word_data(client,CMD_WORD|TMD27723_PDATAL_REG);
		//	data->ps_data=ps_data+data->ps_data;
		//}
		//data->ps_data=data->ps_data/10;
		
		printk(".............................pdata=%d\n",first_ps_data);
				
		if (direction != 2 && first_ps_data < 100)//direction up
		{
			//offset=128;
			if (offset == -127){
				printk("...offset fail");
			//	return 1;
				break;
			//if(offset==255){
				//printk("...offset fail");
				//return 1;
				}
			direction = 1;
			offset--;
			//globle_data->ps_offset=byteVal = (uint8_t)offset;
			data->ps_offset=byteVal = (uint8_t)(128 - offset);
			i2c_smbus_write_byte_data(client,CMD_BYTE|TMD27723_POFFSET_REG, byteVal);
			printk( ".....................direction up, proximity offset %d \n", offset);
			printk("......................direction %d \n", direction);
			//printk ("................... POFFSET_REG=%d\n",i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_POFFSET_REG));
		}
		//else if (direction != 1 && data->ps_data >= 100)//direction down
		else if (first_ps_data >= 100)//direction down
		{
			//offset=0;
			 //printk("\n---------->down----------\n");
			if (offset == 127){
				printk("...offset fail");
				//return 1;
				break;
				}
			direction = 2;
			offset++;
			data->ps_offset=byteVal = (uint8_t)offset;
			status = i2c_smbus_write_byte_data(client,CMD_BYTE|TMD27723_POFFSET_REG, byteVal);
			
			printk("......................direction down, proximity offset %d \n", offset);
			printk("......................direction %d \n", direction);
			//printk ("................... POFFSET_REG=%d\n",i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_POFFSET_REG));
		}
		else{
			printk("......................direction %d \n", direction);
			printk("\n-----------else over----------\n");
			//return 0;
			break;
			}

		//printk("\n----------msleep25----------\n");	
		msleep(25);
		//printk("\n----------msleep25end----------\n");
		//printk("......................direction %d \n", direction);
	}
	 tmd27723_set_enable(client, 1);
       // if (err < 0)
        //        return 1;
  //printk("\n----------msleep10----------\n");       
  msleep(10);  
	   cancel_delayed_work_sync(&data->ps_calibrate_work);
 // printk("\n----------msleep10end----------\n");
// return 0;


    /*    
        i2c_smbus_write_byte_data(client,CMD_BYTE|0x0e,ppcount);
        i2c_smbus_write_byte_data(client,CMD_BYTE|TMD27723_ENABLE_REG,wen|pen|aen|pon);
        msleep(10);   //for optimize sleep out time from 50->10

        status = i2c_smbus_read_byte_data(client, CMD_BYTE|TMD27723_STATUS_REG);
        enable = i2c_smbus_read_byte_data(client, CMD_BYTE|TMD27723_ENABLE_REG);
		printk ("................. status =%d\n",status);
		printk ("................. enable =%d\n",enable);

		printk (".................PDATAL_REG =%d\n",i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_PDATAL_REG));
		printk("....data->ps_offset = %d\n",data->ps_offset );

		
	data->ps_offset =  i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_PDATAL_REG);
		printk("....data->ps_offset = %d\n",data->ps_offset );
	i2c_smbus_write_byte_data(client,CMD_BYTE|TMD27723_POFFSET_REG,data->ps_offset);
		printk ("................... POFFSET_REG=%d\n",i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_POFFSET_REG));

return 0;
*/
}


static int tmd27723_probe(struct i2c_client *client,
                          const struct i2c_device_id *id)
{
        struct tmd27723_data *data;
        int err = 0;
        int chip_id = 0;

        if (!i2c_check_functionality(client->adapter,I2C_FUNC_I2C|I2C_FUNC_SMBUS_BYTE))
        {
                printk("<1>i2c_check_functionality error\n");
                return -ENODEV;
        }

        data = kzalloc(sizeof(struct tmd27723_data), GFP_KERNEL);
        if (!data)
        {
                printk("Failed to allocate memory\n");
                return -ENOMEM;
        }

        //设置默认参数
        tmd27723_ps_detection_threshold  = 350;
        tmd27723_ps_hsyteresis_threshold = 500;
        tmd27723_ps_pulse_number         = 8;
        tmd27723_ps_pgain                = 0;

        tmd27723_coe_b  = 186;
        tmd27723_coe_c  = 75;
        tmd27723_coe_d  = 129;
        tmd27723_ga     = 560;

        data->client = client;
        globle_data = data;
        i2c_set_clientdata(client, data);
#if 1
        err = tmd27723_power_init (data);
        if (err)
        {
                printk ("Failed to get sensor regulators\n");
                err = -EINVAL;
                goto ERROR_1;
        }
        err = tmd27723_power_control (data,true);
        if (err)
        {
                printk ("Failed to enable sensor power\n");
                err = -EINVAL;
                goto ERROR_1_1;
        }
#endif

        data->enable = 0;
        data->ps_threshold = tmd27723_ps_detection_threshold;
        data->ps_hysteresis_threshold = tmd27723_ps_hsyteresis_threshold;
        data->ps_detection = 0;
        data->enable_als_sensor = 0;
        data->enable_ps_sensor = 0;
        data->als_suspend_state = 0;
        data->ps_suspend_state = 0;
        data->suspend_state = 0;
        data->als_poll_delay = 100;
        data->als_atime_index = 2;
        data->als_again_index = 1;
        data->als_reduce = 0;
        data->als_prev_lux = 0;

        /*calibration*/
        if (tmd27723_cross_talk_val > 0 && tmd27723_cross_talk_val <1000)
                data->cross_talk = tmd27723_cross_talk_val;
        else
                data->cross_talk = DEFAULT_CROSS_TALK;

        mutex_init(&data->enable_lock);
        mutex_init(&data->op_lock);
        mutex_init(&data->update_lock);
        mutex_init(&data->ps_lock);
        mutex_init(&data->als_lock);
		
 	INIT_DELAYED_WORK(&data->ps_calibrate_work,tmd27723_ps_calibrate_func);
        INIT_DELAYED_WORK(&data->ps_work, tmd27723_ps_work_func);
#ifdef ALS_POLLING_ENABLED
        INIT_DELAYED_WORK(&data->als_work, tmd27723_als_work_func);
#endif
	
	
        err = tmd27723_check_chip_id(client,&chip_id);
        if (err)
        {
                printk ("tmd27723_id=%d Read ID error\n",chip_id);
                goto ERROR_1_2;
        }

        /*Initialize the TMD27723 chip*/
        err = tmd27723_init_device(client);
        if (err)
        {
                printk ("tmd27723_id init failure\n");
                goto ERROR_1_2;
        }
        /*Register to Input Device*/
        data->input_dev_als = input_allocate_device();
        if (!data->input_dev_als)
        {
                err = -ENOMEM;
                printk ("Failed to allocate input device als!\n");
                goto ERROR_1_2;
        }

        data->input_dev_ps = input_allocate_device();
        if (!data->input_dev_ps)
        {
                err = -ENOMEM;
                printk ("Failed to allocate input device ps!\n");
                goto ERROR_2;
        }

        set_bit(EV_ABS, data->input_dev_als->evbit);
        set_bit(EV_ABS, data->input_dev_ps->evbit);

        input_set_abs_params(data->input_dev_als, ABS_MISC, 0, 60000, 0, 0);
        input_set_abs_params(data->input_dev_ps, ABS_DISTANCE, 0, 99, 0, 0);

        data->input_dev_als->name = "light";
        data->input_dev_ps->name = "proximity";

        err = input_register_device(data->input_dev_als);
        if (err)
        {
                err = -ENOMEM;
                printk ("Unable to register input device als!\n");
                goto ERROR_3;
        }
        err = input_register_device(data->input_dev_ps);
        if (err)
        {
                err = -ENOMEM;
                printk ("Unable to register input device ps!\n");
                goto ERROR_4;
        }
        err = device_create_file (&data->input_dev_ps->dev,&dev_attr_ps_citvalue);
        err = device_create_file (&client->dev,&dev_attr_ps_citvalue);
        if (err)
        {
                printk ("Uable to register ps_citvalue device!\n");
                goto ERROR_4;
        }
        err = device_create_file (&data->input_dev_ps->dev,&dev_attr_ps_5_cal_value);
	 err = device_create_file (&client->dev,&dev_attr_ps_5_cal_value);
        if (err)
        {
                printk ("Uable to register ps_5_cal device!\n");
                goto ERROR_4;
        }
	 err = device_create_file (&data->input_dev_ps->dev,&dev_attr_ps_calibrate_prox);
	 err = device_create_file (&client->dev,&dev_attr_ps_calibrate_prox);
        if (err)
        {
                printk ("Uable to register ps_calibrate_prox device!\n");
                goto ERROR_4;
        }
	 err = device_create_file (&data->input_dev_ps->dev,&dev_attr_ps_offset_level);
	 err = device_create_file (&client->dev,&dev_attr_ps_offset_level);
        if (err)
        {
                printk ("Uable to register ps_offset_level device!\n");
                goto ERROR_4;
        }
        err = device_create_file (&data->input_dev_ps->dev,&dev_attr_ps_3_cal_value);
	 err = device_create_file (&client->dev,&dev_attr_ps_3_cal_value);
        if (err)
        {
                printk ("Uable to register ps_3_cal device!\n");
                goto ERROR_4;
        }
	err = device_create_file (&data->input_dev_ps->dev,&dev_attr_ps_control_reg);
	 err = device_create_file (&client->dev,&dev_attr_ps_control_reg);
        if (err)
        {
                printk ("Uable to register ps_control_reg device!\n");
                goto ERROR_4;
        }
	err = device_create_file (&data->input_dev_ps->dev,&dev_attr_ps_config_reg);
	 err = device_create_file (&client->dev,&dev_attr_ps_config_reg);
	if (err)
        {
                printk ("Uable to register ps_config_reg device!\n");
                goto ERROR_4;
        }
	
	err = device_create_file (&data->input_dev_ps->dev,&dev_attr_ps_ppcount_reg);
	 err = device_create_file (&client->dev,&dev_attr_ps_ppcount_reg);
        if (err)
        {
                printk ("Uable to register ps_ppcount_reg device!\n");
                goto ERROR_4;
        }
		
        atomic_set(&globle_data->ps_5_cal_value,350);
        /*Register to sensors class*/
        data->als_cdev = sensors_light_cdev;
        data->als_cdev.sensors_enable = tmd27723_als_set_enable;
        data->als_cdev.sensors_poll_delay = NULL;
        data->ps_cdev = sensors_proximity_cdev;
        data->ps_cdev.sensors_enable = tmd27723_ps_set_enable;
        data->ps_cdev.sensors_poll_delay = NULL;
#if defined(CONFIG_FB)
        data->fb_notif.notifier_call = fb_notifier_callback;
        err = fb_register_client(&data->fb_notif);
        if (err)
                 dev_err(&client->dev, "Unable to register fb_notifier: %d\n",err);
#endif 
        err = sensors_classdev_register(&client->dev, &data->als_cdev);
        if (err)
        {
                printk ("Unable to register to sensors class:als!\n");
                goto ERROR_5;
        }

        err = sensors_classdev_register(&client->dev, &data->ps_cdev);
        if (err)
        {
                printk ("Unable to register to sensors class:ps!\n");
                goto ERROR_6;
        }
		//add P-sensor calibration
		//schedule_delayed_work(&data->ps_calibrate_work,msecs_to_jiffies(20));

#ifdef SENSOR_DEBUG
        printk ("tmd27723_probe successful tmd27723_probe\n");
        printk ("tmd27723_probe successful tmd27723_probe\n");
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_ENABLE_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_ENABLE_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_ATIME_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_ATIME_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_PTIME_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_PTIME_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_WTIME_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_WTIME_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_AILTL_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_AILTL_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_AILTH_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_AILTH_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_AIHTL_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_AIHTL_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_AIHTH_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_AIHTH_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_PILTL_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_PILTL_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_PILTH_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_PILTH_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_PIHTL_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_PIHTL_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_PIHTH_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_PIHTH_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_PERS_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_PERS_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_CONFIG_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_CONFIG_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_PPCOUNT_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_PPCOUNT_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_CONTROL_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_CONTROL_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_REV_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_REV_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_ID_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_ID_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_STATUS_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_STATUS_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_CH0DATAL_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_CH0DATAL_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_CH0DATAH_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_CH0DATAH_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_CH1DATAL_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_CH1DATAL_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_CH1DATAH_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_CH1DATAH_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_PDATAL_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_PDATAL_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_PDATAH_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_PDATAH_REG));
				printk ("tmd27723_probe 0x%02X=%d\n",TMD27723_POFFSET_REG,i2c_smbus_read_byte_data(client,CMD_BYTE|TMD27723_POFFSET_REG));
#endif

        return 0;
ERROR_6:
        sensors_classdev_unregister(&data->als_cdev);
ERROR_5:
        input_unregister_device(data->input_dev_ps);
ERROR_4:
        input_unregister_device(data->input_dev_als);
ERROR_3:
        input_free_device(data->input_dev_ps);
ERROR_2:
        input_free_device(data->input_dev_als);
ERROR_1_2:
        tmd27723_power_control(data, false);
ERROR_1_1:
        tmd27723_power_deinit(data);
ERROR_1:
        kfree (data);

        return err;
}


static int tmd27723_remove (struct i2c_client *client)
{
        struct tmd27723_data *data = i2c_get_clientdata(client);

        /* Power down the device */
        tmd27723_set_enable(client, 0);
#if defined(CONFIG_FB)
        if (fb_unregister_client(&data->fb_notif)) 
                printk ("%s:Error occurred while unregistering fb_notifier. \n",__func__);
#endif

        input_unregister_device(data->input_dev_ps);
        input_unregister_device(data->input_dev_als);

        input_free_device(data->input_dev_ps);
        input_free_device(data->input_dev_als);

        kfree(data);

        return 0;
}

static int tmd27723_suspend(struct device *dev)
{
        struct tmd27723_data *data;
        int rc;

        data = dev_get_drvdata(dev);
        data->suspend_state = 1;
        data->ps_suspend_state = data->enable_ps_sensor; 
        if (data->enable_ps_sensor)
        {
                rc = tmd27723_enable_ps_sensor(data->client, 0);
                if (rc)
                        printk ("Disable proximity sensor fail!\n");
        }
        rc = tmd27723_set_enable(data->client, 0);
        if(rc)
                printk("Disable sensor fail!\n");

        return 0;
}

static int tmd27723_resume(struct device *dev)
{
        struct tmd27723_data *data;
        int rc;

        data = dev_get_drvdata(dev);


#if 1
        if (data->ps_suspend_state)
        {
                rc = tmd27723_enable_ps_sensor(data->client, 1);
                if (rc)
                        printk ("Enable proximity sensor fail!\n");
        }
#endif
        data->suspend_state = 0;
        return 0;
}

static int tmd27723_earlay_suspend(struct tmd27723_data *data)
{
        int rc;

        data->als_suspend_state = data->enable_als_sensor; 
        if (data->enable_als_sensor)
        {
                
                rc = tmd27723_enable_als_sensor(data->client, 0);
                if (rc)
                        printk ("Disable light sensor fail!\n");
        }
        return 0;
}
static int tmd27723_early_resume(struct tmd27723_data *data)
{
        int rc;


        /* Resume L sensor state as P sensor does not disable */
        if (data->als_suspend_state)
        {
                rc = tmd27723_enable_als_sensor(data->client, 1);
                if (rc)
                        printk ("Enable light sensor fail!\n");
        }
        return 0;
}

#if defined(CONFIG_FB)
static int fb_notifier_callback(struct notifier_block *self,
				 unsigned long event, void *e_data)
{
	struct fb_event *evdata = e_data;
	int *blank;
	struct tmd27723_data *data =
		container_of(self, struct tmd27723_data, fb_notif);

        pr_info("%s event is %ld\n", __func__, event);
	if (evdata && evdata->data && event == FB_EARLY_EVENT_BLANK &&
                data) {
		blank = evdata->data;
		if (*blank == FB_BLANK_UNBLANK)
			tmd27723_early_resume(data);
		else if (*blank == FB_BLANK_POWERDOWN)
			tmd27723_earlay_suspend(data);
	}

	return 0;
}
#endif
static const struct i2c_device_id tmd27723_id[] = {
        { "tmd27723",0},
        { }
};

MODULE_DEVICE_TABLE(i2c, tmd27723_id);

static struct of_device_id tmd27723_match_table[] = {
        { .compatible = "taos,tmd27723",},
        { },
};

static const struct dev_pm_ops tmd27723_pm_ops = {
        .suspend        = tmd27723_suspend,
        .resume         = tmd27723_resume,
};

static struct i2c_driver tmd27723_driver = {
        .driver = {
                .name   = TMD27723_DRV_NAME,
                .owner  = THIS_MODULE,
                .pm     = &tmd27723_pm_ops,
                .of_match_table = tmd27723_match_table,
        },
        .probe    = tmd27723_probe,
        .remove   = tmd27723_remove,
        .id_table = tmd27723_id,
};


static int __init tmd27723_init(void)
{
        return i2c_add_driver(&tmd27723_driver);
}

static void __exit tmd27723_exit(void)
{
        i2c_del_driver(&tmd27723_driver);
}


module_init(tmd27723_init);
module_exit(tmd27723_exit);

MODULE_AUTHOR("Wangruoming<ruoming.wang@sim.com>");
MODULE_DESCRIPTION("TMD27723 ambient light and proximity sensor driver");
MODULE_LICENSE("GPL");
