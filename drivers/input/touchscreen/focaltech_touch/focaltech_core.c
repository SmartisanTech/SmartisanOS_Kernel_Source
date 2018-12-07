/*
 *
 * FocalTech fts TouchScreen driver.
 *
 * Copyright (c) 2010-2015, Focaltech Ltd. All rights reserved.
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
/*******************************************************************************
*
* File Name: focaltech_core.c
*
* Author: Focaltech Driver Team
*
* Created: 2016-08-22
*
* Abstract:
*
* Reference:
*
*******************************************************************************/
/*******************************************************************************
* Included header files
*******************************************************************************/
#include "focaltech_core.h"

#define CREATE_TRACE_POINTS

#if defined(CONFIG_FB)
#include <linux/notifier.h>
#include <linux/fb.h>

#elif defined(CONFIG_HAS_EARLYSUSPEND)
#include <linux/earlysuspend.h>
/* Early-suspend level */
#define FTS_SUSPEND_LEVEL 1
#endif

#define FTS_REG_PMODE		0xA5
#define FTS_PMODE_HIBERNATE	0x03

#define LCD_SELECT_GPIO1 92
#define LCD_SELECT_GPIO2_DVT 91



/*******************************************************************************
* Global variable or extern global variabls/functions
*******************************************************************************/
struct i2c_client *fts_i2c_client;
struct fts_ts_data *fts_wq_data;
struct input_dev *fts_input_dev;

//-luoguojin static unsigned int buf_count_add=0;
//-luoguojin static unsigned int buf_count_neg=0;

#if FTS_DEBUG_EN
int g_show_log = 1;
#else
int g_show_log = 0;
#endif

//-luoguojin u8 buf_touch_data[30*POINT_READ_BUF] = { 0 };

/*******************************************************************************
* Static function prototypes
*******************************************************************************/
static int fts_read_touchdata(struct fts_ts_data *data);
static void fts_report_value(struct fts_ts_data *data);

#define PINCTRL_STATE_ACTIVE	"pmx_ts_active"
#define PINCTRL_STATE_SUSPEND	"pmx_ts_suspend"
#define PINCTRL_STATE_RELEASE	"pmx_ts_release"

/*******************************************************************************
*  Name: fts_read_touchdata
*  Brief:
*  Input:
*  Output:
*  Return:
*******************************************************************************/
static int fts_read_touchdata(struct fts_ts_data *data)
{
    u8 buf[POINT_READ_BUF] = { 0 };
    int ret = -1;
    uint32_t position = 0;
    struct ts_event *event = &data->event;
    int i;
    u8 pointid = FTS_MAX_ID;

#if FTS_GESTURE_EN
    {
        u8 state;
        if (data->suspended)
        {
            fts_i2c_read_reg(data->client, 0xd0, &state);
            if (state ==1)
            {
                fts_gesture_readdata();
                return 1;
            }
        }
    }
#endif

#if FTS_PSENSOR_EN
    if ( (fts_sensor_read_data(data) != 0) && (data->suspended == 1) )
    {
        return 1;
    }
#endif
    ret = fts_i2c_read(data->client, buf, 1, buf, POINT_READ_BUF);
    if (ret < 0)
    {
        FTS_ERROR("%s read touchdata failed.", __func__);
        return ret;
    }
// luoguojin >>
 //   buf_count_add++;
 //   memcpy( buf_touch_data+(((buf_count_add-1)%30)*POINT_READ_BUF), buf, sizeof(u8)*POINT_READ_BUF );
 
    event->point_num=buf[FTS_TOUCH_POINT_NUM] & 0x0F;
    if(event->point_num > FTS_MAX_POINTS)
        event->point_num = FTS_MAX_POINTS;
    event->touch_point = 0;

    for (i = 0; i < FTS_MAX_POINTS; i++)
    {
		position = FTS_ONE_TCH_LEN * i;

        pointid = (buf[FTS_TOUCH_ID_POS + position]) >> 4;
        if (pointid >= FTS_MAX_ID)
            break;
        else
            event->touch_point++;

        event->au16_x[i] =
            (s16) (buf[FTS_TOUCH_X_H_POS + position] & 0x0F) <<
            8 | (s16) buf[FTS_TOUCH_X_L_POS + position];
        event->au16_y[i] =
            (s16) (buf[FTS_TOUCH_Y_H_POS + position] & 0x0F) <<
            8 | (s16) buf[FTS_TOUCH_Y_L_POS + position];
        event->au8_touch_event[i] =
            buf[FTS_TOUCH_EVENT_POS + position] >> 6;
        event->au8_finger_id[i] =
            (buf[FTS_TOUCH_ID_POS + position]) >> 4;
#ifdef FTS_PRESSURE_ENABLE
        event->area[i] =
            (buf[FTS_TOUCH_AREA_POS + position]) >> 4;
#endif
        event->pressure[i] =
            (s16) buf[FTS_TOUCH_PRE_POS + position];

#ifdef FTS_PRESSURE_ENABLE
        if (0 == event->area[i])
            event->area[i] = 0x09;
#endif
        if (0 == event->pressure[i])
            event->pressure[i] = 0x3f;

        if ((event->au8_touch_event[i]==0 || event->au8_touch_event[i]==2)&&(event->point_num==0))
            break;
    }
// luoguojin <<
    return 0;
}

/*******************************************************************************
*  Name: fts_report_value
*  Brief:
*  Input:
*  Output:
*  Return:
*******************************************************************************/
static void fts_report_value(struct fts_ts_data *data)
{
    struct ts_event *event = &data->event;
    int i;
    int uppoint = 0;
    int touchs = 0;

/*
    FTS_DEBUG("point number: %d, touch point: %d", event->point_num,
              event->touch_point);
*/
    if (data->pdata->have_key)
    {
        if ( (1 == event->touch_point || 1 == event->point_num) &&
             (event->au16_y[0] == data->pdata->key_y_coord))
        {

            if (event->point_num == 0)
            {
//                FTS_DEBUG("[B]Keys All Up!");
                for (i = 0; i < data->pdata->key_number; i++)
                {
                    input_report_key(data->input_dev, data->pdata->keys[i], 0);
                }
            }
            else
            {
                for (i = 0; i < data->pdata->key_number; i++)
                {
                    if (event->au16_x[0] > (data->pdata->key_x_coords[i] - FTS_KEY_WIDTH) &&
                        event->au16_x[0] < (data->pdata->key_x_coords[i] + FTS_KEY_WIDTH))
                    {

                        if (event->au8_touch_event[i]== 0 ||
                            event->au8_touch_event[i] == 2)
                        {
                            input_report_key(data->input_dev, data->pdata->keys[i], 1);
//                            FTS_DEBUG("[B]Key%d(%d, %d) DOWN!", i, event->au16_x[0], event->au16_y[0]);
                        }
                        else
                        {
                            input_report_key(data->input_dev, data->pdata->keys[i], 0);
//                            FTS_DEBUG("[B]Key%d(%d, %d) Up!", i, event->au16_x[0], event->au16_y[0]);
                        }
                        break;
                    }
                }
            }
            input_sync(data->input_dev);
            return;
        }
    }

    for (i = 0; i < event->touch_point; i++)
    {
        input_mt_slot(data->input_dev, event->au8_finger_id[i]);

        if (event->au8_touch_event[i] == FTS_TOUCH_DOWN || event->au8_touch_event[i] == FTS_TOUCH_CONTACT)
        {
            input_mt_report_slot_state(data->input_dev, MT_TOOL_FINGER, true);
#ifdef FTS_PRESSURE_ENABLE
            input_report_abs(data->input_dev, ABS_MT_PRESSURE, event->area[i]);
#endif
            input_report_abs(data->input_dev, ABS_MT_TOUCH_MAJOR, event->pressure[i]);
            input_report_abs(data->input_dev, ABS_MT_POSITION_X, event->au16_x[i]);
            input_report_abs(data->input_dev, ABS_MT_POSITION_Y, event->au16_y[i]);
            touchs |= BIT(event->au8_finger_id[i]);
            data->touchs |= BIT(event->au8_finger_id[i]);
//            FTS_DEBUG("[B]Point%d(%d, %d) DOWN!", event->au8_finger_id[i], event->au16_x[i], event->au16_y[i]);
        }
        else
        {
            uppoint++;
            input_mt_report_slot_state(data->input_dev, MT_TOOL_FINGER, false);
            data->touchs &= ~BIT(event->au8_finger_id[i]);
//            FTS_DEBUG("[B]Point%d UP!", event->au8_finger_id[i]);
        }
    }

    if (unlikely(data->touchs ^ touchs))
    {
        for (i = 0; i < data->pdata->max_touch_number; i++)
        {
            if (BIT(i) & (data->touchs ^ touchs))
            {
//                FTS_DEBUG("[B]Point%d UP!", i);
                input_mt_slot(data->input_dev, i);
                input_mt_report_slot_state(data->input_dev, MT_TOOL_FINGER, false);
            }
        }
    }
    data->touchs = touchs;
    if (event->touch_point == uppoint)
    {

//        FTS_DEBUG("[B]Points All Up!");
        input_report_key(data->input_dev, BTN_TOUCH, 0);
    }
    else
    {
        input_report_key(data->input_dev, BTN_TOUCH, event->touch_point > 0);
    }

    input_sync(data->input_dev);
}

#if FTS_POWER_SOURCE_CUST_EN
#define FTS_VTG_MIN_UV          2600000
#define FTS_VTG_MAX_UV          3300000
#define FTS_I2C_VTG_MIN_UV      1800000
#define FTS_I2C_VTG_MAX_UV      1800000
static int fts_power_source_init(struct fts_ts_data *data)
{
    int rc;

    FTS_FUNC_ENTER();

    data->vdd = regulator_get(&data->client->dev, "vdd");
    if (IS_ERR(data->vdd))
    {
        rc = PTR_ERR(data->vdd);
        FTS_ERROR("Regulator get failed vdd rc=%d", rc);
    }

    if (regulator_count_voltages(data->vdd) > 0)
    {
        rc = regulator_set_voltage(data->vdd, FTS_VTG_MIN_UV, FTS_VTG_MAX_UV);
        if (rc)
        {
            FTS_ERROR("Regulator set_vtg failed vdd rc=%d", rc);
            goto reg_vdd_put;
        }
    }

    data->vcc_i2c = regulator_get(&data->client->dev, "vcc_i2c");
    if (IS_ERR(data->vcc_i2c))
    {
        rc = PTR_ERR(data->vcc_i2c);
        FTS_ERROR("Regulator get failed vcc_i2c rc=%d", rc);
        goto reg_vdd_set_vtg;
    }

    if (regulator_count_voltages(data->vcc_i2c) > 0)
    {
        rc = regulator_set_voltage(data->vcc_i2c, FTS_I2C_VTG_MIN_UV, FTS_I2C_VTG_MAX_UV);
        if (rc)
        {
            FTS_ERROR("Regulator set_vtg failed vcc_i2c rc=%d", rc);
            goto reg_vcc_i2c_put;
        }
    }

    FTS_FUNC_EXIT();
    return 0;

reg_vcc_i2c_put:
    regulator_put(data->vcc_i2c);
reg_vdd_set_vtg:
    if (regulator_count_voltages(data->vdd) > 0)
        regulator_set_voltage(data->vdd, 0, FTS_VTG_MAX_UV);
reg_vdd_put:
    regulator_put(data->vdd);
    FTS_FUNC_EXIT();
    return rc;
}

static int fts_power_source_ctrl(struct fts_ts_data *data, int enable)
{
    int rc;

    FTS_FUNC_ENTER();
    if (enable)
    {
        rc = regulator_enable(data->vdd);
        if (rc)
        {
            FTS_ERROR("//////////////////Regulator vdd enable failed rc=%d", rc);
        }

        rc = regulator_enable(data->vcc_i2c);
        if (rc)
        {
            FTS_ERROR("///////////////////////Regulator vcc_i2c enable failed rc=%d", rc);
        }
    }
    else
    {
        rc = regulator_disable(data->vdd);
        if (rc)
        {
            FTS_ERROR("////////////////////////////////////Regulator vdd disable failed rc=%d", rc);
        }
        rc = regulator_disable(data->vcc_i2c);
        if (rc)
        {
            FTS_ERROR("///////////////////////////////////Regulator vcc_i2c disable failed rc=%d", rc);
        }
    }
    FTS_FUNC_EXIT();
    return 0;
}

#endif


/*******************************************************************************
*  Name: fts_touch_irq_work
*  Brief:
*  Input:
*  Output:
*  Return:
*******************************************************************************/
static void fts_touch_irq_work(struct work_struct *work)
{
    int ret = -1;

	mutex_lock(&fts_wq_data->wlock);
#if FTS_POINT_REPORT_CHECK_EN
    fts_point_report_check_queue_work();
#endif

#if FTS_ESDCHECK_EN
    fts_esdcheck_set_intr(1);
#endif

    ret = fts_read_touchdata(fts_wq_data);

    if (ret == 0)
    {
        fts_report_value(fts_wq_data);
    }

    enable_irq(fts_wq_data->client->irq);

#if FTS_ESDCHECK_EN
    fts_esdcheck_set_intr(0);
#endif
	mutex_unlock(&fts_wq_data->wlock);
}

static irqreturn_t fts_ts_interrupt(int irq, void *dev_id)
{
	struct fts_ts_data *fts_ts = dev_id;

	disable_irq_nosync(fts_ts->client->irq);

	if (!fts_ts) {
		pr_err("%s: Invalid fts_ts\n", __func__);
		return IRQ_HANDLED;
	} 
	queue_work(fts_ts->ts_workqueue, &fts_ts->touch_event_work);
	return IRQ_HANDLED;
}

int fts_reset_proc(int hdelayms)
{
#if 1
    gpio_direction_output(fts_wq_data->pdata->reset_gpio, 0);
    msleep(20);
    gpio_direction_output(fts_wq_data->pdata->reset_gpio, 1);
    msleep(hdelayms);
#endif

    return 0;
}

static int fts_pinctrl_init(struct fts_ts_data *fts_data)
{
	int retval;

	/* Get pinctrl if target uses pinctrl */
	fts_data->ts_pinctrl = devm_pinctrl_get(&(fts_data->client->dev));
	if (IS_ERR_OR_NULL(fts_data->ts_pinctrl)) {
		retval = PTR_ERR(fts_data->ts_pinctrl);
		dev_dbg(&fts_data->client->dev,
			"Target does not use pinctrl %d\n", retval);
		goto err_pinctrl_get;
	}

	fts_data->pinctrl_state_active
		= pinctrl_lookup_state(fts_data->ts_pinctrl,
				PINCTRL_STATE_ACTIVE);
	if (IS_ERR_OR_NULL(fts_data->pinctrl_state_active)) {
		retval = PTR_ERR(fts_data->pinctrl_state_active);
		dev_err(&fts_data->client->dev,
			"Can not lookup %s pinstate %d\n",
			PINCTRL_STATE_ACTIVE, retval);
		goto err_pinctrl_lookup;
	}

	fts_data->pinctrl_state_suspend
		= pinctrl_lookup_state(fts_data->ts_pinctrl,
			PINCTRL_STATE_SUSPEND);
	if (IS_ERR_OR_NULL(fts_data->pinctrl_state_suspend)) {
		retval = PTR_ERR(fts_data->pinctrl_state_suspend);
		dev_err(&fts_data->client->dev,
			"Can not lookup %s pinstate %d\n",
			PINCTRL_STATE_SUSPEND, retval);
		goto err_pinctrl_lookup;
	}

	fts_data->pinctrl_state_release
		= pinctrl_lookup_state(fts_data->ts_pinctrl,
			PINCTRL_STATE_RELEASE);
	if (IS_ERR_OR_NULL(fts_data->pinctrl_state_release)) {
		retval = PTR_ERR(fts_data->pinctrl_state_release);
		dev_dbg(&fts_data->client->dev,
			"Can not lookup %s pinstate %d\n",
			PINCTRL_STATE_RELEASE, retval);
	}

	return 0;

	err_pinctrl_lookup:
		devm_pinctrl_put(fts_data->ts_pinctrl);
	err_pinctrl_get:
		fts_data->ts_pinctrl = NULL;
		return retval;
}

/*******************************************************************************
*  Name: fts_gpio_configure
*  Brief:
*  Input:
*  Output: 
*  Return: 
*******************************************************************************/
static int fts_gpio_configure(struct fts_ts_data *data, bool on)
{
	int err = 0;

	if (on) {
		if (gpio_is_valid(data->pdata->irq_gpio)) {
			err = gpio_request(data->pdata->irq_gpio,
						"fts_irq_gpio");
			if (err) {
				dev_err(&data->client->dev,
					"irq gpio request failed");
				goto err_irq_gpio_req;
			}

			err = gpio_direction_input(data->pdata->irq_gpio);
			if (err) {
				dev_err(&data->client->dev,
					"set_direction for irq gpio failed\n");
				goto err_irq_gpio_dir;
			}
		}

#if 1
		if (gpio_is_valid(data->pdata->reset_gpio)) {
			printk("start to reset gpio\n");
			err = gpio_request(data->pdata->reset_gpio,
						"fts_reset_gpio");
			if (err) {
				dev_err(&data->client->dev,
					"reset gpio request failed");
				goto err_irq_gpio_dir;
			}
			err = gpio_direction_output(data->pdata->reset_gpio, 1);
			mdelay(2);
			err = gpio_direction_output(data->pdata->reset_gpio, 0);
			if (err) {
				dev_err(&data->client->dev,
				"set_direction for reset gpio failed\n");
				goto err_reset_gpio_dir;
			}
			mdelay(2);
			gpio_set_value_cansleep(data->pdata->reset_gpio, 1);
		}
#endif

		return 0;
	} else {
		if (gpio_is_valid(data->pdata->irq_gpio))
			gpio_free(data->pdata->irq_gpio);
#if 1
		if (gpio_is_valid(data->pdata->reset_gpio)) {
			/*
			 * This is intended to save leakage current
			 * only. Even if the call(gpio_direction_input)
			 * fails, only leakage current will be more but
			 * functionality will not be affected.
			 */
			  gpio_set_value_cansleep(data->pdata->reset_gpio, 0);
/*
			err = gpio_direction_input(data->pdata->reset_gpio);
			if (err) {
				dev_err(&data->client->dev,
					"unable to set direction for gpio "
					"[%d]\n", data->pdata->irq_gpio);
			}
*/
			gpio_free(data->pdata->reset_gpio);
		}
#endif

		return 0;
	}

#if 1
err_reset_gpio_dir:
	if (gpio_is_valid(data->pdata->reset_gpio))
		gpio_free(data->pdata->reset_gpio);
#endif
err_irq_gpio_dir:
	if (gpio_is_valid(data->pdata->irq_gpio))
		gpio_free(data->pdata->irq_gpio);
err_irq_gpio_req:
	return err;
}

#ifdef CONFIG_PM
/*******************************************************************************
*  Name: fts_ts_start
*  Brief:
*  Input:
*  Output: 
*  Return: 
*******************************************************************************/
static int fts_ts_start(struct device *dev)
{
	struct fts_ts_data *data = dev_get_drvdata(dev);
	int err;

	err = fts_power_source_ctrl(data, true);
	if (err) {
		dev_err(dev, "power on failed");
		return err;
	}

	if (data->ts_pinctrl) {
		err = pinctrl_select_state(data->ts_pinctrl,
				data->pinctrl_state_active);
		if (err < 0)
			dev_err(dev, "Cannot get active pinctrl state\n");
	}

	err = fts_gpio_configure(data, true);
	if (err < 0) {
		dev_err(&data->client->dev,
			"failed to put gpios in resue state\n");
		goto err_gpio_configuration;
	}
/*
	if (gpio_is_valid(data->pdata->reset_gpio)) {
		gpio_set_value_cansleep(data->pdata->reset_gpio, 0);
		msleep(20);
		gpio_set_value_cansleep(data->pdata->reset_gpio, 1);
	}
*/
	mdelay(3);

	err = request_irq(data->client->irq, fts_ts_interrupt,
                               data->irq_gpio_flags, /* | IRQF_TRIGGER_FALLING,*/
                               data->client->dev.driver->name, data);
	if (err)
	{
	    FTS_ERROR("request irq failed!");
	}
	data->suspended = false;

	return 0;

err_gpio_configuration:
	if (data->ts_pinctrl) {
		err = pinctrl_select_state(data->ts_pinctrl,
					data->pinctrl_state_suspend);
		if (err < 0)
			dev_err(dev, "Cannot get suspend pinctrl state\n");
	}
	err = fts_power_source_ctrl(data, false);
	if (err)
		dev_err(dev, "power off failed");
	return err;
}

/*******************************************************************************
*  Name: fts_ts_stop
*  Brief:
*  Input:
*  Output: 
*  Return: 
*******************************************************************************/
static int fts_ts_stop(struct device *dev)
{
	struct fts_ts_data *data = dev_get_drvdata(dev);
	char txbuf[2];
	int i, err;

	disable_irq(data->client->irq);
	free_irq(data->client->irq, data);

#if 1
	if (gpio_is_valid(data->pdata->reset_gpio)) {
		txbuf[0] = FTS_REG_PMODE;
		txbuf[1] = FTS_PMODE_HIBERNATE;
		fts_i2c_write(data->client, txbuf, sizeof(txbuf));
	}
#endif
	
	err = fts_power_source_ctrl(data, false);
	if (err) {
		dev_err(dev, "power off failed");
		goto pwr_off_fail;
	}

	if (data->ts_pinctrl) {
		err = pinctrl_select_state(data->ts_pinctrl,
					data->pinctrl_state_suspend);
		if (err < 0)
			dev_err(dev, "Cannot get suspend pinctrl state\n");
	}

	err = fts_gpio_configure(data, false);
	if (err < 0) {
		dev_err(&data->client->dev,
			"failed to put gpios in suspend state\n");
		goto gpio_configure_fail;
	}

	data->suspended = true;

	/* release all touches */
	for (i = 0; i < data->pdata->max_touch_number; i++) {
		input_mt_slot(data->input_dev, i);
		input_mt_report_slot_state(data->input_dev, MT_TOOL_FINGER, 0);
	}
	input_report_key(data->input_dev, BTN_TOUCH, 0);
	input_sync(data->input_dev);

	return 0;

gpio_configure_fail:
	if (data->ts_pinctrl) {
		err = pinctrl_select_state(data->ts_pinctrl,
					data->pinctrl_state_active);
		if (err < 0)
			dev_err(dev, "Cannot get active pinctrl state\n");
	}
	err = fts_power_source_ctrl(data, true);
	if (err)
		dev_err(dev, "power on failed");

pwr_off_fail:
#if 1
	if (gpio_is_valid(data->pdata->reset_gpio)) {
		gpio_set_value_cansleep(data->pdata->reset_gpio, 0);
		msleep(20);
		gpio_set_value_cansleep(data->pdata->reset_gpio, 1);
	}
#endif
	enable_irq(data->client->irq);
	return err;
}

/*******************************************************************************
*  Name: fts_ts_suspend
*  Brief:
*  Input:
*  Output: 
*  Return: 
*******************************************************************************/
int fts_ts_suspend(struct device *dev)
{
	int retval = 0;
	struct fts_ts_data *data;
	if(dev == NULL)
		dev = &fts_i2c_client->dev;
	data = dev_get_drvdata(dev);
	printk("fts_ts_suspend......enter\n");
	mutex_lock(&fts_wq_data->wlock);

	if (data->loading_fw) {
		dev_info(dev, "Firmware loading in process...\n");
		mutex_unlock(&fts_wq_data->wlock);
		return 0;
	}

	if (data->suspended) {
		dev_info(dev, "Already in suspend state\n");
		mutex_unlock(&fts_wq_data->wlock);
		return 0;
	}
#if FTS_ESDCHECK_EN
	fts_esdcheck_suspend(DISABLE);
#endif
	retval = fts_ts_stop(dev);
	mutex_unlock(&fts_wq_data->wlock);
	return retval;
}

/*******************************************************************************
*  Name: fts_ts_resume
*  Brief:
*  Input:
*  Output: 
*  Return: 
*******************************************************************************/
int fts_ts_resume(struct device *dev)
{
	int err;
	struct fts_ts_data *data;
	if(dev == NULL)
		dev = &fts_i2c_client->dev;
	data = dev_get_drvdata(dev);
	printk("fts_ts_resume......enter\n");
	mutex_lock(&fts_wq_data->wlock);

	if (!data->suspended) {
		dev_dbg(dev, "Already in awake state\n");
		mutex_unlock(&fts_wq_data->wlock);
		return 0;
	}

	err = fts_ts_start(dev);
	if (err < 0){
		mutex_unlock(&fts_wq_data->wlock);
		return err;
	}

#if FTS_ESDCHECK_EN
	fts_esdcheck_resume();
#endif
	mutex_unlock(&fts_wq_data->wlock);
	return 0;
}

static const struct dev_pm_ops fts_ts_pm_ops = {
#if (!defined(CONFIG_FB) && !defined(CONFIG_HAS_EARLYSUSPEND))
	.suspend = fts_ts_suspend,
	.resume = fts_ts_resume,
#endif
};
#else
/*******************************************************************************
*  Name: fts_ts_suspend
*  Brief:
*  Input:
*  Output: 
*  Return: 
*******************************************************************************/
static int fts_ts_suspend(struct device *dev)
{
	return 0;
}
/*******************************************************************************
*  Name: fts_ts_resume
*  Brief:
*  Input:
*  Output: 
*  Return: 
*******************************************************************************/
static int fts_ts_resume(struct device *dev)
{
	return 0;
}
#endif


#if defined(CONFIG_FB)
/*******************************************************************************
*  Name: fb_notifier_callback
*  Brief:
*  Input:
*  Output:
*  Return:
*******************************************************************************/
static int ft8716_fb_notifier_callback(struct notifier_block *self,
                                unsigned long event, void *data)
{
    struct fts_ts_data *fts_data =
	container_of(self, struct fts_ts_data, fb_notif);

	switch (event) {
	case LCD_EVENT_ON:
		fts_ts_resume(&fts_data->client->dev);
		break;
	case LCD_EVENT_OFF:
		fts_ts_suspend(&fts_data->client->dev);
		break;
	default:
		break;
	}
    return 0;
}
#elif defined(CONFIG_HAS_EARLYSUSPEND)
/*******************************************************************************
*  Name: fts_ts_early_suspend
*  Brief:
*  Input:
*  Output:
*  Return:
*******************************************************************************/
static void fts_ts_early_suspend(struct early_suspend *handler)
{
    struct fts_ts_data *data = container_of(handler,
                                            struct fts_ts_data,
                                            early_suspend);

    fts_ts_suspend(&data->client->dev);
}

/*******************************************************************************
*  Name: fts_ts_late_resume
*  Brief:
*  Input:
*  Output:
*  Return:
*******************************************************************************/
static void fts_ts_late_resume(struct early_suspend *handler)
{
    struct fts_ts_data *data = container_of(handler,
                                            struct fts_ts_data,
                                            early_suspend);

    fts_ts_resume(&data->client->dev);
}
#endif


/*******************************************************************************
*  Name: fts_get_dt_coords
*  Brief:
*  Input:
*  Output:
*  Return:
*******************************************************************************/
static int fts_get_dt_coords(struct device *dev, char *name,
                             struct fts_ts_platform_data *pdata)
{
    u32 coords[FTS_COORDS_ARR_SIZE];
    struct property *prop;
    struct device_node *np = dev->of_node;
    int coords_size, rc;

    prop = of_find_property(np, name, NULL);
    if (!prop)
        return -EINVAL;
    if (!prop->value)
        return -ENODATA;


    coords_size = prop->length / sizeof(u32);
    if (coords_size != FTS_COORDS_ARR_SIZE)
    {
        FTS_ERROR("invalid %s", name);
        return -EINVAL;
    }

    rc = of_property_read_u32_array(np, name, coords, coords_size);
    if (rc && (rc != -EINVAL))
    {
        FTS_ERROR("Unable to read %s", name);
        return rc;
    }

    if (!strcmp(name, "focaltech,display-coords"))
    {
        pdata->x_min = coords[0];
        pdata->y_min = coords[1];
        pdata->x_max = coords[2];
        pdata->y_max = coords[3];
    }
    else
    {
        FTS_ERROR("unsupported property %s", name);
        return -EINVAL;
    }

    return 0;
}

/*******************************************************************************
*  Name: fts_parse_dt
*  Brief:
*  Input:
*  Output:
*  Return:
*******************************************************************************/
static int fts_parse_dt(struct device *dev, struct fts_ts_platform_data *pdata)
{
    int rc;
    struct device_node *np = dev->of_node;
    u32 temp_val;

    FTS_FUNC_ENTER();
    rc = of_property_read_string(np, "focaltech,name", &pdata->name);
    if (rc && (rc != -EINVAL))
    {
        FTS_ERROR("Unable to read name");
    }

    rc = fts_get_dt_coords(dev, "focaltech,display-coords", pdata);
    if (rc)
        FTS_ERROR("Unable to get display-coords");

    /* key */
    pdata->have_key = of_property_read_bool(np, "focaltech,have-key");
    if (pdata->have_key)
    {
        rc = of_property_read_u32(np, "focaltech,key-number", &pdata->key_number);
        if (rc)
        {
            FTS_ERROR("Key number undefined!");
        }
        rc = of_property_read_u32_array(np, "focaltech,keys",
                                        pdata->keys, pdata->key_number);
        if (rc)
        {
            FTS_ERROR("Keys undefined!");
        }
        rc = of_property_read_u32(np, "focaltech,key-y-coord", &pdata->key_y_coord);
        if (rc)
        {
            FTS_ERROR("Key Y Coord undefined!");
        }
        rc = of_property_read_u32_array(np, "focaltech,key-x-coords",
                                        pdata->key_x_coords, pdata->key_number);
        if (rc)
        {
            FTS_ERROR("Key X Coords undefined!");
        }
        FTS_DEBUG("%d: (%d, %d, %d), [%d, %d, %d][%d]",
                  pdata->key_number, pdata->keys[0], pdata->keys[1], pdata->keys[2],
                  pdata->key_x_coords[0], pdata->key_x_coords[1], pdata->key_x_coords[2],
                  pdata->key_y_coord);
    }

    /* reset, irq gpio info */
    pdata->reset_gpio = of_get_named_gpio_flags(np, "focaltech,reset-gpio", 0, &pdata->reset_gpio_flags);
    if (pdata->reset_gpio < 0)
    {
        FTS_ERROR("Unable to get reset_gpio");
    }
/*
	gpio_direction_output(pdata->reset_gpio, 0);
	mdelay(500);
	gpio_set_value_cansleep(pdata->reset_gpio, 1);
*/
    pdata->irq_gpio = of_get_named_gpio_flags(np, "focaltech,irq-gpio", 0, &pdata->irq_gpio_flags);
    if (pdata->irq_gpio < 0)
    {
        FTS_ERROR("Unable to get irq_gpio");
    }
    rc = of_property_read_u32(np, "focaltech,max-touch-number", &temp_val);
    if (!rc)
        pdata->max_touch_number = temp_val;
    else
        FTS_ERROR("Unable to get max-touch-number");

    FTS_FUNC_EXIT();
    return 0;
}

u8 panel_vendor = 1;
/*******************************************************************************
*  Name: fts_ts_probe
*  Brief:
*  Input:
*  Output:
*  Return:
*******************************************************************************/
static int fts_ts_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
    struct fts_ts_platform_data *pdata;
    struct fts_ts_data *data;
    struct input_dev *input_dev;

    u8 reg_value;
    u8 reg_addr;
    int err, len;

    FTS_FUNC_ENTER();
    if (client->dev.of_node)
    {
        pdata = devm_kzalloc(&client->dev,
                             sizeof(struct fts_ts_platform_data), GFP_KERNEL);
        if (!pdata)
        {
            FTS_ERROR("Failed to allocate memory");
            FTS_FUNC_EXIT();
            return -ENOMEM;
        }
        err = fts_parse_dt(&client->dev, pdata);
        if (err)
        {
            FTS_ERROR("DT parsing failed");
        }
    }
    else
    {
        pdata = client->dev.platform_data;
    }

    if (!pdata)
    {
        FTS_ERROR("Invalid pdata");
        FTS_FUNC_EXIT();
        return -EINVAL;
    }

    if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C))
    {
        FTS_ERROR("I2C not supported");
        FTS_FUNC_EXIT();
        return -ENODEV;
    }

    data = devm_kzalloc(&client->dev, sizeof(struct fts_ts_data), GFP_KERNEL);
    if (!data)
    {
        FTS_ERROR("Not enough memory");
        FTS_FUNC_EXIT();
        return -ENOMEM;
    }

    input_dev = input_allocate_device();
    if (!input_dev)
    {
        FTS_ERROR("failed to allocate input device");
        FTS_FUNC_EXIT();
        return -ENOMEM;
    }

    data->input_dev = input_dev;
    data->client = client;
    data->pdata = pdata;

    fts_wq_data = data;
    fts_i2c_client = client;
    fts_input_dev = input_dev;

    input_dev->name = "fts_ts";
    input_dev->id.bustype = BUS_I2C;
    input_dev->dev.parent = &client->dev;

    input_set_drvdata(input_dev, data);
    i2c_set_clientdata(client, data);

    __set_bit(EV_KEY, input_dev->evbit);
    if (data->pdata->have_key)
    {
        FTS_DEBUG("set key capabilities");
        for (len = 0; len < data->pdata->key_number; len++)
        {
            input_set_capability(input_dev, EV_KEY, data->pdata->keys[len]);
        }
    }
    __set_bit(EV_ABS, input_dev->evbit);
    __set_bit(BTN_TOUCH, input_dev->keybit);
    __set_bit(INPUT_PROP_DIRECT, input_dev->propbit);

    input_mt_init_slots(input_dev, pdata->max_touch_number,0);
    input_set_abs_params(input_dev, ABS_MT_POSITION_X, pdata->x_min, pdata->x_max, 0, 0);
    input_set_abs_params(input_dev, ABS_MT_POSITION_Y, pdata->y_min, pdata->y_max, 0, 0);
	input_set_abs_params(input_dev, ABS_MT_TOUCH_MAJOR, 0, 100, 0, 0);
#ifdef FTS_PRESSURE_ENABLE
    input_set_abs_params(input_dev, ABS_MT_PRESSURE, 0, 0xff, 0, 0);
#endif
    err = input_register_device(input_dev);
    if (err)
    {
        FTS_ERROR("Input device registration failed");
        goto free_inputdev;
    }

#if FTS_POWER_SOURCE_CUST_EN
    fts_power_source_init(data);
    fts_power_source_ctrl(data, 1);
#endif

    err = fts_gpio_configure(data, true);
    if (err < 0)
    {
        FTS_ERROR("Failed to configure the gpios");
        goto free_gpio;
    }
	msleep(300);
	err = fts_pinctrl_init(data);
	if (!err && data->ts_pinctrl) {
		/*
		 * Pinctrl handle is optional. If pinctrl handle is found
		 * let pins to be configured in active state. If not
		 * found continue further without error.
		 */
		err = pinctrl_select_state(data->ts_pinctrl,
					data->pinctrl_state_active);
		if (err < 0) {
			dev_err(&client->dev,
				"failed to select pin to active state");
		}
	}

#if FTS_ESDCHECK_EN
    fts_esdcheck_init();
#endif
    INIT_WORK(&data->touch_event_work, fts_touch_irq_work);
	mutex_init(&data->wlock);
    data->ts_workqueue = create_workqueue(FTS_WORKQUEUE_NAME);
    if (!data->ts_workqueue)
    {
        err = -ESRCH;
        goto exit_create_singlethread;
    }

    reg_addr = FTS_REG_CHIP_ID;
	printk("tp addr = %#x\n", client->addr);
    err = fts_i2c_read(client, &reg_addr, 1, &reg_value, 1);
    if (err < 0)
    {
        FTS_ERROR("version read failed\n");
		return 0;
    }
    FTS_ERROR("Device ID = 0x%x", reg_value);

    fts_get_upgrade_array();

	data->irq_gpio_flags = IRQF_TRIGGER_FALLING;
    err = request_irq(client->irq, fts_ts_interrupt,
                               data->irq_gpio_flags, /* | IRQF_TRIGGER_FALLING,*/
                               client->dev.driver->name, data);
	if (err)
    {
        FTS_ERROR("request irq failed!");
        goto free_gpio;
    }

    disable_irq(client->irq);

#if FTS_PSENSOR_EN
    if ( fts_sensor_init(data) != 0)
    {
        FTS_ERROR("fts_sensor_init failed!");
        FTS_FUNC_EXIT();
        return 0;
    }
#endif

#if FTS_APK_NODE_EN
    fts_create_apk_debug_channel(client);
#endif

#if FTS_SYSFS_NODE_EN
    fts_create_sysfs(client);
#endif

#if FTS_POINT_REPORT_CHECK_EN
    fts_point_report_check_init();
#endif

	fts_ex_mode_init(client);

#if FTS_GESTURE_EN
    fts_gesture_init(input_dev);
#endif

#if FTS_ESDCHECK_EN
    fts_esdcheck_switch(ENABLE);
#endif

#if FTS_AUTO_UPGRADE_EN
    {
        err= fts_workqueue_init();
        if ( err!= 0 )
        {
            FTS_ERROR("fts_workqueue_init failed");
        }
        else
        {
            queue_work(touch_wq, &fw_update_work);
        }
    }
#endif
    fts_update_fw_ver(data);
    fts_update_fw_vendor_id(data);

    FTS_INFO("Firmware version = 0x%02x.%d.%d, fw_vendor_id=0x%02x",
             data->fw_ver[0], data->fw_ver[1], data->fw_ver[2], data->fw_vendor_id);

#if defined(CONFIG_FB)
    data->fb_notif.notifier_call = ft8716_fb_notifier_callback;

    err = fb_register_client(&data->fb_notif);

    if (err)
        FTS_ERROR("Unable to register fb_notifier: %d", err);


#elif defined(CONFIG_HAS_EARLYSUSPEND)
    data->early_suspend.level = EARLY_SUSPEND_LEVEL_BLANK_SCREEN + FTS_SUSPEND_LEVEL;
    data->early_suspend.suspend = fts_ts_early_suspend;
    data->early_suspend.resume = fts_ts_late_resume;
    register_early_suspend(&data->early_suspend);
#endif

#if FTS_TEST_EN
    fts_test_init(client);
#endif
	data->suspended = false;

    enable_irq(client->irq);
/*
    reg_addr = 0xA6;
    err = fts_i2c_read(client, &reg_addr, 1, &reg_value, 1);
    if (err < 0)
    {
        FTS_ERROR("version read failed");
    }
    FTS_ERROR("fw ID = 0x%x", reg_value);
    reg_addr = 0xA8;
    err = fts_i2c_read(client, &reg_addr, 1, &reg_value, 1);
    if (err < 0)
    {
        FTS_ERROR("version read failed");
    }
    FTS_ERROR("fw ID = 0x%x", reg_value);
*/
    FTS_FUNC_EXIT();
    return 0;
exit_create_singlethread:
	if (data->ts_pinctrl) {
		if (IS_ERR_OR_NULL(data->pinctrl_state_release)) {
			devm_pinctrl_put(data->ts_pinctrl);
			data->ts_pinctrl = NULL;
		} else {
			err = pinctrl_select_state(data->ts_pinctrl,
					data->pinctrl_state_release);
			if (err)
				pr_err("failed to select relase pinctrl state\n");
		}
	}
    FTS_ERROR("==singlethread error =");
    i2c_set_clientdata(client, NULL);
free_gpio:
#if 1
    if (gpio_is_valid(pdata->reset_gpio))
        gpio_free(pdata->reset_gpio);
#endif
    if (gpio_is_valid(pdata->irq_gpio))
        gpio_free(pdata->irq_gpio);
free_inputdev:
    input_free_device(input_dev);
	mutex_destroy(&data->wlock);
    FTS_FUNC_EXIT();
    return err;
}

/*******************************************************************************
*  Name: fts_ts_remove
*  Brief:
*  Input:
*  Output:
*  Return:
*******************************************************************************/
static int fts_ts_remove(struct i2c_client *client)
{
    struct fts_ts_data *data = i2c_get_clientdata(client);
	int retval;

    FTS_FUNC_ENTER();

    cancel_work_sync(&data->touch_event_work);
    destroy_workqueue(data->ts_workqueue);

#if FTS_PSENSOR_EN
    fts_sensor_remove(data);
#endif

#if FTS_APK_NODE_EN
    fts_release_apk_debug_channel();
#endif

#if FTS_SYSFS_NODE_EN
    fts_remove_sysfs(fts_i2c_client);
#endif

	fts_ex_mode_exit(client);

#if FTS_POINT_REPORT_CHECK_EN
    fts_point_report_check_exit();
#endif

#if FTS_AUTO_UPGRADE_EN
    cancel_work_sync(&fw_update_work);
#endif
    mutex_destroy(&data->wlock);
#if defined(CONFIG_FB)
    if (fb_unregister_client(&data->fb_notif))
        FTS_ERROR("Error occurred while unregistering fb_notifier.");
#elif defined(CONFIG_HAS_EARLYSUSPEND)
    unregister_early_suspend(&data->early_suspend);
#endif
    free_irq(client->irq, data);

#if 1
    if (gpio_is_valid(data->pdata->reset_gpio))
        gpio_free(data->pdata->reset_gpio);
#endif

    if (gpio_is_valid(data->pdata->irq_gpio))
        gpio_free(data->pdata->irq_gpio);

	if (data->ts_pinctrl) {
		if (IS_ERR_OR_NULL(data->pinctrl_state_release)) {
			devm_pinctrl_put(data->ts_pinctrl);
			data->ts_pinctrl = NULL;
		} else {
			retval = pinctrl_select_state(data->ts_pinctrl,
					data->pinctrl_state_release);
			if (retval < 0)
				pr_err("failed to select release pinctrl state\n");
		}
	}

    input_unregister_device(data->input_dev);

#if FTS_TEST_EN
    fts_test_exit(client);
#endif

#if FTS_ESDCHECK_EN
    fts_esdcheck_exit();
#endif

    FTS_FUNC_EXIT();
    return 0;
}

static const struct i2c_device_id fts_ts_id[] =
{
    {"fts_ts", 0},
    {},
};

MODULE_DEVICE_TABLE(i2c, fts_ts_id);

static struct of_device_id fts_match_table[] =
{
    { .compatible = "focaltech,fts",},
    { },
};

static struct i2c_driver fts_ts_driver =
{
    .probe = fts_ts_probe,
    .remove = fts_ts_remove,
    .driver = {
        .name = "fts_ts",
        .owner = THIS_MODULE,
        .of_match_table = fts_match_table,
    },
    .id_table = fts_ts_id,
};

/*******************************************************************************
*  Name: fts_ts_init
*  Brief:
*  Input:
*  Output:
*  Return:
*******************************************************************************/
//static int __init fts_ts_init(void)
int fts_ts_init(void)
{
    int ret = 0;

    FTS_FUNC_ENTER();
    ret = i2c_add_driver(&fts_ts_driver);
    if ( ret != 0 )
    {
        FTS_ERROR("Focaltech touch screen driver init failed!");
    }
    FTS_FUNC_EXIT();
    return ret;
}

/*******************************************************************************
*  Name: fts_ts_exit
*  Brief:
*  Input:
*  Output:
*  Return:
*******************************************************************************/
static void __exit fts_ts_exit(void)
{
    i2c_del_driver(&fts_ts_driver);
}

//module_init(fts_ts_init);
module_exit(fts_ts_exit);

MODULE_AUTHOR("FocalTech Driver Team");
MODULE_DESCRIPTION("FocalTech Touchscreen Driver");
MODULE_LICENSE("GPL v2");
