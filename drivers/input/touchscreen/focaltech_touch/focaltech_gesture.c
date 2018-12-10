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
* File Name: focaltech_gesture.c
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
* 1.Included header files
*******************************************************************************/
#include "focaltech_core.h"
#if FTS_GESTURE_EN

/*******************************************************************************
* Private constant and macro definitions using #define
*******************************************************************************/
#define  KEY_GESTURE_U                      KEY_U
#define  KEY_GESTURE_UP                     KEY_UP
#define  KEY_GESTURE_DOWN                   KEY_DOWN
#define  KEY_GESTURE_LEFT                   KEY_LEFT
#define  KEY_GESTURE_RIGHT                  KEY_RIGHT
#define  KEY_GESTURE_O                      KEY_O
#define  KEY_GESTURE_E                      KEY_E
#define  KEY_GESTURE_M                      KEY_M
#define  KEY_GESTURE_L                      KEY_L
#define  KEY_GESTURE_W                      KEY_W
#define  KEY_GESTURE_S                      KEY_S
#define  KEY_GESTURE_V                      KEY_V
#define  KEY_GESTURE_C                      KEY_C
#define  KEY_GESTURE_Z                      KEY_Z

#define GESTURE_LEFT                        0x20
#define GESTURE_RIGHT                       0x21
#define GESTURE_UP                          0x22
#define GESTURE_DOWN                        0x23
#define GESTURE_DOUBLECLICK                 0x24
#define GESTURE_O                           0x30
#define GESTURE_W                           0x31
#define GESTURE_M                           0x32
#define GESTURE_E                           0x33
#define GESTURE_L                           0x44
#define GESTURE_S                           0x46
#define GESTURE_V                           0x54
#define GESTURE_Z                           0x41
#define GESTURE_C                           0x34
#define FTS_GESTRUE_POINTS                  255
#define FTS_GESTRUE_POINTS_ONETIME          62
#define FTS_GESTRUE_POINTS_HEADER           8
#define FTS_GESTURE_OUTPUT_ADRESS           0xD3
#define FTS_GESTURE_OUTPUT_UNIT_LENGTH      4

/*******************************************************************************
* Private enumerations, structures and unions using typedef
*******************************************************************************/


/*******************************************************************************
* Static variables
*******************************************************************************/
short pointnum = 0;
unsigned short coordinate_x[150] = {0};
unsigned short coordinate_y[150] = {0};
extern struct fts_ts_data *fts_wq_data;
/*******************************************************************************
* Global variable or extern global variabls/functions
*******************************************************************************/

/*******************************************************************************
* Static function prototypes
*******************************************************************************/


/*******************************************************************************
* Name: fts_gesture_init
* Brief:
* Input:
* Output: None
* Return: None
*******************************************************************************/
int fts_gesture_init(struct input_dev *input_dev)
{
    FTS_FUNC_ENTER();

    input_set_capability(input_dev, EV_KEY, KEY_POWER);
    input_set_capability(input_dev, EV_KEY, KEY_GESTURE_U);
    input_set_capability(input_dev, EV_KEY, KEY_GESTURE_UP);
    input_set_capability(input_dev, EV_KEY, KEY_GESTURE_DOWN);
    input_set_capability(input_dev, EV_KEY, KEY_GESTURE_LEFT);
    input_set_capability(input_dev, EV_KEY, KEY_GESTURE_RIGHT);
    input_set_capability(input_dev, EV_KEY, KEY_GESTURE_O);
    input_set_capability(input_dev, EV_KEY, KEY_GESTURE_E);
    input_set_capability(input_dev, EV_KEY, KEY_GESTURE_M);
    input_set_capability(input_dev, EV_KEY, KEY_GESTURE_L);
    input_set_capability(input_dev, EV_KEY, KEY_GESTURE_W);
    input_set_capability(input_dev, EV_KEY, KEY_GESTURE_S);
    input_set_capability(input_dev, EV_KEY, KEY_GESTURE_V);
    input_set_capability(input_dev, EV_KEY, KEY_GESTURE_Z);
    input_set_capability(input_dev, EV_KEY, KEY_GESTURE_C);

    __set_bit(KEY_GESTURE_RIGHT, input_dev->keybit);
    __set_bit(KEY_GESTURE_LEFT, input_dev->keybit);
    __set_bit(KEY_GESTURE_UP, input_dev->keybit);
    __set_bit(KEY_GESTURE_DOWN, input_dev->keybit);
    __set_bit(KEY_GESTURE_U, input_dev->keybit);
    __set_bit(KEY_GESTURE_O, input_dev->keybit);
    __set_bit(KEY_GESTURE_E, input_dev->keybit);
    __set_bit(KEY_GESTURE_M, input_dev->keybit);
    __set_bit(KEY_GESTURE_W, input_dev->keybit);
    __set_bit(KEY_GESTURE_L, input_dev->keybit);
    __set_bit(KEY_GESTURE_S, input_dev->keybit);
    __set_bit(KEY_GESTURE_V, input_dev->keybit);
    __set_bit(KEY_GESTURE_C, input_dev->keybit);
    __set_bit(KEY_GESTURE_Z, input_dev->keybit);

    FTS_FUNC_EXIT();
    return 0;
}

/*******************************************************************************
* Name: fts_check_gesture
* Brief:
* Input:
* Output: None
* Return: None
*******************************************************************************/
static void fts_check_gesture(struct input_dev *input_dev,int gesture_id)
{
    char *envp[2];
    int gesture;

    FTS_FUNC_ENTER();
    switch (gesture_id)
    {
        case GESTURE_LEFT:
            envp[0]="GESTURE=LEFT";
            gesture = KEY_GESTURE_LEFT;
            break;
        case GESTURE_RIGHT:
            envp[0]="GESTURE=RIGHT";
            gesture = KEY_GESTURE_RIGHT;
            break;
        case GESTURE_UP:
            envp[0]="GESTURE=UP";
            gesture = KEY_GESTURE_UP;
            break;
        case GESTURE_DOWN:
            envp[0]="GESTURE=DOWN";
            gesture = KEY_GESTURE_DOWN;
            break;
        case GESTURE_DOUBLECLICK:
            envp[0]="GESTURE=DOUBLE_CLICK";
            gesture = KEY_POWER;
            break;
        case GESTURE_O:
            envp[0]="GESTURE=O";
            gesture = KEY_GESTURE_O;
            break;
        case GESTURE_W:
            envp[0]="GESTURE=W";
            gesture = KEY_GESTURE_W;
            break;
        case GESTURE_M:
            envp[0]="GESTURE=M";
            gesture = KEY_GESTURE_M;
            break;
        case GESTURE_E:
            envp[0]="GESTURE=E";
            gesture = KEY_GESTURE_E;
            break;
        case GESTURE_L:
            envp[0]="GESTURE=L";
            gesture = KEY_GESTURE_L;
            break;
        case GESTURE_S:
            envp[0]="GESTURE=S";
            gesture = KEY_GESTURE_S;
            break;
        case GESTURE_V:
            envp[0]="GESTURE=V";
            gesture = KEY_GESTURE_V;
            break;
        case GESTURE_Z:
            envp[0]="GESTURE=Z";
            gesture = KEY_GESTURE_Z;
            break;
        case  GESTURE_C:
            envp[0]="GESTURE=C";
            gesture = KEY_GESTURE_C;
            break;
        default:
            envp[0]="GESTURE=NONE";
            gesture = -1;
            break;
    }
    FTS_DEBUG("envp[0]: %s", envp[0]);
    /*if (gesture != -1)
    {
        input_report_key(input_dev, gesture, 1);
        input_sync(input_dev);
        input_report_key(input_dev, gesture, 0);
        input_sync(input_dev);
    }*/

    envp[1]=NULL;
    kobject_uevent_env(&fts_wq_data->client->dev.kobj, KOBJ_CHANGE, envp);
    sysfs_notify(&fts_wq_data->client->dev.kobj, NULL, "GESTURE_ID");

    FTS_FUNC_EXIT();
}

/************************************************************************
*   Name: fts_gesture_readdata
* Brief: read data from TP register
* Input: no
* Output: no
* Return: fail <0
***********************************************************************/
int fts_gesture_readdata(void)
{
    unsigned char buf[FTS_GESTRUE_POINTS * 3] = { 0 };
    int ret = -1;
    int i = 0;
    int gestrue_id = 0;

    buf[0] = 0xd3;
    pointnum = 0;

    FTS_FUNC_ENTER();
    ret = fts_i2c_read(fts_i2c_client, buf, 1, buf, FTS_GESTRUE_POINTS_HEADER);

    if (ret < 0)
    {
        FTS_ERROR( "%s read touchdata failed.", __func__);
        FTS_FUNC_EXIT();
        return ret;
    }

    /* FW */
    if (fts_updateinfo_curr.CHIP_ID==0x54 || fts_updateinfo_curr.CHIP_ID==0x58 || fts_updateinfo_curr.CHIP_ID==0x86 || fts_updateinfo_curr.CHIP_ID==0x87  || fts_updateinfo_curr.CHIP_ID == 0x64)
    {
        gestrue_id = buf[0];
        pointnum = (short)(buf[1]) & 0xff;
        buf[0] = 0xd3;

        if ((pointnum * 4 + 2)<255)
        {
            ret = fts_i2c_read(fts_i2c_client, buf, 1, buf, (pointnum * 4 + 2));
        }
        else
        {
            ret = fts_i2c_read(fts_i2c_client, buf, 1, buf, 255);
            ret = fts_i2c_read(fts_i2c_client, buf, 0, buf+255, (pointnum * 4 + 2) -255);
        }
        if (ret < 0)
        {
            printk( "%s read touchdata failed.", __func__);
            FTS_FUNC_EXIT();
            return ret;
        }

        fts_check_gesture(fts_input_dev,gestrue_id);
        FTS_FUNC_EXIT();
        return 0;
    }
    // other IC's gestrue in driver
    if (0x24 == buf[0])
    {
        gestrue_id = 0x24;
        fts_check_gesture(fts_input_dev,gestrue_id);
        printk( "%d check_gesture gestrue_id.", gestrue_id);
        FTS_FUNC_EXIT();
        return -1;
    }

    pointnum = (short)(buf[1]) & 0xff;
    buf[0] = 0xd3;
    if ((pointnum * 4 + 8)<255)
    {
        ret = fts_i2c_read(fts_i2c_client, buf, 1, buf, (pointnum * 4 + 8));
    }
    else
    {
        ret = fts_i2c_read(fts_i2c_client, buf, 1, buf, 255);
        ret = fts_i2c_read(fts_i2c_client, buf, 0, buf+255, (pointnum * 4 + 8) -255);
    }
    if (ret < 0)
    {
        FTS_ERROR("%s read touchdata failed.", __func__);
        FTS_FUNC_EXIT();
        return ret;
    }

    //gestrue_id = fetch_object_sample(buf, pointnum);//need gesture lib.a
    fts_check_gesture(fts_input_dev,gestrue_id);
    FTS_DEBUG("%d read gestrue_id.", gestrue_id);

    for (i = 0; i < pointnum; i++)
    {
        coordinate_x[i] =  (((s16) buf[0 + (4 * i+8)]) & 0x0F) <<
                           8 | (((s16) buf[1 + (4 * i+8)])& 0xFF);
        coordinate_y[i] = (((s16) buf[2 + (4 * i+8)]) & 0x0F) <<
                          8 | (((s16) buf[3 + (4 * i+8)]) & 0xFF);
    }
    FTS_FUNC_EXIT();
    return -1;
}
int fts_gesture_suspend(struct i2c_client *fts_i2c_client)
{

    FTS_DEBUG("Enter gesturne mode");
    fts_i2c_write_reg(fts_i2c_client, 0xd0, 0x01);
    if (fts_updateinfo_curr.CHIP_ID==0x54 || fts_updateinfo_curr.CHIP_ID==0x58 ||
        fts_updateinfo_curr.CHIP_ID==0x86 || fts_updateinfo_curr.CHIP_ID==0x87)
    {
        fts_i2c_write_reg(fts_i2c_client, 0xd1, 0xff);
        fts_i2c_write_reg(fts_i2c_client, 0xd2, 0xff);
        fts_i2c_write_reg(fts_i2c_client, 0xd5, 0xff);
        fts_i2c_write_reg(fts_i2c_client, 0xd6, 0xff);
        fts_i2c_write_reg(fts_i2c_client, 0xd7, 0xff);
        fts_i2c_write_reg(fts_i2c_client, 0xd8, 0xff);
    }

    return 0;
}
#endif /* FTS_GESTURE_EN */
