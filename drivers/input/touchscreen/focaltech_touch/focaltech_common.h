/*
 *
 * FocalTech fts TouchScreen driver.
 *
 * Copyright (c) 2010-2016, Focaltech Ltd. All rights reserved.
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
* File Name: focaltech_common.h
*
* Author: Focaltech Driver Team
*
* Created: 2016-08-16
*
* Abstract:
*
* Reference:
*
*******************************************************************************/

#ifndef __LINUX_FOCALTECH_COMMON_H__
#define __LINUX_FOCALTECH_COMMON_H__

#include "focaltech_config.h"

#define FTS_DRIVER_VERSION                  "Focaltech V1.0 20160826"

/* pramboot */
#define FTS_PRAMBOOT_8716   "include/pramboot/FT8716_Pramboot_V0.5_20160723.i"
#define FTS_PRAMBOOT_8607   "include/pramboot/FT8607_Pramboot_V0.3_20160727.i"

/* ic types */
#if (FTS_CHIP_TYPE == _FT8716)

#define FTS_CHIP_ID             0x87
#define FTS_UPGRADE_PRAMBOOT    FTS_PRAMBOOT_8716
#define FTS_REG_GLOVE_MODE_EN               0xC0

#elif (FTS_CHIP_TYPE == _FT8607)

#define FTS_CHIP_ID             0x86
#define FTS_UPGRADE_PRAMBOOT    FTS_PRAMBOOT_8607

#elif (FTS_CHIP_TYPE == _FT5X46)

#define FTS_CHIP_ID             0x54

#else
#error "unsupported chip type!"
#endif


#if ((FTS_CHIP_TYPE == _FT8716) || (FTS_CHIP_TYPE == _FT8607))
#define FTS_CHIP_IDC            1
#else
#define FTS_CHIP_IDC            0
#endif

#define FTS_POINT_REPORT_CHECK_EN               1

/* Point Report Check*/
#if FTS_POINT_REPORT_CHECK_EN
int fts_point_report_check_init(void);
int fts_point_report_check_exit(void);
void fts_point_report_check_queue_work(void);
#endif


//i2c
extern int fts_i2c_write_reg(struct i2c_client *client, u8 regaddr, u8 regvalue);
extern int fts_i2c_read_reg(struct i2c_client *client, u8 regaddr, u8 *regvalue);
extern int fts_i2c_read(struct i2c_client *client, char *writebuf,int writelen, char *readbuf, int readlen);
extern int fts_i2c_write(struct i2c_client *client, char *writebuf, int writelen);
extern int fts_i2c_init(void);
extern int fts_i2c_exit(void);

//Gesture functions
#if FTS_GESTURE_EN
extern int fts_gesture_init(struct input_dev *input_dev);
extern int fts_gesture_readdata(void);
extern int fts_gesture_suspend(struct i2c_client *i2c_client);
#endif

//Apk and functions
#if FTS_APK_NODE_EN
extern int fts_create_apk_debug_channel(struct i2c_client * client);
extern void fts_release_apk_debug_channel(void);
#endif

//ADB functions
#if FTS_SYSFS_NODE_EN
extern int fts_create_sysfs(struct i2c_client *client);
extern int fts_remove_sysfs(struct i2c_client *client);
#endif

extern int g_show_log;
extern int fts_reset_proc(int hdelayms);

#if FTS_ESDCHECK_EN
extern int fts_esdcheck_init(void);
extern int fts_esdcheck_exit(void);
extern int fts_esdcheck_switch(bool enable);
extern int fts_esdcheck_proc_busy(bool proc_debug);
extern int fts_esdcheck_set_intr(bool intr);
extern int fts_esdcheck_suspend(bool gesture_en);
extern int fts_esdcheck_resume(void);
extern int fts_esdcheck_get_status(void);

#define FTS_REG_FLOW_WORK_CNT                   0x91
#define FTS_REG_WORKMODE                        0x00
#define FTS_FACTORYMODE_VALUE                   0x40
#define FTS_WORKMODE_VALUE                      0x00
#define ENABLE                                  1
#define DISABLE                                 0
#endif

#if FTS_TEST_EN
int fts_test_init(struct i2c_client *client);
int fts_test_exit(struct i2c_client *client);
#endif
//other
int fts_ex_mode_init(struct i2c_client *client);
int fts_ex_mode_exit(struct i2c_client *client);
int fts_ex_mode_recovery(struct i2c_client *client);

/*******************************************************************************
* Static function prototypes
*******************************************************************************/

#if FTS_DEBUG_EN
#define FTS_DEBUG_LEVEL     1

#if (FTS_DEBUG_LEVEL == 2)
#define FTS_DEBUG(fmt, args...) printk(KERN_DEBUG"[FTS][%s]"fmt"\n", __func__, ##args)
#else
#define FTS_DEBUG(fmt, args...) printk(KERN_ERR"[FTS]"fmt"\n", ##args)
#endif

#define FTS_FUNC_ENTER() printk(KERN_ERR "[FTS]%s: Enter\n", __func__)
#define FTS_FUNC_EXIT()  printk(KERN_ERR "[FTS]%s: Exit(%d)\n", __func__, __LINE__)
#else
#define FTS_DEBUG(fmt, args...)
#define FTS_FUNC_ENTER()
#define FTS_FUNC_EXIT()
#endif

#define FTS_INFO(fmt, args...) do { \
            if (g_show_log) {printk(KERN_ERR "[FTS][Info]"fmt"\n", ##args);} \
        }  while (0)\
 
#define FTS_ERROR(fmt, args...)  do { \
             if (g_show_log) {printk(KERN_ERR "[FTS][Error]"fmt"\n", ##args);} \
        }  while (0)\
 

#endif /* __LINUX_FOCALTECH_COMMON_H__ */
