/*
 *
 * FocalTech TouchScreen driver.
 *
 * Copyright (c) 2010-2016, FocalTech Systems, Ltd., all rights reserved.
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
/************************************************************************
*
* File Name: focaltech_config.h
*
*    Author: Focaltech Driver Team
*
*   Created: 2016-08-22
*
*  Abstract: global configurations
*
*   Version: v1.0
*
************************************************************************/
#ifndef _LINUX_FOCLATECH_CONFIG_H_
#define _LINUX_FOCLATECH_CONFIG_H_

/**************************************************/
/****** chip type defines, do not modify *********/
#define _FT5X46     0x5F46
#define _FT8607     0x8607
#define _FT8716     0x8716

/*************************************************/

/*
 * choose your ic chip type of focaltech
 */
#define FTS_CHIP_TYPE   _FT8716

/******************* Enables *********************/
/*********** 1 to enable, 0 to disable ***********/

/*
 * show debug log info
 * enable it for debug, disable it for release
 */
#define FTS_DEBUG_EN                            1

/*
 * Gesture function enable
 * default: disable
 */
#define FTS_GESTURE_EN                          0

/*
 * ESD check & protection
 * default: disable
 */
#define FTS_ESDCHECK_EN                         0

/*
 * Proximity sensor
 * default: disable
 */
#define FTS_PSENSOR_EN                          0

/*
 * Production test enable
 * 1: enable, 0:disable(default)
 */
#define FTS_TEST_EN                             1

/*
 * Glove mode enable
 * 1: enable, 0:disable(default)
 */
#define FTS_GLOVE_EN                            1

/*
 * cover enable
 * 1: enable, 0:disable(default)
 */
#define FTS_COVER_EN                            0

/*
 * Charger enable
 * 1: enable, 0:disable(default)
 */
#define FTS_CHARGER_EN                          0

/*
 * Nodes for tools, please keep enable
 */
#define FTS_SYSFS_NODE_EN                       1
#define FTS_APK_NODE_EN                         1

/*
 * Customer power enable
 * enable it when customer need control TP power
 * default: disable
 */
#define FTS_POWER_SOURCE_CUST_EN                1

/****************************************************/

/*
 * max touch points number
 * default: 10
 */
#define FTS_MAX_POINTS                          10


/********************** Upgrade ****************************/
/*
 * auto upgrade, please keep enable
 */
#define FTS_AUTO_UPGRADE_EN                     0

/* auto cb check
 * default: disable
 */
#define FTS_AUTO_CLB_EN                         0

/*
 * FW_APP.i files for upgrade
 * define your own fw_app, the sample one is invalid
 */
// #define FTS_UPGRADE_FW_APP        "include/firmware/FT8716_app_sample.i"
//#define FTS_UPGRADE_FW_APP        "include/firmware/Smartisan_Odin_FT8716_FW_Debug_V02_D01_20161024_app.i"
//#define FTS_UPGRADE_FW_APP        "include/firmware/Smartisan_Odin_FT8716_V05_D01_20161129_app.i"
//#define FTS_UPGRADE_FW_APP        "include/firmware/Smartisan_Odin_FT8716_V06_D01_20161207_app.i"
//#define FTS_UPGRADE_FW_APP        "include/firmware/Smartisan_Odin_FT8716_V07_D01_20161215_app.i"
//#define FTS_UPGRADE_FW_APP        "include/firmware/Smartisan_Odin_FT8716_Tianma_ID0x8d_V08_D01_20170104_app.i"
//#define FTS_UPGRADE_FW_APP        "include/firmware/FT8716_Smartisan_V0A_D01_20170117_app.i"
//#define FTS_UPGRADE_FW_APP        "include/firmware/FT8716_Smartisan_V0B_D01_20170215_app.i"
//#define FTS_UPGRADE_FW_APP        "include/firmware/FT8716_Smartisan_V0c_D01_20170217_app.i"
//#define FTS_UPGRADE_FW_APP        "include/firmware/FT8716_Smartisan_V0D_D01_20170219_app.i"
//#define FTS_UPGRADE_FW_APP          "include/firmware/FT8716_Smartisan_V0E_D01_20170221_app.i"
//#define FTS_UPGRADE_FW_APP          "include/firmware/FT8716_Smartisan_V0F_D01_20170224_app.i"
//#define FTS_UPGRADE_FW_APP          "include/firmware/Smartisan_Odin_FT8716_Tianma_ID0x8d_V10_D01_20170329_app.i"
//#define FTS_UPGRADE_FW_APP          "include/firmware/Smartisan_Odin_FT8716_Tianma_ID0x8d_V11_D01_20170411_app.i"
//#define FTS_UPGRADE_FW_APP          "include/firmware/Smartisan_Odin_FT8716_Tianma_ID0x8d_V12_D01_20170418_app.i"
#define FTS_UPGRADE_FW_APP          "include/firmware/Smartisan_Odin_FT8716_Tianma_ID0x8d_V13_D01_20170717_app.i"
//#define FTS_UPGRADE_FW_APP_SHARP        "include/firmware/Smartisan_Odin_FT8716_Sharp_ID0xe9_FW_V50_D01_20161221_app.i"
//#define FTS_UPGRADE_FW_APP_SHARP        "include/firmware/Smartisan_Odin_FT8716_Sharp_ID0xe9_FW_V52_D01_20170207_app.i"
//#define FTS_UPGRADE_FW_APP_SHARP        "include/firmware/Smartisan_Odin_FT8716_Sharp_ID0xe9_FW_V53_D01_20170208_app.i"
//#define FTS_UPGRADE_FW_APP_SHARP        "include/firmware/FT8716_Smartisan_V54_D01_20170215_app.i"
//#define FTS_UPGRADE_FW_APP_SHARP        "include/firmware/FT8716_Smartisan_V55_D01_20170219_app.i"
//#define FTS_UPGRADE_FW_APP_SHARP        "include/firmware/FT8716_Smartisan_V57_D01_20170221_app.i"
//#define FTS_UPGRADE_FW_APP_SHARP        "include/firmware/FT8716_Smartisan_V58_D01_20170224_app.i"
//#define FTS_UPGRADE_FW_APP_SHARP        "include/firmware/Smartisan_Odin_FT8716_Sharp_ID0xe9_V5a_D01_20170401_app.i"
//#define FTS_UPGRADE_FW_APP_SHARP        "include/firmware/Smartisan_Odin_FT8716_Sharp_ID0xe9_V5b_D01_20170411_app.i"
#define FTS_UPGRADE_FW_APP_SHARP        "include/firmware/Smartisan_Odin_FT8716_Sharp_ID0xe9_V5c_D01_20170418_app.i"


/*
 * vendor_id(s) for the ic
 * you need confirm vendor_id for upgrade
 * if only one vendor, ignore vendor_2_id, otherwise
 * you need define both of them
 */
#define FTS_VENDOR_1_ID                         0x8d
#define FTS_VENDOR_2_ID                         0x8d

/* show upgrade time in log
 * default: disable
 */
#define FTS_GET_UPGRADE_TIME                    1

/*
 * upgrade ping-pong test for debug
 * enable it for upgrade debug if needed
 * default: disable
 */
#define FTS_UPGRADE_PINGPONG_TEST               0
/* pingpong or error test times, default: 1000 */
#define FTS_UPGRADE_TEST_NUMBER                 1000

/*********************************************************/



#endif /* _LINUX_FOCLATECH_CONFIG_H_ */





