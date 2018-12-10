/************************************************************************
* Copyright (C) 2012-2016, Focaltech Systems (R)£¬All Rights Reserved.
*
* File Name: focaltech_ftxxxx_upgrade.h
*
*    Author: fupeipei
*
*   Created: 2016-08-16
*
*  Abstract:
*
************************************************************************/
#ifndef __LINUX_FOCALTECH_FTXXXX_UPGRADE_H__
#define __LINUX_FOCALTECH_FTXXXX_UPGRADE_H__

/*******************************************************************************
* 1.Included header files
*******************************************************************************/
#include "../focaltech_flash.h"

/*******************************************************************************
* Private constant and macro definitions using #define
*******************************************************************************/

/*******************************************************************************
* Private enumerations, structures and unions using typedef
*******************************************************************************/

/*******************************************************************************
* Static variables
*******************************************************************************/

/*******************************************************************************
* Global variable or extern global variabls/functions
*******************************************************************************/

/*******************************************************************************
* Static function prototypes
*******************************************************************************/
#if (FTS_UPGRADE_PINGPONG_TEST)
int fts_ctpm_auto_upgrade_test(struct i2c_client *client);
#endif
int fts_ctpm_get_bin_file_ver(char *firmware_name);

#if ((FTS_CHIP_TYPE == _FT8716) || (FTS_CHIP_TYPE == _FT8607) )
int fts_eraseflash(struct i2c_client * client);
int fts_pramboot_ecc(struct i2c_client * client);
bool fts_check_in_rom(struct i2c_client * client);
bool fts_start_pramboot(struct i2c_client * client);
bool fts_start_fw_upgrade(struct i2c_client * client);
bool fts_check_in_pramboot(struct i2c_client * client);
int fts_upgrade_init(struct i2c_client * client, u32 dw_lenth);
int fts_writeapp(struct i2c_client * client, u32 length, u8* readbuf);
int fts_upgrade_ecc(struct i2c_client * client, u32 startaddr, u32 length);
int fts_write_pramboot(struct i2c_client * client, u32 length, u8* readbuf);
int fts_writeflash(struct i2c_client * client, u32 writeaddr, u32 length, u8* readbuf, u32 cnt);
#endif

int fts_6x36_ctpm_fw_upgrade(struct i2c_client *client, u8 *pbt_buf, u32 dw_lenth);
int fts_6336GU_ctpm_fw_upgrade(struct i2c_client *client, u8 *pbt_buf, u32 dw_lenth);
int fts_6x06_ctpm_fw_upgrade(struct i2c_client *client, u8 *pbt_buf, u32 dw_lenth);
int fts_5x36_ctpm_fw_upgrade(struct i2c_client *client, u8 *pbt_buf, u32 dw_lenth);
int fts_5x06_ctpm_fw_upgrade(struct i2c_client *client, u8 *pbt_buf, u32 dw_lenth);
int fts_5x46_ctpm_fw_upgrade(struct i2c_client * client, u8* pbt_buf, u32 dw_lenth);
int fts_5822_ctpm_fw_upgrade(struct i2c_client * client, u8* pbt_buf, u32 dw_lenth);
int fts_5x26_ctpm_fw_upgrade(struct i2c_client *client, u8 *pbt_buf, u32 dw_lenth);
int fts_8606_writepram(struct i2c_client * client, u8* pbt_buf, u32 dw_lenth);
int fts_8606_ctpm_fw_upgrade(struct i2c_client * client, u8* pbt_buf, u32 dw_lenth);
int fts_8607_ctpm_fw_upgrade(struct i2c_client * client, u8* pbt_buf, u32 dw_lenth);
int fts_8607_writepram(struct i2c_client * client, u8* pbt_buf, u32 dw_lenth);
int fts_8716_ctpm_fw_upgrade(struct i2c_client * client, u8* pbt_buf, u32 dw_lenth);
int fts_8716_writepram(struct i2c_client * client, u8* pbt_buf, u32 dw_lenth);
int fts_3x07_ctpm_fw_upgrade(struct i2c_client *client, u8 *pbt_buf, u32 dw_lenth);

#endif
