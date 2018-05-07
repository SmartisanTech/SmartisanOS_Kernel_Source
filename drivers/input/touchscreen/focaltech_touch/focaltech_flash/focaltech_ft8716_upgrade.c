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
* File Name: focaltech_ft8716_upgrade.c
*
* Author:    fupeipei
*
* Created:    2016-08-15
*
* Abstract:
*
* Reference:
*
*******************************************************************************/

/*******************************************************************************
* 1.Included header files
*******************************************************************************/
#include "../focaltech_core.h"
#include "../focaltech_flash.h"
#include "focaltech_ftxxxx_upgrade.h"

/*******************************************************************************
* Static variables
*******************************************************************************/

/*******************************************************************************
* Global variable or extern global variabls/functions
*******************************************************************************/

/*******************************************************************************
* Static function prototypes
*******************************************************************************/
#if (FTS_CHIP_TYPE == _FT8716)
extern u8 panel_vendor;
/************************************************************************
* Name: fts_ctpm_get_bin_file_ver
* Brief:  get .i file version
* Input: no
* Output: no
* Return: fw version
***********************************************************************/
int fts_ctpm_get_bin_file_ver(char *firmware_name)
{
    u8 *pbt_buf = NULL;
    int fwsize = fts_GetFirmwareSize(firmware_name);

    FTS_FUNC_ENTER();

    FTS_INFO("start upgrade with app.bin!!");

    if (fwsize <= 0)
    {
        FTS_ERROR("[UPGRADE]: Get firmware size failed!!");
        return -EIO;
    }

    if (fwsize < 8 || fwsize > 60 * 1024)
    {
        FTS_ERROR("[UPGRADE]: FW length error, upgrade fail!!");
        return -EIO;
    }

    pbt_buf = (unsigned char *)kmalloc(fwsize + 1, GFP_ATOMIC);
    if (fts_ReadFirmware(firmware_name, pbt_buf))
    {
        FTS_ERROR("[UPGRADE]: request_firmware failed!!");
        kfree(pbt_buf);
        return -EIO;
    }

    FTS_FUNC_EXIT();

    return pbt_buf[0x10E];
}

/************************************************************************
* Name: fts_ctpm_get_i_file_ver
* Brief:  get .i file version
* Input: no
* Output: no
* Return: fw version
***********************************************************************/
int fts_ctpm_get_i_file_ver(void)
{
	if (panel_vendor == 1)
		return CTPM_FW[0x10E];
	else if (panel_vendor == 0)
		return CTPM_FW_SHARP[0x10E];
	else {
		FTS_ERROR("incorrect panel vendor value:%d\n", panel_vendor);
		return -1;
	}
}
/************************************************************************
* Name: fts_8716_ctpm_fw_write_pram
* Brief:  fw upgrade
* Input: i2c info, file buf, file len
* Output: no
* Return: fail <0
***********************************************************************/
int  fts_8716_writepram(struct i2c_client * client, u8* pbt_buf, u32 dw_lenth)
{
    int i_ret;
    bool inrom = false;

    FTS_FUNC_ENTER();

    /*check the length of the pramboot*/
    FTS_DEBUG("[UPGRADE]: pramboot length: %d!!", dw_lenth);
    if (dw_lenth > 0x10000 || dw_lenth ==0)
    {
        return -EIO;
    }

    /*send comond to FW, reset and start write pramboot*/
    i_ret = fts_start_fw_upgrade(client);
    if (i_ret < 0)
    {
        FTS_ERROR( "[UPGRADE]: send upgrade cmd to FW error!!");
        return i_ret;
    }

    /*check run in rom or not! if run in rom, will write pramboot*/
    inrom = fts_check_in_rom(client);
    if (!inrom)
    {
        FTS_ERROR( "[UPGRADE]: not run in rom, write pramboot fail!!");
        return -EIO;
    }

    /*write pramboot to pram*/
    i_ret = fts_write_pramboot(client, dw_lenth, aucFW_PRAM_BOOT);
    if (i_ret < 0)
    {
        return i_ret;
        FTS_ERROR( "[UPGRADE]: write pramboot fail!!");
    }

    /*read out checksum*/
    i_ret = fts_pramboot_ecc(client);
    if (i_ret < 0)
    {
        return i_ret;
        FTS_ERROR( "[UPGRADE]: write pramboot ecc error!!");
    }

    /*start pram*/
    fts_start_pramboot(client);

    FTS_FUNC_EXIT();

    return 0;
}

/************************************************************************
* Name: fts_8716_ctpm_fw_upgrade
* Brief:  fw upgrade
* Input: i2c info, file buf, file len
* Output: no
* Return: fail <0
***********************************************************************/
int  fts_8716_ctpm_fw_upgrade(struct i2c_client * client, u8* pbt_buf, u32 dw_lenth)
{
    u32 temp;
    int i_ret;
    bool inpram = false;

    FTS_FUNC_ENTER();

    /*check run in pramboot or not! if not rum in pramboot, can not upgrade*/
    inpram = fts_check_in_pramboot(client);
    if (!inpram)
    {
        FTS_ERROR( "[UPGRADE]: not run in pram, upgrade fail!!");
        return -EIO;
    }

    /*upgrade init*/
    i_ret = fts_upgrade_init(client, dw_lenth);
    if (i_ret < 0)
    {
        FTS_ERROR( "[UPGRADE]: upgrade init error, upgrade fail!!");
        return i_ret;
    }

    /*erase the app erea in flash*/
    i_ret = fts_eraseflash(client);
    if (i_ret < 0)
    {
        FTS_ERROR( "[UPGRADE]: erase flash error!!");
        return i_ret;
    }

    /*start to write app*/
    i_ret = fts_writeapp(client, dw_lenth, pbt_buf);
    if (i_ret < 0)
    {
        return i_ret;
        FTS_ERROR( "[UPGRADE]: write app error!!");
    }

    /*read check sum*/
    temp = 0x1000;
    i_ret = fts_upgrade_ecc(client, temp, dw_lenth);
    if (i_ret < 0)
    {
        FTS_ERROR( "[UPGRADE]: ecc error!!");
        return i_ret;
    }

    /*upgrade success, reset the FW*/
    fts_rom_or_pram_reset(client, false);

    FTS_FUNC_EXIT();

    return 0;
}

/************************************************************************
* Name: fts_ctpm_fw_upgrade_with_i_file
* Brief:  upgrade with *.i file
* Input: i2c info
* Output: no
* Return: fail <0
***********************************************************************/
int fts_ctpm_fw_upgrade_with_i_file(struct i2c_client *client)
{
    int i_ret=0;
    u32 fw_len;

    FTS_FUNC_ENTER();

    FTS_DEBUG( "[UPGRADE]: write pram now!!");
    /*call the write pramboot function*/
    fw_len = fts_getsize(false);
    FTS_DEBUG( "[UPGRADE]: pramboot size : %d!!", fw_len);

    i_ret = fts_8716_writepram(client, aucFW_PRAM_BOOT, fw_len);
    if (i_ret != 0)
    {
        FTS_ERROR("[UPGRADE]: write pram error!!");
        return -EIO;
    }

    /*call the write fw upgrade function*/
    fw_len = fts_getsize(true);
    FTS_DEBUG("[UPGRADE]: app size : %d!!", fw_len);
	if (panel_vendor == 1)
		i_ret =  fts_8716_ctpm_fw_upgrade(client, CTPM_FW, fw_len);
	else if (panel_vendor == 0)
		i_ret =  fts_8716_ctpm_fw_upgrade(client, CTPM_FW_SHARP, fw_len);
    if (i_ret != 0)
    {
        FTS_ERROR("[UPGRADE]: upgrade failed!!");
    }
    else
    {
#if FTS_AUTO_CLB_EN
        fts_ctpm_auto_clb(client);  /*start auto CLB*/
#endif
    }

    FTS_FUNC_EXIT();

    return i_ret;
}

/************************************************************************
* Name: fts_ctpm_fw_upgrade_with_app_file
* Brief:  upgrade with *.bin file
* Input: i2c info, file name
* Output: no
* Return: success =0
***********************************************************************/
int fts_ctpm_fw_upgrade_with_app_file(struct i2c_client *client, char *firmware_name)
{
    u8 *pbt_buf = NULL;
    int i_ret=0;
    int fwsize = fts_GetFirmwareSize(firmware_name);
    int fw_len;

    FTS_INFO("[UPGRADE]: start upgrade with app.bin!!");

    if (fwsize <= 0)
    {
        FTS_ERROR("[UPGRADE]: Get firmware size failed!!");
        return -EIO;
    }
    if (fwsize < 8 || fwsize > 60 * 1024)
    {
        FTS_ERROR("[UPGRADE]: FW length error!!");
        return -EIO;
    }
    /*=========FW upgrade========================*/
    pbt_buf = (unsigned char *)kmalloc(fwsize + 1, GFP_ATOMIC);
    if (fts_ReadFirmware(firmware_name, pbt_buf))
    {
        FTS_ERROR("[UPGRADE]: request_firmware failed!!");
        kfree(pbt_buf);
        return -EIO;
    }

    /*call the upgrade function*/
    fw_len = fts_getsize(false);
    i_ret = fts_8716_writepram(client, aucFW_PRAM_BOOT, fw_len);
    if (i_ret != 0)
    {
        FTS_ERROR("[UPGRADE]: write pram failed!!");
        return -EIO;
    }

    i_ret =  fts_8716_ctpm_fw_upgrade(client, pbt_buf, fwsize);
    if (i_ret != 0)
    {
        FTS_ERROR("[UPGRADE]: upgrade failed!!");
    }
    else if (fts_updateinfo_curr.AUTO_CLB==AUTO_CLB_NEED)
    {
        fts_ctpm_auto_clb(client);
    }

    kfree(pbt_buf);

    return i_ret;
}
#endif

