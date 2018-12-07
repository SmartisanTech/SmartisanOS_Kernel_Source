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
* File Name: focaltech_flash.c
*
* Author:    fupeipei
*
* Created:    2016-08-08
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
#include "focaltech_flash.h"
#include <linux/kthread.h>
#include "focaltech_flash/focaltech_ftxxxx_upgrade.h"
extern u8 panel_vendor;

/*******************************************************************************
* Static variables
*******************************************************************************/
struct fts_Upgrade_Info fts_updateinfo[] =
{
    {0x54,FTS_MAX_POINTS_10,AUTO_CLB_NONEED,2, 2, 0x54, 0x2c, 20, 2000}, //,"FT5x46"
    {0x55,FTS_MAX_POINTS_5,AUTO_CLB_NEED,50, 30, 0x79, 0x03, 10, 2000}, //,"FT5x06"
    {0x08,FTS_MAX_POINTS_5,AUTO_CLB_NEED,50, 10, 0x79, 0x06, 100, 2000}, //,"FT5606"
    {0x0a,FTS_MAX_POINTS_5,AUTO_CLB_NEED,50, 30, 0x79, 0x07, 10, 1500}, //,"FT5x16"
    {0x06,FTS_MAX_POINTS_2,AUTO_CLB_NONEED,100, 30, 0x79, 0x08, 10, 2000}, //,"FT6x06"
    {0x36,FTS_MAX_POINTS_2,AUTO_CLB_NONEED,10, 10, 0x79, 0x18, 10, 2000}, //,"FT6x36"
    {0x64,FTS_MAX_POINTS_2,AUTO_CLB_NONEED,10, 10, 0x79, 0x1c, 10, 2000}, //,"FT6336GU"
    {0x55,FTS_MAX_POINTS_5,AUTO_CLB_NEED,50, 30, 0x79, 0x03, 10, 2000}, //,"FT5x06i"
    {0x14,FTS_MAX_POINTS_5,AUTO_CLB_NONEED,30, 30, 0x79, 0x11, 10, 2000}, //,"FT5336"
    {0x13,FTS_MAX_POINTS_5,AUTO_CLB_NONEED,30, 30, 0x79, 0x11, 10, 2000}, //,"FT3316"
    {0x12,FTS_MAX_POINTS_5,AUTO_CLB_NONEED,30, 30, 0x79, 0x11, 10, 2000}, //,"FT5436i"
    {0x11,FTS_MAX_POINTS_5,AUTO_CLB_NONEED,30, 30, 0x79, 0x11, 10, 2000}, //,"FT5336i"
    {0x58,FTS_MAX_POINTS_5,AUTO_CLB_NONEED,2, 2, 0x58, 0x2c, 20, 2000},//"FT5822"
    {0x59,FTS_MAX_POINTS_10,AUTO_CLB_NONEED,30, 50, 0x79, 0x10, 1, 2000},//"FT5x26"
    {0x86,FTS_MAX_POINTS_10,AUTO_CLB_NONEED,2, 2, 0x86, 0xA7, 20, 2000},//"FT8607"
    {0x87,FTS_MAX_POINTS_10,AUTO_CLB_NONEED,2, 2, 0x87, 0xA6, 20, 2000},//"FT8716"
    {0x0E,FTS_MAX_POINTS_2,AUTO_CLB_NONEED,10, 10, 0x79, 0x18, 10, 2000}, //,"FT3x07"
};

unsigned char CTPM_FW[] =
{
#include FTS_UPGRADE_FW_APP
};

unsigned char CTPM_FW_SHARP[] =
{
#include FTS_UPGRADE_FW_APP_SHARP
};

unsigned char aucFW_PRAM_BOOT[] =
{
#if defined(FTS_UPGRADE_PRAMBOOT)
    #include FTS_UPGRADE_PRAMBOOT
#endif
};

/*******************************************************************************
* Global variable or extern global variabls/functions
*******************************************************************************/
struct fts_Upgrade_Info fts_updateinfo_curr;

#if FTS_AUTO_UPGRADE_EN
static bool is_update = false;
struct workqueue_struct *touch_wq;
struct work_struct fw_update_work;
#endif

#if FTS_UPGRADE_WITH_APP_BIN_EN
bool no_appbin = false;
#endif
/*******************************************************************************
* Static function prototypes
*******************************************************************************/

/************************************************************************
* Name: fts_i2c_hid2std
* Brief:  HID to I2C
* Input: i2c info
* Output: no
* Return: fail =0
***********************************************************************/
void fts_delay(u32 cnt)
{
    do
    {
        cnt--;
    }while(cnt>0);
}

/************************************************************************
* Name: fts_i2c_hid2std
* Brief:  HID to I2C
* Input: i2c info
* Output: no
* Return: fail =0
***********************************************************************/
int fts_i2c_hid2std(struct i2c_client * client)
{
#if (FTS_CHIP_IDC)
    return 0;
#else
    u8 auc_i2c_write_buf[5] = {0};
    int bRet = 0;

    auc_i2c_write_buf[0] = 0xeb;
    auc_i2c_write_buf[1] = 0xaa;
    auc_i2c_write_buf[2] = 0x09;
    bRet =fts_i2c_write(client, auc_i2c_write_buf, 3);
    msleep(10);
    auc_i2c_write_buf[0] = auc_i2c_write_buf[1] = auc_i2c_write_buf[2] = 0;
    fts_i2c_read(client, auc_i2c_write_buf, 0, auc_i2c_write_buf, 3);

    if (0xeb==auc_i2c_write_buf[0] && 0xaa==auc_i2c_write_buf[1] && 0x08==auc_i2c_write_buf[2])
    {
        pr_info("fts_i2c_hid2std successful.\n");
        bRet = 1;
    }
    else
    {
        pr_err("fts_i2c_hid2std error.\n");
        bRet = 0;
    }

    return bRet;
#endif
}

/*******************************************************************************
* Name: fts_update_fw_vendor_id
* Brief:
* Input:
* Output: None
* Return: None
*******************************************************************************/
void fts_update_fw_vendor_id(struct fts_ts_data *data)
{
    struct i2c_client *client = data->client;
    u8 reg_addr;
    int err;

    FTS_DEBUG("[UPGRADE]: read fw_vendor_id!!");
    reg_addr = FTS_REG_VENDOR_ID;
    err = fts_i2c_read(client, &reg_addr, 1, &data->fw_vendor_id, 1);
    if (err < 0)
        FTS_ERROR( "fw vendor id read failed");
}

/*******************************************************************************
* Name: fts_update_fw_ver
* Brief:
* Input:
* Output: None
* Return: None
*******************************************************************************/
void fts_update_fw_ver(struct fts_ts_data *data)
{
    struct i2c_client *client = data->client;
    u8 reg_addr;
    int err;

    FTS_DEBUG("[UPGRADE]: read fw_vendor_id!!\n");
    reg_addr = FTS_REG_FW_VER;
    err = fts_i2c_read(client, &reg_addr, 1, &data->fw_ver[0], 1);
    if (err < 0)
        FTS_ERROR( "fw major version read failed");

    reg_addr = FTS_REG_FW_MIN_VER;
    err = fts_i2c_read(client, &reg_addr, 1, &data->fw_ver[1], 1);
    if (err < 0)
        FTS_ERROR( "fw minor version read failed");

    reg_addr = FTS_REG_FW_SUB_MIN_VER;
    err = fts_i2c_read(client, &reg_addr, 1, &data->fw_ver[2], 1);
    if (err < 0)
        FTS_ERROR( "fw sub minor version read failed");

    dev_info(&client->dev, "Firmware version = %d.%d.%d",
             data->fw_ver[0], data->fw_ver[1], data->fw_ver[2]);
}

/************************************************************************
* Name: fts_ctpm_fw_upgrade_ReadVendorID
* Brief:  read vendor ID
* Input: i2c info, vendor ID
* Output: no
* Return: fail <0
***********************************************************************/
int fts_ctpm_fw_upgrade_ReadVendorID(struct i2c_client *client, u8 *ucPVendorID)
{
    u8 reg_val[4] = {0};
    u32 i = 0;
    u8 auc_i2c_write_buf[10];
    int i_ret;

    *ucPVendorID = 0;
    i_ret = fts_i2c_hid2std(client);
    if (i_ret == 0)
    {
        FTS_DEBUG("hidi2c change to stdi2c fail ! ");
    }

    for (i = 0; i < FTS_UPGRADE_LOOP; i++)
    {
        /*********Step 1:Reset  CTPM *****/
        fts_i2c_write_reg(client, 0xfc, FTS_UPGRADE_AA);
        msleep(fts_updateinfo_curr.delay_aa);
        fts_i2c_write_reg(client, 0xfc, FTS_UPGRADE_55);
        msleep(200);
        /*********Step 2:Enter upgrade mode *****/
        i_ret = fts_i2c_hid2std(client);
        if (i_ret == 0)
        {
            FTS_DEBUG("hidi2c change to stdi2c fail ! ");
        }
        msleep(10);
        auc_i2c_write_buf[0] = FTS_UPGRADE_55;
        auc_i2c_write_buf[1] = FTS_UPGRADE_AA;
        i_ret = fts_i2c_write(client, auc_i2c_write_buf, 2);
        if (i_ret < 0)
        {
            FTS_DEBUG("failed writing  0x55 and 0xaa ! ");
            continue;
        }
        /*********Step 3:check READ-ID***********************/
        msleep(10);
        auc_i2c_write_buf[0] = 0x90;
        auc_i2c_write_buf[1] = auc_i2c_write_buf[2] = auc_i2c_write_buf[3] = 0x00;
        reg_val[0] = reg_val[1] = 0x00;
        fts_i2c_read(client, auc_i2c_write_buf, 4, reg_val, 2);
        if (reg_val[0] == fts_updateinfo_curr.upgrade_id_1 && reg_val[1] == fts_updateinfo_curr.upgrade_id_2)
        {
            FTS_DEBUG("[FTS] Step 3: READ OK CTPM ID,ID1 = 0x%x,ID2 = 0x%x", reg_val[0], reg_val[1]);
            break;
        }
        else
        {
            FTS_DEBUG("[FTS] Step 3: CTPM ID,ID1 = 0x%x,ID2 = 0x%x", reg_val[0], reg_val[1]);
            continue;
        }
    }
    if (i >= FTS_UPGRADE_LOOP)
        return -EIO;
    /*********Step 4: read vendor id from app param area***********************/
    msleep(10);
    auc_i2c_write_buf[0] = 0x03;
    auc_i2c_write_buf[1] = 0x00;
    auc_i2c_write_buf[2] = 0xd7;
    auc_i2c_write_buf[3] = 0x84;
    for (i = 0; i < FTS_UPGRADE_LOOP; i++)
    {
        fts_i2c_write(client, auc_i2c_write_buf, 4);
        msleep(5);
        reg_val[0] = reg_val[1] = 0x00;
        i_ret = fts_i2c_read(client, auc_i2c_write_buf, 0, reg_val, 2);
        if (0 != reg_val[0])
        {
            *ucPVendorID = 0;
            FTS_DEBUG("In upgrade Vendor ID Mismatch, REG1 = 0x%x, REG2 = 0x%x, Definition:0x%x, i_ret=%d", reg_val[0], reg_val[1], 0, i_ret);
        }
        else
        {
            *ucPVendorID = reg_val[0];
            FTS_DEBUG("In upgrade Vendor ID, REG1 = 0x%x, REG2 = 0x%x", reg_val[0], reg_val[1]);
            break;
        }
    }
    msleep(50);
    /*********Step 5: reset the new FW***********************/
    FTS_DEBUG("Step 5: reset the new FW");
    auc_i2c_write_buf[0] = 0x07;
    fts_i2c_write(client, auc_i2c_write_buf, 1);
    msleep(200);
    i_ret = fts_i2c_hid2std(client);
    if (i_ret == 0)
    {
        FTS_DEBUG("hidi2c change to stdi2c fail ! ");
    }
    msleep(10);
    return 0;
}

/************************************************************************
* Name: fts_ctpm_fw_upgrade_ReadProjectCode
* Brief:  read project code
* Input: i2c info, project code
* Output: no
* Return: fail <0
***********************************************************************/
int fts_ctpm_fw_upgrade_ReadProjectCode(struct i2c_client *client, char *pProjectCode)
{
    u8 reg_val[4] = {0};
    u32 i = 0;
    u8 j = 0;
    u8 auc_i2c_write_buf[10];
    int i_ret;
    u32 temp;
    i_ret = fts_i2c_hid2std(client);
    if (i_ret == 0)
    {
        FTS_DEBUG("hidi2c change to stdi2c fail ! ");
    }
    for (i = 0; i < FTS_UPGRADE_LOOP; i++)
    {
        /*********Step 1:Reset  CTPM *****/
        fts_i2c_write_reg(client, 0xfc, FTS_UPGRADE_AA);
        msleep(fts_updateinfo_curr.delay_aa);
        fts_i2c_write_reg(client, 0xfc, FTS_UPGRADE_55);
        msleep(200);
        /*********Step 2:Enter upgrade mode *****/
        i_ret = fts_i2c_hid2std(client);
        if (i_ret == 0)
        {
            FTS_DEBUG("hidi2c change to stdi2c fail ! ");
        }
        msleep(10);
        auc_i2c_write_buf[0] = FTS_UPGRADE_55;
        auc_i2c_write_buf[1] = FTS_UPGRADE_AA;
        i_ret = fts_i2c_write(client, auc_i2c_write_buf, 2);
        if (i_ret < 0)
        {
            FTS_DEBUG("failed writing  0x55 and 0xaa ! ");
            continue;
        }
        /*********Step 3:check READ-ID***********************/
        msleep(10);
        auc_i2c_write_buf[0] = 0x90;
        auc_i2c_write_buf[1] = auc_i2c_write_buf[2] = auc_i2c_write_buf[3] = 0x00;
        reg_val[0] = reg_val[1] = 0x00;
        fts_i2c_read(client, auc_i2c_write_buf, 4, reg_val, 2);
        if (reg_val[0] == fts_updateinfo_curr.upgrade_id_1 && reg_val[1] == fts_updateinfo_curr.upgrade_id_2)
        {
            FTS_DEBUG("[FTS] Step 3: READ OK CTPM ID,ID1 = 0x%x,ID2 = 0x%x", reg_val[0], reg_val[1]);
            break;
        }
        else
        {
            FTS_DEBUG("[FTS] Step 3: CTPM ID,ID1 = 0x%x,ID2 = 0x%x", reg_val[0], reg_val[1]);
            continue;
        }
    }
    if (i >= FTS_UPGRADE_LOOP)
        return -EIO;
    /*********Step 4: read vendor id from app param area***********************/
    msleep(10);
    /*read project code*/
    auc_i2c_write_buf[0] = 0x03;
    auc_i2c_write_buf[1] = 0x00;
    for (j = 0; j < 33; j++)
    {
        temp = 0xD7A0 + j;
        auc_i2c_write_buf[2] = (u8)(temp>>8);
        auc_i2c_write_buf[3] = (u8)temp;
        fts_i2c_read(client, auc_i2c_write_buf, 4, pProjectCode+j, 1);
        if (*(pProjectCode+j) == '\0')
            break;
    }
    pr_info("project code = %s ", pProjectCode);
    msleep(50);
    /*********Step 5: reset the new FW***********************/
    FTS_DEBUG("Step 5: reset the new FW");
    auc_i2c_write_buf[0] = 0x07;
    fts_i2c_write(client, auc_i2c_write_buf, 1);
    msleep(200);
    i_ret = fts_i2c_hid2std(client);
    if (i_ret == 0)
    {
        FTS_DEBUG("hidi2c change to stdi2c fail ! ");
    }
    msleep(10);
    return 0;
}

/************************************************************************
* Name: fts_get_upgrade_array
* Brief: decide which ic
* Input: no
* Output: get ic info in fts_updateinfo_curr
* Return: no
***********************************************************************/
void fts_get_upgrade_array(void)
{

    u8 chip_id;
    u32 i;
    int ret = 0;
    unsigned char auc_i2c_write_buf[10];
    unsigned char reg_val[4] = {0};

    fts_i2c_hid2std(fts_i2c_client);

    for (i=0; i<5; i++)
    {
        ret = fts_i2c_read_reg(fts_i2c_client, FTS_REG_CHIP_ID,&chip_id);
        if (ret<0)
        {
            FTS_DEBUG("[UPGRADE]: read value fail!!");
        }
        else
        {
            break;
        }
    }
    FTS_DEBUG("[UPGRADE]: chip_id = %x!!", chip_id);


    if (ret<0 || chip_id == 0xEF || chip_id == 0)
    {
        auc_i2c_write_buf[0] = FTS_UPGRADE_55;
        fts_i2c_write(fts_i2c_client, auc_i2c_write_buf, 1);
        msleep(fts_updateinfo_curr.delay_readid);

        auc_i2c_write_buf[0] = 0x90;
        auc_i2c_write_buf[1] = auc_i2c_write_buf[2] = auc_i2c_write_buf[3] =0x00;
        fts_i2c_read(fts_i2c_client, auc_i2c_write_buf, 4, reg_val, 2);

        if (reg_val[0] == FTS_CHIP_ID)
        {
            chip_id = FTS_CHIP_ID;
            FTS_DEBUG("[UPGRADE]: read id for success : id is: ID1 = 0x%x,ID2 = 0x%x!!", reg_val[0], reg_val[1]);
        }
        else
        {
            FTS_DEBUG("[UPGRADE]: read id for test error: id is: ID1 = 0x%x,ID2 = 0x%x!!", reg_val[0], reg_val[1]);
        }
    }
    for (i=0; i<sizeof(fts_updateinfo)/sizeof(struct fts_Upgrade_Info); i++)
    {
        if (chip_id==fts_updateinfo[i].CHIP_ID || FTS_CHIP_ID==fts_updateinfo[i].CHIP_ID)
        {
            memcpy(&fts_updateinfo_curr, &fts_updateinfo[i], sizeof(struct fts_Upgrade_Info));
            break;
        }
    }

    if (i >= sizeof(fts_updateinfo)/sizeof(struct fts_Upgrade_Info))
    {
        memcpy(&fts_updateinfo_curr, &fts_updateinfo[0], sizeof(struct fts_Upgrade_Info));
    }
}

/************************************************************************
* Name: fts_8716_ctpm_fw_write_pram
* Brief:  fw upgrade
* Input: i2c info, file buf, file len
* Output: no
* Return: fail <0
***********************************************************************/
void fts_rom_or_pram_reset(struct i2c_client * client, bool needupgrade)
{
    u8 i = 0;
    u8 auc_i2c_write_buf[10];
    unsigned char inRomBoot = 0x00;  //0x01 : run in rom boot;  0x02 : run in pram boot

    FTS_FUNC_ENTER();

    FTS_DEBUG( "[UPGRADE]: reset the new FW!!");

    auc_i2c_write_buf[0] = 0x07;
    fts_i2c_write(client, auc_i2c_write_buf, 1);

    if (needupgrade)
    {
        for (i=0; i<30; i++)
        {
            msleep(10);

            inRomBoot = fts_flash_get_pram_or_rom_id(client);
            FTS_DEBUG( "[UPGRADE]: inRomBoot = %d!!", inRomBoot);
            if (inRomBoot == FTS_RUN_IN_ROM)
            {
                FTS_DEBUG( "[UPGRADE]: reset ok!!");
                return;
            }
            else
            {
                FTS_ERROR( "[UPGRADE]: reset fail!!");
                continue;
            }
        }
    }
    else
    {
        msleep(300);
    }

    FTS_FUNC_EXIT();
}

/************************************************************************
* Name: fts_ctpm_auto_clb
* Brief:  auto calibration
* Input: i2c info
* Output: no
* Return: 0
***********************************************************************/
int fts_ctpm_auto_clb(struct i2c_client *client)
{
    unsigned char uc_temp = 0x00;
    unsigned char i = 0;

    /*start auto CLB */
    msleep(200);

    fts_i2c_write_reg(client, 0, FTS_FACTORYMODE_VALUE);
    /*make sure already enter factory mode */
    msleep(100);
    /*write command to start calibration */
    fts_i2c_write_reg(client, 2, 0x4);
    msleep(300);
    if ((fts_updateinfo_curr.CHIP_ID==0x11) ||(fts_updateinfo_curr.CHIP_ID==0x12) ||(fts_updateinfo_curr.CHIP_ID==0x13) ||(fts_updateinfo_curr.CHIP_ID==0x14)) //5x36,5x36i
    {
        for (i=0; i<100; i++)
        {
            fts_i2c_read_reg(client, 0x02, &uc_temp);
            if (0x02 == uc_temp ||
                0xFF == uc_temp)
            {
                break;
            }
            msleep(20);
        }
    }
    else
    {
        for (i=0; i<100; i++)
        {
            fts_i2c_read_reg(client, 0, &uc_temp);
            if (0x0 == ((uc_temp&0x70)>>4))
            {
                break;
            }
            msleep(20);
        }
    }
    fts_i2c_write_reg(client, 0, 0x40);
    msleep(200);
    fts_i2c_write_reg(client, 2, 0x5);
    msleep(300);
    fts_i2c_write_reg(client, 0, FTS_WORKMODE_VALUE);
    msleep(300);
    return 0;
}

/************************************************************************
* Name: fts_GetFirmwareSize
* Brief:  get file size
* Input: file name
* Output: no
* Return: file size
***********************************************************************/
int fts_GetFirmwareSize(char *firmware_name)
{
    struct file *pfile = NULL;
    struct inode *inode;
    unsigned long magic;
    off_t fsize = 0;
    char filepath[128];

    FTS_DEBUG("[UPGRADE]: get fw_size\n");
    memset(filepath, 0, sizeof(filepath));
    sprintf(filepath, "%s%s", FTXXXX_INI_FILEPATH_CONFIG, firmware_name);
    if (NULL == pfile)
    {
        pfile = filp_open(filepath, O_RDONLY, 0);
    }
    if (IS_ERR(pfile))
    {
        pr_err("error occured while opening file %s.\n", filepath);
        return -EIO;
    }
    inode = pfile->f_path.dentry->d_inode;
    magic = inode->i_sb->s_magic;
    fsize = inode->i_size;
    filp_close(pfile, NULL);
    return fsize;
}

/************************************************************************
* Name: fts_ReadFirmware
* Brief:  read firmware buf for .bin file.
* Input: file name, data buf
* Output: data buf
* Return: 0
***********************************************************************/
int fts_ReadFirmware(char *firmware_name,unsigned char *firmware_buf)
{
    struct file *pfile = NULL;
    struct inode *inode;
    unsigned long magic;
    off_t fsize;
    char filepath[128];
    loff_t pos;
    mm_segment_t old_fs;

    FTS_DEBUG("[UPGRADE]: READ Firmware\n");
    memset(filepath, 0, sizeof(filepath));
    sprintf(filepath, "%s%s", FTXXXX_INI_FILEPATH_CONFIG, firmware_name);
    if (NULL == pfile)
    {
        pfile = filp_open(filepath, O_RDONLY, 0);
    }
    if (IS_ERR(pfile))
    {
        pr_err("error occured while opening file %s.\n", filepath);
        return -EIO;
    }
    inode = pfile->f_path.dentry->d_inode;
    magic = inode->i_sb->s_magic;
    fsize = inode->i_size;
    old_fs = get_fs();
    set_fs(KERNEL_DS);
    pos = 0;
    vfs_read(pfile, firmware_buf, fsize, &pos);
    filp_close(pfile, NULL);
    set_fs(old_fs);
    return 0;
}

/************************************************************************
* Name: fts_getsize
* Brief: 0
* Input: 0
* Output: 0
* Return: 0
***********************************************************************/
u32 fts_getsize(bool isapp)
{
    int fw_len = 0;

#if ((FTS_CHIP_TYPE == _FT8716) || (FTS_CHIP_TYPE == _FT8607))
    if (isapp)
    {
		if(panel_vendor == 1)
			fw_len = sizeof(CTPM_FW);
		else if(panel_vendor == 0)
			fw_len = sizeof(CTPM_FW_SHARP);
    }
    else
    {
        fw_len = sizeof(aucFW_PRAM_BOOT);
    }
#else
		if(panel_vendor == 1)
			fw_len = sizeof(CTPM_FW);
		else if(panel_vendor == 0)
			fw_len = sizeof(CTPM_FW_SHARP);
#endif
    return fw_len;
}

/************************************************************************
* Name: fts_ctpm_update_project_setting
* Brief:  update project setting, only update these settings for COB project, or for some special case
* Input: i2c info
* Output: no
* Return: fail <0
***********************************************************************/
int fts_ctpm_update_project_setting(struct i2c_client *client)
{
    u8 uc_i2c_addr;
    u8 uc_io_voltage;
    u8 uc_panel_factory_id;
    u8 buf[FTS_SETTING_BUF_LEN];
    u8 reg_val[2] = {0};
    u8 auc_i2c_write_buf[10] = {0};
    u8 packet_buf[FTS_SETTING_BUF_LEN + 6];
    u32 i = 0;
    int i_ret;

    uc_i2c_addr = client->addr;
    uc_io_voltage = 0x0;
    uc_panel_factory_id = 0x5a;


    FTS_DEBUG("[UPGRADE]: fts upgrade project setting\n");
    /*Step 1:Reset  CTPM*/
    if (fts_updateinfo_curr.CHIP_ID==0x06 || fts_updateinfo_curr.CHIP_ID==0x36)
    {
        fts_i2c_write_reg(client, 0xbc, 0xaa);
    }
    else
    {
        fts_i2c_write_reg(client, 0xfc, 0xaa);
    }
    msleep(50);

    /*write 0x55 to register 0xfc */
    if (fts_updateinfo_curr.CHIP_ID==0x06 || fts_updateinfo_curr.CHIP_ID==0x36)
    {
        fts_i2c_write_reg(client, 0xbc, 0x55);
    }
    else
    {
        fts_i2c_write_reg(client, 0xfc, 0x55);
    }
    msleep(30);

    /*********Step 2:Enter upgrade mode *****/
    auc_i2c_write_buf[0] = 0x55;
    auc_i2c_write_buf[1] = 0xaa;
    do
    {
        i++;
        i_ret = fts_i2c_write(client, auc_i2c_write_buf, 2);
        msleep(5);
    }
    while (i_ret <= 0 && i < 5);


    /*********Step 3:check READ-ID***********************/
    auc_i2c_write_buf[0] = 0x90;
    auc_i2c_write_buf[1] = auc_i2c_write_buf[2] = auc_i2c_write_buf[3] =
                               0x00;

    fts_i2c_read(client, auc_i2c_write_buf, 4, reg_val, 2);

    if (reg_val[0] == fts_updateinfo_curr.upgrade_id_1 && reg_val[1] == fts_updateinfo_curr.upgrade_id_2)
        dev_dbg(&client->dev, "[FTS] Step 3: CTPM ID,ID1 = 0x%x,ID2 = 0x%x\n",reg_val[0], reg_val[1]);
    else
        return -EIO;

    auc_i2c_write_buf[0] = 0xcd;
    fts_i2c_read(client, auc_i2c_write_buf, 1, reg_val, 1);
    dev_dbg(&client->dev, "bootloader version = 0x%x\n", reg_val[0]);

    /*--------- read current project setting  ---------- */
    /*set read start address */
    buf[0] = 0x3;
    buf[1] = 0x0;
    buf[2] = 0x78;
    buf[3] = 0x0;

    fts_i2c_read(client, buf, 4, buf, FTS_SETTING_BUF_LEN);
    dev_dbg(&client->dev, "[FTS] old setting: uc_i2c_addr = 0x%x,\
            uc_io_voltage = %d, uc_panel_factory_id = 0x%x\n",
            buf[0], buf[2], buf[4]);

    /*--------- Step 4:erase project setting --------------*/
    auc_i2c_write_buf[0] = 0x63;
    fts_i2c_write(client, auc_i2c_write_buf, 1);
    msleep(100);

    /*----------  Set new settings ---------------*/
    buf[0] = uc_i2c_addr;
    buf[1] = ~uc_i2c_addr;
    buf[2] = uc_io_voltage;
    buf[3] = ~uc_io_voltage;
    buf[4] = uc_panel_factory_id;
    buf[5] = ~uc_panel_factory_id;
    packet_buf[0] = 0xbf;
    packet_buf[1] = 0x00;
    packet_buf[2] = 0x78;
    packet_buf[3] = 0x0;
    packet_buf[4] = 0;
    packet_buf[5] = FTS_SETTING_BUF_LEN;

    for (i = 0; i < FTS_SETTING_BUF_LEN; i++)
        packet_buf[6 + i] = buf[i];

    fts_i2c_write(client, packet_buf, FTS_SETTING_BUF_LEN + 6);
    msleep(100);

    /********* reset the new FW***********************/
    auc_i2c_write_buf[0] = 0x07;
    fts_i2c_write(client, auc_i2c_write_buf, 1);

    msleep(200);
    return 0;
}

/************************************************************************
* Name: fts_flash_get_pram_or_rom_id
* Brief: 0
* Input: 0
* Output: 0
* Return: 0
***********************************************************************/
unsigned char fts_flash_get_pram_or_rom_id(struct i2c_client *client)
{
    unsigned char auc_i2c_write_buf[4];
    unsigned char reg_val[2] = {0};
    unsigned char inRomBoot = 0x00;  //0x01 : run in rom boot;  0x02 : run in pram boot
    int i_ret;

    i_ret = fts_i2c_hid2std(client);
    if (i_ret == 0)
    {
        FTS_ERROR("[UPGRADE]: hidi2c change to stdi2c fail!!");
    }

    FTS_DEBUG("[UPGRADE]: fts get rom id\n");
    /*Enter upgrade mode*/
    /*send 0x55 in time windows*/
    auc_i2c_write_buf[0] = FTS_UPGRADE_55;
    auc_i2c_write_buf[1] = FTS_UPGRADE_AA;
    i_ret = fts_i2c_write(client, auc_i2c_write_buf, 2);
    if (i_ret < 0)
    {
        FTS_ERROR( "[UPGRADE]: write 0x55, 0xaa fail!!");
    }
    msleep(fts_updateinfo_curr.delay_readid);

    auc_i2c_write_buf[0] = 0x90;
    auc_i2c_write_buf[1] = auc_i2c_write_buf[2] = auc_i2c_write_buf[3] =0x00;
    fts_i2c_read(client, auc_i2c_write_buf, 4, reg_val, 2);

    if (reg_val[0] == fts_updateinfo_curr.upgrade_id_1 && reg_val[1] == fts_updateinfo_curr.upgrade_id_2)
    {
        inRomBoot = FTS_RUN_IN_PRAM;
        FTS_DEBUG("[UPGRADE]: read pram boot id for success , pram boot id is: ID1 = 0x%x,ID2 = 0x%x!!", reg_val[0], reg_val[1]);
    }
    else if (reg_val[0] == fts_updateinfo_curr.upgrade_id_1 && reg_val[1] != fts_updateinfo_curr.upgrade_id_2)
    {
        inRomBoot = FTS_RUN_IN_ROM;
        FTS_DEBUG("[UPGRADE]: read rom boot id for success , rom boot id is: ID1 = 0x%x,ID2 = 0x%x!!", reg_val[0], reg_val[1]);
    }
    else
    {
        FTS_DEBUG("[UPGRADE]: read pram boot id for test error: pram boot id is: ID1 = 0x%x,ID2 = 0x%x!!", reg_val[0], reg_val[1]);
    }

    return inRomBoot;
}

/************************************************************************
* Name: fts_check_fw_status
* Brief: 0
* Input: 0
* Output: 0
* Return: 0
***********************************************************************/
u8 fts_check_fw_status(struct i2c_client *client)
{
    u8 uc_chip_id = 0;
    u8 uc_tp_vendor_id;
    u8 fw_status = 0;
    u8 i = 0;
    unsigned char inRomBoot = 0x00;  //0x01 : run in rom boot;  0x02 : run in pram boot

    FTS_FUNC_ENTER();

    for (i=0; i<5; i++)
    {
        fts_i2c_read_reg(client, FTS_REG_VENDOR_ID, &uc_tp_vendor_id);
        fts_i2c_read_reg(client, FTS_REG_CHIP_ID, &uc_chip_id);

        if ((uc_chip_id != fts_updateinfo_curr.CHIP_ID) ||
            ((uc_tp_vendor_id != FTS_VENDOR_1_ID)|| (uc_tp_vendor_id != FTS_VENDOR_2_ID)))
        {
            continue;
        }
        else
        {
            break;
        }
    }
    FTS_DEBUG("[UPGRADE]: uc_tp_vendor_id = %x, uc_chip_id = %x, fts_updateinfo_curr.CHIP_ID = %x, FTS_VENDOR_1_ID = %x!!", uc_tp_vendor_id, uc_chip_id, fts_updateinfo_curr.CHIP_ID, FTS_VENDOR_1_ID);

    if ((uc_chip_id == fts_updateinfo_curr.CHIP_ID) &&
        ((uc_tp_vendor_id == FTS_VENDOR_1_ID)|| (uc_tp_vendor_id == FTS_VENDOR_2_ID) || (uc_tp_vendor_id == 0xe9)))//call fts_flash_get_upgrade_info in probe function firstly.
    {
        fw_status = FTS_RUN_IN_APP;
        FTS_INFO("[UPGRADE]: APP OK!!");
    }
    else
    {
        inRomBoot = fts_flash_get_pram_or_rom_id(client);
        FTS_DEBUG( "[UPGRADE]: inRomBoot = %d!!", inRomBoot);
        if (inRomBoot == FTS_RUN_IN_ROM)
        {
            fw_status = FTS_RUN_IN_ROM;
            FTS_INFO( "[UPGRADE]: run in pram!!");
        }
        else
        {
            fw_status = FTS_RUN_IN_PRAM;
            FTS_INFO( "[UPGRADE]: not run in pram!!");
        }

        FTS_INFO("[UPGRADE]: APP invalid!!");
    }

    FTS_FUNC_EXIT();

    return fw_status;
}

/************************************************************************
* Name: fts_check_need_upgrade
* Brief: 0
* Input: 0
* Output: 0
* Return: 0
***********************************************************************/
bool fts_check_need_upgrade(struct i2c_client *client)
{
    int i = 0;
    u8 fw_status = 0;
    bool bUpgradeFlag = false;
    u8 uc_tp_fm_ver;
    u8 uc_host_fm_ver = 0;
#if FTS_UPGRADE_WITH_APP_BIN_EN
    int fwsize = 0;
#endif
    FTS_FUNC_ENTER();

    FTS_DEBUG("[UPGRADE]: check_need_upgrade\n");
#if FTS_UPGRADE_WITH_APP_BIN_EN
    for (i=0; i<100; i++)
    {
        fwsize = fts_GetFirmwareSize(FTS_UPGRADE_FW_APP_BIN);
        if (fwsize <= 0)
        {
            msleep(1000);
            FTS_ERROR("[UPGRADE]: Get app.bin failed!!");
            continue;
        }
        else
        {
            FTS_INFO("[UPGRADE]: Get app.bin success!!");
            break;
        }
    }

    if ((i >= 100) && (fwsize <= 0))
    {
        bUpgradeFlag = false;
        no_appbin = true;
        return bUpgradeFlag;
    }
#endif

    for (i=0; i<5; i++)
    {
        fw_status = fts_check_fw_status(client);
        if (!fw_status)
        {
            msleep(5);
        }
        else
        {
            break;
        }
        FTS_DEBUG( "[UPGRADE]: fw_status = %d!!", fw_status);
    }

    if (fw_status == FTS_RUN_IN_APP) //call fts_flash_get_upgrade_info in probe function firstly.
    {
        fts_i2c_read_reg(client, FTS_REG_FW_VER, &uc_tp_fm_ver);

#if FTS_UPGRADE_WITH_APP_BIN_EN
        uc_host_fm_ver = fts_ctpm_get_bin_file_ver(FTS_UPGRADE_FW_APP_BIN);
#else
        uc_host_fm_ver = fts_ctpm_get_i_file_ver();
#endif
        FTS_DEBUG("[UPGRADE]: uc_tp_fm_ver = 0x%x, uc_host_fm_ver = 0x%x!!", uc_tp_fm_ver, uc_host_fm_ver);
        if (uc_tp_fm_ver < uc_host_fm_ver )
        {
            bUpgradeFlag = true;
        }
    }
    else if (fw_status == FTS_RUN_IN_ROM)
    {
        FTS_DEBUG("[UPGRADE]: run in rom!!");
        bUpgradeFlag = true;
    }
    else if (fw_status == FTS_RUN_IN_PRAM)
    {
#if (FTS_CHIP_IDC)
        FTS_DEBUG("[UPGRADE]: run in pram, reset and upgrade!!");
        fts_rom_or_pram_reset(client, true);
#else
        FTS_DEBUG("[UPGRADE]: run in pram, app invalid!!");
#endif
        bUpgradeFlag = true;
    }

    FTS_FUNC_EXIT();

    return bUpgradeFlag;
}

/************************************************************************
* Name: fts_ctpm_auto_upgrade
* Brief:  auto upgrade
* Input: i2c info
* Output: no
* Return: 0
***********************************************************************/
int fts_ctpm_auto_upgrade(struct i2c_client *client)
{
    u8 uc_tp_fm_ver;
    int i_ret = 0;
    bool bUpgradeFlag = false;
    u8 uc_upgrade_times = 0;

    FTS_FUNC_ENTER();

    FTS_DEBUG("[UPGRADE]: auto_upgrade\n");
    /* check need upgrade or not */
    bUpgradeFlag = fts_check_need_upgrade(client);
    FTS_DEBUG("[UPGRADE]: bUpgradeFlag = 0x%x", bUpgradeFlag);

    /* will upgrade */
    if (bUpgradeFlag)
    {
        FTS_INFO("[UPGRADE]: need upgrade!!");
        do
        {
            uc_upgrade_times++;

            /* esd check */
#if FTS_ESDCHECK_EN
            fts_esdcheck_switch(DISABLE);
#endif

#if FTS_UPGRADE_WITH_APP_BIN_EN
            /* upgrade with bin file */
            i_ret = fts_ctpm_fw_upgrade_with_app_file(client, FTS_UPGRADE_FW_APP_BIN);
#else
            /* upgrade with i file */
            i_ret = fts_ctpm_fw_upgrade_with_i_file(client);
#endif

#if FTS_ESDCHECK_EN
            fts_esdcheck_switch(ENABLE);
#endif
            if (i_ret == 0) /* upgrade success */
            {
                fts_i2c_read_reg(client, FTS_REG_FW_VER, &uc_tp_fm_ver);
                FTS_DEBUG("[UPGRADE]: upgrade to new version 0x%x", uc_tp_fm_ver);
            }
            else /* upgrade fail */
            {
                /* if upgrade fail, reset to run ROM. if app in flash is ok. TP will work success */
                FTS_INFO("[UPGRADE]: upgrade fail, reset now!!");
                fts_rom_or_pram_reset(client, (uc_upgrade_times-1));
            }
        }
        while ((i_ret != 0) && (uc_upgrade_times < 2));  /* if upgrade fail, upgrade again. then return */
    }

    FTS_FUNC_EXIT();
    return i_ret;
}

#if  FTS_AUTO_UPGRADE_EN
static void fts_fw_update_work_func(struct work_struct *work)
{
    FTS_DEBUG( "[UPGRADE]:FTS enter upgrade!!");

	mutex_lock(&fts_wq_data->wlock);
    disable_irq(fts_wq_data->client->irq);

    is_update = true ;
#if (FTS_UPGRADE_PINGPONG_TEST)
    fts_ctpm_auto_upgrade_test(fts_i2c_client);
#else
    fts_ctpm_auto_upgrade(fts_i2c_client);
#endif
    is_update = false;
    enable_irq(fts_wq_data->client->irq);
	mutex_unlock(&fts_wq_data->wlock);
}

int fts_workqueue_init(void)
{
    touch_wq = create_singlethread_workqueue("touch_wq");
    if (touch_wq)
    {
        INIT_WORK(&fw_update_work, fts_fw_update_work_func);
		FTS_DEBUG( "[UPGRADE]:FTS touch_wq init\n");
    }
    else
    {
        goto err_workqueue_init;
    }
    return 0;

err_workqueue_init:
    FTS_ERROR("create_singlethread_workqueue failed\n");
    return -1;
}
#endif


