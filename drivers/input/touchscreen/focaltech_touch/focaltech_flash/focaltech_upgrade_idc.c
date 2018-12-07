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
* File Name: focaltech_upgrade_idc.c
*
* Author:    fupeipei
*
* Created:    2016-08-22
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

/*******************************************************************************
* Static variables
*******************************************************************************/

/*******************************************************************************
* Global variable or extern global variabls/functions
*******************************************************************************/
u8 upgrade_ecc;

/*******************************************************************************
* Static function prototypes
*******************************************************************************/
#if ((FTS_CHIP_TYPE == _FT8716) || (FTS_CHIP_TYPE == _FT8607))

/************************************************************************
* Name: fts_upgrade_init
* Brief: 0
* Input: 0
* Output: 0
* Return: 0
***********************************************************************/
int fts_upgrade_init(struct i2c_client * client, u32 dw_lenth)
{
    int i_ret = 0;
    u8 reg_val_id[4] = {0};
    u8 auc_i2c_write_buf[10];

    FTS_FUNC_ENTER();

    /*read flash ID*/
    auc_i2c_write_buf[0] = 0x05;
    reg_val_id[0] = 0x00;
    i_ret =fts_i2c_read(client, auc_i2c_write_buf, 1, reg_val_id, 1);
    if (i_ret < 0)
    {
        return -EIO;
    }

    if (dw_lenth == 0)
    {
        return -EIO;
    }

    /*check the fw length by falsh type*/
    if (0x81 == (int)reg_val_id[0])
    {
        if (dw_lenth > 1024*60)
        {
            return -EIO;
        }
    }
    else if (0x80 == (int)reg_val_id[0])
    {
        if (dw_lenth > 1024*64)
        {
            return -EIO;
        }
    }

    /*set flash clk*/
    {
        auc_i2c_write_buf[0] = 0x05;
        auc_i2c_write_buf[1] = reg_val_id[0];//0x80;
        auc_i2c_write_buf[2] = 0x00;
        fts_i2c_write(client, auc_i2c_write_buf, 3);
    }

    /*send upgrade type to reg 0x09: 0x0B: upgrade; 0x0A: download*/
    {
        auc_i2c_write_buf[0] = 0x09;
        auc_i2c_write_buf[1] = 0x0B;
        fts_i2c_write(client, auc_i2c_write_buf, 2);
    }

    FTS_FUNC_EXIT();

    return 0;
}

/************************************************************************
* Name: fts_start_pramboot
* Brief: 0
* Input: 0
* Output: 0
* Return: 0
***********************************************************************/
bool fts_start_pramboot(struct i2c_client * client)
{
    int i_ret = 0;
    u8 auc_i2c_write_buf[10];

    FTS_FUNC_ENTER();

    FTS_INFO("[UPGRADE]: start pramboot!!");
    auc_i2c_write_buf[0] = 0x08;
    fts_i2c_write(client, auc_i2c_write_buf, 1);
    msleep(20);

    FTS_FUNC_EXIT();

    return i_ret;
}

/************************************************************************
* Name: fts_start_fw_upgrade
* Brief: 0
* Input: 0
* Output: 0
* Return: 0
***********************************************************************/
bool fts_start_fw_upgrade(struct i2c_client * client)
{
    int i_ret = 0;
    FTS_FUNC_ENTER();

    /*send the soft upgrade commond to FW, and start upgrade*/
    FTS_INFO("[UPGRADE]: send 0xAA and 0x55 to FW, and start upgrade!!");

    i_ret = fts_i2c_write_reg(client, 0xfc, FTS_UPGRADE_AA);
    msleep(fts_updateinfo_curr.delay_aa);
    i_ret = fts_i2c_write_reg(client, 0xfc, FTS_UPGRADE_55);
    msleep(200);

    FTS_FUNC_EXIT();

    return i_ret;
}

/************************************************************************
* Name: fts_check_in_rom
* Brief: 0
* Input: 0
* Output: 0
* Return: 0
***********************************************************************/
bool fts_check_in_rom(struct i2c_client * client)
{
    u32 i = 0;
    unsigned char inRomBoot = 0x00;  //0x01 : run in rom boot;  0x02 : run in pram boot

    FTS_FUNC_ENTER();

    for (i = 0; i < FTS_UPGRADE_LOOP; i++)
    {
        /*read ID and check run in ROM or not*/
        inRomBoot = fts_flash_get_pram_or_rom_id(client);
        FTS_DEBUG( "[UPGRADE]: inRomBoot = %d!!", inRomBoot);
        if (inRomBoot == FTS_RUN_IN_ROM)
        {
            FTS_INFO( "[UPGRADE]: run in ROM!!");
            return true;
        }
        else
        {
            FTS_INFO( "[UPGRADE]: not run in ROM!!");
            continue;
        }
    }

    if (i >= FTS_UPGRADE_LOOP )  /*not run in ROM, can not upgrade*/
    {
        FTS_ERROR( "[UPGRADE]: read rom id fail, not run in rom!!");
        return false;
    }

    FTS_FUNC_EXIT();

    return true;
}

/************************************************************************
* Name: fts_check_in_pramboot
* Brief: 0
* Input: 0
* Output: 0
* Return: 0
***********************************************************************/
bool fts_check_in_pramboot(struct i2c_client * client)
{
    u32 i = 0;
    unsigned char inRomBoot = 0x00;  //0x01 : run in rom boot;  0x02 : run in pram boot

    FTS_FUNC_ENTER();
    for (i = 0; i < FTS_UPGRADE_LOOP; i++)
    {
        msleep(10);

        /*read ID and check run in pram or not*/
        inRomBoot = fts_flash_get_pram_or_rom_id(client);
        FTS_DEBUG( "[UPGRADE]: inRomBoot = %d", inRomBoot);
        if (inRomBoot == FTS_RUN_IN_PRAM)
        {
            FTS_INFO( "[UPGRADE]: run in pram!!");
            return true;
        }
        else
        {
            FTS_INFO( "[UPGRADE]: not run in pram!!");
            continue;
        }
    }

    /*not run in pramboot, can not upgrade. return. upgrade fail*/
    if (i >= FTS_UPGRADE_LOOP )
    {
        FTS_ERROR( "[UPGRADE]: read pram id fail, not run in pram!!");
        return false;
    }

    FTS_FUNC_EXIT();

    return true;
}

/************************************************************************
* Name: fts_pramboot_ecc
* Brief: 0
* Input: 0
* Output: 0
* Return: 0
***********************************************************************/
int fts_pramboot_ecc(struct i2c_client * client)
{
    u8 auc_i2c_write_buf[10];
    u8 reg_val[4] = {0};

    FTS_FUNC_ENTER();

    /*read out checksum, if pramboot checksum != host checksum, upgrade fail*/
    FTS_INFO("[UPGRADE]: read out pramboot checksum");
    auc_i2c_write_buf[0] = 0xcc;
    msleep(2);
    fts_i2c_read(client, auc_i2c_write_buf, 1, reg_val, 1);
    if (reg_val[0] != upgrade_ecc) /*pramboot checksum != host checksum, upgrade fail*/
    {
        FTS_ERROR("[UPGRADE]: checksum fail : pramboot_ecc = %X, host_ecc = %X!!",reg_val[0],upgrade_ecc);
        return -EIO;
    }
    FTS_DEBUG("[UPGRADE]: checksum success : pramboot_ecc = %X, host_ecc = %X!!",reg_val[0],upgrade_ecc);
    msleep(100);

    FTS_FUNC_EXIT();

    return 0;
}

/************************************************************************
* Name: fts_upgrade_ecc
* Brief: 0
* Input: 0
* Output: 0
* Return: 0
***********************************************************************/
int fts_upgrade_ecc(struct i2c_client * client, u32 startaddr, u32 length)
{
    u32 i = 0;
    u8 auc_i2c_write_buf[10];
    u32 temp;
    u8 reg_val[4] = {0};
    int i_ret = 0;

    FTS_FUNC_ENTER();

    FTS_INFO( "[UPGRADE]: read out checksum!!");

    /*check sum init*/
    auc_i2c_write_buf[0] = 0x64;
    fts_i2c_write(client, auc_i2c_write_buf, 1);
    msleep(300);

    /*send commond to pramboot to start checksum*/
    auc_i2c_write_buf[0] = 0x65;
    auc_i2c_write_buf[1] = (u8)(startaddr >> 16);
    auc_i2c_write_buf[2] = (u8)(startaddr >> 8);
    auc_i2c_write_buf[3] = (u8)(startaddr);

    if (length > LEN_FLASH_ECC_MAX)
    {
        temp = LEN_FLASH_ECC_MAX;
    }
    else
    {
        temp = length;
    }

    auc_i2c_write_buf[4] = (u8)(temp >> 8);
    auc_i2c_write_buf[5] = (u8)(temp);
    i_ret = fts_i2c_write(client, auc_i2c_write_buf, 6);
    msleep(length/256);

    /*read status : if check sum is finished?*/
    for (i = 0; i < 100; i++)
    {
        auc_i2c_write_buf[0] = 0x6a;
        reg_val[0] = reg_val[1] = 0x00;
        fts_i2c_read(client, auc_i2c_write_buf, 1, reg_val, 2);

        if (0xF0==reg_val[0] && 0x55==reg_val[1])
        {
            break;
        }
        msleep(1);

    }

    if (length > LEN_FLASH_ECC_MAX)
    {
        temp = LEN_FLASH_ECC_MAX;
        auc_i2c_write_buf[0] = 0x65;
        auc_i2c_write_buf[1] = (u8)(temp >> 16);
        auc_i2c_write_buf[2] = (u8)(temp >> 8);
        auc_i2c_write_buf[3] = (u8)(temp);
        temp = length-LEN_FLASH_ECC_MAX;
        auc_i2c_write_buf[4] = (u8)(temp >> 8);
        auc_i2c_write_buf[5] = (u8)(temp);
        i_ret = fts_i2c_write(client, auc_i2c_write_buf, 6);

        msleep(length/256);

        for (i = 0; i < 100; i++)
        {
            auc_i2c_write_buf[0] = 0x6a;
            reg_val[0] = reg_val[1] = 0x00;
            fts_i2c_read(client, auc_i2c_write_buf, 1, reg_val, 2);

            if (0xF0==reg_val[0] && 0x55==reg_val[1])
            {
                break;
            }
            msleep(1);
        }
    }

    /*read out check sum*/
    auc_i2c_write_buf[0] = 0x66;
    i_ret = fts_i2c_read(client, auc_i2c_write_buf, 1, reg_val, 1);
    if (reg_val[0] != upgrade_ecc) /*if check sum fail, upgrade fail*/
    {
        FTS_ERROR( "[UPGRADE]: ecc error! FW=%02x upgrade_ecc=%02x!!", reg_val[0], upgrade_ecc);
        return -EIO;
    }

    FTS_DEBUG( "[UPGRADE]: ecc success : FW=%02x upgrade_ecc=%02x!!", reg_val[0], upgrade_ecc);

    upgrade_ecc = 0;

    FTS_FUNC_EXIT();

    return i_ret;
}

/************************************************************************
* Name: fts_eraseflash
* Brief: 0
* Input: 0
* Output: 0
* Return: 0
***********************************************************************/
int fts_eraseflash(struct i2c_client * client)
{
    u32 i = 0;
    u8 auc_i2c_write_buf[10];
    u8 reg_val[4] = {0};

    FTS_FUNC_ENTER();

    FTS_DEBUG("[UPGRADE]: erase app now!!");

    /*send to erase flash*/
    auc_i2c_write_buf[0] = 0x61;
    fts_i2c_write(client, auc_i2c_write_buf, 1);
    msleep(1350);

    for (i = 0; i < 15; i++)
    {
        /*get the erase app status, if get 0xF0AA£¬erase flash success*/
        auc_i2c_write_buf[0] = 0x6a;
        reg_val[0] = reg_val[1] = 0x00;
        fts_i2c_read(client, auc_i2c_write_buf, 1, reg_val, 2);

        if (0xF0==reg_val[0] && 0xAA==reg_val[1]) /*erase flash success*/
        {
            break;
        }
        msleep(50);
    }

    if ((0xF0!=reg_val[0] || 0xAA!=reg_val[1]) && (i >= 15)) /*erase flash fail*/
    {
        FTS_ERROR("[UPGRADE]: erase app error.reset tp and reload FW!!");
        return -EIO;
    }
    FTS_DEBUG("[UPGRADE]: erase app ok!!");

    FTS_FUNC_EXIT();

    return 0;
}

/************************************************************************
* Name: fts_write_pramboot
* Brief: 0
* Input: 0
* Output: 0
* Return: 0
***********************************************************************/
int fts_write_pramboot(struct i2c_client * client, u32 length, u8* readbuf)
{
    u32 i = 0;
    u32 j;
    u32 temp;
    u32 packet_number;
    u8 packet_buf[FTS_PACKET_LENGTH + 6];

    FTS_FUNC_ENTER();

    upgrade_ecc = 0;
    FTS_INFO("[UPGRADE]: write pramboot to pram!!");

    temp = 0;
    packet_number = (length) / FTS_PACKET_LENGTH;
    if ((length) % FTS_PACKET_LENGTH > 0)
    {
        packet_number++;
    }
    packet_buf[0] = 0xae;
    packet_buf[1] = 0x00;

    for (j = 0; j < packet_number; j++)
    {
        temp = j * FTS_PACKET_LENGTH;
        packet_buf[2] = (u8) (temp >> 8);
        packet_buf[3] = (u8) temp;
        if (j < (packet_number-1))
        {
            temp = FTS_PACKET_LENGTH;
        }
        else
        {
            temp = (length) % FTS_PACKET_LENGTH;
        }
        packet_buf[4] = (u8) (temp >> 8);
        packet_buf[5] = (u8) temp;

        for (i = 0; i < temp; i++)
        {
            packet_buf[6 + i] = readbuf[j * FTS_PACKET_LENGTH + i];
            upgrade_ecc ^= packet_buf[6 + i];
        }
        fts_i2c_write(client, packet_buf, temp + 6);
    }

    FTS_FUNC_EXIT();

    return 0;
}

/************************************************************************
* Name: fts_writeapp
* Brief: 0
* Input: 0
* Output: 0
* Return: 0
***********************************************************************/
int fts_writeapp(struct i2c_client * client, u32 length, u8* readbuf)
{
    u32 j;
    u32 i = 0;
    u32 packet_number;
    u32 temp;
    u32 writelenght;
    u8 packet_buf[FTS_PACKET_LENGTH + 6];
    u8 auc_i2c_write_buf[10];
    u8 reg_val[4] = {0};

    FTS_FUNC_ENTER();

    FTS_INFO( "[UPGRADE]: write app to flash!!");

    upgrade_ecc = 0;

    packet_number = (length) / FTS_PACKET_LENGTH;
    if (((length) % FTS_PACKET_LENGTH) > 0)
    {
        packet_number++;
    }

    packet_buf[0] = 0xbf;

    for (j = 0; j < packet_number; j++)
    {
        temp = 0x1000+j * FTS_PACKET_LENGTH;

        if (j<(packet_number-1))
        {
            writelenght = FTS_PACKET_LENGTH;
        }
        else
        {
            writelenght = ((length) % FTS_PACKET_LENGTH);
        }
        packet_buf[1] = (u8) (temp >> 16);
        packet_buf[2] = (u8) (temp >> 8);
        packet_buf[3] = (u8) temp;
        packet_buf[4] = (u8) (writelenght >> 8);
        packet_buf[5] = (u8) writelenght;

        for (i = 0; i < writelenght; i++)
        {
            packet_buf[6 + i] = readbuf[(temp - 0x1000+i)];
            upgrade_ecc ^= packet_buf[6 + i];
        }

        fts_i2c_write(client, packet_buf, (writelenght + 6));

        for (i = 0; i < 30; i++)
        {
            /*read status and check if the app writting is finished*/
            auc_i2c_write_buf[0] = 0x6a;
            reg_val[0] = reg_val[1] = 0x00;
            fts_i2c_read(client, auc_i2c_write_buf, 1, reg_val, 2);

            if ((j + 0x20+0x1000) == (((reg_val[0]) << 8) | reg_val[1]))
            {
                break;
            }
            msleep(1);
        }
    }
    msleep(50);

    FTS_FUNC_EXIT();

    return 0;
}
#endif

