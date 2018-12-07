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
* File Name: focaltech_upgrade_test.c
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
#include "focaltech_core.h"
#include "focaltech_flash.h"
#include <linux/timer.h>

/*******************************************************************************
* Static variables
*******************************************************************************/

/*******************************************************************************
* Global variable or extern global variabls/functions
*******************************************************************************/
//extern struct wake_lock ps_lock;
extern u8 upgrade_ecc;

/*******************************************************************************
* Static function prototypes
*******************************************************************************/
#if (FTS_UPGRADE_PINGPONG_TEST)
/************************************************************************
* Name: fts_ctpm_auto_upgrade
* Brief:  auto upgrade
* Input: i2c info
* Output: no
* Return: 0
***********************************************************************/
static int fts_ctpm_auto_upgrade_pingpong(struct i2c_client *client)
{
    u8 uc_tp_fm_ver;
    int i_ret = 0;
    bool bUpgradeFlag = false;
    u8 uc_upgrade_times = 0;

    FTS_FUNC_ENTER();

    /* check need upgrade or not */
    bUpgradeFlag = fts_check_need_upgrade(client);
    FTS_DEBUG("[UPGRADE]: bUpgradeFlag = 0x%x", bUpgradeFlag);

    /* pingpang test need upgrade */
#if (FTS_UPGRADE_PINGPONG_TEST)
#if FTS_UPGRADE_WITH_APP_BIN_EN
    if (no_appbin)
    {
        bUpgradeFlag = false;
    }
    else
    {
        bUpgradeFlag = true;
    }
#else
    bUpgradeFlag = true;
#endif
#endif

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


/************************************************************************
* Name: fts_ctpm_auto_upgrade_test
* Brief:  auto upgrade
* Input: i2c info
* Output: no
* Return: 0
***********************************************************************/
int fts_ctpm_auto_upgrade_test(struct i2c_client *client)
{
    int i_ret = 0;
    static int uc_ErrorTimes = 0;
    static int uc_UpgradeTimes = 0;
#if FTS_GET_UPGRADE_TIME
    struct timeval tpstart,tpend;
    int timeuse;
#endif
    //wake_lock(&ps_lock);

    do
    {
        uc_UpgradeTimes++;
        FTS_DEBUG( "[UPGRADE]:##############################################################################");
        FTS_DEBUG( "[UPGRADE]: start to upgrade %d times !!", uc_UpgradeTimes);
        FTS_DEBUG( "[UPGRADE]:##############################################################################");

#if FTS_GET_UPGRADE_TIME
        do_gettimeofday(&tpstart);
#endif
        i_ret = fts_ctpm_auto_upgrade_pingpong(client);
        if (i_ret == 0)
        {
#if FTS_GET_UPGRADE_TIME
            do_gettimeofday(&tpend);
            timeuse=1000000*(tpend.tv_sec-tpstart.tv_sec)+ tpend.tv_usec-tpstart.tv_usec;
            timeuse/=1000000;
            FTS_DEBUG( "[UPGRADE]: upgrade success : Use time: %d Seconds!!", timeuse);
#endif
        }
        else
        {
            uc_ErrorTimes++;
        }

#if (FTS_UPGRADE_PINGPONG_TEST)
        FTS_DEBUG( "[UPGRADE]:##############################################################################");
        FTS_DEBUG( "[UPGRADE]: upgrade %d times, error %d times!!", uc_UpgradeTimes, uc_ErrorTimes);
        FTS_DEBUG( "[UPGRADE]:##############################################################################");
#endif
    }
#if (FTS_UPGRADE_PINGPONG_TEST)
    while (uc_UpgradeTimes < (FTS_UPGRADE_TEST_NUMBER));
#endif
    //wake_unlock(&ps_lock);

    return 0;
}
#endif

