/************************************************************************
* Copyright (C) 2012-2016, Focaltech Systems (R)£¬All Rights Reserved.
*
* File Name: focaltech_flash.h
*
*    Author: fupeipei
*
*   Created: 2016-08-07
*
*  Abstract:
*
************************************************************************/
#ifndef __LINUX_FOCALTECH_FLASH_H__
#define __LINUX_FOCALTECH_FLASH_H__

/*******************************************************************************
* 1.Included header files
*******************************************************************************/

/*******************************************************************************
* Private constant and macro definitions using #define
*******************************************************************************/
#define FTS_REG_FW_MAJ_VER                           0xB1
#define FTS_REG_FW_MIN_VER                           0xB2
#define FTS_REG_FW_SUB_MIN_VER                       0xB3
#define FTS_FW_MIN_SIZE                              8
#define FTS_FW_MAX_SIZE                              (54 * 1024)
/* Firmware file is not supporting minor and sub minor so use 0 */
#define FTS_FW_FILE_MAJ_VER(x)                       ((x)->data[(x)->size - 2])
#define FTS_FW_FILE_MIN_VER(x)                       0
#define FTS_FW_FILE_SUB_MIN_VER(x)                   0
#define FTS_FW_FILE_VENDOR_ID(x)                     ((x)->data[(x)->size - 1])
#define FTS_FW_FILE_MAJ_VER_FT6X36(x)                ((x)->data[0x10a])
#define FTS_FW_FILE_VENDOR_ID_FT6X36(x)              ((x)->data[0x108])
#define FTS_MAX_TRIES                                5
#define FTS_RETRY_DLY                                20
#define FTS_MAX_WR_BUF                               10
#define FTS_MAX_RD_BUF                               2
#define FTS_FW_PKT_META_LEN                          6
#define FTS_FW_PKT_DLY_MS                            20
#define FTS_FW_LAST_PKT                              0x6ffa
#define FTS_EARSE_DLY_MS                             100
#define FTS_55_AA_DLY_NS                             5000
#define FTS_CAL_START                                0x04
#define FTS_CAL_FIN                                  0x00
#define FTS_CAL_STORE                                0x05
#define FTS_CAL_RETRY                                100
#define FTS_REG_CAL                                  0x00
#define FTS_CAL_MASK                                 0x70
#define FTS_BLOADER_SIZE_OFF                         12
#define FTS_BLOADER_NEW_SIZE                         30
#define FTS_DATA_LEN_OFF_OLD_FW                      8
#define FTS_DATA_LEN_OFF_NEW_FW                      14
#define FTS_FINISHING_PKT_LEN_OLD_FW                 6
#define FTS_FINISHING_PKT_LEN_NEW_FW                 12
#define FTS_MAGIC_BLOADER_Z7                         0x7bfa
#define FTS_MAGIC_BLOADER_LZ4                        0x6ffa
#define FTS_MAGIC_BLOADER_GZF_30                     0x7ff4
#define FTS_MAGIC_BLOADER_GZF                        0x7bf4
#define FTS_REG_ECC                                  0xCC
#define FTS_RST_CMD_REG2                             0xBC
#define FTS_READ_ID_REG                              0x90
#define FTS_ERASE_APP_REG                            0x61
#define FTS_ERASE_PARAMS_CMD                         0x63
#define FTS_FW_WRITE_CMD                             0xBF
#define FTS_REG_RESET_FW                             0x07
#define FTS_RST_CMD_REG1                             0xFC
#define FTS_FACTORYMODE_VALUE                        0x40
#define FTS_WORKMODE_VALUE                           0x00
#define FTS_APP_INFO_ADDR                            0xd7f8
#define LEN_FLASH_ECC_MAX                            0xFFFE

#define BL_VERSION_LZ4                               0
#define BL_VERSION_Z7                                1
#define BL_VERSION_GZF                               2

#define FTS_PACKET_LENGTH                            128
#define FTS_SETTING_BUF_LEN                          128

#define FTS_UPGRADE_LOOP                             30
#define FTS_MAX_POINTS_2                             2
#define FTS_MAX_POINTS_5                             5
#define FTS_MAX_POINTS_10                            10
#define AUTO_CLB_NEED                                1
#define AUTO_CLB_NONEED                              0
#define FTS_UPGRADE_AA                               0xAA
#define FTS_UPGRADE_55                               0x55
#define FTXXXX_INI_FILEPATH_CONFIG                   "/sdcard/"

#define FTS_RUN_IN_APP                               0x01
#define FTS_RUN_IN_ROM                               0x02
#define FTS_RUN_IN_PRAM                              0x03

#define FTS_UPGRADE_PINGPONG_TEST                    0
/*
 * auto upgrade with app.bin in sdcard
 * default: disable
 */
#define FTS_UPGRADE_WITH_APP_BIN_EN                  0
/*
 * app.bin file name for upgrade with app bin file
 * this file must put in sdcard
 * default: "app.bin"
 */
#define FTS_UPGRADE_FW_APP_BIN                       "app.bin"

/*******************************************************************************
* Private enumerations, structures and unions using typedef
*******************************************************************************/

/*******************************************************************************
* Static variables
*******************************************************************************/

/*******************************************************************************
* Global variable or extern global variabls/functions
*******************************************************************************/
extern unsigned char CTPM_FW[];
extern unsigned char CTPM_FW_SHARP[];
extern unsigned char aucFW_PRAM_BOOT[];
#if FTS_UPGRADE_WITH_APP_BIN_EN
extern bool no_appbin;
#endif

extern void fts_get_upgrade_array(void);
extern int fts_ctpm_auto_upgrade(struct i2c_client *client);
extern int fts_fw_upgrade(struct device *dev, bool force);
extern int fts_ctpm_auto_clb(struct i2c_client *client);
extern int fts_ctpm_fw_upgrade_with_app_file(struct i2c_client *client, char *firmware_name);
extern int fts_ctpm_fw_upgrade_with_i_file(struct i2c_client *client);
extern int fts_ctpm_get_i_file_ver(void);

/*******************************************************************************
* Static function prototypes
*******************************************************************************/
u32 fts_getsize(bool isapp);
int fts_GetFirmwareSize(char *firmware_name);
int fts_i2c_hid2std(struct i2c_client * client);
bool fts_check_need_upgrade(struct i2c_client *client);
int fts_ReadFirmware(char *firmware_name,unsigned char *firmware_buf);
void fts_rom_or_pram_reset(struct i2c_client * client, bool needupgrade);
unsigned char fts_flash_get_pram_or_rom_id(struct i2c_client *client);

#endif
