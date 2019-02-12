/*
 * Reference Driver for NextInput Sensor
 *
 * The GPL Deliverables are provided to Licensee under the terms
 * of the GNU General Public License version 2 (the "GPL") and
 * any use of such GPL Deliverables shall comply with the terms
 * and conditions of the GPL. A copy of the GPL is available
 * in the license txt file accompanying the Deliverables and
 * at http://www.gnu.org/licenses/gpl.txt
 *
 * Copyright (C) NextInput, Inc.
 * All rights reserved
 *
 * 1. Redistribution in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 * 2. Neither the name of NextInput nor the names of the contributors
 *    may be used to endorse or promote products derived from
 *    the software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES INCLUDING BUT
 * NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE. 
 */

/* NI Application Firmware for Atmel SAMD10 */
#ifdef NI_BOOTLOADER
#include "NI_ATSAMD10D14AM_NIBL_00_04_00.h"
#else
#include "NI_ATSAMD10D14AU_ATBL_00_04_00.h"
#endif

// MCU CONSTANT VALUES
#define BOOTLOADER_DELAY                        10      // DELAY IN BOOTLOADER MODE

// NI BOOTLOADER COMMAND SET
#define BL_CMD_READ_STATUS                      0x00    // NI BL always retuns 0b1XXXXXXX
#define BL_CMD_WRITE_PAGE                       0x01
#define BL_CMD_CRC_VERIFY                       0x02
#define BL_CMD_RESET                            0x03
#define BOOTLOADER_PAGE_SIZE                    256
#define TOTAL_APPLICATION_PAGES                 128
#define BOOTLOADER_TRY_MAX                      10

/* ni_force_fw_show
 *
 * Show the firmware and driver information
 * ADB Console Usage: cat version
 */
static ssize_t ni_force_version_show(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct ni_force_ts_data *ts = dev_get_drvdata(dev);
    int ret = 0;

    ret = sprintf(buf, "====== Firmware Info ======\n");
    ret += sprintf(buf + ret, "FORCE FW = %d.%d.%d\n",
                   ts->fw_info.fw_ver, ts->fw_info.fw_rev, ts->fw_info.fw_build);
    ret +=
        sprintf(buf + ret, "NI CORE = %d.%d.%d\n", ts->fw_info.ni_core_ver,
                ts->fw_info.ni_core_rev, ts->fw_info.ni_core_build);
    ret += sprintf(buf + ret, "Build Date: %s\n",
                   ts->fw_info.buildDate);
    ret += sprintf(buf + ret, "Build Time: %s\n",
                   ts->fw_info.buildTime);
    ret += sprintf(buf + ret, "====== Driver Info ======\n");
    ret += sprintf(buf + ret, "%d.%d.%d\n",
                   DRIVER_VERSION, DRIVER_REVISION, DRIVER_BUILD);
    ret += sprintf(buf + ret, "Build Date: %s %s\n",
                   OEM_DATE, OEM_TIME);

    return ret;
}

/* ni_force_fw_store
 *
 * Push firmware from console
 * ADB Console Usage: cat firmware
 * Process:
 *  * Rename xx-xx.nif firmware to xx-xx.bin
 *  * ADB Shell: push xx-xx.bin /vendor/firmware
 *  * ADB Shell: cd /sys/devices/f9968000.i2c/i2c-12/12-0034
 *  * ADB Shell: echo 1 xx-xx.bin > firmware
 * OPTIONAL: To install default firmware:
 *  * ADB Shell: echo 1 > firmware
 */
static ssize_t ni_force_fw_store(struct device *dev,
                                 struct device_attribute *attr,
                                 const char *buf, size_t count)
{
    int value = 0;
    int repeat = 0;
    int ret = 0;
    char path[256] = { 0 };
    const struct firmware *fw_entry;

    struct ni_force_ts_data *ts = dev_get_drvdata(dev);

    sscanf(buf, "%d %s", &value, path);

    LOGI("Firmware image path: %s\n", path[0] != 0 ? path : "Internal");

    if (value)
    {
        /* sync for n-th repeat test */
        while (ts->fw_info.fw_upgrade.is_downloading) ;

        msleep(BOOTING_DELAY * 2);
        LOGI("Firmware image upgrade: No.%d", repeat + 1);
        if (path[0] != 0)
        {
            ret = request_firmware(&fw_entry, path, dev);
            if (ret)
            {
                LOGI("request firmware file failed%d\n", ret);
                ts->fw_info.fw_upgrade.fwdata_ptr = NULL;
                ts->fw_info.fw_upgrade.fw_size = 0;

            }
            else
            {
                LOGI("Request firmware file ok size:%d\n", (int)(fw_entry->size));
                if (fw_entry->size <= 16384)
                {
                    ts->fw_info.fw_upgrade.fwdata_ptr = (u8 *) fw_entry->data;
                    ts->fw_info.fw_upgrade.fw_size = (size_t) fw_entry->size;
                }
                else
                {
                    ts->fw_info.fw_upgrade.fwdata_ptr = NULL;
                    ts->fw_info.fw_upgrade.fw_size = 0;
                }
            }
        }
        else
        {
            ts->fw_info.fw_upgrade.fwdata_ptr = NULL;
        }
        /* for n-th repeat test - because ts->fw_info.fw_upgrade is setted 0 after FW upgrade */
        memcpy(ts->fw_info.fw_upgrade.fw_path,
               path, sizeof(ts->fw_info.fw_upgrade.fw_path) - 1);

        /* set downloading flag for sync for n-th test */
        ts->fw_info.fw_upgrade.is_downloading = UNDER_DOWNLOADING;
        ts->fw_info.fw_upgrade.fw_force_upgrade = 1;
        queue_work(ni_force_wq, &ts->work_fw_upgrade);

        /* sync for fw_upgrade test */
        while (ts->fw_info.fw_upgrade.is_downloading) ;
    }

    return count;
}

#ifdef HOST_DEBUGGER
/* ni_force_dump_trace
*
* Dump trace data from MCU in app friendly format
* ADB Console Usage: cat dump_trace
*
*/
static ssize_t ni_force_dump_trace(struct device *dev,
                                   struct device_attribute *attr,
                                   char *buf)
{
    u8 databuf[32];
    int     ret = 0;

    struct ni_force_ts_data *ts = dev_get_drvdata(dev);

    if (ts->fw_info.fw_upgrade.bootloadermode == true)
        return 0;
    if (unlikely(ni_force_i2c_read(ts->client, NI_CMD_DEBUG_DUMP_TRACE, sizeof(databuf), databuf) < 0)) {
        ret = sprintf(buf, "%s", "i2c_read error\n");
    }
    else {
        u8  i;
        u16 sample;
        u32 counter;

        for (i = 0; i < 4; i++) {
            sample = (databuf[(i * 2) + 0] << 0) +
                     (databuf[(i * 2) + 1] << 8);
            ret += sprintf(buf + ret, "%04x ", sample);
        }

        counter = (databuf[8]  <<  0) +
                  (databuf[9]  <<  8) +
                  (databuf[10] << 16) +
                  (databuf[11] << 24);
        ret += sprintf(buf + ret, "%08x ", counter);

        ret += sprintf(buf + ret, "%s", "\n");
    }

    return ret;
}
#endif

#ifndef NI_BOOTLOADER
//-----------------------------------------------------------------------------
static int ni_force_read_stream(struct i2c_client *client, int len,
                                u8 * buf)
{
#ifdef DEVICE_INTERRUPT
    struct ni_force_ts_data *ts =
            (struct ni_force_ts_data *)get_touch_handle(client);
#endif

    struct i2c_msg msgs[] = {
        {
            .addr = client->addr,
            .flags = I2C_M_RD,
            .len = len,
            .buf = buf,
        },
    };

#ifdef DEVICE_INTERRUPT
    ts->enableInterrupt = 0;
#endif

    if (i2c_transfer(client->adapter, msgs, 1) < 0)
    {
        if (printk_ratelimit())
            LOGE("transfer error\n");
        return -EIO;
    }

#ifdef DEVICE_INTERRUPT
    ts->enableInterrupt = 1;
#endif

    return 0;
}

//-----------------------------------------------------------------------------
static int ni_force_write_stream(struct i2c_client *client, int len,
                                 u8 * buf)
{
#ifdef DEVICE_INTERRUPT
    struct ni_force_ts_data *ts =
            (struct ni_force_ts_data *)get_touch_handle(client);
#endif

    struct i2c_msg msgs[] = {
        {
            .addr = client->addr,
            .flags = 0,
            .len = len,
            .buf = buf,
        },
    };

#ifdef DEVICE_INTERRUPT
    ts->enableInterrupt = 0;
#endif

    if (i2c_transfer(client->adapter, msgs, 1) < 0)
    {
        if (printk_ratelimit())
            LOGE("transfer error\n");
        return -EIO;
    }

#ifdef DEVICE_INTERRUPT
    ts->enableInterrupt = 1;
#endif

    return 0;
}

//-----------------------------------------------------------------------------
#endif

#ifndef NI_BOOTLOADER
/*- Definitions -------------------------------------------------------------*/
#define ATMEL_BL_ADDRESS  0x3E  // possible addresses are: 0x2C, 0x3C, 0x2E, 0x3E
#define ATMEL_MAGIC_WORD  0x78656c41
#define ATMEL_APP_OFFSET  0x400
#define DATA_SIZE         64
#define DATA_SIZE_WORDS   (int)(DATA_SIZE / sizeof(u32))

enum
{
    ATMEL_BL_CMD_UNLOCK = 0xa0,
    ATMEL_BL_CMD_DATA   = 0xa1,
    ATMEL_BL_CMD_RESET  = 0xa2,
};

enum
{
    ATMEL_BL_STATUS_READY      = (1 << 0),
    ATMEL_BL_STATUS_ERROR      = (1 << 1),
    ATMEL_BL_STATUS_FLASH_BUSY = (1 << 2),
    ATMEL_BL_STATUS_CRC_OK     = (1 << 3),
};

/*- Implementations ---------------------------------------------------------*/

//-----------------------------------------------------------------------------
static bool boot_cmd(struct i2c_client *client, int cmd, u32 data[DATA_SIZE_WORDS])
{
    u8 status;
    u8 buf[1 + DATA_SIZE];
    int i;
  
    buf[0] = cmd;
    memcpy(&buf[1], (u8 *)data, DATA_SIZE);
  
    for (i = 0; i < 1000; i++)
    {
        if (ni_force_read_stream(client, 1, &status) < 0)
          return false;
        
        if (status & ATMEL_BL_STATUS_ERROR)
          return false;
        
        if (0 == (status & ATMEL_BL_STATUS_READY))
          continue;
        
        if (ni_force_write_stream(client, sizeof(buf), buf) >= 0)
          return true;
    };
  
    return false;
}

//-----------------------------------------------------------------------------
static bool boot_upload(struct i2c_client *client, int offset, u8 *data, int size, u32 *crc)
{
  u32 buf[DATA_SIZE_WORDS];
  u8 status;
  int offs = 0;
  int i;

#if 1
    // HACK: Atmel BL requires 'size' to be multiple of DATA_SIZE, but
    // for now do a temporary (very dirty) workaround
    if (size % DATA_SIZE)
    {
      size = ((size / DATA_SIZE) + 1) * DATA_SIZE;
    }
#endif

    buf[0] = ATMEL_MAGIC_WORD;
    buf[1] = offset;
    buf[2] = size;
    buf[3] = (NULL == crc) ? 0 : *crc;
  
    LOGI("Unlock BL to write %d bytes to offset 0x%x\n", size, offset);
    if (!boot_cmd(client, ATMEL_BL_CMD_UNLOCK, buf))
      return false;
  
    while (size)
    {
        memcpy((u8 *)buf, &data[offs], DATA_SIZE);
       
        LOGI("Write page %d\n", offs / DATA_SIZE);
        if (!boot_cmd(client, ATMEL_BL_CMD_DATA, buf))
          return false;
       
        size -= DATA_SIZE;
        offs += DATA_SIZE;
    }
  
    LOGI("Check BL status\n");
    for (i = 0; i < 1000; i++)
    {
        ni_force_read_stream(client, 1, &status);
       
        if (status & ATMEL_BL_STATUS_FLASH_BUSY)
          continue;
       
        if (status & ATMEL_BL_STATUS_ERROR)
          return false;
       
        break;
    }
  
    LOGI("BL success\n");
    if (NULL != crc)
        *crc = (status & ATMEL_BL_STATUS_CRC_OK) ? 1 : 0;
  
    return true;
}

//-----------------------------------------------------------------------------
static bool boot_reset(struct i2c_client *client, u32 ram[4])
{
    u32 buf[DATA_SIZE_WORDS];
    int i;
  
    for (i = 0; i < 4; i++)
        buf[i] = (NULL == ram) ? 0 : ram[i];
  
    return boot_cmd(client, ATMEL_BL_CMD_RESET, buf);
}

//-----------------------------------------------------------------------------
#endif

static int ni_force_ts_fw_upgrade(struct i2c_client *client,
                                  struct ni_force_ts_fw_info *fw_info)
{
    struct ni_force_ts_data *ts =
        (struct ni_force_ts_data *)get_touch_handle(client);
    int ret = 0;
    u8 tries = 0;               /* Byte to hold number of Page Write tries */
    u8 status;                  /* Byte to hold Bootloader status */

#ifdef NI_BOOTLOADER
    int i = 0;
    int timeout = 0;
    int blocks = 0;
    int left_packet_size = 0;
    char i2c_buffer[258];
    char *write_firmware_data_buffer;
    bool bootloader_mode = false;

    if (ts->fw_info.fw_upgrade.fwdata_ptr != NULL)
    {
        LOGI("Upgrade external firmware from ADB file size:%d\n",
             (int)(ts->fw_info.fw_upgrade.fw_size));
        write_firmware_data_buffer = (char *)ts->fw_info.fw_upgrade.fwdata_ptr;
        blocks = ts->fw_info.fw_upgrade.fw_size >> 8;   /* BOOTLOADER_PAGE_SIZE=256; */
        left_packet_size = ts->fw_info.fw_upgrade.fw_size % 256;
        LOGI("Write firmware blocks:%d left_size:%d\n", blocks,
             left_packet_size);
    }
    else
    {
        LOGI("Upgrade internal firmware\n");
        write_firmware_data_buffer = NI_SAMD10_FIRMWARE;
        blocks = 59;
        left_packet_size = 0;
    }
    ts->is_probed = 0;

    do
    {
        ret =
            ni_force_i2c_write_byte(ts->client, NI_CMD_ENTER_BOOTLOADER, 1);
        msleep(BOOTING_DELAY);

        /* TODO: Verify we entered boot mode */
        if (!ret)
        {
            LOGI("We are in boot mode!\n");
            break;
        }

        tries++;
    } while ((!bootloader_mode) && (tries < BOOTLOADER_TRY_MAX));

    if (tries >= BOOTLOADER_TRY_MAX)
    {
        LOGI("ni_loadfirmware enter bootloader mode fail\n");
        goto error_case;
    }

    /* Send pages to Bootloader */
    for (i = 0; i < blocks; i++)
    {
        /* NIF_read_page(page_buf, i);  */ /* Function that puts 256 byes of NIF data given a Page offset */
        LOGI("Write page %d\n", i);
        i2c_buffer[0] = i;         /* The page address (0 to 58) */

        memcpy(&i2c_buffer[1],
               write_firmware_data_buffer + i * BOOTLOADER_PAGE_SIZE,
               BOOTLOADER_PAGE_SIZE);

        ret =
            ni_force_i2c_write(ts->client, BL_CMD_WRITE_PAGE,
                               BOOTLOADER_PAGE_SIZE + 1, i2c_buffer);

        do
        {
            ni_force_i2c_read(ts->client, BL_CMD_READ_STATUS, sizeof(status), &status);     /* Read status from Bootloader */
            msleep(BOOTLOADER_DELAY);
            timeout++;
        }
        while ((status & 0x02) && (timeout < 100));     /* While Bootloader is busy */

        if (timeout >= 100)
        {
            LOGI("ni_write firmware page:%d error\n", i);
        }
        else
        {
            timeout = 0;
        }
    }
    if (left_packet_size)
    {
        LOGI("The last page %d\n", i);
        i2c_buffer[0] = i;         /* The page address (0 to 58) */

        memcpy(&i2c_buffer[1],
               write_firmware_data_buffer + i * BOOTLOADER_PAGE_SIZE,
               left_packet_size);
        ret =
            ni_force_i2c_write(ts->client, BL_CMD_WRITE_PAGE,
                               left_packet_size + 1, i2c_buffer);
        do
        {
            ni_force_i2c_read(ts->client, BL_CMD_READ_STATUS, sizeof(status), &status);     /* Read status from Bootloader */
            msleep(BOOTLOADER_DELAY);
            timeout++;
        }
        while ((status & 0x02) && (timeout < 100));     /* While Bootloader is busy */
        if (timeout >= 100)
        {
            LOGI("ni_write firmware page:%d error\n", i);
        }
        else
        {
            timeout = 0;
        }
    }
    /* Now all pages have been written to Bootloader */
    ret = ni_force_i2c_write_byte(ts->client, BL_CMD_RESET, 1);
#else
    int fw_size;
    char *write_firmware_data_buffer;
    bool bootloader_mode = false;
    u32 fw_crc;
    unsigned short save_addr = client->addr;

    if (ts->fw_info.fw_upgrade.fwdata_ptr != NULL)
    {
        LOGI("Upgrade external firmware from ADB file size:%ld\n",
             ts->fw_info.fw_upgrade.fw_size);
        write_firmware_data_buffer = (char *)ts->fw_info.fw_upgrade.fwdata_ptr;
        fw_size = ts->fw_info.fw_upgrade.fw_size;
    }
    else
    {
        LOGI("Upgrade internal firmware\n");
        write_firmware_data_buffer = NI_SAMD10_FIRMWARE;
        fw_size = sizeof(NI_SAMD10_FIRMWARE);
    }
    ts->is_probed = 0;

    do
    {
        client->addr = save_addr;
        ret =
            ni_force_i2c_write_byte(ts->client, NI_CMD_ENTER_BOOTLOADER, 1);
        msleep(BOOTING_DELAY);

        client->addr = ATMEL_BL_ADDRESS;
        ret =
            ni_force_read_stream(ts->client, 1, &status);
        if (ret < 0)
        {
            LOGI("Failed to get Atmel BL status\n");
            goto error_io;
        }

        if (status & ATMEL_BL_STATUS_READY)
        {
            bootloader_mode = true;
            LOGI("We are in boot mode!\n");
        }

 error_io:
        tries++;
    } while ((!bootloader_mode) && (tries < BOOTLOADER_TRY_MAX));

    if (tries >= BOOTLOADER_TRY_MAX)
    {
        LOGI("ni_loadfirmware enter bootloader mode fail\n");
        goto restore_addr;
    }
    /* Send pages to Bootloader */
    fw_crc = *((u32 *)(write_firmware_data_buffer + fw_size - sizeof(fw_crc)));
    if (!boot_upload(ts->client,
                     ATMEL_APP_OFFSET,
                     write_firmware_data_buffer,
                     fw_size,
                     &fw_crc))
    {
        LOGI("ni_write firmware error\n");
        ret = -EIO;
        goto restore_addr;
    }

    /* Now all pages have been written to Bootloader */
    if (!boot_reset(ts->client,
                    NULL))
    {
        LOGI("ni_reset firmware error\n");
        ret = -EIO;
    }

 restore_addr:
    client->addr = save_addr;
#endif

    msleep(BOOTING_DELAY);

#ifdef NI_BOOTLOADER
error_case:
#endif
    ts->fw_info.fw_upgrade.is_downloading = DOWNLOAD_COMPLETE;
    ts->fw_info.fw_upgrade.bootloadermode = false;

    /* update IC info, confirm version etc */
    if (ret >= 0)
        ni_force_get_ic_info(ts);

    return ret;
}

/* ni_force_fw_upgrade_func
 *
 * Upgrades the firmware of MCU IC
 */
static void ni_force_fw_upgrade_func(struct work_struct *work_fw_upgrade)
{
    struct ni_force_ts_data *ts = container_of(work_fw_upgrade,
                                               struct ni_force_ts_data,
                                               work_fw_upgrade);
    u8 saved_state;
    int ver, img_ver;

    LOGI("%s\n", __func__);

    ver = 0;

    img_ver = 0;

    if (!ts->fw_info.fw_upgrade.fw_force_upgrade && ver >= img_ver)
    {
        /* No Upgrade */
        LOGI("FW-upgrade is not executed\n");
        goto out;
    }

    ts->fw_info.fw_upgrade.is_downloading = UNDER_DOWNLOADING;
    ts->fw_info.fw_upgrade.bootloadermode = true;
    msleep(BOOTING_DELAY);      /* some delay to let other I2C read cmd finish in work_pre() */

    saved_state = ts->curr_pwr_state;

    if (ts->curr_pwr_state == POWER_ON)
    {
        disable_irq(ts->client->irq);
    }
    else
    {
        OEM_FW_UPGRADE_POWER_ON
    }

    LOGI("F/W upgrade - Start\n");

    if (ni_force_ts_fw_upgrade(ts->client, &ts->fw_info) < 0)
    {
        LOGE("Firmware upgrade was failed\n");
        safety_reset(ts);
    }

    if (saved_state == POWER_ON)
    {
        ni_force_ic_init(ts);
        enable_irq(ts->client->irq);
    }
    else
    {
        OEM_FW_UPGRADE_POWER_OFF
    }

    LOGI("F/W upgrade - Finish\n");

out:

    memset(&ts->fw_info.fw_upgrade, 0, sizeof(ts->fw_info.fw_upgrade));

    return;
}

