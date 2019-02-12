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

#include <linux/module.h>
#include <linux/delay.h>
#include <linux/i2c.h>
#include <asm/uaccess.h>
#include <linux/input.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/platform_device.h>
#include <linux/time.h>
#include <linux/timer.h>
#include <linux/firmware.h>
#include <linux/timer.h>
#include <linux/gpio.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/workqueue.h>
#include <linux/of_gpio.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/regulator/consumer.h>
#include <linux/ctype.h>
#include "oem.h"
#include "ni_force.h"

#ifdef FORCE_BUTTON
static int suspend_flag = 0;
static int irq_count    = 0;
#endif

static int num_clients  = 0;
static int adcraw_mode  = 0;
static struct workqueue_struct *ni_force_wq;    // Primary Linux work queue

#include "oem.c"
#ifdef NI_MCU
#include "ni_mcu.c"
#endif

// DRIVER SYS FUNCTIONS
// System functions accessible via ADB Shell or similar Linux shell

static ssize_t ni_force_force_show(struct device *dev,
                                   struct device_attribute *attr,
                                   char *buf);
static ssize_t ni_force_force_mode_show(struct device *dev,
                                        struct device_attribute *attr,
                                        char *buf);
static ssize_t ni_force_force_mode_store(struct device *dev,
                                         struct device_attribute *attr,
                                         const char *buf, size_t count);
static ssize_t ni_force_baseline_show(struct device *dev,
                                      struct device_attribute *attr,
                                      char *buf);

#ifdef DEVICE_INTERRUPT
static ssize_t ni_force_interrupt_store(struct device *dev,
                                        struct device_attribute *attr,
                                        const char *buf, size_t count);
#endif

static ssize_t ni_force_threshold_store(struct device *dev,
                                        struct device_attribute *attr,
                                        const char *buf, size_t count);
static ssize_t ni_force_register_show(struct device *dev,
                                      struct device_attribute *attr,
                                      char *buf);
static ssize_t ni_force_register_store(struct device *dev,
                                       struct device_attribute *attr,
                                       const char *buf, size_t count);

// System Function Definitions:
static struct device_attribute ni_force_device_attrs[] = {

#ifdef NI_MCU
  __ATTR (firmware,      S_IRUGO | NI_WRITE_PERMISSIONS, ni_force_version_show,    ni_force_fw_store),
#endif

  __ATTR (force,         S_IRUGO,                        ni_force_force_show,      NULL),
  __ATTR (force_mode,    S_IRUGO | NI_WRITE_PERMISSIONS, ni_force_force_mode_show, ni_force_force_mode_store),
  __ATTR (baseline,      S_IRUGO,                        ni_force_baseline_show,   NULL),

#ifdef DEVICE_INTERRUPT
  __ATTR (interrupt,               NI_WRITE_PERMISSIONS, NULL,                     ni_force_interrupt_store),
#endif

  __ATTR (threshold,               NI_WRITE_PERMISSIONS, NULL,                     ni_force_threshold_store),
  __ATTR (register,      S_IRUGO | NI_WRITE_PERMISSIONS, ni_force_register_show,   ni_force_register_store),

  OEM_SYSFS

#ifdef NI_MCU
#ifdef HOST_DEBUGGER
  __ATTR (dump_trace,    S_IRUGO,                        ni_force_dump_trace,      NULL),
#endif
#endif
};

/* SYSFS Commands -------------------------------------------------------------- */
/* ni_force_force_show
 *
 * Show force data from DIC in app friendly format
 * ADB Console Usage: cat force
 *
 */
static ssize_t ni_force_force_show(struct device *dev,
                                   struct device_attribute *attr,
                                   char *buf)
{
    u8 data_buffer_out[NUM_SENSORS * OEM_ADCOUT_LEN];
    int ret = 0;

    struct ni_force_ts_data *ts = dev_get_drvdata(dev);

#ifdef NI_MCU
    if (ts->fw_info.fw_upgrade.bootloadermode == true)
        return 0;
#endif

    if (unlikely(ni_force_i2c_read(ts->client, ADCOUT_REG,
                                   sizeof(data_buffer_out), data_buffer_out) < 0)) {
        ret = sprintf(buf, "%s", "i2c_read error\n");
    }
    else {
        u8  i;
        int sample;

        ret = sprintf(buf, "%d ", NUM_SENSORS);

        for (i = 0; i < NUM_SENSORS; i++) {
            sample = OEM_ADCOUT_SAMPLE

#ifdef AFE_REV1
            if (adcraw_mode)
            {
                // Convert sign/magnitude format to 2's complement
                if (sample & 0x800) {
                    sample = -(sample & 0x7ff);
                }
            }
            else
#endif
            OEM_ADCOUT_SWITCH
            {
                // If force is negative then sign extend it
                if (sample & OEM_ADC_SIGN_MASK) {
                    sample |= ((-1) & ~OEM_ADC_DATA_MASK);
                }
            }

            ret += sprintf(buf + ret, "%d ", sample);
        }

        ret += sprintf(buf + ret, "%s", "\n");
    }

    return ret;
}

/* ni_force_force_mode_show
 *
 * Show force mode from DIC in app friendly format
 * ADB Console Usage: cat force_mode
 *
 */
static ssize_t ni_force_force_mode_show(struct device *dev,
                                        struct device_attribute *attr,
                                        char *buf)
{
    u8 mode;
    int ret = 0;

    struct ni_force_ts_data *ts = dev_get_drvdata(dev);

#ifdef NI_MCU
    if (ts->fw_info.fw_upgrade.bootloadermode == true)
        return 0;
#endif

    if (unlikely(ni_force_i2c_read(ts->client, ADCRAW_REG,
                                   sizeof(mode), &mode) < 0)) {
        ret = sprintf(buf, "%s", "i2c_read error\n");
    }
    else {
        ret = sprintf(buf, "%d\n", (mode & ADCRAW_MSK) >> ADCRAW_POS);
    }

    return ret;
}

/* ni_force_force_mode_store
 *
 * Store force mode
 * ADB Console Usage: echo [mode] > force_mode
 *
 */
static ssize_t ni_force_force_mode_store(struct device *dev,
                                         struct device_attribute *attr,
                                         const char *buf, size_t count)
{
    int mode;
    struct ni_force_ts_data *ts = dev_get_drvdata(dev);

#ifdef NI_MCU
    if (ts->fw_info.fw_upgrade.bootloadermode == true)
        return count;
#endif

    if ((sscanf(buf, "%d", &mode) != 1) || (mode < 0) || (mode > 1))
    {
        LOGE("Invalid force mode\n");
        return count;
    }

    if (unlikely
        (ni_force_i2c_modify_byte(ts->client, ADCRAW_REG, mode << ADCRAW_POS, ADCRAW_MSK) < 0))
    {
        LOGE("Force mode not changed");
    }

    adcraw_mode = mode;

    return count;
}

/* ni_force_baseline_show
 *
 * Show baseline data from DIC in app friendly format
 * ADB Console Usage: cat baseline
 *
 */
static ssize_t ni_force_baseline_show(struct device *dev,
                                      struct device_attribute *attr,
                                      char *buf)
{
    u8 data_buffer_out[NUM_SENSORS * OEM_ADCOUT_LEN];
    int ret = 0;

    struct ni_force_ts_data *ts = dev_get_drvdata(dev);

#ifdef NI_MCU
    if (ts->fw_info.fw_upgrade.bootloadermode == true)
        return 0;
#endif

    if (unlikely(ni_force_i2c_read(ts->client, BASELINE_REG,
                                   sizeof(data_buffer_out), data_buffer_out) < 0)) {
        ret = sprintf(buf, "%s", "i2c_read error\n");
    }
    else {
        u8  i;
        int baseline;

        ret = sprintf(buf, "%d ", NUM_SENSORS);

        for (i = 0; i < NUM_SENSORS; i++) {
            baseline = OEM_ADCOUT_SAMPLE        /* adcout macro also works for baseline */

#ifdef AFE_REV1
            // Convert sign/magnitude format to 2's complement
            if (baseline & 0x800) {
                baseline = -(baseline & 0x7ff);
            }
#else
            // If baseline is negative then sign extend it
            if (baseline & OEM_ADC_SIGN_MASK) {
                baseline |= ((-1) & ~OEM_ADC_DATA_MASK);
            }
#endif

            ret += sprintf(buf + ret, "%d ", baseline);
        }

        ret += sprintf(buf + ret, "%s", "\n");
    }

    return ret;
}

#ifdef DEVICE_INTERRUPT
/* ni_force_interrupt_store
 *
 * Store interrupt (enable/disable)
 * ADB Console Usage: echo [mode] > interrupt
 *
 */
static ssize_t ni_force_interrupt_store(struct device *dev,
                                        struct device_attribute *attr,
                                        const char *buf, size_t count)
{
    int interrupt;

    struct ni_force_ts_data *ts = dev_get_drvdata(dev);

#ifdef NI_MCU
    if (ts->fw_info.fw_upgrade.bootloadermode == true)
        return count;
#endif

    if ((sscanf(buf, "%d", &interrupt) != 1) || (interrupt < 0) || (interrupt > 1))
    {
        LOGE("Invalid interrupt\n");
        return count;
    }

    if (unlikely(ni_force_i2c_modify_array(ts->client, INTREN_REG, interrupt << INTREN_POS,
                                           INTREN_MSK, 2) < 0)) {
        LOGE("Error modifying interrupts\n");
    }

    return count;
}
#endif

/* ni_force_threshold_store
 *
 * Store thresholds
 * ADB Console Usage: echo [num_sensors threshold ...] > threshold
 *
 */
static ssize_t ni_force_threshold_store(struct device *dev,
                                        struct device_attribute *attr,
                                        const char *buf, size_t count)
{
    int i;
    const char *pbuf = buf;
    u32 autocal  [NUM_SENSORS];
    u32 interrupt[NUM_SENSORS];
    u8 data_buffer_out[NUM_SENSORS * OEM_ADCOUT_LEN];

    struct ni_force_ts_data *ts = dev_get_drvdata(dev);

#ifdef NI_MCU
    if (ts->fw_info.fw_upgrade.bootloadermode == true)
        return count;
#endif

    /* sanity check number of sensors */
    SKIP_BLANKS(pbuf)

    if ((sscanf(pbuf, "%d", &i) != 1) || (i != NUM_SENSORS))
    {
        LOGE("Invalid number of sensors\n");
        return count;
    }

    SKIP_DIGITS(pbuf)

    /* get autocal thresholds */
    for (i = 0; i < NUM_SENSORS; i++) {
        SKIP_BLANKS(pbuf)

        if ((sscanf(pbuf, "%d", &autocal[i]) != 1) || (autocal[i] > OEM_MAX_AUTOCAL))
        {
            LOGE("Invalid autocal threshold\n");
            return count;
        }

        SKIP_DIGITS(pbuf)
    }

    /* get interrupt thresholds */
    for (i = 0; i < NUM_SENSORS; i++) {
        SKIP_BLANKS(pbuf)

        if ((sscanf(pbuf, "%d", &interrupt[i]) != 1) || (interrupt[i] > OEM_MAX_INTERRUPT))
        {
            LOGE("Invalid interrupt threshold\n");
            return count;
        }

        SKIP_DIGITS(pbuf)
    }

    /* read, modify, write autocal thresholds */
    if (unlikely(ni_force_i2c_read(ts->client, AUTOCAL_REG,
                                   sizeof(data_buffer_out), data_buffer_out) < 0)) {
        LOGE("Error reading autocal thresholds\n");
        return count;
    }

    for (i = 0; i < NUM_SENSORS; i++) {
        OEM_AUTOCAL
    }

    if (unlikely(ni_force_i2c_write(ts->client, AUTOCAL_REG,
                                    sizeof(data_buffer_out), data_buffer_out) < 0)) {
        LOGE("Error writing autocal thresholds\n");
        return count;
    }

    /* read, modify, write interrupt thresholds */
    if (unlikely(ni_force_i2c_read(ts->client, INTRTHRSLD_REG,
                                   sizeof(data_buffer_out), data_buffer_out) < 0)) {
        LOGE("Error reading interrupt thresholds\n");
        return count;
    }

    for (i = 0; i < NUM_SENSORS; i++) {
        OEM_INTRTHRSLD
    }

    if (unlikely(ni_force_i2c_write(ts->client, INTRTHRSLD_REG,
                                    sizeof(data_buffer_out), data_buffer_out) < 0)) {
        LOGE("Error writing interrupt thresholds\n");
        return count;
    }

    return count;
}

/* ni_force_register_show
 *
 * Show register data from DIC in app friendly format
 * ADB Console Usage: cat register
 *
 */
static ssize_t ni_force_register_show(struct device *dev,
                                      struct device_attribute *attr,
                                      char *buf)
{
    u8 data_buffer_out[LAST_REG - FIRST_REG + 1];
    int ret = 0;

    struct ni_force_ts_data *ts = dev_get_drvdata(dev);

#ifdef NI_MCU
    if (ts->fw_info.fw_upgrade.bootloadermode == true)
        return 0;
#endif

    if (unlikely(ni_force_i2c_read(ts->client, FIRST_REG,
                                   sizeof(data_buffer_out), data_buffer_out) < 0)) {
        ret = sprintf(buf, "%s", "i2c_read error\n");
    }
    else {
        u8 i;

        for (i = 0; i < sizeof(data_buffer_out); i++) {
            ret += sprintf(buf + ret, "%02x ", data_buffer_out[i]);
            if ((i & 0x3) == 0x3) {
                ret += sprintf(buf + ret, "%s", " ");
            }
        }

        ret += sprintf(buf + ret, "%s", "\n");
    }

    return ret;
}

/* ni_force_register_store
 *
 * Store register data
 * ADB Console Usage: echo [addr] [data ...] > register
 *
 */
static ssize_t ni_force_register_store(struct device *dev,
                                       struct device_attribute *attr,
                                       const char *buf, size_t count)
{
    #define UCHAR_MAX ((u8)(-1))

    int i;
    u32 u;
    const char *pbuf = buf;
    u8 reg;
    u8 data_buffer_out[LAST_REG - FIRST_REG + 1];

    struct ni_force_ts_data *ts = dev_get_drvdata(dev);

#ifdef NI_MCU
    if (ts->fw_info.fw_upgrade.bootloadermode == true)
        return count;
#endif

    /* get register address */
    SKIP_BLANKS(pbuf)

    if ((sscanf(pbuf, "%x", &u) != 1) || (u > UCHAR_MAX))
    {
        LOGE("Invalid register address\n");
        return count;
    }
    reg = (u8)u;

    SKIP_HEXDIGITS(pbuf)

    /* get register data */
    for (i = 0; i <= LAST_REG; i++) {
        SKIP_BLANKS(pbuf)

        if ((sscanf(pbuf, "%x", &u) != 1) || (u > UCHAR_MAX))
        {
            /* check if at least one valid byte found */
            if (i) break;

            LOGE("Invalid register data\n");
            return count;
        }
        data_buffer_out[i] = (u8)u;

        SKIP_HEXDIGITS(pbuf)
    }

    /* make sure registers to be written are within valid range */
    if ((reg < FIRST_REG) || (reg + i - 1 > LAST_REG)) {
        LOGE("Invalid register range\n");
        return count;
    }

    if (unlikely(ni_force_i2c_write(ts->client, reg,
                                    i, data_buffer_out) < 0)) {
        LOGE("Error writing registers\n");
        return count;
    }

    return count;
}

/* END EXPORTED FUNCTIONS --------------------------------------------------------*/

/* DRIVER FUNCTIONS  ----------------------------------------------------------- */

#ifdef INPUT_DEVICE
/* ni_force_abs_input_report
 *
 * Send force status report to Android
 */
static void ni_force_abs_input_report(struct ni_force_ts_data *ts,
                                      const ktime_t timestamp)
{
    int i;

#ifdef EVENT_SYN
    input_event(ts->input_dev, EV_SYN, SYN_TIME_SEC,
                ktime_to_timespec(timestamp).tv_sec);
    input_event(ts->input_dev, EV_SYN, SYN_TIME_NSEC,
                ktime_to_timespec(timestamp).tv_nsec);
#endif

#ifdef FORCE_BUTTON
//#pragma message "TODO: Handle INPUT REPORT for NUM_SENSORS > 1 on same client"

    for (i = 0; i < NUM_SENSORS; i++)
    {
#ifdef RELEASE_INTERRUPT
        int state = 1;
        OEM_RELEASE_SWITCH
        {
            state = 0;
        }
        /* Report button state */
        input_event(ts->input_dev, EV_KEY, ts->input_event_code[i], state);
        input_sync(ts->input_dev);
        LOGI("report button state\n");
#else
        /* Report button press */
        input_event(ts->input_dev, EV_KEY, ts->input_event_code[i], 1);
        input_sync(ts->input_dev);
#ifndef RELEASE_POLLED
        input_event(ts->input_dev, EV_KEY, ts->input_event_code[i], 0);
        input_sync(ts->input_dev);
#endif
        LOGI("report button press\n");
#endif
    }
#endif

}
#endif

#ifdef RELEASE_POLLED
/* ni_force_release_polled_func
 *
 */
static void ni_force_release_polled_func(struct work_struct *work_release_polled)
{
    #define RELEASE_DELAY 2

    struct ni_force_ts_data *ts = container_of(work_release_polled,
                                               struct ni_force_ts_data,
                                               work_release_polled);
    bool released = false;

    LOGI("%s\n", __func__);

    OEM_RELEASE_READ
    {
//#pragma message "TODO: Handle RELEASE POLLING for NUM_SENSORS > 1 on same client"

        int i;

        for (i = 0; i < NUM_SENSORS; i++)
        {
            OEM_RELEASE_SWITCH
            {
#ifdef INPUT_DEVICE
                input_event(ts->input_dev, EV_KEY, ts->input_event_code[i], 0);
                input_sync(ts->input_dev);
#endif
                released = true;
            }
        }
    }

    if (!released)
    {
        /* continue checking if force < release threshold */
        msleep(RELEASE_DELAY);
        queue_work(ni_force_wq, &ts->work_release_polled);
    }
}
#endif

/* ni_force_recover_func
 *
 */
static void ni_force_recover_func(struct work_struct *work_recover)
{
    struct ni_force_ts_data *ts = container_of(work_recover,
                                               struct ni_force_ts_data,
                                               work_recover);

    LOGI("%s\n", __func__);

    disable_irq(ts->client->irq);
    safety_reset(ts);
    if (ts->curr_pwr_state == POWER_ON)
    {
        ni_force_ic_init(ts);
        enable_irq(ts->client->irq);
    }
    enable_irq(ts->client->irq);
}

/* safety_reset
 *
 * 1. turn off the power.
 * 2. turn on the power.
 * 3. sleep (booting_delay)ms, usually 400ms(ni_force).
 *
 * Caller should take care of enable/disable irq
 */
static void safety_reset(struct ni_force_ts_data *ts)
{
    LOGI(">>>safety_reset\n");

    release_all_ts_event(ts);

    OEM_SAFETY_RESET

    LOGI("<<safety_reset\n");
}

/* release_all_ts_event
*
* When system enters suspend-state,
* if user press touch-panel, release them automatically.
*/
static void release_all_ts_event(struct ni_force_ts_data *ts)
{
#ifdef INPUT_DEVICE
#ifdef FORCE_BUTTON
    int i;

    for (i = 0; i < NUM_SENSORS; i++)
    {
        input_event(ts->input_dev, EV_KEY, ts->input_event_code[i], 0);
        input_sync(ts->input_dev);
    }
#endif
#endif
}

static void *get_touch_handle(struct i2c_client *client)
{
    return i2c_get_clientdata(client);
}

static int ni_force_i2c_read(struct i2c_client *client, u8 reg, int len,
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
            .len = 1,
            .buf = &reg,
        },
        {
            .addr = client->addr,
            .flags = I2C_M_RD,
            .len = len,
            .buf = buf,
        },
    };

    OEM_I2C

#ifdef DEVICE_INTERRUPT
    ts->enableInterrupt = 0;
#endif

    if (i2c_transfer(client->adapter, msgs, 2) < 0)
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

static int ni_force_i2c_write(struct i2c_client *client, u8 reg, int len,
                              u8 * buf)
{
#ifdef DEVICE_INTERRUPT
    struct ni_force_ts_data *ts =
        (struct ni_force_ts_data *)get_touch_handle(client);
#endif

    u8 send_buf[len + 1];
    struct i2c_msg msgs[] = {
        {
            .addr = client->addr,
            .flags = client->flags,
            .len = len + 1,
            .buf = send_buf,
        },
    };
    int i;
    int ret = -EIO;

#ifdef VERIFIED_WRITE
    u8  verify_buf[len];
#endif

    OEM_I2C

    for (i = 0; i < OEM_I2C_ATTEMPTS; i++)
    {
#ifdef DEVICE_INTERRUPT
        ts->enableInterrupt = 0;
#endif

        send_buf[0] = (u8)reg;
        memcpy(&send_buf[1], buf, len);

        if (i2c_transfer(client->adapter, msgs, 1) < 0)
        {
            if (printk_ratelimit())
                LOGE("transfer error\n");
            continue;
        }

#ifdef DEVICE_INTERRUPT
        ts->enableInterrupt = 1;
#endif

#ifdef VERIFIED_WRITE
        if (unlikely(ni_force_i2c_read(client, reg, len, verify_buf) < 0))
        {
            continue;
        }

        if (memcmp(buf, verify_buf, len))
        {
            continue;
        }
#endif

        ret = 0;
        break;
    }

    return ret;
}

static int ni_force_i2c_write_byte(struct i2c_client *client, u8 reg, u8 data)
{
#ifdef DEVICE_INTERRUPT
    struct ni_force_ts_data *ts =
            (struct ni_force_ts_data *)get_touch_handle(client);
#endif

    u8 send_buf[2];
    struct i2c_msg msgs[] = {
        {
            .addr = client->addr,
            .flags = client->flags,
            .len = 2,
            .buf = send_buf,
        },
    };
    int i;
    int ret = -EIO;

#ifdef VERIFIED_WRITE
    u8  verify_buf;
#endif

    OEM_I2C

    for (i = 0; i < OEM_I2C_ATTEMPTS; i++)
    {
#ifdef DEVICE_INTERRUPT
        ts->enableInterrupt = 0;
#endif

        send_buf[0] = (u8)reg;
        send_buf[1] = (u8)data;

        if (i2c_transfer(client->adapter, msgs, 1) < 0)
        {
            if (printk_ratelimit())
                LOGE("transfer error\n");
            continue;
        }

#ifdef DEVICE_INTERRUPT
        ts->enableInterrupt = 1;
#endif

#ifdef VERIFIED_WRITE
        if (unlikely(ni_force_i2c_read(client, reg, 1, &verify_buf) < 0))
        {
            continue;
        }

        if (data != verify_buf)
        {
            continue;
        }
#endif

        ret = 0;
        break;
    }

    return ret;
}

/* ni_force_i2c_modify_byte
 *
 * Read register, clear bits specified by 'mask', set any bits specified by 'data',
 * then write back to register
 *
 */
static int ni_force_i2c_modify_byte(struct i2c_client *client, u8 reg, u8 data,
                                    u8 mask)
{
    u8 buf;

    if (unlikely(ni_force_i2c_read(client, reg, sizeof(buf), &buf) < 0))
    {
        return -EIO;
    }

    buf = (buf & ~mask) | data;

    if (unlikely(ni_force_i2c_write_byte(client, reg, buf) < 0))
    {
        return -EIO;
    }

    return 0;
}

/* ni_force_i2c_modify_array
 *
 * Read NUM_SENSORS-length register array, and for each register spaced 'offset'
 * bytes apart within this array, clear bits specified by 'mask', set any bits
 * specified by 'data', then write back to register
 *
 */
static int ni_force_i2c_modify_array(struct i2c_client *client, u8 reg, u8 data,
                                     u8 mask, u8 offset)
{
    int i;
    u8 buf[NUM_SENSORS * offset];

    if (unlikely(ni_force_i2c_read(client, reg, sizeof(buf), buf) < 0))
    {
        return -EIO;
    }

    for (i = 0; i < NUM_SENSORS; i++) {
        buf[i * offset] = (buf[i * offset] & ~mask) | data;
    }

    if (unlikely(ni_force_i2c_write(client, reg, sizeof(buf), buf) < 0))
    {
        return -EIO;
    }

    return 0;
}

#ifdef DEVICE_INTERRUPT
static int ni_force_ts_get_data(struct i2c_client *client)
{
    int i = 0;
    struct ni_force_ts_data *ts =
        (struct ni_force_ts_data *)get_touch_handle(client);

    u8 data_buffer_out[NUM_SENSORS * OEM_ADCOUT_LEN];

#ifdef NI_MCU
    if (ts->fw_info.fw_upgrade.bootloadermode == true)
        return 0;
#endif

    if (unlikely(ni_force_i2c_read(client, ADCOUT_REG,
                                   sizeof(data_buffer_out), data_buffer_out) < 0))
    {
        LOGE("ADCOUT_REG fail\n");
        return -EIO;
    }

    /* Sensor data */
    for (i = 0; i < NUM_SENSORS; i++)
    {
        ts->force[i] = OEM_ADCOUT_SAMPLE
    }
    
    return 0;
}
#endif

static int ni_force_get_ic_info(struct ni_force_ts_data *ts)
{
#ifdef NI_MCU
    u8 databuffer[64];
    int i;

    LOGI("%s\n", __func__);

    memset(&ts->fw_info, 0, sizeof(struct ni_force_ts_fw_info));

    if (unlikely
        (ni_force_i2c_read
         (ts->client, NI_CMD_FW_VERSION, sizeof(databuffer), databuffer) < 0))
    {
        LOGE("NI_CMD_FW_VERSION read fail\n");
        return -EIO;
    }

    ts->fw_info.fw_ver   = databuffer[0];
    ts->fw_info.fw_rev   = databuffer[1];
    ts->fw_info.fw_build = databuffer[2];

    for(i = 0; i < 11; i ++)
      ts->fw_info.buildDate[i] = databuffer[3 + i];

    for(i = 0; i < 8; i ++)
      ts->fw_info.buildTime[i] = databuffer[14 + i];

    snprintf(ts->fw_info.ic_fw_identifier, sizeof(ts->fw_info.ic_fw_identifier),
             "FP %d.%d.%d",
             ts->fw_info.fw_ver, ts->fw_info.fw_rev, ts->fw_info.fw_build);

    LOGI("%s: IC identifier[%s]\n", __func__, ts->fw_info.ic_fw_identifier);
#else
    u8 databuffer;
    u8 devid;
    u8 rev;

    LOGI("%s\n", __func__);

#if DEVID_REG != REV_REG
#error "Assumption about DEVID_REG and REV_REG invalid"
#endif

    if (unlikely
        (ni_force_i2c_read
         (ts->client, DEVID_REG, sizeof(databuffer), &databuffer) < 0))
    {
        LOGE("DEVID_REG read fail\n");
        return -EIO;
    }

    devid = (databuffer & DEVID_MSK) >> DEVID_POS;
    rev   = (databuffer & REV_MSK)   >> REV_POS;

    LOGI("%s: IC DEVID %d, REV %d\n", __func__, devid, rev);
#endif

    return 0;
}

static int ni_force_parse_dt(struct device *dev,
                             struct ni_force_platform_data *pdata
)
{
    int rc;
    struct device_node *np = dev->of_node;

#ifdef REGISTER_INIT
    static char szRegInit[] = "nif,reg-init";
    int sz;
    struct property *prop;
#endif

    LOGV("%s\n", __func__);

#ifdef DEVICE_INTERRUPT
    rc = of_get_named_gpio_flags(np, "nif,irq-gpio", 0, &pdata->irq_gpio_flags);
    if (rc < 0)
    {
        LOGE("%s: Failed with error %d\n", __func__, rc);
        dev_err(dev, "Unable to get reset gpio\n");
        return rc;
    }
    else
    {
        LOGV("%s: RC %d\n", __func__, rc);
        pdata->irq_gpio = rc;
    }
#endif

#ifdef REGISTER_INIT
    prop = of_find_property(np, szRegInit, NULL);
    if (!prop)
    {
        LOGI("%s: reg-init not defined\n", __func__);
        return 0;
    }
    if (!prop->value)
    {
        LOGE("%s: Failed. prop->value is NULL\n", __func__);
        return -ENODATA;
    }
    if (prop->length > sizeof(pdata->reg_init))
    {
        LOGE("%s: Failed. prop->length too large\n", __func__);
        return -EINVAL;
    }

    sz = prop->length / sizeof(u32);
    if (sz % 2)
    {
        LOGE("%s: Failed. reg-init data must be paired\n", __func__);
        return -EINVAL;
    }

    rc = of_property_read_u32_array(np, szRegInit, pdata->reg_init, sz);
    if (rc)
    {
        LOGE("%s: Failed with error %d\n", __func__, rc);
        dev_err(dev, "Unable to read %s\n", szRegInit);
        return rc;
    }

    pdata->reg_init_sz = sz;
#endif

    return 0;
}

/* END DRIVER FUNCTIONS -------------------------------------------------------- */

/* DRIVE MODULE FUNCTIONS ------------------------------------------------------ */

#ifdef DEVICE_INTERRUPT
/* ni_force_work_pre_proc
 *
 * Pre-process work at touch_work
 */
static int ni_force_work_pre_proc(struct ni_force_ts_data *ts)
{
    int ret;

    //LOGI("%s\n", __func__);

    ret = ni_force_ts_get_data(ts->client);

    if (ret != 0)
    {
        LOGE("get data fail\n");
        return ret;
    }
    return 0;
}

/* ni_force_irq_handler
 *
 * Called when INT pin asserts low and IRQ enabled
 */
static irqreturn_t ni_force_irq_handler(int irq, void *dev_id)
{
    struct ni_force_ts_data *ts = (struct ni_force_ts_data *)dev_id;
#ifdef INPUT_DEVICE
    ktime_t timestamp = ktime_get();
#endif
    u8 buf;

    LOGI("enter IRQ\n");
    
#ifdef FORCE_BUTTON
    if(suspend_flag)
    {
        irq_count++;
        LOGI("enter IRQ: irqCount = %d\n",irq_count);
        if(irq_count > 10)
        {
#ifdef INPUT_DEVICE
            int i;

            for (i = 0; i < NUM_SENSORS; i++)
            {
                input_event(ts->input_dev, EV_KEY, ts->input_event_code[i], 0);
                input_sync(ts->input_dev);
            }
#endif
            irq_count = 0;
        }
    }
    else
#endif
    {
        LOGI("enter IRQ: enableInt = %d\n",ts->enableInterrupt);
        if(ts->enableInterrupt)
        {
            switch (ni_force_work_pre_proc(ts))
            {
                case 0:
#ifdef INPUT_DEVICE
                    ni_force_abs_input_report(ts, timestamp);
#endif

#ifdef RELEASE_POLLED
                    /* start checking if force < release threshold */
                    queue_work(ni_force_wq, &ts->work_release_polled);
#endif
                    break;
                case -EIO:
                    queue_work(ni_force_wq, &ts->work_recover);
                    break;
            }
        } 
    }

    /* acknowledge DIC interrupt */
    if (unlikely(ni_force_i2c_read(ts->client, INTR_REG, sizeof(buf), &buf) < 0))
    {
        LOGE("Error reading INTR_REG\n");
    }

    return IRQ_HANDLED;
}
#endif

/* ni_force_init_func
 *
 * In order to reduce the booting-time,
 * we used delayed_work_queue instead of msleep or mdelay.
 */
static void ni_force_init_func(struct work_struct *work_init)
{
    struct ni_force_ts_data *ts = container_of(to_delayed_work(work_init),
                                               struct ni_force_ts_data,
                                               work_init);

    LOGI("%s\n", __func__);

#ifdef INPUT_DEVICE
    mutex_lock(&ts->input_dev->mutex);
#endif

    if (!ts->curr_resume_state)
    {
        enable_irq(ts->client->irq);
#ifdef INPUT_DEVICE
        mutex_unlock(&ts->input_dev->mutex);
#endif
        return;
    }

    /* Specific device initialization */
    ni_force_ic_init(ts);
    enable_irq(ts->client->irq);

#ifdef INPUT_DEVICE
    mutex_unlock(&ts->input_dev->mutex);
#endif
}

/* ni_force_ic_init
 *
 * initialize the device_IC and variables.
 */
static int ni_force_ic_init(struct ni_force_ts_data *ts)
{
    LOGI("%s\n", __func__);

    if (unlikely(ts->ic_init_err_cnt >= MAX_RETRY_COUNT))
    {
        LOGE("Init Failed: Irq-pin has some unknown problems\n");
        ts->ic_init_err_cnt = 0;

        return -1;
    }

    if (ni_force_init_panel(ts->client) < 0)
    {
        LOGE("specific device initialization fail\n");
        ts->ic_init_err_cnt++;
        disable_irq_nosync(ts->client->irq);
        safety_reset(ts);
        queue_delayed_work(ni_force_wq, &ts->work_init, msecs_to_jiffies(10));

        return 0;
    }

    /* make devices active */
    if (unlikely(ni_force_i2c_modify_array(ts->client, EN_REG,
                                           1 << EN_POS, EN_MSK, 1) < 0))
    {
        LOGE("EN_REG modify fail\n");
        return -EIO;
    }

#ifdef AFE_REV1
#pragma message "afe silicon: using temporary required settings"

#define REG0_VALUE (WAIT_8MS<<WAIT_POS)|(ADCRAW_RAW<<ADCRAW_POS)|(1<<EN_POS) /* 0x39 */

    if (unlikely(ni_force_i2c_write_byte(ts->client, 0, REG0_VALUE) < 0))
    {
        LOGE("afe silicon: Reg 0 write fail\n");
        return -EIO;
    }
    adcraw_mode = 1;
    if (unlikely(ni_force_i2c_write_byte(ts->client, 1, 0x70) < 0))
    {
        LOGE("afe silicon: Reg 1 write fail\n");
        return -EIO;
    }
    if (unlikely(ni_force_i2c_write_byte(ts->client, 0xb, 0x18) < 0))
    {
        LOGE("afe silicon: Reg 0xb write fail\n");
        return -EIO;
    }
#endif

#ifdef DEVICE_INTERRUPT
    /* enable interrupts */
    if (unlikely(ni_force_i2c_modify_array(ts->client, INTREN_REG,
                                           1 << INTREN_POS, INTREN_MSK, 2) < 0))
    {
        LOGE("INTREN_REG modify fail\n");
        return -EIO;
    }

    /* enable interrupt persist mode */
    if (unlikely(ni_force_i2c_modify_byte(ts->client, INTRPERSIST_REG,
                                          INTRPERSIST_INF << INTRPERSIST_POS, INTRPERSIST_MSK) < 0))
    {
        LOGE("INTRPERSIST_REG modify fail\n");
        return -EIO;
    }
#endif

#ifdef REGISTER_INIT
    if (ts->pdata->reg_init_sz)
    {
        int i;

        for (i = 0; i < ts->pdata->reg_init_sz; i+=2)
        {
            LOGI("%s: reg-init[%d] = <0x%02x 0x%02x>\n", __func__,
                 i/2, ts->pdata->reg_init[i], ts->pdata->reg_init[i+1]);

            if (unlikely(ni_force_i2c_write_byte(ts->client,
                         ts->pdata->reg_init[i], ts->pdata->reg_init[i+1]) < 0))
            {
                LOGE("reg_init: Reg 0x%02x write fail\n", ts->pdata->reg_init[i]);
                return -EIO;
            }
        }
    }
#endif

    atomic_set(&ts->device_init, 1);
    ts->ic_init_err_cnt = 0;

    return 0;
}

static int ni_force_init_panel(struct i2c_client *client)
{
    struct ni_force_ts_data *ts =
        (struct ni_force_ts_data *)get_touch_handle(client);

    LOGI("%s\n", __func__);

    if (!ts->is_probed)
        if (unlikely(ni_force_get_ic_info(ts) < 0))
            return -EIO;

    ts->is_probed = 1;

    return 0;
}

/* END DRIVER MODULE FUNCTIONS --------------------------------------------------- */

/* DRIVER MODULE INITIALIZATION FUNCTIONS ---------------------------------------- */
static int ni_force_free_wq(void)
{
    if (--num_clients <= 0)
    {
        if (ni_force_wq)
        {
            destroy_workqueue(ni_force_wq);
            ni_force_wq = NULL;
        }
    }

    return 0;
}

static int ni_force_ts_probe(struct i2c_client *client,
                             const struct i2c_device_id *id)
{
    struct ni_force_ts_data *ts;
    struct ni_force_platform_data *pdata;
    int ret = 0;
    u8 i2c_test = 0;
    int i;

    LOGI("%s\n", __func__);

    if (client->dev.of_node)
    {
        LOGV("%s: Allocating Memory... \n", __func__);
        pdata = devm_kzalloc(&client->dev,
                             sizeof(struct ni_force_platform_data),
                             GFP_KERNEL);
        if (!pdata)
        {
            LOGE("%s: Failed to allocate memory\n", __func__);
            dev_err(&client->dev, "Failed to allocate memory\n");
            return -ENOMEM;
        }
        ret = ni_force_parse_dt(&client->dev, pdata);
        if (ret)
        {
            LOGE("%s: Failed with error %d\n", __func__, ret);
            return ret;
        }
    }
    else
    {
        pdata = client->dev.platform_data;
        if (!pdata)
        {
            LOGE("%s: Failed with error %d\n", __func__, -ENODEV);
            return -ENODEV;
        }
    }

    LOGI("%s: Checking I2C Functionality\n", __func__);

    if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C))
    {
        LOGE("i2c functionality check error\n");
        return -EPERM;
    }

    if (!ni_force_wq)
    {
        ni_force_wq = create_singlethread_workqueue("ni_force_wq");

        if (!ni_force_wq)
        {
            LOGE("create_singlethread_workqueue error\n");
            return -ENOMEM;
        }
    }

    if (1)  /* we use the else to contain our exceptions and use goto to get to them. */
    {
        ts = kzalloc(sizeof(struct ni_force_ts_data), GFP_KERNEL);

        if (!ts)
        {
            LOGE("Can not allocate memory\n");
            ret = -ENOMEM;
            goto err_kzalloc_failed;
        }

        ts->pdata = pdata;
        ts->ic_init_err_cnt = 0;

        ts->client = client;
        i2c_set_clientdata(client, ts);

        atomic_set(&ts->device_init, 0);
        ts->curr_resume_state = 1;

#ifdef RELEASE_POLLED
        OEM_RELEASE_INIT
#endif

#ifdef FORCE_BUTTON
        OEM_PROBE_ASSIGN
#endif

        OEM_PROBE_INIT

        msleep(BOOTING_DELAY);

        /* init work_queue */
        INIT_DELAYED_WORK(&ts->work_init, ni_force_init_func);
#ifdef NI_MCU
        INIT_WORK(&ts->work_fw_upgrade, ni_force_fw_upgrade_func);
#endif
        INIT_WORK(&ts->work_recover, ni_force_recover_func);
#ifdef RELEASE_POLLED
        INIT_WORK(&ts->work_release_polled, ni_force_release_polled_func);
#endif

#ifdef INPUT_DEVICE
        /* input dev setting */
        ts->input_dev = input_allocate_device();
        if (ts->input_dev == NULL)
        {
            LOGE("Failed to allocate input device\n");
            ret = -ENOMEM;
            goto err_input_dev_alloc_failed;
        }

        ts->input_dev->name = DEVICE_NAME;
        
        ts->input_dev->id.vendor  = OEM_ID_VENDOR;
        ts->input_dev->id.product = OEM_ID_PRODUCT;
        ts->input_dev->id.version = OEM_ID_VERSION;

#ifdef EVENT_SYN
        set_bit(EV_SYN, ts->input_dev->evbit);        
#endif
        set_bit(EV_KEY, ts->input_dev->evbit);
        set_bit(INPUT_PROP_DIRECT, ts->input_dev->propbit);        
#ifdef FORCE_BUTTON
        for (i = 0; i < NUM_SENSORS; i++)
        {
            set_bit(ts->input_event_code[i], ts->input_dev->keybit);
        }
#endif

        ret = input_register_device(ts->input_dev);
        if (ret < 0)
        {
            LOGE("Unable to register %s input device\n", ts->input_dev->name);
            goto err_input_register_device_failed;
        }
#endif

#ifdef DEVICE_INTERRUPT
        ts->enableInterrupt = 1;    // Enable interrupt handling in ni_force_irq_handler

        /* interrupt mode */
        ret = gpio_request(ts->pdata->irq_gpio, "nif,irq-gpio");
        if (ret < 0)
        {
            LOGE("FAIL: irq-gpio gpio_request\n");
            goto err_int_gpio_request_failed;
        }
        gpio_direction_input(ts->pdata->irq_gpio);

        ret = request_threaded_irq(client->irq, NULL, ni_force_irq_handler,
                                   OEM_IRQ_TRIGGER,
                                   client->name, ts);

        if (ret < 0)
        {
            LOGE("request_irq failed\n");
            goto err_interrupt_failed;
        }
#endif

        OEM_PROBE_PRE_I2C

        LOGI("%s: Attempting I2C read from device @0x%x\n", __func__, ts->client->addr);

        /* Add i2c check routine for booting in no touch panel/ic case */
        for (i = 0; i < MAX_RETRY_COUNT; i++)
        {
            if (unlikely
                (ni_force_i2c_read
                 (ts->client, WAIT_REG, sizeof(i2c_test),
                  &i2c_test) < 0))
            {
                LOGE("I2C read fail\n");
                if (i == MAX_RETRY_COUNT - 1)
                {
                    LOGE("No I2C device\n");
                    ret = -EIO;
                    goto err_ni_force_i2c_read_failed;
                }
            }
            else
            {
                LOGI("%s: I2C read success\n", __func__);
                break;
            }
        }

        /* Specific device initialization */
        ret = ni_force_ic_init(ts);
        if (ret < 0)
        {
            goto err_ni_force_i2c_read_failed;
        }

        /* Firmware Upgrade Check - use thread for booting time reduction */
        //queue_work(ni_force_wq, &ts->work_fw_upgrade);

        for (i = 0; i < ARRAY_SIZE(ni_force_device_attrs); i++)
        {
            ret = device_create_file(&client->dev, &ni_force_device_attrs[i]);
            if (ret)
                goto err_dev_create_file;
        }

        num_clients++;

        LOGI("%s OK (%d)\n", __func__, ret);
    }
    else     /* only reched on an error */
    {
err_dev_create_file:
        for (i = i - 1; i >= 0; i--)
        {
            device_remove_file(&ts->client->dev, &ni_force_device_attrs[i]);
        }
err_ni_force_i2c_read_failed:
#ifdef DEVICE_INTERRUPT
        free_irq(ts->client->irq, ts);
#endif

#ifdef DEVICE_INTERRUPT
err_interrupt_failed:
        gpio_free(ts->pdata->irq_gpio);
err_int_gpio_request_failed:
#endif

#ifdef INPUT_DEVICE
        input_unregister_device(ts->input_dev);
err_input_register_device_failed:
        input_free_device(ts->input_dev);
err_input_dev_alloc_failed:
#endif

        OEM_PROBE_UNINIT

err_kzalloc_failed:
        kfree(ts);
        ni_force_free_wq();

        LOGI("%s error (%d)\n", __func__, ret);
    }

    return ret;
}

static int ni_force_ts_remove(struct i2c_client *client)
{
    struct ni_force_ts_data *ts = i2c_get_clientdata(client);
    int i;

    LOGI("%s\n", __func__);

    for (i = 0; i < ARRAY_SIZE(ni_force_device_attrs); i++)
    {
        device_remove_file(&client->dev, &ni_force_device_attrs[i]);
    }

#ifdef DEVICE_INTERRUPT
    free_irq(client->irq, ts);
    gpio_free(ts->pdata->irq_gpio);
#endif

#ifdef INPUT_DEVICE
    input_unregister_device(ts->input_dev);
    input_free_device(ts->input_dev);
#endif

    OEM_REMOVE

    kfree(ts);
    ni_force_free_wq();

    return 0;
}

static struct of_device_id ni_force_match_table[] = {
    {.compatible = DEVICE_TREE_NAME,},
    {},
};

static struct i2c_device_id ni_force_ts_id[] = {
    {DEVICE_NAME, 0},
    {},
};

static struct i2c_driver ni_force_ts_driver = {
    .probe    = ni_force_ts_probe,
    .remove   = ni_force_ts_remove,
    .id_table = ni_force_ts_id,
    .driver = {
        .name  = DEVICE_NAME,
        .owner = THIS_MODULE,
        .of_match_table = ni_force_match_table,
    },
};

static int __init ni_force_ts_init(void)
{
    LOGI("***NextInput driver __init!\n");
    return i2c_add_driver(&ni_force_ts_driver);
}

static void __exit ni_force_ts_exit(void)
{
    LOGI("***NextInput driver __exit!\n");
    i2c_del_driver(&ni_force_ts_driver);
    ni_force_free_wq();
}

/* END DRIVER MODULE INITIALIZATION FUNCTIONS ------------------------------------ */

module_init(ni_force_ts_init);
module_exit(ni_force_ts_exit);

MODULE_AUTHOR("NextInput Corporation");
MODULE_DESCRIPTION("NextInput ForceTouch Driver");
MODULE_LICENSE("GPL");
