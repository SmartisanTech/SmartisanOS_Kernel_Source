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

#ifndef NI_FORCE_H
#define NI_FORCE_H

#include <linux/power_supply.h>
#include <linux/types.h>
#include <linux/ioctl.h>
#ifndef DIC_VARIANT
#include "ni_force_command_set.h"
#endif

#define VERBOSE_LOGGING    // Comment this out to remove verbose logging

// DRIVER CONSTANT VALUES
#define DRIVER_VERSION                          4
#define DRIVER_REVISION                         5
#define DRIVER_BUILD                            1

#define NI_STATUS_OK                            0b01000000

// CONSTANT VALUES
#define MAX_RETRY_COUNT                         3
#define BOOTING_DELAY                           400     // DELAY IF MCU OFF
#define RESET_DELAY                             20      // DELAY AFTER WAKING MCU
#define SLEEP_DELAY                             20      // DELAY BEFORE MAKING INT OUTPUT

#define SKIP_BLANKS(p)    while((*p==' ')||(*p=='\t')){p++;}
#define SKIP_DIGITS(p)    while((*p>='0')&&(*p<='9' )){p++;}
#define SKIP_HEXDIGITS(p) while(isxdigit(*p)         ){p++;}

struct ni_force_platform_data
{
#ifdef DEVICE_INTERRUPT
    int irq_gpio;               // Interrupt for MCU INT or Data Ready signal
    u32 irq_gpio_flags;
#endif

#ifdef REGISTER_INIT
    int reg_init_sz;
    u32 reg_init[(LAST_REG - FIRST_REG + 1) * 2];
#endif

    int dummy;                  // Make sure struct has at least one field
};

#ifdef NI_MCU
struct ni_force_ts_fw_upgrade_info
{
    char fw_path[256];          // Path to FW on file system
    u8 fw_force_upgrade;        // Flag to force upgrade if no FW
    volatile u8 is_downloading; // Flag while downloading FW to MCU
    bool bootloadermode;
    u8 *fwdata_ptr;
    size_t fw_size;
};

struct ni_force_ts_fw_info
{
    u8 fw_ver;                  // FW Version on MCU
    u8 fw_rev;                  // FW Revision on MCU
    u8 fw_build;                // FW Build on MCU
    u8 ni_core_ver;             // NI Algo Core Version on MCU
    u8 ni_core_rev;             // NI Algo Core Revision on MCU
    u8 ni_core_build;           // NI Algo Core Build on MCU

    char buildDate[11];
    char buildTime[8];

    struct ni_force_ts_fw_upgrade_info fw_upgrade;
    u8 ic_fw_identifier[31];    /* String */
};
#endif

// Primary MCU Data Struct
struct ni_force_ts_data
{
    struct i2c_client *client;                  // Pointer to i2c client

#ifdef INPUT_DEVICE
    struct input_dev *input_dev;                // Pointer to input device
#endif

#ifdef DEVICE_INTERRUPT
    u8 enableInterrupt;                         // If enabled, driver will service IRQ
#endif

    struct ni_force_platform_data *pdata;       // Pointer to MCU platform data
#ifdef NI_MCU
    struct ni_force_ts_fw_info fw_info;         // MCU firmware info
#endif
    int force[NUM_SENSORS];

    atomic_t device_init;
    volatile int curr_pwr_state;
    int curr_resume_state;
    u8 ic_init_err_cnt;
    u8 is_probed;

    struct delayed_work work_init;
#ifdef NI_MCU
    struct work_struct work_fw_upgrade;
#endif
    struct work_struct work_recover;
#ifdef RELEASE_POLLED
    struct work_struct work_release_polled;
    int release_threshold[NUM_SENSORS];
#endif
    struct delayed_work work_queue;

    struct delayed_work set_captouch_event_queue;
    struct delayed_work clear_captouch_event_queue;

    struct notifier_block notif;

#ifdef FORCE_BUTTON
    unsigned int input_event_code[NUM_SENSORS];
#endif
};

// MCU Power States
enum
{
    POWER_OFF = 0,
    POWER_ON,
    POWER_SLEEP,
    POWER_IDLE,
    POWER_RESUME,
    POWER_WAKE            // Not implemented in Beta driver
};

#ifdef NI_MCU
// MCU firmware update states
enum
{
    DOWNLOAD_COMPLETE = 0,
    UNDER_DOWNLOADING,
};
#endif

enum{
    DEBUG_NONE          = 0,
    DEBUG_BASE_INFO     = (1U << 0),
    DEBUG_COMMAND       = (1U << 1),
    DEBUG_VERBOSE       = (1U << 2),
    DEBUG_DATA          = (1U << 3),
    DEBUG_HARDWARE      = (1U << 4),
};

/* Debug mask value
 * usage: echo [debug_mask] > /sys/module/ni_force_ts/parameters/debug_mask
 */
static u32 ni_debug_mask = DEBUG_BASE_INFO;
module_param_named(debug_mask, ni_debug_mask, int, S_IRUGO|S_IWUSR|S_IWGRP);

// MCU DRIVER FUNCTION PROTOTYPES

static int  ni_force_ic_init (struct ni_force_ts_data *ts);
static void ni_force_init_func (struct work_struct *work_init);
static void safety_reset (struct ni_force_ts_data *ts);
static void release_all_ts_event (struct ni_force_ts_data *ts);
#ifdef DEVICE_INTERRUPT
static int  ni_force_ts_get_data (struct i2c_client *client);
#endif
static int  ni_force_init_panel (struct i2c_client *client);
static int  ni_force_get_ic_info (struct ni_force_ts_data *ts);
static void *get_touch_handle (struct i2c_client *client);
//static int  ni_force_i2c_write_mode (struct i2c_client *client, u8 mode);
static int  ni_force_i2c_read (struct i2c_client *client, u8 reg, int len,
                               u8 * buf);
static int ni_force_i2c_write (struct i2c_client *client, u8 reg, int len,
                               u8 * buf);
static int ni_force_i2c_write_byte (struct i2c_client *client, u8 reg,
                                    u8 data);
static int ni_force_i2c_modify_byte(struct i2c_client *client, u8 reg, u8 data,
                                    u8 mask);
static int ni_force_i2c_modify_array(struct i2c_client *client, u8 reg, u8 data,
                                     u8 mask, u8 offset);

// Info Log
#define LOGI(fmt, args...) \
    if(unlikely(ni_debug_mask & DEBUG_BASE_INFO )) \
        printk(KERN_INFO "[NextInput] " fmt, ##args)

// Info Command Log
#define LOGC(fmt, args...) \
    if(unlikely(ni_debug_mask & DEBUG_COMMAND )) \
        printk(KERN_INFO "[NextInput C] " fmt, ##args)

// Error Log
#define LOGE(fmt, args...) \
        printk(KERN_ERR "[NextInput E] [%s %d] " fmt, \
               __FUNCTION__, __LINE__, ##args)

// Verbose log
#define LOGV(fmt, args...) \
    if(unlikely(ni_debug_mask & DEBUG_VERBOSE )) \
        printk(KERN_ERR "[NextInput V] [%s %d] " fmt, \
                __FUNCTION__, __LINE__, ##args)

// Used for data flow
#define LOGD(fmt, args...) \
    if(unlikely(ni_debug_mask & DEBUG_DATA )) \
        printk(KERN_ERR "[NextInput D] [%s %d] " fmt, \
                __FUNCTION__, __LINE__, ##args)

// Used for hardware
#define LOGH(fmt, args...) \
    if(unlikely(ni_debug_mask & DEBUG_HARDWARE )) \
        printk(KERN_ERR "[NextInput H] [%s %d] " fmt, \
                __FUNCTION__, __LINE__, ##args)

#endif
