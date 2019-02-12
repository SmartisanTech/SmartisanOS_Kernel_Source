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

#define OEM_SYSFS

#define OEM_PROBE_ASSIGN                                                \
        /* assign input event codes to each sensor. Note custom codes   \
         * (e.g. 250) require Android input stack changes               \
         */                                                             \
                                                                        \
        for (i = 0; i < NUM_SENSORS; i++)                               \
        {                                                               \
            ts->input_event_code[i] = OEM_EVENT_CUSTOM;                 \
        }

#ifdef NI_MCU
#define OEM_PROBE_INIT                                                        \
        /* on Pixel with external development MCU, if phone is booted but     \
         * MCU firmware is left running from a previous boot, the firmware    \
         * malfunctions. So do firmware reset to avoid this problem           \
         */                                                                   \
                                                                              \
        LOGI("%s: Resetting device @0x%x...\n", __func__, ts->client->addr);  \
        ni_force_i2c_write_byte(ts->client, NI_CMD_RESET, 0);
#else
#define OEM_PROBE_INIT
#endif

#define OEM_PROBE_PRE_I2C

#define OEM_PROBE_UNINIT

#define OEM_SAFETY_RESET

#define OEM_FW_UPGRADE_POWER_ON

#define OEM_FW_UPGRADE_POWER_OFF

#define OEM_ADCOUT_LEN 2

#define OEM_ADCOUT_SWITCH

#define OEM_ADCOUT_SAMPLE                                                     \
        (((u16) data_buffer_out[(i * OEM_ADCOUT_LEN) + 0]) << ADCOUT_SHIFT) + \
        (       data_buffer_out[(i * OEM_ADCOUT_LEN) + 1]  >> ADCOUT_SHIFT);

#define OEM_AUTOCAL                                                                                                                               \
        data_buffer_out[(i * OEM_ADCOUT_LEN) + 0] = (u8) (autocal[i] >> AUTOCAL_SHIFT);                                                           \
        data_buffer_out[(i * OEM_ADCOUT_LEN) + 1] = (u8) (data_buffer_out[(i * OEM_ADCOUT_LEN) + 1] & 0x0f) | (u8) (autocal[i] << AUTOCAL_SHIFT);

#define OEM_INTRTHRSLD                                                                                                                                 \
        data_buffer_out[(i * OEM_ADCOUT_LEN) + 0] = (u8) (interrupt[i] >> INTRTHRSLD_SHIFT);                                                           \
        data_buffer_out[(i * OEM_ADCOUT_LEN) + 1] = (u8) (data_buffer_out[(i * OEM_ADCOUT_LEN) + 1] & 0x0f) | (u8) (interrupt[i] << INTRTHRSLD_SHIFT);

#define OEM_I2C

#ifdef RELEASE_POLLED
#define OEM_RELEASE_INIT                                      \
        for (i = 0; i < NUM_SENSORS; i++)                     \
        {                                                     \
            ts->release_threshold[i] = OEM_RELEASE_THRESHOLD; \
        }

#define OEM_RELEASE_READ                             \
        if (ni_force_ts_get_data(ts->client) == 0)

#define OEM_RELEASE_SWITCH                            \
        if (ts->force[i] < ts->release_threshold[i])
#endif

#define OEM_REMOVE

