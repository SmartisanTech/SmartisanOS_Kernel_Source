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

#ifndef OEM_KITTY_H_
#define OEM_KITTY_H_

#define FORCE_SCREEN
#define REGISTER_INIT

/*
 * NUM_SENSORS is the number of sensors per client. A client
 * is defined as an I2C slave (e.g. AFE) that communicates with
 * a sensor. Feature-reduced FORCE_SCREEN drivers for MCU-based
 * solutions support one or more sensors per client.
 */

#define NUM_SENSORS                     4

#define DEVICE_NAME                     "ni_force"
#define DEVICE_TREE_NAME                "nif,ni_force"

#define NI_WRITE_PERMISSIONS            (S_IWUSR | S_IWGRP)

#define OEM_ID_VENDOR                   0x0101
#define OEM_ID_PRODUCT                  0x0101
#define OEM_ID_VERSION                  0x0101

#define OEM_DATE                        "MM DD YYYY"
#define OEM_TIME                        "HH:MM:SS"

#define OEM_ADC_DATA_MASK               0xfff
#define OEM_ADC_SIGN_MASK               0x800
#define OEM_MAX_AUTOCAL                 OEM_ADC_DATA_MASK
#define OEM_MAX_INTERRUPT               OEM_ADC_DATA_MASK

#define OEM_I2C_ATTEMPTS                1

#define OEM_IRQ_TRIGGER                 (IRQF_TRIGGER_FALLING | IRQF_ONESHOT)

#ifdef RELEASE_POLLED
#define OEM_RELEASE_THRESHOLD           150
#endif

#define OEM_EVENT_CUSTOM                250

#endif /* OEM_KITTY_H_ */

