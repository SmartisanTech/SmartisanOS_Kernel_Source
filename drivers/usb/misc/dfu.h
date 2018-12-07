#ifndef __DFU_H__
#define __DFU_H__

/* DFU Class-Specific Request Values */
#define DFU_GETVERSION		0x0
#define DFU_DNLOAD		0x1
#define DFU_UPLOAD		0x2
#define DFU_GETSTATUS		0x3
#define DFU_CLRSTATUS		0x4
#define DFU_GETSTATE		0x5
#define DFU_ABORT		0x6

/* DFU Device ID Values */
#define DEVICE_MCU_0		0x00A0
#define DEVICE_SMARTPA_1	0x00A1
#define DEVICE_SMARTPA_2	0x00A2
#define DEVICE_SMARTPA_3	0x00A3
#define DEVICE_CX20921		0x00A4
#define DEVICE_MCU_1		0x00B0
#define DEVICE_SCALER		0x00B1

/* MCU0 <-> DOWNSTREADM
 * MCU1 <-> UPSTREADM
 */
#define USB_DFU_VENDOR_ID			0x29A9
#define USB_DFU_DOWN_STREAM_PRODUCT_ID		0x8201
#define USB_DFU_UP_STREAM_PRODUCT_ID		0x8202

#define DFU_LOCAL_FW_SYS_PATH	"/vendor/firmware/"
#define MCU_DOWN_STREAM_FW	"mcu0.bin"
#define MCU_UP_STREAM_FW	"mcu1.bin"
#define SMART_PA_1_FW		"smartpa1.bin"
#define SMART_PA_2_FW		"smartpa2.bin"
#define SMART_PA_3_FW		"smartpa3.bin"
#define CX20921_FW		"cx20921.bin"
#define SCALER_FW		"scaler.bin"

#define USB_BLOCK_SIZE			4096
#define DEVICE_MCU_0_BIT_MASK		0x01
#define DEVICE_SMARTPA_1_BIT_MASK	0x02
#define DEVICE_SMARTPA_2_BIT_MASK	0x04
#define DEVICE_SMARTPA_3_BIT_MASK	0x08
#define DEVICE_CX20921_BIT_MASK		0x10
#define DEVICE_MCU_1_BIT_MASK		0x20
#define DEVICE_SCALER_BIT_MASK		0x40
#define DEVICE_ALL_BIT_MASK		0x7f


#endif
