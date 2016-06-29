#if 0
#if defined(CONFIG_TOUCHSCREEN_SHTSC_I2C)
#elif defined (CONFIG_TOUCHSCREEN_SHTSC_SPI)
#else // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
error
#endif // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
#endif /* 0 */

/*
 * Driver for sharp touch screen controller
 *
 * Copyright (c) 2013 Sharp Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/input.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/gpio.h>
#include <linux/input/mt.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/fs.h>
//#include <generated/uapi/linux/version.h>

// should be defined automatically
#define PINCTRL_ACTIVE_SUSPEND
#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#endif /* KERNEL_VERSION */

#ifndef LINUX_VERSION_CODE
#define LINUX_VERSION_CODE (KERNEL_VERSION(3,4,0)) //dp qualcomm
#endif /* LINUX_VERSION_CODE */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0))
#define __devinit
#define __devexit
#define __devexit_p
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)) */


//2014.10.16 added
#include <linux/string.h>
#include <linux/of_gpio.h>

#if defined(CONFIG_FB)
#include <linux/notifier.h>
#include <linux/fb.h>
#endif

#include <linux/ioctl.h>
#include <linux/miscdevice.h>
#include <asm/uaccess.h>

#include <linux/mutex.h>

#if defined(CONFIG_TOUCHSCREEN_SHTSC_I2C)
#include <linux/i2c.h>
#elif defined (CONFIG_TOUCHSCREEN_SHTSC_SPI)
#include <linux/spi/spi.h>
#else // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
error
#endif // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)

#include "shtsc_ioctl.h"
#include "shtsc.h"

#define DEVICE_LR388K5
//#define DEVICE_LR388K4

// device code
#define DEVICE_CODE_LR388K4 1
#define DEVICE_CODE_LR388K5 2

char VersionYear = 14;
char VersionMonth = 12;
char VersionDay = 02;
char VersionSerialNumber = 12; // reset on another day
#if defined (DEVICE_LR388K5)
char VersionModelCode = DEVICE_CODE_LR388K5;
#else
char VersionModelCode = DEVICE_CODE_LR388K4;
#endif
#define DRIVER_VERSION_LEN (5) // do not change

static int touch_once = 0;
static bool irq_disable = false;

static void resume_event(struct work_struct *work);
static void suspend_event(struct work_struct *work);
#if defined(CONFIG_TOUCHSCREEN_SHTSC_I2C)
static int shtsc_i2c_probe(struct i2c_client *client, const struct i2c_device_id *id);
static int shtsc_i2c_remove(struct i2c_client *client);
#else
static int shtsc_spi_probe(struct spi_device *spi);
static int shtsc_spi_remove(struct spi_device *spi);
#endif

/* Touch coordinates */
#define SHTSC_I2C_X_MIN		0
#define SHTSC_I2C_Y_MIN		0
#define SHTSC_I2C_X_MAX		(1080 -1) // 1080 for FHD
#define SHTSC_I2C_Y_MAX		(1920 -1) // 1920 for FHD
#if defined(DEVICE_LR388K5)
#define SHTSC_I2C_P_MAX		((1<<16)-1) //8000 // depends on firmware
#else
#define SHTSC_I2C_P_MAX		1023
#endif
#define SHTSC_I2C_SIZE_MAX		((1<<6)-1)

#define SHTSC_MAX_FINGERS 10

/* DEBUG */
#if 0
#ifndef DEBUG_SHTSC
#define DEBUG_SHTSC
#endif//DEBUG_SHTSC
#endif /* 0 */

#define DBGLOG(format, args...)  printk(KERN_INFO format, ## args)
#define ERRLOG(format, args...)  printk(KERN_ERR format, ## args)

#if defined (DEVICE_LR388K5)
/* INT STATUS */
#define SHTSC_STATUS_TOUCH_READY    (1<<0)
#define SHTSC_STATUS_POWER_UP       (1<<1)
#define SHTSC_STATUS_RESUME_PROX    (1<<2)
#define SHTSC_STATUS_WDT            (1<<3)
#define SHTSC_STATUS_DCMAP_READY    (1<<4)
#define SHTSC_STATUS_COMMAND_RESULT (1<<5)
#define SHTSC_STATUS_FLASH_LOAD_ERROR    (1<<8)
#define SHTSC_STATUS_PLL_UNLOCK    (1<<9)

/* DONE IND */
#define SHTSC_IND_CMD   0x20
#define SHTSC_IND_TOUCH 0x01

/* BANK Address */
#define SHTSC_BANK_TOUCH_REPORT   0x00
#define SHTSC_BANK_COMMAND        0x02
#define SHTSC_BANK_COMMAND_RESULT 0x03

/* Common Register Address */
#define SHTSC_ADDR_INT0  0x00
#define SHTSC_ADDR_INTMASK0 0x01
#define SHTSC_ADDR_BANK 0x02
#define SHTSC_ADDR_IND  0x03
#define SHTSC_ADDR_INT1  0x04
#define SHTSC_ADDR_INTMASK1 0x05

/* Touch Report Register Address */
#define SHTSC_ADDR_TOUCH_NUM 0x08
#define SHTSC_ADDR_RESUME_PROX 0x09
#define SHTSC_ADDR_TOUCH_REPORT 0x10

/* Touch Parmeters */
#define SHTSC_MAX_TOUCH_1PAGE 10
#define SHTSC_LENGTH_OF_TOUCH 8

/* Touch Status */
#define SHTSC_F_TOUCH ((u8)0x01)
#define SHTSC_F_TOUCH_OUT ((u8)0x03)
//#define SHTSC_P_TOUCH ((u8)0x02)
//#define SHTSC_P_TOUCH_OUT ((u8)0x04)

#define SHTSC_TOUCHOUT_STATUS ((u8)0x80)

#define SHTSC_ADDR_COMMAND 0x08

typedef enum _cmd_state_e {
  CMD_STATE_SLEEP         = 0x00,
  CMD_STATE_IDLE          = 0x03,
  CMD_STATE_DEEP_IDLE     = 0x04,
  CMD_STATE_HOVER         = 0x06,
  CMD_STATE_PROX          = 0x07,
  CMD_STATE_MAX
} dCmdState_e ;

typedef enum _cmd_CalibratioMode_e
{
  CMD_CALIB_MANUAL	  = 0x00,
  CMD_CALIB_START_OF_FORCE= 0x01,
  CMD_CALIB_END_OF_FORCE  = 0x02,
  CMD_CALIB_MAX
} dCmdCalibMode_e;

#define CMD_INIT              0x01
#define CMD_SETSYSTEM_STATE   0x02
#define CMD_EXEC_CALIBRATION  0x0F

#define CMD_PAYLOAD_LENGTH(X)              \
	X == CMD_INIT		?	0x04 : \
	X == CMD_SETSYSTEM_STATE?	0x04 : \
	X == CMD_EXEC_CALIBRATION?	0x04 : \
	0x0


#else // DEVICE_LR388K4

/* INT STATUS */
#define SHTSC_STATUS_TOUCH_READY    (1<<3)
#define SHTSC_STATUS_POWER_UP       (1<<1)
#define SHTSC_STATUS_COMMAND_RESULT (1<<0)

/* DONE IND */
#define SHTSC_IND_CMD   0x01
#define SHTSC_IND_TOUCH 0x10

/* BANK Address */
#define SHTSC_BANK_TOUCH_REPORT   0x18
#define SHTSC_BANK_COMMAND        0x16
#define SHTSC_BANK_COMMAND_RESULT 0x17

/* Common Register Address */
#define SHTSC_ADDR_INT0  0x00
#define SHTSC_ADDR_INTMASK0 0x01
#define SHTSC_ADDR_BANK 0x02
#define SHTSC_ADDR_IND  0x03
#define SHTSC_ADDR_INT1  0x04
#define SHTSC_ADDR_INTMASK1 0x05

/* Touch Report Register Address */
#define SHTSC_ADDR_TOUCH_NUM 0x08
#define SHTSC_ADDR_TOUCH_REPORT 0x0F

/* Touch Parmeters */
#define SHTSC_MAX_TOUCH_1PAGE 5
#define SHTSC_LENGTH_OF_TOUCH 9

/* Touch Status */
#define SHTSC_F_TOUCH ((u8)0x00)
#define SHTSC_F_TOUCH_OUT ((u8)0x04)
#define SHTSC_P_TOUCH ((u8)0x08)
#define SHTSC_P_TOUCH_OUT ((u8)0x0C)

#define SHTSC_TOUCHOUT_STATUS ((u8)0x08)

#include "k4_touch_ini.h"

#define SHTSC_ADDR_COMMAND 0x08

typedef enum _cmd_state_e {
  CMD_STATE_SLEEP         = 0x00,
  CMD_STATE_DEBUG         = 0x01,
  CMD_STATE_ACTIVE        = 0x02,
  CMD_STATE_IDLE          = 0x03,
  CMD_STATE_MAX
} dCmdState_e ;

typedef enum _cmd_CalibratioMode_e
{
  CMD_CALIB_MANUAL	  = 0x00,
  CMD_CALIB_START_OF_FORCE= 0x01,
  CMD_CALIB_END_OF_FORCE  = 0x02,
  CMD_CALIB_MAX
} dCmdCalibMode_e;

#define CMD_INIT              0x01
#define CMD_SETSYSTEM_STATE   0x02
#define CMD_EXEC_CALIBRATION  0x06
#define CMD_SETSCAN_CONFIG    0x11

#define CMD_PAYLOAD_LENGTH(X)              \
	X == CMD_INIT		?	0x04 : \
	X == CMD_SETSYSTEM_STATE?	0x04 : \
	X == CMD_EXEC_CALIBRATION?	0x04 : \
	X == CMD_SETSCAN_CONFIG	?	0x09 : \
	0x0


#endif // DEVICE_LR388K4

//2014.11.20 added
#define CMD_DELAY             16

#define WAIT_NONE   (0)
#define WAIT_CMD    (1)
#define WAIT_RESET  (2)


#define MAX_16BIT			0xffff
#define MAX_12BIT			0xfff

#define MAX_DCMAP_SIZE (37*37*2)

#define LOW_LEVEL 0
#define HIGH_LEVEL 1

#if defined (DEVICE_LR388K5)

/* ======== EEPROM command ======== */
#define	FLASH_CMD_WRITE_EN		(0x06)		/* Write enable command */
#define	FLASH_CMD_PAGE_WR			(0x02)		/* Page write command */
#define	FLASH_CMD_READ_ST			(0x05)		/* Read status command */
#define	FLASH_CMD_SECTOR_ERASE	(0xD7)		/* Sector erase command */
#define	FLASH_CMD_READ			(0x03)		/* Read command */

/* ======== EEPROM status ======== */
#define	FLASH_ST_BUSY		(1 << 0)	/* Busy with a write operation */

#else // DEVICE_LR388K4
// nothing 
#endif // DEVICE_LR388K4

#define SHTSC_COORDS_ARR_SIZE	4 //2014.10.17 added
/* Software reset delay */
#define SHTSC_RESET_TIME	250	/* msec */

#define FLASH_CHECK // experimental code - not checked yet

/*
 * The touch driver structure.
 */
struct shtsc_touch {
  u8 status;
  u8 id;
  u8 size;
  u8 type;
  u16 x;
  u16 y;
  u16 z;
};

#if defined(CONFIG_TOUCHSCREEN_SHTSC_I2C)
struct shtsc_i2c {
  u8 cmd;//2014.11.19 added
  u8 wait_state;//2014.11.19 added
  bool wait_result;//2014.11.19 added
  u8 disabled;		/* interrupt status */ //2014.11.6 added
  struct delayed_work resume_work;
  struct workqueue_struct *resume_wq;
  struct delayed_work suspend_work;
  struct workqueue_struct *suspend_wq;
  struct input_dev *input;
  struct shtsc_i2c_pdata *pdata;//2014.10.16 added
  char phys[32];
  struct i2c_client *client;
  int reset_pin;
  int irq_pin;
  struct shtsc_touch touch[SHTSC_MAX_FINGERS];
  struct mutex mutex;
#if defined(CONFIG_FB)
  struct notifier_block fb_notif;
  bool dev_sleep;
#endif

  unsigned int            max_num_touch;
  int                     min_x;
  int                     min_y;
  int                     max_x;
  int                     max_y;
  int                     pressure_max;
  int                     touch_num_max;
  bool                    flip_x;
  bool                    flip_y;
  bool                    swap_xy;
  struct pinctrl *ts_pinctrl;
  struct pinctrl_state *pinctrl_state_active;
  struct pinctrl_state *pinctrl_state_suspend;
  struct pinctrl_state *pinctrl_state_release;
};
#elif defined (CONFIG_TOUCHSCREEN_SHTSC_SPI)
struct shtsc_spi {
  u8 cmd;//2014.11.19 added
  u8 wait_state;//2014.11.19 added
  bool wait_result;//2014.11.19 added
  struct spi_device	*spi;
  struct shtsc_touch touch[SHTSC_MAX_FINGERS];
  struct input_dev	*input;

  char			phys[32];
  struct mutex		mutex;
  unsigned int		irq;
  int reset_pin;  
  int spiss_pin;  
  spinlock_t		lock;
  struct timer_list	timer;

  unsigned int            max_num_touch;
  int                     min_x;
  int                     min_y;
  int                     max_x;
  int                     max_y;
  bool                    flip_x;
  bool                    flip_y;
  bool                    swap_xy;

  bool			opened;
  bool			suspended;
};
#else // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
error
#endif // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)

#define SHTSC_DEVBUF_SIZE 1500

volatile static int buf_pos;
static u8 devbuf[SHTSC_DEVBUF_SIZE];

#if defined(DEVICE_LR388K5)
static void WriteMultiBytes(void *ts, u8 u8Addr, u8 *data, int len);
#endif
static void WriteOneByte(void *ts, u8 u8Addr, u8 u8Val);
static u8 ReadOneByte(void *ts, u8 u8Addr);
static void ReadMultiBytes(void *ts, u8 u8Addr, u16 u16Len, u8 *u8Buf);

u8 s_shtsc_addr;
u8 s_shtsc_buf[4*4096];
u8 s_shtsc_i2c_data[4*4096];
unsigned s_shtsc_len;

#define MAX_COMMAND_RESULT_LEN (64-8)
unsigned char CommandResultBuf[MAX_COMMAND_RESULT_LEN];

int	G_reset_done = false;
u16 G_Irq_Mask = 0xffff;
unsigned G_touch=0;

pid_t pid = 0;
unsigned char resumeStatus; // bank 0, address 9


#if defined(CONFIG_TOUCHSCREEN_SHTSC_I2C)
static int shtsc_write_regs(struct shtsc_i2c *tsc, unsigned char addr,
				unsigned char len, unsigned char *value)
{
  struct i2c_client *client = tsc->client;
  int ret;

  s_shtsc_i2c_data[0] = addr;
  memcpy(s_shtsc_i2c_data + 1, value, len);

  ret = i2c_master_send(client, s_shtsc_i2c_data, len + 1);

  return 0;
}

static int shtsc_read_regs(struct shtsc_i2c *tsc,
			       unsigned char *data, unsigned short len, unsigned char addr)
{
  struct i2c_client *client = tsc->client;
  //	int ret;
  u8 buf[256+512];

  buf[0] = addr;
  /* set reg addr to read out */
  if (i2c_master_send(client, buf, 1) != 1) {
    dev_err(&client->dev, "Unable to write i2c index\n");
    goto out;
  }

  /* Now do Page Read */
  i2c_master_recv(client, data, len);

  return 0;
 out:
  return -1;
}
#elif defined (CONFIG_TOUCHSCREEN_SHTSC_SPI)
static int shtsc_write_regs(struct shtsc_spi *tsc, u8 u8Addr, int len, u8 *data)
{
  u8 tx_buf[256+3];
  struct spi_message msg;
  struct spi_transfer t = {
    .tx_buf		= &tx_buf[0],
    .len		= (2+len),
    .bits_per_word	= 8,
    .speed_hz           = SHTSC_MAX_SPI_SPEED_IN_HZ,
  };
  int err;

  tx_buf[0] = 0x00;
  tx_buf[1] = u8Addr;
  memcpy(&(tx_buf[2]), data, len);

  spi_message_init(&msg);
  spi_message_add_tail(&t, &msg);
  err = spi_sync(tsc->spi, &msg);
  if (err) {
    dev_err(&tsc->spi->dev, "%s: failed, error: %d\n",
	    __func__, err);
    return err;
  }
  return 0;
}

static int shtsc_read_regs(struct shtsc_spi *tsc, u8 *u8Buf,  u16 u16Len, u8 u8Addr)
{
  u8 tx_buf[128];
  //  u8 tx_buf[128], rx_buf[512+128];
  struct spi_message msg;
  struct spi_transfer t = {
    .tx_buf		= &tx_buf[0],
    //    .rx_buf             = &rx_buf[0],
    .rx_buf             = &u8Buf[0],
    .len		= 2,
    .bits_per_word	= 8,
    .speed_hz           = SHTSC_MAX_SPI_SPEED_IN_HZ,
  };
  int err;
  int i;

  tx_buf[0] = 0x00;
  tx_buf[1] = u8Addr;

  spi_message_init(&msg);
  spi_message_add_tail(&t, &msg);
  err = spi_sync(tsc->spi, &msg);
  if (err) {
    dev_err(&tsc->spi->dev, "%s: failed, error: %d\n",
	    __func__, err);
    goto exitReadMultiBytes;
  }

  tx_buf[0] = 0x80;
  t.len = u16Len + 1;

  spi_message_init(&msg);
  spi_message_add_tail(&t, &msg);
  err = spi_sync(tsc->spi, &msg);
  if (err) {
    dev_err(&tsc->spi->dev, "%s: failed, error: %d\n",
	    __func__, err);
    goto exitReadMultiBytes;    
  }
  for(i = 0;i < u16Len;i++){
    u8Buf[i] = u8Buf[1 + i];
  }
  u8Buf[i] = 0; // not required. just for testing
  return 0;

 exitReadMultiBytes:  
  return err;
}
#else // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
error
#endif // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)

#if defined(DEVICE_LR388K5)
static void WriteMultiBytes(void *_ts, u8 u8Addr, u8 *data, int len)
{
#if defined(CONFIG_TOUCHSCREEN_SHTSC_I2C)
  struct shtsc_i2c *ts = _ts;
#elif defined (CONFIG_TOUCHSCREEN_SHTSC_SPI)
  struct shtsc_spi *ts = _ts;
#else // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
  error
#endif // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)

  shtsc_write_regs(ts, u8Addr, len, data);
}
#endif

static void WriteOneByte(void *_ts, u8 u8Addr, u8 u8Val)
{
#if defined(CONFIG_TOUCHSCREEN_SHTSC_I2C)
  struct shtsc_i2c *ts = _ts;
#elif defined (CONFIG_TOUCHSCREEN_SHTSC_SPI)
  struct shtsc_spi *ts = _ts;
#else // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
  error
#endif // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
  u8 wData[1];
  wData[0] = u8Val;

  shtsc_write_regs(ts, u8Addr, 1, wData);
}

static u8 ReadOneByte(void *_ts, u8 u8Addr)
{  
#if defined(CONFIG_TOUCHSCREEN_SHTSC_I2C)
  struct shtsc_i2c *ts = _ts;
#elif defined (CONFIG_TOUCHSCREEN_SHTSC_SPI)
  struct shtsc_spi *ts = _ts;
#else // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
  error
#endif // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
  u8 rData[1+1]; //requires one more byte to hold
  
  shtsc_read_regs(ts, rData, 1, u8Addr);
  return rData[0];
}

static void ReadMultiBytes(void *_ts, u8 u8Addr, u16 u16Len, u8 *u8Buf)
{
#if defined(CONFIG_TOUCHSCREEN_SHTSC_I2C)
  struct shtsc_i2c *ts = _ts;
#elif defined (CONFIG_TOUCHSCREEN_SHTSC_SPI)
  struct shtsc_spi *ts = _ts;
#else // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
error
#endif // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
  shtsc_read_regs(ts, u8Buf, u16Len, u8Addr);
}

static void SetBankAddr(void *_ts, u8 u8Bank)
{
#if defined(CONFIG_TOUCHSCREEN_SHTSC_I2C)
  struct shtsc_i2c *ts = _ts;
#elif defined (CONFIG_TOUCHSCREEN_SHTSC_SPI)
  struct shtsc_spi *ts = _ts;
#else // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
error
#endif // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)

  WriteOneByte(ts, SHTSC_ADDR_BANK, u8Bank);  
}

static u8 GetNumOfTouch(void *_ts)
{
#if defined(CONFIG_TOUCHSCREEN_SHTSC_I2C)
  struct shtsc_i2c *ts = _ts;
#elif defined (CONFIG_TOUCHSCREEN_SHTSC_SPI)
  struct shtsc_spi *ts = _ts;
#else // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
error
#endif // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
  u8 ret = 0;
  
  SetBankAddr(ts, SHTSC_BANK_TOUCH_REPORT);
#if defined(DEVICE_LR388K5)
  ret = ReadOneByte(ts, SHTSC_ADDR_TOUCH_NUM) & 0x0F;
#else //DEVICE_LR388K4
  ret = ReadOneByte(ts, SHTSC_ADDR_TOUCH_NUM) & 0x3F;
#endif
  return ret;
}

static u16 GetInterruptStatus(void *_ts)
{
#if defined(CONFIG_TOUCHSCREEN_SHTSC_I2C)
  struct shtsc_i2c *ts = _ts;
#elif defined (CONFIG_TOUCHSCREEN_SHTSC_SPI)
  struct shtsc_spi *ts = _ts;
#else // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
error
#endif // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
  u16 ret = 0;
  
  ret = (ReadOneByte(ts, SHTSC_ADDR_INT1) << 8)
    | ReadOneByte(ts, SHTSC_ADDR_INT0);

  return ret & G_Irq_Mask;
}

static void ClearInterrupt(void *_ts, u16 u16Val)
{
#if defined(CONFIG_TOUCHSCREEN_SHTSC_I2C)
  struct shtsc_i2c *ts = _ts;
#elif defined (CONFIG_TOUCHSCREEN_SHTSC_SPI)
  struct shtsc_spi *ts = _ts;
#else // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
error
#endif // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)

  WriteOneByte(ts, SHTSC_ADDR_INT0, (u16Val & 0x00FF));
  WriteOneByte(ts, SHTSC_ADDR_INT1, ((u16Val & 0xFF00) >> 8));
}

static void SetIndicator(void *_ts, u8 u8Val)
{
#if defined(CONFIG_TOUCHSCREEN_SHTSC_I2C)
  struct shtsc_i2c *ts = _ts;
#elif defined (CONFIG_TOUCHSCREEN_SHTSC_SPI)
  struct shtsc_spi *ts = _ts;
#else // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
error
#endif // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)

  WriteOneByte(ts, SHTSC_ADDR_IND, u8Val);
}

#if defined(DEVICE_LR388K4)
static int WaitAsync(void *_ts)
{
#if defined(CONFIG_TOUCHSCREEN_SHTSC_I2C)
  struct shtsc_i2c *ts = _ts;
#elif defined (CONFIG_TOUCHSCREEN_SHTSC_SPI)
  struct shtsc_spi *ts = _ts;
#else // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
  error
#endif // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)

  int i;
  for(i=0;i<50;i++) {
    mdelay(CMD_DELAY);//16ms
    DBGLOG("wait 16ms for state change\n");
    switch(ts->wait_state) {
    case WAIT_RESET:
      break;
    case WAIT_CMD:
      break;
    case WAIT_NONE:
      if (ts->wait_result == true) {
	DBGLOG("wait state change: success\n");
	return 0;
      }
      else
	return -EIO;
    default:
      break;
    }
  }
  DBGLOG("wait state change: failure\n");
  return -EIO;
}

#endif
#if defined(_DEVICE_LR388K4_)
static int shtsc_ts_command(void *ts, u8 *cmd, u8 len)
{
    int err = 0;

    // bank command
    SetBankAddr(ts, SHTSC_BANK_COMMAND);
    DBGLOG("bank command\n");

    // set command
    WriteMultiBytes(ts, SHTSC_ADDR_COMMAND, cmd, len);
    DBGLOG("set command (%x)\n",cmd[0]);

    // prepare waiting
    ((struct shtsc_i2c *)ts)->cmd = cmd[0];
    ((struct shtsc_i2c *)ts)->wait_state = WAIT_CMD;
    ((struct shtsc_i2c *)ts)->wait_result = true;

    // do it
    SetIndicator(ts, SHTSC_IND_CMD);
    DBGLOG("do it\n");

    // wait
    err = WaitAsync(ts);

    return err;
}


static int shtsc_CMD_Init(void *ts, u16 u16Sense, u16 u16Drive)
{
    u8 u8Buf[16] = {0};
    u16 u16Len = 0;

    u16Len = 0;
    u8Buf[u16Len++] = CMD_INIT;         // opcode (1)
    u8Buf[u16Len++] = 0x00;             // Reserved
    u8Buf[u16Len++] = CMD_PAYLOAD_LENGTH(CMD_INIT);      // Payload length(4)
    u8Buf[u16Len++] = 0x00;             // Reserved
    u8Buf[u16Len++] = ( u16Sense & 0xFF );			// LSB of Sense Parameter
    u8Buf[u16Len++] = (( u16Sense >> 8 ) & 0xFF );	// MSB of Sense Parameter
    u8Buf[u16Len++] = ( u16Drive & 0xFF );			// LSB of Drive Parameter
    u8Buf[u16Len++] = (( u16Drive >> 8 ) & 0xFF );	// MSB of Drive Parameter
  return shtsc_ts_command(ts, u8Buf, u16Len);
}

static int shtsc_CMD_SetSystemState(void *ts, dCmdState_e eState, bool bEnable, u16 u16Time)
{
    u8 u8Buf[16] = {0};
    u16 u16Len = 0;

    u8Buf[u16Len++] = CMD_SETSYSTEM_STATE;                    // opcode (2)
    u8Buf[u16Len++] = 0x00;                                   // Reserved
    u8Buf[u16Len++] = CMD_PAYLOAD_LENGTH(CMD_SETSYSTEM_STATE);// Payload length(4)
    u8Buf[u16Len++] = 0x00;                                   // Reserved
    u8Buf[u16Len++] = (u8)eState;                          // status of transtion
    u8Buf[u16Len++] = bEnable == true ? 0x1 : 0x0;        // Automatic transition indicator
    u8Buf[u16Len++] = (u16Time & 0xFF);                       // LSB of time parameter
    u8Buf[u16Len++] = (u16Time >> 8) & 0xFF;                  // MSB of time parameter

  return shtsc_ts_command(ts, u8Buf, u16Len);
}

static int shtsc_CMD_SetScanConfig(void *ts,  u8 u8Sync, u32 u32ActiveState, u32 u32IdleState )
{
    u8 u8Buf[16] = {0};
    u16 u16Len = 0;

    u8Buf[u16Len++] = CMD_SETSCAN_CONFIG;                       // opcode(17)
    u8Buf[u16Len++] = 0x00;                                     // Reserved
    u8Buf[u16Len++] = CMD_PAYLOAD_LENGTH(CMD_SETSCAN_CONFIG);   // Payload length
    u8Buf[u16Len++] = 0x00;                                     // Reserved
    u8Buf[u16Len++] = u8Sync;                                   // Sync
    u8Buf[u16Len++] = (u32ActiveState & 0xFF);                  // Active State(LSB)
    u8Buf[u16Len++] = ((u32ActiveState >> 8 ) & 0xFF);          // Active State
    u8Buf[u16Len++] = ((u32ActiveState >> 16 ) & 0xFF);         // Active State
    u8Buf[u16Len++] = ((u32ActiveState >> 24 ) & 0xFF);         // Active State(MSB)
    u8Buf[u16Len++] = (u32IdleState & 0xFF);                    // Idle State(LSB)
    u8Buf[u16Len++] = ((u32IdleState >> 8 ) & 0xFF);            // Idle State
    u8Buf[u16Len++] = ((u32IdleState >> 16 ) & 0xFF);           // Idle State
    u8Buf[u16Len++] = ((u32IdleState >> 24 ) & 0xFF);           // Idle State(MSB)

  return shtsc_ts_command(ts, u8Buf, u16Len);
}

static int shtsc_CMD_ExecCalibration(void *ts, u8 ucCalFactor, u16 uiFrameCnt, dCmdCalibMode_e eMode )
{
    u8 u8Buf[16] = {0};
    u16 u16Len = 0;

    u8Buf[u16Len++] = CMD_EXEC_CALIBRATION;                     // opcode(6)
    u8Buf[u16Len++] = 0x00;                                     // Reserved
    u8Buf[u16Len++] = CMD_PAYLOAD_LENGTH(CMD_EXEC_CALIBRATION); // Payload length
    u8Buf[u16Len++] = 0x00;                                     // Reserved
    u8Buf[u16Len++] = ucCalFactor;                              // cal Factor
    u8Buf[u16Len++] = (u8)( uiFrameCnt & 0xFF );             // Number of frame count (LSB)
    u8Buf[u16Len++] = (u8)(( uiFrameCnt >> 8 ) & 0xFF );     // Number of frame count (MSB)
    u8Buf[u16Len++] = (u8)eMode;                             // status of transtion

  return shtsc_ts_command(ts, u8Buf, u16Len);
}
#endif//DEVICE_LR388K4

static int shtsc_system_init(void *ts)
{
  /* PLL unlock - not used*/
  //  WriteOneByte(ts, SHTSC_ADDR_INTMASK1, (unsigned char)0x02);
  //  WriteOneByte(ts, (unsigned char)0x04, (unsigned char)0x02);
  struct input_dev *input_dev = ((struct shtsc_i2c *)ts)->input;
  unsigned int cnt;
#if 0
  int i;
  u8 txbuf[8];
  u8 rxbuf[8];
  for(i=0;i<10;i++) {
    txbuf[0] = 0x02;
    txbuf[1] = i;
    i2c_master_send(((struct shtsc_i2c *)ts)->client, txbuf,2);
    i2c_master_send(((struct shtsc_i2c *)ts)->client, txbuf,1);
    i2c_master_recv(((struct shtsc_i2c *)ts)->client, rxbuf,1);
    printk(KERN_INFO "i2c master: tx=0x%x, rx=0x%x\n",i,rxbuf[0]);
  }
#endif
#if defined(_DEVICE_LR388K4_)
  int i=0;
  int err = 0;

  err = shtsc_CMD_SetSystemState(ts,CMD_STATE_SLEEP,true,60000);
  if (err != 0)
    return -EIO;

  err = shtsc_CMD_Init(ts,0x19,0x27);
  if (err != 0)
    return -EIO;

  //  msleep(1000);

  for(i = 0;i < CMD_SIZE;i++) {
    // bank command
    SetBankAddr(ts, cmds[i].bank);
    // write one byte
    WriteOneByte(ts, cmds[i].reg, cmds[i].val);
  }

  err = shtsc_CMD_SetScanConfig(ts,0,0x9a12,0x9a12);
  if (err != 0)
    return -EIO;

  // msleep(1000);

  err = shtsc_CMD_SetSystemState(ts,CMD_STATE_ACTIVE,true,60000);
  if (err != 0)
    return -EIO;

  //msleep(1000);

  err = shtsc_CMD_ExecCalibration(ts,0x0,15,CMD_CALIB_START_OF_FORCE);
  if (err != 0)
    return -EIO;

  //msleep(1000);

  err = shtsc_CMD_ExecCalibration(ts,0x0,15,CMD_CALIB_END_OF_FORCE);
  if (err != 0)
    return -EIO;

  //msleep(1000);

#endif

  for(cnt=0; cnt < SHTSC_MAX_FINGERS; cnt++)
  {
	  input_mt_slot(input_dev, cnt);
	  input_mt_report_slot_state(input_dev, MT_TOOL_FINGER, false);
#if defined(DEBUG_SHTSC)
	  printk(KERN_INFO "shtsc_system_init() clear mt_slot(%d)\n",cnt);
#endif
  }
  input_report_key(input_dev, BTN_TOUCH, false );
  input_sync(input_dev);

  return 0;
}


static void GetTouchReport(void *ts, u8 u8Num)
{
#if defined(CONFIG_TOUCHSCREEN_SHTSC_I2C)
  struct shtsc_touch *touch = ((struct shtsc_i2c *)ts)->touch;
  struct input_dev *input_dev = ((struct shtsc_i2c *)ts)->input;
#elif defined (CONFIG_TOUCHSCREEN_SHTSC_SPI)
  struct shtsc_touch *touch = ((struct shtsc_spi *)ts)->touch;
  struct input_dev *input_dev = ((struct shtsc_spi *)ts)->input;
#else // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
  error
#endif // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)

  u8 u8Buf[128];
  int i;
  u8 ID,Status;
  int touchNum = 0;//2014.11.12 added

#if defined(CONFIG_TOUCHSCREEN_SHTSC_I2C)
  ReadMultiBytes((struct shtsc_i2c *)ts, SHTSC_ADDR_TOUCH_REPORT, SHTSC_LENGTH_OF_TOUCH * u8Num, u8Buf);
#elif defined (CONFIG_TOUCHSCREEN_SHTSC_SPI)
  ReadMultiBytes((struct shtsc_spi *)ts, SHTSC_ADDR_TOUCH_REPORT, SHTSC_LENGTH_OF_TOUCH * u8Num, u8Buf);
#else // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
  error
#endif // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)

    for(i = 0;i < u8Num;i++){
#if defined(DEVICE_LR388K5)
      Status = (u8Buf[i * SHTSC_LENGTH_OF_TOUCH] & 0xF0);
      touch[i].id = ID = u8Buf[i * SHTSC_LENGTH_OF_TOUCH] & 0x0F;    
      touch[i].size = u8Buf[i * SHTSC_LENGTH_OF_TOUCH + 1] & 0x3F;
      touch[i].type = (u8Buf[i * SHTSC_LENGTH_OF_TOUCH + 1] & 0xC0) >> 6;
      touch[i].x =
	(u8Buf[i * SHTSC_LENGTH_OF_TOUCH + 2] << 0) |
	(u8Buf[i * SHTSC_LENGTH_OF_TOUCH + 3] << 8);
      touch[i].y =
	(u8Buf[i * SHTSC_LENGTH_OF_TOUCH + 4] << 0) |
	(u8Buf[i * SHTSC_LENGTH_OF_TOUCH + 5] << 8);
      touch[i].z =
	(u8Buf[i * SHTSC_LENGTH_OF_TOUCH + 6] << 0) |
	(u8Buf[i * SHTSC_LENGTH_OF_TOUCH + 7] << 8);
#else
      touch[i].id = ID = u8Buf[i * SHTSC_LENGTH_OF_TOUCH];
      Status = (u8Buf[i * SHTSC_LENGTH_OF_TOUCH + 1] & 0x0F);
      touch[i].x =
	(u8Buf[i * SHTSC_LENGTH_OF_TOUCH + 2] << 0) |
	(u8Buf[i * SHTSC_LENGTH_OF_TOUCH + 3] << 8);
      touch[i].y =
	(u8Buf[i * SHTSC_LENGTH_OF_TOUCH + 4] << 0) |
	(u8Buf[i * SHTSC_LENGTH_OF_TOUCH + 5] << 8);
      touch[i].size = (u8Buf[i * SHTSC_LENGTH_OF_TOUCH + 6] >> 4) & 0x0F;
      touch[i].z =
	(u8Buf[i * SHTSC_LENGTH_OF_TOUCH + 7] << 0) |
	(u8Buf[i * SHTSC_LENGTH_OF_TOUCH + 8] << 8);
#endif    

#if 0 // no hover?
      if (!touch[i].z) {//14.11.28 added
	touch[i].z = 1;
      }
#endif /* 0 */

      pr_debug("shtsc ID=%2d, Status=%02x, Size=%3d, X=%5d, Y=%5d, z=%5d, num=%2d\n"
	     ,ID
	     ,Status
	     ,touch[i].size
	     ,touch[i].x
	     ,touch[i].y
	     ,touch[i].z
	     ,u8Num);

      input_mt_slot(input_dev, ID);
      if(Status & SHTSC_TOUCHOUT_STATUS){
	touch[i].status = SHTSC_F_TOUCH_OUT;
	input_mt_report_slot_state(input_dev, MT_TOOL_FINGER, false); // the 2nd parameter is DON'T CARE
	continue;
      }

      if(((struct shtsc_i2c *)ts)->swap_xy){//2014.11.12 added
	int tmp;
	tmp = touch[i].x;
	touch[i].x = touch[i].y;
	touch[i].y = tmp;
      }
      if(((struct shtsc_i2c *)ts)->flip_x){
	touch[i].x = (((struct shtsc_i2c *)ts)->max_x - touch[i].x) < 0 ? 0 : ((struct shtsc_i2c *)ts)->max_x - touch[i].x;
      }
      if(((struct shtsc_i2c *)ts)->flip_y){
	touch[i].y = (((struct shtsc_i2c *)ts)->max_y - touch[i].y) < 0 ? 0 : ((struct shtsc_i2c *)ts)->max_y - touch[i].y;
      }
      touchNum++;

      touch[i].status = SHTSC_F_TOUCH;
      input_mt_report_slot_state(input_dev, MT_TOOL_FINGER, true);

      input_report_abs(input_dev, ABS_MT_TOUCH_MAJOR, touch[i].size);
      input_report_abs(input_dev, ABS_MT_POSITION_X, touch[i].x);
      input_report_abs(input_dev, ABS_MT_POSITION_Y, touch[i].y);
      //input_report_abs(input_dev, ABS_MT_PRESSURE  , touch[i].z);
    }
  input_report_key(input_dev, BTN_TOUCH, touchNum?true:false );//2014.11.12 added
  input_sync(input_dev);

  if (touch_once == 0)
  {
	  printk("TP resume success\n");
	  touch_once = 1;
  }
}


#define GET_REPORT  // experimental

#ifdef GET_REPORT
#include <linux/time.h>

#define REP_SIZE (4+4+4+120)
#define MAX_REPORTS 14

unsigned char reportBuf[4+ MAX_REPORTS*REP_SIZE];
volatile unsigned char Mutex_GetReport = false;

#endif /* GET_REPORT */

u8 dcmapBuf[MAX_DCMAP_SIZE+128];
u8 dcmap[31*18*2+128]; // greater than 17*32*2

static irqreturn_t shtsc_irq_thread(int irq, void *_ts)
{
#if defined(CONFIG_TOUCHSCREEN_SHTSC_I2C)
  struct shtsc_i2c *ts = _ts;
#elif defined (CONFIG_TOUCHSCREEN_SHTSC_SPI)
  struct shtsc_spi *ts = _ts;
#else // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
  error
#endif // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)

  u16 u16status;
  u8 u8TotalTouchNum = 0;
  u8 u8Num = 0;
#if defined(DEVICE_LR388K5)
  u8 tmpbuf[128];
  u8 numDriveLine2, numSenseLine2;
  u8 num_adc_dmy[3];
#endif
  u8 buf[256+512];

#if defined(DEBUG_SHTSC)
  if (G_touch) {
    printk(KERN_INFO "[IRQ] shtsc touch-ready %d\n", G_touch);
  }
#endif

  if (irq_disable)
  {
	  return IRQ_HANDLED;
  }

  buf[0] = 0;
  /* set reg addr to read out */
  if (i2c_master_send(ts->client, buf, 1) != 1) {
	  printk("irq fail !!!!\n");
	  irq_disable = true;
	  return IRQ_HANDLED;
  }
  else
	  irq_disable = false;

#if defined(DEBUG_SHTSC)
  printk(KERN_INFO "[ENTER] shtsc_irq\n");
#endif

  if (! G_reset_done) {
    // On POR. not intended interrupt by RESET pin
    // mask everything
    WriteOneByte(ts, (unsigned char)SHTSC_ADDR_INTMASK0, (unsigned char)0xff);
    WriteOneByte(ts, (unsigned char)SHTSC_ADDR_INTMASK1, (unsigned char)0x03);
    // and clear them
    WriteOneByte(ts, (unsigned char)SHTSC_ADDR_INT0, (unsigned char)0xff);
    WriteOneByte(ts, (unsigned char)SHTSC_ADDR_INT1, (unsigned char)0x03);
    return IRQ_HANDLED;
  }

  /* Get Interrupt State */
  u16status = GetInterruptStatus(ts);
#if defined(DEBUG_SHTSC)
  if ((u16status != 0x0001) && (u16status != 0x0000)) {
    printk(KERN_CRIT "[IRQ] shtsc_irq: %04X\n", u16status);
  }
#endif
	
  while(u16status != 0){
#if defined(DEVICE_LR388K5)
    if (u16status & SHTSC_STATUS_PLL_UNLOCK) {
      //
      // PLL unlock
      //

#if defined(DEBUG_SHTSC)
      printk(KERN_INFO "[IRQ] shtsc_irq PLL_UNLOCK: %04X\n", u16status);
#endif
#if defined(DEBUG_SHTSC)
      printk(KERN_INFO "[IRQ] shtsc pll-unlock\n");
#endif
      // mask it
      WriteOneByte(ts, (unsigned char)SHTSC_ADDR_INTMASK1, (unsigned char)0x03);
      // from now on, no int for this
      G_Irq_Mask &= ~SHTSC_STATUS_PLL_UNLOCK;

      /* Clear Interrupt */
      ClearInterrupt(ts, SHTSC_STATUS_PLL_UNLOCK);
      u16status &= ~SHTSC_STATUS_PLL_UNLOCK;

#if defined(DEBUG_SHTSC)
      printk(KERN_INFO "[IRQ] shtsc_irq PLL_UNLOCK: %04X\n", u16status);
#endif
    }

    if (u16status & SHTSC_STATUS_POWER_UP) {
      //
      // Power-up
      //

#if defined(DEBUG_SHTSC)
      printk(KERN_INFO "[IRQ] shtsc power-up\n");
#endif

      /* Clear Interrupt */
      ClearInterrupt(ts, SHTSC_STATUS_POWER_UP);
      u16status &= ~SHTSC_STATUS_POWER_UP;
    }

    if (u16status & SHTSC_STATUS_WDT) {
      ClearInterrupt(ts, SHTSC_STATUS_WDT);
      u16status &= ~SHTSC_STATUS_WDT;
      ERRLOG("[IRQ] shtsc_irq WDT");
    }

    if (u16status & SHTSC_STATUS_RESUME_PROX) {
      //
      // Resume from DeepIdle
      // or
      // PROXIMITY
      //
      
#if defined(DEBUG_SHTSC)
      printk(KERN_INFO "[IRQ] shtsc resume from DeepIdle or prox\n");
#endif

      SetBankAddr(ts, SHTSC_BANK_TOUCH_REPORT);
      resumeStatus = ReadOneByte(ts, SHTSC_ADDR_RESUME_PROX);

      // throw interrupt to userland
#if 1
    {
      struct siginfo info;
      struct task_struct *task;
      
      memset(&info, 0, sizeof(struct siginfo));
      info.si_signo = SHTSC_SIGNAL;
      info.si_code = SI_QUEUE;
      info.si_int = 0;

      rcu_read_lock();
      task = find_task_by_vpid(pid);
      rcu_read_unlock();

#if 0
      if( !task ) {
	ret = -ENODEV;
      } else {
	ret = send_sig_info(SHTSC_SIGNAL, &info, task); //send signal to user land
      }
#else /* 0 */
      if (task) {
	send_sig_info(SHTSC_SIGNAL, &info, task); //send signal to user land
	printk(KERN_INFO "[SIGNAL] sending shtsc signal (resume_prox)\n");
      }
#endif /* 0 */
    }
#endif /* 1 */
 
      /* Clear Interrupt */
      ClearInterrupt(ts, SHTSC_STATUS_RESUME_PROX);
      u16status &= ~SHTSC_STATUS_RESUME_PROX;
    }

    if (u16status & SHTSC_STATUS_FLASH_LOAD_ERROR) {
      //
      // FLASH_LOAD_ERROR
      // occurs when flash is erased
      // nothing can be done
      //
#if defined(DEBUG_SHTSC)
      printk(KERN_INFO "[IRQ] shtsc flash load error\n");
#endif
      // from now on, no int for this
      G_Irq_Mask &= ~SHTSC_STATUS_FLASH_LOAD_ERROR;

      /* Clear Interrupt */
      ClearInterrupt(ts, SHTSC_STATUS_FLASH_LOAD_ERROR);
      u16status &= ~SHTSC_STATUS_FLASH_LOAD_ERROR;
    }


    if (u16status & SHTSC_STATUS_COMMAND_RESULT) {
#if defined(DEBUG_SHTSC)
      printk(KERN_INFO "[IRQ] shtsc command result\n");
#endif
      WriteOneByte(ts, (unsigned char)0x02, (unsigned char)SHTSC_BANK_COMMAND_RESULT); // bank change reg
      ReadMultiBytes(ts, 0x08, MAX_COMMAND_RESULT_LEN, CommandResultBuf); // always read entire result. TEGAPP will handle it.

#if defined(DEBUG_SHTSC)
      printk(KERN_INFO "[IRQ] shtsc command result, %02X, %02X\n", CommandResultBuf[0], CommandResultBuf[1]);
#endif
      /* Clear Interrupt */
      ClearInterrupt(ts, SHTSC_STATUS_COMMAND_RESULT);
      u16status &= ~SHTSC_STATUS_COMMAND_RESULT;
    }

    if (u16status & SHTSC_STATUS_DCMAP_READY) {
#if defined(DEBUG_SHTSC)
      printk(KERN_INFO "[IRQ] shtsc DCMAP READY\n");
#endif
      /* Clear Interrupt */
      ClearInterrupt(ts, SHTSC_STATUS_DCMAP_READY);
      u16status &= ~SHTSC_STATUS_DCMAP_READY;

      { // L2
	unsigned char dsFlag, readingSenseNum;
	unsigned vramAddr;
	unsigned readingSize;

	// get SD/DS and size
	WriteOneByte(ts, (unsigned char)0x06, (unsigned char)0x58);    
	WriteOneByte(ts, (unsigned char)0x07, (unsigned char)0xBF);    

	WriteOneByte(ts, (unsigned char)0x02, (unsigned char)0x05); // bank change reg
	ReadMultiBytes(ts, 0x08, 5, tmpbuf);

	numSenseLine2 = tmpbuf[0];
	numDriveLine2 = tmpbuf[1];

	dsFlag = tmpbuf[4]; // 1 for DS, 0 for SD
	vramAddr = ((tmpbuf[3]<<8) | tmpbuf[2]);
	// readingSenseNum is greater or equal to itself, but a multiply of 4
	readingSenseNum = (unsigned char)((numSenseLine2+3)/4); // not a double but int
	readingSenseNum *= 4;

	readingSize = readingSenseNum * numDriveLine2 * 2; /* 2:16bit */

	num_adc_dmy[0] = num_adc_dmy[2] = 0; //top and left have no 0-filled lines
	num_adc_dmy[1] = readingSenseNum - numSenseLine2; //right side

	//	      printk(KERN_INFO "%s(%d): num_adc_dmy[1]:%d\n", __FILE__, __LINE__, num_adc_dmy[1]);
	//	      printk(KERN_INFO "%s(%d):Sense:%d, Drive:%d\n", __FILE__, __LINE__, numSenseLine2, numDriveLine2);
	//	      printk(KERN_INFO "%s(%d): dsFlag:%d\n", __FILE__, __LINE__, dsFlag);

	WriteOneByte(ts, (unsigned char)0x02, (unsigned char)0x0C); // bank change reg
	WriteOneByte(ts, (unsigned char)0x4B, (unsigned char)0x05); // Blue ON

	// read DCmap values from register
	// store it to read buffer memory for read action
	{ // L1
	  /* read 120 bytes from Bank5, address 8 */
	  /* read loop required */
	  int bytes = readingSize;
	  int size;
	  int index = 0;
	  WriteOneByte(ts, (unsigned char)0x02, (unsigned char)0x05); // bank change reg

	  //	      printk(KERN_INFO "%s(%d):readingSize:%d\n", __FILE__, __LINE__, readingSize);
	  while (bytes > 0) {
	    WriteOneByte(ts, (unsigned char)0x06, (unsigned char)(vramAddr&0xff)); // address to read (Lower)
	    WriteOneByte(ts, (unsigned char)0x07, (unsigned char)((vramAddr&0xff00)>>8)); // address to read (Higher)

	    size = ((bytes >= 120) ? 120 : bytes);
	    //		printk(KERN_INFO "%s(%d):bytes:%d, size:%d, index:%d, vramAddr:%x\n", __FILE__, __LINE__, bytes, size, index, vramAddr);

	    ReadMultiBytes(ts, 0x08, size, &(dcmapBuf[index]));
	    index += size;
	    bytes -= size;
	    vramAddr += size;
	  } // while
	} // L1

	WriteOneByte(ts, (unsigned char)0x02, (unsigned char)0x0C); // bank change reg
	WriteOneByte(ts, (unsigned char)0x4B, (unsigned char)0x00); // Blue OFF

#if 0
	printk(KERN_INFO "DCmap Drive x Sense: %d x %d, dsFlag:%02X, num_adc_dmy:%02X %02X %02X\n", numDriveLine2, numSenseLine2, dsFlag, num_adc_dmy[0], num_adc_dmy[1], num_adc_dmy[2]);
#endif /* 0 */

	{ //L3
	  int sindex = 0, dindex = 0;
	  int l, x, y;
#if 0 // debug
	  static unsigned char frm_count = 0;
#endif /* 1 */

	  // dcmap header
	  // [0]: horizontal data num (in short, not byte)
	  // [1]: vertical data num

	  x = dcmap[dindex++] = numSenseLine2;
	  y = dcmap[dindex++] = numDriveLine2;
	  dcmap[dindex++] = dsFlag;
#if 0 // debug
	  dcmap[dindex++] = frm_count++; // just for debug
#else /* 1 */
	  dcmap[dindex++] = 0x00; // reserved
#endif /* 1 */

	  //top
	  sindex = (num_adc_dmy[0] + x + num_adc_dmy[1]) * num_adc_dmy[2] * 2;

	  // contents line
	  for (l = 0; l < y; l++) {
	    // left
	    sindex += (num_adc_dmy[0] * 2);

	    // contents
	    memcpy((u8 *)&(dcmap[dindex]), (u8 *)&(dcmapBuf[sindex]), (x*2));
	    dindex += (x*2);
	    sindex += (x*2);
		
	    // right
	    sindex += (num_adc_dmy[1] * 2);
	  }

	  // for read()
	  //	      printk(KERN_INFO "check buf_pos: %d\n", buf_pos);
	  if (buf_pos == 0) {
	    memcpy((u8 *)devbuf, (u8 *)dcmap, (4+x*y*2));
	    //		printk(KERN_INFO "setting buf_pos: %d\n", buf_pos);
	    buf_pos = (4+x*y*2);
	    //		printk(KERN_INFO "set buf_pos: %d\n", buf_pos);
	  }

#if 0 // DCmap debug
	  printk(KERN_INFO "DC map size HxV: %d x %d = %d\n", dcmap[0], dcmap[1], dcmap[0]*dcmap[1]);
	  printk(KERN_INFO "[0-3, %d-%d]: %02X %02X %02X %02X, %02X %02X %02X %02X\n", (x*y-4), (x*y-1), dcmap[4], dcmap[5], dcmap[6], dcmap[7], dcmap[x*y*2+4-4], dcmap[x*y*2+4-3], dcmap[x*y*2+4-2], dcmap[x*y*2+4-1]);
#endif /* 0 */
#if 0 // DCmap debug
	  for (j = 0; j < y; j++) {
	    for (i = 0; i < x; i++) {
	      printk(KERN_INFO "%d: %02X ", (y*j+i), dcmap[y*j + i + 4]);
	    }
	    printk(KERN_INFO "\n");
	  }
#endif
	} //L3
      } // L2 DEVICE_LR388K5 block
      //*************************
    }
#else //DEVICE_LR388K4
    if (u16status & SHTSC_STATUS_POWER_UP) {
      //
      // Power-up
      //

#if defined(DEBUG_SHTSC)
      printk(KERN_INFO "[IRQ] shtsc power-up\n");
#endif

      /* Clear Interrupt */
      ClearInterrupt(ts, SHTSC_STATUS_POWER_UP);
      u16status &= ~SHTSC_STATUS_POWER_UP;

      if (ts->wait_state == WAIT_RESET) {//2014.11.20 added
	ts->wait_state = WAIT_NONE;
	ts->wait_result = true;
      }
    }
    if (u16status & SHTSC_STATUS_COMMAND_RESULT) {
#if defined(DEBUG_SHTSC)
      printk(KERN_INFO "[IRQ] shtsc command result\n");
#endif
      WriteOneByte(ts, (unsigned char)0x02, (unsigned char)SHTSC_BANK_COMMAND_RESULT); // bank change reg
      ReadMultiBytes(ts, 0x08, MAX_COMMAND_RESULT_LEN, CommandResultBuf); // always read entire result. TEGAPP will handle it.

#if defined(DEBUG_SHTSC)
      printk(KERN_INFO "[IRQ] shtsc command result, %02X, %02X\n", CommandResultBuf[0], CommandResultBuf[1]);
#endif
      /* Clear Interrupt */
      ClearInterrupt(ts, SHTSC_STATUS_COMMAND_RESULT);
      u16status &= ~SHTSC_STATUS_COMMAND_RESULT;
	DBGLOG("command result:0x%x 0x%x 0x%x 0x%x 0x%x 0x%x\n",CommandResultBuf[0],CommandResultBuf[1],CommandResultBuf[2],CommandResultBuf[3],CommandResultBuf[4],CommandResultBuf[5]);

	if ((CommandResultBuf[0] != ts->cmd) || (CommandResultBuf[1] != 0)) {
	  ERRLOG("%s: bad resul, cmd=%x, rx=%x,%x\n", __func__,ts->cmd,CommandResultBuf[0],CommandResultBuf[1]);
	}
	if (ts->wait_state == WAIT_CMD) {
	  if ((CommandResultBuf[0] != ts->cmd) || (CommandResultBuf[1] != 0)) {
	    ts->wait_state = WAIT_NONE;
	    ts->wait_result = false;
	  } else {
	    ts->wait_state = WAIT_NONE;
	    ts->wait_result = true;
	  }
	}
    }
#endif //DEVICE_LR388K4
    if (u16status & SHTSC_STATUS_TOUCH_READY) {
      //
      // Touch report
      //

      /* Clear Interrupt */
      ClearInterrupt(ts, SHTSC_STATUS_TOUCH_READY);	    
      u16status &= ~SHTSC_STATUS_TOUCH_READY;
#if defined(DEBUG_SHTSC)
      printk(KERN_INFO "[IRQ] shtsc touch-ready cleared\n");
#endif


#ifdef GET_REPORT
      {
	/*
	  header:
	  1: counts of report (not a number of touch)
	  3: reserved

	  repeated contents if "counts of report"  is more than one.
	  1: cyclic counter (from 0 to 255. return to zero on next to 255)
	  3: reserved
	  4: report time (sec)
	  4: report time (usec)
	  120: bank0 report
	*/

	static unsigned char cyclic = 255;
	volatile unsigned char count;
	unsigned char bank0[120];
	struct timeval tv;

	while (Mutex_GetReport)
	  ;

	Mutex_GetReport = true;

	count = reportBuf[0];

	if (cyclic == 255) {
	  cyclic = 0;
	} else {
	  cyclic++;
	}
	
#if defined(DEBUG_SHTSC)
	//	printk(KERN_INFO "touch report: count %d, cyclic %d\n", count, cyclic);
#endif
	if (count == MAX_REPORTS) {
	  //	  printk(KERN_INFO "touch report buffer full\n");
	  ;
	} else {	
	  do_gettimeofday(&tv);
#if defined(DEBUG_SHTSC)
	  //	  printk(KERN_INFO "touch time: %ld.%ld, bank0pos:%d\n", (long)tv.tv_sec, (long)tv.tv_usec, (1+3+ count*REP_SIZE + 12));
#endif

	  reportBuf[1+3+ count*REP_SIZE +0] = cyclic;
	  reportBuf[1+3+ count*REP_SIZE +1] = 0;
	  reportBuf[1+3+ count*REP_SIZE +2] = 0;
	  reportBuf[1+3+ count*REP_SIZE +3] = 0;

	  reportBuf[1+3+ count*REP_SIZE +4+0] = (tv.tv_sec & 0xff);
	  reportBuf[1+3+ count*REP_SIZE +4+1] = ((tv.tv_sec >> 8) & 0xff);
	  reportBuf[1+3+ count*REP_SIZE +4+2] = ((tv.tv_sec >> 16) & 0xff);
	  reportBuf[1+3+ count*REP_SIZE +4+3] = ((tv.tv_sec >> 24) & 0xff);

	  reportBuf[1+3+ count*REP_SIZE +4+4+0] = (tv.tv_usec & 0xff);
	  reportBuf[1+3+ count*REP_SIZE +4+4+1] = ((tv.tv_usec >> 8) & 0xff);
	  reportBuf[1+3+ count*REP_SIZE +4+4+2] = ((tv.tv_usec >> 16) & 0xff);
	  reportBuf[1+3+ count*REP_SIZE +4+4+3] = ((tv.tv_usec >> 24) & 0xff);
	
	  SetBankAddr(ts, SHTSC_BANK_TOUCH_REPORT);
	  ReadMultiBytes(ts, 0x08, 120, bank0);

	  memcpy((unsigned char *)(&reportBuf[1+3+ count*REP_SIZE + 12]), (unsigned char *)bank0, 120);
	  reportBuf[0] = (unsigned char)(count+1);
	}

	Mutex_GetReport = false;
      }
#endif /* GET_REPORT */


      /* Get number of touches */
      {
	u8Num = GetNumOfTouch(ts);
	      
#if defined(DEBUG_SHTSC)
	printk(KERN_INFO "shtsc touch num=%d\n", u8Num);
#endif

	if(u8TotalTouchNum == 0)
	  u8TotalTouchNum = u8Num;

	if(u8Num == 0)
	  u8Num = u8TotalTouchNum;
	      
	if(SHTSC_MAX_TOUCH_1PAGE < u8TotalTouchNum){
	  u8Num = SHTSC_MAX_TOUCH_1PAGE;
	  u8TotalTouchNum -= SHTSC_MAX_TOUCH_1PAGE;
	}else{
	  u8TotalTouchNum = 0;
	}
	      
	/* Retrieve touch report */
	if (u8Num > 0)//2014.11.4 changed
	  GetTouchReport(ts, u8Num);

	/* Indicate done */
	SetIndicator(ts, SHTSC_IND_TOUCH);
      }
    }
    if (u16status != 0) {
      printk(KERN_INFO "[IRQ] shtsc unknown interrupt status %04X\n", u16status);
      /* Clear all interrupts and mask.  */
      WriteOneByte(ts, (unsigned char)SHTSC_ADDR_INTMASK0, (unsigned char)0xFF);
#if defined(DEVICE_LR388K5)
      WriteOneByte(ts, (unsigned char)SHTSC_ADDR_INTMASK1, (unsigned char)0x03);
#endif
      u16status = 0;
      ClearInterrupt(ts, u16status);
    }
  }

  if (u8Num != 0 && u8TotalTouchNum == 0) {
#if defined(DEBUG_SHTSC)
    printk(KERN_INFO "shtsc flush touch input(%d)\n", u8Num);
#endif
    /*
      input_report_key(ts->input, BTN_TOUCH, touchNum?true:false );
		
      input_sync(ts->input);
    */
  }

  return IRQ_HANDLED;
}


static ssize_t 
dev_read( struct file* filp, char* buf, size_t count, loff_t* pos )
{
  int copy_len;
  int i;

  //	printk( KERN_INFO "shtsc : read()  called, buf_pos: %d, count: %d\n", buf_pos, count);
  if ( count > buf_pos )
    copy_len = buf_pos;
  else
    copy_len = count;

  //	printk( KERN_INFO "shtsc : copy_len = %d\n", copy_len );
  if ( copy_to_user( buf, devbuf, copy_len ) ) {
    printk( KERN_INFO "shtsc : copy_to_user failed\n" );
    return -EFAULT;
  }

  *pos += copy_len;

  for ( i = copy_len; i < buf_pos; i ++ )
    devbuf[ i - copy_len ] = devbuf[i];

  buf_pos -= copy_len;

  //	printk( KERN_INFO "shtsc : buf_pos = %d\n", buf_pos );
  return copy_len;
}

static void shtsc_reset(void *_ts, bool reset)
{
#if defined(CONFIG_TOUCHSCREEN_SHTSC_I2C)
  struct shtsc_i2c *ts = _ts;
#elif defined (CONFIG_TOUCHSCREEN_SHTSC_SPI)
  struct shtsc_spi *ts = _ts;
#else // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
  error
#endif // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)

    if (ts->reset_pin) {
      G_reset_done = reset;
      gpio_direction_output(ts->reset_pin, reset);
      if (! reset) {
	G_Irq_Mask = 0xffff;
      }
    }
}

#if defined(DEVICE_LR388K5)
int flash_access_start_shtsc(void *_ts)
{
#if defined(CONFIG_TOUCHSCREEN_SHTSC_I2C)
  struct shtsc_i2c *ts = _ts;
#elif defined (CONFIG_TOUCHSCREEN_SHTSC_SPI)
  struct shtsc_spi *ts = _ts;
#else // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
  error
#endif // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)

    // mask everything
    WriteOneByte(ts, (unsigned char)SHTSC_ADDR_INTMASK0, (unsigned char)0xff);
  WriteOneByte(ts, (unsigned char)SHTSC_ADDR_INTMASK1, (unsigned char)0x03);
  msleep(100);

  /* TRIM_OSC = 0 */
  WriteOneByte(ts, (unsigned char)0x02, (unsigned char)0x18); // bank change reg
  WriteOneByte(ts, (unsigned char)0x11, (unsigned char)0x19);
  return 0;
}

int flash_access_end_shtsc(void *_ts)
{
#if defined(CONFIG_TOUCHSCREEN_SHTSC_I2C)
  struct shtsc_i2c *ts = _ts;
#elif defined (CONFIG_TOUCHSCREEN_SHTSC_SPI)
  struct shtsc_spi *ts = _ts;
#else // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
  error
#endif // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)

    msleep(100);

  shtsc_reset(ts, false);
  msleep(100);
  shtsc_reset(ts, true);
  msleep(10);
  shtsc_system_init(ts);

  msleep(100);

  return 0;
}

#define RETRY_COUNT (2000*10) //experimental
int flash_erase_page_shtsc(void *_ts, int page)
{
#if defined(CONFIG_TOUCHSCREEN_SHTSC_I2C)
  struct shtsc_i2c *ts = _ts;
#elif defined (CONFIG_TOUCHSCREEN_SHTSC_SPI)
  struct shtsc_spi *ts = _ts;
#else // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
  error
#endif // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)

    //  int chan= 0;
    volatile unsigned char readData;
  int retry=0;

  /* BankChange */
  //SPI_ArrieRegWrite(0x02,0x1C);
  WriteOneByte(ts, (unsigned char)0x02, (unsigned char)0x1C); // bank change reg

  /* CLKON_CTL0 */
  //SPI_ArrieRegWrite(0x14,0x22);	/* CLKON_FLC,CLKON_REGBUS */
  WriteOneByte(ts, (unsigned char)0x14, (unsigned char)0x22);

  /* FLC_CTL CS_HIGH,WP_DISABLE */
  //	SPI_ArrieRegWrite(0x3C,0x14);
  WriteOneByte(ts, (unsigned char)0x3C, (unsigned char)0x14);

  /* FLC_CTL CS_LOW,WP_DISABLE */
  //	SPI_ArrieRegWrite(0x3C,0x16);
  WriteOneByte(ts, (unsigned char)0x3C, (unsigned char)0x16);
  /* FLC_TxDATA WRITE_ENABLE */
  //SPI_ArrieRegWrite(0x3D,SPI_CMD_WRITE_EN);
  WriteOneByte(ts, (unsigned char)0x3D, (unsigned char)FLASH_CMD_WRITE_EN);
  /* FLC_CTL CS_HIGH,WP_DISABLE */
  //	SPI_ArrieRegWrite(0x3C,0x14);
  WriteOneByte(ts, (unsigned char)0x3C, (unsigned char)0x14);

  /* FLC_CTL CS_LOW,WP_DISABLE */
  //	SPI_ArrieRegWrite(0x3C,0x16);
  WriteOneByte(ts, (unsigned char)0x3C, (unsigned char)0x16);


  /* FLC_TxDATA CHIP_ERASE_COMMAND */
  //	SPI_ArrieRegWrite(0x3D,SPI_CMD_CHIP_ERASE);
  // not a chip erase, but a sector erase for the backward compatibility!!
  WriteOneByte(ts, (unsigned char)0x3D, (unsigned char)FLASH_CMD_SECTOR_ERASE);
  // 24bit address. 4kByte=001000H. 00x000H:x=0-f -> 4kB*16=64kB
  WriteOneByte(ts, (unsigned char)0x3D, (unsigned char)0x00);
  WriteOneByte(ts, (unsigned char)0x3D, (unsigned char)((page<<4)&0xFF));
  WriteOneByte(ts, (unsigned char)0x3D, (unsigned char)0x00);

  /* FLC_CTL CS_HIGH,WP_DISABLE */
  //	SPI_ArrieRegWrite(0x3C,0x14);
  WriteOneByte(ts, (unsigned char)0x3C, (unsigned char)0x14);


  /* wait until 'BUSY = LOW' */
  do {
    retry++;
    ////		msleep(10);
    if (retry > RETRY_COUNT)
      goto RETRY_ERROR;

    /* FLC_CTL CS_LOW,WP_DISABLE */
    //		SPI_ArrieRegWrite(0x3C,0x16);
    WriteOneByte(ts, (unsigned char)0x3C, (unsigned char)0x16);
    /* FLC_TxDATA READ_STATUS_COMMAND*/
    //		SPI_ArrieRegWrite(0x3D,SPI_CMD_READ_ST);
    WriteOneByte(ts, (unsigned char)0x3D, FLASH_CMD_READ_ST);
    /* Dummy data */
    //		SPI_ArrieRegWrite(0x3D,0);
    WriteOneByte(ts, (unsigned char)0x3D, (unsigned char)0x00);
    /* FLC_RxDATA */
    //		readData = SPI_ArrieRegRead(0x3F);
    readData = ReadOneByte(ts, 0x3F);
    /* FLC_CTL CS_HIGH,WP_DISABLE */
    //		SPI_ArrieRegWrite(0x3C,0x14);
    WriteOneByte(ts, (unsigned char)0x3C, (unsigned char)0x14);
  } while (readData & FLASH_ST_BUSY); 		/* check busy bit */

  return 0;

 RETRY_ERROR:
  printk(KERN_INFO "FATAL: flash_erase_page_shtsc retry %d times for page %d - FAILED!\n", retry, page);
  return 1;
}
#define FLASH_PAGE_SIZE (4<<10) // 4k block for each page
#define FLASH_PHYSICAL_PAGE_SIZE (256) // can write 256bytes at a time.

int flash_write_page_shtsc(void *_ts, int page, unsigned char *data)
{
#if defined(CONFIG_TOUCHSCREEN_SHTSC_I2C)
  struct shtsc_i2c *ts = _ts;
#elif defined (CONFIG_TOUCHSCREEN_SHTSC_SPI)
  struct shtsc_spi *ts = _ts;
#else // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
  error
#endif // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)

    //  int chan = 0;
    int retry = 0;
  //  unsigned addr; // in-page address (from 0 to FLASH_PAGE_SIZE-1)
  unsigned paddr; // address (32 or 64kB area)
  volatile unsigned char readData;
  int cnt, idx;

  /* BankChange */
  //	SPI_ArrieRegWrite(0x02,0x1C);
  WriteOneByte(ts, (unsigned char)0x02, (unsigned char)0x1C); // bank change reg

  /* CLKON_CTL0 */
  //	SPI_ArrieRegWrite(0x14,0x22);	/* CLKON_FLC,CLKON_REGBUS */
  WriteOneByte(ts, (unsigned char)0x14, (unsigned char)0x22);

  /* FLC_CTL */
  //	SPI_ArrieRegWrite(0x3C,0x14);
  WriteOneByte(ts, (unsigned char)0x3C, (unsigned char)0x14);

  /* 256 bytes / Flash write page, 4kByte / logical(virtual) flash page */
  for (cnt = 0; cnt < (FLASH_PAGE_SIZE / FLASH_PHYSICAL_PAGE_SIZE); cnt++) {
    paddr = (page * FLASH_PAGE_SIZE) + (cnt * FLASH_PHYSICAL_PAGE_SIZE);
    // 4k page offset + in-page offset. 4k*n+256*m

    /* FLC_CTL CS_LOW,WP_DISABLE */
    //		SPI_ArrieRegWrite(0x3C,0x16);
    WriteOneByte(ts, (unsigned char)0x3C, (unsigned char)0x16);
    /* FLC_TxDATA WRITE_ENABLE */
    //		SPI_ArrieRegWrite(0x3D,SPI_CMD_WRITE_EN);
    WriteOneByte(ts, (unsigned char)0x3D, FLASH_CMD_WRITE_EN);
    /* FLC_CTL CS_HIGH,WP_DISABLE */
    //		SPI_ArrieRegWrite(0x3C,0x14);
    WriteOneByte(ts, (unsigned char)0x3C, (unsigned char)0x14);

    /* FLC_CTL CS_LOW,WP_DISABLE */
    //		SPI_ArrieRegWrite(0x3C,0x16);
    WriteOneByte(ts, (unsigned char)0x3C, (unsigned char)0x16);

    /* FLC_TxDATA PAGE_PROGRAM_COMMAND */
    //		SPI_ArrieRegWrite(0x3D,SPI_CMD_PAGE_WR);
    WriteOneByte(ts, (unsigned char)0x3D, FLASH_CMD_PAGE_WR);
    /* FLC_TxDATA Address(bit16~23) */
    //		SPI_ArrieRegWrite(0x3D,((address>>16)&0xFF));
    WriteOneByte(ts, (unsigned char)0x3D, ((paddr>>16)&0xFF));
    /* FLC_TxDATA Address(bit8~15) */
    //		SPI_ArrieRegWrite(0x3D,((address>>8)&0xFF));
    WriteOneByte(ts, (unsigned char)0x3D, ((paddr>>8)&0xFF));
    /* FLC_TxDATA Address(bit0~7) */
    //		SPI_ArrieRegWrite(0x3D,(address&0xFF));
    WriteOneByte(ts, (unsigned char)0x3D, (paddr&0xFF));
    /* Data write 1page = 256byte */
    for(idx=0;idx<256;idx++){
      //			SPI_ArrieRegWrite(0x3D,*pData++);
      // addr=in-page(virtual, in 4k block) 256xN
      WriteOneByte(ts, (unsigned char)0x3D, data[(cnt*FLASH_PHYSICAL_PAGE_SIZE) +idx]);
    }
    /* FLC_CTL CS_HIGH,WP_DISABLE */
    //		SPI_ArrieRegWrite(0x3C,0x14);
    WriteOneByte(ts, (unsigned char)0x3C, (unsigned char)0x14);


    /* wait until 'BUSY = LOW' */
    do {
      retry++;
      ////		  msleep(10);
      if (retry > RETRY_COUNT)
	goto RETRY_ERROR;

      /* FLC_CTL CS_LOW,WP_DISABLE */
      //		SPI_ArrieRegWrite(0x3C,0x16);
      WriteOneByte(ts, (unsigned char)0x3C, (unsigned char)0x16);
      /* FLC_TxDATA READ_STATUS_COMMAND*/
      //		SPI_ArrieRegWrite(0x3D,SPI_CMD_READ_ST);
      WriteOneByte(ts, (unsigned char)0x3D, FLASH_CMD_READ_ST);
      /* Dummy data */
      //		SPI_ArrieRegWrite(0x3D,0);
      WriteOneByte(ts, (unsigned char)0x3D, (unsigned char)0x00);
      /* FLC_RxDATA */
      //		readData = SPI_ArrieRegRead(0x3F);
      readData = ReadOneByte(ts, 0x3F);
      /* FLC_CTL CS_HIGH,WP_DISABLE */
      //		SPI_ArrieRegWrite(0x3C,0x14);
      WriteOneByte(ts, (unsigned char)0x3C, (unsigned char)0x14);
    } while (readData & FLASH_ST_BUSY); 		/* check busy bit */
  }

  return 0;

 RETRY_ERROR:
  printk(KERN_INFO "FATAL: flash_write_page_shtsc retry %d times for page %d, addr %04X - FAILED!\n", retry, page, paddr);
  return 1;
}

#define FLASH_VERIFY_SIZE 512
unsigned char readBuf[FLASH_VERIFY_SIZE];

int flash_verify_page_shtsc(void *_ts, int page, unsigned char *data)
{
#if defined(CONFIG_TOUCHSCREEN_SHTSC_I2C)
  struct shtsc_i2c *ts = _ts;
#elif defined (CONFIG_TOUCHSCREEN_SHTSC_SPI)
  struct shtsc_spi *ts = _ts;
#else // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
  error
#endif // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
    unsigned addr; // in-page address (from 0 to FLASH_PAGE_SIZE-1)
  int cnt;

  /* BankChange */
  //	SPI_ArrieRegWrite(0x02,0x1C);
  WriteOneByte(ts, (unsigned char)0x02, (unsigned char)0x1C); // bank change reg

  /* CLKON_CTL0 */
  //	SPI_ArrieRegWrite(0x14,0x22);	/* CLKON_FLC,CLKON_REGBUS */
  WriteOneByte(ts, (unsigned char)0x14, (unsigned char)0x22);

  /* FLC_CTL CS_HIGH,WP_ENABLE */
  //	SPI_ArrieRegWrite(0x3C,0x10);
  WriteOneByte(ts, (unsigned char)0x3C, (unsigned char)0x10);
	
  /* FLC_CTL CS_LOW,WP_ENABLE */
  //	SPI_ArrieRegWrite(0x3C,0x12);
  WriteOneByte(ts, (unsigned char)0x3C, (unsigned char)0x12);

  /* FLC_TxDATA READ_COMMAND*/
  //	SPI_ArrieRegWrite(0x3D,SPI_CMD_READ);
  WriteOneByte(ts, (unsigned char)0x3D, FLASH_CMD_READ);
  /* FLC_TxDATA Address(bit16~23) */
  //	SPI_ArrieRegWrite(0x3D,((address>>16)&0xFF));
  WriteOneByte(ts, (unsigned char)0x3D, (unsigned char)0x00);
  /* FLC_TxDATA Address(bit8~15) */
  //	SPI_ArrieRegWrite(0x3D,((address>>8)&0xFF));
  WriteOneByte(ts, (unsigned char)0x3D, ((page<<4)&0xFF));
  /* FLC_TxDATA Address(bit0~7) */
  //	SPI_ArrieRegWrite(0x3D,(address&0xFF));
  WriteOneByte(ts, (unsigned char)0x3D, (unsigned char)0x00);
  /* FLC_TxDATA Dummy data */
  //	SPI_ArrieRegWrite(0x3D,0);
  WriteOneByte(ts, (unsigned char)0x3D, (unsigned char)0x00);

  for (addr = 0; addr < FLASH_PAGE_SIZE; addr += FLASH_VERIFY_SIZE) {
    for(cnt=0; cnt<FLASH_VERIFY_SIZE; cnt++){
      /* FLC_RxDATA */
      //		*pData++ = SPI_ArrieRegRead(0x3F);
      readBuf[cnt] = ReadOneByte(ts, 0x3F);
    }
    if (memcmp((unsigned char *)&(data[addr]), (unsigned char *)readBuf, FLASH_VERIFY_SIZE)) {
      goto VERIFY_ERROR;
    }
  }

  /* FLC_CTL CS_LOW,WP_ENABLE */
  //	SPI_ArrieRegWrite(0x3C,0x10);
  WriteOneByte(ts, (unsigned char)0x3C, (unsigned char)0x10);

  return 0;

 VERIFY_ERROR:
  /* FLC_CTL CS_LOW,WP_ENABLE */
  //	SPI_ArrieRegWrite(0x3C,0x10);
  WriteOneByte(ts, (unsigned char)0x3C, (unsigned char)0x10);
  // verify error
  printk(KERN_INFO "FATAL: flash_verify_page_shtsc for page %d - FAILED!\n", page);

  return 1;
}

int flash_read(void *_ts, unsigned address, unsigned length, unsigned char *data)
{
#if defined(CONFIG_TOUCHSCREEN_SHTSC_I2C)
  struct shtsc_i2c *ts = _ts;
#elif defined (CONFIG_TOUCHSCREEN_SHTSC_SPI)
  struct shtsc_spi *ts = _ts;
#else // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
  error
#endif // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
    int cnt;

  /* BankChange */
  //	SPI_ArrieRegWrite(0x02,0x1C);
  WriteOneByte(ts, (unsigned char)0x02, (unsigned char)0x1C); // bank change reg

  /* CLKON_CTL0 */
  //	SPI_ArrieRegWrite(0x14,0x22);	/* CLKON_FLC,CLKON_REGBUS */
  WriteOneByte(ts, (unsigned char)0x14, (unsigned char)0x22);

  /* FLC_CTL CS_HIGH,WP_ENABLE */
  //	SPI_ArrieRegWrite(0x3C,0x10);
  WriteOneByte(ts, (unsigned char)0x3C, (unsigned char)0x10);
	
  /* FLC_CTL CS_LOW,WP_ENABLE */
  //	SPI_ArrieRegWrite(0x3C,0x12);
  WriteOneByte(ts, (unsigned char)0x3C, (unsigned char)0x12);

  /* FLC_TxDATA READ_COMMAND*/
  //	SPI_ArrieRegWrite(0x3D,SPI_CMD_READ);
  WriteOneByte(ts, (unsigned char)0x3D, FLASH_CMD_READ);
  /* FLC_TxDATA Address(bit16~23) */
  //	SPI_ArrieRegWrite(0x3D,((address>>16)&0xFF));
  WriteOneByte(ts, (unsigned char)0x3D, (unsigned char)((address>>16)&0xFF));
  /* FLC_TxDATA Address(bit8~15) */
  //	SPI_ArrieRegWrite(0x3D,((address>>8)&0xFF));
  WriteOneByte(ts, (unsigned char)0x3D, (unsigned char)((address>>8)&0xFF));
  /* FLC_TxDATA Address(bit0~7) */
  //	SPI_ArrieRegWrite(0x3D,(address&0xFF));
  WriteOneByte(ts, (unsigned char)0x3D, (unsigned char)(address&0xFF));
  /* FLC_TxDATA Dummy data */
  //	SPI_ArrieRegWrite(0x3D,0);
  WriteOneByte(ts, (unsigned char)0x3D, (unsigned char)0x00);

  for(cnt=0; cnt<length; cnt++){
    /* FLC_RxDATA */
    //		*pData++ = SPI_ArrieRegRead(0x3F);
    data[cnt] = ReadOneByte(ts, 0x3F);
  }

  /* FLC_CTL CS_LOW,WP_ENABLE */
  //	SPI_ArrieRegWrite(0x3C,0x10);
  WriteOneByte(ts, (unsigned char)0x3C, (unsigned char)0x10);

  return 0;
}
#endif

#if defined(CONFIG_TOUCHSCREEN_SHTSC_I2C)
struct shtsc_i2c *g_ts;
#elif defined (CONFIG_TOUCHSCREEN_SHTSC_SPI)
struct spi_device *g_spi;
struct shtsc_spi *g_ts;
#else // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
error
#endif // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)

int detectDevice(void)
{
#if defined (DEVICE_LR388K5)
  return DEVICE_CODE_LR388K5;
#else
  return DEVICE_CODE_LR388K4;
#endif
}

static void shtsc_reset_delay(struct shtsc_i2c *data)
{
  msleep(SHTSC_RESET_TIME);
}

static void touch_enable (struct shtsc_i2c *ts)
{
  if(ts->disabled)
    {
      if(ts->client->irq) enable_irq(ts->client->irq);
      ts->disabled = false;
    }
}


static	void	touch_disable(struct shtsc_i2c *ts)
{
  if(!ts->disabled)	{
    if(ts->client->irq)		disable_irq(ts->client->irq);
    ts->disabled = true;
  }
}

static int shtsc_input_open(struct input_dev *dev)
{
  struct shtsc_i2c *ts = input_get_drvdata(dev);

  touch_enable(ts);

  printk("%s\n", __func__);

  return 0;
}

static void shtsc_input_close(struct input_dev *dev)
{
  struct shtsc_i2c *ts = input_get_drvdata(dev);

  touch_disable(ts);

  printk("%s\n", __func__);
}

#ifdef CONFIG_OF
static int shtsc_get_dt_coords(struct device *dev, char *name,
			       struct shtsc_i2c_pdata *pdata)
{
  u32 coords[SHTSC_COORDS_ARR_SIZE];
  struct property *prop;
  struct device_node *np = dev->of_node;
  int coords_size, rc;

  prop = of_find_property(np, name, NULL);
  if (!prop)
    return -EINVAL;
  if (!prop->value)
    return -ENODATA;

  coords_size = prop->length / sizeof(u32);
  if (coords_size != SHTSC_COORDS_ARR_SIZE) {
    dev_err(dev, "invalid %s\n", name);
    return -EINVAL;
  }

  rc = of_property_read_u32_array(np, name, coords, coords_size);
  if (rc && (rc != -EINVAL)) {
    dev_err(dev, "Unable to read %s\n", name);
    return rc;
  }

  if (strncmp(name, "sharp,panel-coords",
	      sizeof("sharp,panel-coords")) == 0) {
    pdata->panel_minx = coords[0];
    pdata->panel_miny = coords[1];
    pdata->panel_maxx = coords[2];
    pdata->panel_maxy = coords[3];
  } else if (strncmp(name, "sharp,display-coords",
		     sizeof("sharp,display-coords")) == 0) {
    pdata->disp_minx = coords[0];
    pdata->disp_miny = coords[1];
    pdata->disp_maxx = coords[2];
    pdata->disp_maxy = coords[3];
  } else {
    dev_err(dev, "unsupported property %s\n", name);
    return -EINVAL;
  }

  return 0;
}


static int shtsc_parse_dt(struct device *dev, struct shtsc_i2c_pdata *pdata)
{
  struct device_node *np = dev->of_node;
  int rc;
  u32 temp_val;

  rc = shtsc_get_dt_coords(dev, "sharp,panel-coords", pdata);
  if (rc)
    return rc;

  rc = shtsc_get_dt_coords(dev, "sharp,display-coords", pdata);
  if (rc)
    return rc;

  /* regulator info */
  pdata->i2c_pull_up = of_property_read_bool(np, "sharp,i2c-pull-up");

  /* reset, irq gpio info */
  pdata->reset_gpio = of_get_named_gpio_flags(np, "sharp,reset-gpio",0, &pdata->reset_gpio_flags);
  pdata->irq_gpio = of_get_named_gpio_flags(np, "sharp,irq-gpio",0, &pdata->irq_gpio_flags);
  if (of_find_property(np, "sharp,id-gpio", NULL))
	  pdata->id_gpio = of_get_named_gpio_flags(np, "sharp,id-gpio",0, &pdata->id_gpio_flags);
  else
	  pdata->id_gpio = -1;
  pdata->disable_gpios = of_property_read_bool(np, "sharp,disable-gpios");
				
  rc = of_property_read_u32(np, "ts_touch_num_max", &temp_val);
  if( !rc ) pdata->ts_touch_num_max = temp_val;
  rc = of_property_read_u32(np, "ts_pressure_max", &temp_val);
  if( !rc ) pdata->ts_pressure_max = temp_val;
  rc = of_property_read_u32(np, "ts_flip_x", &temp_val);
  if( !rc ) pdata->ts_flip_x = temp_val;
  rc = of_property_read_u32(np, "ts_flip_y", &temp_val);
  if( !rc ) pdata->ts_flip_y = temp_val;
  rc = of_property_read_u32(np, "ts_swap_xy", &temp_val);
  if( !rc ) pdata->ts_swap_xy = temp_val;
#if 1
  printk(KERN_INFO "[SHTP PARSE DT] reset gpio = %d\n",pdata->reset_gpio);
  printk(KERN_INFO "[SHTP PARSE DT] irq gpio = %d\n",pdata->irq_gpio);
#endif
  return 0;
}
#else
static int shtsc_parse_dt(struct device *dev, struct shtsc_i2c_pdata *pdata)
{
  return -ENODEV;
}
#endif

#ifdef PINCTRL_ACTIVE_SUSPEND
static int shtsc_gpio_configure(struct shtsc_i2c * ts,
					bool on)
{
	int retval = 0;

	if (on) {
		if (gpio_is_valid(ts->pdata->irq_gpio)) {
			/* configure touchscreen irq gpio */
			retval = gpio_request(ts->pdata->irq_gpio,
				"shtsc_irq_gpio");
			if (retval) {
				printk("request irq err\n");
				goto err_irq_gpio_req;
			}
			retval = gpio_direction_input(ts->pdata->irq_gpio);
			if (retval) {
				printk("irq direction set err\n");
				goto err_irq_gpio_dir;
			}
		} else {
			printk("irq gpio not provided\n");
			goto err_irq_gpio_req;
		}

		if (gpio_is_valid(ts->pdata->reset_gpio)) {
			/* configure touchscreen reset out gpio */
			retval = gpio_request(ts->pdata->reset_gpio,
					NULL);
			if (retval) {
				printk("request reset err\n");
				goto err_irq_gpio_dir;
			}

			retval = gpio_direction_output(ts->pdata->reset_gpio, 1);
			if (retval) {
				printk("reset direction set err\n");
				goto err_reset_gpio_dir;
			}

			//gpio_set_value(ts->pdata->reset_gpio, 1);
			//msleep(ts->pdata->reset_delay_ms);
		}

		return 0;
	} else {
		if (ts->pdata->disable_gpios) {
			if (gpio_is_valid(ts->pdata->irq_gpio))
				gpio_free(ts->pdata->irq_gpio);
			if (gpio_is_valid(ts->pdata->reset_gpio)) {
				/*
				 * This is intended to save leakage current
				 * only. Even if the call(gpio_direction_input)
				 * fails, only leakage current will be more but
				 * functionality will not be affected.
				 */
				retval = gpio_direction_input(
							ts->pdata->reset_gpio);
				if (retval) {
					printk("reset direction set err\n");
				}
				gpio_free(ts->pdata->reset_gpio);
			}
		}

		return 0;
	}

err_reset_gpio_dir:
	if (gpio_is_valid(ts->pdata->reset_gpio))
		gpio_free(ts->pdata->reset_gpio);
err_irq_gpio_dir:
	if (gpio_is_valid(ts->pdata->irq_gpio))
		gpio_free(ts->pdata->irq_gpio);
err_irq_gpio_req:
	return retval;
}
#endif

#if defined(CONFIG_FB)
static int shtsc_suspend(struct device *dev)
{
#ifdef PINCTRL_ACTIVE_SUSPEND
	int ret = 0;
#endif
	struct i2c_client *client = to_i2c_client(dev);
	struct shtsc_i2c *data = i2c_get_clientdata(client);
	//	struct input_dev *input_dev = data->input;

	if (data->dev_sleep) {
	        DBGLOG("Device already in sleep\n");
		return 0;
	}

	disable_irq(data->client->irq);
#ifdef PINCTRL_ACTIVE_SUSPEND
	if (g_ts->pdata->disable_gpios) {
		if (g_ts->ts_pinctrl) {
			ret = pinctrl_select_state(g_ts->ts_pinctrl, g_ts->pinctrl_state_suspend);
			if (ret < 0)
				printk("can't get suspend pinctrl state\n");

			shtsc_gpio_configure(g_ts, false);
		}
	}
#endif

	shtsc_system_init(g_ts);

	DBGLOG("Device in sleep\n");
	
	data->dev_sleep = true;
	return 0;
}

static int shtsc_resume(struct device *dev)
{
#ifdef PINCTRL_ACTIVE_SUSPEND
	int ret = 0;
#endif
	struct i2c_client *client = to_i2c_client(dev);
	struct shtsc_i2c *data = i2c_get_clientdata(client);
	//	struct input_dev *input_dev = data->input;

	if (!data->dev_sleep) {
	        DBGLOG( "Device already in resume\n");
		return 0;
	}
	touch_once = 0;

#ifdef PINCTRL_ACTIVE_SUSPEND
	if (g_ts->pdata->disable_gpios) {
		if (g_ts->ts_pinctrl) {
			ret = pinctrl_select_state(g_ts->ts_pinctrl, g_ts->pinctrl_state_active);
			if (ret < 0)
				printk("can't get suspend pinctrl state\n");

			shtsc_gpio_configure(g_ts, true);
		}
	}
#endif

	shtsc_reset(g_ts, false);

	G_Irq_Mask = 0xffff;
#ifdef GET_REPORT
	reportBuf[0] = (unsigned char)0;
#endif /* GET_REPORT */

//	shtsc_reset_delay(data);

#if defined(DEVICE_LR388K5)
	shtsc_reset(g_ts, true);
	msleep(10);
	shtsc_system_init(g_ts);
	msleep(100);

	DBGLOG("Device in active\n");

	enable_irq(data->client->irq);
#else
	enable_irq(data->client->irq);//enable irg beforfe wait

	g_ts->wait_state = WAIT_RESET;
	g_ts->wait_result = false;
	shtsc_reset(g_ts, true);
	// wait
	WaitAsync(g_ts);

	shtsc_system_init(g_ts);
	msleep(100);

	DBGLOG("Device in active\n");
#endif
	data->dev_sleep = false;
	return 0;
}

static int fb_notifier_callback(struct notifier_block *self,
				 unsigned long event, void *data)
{
	struct shtsc_i2c *shtsc_dev_data =
		container_of(self, struct shtsc_i2c, fb_notif);

	switch (event) {
	case LCD_EVENT_ON_END:
		if (!cancel_delayed_work_sync(&shtsc_dev_data->resume_work))
			queue_delayed_work(shtsc_dev_data->resume_wq, &shtsc_dev_data->resume_work, msecs_to_jiffies(1));
		break;
	case LCD_EVENT_OFF_START:
		if (!cancel_delayed_work_sync(&shtsc_dev_data->suspend_work))
			queue_delayed_work(shtsc_dev_data->suspend_wq, &shtsc_dev_data->suspend_work, msecs_to_jiffies(1));
		break;
	default:
		break;
	}

	return 0;
}
#endif

static void resume_event(struct work_struct *work)
{
	struct shtsc_i2c *shtsc_dev_data =
		container_of(to_delayed_work(work), struct shtsc_i2c, resume_work);

	shtsc_resume(&shtsc_dev_data->client->dev);
	return;
}

static void suspend_event(struct work_struct *work)
{
	struct shtsc_i2c *shtsc_dev_data =
		container_of(to_delayed_work(work), struct shtsc_i2c, suspend_work);

	shtsc_suspend(&shtsc_dev_data->client->dev);
	return;
}
#ifdef PINCTRL_ACTIVE_SUSPEND
static int shtsc_pinctrl_init(struct shtsc_i2c * g_ts)
{
	int retval;

	/* Get pinctrl if target uses pinctrl */
	g_ts->ts_pinctrl = devm_pinctrl_get(&(g_ts->client->dev));
	if (IS_ERR_OR_NULL(g_ts->ts_pinctrl)) {
		retval = PTR_ERR(g_ts->ts_pinctrl);
		printk("Target does not use pinctrl %d\n", retval);
		goto err_pinctrl_get;
	}

	g_ts->pinctrl_state_active
		= pinctrl_lookup_state(g_ts->ts_pinctrl, "pmx_ts_active");
	if (IS_ERR_OR_NULL(g_ts->pinctrl_state_active)) {
		retval = PTR_ERR(g_ts->pinctrl_state_active);
		printk("Can not lookup active pinstate %d\n", retval);
		goto err_pinctrl_lookup;
	}

	g_ts->pinctrl_state_suspend
		= pinctrl_lookup_state(g_ts->ts_pinctrl, "pmx_ts_suspend");
	if (IS_ERR_OR_NULL(g_ts->pinctrl_state_suspend)) {
		retval = PTR_ERR(g_ts->pinctrl_state_suspend);
		printk("Can not lookup suspend pinstate %d\n", retval);
		goto err_pinctrl_lookup;
	}

#if 0
	g_ts->pinctrl_state_release
		= pinctrl_lookup_state(g_ts->ts_pinctrl, "pmx_ts_release");
	if (IS_ERR_OR_NULL(g_ts->pinctrl_state_release)) {
		retval = PTR_ERR(g_ts->pinctrl_state_release);
		printk("Can not lookup release pinstate %d\n", retval);
	}
#endif

	return 0;

err_pinctrl_lookup:
	devm_pinctrl_put(g_ts->ts_pinctrl);
err_pinctrl_get:
	g_ts->ts_pinctrl = NULL;
	return retval;
}
#endif

int current_page = 0;

char iobuf[4*1024];
static long dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
  long ret = true;

  //  unsigned int index;
  u8 addr, val;
  //  unsigned long r;
  int r;

#if defined(DEBUG_SHTSC)
  printk(KERN_INFO "[ENTER] shtsc_ioctl\n");    
#endif

#if defined(DEBUG_SHTSC)
  printk(KERN_INFO "shtsc dev_ioctl switch - cmd: %x, arg: %lx\n", cmd, arg);
#endif

  switch(cmd) {
#if defined(DEVICE_LR388K5)//2014.11.19 added

  case SHTSC_IOCTL_SET_PAGE:
#if defined(DEBUG_SHTSC)
    printk(KERN_INFO "shtsc dev_ioctl case - SET_PAGE; cmd %x, arg %lx\n", cmd, arg);
#endif
    current_page = arg;
    break;

  case SHTSC_IOCTL_FLASH_ACCESS_START:
#if defined(DEBUG_SHTSC)
    printk(KERN_INFO "shtsc dev_ioctl case - FLASH_ACCESS_START; cmd %x\n", cmd);
#endif
    flash_access_start_shtsc(g_ts);
    break;

  case SHTSC_IOCTL_FLASH_ACCESS_END:
#if defined(DEBUG_SHTSC)
    printk(KERN_INFO "shtsc dev_ioctl case - FLASH_ACCESS_END; cmd %x\n", cmd);
#endif
    flash_access_end_shtsc(g_ts);
    break;

  case SHTSC_IOCTL_ERASE:
#if defined(DEBUG_SHTSC)
    printk(KERN_INFO "shtsc dev_ioctl case - ERASE; cmd %x, current_page %d\n", cmd, current_page);
#endif
#ifdef FLASH_CHECK
    if (flash_erase_page_shtsc(g_ts, current_page))
      return -1;
#else /* FLASH_CHECK */
    flash_erase_page_shtsc(g_ts, current_page);
#endif /* FLASH_CHECK */
    break;

  case SHTSC_IOCTL_WRITE:
#if defined(DEBUG_SHTSC)
    printk(KERN_INFO "shtsc dev_ioctl case - WRITE; cmd %x, current_page %d\n", cmd, current_page);
#endif
    if (copy_from_user(iobuf, (char *)arg, (4*1024))) {
      printk(KERN_INFO "shtsc dev_ioctl ERROR by copy_from_user\n");
      return -1;
    }
#ifdef FLASH_CHECK
    if (flash_write_page_shtsc(g_ts, current_page, iobuf))
      return -1;
#else /* FLASH_CHECK */
    flash_write_page_shtsc(g_ts, current_page, iobuf);
#endif /* FLASH_CHECK */
    break;

  case SHTSC_IOCTL_VERIFY:
#if defined(DEBUG_SHTSC)
    printk(KERN_INFO "shtsc dev_ioctl case - VERIFY; cmd %x, current_page %d\n", cmd, current_page);
#endif
    if (copy_from_user(iobuf, (char *)arg, (4*1024))) {
      printk(KERN_INFO "shtsc dev_ioctl ERROR by copy_from_user\n");
      return -1;
    }
#ifdef FLASH_CHECK
    if (flash_verify_page_shtsc(g_ts, current_page, iobuf))
      return -1;
#else /* FLASH_CHECK */
    flash_verify_page_shtsc(g_ts, current_page, iobuf);
#endif /* FLASH_CHECK */
    break;

  case SHTSC_IOCTL_ERASE_ALL:
    {
#if defined (DEVICE_LR388K5)
#define LAST_PAGE 16 
#else // DEVICE_LR388K4
      // error
#endif // DEVICE_LR388K4
      int page;
      printk(KERN_INFO "%s(%d): flash_access start\n", __FILE__, __LINE__);
      flash_access_start_shtsc(g_ts);
      for (page = 0; page < LAST_PAGE; page++) {
	flash_erase_page_shtsc(g_ts, page);
	printk(KERN_INFO "flash_erase_page_shtsc done: page %d\n",  page);
      }
      printk(KERN_INFO "%s(%d): flash_access end\n", __FILE__, __LINE__);
      flash_access_end_shtsc(g_ts);
      printk(KERN_INFO "%s(%d): flash erased.\n", __FILE__, __LINE__);
    }
    break;
  case SHTSC_IOCTL_REG_1WRITE:
    //    printk(KERN_INFO "SHTSC_IOCTL_REG_1WRITE\n");
    addr = (arg >> 8) & 0xFF;
    val = arg & 0xFF;
    //    printk(KERN_INFO "SHTSC_IOCTL_REG_1WRITE: cmd %x, arg %lx a:0x%x d:0x%x(%d)\n", cmd, arg, addr, val, val);
#if defined(DEBUG_SHTSC)
    printk(KERN_INFO "SHTSC_IOCTL_REG_1WRITE: addr: %02X (Hex), data: %02X (Hex)\n", addr, val);
#endif
    WriteOneByte(g_ts, addr, val);
    //    printk(KERN_INFO "SHTSC_IOCTL_REG_1WRITE done\n");
    break;

  case SHTSC_IOCTL_REG_1READ:
    //    printk(KERN_INFO "SHTSC_IOCTL_REG_1READ\n");
    //addr = 0xFF & arg;
    val = ReadOneByte(g_ts, ((struct reg *)arg)->addr);
    ((struct reg *)arg)->data = val;

#if defined(DEBUG_SHTSC)
    printk(KERN_INFO "SHTSC_IOCTL_REG_1READ: cmd %x, arg %lx a:0x%x d:0x%x(%d)\n", cmd, arg, ((struct reg *)arg)->addr, val, val);
#endif
    //    printk(KERN_INFO "SHTSC_IOCTL_REG_1READ done\n");
    break;

  case SHTSC_IOCTL_REG_N_RW_SET_ADDR:
    s_shtsc_addr = 0xFF & (arg >> 16);
    s_shtsc_len = 0xFFFF & arg;
#if defined(DEBUG_SHTSC)
    printk(KERN_INFO "SHTSC_IOCTL_REG_N_RW_SET_ADDR: cmd %x, arg %lx a:0x%x len:%d\n", cmd, arg, s_shtsc_addr, s_shtsc_len);
#endif
    break;

  case SHTSC_IOCTL_REG_N_WRITE_1ADDR_GO:
    /* s_shtsc_len is initialized __IF__ SHTSC_IOCTL_REG_N_RW_SET_ADDR is issued before */
    r = copy_from_user(s_shtsc_buf, (char *)arg, s_shtsc_len);
#if defined(DEBUG_SHTSC)
    printk(KERN_INFO "Driver Multibyte write. addr %02X, len: %x, data[0-3]: %02X %02X %02X %02X ....\n", 
	   s_shtsc_addr, s_shtsc_len, s_shtsc_buf[0], s_shtsc_buf[1], s_shtsc_buf[2], s_shtsc_buf[3]);
#endif
    if (r != 0) {
      printk(KERN_INFO "shtsc dev_ioctl ERROR by copy_from_user(%d)\n", r);
      return -1;
    }
    //    printk(KERN_INFO "SHTSC_IOCTL_REG_N_WRITE_1ADDR: cmd %x, arg %lx a:0x%x d:0x%x(%d)\n", cmd, arg, addr, val, val);
#if defined(DEBUG_SHTSC)
    printk(KERN_INFO "SHTSC_IOCTL_REG_N_WRITE_1ADDR: cmd %x, arg %lx a:0x%x d:0x%x(%d)\n", cmd, arg, s_shtsc_addr, s_shtsc_len, s_shtsc_len);
#endif
    WriteMultiBytes(g_ts, s_shtsc_addr, s_shtsc_buf, s_shtsc_len);

    break;

  case SHTSC_IOCTL_REG_N_READ_1ADDR_GO:
    /* s_shtsc_len is initialized __IF__ SHTSC_IOCTL_REG_N_RW_SET_ADDR is issued before */
    ReadMultiBytes(g_ts, s_shtsc_addr, s_shtsc_len, s_shtsc_buf);
    msleep(10); // not checked yet
#if defined(DEBUG_SHTSC)
    printk(KERN_INFO "Driver Multibyte read done. addr %02X, len: %x, data[0-3]: %02X %02X %02X %02X ....\n", 
	   s_shtsc_addr, s_shtsc_len, s_shtsc_buf[0], s_shtsc_buf[1], s_shtsc_buf[2], s_shtsc_buf[3]);
#endif
    r = copy_to_user((char *)arg, s_shtsc_buf, s_shtsc_len);
    if (r != 0) {
      printk(KERN_INFO "shtsc dev_ioctl ERROR by copy_to_user(%d)\n", r);
      return -1;
    }

    break;

  case SHTSC_IOCTL_SETIRQMASK:
#if defined(CONFIG_TOUCHSCREEN_SHTSC_I2C)
    if (arg) {
      enable_irq(g_ts->client->irq);
    } else {
      disable_irq(g_ts->client->irq);
    }
#elif defined (CONFIG_TOUCHSCREEN_SHTSC_SPI)
    if (arg) {
      enable_irq(g_ts->spi->irq);
    } else {
      disable_irq(g_ts->spi->irq);
    }
#else // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
    error
#endif // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
#if defined(DEBUG_SHTSC)
    printk(KERN_INFO "shtsc dev_ioctl case - SETIRQMASK; cmd %x, arg %lx\n", cmd, arg);
#endif
    break;

  case SHTSC_IOCTL_RESET:
    if (arg) {
      shtsc_reset(g_ts, true);
      msleep(10);
      shtsc_system_init(g_ts);
      msleep(100);
    } else {
      shtsc_reset(g_ts, false);
    }
#if defined(DEBUG_SHTSC)
    printk(KERN_INFO "shtsc dev_ioctl case - RESET; cmd %x, arg %lx\n", cmd, arg);
#endif
    break;

  case SHTSC_IOCTL_DEBUG:
#if defined(DEBUG_SHTSC)
    printk(KERN_INFO "shtsc dev_ioctl case - DEBUG; cmd %x, arg %lx\n", cmd, arg);
#endif
    break;

  case SHTSC_IOCTL_CMD_ISSUE_RESULT:
    msleep(100);
    r = copy_to_user((char *)arg, CommandResultBuf, MAX_COMMAND_RESULT_LEN);
    if (r != 0) {
      printk(KERN_INFO "shtsc dev_ioctl ERROR by copy_to_user(%d)\n", r);
      return -1;
    }
    break;

  case SHTSC_IOCTL_DRIVER_VERSION_READ:
    {
      char versionBuf[16];
      versionBuf[0] = VersionYear;
      versionBuf[1] = VersionMonth;
      versionBuf[2] = VersionDay;
      versionBuf[3] = VersionSerialNumber;
      versionBuf[4] = VersionModelCode;

      r = copy_to_user((char *)arg, versionBuf, DRIVER_VERSION_LEN); 
      if (r != 0) {
	printk(KERN_INFO "shtsc dev_ioctl ERROR by copy_to_user(%d)\n", r);
	return -1;
      }
    }
    break;

  case SHTSC_IOCTL_DCMAP:
    {
      int x = dcmap[0];
      int y = dcmap[1];
      int len = (x * y * 2) + 4;

#if defined(DEBUG_SHTSC)
      printk(KERN_INFO "shtsc dev_ioctl case - DCMAP; cmd %x, arg %lx, %d*%d+4=%d\n", cmd, arg, x, y, len);
#endif

      if (buf_pos) {
	/* DC map ready to send out */
	if ( copy_to_user( (char *)arg, dcmap, len ) ) {
	  printk( KERN_INFO "shtsc : copy_to_user failed\n" );
	  return -EFAULT;
	}
	buf_pos = 0;
      }
      break;
    }

#ifdef GET_REPORT
  case SHTSC_IOCTL_GET_REPORT:
    {
      volatile int count;
      int len;


      while (Mutex_GetReport)
	;
      Mutex_GetReport = true;
      
      count = reportBuf[0];
      len = 4+ count*REP_SIZE;

#if defined(DEBUG_SHTSC)
      printk(KERN_INFO "shtsc dev_ioctl case - GET_REPORT; cmd %x, arg %lx, count=%d, len=%d\n", cmd, arg, count, len);
#endif

      r = copy_to_user((char *)arg, reportBuf, len);
      if (r != 0) {
	printk(KERN_INFO "shtsc dev_ioctl ERROR by copy_to_user(%d)\n", r);
	return -1;
      }

      reportBuf[0] = (unsigned char)0;

      Mutex_GetReport = false;
    }
    break;
#endif /* GET_REPORT */

  case SHTSC_IOCTL_FLASH_READ:
    {
#if defined (DEVICE_LR388K5)
      /* arg: pointer to the content buffer */
      /* arg[3:0]: address to read (little endian) */
      /* arg[5:4]: length to read (little endian) */

      unsigned address;
      unsigned length;

      if (copy_from_user(iobuf, (char *)arg, (4+2))) {
	printk(KERN_INFO "shtsc dev_ioctl ERROR by copy_from_user\n");
	return -1;
      }
      address = (iobuf[3] << 24) | (iobuf[2] << 16) | (iobuf[1] << 8) | (iobuf[0] << 0);
      length = (iobuf[5] << 8) | (iobuf[4] << 0);

#if defined(DEBUG_SHTSC)
      printk(KERN_INFO "shtsc dev_ioctl case - FLASH_READ; addr %x, arg %x\n", address, length);
#endif

      flash_read(g_ts, address, length, iobuf);
      if ( copy_to_user( (char *)arg, iobuf, length ) ) {
	printk( KERN_INFO "shtsc : copy_to_user failed\n" );
	return -EFAULT;
      }
#else // DEVICE_LR388K4
      //nothing
#endif // DEVICE_LR388K4
	break;
    }

  case SHTSC_IOCTL_NOTIFY_PID:
    pid = arg; // save pid for later kill();
    printk(KERN_INFO "SHTSC_IOCTL_NOTIFY_PID: pid: %d\n", pid);
#if defined(DEBUG_SHTSC)
    printk(KERN_INFO "SHTSC_IOCTL_NOTIFY_PID: pid: %d\n", pid);
#endif
    break;

  case SHTSC_IOCTL_GET_INTERRUPT_STATUS:
#if defined(DEBUG_SHTSC)
    printk(KERN_INFO "Received SHTSC_IOCTL_GET_INTERRUPT_STATUS, %d\n", resumeStatus);
#endif

    r = copy_to_user((char *)arg, &resumeStatus, 1); // copy one-byte status
    if (r != 0) {
      printk(KERN_INFO "shtsc dev_ioctl ERROR by copy_to_user(%d)\n", r);
      return -1;
    }
    break;

#else //DEVICE_LR388K5

  case SHTSC_IOCTL_CMD_ISSUE_RESULT:
    msleep(100);
    r = copy_to_user((char *)arg, CommandResultBuf, MAX_COMMAND_RESULT_LEN);
    if (r != 0) {
      printk(KERN_INFO "shtsc dev_ioctl ERROR by copy_to_user(%d)\n", r);
      return -1;
    }
    break;

  case SHTSC_IOCTL_REG_1WRITE:
    //    printk(KERN_INFO "SHTSC_IOCTL_REG_1WRITE\n");
    addr = (arg >> 8) & 0xFF;
    val = arg & 0xFF;
    //    printk(KERN_INFO "SHTSC_IOCTL_REG_1WRITE: cmd %x, arg %lx a:0x%x d:0x%x(%d)\n", cmd, arg, addr, val, val);
#if defined(DEBUG_SHTSC)
    printk(KERN_INFO "SHTSC_IOCTL_REG_1WRITE: addr: %02X (Hex), data: %02X (Hex)\n", addr, val);
#endif
    WriteOneByte(g_ts, addr, val);
    //    printk(KERN_INFO "SHTSC_IOCTL_REG_1WRITE done\n");
    break;

  case SHTSC_IOCTL_REG_1READ:
    //    printk(KERN_INFO "SHTSC_IOCTL_REG_1READ\n");
    //addr = 0xFF & arg;
    val = ReadOneByte(g_ts, ((struct reg *)arg)->addr);
    ((struct reg *)arg)->data = val;

#if defined(DEBUG_SHTSC)
    printk(KERN_INFO "SHTSC_IOCTL_REG_1READ: cmd %x, arg %lx a:0x%x d:0x%x(%d)\n", cmd, arg, ((struct reg *)arg)->addr, val, val);
#endif
    //    printk(KERN_INFO "SHTSC_IOCTL_REG_1READ done\n");
    break;

  case SHTSC_IOCTL_SETIRQMASK://2014.11.28 added
#if defined(CONFIG_TOUCHSCREEN_SHTSC_I2C)
    if (arg) {
      enable_irq(g_ts->client->irq);
    } else {
      disable_irq(g_ts->client->irq);
    }
#elif defined (CONFIG_TOUCHSCREEN_SHTSC_SPI)
    if (arg) {
      enable_irq(g_ts->spi->irq);
    } else {
      disable_irq(g_ts->spi->irq);
    }
#else // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
    error
#endif // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
#if defined(DEBUG_SHTSC)
    printk(KERN_INFO "shtsc dev_ioctl case - SETIRQMASK; cmd %x, arg %lx\n", cmd, arg);
#endif
    break;

  case SHTSC_IOCTL_RESET:
    if (arg) {
      g_ts->wait_state = WAIT_RESET;
      g_ts->wait_result = false;
      shtsc_reset(g_ts, true);
      // wait
      WaitAsync(g_ts);
      shtsc_system_init(g_ts);
      msleep(100);
    } else {
      shtsc_reset(g_ts, false);
    }
#if defined(DEBUG_SHTSC)
    printk(KERN_INFO "shtsc dev_ioctl case - RESET; cmd %x, arg %lx\n", cmd, arg);
#endif
    break;

#endif// DEVICE_LR388K4
  default:
    ret = false;
    break;
  }

#if defined(DEBUG_SHTSC)
  printk(KERN_INFO "[EXIT] shtsc_ioctl\n");
#endif

  return ret;
}


#if defined(CONFIG_TOUCHSCREEN_SHTSC_I2C)
static int dev_open(struct inode *inode, struct file *filp)
{
#if defined(DEBUG_SHTSC)
  printk(KERN_INFO "shtsc dev_open\n");
#endif
  return 0;
}

static int dev_release(struct inode *inode, struct file *filp)
{
#if defined(DEBUG_SHTSC)
  printk(KERN_INFO "shtsc dev_release\n");
#endif
  return 0;
}

#elif defined (CONFIG_TOUCHSCREEN_SHTSC_SPI)

static int dev_open(struct inode *inode, struct file *filp)
{
  struct shtsc_spi *ts = spi_get_drvdata(g_spi);

  if(!ts)
    return -EFAULT;

  return 0;
}

static int dev_release(struct inode *inode, struct file *filp)
{
  return 0;
}
#else // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
error
#endif // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)

static const struct file_operations dev_fops = {
  .owner = THIS_MODULE,
  .open = dev_open,
  .release = dev_release,
  .read = dev_read,
  //	.write = dev_write,
  .unlocked_ioctl = dev_ioctl,
};

static struct miscdevice shtsc_miscdev = {
  .minor = MISC_DYNAMIC_MINOR,
  .name = SHTSC_DRIVER_NAME, // should be "/dev/shtsc"
  .fops = &dev_fops,
};

#if defined(CONFIG_TOUCHSCREEN_SHTSC_I2C)
static struct i2c_device_id shtsc_i2c_idtable[] = {
  { SHTSC_DRIVER_NAME, 0 },
  { }
};
#ifdef CONFIG_OF
static struct of_device_id shtsc_match_table[] = {
  { .compatible = "sharp,shtsc_i2c",},
  { },
};
#else
#define shtsc_match_table NULL
#endif

MODULE_DEVICE_TABLE(i2c, shtsc_i2c_idtable);

static struct i2c_driver shtsc_i2c_driver = {
  .driver		= {
    .owner	= THIS_MODULE,
    .name	= SHTSC_DRIVER_NAME,
    .of_match_table = shtsc_match_table,//2014.10.16 added
  },
  .id_table	= shtsc_i2c_idtable,
  .probe	= shtsc_i2c_probe,
  .remove	= shtsc_i2c_remove,
};

static int __init shtsc_init(void)
{
  int ret = 1;
  ret = misc_register(&shtsc_miscdev);
  if (ret) {
    printk(KERN_INFO "%s(%d): misc_register returns %d. Failed.\n", __FILE__, __LINE__, ret);
  }
#if defined(DEBUG_SHTSC)
  printk(KERN_INFO "%s(%d): loaded successfully\n", __FILE__, __LINE__);
#endif

  return i2c_add_driver(&shtsc_i2c_driver);
}
static void __exit shtsc_exit(void)
{
  misc_deregister(&shtsc_miscdev);
  i2c_del_driver(&shtsc_i2c_driver);
}

#elif defined (CONFIG_TOUCHSCREEN_SHTSC_SPI)

static struct spi_driver shtsc_spi_driver = {
  .driver		= {
    .owner	= THIS_MODULE,
    .name	= SHTSC_DRIVER_NAME,
  },
  .probe	= shtsc_spi_probe,
  .remove	= shtsc_spi_remove,
};

static int __init shtsc_init(void)
{
  int ret;
  ret = misc_register(&shtsc_miscdev);
  if (ret) {
    printk(KERN_INFO "%s(%d): misc_register returns %d. Failed.\n", __FILE__, __LINE__, ret);
  }
#if defined(DEBUG_SHTSC)
  printk(KERN_INFO "%s(%d): loaded successfully\n", __FILE__, __LINE__);
#endif

  return spi_register_driver(&shtsc_spi_driver);
}
static void __exit shtsc_exit(void)
{
  misc_deregister(&shtsc_miscdev);
  spi_unregister_driver(&shtsc_spi_driver);
}
#else // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
error
#endif // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)

#if defined(CONFIG_TOUCHSCREEN_SHTSC_I2C)
static int shtsc_i2c_probe(struct i2c_client *client,
				     const struct i2c_device_id *id)
{
  //  const struct shtsc_pdata *pdata = client->dev.platform_data;
  struct shtsc_i2c_pdata *pdata;
  struct shtsc_i2c *ts;
  struct input_dev *input_dev;
  int err;
  int count;
  u8 rData[1+1]; //requires one more byte to hold

#if defined(DEBUG_SHTSC)
  printk(KERN_INFO "[ENTER] shtsc_probe\n");
#endif

  //2014.10.16 added
  if (client->dev.of_node) {
    pdata = devm_kzalloc(&client->dev,
			 sizeof(struct shtsc_i2c_pdata), GFP_KERNEL);
    if (!pdata) {
      dev_err(&client->dev, "Failed to allocate memory\n");
      return -ENOMEM;
    }
    err = shtsc_parse_dt(&client->dev, pdata);
    if (err){
      kfree(pdata);
      return err;
    }
	if (pdata->id_gpio > 0) {
		err = gpio_get_value(pdata->id_gpio);
		if (0 == err)
		{
			printk("gpio %d is 0, Sharp Panel not used\n", pdata->id_gpio);
			misc_deregister(&shtsc_miscdev);
			return -EIO;
		}
	}
  } else{
    pdata = client->dev.platform_data;
  }

  /* No pdata no way forward */
  if (pdata == NULL) {
    dev_err(&client->dev, "no pdata\n");
#if defined(DEBUG_SHTSC)
    printk(KERN_INFO "%s(%d):\n", __FILE__, __LINE__);
#endif
    return -ENODEV;
  }

  if (!i2c_check_functionality(client->adapter, I2C_FUNC_SMBUS_READ_WORD_DATA))
    return -EIO;

  ts = kzalloc(sizeof(struct shtsc_i2c), GFP_KERNEL);
  g_ts = ts;

  input_dev = input_allocate_device();
  if (!ts || !input_dev) {
    err = -ENOMEM;
    goto err_free_mem;
  }

  ts->client = client;
  ts->input = input_dev;
  ts->pdata = pdata;//2014.10.16 added

  ts->min_x = pdata->panel_minx;
  ts->max_x = pdata->panel_maxx;
  ts->min_y = pdata->panel_miny;
  ts->max_y = pdata->panel_maxy;
  ts->pressure_max = pdata->ts_pressure_max;
  ts->touch_num_max = pdata->ts_touch_num_max;//2014.10.16 added
  ts->flip_x = pdata->ts_flip_x;
  ts->flip_y = pdata->ts_flip_y;
  ts->swap_xy = pdata->ts_swap_xy;

  ts->reset_pin = pdata->reset_gpio;
  ts->irq_pin = pdata->irq_gpio;

  mutex_init(&(ts->mutex));

  snprintf(ts->phys, sizeof(ts->phys),
	   "%s/input0", dev_name(&client->dev));

  input_dev->name = SHTSC_DRIVER_NAME;
  input_dev->phys = ts->phys;
  input_dev->id.bustype = BUS_I2C;
  input_dev->dev.parent = &client->dev;
  input_dev->open = shtsc_input_open;//2014.10.16 added
  input_dev->close = shtsc_input_close;//2014.10.16 added

  __set_bit(EV_ABS, input_dev->evbit);
  __set_bit(EV_KEY, input_dev->evbit);
  __set_bit(BTN_TOUCH, input_dev->keybit);//2014.10.16 added
  __set_bit(INPUT_PROP_DIRECT, input_dev->propbit);//2014.10.16 added

  /* For multi-touch */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0))
  err = input_mt_init_slots(input_dev, SHTSC_MAX_FINGERS, INPUT_MT_DIRECT);
#else /*  KERNEL_3_10 */
  err = input_mt_init_slots(input_dev, SHTSC_MAX_FINGERS, 0);
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)) */

  if (err)
    goto err_free_mem;
  input_set_abs_params(input_dev, ABS_MT_TOUCH_MAJOR, 0, SHTSC_I2C_SIZE_MAX, 0, 0);
  input_set_abs_params(input_dev, ABS_MT_POSITION_X,
		       pdata->disp_minx, pdata->disp_maxx, 0, 0);
  input_set_abs_params(input_dev, ABS_MT_POSITION_Y,
		       pdata->disp_miny, pdata->disp_maxy, 0, 0);
  //input_set_abs_params(input_dev, ABS_MT_PRESSURE  , 0, SHTSC_I2C_P_MAX, 0, 0);
  input_set_abs_params(input_dev, ABS_MT_TOOL_TYPE , 0, MT_TOOL_MAX, 0, 0);

#ifdef PINCTRL_ACTIVE_SUSPEND
  err = shtsc_pinctrl_init(g_ts);
  if (!err && g_ts->ts_pinctrl) {
	  err = pinctrl_select_state(g_ts->ts_pinctrl, g_ts->pinctrl_state_active);
	  if (err < 0)
		  printk("Failed to select active pinstate\n");
  }
#endif

  if (ts->reset_pin) {
    err = gpio_request(ts->reset_pin, NULL);
    if (err) {
      dev_err(&client->dev,
	      "Unable to request GPIO pin %d.\n",
	      ts->reset_pin);
      goto err_free_mem;
    }
  }

  shtsc_reset(ts, false);
  shtsc_reset_delay(ts);//2014.11.12 added

  if (gpio_is_valid(ts->irq_pin)) {//2014.11.12 added
    /* configure touchscreen irq gpio */
    err = gpio_request(ts->irq_pin, "shtsc_irq_gpio");
    if (err) {
      dev_err(&client->dev, "unable to request gpio [%d]\n",
	      ts->irq_pin);
      goto err_free_irq_gpio;
    }
  }
  err = gpio_direction_input(ts->irq_pin);
  if (err < 0) {
    dev_err(&client->dev,
	    "Failed to configure input direction for GPIO %d, error %d\n",
	    ts->irq_pin, err);
    goto err_free_irq_gpio;
  }

  client->irq = gpio_to_irq(ts->irq_pin);
  if (client->irq < 0) {
    err = client->irq;
    dev_err(&client->dev,
	    "Unable to get irq number for GPIO %d, error %d\n",
	    ts->irq_pin, err);
    goto err_free_irq_gpio;
  }

  err = request_threaded_irq(client->irq, NULL, shtsc_irq_thread,
                             (IRQF_TRIGGER_HIGH|IRQF_ONESHOT), client->dev.driver->name, ts);
//                             pdata->irqflags | IRQF_ONESHOT, client->dev.driver->name, ts);

  if (err < 0) {
    dev_err(&client->dev,
	    "irq %d busy? error %d\n", client->irq, err);
    goto err_free_irq_gpio;
  }

  input_set_drvdata(input_dev, ts);//2014.10.16 added
  err = input_register_device(input_dev);
  if (err)
    goto err_free_irq;

  i2c_set_clientdata(client, ts);
  device_init_wakeup(&client->dev, 1);

#if defined(DEVICE_LR388K5)
  shtsc_reset(ts, true);
  msleep(100);
#else//DEVICE_LR388K4
  ts->wait_state = WAIT_RESET;
  ts->wait_result = false;
  shtsc_reset(ts, true);
  // wait
  err = WaitAsync(ts);
  if (err)
    goto err_free_irq;

#endif
#if 1
  count = 5;
  while (count)
  {
	  if (shtsc_read_regs(ts, rData, 1, SHTSC_ADDR_BANK))
		  count --;
	  else
		  break;
	  if (count == 0)
	  {
		  printk("sharp TP not connect\n");
		  goto err_free_irq;
	  }
  }
#endif
  VersionModelCode = detectDevice();
  shtsc_system_init(ts);

#if defined(CONFIG_FB)
  ts->fb_notif.notifier_call = fb_notifier_callback;
  ts->dev_sleep = false;
  err = fb_register_client(&ts->fb_notif);

  if (err)
    dev_err(&ts->client->dev, "Unable to register fb_notifier: %d\n",
      err);
#endif
  ts->resume_wq = create_singlethread_workqueue("resume_wq");
  INIT_DELAYED_WORK(&ts->resume_work, resume_event);
  ts->suspend_wq = create_singlethread_workqueue("suspend_wq");
  INIT_DELAYED_WORK(&ts->suspend_work, suspend_event);

#if defined(DEBUG_SHTSC)
  printk(KERN_INFO "[EXIT] shtsc_probe\n");
#endif

  printk(KERN_INFO "SHARP touchscreen controller I2C driver\n");

  return 0;

 err_free_irq:
  free_irq(client->irq, ts);
 err_free_irq_gpio:
  gpio_free(ts->irq_pin);
  shtsc_reset(ts, true);
  if (ts->reset_pin)
    gpio_free(ts->reset_pin);
 err_free_mem:
  input_free_device(input_dev);
  kfree(ts);
  misc_deregister(&shtsc_miscdev);
  return err;
}

static int shtsc_i2c_remove(struct i2c_client *client)
{
  struct shtsc_i2c *ts = i2c_get_clientdata(client);

  shtsc_reset(ts, true);

  mutex_init(&(ts->mutex));

  //	sysfs_remove_group(&client->dev.kobj, &mxt_attr_group);
  free_irq(ts->client->irq, ts);
  input_unregister_device(ts->input);
#if defined(CONFIG_FB)
  if (fb_unregister_client(&ts->fb_notif))
    dev_err(&client->dev, "Error occurred while unregistering fb_notifier.\n");
#elif defined(CONFIG_HAS_EARLYSUSPEND)
  //	unregister_early_suspend(&ts->early_suspend);
#endif
  if (gpio_is_valid(ts->pdata->reset_gpio))
    gpio_free(ts->pdata->reset_gpio);

  if (gpio_is_valid(ts->pdata->irq_gpio))
    gpio_free(ts->pdata->irq_gpio);

  if (client->dev.of_node) {
    kfree(ts->pdata);
  }
  //  kfree(ts->object_table);
  kfree(ts);

  //	debugfs_remove_recursive(debug_base);

  return 0;
}

#elif defined (CONFIG_TOUCHSCREEN_SHTSC_SPI)

/* must be called with ts->mutex held */
static void shtsc_disable(struct shtsc_spi *ts)
{
}

/* must be called with ts->mutex held */
static void shtsc_enable(struct shtsc_spi *ts)
{
}

static int shtsc_open(struct input_dev *input)
{
  struct shtsc_spi *ts = input_get_drvdata(input);

#if defined(DEBUG_SHTSC)
  printk(KERN_INFO "[ENTER] shtsc_open\n");
#endif
  mutex_lock(&ts->mutex);

  if (!ts->suspended)
    shtsc_enable(ts);

  ts->opened = true;

  mutex_unlock(&ts->mutex);

#if defined(DEBUG_SHTSC)
  printk(KERN_INFO "[EXIT] shtsc_open\n");
#endif
  return 0;
}

static void shtsc_close(struct input_dev *input)
{
  struct shtsc_spi *ts = input_get_drvdata(input);

  mutex_lock(&ts->mutex);

  if (!ts->suspended)
    shtsc_disable(ts);

  ts->opened = false;

  mutex_unlock(&ts->mutex);
}

static int shtsc_spi_probe(struct spi_device *spi)
{
  //  const struct shtsc_pdata *pdata = spi->dev.platform_data;
  struct shtsc_i2c_pdata *pdata;

  struct shtsc_spi *ts;
  struct input_dev *input_dev;

  int error;

  g_spi = spi;

#ifdef DEBUG_SHTSC
  printk(KERN_INFO "[ENTER] shtsc_probe\n");
#endif /* DEBUG_SHTSC */

  //2014.10.16 added
  if (client->dev.of_node) {
    pdata = devm_kzalloc(&client->dev,
			 sizeof(struct shtsc_i2c_pdata), GFP_KERNEL);
    if (!pdata) {
      dev_err(&client->dev, "Failed to allocate memory\n");
      return -ENOMEM;
    }
    err = shtsc_parse_dt(&client->dev, pdata);
    if (err){
      kfree(pdata);
      return err;
    }
  } else{
    pdata = client->dev.platform_data;
  }

  /* No pdata no way forward */
  if (!pdata) {
    dev_dbg(&spi->dev, "no platform data\n");
    return -ENODEV;
  }

  if (spi->irq <= 0) {
    dev_dbg(&spi->dev, "no irq\n");
    return -ENODEV;
  }
	
#ifdef DEBUG_SHTSC
  printk(KERN_INFO "[2] shtsc_probe %d\n", spi->irq);
#endif /* DEBUG_SHTSC */
	
  spi->mode = SPI_MODE_3;
  spi->bits_per_word = 8;
  if (!spi->max_speed_hz)
    spi->max_speed_hz = SHTSC_MAX_SPI_SPEED_IN_HZ;

  error = spi_setup(spi);
  if (error)
    return error;

#ifdef DEBUG_SHTSC
  printk(KERN_INFO "[3] shtsc_probe\n");
#endif /* DEBUG_SHTSC */

  ts = kzalloc(sizeof(*ts), GFP_KERNEL);
  g_ts = ts;
  input_dev = input_allocate_device();
	
  if (!ts || !input_dev) {
    error = -ENOMEM;
    goto err_free_mem;
  }
	
#ifdef DEBUG_SHTSC
  printk(KERN_INFO "[4] shtsc_probe\n");
#endif /* DEBUG_SHTSC */
	
  ts->spi = spi;
  ts->input = input_dev;

  ts->pdata = pdata;//2014.10.16 added

  ts->min_x = pdata->panel_minx;
  ts->max_x = pdata->panel_maxx;
  ts->min_y = pdata->panel_miny;
  ts->max_y = pdata->panel_maxy;
  ts->pressure_max = pdata->ts_pressure_max;
  ts->touch_num_max = pdata->ts_touch_num_max;//2014.10.16 added
  ts->flip_x = pdata->ts_flip_x;
  ts->flip_y = pdata->ts_flip_y;
  ts->swap_xy = pdata->ts_swap_xy;

  ts->reset_pin = pdata->reset_gpio;
  ts->irq_pin = pdata->irq_gpio;
  /*
    ts->irq = spi->irq;

    ts->reset_pin = OMAP4PANDA_GPIO_SHTSC_RESET;
  */
  mutex_init(&ts->mutex);
  spin_lock_init(&ts->lock);
  //	setup_timer(&ts->timer, shtsc_timer, (unsigned long)ts); 20141014

  snprintf(ts->phys, sizeof(ts->phys),
	   "%s/input-ts", dev_name(&spi->dev));

  input_dev->name = SHTSC_DRIVER_NAME;
  input_dev->phys = ts->phys;
  input_dev->id.bustype = BUS_SPI;
  input_dev->dev.parent = &spi->dev;
  input_dev->open = shtsc_input_open;//2014.10.16 added
  input_dev->close = shtsc_input_close;//2014.10.16 added

  __set_bit(EV_ABS, input_dev->evbit);
  __set_bit(EV_KEY, input_dev->evbit);
  __set_bit(BTN_TOUCH, input_dev->keybit);//2014.10.16 added
  __set_bit(INPUT_PROP_DIRECT, input_dev->propbit);//2014.10.16 added

  error = input_mt_init_slots(input_dev, SHTSC_MAX_FINGERS);

  if (error)
    goto err_free_mem;
	
  input_set_abs_params(input_dev, ABS_MT_TOUCH_MAJOR, 0, SHTSC_I2C_SIZE_MAX, 0, 0);
  input_set_abs_params(input_dev, ABS_MT_POSITION_X,
		       pdata->disp_minx, pdata->disp_maxx, 0, 0);
  input_set_abs_params(input_dev, ABS_MT_POSITION_Y,
		       pdata->disp_miny, pdata->disp_maxy, 0, 0);
  input_set_abs_params(input_dev, ABS_MT_PRESSURE  , 0, SHTSC_I2C_P_MAX, 0, 0);
  input_set_abs_params(input_dev, ABS_MT_TOOL_TYPE , 0, MT_TOOL_MAX, 0, 0);

  if (ts->reset_pin) {
    error = gpio_request(ts->reset_pin, NULL);
    if (error) {
      dev_err(&spi->dev,
	      "Unable to request GPIO pin %d.\n",
	      ts->reset_pin);
      goto err_free_mem;
    }
  }

  if (ts->spiss_pin) {
    error = gpio_request(ts->spiss_pin, NULL);
    if (error) {
      dev_err(&spi->dev,
	      "Unable to request GPIO pin %d.\n",
	      ts->spiss_pin);
      goto err_free_mem;
    }
  }
	
  input_dev->open = shtsc_open;
  input_dev->close = shtsc_close;

  input_set_drvdata(input_dev, ts);

  error = request_threaded_irq(spi->irq, NULL, shtsc_irq_thread,
			       pdata->irqflags, client->dev.driver->name, ts);

#if defined(DEBUG_SHTSC)
  printk(KERN_INFO "%s(%d): %d\n", __FILE__, __LINE__, error);
#endif
  if (error) {
    dev_err(&spi->dev, "Failed to request irq, err: %d\n", error);
    goto err_free_mem;
  }

#if defined(DEBUG_SHTSC)
  printk(KERN_INFO "[5] shtsc_probe\n");
#endif

  spi_set_drvdata(spi, ts);
  input_set_drvdata(ts->input, ts);//2014.10.16 added
  error = input_register_device(ts->input);
  if (error) {
    dev_err(&spi->dev,
	    "Failed to register input device, err: %d\n", error);
    goto err_clear_drvdata;
  }

  shtsc_reset(g_ts, false);
  msleep(100);
  shtsc_reset(g_ts, true);
  msleep(10);

  VersionModelCode = detectDevice();

  shtsc_system_init(ts);
  msleep(100);

#if defined(DEBUG_SHTSC)
  printk(KERN_INFO "[EXIT] shtsc_probe\n");
#endif

  printk(KERN_INFO "SHARP touchscreen controller SPI driver\n");

  return 0;

 err_clear_drvdata:
  spi_set_drvdata(spi, NULL);
  free_irq(spi->irq, ts);
 err_free_mem:
  input_free_device(input_dev);
  kfree(ts);
  return error;
}

static int shtsc_spi_remove(struct spi_device *spi)
{
  struct shtsc_spi *ts = spi_get_drvdata(spi);

  free_irq(ts->spi->irq, ts);
  input_unregister_device(ts->input);
  kfree(ts);

  spi_set_drvdata(spi, NULL);
  return 0;
}
#else // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
error
#endif // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)

module_init(shtsc_init);
module_exit(shtsc_exit);

MODULE_DESCRIPTION("shtsc SHARP Touchscreen controller Driver");
MODULE_LICENSE("GPL v2");
