/************************************************************************
 *
 *  WILLSEMI TypeC Chipset Driver for Linux & Android.  
 *
 *
 * ######################################################################
 *
 *  Author: lei.huang (lhuang@sh-willsemi.com)
 *
 * Copyright (c) 2016, WillSemi Inc. All rights reserved.
 *
 ************************************************************************/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/gpio.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/of_device.h>
#include <linux/err.h>
#include <linux/i2c.h>
#include <linux/interrupt.h>
#include <linux/power_supply.h>
#include <linux/irq.h>
#include <linux/delay.h>
#include <linux/wakelock.h>
#include <linux/workqueue.h>
#include <linux/usb/class-dual-role.h>
#undef  __CONST_FFS
#define __CONST_FFS(_x) \
        ((_x) & 0x0F ? ((_x) & 0x03 ? ((_x) & 0x01 ? 0 : 1) :\
                                      ((_x) & 0x04 ? 2 : 3)) :\
                       ((_x) & 0x30 ? ((_x) & 0x10 ? 4 : 5) :\
                                      ((_x) & 0x40 ? 6 : 7)))
#undef  FFS
#define FFS(_x) \
        ((_x) ? __CONST_FFS(_x) : 0)
#undef  BITS
#define BITS(_end, _start) \
        ((BIT(_end) - BIT(_start)) + BIT(_end))
#undef  __BITS_GET
#define __BITS_GET(_byte, _mask, _shift) \
        (((_byte) & (_mask)) >> (_shift))
#undef  BITS_GET
#define BITS_GET(_byte, _bit) \
        __BITS_GET(_byte, _bit, FFS(_bit))
#undef  __BITS_SET
#define __BITS_SET(_byte, _mask, _shift, _val) \
        (((_byte) & ~(_mask)) | (((_val) << (_shift)) & (_mask)))
#undef  BITS_SET
#define BITS_SET(_byte, _bit, _val) \
        __BITS_SET(_byte, _bit, FFS(_bit), _val)
#undef  BITS_MATCH
#define BITS_MATCH(_byte, _bit) \
        (((_byte) & (_bit)) == (_bit))
/* Register Map */

#define WUSB3801_REG_VERSION_ID         0x01
#define WUSB3801_REG_CONTROL0           0x02
#define WUSB3801_REG_INTERRUPT          0x03
#define WUSB3801_REG_STATUS             0x04
#define WUSB3801_REG_CONTROL1           0x05
#define WUSB3801_REG_TEST0              0x06
#define WUSB3801_REG_TEST_01            0x07
#define WUSB3801_REG_TEST_02            0x08
#define WUSB3801_REG_TEST_03            0x09
#define WUSB3801_REG_TEST_04            0x0A
#define WUSB3801_REG_TEST_05            0x0B
#define WUSB3801_REG_TEST_06            0x0C
#define WUSB3801_REG_TEST_07            0x0D
#define WUSB3801_REG_TEST_08            0x0E
#define WUSB3801_REG_TEST_09            0x0F
#define WUSB3801_REG_TEST_0A            0x10
#define WUSB3801_REG_TEST_0B            0x11
#define WUSB3801_REG_TEST_0C            0x12
#define WUSB3801_REG_TEST_0D            0x13
#define WUSB3801_REG_TEST_0E            0x14
#define WUSB3801_REG_TEST_0F            0x15
#define WUSB3801_REG_TEST_10            0x16
#define WUSB3801_REG_TEST_11            0x17
#define WUSB3801_REG_TEST_12            0x18


#define WUSB3801_SLAVE_ADDR0            0xc0
#define WUSB3801_SLAVE_ADDR1            0xd0


/*Available modes*/
#define WUSB3801_DRP_ACC                (BIT_REG_CTRL0_RLE_DRP)
#define WUSB3801_DRP                    (BIT_REG_CTRL0_RLE_DRP | BIT_REG_CTRL0_DIS_ACC)
#define WUSB3801_SNK_ACC                (BIT_REG_CTRL0_RLE_SNK)
#define WUSB3801_SNK                    (BIT_REG_CTRL0_RLE_SNK | BIT_REG_CTRL0_DIS_ACC)
#define WUSB3801_SRC_ACC                (BIT_REG_CTRL0_RLE_SRC) 
#define WUSB3801_SRC                    (BIT_REG_CTRL0_RLE_SRC | BIT_REG_CTRL0_DIS_ACC)
#define WUSB3801_DRP_PREFER_SRC_ACC     (WUSB3801_DRP_ACC | BIT_REG_CTRL0_TRY_SRC)  
#define WUSB3801_DRP_PREFER_SRC         (WUSB3801_DRP     | BIT_REG_CTRL0_TRY_SRC)
#define WUSB3801_DRP_PREFER_SNK_ACC     (WUSB3801_DRP_ACC | BIT_REG_CTRL0_TRY_SNK)           
#define WUSB3801_DRP_PREFER_SNK         (WUSB3801_DRP     | BIT_REG_CTRL0_TRY_SNK)


/*TODO: redefine your prefer role here*/
#define WUSB3801_INIT_MODE              (WUSB3801_DRP_PREFER_SNK_ACC)
                                        
/*Registers relevant values*/                                      
#define WUSB3801_VENDOR_ID              0x06

/*Switch to enable/disable feature of specified Registers*/             
#define BIT_REG_CTRL0_DIS_ACC           (0x01 << 7)
#define BIT_REG_CTRL0_TRY_SRC           (0x02 << 5)
#define BIT_REG_CTRL0_TRY_SNK           (0x01 << 5)
#define BIT_REG_CTRL0_CUR_DEF           (0x00 << 3)
#define BIT_REG_CTRL0_CUR_1P5           (0x01 << 3)
#define BIT_REG_CTRL0_CUR_3P0           (0x02 << 3)
#define BIT_REG_CTRL0_RLE_SNK           (0x00 << 1)
#define BIT_REG_CTRL0_RLE_SRC           (0x01 << 1)
#define BIT_REG_CTRL0_RLE_DRP           (0x02 << 1)
#define BIT_REG_CTRL0_INT_MSK           (0x01 << 0)
           
                                        
#define BIT_REG_STATUS_VBUS             (0x01 << 7)
#define BIT_REG_STATUS_STANDBY          (0x00 << 5)
#define BIT_REG_STATUS_CUR_DEF          (0x01 << 5)
#define BIT_REG_STATUS_CUR_MID          (0x02 << 5)
#define BIT_REG_STATUS_CUR_HIGH         (0x03 << 5)
                                        
#define BIT_REG_STATUS_ATC_STB          (0x00 << 1)
#define BIT_REG_STATUS_ATC_SNK          (0x01 << 1)
#define BIT_REG_STATUS_ATC_SRC          (0x02 << 1)
#define BIT_REG_STATUS_ATC_ACC          (0x03 << 1)
#define BIT_REG_STATUS_ATC_DACC         (0x04 << 1)
                                        
#define BIT_REG_STATUS_PLR_STB          (0x00 << 0)
#define BIT_REG_STATUS_PLR_CC1          (0x01 << 0)
#define BIT_REG_STATUS_PLR_CC2          (0x02 << 0)
#define BIT_REG_STATUS_PLR_BOTH         (0x03 << 0)
                                        
#define BIT_REG_CTRL1_SW02_DIN          (0x01 << 4)
#define BIT_REG_CTRL1_SW02_EN           (0x01 << 3)
#define BIT_REG_CTRL1_SW01_DIN          (0x01 << 2)
#define BIT_REG_CTRL1_SW01_EN           (0x01 << 1)
#define BIT_REG_CTRL1_SM_RST            (0x01 << 0)



#define BIT_REG_TEST02_FORCE_ERR_RCY    (0x01)

#define WUSB3801_WAIT_VBUS               0x40
/*Fixed duty cycle period. 40ms:40ms*/
#define WUSB3801_TGL_40MS                0
#define WUSB3801_HOST_DEFAULT            0
#define WUSB3801_HOST_1500MA             1
#define WUSB3801_HOST_3000MA             2
#define WUSB3801_INT_ENABLE              0x00
#define WUSB3801_INT_DISABLE             0x01
#define WUSB3801_DISABLED                0x0A
#define WUSB3801_ERR_REC                 0x01
#define WUSB3801_VBUS_OK                 0x80

#define WUSB3801_SNK_0MA                (0x00 << 5)
#define WUSB3801_SNK_DEFAULT            (0x01 << 5)
#define WUSB3801_SNK_1500MA             (0x02 << 5)
#define WUSB3801_SNK_3000MA             (0x03 << 5)
#define WUSB3801_ATTACH                  0x1C

//#define WUSB3801_TYPE_PWR_ACC           (0x00 << 2) /*Ra/Rd treated as Open*/  
#define WUSB3801_TYPE_INVALID           (0x00)
#define WUSB3801_TYPE_SNK               (0x01 << 2)
#define WUSB3801_TYPE_SRC               (0x02 << 2)      
#define WUSB3801_TYPE_AUD_ACC           (0x03 << 2)
#define WUSB3801_TYPE_DBG_ACC           (0x04 << 2)

#define WUSB3801_INT_DETACH              (0x01 << 1)
#define WUSB3801_INT_ATTACH              (0x01 << 0)

#define WUSB3801_REV20                   0x02

/* Masks for Read-Modified-Write operations*/
#define WUSB3801_HOST_CUR_MASK           0x18  /*Host current for IIC*/
#define WUSB3801_INT_MASK                0x01
#define WUSB3801_BCLVL_MASK              0x60
#define WUSB3801_TYPE_MASK               0x1C
#define WUSB3801_MODE_MASK               0xE6  /*Roles relevant bits*/
#define WUSB3801_INT_STS_MASK            0x03
#define WUSB3801_FORCE_ERR_RCY_MASK      0x80  /*Force Error recovery*/
#define WUSB3801_ROLE_MASK               0x06
#define WUSB3801_VENDOR_ID_MASK          0x07
#define WUSB3801_VERSION_ID_MASK         0xF8
#define WUSB3801_POLARITY_CC_MASK        0x03
#define WUSB3801_CC_STS_MASK            0x03


/* WUSB3801 STATES MACHINES */
#define WUSB3801_STATE_DISABLED             0x00
#define WUSB3801_STATE_ERROR_RECOVERY       0x01
#define WUSB3801_STATE_UNATTACHED_SNK       0x02
#define WUSB3801_STATE_UNATTACHED_SRC       0x03
#define WUSB3801_STATE_ATTACHWAIT_SNK       0x04
#define WUSB3801_STATE_ATTACHWAIT_SRC       0x05
#define WUSB3801_STATE_ATTACHED_SNK         0x06
#define WUSB3801_STATE_ATTACHED_SRC         0x07
#define WUSB3801_STATE_AUDIO_ACCESSORY      0x08
#define WUSB3801_STATE_DEBUG_ACCESSORY      0x09
#define WUSB3801_STATE_TRY_SNK              0x0A
#define WUSB3801_STATE_TRYWAIT_SRC          0x0B
#define WUSB3801_STATE_TRY_SRC              0x0C
#define WUSB3801_STATE_TRYWAIT_SNK          0x0D

#define WUSB3801_CC2_CONNECTED 1
#define WUSB3801_CC1_CONNECTED 0

/* wake lock timeout in ms */
#define WUSB3801_WAKE_LOCK_TIMEOUT          1000
/*1.5 Seconds timeout for force detection*/
#define ROLE_SWITCH_TIMEOUT		              1500


/*Private data*/
typedef struct wusb3801_data 
{
	uint32_t  int_gpio;
	uint8_t  init_mode;
	uint8_t  dfp_power;
	uint8_t  dttime;
	// ontim : houzn add start
	u8 usb_switch_asel;
	u8 hs_det;
	// ontim : houzn add end
}wusb3801_data_t;

/*Working context structure*/
typedef struct wusb3801_chip 
{
	struct      i2c_client *client;
	struct      wusb3801_data *pdata;
	struct      workqueue_struct  *cc_wq;
	int         irq_gpio;
	int         ufp_power;
	uint8_t     mode;
	uint8_t     dev_id;
	uint8_t     type;
	uint8_t     state;
	uint8_t     bc_lvl;
	uint8_t     dfp_power;
	uint8_t     dttime;
	uint8_t     attached;
	uint8_t     init_state;
	uint8_t		defer_init;	//work round the additional interrupt caused by mode change 
	int         try_attcnt;
	struct      work_struct dwork;
	struct      wake_lock wlock;
	struct      mutex mlock;
	struct      power_supply *usb_psy;
	struct      dual_role_phy_instance *dual_role;
	struct      dual_role_phy_desc *desc;
	

	struct pinctrl *wusb3801_pinctrl;
    struct pinctrl_state *gpio_state_active;
    struct pinctrl_state *gpio_state_suspend;

}wusb3801_chip_t;

#define wusb3801_update_state(chip, st)                      \
	if(chip) {                                                 \
		chip->state = st;                                        \
		dev_info(&chip->client->dev, "%s: %s\n", __func__, #st); \
		wake_up_interruptible(&wmode_switch);                     \
	}

#define STR(s)    #s
#define STRV(s)   STR(s)
// ontim : houzn add start
enum WUSB_SELECTION {
	WUSB_USB,
	WUSB_AUDIO,
};
enum WAUDIO_DETECTION {
	WAUDIO_INSERT,
	WAUDIO_REMOVE,
};
// ontim : houzn add end

static void wusb3801_detach(struct wusb3801_chip *chip);

DECLARE_WAIT_QUEUE_HEAD(wmode_switch);


/************************************************************************
 *
 *       wusb3801_write_masked_byte
 *
 *  Description :
 *  -------------
 *  Read-Modified-Writeback operation through I2C communication.
 *
 *  Parameter     :
 *  -----------
 *  Client         :    Pointer to I2C client. 
 *  Addr           :    Address of internal register of slave device
 *  Mask           :    Mask to prevent irrelevant bit changes
 *  val            :    Data wants to write.   
 *  Return values  :    Zero if no error, else error code.
 *  ---------------
 *  None
 *
 ************************************************************************/
 
static int wusb3801_write_masked_byte(struct i2c_client *client,
					uint8_t addr, uint8_t mask, uint8_t val)
{
	int rc;
	if (!mask){
		/* no actual access */
		rc = -EINVAL;
		goto out;
	}
	rc = i2c_smbus_read_byte_data(client, addr);
	if (!IS_ERR_VALUE(rc)){
		rc = i2c_smbus_write_byte_data(client,
			addr, BITS_SET((uint8_t)rc, mask, val));
	}
out:
	return rc;
}

static int wusb3801_read_device_id(struct wusb3801_chip *chip)
{
	struct device *cdev = &chip->client->dev;
	int rc;
	rc = i2c_smbus_read_byte_data(chip->client, WUSB3801_REG_VERSION_ID);
	if (IS_ERR_VALUE(rc))
		return rc;
	dev_info(cdev, "VendorID register: 0x%02x\n", rc );
	if((rc & WUSB3801_VENDOR_ID_MASK) != WUSB3801_VENDOR_ID){
		return -EINVAL;	
	}
	chip->dev_id = rc;
	dev_info(cdev, "Vendor id: 0x%02x, Version id: 0x%02x\n"
			,rc & WUSB3801_VENDOR_ID_MASK, (rc & WUSB3801_VERSION_ID_MASK) >> 3);
	
	return 0;
}

static int wusb3801_update_status(struct wusb3801_chip *chip)
{
	struct device *cdev = &chip->client->dev;
	int rc;

	/* Get control0 register */
	rc = i2c_smbus_read_byte_data(chip->client, WUSB3801_REG_CONTROL0);
	if (IS_ERR_VALUE(rc)) {
		dev_err(cdev, "%s: fail to read mode\n", __func__);
		return rc;
	}

	chip->mode      =  rc & WUSB3801_MODE_MASK;
	chip->dfp_power =  BITS_GET(rc, WUSB3801_HOST_CUR_MASK);
	chip->dttime    =  WUSB3801_TGL_40MS;

	return 0;
}


static int wusb3801_check_modes(uint8_t mode)
{
	switch(mode){
		case WUSB3801_DRP_ACC            :
		case WUSB3801_DRP                :
		case WUSB3801_SNK_ACC            :
		case WUSB3801_SNK                :
		case WUSB3801_SRC_ACC            :
		case WUSB3801_SRC                :
		case WUSB3801_DRP_PREFER_SRC_ACC :
		case WUSB3801_DRP_PREFER_SRC     :
		case WUSB3801_DRP_PREFER_SNK_ACC :
		case WUSB3801_DRP_PREFER_SNK     :
			return 0;
			break;
		default:
			break;
	}
	return -EINVAL;
}


static int wusb3801_set_chip_state(struct wusb3801_chip *chip, uint8_t state)
{
	struct device *cdev = &chip->client->dev;
	int rc = 0;

	if(state > WUSB3801_STATE_UNATTACHED_SRC)
		return -EINVAL;
		

  rc = i2c_smbus_write_byte_data(chip->client,
			   WUSB3801_REG_CONTROL1, 
			   (state == WUSB3801_STATE_DISABLED) ? \
			             WUSB3801_DISABLED :        \
			             0);

	if (IS_ERR_VALUE(rc)) {
		dev_err(cdev, "failed to write state machine(%d)\n", rc);
	}
	
	chip->init_state = state;

	return rc;
}


static int wusb3801_set_mode(struct wusb3801_chip *chip, uint8_t mode)
{
	struct device *cdev = &chip->client->dev;
	int rc = 0;
	
	if (mode != chip->mode) {
		rc = i2c_smbus_read_byte_data(chip->client, WUSB3801_REG_CONTROL0);
		if (IS_ERR_VALUE(rc)) {
			dev_err(cdev, "%s: fail to read mode\n", __func__);
			return rc;
		}
		rc &= ~WUSB3801_MODE_MASK;

		rc |= (mode | WUSB3801_INT_MASK);//Disable the chip interrupt
	  	rc = i2c_smbus_write_byte_data(chip->client,
				   WUSB3801_REG_CONTROL0, rc);

		if (IS_ERR_VALUE(rc)) {
			dev_err(cdev, "failed to write mode(%d)\n", rc);
			return rc;
		}

		//Clear the chip interrupt
		rc = i2c_smbus_read_byte_data(chip->client, WUSB3801_REG_INTERRUPT);
		if (IS_ERR_VALUE(rc)) {
			dev_err(cdev, "%s: fail to clear chip interrupt\n", __func__);
			return rc;
		}

		rc = i2c_smbus_read_byte_data(chip->client, WUSB3801_REG_CONTROL0);
		if (IS_ERR_VALUE(rc)) {
			dev_err(cdev, "%s: fail to read chip interrupt\n", __func__);
			return rc;
		}
		rc &= ~WUSB3801_INT_MASK;//enable the chip interrupt
		rc = i2c_smbus_write_byte_data(chip->client,
				   WUSB3801_REG_CONTROL0, rc);

		if (IS_ERR_VALUE(rc)) {
			dev_err(cdev, "failed to enable chip interrupt(%d)\n", rc);
			return rc;
		}

		chip->mode = mode;
	}

 	dev_dbg(cdev, "%s: mode (0x%02x) (0x%02x)\n", __func__, chip->mode , mode);

	return rc;
}

static int wusb3801_set_dfp_power(struct wusb3801_chip *chip, uint8_t hcurrent)
{
	struct device *cdev = &chip->client->dev;
	int rc = 0;

	if (hcurrent == chip->dfp_power) {
		dev_dbg(cdev, "vaule is not updated(%d)\n",
					hcurrent);
		return rc;
	}

	rc = wusb3801_write_masked_byte(chip->client,
					WUSB3801_REG_CONTROL0,
					WUSB3801_HOST_CUR_MASK,
					hcurrent);
	if (IS_ERR_VALUE(rc)) {
		dev_err(cdev, "failed to write current(%d)\n", rc);
		return rc;
	}

	chip->dfp_power = hcurrent;

	dev_dbg(cdev, "%s: host current(%d)\n", __func__, hcurrent);

	return rc;
}

/**********************************************************************
 * When 3A capable DRP device is connected without VBUS,
 * DRP always detect it as SINK device erroneously.
 * Since USB Type-C specification 1.0 and 1.1 doesn't
 * consider this corner case, apply workaround for this case.
 * Set host mode current to 1.5A initially, and then change
 * it to default USB current right after detection SINK port.
 ***********************************************************************/
static int wusb3801_init_force_dfp_power(struct wusb3801_chip *chip)
{
	struct device *cdev = &chip->client->dev;
	int rc = 0;

	rc = wusb3801_write_masked_byte(chip->client,
					WUSB3801_REG_CONTROL0,
					WUSB3801_HOST_CUR_MASK,
					WUSB3801_HOST_3000MA);
	if (IS_ERR_VALUE(rc)) {
		dev_err(cdev, "failed to write current\n");
		return rc;
	}

	chip->dfp_power = WUSB3801_HOST_3000MA;

	dev_dbg(cdev, "%s: host current (%d)\n", __func__, rc);

	return rc;
}

/************************************************************************
 *
 *       wusb3801_set_toggle_time
 *
 *  Description :
 *  -------------
 *  Wusb3801 varints only support for fixed duty cycles periods (40ms:40ms)
 *
 ************************************************************************/
static int wusb3801_set_toggle_time(struct wusb3801_chip *chip, uint8_t toggle_time)
{
	struct device *cdev = &chip->client->dev;
	int rc = 0;

	if (toggle_time != WUSB3801_TGL_40MS) {
		dev_err(cdev, "toggle_time(%d) is unavailable\n", toggle_time);
		return -EINVAL;
	}
	
	chip->dttime = WUSB3801_TGL_40MS;

	dev_dbg(cdev, "%s: Fixed toggle time (%d)\n", __func__, chip->dttime);

	return rc;
}


static int wusb3801_init_reg(struct wusb3801_chip *chip)
{
	struct device *cdev = &chip->client->dev;
	int rc = 0;

	/* change current */
	rc = wusb3801_init_force_dfp_power(chip);
	if (IS_ERR_VALUE(rc))
		dev_err(cdev, "%s: failed to force dfp power\n",
				__func__);


	/* change mode */
	rc = wusb3801_set_mode(chip, chip->pdata->init_mode);
	if (IS_ERR_VALUE(rc))
		dev_err(cdev, "%s: failed to set mode\n",
				__func__);
	rc = wusb3801_set_chip_state(chip,
				WUSB3801_STATE_ERROR_RECOVERY);

	if (IS_ERR_VALUE(rc))
		dev_err(cdev, "%s: Reset state failed.\n",
				__func__);

	return rc;
}

static int wusb3801_reset_device(struct wusb3801_chip *chip)
{
	struct device *cdev = &chip->client->dev;
	int rc = 0;

	rc = wusb3801_update_status(chip);
	if (IS_ERR_VALUE(rc))
		dev_err(cdev, "fail to read status\n");

	rc = wusb3801_init_reg(chip);
	if (IS_ERR_VALUE(rc))
		dev_err(cdev, "fail to init reg\n");

	wusb3801_detach(chip);

	/* clear global interrupt mask */
	rc = wusb3801_write_masked_byte(chip->client,
				WUSB3801_REG_CONTROL0,
				WUSB3801_INT_MASK,
				WUSB3801_INT_ENABLE);
	if (IS_ERR_VALUE(rc)) {
		dev_err(cdev, "%s: fail to init\n", __func__);
		return rc;
	}

	dev_info(cdev, "mode[0x%02x], host_cur[0x%02x], dttime[0x%02x]\n",
			chip->mode, chip->dfp_power, chip->dttime);

	return rc;
}

// ontim : houzn add start
static void wusb3801_usb_aud_switch(struct wusb3801_chip *chip, enum WUSB_SELECTION value) {
	struct device *cdev = &chip->client->dev;

	if (!gpio_is_valid(chip->pdata->usb_switch_asel)) {
		dev_err(cdev, "%s: gpio %d not valid.\n", __func__, chip->pdata->usb_switch_asel);
		return;
	}
	// gpio33
	switch (value) {
	case WUSB_USB:
		dev_info(cdev, "wusb3801 select usb side.\n");
		if (gpio_get_value_cansleep(chip->pdata->usb_switch_asel))
			gpio_set_value_cansleep(chip->pdata->usb_switch_asel, 0); /* select usb */
		break;
	case WUSB_AUDIO:
		dev_info(cdev, "wusb3801 select audio side.\n");
		if (!gpio_get_value_cansleep(chip->pdata->usb_switch_asel))
			gpio_set_value_cansleep(chip->pdata->usb_switch_asel, 1); /* select audio */
		break;
	default:
		dev_err(cdev, "%s: value: %d is not valid.\n", __func__, value);
		break;
	}
}

static void wusb3801_hs_det(struct wusb3801_chip *chip, enum WAUDIO_DETECTION value) {
	struct device *cdev = &chip->client->dev;

	if (!gpio_is_valid(chip->pdata->hs_det)) {
		dev_err(cdev, "%s: gpio %d not valid.\n", __func__, chip->pdata->hs_det);
		return;
	}
	// gpio25
	switch (value) {
	case WAUDIO_INSERT:
		dev_info(cdev, "wusb3801 trigger insert detection.\n");
		if (gpio_get_value_cansleep(chip->pdata->hs_det))
			gpio_set_value_cansleep(chip->pdata->hs_det, 0); /* insert */
		break;
	case WAUDIO_REMOVE:
		dev_info(cdev, "wusb3801 trigger remove detection.\n");
		if (!gpio_get_value_cansleep(chip->pdata->hs_det))
			gpio_set_value_cansleep(chip->pdata->hs_det, 1); /* remove */
		break;
	default:
		dev_err(cdev, "%s: value: %d is not valid.\n", __func__, value);
		break;
	}
}

// ontim : houzn add end


/************************************************************************
 *
 *       fregdump_show
 *
 *  Description :
 *  -------------
 *  Dump registers to user space. there is side-effects for Read/Clear 
 *  registers. For example interrupt status. 
 *
 ************************************************************************/
static ssize_t wregdump_show(struct device *dev,
				struct device_attribute *attr,
				char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct wusb3801_chip *chip = i2c_get_clientdata(client);
	int i, rc, ret = 0;

	mutex_lock(&chip->mlock);
	for (i = WUSB3801_REG_VERSION_ID ; i <= WUSB3801_REG_TEST_12; i++) 
	{
		rc = i2c_smbus_read_byte_data(chip->client, (uint8_t)i);
		if (IS_ERR_VALUE(rc)) 
		{
			pr_err("cannot read 0x%02x\n", i);
			rc = 0;
		}
		ret += snprintf(buf + ret, 1024 - ret, "from 0x%02x read 0x%02x\n", (uint8_t)i, rc);
	}
	mutex_unlock(&chip->mlock);

	return ret;
}

DEVICE_ATTR(wregdump, S_IRUGO, wregdump_show, NULL);


/************************************************************************
 *
 *       ftype_show
 *
 *  Description :
 *  -------------
 *  Dump types of attached devices
 *
 ************************************************************************/
static ssize_t wtype_show(struct device *dev,
			struct device_attribute *attr,
			char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct wusb3801_chip *chip = i2c_get_clientdata(client);
	int ret;

	mutex_lock(&chip->mlock);
	switch (chip->type) {
	case WUSB3801_TYPE_SNK:
		ret = snprintf(buf, PAGE_SIZE, "SINK(%d)\n", chip->type);
		break;
	case WUSB3801_TYPE_SRC:
		ret = snprintf(buf, PAGE_SIZE, "SOURCE(%d)\n", chip->type);
		break;
	case WUSB3801_TYPE_DBG_ACC:
		ret = snprintf(buf, PAGE_SIZE, "DEBUGACC(%d)\n", chip->type);
		break;
	case WUSB3801_TYPE_AUD_ACC:
		ret = snprintf(buf, PAGE_SIZE, "AUDIOACC(%d)\n", chip->type);
		break;
	default:
		ret = snprintf(buf, PAGE_SIZE, "NOTYPE(%d)\n", chip->type);
		break;
	}
	mutex_unlock(&chip->mlock);

	return ret;
}

DEVICE_ATTR(wtype, S_IRUGO , wtype_show, NULL);

/************************************************************************
 *
 *  fchip_state_show/fchip_state_store
 *
 *  Description :
 *  -------------
 *  Get/Set state to/from user spaces.
 *
 ************************************************************************/
 
static ssize_t wchip_state_show(struct device *dev,
			struct device_attribute *attr,
			char *buf)
{
	return snprintf(buf, PAGE_SIZE,
			STRV(WUSB3801_STATE_DISABLED) " - WUSB3801_STATE_DISABLED\n"
			STRV(WUSB3801_STATE_ERROR_RECOVERY) " - WUSB3801_STATE_ERROR_RECOVERY\n"
			STRV(WUSB3801_STATE_UNATTACHED_SNK) " - WUSB3801_STATE_UNATTACHED_SNK\n"
			STRV(WUSB3801_STATE_UNATTACHED_SRC) " - WUSB3801_STATE_UNATTACHED_SRC\n");

}


static ssize_t wchip_state_store(struct device *dev,
				struct device_attribute *attr,
				const char *buff, size_t size)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct wusb3801_chip *chip = i2c_get_clientdata(client);
	int state = 0;
	int rc = 0;

	if (sscanf(buff, "%d", &state) == 1) 
	{
		mutex_lock(&chip->mlock);
		if(((state == WUSB3801_STATE_UNATTACHED_SNK) &&
		((chip->mode & WUSB3801_ROLE_MASK) == BIT_REG_CTRL0_RLE_SRC)) || \
		((state == WUSB3801_STATE_UNATTACHED_SRC) &&
		((chip->mode & WUSB3801_ROLE_MASK) == BIT_REG_CTRL0_RLE_SNK)))
		{
			mutex_unlock(&chip->mlock);
			return -EINVAL;
		}


		rc = wusb3801_set_chip_state(chip, (uint8_t)state);
		if (IS_ERR_VALUE(rc)) {
			mutex_unlock(&chip->mlock);
			return rc;
		}

		wusb3801_detach(chip);
		mutex_unlock(&chip->mlock);
		return size;
	}

	return -EINVAL;
}

DEVICE_ATTR(wchip_state, S_IRUGO | S_IWUSR, wchip_state_show, wchip_state_store);

/************************************************************************
 *
 *  fmode_show/fmode_store
 *
 *  Description :
 *  -------------
 *  Dump/Set role to/from user spaces.
 ************************************************************************/
static ssize_t wmode_show(struct device *dev,
			struct device_attribute *attr,
			char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct wusb3801_chip *chip = i2c_get_clientdata(client);
	int ret;

	mutex_lock(&chip->mlock);
	switch (chip->mode) {
		case WUSB3801_DRP_ACC:
			ret = snprintf(buf, PAGE_SIZE, "DRP+ACC(%d)\n", chip->mode);
			break;
		case WUSB3801_DRP:
			ret = snprintf(buf, PAGE_SIZE, "DRP(%d)\n", chip->mode);
			break;
		case WUSB3801_SNK_ACC:
			ret = snprintf(buf, PAGE_SIZE, "SNK+ACC(%d)\n", chip->mode);
			break;
		case WUSB3801_SNK:
			ret = snprintf(buf, PAGE_SIZE, "SNK(%d)\n", chip->mode);
			break;
		case WUSB3801_SRC_ACC:
			ret = snprintf(buf, PAGE_SIZE, "SRC+ACC(%d)\n", chip->mode);
			break;
		case WUSB3801_SRC:
			ret = snprintf(buf, PAGE_SIZE, "SRC(%d)\n", chip->mode);
			break;
		case WUSB3801_DRP_PREFER_SRC_ACC:
			ret = snprintf(buf, PAGE_SIZE, "DRP+ACC+PREFER_SRC(%d)\n", chip->mode);
			break;
		case WUSB3801_DRP_PREFER_SRC:
			ret = snprintf(buf, PAGE_SIZE, "DRP+PREFER_SRC(%d)\n", chip->mode);
			break;
		case WUSB3801_DRP_PREFER_SNK_ACC:
			ret = snprintf(buf, PAGE_SIZE, "DRP+ACC+PREFER_SNK(%d)\n", chip->mode);
			break;
		case WUSB3801_DRP_PREFER_SNK:
			ret = snprintf(buf, PAGE_SIZE, "DRP+PREFER_SNK(%d)\n", chip->mode);
			break;
		default:
			ret = snprintf(buf, PAGE_SIZE, "UNKNOWN(%d)\n", chip->mode);
			break;
	}
	mutex_unlock(&chip->mlock);

	return ret;
}

static ssize_t wmode_store(struct device *dev,
				struct device_attribute *attr,
				const char *buff, size_t size)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct wusb3801_chip *chip = i2c_get_clientdata(client);
	int mode = 0;
	int rc = 0;

	if (sscanf(buff, "%d", &mode) == 1) {
		mutex_lock(&chip->mlock);

		/*
		 * since device trigger to usb happens independent
		 * from charger based on vbus, setting SRC modes
		 * doesn't prevent usb enumeration as device
		 * KNOWN LIMITATION
		 */
		rc = wusb3801_set_mode(chip, (uint8_t)mode);
		if (IS_ERR_VALUE(rc)) {
			mutex_unlock(&chip->mlock);
			return rc;
		}

		rc = wusb3801_set_chip_state(chip,
					WUSB3801_STATE_ERROR_RECOVERY);
		if (IS_ERR_VALUE(rc)) {
			mutex_unlock(&chip->mlock);
			return rc;
		}


		wusb3801_detach(chip);
		mutex_unlock(&chip->mlock);
		return size;
	}

	return -EINVAL;
}
DEVICE_ATTR(wmode, S_IRUGO | S_IWUSR, wmode_show, wmode_store);

/************************************************************************
 *
 *  fdttime_show/fdttime_store
 *
 *  Description :
 *  -------------
 *  Get/Set duty cycles period from/to user spaces. 
 *  Noted that: Wusb3801 uses fixed duty cycles percentage.
 ************************************************************************/
static ssize_t wdttime_show(struct device *dev,
				struct device_attribute *attr,
				char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct wusb3801_chip *chip = i2c_get_clientdata(client);
	int ret;

	mutex_lock(&chip->mlock);
	ret = snprintf(buf, PAGE_SIZE, "%u\n", chip->dttime);
	mutex_unlock(&chip->mlock);
	return ret;
}

static ssize_t wdttime_store(struct device *dev,
				struct device_attribute *attr,
				const char *buff, size_t size)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct wusb3801_chip *chip = i2c_get_clientdata(client);
	int dttime = 0;
	int rc = 0;

	if (sscanf(buff, "%d", &dttime) == 1) {
		mutex_lock(&chip->mlock);
		rc = wusb3801_set_toggle_time(chip, (uint8_t)dttime);
		mutex_unlock(&chip->mlock);
		if (IS_ERR_VALUE(rc))
			return rc;

		return size;
	}

	return -EINVAL;
}
DEVICE_ATTR(wdttime, S_IRUGO | S_IWUSR, wdttime_show, wdttime_store);

/************************************************************************
 *
 *  fhostcur_show/fhostcur_store
 *
 *  Description :
 *  -------------
 *  Get/Set host current from/to user spaces. 
 ************************************************************************/
static ssize_t whostcur_show(struct device *dev,
				struct device_attribute *attr,
				char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct wusb3801_chip *chip = i2c_get_clientdata(client);
	int ret;

	mutex_lock(&chip->mlock);
	ret = snprintf(buf, PAGE_SIZE, "%u\n", chip->dfp_power);
	mutex_unlock(&chip->mlock);
	return ret;
}

static ssize_t whostcur_store(struct device *dev,
				struct device_attribute *attr,
				const char *buff, size_t size)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct wusb3801_chip *chip = i2c_get_clientdata(client);
	int buf = 0;
	int rc = 0;

	if (sscanf(buff, "%d", &buf) == 1) {
		mutex_lock(&chip->mlock);
		rc = wusb3801_set_dfp_power(chip, (uint8_t)buf);
		mutex_unlock(&chip->mlock);
		if (IS_ERR_VALUE(rc))
			return rc;

		return size;
	}

	return -EINVAL;
}
DEVICE_ATTR(whostcur, S_IRUGO | S_IWUSR, whostcur_show, whostcur_store);

/************************************************************************
 *
 *  fclientcur_show
 *
 *  Description :
 *  -------------
 *  dumps client current to user spaces. 
 ************************************************************************/
static ssize_t wclientcur_show(struct device *dev,
				struct device_attribute *attr,
				char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct wusb3801_chip *chip = i2c_get_clientdata(client);
	int ret;

	mutex_lock(&chip->mlock);
	ret = snprintf(buf, PAGE_SIZE, "%d\n", chip->ufp_power);
	mutex_unlock(&chip->mlock);
	return ret;
}
DEVICE_ATTR(wclientcur, S_IRUGO, wclientcur_show, NULL);

/************************************************************************
 *
 *  freset_store
 *
 *  Description :
 *  -------------
 *  Reset state machine of WUSB3801
 ************************************************************************/
 
static ssize_t wreset_store(struct device *dev,
				struct device_attribute *attr,
				const char *buff, size_t size)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct wusb3801_chip *chip = i2c_get_clientdata(client);
	uint32_t reset = 0;
	int rc = 0;

	if (sscanf(buff, "%u", &reset) == 1) {
		mutex_lock(&chip->mlock);
		rc = wusb3801_reset_device(chip);
		mutex_unlock(&chip->mlock);
		if (IS_ERR_VALUE(rc))
			return rc;

		return size;
	}

	return -EINVAL;
}
DEVICE_ATTR(wreset, S_IWUSR, NULL, wreset_store);



static int wusb3801_create_devices(struct device *cdev)
{
	int ret = 0;

	ret = device_create_file(cdev, &dev_attr_wchip_state);
	if (ret < 0) {
		dev_err(cdev, "failed to create dev_attr_wchip_state\n");
		ret = -ENODEV;
		goto err0;
	}

	ret = device_create_file(cdev, &dev_attr_wtype);
	if (ret < 0) {
		dev_err(cdev, "failed to create dev_attr_wtype\n");
		ret = -ENODEV;
		goto err1;
	}

	ret = device_create_file(cdev, &dev_attr_wmode);
	if (ret < 0) {
		dev_err(cdev, "failed to create dev_attr_wmode\n");
		ret = -ENODEV;
		goto err2;
	}

	ret = device_create_file(cdev, &dev_attr_wreset);
	if (ret < 0) {
		dev_err(cdev, "failed to create dev_attr_wreset\n");
		ret = -ENODEV;
		goto err3;
	}

	ret = device_create_file(cdev, &dev_attr_wdttime);
	if (ret < 0) {
		dev_err(cdev, "failed to create dev_attr_wdttime\n");
		ret = -ENODEV;
		goto err4;
	}

	ret = device_create_file(cdev, &dev_attr_whostcur);
	if (ret < 0) {
		dev_err(cdev, "failed to create dev_attr_whostcur\n");
		ret = -ENODEV;
		goto err5;
	}

	ret = device_create_file(cdev, &dev_attr_wclientcur);
	if (ret < 0) {
		dev_err(cdev, "failed to create dev_attr_wclientcur\n");
		ret = -ENODEV;
		goto err6;
	}

	ret = device_create_file(cdev, &dev_attr_wregdump);
	if (ret < 0) {
		dev_err(cdev, "failed to create dev_attr_wregdump\n");
		ret = -ENODEV;
		goto err7;
	}

err7:
	device_remove_file(cdev, &dev_attr_wclientcur);
err6:
	device_remove_file(cdev, &dev_attr_whostcur);
err5:
	device_remove_file(cdev, &dev_attr_wdttime);
err4:
	device_remove_file(cdev, &dev_attr_wreset);
err3:
	device_remove_file(cdev, &dev_attr_wmode);
err2:
	device_remove_file(cdev, &dev_attr_wtype);
err1:
	device_remove_file(cdev, &dev_attr_wchip_state);
err0:
	return ret;
}

static void wusb3801_destory_device(struct device *cdev)
{
	device_remove_file(cdev, &dev_attr_wchip_state);
	device_remove_file(cdev, &dev_attr_wtype);
	device_remove_file(cdev, &dev_attr_wmode);
	device_remove_file(cdev, &dev_attr_wreset);
	device_remove_file(cdev, &dev_attr_wdttime);
	device_remove_file(cdev, &dev_attr_whostcur);
	device_remove_file(cdev, &dev_attr_wclientcur);
	device_remove_file(cdev, &dev_attr_wregdump);
}



static int wusb3801_power_set_icurrent_max(struct wusb3801_chip *chip,
						int icurrent)
{
/*
* TODO: Set your PMIC function
*/

	const union power_supply_propval ret = {icurrent,};

	chip->ufp_power = icurrent;
	if (chip->usb_psy->set_property)
		return chip->usb_psy->set_property(chip->usb_psy,
				POWER_SUPPLY_PROP_INPUT_CURRENT_MAX, &ret);
	return -ENXIO;
}

static void wusb3801_bclvl_changed(struct wusb3801_chip *chip)
{
	struct device *cdev = &chip->client->dev;
	int rc, limit;
	uint8_t status, type;

	rc = i2c_smbus_read_byte_data(chip->client,
				WUSB3801_REG_STATUS);
	if (IS_ERR_VALUE(rc)) {
		dev_err(cdev, "%s: failed to read\n", __func__);
		if(IS_ERR_VALUE(wusb3801_reset_device(chip)))
			dev_err(cdev, "%s: failed to reset\n", __func__);
		return;
	}

	status = (rc & WUSB3801_TYPE_MASK) ? 1 : 0;
	type = status  ? rc & WUSB3801_TYPE_MASK : WUSB3801_TYPE_INVALID;

	dev_info(cdev, "%s: sts[0x%02x], type[0x%02x]\n",__func__, status, type);

	if (type == WUSB3801_TYPE_SRC) {

		
		chip->bc_lvl = rc & WUSB3801_BCLVL_MASK;
		limit = (chip->bc_lvl == WUSB3801_SNK_3000MA ? 3000 :
				(chip->bc_lvl == WUSB3801_SNK_1500MA ? 1500 : 0));

		wusb3801_power_set_icurrent_max(chip, limit);
		
	    dev_dbg(cdev, "%s: limit = %d\n",__func__, limit);
	}
	
}



static void wusb3801_src_detected(struct wusb3801_chip *chip)
{
	struct device *cdev = &chip->client->dev;
	dev_info(cdev, "%s \n",__func__);
	if((chip->mode & WUSB3801_ROLE_MASK) == BIT_REG_CTRL0_RLE_SRC){
		dev_err(cdev, "not support in source mode\n");
		if(IS_ERR_VALUE(wusb3801_reset_device(chip)))
			dev_err(cdev, "%s: failed to reset\n", __func__);
		return;
	}
	
	wusb3801_update_state(chip, WUSB3801_STATE_ATTACHED_SNK);
	
	if(chip->dual_role == NULL)
	{
		pr_err("houzn : chip->dual_role == NULL src\n");
		return;
	}
	dual_role_instance_changed(chip->dual_role);
	
	chip->type = WUSB3801_TYPE_SRC;
}

static void wusb3801_snk_detected(struct wusb3801_chip *chip)
{
	struct device *cdev = &chip->client->dev;
	dev_info(cdev, "%s \n",__func__);
	if((chip->mode & WUSB3801_ROLE_MASK) == BIT_REG_CTRL0_RLE_SNK){
		dev_err(cdev, "not support in sink mode\n");
		if(IS_ERR_VALUE(wusb3801_reset_device(chip)))
			dev_err(cdev, "%s: failed to reset\n", __func__);
		return;
	}

	/**
	*  TODO: Add you code here if you want doing something special during
	*        TYPEC Sink has detected.
	*/
		/*
		 * mode == WUSB3801_SRC/WUSB3801_SRC_ACC
		 */

	power_supply_set_usb_otg(chip->usb_psy, true);

	wusb3801_set_dfp_power(chip, chip->pdata->dfp_power);
	wusb3801_update_state(chip, WUSB3801_STATE_ATTACHED_SRC);
	if(chip->dual_role == NULL)
	{
		pr_err("houzn : chip->dual_role == NULL snk\n");
		return;
	}
	dual_role_instance_changed(chip->dual_role);

	chip->type = WUSB3801_TYPE_SNK;
}

static void wusb3801_dbg_acc_detected(struct wusb3801_chip *chip)
{
	struct device *cdev = &chip->client->dev;
	dev_info(cdev, "%s \n",__func__);
	if (chip->mode & BIT_REG_CTRL0_DIS_ACC) {
		dev_err(cdev, "not support accessory mode\n");
		if(IS_ERR_VALUE(wusb3801_reset_device(chip)))
			dev_err(cdev, "%s: failed to reset\n", __func__);
		return;
	}

	/**
	*  TODO: Add you code here if you want doing something special during
	*        TYPEC Debug accessory has detected.
	*/
	wusb3801_update_state(chip, WUSB3801_STATE_DEBUG_ACCESSORY);
}

static void wusb3801_aud_acc_detected(struct wusb3801_chip *chip)
{
	struct device *cdev = &chip->client->dev;
	dev_info(cdev, "%s \n",__func__);
	if (chip->mode & BIT_REG_CTRL0_DIS_ACC) {
		dev_err(cdev, "not support accessory mode\n");
		if(IS_ERR_VALUE(wusb3801_reset_device(chip)))
			dev_err(cdev, "%s: failed to reset\n", __func__);
		return;
	}
// ontim : houzn add start
	wusb3801_usb_aud_switch(chip, WUSB_AUDIO);
	/*
	 * mbhc hardware will delay for 256ms, so need not to delay here.
	 */
	//msleep(5); // value is adjustable
	wusb3801_hs_det(chip, WAUDIO_INSERT);
// ontim : houzn add end
	wusb3801_update_state(chip, WUSB3801_STATE_AUDIO_ACCESSORY);
}


static void wusb3801_detach(struct wusb3801_chip *chip)
{
	struct device *cdev = &chip->client->dev;
	dev_info(cdev, "%s: type[0x%02x] chipstate[0x%02x]\n",
			__func__, chip->type, chip->state);
	
	switch (chip->state) {
		case WUSB3801_STATE_ATTACHED_SRC:
			pr_info("houzn : wusb3801_detach:WUSB3801_STATE_ATTACHED_SRC\n");
			
			power_supply_set_usb_otg(chip->usb_psy, false);
			wusb3801_init_force_dfp_power(chip);
			break;
		case WUSB3801_STATE_ATTACHED_SNK:
			pr_info("houzn : wusb3801_detach:WUSB3801_STATE_ATTACHED_SNK\n");
			
			wusb3801_power_set_icurrent_max(chip, 0);
			break;
	// ontim : houzn add start
		case WUSB3801_STATE_DEBUG_ACCESSORY:
		case WUSB3801_STATE_AUDIO_ACCESSORY:
			wusb3801_hs_det(chip, WAUDIO_REMOVE);
			break;
	// ontim : houzn add end
		case WUSB3801_STATE_DISABLED:
		case WUSB3801_STATE_ERROR_RECOVERY:
			pr_info("houzn : wusb3801_detach:WUSB3801_STATE_ERROR_RECOVERY\n");
			break;
		default:
			dev_err(cdev, "%s: Invaild chipstate[0x%02x]\n",
					__func__, chip->state);
			break;
	}
	
	chip->type = WUSB3801_TYPE_INVALID;
	chip->bc_lvl = WUSB3801_SNK_0MA;
	chip->ufp_power  = 0;
	chip->try_attcnt = 0;
	chip->attached   = 0;
	//Excute the defered init mode into drp+try.snk when detached
	if(chip->defer_init == 1) {
		dev_err(cdev, "%s: reset to init mode\n", __func__);
		if (IS_ERR_VALUE(wusb3801_set_mode(chip, chip->pdata->init_mode)))
			dev_err(cdev, "%s: failed to set init mode\n", __func__);
		chip->defer_init = 0;
	}
	wusb3801_update_state(chip, WUSB3801_STATE_ERROR_RECOVERY);
	if(chip->dual_role == NULL)
	{
		pr_err("houzn : chip->dual_role == NULL wusb3801_detach\n");
		return;
	}
	dual_role_instance_changed(chip->dual_role);
	// ontim : houzn add start
	if (chip->state != WUSB3801_STATE_ERROR_RECOVERY)
		wusb3801_usb_aud_switch(chip, WUSB_AUDIO);
	// ontim : houzn add end
}



static unsigned wusb3801_is_waiting_for_vbus(struct wusb3801_chip *chip)
{
	struct device *cdev = &chip->client->dev;
	int rc;
	rc = i2c_smbus_read_byte_data(chip->client, WUSB3801_REG_TEST_0A);
	if (IS_ERR_VALUE(rc)) {
		dev_err(cdev, "%s: failed to read test0a\n", __func__);
		return false;
	}
	return !!(rc & WUSB3801_WAIT_VBUS);
}



static void wusb3801_attach(struct wusb3801_chip *chip)
{
	struct device *cdev = &chip->client->dev;
	int rc = 0;
	uint8_t status, type;

	/* get status */
	rc = i2c_smbus_read_byte_data(chip->client,
			WUSB3801_REG_STATUS);
	if (IS_ERR_VALUE(rc)) {
		dev_err(cdev, "%s: failed to read status\n", __func__);
		return;
	}
	status = (rc & WUSB3801_ATTACH) ? true : false;
	type = status ? \
			rc & WUSB3801_TYPE_MASK : WUSB3801_TYPE_INVALID;
	dev_info(cdev, "sts[0x%02x], type[0x%02x]\n", status, type);

	if (chip->state != WUSB3801_STATE_ERROR_RECOVERY) {
		rc = wusb3801_set_chip_state(chip,
				WUSB3801_STATE_ERROR_RECOVERY);
		if (IS_ERR_VALUE(rc))
			dev_err(cdev, "%s: failed to set error recovery\n",
					__func__);
		wusb3801_detach(chip);
		dev_err(cdev, "%s: Invaild chipstate[0x%02x]\n",
				__func__, chip->state);
		return;
	}
	
// ontim : houzn add start
	if (type != WUSB3801_TYPE_AUD_ACC && type != WUSB3801_TYPE_DBG_ACC)
		wusb3801_usb_aud_switch(chip, WUSB_USB);
// ontim : houzn add end
	
	switch (type) {
		case WUSB3801_TYPE_SRC:
			wusb3801_src_detected(chip);
			break;
		case WUSB3801_TYPE_SNK:
			wusb3801_snk_detected(chip);
			break;
		case WUSB3801_TYPE_DBG_ACC:
			wusb3801_dbg_acc_detected(chip);
			chip->type = type;
			break;
		case WUSB3801_TYPE_AUD_ACC:
			wusb3801_aud_acc_detected(chip);
			chip->type = type;
			break;
		case WUSB3801_TYPE_INVALID:
			wusb3801_detach(chip);
			dev_err(cdev, "%s: Invaild type[0x%02x]\n", __func__, type);
			break;
		default:
			rc = wusb3801_set_chip_state(chip,
					WUSB3801_STATE_ERROR_RECOVERY);
			if (IS_ERR_VALUE(rc))
				dev_err(cdev, "%s: failed to set error recovery\n",
						__func__);

			wusb3801_detach(chip);
			dev_err(cdev, "%s: Unknwon type[0x%02x]\n", __func__, type);
			break;
	}
	chip->attached = true;
}
static void wusb3801_work_handler(struct work_struct *work)
{
	struct wusb3801_chip *chip =
			container_of(work, struct wusb3801_chip, dwork);
	struct device *cdev = &chip->client->dev;
	int rc;
	uint8_t int_sts;
	
	mutex_lock(&chip->mlock);
	/* get interrupt */
	rc = i2c_smbus_read_byte_data(chip->client, WUSB3801_REG_INTERRUPT);
	mutex_unlock(&chip->mlock);	
	if (IS_ERR_VALUE(rc)) {
		dev_err(cdev, "%s: failed to read interrupt\n", __func__);
		goto work_unlock;
	}
	int_sts = rc & WUSB3801_INT_STS_MASK;

	rc = i2c_smbus_read_byte_data(chip->client, WUSB3801_REG_STATUS);
	if (IS_ERR_VALUE(rc)) {
		dev_err(cdev, "%s: failed to read reg status\n", __func__);
		goto work_unlock;
	}
	dev_info(cdev,"%s WUSB3801_REG_STATUS : 0x%02x\n", __func__, rc);
	
	dev_info(cdev, "%s: int_sts[0x%02x]\n", __func__, int_sts);
	if (int_sts & WUSB3801_INT_DETACH){
		
		wusb3801_detach(chip);
	}
	if (int_sts & WUSB3801_INT_ATTACH){
		if(chip->attached){
			
			wusb3801_bclvl_changed(chip);
		}
		else{
			
			wusb3801_attach(chip);
		}
	}
work_unlock:
	enable_irq(chip->irq_gpio);
}

static irqreturn_t wusb3801_interrupt(int irq, void *data)
{
	struct wusb3801_chip *chip = (struct wusb3801_chip *)data;
	if (!chip) {
		dev_err(&chip->client->dev, "%s : called before init.\n", __func__);
		return IRQ_HANDLED;
	}
	disable_irq_nosync(irq);
	
	/*
	 * wake_lock_timeout, prevents multiple suspend entries
	 * before charger gets chance to trigger usb core for device
	 */
	wake_lock_timeout(&chip->wlock,
				msecs_to_jiffies(WUSB3801_WAKE_LOCK_TIMEOUT));
	if (!queue_work(chip->cc_wq, &chip->dwork))
	{
		dev_err(&chip->client->dev, "%s: can't alloc work\n", __func__);
		enable_irq(irq);
	}

	return IRQ_HANDLED;
}



static int wusb3801_init_gpio(struct wusb3801_chip *chip)
{

	int rc = 0;

	struct device *cdev = &chip->client->dev;
	/* Start to enable wusb3801 Chip */
	if (gpio_is_valid(chip->pdata->int_gpio)) {
		rc = gpio_request_one(chip->pdata->int_gpio,
				GPIOF_DIR_IN, "wusb3801_int_gpio");
		if (rc)
			dev_err(cdev, "unable to request int_gpio %d\n",
					chip->pdata->int_gpio);
	} else {
		dev_err(cdev, "int_gpio %d is not valid\n",
				chip->pdata->int_gpio);
		rc = -EINVAL;
		goto err_init_gpio1; // ontim : houzn add
	}
// ontim : houzn add start
	if (gpio_is_valid(chip->pdata->usb_switch_asel)) {
		/*
		 * The default config of usb_switch_asel in devicetree is output low
		 */
		rc = gpio_request(chip->pdata->usb_switch_asel, "usb_switch_asel"); /* select usb default */
		if (rc) {
			dev_err(cdev, "unable to request usb_switch_asel %d\n",
					chip->pdata->usb_switch_asel);
			goto err_init_gpio2;
		}
	} else {
		dev_err(cdev, "usb_switch_asel %d is not valid\n",
				chip->pdata->usb_switch_asel);
		rc = -EINVAL;
		goto err_init_gpio2;
	}

	if (gpio_is_valid(chip->pdata->hs_det)) {
		/*
		 * The default config of hs_det in devicetree is output high
		 */
		rc = gpio_request(chip->pdata->hs_det, "hs_det"); /* do not trigger insert detection */
		if (rc) {
			dev_err(cdev, "unable to request hs_det %d\n",
					chip->pdata->hs_det);
			goto err_init_gpio3;
		}
	} else {
		dev_err(cdev, "hs_det %d is not valid\n",
				chip->pdata->hs_det);
		rc = -EINVAL;
		goto err_init_gpio3;
	}

	return rc;

err_init_gpio3:
	gpio_free(chip->pdata->usb_switch_asel);
err_init_gpio2:
	gpio_free(chip->pdata->int_gpio);
err_init_gpio1:
// ontim : houzn add end
	return rc;
}

static void wusb3801_free_gpio(struct wusb3801_chip *chip)
{
	if (gpio_is_valid(chip->pdata->int_gpio))
		gpio_free(chip->pdata->int_gpio);
// ontim : houzn add start
	if (gpio_is_valid(chip->pdata->usb_switch_asel))
		gpio_free(chip->pdata->usb_switch_asel);

	if (gpio_is_valid(chip->pdata->hs_det))
		gpio_free(chip->pdata->hs_det);
// ontim : houzn add end
}

static int wusb3801_parse_dt(struct wusb3801_chip *chip)
{
	struct device *cdev = &chip->client->dev;
	struct device_node *dev_node = cdev->of_node;
	struct wusb3801_data *data = chip->pdata;
	u32 val = 0;
	int rc = 0;
	dev_err(cdev, "dev_node->name=%s.\n",dev_node->name);
	data->int_gpio = of_get_named_gpio_flags(dev_node,
				"wusb3801,irq-gpio", 0,NULL);
	dev_err(cdev, "data->int_gpio=%d",data->int_gpio);
	if (data->int_gpio < 0) {
		dev_err(cdev, "int_gpio is not available\n");
		rc = data->int_gpio;
        
		goto out;
	}

	rc = of_property_read_u32(dev_node,
				"wusb3801,init-mode", &val);
	data->init_mode = (u8)val;
	dev_err(cdev, "data->init_mode=%d.\n",data->init_mode);
	if (rc || wusb3801_check_modes(data->init_mode)) {
		dev_err(cdev, "init mode is not available and set default\n");
		data->init_mode = WUSB3801_INIT_MODE; //WUSB3801_DRP_ACC;
		rc = 0;
	}

	rc = of_property_read_u32(dev_node,
				"wusb3801,host-current", &val);
	data->dfp_power = (u8)val;
	dev_err(cdev, "data->dfp_power=%d.\n",data->dfp_power);
	if (rc || (data->dfp_power > WUSB3801_HOST_3000MA)) {
		dev_err(cdev, "host current is not available and set default\n");
		data->dfp_power = WUSB3801_HOST_DEFAULT;
		rc = 0;
	}

	rc = of_property_read_u32(dev_node,
				"wusb3801,drp-toggle-time", &val);
	data->dttime = (u8)val;
	if (rc || (data->dttime != WUSB3801_TGL_40MS)) {
		dev_err(cdev, "Fixed drp time and set default (40ms:40ms)\n");
		data->dttime = WUSB3801_TGL_40MS;
		rc = 0;
	}
	
	dev_dbg(cdev, "init_mode:%d dfp_power:%d toggle_time:%d\n",
			data->init_mode, data->dfp_power, data->dttime);
// ontim : houzn add start
	data->usb_switch_asel = of_get_named_gpio(dev_node,
				"qcom,usb_switch_asel", 0);
	if (data->usb_switch_asel < 0) {
		dev_err(cdev, "usb_switch_asel is not available\n");
		rc = data->usb_switch_asel;
		goto out;
	}

	data->hs_det = of_get_named_gpio(dev_node,
				"qcom,cdc_hsdet_l", 0);
	if (data->hs_det < 0) {
		dev_err(cdev, "hs_det is not available\n");
		rc = data->hs_det;
		goto out;
	}
// ontim : houzn add end
out:
	return rc;
}


static enum dual_role_property wusb3801_drp_properties[] = {
	DUAL_ROLE_PROP_MODE,
	DUAL_ROLE_PROP_PR,
	DUAL_ROLE_PROP_DR,
};

 /* Callback for "cat /sys/class/dual_role_usb/otg_default/<property>" */
static int dual_role_get_local_prop(struct dual_role_phy_instance *dual_role,
			enum dual_role_property prop,
			unsigned int *val)
{
	struct wusb3801_chip *chip;
	struct i2c_client *client = dual_role_get_drvdata(dual_role);
	int ret = 0;

	if (!client)
	{
		pr_info("%s: Get prop %d fail. Can not get drvdata!\n",__func__, prop);
		return -EINVAL;
	}

	chip = i2c_get_clientdata(client);

	mutex_lock(&chip->mlock);
	if (chip->state == WUSB3801_STATE_ATTACHED_SRC) {
		if (prop == DUAL_ROLE_PROP_MODE)
			*val = DUAL_ROLE_PROP_MODE_DFP;
		else if (prop == DUAL_ROLE_PROP_PR)
			*val = DUAL_ROLE_PROP_PR_SRC;
		else if (prop == DUAL_ROLE_PROP_DR)
			*val = DUAL_ROLE_PROP_DR_HOST;
		else
			ret = -EINVAL;
	} else if (chip->state == WUSB3801_STATE_ATTACHED_SNK) {
		if (prop == DUAL_ROLE_PROP_MODE)
			*val = DUAL_ROLE_PROP_MODE_UFP;
		else if (prop == DUAL_ROLE_PROP_PR)
			*val = DUAL_ROLE_PROP_PR_SNK;
		else if (prop == DUAL_ROLE_PROP_DR)
			*val = DUAL_ROLE_PROP_DR_DEVICE;
		else
			ret = -EINVAL;
	} else {
		if (prop == DUAL_ROLE_PROP_MODE)
			*val = DUAL_ROLE_PROP_MODE_NONE;
		else if (prop == DUAL_ROLE_PROP_PR)
			*val = DUAL_ROLE_PROP_PR_NONE;
		else if (prop == DUAL_ROLE_PROP_DR)
			*val = DUAL_ROLE_PROP_DR_NONE;
		else
			ret = -EINVAL;
	}
	mutex_unlock(&chip->mlock);

	pr_debug("%s: chip->state = 0x%02x, prop = %d, val = %d\n",__func__,chip->state, prop, *val);
	return ret;
}

/* Decides whether userspace can change a specific property */
static int dual_role_is_writeable(struct dual_role_phy_instance *drp,
				enum dual_role_property prop) {

	if (prop == DUAL_ROLE_PROP_MODE) {
		pr_info("%s: prop = %d, is DUAL_ROLE_PROP_MODE\n",__func__,prop);
		return 1;
	} 
	else {
		pr_info("%s: prop = %d, not DUAL_ROLE_PROP_MODE\n",__func__,prop);
		return 1; // Patch for PowerRole & DataRole Swap
	}
}


 
/* ***********************************************************************
 * Callback for "echo <value> > /sys/class/dual_role_usb/<name>/<property>"
 * Block until the entire final state is reached.
 * Blocking is one of the better ways to signal when the operation
 * is done.
 * This function tries to switched to Attached.SRC or Attached.SNK
 * by forcing the mode into SRC or SNK.
 * On failure, we fall back to previous state machine.
 ************************************************************************/

static int dual_role_set_prop(struct dual_role_phy_instance *dual_role,
				enum dual_role_property prop,
				const unsigned int *val) 
{
	struct wusb3801_chip *chip;
	struct i2c_client *client = dual_role_get_drvdata(dual_role);
	uint8_t mode, target_state, fallback_state;
	int rc;
	struct device *cdev;
	long timeout;

	if (!client)
		return -EIO;

	chip = i2c_get_clientdata(client);
	cdev = &client->dev;

    dev_dbg(cdev, "%s: chip->state = 0x%02x, prop = %d\n",__func__,chip->state,prop);

	if (prop == DUAL_ROLE_PROP_MODE) {
		if (*val == DUAL_ROLE_PROP_MODE_DFP) {
			dev_dbg(cdev, "%s: Setting SRC mode\n", __func__);
			mode           = WUSB3801_DRP_PREFER_SRC;
			target_state   = WUSB3801_STATE_ATTACHED_SRC;
			fallback_state = WUSB3801_STATE_ATTACHED_SNK;
		} else if (*val == DUAL_ROLE_PROP_MODE_UFP) {
			dev_dbg(cdev, "%s: Setting SNK mode\n", __func__);
			mode           = WUSB3801_DRP_PREFER_SNK;
			target_state   = WUSB3801_STATE_ATTACHED_SNK;
			fallback_state = WUSB3801_STATE_ATTACHED_SRC;
		} else {
			dev_err(cdev, "%s: Trying to set invalid mode\n",
								__func__);
			return -EINVAL;
		}
	} else if (prop == DUAL_ROLE_PROP_PR) {
		if (*val == DUAL_ROLE_PROP_PR_SRC) {
			dev_dbg(cdev, "%s: Setting SRC mode\n", __func__);
			mode		   = WUSB3801_DRP_PREFER_SRC;
			target_state   = WUSB3801_STATE_ATTACHED_SRC;
			fallback_state = WUSB3801_STATE_ATTACHED_SNK;
		} else if (*val == DUAL_ROLE_PROP_PR_SNK) {
			dev_dbg(cdev, "%s: Setting SNK mode\n", __func__);
			mode		   = WUSB3801_DRP_PREFER_SNK;
			target_state   = WUSB3801_STATE_ATTACHED_SNK;
			fallback_state = WUSB3801_STATE_ATTACHED_SRC;
		} else {
			dev_err(cdev, "%s: Trying to set invalid mode\n",
								__func__);
			return -EINVAL;
		}
	} else if (prop == DUAL_ROLE_PROP_DR) {
		if (*val == DUAL_ROLE_PROP_DR_HOST) {
			dev_dbg(cdev, "%s: Setting HOST mode\n", __func__);
			mode		   = WUSB3801_DRP_PREFER_SRC;
			target_state   = WUSB3801_STATE_ATTACHED_SRC;
			fallback_state = WUSB3801_STATE_ATTACHED_SNK;
		} else if (*val == DUAL_ROLE_PROP_DR_DEVICE) {
			dev_dbg(cdev, "%s: Setting DEVICE mode\n", __func__);
			mode		   = WUSB3801_DRP_PREFER_SNK;
			target_state   = WUSB3801_STATE_ATTACHED_SNK;
			fallback_state = WUSB3801_STATE_ATTACHED_SRC;
		} else {
			dev_err(cdev, "%s: Trying to set invalid mode\n",
								__func__);
			return -EINVAL;
		}
	} else {
		dev_err(cdev, "%s: Property cannot be set\n", __func__);
		return -EINVAL;
	}

	if (chip->state == target_state)
		return 0;

	mutex_lock(&chip->mlock);
    dev_info(cdev, "%s: enter wusb3801_set_mode mode = 0x%02x\n",__func__,mode);
	rc = wusb3801_set_mode(chip, (uint8_t)mode);
	if (IS_ERR_VALUE(rc)) {
		if (IS_ERR_VALUE(wusb3801_reset_device(chip)))
			dev_err(cdev, "%s: failed to reset\n", __func__);
		mutex_unlock(&chip->mlock);
		return rc;
	}

	rc = wusb3801_set_chip_state(chip, WUSB3801_STATE_ERROR_RECOVERY);
	if (IS_ERR_VALUE(rc)) {
		if (IS_ERR_VALUE(wusb3801_reset_device(chip)))
			dev_err(cdev, "%s: failed to reset\n", __func__);
		mutex_unlock(&chip->mlock);
		return rc;
	}

	wusb3801_detach(chip);

	mutex_unlock(&chip->mlock);

	timeout = wait_event_interruptible_timeout(wmode_switch,
			((chip->state == target_state) || (chip->state == fallback_state)),
			msecs_to_jiffies(ROLE_SWITCH_TIMEOUT));

	if (timeout > 0 )
	{
		if(chip->state == target_state)
		    return 0;
	}
	else
	{
		if(wusb3801_is_waiting_for_vbus(chip))
		{
			dev_err(cdev, "%s: Device is blocking on waiting for VBus.\n", __func__);
		}	
	}
	mutex_lock(&chip->mlock);
	if (IS_ERR_VALUE(wusb3801_set_mode(chip,	chip->pdata->init_mode)))
		dev_err(cdev, "%s: failed to set init mode\n", __func__);
	mutex_unlock(&chip->mlock);

	return -EIO;

}




static int wusb3801_pinctrl_init(struct wusb3801_chip *chip)//(struct mxt_data *data)
{
	int error;

	/* Get pinctrl if target uses pinctrl */
	chip->wusb3801_pinctrl = devm_pinctrl_get((&chip->client->dev));
	if (IS_ERR_OR_NULL(chip->wusb3801_pinctrl)) {
		pr_info("Device does not use pinctrl\n");
		error = PTR_ERR(chip->wusb3801_pinctrl);
		chip->wusb3801_pinctrl = NULL;
		return error;
	}

	chip->gpio_state_active
		= pinctrl_lookup_state(chip->wusb3801_pinctrl, "pmx_wusb3801_active");
	if (IS_ERR_OR_NULL(chip->gpio_state_active)) {
		pr_info("Can not get wusb3801 default pinstate\n");
		error = PTR_ERR(chip->gpio_state_active);
		chip->wusb3801_pinctrl = NULL;
		return error;
	}

	chip->gpio_state_suspend
		= pinctrl_lookup_state(chip->wusb3801_pinctrl, "pmx_wusb3801_suspend");
	if (IS_ERR_OR_NULL(chip->gpio_state_suspend)) {
		pr_info("Can not get wusb3801 sleep pinstate\n");
		error = PTR_ERR(chip->gpio_state_suspend);
		chip->wusb3801_pinctrl = NULL;
		return error;
	}

	return 0;
}



static int wusb3801_probe(struct i2c_client *client,
			const struct i2c_device_id *id)
{
	struct wusb3801_chip *chip;
	struct device *cdev = &client->dev;
	struct power_supply *usb_psy;

	struct dual_role_phy_desc *desc;
	struct dual_role_phy_instance *dual_role;

	int ret = 0;

	dev_info(cdev,"wusb3801_probe start \n");

	usb_psy = power_supply_get_by_name("usb");
	if (!usb_psy) {
		dev_err(cdev, "USB supply not found, deferring probe\n");
		return -EPROBE_DEFER;
	}

	if (!i2c_check_functionality(client->adapter,
				I2C_FUNC_SMBUS_BYTE_DATA |
				I2C_FUNC_SMBUS_WORD_DATA)) {
		dev_err(cdev, "smbus data not supported!\n");
		return -EIO;
	}

	chip = devm_kzalloc(cdev, sizeof(struct wusb3801_chip), GFP_KERNEL);
	if (!chip) {
		dev_err(cdev, "can't alloc wusb3801_chip\n");
		return -ENOMEM;
	}

	chip->client = client;
	i2c_set_clientdata(client, chip);

	ret = wusb3801_read_device_id(chip);
	if (ret){
		dev_err(cdev, "wusb3801 doesn't find, try again\n");
		ret = wusb3801_read_device_id(chip);
		if(ret){
			dev_err(cdev, "wusb3801 doesn't find, stop find\n");
			goto err1;
		}
	}
	if (&client->dev.of_node){
		struct wusb3801_data *data = devm_kzalloc(cdev,
				sizeof(struct wusb3801_data), GFP_KERNEL);

		if (!data) {
			dev_err(cdev, "can't alloc wusb3801_data\n");
			ret = -ENOMEM;
			goto err1;
		}

		chip->pdata = data;

		ret = wusb3801_parse_dt(chip);
		if (ret) {
			dev_err(cdev, "can't parse dt\n");
			goto err2;
		}
	} else {
		chip->pdata = client->dev.platform_data;
	}

	ret = wusb3801_init_gpio(chip);
	if (ret) {
		dev_err(cdev, "fail to init gpio\n");
		goto err2;
	}

	chip->type      = WUSB3801_TYPE_INVALID;
	chip->state     = WUSB3801_STATE_ERROR_RECOVERY;
	chip->attached  = 0;
	chip->bc_lvl    = WUSB3801_SNK_0MA;
	chip->ufp_power = 0;
	chip->defer_init = 0;	// Do the mode init when chip init


	chip->cc_wq = alloc_ordered_workqueue("wusb3801-wq", WQ_HIGHPRI);
	if (!chip->cc_wq) {
		dev_err(cdev, "unable to create workqueue wusb3801-wq\n");
		goto err2;
	}
	INIT_WORK(&chip->dwork, wusb3801_work_handler);
	wake_lock_init(&chip->wlock, WAKE_LOCK_SUSPEND, "wusb3801_wake");
	mutex_init(&chip->mlock);

	ret = wusb3801_create_devices(cdev);
	if (IS_ERR_VALUE(ret)) {
		dev_err(cdev, "could not create devices\n");
		goto err3;
	}


   	chip->usb_psy = usb_psy;
	chip->irq_gpio = gpio_to_irq(chip->pdata->int_gpio);
	gpio_direction_input(chip->pdata->int_gpio);

	if (chip->irq_gpio < 0) {
		dev_err(cdev, "could not register int_gpio\n");
		ret = -ENXIO;
		goto err4;
	}


	ret = wusb3801_pinctrl_init(chip);
	if (ret)
		dev_err(cdev, "No pinctrl support\n");

	ret = pinctrl_select_state(chip->wusb3801_pinctrl, chip->gpio_state_active);
	if (ret)
		dev_err(cdev, "select failedt\n");

	ret = devm_request_irq(cdev, chip->irq_gpio,
				wusb3801_interrupt,
				IRQF_TRIGGER_LOW,
				"wusb3801_int_irq", chip);
	if (ret) {
		dev_err(cdev, "failed to reqeust IRQ\n");
		goto err4;
	}

	if (IS_ENABLED(CONFIG_DUAL_ROLE_USB_INTF)) {
		desc = devm_kzalloc(cdev, sizeof(struct dual_role_phy_desc),
					GFP_KERNEL);
		if (!desc) {
			dev_err(cdev, "unable to allocate dual role descriptor\n");
			goto err4;
		}
	
		desc->name = "otg_default";
		desc->supported_modes = DUAL_ROLE_SUPPORTED_MODES_DFP_AND_UFP;
		desc->get_property = dual_role_get_local_prop;
		desc->set_property = dual_role_set_prop;
		desc->properties = wusb3801_drp_properties;
		desc->num_properties = ARRAY_SIZE(wusb3801_drp_properties);
		desc->property_is_writeable = dual_role_is_writeable;
		dual_role = devm_dual_role_instance_register(cdev, desc);
		dual_role->drv_data = client;
		chip->dual_role = dual_role;
		chip->desc = desc;
	}
	ret = wusb3801_reset_device(chip);
	if (ret) {
		dev_err(cdev, "failed to initialize\n");
		goto err5;
	}

	enable_irq_wake(chip->irq_gpio);
	
	//huanglei add for debug init reg status begin	
	ret = i2c_smbus_read_byte_data(chip->client, WUSB3801_REG_STATUS);
	if (IS_ERR_VALUE(ret)) {
		dev_err(cdev, "%s: failed to read reg status\n", __func__);
	}
	dev_err(cdev, "%s WUSB3801_REG_STATUS : 0x%02x\n", __func__, ret);	
	//huanglei add for debug init reg status end
		
	
	i2c_smbus_write_byte_data(chip->client,
			WUSB3801_REG_CONTROL1, BIT_REG_CTRL1_SM_RST);
			
	dev_info(cdev,"wusb3801_probe end \n");
	return 0;


err5:
	if (IS_ENABLED(CONFIG_DUAL_ROLE_USB_INTF))
		devm_kfree(cdev, chip->desc);

err4:
	wusb3801_destory_device(cdev);
err3:
	destroy_workqueue(chip->cc_wq);
	mutex_destroy(&chip->mlock);
	wake_lock_destroy(&chip->wlock);
	wusb3801_free_gpio(chip);
err2:
	if (&client->dev.of_node)
		devm_kfree(cdev, chip->pdata);
err1:
	i2c_set_clientdata(client, NULL);
	devm_kfree(cdev, chip);

	return ret;
}

static int wusb3801_remove(struct i2c_client *client)
{
	struct wusb3801_chip *chip = i2c_get_clientdata(client);
	struct device *cdev = &client->dev;

	if (!chip) {
		dev_err(cdev, "%s : chip is null\n", __func__);
		return -ENODEV;
	}

	if (chip->irq_gpio > 0)
		devm_free_irq(cdev, chip->irq_gpio, chip);


	if (IS_ENABLED(CONFIG_DUAL_ROLE_USB_INTF)) {
		devm_dual_role_instance_unregister(cdev, chip->dual_role);
		devm_kfree(cdev, chip->desc);
	}


	wusb3801_destory_device(cdev);
	destroy_workqueue(chip->cc_wq);
	mutex_destroy(&chip->mlock);
	wake_lock_destroy(&chip->wlock);
	wusb3801_free_gpio(chip);

	if (&client->dev.of_node)
		devm_kfree(cdev, chip->pdata);

	i2c_set_clientdata(client, NULL);
	devm_kfree(cdev, chip);

	return 0;
}

static void wusb3801_shutdown(struct i2c_client *client)
{
	struct wusb3801_chip *chip = i2c_get_clientdata(client);
	struct device *cdev = &client->dev;

	if (IS_ERR_VALUE(wusb3801_set_mode(chip, WUSB3801_SNK)) ||
			IS_ERR_VALUE(wusb3801_set_chip_state(chip,
					WUSB3801_STATE_ERROR_RECOVERY)))
		dev_err(cdev, "%s: failed to set sink mode\n", __func__);
}

#ifdef CONFIG_PM
static int wusb3801_suspend(struct device *dev)
{
	return 0;
}

static int wusb3801_resume(struct device *dev)
{
	return 0;
}

static const struct dev_pm_ops wusb3801_dev_pm_ops = {
	.suspend = wusb3801_suspend,
	.resume  = wusb3801_resume,
};
#endif

static const struct i2c_device_id wusb3801_id_table[] = {
	{"wusb3801", 0},
	{},
};
MODULE_DEVICE_TABLE(i2c, wusb3801_id_table);

#ifdef CONFIG_OF

static struct of_device_id wusb3801_match_table[] = {

	{ .compatible = "qcom,wusb3801x",},

	{ },
};
#else /*!CONFIG_OF*/
#define wusb3801_match_table NULL
#endif /*!CONFIG_OF*/

static const unsigned short normal_i2c[] = {WUSB3801_SLAVE_ADDR0, WUSB3801_SLAVE_ADDR1, I2C_CLIENT_END};
static struct i2c_driver wusb3801_i2c_driver = {
	.driver = {
		.name = "wusb3801",
		.owner = THIS_MODULE,
		.of_match_table = wusb3801_match_table,
#ifdef CONFIG_PM
		.pm = &wusb3801_dev_pm_ops,
#endif
	},
	.probe = wusb3801_probe,
	.remove = wusb3801_remove,
	.shutdown = wusb3801_shutdown,
	.id_table = wusb3801_id_table,
	.address_list = (const unsigned short *) normal_i2c,
};

static __init int wusb3801_i2c_init(void)
{
	return i2c_add_driver(&wusb3801_i2c_driver);
}

static __exit void wusb3801_i2c_exit(void)
{
	i2c_del_driver(&wusb3801_i2c_driver);
}

module_init(wusb3801_i2c_init);
module_exit(wusb3801_i2c_exit);

MODULE_AUTHOR("lhuang@sh-willsemi.com");
MODULE_DESCRIPTION("WUSB3801x USB Type-C driver for MSM and Qcom/Mediatek/Others Linux/Android Platform");
MODULE_LICENSE("GPL v2");
