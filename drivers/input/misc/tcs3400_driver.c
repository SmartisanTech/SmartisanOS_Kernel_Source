#include <linux/i2c.h>
#include <linux/delay.h>
#include <linux/platform_device.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>

#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/cdev.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/time.h>

#include <linux/regulator/consumer.h>
#define TCS3400_DEBUG_LOG
#ifdef TCS3400_DEBUG_LOG
#define TCS3400_FUNC_ENTER() printk(KERN_INFO "[TCS3400]%s: Enter\n", __func__)
#define TCS3400_FUNC_EXIT()  printk(KERN_INFO "[TCS3400]%s: Exit(%d)\n", __func__, __LINE__)
#else
#define TCS3400_FUNC_ENTER() pr_debug("[TCS3400]%s: Enter\n", __func__)
#define TCS3400_FUNC_EXIT()  pr_debug("[TCS3400]%s: Exit(%d)\n", __func__, __LINE__)
#endif
#define TCS3400_VTG_MIN_UV          2800000
#define TCS3400_VTG_MAX_UV          2800000
#define LENS_I2C_BUSNUM 3
//#define TCS3400_RGBW_RETRY_TIMES 3
//#define I2C_ADDR_OFFSET     0X80

#define TCS3400_DRVNAME          "tcs3400"
#define TCS3400_SLAVE_ADDR          0x29

#define TCS3400_DEBUG
#ifdef TCS3400_DEBUG
#define TCS3400DB(fmt, args...) pr_err(fmt, ##args)

#else
#define TCS3400DB(x, ...)
#endif

typedef struct {
	int16_t r_data;
	int16_t g_data;
	int16_t b_data;
	int16_t w_data;
} GET_TCS3400_DATA ;

struct tcs3400_data {
	struct i2c_client *client;
	struct regulator *vdd;
	struct miscdevice miscdev;
	struct mutex work_mutex;

};

struct tcs3400_als_info {
    u32 cpl;
    u32 saturation;
    u16 clear_raw;
    u16 red_raw;
    u16 green_raw;
    u16 blue_raw;
    u8 atime;
    u8 again;
    u16 lux;
    u16 cct;
    s16 ir;
#if 0
    struct tcs3400_color_bins bin;
    struct tcs3400_crgb_sdef  correct;
    struct tcs3400_rgb_sdef   prime;
#endif
};
struct tcs3400_chip {
    struct tcs3400_als_info als_inf;
#if 0
    struct mutex lock;
    struct i2c_client *client;
    struct tcs3400_parameters params;
    struct tcs3400_i2c_platform_data *pdata;
    u8 shadow[42];
    u16 bins_shadow;

    struct input_dev *a_idev;
    int in_suspend;
    int wake_irq;
    int irq_pending;
    bool unpowered;
    bool als_enabled;

    struct lux_segment *segment;
    int segment_num;
    int seg_num_max;
    bool als_gain_auto;
    u8 device_index;
    u8 bc_symbol_table[128];
    u16 bc_nibbles;
    u16 hop_count;
    u8 hop_next_slot;
    u8 hop_index;
#endif
};
struct tcs3400_chip chip;

#define R_LOW_DATA				0x20
#define R_HIGH_DATA				0x21
#define G_LOW_DATA				0x22
#define G_HIGH_DATA				0x23
#define B_LOW_DATA				0x24
#define B_HIGH_DATA				0x25
#define W_LOW_DATA				0x26
#define W_HIGH_DATA				0x27
#define CORRELATION_CODE		0x2A
#define MODULE_ID		0x35
#define SLEEP_ADDR				0x00
#define SLEEP_VALUE				0x22

enum tcs3400_regs {
    TCS3400_CONTROL=0x80,
    TCS3400_ALS_TIME,                  // 0x81
    TCS3400_RESV_1,
    TCS3400_WAIT_TIME,               // 0x83
    TCS3400_ALS_MINTHRESHLO,   // 0x84
    TCS3400_ALS_MINTHRESHHI,   // 0x85
    TCS3400_ALS_MAXTHRESHLO,  // 0x86
    TCS3400_ALS_MAXTHRESHHI,  // 0x87
    TCS3400_RESV_2,                     // 0x88
    TCS3400_PRX_MINTHRESHLO,  // 0x89 -> Not used for TCS3400

    TCS3400_RESV_3,                    // 0x8A
    TCS3400_PRX_MAXTHRESHHI, // 0x8B  -> Not used for TCS3400
    TCS3400_PERSISTENCE,          // 0x8C
    TCS3400_CONFIG,                    // 0x8D
    TCS3400_PRX_PULSE_COUNT,  // 0x8E  -> Not used for TCS3400
    TCS3400_GAIN,                        // 0x8F  : Gain Control Register
    TCS3400_AUX,                          // 0x90
    TCS3400_REVID,
    TCS3400_CHIPID,
    TCS3400_STATUS,                    // 0x93

    TCS3400_CLR_CHANLO,            // 0x94
    TCS3400_CLR_CHANHI,            // 0x95
    TCS3400_RED_CHANLO,           // 0x96
    TCS3400_RED_CHANHI,           // 0x97
    TCS3400_GRN_CHANLO,           // 0x98
    TCS3400_GRN_CHANHI,           // 0x99
    TCS3400_BLU_CHANLO,           // 0x9A
    TCS3400_BLU_CHANHI,           // 0x9B
    TCS3400_PRX_HI,                    // 0x9C
    TCS3400_PRX_LO,                    // 0x9D

    TCS3400_PRX_OFFSET,            // 0x9E
    TCS3400_RESV_4,                    // 0x9F
    TCS3400_IRBEAM_CFG,            // 0xA0
    TCS3400_IRBEAM_CARR,          // 0xA1
    TCS3400_IRBEAM_NS,              // 0xA2
    TCS3400_IRBEAM_ISD,            // 0xA3
    TCS3400_IRBEAM_NP,              // 0xA4
    TCS3400_IRBEAM_IPD,            // 0xA5
    TCS3400_IRBEAM_DIV,            // 0xA6
    TCS3400_IRBEAM_LEN,            // 0xA7

    TCS3400_IRBEAM_STAT,         // 0xA8

    TCS3400_REG_COLOR_BINLO=0xD5,  // 0xD5
    TCS3400_REG_COLOR_BINHI=0xD6,  // 0xD6

    TCS3400_REG_MAX,

};

extern struct platform_driver g_tcs3400_driver;

static struct i2c_board_info __initdata tcs3400_board_info = { I2C_BOARD_INFO("tcs3400", TCS3400_SLAVE_ADDR) };
static struct mutex tcs3400_mutex;

static int tcs3400_i2c_probe(struct i2c_client *client, const struct i2c_device_id *id);
static int tcs3400_i2c_remove(struct i2c_client *client);
static int tcs3400_init(void);

static const struct i2c_device_id tcs3400_i2c_id[] = { {TCS3400_DRVNAME, 0}, {"", 0} };
//add for dts load
static const struct of_device_id tcs3400_als_of_match[] = {
    { .compatible = "tcs3400"},
    { }
};

static struct tcs3400_data *tcs_data;

static int tcs3400_read2(u8 addr, u8 *values)
{
	u8 pBuff[3];

	int ret = 0;

	mutex_lock(&tcs3400_mutex);
	tcs_data->client->addr = TCS3400_SLAVE_ADDR;

	pBuff[0] = addr;

	ret = i2c_master_send(tcs_data->client, pBuff, 1);

	if (ret < 0) {
		TCS3400DB("[TCS3400] i2c send failed!!\n");
		mutex_unlock(&tcs3400_mutex);
		return -1;
	}
	ret = i2c_master_recv(tcs_data->client, &pBuff[1], 2); // 2 bytes

	if (ret < 0) {
		mutex_unlock(&tcs3400_mutex);
		TCS3400DB("[TCS3400] i2c recv failed!!\n");
		return -1;
	}

	// i2c data
	values[0] = pBuff[1];
	values[1] = pBuff[2];

	mutex_unlock(&tcs3400_mutex);

	//TCS3400DB("[TCS3400] tcs3400_read: address=0x%02x value=0x%02x\n", pBuff[0], pBuff[1]);

	return 0;
}

// i2c read
// addr : i2c register address
// value : i2c register value
static int tcs3400_read(u8 addr, u8 *value)
{
	u8 pBuff[2];
	int ret;

	TCS3400_FUNC_ENTER();

	mutex_lock(&tcs3400_mutex);
	tcs_data->client->addr = 0x29;
	//addr += I2C_ADDR_OFFSET;
	pBuff[0] = addr;
	ret = i2c_master_send(tcs_data->client, pBuff, 1);
	if (ret < 0) {
		TCS3400DB("[TCS3400] i2c send failed!!\n");
		mutex_unlock(&tcs3400_mutex);
		return -1;
	}
	ret = i2c_master_recv(tcs_data->client, &pBuff[1], 1);
	if (ret < 0) {
		mutex_unlock(&tcs3400_mutex);
		TCS3400DB("[TCS3400]  i2c recv failed!!\n");
		return -1;
	}
	// i2c data
	*value = pBuff[1];
	mutex_unlock(&tcs3400_mutex);
	TCS3400DB("[TCS3400] tcs3400_read: address=0x%02x value=0x%02x\n", pBuff[0], pBuff[1]);

	TCS3400_FUNC_EXIT();
	return 0;
}

// i2c write
// addr : i2c register address
// value : i2c register value
static int tcs3400_write(u8 addr, u8 value)
{
	int ret = 0;
	u8 pBuff[2] = {0};

	mutex_lock(&tcs3400_mutex);
	tcs_data->client->addr = TCS3400_SLAVE_ADDR;

	pBuff[0] = addr;
	pBuff[1] = value;

	ret = i2c_master_send(tcs_data->client, pBuff, 2);

	if (ret < 0) {
		mutex_unlock(&tcs3400_mutex);
		TCS3400DB("[TCS3400] i2c send failed!!\n");
		return -1;
	}
	mutex_unlock(&tcs3400_mutex);

//	TCS3400DB("[TCS3400] tcs3400_write: address=0x%02x value=0x%02x\n", pBuff[0], pBuff[1]);
	return 0;
}

static int tcs3400_sleepMode(bool is_sleep)
{
	int ret = 0;
	int count = 0;

	if ( is_sleep ) {
		ret = tcs3400_write(0x34, 0x00); // ADC Off
		if( ret == -1 ) count++;
		ret = tcs3400_write(0x00, 0x22); // Sleep On
		if( ret == -1 ) count++;
		TCS3400DB("[TCS3400] Sleep (sleep mode start)\n");
	}
	else {
		ret = tcs3400_write(0x00, 0x02); // Sleep Off
		if( ret == -1 ) count++;
		//tcs3400_write(0x34, 0x00); // ADC On
		TCS3400DB("[TCS3400] Wake-Up (sleep mode stop)\n");
	}

	return count;
}

static int tcs3400_level(int level)
{
	int ret = 0;
	int count = 0;

	ret = tcs3400_write(0x34, 0x00); // ADC Off
	if( ret == -1 ) count++;

	switch (level) {

	case 1:
		ret = tcs3400_write(0x00, 0x22);
		if( ret == -1 ) count++;
		ret = tcs3400_write(0x00, 0x02);
		if( ret == -1 ) count++;
		ret = tcs3400_write(0x07, 0x0A);
		if( ret == -1 ) count++;
		ret = tcs3400_write(0x08, 0x08);
		if( ret == -1 ) count++;
		ret = tcs3400_write(0x0E, 0x08);
		if( ret == -1 ) count++;
		ret = tcs3400_write(0x14, 0x08);
		if( ret == -1 ) count++;
		ret = tcs3400_write(0x1A, 0x08);
		if( ret == -1 ) count++;
		break;


	case 2:
		ret = tcs3400_write(0x00, 0x22);
		if( ret == -1 ) count++;
		ret = tcs3400_write(0x00, 0x02);
		if( ret == -1 ) count++;
		ret = tcs3400_write(0x07, 0x05);
		if( ret == -1 ) count++;
		ret = tcs3400_write(0x08, 0x05);
		if( ret == -1 ) count++;
		ret = tcs3400_write(0x0E, 0x05);
		if( ret == -1 ) count++;
		ret = tcs3400_write(0x14, 0x05);
		if( ret == -1 ) count++;
		ret = tcs3400_write(0x1A, 0x05);
		if( ret == -1 ) count++;
	    break;
	} // swtich

	ret = tcs3400_write(0x34, 0x03);  // ADC On
	if( ret == -1 ) count++;

	return count;
}

// tcs3400 initializing
// set initial register
static int tcs3400_init(void)
{
    TCS3400_FUNC_ENTER();

    tcs3400_write(TCS3400_CONTROL, 0x01);
    msleep(10);
    tcs3400_write(TCS3400_ALS_TIME, 0xDB);
    tcs3400_write(TCS3400_GAIN, 0x01);
    tcs3400_write(TCS3400_CONTROL, 0x03);

    TCS3400_FUNC_EXIT();
    return 0;
}

static ssize_t store_reg(struct device_driver *drv, const char *buf, size_t count)
{
///	int len = 0;
	int reg_addr = 0x0;
	int reg_val = 0x0;

	TCS3400DB("[TCS3400] store_reg=%s\n", buf);
	sscanf(buf, "0x%x 0x%x", &reg_addr, &reg_val);
	tcs3400_write((u8)reg_addr, (u8)reg_val);
	return count;
}

static ssize_t show_reg(struct device_driver *drv, char *buf)
{
	int ret = 0;
	int len = 0;
	TCS3400_FUNC_ENTER();

	ret = tcs3400_init();

	if(ret == 0)
	{
		len = snprintf(buf, 32, "Initialized...\n");
	}
	else
	{
		len = snprintf(buf, 32, "No Initialized...\n");
	}
	TCS3400_FUNC_EXIT();
	return len;
}


static int gRegValueAddr = 0;
static ssize_t store_regvalue(struct device_driver *drv, const char *buf, size_t count)
{
///	int len = 0;
	int reg_addr = 0x0;

	TCS3400DB("[TCS3400] store_regvalue=%s\n", buf);
	sscanf(buf, "0x%x", &reg_addr);
	//tcs3400_write((u8)reg_addr, (u8)reg_val);
	gRegValueAddr = reg_addr;

	return count;
}

static ssize_t show_regvalue(struct device_driver *drv, char *buf)
{
	int len = 0;
	u8 read_buf = 0;
	TCS3400_FUNC_ENTER();

	tcs3400_read((u8)gRegValueAddr, &read_buf);

	len = snprintf(buf, 128, "Read Register addr=0x%02x, value=0x%02x\n", gRegValueAddr, (int)read_buf);
	TCS3400_FUNC_EXIT();
	return len;
}

static ssize_t show_level1(struct device_driver *drv, char *buf)
{
	int ret = 0;
	int len = 0;
	TCS3400_FUNC_ENTER();

	ret = tcs3400_level(1);

	if(ret == 0)
	{
		len = snprintf(buf, 16, "Level1\n");
	}
	else
	{
		len = snprintf(buf, 16, "No Level1\n");
	}
	TCS3400_FUNC_EXIT();
	return len;
}

static ssize_t show_level2(struct device_driver *drv, char *buf)
{
	int ret = 0;
	int len = 0;
	TCS3400_FUNC_ENTER();

	ret = tcs3400_level(2);

	if(ret == 0)
	{
		len = snprintf(buf, 16, "Level2\n");
	}
	else
	{
		len = snprintf(buf, 16, "No Level2\n");
	}
	TCS3400_FUNC_EXIT();
	return len;
}

static int tcs3400_power_up(struct tcs3400_data *data)
{
    int rc;

    TCS3400_FUNC_ENTER();

    data->vdd = regulator_get(&data->client->dev, "vdd");
    if (IS_ERR(data->vdd))
    {
        rc = PTR_ERR(data->vdd);
        TCS3400DB("[TCS3400] Regulator get failed vdd rc=%d", rc);
    }

    if (regulator_count_voltages(data->vdd) > 0)
    {
        rc = regulator_set_voltage(data->vdd, TCS3400_VTG_MIN_UV, TCS3400_VTG_MAX_UV);
        if (rc)
        {
            TCS3400DB("[TCS3400] Regulator set_vtg failed vdd rc=%d", rc);
            goto reg_vdd_put;
        }
    }

    rc = regulator_enable(data->vdd);
    if (rc) {
        TCS3400DB("[TCS3400] Regulator vdd enable failed rc=%d", rc);
    }

    TCS3400_FUNC_EXIT();
    return 0;

reg_vdd_put:
    regulator_put(data->vdd);
    TCS3400_FUNC_EXIT();
    return rc;
}

static int tcs3400_power_down(struct tcs3400_data *data)
{
    int rc;
    TCS3400_FUNC_ENTER();
    rc = regulator_disable(data->vdd);
    if (rc) {
        TCS3400DB("[TCS3400] Regulator vdd disable failed rc=%d", rc);
    }
    regulator_set_voltage(
        data->vdd, 0, TCS3400_VTG_MAX_UV);
    regulator_put(data->vdd);
    data->vdd = NULL;
    TCS3400_FUNC_EXIT();
    return rc;
}

static ssize_t show_values(struct device_driver *drv, char *buf)
{
	u8 read_buf[2] = {0,};
	int len = 0, i = 0;
	int values[4] = {0,};
	int ret_low = 0, ret_high = 0;

	TCS3400_FUNC_ENTER();

	/* Power Up */
	tcs3400_power_up(tcs_data);
	msleep(20);
	tcs3400_init();
	msleep(100);
	/* Read ALL Data */
	for (i=TCS3400_CONTROL;i<TCS3400_IRBEAM_STAT;i++)
		tcs3400_read(i, &read_buf[0]);
	/* Read CL Data */
	ret_low = tcs3400_read(TCS3400_CLR_CHANLO, &read_buf[0]);
	ret_high = tcs3400_read(TCS3400_CLR_CHANHI, &read_buf[1]);
	if (0 == ret_low && 0 == ret_high)
		values[3] = read_buf[0] | (read_buf[1] << 8);
	else{
		TCS3400DB("[TCS3400] Fail to read W value\n");
		goto read_data_failed;
	}

	/* Read R Data */
	ret_low = tcs3400_read(TCS3400_RED_CHANLO, &read_buf[0]);
	ret_high = tcs3400_read(TCS3400_RED_CHANHI, &read_buf[1]);
	if (0 == ret_low && 0 == ret_high)
		values[0] = read_buf[0] | (read_buf[1] << 8);
	else{
		TCS3400DB("[TCS3400] Fail to read R value\n");
		goto read_data_failed;
	}

	/* Read G Data */
	ret_low = tcs3400_read(TCS3400_GRN_CHANLO, &read_buf[0]);
	ret_high = tcs3400_read(TCS3400_GRN_CHANHI, &read_buf[1]);
	if (0 == ret_low && 0 == ret_high)
		values[1] = read_buf[0] | (read_buf[1] << 8);
	else{
		TCS3400DB("[TCS3400] Fail to read G value\n");
		goto read_data_failed;
	}

	/* Read B Data */
	ret_low = tcs3400_read(TCS3400_BLU_CHANLO, &read_buf[0]);
	ret_high = tcs3400_read(TCS3400_BLU_CHANHI, &read_buf[1]);
	if (0 == ret_low && 0 == ret_high)
		values[2] = read_buf[0] | (read_buf[1] << 8);
	else{
		TCS3400DB("[TCS3400] Fail to read B value\n");
		goto read_data_failed;
	}

	tcs3400_power_down(tcs_data);

	TCS3400DB("[TCS3400] Succeed to Read RGBW data(%d %d %d %d)\n",
		values[0], values[1], values[2], values[3]);
	len = snprintf(buf, 64, "%d %d %d %d\n",
		values[0], values[1], values[2], values[3]);
	TCS3400_FUNC_EXIT();
	return len;
read_data_failed:
	tcs3400_power_down(tcs_data);
	TCS3400DB("[TCS3400] Failed to Read RGBW data(%d %d %d %d)\n",
		values[0], values[1], values[2], values[3]);
	len = snprintf(buf, 32, "-1 -1 -1 -1\n");
	TCS3400_FUNC_EXIT();
	return len;
}

static int tcs3400_get_lux(struct tcs3400_chip *chip)
{
#if 1
	s32 rp1, gp1, bp1, cp1, factor, a, c;
	s32 cct;
	/* remove ir from counts*/
	rp1 = chip->als_inf.red_raw   - chip->als_inf.ir;
	gp1 = chip->als_inf.green_raw - chip->als_inf.ir;
	bp1 = chip->als_inf.blue_raw  - chip->als_inf.ir;
	cp1 = chip->als_inf.clear_raw - chip->als_inf.ir;
	if (rp1 == 0) {
		TCS3400DB("[TCS3400] warning rp1 = 0\n");
		return 0;
	}
	if (bp1 == 0) {
		TCS3400DB("[TCS3400] warning bp1 = 0\n");
		return 0;
	}
	factor = (100 * bp1) / rp1;
	if (factor < 30) {
		a = 22;
		c = 2351;
	} else if (factor < 80) {
		a = 3251;
		c = 1627;
	} else {
		a = 23;
		c = 6378;
	}
	cct = ((a * factor) + c*100) / 100;
	TCS3400DB("[TCS3400] a=%d, c=%d, factor=%d, cct=%d\n", a, c, factor, cct);
	chip->als_inf.cct = cct;
	return cct;
#else
    s32 rp1, gp1, bp1, cp1;
    s32 lux = 0;
    s32 lux2 = 0;
    s32 cct;
    u32 sat = chip->als_inf.saturation;
    s32 sf;

    int quarter = (tcs3400_max_colorcount(chip) / 4);

    /* use time in ms get scaling factor */
    tcs3400_calc_cpl(chip);

    tcs3400_compute_rgb_prime(chip);

    /* remove ir from counts*/
    if(chip->als_inf.bin.coeff) {
        rp1 = chip->als_inf.prime.red;
        gp1 = chip->als_inf.prime.grn;
        bp1 = chip->als_inf.prime.blu;
    } else {
        rp1 = chip->als_inf.red_raw   - chip->als_inf.ir;
        gp1 = chip->als_inf.green_raw - chip->als_inf.ir;
        bp1 = chip->als_inf.blue_raw  - chip->als_inf.ir;
        cp1 = chip->als_inf.clear_raw - chip->als_inf.ir;
    }

    if (!chip->als_inf.cpl) {
        dev_info(&chip->client->dev, "%s: zero cpl. Setting to 1\n",
                __func__);
        chip->als_inf.cpl = 1;
    }

    lux += chip->segment[chip->device_index].r_coef * rp1;
    lux += chip->segment[chip->device_index].g_coef * gp1;
    lux += chip->segment[chip->device_index].b_coef * bp1;

    sf = chip->als_inf.cpl;

    lux /= sf;
    lux2 = lux * chip->segment[chip->device_index].d_factor;
    lux2 += 512;
    lux2 >>= 10;

    if (rp1 == 0)
    {
        rp1 = 1;
    }

    cct = ((chip->segment[chip->device_index].ct_coef * bp1) / rp1) +
        chip->segment[chip->device_index].ct_offset;

#ifdef LUX_MESSAGES
    dev_info(&chip->client->dev
            , "%s: cpl: %d, pre-lux: %d, lux: %d, cct: %d\n"
            , __func__
            , sf
            , lux
            , chip->als_inf.lux
            , chip->als_inf.cct
            );
#endif //LUX_MESSAGES

    /* Auto gain */
    if (!chip->als_gain_auto) {
        if (chip->als_inf.clear_raw <= MIN_ALS_VALUE) {
#ifdef LUX_MESSAGES
            dev_info(&chip->client->dev,
                 "%s: darkness\n", __func__);
#endif
            chip->als_inf.lux = 0;
            // cct: no change
            goto exit;
        } else if (chip->als_inf.clear_raw >= sat) {
#ifdef LUX_MESSAGES
            dev_info(&chip->client->dev,
                 "%s: saturation, keep lux & cct\n", __func__);
#endif
            // lux, cct: no change
            goto exit;
        } else {
            if (lux2 < 0)
                goto neg_error;
            chip->als_inf.lux = lux2;
            chip->als_inf.cct = cct;
        }
    } else {
        /* AutoGain */
        if (chip->als_inf.clear_raw < 100) {
            tcs3400_inc_gain(chip);
            tcs3400_flush_regs(chip);
        } else if (chip->als_inf.clear_raw >
            (tcs3400_max_colorcount(chip) - quarter)) {
            tcs3400_dec_gain(chip);
            tcs3400_flush_regs(chip);
        } else {
            if (lux2 < 0)
                goto neg_error;
            chip->als_inf.lux = lux2;
            chip->als_inf.cct = cct;
        }
    }

exit:
return 0;

neg_error:
    dev_err(&chip->client->dev, "%s: ERROR Negative Lux (rp1, gp1, bp1, clr_raw) = (%d, %d, %d, %d). Using previous value. "
            , __func__
            , rp1
            , gp1
            , bp1
            , chip->als_inf.clear_raw
            );
return 1;
#endif
}

static ssize_t show_cct(struct device_driver *drv, char *buf)
{
	u8 buffer[10] = {0,};
	int len = 0, i = 0;
	int ret_low = 0, ret_high = 0;

	TCS3400_FUNC_ENTER();
	memset(&chip,0,sizeof(chip));
	/* Power Up */
	ret_low = tcs3400_power_up(tcs_data);
	if (ret_low != 0) {
		TCS3400DB("[TCS3400] Fail to power up rc %d\n", ret_low);
		len = snprintf(buf, 32, "-1\n");
		TCS3400_FUNC_EXIT();
		return len;
	}
	msleep(20);
	tcs3400_init();
	msleep(100);
	/* Read ALL Data */
	for (i=TCS3400_CONTROL;i<TCS3400_IRBEAM_STAT;i++)
		tcs3400_read(i, &buffer[0]);
	/* Read CL Data */
	ret_low = tcs3400_read(TCS3400_CLR_CHANLO, &buffer[0]);
	ret_high = tcs3400_read(TCS3400_CLR_CHANHI, &buffer[1]);
	if (0 != ret_low && 0 != ret_high) {
		TCS3400DB("[TCS3400] Fail to read W value\n");
		goto read_data_failed;
	}

	/* Read R Data */
	ret_low = tcs3400_read(TCS3400_RED_CHANLO, &buffer[2]);
	ret_high = tcs3400_read(TCS3400_RED_CHANHI, &buffer[3]);
	if (0 != ret_low && 0 != ret_high) {
		TCS3400DB("[TCS3400] Fail to read R value\n");
		goto read_data_failed;
	}

	/* Read G Data */
	ret_low = tcs3400_read(TCS3400_GRN_CHANLO, &buffer[4]);
	ret_high = tcs3400_read(TCS3400_GRN_CHANHI, &buffer[5]);
	if (0 != ret_low && 0 != ret_high) {
		TCS3400DB("[TCS3400] Fail to read G value\n");
		goto read_data_failed;
	}

	/* Read B Data */
	ret_low = tcs3400_read(TCS3400_BLU_CHANLO, &buffer[6]);
	ret_high = tcs3400_read(TCS3400_BLU_CHANHI, &buffer[7]);
	if (0 != ret_low && 0 != ret_high) {
		TCS3400DB("[TCS3400] Fail to read B value\n");
		goto read_data_failed;
	}

	/* Read ATIME Data */
	ret_low = tcs3400_read(TCS3400_ALS_TIME, &buffer[8]);
	if (0 != ret_low) {
		TCS3400DB("[TCS3400] Fail to read ATIM value\n");
		goto read_data_failed;
	}

	/* Read AGAIN Data */
	ret_high = tcs3400_read(TCS3400_GAIN, &buffer[9]);
	if (0 != ret_high) {
		TCS3400DB("[TCS3400] Fail to read AGAIN value\n");
		goto read_data_failed;
	}

	tcs3400_power_down(tcs_data);

	/* extract raw channel data */
	chip.als_inf.clear_raw = le16_to_cpup((const __le16 *)&buffer[0]);
	chip.als_inf.red_raw   = le16_to_cpup((const __le16 *)&buffer[2]);
	chip.als_inf.green_raw = le16_to_cpup((const __le16 *)&buffer[4]);
	chip.als_inf.blue_raw  = le16_to_cpup((const __le16 *)&buffer[6]);

	chip.als_inf.ir =
		(chip.als_inf.red_raw + chip.als_inf.green_raw +
		chip.als_inf.blue_raw - chip.als_inf.clear_raw + 1) >> 1;

	chip.als_inf.atime = buffer[8];
	chip.als_inf.again = buffer[9];

	tcs3400_get_lux(&chip);

	TCS3400DB("[TCS3400] AGAIN=%d ATIME=%d IR=%d CCT=%d C=%d R=%d G=%d B=%d R'=%d G'=%d B'=%d\n", chip.als_inf.again, chip.als_inf.atime,
		chip.als_inf.ir, chip.als_inf.cct, chip.als_inf.clear_raw, chip.als_inf.red_raw, chip.als_inf.green_raw, chip.als_inf.blue_raw,
		chip.als_inf.red_raw-chip.als_inf.ir, chip.als_inf.green_raw-chip.als_inf.ir, chip.als_inf.blue_raw-chip.als_inf.ir);
	len = snprintf(buf, 32, "%d\n", chip.als_inf.cct);
	TCS3400_FUNC_EXIT();
	return len;
read_data_failed:
	tcs3400_power_down(tcs_data);
	TCS3400DB("[TCS3400] Fail to Read RGBW data(C:%d R:%d G:%d B:%d ATIME=%d AGAIN=%d)\n",
		(u16)buffer[0], (u16)buffer[2], (u16)buffer[4], (u16)buffer[6], buffer[8], buffer[9]);
	len = snprintf(buf, 32, "-1\n");
	TCS3400_FUNC_EXIT();
	return len;
}

static ssize_t show_chipid(struct device_driver *drv, char *buf)
{
	u8 buffer[2] = {0,};
	int len = 0;
	int ret_low = 0;

	TCS3400_FUNC_ENTER();
	memset(&chip,0,sizeof(chip));
	/* Power Up */
	ret_low = tcs3400_power_up(tcs_data);
	msleep(20);
	tcs3400_init();
	msleep(100);
	/* Read chipid */
	ret_low = tcs3400_read(TCS3400_CHIPID, &buffer[0]);
	if (0 != ret_low) {
		TCS3400DB("[TCS3400] Fail to read chipid\n");
		goto read_data_failed;
	}
	TCS3400DB("[TCS3400] chipid=%d\n", buffer[0]);
	tcs3400_power_down(tcs_data);
	len = snprintf(buf, 32, "%d\n", buffer[0]);
	TCS3400_FUNC_EXIT();
	return len;
read_data_failed:
	tcs3400_power_down(tcs_data);
	len = snprintf(buf, 32, "-1\n");
	TCS3400_FUNC_EXIT();
	return len;
}

static ssize_t show_debugcct(struct device_driver *drv, char *buf)
{
	u8 buffer[10] = {0,};
	int len = 0, i = 0;
	int ret_low = 0, ret_high = 0;

	TCS3400_FUNC_ENTER();
	memset(&chip,0,sizeof(chip));
	/* Power Up */
	tcs3400_power_up(tcs_data);
	msleep(20);
	tcs3400_init();
	msleep(100);
	/* Read ALL Data */
	for (i=TCS3400_CONTROL;i<TCS3400_IRBEAM_STAT;i++)
		tcs3400_read(i, &buffer[0]);
	/* Read CL Data */
	ret_low = tcs3400_read(TCS3400_CLR_CHANLO, &buffer[0]);
	ret_high = tcs3400_read(TCS3400_CLR_CHANHI, &buffer[1]);
	if (0 != ret_low && 0 != ret_high) {
		TCS3400DB("[TCS3400] Fail to read W value\n");
		goto read_data_failed;
	}

	/* Read R Data */
	ret_low = tcs3400_read(TCS3400_RED_CHANLO, &buffer[2]);
	ret_high = tcs3400_read(TCS3400_RED_CHANHI, &buffer[3]);
	if (0 != ret_low && 0 != ret_high) {
		TCS3400DB("[TCS3400] Fail to read R value\n");
		goto read_data_failed;
	}

	/* Read G Data */
	ret_low = tcs3400_read(TCS3400_GRN_CHANLO, &buffer[4]);
	ret_high = tcs3400_read(TCS3400_GRN_CHANHI, &buffer[5]);
	if (0 != ret_low && 0 != ret_high) {
		TCS3400DB("[TCS3400] Fail to read G value\n");
		goto read_data_failed;
	}

	/* Read B Data */
	ret_low = tcs3400_read(TCS3400_BLU_CHANLO, &buffer[6]);
	ret_high = tcs3400_read(TCS3400_BLU_CHANHI, &buffer[7]);
	if (0 != ret_low && 0 != ret_high) {
		TCS3400DB("[TCS3400] Fail to read B value\n");
		goto read_data_failed;
	}

	/* Read ATIME Data */
	ret_low = tcs3400_read(TCS3400_ALS_TIME, &buffer[8]);
	if (0 != ret_low) {
		TCS3400DB("[TCS3400] Fail to read ATIM value\n");
		goto read_data_failed;
	}

	/* Read AGAIN Data */
	ret_high = tcs3400_read(TCS3400_GAIN, &buffer[9]);
	if (0 != ret_high) {
		TCS3400DB("[TCS3400] Fail to read AGAIN value\n");
		goto read_data_failed;
	}

	tcs3400_power_down(tcs_data);

	/* extract raw channel data */
	chip.als_inf.clear_raw = le16_to_cpup((const __le16 *)&buffer[0]);
	chip.als_inf.red_raw   = le16_to_cpup((const __le16 *)&buffer[2]);
	chip.als_inf.green_raw = le16_to_cpup((const __le16 *)&buffer[4]);
	chip.als_inf.blue_raw  = le16_to_cpup((const __le16 *)&buffer[6]);

	chip.als_inf.ir =
		(chip.als_inf.red_raw + chip.als_inf.green_raw +
		chip.als_inf.blue_raw - chip.als_inf.clear_raw + 1) >> 1;

	chip.als_inf.atime = buffer[8];
	chip.als_inf.again = buffer[9];

	tcs3400_get_lux(&chip);

	TCS3400DB("[TCS3400] AGAIN=%d ATIME=%d IR=%d CCT=%d C=%d R=%d G=%d B=%d R'=%d G'=%d B'=%d\n", chip.als_inf.again, chip.als_inf.atime,
		chip.als_inf.ir, chip.als_inf.cct, chip.als_inf.clear_raw, chip.als_inf.red_raw, chip.als_inf.green_raw, chip.als_inf.blue_raw,
		chip.als_inf.red_raw-chip.als_inf.ir, chip.als_inf.green_raw-chip.als_inf.ir, chip.als_inf.blue_raw-chip.als_inf.ir);
	len = snprintf(buf, 128, "AGAIN=%d ATIME=%d IR=%d CCT=%d C=%d R=%d G=%d B=%d R'=%d G'=%d B'=%d\n", chip.als_inf.again, chip.als_inf.atime,
		chip.als_inf.ir, chip.als_inf.cct, chip.als_inf.clear_raw, chip.als_inf.red_raw, chip.als_inf.green_raw, chip.als_inf.blue_raw,
		chip.als_inf.red_raw-chip.als_inf.ir, chip.als_inf.green_raw-chip.als_inf.ir, chip.als_inf.blue_raw-chip.als_inf.ir);
	TCS3400_FUNC_EXIT();
	return len;
read_data_failed:
	tcs3400_power_down(tcs_data);
	TCS3400DB("[TCS3400] Fail to Read RGBW data(C:%d R:%d G:%d B:%d ATIME=%d AGAIN=%d)\n",
		(u16)buffer[0], (u16)buffer[2], (u16)buffer[4], (u16)buffer[6], buffer[8], buffer[9]);
	len = snprintf(buf, 32, "-1\n");
	TCS3400_FUNC_EXIT();
	return len;
}

static ssize_t show_poweron(struct device_driver *drv, char *buf)
{
	int len = 0;

	TCS3400_FUNC_ENTER();

	/* Power Up */
	tcs3400_power_up(tcs_data);
	msleep(20);
	tcs3400_init();
	TCS3400_FUNC_EXIT();
	TCS3400DB("[TCS3400] RGBW power on\n");
	len = snprintf(buf, 32, "power on succeed\n");
	return len;
}

static ssize_t show_poweroff(struct device_driver *drv, char *buf)
{
	int len = 0;
	TCS3400_FUNC_ENTER();

	tcs3400_power_down(tcs_data);

	TCS3400_FUNC_EXIT();
	TCS3400DB("[TCS3400] RGBW power off\n");
	len = snprintf(buf, 32, "power off succeed\n");
	return len;
}

static ssize_t show_readdata(struct device_driver *drv, char *buf)
{
	u8 read_buf[2] = {0,};
	int len = 0,i = 0;
	int values[3] = {0,};
	int ret_low = 0, ret_high = 0;

	TCS3400_FUNC_ENTER();
	/* Read ALL Data */
	for (i=TCS3400_CONTROL;i<TCS3400_IRBEAM_STAT;i++)
		tcs3400_read(i, &read_buf[0]);

	/* Read CL Data */
	ret_low = tcs3400_read(TCS3400_CLR_CHANLO, &read_buf[0]);
	ret_high = tcs3400_read(TCS3400_CLR_CHANHI, &read_buf[1]);
	if (0 == ret_low && 0 == ret_high)
		values[3] = read_buf[0] | (read_buf[1] << 8);
	else{
		TCS3400DB("[TCS3400] Fail to read W value\n");
		goto read_data_failed;
	}

	/* Read R Data */
	ret_low = tcs3400_read(TCS3400_RED_CHANLO, &read_buf[0]);
	ret_high = tcs3400_read(TCS3400_RED_CHANHI, &read_buf[1]);
	if (0 == ret_low && 0 == ret_high)
		values[0] = read_buf[0] | (read_buf[1] << 8);
	else{
		TCS3400DB("[TCS3400] Fail to read R value\n");
		goto read_data_failed;
	}

	/* Read G Data */
	ret_low = tcs3400_read(TCS3400_GRN_CHANLO, &read_buf[0]);
	ret_high = tcs3400_read(TCS3400_GRN_CHANHI, &read_buf[1]);
	if (0 == ret_low && 0 == ret_high)
		values[1] = read_buf[0] | (read_buf[1] << 8);
	else{
		TCS3400DB("[TCS3400] Fail to read G value\n");
		goto read_data_failed;
	}

	/* Read B Data */
	ret_low = tcs3400_read(TCS3400_BLU_CHANLO, &read_buf[0]);
	ret_high = tcs3400_read(TCS3400_BLU_CHANHI, &read_buf[1]);
	if (0 == ret_low && 0 == ret_high)
		values[2] = read_buf[0] | (read_buf[1] << 8);
	else{
		TCS3400DB("[TCS3400] Fail to read B value\n");
		goto read_data_failed;
	}

	TCS3400DB("[TCS3400] Succeed to Read RGBW data(%d %d %d %d)\n",
		values[0], values[1], values[2], values[3]);
	len = snprintf(buf, 64, "%d %d %d %d\n",
		values[0], values[1], values[2], values[3]);
	TCS3400_FUNC_EXIT();
	return len;
read_data_failed:
	TCS3400DB("[TCS3400] Failed to Read RGBW data(%d %d %d %d)\n",
		values[0], values[1], values[2], values[3]);
	len = snprintf(buf, 32, "-1 -1 -1 -1\n");
	TCS3400_FUNC_EXIT();
	return len;
}

static ssize_t show_values2(struct device_driver *drv, char *buf)
{
	u8 read_buf[2] = {0,};
	int len = 0;
	int values[4] = {0,};
	int ret = 0;

	ret = tcs3400_read2(R_LOW_DATA, read_buf);
	if ( 0 == ret )
		values[0] = read_buf[0] | (read_buf[1] << 8);
	else values[0] = -1;

	ret = tcs3400_read2(G_LOW_DATA, read_buf);
	if ( 0 == ret )
		values[1] = read_buf[0] | (read_buf[1] << 8);
	else values[1] = -1;

	ret = tcs3400_read2(B_LOW_DATA, read_buf);
	if ( 0 == ret )
		values[2] = read_buf[0] | (read_buf[1] << 8);
	else values[2] = -1;

	ret = tcs3400_read2(W_LOW_DATA, read_buf);
	if ( 0 == ret )
		values[3] = read_buf[0] | (read_buf[1] << 8);
	else values[3] = -1;

	//TCS3400DB("[TCS3400] show_values values=%d %d %d %d\n",
	//				values[0], values[1], values[2], values[3]);

	len = snprintf(buf, 64, "%d %d %d %d\n",
					values[0], values[1], values[2], values[3]);

	return len;
}

static ssize_t show_code(struct device_driver *drv, char *buf)
{
	u8 read_buf = 0;
	int len = 0;
	tcs3400_read(CORRELATION_CODE, &read_buf);

	TCS3400DB("[TCS3400] show_code 0x%02x\n", (int)read_buf);

	len = snprintf(buf, 16, "0x%02x\n", (int)read_buf);

	return len;
}

static ssize_t show_sleep(struct device_driver *drv, char *buf)
{
	int ret = 0;
	int len = 0;
	TCS3400_FUNC_ENTER();

	ret = tcs3400_sleepMode(true);

	if(ret == 0)
	{
		len = snprintf(buf, 16, "sleep\n");
	}
	else
	{
		len = snprintf(buf, 16, "No sleep\n");
	}
	TCS3400_FUNC_EXIT();
	return len;
}

static ssize_t show_awake(struct device_driver *drv, char *buf)
{
	int ret = 0;
	int len = 0;
	TCS3400_FUNC_ENTER();

	ret = tcs3400_sleepMode(false);

	if(ret == 0)
	{
		len = snprintf(buf, 16, "awake\n");
	}
	else
	{
		len = snprintf(buf, 16, "No awake\n");
	}
	TCS3400_FUNC_EXIT();
	return len;
}

static ssize_t show_adcon(struct device_driver *drv, char *buf)
{
	int ret = 0;
	int len = 0;
	TCS3400_FUNC_ENTER();

	ret = tcs3400_write(0x34, 0x03);

	if(ret == 0)
	{
		len = snprintf(buf, 16, "adcon\n");
	}
	else
	{
		len = snprintf(buf, 16, "No adcon\n");
	}
	TCS3400_FUNC_EXIT();
	return len;
}

static ssize_t show_adcoff(struct device_driver *drv, char *buf)
{
	int ret = 0;
	int len = 0;
	TCS3400_FUNC_ENTER();

	ret = tcs3400_write(0x34, 0x00);

	if(ret == 0)
	{
		len = snprintf(buf, 16, "adcoff\n");
	}
	else
	{
		len = snprintf(buf, 16, "No adcoff\n");
	}
	TCS3400_FUNC_EXIT();
	return len;
}


static ssize_t show_fastmmi(struct device_driver *drv, char *buf)
{
	u8 read_buf = 0;
	int len = 0;
	TCS3400_FUNC_ENTER();
	tcs3400_init();
	tcs3400_read(0x06, &read_buf);

	TCS3400DB("[TCS3400] show_code 0x%02x\n", (int)read_buf);

	len = snprintf(buf, 16, "0x%02x\n", (int)read_buf);
	TCS3400_FUNC_EXIT();
	return len;
}

static DRIVER_ATTR(reg, S_IWUSR | S_IRUGO, show_reg, store_reg);
static DRIVER_ATTR(regvalue, S_IWUSR | S_IRUGO, show_regvalue, store_regvalue);

static DRIVER_ATTR(level1, S_IWUSR | S_IRUGO, show_level1, NULL);
static DRIVER_ATTR(level2, S_IWUSR | S_IRUGO, show_level2, NULL);

static DRIVER_ATTR(values, S_IWUSR | S_IRUGO, show_values, NULL);
static DRIVER_ATTR(values2, S_IWUSR | S_IRUGO, show_values2, NULL);

static DRIVER_ATTR(cct, S_IWUSR | S_IRUGO, show_cct, NULL);
static DRIVER_ATTR(chipid, S_IWUSR | S_IRUGO, show_chipid, NULL);
static DRIVER_ATTR(debugcct, S_IWUSR | S_IRUGO, show_debugcct, NULL);
static DRIVER_ATTR(poweron, S_IWUSR | S_IRUGO, show_poweron, NULL);
static DRIVER_ATTR(readdata, S_IWUSR | S_IRUGO, show_readdata, NULL);
static DRIVER_ATTR(poweroff, S_IWUSR | S_IRUGO, show_poweroff, NULL);

static DRIVER_ATTR(code, S_IWUSR | S_IRUGO, show_code, NULL);
static DRIVER_ATTR(sleep, S_IWUSR | S_IRUGO, show_sleep, NULL);
static DRIVER_ATTR(awake, S_IWUSR | S_IRUGO, show_awake, NULL);
static DRIVER_ATTR(adcon, S_IWUSR | S_IRUGO, show_adcon, NULL);
static DRIVER_ATTR(adcoff, S_IWUSR | S_IRUGO, show_adcoff, NULL);
static DRIVER_ATTR(fastmmi, S_IWUSR | S_IRUGO, show_fastmmi, NULL);

#define TCS3400_IOCTL_INIT				_IO('n', 0x01)
#define TCS3400_IOCTL_G_DATA			_IOR('n', 0x02, unsigned char)
#define TCS3400_IOCTL_G_CHIPID			_IOR('n', 0x03,GET_TCS3400_DATA)

static int tcs3400_read_chipid(char *buf)
{
	u8 read_buf = 0;
	unsigned int chip_id = 0;
	tcs3400_read(CORRELATION_CODE, &read_buf);

	TCS3400DB("[TCS3400] get chipid 0x%02x\n", (int)read_buf);
	chip_id = (int)read_buf;
	return chip_id;
}

static void tcs3400_read_data(GET_TCS3400_DATA *get_data)

{
	u8 read_buf[2] = {0,};
	int values[4] = {0,};

	tcs3400_read(R_LOW_DATA, &read_buf[0]);
	tcs3400_read(R_HIGH_DATA, &read_buf[1]);
	values[0] = read_buf[0] | (read_buf[1] << 8);

	tcs3400_read(G_LOW_DATA, &read_buf[0]);
	tcs3400_read(G_HIGH_DATA, &read_buf[1]);
	values[1] = read_buf[0] | (read_buf[1] << 8);

	tcs3400_read(B_LOW_DATA, &read_buf[0]);
	tcs3400_read(B_HIGH_DATA, &read_buf[1]);
	values[2] = read_buf[0] | (read_buf[1] << 8);

	tcs3400_read(W_LOW_DATA, &read_buf[0]);
	tcs3400_read(W_HIGH_DATA, &read_buf[1]);
	values[3] = read_buf[0] | (read_buf[1] << 8);

	TCS3400DB("[TCS3400] values= R:%d G: %d B: %d W:%d\n",
					values[0], values[1], values[2], values[3]);

	get_data->r_data = values[0];
	get_data->g_data = values[1];
	get_data->b_data = values[2];
	get_data->w_data = values[3];
}

static int tcs3400_ioctl_handler(struct file *file,
			unsigned int cmd, unsigned long arg,
			void __user *p)
{

	char *r_buf;
	unsigned char chip_id;
	GET_TCS3400_DATA get_data;
    switch(cmd) {
    case TCS3400_IOCTL_INIT:
		TCS3400DB("TCS3400_IOCTL_INIT \n");
		tcs3400_init();
		break;
    case TCS3400_IOCTL_G_DATA:
		TCS3400DB("TCS3400_IOCTL_G_DATA \n");
		tcs3400_read_data(&get_data);
		TCS3400DB("R: %d, G: %d, B: %d W: %d \n",get_data.r_data,get_data.g_data,get_data.b_data,get_data.w_data);
		if (copy_to_user((GET_TCS3400_DATA *)p, &get_data,sizeof(GET_TCS3400_DATA))) {
			return -EFAULT;
		}
		break;
	case TCS3400_IOCTL_G_CHIPID:
		TCS3400DB("TCS3400_IOCTL_G_CHIPID \n");
		chip_id = tcs3400_read_chipid(r_buf);
		TCS3400DB("tcs3400 chip_id:%d\n",chip_id);
		if (copy_to_user((unsigned char *)p, &chip_id,sizeof(unsigned char))) {
			return -EFAULT;
		}
		break;
    default:
        break;
    }
	return 0;
}

static long tcs3400_ioctl(struct file *file,
				unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct tcs3400_data *data =
			container_of(file->private_data,
					struct tcs3400_data, miscdev);

	if(data)
		mutex_lock(&data->work_mutex);
	else
		pr_err("tcs3400_ioctl NULL  ");
	ret = tcs3400_ioctl_handler(file, cmd, arg, (void __user *)arg);
	if(data)

	mutex_unlock(&data->work_mutex);
	else
		pr_err("tcs3400_ioctl NULL ");

	return ret;
}

static int tcs3400_open(struct inode *inode, struct file *file)
{
	return 0;
}

static struct file_operations tcs3400_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = tcs3400_ioctl,
    .open	= tcs3400_open,
};

static int tcs3400_i2c_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
	int ret_driver_file = 0;

	TCS3400_FUNC_ENTER();
	tcs_data = kzalloc(sizeof(struct tcs3400_data), GFP_KERNEL);
	tcs_data->client = client;

	mutex_init(&tcs3400_mutex);

	ret_driver_file = driver_create_file(&(g_tcs3400_driver.driver), &driver_attr_reg);
	ret_driver_file = driver_create_file(&(g_tcs3400_driver.driver), &driver_attr_regvalue);

	ret_driver_file = driver_create_file(&(g_tcs3400_driver.driver), &driver_attr_level1);
	ret_driver_file = driver_create_file(&(g_tcs3400_driver.driver), &driver_attr_level2);

	ret_driver_file = driver_create_file(&(g_tcs3400_driver.driver), &driver_attr_values);
	ret_driver_file = driver_create_file(&(g_tcs3400_driver.driver), &driver_attr_values2);

	ret_driver_file = driver_create_file(&(g_tcs3400_driver.driver), &driver_attr_code);
	ret_driver_file = driver_create_file(&(g_tcs3400_driver.driver), &driver_attr_sleep);
	ret_driver_file = driver_create_file(&(g_tcs3400_driver.driver), &driver_attr_awake);

	ret_driver_file = driver_create_file(&(g_tcs3400_driver.driver), &driver_attr_adcon);
	ret_driver_file = driver_create_file(&(g_tcs3400_driver.driver), &driver_attr_adcoff);

	ret_driver_file = driver_create_file(&(g_tcs3400_driver.driver), &driver_attr_fastmmi);

	ret_driver_file = driver_create_file(&(g_tcs3400_driver.driver), &driver_attr_cct);
	ret_driver_file = driver_create_file(&(g_tcs3400_driver.driver), &driver_attr_chipid);
	ret_driver_file = driver_create_file(&(g_tcs3400_driver.driver), &driver_attr_debugcct);
	ret_driver_file = driver_create_file(&(g_tcs3400_driver.driver), &driver_attr_poweron);
	ret_driver_file = driver_create_file(&(g_tcs3400_driver.driver), &driver_attr_readdata);
	ret_driver_file = driver_create_file(&(g_tcs3400_driver.driver), &driver_attr_poweroff);

	mutex_init(&tcs_data->work_mutex);
	tcs_data->miscdev.minor = MISC_DYNAMIC_MINOR;
	tcs_data->miscdev.name = "tcs3400_dev";
	tcs_data->miscdev.fops = &tcs3400_fops;

	if (misc_register(&tcs_data->miscdev) != 0)
		pr_err("cannot register misc devices\n");

	TCS3400_FUNC_EXIT();

	return 0;
}

static int tcs3400_i2c_remove(struct i2c_client *client)
{
	return 0;
}

//MODULE_DEVICE_TABLE(i2c, tcs3400_i2c_id);

#ifndef WIN32
struct i2c_driver tcs3400_i2c_driver = {
	.probe = tcs3400_i2c_probe,
	.remove = tcs3400_i2c_remove,
	.driver.name = TCS3400_DRVNAME,
	.id_table = tcs3400_i2c_id,
};
#else
struct i2c_driver tcs3400_i2c_driver = {tcs3400_i2c_probe, tcs3400_i2c_remove};
#endif // WIN32



static int tcs3400_probe(struct platform_device *pdev)
{
	int rc;

	TCS3400_FUNC_ENTER();
	rc = i2c_add_driver(&tcs3400_i2c_driver);
	if (rc)
		pr_err("[TCS3400] %d erro ret:%d\n", __LINE__, rc);
	TCS3400_FUNC_EXIT();
	return 0;
}

static int tcs3400_remove(struct platform_device *pdev)
{
	i2c_del_driver(&tcs3400_i2c_driver);
	return 0;
}

static int tcs3400_suspend(struct platform_device *pdev, pm_message_t mesg)
{
	return 0;
}

static int tcs3400_resume(struct platform_device *pdev)
{
	return 0;
}

/* platform structure */
#ifndef WIN32
 struct platform_driver g_tcs3400_driver = {
	.probe = tcs3400_probe,
	.remove = tcs3400_remove,
	.suspend = tcs3400_suspend,
	.resume = tcs3400_resume,
	.driver = {
		   .name = "tcs3400",
		   .owner = THIS_MODULE,
		   .of_match_table = of_match_ptr(tcs3400_als_of_match),
	},
};

 struct platform_device g_tcs3400_device = {
    .name = "tcs3400",
    .id = 0,
    .dev = {}
};
#else
static struct platform_driver g_tcs3400_driver = {tcs3400_probe, tcs3400_remove, {"tcs3400", THIS_MODULE}};
static struct platform_device g_tcs3400_device;
#endif // WIN32

static int __init tcs3400_i2c_init(void)
{
	TCS3400_FUNC_ENTER();
	i2c_register_board_info(LENS_I2C_BUSNUM, &tcs3400_board_info, 1);
	if(platform_device_register(&g_tcs3400_device)){
		TCS3400DB("[TCS3400] failed to register tcs3400 device\n");
		return -ENODEV;
	}
	if (platform_driver_register(&g_tcs3400_driver)) {
		TCS3400DB("[TCS3400] failed to register tcs3400 driver\n");
		return -ENODEV;
	}
	TCS3400_FUNC_EXIT();
	return 0;
}

static void __exit tcs3400_i2c_exit(void)
{
	platform_driver_unregister(&g_tcs3400_driver);
}

module_init(tcs3400_i2c_init);
module_exit(tcs3400_i2c_exit);
