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

#define NXU8010_FUNC_ENTER() printk(KERN_INFO "[NXU8010]%s: Enter\n", __func__)
#define NXU8010_FUNC_EXIT()  printk(KERN_INFO "[NXU8010]%s: Exit(%d)\n", __func__, __LINE__)

#define NXU8010_VTG_MIN_UV          2800000
#define NXU8010_VTG_MAX_UV          2800000
#define LENS_I2C_BUSNUM 3
#define NXU8010_RGBW_RETRY_TIMES 3

typedef struct {
	int16_t r_data;
	int16_t g_data;
	int16_t b_data;
	int16_t w_data;
} GET_NEXU8010_DATA ;

struct nxu8010_data {
	struct i2c_client *client;
	struct regulator *vdd;
	struct miscdevice miscdev;
	struct mutex work_mutex;

};

static const unsigned char NXU8010_RGBW_INIT_DATA[] = {
0x01, 0x08,
0x00, 0x02,
0x02, 0x00,
0x03, 0x70,
0x04, 0x28,
0x05, 0x00,
0x06, 0x40,
0x07, 0x0A,
0x30, 0x0C,
0x31, 0x00,
0x32, 0x00,
0x33, 0x00,
0x08, 0x08,
0x09, 0x18,
0x0A, 0x00,
0x0B, 0x00,
0x0C, 0x00,
0x0D, 0x00,
0x0E, 0x08,
0x0F, 0x18,
0x10, 0x00,
0x11, 0x00,
0x12, 0x00,
0x13, 0x00,
0x14, 0x08,
0x15, 0x18,
0x16, 0x00,
0x17, 0x00,
0x18, 0x00,
0x19, 0x00,
0x1A, 0x08,
0x1B, 0x18,
0x1C, 0x00,
0x1D, 0x00,
0x1E, 0x00,
0x1F, 0x00,
0x35, 0x15,
0x50, 0x01,
0x51, 0x23,
0x52, 0x45,
0x53, 0x67,
0x54, 0x89,
0x55, 0xAB,
0x56, 0xCD,
0x57, 0xEF,
0x41, 0x00,
0x40, 0x01,

0x01, 0x04,
0x34, 0x00, // gain control begin
0x00, 0x22,
0x00, 0x02,
0x07, 0x0A,
0x08, 0x08,
0x0E, 0x08,
0x14, 0x08,
0x1A, 0x08, // gain control end

0x34, 0x03
};

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

#define NXU8010_DRVNAME				"nxu8010"
#define NXU8010_SLAVE_ADDR           0x44

// Slave Address by SLADR
// SLADR <== Floating -> 0x44
// SLADR <== GND --> 0x0E
// SLADR <== VCC --> 0x0D

#define NXU8010_DEBUG
#ifdef NXU8010_DEBUG
//#define NXU8010DB printk
#define NXU8010DB(fmt, args...) pr_err(fmt, ##args)

#else
#define NXU8010DB(x, ...)
#endif

extern struct platform_driver g_nxu8010_driver;

static struct i2c_board_info __initdata nxu8010_board_info = { I2C_BOARD_INFO("nxu8010", NXU8010_SLAVE_ADDR) };
static struct mutex nxu8010_mutex;

static int nxu8010_i2c_probe(struct i2c_client *client, const struct i2c_device_id *id);
static int nxu8010_i2c_remove(struct i2c_client *client);
static int nxu8010_init(void);

static const struct i2c_device_id nxu8010_i2c_id[] = { {NXU8010_DRVNAME, 0}, {"", 0} };
//add for dts load
static const struct of_device_id nxu8010_als_of_match[] = {
    { .compatible = "nxu8010"},
    { }
};

static struct nxu8010_data *nxu_data;

static int nxu8010_read2(u8 addr, u8 *values)
{
	u8 pBuff[3];

	int ret = 0;

	mutex_lock(&nxu8010_mutex);
	nxu_data->client->addr = NXU8010_SLAVE_ADDR;

	pBuff[0] = addr;

	ret = i2c_master_send(nxu_data->client, pBuff, 1);

	if (ret < 0) {
		NXU8010DB("[NXU8010] i2c send failed!!\n");
		mutex_unlock(&nxu8010_mutex);
		return -1;
	}
	ret = i2c_master_recv(nxu_data->client, &pBuff[1], 2); // 2 bytes

	if (ret < 0) {
		mutex_unlock(&nxu8010_mutex);
		NXU8010DB("[NXU8010] i2c recv failed!!\n");
		return -1;
	}

	// i2c data
	values[0] = pBuff[1];
	values[1] = pBuff[2];

	mutex_unlock(&nxu8010_mutex);

	//NXU8010DB("[nxu8010] nxu8010_read: address=0x%02x value=0x%02x\n", pBuff[0], pBuff[1]);

	return 0;
}

// i2c read
// addr : i2c register address
// value : i2c register value
static int nxu8010_read(u8 addr, u8 *value)
{
	u8 pBuff[2];

	int ret = 0;
	NXU8010_FUNC_ENTER();

	mutex_lock(&nxu8010_mutex);
	nxu_data->client->addr = NXU8010_SLAVE_ADDR;

	pBuff[0] = addr;

	ret = i2c_master_send(nxu_data->client, pBuff, 1);

	if (ret < 0) {
		NXU8010DB("[NXU8010] i2c send failed!!\n");
		mutex_unlock(&nxu8010_mutex);
		return -1;
	}
	ret = i2c_master_recv(nxu_data->client, &pBuff[1], 1);

	if (ret < 0) {
		mutex_unlock(&nxu8010_mutex);
		NXU8010DB("[NXU8010]  i2c recv failed!!\n");
		return -1;
	}

	// i2c data
	*value = pBuff[1];

	mutex_unlock(&nxu8010_mutex);

	//NXU8010DB("[NXU8010] nxu8010_read: address=0x%02x value=0x%02x\n", pBuff[0], pBuff[1]);
	NXU8010_FUNC_EXIT();

	return 0;
}

// i2c write
// addr : i2c register address
// value : i2c register value
static int nxu8010_write(u8 addr, u8 value)
{
	int ret = 0;
	u8 pBuff[2] = {0};

	mutex_lock(&nxu8010_mutex);
	nxu_data->client->addr = NXU8010_SLAVE_ADDR;

	pBuff[0] = addr;
	pBuff[1] = value;

	ret = i2c_master_send(nxu_data->client, pBuff, 2);

	if (ret < 0) {
		mutex_unlock(&nxu8010_mutex);
		NXU8010DB("[NXU8010] i2c send failed!!\n");
		return -1;
	}
	mutex_unlock(&nxu8010_mutex);

//	NXU8010DB("[nxu8010] nxu8010_write: address=0x%02x value=0x%02x\n", pBuff[0], pBuff[1]);
	return 0;
}

static int nxu8010_sleepMode(bool is_sleep)
{
	int ret = 0;
	int count = 0;

	if ( is_sleep ) {
		ret = nxu8010_write(0x34, 0x00); // ADC Off
		if( ret == -1 ) count++;
		ret = nxu8010_write(0x00, 0x22); // Sleep On
		if( ret == -1 ) count++;
		NXU8010DB("[NXU8010] Sleep (sleep mode start)\n");
	}
	else {
		ret = nxu8010_write(0x00, 0x02); // Sleep Off
		if( ret == -1 ) count++;
		//nxu8010_write(0x34, 0x00); // ADC On
		NXU8010DB("[NXU8010] Wake-Up (sleep mode stop)\n");
	}

	return count;
}

static int nxu8010_level(int level)
{
	int ret = 0;
	int count = 0;

	ret = nxu8010_write(0x34, 0x00); // ADC Off
	if( ret == -1 ) count++;

	switch (level) {

	case 1:
		ret = nxu8010_write(0x00, 0x22);
		if( ret == -1 ) count++;
		ret = nxu8010_write(0x00, 0x02);
		if( ret == -1 ) count++;
		ret = nxu8010_write(0x07, 0x0A);
		if( ret == -1 ) count++;
		ret = nxu8010_write(0x08, 0x08);
		if( ret == -1 ) count++;
		ret = nxu8010_write(0x0E, 0x08);
		if( ret == -1 ) count++;
		ret = nxu8010_write(0x14, 0x08);
		if( ret == -1 ) count++;
		ret = nxu8010_write(0x1A, 0x08);
		if( ret == -1 ) count++;
		break;


	case 2:
		ret = nxu8010_write(0x00, 0x22);
		if( ret == -1 ) count++;
		ret = nxu8010_write(0x00, 0x02);
		if( ret == -1 ) count++;
		ret = nxu8010_write(0x07, 0x05);
		if( ret == -1 ) count++;
		ret = nxu8010_write(0x08, 0x05);
		if( ret == -1 ) count++;
		ret = nxu8010_write(0x0E, 0x05);
		if( ret == -1 ) count++;
		ret = nxu8010_write(0x14, 0x05);
		if( ret == -1 ) count++;
		ret = nxu8010_write(0x1A, 0x05);
		if( ret == -1 ) count++;
	    break;
	} // swtich

	ret = nxu8010_write(0x34, 0x03);  // ADC On
	if( ret == -1 ) count++;

	return count;
}

// nxu8010 initializing
// set initial register
static int nxu8010_init(void)
{
    int check = 0;
    int i;
    int count = sizeof(NXU8010_RGBW_INIT_DATA) / sizeof(u8) / 2;
    u8 reg_addr = 0, reg_val = 0;
    NXU8010_FUNC_ENTER();

    for(i = 0; i < count; ++i) {
        reg_addr = NXU8010_RGBW_INIT_DATA[i*2];
        reg_val = NXU8010_RGBW_INIT_DATA[i*2+1];

        if( nxu8010_write(reg_addr, reg_val) )  {
            NXU8010DB("[NXU8010] Error RGBW init...\n");
            check++;
        } // write register

    } // int i
    NXU8010_FUNC_EXIT();
    return check;
}

static ssize_t store_reg(struct device_driver *drv, const char *buf, size_t count)
{
///	int len = 0;
	int reg_addr = 0x0;
	int reg_val = 0x0;

	NXU8010DB("[NXU8010] store_reg=%s\n", buf);
	sscanf(buf, "0x%x 0x%x", &reg_addr, &reg_val);
	nxu8010_write((u8)reg_addr, (u8)reg_val);
	return count;
}

static ssize_t show_reg(struct device_driver *drv, char *buf)
{
	int ret = 0;
	int len = 0;
	NXU8010_FUNC_ENTER();

	ret = nxu8010_init();

	if(ret == 0)
	{
		len = snprintf(buf, 32, "Initialized...\n");
	}
	else
	{
		len = snprintf(buf, 32, "No Initialized...\n");
	}
	NXU8010_FUNC_EXIT();
	return len;
}


static int gRegValueAddr = 0;
static ssize_t store_regvalue(struct device_driver *drv, const char *buf, size_t count)
{
///	int len = 0;
	int reg_addr = 0x0;

	NXU8010DB("[NXU8010] store_regvalue=%s\n", buf);
	sscanf(buf, "0x%x", &reg_addr);
	//nxu8010_write((u8)reg_addr, (u8)reg_val);
	gRegValueAddr = reg_addr;

	return count;
}

static ssize_t show_regvalue(struct device_driver *drv, char *buf)
{
	int len = 0;
	u8 read_buf = 0;
	NXU8010_FUNC_ENTER();

	nxu8010_read((u8)gRegValueAddr, &read_buf);

	len = snprintf(buf, 128, "Read Register addr=0x%02x, value=0x%02x\n", gRegValueAddr, (int)read_buf);
	NXU8010_FUNC_EXIT();
	return len;
}

static ssize_t show_level1(struct device_driver *drv, char *buf)
{
	int ret = 0;
	int len = 0;
	NXU8010_FUNC_ENTER();

	ret = nxu8010_level(1);

	if(ret == 0)
	{
		len = snprintf(buf, 16, "Level1\n");
	}
	else
	{
		len = snprintf(buf, 16, "No Level1\n");
	}
	NXU8010_FUNC_EXIT();
	return len;
}

static ssize_t show_level2(struct device_driver *drv, char *buf)
{
	int ret = 0;
	int len = 0;
	NXU8010_FUNC_ENTER();

	ret = nxu8010_level(2);

	if(ret == 0)
	{
		len = snprintf(buf, 16, "Level2\n");
	}
	else
	{
		len = snprintf(buf, 16, "No Level2\n");
	}
	NXU8010_FUNC_EXIT();
	return len;
}

static int nxu8010_power_up(struct nxu8010_data *data)
{
    int rc;

    NXU8010_FUNC_ENTER();

    data->vdd = regulator_get(&data->client->dev, "vdd");
    if (IS_ERR(data->vdd))
    {
        rc = PTR_ERR(data->vdd);
        NXU8010DB("[NXU8010] Regulator get failed vdd rc=%d", rc);
    }

    if (regulator_count_voltages(data->vdd) > 0)
    {
        rc = regulator_set_voltage(data->vdd, NXU8010_VTG_MIN_UV, NXU8010_VTG_MAX_UV);
        if (rc)
        {
            NXU8010DB("[NXU8010] Regulator set_vtg failed vdd rc=%d", rc);
            goto reg_vdd_put;
        }
    }

    rc = regulator_enable(data->vdd);
    if (rc) {
        NXU8010DB("[NXU8010] Regulator vdd enable failed rc=%d", rc);
    }

    NXU8010_FUNC_EXIT();
    return 0;

reg_vdd_put:
    regulator_put(data->vdd);
    NXU8010_FUNC_EXIT();
    return rc;
}

static int nxu8010_power_down(struct nxu8010_data *data)
{
    int rc;
    NXU8010_FUNC_ENTER();
    rc = regulator_disable(data->vdd);
    if (rc) {
        NXU8010DB("[NXU8010] Regulator vdd disable failed rc=%d", rc);
    }
    regulator_set_voltage(
        data->vdd, 0, NXU8010_VTG_MAX_UV);
    regulator_put(data->vdd);
    data->vdd = NULL;
    NXU8010_FUNC_EXIT();
    return rc;
}

static ssize_t show_values(struct device_driver *drv, char *buf)
{
	u8 read_buf[2] = {0,};
	int len = 0;
	int values[4] = {0,};
	int ret_low = 0, ret_high = 0;
	int ret = 0, i = 0;

	NXU8010_FUNC_ENTER();

	for (i = 0;i < NXU8010_RGBW_RETRY_TIMES;i++) {
		/* Power Up */
		nxu8010_power_up(nxu_data);
		msleep(20);
		ret = nxu8010_init();
		if(ret != 0){
			NXU8010DB("[NXU8010] init failed(%d)\n", i+1);
			nxu8010_power_down(nxu_data);
			ret = -1;
			continue;
		}
		msleep(500);
		/* Read R Data */
		ret_low = nxu8010_read(R_LOW_DATA, &read_buf[0]);
		ret_high = nxu8010_read(R_HIGH_DATA, &read_buf[1]);
		if ((0 == ret_low && 0 == ret_high) && (read_buf[0] || read_buf[1]))
			values[0] = read_buf[0] | (read_buf[1] << 8);
		else{
			NXU8010DB("[NXU8010] Fail to read R value(%d)\n", i+1);
			nxu8010_power_down(nxu_data);
			ret = -1;
			continue;
		}
		/* Read G Data */
		ret_low = nxu8010_read(G_LOW_DATA, &read_buf[0]);
		ret_high = nxu8010_read(G_HIGH_DATA, &read_buf[1]);
		if ((0 == ret_low && 0 == ret_high) && (read_buf[0] || read_buf[1]))
			values[1] = read_buf[0] | (read_buf[1] << 8);
		else{
			NXU8010DB("[NXU8010] Fail to read G value(%d)\n", i+1);
			nxu8010_power_down(nxu_data);
			ret = -1;
			continue;
		}
		/* Read B Data */
		ret_low = nxu8010_read(B_LOW_DATA, &read_buf[0]);
		ret_high = nxu8010_read(B_HIGH_DATA, &read_buf[1]);
		if ((0 == ret_low && 0 == ret_high) && (read_buf[0] || read_buf[1]))
			values[2] = read_buf[0] | (read_buf[1] << 8);
		else{
			NXU8010DB("[NXU8010] Fail to read B value(%d)\n", i+1);
			nxu8010_power_down(nxu_data);
			ret = -1;
			continue;
		}
		/* Read W Data */
		ret_low = nxu8010_read(W_LOW_DATA, &read_buf[0]);
		ret_high = nxu8010_read(W_HIGH_DATA, &read_buf[1]);
		if ((0 == ret_low && 0 == ret_high) && (read_buf[0] || read_buf[1]))
			values[3] = read_buf[0] | (read_buf[1] << 8);
		else{
			NXU8010DB("[NXU8010] Fail to read W value(%d)\n", i+1);
			nxu8010_power_down(nxu_data);
			ret = -1;
			continue;
		}
		NXU8010DB("[NXU8010] Succeed to Read RGBW data(%d %d %d %d)\n",
			values[0], values[1], values[2], values[3]);
		/* Power Down */
		nxu8010_power_down(nxu_data);
		ret = 0;
		break;
	}

	if (ret != 0 || (values[1] >= values[3]))
		len = snprintf(buf, 32, "-1 -1 -1 -1\n");
	else
		len = snprintf(buf, 64, "%d %d %d %d\n",
			values[0], values[1], values[2], values[3]);
	NXU8010_FUNC_EXIT();
	return len;
}

static ssize_t show_poweron(struct device_driver *drv, char *buf)
{
	int ret = 0, i = 0, len = 0;

	NXU8010_FUNC_ENTER();

	for (i = 0;i < NXU8010_RGBW_RETRY_TIMES;i++) {
		/* Power Up */
		nxu8010_power_up(nxu_data);
		msleep(20);
		ret = nxu8010_init();
		if(ret != 0){
			NXU8010DB("[NXU8010] init failed(%d)\n", i+1);
			nxu8010_power_down(nxu_data);
			ret = 0;
			continue;
		}
		ret = 1;
		break;
	}

	NXU8010_FUNC_EXIT();
	NXU8010DB("[NXU8010] RGBW power on %d(1:Pass 0:Fail)\n", ret);
	len = snprintf(buf, 32, "%d\n", ret);
	return len;
}

static ssize_t show_poweroff(struct device_driver *drv, char *buf)
{
	int len = 0;
	NXU8010_FUNC_ENTER();

	nxu8010_power_down(nxu_data);

	NXU8010_FUNC_EXIT();
	NXU8010DB("[NXU8010] RGBW power off\n");
	len = snprintf(buf, 32, "1\n");
	return len;
}

static ssize_t show_readdata(struct device_driver *drv, char *buf)
{
	u8 read_buf[2] = {0,};
	int len = 0;
	int values[4] = {0,};
	int ret_low = 0, ret_high = 0;

	NXU8010_FUNC_ENTER();

	/* Read R Data */
	ret_low = nxu8010_read(R_LOW_DATA, &read_buf[0]);
	ret_high = nxu8010_read(R_HIGH_DATA, &read_buf[1]);
	if (0 == ret_low && 0 == ret_high)
		values[0] = read_buf[0] | (read_buf[1] << 8);
	else{
		NXU8010DB("[NXU8010] Fail to read R value\n");
		goto read_data_failed;
	}

	/* Read G Data */
	ret_low = nxu8010_read(G_LOW_DATA, &read_buf[0]);
	ret_high = nxu8010_read(G_HIGH_DATA, &read_buf[1]);
	if (0 == ret_low && 0 == ret_high)
		values[1] = read_buf[0] | (read_buf[1] << 8);
	else{
		NXU8010DB("[NXU8010] Fail to read G value\n");
		goto read_data_failed;
	}

	/* Read B Data */
	ret_low = nxu8010_read(B_LOW_DATA, &read_buf[0]);
	ret_high = nxu8010_read(B_HIGH_DATA, &read_buf[1]);
	if (0 == ret_low && 0 == ret_high)
		values[2] = read_buf[0] | (read_buf[1] << 8);
	else{
		NXU8010DB("[NXU8010] Fail to read B value\n");
		goto read_data_failed;
	}

	/* Read W Data */
	ret_low = nxu8010_read(W_LOW_DATA, &read_buf[0]);
	ret_high = nxu8010_read(W_HIGH_DATA, &read_buf[1]);
	if (0 == ret_low && 0 == ret_high)
		values[3] = read_buf[0] | (read_buf[1] << 8);
	else{
		NXU8010DB("[NXU8010] Fail to read W value\n");
		goto read_data_failed;
	}

	NXU8010DB("[NXU8010] Succeed to Read RGBW data(%d %d %d %d)\n",
		values[0], values[1], values[2], values[3]);
	len = snprintf(buf, 64, "%d %d %d %d\n",
		values[0], values[1], values[2], values[3]);
	NXU8010_FUNC_EXIT();
	return len;
read_data_failed:
	NXU8010DB("[NXU8010] Failed to Read RGBW data(%d %d %d %d)\n",
		values[0], values[1], values[2], values[3]);
	len = snprintf(buf, 32, "-1 -1 -1 -1\n");
	NXU8010_FUNC_EXIT();
	return len;
}

static ssize_t show_values2(struct device_driver *drv, char *buf)
{
	u8 read_buf[2] = {0,};
	int len = 0;
	int values[4] = {0,};
	int ret = 0;

	ret = nxu8010_read2(R_LOW_DATA, read_buf);
	if ( 0 == ret )
		values[0] = read_buf[0] | (read_buf[1] << 8);
	else values[0] = -1;

	ret = nxu8010_read2(G_LOW_DATA, read_buf);
	if ( 0 == ret )
		values[1] = read_buf[0] | (read_buf[1] << 8);
	else values[1] = -1;

	ret = nxu8010_read2(B_LOW_DATA, read_buf);
	if ( 0 == ret )
		values[2] = read_buf[0] | (read_buf[1] << 8);
	else values[2] = -1;

	ret = nxu8010_read2(W_LOW_DATA, read_buf);
	if ( 0 == ret )
		values[3] = read_buf[0] | (read_buf[1] << 8);
	else values[3] = -1;

	//NXU8010DB("[NXU8010] show_values values=%d %d %d %d\n",
	//				values[0], values[1], values[2], values[3]);

	len = snprintf(buf, 64, "%d %d %d %d\n",
					values[0], values[1], values[2], values[3]);

	return len;
}

static ssize_t show_chipid(struct device_driver *drv, char *buf)
{
	u8 read_buf = 0;
	int ret = 0, i = 0, len = 0;

	NXU8010_FUNC_ENTER();

	for (i = 0;i < NXU8010_RGBW_RETRY_TIMES;i++) {
		/* Power Up */
		ret = nxu8010_power_up(nxu_data);
		if(ret != 0){
			NXU8010DB("[NXU8010] power up failed(%d)\n", i+1);
			ret = 0;
			continue;
		}
		msleep(20);
		ret = nxu8010_init();
		if(ret != 0){
			NXU8010DB("[NXU8010] init failed(%d)\n", i+1);
			nxu8010_power_down(nxu_data);
			ret = 0;
			continue;
		}
		ret = 1;
		break;
	}
	if (ret == 1) {
		nxu8010_read(CORRELATION_CODE, &read_buf);
		NXU8010DB("[NXU8010] chipid %02x\n", (int)read_buf);
		len = snprintf(buf, 16, "%d\n", (int)read_buf);
	} else {
		NXU8010DB("[NXU8010] read chipid failed\n");
		len = snprintf(buf, 16, "-1\n");
	}
	nxu8010_power_down(nxu_data);
	return len;
}

static ssize_t show_code(struct device_driver *drv, char *buf)
{
	u8 read_buf = 0;
	int len = 0;
	nxu8010_read(CORRELATION_CODE, &read_buf);

	NXU8010DB("[NXU8010] show_code 0x%02x\n", (int)read_buf);

	len = snprintf(buf, 16, "0x%02x\n", (int)read_buf);

	return len;
}

static ssize_t show_sleep(struct device_driver *drv, char *buf)
{
	int ret = 0;
	int len = 0;
	NXU8010_FUNC_ENTER();

	ret = nxu8010_sleepMode(true);

	if(ret == 0)
	{
		len = snprintf(buf, 16, "sleep\n");
	}
	else
	{
		len = snprintf(buf, 16, "No sleep\n");
	}
	NXU8010_FUNC_EXIT();
	return len;
}

static ssize_t show_awake(struct device_driver *drv, char *buf)
{
	int ret = 0;
	int len = 0;
	NXU8010_FUNC_ENTER();

	ret = nxu8010_sleepMode(false);

	if(ret == 0)
	{
		len = snprintf(buf, 16, "awake\n");
	}
	else
	{
		len = snprintf(buf, 16, "No awake\n");
	}
	NXU8010_FUNC_EXIT();
	return len;
}

static ssize_t show_adcon(struct device_driver *drv, char *buf)
{
	int ret = 0;
	int len = 0;
	NXU8010_FUNC_ENTER();

	ret = nxu8010_write(0x34, 0x03);

	if(ret == 0)
	{
		len = snprintf(buf, 16, "adcon\n");
	}
	else
	{
		len = snprintf(buf, 16, "No adcon\n");
	}
	NXU8010_FUNC_EXIT();
	return len;
}

static ssize_t show_adcoff(struct device_driver *drv, char *buf)
{
	int ret = 0;
	int len = 0;
	NXU8010_FUNC_ENTER();

	ret = nxu8010_write(0x34, 0x00);

	if(ret == 0)
	{
		len = snprintf(buf, 16, "adcoff\n");
	}
	else
	{
		len = snprintf(buf, 16, "No adcoff\n");
	}
	NXU8010_FUNC_EXIT();
	return len;
}


static ssize_t show_fastmmi(struct device_driver *drv, char *buf)
{
	u8 read_buf = 0;
	int len = 0;
	NXU8010_FUNC_ENTER();
	nxu8010_init();
	nxu8010_read(0x06, &read_buf);

	NXU8010DB("[NXU8010] show_code 0x%02x\n", (int)read_buf);

	len = snprintf(buf, 16, "0x%02x\n", (int)read_buf);
	NXU8010_FUNC_EXIT();
	return len;
}

static DRIVER_ATTR(reg, S_IWUSR | S_IRUGO, show_reg, store_reg);
static DRIVER_ATTR(regvalue, S_IWUSR | S_IRUGO, show_regvalue, store_regvalue);

static DRIVER_ATTR(level1, S_IWUSR | S_IRUGO, show_level1, NULL);
static DRIVER_ATTR(level2, S_IWUSR | S_IRUGO, show_level2, NULL);

static DRIVER_ATTR(values, S_IWUSR | S_IRUGO, show_values, NULL);
static DRIVER_ATTR(values2, S_IWUSR | S_IRUGO, show_values2, NULL);

static DRIVER_ATTR(chipid, S_IWUSR | S_IRUGO, show_chipid, NULL);

static DRIVER_ATTR(poweron, S_IWUSR | S_IRUGO, show_poweron, NULL);
static DRIVER_ATTR(readdata, S_IWUSR | S_IRUGO, show_readdata, NULL);
static DRIVER_ATTR(poweroff, S_IWUSR | S_IRUGO, show_poweroff, NULL);

static DRIVER_ATTR(code, S_IWUSR | S_IRUGO, show_code, NULL);
static DRIVER_ATTR(sleep, S_IWUSR | S_IRUGO, show_sleep, NULL);
static DRIVER_ATTR(awake, S_IWUSR | S_IRUGO, show_awake, NULL);
static DRIVER_ATTR(adcon, S_IWUSR | S_IRUGO, show_adcon, NULL);
static DRIVER_ATTR(adcoff, S_IWUSR | S_IRUGO, show_adcoff, NULL);
static DRIVER_ATTR(fastmmi, S_IWUSR | S_IRUGO, show_fastmmi, NULL);

#define NXU8010_IOCTL_INIT				_IO('n', 0x01)
#define NXU8010_IOCTL_G_DATA			_IOR('n', 0x02, unsigned char)
#define NXU8010_IOCTL_G_CHIPID			_IOR('n', 0x03,GET_NEXU8010_DATA)

static int nxu8010_read_chipid(char *buf)
{
	u8 read_buf = 0;
	unsigned int chip_id = 0;
	nxu8010_read(CORRELATION_CODE, &read_buf);

	NXU8010DB("[NXU8010] get chipid 0x%02x\n", (int)read_buf);
	chip_id = (int)read_buf;
	return chip_id;
}

static void nxu8010_read_data(GET_NEXU8010_DATA *get_data)

{
	u8 read_buf[2] = {0,};
	int values[4] = {0,};

	nxu8010_read(R_LOW_DATA, &read_buf[0]);
	nxu8010_read(R_HIGH_DATA, &read_buf[1]);
	values[0] = read_buf[0] | (read_buf[1] << 8);

	nxu8010_read(G_LOW_DATA, &read_buf[0]);
	nxu8010_read(G_HIGH_DATA, &read_buf[1]);
	values[1] = read_buf[0] | (read_buf[1] << 8);

	nxu8010_read(B_LOW_DATA, &read_buf[0]);
	nxu8010_read(B_HIGH_DATA, &read_buf[1]);
	values[2] = read_buf[0] | (read_buf[1] << 8);

	nxu8010_read(W_LOW_DATA, &read_buf[0]);
	nxu8010_read(W_HIGH_DATA, &read_buf[1]);
	values[3] = read_buf[0] | (read_buf[1] << 8);

	NXU8010DB("[NXU8010] values= R:%d G: %d B: %d W:%d\n",
					values[0], values[1], values[2], values[3]);

	get_data->r_data = values[0];
	get_data->g_data = values[1];
	get_data->b_data = values[2];
	get_data->w_data = values[3];
}

static int nxu8010_ioctl_handler(struct file *file,
			unsigned int cmd, unsigned long arg,
			void __user *p)
{

	char *r_buf;
	unsigned char chip_id;
	GET_NEXU8010_DATA get_data;
    switch(cmd) {
    case NXU8010_IOCTL_INIT:
		NXU8010DB("NXU8010_IOCTL_INIT \n");
		nxu8010_init();
		break;
    case NXU8010_IOCTL_G_DATA:
		NXU8010DB("NXU8010_IOCTL_G_DATA \n");
		nxu8010_read_data(&get_data);
		NXU8010DB("R: %d, G: %d, B: %d W: %d \n",get_data.r_data,get_data.g_data,get_data.b_data,get_data.w_data);
		if (copy_to_user((GET_NEXU8010_DATA *)p, &get_data,sizeof(GET_NEXU8010_DATA))) {
			return -EFAULT;
		}
		break;
	case NXU8010_IOCTL_G_CHIPID:
		NXU8010DB("NXU8010_IOCTL_G_CHIPID \n");
		chip_id = nxu8010_read_chipid(r_buf);
		NXU8010DB("NXU8010 chip_id:%d\n",chip_id);
		if (copy_to_user((unsigned char *)p, &chip_id,sizeof(unsigned char))) {
			return -EFAULT;
		}
		break;
    default:
        break;
    }
	return 0;
}

static long nxu8010_ioctl(struct file *file,
				unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct nxu8010_data *data =
			container_of(file->private_data,
					struct nxu8010_data, miscdev);

	if(data)
		mutex_lock(&data->work_mutex);
	else
		pr_err("nxu8010_ioctl NULL  ");
	ret = nxu8010_ioctl_handler(file, cmd, arg, (void __user *)arg);
	if(data)

	mutex_unlock(&data->work_mutex);
	else
		pr_err("nxu8010_ioctl NULL ");

	return ret;
}

static int nxu8010_open(struct inode *inode, struct file *file)
{
	return 0;
}

static struct file_operations nxu8010_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = nxu8010_ioctl,
    .open	= nxu8010_open,
};

static int nxu8010_i2c_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
	int ret_driver_file = 0;

	NXU8010_FUNC_ENTER();
	nxu_data = kzalloc(sizeof(struct nxu8010_data), GFP_KERNEL);
	nxu_data->client = client;

	mutex_init(&nxu8010_mutex);

	ret_driver_file = driver_create_file(&(g_nxu8010_driver.driver), &driver_attr_reg);
	ret_driver_file = driver_create_file(&(g_nxu8010_driver.driver), &driver_attr_regvalue);

	ret_driver_file = driver_create_file(&(g_nxu8010_driver.driver), &driver_attr_level1);
	ret_driver_file = driver_create_file(&(g_nxu8010_driver.driver), &driver_attr_level2);

	ret_driver_file = driver_create_file(&(g_nxu8010_driver.driver), &driver_attr_values);
	ret_driver_file = driver_create_file(&(g_nxu8010_driver.driver), &driver_attr_values2);

	ret_driver_file = driver_create_file(&(g_nxu8010_driver.driver), &driver_attr_chipid);
	ret_driver_file = driver_create_file(&(g_nxu8010_driver.driver), &driver_attr_poweron);
	ret_driver_file = driver_create_file(&(g_nxu8010_driver.driver), &driver_attr_readdata);
	ret_driver_file = driver_create_file(&(g_nxu8010_driver.driver), &driver_attr_poweroff);

	ret_driver_file = driver_create_file(&(g_nxu8010_driver.driver), &driver_attr_code);
	ret_driver_file = driver_create_file(&(g_nxu8010_driver.driver), &driver_attr_sleep);
	ret_driver_file = driver_create_file(&(g_nxu8010_driver.driver), &driver_attr_awake);

	ret_driver_file = driver_create_file(&(g_nxu8010_driver.driver), &driver_attr_adcon);
	ret_driver_file = driver_create_file(&(g_nxu8010_driver.driver), &driver_attr_adcoff);

	ret_driver_file = driver_create_file(&(g_nxu8010_driver.driver), &driver_attr_fastmmi);

	mutex_init(&nxu_data->work_mutex);
	nxu_data->miscdev.minor = MISC_DYNAMIC_MINOR;
	nxu_data->miscdev.name = "nxu8010_dev";
	nxu_data->miscdev.fops = &nxu8010_fops;

	if (misc_register(&nxu_data->miscdev) != 0)
		pr_err("cannot register misc devices\n");

	NXU8010_FUNC_EXIT();

	return 0;
}

static int nxu8010_i2c_remove(struct i2c_client *client)
{
	return 0;
}

//MODULE_DEVICE_TABLE(i2c, nxu8010_i2c_id);

#ifndef WIN32
struct i2c_driver nxu8010_i2c_driver = {
	.probe = nxu8010_i2c_probe,
	.remove = nxu8010_i2c_remove,
	.driver.name = NXU8010_DRVNAME,
	.id_table = nxu8010_i2c_id,
};
#else
struct i2c_driver nxu8010_i2c_driver = {nxu8010_i2c_probe, nxu8010_i2c_remove};
#endif // WIN32



static int nxu8010_probe(struct platform_device *pdev)
{
	int rc;

	NXU8010_FUNC_ENTER();
	rc = i2c_add_driver(&nxu8010_i2c_driver);
	if (rc)
		pr_err("[NXU8010] %d erro ret:%d\n", __LINE__, rc);
	NXU8010_FUNC_EXIT();
	return 0;
}

static int nxu8010_remove(struct platform_device *pdev)
{
	i2c_del_driver(&nxu8010_i2c_driver);
	return 0;
}

static int nxu8010_suspend(struct platform_device *pdev, pm_message_t mesg)
{
	return 0;
}

static int nxu8010_resume(struct platform_device *pdev)
{
	return 0;
}

/* platform structure */
#ifndef WIN32
 struct platform_driver g_nxu8010_driver = {
	.probe = nxu8010_probe,
	.remove = nxu8010_remove,
	.suspend = nxu8010_suspend,
	.resume = nxu8010_resume,
	.driver = {
		   .name = "nxu8010",
		   .owner = THIS_MODULE,
		   .of_match_table = of_match_ptr(nxu8010_als_of_match),
	},
};

 struct platform_device g_nxu8010_device = {
    .name = "nxu8010",
    .id = 0,
    .dev = {}
};
#else
static struct platform_driver g_nxu8010_driver = {nxu8010_probe, nxu8010_remove, {"nxu8010", THIS_MODULE}};
static struct platform_device g_nxu8010_device;
#endif // WIN32

static int __init nxu8010_i2c_init(void)
{
	NXU8010_FUNC_ENTER();
	i2c_register_board_info(LENS_I2C_BUSNUM, &nxu8010_board_info, 1);
	if(platform_device_register(&g_nxu8010_device)){
		NXU8010DB("[NXU8010] failed to register nxu8010 device\n");
		return -ENODEV;
	}
	if (platform_driver_register(&g_nxu8010_driver)) {
		NXU8010DB("[NXU8010] failed to register nxu8010 driver\n");
		return -ENODEV;
	}
	NXU8010_FUNC_EXIT();
	return 0;
}

static void __exit nxu8010_i2c_exit(void)
{
	platform_driver_unregister(&g_nxu8010_driver);
}

module_init(nxu8010_i2c_init);
module_exit(nxu8010_i2c_exit);
