/**
 * @file   idtp9220.c
 * @author  <roy@ROY-PC>
 * @date   Sun Nov 22 11:50:06 2015
 * 
 * @brief  
 * 
 * 
 */
#include <linux/types.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/i2c.h>
#include <linux/workqueue.h>
#include <linux/sysfs.h>
#include <linux/of_gpio.h>
#include <linux/gpio.h>
#include <linux/regulator/consumer.h>
#include <linux/timer.h>

//#include <asm/unaligned.h>

#include <smartisan/hwstate.h>
#include "idtp9220.h"

#define I2C_MASTER_CLOCK 100
static int Xfer9220i2c(u8 i2cAddr, ushort reg, uint page, char *bBuf, int bOffs, int bSize);

struct idtp9220_device_info *g_di;
static int program_fw(char *srcData, int srcOffs, int size);
static int program_bootloader(struct idtp9220_device_info *di);

static u16 p9221_reg;
static struct mutex mutex;

static struct idtp9220_platform_data idtp9220_pdata = {
	.vout_val_default    = VOUT_VAL_5000_MV,
	.curr_val_default    = CURR_VAL_1300_MA,
};

struct idtp9220_access_func {
	unsigned char (*read)(struct idtp9220_device_info *di, u16 reg);
	int (*write)(struct idtp9220_device_info *di, u8 val, u16 reg);
};

struct idtp9220_device_info {
	int chip_enable;
	char *name;
	struct device *dev;
	struct idtp9220_platform_data *pdata;
	struct idtp9220_access_func bus;
	struct workqueue_struct *wq;
	struct delayed_work dwork;
};

static void show_stored_vout_val(struct idtp9220_device_info *di, int index)
{
	struct vol_curr_table voltage_table[] = {
		{ VOUT_VAL_3500_MV, "3500MV" },
		{ VOUT_VAL_3600_MV, "3600MV" },
		{ VOUT_VAL_3700_MV, "3700MV" },
		{ VOUT_VAL_3800_MV, "3800MV" },
		{ VOUT_VAL_3900_MV, "3900MV" },
		{ VOUT_VAL_4000_MV, "4000MV" },
		{ VOUT_VAL_4100_MV, "4100MV" },
		{ VOUT_VAL_4200_MV, "4200MV" },
		{ VOUT_VAL_4300_MV, "4300MV" },
		{ VOUT_VAL_4400_MV, "4400MV" },
		{ VOUT_VAL_4500_MV, "4500MV" },
		{ VOUT_VAL_4600_MV, "4600MV" },
		{ VOUT_VAL_4700_MV, "4700MV" },
		{ VOUT_VAL_4800_MV, "4800MV" },
		{ VOUT_VAL_4900_MV, "4900MV" },
		{ VOUT_VAL_5000_MV, "5000MV" },
	};

	dev_err(di->dev, "Store Voltage Index:%d Value:%s", index, voltage_table[index].val);
}

static void show_stored_current_val(struct idtp9220_device_info *di, unsigned int index)
{
	struct vol_curr_table curr_table[] = {
		{ CURR_VAL_100_MA, "100MA" },
		{ CURR_VAL_200_MA, "200MA" },
		{ CURR_VAL_300_MA, "300MA" },
		{ CURR_VAL_400_MA, "400MA" },
		{ CURR_VAL_500_MA, "500MA" },
		{ CURR_VAL_600_MA, "600MA" },
		{ CURR_VAL_700_MA, "700MA" },
		{ CURR_VAL_800_MA, "800MA" },
		{ CURR_VAL_900_MA, "900MA" },
		{ CURR_VAL_1000_MA, "1000MA" },
		{ CURR_VAL_1100_MA, "1100MA" },
		{ CURR_VAL_1200_MA, "1200MA" },
		{ CURR_VAL_1300_MA, "1300MA" },
	};

	dev_err(di->dev, "Store Current Index:%d Value:%s\n", index, curr_table[index].val);
}
#if 0
static unsigned char idtp9220_read_ram(struct idtp9220_device_info *di, u16 reg)
{
	struct i2c_client *client = to_i2c_client(di->dev);
	struct i2c_msg msg[2];
	u16 reg_be = cpu_to_be16(reg);
	u8 ret = 0;
	u8 data[1];

	memset(msg, 0, sizeof(msg));

	if (!client->adapter)
		return -ENODEV;

	msg[0].addr = client->addr;
	msg[0].flags = 0;
	msg[0].buf = &reg_be;
	msg[0].len = sizeof(reg_be);
	//msg[0].timing = I2C_MASTER_CLOCK;
	msg[1].addr = client->addr;
	msg[1].flags = I2C_M_RD;
	msg[1].buf = &data;
	msg[1].len = 1;
	//msg[1].timing = I2C_MASTER_CLOCK;

	ret = i2c_transfer(client->adapter, msg, ARRAY_SIZE(msg));
	if (ret < 0) {
		dev_err(di->dev, "I2c read failed!\n");
		return ret;
	}

	dev_err(di->dev, "read reg[%04x] 16bits data:%02x\n guess you need high bits:%02x\n",
			reg, *(u8 *)data, data[0]);

	ret = data[0];

	return ret;
}

#endif

static unsigned char idtp9220_read(struct idtp9220_device_info *di, u16 reg)
{
	struct i2c_client *client = to_i2c_client(di->dev);
	struct i2c_msg msg[2];
	//u8 reg_be = (u8) (reg & 0x00ff);
	u8 ret = 0;
	u8 data[2];
	u8 rec;

	data[0] = reg >> 8;
	data[1] = reg & 0xff;

	memset(msg, 0, sizeof(msg));

	if (!client->adapter)
		return -ENODEV;

	msg[0].addr = client->addr;
	msg[0].flags = 0;
	msg[0].buf = data;
	msg[0].len = sizeof(data);
	//msg[0].timing = I2C_MASTER_CLOCK;
	msg[1].addr = client->addr;
	msg[1].flags = I2C_M_RD;
	msg[1].buf = &rec;
	msg[1].len = 1;
	//msg[1].timing = I2C_MASTER_CLOCK;

	ret = i2c_transfer(client->adapter, msg, ARRAY_SIZE(msg));
	if (ret < 0) {
		dev_err(di->dev, "I2c read failed!\n");
		return ret;
	}

	// dev_err(di->dev, "read reg[%04x] 16bits data:%04x\n guess you need high bits:%02x\n",reg, *(u16 *)data, data[1]);
	// dev_err(di->dev, "read reg[%04x] 8bits data:%02x \n",reg, rec);

	//ret = data[1];

	return rec;
}

int idtp9220_write(struct idtp9220_device_info *di, u8 val, u16 reg)
{
	struct i2c_client *client = to_i2c_client(di->dev);
	struct i2c_msg msg[1];
	u8 data[3];
	int ret;

	memset(msg, 0, sizeof(msg));

	data[0] = reg >> 8;
	data[1] = reg & 0xff;
	data[2] = val;

	msg[0].addr = client->addr;
	msg[0].flags = 0;
	msg[0].buf = data;
	msg[0].len = ARRAY_SIZE(data);
	//msg[0].timing = I2C_MASTER_CLOCK;

	ret = i2c_transfer(client->adapter, msg, ARRAY_SIZE(msg));

	if (ret < 0) {
		dev_err(di->dev, "I2C write failed!\n");
		return ret;
	}

	return true;

}

#if 0
static void idtp9220_chip_enable(struct idtp9220_device_info *di, bool enable)
{
	mt_set_gpio_mode(di->pdata->gpio_en, GPIO_MODE_00);
	mt_set_gpio_dir(di->pdata->gpio_en, GPIO_DIR_OUT);

	dev_err(di->dev, "set chip enable:%d\n", enable);

	if (enable) {
		di->chip_enable = true;
		mt_set_gpio_out(di->pdata->gpio_en, GPIO_OUT_ZERO);
	} else {
		di->chip_enable = false;
		mt_set_gpio_out(di->pdata->gpio_en, GPIO_OUT_ONE);
	}
}
#endif


#if 1
static void clritr(struct idtp9220_device_info *di,u8 s)
{
	idtp9220_write(di, s, REG_INT_CLEAR_L);
	idtp9220_write(di, 0x20, REG_COMMAND);
}

static int checkitr(struct idtp9220_device_info *di, u8 s)
{
	int t = 0;
	u8 tmp;
	while( (tmp = idtp9220_read(di,REG_INTR_L) & s) == 0)
	{
		//dev_err(di->dev, "%d \n",tmp);
		mdelay(200);
		t++;
		if (t == 10) {
			dev_err(di->dev, "Timeout...\n");
			return false;
		}
	}
	return true;
}

static void sendpkt(struct idtp9220_device_info *di, u8 cmd)
{
	idtp9220_write(di, 0x18, REG_PROPPKT);
	idtp9220_write(di, cmd, REG_PROPPKT+1);
	idtp9220_write(di, 1, REG_COMMAND);
}

static int receivepkt(struct idtp9220_device_info *di, u8 data[])
{
	u8 head = 0 , cmd = 0 ;
	if(checkitr(di, STATUS_TX_DATA_RECV)) {
		clritr(di, STATUS_TX_DATA_RECV);
		head = idtp9220_read(di, REG_BCHEADER);
		cmd = idtp9220_read(di, REG_BCCMD);

		data[0] =   idtp9220_read(di, REG_BCDATA);
		data[1] =   idtp9220_read(di, REG_BCDATA+1);
		//dev_err(di->dev, "head = %d, cmd = %d data = %02x %02x\n",head,cmd,data[0],data[1]);
		return 0;
	}
	return -1;
}

static ssize_t get_vin_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf,
		size_t count)
{
	return count;
}


static ssize_t get_vin_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	int ret, mv = 0;
	u8 data[4];
	struct i2c_client *client = container_of(dev, struct i2c_client, dev);
	struct idtp9220_device_info *di = i2c_get_clientdata(client);

	mutex_lock(&mutex);
	sendpkt(di, BC_READ_Vin);
	ret = receivepkt(di, data);
	if(ret >= 0) {
		mv = data[0]| data[1] << 8;
	}
	mutex_unlock(&mutex);
	if(data[1] != 0xff)
		return sprintf(buf, "vout:%d\n", mv);
	else
		return sprintf(buf, "error\n");
}

static ssize_t get_iin_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf,
		size_t count)
{
	return count;
}


static ssize_t get_iin_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	int ret, ma = 0;
	u8 data[4];
	struct i2c_client *client = container_of(dev, struct i2c_client, dev);
	struct idtp9220_device_info *di = i2c_get_clientdata(client);

	mutex_lock(&mutex);
	sendpkt(di, BC_READ_Iin);
	ret = receivepkt(di, data);
	if(ret >= 0) {
		ma = data[0]| data[1] << 8;
	}
	mutex_unlock(&mutex);
	if(data[1] != 0xff)
		return sprintf(buf, "iout:%dMA\n", ma);
	else
		return sprintf(buf, "error\n");
}

static ssize_t get_efficiency_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf,
		size_t count)
{
	return count;
}


static ssize_t get_efficiency_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	int ret, iin = 0, vin = 0, iout = 0, vout = 0;
	u8 data[4];
	int efficiency = 0;
	struct i2c_client *client = container_of(dev, struct i2c_client, dev);
	struct idtp9220_device_info *di = i2c_get_clientdata(client);

	sendpkt(di, BC_READ_Iin);
	ret = receivepkt(di, data);
	if(ret >= 0) {
		iin = data[0]| data[1] << 8;
	}
	
	sendpkt(di, BC_READ_Vin);
	ret = receivepkt(di, data);
	if(ret >= 0) {
		vin = data[0]| data[1] << 8;
	}

	data[0] = di->bus.read(di, REG_RX_LOUT_L);
	data[1] = di->bus.read(di, REG_RX_LOUT_H);
	iout = data[0] | (data[1] << 8);

	data[0]= di->bus.read(di, REG_ADC_VOUT_L);
	data[1] = di->bus.read(di, REG_ADC_VOUT_H);
	vout = data[0] | ((data[1] & 0xf)<< 8);
	vout = vout * 6 * 21 * 1000 / 40950 + ADJUST_METE_MV;

	efficiency = (vout * iout ) / (vin * iin/1000) ;
	
	dev_err(di->dev, "vin:%d iin %d iout: %d iout: %d efficiency: %d\n", vin, iin, vout, iout, efficiency);
	
	if(data[1] != 0xff)
		return sprintf(buf, "vin:%d iin %d\niout: %d iout: %d\nefficiency: %d\n", vin, iin, vout, iout, efficiency);
	else
		return sprintf(buf, "error\n");
}

static ssize_t reset_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf,
		size_t count)
{
	struct i2c_client *client = container_of(dev, struct i2c_client, dev);
	struct idtp9220_device_info *di = i2c_get_clientdata(client);
	bool enable = strncmp(buf, "1", 1) ? false : true;

	if(enable) {
		//reset TX
		sendpkt(di, BC_RESET);
		//reset RX
		idtp9220_write(di, 0x5a, 0x3000);
		idtp9220_write(di, 0x10, 0x3040);

		msleep(2000);

		idtp9220_write(di, 0x5a, 0x3000);
		idtp9220_write(di, 0x00, 0x3048);
		idtp9220_write(di, 0x80, 0x3040);
		dev_err(di->dev, "reset done");
	}
	return count;
}


static ssize_t reset_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	return sprintf(buf, "ok\n");
}

#endif 

static void idtp9220_chip_ldout_enable(struct idtp9220_device_info *di, bool enable)
{
	u8 reg_status;
	u8 reg_cmd;

	reg_status = di->bus.read(di, REG_STATUS_L);
	reg_cmd = di->bus.read(di, REG_COMMAND);

	if (enable) {
		if (reg_status & STATUS_VOUT_ON) {
			dev_err(di->dev, "Vout Already ON\n");
			return;
		}
		else {
			dev_err(di->dev, "Switch Vout ON\n");
			reg_cmd |= TOGGLE_LDO_ON_OFF;
			di->bus.write(di, reg_cmd, REG_COMMAND);
		}
	} else {
		if (reg_status & STATUS_VOUT_OFF) {
			dev_err(di->dev, "Vout Already OFF\n");
			return;
		}
		else {
			dev_err(di->dev, "Switch Vout OFF\n");
			reg_cmd |= TOGGLE_LDO_ON_OFF;
			di->bus.write(di, reg_cmd, REG_COMMAND);
		}
	}
}

static int idtp9220_chip_detect_receive(struct idtp9220_device_info *di)
{
	u8 receive = di->bus.read(di, REG_STATUS_L);

	dev_err(di->dev, "reg status:%02x\n", receive);

	return receive & STATUS_TX_DATA_RECV;
}

static int program_ramupdate(char *srcdata, int size)
{
	u8 otp_on = g_di->bus.read(g_di, 0x4d);
	//u8 val;
	u8 data[20480];
	int i, len;
	if(0) {
		printk(KERN_ERR "OTP_ON:%02x\n", otp_on);
		if (!Xfer9220i2c(0x61, 0x600, 0x100, srcdata, 0, size)) {
			printk(KERN_ERR"program_ramupdate failed.\n");
		}
	}
#if 1
	len = sizeof(idtp9220_ramupdate_fw);
	for (i = 0; i < len; i++) {
		data[i] = g_di->bus.read(g_di, 0x600+i);
		if (data[i] != idtp9220_ramupdate_fw[i]) {
			printk(KERN_ERR " bootloader check err data[%d]:%02x != boot[%d]:%02x.\n", i, data[i], i, idtp9220_ramupdate_fw[i]);
			return 1;
		}
		printk(KERN_ERR "%02x ", data[i]);
		if (i+1 % 16 == 0)
			printk(KERN_ERR "\n");
	}
#endif

	g_di->bus.write(g_di, 0x5a, 0x4f);
	g_di->bus.write(g_di, 0x40, 0x4e);
	for (i = 0; i < len; i++) {
		data[i] = g_di->bus.read(g_di, 0x600+i);
		if (data[i] != idtp9220_ramupdate_fw[i]) {
			printk(KERN_ERR " bootloader check err data[%d]:%02x != boot[%d]:%02x.\n", i, data[i], i, idtp9220_ramupdate_fw[i]);
			return 1;
		}
		printk(KERN_ERR "%02x ", data[i]);
		if (i+1 % 16 == 0)
			printk(KERN_ERR "\n");
	}

	do {
		printk(KERN_ERR "update: mode:%02x\n", g_di->bus.read(g_di, 0x4d));
	}while((g_di->bus.read(g_di, 0x4d) & (1<<6)) == 0);
	printk(KERN_ERR " update: mode:%02x\n", g_di->bus.read(g_di, 0x4d));

	return 0;
}

static ssize_t chip_version_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf,
		size_t count)
{
	return count;
}


static ssize_t chip_version_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	u8 chip_id_l, chip_id_h, chip_rev, cust_id;
	struct i2c_client *client = container_of(dev, struct i2c_client, dev);
	struct idtp9220_device_info *di = i2c_get_clientdata(client);
	u8 status = di->bus.read(di, REG_STATUS_L);
	u8 vset = di->bus.read(di, REG_VOUT_SET);

	u8 reg5870 = di->bus.read(di,0x5870);
	u8 reg5871 = di->bus.read(di,0x5871);

	chip_id_l = di->bus.read(di, REG_CHIP_ID_L);
	chip_id_h = di->bus.read(di, REG_CHIP_ID_H);
	chip_rev = di->bus.read(di, REG_CHIP_REV) >> 4;
	cust_id = di->bus.read(di, REG_CTM_ID);

	return sprintf(buf, "chip_id_l:%02x\nchip_id_h:%02x\nchip_rev:%02x\ncust_id:%02x status:%02x vset:%02x\n reg0x5870 : %02x  %02x",
			chip_id_l, chip_id_h, chip_rev, cust_id, status, vset, reg5870, reg5871);
}

static ssize_t FW_version_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf,
		size_t count)
{
	return count;
}


static ssize_t FW_version_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	struct i2c_client *client = container_of(dev, struct i2c_client, dev);
	struct idtp9220_device_info *di = i2c_get_clientdata(client);
	u8 otp_maj_ver_l = di->bus.read(di, REG_OTP_VER);
	u8 otp_maj_ver_h = di->bus.read(di, REG_OTP_VER+1);
	u8 otp_min_ver_l = di->bus.read(di, REG_OTP_VER+2);
	u8 otp_min_ver_h = di->bus.read(di, REG_OTP_VER+3);

         if((otp_maj_ver_l & otp_maj_ver_h)  != 0xff)
		return sprintf(buf, "%02x%02x:%02x%02x\n",
				otp_min_ver_h, otp_min_ver_l, otp_maj_ver_h, otp_maj_ver_l);
	else
		return sprintf(buf, "unknown\n");
}


static ssize_t chip_detect_receive_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	u8 receive;
	struct i2c_client *client = container_of(dev, struct i2c_client, dev);
	struct idtp9220_device_info *di = i2c_get_clientdata(client);

	receive = idtp9220_chip_detect_receive(di);

	if (receive)
		return sprintf(buf, "detect valid tx data.\n");
	else
		return sprintf(buf, "detect no tx data.\n");
}

static ssize_t chip_enable_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	struct i2c_client *client = container_of(dev, struct i2c_client, dev);
	struct idtp9220_device_info *di = i2c_get_clientdata(client);

	return sprintf(buf, "chip enable:%d\n", di->chip_enable);
}

static ssize_t chip_enable_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf,
		size_t count)
{
	struct i2c_client *client = container_of(dev, struct i2c_client, dev);
	struct idtp9220_device_info *di = i2c_get_clientdata(client);
	bool enable = strncmp(buf, "1", 1) ? false : true;

	dev_err(di->dev, "chip enable:%d", enable);

	//idtp9220_chip_enable(di, enable);

	return count;
}

static ssize_t chip_ldout_enable_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	u8 ldout_enable;
	struct i2c_client *client = container_of(dev, struct i2c_client, dev);
	struct idtp9220_device_info *di = i2c_get_clientdata(client);

	ldout_enable = di->bus.read(di, REG_STATUS_L);
	dev_err(di->dev, "0x34 %02x .\n", ldout_enable);

	if(ldout_enable & STATUS_VOUT_ON)
		return sprintf(buf, "LDO Vout is ON.\n");
	else
		return sprintf(buf, "LDO Vout is OFF.\n");
}

static ssize_t chip_ldout_enable_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf,
		size_t count)
{
	struct i2c_client *client = container_of(dev, struct i2c_client, dev);
	struct idtp9220_device_info *di = i2c_get_clientdata(client);
	bool ldout_enable = strncmp(buf, "1", 1) ? false : true;


	if (ldout_enable)
		dev_err(di->dev, "enable LDO Vout.\n");
	else
		dev_err(di->dev, "disable LDO Vout.\n");

	idtp9220_chip_ldout_enable(di, ldout_enable);

	return count;
}

/* voltage limit attrs */
static ssize_t chip_vout_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	struct i2c_client *client = container_of(dev, struct i2c_client, dev);
	struct idtp9220_device_info *di = i2c_get_clientdata(client);

	u8 vout_l, vout_h;
	u16 vout;

	vout_l = di->bus.read(di, REG_ADC_VOUT_L);
	vout_h = di->bus.read(di, REG_ADC_VOUT_H);
	vout = vout_l | ((vout_h & 0xf)<< 8);
	vout = vout * 6 * 21 * 1000 / 40950 + ADJUST_METE_MV; //vout = val/4095*6*2.1

	dev_err(di->dev, "vout_l:%02x vout_h:%02x\n", vout_l, vout_h);

	if(vout_h != 0xff)
		return sprintf(buf, "Vout ADC Value: %dMV\n", vout);
	else
		return sprintf(buf, "error\n");
}

static ssize_t chip_vout_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf,
		size_t count)
{
	int index;
	struct i2c_client *client = container_of(dev, struct i2c_client, dev);
	struct idtp9220_device_info *di = i2c_get_clientdata(client);

	index = (int)simple_strtoul(buf, NULL, 16);

	dev_err(di->dev, "Store index %d is invalid!\n", index);
	//BSP_SYS: Alex_Ma(majianbo@smatisan.com) change checking field  with Coverity tool on 2018-4-12,begin
	//Max=16 
	if ((index < VOUT_VAL_3500_MV) || (index > VOUT_VAL_5000_MV)) {
	//if ((index < VOUT_VAL_3500_MV) || (index > 55)) {
	//BSP_SYS: Alex_Ma(majianbo@smatisan.com) change checking field with Coverity tool on 2018-4-12,end
		dev_err(di->dev, "Store Val %s is invalid!\n", buf);
		return count;
	}

	show_stored_vout_val(di, index);

	di->bus.write(di, index, REG_VOUT_SET);

	return count;
}

/* current limit attrs */
static ssize_t chip_cout_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	u8 cout_l, cout_h;
	u16 cout;
	struct i2c_client *client = container_of(dev, struct i2c_client, dev);
	struct idtp9220_device_info *di = i2c_get_clientdata(client);

	cout_l = di->bus.read(di, REG_RX_LOUT_L);
	cout_h = di->bus.read(di, REG_RX_LOUT_H);
	cout = cout_l | (cout_h << 8);

	dev_err(di->dev, "cout_l:%02x cout_h:%02x\n", cout_l, cout_h);
	
	if(cout_h != 0xff)
		return sprintf(buf, "Output Current: %dMA\n", cout);
	else
		return sprintf(buf, "error\n");
}

static ssize_t chip_cout_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf,
		size_t count)
{
	int index;
	struct i2c_client *client = container_of(dev, struct i2c_client, dev);
	struct idtp9220_device_info *di = i2c_get_clientdata(client);

	index = (int)simple_strtoul(buf, NULL, 10);

	if ((index < CURR_VAL_100_MA) || (index > CURR_VAL_1300_MA)) {
		dev_err(di->dev, "Store Val %s is invalid", buf);
		return count;
	}

	show_stored_current_val(di, index);

	di->bus.write(di, index, REG_ILIM_SET);

	return count;
}
#if 0
static ssize_t chip_OTP_update_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	return sprintf(buf, "chip_OTP_update_show \n");
}

static ssize_t chip_OTP_update_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf,
		size_t count)
{
	int index, ret;
	struct i2c_client *client = container_of(dev, struct i2c_client, dev);

	index = (int)simple_strtoul(buf, NULL, 10);

	if(index == 1) {
		ret = program_fw(idtp9220_ramupdate_fw, 0, sizeof(idtp9220_ramupdate_fw));
		if (!ret) {
			dev_err(&client->dev, "program fw failed.\n");
			return count;
		}
		dev_err(&client->dev, "chip_OTP_update completed \n");
	}
	return count;
}
#endif
static ssize_t chip_FC_enable_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	u8 cout_l, cout_h;
	u16 cout;
	struct i2c_client *client = container_of(dev, struct i2c_client, dev);
	struct idtp9220_device_info *di = i2c_get_clientdata(client);

	cout_l = di->bus.read(di, REG_RX_LOUT_L);
	cout_h = di->bus.read(di, REG_RX_LOUT_H);
	cout = cout_l | (cout_h << 8);

	dev_err(di->dev, "cout_l:%02x cout_h:%02x\n", cout_l, cout_h);

	return sprintf(buf, "chip_FC_enable_show Output Current: %dMA\n", cout);
}

static ssize_t chip_FC_enable_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf,
		size_t count)
{
	int index;
	struct i2c_client *client = container_of(dev, struct i2c_client, dev);
	struct idtp9220_device_info *di = i2c_get_clientdata(client);

	index = (int)simple_strtoul(buf, NULL, 10);

	if ((index < 5000) || (index > 12000)) {
		dev_err(di->dev, "Store Val %s is invalid", buf);
		return count;
	}

	di->bus.write(di, index&0xff, REG_FC_VOLTAGE_L_ADDR);
	di->bus.write(di, (index>>8)&0xff, REG_FC_VOLTAGE_H_ADDR);
	di->bus.write(di, STATUS_VOUT_ON, REG_COMMAND);
	dev_err(di->dev, "Store FC  Val %d ", index);

	return count;
}

int idtp_9220_FC_enable(int mv)
{
	if(g_di != NULL) {
		g_di->bus.write( g_di, mv&0xff, REG_FC_VOLTAGE_L_ADDR);
		g_di->bus.write( g_di,  (mv>>8)&0xff, REG_FC_VOLTAGE_H_ADDR);
		g_di->bus.write(g_di, STATUS_VOUT_ON, REG_COMMAND);
		printk(KERN_ERR "lgy irq enable_FC ");
	}
	return 0;
}


static ssize_t reg_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf,
		size_t count)
{
	struct i2c_client *client = container_of(dev, struct i2c_client, dev);
	struct idtp9220_device_info *di = i2c_get_clientdata(client);

	p9221_reg = (int)simple_strtoul(buf, NULL, 10);

	dev_err(di->dev, "reg %04x ", p9221_reg);

	return count;
}

static ssize_t reg_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	u8 value;
	struct i2c_client *client = container_of(dev, struct i2c_client, dev);
	struct idtp9220_device_info *di = i2c_get_clientdata(client);

	value = di->bus.read(di, p9221_reg);

	return sprintf(buf,"read reg %04x  Val %02x ", p9221_reg, value);
}

static ssize_t value_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf,
		size_t count)
{
	int index;
	struct i2c_client *client = container_of(dev, struct i2c_client, dev);
	struct idtp9220_device_info *di = i2c_get_clientdata(client);

	index = (int)simple_strtoul(buf, NULL, 10);

	di->bus.write(di, index&0xff, p9221_reg);

	dev_err(di->dev, "write reg %04x  Val %02x ", p9221_reg, index);

	return count;
}

static ssize_t ept_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf,
		size_t count)
{
	struct i2c_client *client = container_of(dev, struct i2c_client, dev);
	struct idtp9220_device_info *di = i2c_get_clientdata(client);
	bool enable = strncmp(buf, "1", 1) ? false : true;

	if(enable) {
		di->bus.write( g_di, 0x03, 0x003b);
		di->bus.write( g_di, 0x08, REG_COMMAND);
		dev_err(di->dev, "ept done");
	}
	return count;
}

static ssize_t ept_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	return sprintf(buf, "ept\n");
}

static ssize_t FOD_5V_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf,
		size_t count)
{
	struct i2c_client *client = container_of(dev, struct i2c_client, dev);
	struct idtp9220_device_info *di = i2c_get_clientdata(client);
	bool enable = strncmp(buf, "1", 1) ? false : true;

	if(enable) {
		di->bus.write( g_di, 180, 0x0068);
		di->bus.write( g_di,   30, 0x0069);
		di->bus.write( g_di, 147, 0x006A);
		di->bus.write( g_di,   35, 0x006B);
		di->bus.write( g_di, 136, 0x006C);
		di->bus.write( g_di,   50, 0x006D);
		di->bus.write( g_di, 157, 0x006E);
		di->bus.write( g_di,   10, 0x006F);
		di->bus.write( g_di, 155, 0x0070);
		di->bus.write( g_di,   20, 0x0071);
		di->bus.write( g_di, 180, 0x0072);
		di->bus.write( g_di,   25, 0x0073);

		dev_err(di->dev, "FOD_5V done");
	}
	return count;
}

static ssize_t FOD_5V_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	return sprintf(buf, "FOD_5V\n");
}

static ssize_t FOD_9V_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf,
		size_t count)
{
	struct i2c_client *client = container_of(dev, struct i2c_client, dev);
	struct idtp9220_device_info *di = i2c_get_clientdata(client);
	bool enable = strncmp(buf, "1", 1) ? false : true;

	if(enable) {
		di->bus.write( g_di, 255, 0x0068);
		di->bus.write( g_di, 127, 0x0069);
		di->bus.write( g_di, 200, 0x006A);
		di->bus.write( g_di,   90, 0x006B);
		di->bus.write( g_di, 135, 0x006C);
		di->bus.write( g_di,   65, 0x006D);
		di->bus.write( g_di, 145, 0x006E);
		di->bus.write( g_di,   25, 0x006F);
		di->bus.write( g_di, 145, 0x0070);
		di->bus.write( g_di,   25, 0x0071);
		di->bus.write( g_di, 145, 0x0072);
		di->bus.write( g_di,   25, 0x0073);

		dev_err(di->dev, "FOD_9V done");
	}
	return count;
}

static ssize_t FOD_9V_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	return sprintf(buf, "FOD_9V\n");
}


//static DEVICE_ATTR(chip_version, S_IRUGO|S_IWUSR, chip_version_show, chip_version_store);
static DEVICE_ATTR(chip_version, S_IWUSR | S_IRUGO, chip_version_show, chip_version_store);
//static DEVICE_ATTR(chip_version, S_IRUGO, chip_version_show, NULL);
static DEVICE_ATTR(chip_detect_receive, S_IRUGO, chip_detect_receive_show, NULL);
static DEVICE_ATTR(chip_enable, S_IWUSR | S_IRUGO, chip_enable_show, chip_enable_store);
static DEVICE_ATTR(chip_ldout_enable, S_IWUSR | S_IRUGO, chip_ldout_enable_show, chip_ldout_enable_store);
static DEVICE_ATTR(chip_vout, S_IWUSR | S_IRUGO, chip_vout_show, chip_vout_store);
static DEVICE_ATTR(chip_cout, S_IWUSR | S_IRUGO, chip_cout_show, chip_cout_store);
static DEVICE_ATTR(get_vin, S_IWUSR | S_IRUGO, get_vin_show, get_vin_store);
static DEVICE_ATTR(get_iin, S_IWUSR | S_IRUGO, get_iin_show, get_iin_store);
static DEVICE_ATTR(get_efficiency, S_IWUSR | S_IRUGO, get_efficiency_show, get_efficiency_store);
static DEVICE_ATTR(reset, S_IWUSR | S_IRUGO, reset_show, reset_store);
//static DEVICE_ATTR(chip_OTP_update, S_IWUSR | S_IRUGO, chip_OTP_update_show, chip_OTP_update_store);
static DEVICE_ATTR(chip_FC_enable, S_IWUSR | S_IRUGO, chip_FC_enable_show, chip_FC_enable_store);

static DEVICE_ATTR(reg, S_IWUSR | S_IRUGO, reg_show, reg_store);
static DEVICE_ATTR(value, S_IWUSR | S_IRUGO, NULL, value_store);
static DEVICE_ATTR(FW_version, S_IWUSR | S_IRUGO, FW_version_show, FW_version_store);
static DEVICE_ATTR(ept, S_IWUSR | S_IRUGO, ept_show, ept_store);
static DEVICE_ATTR(FOD_5V, S_IWUSR | S_IRUGO, FOD_5V_show, FOD_5V_store);
static DEVICE_ATTR(FOD_9V, S_IWUSR | S_IRUGO, FOD_9V_show, FOD_9V_store);


static struct attribute *idtp9220_sysfs_attrs[] = {
	&dev_attr_chip_version.attr,
	&dev_attr_chip_detect_receive.attr,
	&dev_attr_chip_enable.attr,
	&dev_attr_chip_ldout_enable.attr,
	&dev_attr_chip_vout.attr,
	&dev_attr_chip_cout.attr,
	&dev_attr_get_vin.attr,
	&dev_attr_get_iin.attr,
	&dev_attr_get_efficiency.attr,
	&dev_attr_reset.attr,
//	&dev_attr_chip_OTP_update.attr,
	&dev_attr_chip_FC_enable.attr,
	&dev_attr_reg.attr,
	&dev_attr_value.attr,
	&dev_attr_FW_version.attr,
	&dev_attr_ept.attr,
	&dev_attr_FOD_5V.attr,
	&dev_attr_FOD_9V.attr,
	NULL,
};

static const struct attribute_group idtp9220_sysfs_group_attrs = {
	.attrs = idtp9220_sysfs_attrs,
};
#if 1
static int program_bootloader(struct idtp9220_device_info *di)
{
	int i;
	int len;
	//char data[512];

	len = sizeof(bootloader_data);

	for (i = 0; i < len; i++) {
		di->bus.write(di, bootloader_data[i], 0x1c00+i);
	}

	return true;
}

static int Write9220Byte(u16 reg, u8 data)
{
	return g_di->bus.write(g_di, data, reg);
}
#endif

static int Xfer9220i2c(u8 i2cAddr, ushort reg, uint page, char *bBuf, int bOffs, int bSize)
{

	int i, ret;

	for (i = 0; i < bSize; i++) {
		ret = g_di->bus.write(g_di, bBuf[bOffs+i], reg+i);
	}

	return ret;
}
#if 1
static int program_fw(char *srcData, int srcOffs, int size)
{
	int i;
	u8 data;
	u8 data_array[512];
	u8 i2cDeviceAddr = 0x61;    // 7-bit I2C address as 9220 device works as I2C slave


	//  === Step-1 ===
	// Transfer 9220 boot loader code "OTPBootloader" to 9220 SRAM
	// - Setup 9220 registers before transferring the boot loader code
	// - Transfer the boot loader code to 9220 SRAM
	// - Reset 9220 => 9220 M0 runs the boot loader
	//
	/*for test*/
	Write9220Byte(0x88, 0x5b);
	Write9220Byte(0x58, 0x5b);

	if (1) {

		data = g_di->bus.read(g_di, 0x5870);
		printk(KERN_DEBUG "0x5870 %s:%d :%02x\n", __func__, __LINE__, data);
		data = g_di->bus.read(g_di, 0x5874);
		printk(KERN_DEBUG "0x5874 %s:%d :%02x\n", __func__, __LINE__, data);
		// configure the system
		if (!Write9220Byte(0x3000, 0x5a)) return false;        // write key
		if (!Write9220Byte(0x3040, 0x10)) return false;        // halt M0 execution
		if (!program_bootloader(g_di)) return false;
		if (!Write9220Byte(0x3048, 0x80)) return false;        // map RAM to OTP
		/* ignoreNAK */
		if (!Write9220Byte(0x3040, 0x80)) return false;        // reset chip and run the bootloader
		mdelay(100);
		printk(KERN_ERR "%s:%d\n", __func__, __LINE__);
#if 1
		data = g_di->bus.read(g_di, 0x3048);
		printk(KERN_EMERG "0x3048 %s:%d :%02x\n", __func__, __LINE__, data);
		for (i = 0; i < 512; i++) {
			data_array[i] = g_di->bus.read(g_di, 0x1c00+i);
			if (data_array[i] != bootloader_data[i]) {
				printk(KERN_EMERG " bootloader check err data[%d]:%02x != boot[%d]:%02x.\n", i, data_array[i], i, bootloader_data[i]);
				return 1;
			}
#ifdef IDT_DEBUG
			printk(KERN_EMERG "%02x ", data_array[i]);
			if (i+1 % 16 == 0)
				printk(KERN_EMERG "\n");
#endif
		}
#endif


		//
		// === Step-2 ===
		// Program OTP image data to 9220 OTP memory
		//
		for (i = 0; i < size; i += 128)        // program pages of 128 bytes
		{

			//
			// Build a packet
			//
			char sBuf[136];        // 136=8+128 --- 8-byte header plus 128-byte data
			u16 StartAddr = (u16)i;
			u16 CheckSum = StartAddr;
			u16 CodeLength = 128;
			int j;

			memset(sBuf, 0, 136);

			//(1) Copy the 128 bytes of the OTP image data to the packet data buffer
			//    Array.Copy(srcData, i + srcOffs, sBuf, 8, 128);// Copy 128 bytes from srcData (starting at i+srcOffs)
			memcpy(sBuf+8, srcData+i+ srcOffs, 128);// Copy 128 bytes from srcData (starting at i+srcOffs)
			// to sBuf (starting at 8)
			//srcData     --- source array
			//i + srcOffs     --- start index in source array
			//sBuf         --- destination array
			//8         --- start index in destination array
			//128         --- elements to copy


			//(2) Calculate the packet checksum of the 128-byte data, StartAddr, and CodeLength
			for (j = 127; j >= 0; j--)        // find the 1st non zero value byte from the end of the sBuf[] buffer
			{
				if (sBuf[j + 8] != 0)
				{
					//printk(KERN_EMERG "sBuf[%d] = %02x\n", j+8, sBuf[j + 8]);
					break;
				}
				else
					CodeLength--;
			}
			if (CodeLength == 0)
				continue;            // skip programming if nothing to program

			for (; j >= 0; j--)
				CheckSum += sBuf[j + 8];    // add the nonzero values

			CheckSum += CodeLength;        // finish calculation of the check sum

			//(3) Fill up StartAddr, CodeLength, CheckSum of the current packet.
			memcpy(sBuf+2, &StartAddr, 2);
			memcpy(sBuf+4, &CodeLength, 2);
			memcpy(sBuf+6, &CheckSum, 2);


			//
			// Send the current packet to 9220 SRAM via I2C
			//

			// read status is guaranteed to be != 1 at this point
			if (!Xfer9220i2c(i2cDeviceAddr, 0x400, 0x100, sBuf, 0, CodeLength + 8))
			{
				printk(KERN_ERR "ERROR: on writing to OTP buffer");
				return false;
			}


			//
			// Write 1 to the Status in the SRAM. This informs the 9220 to start programming the new packet
			// from SRAM to OTP memory
			//

			sBuf[0] = 1;
			if (!Xfer9220i2c(i2cDeviceAddr, 0x400, 0x100, sBuf, 0, 1))
			{
				printk(KERN_ERR "ERROR: on OTP buffer validation");
				return false;
			}


			//
			// Wait for 9220 bootloader to complete programming the current packet image data from SRAM to the OTP.
			// The boot loader will update the Status in the SRAM as follows:
			//     Status:
			//     "0" - reset value (from AP)
			//     "1" - buffer validated / busy (from AP)
			//     "2" - finish "OK" (from the boot loader)
			//     "4" - programming error (from the boot loader)
			//     "8" - wrong check sum (from the boot loader)
			//     "16"- programming not possible (try to write "0" to bit location already programmed to "1")
			//         (from the boot loader)

			//        DateTime startT = DateTime.Now;
			do
			{
				mdelay(100);
				sBuf[0] = g_di->bus.read(g_di, 0x400);
				{
					//printk(KERN_ERR "ERROR: on readign OTP buffer status sBuf:%02x i:%d\n", sBuf[0], i);
				}
			} while (sBuf[0] == 1); //check if OTP programming finishes "OK"

			if (sBuf[0] != 2)        // not OK
			{
				printk(KERN_ERR "ERROR: buffer write to OTP returned status:%d :%s\n" , sBuf[0], "X4");
				return false;
			}
		}

		// === Step-3 ===
		// Restore system (Need to reset or power cycle 9220 to run the OTP code)
		//
		if (!Write9220Byte(0x3000, 0x5a)) return false;        // write key
		if (!Write9220Byte(0x3048, 0x00)) return false;        // remove code remapping
		//if (!Write9220Byte(0x3040, 0x80)) return false;    // reset M0

	}
	return true;
}
#endif
static void idtp9220_chip_init(struct idtp9220_device_info *di)
{
	int len;
	u8 status = di->bus.read(di, REG_STATUS_L);
	printk(KERN_ERR "chip status:%02x\n", status);

	/* default 5V 1.3A LDO Vout */
	di->bus.write(di, VOUT_VAL_5000_MV, REG_VOUT_SET);
	di->bus.write(di, CURR_VAL_1300_MA, REG_ILIM_SET);

	idtp9220_chip_ldout_enable(di, true);
	/*TODO*/
	if (0) {
		len = sizeof(idtp9220_ramupdate_fw);
		program_ramupdate(idtp9220_ramupdate_fw,len);
	}
}
#if 0
static int over_status_detect(struct idtp9220_device_info *di)
{
	u8 reg;
	int over = 0;

	reg = di->bus.read(di, REG_STATUS_L);
	if (reg & OVER_EVENT_OCCUR) {
		dev_err(di->dev, "Over temperature/voltage/current occured!\n");
		over = 1;
	}

	return over;
}
#endif

static void idtp9220_work(struct work_struct *work)
{
#if 0
	int receive;
	int capacity;
	struct delayed_work *dwork = to_delayed_work(work);
	struct idtp9220_device_info *di = container_of(dwork, struct idtp9220_device_info, dwork);

	/* FIX ME it's need change int the future */
	capacity = 90;

	if (over_status_detect(di)) {
		idtp9220_chip_enable(di, false);
		idtp9220_chip_ldout_enable(di, false);
		queue_delayed_work(di->wq, &di->dwork, IDTP9220_DELAY);
		return;
	}

	receive = idtp9220_chip_detect_receive(di);

	if (CHARGING_FULL == capacity) {
		idtp9220_chip_enable(di, false);
		idtp9220_chip_ldout_enable(di, false);
		//dev_err(di->dev, "charging full already.\n");
	} else if ((capacity < CHARGING_NEED) & receive) {
		idtp9220_chip_enable(di, true);
		idtp9220_chip_ldout_enable(di, true);
		//dev_err(di->dev, "need charging.\n");
	}

	queue_delayed_work(di->wq, &di->dwork, IDTP9220_DELAY);
#endif
}

static int idtp9220_probe(struct i2c_client *client,
		const struct i2c_device_id *id)
{
	char *name;
	struct idtp9220_device_info *di;
	struct idtp9220_platform_data *pd = client->dev.platform_data;
	struct i2c_adapter *adapter = to_i2c_adapter(client->dev.parent);
	int ret, irq_gpio;
	u8 reg5870 = 0;
	printk(KERN_ERR "probe idtp9220 i2c driver\n");

	mutex_init(&mutex);

	if (!i2c_check_functionality(adapter, I2C_FUNC_SMBUS_BYTE)) {
		dev_err(&client->dev, "i2c check functionality failed!\n");
		return -EIO;
	}

	di = devm_kzalloc(&client->dev, sizeof(*di), GFP_KERNEL);
	if (!di) {
		dev_err(&client->dev, "i2c allocated device info data failed!\n");
		return -ENOMEM;
	}

	name = kasprintf(GFP_KERNEL, "%s-%d", id->name, (unsigned int)id->driver_data);
	if (!name) {
		dev_err(&client->dev, "failed to allocate device name\n");
		return -ENOMEM;
	}

	di->name = name;
	di->dev = &client->dev;
	di->chip_enable = 1;
	di->pdata = pd;
	di->bus.read = idtp9220_read;
	di->bus.write = idtp9220_write;
	g_di = di;

	i2c_set_clientdata(client, di);

	//idtp9220_chip_enable(di, true);
	reg5870 = di->bus.read(di,0x5870);
    if (reg5870 != 0xff)
        smartisan_hwstate_set("wipower", "ok");
    else
        smartisan_hwstate_set("wipower", "fail");

	if(0) {
		ret = program_fw(idtp9220_ramupdate_fw, 0, sizeof(idtp9220_ramupdate_fw));
		if (!ret) {
			dev_err(&client->dev, "program fw failed.\n");
			return -EINVAL;
		}
	}

	if (0) {
		idtp9220_chip_init(di);
	}

	if(sysfs_create_group(&client->dev.kobj, &idtp9220_sysfs_group_attrs)) {
		dev_err(&client->dev, "create sysfs attrs failed!\n");
		return -EIO;
	}

	di->wq = create_singlethread_workqueue(IDT_DRIVER_NAME);
	if (!di->wq) {
		dev_err(&client->dev, "create single thread wrokqueue failed!\n");
		return -EINVAL;
	}

	INIT_DELAYED_WORK(&di->dwork, idtp9220_work);
	queue_delayed_work(di->wq, &di->dwork, IDTP9220_DELAY);

	irq_gpio = of_get_named_gpio(di->dev->of_node, "p9220_irq", 0);
	if(!gpio_is_valid(irq_gpio)) {
		dev_err(&client->dev, "parse of  irq_gpio failed \n");
		return -1;
	}

	dev_warn(&client->dev, "irq_gpio %d \n", irq_gpio);
	if(1) {
		ret = devm_gpio_request(di->dev, irq_gpio, "p9220_irq");
		if(ret) {
			dev_err(&client->dev, "request irq_gpio failed \n");
			return -1;
		}
		gpio_direction_input(irq_gpio);
	}
	return 0;
}

static int idtp9220_remove(struct i2c_client *client)
{
	struct idtp9220_device_info *di = i2c_get_clientdata(client);

	cancel_delayed_work_sync(&di->dwork);
	destroy_workqueue(di->wq);

	return 0;
}

static const struct of_device_id i2c_p9220_match_table[] = {
	{ .compatible = "p9220_charger", },
	{ },
};

static struct i2c_board_info __initdata i2c_idtp9220_boardinfo[] =
{
	{
		I2C_BOARD_INFO(IDT_DRIVER_NAME, (IDT_I2C_ADDR)),
		.platform_data = &idtp9220_pdata,
	},
};

static const struct i2c_device_id idtp9220_id[] = {
	{IDT_DRIVER_NAME, 0},
	{}
};
MODULE_DEVICE_TABLE(i2c, idtp9220_id);

static struct i2c_driver idtp9220_driver = {
	.driver = {
		.owner = THIS_MODULE,
		.name = IDT_DRIVER_NAME,
		.of_match_table = i2c_p9220_match_table,
	},
	.probe = idtp9220_probe,
	.remove = idtp9220_remove,
	.id_table = idtp9220_id,
};

static inline int idtp9220_i2c_driver_init(void)
{
	int ret =  i2c_add_driver(&idtp9220_driver);
	if (ret)
		printk(KERN_ERR "Unable to register idtp9220 i2c driver\n");

	return ret;
}

static int __init idtp9220_init(void)
{
	int ret;

	ret = i2c_register_board_info(0, i2c_idtp9220_boardinfo, ARRAY_SIZE(i2c_idtp9220_boardinfo));

	ret = idtp9220_i2c_driver_init();
	if (ret)
		printk(KERN_ERR "idtp9220 i2c driver init failed!\n");

	return ret;
}

static void __exit idtp9220_exit(void)
{
	i2c_del_driver(&idtp9220_driver);
}

module_init(idtp9220_init);
module_exit(idtp9220_exit);

MODULE_AUTHOR("bsp@mobvoi.com");
MODULE_DESCRIPTION("IDTP9220 Wireless Power Charger Monitor driver");
MODULE_LICENSE("GPL/BSD");
