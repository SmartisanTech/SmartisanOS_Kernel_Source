/*
 * Copyright (C) 2010 - 2016 Novatek, Inc.
 *
 * $Revision: 7374 $
 * $Date: 2016-11-14 21:51:52 +0800 (週一, 14 十一月 2016) $
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */


#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/delay.h>
#include <asm/uaccess.h>

#include "nt36xxx.h"

#if NVT_TOUCH_EXT_PROC
#define NVT_POINT_STABLE "nvt_point_stable"
#define NVT_GLOVE	"nvt_glove"
#define NVT_FW_VERSION "nvt_fw_version"
#define NVT_BASELINE "nvt_baseline"
#define NVT_RAW "nvt_raw"
#define NVT_DIFF "nvt_diff"

#define I2C_TANSFER_LENGTH  64

#define NORMAL_MODE 0x00
#define TEST_MODE_1 0x21
#define TEST_MODE_2 0x22

#define RAW_PIPE0_ADDR  0x10000
#define RAW_PIPE1_ADDR  0x12000
#define BASELINE_ADDR   0x10E70
#define DIFF_PIPE0_ADDR 0x10830
#define DIFF_PIPE1_ADDR 0x12830

#define RAW_BTN_PIPE0_ADDR  0x10E60
#define RAW_BTN_PIPE1_ADDR  0x12E60
#define BASELINE_BTN_ADDR   0x12E70
#define DIFF_BTN_PIPE0_ADDR 0x10E68
#define DIFF_BTN_PIPE1_ADDR 0x12E68

#define XDATA_SECTOR_SIZE   256

static uint8_t xdata_tmp[2048] = {0};
static int32_t xdata[2048] = {0};
static uint8_t fw_ver = 0;
static int point_stable = 0;
static int glove_mode = 0;
static uint8_t x_num = 0;
static uint8_t y_num = 0;
static uint8_t button_num = 0;

static struct proc_dir_entry *NVT_proc_point_stable_entry;
static struct proc_dir_entry *NVT_proc_glove_entry;
static struct proc_dir_entry *NVT_proc_fw_version_entry;
static struct proc_dir_entry *NVT_proc_baseline_entry;
static struct proc_dir_entry *NVT_proc_raw_entry;
static struct proc_dir_entry *NVT_proc_diff_entry;

extern struct nvt_ts_data *ts;
extern int32_t CTP_I2C_READ(struct i2c_client *client, uint16_t address, uint8_t *buf, uint16_t len);
extern int32_t CTP_I2C_WRITE(struct i2c_client *client, uint16_t address, uint8_t *buf, uint16_t len);
extern int32_t NVT_I2C_READ(struct i2c_client *client, uint16_t address, uint8_t *buf, uint16_t len);
extern int32_t nvt_clear_fw_status(void);
extern int32_t nvt_check_fw_status(void);
//glove mode
int glove_mode_open = -1;
/*******************************************************
Description:
	Novatek touchscreen change mode function.

return:
	n.a.
*******************************************************/
void nvt_change_mode(uint8_t mode)
{
	uint8_t buf[8] = {0};

	//---set xdata index to 0x11E00---
	buf[0] = 0xFF;
	buf[1] = 0x01;
	buf[2] = 0x1E;
	CTP_I2C_WRITE(ts->client, I2C_FW_Address, buf, 3);

	//---set mode---
	buf[0] = 0x50;
	buf[1] = mode;
	CTP_I2C_WRITE(ts->client, I2C_FW_Address, buf, 2);

	if (mode == NORMAL_MODE) {
		buf[0] = 0x51;
		buf[1] = 0xBB;
		CTP_I2C_WRITE(ts->client, I2C_FW_Address, buf, 2);
	}
}

/*******************************************************
Description:
	Novatek touchscreen get firmware related information
	function.

return:
	Executive outcomes. 0---success. -1---fail.
*******************************************************/
int8_t nvt_get_fw_info(void)
{
	uint8_t buf[64] = {0};
	uint32_t retry_count = 0;
	int8_t ret = 0;

info_retry:
	//---set xdata index to 0x11E00---
	buf[0] = 0xFF;
	buf[1] = 0x01;
	buf[2] = 0x1E;
	CTP_I2C_WRITE(ts->client, I2C_FW_Address, buf, 3);

	//---read fw info---
	buf[0] = 0x78;
	CTP_I2C_READ(ts->client, I2C_FW_Address, buf, 17);
	fw_ver = buf[1];
	x_num = buf[3];
	y_num = buf[4];
	button_num = buf[11];

	//---clear x_num, y_num if fw info is broken---
	if ((buf[1] + buf[2]) != 0xFF) {
		dev_err(&ts->client->dev,"%s: FW info is broken! fw_ver=0x%02X, ~fw_ver=0x%02X\n", __func__, buf[1], buf[2]);
		x_num = 0;
		y_num = 0;
		button_num = 0;

		if(retry_count < 3) {
			retry_count++;
			dev_err(&ts->client->dev,"%s: retry_count=%d\n", __func__, retry_count);
			goto info_retry;
		} else {
			ret = -1;
		}
	} else {
		ret = 0;
	}

	return ret;
}

/*******************************************************
Description:
	Novatek touchscreen get firmware pipe function.

return:
	Executive outcomes. 0---pipe 0. 1---pipe 1.
*******************************************************/
uint8_t nvt_get_fw_pipe(void)
{
	uint8_t buf[8]= {0};

	//---set xdata index to 0x11E00---
	buf[0] = 0xFF;
	buf[1] = 0x01;
	buf[2] = 0x1E;
	CTP_I2C_WRITE(ts->client, I2C_FW_Address, buf, 3);

	//---read fw status---
	buf[0] = 0x51;
	buf[1] = 0x00;
	CTP_I2C_READ(ts->client, I2C_FW_Address, buf, 2);

	//dev_info(&ts->client->dev,"FW pipe=%d, buf[1]=0x%02X\n", (buf[1]&0x01), buf[1]);

	return (buf[1] & 0x01);
}

/*******************************************************
Description:
	Novatek touchscreen read meta data function.

return:
	n.a.
*******************************************************/
void nvt_read_mdata(uint32_t xdata_addr, uint32_t xdata_btn_addr)
{
	int32_t i = 0;
	int32_t j = 0;
	int32_t k = 0;
	uint8_t buf[I2C_TANSFER_LENGTH + 1] = {0};
	uint32_t head_addr = 0;
	int32_t dummy_len = 0;
	int32_t data_len = 0;
	int32_t residual_len = 0;

	//---set xdata sector address & length---
	head_addr = xdata_addr - (xdata_addr % XDATA_SECTOR_SIZE);
	dummy_len = xdata_addr - head_addr;
	data_len = x_num * y_num * 2;
	residual_len = (head_addr + dummy_len + data_len) % XDATA_SECTOR_SIZE;

	//printk("head_addr=0x%05X, dummy_len=0x%05X, data_len=0x%05X, residual_len=0x%05X\n", head_addr, dummy_len, data_len, residual_len);

	//read xdata : step 1
	for (i = 0; i < ((dummy_len + data_len) / XDATA_SECTOR_SIZE); i++) {
		//---change xdata index---
		buf[0] = 0xFF;
		buf[1] = ((head_addr + XDATA_SECTOR_SIZE * i) >> 16);
		buf[2] = ((head_addr + XDATA_SECTOR_SIZE * i) >> 8) & 0xFF;
		CTP_I2C_WRITE(ts->client, I2C_FW_Address, buf, 3);

		//---read xdata by I2C_TANSFER_LENGTH
		for (j = 0; j < (XDATA_SECTOR_SIZE / I2C_TANSFER_LENGTH); j++) {
			//---read data---
			buf[0] = I2C_TANSFER_LENGTH * j;
			CTP_I2C_READ(ts->client, I2C_FW_Address, buf, I2C_TANSFER_LENGTH + 1);

			//---copy buf to xdata_tmp---
			for (k = 0; k < I2C_TANSFER_LENGTH; k++) {
				xdata_tmp[XDATA_SECTOR_SIZE * i + I2C_TANSFER_LENGTH * j + k] = buf[k + 1];
				//printk("0x%02X, 0x%04X\n", buf[k+1], (XDATA_SECTOR_SIZE*i + I2C_TANSFER_LENGTH*j + k));
			}
		}
		//printk("addr=0x%05X\n", (head_addr+XDATA_SECTOR_SIZE*i));
	}

	//read xdata : step2
	if (residual_len != 0) {
		//---change xdata index---
		buf[0] = 0xFF;
		buf[1] = ((xdata_addr + data_len - residual_len) >> 16);
		buf[2] = ((xdata_addr + data_len - residual_len) >> 8) & 0xFF;
		CTP_I2C_WRITE(ts->client, I2C_FW_Address, buf, 3);

		//---read xdata by I2C_TANSFER_LENGTH
		for (j = 0; j < (residual_len / I2C_TANSFER_LENGTH + 1); j++) {
			//---read data---
			buf[0] = I2C_TANSFER_LENGTH * j;
			CTP_I2C_READ(ts->client, I2C_FW_Address, buf, I2C_TANSFER_LENGTH + 1);

			//---copy buf to xdata_tmp---
			for (k = 0; k < I2C_TANSFER_LENGTH; k++) {
				xdata_tmp[(dummy_len + data_len - residual_len) + I2C_TANSFER_LENGTH * j + k] = buf[k + 1];
				//printk("0x%02X, 0x%04x\n", buf[k+1], ((dummy_len+data_len-residual_len) + I2C_TANSFER_LENGTH*j + k));
			}
		}
		//printk("addr=0x%05X\n", (xdata_addr+data_len-residual_len));
	}

	//---remove dummy data and 2bytes-to-1data---
	for (i = 0; i < (data_len / 2); i++) {
		xdata[i] = (xdata_tmp[dummy_len + i * 2] + 256 * xdata_tmp[dummy_len + i * 2 + 1]);
	}

#if TOUCH_KEY_NUM > 0
	//read button xdata : step3
	//---change xdata index---
	buf[0] = 0xFF;
	buf[1] = (xdata_btn_addr >> 16);
	buf[2] = ((xdata_btn_addr >> 8) & 0xFF);
	CTP_I2C_WRITE(ts->client, I2C_FW_Address, buf, 3);

	//---read data---
	buf[0] = (xdata_btn_addr & 0xFF);
	CTP_I2C_READ(ts->client, I2C_FW_Address, buf, (TOUCH_KEY_NUM * 2 + 1));

	//---2bytes-to-1data---
	for (i = 0; i < TOUCH_KEY_NUM; i++) {
		xdata[x_num * y_num + i] = (buf[1 + i * 2] + 256 * buf[1 + i * 2 + 1]);
	}
#endif

	//---set xdata index to 0x11E00---
	buf[0] = 0xFF;
	buf[1] = 0x01;
	buf[2] = 0x1E;
	CTP_I2C_WRITE(ts->client, I2C_FW_Address, buf, 3);
}

/*******************************************************
Description:
    Novatek touchscreen get meta data function.

return:
    n.a.
*******************************************************/
void nvt_get_mdata(int32_t *buf, uint8_t *m_x_num, uint8_t *m_y_num)
{
    *m_x_num = x_num;
    *m_y_num = y_num;
#if TOUCH_KEY_NUM > 0
    memcpy(buf, xdata, ((x_num * y_num + TOUCH_KEY_NUM) * 4));
#else
    memcpy(buf, xdata, (x_num * y_num * 4));
#endif /* #if TOUCH_KEY_NUM > 0 */
}

/*******************************************************
Description:
    Novatek touchscreen get fw version function.

return:
    n.a.
*******************************************************/
void nvt_get_fw_version(uint8_t *fw_version)
{
	*fw_version = fw_ver;
}

/*******************************************************
Description:
	Novatek touchscreen firmware version show function.

return:
	Executive outcomes. 0---succeed.
*******************************************************/
static int32_t c_fw_version_show(struct seq_file *m, void *v)
{
	seq_printf(m, "fw_ver=%d, x_num=%d, y_num=%d, button_num=%d\n", fw_ver, x_num, y_num, button_num);
	return 0;
}

/*******************************************************
Description:
	Novatek touchscreen xdata sequence print show
	function.

return:
	Executive outcomes. 0---succeed.
*******************************************************/
static int32_t c_show(struct seq_file *m, void *v)
{
	int32_t i = 0;
	int32_t j = 0;

	for (i = 0; i < y_num; i++) {
		for (j = 0; j < x_num; j++) {
			seq_printf(m, "%5d, ", (int16_t)xdata[i * x_num + j]);
		}
		seq_puts(m, "\n");
	}

#if TOUCH_KEY_NUM > 0
	for (i = 0; i < TOUCH_KEY_NUM; i++) {
		seq_printf(m, "%5d, ", (int16_t)xdata[x_num * y_num + i]);
	}
	seq_puts(m, "\n");
#endif

	seq_printf(m, "\n\n");
	return 0;
}

/*******************************************************
Description:
	Novatek touchscreen xdata sequence print start
	function.

return:
	Executive outcomes. 1---call next function.
	NULL---not call next function and sequence loop
	stop.
*******************************************************/
static void *c_start(struct seq_file *m, loff_t *pos)
{
	return *pos < 1 ? (void *)1 : NULL;
}

/*******************************************************
Description:
	Novatek touchscreen xdata sequence print next
	function.

return:
	Executive outcomes. NULL---no next and call sequence
	stop function.
*******************************************************/
static void *c_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return NULL;
}

/*******************************************************
Description:
	Novatek touchscreen xdata sequence print stop
	function.

return:
	n.a.
*******************************************************/
static void c_stop(struct seq_file *m, void *v)
{
	return;
}

const struct seq_operations nvt_fw_version_seq_ops = {
	.start  = c_start,
	.next   = c_next,
	.stop   = c_stop,
	.show   = c_fw_version_show
};

const struct seq_operations nvt_seq_ops = {
	.start  = c_start,
	.next   = c_next,
	.stop   = c_stop,
	.show   = c_show
};

/*******************************************************
Description:
	Novatek touchscreen /proc/nvt_fw_version open
	function.

return:
	n.a.
*******************************************************/
static int32_t nvt_fw_version_open(struct inode *inode, struct file *file)
{
	if (mutex_lock_interruptible(&ts->lock)) {
		return -ERESTARTSYS;
	}

	dev_info(&ts->client->dev, "%s:++\n", __func__);

	if (nvt_get_fw_info()) {
		mutex_unlock(&ts->lock);
		return -EAGAIN;
	}

	mutex_unlock(&ts->lock);

	dev_info(&ts->client->dev, "%s:--\n", __func__);

	return seq_open(file, &nvt_fw_version_seq_ops);
}

static const struct file_operations nvt_fw_version_fops = {
	.owner = THIS_MODULE,
	.open = nvt_fw_version_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};
static int32_t c_point_stable_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", point_stable);
	return 0;
}
const struct seq_operations nvt_point_stable_seq_ops = {
	.start  = c_start,
	.next   = c_next,
	.stop   = c_stop,
	.show   = c_point_stable_show,
};

static int32_t nvt_point_stable_open(struct inode *inode, struct file *file)
{
	uint8_t tmp_buf[5] = {0};

	dev_info(&ts->client->dev, "%s:++\n", __func__);
	if (mutex_lock_interruptible(&ts->lock)) {
		return -ERESTARTSYS;
	}

	// switch index to 0x18000
	tmp_buf[0] = 0xFF;
	tmp_buf[1] = 0x01;
	tmp_buf[2] = 0x1E;
	CTP_I2C_WRITE(ts->client, I2C_FW_Address, tmp_buf, 3);

	// read 1 byte from offset 0x30 (i.e. start from 0x18030)
	tmp_buf[0] = 0x9c;
	tmp_buf[1] = 0x00;
	tmp_buf[2] = 0x00;
	tmp_buf[3] = 0x00;
	tmp_buf[4] = 0x00;
	CTP_I2C_READ(ts->client, I2C_FW_Address, tmp_buf, 5);
	point_stable = tmp_buf[1] | (tmp_buf[2] << 8);
	dev_info(&ts->client->dev, "%s:--\n", __func__);

	mutex_unlock(&ts->lock);
	return seq_open(file, &nvt_point_stable_seq_ops);
}

static ssize_t nvt_point_stable_write(struct file *filp, const char __user * buf, size_t count, loff_t *lof_p)
{
	int kbuf; /* "on" or "off" plus null. */
	char tmp_buf[8];

	if (sscanf(buf, "%d", &kbuf) != 1) {
		pr_err("sccanf buf error!\n");
		return count;
	}
	if (mutex_lock_interruptible(&ts->lock)) {
		return -ERESTARTSYS;
	}
	pr_err("%s:********kbuf is %d******8\n", __FUNCTION__, kbuf);
	kbuf = kbuf * kbuf;
	pr_err("%s:********kbuf is %d******8\n", __FUNCTION__, kbuf);
	tmp_buf[0] = 0xFF;
	tmp_buf[1] = 0x01;
	tmp_buf[2] = 0x1E;
	CTP_I2C_WRITE(ts->client, I2C_FW_Address, tmp_buf, 3);

	tmp_buf[0] = 0x9C;
	tmp_buf[1] = kbuf;
	tmp_buf[2] = kbuf >> 8;
	tmp_buf[3] = 0x00;
	tmp_buf[4] = 0x00;
	CTP_I2C_WRITE(ts->client, I2C_FW_Address, tmp_buf, 5);
	mutex_unlock(&ts->lock);
	return count;
}
static const struct file_operations nvt_point_stable_fops = {
	.owner = THIS_MODULE,
	.open = nvt_point_stable_open,
	.read = seq_read,
	.write = nvt_point_stable_write,
	.release = seq_release,
};

static int32_t c_glove_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", glove_mode);
	return 0;
}
const struct seq_operations nvt_glove_seq_ops = {
	.start  = c_start,
	.next   = c_next,
	.stop   = c_stop,
	.show   = c_glove_show,
};

static int32_t nvt_glove_open(struct inode *inode, struct file *file)
{
	uint8_t tmp_buf[3] = {0};

	dev_info(&ts->client->dev, "%s:++\n", __func__);
	if (mutex_lock_interruptible(&ts->lock)) {
		return -ERESTARTSYS;
	}

	// switch index to 0x18000
	tmp_buf[0] = 0xFF;
	tmp_buf[1] = 0x01;
	tmp_buf[2] = 0x1E;
	CTP_I2C_WRITE(ts->client, I2C_FW_Address, tmp_buf, 3);

	// read 1 byte from offset 0x30 (i.e. start from 0x18030)
	tmp_buf[0] = 0x50;
	tmp_buf[1] = 0x00;
	CTP_I2C_READ(ts->client, I2C_FW_Address, tmp_buf, 2);
	glove_mode = tmp_buf[1]; //0x71 open glove mode; 0x70 close glove mode
	dev_info(&ts->client->dev, "%s:--\n", __func__);

	mutex_unlock(&ts->lock);
	return seq_open(file, &nvt_glove_seq_ops);
}

void nvt_glove_set(int glove_mode)
{
	char tmp_buf[8];

	if(glove_mode == 0x71)
		glove_mode_open = 1;
	else
		glove_mode_open = 0;

	if (mutex_lock_interruptible(&ts->lock)) {
		return;
	}
	tmp_buf[0] = 0xFF;
	tmp_buf[1] = 0x01;
	tmp_buf[2] = 0x1E;
	CTP_I2C_WRITE(ts->client, I2C_FW_Address, tmp_buf, 3);

	tmp_buf[0] = 0x50;
	tmp_buf[1] = glove_mode;
	CTP_I2C_WRITE(ts->client, I2C_FW_Address, tmp_buf, 2);
	mutex_unlock(&ts->lock);

	return;
}
static ssize_t nvt_glove_write(struct file *filp, const char __user * buf, size_t count, loff_t *lof_p)
{
	int kbuf; /* "on" or "off" plus null. */

	if (sscanf(buf, "%d", &kbuf) != 1) {
		pr_err("sccanf buf error!\n");
		return count;
	}
	nvt_glove_set(kbuf);
	return count;
}
static const struct file_operations nvt_glove_fops = {
	.owner = THIS_MODULE,
	.open = nvt_glove_open,
	.read = seq_read,
	.write = nvt_glove_write,
	.release = seq_release,
};

/*******************************************************
Description:
	Novatek touchscreen /proc/nvt_baseline open function.

return:
	Executive outcomes. 0---succeed.
*******************************************************/
static int32_t nvt_baseline_open(struct inode *inode, struct file *file)
{
	if (mutex_lock_interruptible(&ts->lock)) {
		return -ERESTARTSYS;
	}

	dev_info(&ts->client->dev, "%s:++\n", __func__);

	if (nvt_clear_fw_status()) {
		mutex_unlock(&ts->lock);
		return -EAGAIN;
	}

	nvt_change_mode(TEST_MODE_2);

	if (nvt_check_fw_status()) {
		mutex_unlock(&ts->lock);
		return -EAGAIN;
	}

	if (nvt_get_fw_info()) {
		mutex_unlock(&ts->lock);
		return -EAGAIN;
	}

	nvt_read_mdata(BASELINE_ADDR, BASELINE_BTN_ADDR);

	nvt_change_mode(NORMAL_MODE);

	mutex_unlock(&ts->lock);

	dev_info(&ts->client->dev, "%s:--\n", __func__);

	return seq_open(file, &nvt_seq_ops);
}

static const struct file_operations nvt_baseline_fops = {
	.owner = THIS_MODULE,
	.open = nvt_baseline_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

/*******************************************************
Description:
	Novatek touchscreen /proc/nvt_raw open function.

return:
	Executive outcomes. 0---succeed.
*******************************************************/
static int32_t nvt_raw_open(struct inode *inode, struct file *file)
{
	if (mutex_lock_interruptible(&ts->lock)) {
		return -ERESTARTSYS;
	}

	dev_info(&ts->client->dev, "%s:++\n", __func__);

	if (nvt_clear_fw_status()) {
		mutex_unlock(&ts->lock);
		return -EAGAIN;
	}

	nvt_change_mode(TEST_MODE_2);

	if (nvt_check_fw_status()) {
		mutex_unlock(&ts->lock);
		return -EAGAIN;
	}

	if (nvt_get_fw_info()) {
		mutex_unlock(&ts->lock);
		return -EAGAIN;
	}

	if (nvt_get_fw_pipe() == 0)
		nvt_read_mdata(RAW_PIPE0_ADDR, RAW_BTN_PIPE0_ADDR);
	else
		nvt_read_mdata(RAW_PIPE1_ADDR, RAW_BTN_PIPE1_ADDR);

	nvt_change_mode(NORMAL_MODE);

	dev_info(&ts->client->dev, "%s:--\n", __func__);

	mutex_unlock(&ts->lock);

	return seq_open(file, &nvt_seq_ops);
}

static const struct file_operations nvt_raw_fops = {
	.owner = THIS_MODULE,
	.open = nvt_raw_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

/*******************************************************
Description:
	Novatek touchscreen /proc/nvt_diff open function.

return:
	Executive outcomes. 0---succeed. negative---failed.
*******************************************************/
static int32_t nvt_diff_open(struct inode *inode, struct file *file)
{
	if (mutex_lock_interruptible(&ts->lock)) {
		return -ERESTARTSYS;
	}

	dev_info(&ts->client->dev, "%s:++\n", __func__);

	if (nvt_clear_fw_status()) {
		mutex_unlock(&ts->lock);
		return -EAGAIN;
	}

	nvt_change_mode(TEST_MODE_2);

	if (nvt_check_fw_status()) {
		mutex_unlock(&ts->lock);
		return -EAGAIN;
	}

	nvt_get_fw_info();

	if (nvt_get_fw_pipe() == 0)
		nvt_read_mdata(DIFF_PIPE0_ADDR, DIFF_BTN_PIPE0_ADDR);
	else
		nvt_read_mdata(DIFF_PIPE1_ADDR, DIFF_BTN_PIPE1_ADDR);

	nvt_change_mode(NORMAL_MODE);

	mutex_unlock(&ts->lock);

	dev_info(&ts->client->dev, "%s:--\n", __func__);

	return seq_open(file, &nvt_seq_ops);
}

static const struct file_operations nvt_diff_fops = {
	.owner = THIS_MODULE,
	.open = nvt_diff_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

/*******************************************************
Description:
	Novatek touchscreen extra function proc. file node
	initial function.

return:
	Executive outcomes. 0---succeed. -12---failed.
*******************************************************/
int32_t nvt_extra_proc_init(void)
{
	NVT_proc_glove_entry = proc_create(NVT_GLOVE, S_IRUGO|S_IWUSR, NULL,&nvt_glove_fops);
	if (NVT_proc_glove_entry == NULL) {
		dev_err(&ts->client->dev,"%s: create proc/nvt_glove Failed!\n", __func__);
		return -ENOMEM;
	} else {
		dev_info(&ts->client->dev,"%s: create proc/nvt_glove Succeeded!\n", __func__);
	}

	NVT_proc_point_stable_entry = proc_create(NVT_POINT_STABLE, S_IRUGO|S_IWUSR, NULL,&nvt_point_stable_fops);
	if (NVT_proc_point_stable_entry == NULL) {
		dev_err(&ts->client->dev,"%s: create proc/nvt_point_stable Failed!\n", __func__);
		return -ENOMEM;
	} else {
		dev_info(&ts->client->dev,"%s: create proc/nvt_point_stable Succeeded!\n", __func__);
	}

	NVT_proc_fw_version_entry = proc_create(NVT_FW_VERSION, 0444, NULL,&nvt_fw_version_fops);
	if (NVT_proc_fw_version_entry == NULL) {
		dev_err(&ts->client->dev,"%s: create proc/nvt_fw_version Failed!\n", __func__);
		return -ENOMEM;
	} else {
		dev_info(&ts->client->dev,"%s: create proc/nvt_fw_version Succeeded!\n", __func__);
	}

	NVT_proc_baseline_entry = proc_create(NVT_BASELINE, 0444, NULL,&nvt_baseline_fops);
	if (NVT_proc_baseline_entry == NULL) {
		dev_err(&ts->client->dev,"%s: create proc/nvt_baseline Failed!\n", __func__);
		return -ENOMEM;
	} else {
		dev_info(&ts->client->dev,"%s: create proc/nvt_baseline Succeeded!\n", __func__);
	}

	NVT_proc_raw_entry = proc_create(NVT_RAW, 0444, NULL,&nvt_raw_fops);
	if (NVT_proc_raw_entry == NULL) {
		dev_err(&ts->client->dev,"%s: create proc/nvt_raw Failed!\n", __func__);
		return -ENOMEM;
	} else {
		dev_info(&ts->client->dev,"%s: create proc/nvt_raw Succeeded!\n", __func__);
	}

	NVT_proc_diff_entry = proc_create(NVT_DIFF, 0444, NULL,&nvt_diff_fops);
	if (NVT_proc_diff_entry == NULL) {
		dev_err(&ts->client->dev,"%s: create proc/nvt_diff Failed!\n", __func__);
		return -ENOMEM;
	} else {
		dev_info(&ts->client->dev,"%s: create proc/nvt_diff Succeeded!\n", __func__);
	}

	return 0;
}
#endif
