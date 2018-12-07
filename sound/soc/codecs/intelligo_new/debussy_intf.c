#include <linux/delay.h>
#include <linux/i2c.h>
#include "debussy_snd_ctrl.h"
#include "debussy_intf.h"
#include "debussy.h"

#define IGO_TIMEOUT_TICKS (1 * HZ)	// 1s
//#define IGO_TIMEOUT_RESET_CHIP      // Reset iGo chip while iGo CMD timeout occured
#define ENABLE_MASK_CONFIG_CMD
//#define ENABLE_CMD_BATCH_MODE
#ifndef ENABLE_CMD_BATCH_MODE
#define ENABLE_CMD_BATCH_MODE_BUFFERED
#endif

#define HW_RESET_INSTEAD_OF_STANDBY

#if defined(ENABLE_CMD_BATCH_MODE) || defined(ENABLE_CMD_BATCH_MODE_BUFFERED)
#define MAX_BATCH_MODE_CMD_NUM          (32)
static atomic_t batchMode = ATOMIC_INIT(0);
static atomic_t batchCmdNum = ATOMIC_INIT(0);
#endif

#ifdef ENABLE_CMD_BATCH_MODE_BUFFERED
static unsigned int batch_cmd_buffer[64];
#endif

int igo_i2c_read(struct i2c_client* client, unsigned int addr, unsigned int* value)
{
	//	struct i2c_client *client;
	unsigned char buf[4];
	struct i2c_msg xfer[2];
	unsigned int regVal;
	int ret;

	//	client = context;

	buf[0] = (unsigned char)(addr >> 24);
	buf[1] = (unsigned char)(addr >> 16);
	buf[2] = (unsigned char)(addr >> 8);
	buf[3] = (unsigned char)(addr & 0xff);

	xfer[0].addr = client->addr;
	xfer[0].flags = 0;
	xfer[0].len = 4;
	xfer[0].buf = buf;

	xfer[1].addr = client->addr;
	xfer[1].flags = I2C_M_RD;
	xfer[1].len = 4;
	xfer[1].buf = (u8*)&regVal;

	ret = i2c_transfer(client->adapter, xfer, 2);
	if (ret < 0)
		return ret;
	else if (ret != 2)
		return -EIO;

	*value = regVal;

	return 0;
}

int igo_i2c_write(struct i2c_client* client, unsigned int reg, unsigned int* data, unsigned int len)
{
	//	struct i2c_client *client;
	unsigned char buf[512 + 4];
	struct i2c_msg xfer[1];
	int i, ret;

	//	client = context;

	buf[0] = (unsigned char)(reg >> 24);
	buf[1] = (unsigned char)(reg >> 16);
	buf[2] = (unsigned char)(reg >> 8);
	buf[3] = (unsigned char)(reg & 0xff);

	for (i = 0; i < len; i++) {
		buf[(i + 1) * 4 + 0] = (unsigned char)(data[i] & 0xff);
		buf[(i + 1) * 4 + 1] = (unsigned char)(data[i] >> 8);
		buf[(i + 1) * 4 + 2] = (unsigned char)(data[i] >> 16);
		buf[(i + 1) * 4 + 3] = (unsigned char)(data[i] >> 24);
	}

	xfer[0].addr = client->addr;
	xfer[0].flags = 0;
	xfer[0].len = 4 + len * 4;
	xfer[0].buf = (u8*)buf;

	ret = i2c_transfer(client->adapter, xfer, 1);
	if (ret < 0)
		return ret;
	else if (ret != 1)
		return -EIO;

	return 0;
}

int igo_ch_chk_done(struct device* dev)
{
	struct i2c_client* client;
	unsigned int status = IGO_CH_STATUS_BUSY;
	unsigned long start_time = jiffies;
	client = to_i2c_client(dev);

	while (status == IGO_CH_STATUS_BUSY || status == IGO_CH_STATUS_CMD_RDY || status > IGO_CH_STATUS_MAX) {
		usleep_range(50, 50);
		igo_i2c_read(client, IGO_CH_STATUS_ADDR, &status);
		if (jiffies - start_time >= IGO_TIMEOUT_TICKS) {
			dev_err(dev, "igo cmd timeout\n");
			return IGO_CH_STATUS_TIMEOUT;
		}
	}

	return status;
}

int igo_ch_buf_write(struct device* dev, unsigned int reg, unsigned int* data_buf, unsigned int len)
{
	struct i2c_client* client;
	unsigned int cmd[3];
	unsigned int status = IGO_CH_STATUS_CMD_RDY;
	unsigned int default_data_len = 4;

	client = to_i2c_client(dev);
	igo_i2c_write(client, IGO_CH_BUF_ADDR, data_buf, len / 4);

	cmd[0] = len;
	cmd[1] = IGO_CH_STATUS_CMD_RDY;
	cmd[2] = (IGO_CH_ACTION_WRITE << IGO_CH_ACTION_OFFSET) + reg;
	igo_i2c_write(client, IGO_CH_OPT_ADDR, cmd, 3);

	status = igo_ch_chk_done(dev);

	if (status != IGO_CH_STATUS_DONE) {
		dev_err(dev, "igo cmd buf write 0x%08x len %d fail, error no : %d\n", reg, len, status);
	}

	igo_i2c_write(client, IGO_CH_OPT_ADDR, &default_data_len, 4);

	return status;
}

int igo_ch_slow_write(struct device* dev, unsigned int reg, unsigned int data)
{
	struct i2c_client *client = to_i2c_client(dev);
	unsigned int cmd[2];
	unsigned int status = IGO_CH_STATUS_CMD_RDY;
	unsigned int noDelayAfterWrite = 0;
	struct debussy_priv *debussy = dev_get_drvdata(dev);

#ifdef ENABLE_MASK_CONFIG_CMD
	if (IGO_CH_POWER_MODE_ADDR == reg)
		if (POWER_MODE_WORKING == data) {
			debussy_set_maskconfig(debussy, 0);
			noDelayAfterWrite = 1;
		}
#endif

#ifdef ENABLE_CMD_BATCH_MODE
	if (IGO_CH_POWER_MODE_ADDR == reg) {
		atomic_set(&batchCmdNum, 0);

		if (POWER_MODE_WORKING == data) {
			atomic_set(&batchMode, 1);
			dev_info(dev, "%s: Enable batch CMD mode\n", __func__);
		}
		else {
			// POWER_MODE_STANDBY
			atomic_set(&batchMode, 0);
			dev_info(dev, "%s: Disable batch CMD mode\n", __func__);

			#ifdef HW_RESET_INSTEAD_OF_STANDBY
			// about 40ms
			debussy_reset_chip(debussy, DEBUSSY_RESET_CLEAR); // at least 1ms
			msleep(40);

			return IGO_CH_STATUS_DONE;
			#endif
		}
	}

	if (atomic_read(&batchMode) && (IGO_CH_POWER_MODE_ADDR != reg)) {
		int status;
		unsigned int batch_data[2];

		batch_data[0] = reg;
		batch_data[1] = data;
		status = igo_ch_batch_write(dev, atomic_read(&batchCmdNum), batch_data, ARRAY_SIZE(batch_data));

		if (0 == status) {
			atomic_add(1, &batchCmdNum);

			if (IGO_CH_OP_MODE_ADDR == reg) {
				igo_ch_batch_finish_write(dev, atomic_read(&batchCmdNum));
				atomic_set(&batchMode, 0);
				atomic_set(&batchCmdNum, 0);
				dev_info(dev, "%s: IGO_CH_OP_MODE_ADDR: Disable batch mode\n", __func__);
			}
			else if (MAX_BATCH_MODE_CMD_NUM == atomic_read(&batchCmdNum)) {
				igo_ch_batch_finish_write(dev, MAX_BATCH_MODE_CMD_NUM);
				atomic_set(&batchCmdNum, 0);
			}

			status = IGO_CH_STATUS_DONE;
		}
		else {
			status = IGO_CH_STATUS_ACTION_ERROR;
			dev_info(dev, "%s: igo_ch_batch_write: I2C Error\n", __func__);
		}

		return status;
	}
#elif defined(ENABLE_CMD_BATCH_MODE_BUFFERED)
	if (IGO_CH_POWER_MODE_ADDR == reg) {
		atomic_set(&batchCmdNum, 0);

		if (POWER_MODE_WORKING == data) {
			atomic_set(&batchMode, 1);
			dev_info(dev, "%s: Enable batch CMD mode\n", __func__);
		}
		else {
			// POWER_MODE_STANDBY
			atomic_set(&batchMode, 0);
			dev_info(dev, "%s: Disable batch CMD mode\n", __func__);

			#ifdef HW_RESET_INSTEAD_OF_STANDBY
			// about 40ms
			debussy_reset_chip(debussy, DEBUSSY_RESET_CLEAR); // at least 1ms
			msleep(40);

			return IGO_CH_STATUS_DONE;
			#endif
		}
	}

	if (atomic_read(&batchMode) && (IGO_CH_POWER_MODE_ADDR != reg)) {
		int status = IGO_CH_STATUS_DONE;
		unsigned int index = atomic_read(&batchCmdNum) << 1;

		batch_cmd_buffer[index] = reg;
		batch_cmd_buffer[index + 1] = data;
		atomic_add(1, &batchCmdNum);

		if ((atomic_read(&batchCmdNum) >= MAX_BATCH_MODE_CMD_NUM) || (IGO_CH_OP_MODE_ADDR == reg)) {
			igo_ch_batch_write(dev, 0, batch_cmd_buffer, atomic_read(&batchCmdNum) << 1);
			status = igo_ch_batch_finish_write(dev, atomic_read(&batchCmdNum));
			atomic_set(&batchCmdNum, 0);

			if (IGO_CH_OP_MODE_ADDR == reg) {
				atomic_set(&batchMode, 0);
				dev_info(dev, "%s: IGO_CH_OP_MODE_ADDR: Disable batch mode\n", __func__);
			}
		}

		return status;
	}
#endif
	igo_i2c_write(client, IGO_CH_BUF_ADDR, &data, 1);
	cmd[0] = IGO_CH_STATUS_CMD_RDY;
	cmd[1] = (IGO_CH_ACTION_WRITE << IGO_CH_ACTION_OFFSET) + reg;
	igo_i2c_write(client, IGO_CH_STATUS_ADDR, cmd, 2);

	if (0 == noDelayAfterWrite)
		msleep(20);

	status = igo_ch_chk_done(dev);

	if (status != IGO_CH_STATUS_DONE) {
		dev_err(dev, "igo cmd write 0x%08x : 0x%08x fail, error no : %d\n", reg, data, status);

#ifdef IGO_TIMEOUT_RESET_CHIP
		if (IGO_CH_STATUS_TIMEOUT == status) {
			// Reset IGO chip while IGO CMD timeout occured
			debussy_reset_chip(debussy, DEBUSSY_RESET_TIMEOUT);
		}
#else
		if ((IGO_CH_STATUS_TIMEOUT == status) && (IGO_CH_POWER_MODE_ADDR == reg)) {
			// Force HW Reset about 40ms
			debussy_reset_chip(debussy, DEBUSSY_RESET_TIMEOUT); // at least 1ms
			msleep(40);

			return IGO_CH_STATUS_DONE;
		}
#endif
	}

	return status;
}

int igo_ch_write(struct device* dev, unsigned int reg, unsigned int data)
{
	struct i2c_client* client;
	unsigned int cmd[2];
	unsigned int status = IGO_CH_STATUS_CMD_RDY;
	struct debussy_priv *debussy = dev_get_drvdata(dev);

#ifdef ENABLE_MASK_CONFIG_CMD
	if (false && IGO_CH_OP_MODE_ADDR == reg) {
		if (OP_MODE_CONFIG == data) {
			// debussy_shutdown is ignored, change to Standby CMD
			return igo_ch_slow_write(dev, IGO_CH_POWER_MODE_ADDR, POWER_MODE_STANDBY);
		}
	}

	if (debussy_get_maskconfig(debussy)) {
		return IGO_CH_STATUS_DONE;
	}
#endif

#if defined(ENABLE_CMD_BATCH_MODE)
	if (atomic_read(&batchMode)) {
		int status;
		unsigned int batch_data[2];

		batch_data[0] = reg;
		batch_data[1] = data;
		status = igo_ch_batch_write(dev, atomic_read(&batchCmdNum), batch_data, ARRAY_SIZE(batch_data));

		if (0 == status) {
			atomic_add(1, &batchCmdNum);

			if (IGO_CH_OP_MODE_ADDR == reg) {
				igo_ch_batch_finish_write(dev, atomic_read(&batchCmdNum));
				atomic_set(&batchCmdNum, 0);
				atomic_set(&batchMode, 0);
				dev_info(dev, "%s: IGO_CH_OP_MODE_ADDR: Disable batch mode\n", __func__);
			}
			else if (MAX_BATCH_MODE_CMD_NUM == atomic_read(&batchCmdNum)) {
				igo_ch_batch_finish_write(dev, MAX_BATCH_MODE_CMD_NUM);
				atomic_set(&batchCmdNum, 0);
			}

			status = IGO_CH_STATUS_DONE;
		}
		else {
			dev_info(dev, "%s: igo_ch_batch_write: I2C Error\n", __func__);
			status = IGO_CH_STATUS_ACTION_ERROR;
		}

		return status;
	}
#elif defined(ENABLE_CMD_BATCH_MODE_BUFFERED)
	if (atomic_read(&batchMode)) {
		int status = IGO_CH_STATUS_DONE;
		unsigned int index = atomic_read(&batchCmdNum) << 1;

		batch_cmd_buffer[index] = reg;
		batch_cmd_buffer[index + 1] = data;
		atomic_add(1, &batchCmdNum);

		if ((atomic_read(&batchCmdNum) >= MAX_BATCH_MODE_CMD_NUM) || (IGO_CH_OP_MODE_ADDR == reg)) {
			igo_ch_batch_write(dev, 0, batch_cmd_buffer, atomic_read(&batchCmdNum) << 1);
			status = igo_ch_batch_finish_write(dev, atomic_read(&batchCmdNum));
			atomic_set(&batchCmdNum, 0);

			if (IGO_CH_OP_MODE_ADDR == reg) {
				atomic_set(&batchMode, 0);
				dev_info(dev, "%s: IGO_CH_OP_MODE_ADDR: Disable batch mode\n", __func__);
			}
		}

		return status;
	}
#endif

	client = to_i2c_client(dev);
	igo_i2c_write(client, IGO_CH_BUF_ADDR, &data, 1);
	cmd[0] = IGO_CH_STATUS_CMD_RDY;
	cmd[1] = (IGO_CH_ACTION_WRITE << IGO_CH_ACTION_OFFSET) + reg;
	igo_i2c_write(client, IGO_CH_STATUS_ADDR, cmd, 2);

	status = igo_ch_chk_done(dev);

	if (status != IGO_CH_STATUS_DONE) {
		dev_err(dev, "igo cmd write 0x%08x : 0x%08x fail, error no : %d\n", reg, data, status);

#ifdef IGO_TIMEOUT_RESET_CHIP
		if (IGO_CH_STATUS_TIMEOUT == status) {
			// Reset IGO chip while IGO CMD timeout occured
			debussy_reset_chip(debussy, DEBUSSY_RESET_TIMEOUT);
		}
#endif
	}

	return status;
}

int igo_ch_read(struct device* dev, unsigned int reg, unsigned int* data)
{
	struct i2c_client* client;
	unsigned int cmd[2];
	unsigned int status = IGO_CH_STATUS_CMD_RDY;

	client = to_i2c_client(dev);

	cmd[0] = status;
	cmd[1] = (IGO_CH_ACTION_READ << IGO_CH_ACTION_OFFSET) + reg;
	igo_i2c_write(client, IGO_CH_STATUS_ADDR, cmd, 2);

	status = igo_ch_chk_done(dev);

	igo_i2c_read(client, IGO_CH_BUF_ADDR, data);

	if (status != IGO_CH_STATUS_DONE) {
		dev_err(dev, "igo cmd read 0x%08x fail, error no : %d\n", reg, status);
	}

	return status;
}

#if defined(ENABLE_CMD_BATCH_MODE) || defined(ENABLE_CMD_BATCH_MODE_BUFFERED)
int igo_ch_batch_write(struct device* dev, unsigned int cmd_index, unsigned int *data, unsigned int data_length)
{
	struct i2c_client* client;

	client = to_i2c_client(dev);
	return igo_i2c_write(client, IGO_CH_BUF_ADDR + (cmd_index << 3), data, data_length);
}

int igo_ch_batch_finish_write(struct device* dev, unsigned int num_of_cmd)
{
	struct i2c_client* client;
	unsigned int cmd[2];
	unsigned int status = IGO_CH_STATUS_CMD_RDY;
	//struct debussy_priv *debussy = dev_get_drvdata(dev);

	client = to_i2c_client(dev);
	cmd[0] = IGO_CH_STATUS_CMD_RDY;
	cmd[1] = (IGO_CH_ACTION_BATCH << IGO_CH_ACTION_OFFSET) + num_of_cmd;
	igo_i2c_write(client, IGO_CH_STATUS_ADDR, cmd, 2);
	//msleep(20);
	status = igo_ch_chk_done(dev);

	if (status != IGO_CH_STATUS_DONE) {
		dev_err(dev, "igo batch cmd write fail, error no : %d\n", status);
		igo_i2c_read(client, IGO_CH_RSV_ADDR, &cmd[0]);
		dev_err(dev, "igo cmd batch write fail: error bit 0x%08X\n", cmd[0]);

#ifdef IGO_TIMEOUT_RESET_CHIP
		if (IGO_CH_STATUS_TIMEOUT == status) {
			// Reset IGO chip while IGO CMD timeout occured
			debussy_reset_chip(debussy, DEBUSSY_RESET_TIMEOUT);
		}
#endif
	}

	return status;
}
#endif
