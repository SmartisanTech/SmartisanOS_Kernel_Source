#include "debussy.h"
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/firmware.h>
#include <linux/gpio.h>
#include <linux/i2c.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/of_gpio.h>
#include <linux/platform_device.h>
#include <linux/pm.h>
#include <linux/regulator/consumer.h>
#include <sound/core.h>
#include <sound/initval.h>
#include <sound/pcm.h>
#include <sound/pcm_params.h>
#include <sound/soc-dapm.h>
#include <sound/soc.h>
#include <sound/tlv.h>

#define FW_PATH "./"
#define FW_NAME_SIZE 256
#define DEBUSSY_RATES SNDRV_PCM_RATE_48000
#define DEBUSSY_FORMATS (SNDRV_PCM_FMTBIT_S16_LE | SNDRV_PCM_FMTBIT_S24_LE)

#define DVDD_MIN_UV        1200000
#define DVDD_MAX_UV        1260000
#define DVDD_UA            80000

#define IOVDD_MIN_UV       1800000
#define IOVDD_MAX_UV       1900000
#define IOVDD_UA           10000

#define AVDD_MIN_UV        2800000
#define AVDD_MAX_UV        3000000
#define AVDD_UA            10000
#define SHUTDOWNDEBUSSY 1


static unsigned int presence = 0;

static ssize_t debussy_download_firmware(struct file* file,
	const char __user* user_buf,
	size_t count, loff_t* ppos);
static const struct file_operations debussy_download_firmware_fops = {
	.open = simple_open,
	.write = debussy_download_firmware,
};

static ssize_t debussy_dmic_bypass(struct file* file,
	const char __user* user_buf,
	size_t count, loff_t* ppos);
static const struct file_operations debussy_dmic_bypass_fops = {
	.open = simple_open,
	.write = debussy_dmic_bypass,
};

static ssize_t debussy_dmic_sw_bypass(struct file* file,
	const char __user* user_buf,
	size_t count, loff_t* ppos);
static const struct file_operations debussy_dmic_sw_bypass_fops = {
	.open = simple_open,
	.write = debussy_dmic_sw_bypass,
};

static ssize_t debussy_i2s0_loopback(struct file* file,
	const char __user* user_buf,
	size_t count, loff_t* ppos);
static const struct file_operations debussy_i2s0_loopback_fops = {
	.open = simple_open,
	.write = debussy_i2s0_loopback,
};

static ssize_t debussy_i2s3_loopback(struct file* file,
	const char __user* user_buf,
	size_t count, loff_t* ppos);
static const struct file_operations debussy_i2s3_loopback_fops = {
	.open = simple_open,
	.write = debussy_i2s3_loopback,
};

static ssize_t debussy_chip_reset(struct file* file,
	const char __user* user_buf,
	size_t count, loff_t* ppos);
#ifdef SHUTDOWNDEBUSSY
static ssize_t debussy_chip_shutdown(struct file* file,
	const char __user* user_buf,
	size_t count, loff_t* ppos);
#endif
static const struct file_operations debussy_reset_chip_fops = {
	.open = simple_open,
	.write = debussy_chip_reset,
};
#ifdef SHUTDOWNDEBUSSY
static const struct file_operations debussy_shutdown_chip_fops = {
	.open = simple_open,
	.write = debussy_chip_shutdown,
};

#endif
static const struct i2c_device_id debussy_i2c_id[] = {
	{ "debussy", 0 },
	{}
};
MODULE_DEVICE_TABLE(i2c, debussy_i2c_id);

static const struct of_device_id debussy_of_match[] = {
	{.compatible = "intelligo,debussy" },
	{},
};
MODULE_DEVICE_TABLE(of, debussy_of_match);

static int debussy_i2c_write(struct i2c_client* client, unsigned int reg, unsigned int* data, unsigned int len);
static int debussy_i2c_read(struct i2c_client* client, unsigned int addr, unsigned int* value);
static void debussy_reset_chip(struct debussy_priv* debussy);
static void debussy_fw_chk(struct debussy_priv *debussy);

static ssize_t debussy_download_firmware(struct file* file,
	const char __user* user_buf,
	size_t count, loff_t* ppos)
{
	struct debussy_priv* debussy;

	debussy = file->private_data;
	dev_info(debussy->dev, "%s\n", __func__);

	queue_work(debussy->debussy_wq, &debussy->init_work);

	return count;
}

static ssize_t debussy_dmic_bypass(struct file* file,
	const char __user* user_buf,
	size_t count, loff_t* ppos)
{
	struct debussy_priv* debussy;
	struct i2c_client* client;
	unsigned int data;

	debussy = file->private_data;
	dev_info(debussy->dev, "%s\n", __func__);
	client = to_i2c_client(debussy->dev);
	data = 0;
	debussy_i2c_write(client, 0x2A00003C, &data, 1);
	data = 1;
	debussy_i2c_write(client, 0x2A000018, &data, 1);
	data = 0x10300;
	debussy_i2c_write(client, 0x2A011070, &data, 1);
	data = 0x1010000;
	debussy_i2c_write(client, 0x2A011098, &data, 1);
	data = 0x1000000;
	debussy_i2c_write(client, 0x2A0110A8, &data, 1);
	data = 0xFFFFFFFF;
	debussy_i2c_write(client, 0x2A014008, &data, 1);
	data = 0x40000;
	debussy_i2c_write(client, 0x2A014084, &data, 1);

	return count;
}

static ssize_t debussy_dmic_sw_bypass(struct file* file,
	const char __user* user_buf,
	size_t count, loff_t* ppos)
{
	struct debussy_priv* debussy;
	struct i2c_client* client;
	unsigned int data;

	debussy = file->private_data;
	dev_info(debussy->dev, "%s\n", __func__);
	client = to_i2c_client(debussy->dev);
	data = 1;
	debussy_i2c_write(client, 0x2A0141C0, &data, 1);
	data = 1;
	debussy_i2c_write(client, 0x2A0160C4, &data, 1);

	return count;
}

static ssize_t debussy_i2s0_loopback(struct file* file,
				     const char __user* user_buf,
				     size_t count, loff_t* ppos)
{
	struct debussy_priv* debussy;
	struct i2c_client* client;
	unsigned int data;

	debussy = file->private_data;
	dev_info(debussy->dev, "%s\n", __func__);
	client = to_i2c_client(debussy->dev);
	data = 0;
	debussy_i2c_write(client, 0x2A00003C, &data, 1);
	data = 1;
	debussy_i2c_write(client, 0x2A000018, &data, 1);
	data = 1;
	debussy_i2c_write(client, 0x2A000030, &data, 1);
	msleep(500);
	data = 0x830001;
	debussy_i2c_write(client, 0x2A00003C, &data, 1);
	data = 0;
	debussy_i2c_write(client, 0x2A011070, &data, 1);
	data = 0x1000000;
	debussy_i2c_write(client, 0x2A011088, &data, 1);
	data = 0x3;
	debussy_i2c_write(client, 0x2A014020, &data, 1);

	return count;
}

static ssize_t debussy_i2s3_loopback(struct file* file,
				     const char __user* user_buf,
				     size_t count, loff_t* ppos)
{
	struct debussy_priv* debussy;
	struct i2c_client* client;
	unsigned int data;

	debussy = file->private_data;
	dev_info(debussy->dev, "%s\n", __func__);
	client = to_i2c_client(debussy->dev);
	data = 0;
	debussy_i2c_write(client, 0x2A00003C, &data, 1);
	data = 1;
	debussy_i2c_write(client, 0x2A000018, &data, 1);
	data = 1;
	debussy_i2c_write(client, 0x2A000030, &data, 1);
	msleep(500);
	data = 0x830001;
	debussy_i2c_write(client, 0x2A00003C, &data, 1);
	data = 0x01000000;
	debussy_i2c_write(client, 0x2A011070, &data, 1);
	data = 0x1000000;
	debussy_i2c_write(client, 0x2A0110B8, &data, 1);
	data = 0x3;
	debussy_i2c_write(client, 0x2A014038, &data, 1);

	return count;
}

static ssize_t debussy_chip_reset(struct file* file,
				  const char __user* user_buf,
				  size_t count, loff_t* ppos)
{
	struct debussy_priv* debussy;
	unsigned int data;
	char *kbuf;
	int rc;

	debussy = file->private_data;
	dev_info(debussy->dev, "%s\n", __func__);

	kbuf = kzalloc(count, GFP_KERNEL);
	if (!kbuf) {
		dev_err(debussy->dev, "alloc kbuf failed.\n");
		return -ENOMEM;
	}

	rc = simple_write_to_buffer(kbuf, count, ppos, user_buf, count);
	if (rc != count) {
		kfree(kbuf);
		return -EIO;
	}

	rc = sscanf(kbuf, "%d", &data);
	kfree(kbuf);

	if (data == 1)
		debussy_reset_chip(debussy);

	return count;
}
#ifdef SHUTDOWNDEBUSSY
static int debussy_disable_vreg(struct device *dev, struct debussy_vreg *vreg);
static int debussy_enable_vreg(struct device *dev, struct debussy_vreg *vreg);
static void debussy_reset_chip(struct debussy_priv* debussy);

static ssize_t debussy_chip_shutdown(struct file* file,
				  const char __user* user_buf,
				  size_t count, loff_t* ppos)
{
	struct debussy_priv* debussy;
	unsigned int data;
	char *kbuf;
	int rc;

	debussy = file->private_data;
	dev_info(debussy->dev, "%s\n", __func__);

	kbuf = kzalloc(count, GFP_KERNEL);
	if (!kbuf) {
		dev_err(debussy->dev, "alloc kbuf failed.\n");
		return -ENOMEM;
	}
	
	rc = simple_write_to_buffer(kbuf, count, ppos, user_buf, count);
		if (rc != count) {
			kfree(kbuf);
			return -EIO;
		}
	rc = sscanf(kbuf, "%d", &data);
	kfree(kbuf);
	if (data == 1){
		gpio_direction_output(debussy->reset_gpio, 0);
		debussy_disable_vreg(debussy->dev, &debussy->avdd);
		//pinctrl_select_state(debussy->iovdd_pinctrl, debussy->iovdd_disable);
		debussy_disable_vreg(debussy->dev, &debussy->dvdd);
	}
	else
	{
		debussy_enable_vreg(debussy->dev, &debussy->dvdd);
		//pinctrl_select_state(debussy->iovdd_pinctrl, debussy->iovdd_enable);
		debussy_enable_vreg(debussy->dev, &debussy->avdd);
		debussy_reset_chip(debussy);
	}

	return count;
}
#endif
static int debussy_i2c_write(struct i2c_client* client, unsigned int reg, unsigned int* data, unsigned int len)

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
static int debussy_i2c_read(struct i2c_client* client, unsigned int addr, unsigned int* value)
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

static int debussy_hw_params(struct snd_pcm_substream* substream,
	struct snd_pcm_hw_params* params, struct snd_soc_dai* dai)
{
	return 0;
}

static int debussy_set_dai_fmt(struct snd_soc_dai* dai, unsigned int fmt)
{
	return 0;
}

static int debussy_set_dai_sysclk(struct snd_soc_dai* dai,
	int clk_id, unsigned int freq, int dir)
{
	return 0;
}

static int debussy_set_dai_pll(struct snd_soc_dai* dai, int pll_id, int source,
	unsigned int freq_in, unsigned int freq_out)
{
	return 0;
}

static int debussy_nr_uplink_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	struct debussy_priv* debussy;

	dev_info(codec->dev, "%s \n", __func__);
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->dsp_state_lock);
	ucontrol->value.integer.value[0] = debussy->uplink_nr_state;
	mutex_unlock(&debussy->dsp_state_lock);

	return 0;
}

static int debussy_nr_uplink_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	struct debussy_priv* debussy;
	struct i2c_client* client;
	unsigned int val = 0, tmp, mask, setVal;
	unsigned data;

	dev_info(codec->dev, "%s \n", __func__);

	debussy = dev_get_drvdata(codec->dev);
	client = to_i2c_client(codec->dev);
	debussy_i2c_read(client, 0x2A0150C0, &val);
	mask = 0x00000001 << 1;
	mutex_lock(&debussy->dsp_state_lock);
	if (ucontrol->value.integer.value[0] == DEBUSSY_NR_OFF) {
		setVal = 0x00000000;
		debussy->uplink_nr_state = DEBUSSY_NR_OFF;
	} else {
		data = 1;
		debussy_i2c_write(client, 0x2A0160C4, &data, 1);
		setVal = mask;
		debussy->uplink_nr_state = DEBUSSY_NR_ON;
	}
	mutex_unlock(&debussy->dsp_state_lock);
	tmp = val & ~mask;
	tmp |= setVal & mask;
	debussy_i2c_write(client, 0x2A0150C0, &tmp, 1);
	dev_info(codec->dev, "%s: orig = 0x%08x\n", __func__, val);

	return 0;
}

static int debussy_nr_downlink_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	struct debussy_priv* debussy;

	dev_info(codec->dev, "%s \n", __func__);
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->dsp_state_lock);
	ucontrol->value.integer.value[0] = debussy->downlink_nr_state;
	mutex_unlock(&debussy->dsp_state_lock);

	return 0;
}

static int debussy_nr_downlink_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	struct debussy_priv* debussy;
	struct i2c_client* client;
	unsigned int val = 0, tmp, mask, setVal;
	unsigned int data;

	dev_info(codec->dev, "%s \n", __func__);
	debussy = dev_get_drvdata(codec->dev);
	client = to_i2c_client(codec->dev);
	debussy_i2c_read(client, 0x2A0150C0, &val);
	mask = 0x00000001 << 0;
	mutex_lock(&debussy->dsp_state_lock);
	if (ucontrol->value.integer.value[0] == DEBUSSY_NR_OFF) {
		setVal = 0x00000000;
		debussy->downlink_nr_state = DEBUSSY_NR_OFF;
	} else {
		data = 1;
		debussy_i2c_write(client, 0x2A0160C4, &data, 1);
		setVal = mask;
		debussy->downlink_nr_state = DEBUSSY_NR_ON;
	}
	mutex_unlock(&debussy->dsp_state_lock);
	tmp = val & ~mask;
	tmp |= setVal & mask;
	debussy_i2c_write(client, 0x2A0150C0, &tmp, 1);

	dev_info(codec->dev, "%s: orig = 0x%08x\n", __func__, val);
	return 0;
}

static const char* debussy_mode[] = {
	"OFF",
	"ON",
};

static const struct soc_enum debussy_on_off_enum =
	SOC_ENUM_SINGLE_EXT(ARRAY_SIZE(debussy_mode), debussy_mode);

static const struct snd_kcontrol_new debussy_snd_controls[] = {
	SOC_ENUM_EXT("DEBUSSY_NR_DOWNLINK", debussy_on_off_enum,
		debussy_nr_downlink_get, debussy_nr_downlink_put),

	SOC_ENUM_EXT("DEBUSSY_NR_UPLINK", debussy_on_off_enum,
		debussy_nr_uplink_get, debussy_nr_uplink_put),
};

static const struct snd_soc_dai_ops debussy_aif_dai_ops = {
	.hw_params = debussy_hw_params,
	.set_fmt = debussy_set_dai_fmt,
	.set_sysclk = debussy_set_dai_sysclk,
	.set_pll = debussy_set_dai_pll,
};

static struct snd_soc_dai_driver debussy_dai[] = {
	{
		.name = "debussy-aif",
		.id = DEBUSSY_AIF,
		.playback = {
			.stream_name = "AIF Playback",
			.channels_min = 1,
			.channels_max = 2,
			.rates = DEBUSSY_RATES,
			.formats = DEBUSSY_FORMATS,
		},
		.capture = {
			.stream_name = "AIF Capture",
			.channels_min = 1,
			.channels_max = 2,
			.rates = DEBUSSY_RATES,
			.formats = DEBUSSY_FORMATS,
		},
		.ops = &debussy_aif_dai_ops,
	},
};

static int debussy_probe(struct snd_soc_codec* codec)
{
	struct debussy_priv* debussy;

	pr_info("%s\n", __func__);
	debussy = dev_get_drvdata(codec->dev);

	snd_soc_add_codec_controls(codec,
		debussy_snd_controls,
		ARRAY_SIZE(debussy_snd_controls));

	debussy_fw_chk(debussy);

	return 0;
}

static int debussy_remove(struct snd_soc_codec* codec)
{
	pr_info("%s\n", __func__);

	return 0;
}

static struct snd_soc_codec_driver soc_codec_dev_debussy = {
	.probe = debussy_probe,
	.remove = debussy_remove,
};

static void debussy_flash_control(struct device* dev, unsigned int cmd, unsigned int faddr,
	unsigned int baddr, unsigned int len, unsigned int f2b)
{
	struct i2c_client* client;

	client = to_i2c_client(dev);

	if (client != NULL) {
		debussy_i2c_write(client, 0x2A013024, &cmd, 1);
		debussy_i2c_write(client, 0x2A013028, &faddr, 1);
		debussy_i2c_write(client, 0x2A01302C, &baddr, 1);
		debussy_i2c_write(client, 0x2A013030, &len, 1);
		debussy_i2c_write(client, 0x2A013034, &f2b, 1);
	}
}

static unsigned int debussy_flash_readStatus(struct device* dev, unsigned int cmd)
{
	unsigned int ret = 0;
	struct i2c_client* client;

	client = to_i2c_client(dev);

	if (client != NULL) {
		debussy_flash_control(dev, 0x410A0000 + cmd, 0, 0x2A0C0000, 4, 1);
		debussy_i2c_read(client, 0x2A0C0000, &ret);
	} else
		ret = 0;

	return ret;
}

static void debussy_flash_pollingDone(struct device* dev)
{
	int count;
	unsigned int ret = 0;

	count = 0;
	while (count < 20) {
		ret = debussy_flash_readStatus(dev, 0x05);
		if ((ret & 0x1) == 0x0)
			break;
		usleep_range(10, 15);
		count++;
	}
	if (count == 20)
		printk("debussy: wait flash complete timeout\n");
}

static void debussy_flash_wren(struct device* dev)
{
	debussy_flash_control(dev, 0x400E0006, 0, 0, 0, 0);
}

static void debussy_flash_erase(struct device* dev, unsigned int faddr)
{
	debussy_flash_wren(dev);
	debussy_flash_control(dev, 0x500E0020, faddr, 0, 0, 0);
	debussy_flash_pollingDone(dev);
}

static void debussy_flash_writepage(struct device* dev, unsigned int faddr, unsigned int* data)
{
	unsigned int cmd;
	int is_ignore, i;
	struct i2c_client* client;

	client = to_i2c_client(dev);

	cmd = 0x530C0032;
	is_ignore = 1;

	for (i = 0; i < 64; ++i) {
		if (data[i] != 0xffffffff)
			is_ignore = 0;
	}

	if (!is_ignore) {
		debussy_flash_wren(dev);
		debussy_i2c_write(client, 0x2A0C0004, data, 32);
		debussy_i2c_write(client, 0x2A0C0004 + 32 * 4, data + 32, 32);
		debussy_flash_control(dev, cmd, faddr, 0x2A0C0004, 256, 0);
		debussy_flash_pollingDone(dev);
	}
}

static int write_bin(struct device* dev, unsigned int faddr, const u8* data, size_t size)
{
	int page_num, left_cnt;
	int idx, i, j;
	int write_cnt;
	unsigned int wdata[64];

	write_cnt = 0;
	page_num = (size / sizeof(char)) / 256;
	left_cnt = (size / sizeof(char)) % 256;
	printk("write_bin page_num = %d and left_cnt = %d\n", page_num, left_cnt);
	for (i = 0; i < page_num; ++i) {
		for (j = 0; j < 64; ++j) {
			idx = i * 256 + j * 4;
			wdata[j] = (data[idx + 3] << 24) | (data[idx + 2] << 16) | (data[idx + 1] << 8) | (data[idx]);
		}

		if ((faddr + write_cnt) % 4096 == 0) {
			//	printk("debussy to flash erase\n");
			debussy_flash_erase(dev, faddr + write_cnt);
		}
		//printk("debussy to flash writepage\n");
		debussy_flash_writepage(dev, faddr + write_cnt, wdata);
		write_cnt += 256;
	}
	if (left_cnt != 0) {
		memset(wdata, 0xff, sizeof(wdata));
		for (j = 0; j < (left_cnt / 4); ++j) {
			idx = i * 256 + j * 4;
			wdata[j] = (data[idx + 3] << 24) | (data[idx + 2] << 16) | (data[idx + 1] << 8) | (data[idx]);
		}

		if ((faddr + write_cnt) % 4096 == 0) {
			//	printk("debussy to flash erase\n");
			debussy_flash_erase(dev, faddr + write_cnt);
		}
		//printk("debussy flash write page\n");
		debussy_flash_writepage(dev, faddr + write_cnt, wdata);
	}

	return 0;
}

static void debussy_load_firmware(struct work_struct* work)
{
	const struct firmware* fw;
	char* fw_path;
	char* fw_name = "debussy.bin";
	int ret;
	struct debussy_priv* debussy;
	unsigned int addr = 0x00000;
	struct i2c_client* client;
	unsigned int fw_ver;
	unsigned int data;
	unsigned int regVal;

	debussy = container_of(work, struct debussy_priv, init_work);
	client = to_i2c_client(debussy->dev);

	fw_path = kzalloc(FW_NAME_SIZE, GFP_KERNEL);
	if (!fw_path) {
		dev_err(debussy->dev, "%s: Failed to allocate fw_path\n",
			__func__);
		goto out;
	}

	scnprintf(fw_path, FW_NAME_SIZE,
		"%s%s", FW_PATH, fw_name);
	dev_info(debussy->dev, "debussy fw name =%s", fw_path);

	ret = request_firmware(&fw, fw_path, debussy->dev);
	if (ret) {
		dev_err(debussy->dev,
			"%s: Failed to locate firmware %s errno = %d\n",
			__func__, fw_path, ret);
		goto out;
	}

#define FW_VER_OFFSET 0x00002014
	dev_info(debussy->dev, "%s size = %d\n", fw_path, (int)(fw->size));
	fw_ver = *(unsigned int*)&fw->data[FW_VER_OFFSET];
	dev_info(debussy->dev, "BIN VER: 0x%08X\n", fw_ver);

	debussy_i2c_read(client, 0x0A000200, &data );
	dev_info(debussy->dev, "CHIP VER: 0x%08X\n", data);

	/* Update firmware init sequence */
	data = 0;
	debussy_i2c_write(client, 0x2A00003C, &data, 1);
	data = 1;
	debussy_i2c_write(client, 0x2A000018, &data, 1);
	data = 1;
	ret = debussy_i2c_write(client, 0x2A000030, &data, 1);
	msleep(500);
	data = 0x830001;
	debussy_i2c_write(client, 0x2A00003C, &data, 1);
	data = 0x4;
	debussy_i2c_write(client, 0x2A013020, &data, 1);
	data = 0x5500;
	debussy_i2c_write(client, 0x2A0130C8, &data, 1);
	data = 0x0;
	debussy_i2c_write(client, 0x2A013048, &data, 1);

	write_bin(debussy->dev, addr, fw->data, fw->size);

	data = 0;
	debussy_i2c_write(client, 0x2A000018, &data, 1);

	usleep_range(10, 15);

	debussy_i2c_read(client, 0x0A018FFC, &regVal);

	printk("debussy FW check register val after download  = 0x%08x\n", regVal);

out:
	release_firmware(fw);
}

static void debussy_fw_chk(struct debussy_priv *debussy)
{
	const struct firmware* fw;
	char* fw_path;
	char* fw_name = "debussy.bin";
	int ret;
	unsigned int addr = 0x00000;
	struct i2c_client* client;
	unsigned int fw_ver;
	unsigned int data;
	unsigned int regVal;

	client = to_i2c_client(debussy->dev);

	fw_path = kzalloc(FW_NAME_SIZE, GFP_KERNEL);
	if (!fw_path) {
		dev_err(debussy->dev, "%s: Failed to allocate fw_path\n",
			__func__);
		return;
	}

	scnprintf(fw_path, FW_NAME_SIZE,
		"%s%s", FW_PATH, fw_name);
	dev_info(debussy->dev, "debussy fw name =%s", fw_path);

	ret = request_firmware(&fw, fw_path, debussy->dev);
	if (ret) {
		dev_err(debussy->dev,
			"%s: Failed to locate firmware %s errno = %d\n",
			__func__, fw_path, ret);
		goto out;
	}

#define FW_VER_OFFSET 0x00002014
	dev_info(debussy->dev, "%s size = %d\n", fw_path, (int)(fw->size));
	fw_ver = *(unsigned int*)&fw->data[FW_VER_OFFSET];
	dev_info(debussy->dev, "BIN VER: 0x%08X\n", fw_ver);

	debussy_i2c_read(client, 0x0A000200, &data );
	dev_info(debussy->dev, "CHIP VER: 0x%08X\n", data);

	if (fw_ver > data) {
		dev_info(debussy->dev, "Update FW to 0x%08x\n", fw_ver);

		/* Update firmware init sequence */
		data = 0;
		debussy_i2c_write(client, 0x2A00003C, &data, 1);
		data = 1;
		debussy_i2c_write(client, 0x2A000018, &data, 1);
		data = 1;
		ret = debussy_i2c_write(client, 0x2A000030, &data, 1);
		msleep(500);
		data = 0x830001;
		debussy_i2c_write(client, 0x2A00003C, &data, 1);
		data = 0x4;
		debussy_i2c_write(client, 0x2A013020, &data, 1);
		data = 0x5500;
		debussy_i2c_write(client, 0x2A0130C8, &data, 1);
		data = 0x0;
		debussy_i2c_write(client, 0x2A013048, &data, 1);

		write_bin(debussy->dev, addr, fw->data, fw->size);

		data = 0;
		debussy_i2c_write(client, 0x2A000018, &data, 1);

		usleep_range(10, 15);

		debussy_i2c_read(client, 0x0A018FFC, &regVal);

		printk("debussy FW check register val after download  = 0x%08x\n", regVal);

	} else {
		dev_info(debussy->dev, "Use chip built-in FW\n");
	}

	release_firmware(fw);

out:
	kfree(fw_path);
}

static int debussy_debufs_init(struct debussy_priv* debussy)
{
	int ret;

	struct dentry* dir;

	dir = debugfs_create_dir("debussy", NULL);
	if (IS_ERR_OR_NULL(dir)) {
		dir = NULL;
		ret = -ENODEV;
		goto err_create_dir;
	}

	if (!debugfs_create_file("download_firmware", S_IRUGO | S_IWUGO,
			dir, debussy, &debussy_download_firmware_fops)) {
		dev_err(debussy->dev, "%s: Failed to create debugfs node %s\n",
			__func__, "download_firmware");
		ret = -ENODEV;
		goto err_create_entry;
	}

	if (!debugfs_create_file("bypass_dmic", S_IRUGO | S_IWUGO,
			dir, debussy, &debussy_dmic_bypass_fops)) {
		dev_err(debussy->dev, "%s: Failed to create debugfs node %s\n",
			__func__, "bypass_dmic");
		ret = -ENODEV;
		goto err_create_entry;
	}

	if (!debugfs_create_file("sw_bypass_dmic", S_IRUGO | S_IWUGO,
			dir, debussy, &debussy_dmic_sw_bypass_fops)) {
		dev_err(debussy->dev, "%s: Failed to create debugfs node %s\n",
			__func__, "sw_bypass_dmic");
		ret = -ENODEV;
		goto err_create_entry;
	}

	if (!debugfs_create_file("enable_i2s0_loopback", S_IRUGO | S_IWUGO,
			dir, debussy, &debussy_i2s0_loopback_fops)) {
		dev_err(debussy->dev, "%s: Failed to create debugfs node %s\n",
			__func__, "enable_i2s0_loopback");
		ret = -ENODEV;
		goto err_create_entry;
	}

	if (!debugfs_create_file("enable_i2s3_loopback", S_IRUGO | S_IWUGO,
			dir, debussy, &debussy_i2s3_loopback_fops)) {
		dev_err(debussy->dev, "%s: Failed to create debugfs node %s\n",
			__func__, "enable_i2s3_loopback");
		ret = -ENODEV;
		goto err_create_entry;
	}

	if (!debugfs_create_file("reset_chip", S_IRUGO | S_IWUGO,
			dir, debussy, &debussy_reset_chip_fops)) {
		dev_err(debussy->dev, "%s: Failed to create debugfs node %s\n",
			__func__, "reset_chip");
		ret = -ENODEV;
		goto err_create_entry;
	}
#ifdef SHUTDOWNDEBUSSY
	if (!debugfs_create_file("shutdown_chip", S_IRUGO | S_IWUGO,
			dir, debussy, &debussy_shutdown_chip_fops)) {
		dev_err(debussy->dev, "%s: Failed to create debugfs node %s\n",
			__func__, "shutdown_chip");
		ret = -ENODEV;
		goto err_create_entry;
	}
#endif
err_create_dir:
	debugfs_remove(dir);

err_create_entry:
	return ret;
}

static void debussy_reset_gpio_pull_high(struct debussy_priv *debussy, bool high)
{
	dev_dbg(debussy->dev, "%s set reset gpio to %d\n", __func__, high);

	if (high)
		gpio_direction_output(debussy->reset_gpio, 1);
	else
		gpio_direction_output(debussy->reset_gpio, 0);
}

static void debussy_reset_chip(struct debussy_priv* debussy)
{
	debussy_reset_gpio_pull_high(debussy, false);
	msleep(10);
	debussy_reset_gpio_pull_high(debussy, true);
	msleep(50);
	dev_info(debussy->dev, "reset chip succeed\n");
}

static int debussy_config_vreg(struct device *dev,
		struct debussy_vreg *vreg, bool on)
{
	int ret = 0;
	struct regulator *reg;
	int min_uV, uA_load;

	if (!vreg) {
		WARN_ON(1);
		ret = -EINVAL;
		goto out;
	}

	reg = vreg->reg;
	if (regulator_count_voltages(reg) > 0) {
		min_uV = on ? vreg->min_uV : 0;
		ret = regulator_set_voltage(reg, min_uV, vreg->max_uV);
		if (ret) {
			dev_err(dev, "%s: %s set voltage failed, err=%d\n",
					__func__, vreg->name, ret);
			goto out;
		}

		uA_load = on ? vreg->max_uA : 0;
		ret = regulator_set_load(vreg->reg, uA_load);
		if (ret)
			goto out;
	}
out:
	return ret;
}

static int debussy_enable_vreg(struct device *dev, struct debussy_vreg *vreg)
{
	int ret = 0;

	if (vreg->enabled)
		return ret;

	ret = debussy_config_vreg(dev, vreg, true);
	if (ret)
		goto out;

	ret = regulator_enable(vreg->reg);
	if (ret)
		goto out;

	vreg->enabled = true;
out:
	return ret;
}

static int debussy_disable_vreg(struct device *dev, struct debussy_vreg *vreg)
{
	int ret = 0;

	if (!vreg->enabled)
		return ret;

	ret = regulator_disable(vreg->reg);
	if (ret)
		goto out;

	ret = debussy_config_vreg(dev, vreg, false);
	if (ret)
		goto out;

	vreg->enabled = false;
out:
	return ret;
}

static int debussy_check_presence(struct i2c_client *i2c)
{
	int ret, regVal = 0;
	int i;

	ret = debussy_i2c_read(i2c, 0x0A000FF0, &regVal);
	if (ret < 0) {
		for (i = 0; i < 5; i++ ) {
			msleep(2);
			ret = debussy_i2c_read(i2c, 0x0A000FF0, &regVal);
			if (ret < 0)
				continue;
		}
	}

	if (ret < 0) {
		dev_err(&i2c->dev, "%s: Failed reading vesion: 0x%x, ret: %d\n",
			__func__, regVal, ret);
		return -EINVAL;
	} else {
		dev_info(&i2c->dev,
			"%s: Hardware fixed register 0x0A000FF0 = 0x%08x and ret = %d\n",
			__func__, regVal, ret);
		return 0;
	}
}

int debussy_get_presence(void)
{
	return presence;
}
EXPORT_SYMBOL(debussy_get_presence);

static int igo_i2c_suspend(struct device *dev)
{
	struct debussy_priv *debussy = dev_get_drvdata(dev);

	dev_dbg(dev, "%s enter.\n", __func__);

	if (debussy && debussy->power_on) {
		debussy->power_on = false;
		if (debussy->dvdd.reg) {
			debussy_disable_vreg(debussy->dev, &debussy->dvdd);
			dev_dbg(dev, "%s: dvdd disabled\n", __func__);
		}

		if (debussy->avdd.reg) {
			debussy_disable_vreg(debussy->dev, &debussy->avdd);
			dev_dbg(dev, "%s: avdd disabled\n", __func__);
		}
		debussy_reset_gpio_pull_high(debussy, false);
	}

	return 0;
}

static int igo_i2c_resume(struct device *dev)
{
	struct debussy_priv *debussy = dev_get_drvdata(dev);
	int ret;

	dev_dbg(dev, "%s enter.\n", __func__);

	if (debussy && !debussy->power_on) {
		debussy->power_on = true;

		if (debussy->dvdd.reg) {
			ret = debussy_enable_vreg(debussy->dev, &debussy->dvdd);
			if (ret)
				dev_err(dev, "%s: dvdd enable failed\n", __func__);
			else
				dev_dbg(dev, "%s: dvdd enabled\n", __func__);
		}

		if (debussy->avdd.reg) {
			ret = debussy_enable_vreg(debussy->dev, &debussy->avdd);
			if (ret)
				dev_err(dev, "%s: avdd enable failed\n", __func__);
			else
				dev_dbg(dev, "%s: avdd enabled\n", __func__);
		}

		debussy_reset_chip(debussy);
		// workaround: resume to sw bypass mode
		{
			struct i2c_client* client = to_i2c_client(debussy->dev);
			int data;
			data = 1;
			debussy_i2c_write(client, 0x2A0141C0, &data, 1);
			data = 1;
			debussy_i2c_write(client, 0x2A0160C4, &data, 1);
		}
	}
	return 0;
}

static int debussy_i2c_probe(struct i2c_client* i2c,
	const struct i2c_device_id* id)
{
	struct debussy_priv* debussy;
	struct device_node *fnode = i2c->dev.of_node;
	int ret = 0;
	unsigned int regVal;
	struct pinctrl *pinctrl;
	//struct i2c_msg xfer[2];
	//unsigned int reg;
	//unsigned char idx [4];

	//dev_set_name(&i2c->dev, "intelligo");
	dev_info(&i2c->dev, "%s \n", __func__);

	debussy = devm_kzalloc(&i2c->dev, sizeof(struct debussy_priv),
		GFP_KERNEL);
	if (!debussy) {
		dev_err(&i2c->dev, "Failed to allocate memory\n");
		return -ENOMEM;
	}
	dev_info(&i2c->dev, "debussy p=%p\n", debussy);

	debussy->dev = &i2c->dev;
	i2c_set_clientdata(i2c, debussy);

	if (!debussy->i2c_pull) {
		debussy->i2c_pull = devm_regulator_get(&i2c->dev, "i2c-pull");
		if (IS_ERR(debussy->i2c_pull)) {
			pr_err("%s: regulator i2c_pull get failed\n ", __func__);
			return PTR_ERR(debussy->i2c_pull);
		}

		ret = regulator_enable(debussy->i2c_pull);
		if (ret) {
			pr_err("%s: regulator_enable i2c_pull failed! \n", __func__);
			return ret;
		}
	}

	pinctrl = devm_pinctrl_get(&i2c->dev);
	if (IS_ERR_OR_NULL(pinctrl)) {
		dev_err(&i2c->dev, "%s: Unable to get pinctrl handle\n", __func__);
		ret = -EINVAL;
		goto err1;
	}
	debussy->iovdd_pinctrl = pinctrl;

	/* get all the states handles from Device Tree */
	debussy->iovdd_enable = pinctrl_lookup_state(pinctrl,
						"power_up");
	if (IS_ERR(debussy->iovdd_enable)) {
		dev_err(&i2c->dev, "%s: could not get power_up pinstate\n", __func__);
		ret = -EINVAL;
		goto err1;
	}

	debussy->iovdd_disable = pinctrl_lookup_state(pinctrl,
						"power_down");
	if (IS_ERR(debussy->iovdd_disable)) {
		dev_err(&i2c->dev, "%s: could not get power_down pinstate\n", __func__);
		ret = -EINVAL;
		goto err1;
	}

	if (!debussy->dvdd.reg) {
		/*
		 * voltage: min: 1.14v  typ: 1.2v  max: 1.26v
		 * current: 80mA
		 */
		strncpy(debussy->dvdd.name, "DVDD", sizeof(debussy->dvdd.name));
		debussy->dvdd.reg = devm_regulator_get(&i2c->dev, "dvdd");
		if (IS_ERR(debussy->dvdd.reg)) {
			dev_err(&i2c->dev, "%s: regulator %s get failed\n", __func__,
				debussy->dvdd.name);
			return PTR_ERR(debussy->dvdd.reg);
		}
		debussy->dvdd.min_uV = DVDD_MIN_UV;
		debussy->dvdd.max_uV = DVDD_MAX_UV;
		debussy->dvdd.min_uA = DVDD_UA;
		debussy->dvdd.max_uA = DVDD_UA;
		debussy->dvdd.enabled = false;
	}

	if (!debussy->avdd.reg) {
		/*
		 * min: 2.6v  typ: 2.8v  max: 3.0v
		 * current: 10mA
		 */
		strncpy(debussy->avdd.name, "AVDD28", sizeof(debussy->avdd.name));
		debussy->avdd.reg = devm_regulator_get(&i2c->dev, "avdd");
		if (IS_ERR(debussy->avdd.reg)) {
			dev_err(&i2c->dev, "%s: regulator %s get failed\n", __func__,
				debussy->avdd.name);
			return PTR_ERR(debussy->avdd.reg);
		}
		debussy->avdd.min_uV = AVDD_MIN_UV;
		debussy->avdd.max_uV = AVDD_MAX_UV;
		debussy->avdd.min_uA = AVDD_UA;
		debussy->avdd.max_uA = AVDD_UA;
		debussy->avdd.enabled = false;
	}

	ret = debussy_enable_vreg(&i2c->dev, &debussy->dvdd);
	if (ret) {
		dev_err(&i2c->dev, "enable %s failed.\n", debussy->dvdd.name);
		goto err1;
	}

	ret = pinctrl_select_state(pinctrl, debussy->iovdd_enable);
	if (ret != 0) {
		dev_err(&i2c->dev, "%s: enable iovdd enable pin failed with %d\n",
			__func__, ret);
		ret = -EIO;
		goto err2;
	}

	ret = debussy_enable_vreg(&i2c->dev, &debussy->avdd);
	if (ret) {
		dev_err(&i2c->dev, "enable %s failed.\n", debussy->avdd.name);
		goto err3;
	}

	debussy->power_on = true;
	msleep(1);

	debussy->reset_gpio = of_get_named_gpio(fnode, "reset-gpio", 0);
	if (gpio_is_valid(debussy->reset_gpio)) {
		dev_info(&i2c->dev, "Get reset gpio: %d\n", debussy->reset_gpio);
	} else {
		dev_err(&i2c->dev, "Get reset gpio failed: %d\n", debussy->reset_gpio);
		ret = -EINVAL;
		goto err4;
	}

	ret = devm_gpio_request(&i2c->dev, debussy->reset_gpio, "intelligo_reset_gpio");
	if (ret) {
		dev_err(&i2c->dev, "%s request gpio %d failed: %d\n", __func__,
			debussy->reset_gpio, ret);
		goto err4;
	}

	debussy_reset_chip(debussy);

	ret = debussy_check_presence(i2c);
	if (ret < 0)
		goto err4;

	presence = 1;

	debussy->debussy_wq = create_singlethread_workqueue("debussy");
	if (debussy->debussy_wq == NULL) {
		ret = -ENOMEM;
		goto err4;
	}
	INIT_WORK(&debussy->init_work, debussy_load_firmware);

	debussy_debufs_init(debussy);

	debussy_i2c_read(i2c, 0x2A0150C0, &regVal);
	mutex_init(&debussy->dsp_state_lock);
	mutex_lock(&debussy->dsp_state_lock);
	debussy->dsp_state = STATE_BOOT;
	debussy->downlink_nr_state = (regVal & 0x1) ? DEBUSSY_NR_ON : DEBUSSY_NR_OFF;
	debussy->uplink_nr_state = (regVal & (0x1 << 1)) ? DEBUSSY_NR_ON : DEBUSSY_NR_OFF;
	debussy->dmic_bypass_state = DEBUSSY_DMIC_BYPASS;
	mutex_unlock(&debussy->dsp_state_lock);

	ret = snd_soc_register_codec(&i2c->dev, &soc_codec_dev_debussy,
		debussy_dai, ARRAY_SIZE(debussy_dai));

	return 0;

err4:
	debussy_disable_vreg(&i2c->dev, &debussy->avdd);
err3:
	//pinctrl_select_state(pinctrl, debussy->iovdd_disable);
err2:
	debussy_disable_vreg(&i2c->dev, &debussy->dvdd);
err1:
	if (debussy->i2c_pull)
		regulator_disable(debussy->i2c_pull);
	return ret;
}

static int debussy_i2c_remove(struct i2c_client* i2c)
{
	struct debussy_priv* debussy = i2c_get_clientdata(i2c);

	snd_soc_unregister_codec(&i2c->dev);
	destroy_workqueue(debussy->debussy_wq);
	debussy_disable_vreg(&i2c->dev, &debussy->dvdd);
	//pinctrl_select_state(debussy->iovdd_pinctrl, debussy->iovdd_disable);
	debussy_disable_vreg(&i2c->dev, &debussy->avdd);

	if (debussy->i2c_pull)
		regulator_disable(debussy->i2c_pull);

	return 0;
}

static const struct dev_pm_ops igo_i2c_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(igo_i2c_suspend, igo_i2c_resume)
};

static struct i2c_driver debussy_i2c_driver = {
	.driver = {
		.name = "debussy",
		.owner = THIS_MODULE,
		.of_match_table = of_match_ptr(debussy_of_match),
		.pm = &igo_i2c_pm_ops,
	},
	.probe = debussy_i2c_probe,
	.remove = debussy_i2c_remove,
	.id_table = debussy_i2c_id,
};
module_i2c_driver(debussy_i2c_driver);

MODULE_DESCRIPTION("Debussy driver");
MODULE_LICENSE("GPL v2");
