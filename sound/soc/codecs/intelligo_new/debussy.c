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
#include <linux/clk.h>
#include <sound/core.h>
#include <sound/initval.h>
#include <sound/pcm.h>
#include <sound/pcm_params.h>
#include <sound/soc.h>
#include <sound/tlv.h>
#include "debussy.h"
#include "debussy_intf.h"
#include "debussy_snd_ctrl.h"

#define DEBUSSY_FW_PATH "./"
#define DEBUSSY_FW_ADDR (0x0)
#define DEBUSSY_FW_NAME_SIZE (256)
#define DEBUSSY_FW_VER_OFFSET (0x00002014)
#define DEBUSSY_RATES SNDRV_PCM_RATE_48000
#define DEBUSSY_FORMATS (SNDRV_PCM_FMTBIT_S16_LE | SNDRV_PCM_FMTBIT_S24_LE)
#define DEBUSSY_FLASH_PAGE_SZ (4096)
#define DEBUSSY_FLASH_SECTOR_SZ (65536)
#define DEBUSSY_FLASH_POLLING_CNT (300 * 1000 / 20)     // about 300ms
#define DEBUSSY_FLASH_ERASE_BY_SECTOR

#define DVDD_MIN_UV        1200000
#define DVDD_MAX_UV        1260000
#define DVDD_UA            80000

#define IOVDD_MIN_UV       1800000
#define IOVDD_MAX_UV       1900000
#define IOVDD_UA           10000

#define AVDD_MIN_UV        2800000
#define AVDD_MAX_UV        3000000
#define AVDD_UA            10000

/* IOCTL CMD */
#define INTELLIGO_IOCTL_GET_CHIP_VERSION	_IOR('I', 0x00, int)
#define INTELLIGO_IOCTL_GET_FW_VERSION		_IOR('I', 0x01, int)
#define INTELLIGO_IOCTL_RESET_CHIP		_IO('I', 0x02)
#define INTELLIGO_IOCTL_HW_BYPASS		_IO('I', 0x03)
#define INTELLIGO_IOCTL_SW_BYPASS		_IO('I', 0x04)
#define INTELLIGO_IOCTL_DAI0_LOOPBACK		_IO('I', 0x05)
#define INTELLIGO_IOCTL_DAI3_LOOPBACK		_IO('I', 0x06)

static unsigned int presence = 0;
static unsigned int igo_status = POWER_MODE_STANDBY;

static ssize_t debussy_download_firmware(struct file* file,
	const char __user* user_buf,
	size_t count, loff_t* ppos);
static const struct file_operations debussy_download_firmware_fops = {
	.open = simple_open,
	.write = debussy_download_firmware,
};

static int debussy_disable_vreg(struct device *dev, struct debussy_vreg *vreg);
static int debussy_enable_vreg(struct device *dev, struct debussy_vreg *vreg);
static int debussy_check_presence(struct i2c_client *i2c);
static void debussy_reset_gpio_pull_high(struct debussy_priv *debussy, bool high);

static ssize_t debussy_chip_reset(struct file* file,
	const char __user* user_buf,
	size_t count, loff_t* ppos);

static const struct file_operations debussy_reset_chip_fops = {
	.open = simple_open,
	.write = debussy_chip_reset,
};

static const struct i2c_device_id igo_i2c_id[] = {
	{ "debussy", 0 },
	{}
};
MODULE_DEVICE_TABLE(i2c, igo_i2c_id);

static const struct of_device_id debussy_of_match[] = {
	{ .compatible = "intelligo,debussy" },
	{},
};
MODULE_DEVICE_TABLE(of, debussy_of_match);

static ssize_t debussy_download_firmware(struct file* file,
	const char __user* user_buf,
	size_t count, loff_t* ppos)
{
	struct debussy_priv* debussy;

	debussy = file->private_data;
	dev_info(debussy->dev, "%s\n", __func__);

	queue_work(debussy->debussy_wq, &debussy->fw_work);

	return count;
}

static ssize_t debussy_chip_reset(struct file* file,
				  const char __user* user_buf,
				  size_t count, loff_t* ppos)
{
	struct debussy_priv* debussy;
	struct i2c_client *i2c;
	unsigned int data;
	char *kbuf;
	int rc;

	debussy = file->private_data;
	i2c = debussy->i2c;
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

	switch (data)
	{
	case 1:
	{
		debussy_reset_chip(debussy, DEBUSSY_RESET_NORMAL);
		break;
	}
	case 2:
	{
		gpio_direction_output(debussy->reset_gpio, 0);
		debussy_disable_vreg(debussy->dev, &debussy->avdd);
		debussy_disable_vreg(debussy->dev, &debussy->dvdd);
		break;
	}
	case 3:
	{
		debussy_enable_vreg(debussy->dev, &debussy->dvdd);
		debussy_enable_vreg(debussy->dev, &debussy->avdd);
		debussy_reset_chip(debussy, DEBUSSY_RESET_NORMAL);
		break;
	}
	default:
		return -EINVAL;
	}

	return count;
}

static int debussy_mclk_enable(struct debussy_priv *debussy, bool enable)
{
	int ret;
	bool mclk_force_enable = debussy->force_enable_mclk;

	mutex_lock(&debussy->mclk_lock);

	dev_dbg(debussy->dev, "%s enter, %s mclk\n", __func__,
		enable ? "enable" : "disable");

	if (enable) {
		if (atomic_read(&debussy->mclk_on)) {
			dev_info(debussy->dev, "%s: mclk is already enabled\n",
				__func__);
			goto out;
		}

		ret = clk_prepare_enable(debussy->mclk);
		if (ret) {
			dev_err(debussy->dev, "%s: Couldn't enable the mclk clock: %d\n",
				__func__, ret);
			goto err1;
		}

		ret = pinctrl_select_state(debussy->igo_pinctrl, debussy->mclk_enable);
		if (ret) {
			dev_err(debussy->dev, "%s: enable mclk failed with %d\n",
				__func__, ret);
			goto err2;
		}
		atomic_set(&debussy->mclk_on, 1);
	} else if (!mclk_force_enable && atomic_read(&debussy->mclk_on)) {
		pinctrl_select_state(debussy->igo_pinctrl, debussy->mclk_disable);
		clk_disable_unprepare(debussy->mclk);
		atomic_set(&debussy->mclk_on, 0);
	}

out:
	mutex_unlock(&debussy->mclk_lock);

	return 0;
err2:
	clk_disable_unprepare(debussy->mclk);
err1:
	mutex_unlock(&debussy->mclk_lock);
	return ret;
}

static int debussy_get_reference(struct debussy_priv *debussy, int id, int stream)
{
	atomic_inc(&debussy->dai_ref[id].ch_ref[stream]);
	return atomic_inc_return(&debussy->ref_count[id]);
}

static int debussy_put_reference(struct debussy_priv *debussy, int id, int stream)
{
	atomic_dec(&debussy->dai_ref[id].ch_ref[stream]);
	return atomic_dec_and_test(&debussy->ref_count[id]);
}

static int debussy_startup (struct snd_pcm_substream *substream, struct snd_soc_dai *dai)
{
	struct snd_soc_codec *codec = dai->codec;
	struct debussy_priv *debussy = snd_soc_codec_get_drvdata(codec);
	int stream = substream->stream;
	int val;

	dev_dbg(debussy->dev, "%s: %s substream, dai: %s(%d)\n", __func__,
		stream ? "capture" : "playback", dai->name, dai->id);

	val = debussy_get_reference(debussy, DEBUSSY_MAX, stream);
	if (val == 1)
		dev_dbg(debussy->dev, "enable igo chip\n");
	else
		dev_dbg(debussy->dev, "igo chip is already enabled\n");

	if (igo_status == POWER_MODE_STANDBY)
		igo_status = POWER_MODE_WORKING;

	switch (dai->id)
	{
	case DEBUSSY_AIF0:
	{
		debussy_get_reference(debussy, DEBUSSY_AIF0, stream);
		break;
	}
	case DEBUSSY_AIF3:
	{
		debussy_get_reference(debussy, DEBUSSY_AIF3, stream);
		break;
	}
	case DEBUSSY_AIF_DMIC:
	{
		debussy_get_reference(debussy, DEBUSSY_AIF_DMIC, stream);
		break;
	}
	default:
		break;
	}

	return 0;
}

static void debussy_shutdown (struct snd_pcm_substream *substream, struct snd_soc_dai *dai)
{
	struct snd_soc_codec *codec = dai->codec;
	struct debussy_priv *debussy = snd_soc_codec_get_drvdata(codec);
	int val;
	int stream = substream->stream;

	dev_dbg(debussy->dev, "%s: %s substream, dai: %s(%d)\n", __func__,
		stream ? "capture" : "playback", dai->name, dai->id);

	val = debussy_put_reference(debussy, DEBUSSY_MAX, stream);
	if (val)
		dev_dbg(debussy->dev, "disable igo chip\n");
	else
		dev_dbg(debussy->dev, "cant disable igo chip, ref_count: %d\n",
			atomic_read(&debussy->ref_count[DEBUSSY_MAX]));

	/*
	 * In order to speed up work mode switch
	 */
	if (igo_status == POWER_MODE_WORKING) {
		igo_status = POWER_MODE_STANDBY;
		debussy_set_maskconfig(debussy, 1);
	}

	switch (dai->id)
	{
	case DEBUSSY_AIF0:
	{
		debussy_put_reference(debussy, DEBUSSY_AIF0, stream);
		break;
	}
	case DEBUSSY_AIF3:
	{
		debussy_put_reference(debussy, DEBUSSY_AIF3, stream);
		break;
	}
	case DEBUSSY_AIF_DMIC:
	{
		debussy_put_reference(debussy, DEBUSSY_AIF_DMIC, stream);
		break;
	}
	default:
		break;
	}
}

static int debussy_hw_params(struct snd_pcm_substream* substream,
	struct snd_pcm_hw_params* params, struct snd_soc_dai* dai)
{
	struct snd_soc_codec *codec = dai->codec;
	struct debussy_priv *debussy = snd_soc_codec_get_drvdata(codec);

	dev_dbg(debussy->dev, "%s: %s substream, dai: %s(%d), bit_width: %d, sample_rate: %d, chan: %d\n",
		__func__, substream->stream ? "capture" : "playback", dai->name, dai->id, params_width(params),
		params_rate(params), params_channels(params));

	switch (dai->id)
	{
	case DEBUSSY_AIF0:
	{
		break;
	}
	case DEBUSSY_AIF3:
	{
		break;
	}
	case DEBUSSY_AIF_DMIC:
	{
		break;
	}
	default:
		break;
	}

	return 0;
}

static int debussy_codec_enable_mclk(struct snd_soc_dapm_widget *w,
				     struct snd_kcontrol *kcontrol,
				     int event)
{
	int ret = 0;
	struct snd_soc_codec *codec = snd_soc_dapm_to_codec(w->dapm);
	struct debussy_priv *debussy = snd_soc_codec_get_drvdata(codec);

	dev_dbg(debussy->dev, "%s enter, event: %d\n", __func__, event);

	switch (event) {
	case SND_SOC_DAPM_PRE_PMU:
		debussy_mclk_enable(debussy, true);
		break;
	case SND_SOC_DAPM_POST_PMD:
		debussy_mclk_enable(debussy, false);
		break;
	}

	return ret;
}

static int igo_dmic_mclk_switch_get(struct snd_kcontrol *kcontrol,
				struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_codec *codec = snd_soc_dapm_kcontrol_codec(kcontrol);
	struct debussy_priv *debussy = snd_soc_codec_get_drvdata(codec);

	ucontrol->value.integer.value[0] = debussy->dmic_switch;
	dev_dbg(debussy->dev, "%s: iGo Dmic Switch: %d\n", __func__,
		debussy->dmic_switch);
	return 0;
}

static int igo_dmic_mclk_switch_put(struct snd_kcontrol *kcontrol,
				struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_dapm_context *dapm = snd_soc_dapm_kcontrol_dapm(kcontrol);
	struct snd_soc_codec *codec = snd_soc_dapm_to_codec(dapm);
	struct debussy_priv *debussy = snd_soc_codec_get_drvdata(codec);
	struct snd_soc_dapm_update *update = NULL;
	int value = ucontrol->value.integer.value[0];

	dev_dbg(debussy->dev, "%s: iGo Dmic Switch: %d\n",
		__func__, value);

	if (value)
		snd_soc_dapm_mixer_update_power(dapm, kcontrol, 1,
						update);
	else
		snd_soc_dapm_mixer_update_power(dapm, kcontrol, 0,
						update);

	debussy->dmic_switch = value;
	return 0;
}

static const struct snd_kcontrol_new igo_dmic_mclk_switch_control =
	SOC_SINGLE_EXT("Switch", SND_SOC_NOPM,
	0, 1, 0, igo_dmic_mclk_switch_get, igo_dmic_mclk_switch_put);

int (*wcd_force_enable_micbias)(int micb_num, bool enable) = NULL;
EXPORT_SYMBOL(wcd_force_enable_micbias);

static int debussy_codec_enable_bias(struct snd_soc_dapm_widget *w,
				     struct snd_kcontrol *kcontrol,
				     int event)
{
	int ret = 0;
	struct snd_soc_codec *codec = snd_soc_dapm_to_codec(w->dapm);
	struct debussy_priv *debussy = snd_soc_codec_get_drvdata(codec);

	dev_dbg(debussy->dev, "%s enter, event: %d\n", __func__, event);

	switch (event) {
	case SND_SOC_DAPM_PRE_PMU:
		/* Enable MIC_BIAS1 */
		if (wcd_force_enable_micbias)
			wcd_force_enable_micbias(1, true);
		break;
	case SND_SOC_DAPM_POST_PMD:
		/* Disable MIC_BIAS1 */
		if (wcd_force_enable_micbias)
			wcd_force_enable_micbias(1, false);
		break;
	}

	return ret;
}

static int igo_dmic_bias_switch_get(struct snd_kcontrol *kcontrol,
				struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_codec *codec = snd_soc_dapm_kcontrol_codec(kcontrol);
	struct debussy_priv *debussy = snd_soc_codec_get_drvdata(codec);

	ucontrol->value.integer.value[0] = debussy->enable_bias;
	dev_dbg(debussy->dev, "%s: iGo Dmic Bias Switch: %d\n", __func__,
		debussy->dmic_switch);
	return 0;
}

static int igo_dmic_bias_switch_put(struct snd_kcontrol *kcontrol,
				struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_dapm_context *dapm = snd_soc_dapm_kcontrol_dapm(kcontrol);
	struct snd_soc_codec *codec = snd_soc_dapm_to_codec(dapm);
	struct debussy_priv *debussy = snd_soc_codec_get_drvdata(codec);
	struct snd_soc_dapm_update *update = NULL;
	int value = ucontrol->value.integer.value[0];

	dev_dbg(debussy->dev, "%s: iGo Dmic Bias Switch: %d\n",
		__func__, value);

	if (value)
		snd_soc_dapm_mixer_update_power(dapm, kcontrol, 1,
						update);
	else
		snd_soc_dapm_mixer_update_power(dapm, kcontrol, 0,
						update);

	debussy->enable_bias = value;
	return 0;
}

static const struct snd_kcontrol_new igo_dmic_bias_switch_control =
	SOC_SINGLE_EXT("Switch", SND_SOC_NOPM,
	0, 1, 0, igo_dmic_bias_switch_get, igo_dmic_bias_switch_put);

static const struct snd_soc_dapm_widget igo_dapm_widgets[] = {
	SND_SOC_DAPM_AIF_IN("DAI0_OUT", "AIF0 Playback", 0,
		SND_SOC_NOPM, 0, 0),
	SND_SOC_DAPM_AIF_OUT("DAI0_IN", "AIF0 Capture", 0,
		SND_SOC_NOPM, 0, 0),
	SND_SOC_DAPM_AIF_IN("DAI3_OUT", "AIF3 Playback", 0,
		SND_SOC_NOPM, 0, 0),
	SND_SOC_DAPM_AIF_OUT("DAI3_IN", "AIF3 Capture", 0,
		SND_SOC_NOPM, 0, 0),
	SND_SOC_DAPM_AIF_OUT("DAI_DMIC", "AIF-DMIC Capture", 0,
		SND_SOC_NOPM, 0, 0),
	SND_SOC_DAPM_SWITCH_E("IGO_DMIC_MCLK", SND_SOC_NOPM, 0, 0,
		&igo_dmic_mclk_switch_control,
		debussy_codec_enable_mclk,
		SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMD),
	SND_SOC_DAPM_SWITCH_E("IGO_DMIC_BIAS", SND_SOC_NOPM, 0, 0,
		&igo_dmic_bias_switch_control,
		debussy_codec_enable_bias,
		SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMD),
	SND_SOC_DAPM_OUTPUT("BE_OUT"),
	SND_SOC_DAPM_INPUT("BE_IN"),
};

static const struct snd_soc_dapm_route igo_dapm_routes[] = {
	{"BE_OUT", NULL, "DAI0_OUT"},
	{"DAI0_IN", NULL, "BE_IN"},
	{"BE_OUT", NULL, "DAI3_OUT"},
	{"DAI3_IN", NULL, "IGO_DMIC_MCLK"},
	{"DAI_DMIC", NULL, "IGO_DMIC_MCLK"},
	{"DAI3_IN", NULL, "IGO_DMIC_BIAS"},
	{"IGO_DMIC_MCLK", "Switch", "BE_IN"},
	{"IGO_DMIC_BIAS", "Switch", "BE_IN"},
};

static const struct snd_soc_dai_ops debussy_aif0_dai_ops = {
	.startup = debussy_startup,
	.shutdown = debussy_shutdown,
	.hw_params = debussy_hw_params,
};

static const struct snd_soc_dai_ops debussy_aif3_dai_ops = {
	.startup = debussy_startup,
	.shutdown = debussy_shutdown,
	.hw_params = debussy_hw_params,
};

static const struct snd_soc_dai_ops debussy_aif_dmic_dai_ops = {
	.startup = debussy_startup,
	.shutdown = debussy_shutdown,
	.hw_params = debussy_hw_params,
};

static struct snd_soc_dai_driver debussy_dai[] = {
	{
		.name = "debussy-aif0",
		.id = DEBUSSY_AIF0,
		.playback = {
			.stream_name = "AIF0 Playback",
			.channels_min = 1,
			.channels_max = 2,
			.rates = DEBUSSY_RATES,
			.formats = DEBUSSY_FORMATS,
		},
		.capture = {
			.stream_name = "AIF0 Capture",
			.channels_min = 1,
			.channels_max = 2,
			.rates = DEBUSSY_RATES,
			.formats = DEBUSSY_FORMATS,
		},
		.ops = &debussy_aif0_dai_ops,
		.symmetric_rates = 1,
	},
	{
		.name = "debussy-aif3",
		.id = DEBUSSY_AIF3,
		.playback = {
			.stream_name = "AIF3 Playback",
			.channels_min = 1,
			.channels_max = 2,
			.rates = DEBUSSY_RATES,
			.formats = DEBUSSY_FORMATS,
		},
		.capture = {
			.stream_name = "AIF3 Capture",
			.channels_min = 1,
			.channels_max = 2,
			.rates = DEBUSSY_RATES,
			.formats = DEBUSSY_FORMATS,
		},
		.ops = &debussy_aif3_dai_ops,
		.symmetric_rates = 1,
	},
	{
		.name = "debussy-aif-dmic",
		.id = DEBUSSY_AIF_DMIC,
		.capture = {
			.stream_name = "AIF-DMIC Capture",
			.channels_min = 1,
			.channels_max = 2,
			.rates = DEBUSSY_RATES,
			.formats = DEBUSSY_FORMATS,
		},
		.ops = &debussy_aif_dmic_dai_ops,
	},
};

static void debussy_flash_control(struct device* dev, unsigned int cmd, unsigned int faddr,
	unsigned int baddr, unsigned int len, unsigned int f2b)
{
	struct i2c_client* client;
	u32 buf[5];

	client = to_i2c_client(dev);

	if (client != NULL) {
		buf[0] = cmd;
		buf[1] = faddr;
		buf[2] = baddr;
		buf[3] = len;
		buf[4] = f2b;
		igo_i2c_write(client, 0x2A013024, buf, 5);
	}
}

static unsigned int debussy_flash_readStatus(struct device* dev, unsigned int cmd)
{
	unsigned int ret = 0;
	struct i2c_client* client;

	client = to_i2c_client(dev);

	if (client != NULL) {
		debussy_flash_control(dev, 0x410A0000 + cmd, 0, 0x2A0C0000, 4, 1);
		igo_i2c_read(client, 0x2A0C0000, &ret);
	} else
		ret = 0;

	return ret;
}

static void debussy_flash_pollingDone(struct device* dev)
{
	int count;
	unsigned int ret = 0;

	count = 0;
	// About 150ms
	while (count < DEBUSSY_FLASH_POLLING_CNT) {
		ret = debussy_flash_readStatus(dev, 0x05);
		if ((ret & 0x1) == 0x0)
			break;
		usleep_range(10, 20);       // 20ms
		count++;
	}
	if (count == DEBUSSY_FLASH_POLLING_CNT)
		printk("debussy: wait flash complete timeout\n");
}

static void debussy_flash_wren(struct device* dev)
{
	debussy_flash_control(dev, 0x400E0006, 0, 0, 0, 0);
}

#ifndef DEBUSSY_FLASH_ERASE_BY_SECTOR
static void debussy_flash_page_erase(struct device* dev, unsigned int faddr)
{
	debussy_flash_wren(dev);
	debussy_flash_control(dev, 0x500E0020, faddr, 0, 0, 0);
	debussy_flash_pollingDone(dev);
}

#else
static void debussy_flash_sector_erase(struct device* dev, unsigned int faddr)
{
	debussy_flash_wren(dev);
	debussy_flash_control(dev, 0x500E00D8, faddr, 0, 0, 0);
	debussy_flash_pollingDone(dev);
}
#endif

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
		igo_i2c_write(client, 0x2A0C0004, data, 64);
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

	for (i = 0; i < page_num; ++i) {
		for (j = 0; j < 64; ++j) {
			idx = i * 256 + j * 4;
			wdata[j] = (data[idx + 3] << 24) | (data[idx + 2] << 16) | (data[idx + 1] << 8) | (data[idx]);
		}

#ifdef DEBUSSY_FLASH_ERASE_BY_SECTOR
		if ((faddr + write_cnt) % DEBUSSY_FLASH_SECTOR_SZ == 0) {
			//	printk("debussy to flash erase\n");
			debussy_flash_sector_erase(dev, faddr + write_cnt);
		}
#else
		if ((faddr + write_cnt) % DEBUSSY_FLASH_PAGE_SZ == 0) {
			//	printk("debussy to flash erase\n");
			debussy_flash_page_erase(dev, faddr + write_cnt);
		}
#endif
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

#ifdef DEBUSSY_FLASH_ERASE_BY_SECTOR
		if ((faddr + write_cnt) % DEBUSSY_FLASH_SECTOR_SZ == 0) {
			//	printk("debussy to flash erase\n");
			debussy_flash_sector_erase(dev, faddr + write_cnt);
		}
#else
		if ((faddr + write_cnt) % DEBUSSY_FLASH_PAGE_SZ == 0) {
			//	printk("debussy to flash erase\n");
			debussy_flash_page_erase(dev, faddr + write_cnt);
		}
#endif
		//printk("debussy flash write page\n");
		debussy_flash_writepage(dev, faddr + write_cnt, wdata);
	}

	return 0;
}

void debussy_update_firmware(struct device* dev, unsigned int faddr, const u8* data, size_t size)
{
	int ret;
	unsigned int addr = 0x00000;
	unsigned int tmp_data;
	struct i2c_client* client;

	client = to_i2c_client(dev);

	/* Update firmware init sequence */
	tmp_data = 0;
	igo_i2c_write(client, 0x2A00003C, &tmp_data, 1);
	tmp_data = 1;
	igo_i2c_write(client, 0x2A000018, &tmp_data, 1);
	tmp_data = 1;
	ret = igo_i2c_write(client, 0x2A000030, &tmp_data, 1);
	msleep(500);
	tmp_data = 0x830001;
	igo_i2c_write(client, 0x2A00003C, &tmp_data, 1);
	tmp_data = 0x4;
	igo_i2c_write(client, 0x2A013020, &tmp_data, 1);
	tmp_data = 0x5500;
	igo_i2c_write(client, 0x2A0130C8, &tmp_data, 1);
	tmp_data = 0x0;
	igo_i2c_write(client, 0x2A013048, &tmp_data, 1);

	dev_info(dev, "Download to address  0x%08x\n", addr);
	write_bin(dev, addr, data, size);

	tmp_data = 0;
	igo_i2c_write(client, 0x2A000018, &tmp_data, 1);
	tmp_data = 1;
	igo_i2c_write(client, 0x2A000030, &tmp_data, 1);
	dev_info(dev, "Debussy FW update done");
}

static int debussy_fw_update(struct debussy_priv *debussy, int force_update)
{
	const struct firmware* fw;
	char* fw_path;
	char* fw_name = "debussy.bin";
	int ret, checkAgain = 0;
	unsigned int fw_ver, data;

	fw_path = kzalloc(DEBUSSY_FW_NAME_SIZE, GFP_KERNEL);
	if (!fw_path) {
		dev_err(debussy->dev, "%s: Failed to allocate fw_path\n",
			__func__);
		goto out1;
	}

	scnprintf(fw_path, DEBUSSY_FW_NAME_SIZE,
		"%s%s", DEBUSSY_FW_PATH, fw_name);
	dev_info(debussy->dev, "debussy fw name =%s", fw_path);

	ret = request_firmware(&fw, fw_path, debussy->dev);
	if (ret) {
		dev_err(debussy->dev,
			"%s: Failed to locate firmware %s errno = %d\n",
			__func__, fw_path, ret);
		goto out2;
	} else {
		dev_info(debussy->dev, "%s size = %d\n", fw_path, (int)(fw->size));
		fw_ver = *(unsigned int*)&fw->data[DEBUSSY_FW_VER_OFFSET];
		dev_info(debussy->dev, "BIN VER: 0x%08X\n", fw_ver);

		ret = igo_ch_read(debussy->dev, IGO_CH_FW_VER_ADDR, &data);
		if (ret != IGO_CH_STATUS_DONE) {
			data = 0;
		}
		dev_info(debussy->dev, "CHIP VER: 0x%08X\n", data);

		if ((fw_ver > data) || (force_update == 1)) {
			debussy->fw_version = fw_ver;
			dev_info(debussy->dev, "Update FW to 0x%08x\n", fw_ver);
			debussy_update_firmware(debussy->dev, DEBUSSY_FW_ADDR, fw->data, fw->size);
			debussy_reset_chip(debussy, DEBUSSY_RESET_NORMAL);
			checkAgain = 1;
		} else {
			debussy->fw_version = data;
			dev_info(debussy->dev, "Use chip built-in FW\n");
		}
	}

out2:
	release_firmware(fw);
	kfree(fw_path);
out1:
	return checkAgain;
}

static void debussy_manual_load_firmware(struct work_struct* work)
{
	struct debussy_priv* debussy;

	debussy = container_of(work, struct debussy_priv, fw_work);
	debussy_fw_update(debussy, 1);
}

static int debussy_probe(struct snd_soc_codec* codec)
{
	struct debussy_priv *debussy = snd_soc_codec_get_drvdata(codec);
	struct snd_soc_dapm_context *dapm = snd_soc_codec_get_dapm(codec);

	dev_dbg(debussy->dev, "%s enter\n", __func__);

	snd_soc_dapm_ignore_suspend(dapm, "BE_IN");
	snd_soc_dapm_ignore_suspend(dapm, "BE_OUT");
	snd_soc_dapm_ignore_suspend(dapm, "AIF0 Playback");
	snd_soc_dapm_ignore_suspend(dapm, "AIF0 Capture");
	snd_soc_dapm_ignore_suspend(dapm, "AIF3 Playback");
	snd_soc_dapm_ignore_suspend(dapm, "AIF3 Capture");
	snd_soc_dapm_ignore_suspend(dapm, "AIF-DMIC Capture");

	debussy_add_codec_controls(codec);
	debussy->codec = codec;

	if (debussy_fw_update(debussy, 0)) {
		debussy_fw_update(debussy, 0);
	}

	return 0;
}

static int debussy_remove(struct snd_soc_codec* codec)
{
	struct debussy_priv *debussy = snd_soc_codec_get_drvdata(codec);

	dev_dbg(debussy->dev, "%s enter\n", __func__);

	return 0;
}

static const char * const igo_hw_reset_text[] = {
	"OFF", "ON"
};

static const struct soc_enum igo_enum[] = {
	SOC_ENUM_SINGLE_EXT(ARRAY_SIZE(igo_hw_reset_text), igo_hw_reset_text),
};

static int igo_hw_reset_put(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_codec *codec = snd_soc_kcontrol_codec(kcontrol);
	struct debussy_priv *debussy = snd_soc_codec_get_drvdata(codec);
	int reset = ucontrol->value.integer.value[0];

	dev_dbg(debussy->dev, "%s enter, reset: %d\n", __func__, reset);

	debussy_reset_chip(debussy, DEBUSSY_RESET_NORMAL);
	return 0;
}

static int igo_mclk_force_enable_get(struct snd_kcontrol *kcontrol,
				struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_codec *codec = snd_soc_kcontrol_codec(kcontrol);
	struct debussy_priv *debussy = snd_soc_codec_get_drvdata(codec);

	ucontrol->value.integer.value[0] = debussy->force_enable_mclk;
	dev_dbg(debussy->dev, "%s: iGo MCLK Force Enable: %d\n", __func__,
		debussy->force_enable_mclk);
	return 0;
}

static int igo_mclk_force_enable_put(struct snd_kcontrol *kcontrol,
				struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_codec *codec = snd_soc_kcontrol_codec(kcontrol);
	struct debussy_priv *debussy = snd_soc_codec_get_drvdata(codec);
	int value = ucontrol->value.integer.value[0];

	dev_dbg(debussy->dev, "%s: iGo MCLK Force Enable: %d\n",
		__func__, value);

	debussy->force_enable_mclk = value;

	if (value)
		debussy_mclk_enable(debussy, true);
	else
		debussy_mclk_enable(debussy, false);

	return 0;
}

static int igo_factory_mode_get(struct snd_kcontrol *kcontrol,
				struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_codec *codec = snd_soc_kcontrol_codec(kcontrol);
	struct debussy_priv *debussy = snd_soc_codec_get_drvdata(codec);

	ucontrol->value.integer.value[0] = debussy->factory_mode;
	dev_dbg(debussy->dev, "%s: iGo Factory Mode: %d\n", __func__,
		debussy->force_enable_mclk);
	return 0;
}

static int igo_factory_mode_put(struct snd_kcontrol *kcontrol,
				struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_codec *codec = snd_soc_kcontrol_codec(kcontrol);
	struct debussy_priv *debussy = snd_soc_codec_get_drvdata(codec);
	int value = ucontrol->value.integer.value[0];

	dev_dbg(debussy->dev, "%s: iGo Factory Mode: %d\n",
		__func__, value);

	debussy->factory_mode = value;
	return 0;
}

static const struct snd_kcontrol_new igo_snd_controls[] = {
	SOC_ENUM_EXT("IGO HW RESET", igo_enum[0],
		NULL, igo_hw_reset_put),
	SOC_SINGLE_EXT("IGO MCLK ENABLE", SND_SOC_NOPM, 0, 1, 0,
		igo_mclk_force_enable_get, igo_mclk_force_enable_put),
	SOC_SINGLE_EXT("IGO FACTORY MODE", SND_SOC_NOPM, 0, 1, 0,
		igo_factory_mode_get, igo_factory_mode_put),
};

static int igo_suspend(struct snd_soc_codec *codec)
{
	struct debussy_priv *debussy = snd_soc_codec_get_drvdata(codec);

	//dev_dbg(debussy->dev, "%s enter\n", __func__);

	if (debussy && debussy->power_on) {
		debussy->power_on = false;
		if (debussy->dvdd.reg) {
			debussy_disable_vreg(debussy->dev, &debussy->dvdd);
			//dev_dbg(debussy->dev, "%s: dvdd disabled\n", __func__);
		}

		if (debussy->avdd.reg) {
			debussy_disable_vreg(debussy->dev, &debussy->avdd);
			//dev_dbg(debussy->dev, "%s: avdd disabled\n", __func__);
		}
		debussy_reset_gpio_pull_high(debussy, false);
	}

	return 0;
}

static int igo_resume(struct snd_soc_codec *codec)
{
	struct debussy_priv *debussy = snd_soc_codec_get_drvdata(codec);
	int ret;

	//dev_dbg(debussy->dev, "%s enter\n", __func__);

	if (debussy && !debussy->power_on) {
		debussy->power_on = true;

		if (debussy->dvdd.reg) {
			ret = debussy_enable_vreg(debussy->dev, &debussy->dvdd);
			if (ret)
				dev_err(debussy->dev, "%s: dvdd enable failed\n", __func__);
			else {
				//dev_dbg(debussy->dev, "%s: dvdd enabled\n", __func__);
			}
		}

		if (debussy->avdd.reg) {
			ret = debussy_enable_vreg(debussy->dev, &debussy->avdd);
			if (ret) {
				dev_err(debussy->dev, "%s: avdd enable failed\n", __func__);
			} else {
				//dev_dbg(debussy->dev, "%s: avdd enabled\n", __func__);
			}
		}

		msleep(10);
		debussy_reset_gpio_pull_high(debussy, true);
		atomic_set(&debussy->maskConfigCmd, 1);
	}

	return 0;
}

static int igo_set_bias_level(struct snd_soc_codec *codec,
				 enum snd_soc_bias_level level)
{
	//struct debussy_priv *debussy = snd_soc_codec_get_drvdata(codec);

	//dev_dbg(debussy->dev, "%s enter, level: %d\n", __func__, level);

	switch (level) {
	case SND_SOC_BIAS_ON:
		break;

	case SND_SOC_BIAS_PREPARE:
		break;

	case SND_SOC_BIAS_STANDBY:
		break;

	case SND_SOC_BIAS_OFF:
		break;
	}
	return 0;
}

static struct snd_soc_codec_driver soc_codec_dev_debussy = {
	.probe = debussy_probe,
	.remove = debussy_remove,
	.suspend = igo_suspend,
	.resume = igo_resume,
	.set_bias_level = igo_set_bias_level,
	.component_driver = {
		.dapm_routes      = igo_dapm_routes,
		.num_dapm_routes  = ARRAY_SIZE(igo_dapm_routes),
		.dapm_widgets     = igo_dapm_widgets,
		.num_dapm_widgets = ARRAY_SIZE(igo_dapm_widgets),
		.controls         = igo_snd_controls,
		.num_controls     = ARRAY_SIZE(igo_snd_controls),
	},
};

static int debussy_info_seq_show(struct seq_file *m, void *v)
{
	struct debussy_priv *debussy = m->private;

	seq_printf(m, "----- Ref Total: %2d, rx: %2d, tx: %2d -----\n",
		atomic_read(&debussy->ref_count[DEBUSSY_MAX]),
		atomic_read(&debussy->dai_ref[DEBUSSY_MAX].ch_ref[DEBUSSY_RX]),
		atomic_read(&debussy->dai_ref[DEBUSSY_MAX].ch_ref[DEBUSSY_TX]));
	seq_printf(m, "  dai0: %d, rx: %d, tx: %d\n",
		atomic_read(&debussy->ref_count[DEBUSSY_AIF0]),
		atomic_read(&debussy->dai_ref[DEBUSSY_AIF0].ch_ref[DEBUSSY_RX]),
		atomic_read(&debussy->dai_ref[DEBUSSY_AIF0].ch_ref[DEBUSSY_TX]));
	seq_printf(m, "  dai3: %d, rx: %d, tx: %d\n",
		atomic_read(&debussy->ref_count[DEBUSSY_AIF3]),
		atomic_read(&debussy->dai_ref[DEBUSSY_AIF3].ch_ref[DEBUSSY_RX]),
		atomic_read(&debussy->dai_ref[DEBUSSY_AIF3].ch_ref[DEBUSSY_TX]));
	seq_printf(m, "  dmic: %d, rx: %d, tx: %d\n",
		atomic_read(&debussy->ref_count[DEBUSSY_AIF_DMIC]),
		atomic_read(&debussy->dai_ref[DEBUSSY_AIF_DMIC].ch_ref[DEBUSSY_RX]),
		atomic_read(&debussy->dai_ref[DEBUSSY_AIF_DMIC].ch_ref[DEBUSSY_TX]));

	seq_printf(m, "------------ MCLK State -----------------\n");
	seq_printf(m, "     status: %s\n",
		atomic_read(&debussy->mclk_on) ? "On" : "Off");
	seq_printf(m, "  frequency: %lu Hz\n", clk_get_rate(debussy->mclk));

	seq_printf(m, "------------ MIC_BIAS1 State ------------\n");
	seq_printf(m, "     status: %s\n",
		debussy->enable_bias ? "On" : "Off");
	seq_printf(m, "---------------- Others  ----------------\n");
	seq_printf(m, " maskConfigCmd: %d\n", debussy_get_maskconfig(debussy));

	seq_printf(m, "--------------- Version -----------------\n");
	seq_printf(m, "      chip version: 0x%x\n", debussy->chip_version);
	seq_printf(m, "  firmware version: 0x%x\n", debussy->fw_version);

	return 0;
}

static int debussy_info_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, &debussy_info_seq_show, inode->i_private);
}

static const struct file_operations debussy_info_fops = {
	.open = debussy_info_seq_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int debussy_debufs_init(struct debussy_priv* debussy)
{
	int ret;

	struct dentry *dir;

	dir = debugfs_create_dir("debussy", NULL);
	if (IS_ERR_OR_NULL(dir)) {
		dir = NULL;
		ret = -ENODEV;
		goto err_create_dir;
	}

	if (!debugfs_create_file("download_firmware", S_IWUSR,
			dir, debussy, &debussy_download_firmware_fops)) {
		dev_err(debussy->dev, "%s: Failed to create debugfs node %s\n",
			__func__, "download_firmware");
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

	if (!debugfs_create_file("info", S_IRUGO | S_IWUGO,
			dir, debussy, &debussy_info_fops)) {
		dev_err(debussy->dev, "%s: Failed to create debugfs node %s\n",
			__func__, "info");
		ret = -ENODEV;
		goto err_create_entry;
	}

	debussy->dbg_dir = dir;
	return 0;

err_create_dir:
err_create_entry:
	return ret;
}

static int debussy_debufs_remove(struct debussy_priv* debussy)
{
	if (debussy->dbg_dir) {
		debugfs_remove_recursive(debussy->dbg_dir);
		debussy->dbg_dir = NULL;
	}

	return 0;
}

static void debussy_reset_gpio_pull_high(struct debussy_priv *debussy, bool high)
{
	//dev_dbg(debussy->dev, "%s set reset gpio to %d\n", __func__, high);

	if (high)
		gpio_direction_output(debussy->reset_gpio, 1);
	else
		gpio_direction_output(debussy->reset_gpio, 0);
}

void debussy_reset_chip(struct debussy_priv* debussy, enum debussy_reset_reason reason)
{
	debussy_reset_gpio_pull_high(debussy, false);
	msleep(2);
	debussy_reset_gpio_pull_high(debussy, true);
	msleep(2);
	dev_info(debussy->dev, "reset ok, reason: %d\n", reason);
}

void debussy_set_maskconfig(struct debussy_priv *debussy, int value)
{
	atomic_set(&debussy->maskConfigCmd, !!value);
	if (!!value)
		dev_dbg(debussy->dev, "%s: Start to mask iGo CMD\n", __func__);
	else
		dev_dbg(debussy->dev, "%s: Stop to mask iGo CMD\n", __func__);
}

int debussy_get_maskconfig(struct debussy_priv *debussy)
{
	return atomic_read(&debussy->maskConfigCmd);
}

int debussy_power_mode_add(struct debussy_priv *debussy)
{
	return atomic_add_return(1, &debussy->ref_power_mode);
}

int debussy_power_mode_sub(struct debussy_priv *debussy)
{
	return atomic_sub_return(1, &debussy->ref_power_mode);
}

int debussy_power_mode_get(struct debussy_priv *debussy)
{
	return atomic_read(&debussy->ref_power_mode);
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
	struct debussy_priv *debussy = i2c_get_clientdata(i2c);
	int ret, regVal = 0;
	int i;

	ret = igo_i2c_read(i2c, 0x0A000FF0, &regVal);
	if (ret < 0) {
		for (i = 0; i < 5; i++ ) {
			msleep(2);
			ret = igo_i2c_read(i2c, 0x0A000FF0, &regVal);
			if (ret < 0)
				continue;
		}
	}

	if (ret < 0) {
		dev_err(&i2c->dev, "%s: Failed reading vesion: 0x%x, ret: %d\n",
			__func__, regVal, ret);
		debussy->chip_version = 0;
		return -EINVAL;
	} else {
		dev_info(&i2c->dev,
			"%s: Hardware fixed register 0x0A000FF0 = 0x%08x and ret = %d\n",
			__func__, regVal, ret);
		debussy->chip_version = regVal;
		return 0;
	}
}

int debussy_get_presence(void)
{
	return presence;
}
EXPORT_SYMBOL(debussy_get_presence);

static long debussy_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	struct debussy_priv *debussy = container_of(filep->private_data, struct debussy_priv, mdev);
	int ret = 0;

	//dev_dbg(debussy->dev, "%s: enter, cmd: 0x%x", __func__, cmd);

	switch (cmd)
	{
	case INTELLIGO_IOCTL_GET_CHIP_VERSION:
	{
		int chip_version = debussy->chip_version;
		int __user *arg1 = (int __user *)arg;

		dev_dbg(debussy->dev, "%s: get chip version: 0x%x\n", __func__,
			chip_version);
		if (put_user(chip_version, arg1))
			return -EFAULT;
		break;
	}
	case INTELLIGO_IOCTL_GET_FW_VERSION:
	{
		int fw_version = debussy->fw_version;
		int __user *arg1 = (int __user *)arg;

		dev_dbg(debussy->dev, "%s: get firmware version: 0x%x\n", __func__,
			fw_version);
		if (put_user(fw_version, arg1))
			return -EFAULT;
		break;
	}
	case INTELLIGO_IOCTL_RESET_CHIP:
	{
		dev_dbg(debussy->dev, "%s: reset chip.\n", __func__);
		debussy_reset_chip(debussy, DEBUSSY_RESET_NORMAL);
		break;
	}
	case INTELLIGO_IOCTL_HW_BYPASS:
	case INTELLIGO_IOCTL_SW_BYPASS:
	case INTELLIGO_IOCTL_DAI0_LOOPBACK:
	case INTELLIGO_IOCTL_DAI3_LOOPBACK:
		ret = -ENOTTY;
		break;
	default:
	{
		dev_err(debussy->dev, "%s: invalid cmd: %d\n", __func__, cmd);
		ret = -EINVAL;
		break;
	}
	}

	return ret;
}

#ifdef CONFIG_COMPAT
static long debussy_compat_ioctl (struct file *filp, unsigned int cmd, unsigned long arg)
{
	return debussy_ioctl(filp, cmd, (unsigned long)compat_ptr(arg));
}
#endif

static const struct file_operations debussy_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl = debussy_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = debussy_compat_ioctl,
#endif
};

static int igo_i2c_probe(struct i2c_client* i2c,
	const struct i2c_device_id* id)
{
	struct debussy_priv* debussy;
	struct device_node *fnode = i2c->dev.of_node;
	struct pinctrl *pinctrl;
	struct clk *mclk;
	int ret, i;

	dev_info(&i2c->dev, "%s enter.\n", __func__);

	debussy = devm_kzalloc(&i2c->dev, sizeof(struct debussy_priv),
		GFP_KERNEL);
	if (!debussy) {
		dev_err(&i2c->dev, "Failed to allocate memory\n");
		return -ENOMEM;
	}

	debussy->dev = &i2c->dev;
	debussy->i2c = i2c;
	i2c_set_clientdata(i2c, debussy);
	debussy->dmic_switch = false;
	debussy->force_enable_mclk = false;
	debussy->factory_mode = false;
	debussy->enable_bias = false;

	atomic_set(&debussy->maskConfigCmd, 1);
	atomic_set(&debussy->mclk_on, 0);
	atomic_set(&debussy->ref_power_mode, 0);
	for (i = 0; i <= DEBUSSY_MAX; i++) {
		atomic_set(&debussy->ref_count[i], 0);
		atomic_set(&debussy->dai_ref[i].ch_ref[DEBUSSY_RX], 0);
		atomic_set(&debussy->dai_ref[i].ch_ref[DEBUSSY_TX], 0);
	}

	if (!debussy->i2c_pull) {
		debussy->i2c_pull = devm_regulator_get(&i2c->dev, "i2c-pull");
		if (IS_ERR(debussy->i2c_pull)) {
			dev_err(&i2c->dev, "%s: regulator i2c_pull get failed\n ", __func__);
			return PTR_ERR(debussy->i2c_pull);
		}

		ret = regulator_enable(debussy->i2c_pull);
		if (ret) {
			dev_err(&i2c->dev, "%s: regulator_enable i2c_pull failed! \n", __func__);
			return ret;
		}
	}

	pinctrl = devm_pinctrl_get(&i2c->dev);
	if (IS_ERR_OR_NULL(pinctrl)) {
		dev_err(&i2c->dev, "%s: Unable to get pinctrl handle\n", __func__);
		ret = -EINVAL;
		goto err;
	}
	debussy->igo_pinctrl = pinctrl;

	/* get all the states handles from Device Tree */
	debussy->iovdd_enable = pinctrl_lookup_state(pinctrl,
						"power_up");
	if (IS_ERR(debussy->iovdd_enable)) {
		ret = PTR_ERR(debussy->iovdd_enable);
		dev_err(&i2c->dev, "%s: could not get power_up pinstate: %d\n",
			__func__, ret);
		goto err;
	}

	debussy->iovdd_disable = pinctrl_lookup_state(pinctrl,
						"power_down");
	if (IS_ERR(debussy->iovdd_disable)) {
		ret = PTR_ERR(debussy->iovdd_disable);
		dev_err(&i2c->dev, "%s: could not get power_down pinstate: %d\n",
			__func__, ret);
		goto err;
	}

	debussy->mclk_enable = pinctrl_lookup_state(pinctrl,
						"mclk_enable");
	if (IS_ERR(debussy->mclk_enable)) {
		ret = PTR_ERR(debussy->mclk_enable);
		dev_err(&i2c->dev, "%s: could not get mclk_enable pinstate: %d\n",
			__func__, ret);
		goto err;
	}

	debussy->mclk_disable = pinctrl_lookup_state(pinctrl,
						"mclk_disable");
	if (IS_ERR(debussy->mclk_disable)) {
		ret = PTR_ERR(debussy->mclk_disable);
		dev_err(&i2c->dev, "%s: could not get mclk_disable pinstate: %d\n",
			__func__, ret);
		goto err;
	}

	if (!debussy->dvdd.reg) {
		/*
		 * voltage: min: 1.14v  typ: 1.2v  max: 1.26v
		 * current: 80mA
		 */
		strncpy(debussy->dvdd.name, "DVDD", sizeof(debussy->dvdd.name));
		debussy->dvdd.reg = devm_regulator_get(&i2c->dev, "dvdd");
		if (IS_ERR(debussy->dvdd.reg)) {
			ret = PTR_ERR(debussy->dvdd.reg);
			dev_err(&i2c->dev, "%s: regulator %s get failed: %d\n", __func__,
				debussy->dvdd.name, ret);
			goto err;
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
			ret = PTR_ERR(debussy->avdd.reg);
			dev_err(&i2c->dev, "%s: regulator %s get failed: %d\n", __func__,
				debussy->avdd.name, ret);
			goto err;
		}
		debussy->avdd.min_uV = AVDD_MIN_UV;
		debussy->avdd.max_uV = AVDD_MAX_UV;
		debussy->avdd.min_uA = AVDD_UA;
		debussy->avdd.max_uA = AVDD_UA;
		debussy->avdd.enabled = false;
	}

	mclk = of_clk_get_by_name(fnode, "div_clk2_19_2m");
	if (IS_ERR(mclk)) {
		ret = PTR_ERR(mclk);
		dev_err(&i2c->dev, "%s: Couldn't get the mclk clock: %d\n", __func__,
			ret);
		goto err;
	}
	debussy->mclk = mclk;

	ret = debussy_enable_vreg(&i2c->dev, &debussy->dvdd);
	if (ret) {
		dev_err(&i2c->dev, "enable %s failed.\n", debussy->dvdd.name);
		goto err1;
	}

	ret = pinctrl_select_state(pinctrl, debussy->iovdd_enable);
	if (ret) {
		dev_err(&i2c->dev, "%s: enable iovdd enable pin failed with %d\n",
			__func__, ret);
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

	debussy_reset_chip(debussy, DEBUSSY_RESET_NORMAL);

	ret = debussy_check_presence(i2c);
	if (ret < 0)
		goto err4;

	debussy->debussy_wq = create_singlethread_workqueue("debussy");
	if (debussy->debussy_wq == NULL) {
		ret = -ENOMEM;
		goto err4;
	}
	INIT_WORK(&debussy->fw_work, debussy_manual_load_firmware);

	mutex_init(&debussy->igo_ch_lock);
	mutex_init(&debussy->mclk_lock);

	debussy->mdev.minor = MISC_DYNAMIC_MINOR;
	debussy->mdev.name = "intelligo";
	debussy->mdev.fops = &debussy_fops;
	ret = misc_register(&debussy->mdev);
	if (ret) {
		dev_err(&i2c->dev, "%s: register misc device failed: %d\n",
			__func__, ret);
		goto err5;
	}

	ret = snd_soc_register_codec(&i2c->dev, &soc_codec_dev_debussy,
		debussy_dai, ARRAY_SIZE(debussy_dai));
	if (ret) {
		dev_err(&i2c->dev, "Codec registration failed\n");
		goto err6;
	}

	debussy_debufs_init(debussy);
	presence = 1;
	return 0;

err6:
	misc_deregister(&debussy->mdev);
err5:
	mutex_destroy(&debussy->igo_ch_lock);
	destroy_workqueue(debussy->debussy_wq);
err4:
	debussy_disable_vreg(&i2c->dev, &debussy->avdd);
err3:
	//pinctrl_select_state(pinctrl, debussy->iovdd_disable);
err2:
	debussy_disable_vreg(&i2c->dev, &debussy->dvdd);
err1:
	//debussy_mclk_enable(debussy, false);
//err0:
	clk_put(debussy->mclk);
err:
	if (debussy->i2c_pull)
		regulator_disable(debussy->i2c_pull);
	return ret;
}

static int igo_i2c_remove(struct i2c_client* i2c)
{
	struct debussy_priv* debussy = i2c_get_clientdata(i2c);

	mutex_destroy(&debussy->igo_ch_lock);
	mutex_destroy(&debussy->mclk_lock);
	misc_deregister(&debussy->mdev);
	snd_soc_unregister_codec(&i2c->dev);
	destroy_workqueue(debussy->debussy_wq);
	debussy_debufs_remove(debussy);
	debussy_disable_vreg(&i2c->dev, &debussy->dvdd);
	//pinctrl_select_state(debussy->iovdd_pinctrl, debussy->iovdd_disable);
	debussy_disable_vreg(&i2c->dev, &debussy->avdd);
	clk_put(debussy->mclk);

	if (debussy->i2c_pull)
		regulator_disable(debussy->i2c_pull);

	return 0;
}

static struct i2c_driver igo_i2c_driver = {
	.driver = {
		.name = "debussy",
		.owner = THIS_MODULE,
		.of_match_table = of_match_ptr(debussy_of_match),
	},
	.probe = igo_i2c_probe,
	.remove = igo_i2c_remove,
	.id_table = igo_i2c_id,
};
module_i2c_driver(igo_i2c_driver);

MODULE_DESCRIPTION("Debussy driver");
MODULE_LICENSE("GPL v2");
