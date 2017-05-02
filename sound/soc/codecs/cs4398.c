/*
 * cs4398.c  --  CS4398 ALSA Soc Audio driver
 *
 * Authors: Junkang.Wang <wangjunkang@smartisan.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/of_gpio.h>
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/gpio.h>
#include <linux/gpio/consumer.h>
#include <linux/platform_device.h>
#include <linux/pm.h>
#include <linux/i2c.h>
#include <linux/of_device.h>
#include <linux/regmap.h>
#include <linux/reboot.h>
#include <linux/slab.h>
#include <sound/core.h>
#include <sound/pcm.h>
#include <sound/pcm_params.h>
#include <sound/soc.h>
#include <sound/soc-dapm.h>
#include <sound/initval.h>
#include <sound/tlv.h>
#include "cs4398.h"

/* register 8 */
#define CS4398_CPEN		0x40
#define CS4398_PDN		0x80

//delay 600ms for external codec to power down
#define POWERDOWN_DELAY_TIME 600

//static int tlv_reset_gpio = 85;
static struct clk *pll_ref_clk;

static const struct reg_default cs4398_reg_defaults[] = {
	{ 0x02, 0x10 },	/* r02	- Mode Control: I2S */
	{ 0x05, 0x09 },	/* r05	- Channel A Volume Control: -4.5dB */
	{ 0x06, 0x09 },	/* r06	- Channel B Volume Control: -4.5dB */
	{ 0x08, 0x40 },	/* r08	- Misc. Control: Control Port Enable */
	{ 0x04, 0xD8 }, /* r04  - Mute Control: default mute DAC output*/
};

// PLL config for i2s to support 48kHz 32bit stereo playback
static const struct reg_default tlv320adc3001_config_48[] = {
	{ 0x04, 0x03 },	/* r04	- Clock-Gen Multiplexing: CODEC_CLKIN = PLL_CLK */
	{ 0x05, 0x91 },	/* r05	- PLL P and R VAL: P = 1, R = 1 */
	{ 0x06, 0x05 },	/* r06	- PLL J VAL: J = 5 */
	{ 0x07, 0x04 },	/* r07	- PLL D VAL MSB */
	{ 0x08, 0xB0 },	/* r08	- PLL D VAL LSB: D = 0x04B0(1200) */
	{ 0x12, 0x88 },	/* r18	- NADC Clock Divider: M = 8 */
	{ 0x13, 0x82 },	/* r19	- MADC Clock Divider: M = 2 */
	{ 0x14, 0x80 },	/* r20	- AOSR = 128 */
	{ 0x19, 0x06 },	/* r25	- CLKOUT MUX: CDIV_CLKIN = ADC_CLK */
	{ 0x1A, 0x81 },	/* r26  - CLKOUT M Divider: M = 1 */
	{ 0x1B, 0x3C },	/* r27	- Audio Interface Control 1: word length: 32bits, BCLK & WCLK output */
	{ 0x1D, 0x06 },	/* r29	- Interface Control 2: enable BCLK and WCLK active even with codec powered down */
	{ 0x1E, 0x84 },	/* r30	- BCLK N Divider: N = 4 */
	{ 0x35, 0x16 },	/* r53	- DOUT control: disable bus keeper, DOUT = CLKOUT */
};

// PLL config for i2s to support 44.1kHz
static const struct reg_default pll_config_44p1[] = {
	{ 0x06, 0x04 },	/* r06	- PLL J VAL: J = 4 */
	{ 0x07, 0x1B },	/* r07	- PLL D VAL MSB */
	{ 0x08, 0x80 },	/* r08	- PLL D VAL LSB: D = 0x1B80(7040) */
};

// PLL config for i2s to support 48kHz
static const struct reg_default pll_config_48[] = {
	{ 0x06, 0x05 },	/* r06	- PLL J VAL: J = 5 */
	{ 0x07, 0x04 },	/* r07	- PLL D VAL MSB */
	{ 0x08, 0xB0 },	/* r08	- PLL D VAL LSB: D = 0x04B0(1200) */
};

/* Private data for the CS4398 */
struct  cs4398_private {
	struct i2c_client		*cs4398_dev;
	struct regmap			*regmap;
	struct mutex                    io_lock;
	u32                             tlv_addr;
	unsigned int			mode;
	int				rate;
	int				reset_gpio;
	int				power_gpio;
	int				tlv_rst;
	int				cs_ana;
	int				hifi_headset_sel;

	struct delayed_work			ext_hifi_pwrdwn_dwork;
	struct notifier_block		notifier_block;
};

static bool cs4398_readable_register(struct device *dev, unsigned int reg)
{
	switch (reg) {
	case CS4398_CHIPID ... CS4398_MISC:
		return true;
	default:
		return false;
	}
}

static bool cs4398_writeable_register(struct device *dev, unsigned int reg)
{
	switch (reg) {
	case CS4398_MODE ...  CS4398_MISC:
		return true;
	default:
		return false;
	}
}

/*
static int cs4398_set_dai_fmt(struct snd_soc_dai *codec_dai,
			      unsigned int format)
{
	struct snd_soc_codec *codec = codec_dai->codec;
	struct cs4398_private *cs4398 = snd_soc_codec_get_drvdata(codec);
	unsigned int fmt;

	fmt = format & SND_SOC_DAIFMT_FORMAT_MASK;

	switch (fmt) {
	case SND_SOC_DAIFMT_I2S:
	case SND_SOC_DAIFMT_LEFT_J:
	case SND_SOC_DAIFMT_RIGHT_J:
		cs4398->mode = format & SND_SOC_DAIFMT_FORMAT_MASK;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int cs4398_pcm_hw_params(struct snd_pcm_substream *substream,
			    struct snd_pcm_hw_params *params,
			    struct snd_soc_dai *dai)
{
	struct snd_soc_codec *codec = dai->codec;
	struct cs4398_private *cs4398 = snd_soc_codec_get_drvdata(codec);
	int fmt, ret;

	cs4398->rate = params_rate(params);

	switch (cs4398->mode) {
	case SND_SOC_DAIFMT_I2S:
		fmt = DIF_I2S;
		break;
	case SND_SOC_DAIFMT_LEFT_J:
		fmt = DIF_LEFT_JST;
		break;
	case SND_SOC_DAIFMT_RIGHT_J:
		switch (params_width(params)) {
		case 16:
			fmt = DIF_RGHT_JST16;
			break;
		case 24:
			fmt = DIF_RGHT_JST24;
			break;
		default:
			return -EINVAL;
		}
		break;
	default:
		return -EINVAL;
	}

	ret = snd_soc_update_bits(codec, CS4398_MODE, DIF_MASK,
				  MODE_FORMAT(fmt));
	if (ret < 0)
		return ret;

	return 0;
}

static DECLARE_TLV_DB_SCALE(dig_tlv, -12750, 50, 0);

static const char * const chan_mix_texts[] = {
	"Mute", "MuteA", "MuteA SwapB", "MuteA MonoB", "SwapA MuteB",
	"BothR", "Swap", "SwapA MonoB", "MuteB", "Normal", "BothL",
	"MonoB", "MonoA MuteB", "MonoA", "MonoA SwapB", "Mono",
*/
	/*Normal == Channel A = Left, Channel B = Right*/
/*
};

static const char * const fm_texts[] = {
	"Auto", "Single", "Double", "Quad",
};

static const char * const deemph_texts[] = {
	"None", "44.1k", "48k", "32k",
};

static const char * const softr_zeroc_texts[] = {
	"Immediate", "Zero Cross", "Soft Ramp", "SR on ZC",
};

static int deemph_values[] = {
	0, 4, 8, 12,
};

static int softr_zeroc_values[] = {
	0, 64, 128, 192,
};

static const struct soc_enum chan_mix_enum =
	SOC_ENUM_SINGLE(CS4398_VMI, 0,
			ARRAY_SIZE(chan_mix_texts),
			chan_mix_texts);

static const struct soc_enum fm_mode_enum =
	SOC_ENUM_SINGLE(CS4398_MODE, 0,
			ARRAY_SIZE(fm_texts),
			fm_texts);

static SOC_VALUE_ENUM_SINGLE_DECL(deemph_enum, CS4398_MODE, 0, DEM_MASK,
				deemph_texts, deemph_values);

static SOC_VALUE_ENUM_SINGLE_DECL(softr_zeroc_enum, CS4398_RMPFLT, 0,
				SR_ZC_MASK, softr_zeroc_texts,
				softr_zeroc_values);

static const struct snd_kcontrol_new cs4398_snd_controls[] = {
	SOC_DOUBLE_R_TLV("Master Playback Volume",
			 CS4398_VOLA, CS4398_VOLB, 0, 0xFF, 1, dig_tlv),
	SOC_ENUM("Functional Mode", fm_mode_enum),
	SOC_ENUM("De-Emphasis Control", deemph_enum),
	SOC_ENUM("Soft Ramp Zero Cross Control", softr_zeroc_enum),
	SOC_ENUM("Channel Mixer", chan_mix_enum),
	SOC_SINGLE("VolA = VolB Switch", CS4398_VMI, 7, 1, 0),
	SOC_SINGLE("InvertA Switch", CS4398_VMI, 6, 1, 0),
	SOC_SINGLE("InvertB Switch", CS4398_VMI, 5, 1, 0),
	SOC_SINGLE("Auto-Mute Switch", CS4398_MUTE, 7, 1, 0),
	SOC_SINGLE("MUTEC A = B Switch", CS4398_MUTE, 5, 1, 0),
	SOC_SINGLE("Soft Ramp Up Switch", CS4398_RMPFLT, 5, 1, 0),
	SOC_SINGLE("Soft Ramp Down Switch", CS4398_RMPFLT, 4, 1, 0),
	SOC_SINGLE("Slow Roll Off Filter Switch", CS4398_RMPFLT, 2, 1, 0),
	SOC_SINGLE("Freeze Switch", CS4398_MISC, 5, 1, 0),
	SOC_SINGLE("Popguard Switch", CS4398_MISC, 4, 1, 0),
};

static const struct snd_soc_dapm_widget cs4398_dapm_widgets[] = {
	SND_SOC_DAPM_DAC("HiFi DAC", NULL, SND_SOC_NOPM, 0, 0),

	SND_SOC_DAPM_OUTPUT("OutputA"),
	SND_SOC_DAPM_OUTPUT("OutputB"),
};

static const struct snd_soc_dapm_route cs4398_routes[] = {
	{"DAC Playback", NULL, "OutputA"},
	{"DAC Playback", NULL, "OutputB"},

	{"OutputA", NULL, "HiFi DAC"},
	{"OutputB", NULL, "HiFi DAC"},
};
*/

static void powerdown_ext_hifi_components(struct work_struct *work)
{
	struct delayed_work *dwork;
	struct cs4398_private *cs4398;

	dwork = to_delayed_work(work);
	cs4398 = container_of(dwork, struct cs4398_private, ext_hifi_pwrdwn_dwork);

	if (gpio_get_value_cansleep(cs4398->cs_ana)) {
		pr_debug("%s: power down external dac and pll\n", __func__);
		mutex_lock(&cs4398->io_lock);

		gpio_direction_output(cs4398->hifi_headset_sel, 1);

		gpio_set_value_cansleep(cs4398->reset_gpio, 0);

		gpio_set_value_cansleep(cs4398->tlv_rst, 0);

		gpio_set_value_cansleep(cs4398->cs_ana, 0);

		clk_disable_unprepare(pll_ref_clk);

		mutex_unlock(&cs4398->io_lock);
	}
}

static int tlv320adc3001_init(struct cs4398_private *cs4398)
{
	u8 buffer[2];
	u8 address;
	u32 i;
	int ret;

	address = cs4398->cs4398_dev->addr;
	cs4398->cs4398_dev->addr = cs4398->tlv_addr;

	dev_dbg(&cs4398->cs4398_dev->dev, "%s: i2c write at addr %d\n", __func__, cs4398->tlv_addr);
	mutex_lock(&cs4398->io_lock);
	for (i = 0; i < ARRAY_SIZE(tlv320adc3001_config_48); i++) {
		buffer[0] = tlv320adc3001_config_48[i].reg;
		buffer[1] = tlv320adc3001_config_48[i].def;
		ret = i2c_master_send(cs4398->cs4398_dev, buffer, 2);
		if (ret != 2) {
			dev_err(&cs4398->cs4398_dev->dev, "%s: i2c write failed at addr %d\n",
				__func__, buffer[0]);
			ret = -EIO;
			goto err;
		}
	}

err:
	mutex_unlock(&cs4398->io_lock);
	cs4398->cs4398_dev->addr = address;

	if (ret == 2)
		ret = 0;
	return ret;
}

static int cs4398_init(struct cs4398_private *cs4398)
{
	u8 buffer[2];
	u32 i;
	int ret;

	mutex_lock(&cs4398->io_lock);

	buffer[0] = 0x08;			//Misc. Control - register addr:0x08
	buffer[1] = CS4398_PDN | CS4398_CPEN;	//enable Control Port but keep power down - PDN:1, CPEN:1
	ret = i2c_master_send(cs4398->cs4398_dev, buffer, 2);
	if (ret != 2) {
		dev_err(&cs4398->cs4398_dev->dev, "%s: i2c write failed at addr %d\n",
			__func__, buffer[0]);
		ret = -EIO;
		goto err;
	}

	msleep(5);

	for (i = 0; i < ARRAY_SIZE(cs4398_reg_defaults); i++) {
		buffer[0] = cs4398_reg_defaults[i].reg;
		buffer[1] = cs4398_reg_defaults[i].def;
		ret = i2c_master_send(cs4398->cs4398_dev, buffer, 2);
		if (ret != 2) {
			dev_err(&cs4398->cs4398_dev->dev, "%s: i2c write failed at addr %d\n",
				__func__, buffer[0]);
			ret = -EIO;
			goto err;
		}
	}

err:
	mutex_unlock(&cs4398->io_lock);

	if (ret == 2)
		ret = 0;
	return ret;
}

static const struct snd_kcontrol_new cs4398_snd_controls[] = {
};

static const struct snd_soc_dapm_widget cs4398_dapm_widgets[] = {
};

static const struct snd_soc_dapm_route cs4398_routes[] = {
};

static int cs4398_pcm_hw_params(struct snd_pcm_substream *substream,
			    struct snd_pcm_hw_params *params,
			    struct snd_soc_dai *dai)
{
	struct snd_soc_codec *codec = dai->codec;
	struct cs4398_private *cs4398 = snd_soc_codec_get_drvdata(codec);
	u8 buffer[2];
	u8 slave_addr;
	int ret, i;

	pr_debug("%s: format = %d, rate = %d\n",
	       __func__, params_format(params), params_rate(params));

	slave_addr = cs4398->cs4398_dev->addr;
	cs4398->cs4398_dev->addr = cs4398->tlv_addr;
	cs4398->rate = params_rate(params);

	mutex_lock(&cs4398->io_lock);
	if (cs4398->rate == 44100) {
		for (i = 0; i < ARRAY_SIZE(pll_config_44p1); i++) {
			buffer[0] = pll_config_44p1[i].reg;
			buffer[1] = pll_config_44p1[i].def;
			ret = i2c_master_send(cs4398->cs4398_dev, buffer, 2);
			if (ret != 2) {
				dev_err(&cs4398->cs4398_dev->dev, "%s: i2c write failed at addr %d\n",
					__func__, buffer[0]);
				ret = -EIO;
				goto err;
			}
		}
	} else {
		for (i = 0; i < ARRAY_SIZE(pll_config_48); i++) {
			buffer[0] = pll_config_48[i].reg;
			buffer[1] = pll_config_48[i].def;
			ret = i2c_master_send(cs4398->cs4398_dev, buffer, 2);
			if (ret != 2) {
				dev_err(&cs4398->cs4398_dev->dev, "%s: i2c write failed at addr %d\n",
					__func__, buffer[0]);
				ret = -EIO;
				goto err;
			}
		}
	}

err:
	mutex_unlock(&cs4398->io_lock);
	cs4398->cs4398_dev->addr = slave_addr;
	if (ret == 2)
		ret = 0;
	return ret;
}

static int cs4398_set_dai_fmt(struct snd_soc_dai *codec_dai,
			      unsigned int format)
{
	return 0;
}

static int cs4398_startup(struct snd_pcm_substream *substream,
	struct snd_soc_dai *dai)
{
	struct snd_soc_codec *codec = dai->codec;
	struct cs4398_private *cs4398 = snd_soc_codec_get_drvdata(codec);
	int ret = 0;

	pr_debug("%s: cancel delay work to power down ext hifi\n", __func__);
	cancel_delayed_work_sync(&cs4398->ext_hifi_pwrdwn_dwork);

	if (gpio_get_value_cansleep(cs4398->cs_ana)) {
		pr_debug("%s: ext hifi still power on, do nothing\n", __func__);
	} else {
		/* Bringup from reset */
		pr_debug("%s: bringup from reset mode for external dac and pll\n", __func__);

		gpio_set_value_cansleep(cs4398->tlv_rst, 1);

		gpio_set_value_cansleep(cs4398->cs_ana, 1);

		ret = tlv320adc3001_init(cs4398);
		if (ret) {
			pr_err("%s: tlv320adc3001 init failed, err = %d\n",
			       __func__, ret);
			return ret;
		}

		msleep(5);

		ret = clk_prepare_enable(pll_ref_clk);
		if (ret) {
			pr_err("%s: div clk3 enable failed\n", __func__);
			return ret;
		}

		msleep(10);
		gpio_set_value_cansleep(cs4398->reset_gpio, 1);

		ret = cs4398_init(cs4398);
		if (ret) {
			pr_err("%s: cs4398 init failed, err = %d\n",
			       __func__, ret);
			return ret;
		}

		usleep_range(20000, 20000);
		gpio_direction_output(cs4398->hifi_headset_sel, 0);
	}

	return ret;
}

static void cs4398_shutdown(struct snd_pcm_substream *substream,
	struct snd_soc_dai *dai)
{
	struct snd_soc_codec *codec = dai->codec;
	struct cs4398_private *cs4398 = snd_soc_codec_get_drvdata(codec);

	cancel_delayed_work_sync(&cs4398->ext_hifi_pwrdwn_dwork);

	pr_debug("%s: delay to power down external dac and pll\n", __func__);
	schedule_delayed_work(&cs4398->ext_hifi_pwrdwn_dwork,
			      msecs_to_jiffies(POWERDOWN_DELAY_TIME));
}

static int cs4398_mute_stream(struct snd_soc_dai *dai, int mute, int stream)
{
	struct snd_soc_codec *codec = dai->codec;
	struct cs4398_private *cs4398 = snd_soc_codec_get_drvdata(codec);
	u8 buffer[2];
	int ret;

	if (stream != SNDRV_PCM_STREAM_PLAYBACK)
		return 0;

	pr_debug("%s: mute %s\n", __func__, mute ? "on" : "off");

	buffer[0] = 0x04;
	if (mute) {
		buffer[1] = 0xD8;  //Mute AB channel DAC output
	} else {
		buffer[1] = 0xC0;  //Unmute AB channel DAC output
	}

	ret = i2c_master_send(cs4398->cs4398_dev, buffer, 2);
	if (ret != 2) {
		dev_err(&cs4398->cs4398_dev->dev, "%s: i2c write failed at addr %d\n",
			__func__, buffer[0]);
		ret = -EIO;
	}

	return 0;
}

static int cs4398_reboot_notifier_event(struct notifier_block *this,
						unsigned long event, void *ptr)
{
	struct cs4398_private *cs4398 = container_of(this, struct cs4398_private,
							notifier_block);
	int hifi_headset_sel = cs4398->hifi_headset_sel;

	pr_debug("%s enter, event: %lu\n", __func__, event);

	if (gpio_is_valid(hifi_headset_sel) &&
		!gpio_get_value_cansleep(hifi_headset_sel))
		gpio_direction_output(hifi_headset_sel, 1);

	return NOTIFY_DONE;
}

#define CS4398_PCM_FORMATS (SNDRV_PCM_FMTBIT_S8  | \
			SNDRV_PCM_FMTBIT_S16_LE  | SNDRV_PCM_FMTBIT_S16_BE  | \
			SNDRV_PCM_FMTBIT_S18_3LE | SNDRV_PCM_FMTBIT_S18_3BE | \
			SNDRV_PCM_FMTBIT_S20_3LE | SNDRV_PCM_FMTBIT_S20_3BE | \
			SNDRV_PCM_FMTBIT_S24_3LE | SNDRV_PCM_FMTBIT_S24_3BE | \
			SNDRV_PCM_FMTBIT_S24_LE  | SNDRV_PCM_FMTBIT_S24_BE  | \
			SNDRV_PCM_FMTBIT_S32_LE)

#define CS4398_PCM_RATES SNDRV_PCM_RATE_8000_192000

static const struct snd_soc_dai_ops cs4398_dai_ops = {
	.startup = cs4398_startup,
	.shutdown = cs4398_shutdown,
	.hw_params = cs4398_pcm_hw_params,
	.set_fmt = cs4398_set_dai_fmt,
	.mute_stream = cs4398_mute_stream,
};

static struct snd_soc_dai_driver cs4398_dai = {
	.name = "cs4398-hifi",
	.playback = {
		.stream_name	= "DAC Playback",
		.channels_min	= 1,
		.channels_max	= 2,
		.rates		= CS4398_PCM_RATES,
		.formats	= CS4398_PCM_FORMATS,
	},
	.ops = &cs4398_dai_ops,
	.symmetric_rates = 1,
};

static struct snd_soc_codec_driver soc_codec_dev_cs4398 = {
	.controls		= cs4398_snd_controls,
	.num_controls		= ARRAY_SIZE(cs4398_snd_controls),

	.dapm_widgets		= cs4398_dapm_widgets,
	.num_dapm_widgets	= ARRAY_SIZE(cs4398_dapm_widgets),
	.dapm_routes		= cs4398_routes,
	.num_dapm_routes	= ARRAY_SIZE(cs4398_routes),
};

static const struct regmap_config cs4398_regmap = {
	.reg_bits		= 8,
	.val_bits		= 8,

	.max_register		= CS4398_MISC,
	.reg_defaults		= cs4398_reg_defaults,
	.num_reg_defaults	= ARRAY_SIZE(cs4398_reg_defaults),
	.readable_reg		= cs4398_readable_register,
	.writeable_reg		= cs4398_writeable_register,
	.cache_type		= REGCACHE_RBTREE,
};

static int cs4398_i2c_probe(struct i2c_client *client,
				      const struct i2c_device_id *id)
{
	struct cs4398_private *cs4398;
	struct device_node *np = client->dev.of_node;
	int ret;

	dev_err(&client->dev, "%s: enter\n", __func__);

	cs4398 = devm_kzalloc(&client->dev, sizeof(*cs4398), GFP_KERNEL);
	if (!cs4398)
		return -ENOMEM;

	cs4398->regmap = devm_regmap_init_i2c(client, &cs4398_regmap);
	if (IS_ERR(cs4398->regmap)) {
		ret = PTR_ERR(cs4398->regmap);
		dev_err(&client->dev, "regmap_init() failed: %d\n", ret);
		return ret;
	}

	ret = of_property_read_u32(np, "ti,tlv-reg", &cs4398->tlv_addr);
	if (ret) {
		dev_err(&client->dev,
			"%s: missing tlv320 slave address in dt node\n", __func__);
		return ret;
	}
	/* Reset the Device */
	cs4398->reset_gpio = of_get_named_gpio(np, "cs,reset-gpio", 0);
	if (gpio_is_valid(cs4398->reset_gpio)) {
		ret = devm_gpio_request_one(&client->dev, cs4398->reset_gpio,
					    GPIOF_OUT_INIT_LOW, "CS4398_RST");
		if (ret) {
			dev_err(&client->dev, "Failed to request cs4398 reset gpio %d \n",
				cs4398->reset_gpio);
			return ret;
		}
	}

	cs4398->tlv_rst = of_get_named_gpio(np, "ti,reset-gpio", 0);
	if (gpio_is_valid(cs4398->tlv_rst)) {
		ret = devm_gpio_request_one(&client->dev, cs4398->tlv_rst,
					    GPIOF_OUT_INIT_HIGH, "TLV320ADC3001_RST");
		if (ret) {
			dev_err(&client->dev, "Failed to request tlv320adc3001 reset gpio %d \n",
				cs4398->tlv_rst);
			return ret;
		}
	}

	cs4398->cs_ana = of_get_named_gpio(np, "cs,va-enable", 0);
	if (gpio_is_valid(cs4398->cs_ana)) {
		ret = devm_gpio_request_one(&client->dev, cs4398->cs_ana,
					    GPIOF_OUT_INIT_HIGH, "CS4398->CS_ANA");
		if (ret) {
			dev_err(&client->dev, "Failed to request cs4398 ldo-en gpio %d \n",
				cs4398->cs_ana);
			return ret;
		}
	}

	cs4398->hifi_headset_sel = of_get_named_gpio(np, "cs,hifi_headset_sel", 0);
	if (gpio_is_valid(cs4398->hifi_headset_sel)) {
		ret = devm_gpio_request_one(&client->dev, cs4398->hifi_headset_sel,
					    GPIOF_OUT_INIT_HIGH, "HIFI_HEADSET_SEL");
		if (ret) {
			dev_err(&client->dev, "Failed to request hifi_headset_sel gpio %d \n",
				cs4398->hifi_headset_sel);
			return ret;
		}
	}

	cs4398->power_gpio = of_get_named_gpio(np, "hifi-ldo-en", 0);
	if (gpio_is_valid(cs4398->power_gpio)) {
		ret = devm_gpio_request_one(&client->dev, cs4398->power_gpio,
					    GPIOF_OUT_INIT_HIGH, "HIFI_LDO_ENABLE");
		if (ret) {
			dev_err(&client->dev, "Failed to request tlv320adc3001 ldo-en gpio %d \n",
				cs4398->power_gpio);
			return ret;
		}
	}

	gpio_set_value_cansleep(cs4398->tlv_rst, 0);

	usleep_range(10, 15);

	gpio_set_value_cansleep(cs4398->tlv_rst, 1);

	usleep_range(100, 150);

	msleep(5);

	if (of_property_read_bool(np, "qcom,node_has_rpm_clock")) {
		pll_ref_clk = clk_get(&client->dev, "pll_ref_clk");
		if (IS_ERR(pll_ref_clk)) {
			dev_err(&client->dev, "Failed to get RPM div clk3\n");
			ret = PTR_ERR(pll_ref_clk);
			return ret;
		}
	}

	ret = clk_prepare_enable(pll_ref_clk);
	if (ret) {
		dev_err(&client->dev, "%s: div clk3 enable failed\n",
			__func__);
		return ret;
	}

	msleep(50);
	gpio_set_value_cansleep(cs4398->reset_gpio, 1);

	msleep(5);

	/*
	  Hold down reset to power down cs4398 and tlv320
	  but keep ldo power enabled cause i2c can be
	  pulled down if tlv is powered off
	*/
	gpio_set_value_cansleep(cs4398->reset_gpio, 0);
	gpio_set_value_cansleep(cs4398->tlv_rst, 0);
	gpio_set_value_cansleep(cs4398->cs_ana, 0);

	clk_disable_unprepare(pll_ref_clk);

	INIT_DELAYED_WORK(&cs4398->ext_hifi_pwrdwn_dwork, powerdown_ext_hifi_components);
	mutex_init(&cs4398->io_lock);

	cs4398->cs4398_dev = client;
	i2c_set_clientdata(client, cs4398);
	dev_err(&client->dev, "%s: i2c dev slave addr %x\n", __func__, client->addr);

	cs4398->notifier_block.notifier_call = cs4398_reboot_notifier_event;
	register_reboot_notifier(&cs4398->notifier_block);

	return snd_soc_register_codec(&client->dev, &soc_codec_dev_cs4398,
		&cs4398_dai, 1);
}

static int cs4398_i2c_remove(struct i2c_client *client)
{
	struct cs4398_private *cs4398 = i2c_get_clientdata(client);

//	snd_soc_unregister_codec(&client->dev);

	/* Hold down reset */
	gpio_set_value_cansleep(cs4398->reset_gpio, 0);
	gpio_set_value_cansleep(cs4398->tlv_rst, 0);
	/* Power down */
	gpio_set_value_cansleep(cs4398->power_gpio, 0);
	gpio_set_value_cansleep(cs4398->cs_ana, 0);

	clk_disable_unprepare(pll_ref_clk);
	clk_put(pll_ref_clk);

	mutex_destroy(&cs4398->io_lock);

	unregister_reboot_notifier(&cs4398->notifier_block);

	return 0;
}
/*
#ifdef CONFIG_PM
static int cs4398_runtime_suspend(struct device *dev)
{
	struct cs4398_private *cs4398 = dev_get_drvdata(dev);
	int ret;

	ret = regmap_update_bits(cs4398->regmap, CS4398_MISC, PWR_DWN, PWR_DWN);
	if (ret < 0)
		return ret;

	regcache_cache_only(cs4398->regmap, true);
*/
	/* Hold down reset */
/*	gpiod_set_value_cansleep(cs4398->reset_gpio, 0);

	return 0;
}

static int cs4398_runtime_resume(struct device *dev)
{
	struct cs4398_private *cs4398 = dev_get_drvdata(dev);
	int ret;

	ret = regmap_update_bits(cs4398->regmap, CS4398_MISC, PWR_DWN, 0);
	if (ret < 0)
		return ret;

	gpiod_set_value_cansleep(cs4398->reset_gpio, 1);

	regcache_cache_only(cs4398->regmap, false);
	regcache_sync(cs4398->regmap);

	return 0;
}
#endif

static const struct dev_pm_ops cs4398_runtime_pm = {
	SET_RUNTIME_PM_OPS(cs4398_runtime_suspend, cs4398_runtime_resume,
			   NULL)
};
*/

static const struct of_device_id cs4398_of_match[] = {
	{ .compatible = "cirrus,cs4398", },
	{},
};

MODULE_DEVICE_TABLE(of, cs4398_of_match);

static const struct i2c_device_id cs4398_i2c_id[] = {
	{"cs4398", 0},
	{}
};

MODULE_DEVICE_TABLE(i2c, cs4398_i2c_id);

static struct i2c_driver cs4398_i2c_driver = {
	.driver = {
		.name		= "cs4398",
		.of_match_table	= cs4398_of_match,
	},
	.id_table	= cs4398_i2c_id,
	.probe		= cs4398_i2c_probe,
	.remove		= cs4398_i2c_remove,
};

module_i2c_driver(cs4398_i2c_driver);

MODULE_AUTHOR("Junkang.Wang<wangjunkang@smartisan.com>");
MODULE_DESCRIPTION("Cirrus Logic CS4398 ALSA SoC Codec Driver");
MODULE_LICENSE("GPL");
