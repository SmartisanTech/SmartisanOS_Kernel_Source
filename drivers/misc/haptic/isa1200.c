/*
** =============================================================================
** Copyright (c) 2017  IMAGIS co.,
**
** This program is free software; you can redistribute it and/or
** modify it under the terms of the GNU General Public License
** as published by the Free Software Foundation; either version 2
** of the License, or (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** File:
**     isa1200.c
**
** Description:
**     ISA1200 Haptic driver
**
** =============================================================================
*/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/i2c.h>
#include <linux/device.h>
#include <asm/uaccess.h>
#include <linux/gpio.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/clk.h>
#include <linux/firmware.h>
#include <linux/of.h>
#include <linux/kthread.h>
#include <linux/of_gpio.h>
#include <linux/regmap.h>
#include <linux/mutex.h>
#include <linux/regmap.h>
#include <linux/workqueue.h>

#include <smartisan/hwstate.h>


#include "isa1200.h"


static uint8_t gRegHPTDRV = 0x11;
static uint8_t gRegSECFG = 0x02;
static uint8_t gRegHptPeriod = 0xcc;

static uint8_t gRegSEHigh = 0x00;
static uint8_t gRegSEFwRvs = 0x00;

static uint16_t gFrequency = BASE_FREQ;

volatile static bool gChip = false;
volatile static bool gClkEn = false;
volatile static bool isDVT2 = false;


stHapticPlayInfo_t *gpHapticPlayer;

#define CMD_MSG_LEN     (128)
static char msg[CMD_MSG_LEN];

stPhe_t gstPheStop = {
    0, 0
};
stPheInfo_t gstPheInfoStop = {
    "Quiscent",
    PHE_STS_QUISCENT,
    BASE_FREQ,
    0x0,
    1,
};

stPhe_t gstPheVibe[] = {
    {0, VIBRATE_AMP}, // 2VRms?
    {1000, 0},
};
stPheInfo_t gstPheInfoVibe = {
    "Vibration",
    PHE_STS_LONG_VIBE,
    BASE_FREQ,
    0x0,
    2,
};


static struct regmap_config isa1200_i2c_regmap = {
    .reg_bits = 8,
    .val_bits = 8,
    .cache_type = REGCACHE_NONE,
};

static uint8_t isa1200_reg_read(stIsa1200Data_t *pIsa1200, uint8_t reg)
{
    int ret;
    uint32_t val = 0;

    ret = regmap_read(pIsa1200->pRegmap, reg, &val);

    if (ret < 0 ) {
        dev_err(pIsa1200->pdev, "err, read 0x%02x (%d)\n",
                reg, ret);
        return ret;
    }

    return (uint8_t)val;
}

static int isa1200_reg_write(stIsa1200Data_t *pIsa1200, uint8_t reg, uint8_t val)
{
    int ret;

    ret = regmap_write(pIsa1200->pRegmap, reg, val);
    if (ret < 0) {
        dev_err(pIsa1200->pdev, "err, write 0x%02x: 0x%02x (%d)\n",
                reg, val, ret);
    }

    return ret;
}

#if 0
static int isa1200_bulk_read(stIsa1200Data_t *pIsa1200,
        uint8_t reg, uint32_t cnt, uint8_t *buf)
{
    int ret;

    ret = regmap_bulk_read(pIsa1200->pRegmap, reg, buf, cnt);
    if (ret < 0) {
        dev_err(pIsa1200->pdev, "err, read 0x%02x - %d (%d)\n", reg, cnt, ret);
    }

    return ret;
}

static int isa1200_bulk_write(stIsa1200Data_t *pIsa1200,
        uint8_t reg, uint32_t cnt, const uint8_t *buf)
{
    int ret;

    ret = regmap_bulk_write(pIsa1200->pRegmap, reg, buf, cnt);
    if (ret < 0) {
        dev_err(pIsa1200->pdev, "err, write 0x%02x - %d (%d)\n", reg, cnt, ret);
    }

    return ret;	
}

static int isa1200_set_bits(stIsa1200Data_t *pIsa1200, uint8_t reg, uint8_t mask, uint8_t val)
{
    int ret;

    ret = regmap_update_bits(pIsa1200->pRegmap, reg, mask, val);
    if (ret < 0) {
        dev_err(pIsa1200->pdev, "err, bit 0x%02x: (%x, %x) (%d)\n",
                reg, mask, val, ret);
    }

    return ret;	
}
#endif

#define isa1200_enable(pdata, en)   \
    gpio_set_value(pdata->stPlatform.en_gpio, (en ? 1 : 0))

static int haptic_player_init(stIsa1200Data_t *pIsa1200)
{
    pr_debug("[HPT] %s\n", __func__);

    isa1200_player_timer_init(pIsa1200);

    pIsa1200->bPlayingHaptic = false;
    pIsa1200->bReadyHaptic = false;

    return 0;
}


static int32_t isa1200_reg_dump(stIsa1200Data_t *pIsa1200, char *pbuf)
{
    int32_t count = 0;

    count += sprintf(msg, "0x%02x: 0x%02x\n", ISA1200_REG_LCTRL,
            isa1200_reg_read(pIsa1200, ISA1200_REG_LCTRL));
    strcat(pbuf, msg);

    count += sprintf(msg, "0x%02x: 0x%02x\n", ISA1200_REG_HPTDRV,
            isa1200_reg_read(pIsa1200, ISA1200_REG_HPTDRV));
    strcat(pbuf, msg);

    count += sprintf(msg, "0x%02x: 0x%02x\n", ISA1200_REG_CLKSEL,
            isa1200_reg_read(pIsa1200, ISA1200_REG_CLKSEL));
    strcat(pbuf, msg);

    count += sprintf(msg, "0x%02x: 0x%02x\n", ISA1200_REG_SECFG,
            isa1200_reg_read(pIsa1200, ISA1200_REG_SECFG));
    strcat(pbuf, msg);

    count += sprintf(msg, "0x%02x: 0x%02x\n", ISA1200_REG_PLLDIV,
            isa1200_reg_read(pIsa1200, ISA1200_REG_PLLDIV));
    strcat(pbuf, msg);

    count += sprintf(msg, "0x%02x: 0x%02x\n", ISA1200_REG_PWMADJ,
            isa1200_reg_read(pIsa1200, ISA1200_REG_PWMADJ));
    strcat(pbuf, msg);

    count += sprintf(msg, "0x%02x: 0x%02x\n", ISA1200_REG_PWMHIGH,
            isa1200_reg_read(pIsa1200, ISA1200_REG_PWMHIGH));
    strcat(pbuf, msg);

    count += sprintf(msg, "0x%02x: 0x%02x\n", ISA1200_REG_PWMPERIOD,
            isa1200_reg_read(pIsa1200, ISA1200_REG_PWMPERIOD));
    strcat(pbuf, msg);

    count += sprintf(msg, "0x%02x: 0x%02x\n", ISA1200_REG_SEHIGH,
            isa1200_reg_read(pIsa1200, ISA1200_REG_SEHIGH));
    strcat(pbuf, msg);

    count += sprintf(msg, "0x%02x: 0x%02x\n", ISA1200_REG_SEPERIOD,
            isa1200_reg_read(pIsa1200, ISA1200_REG_SEPERIOD));
    strcat(pbuf, msg);

    count += sprintf(msg, "0x%02x: 0x%02x\n", ISA1200_REG_SEFWRVS,
            isa1200_reg_read(pIsa1200, ISA1200_REG_SEFWRVS));
    strcat(pbuf, msg);

    return count;
}

static void isa1200_reg_debug(stIsa1200Data_t *pIsa1200)
{
    pr_info("[HPT] ** isa1200 haptic register dump **\n");

    pr_debug("[HPT] 0x%02x: 0x%02x\n", ISA1200_REG_LCTRL,
            isa1200_reg_read(pIsa1200, ISA1200_REG_LCTRL));
    pr_debug("[HPT] 0x%02x: 0x%02x\n", ISA1200_REG_HPTDRV,
            isa1200_reg_read(pIsa1200, ISA1200_REG_HPTDRV));
    pr_debug("[HPT] 0x%02x: 0x%02x\n", ISA1200_REG_CLKSEL,
            isa1200_reg_read(pIsa1200, ISA1200_REG_CLKSEL));
    pr_debug("[HPT] 0x%02x: 0x%02x\n", ISA1200_REG_SECFG,
            isa1200_reg_read(pIsa1200, ISA1200_REG_SECFG));
    pr_debug("[HPT] 0x%02x: 0x%02x\n", ISA1200_REG_PLLDIV,
            isa1200_reg_read(pIsa1200, ISA1200_REG_PLLDIV));
    pr_debug("[HPT] 0x%02x: 0x%02x\n", ISA1200_REG_PWMADJ,
            isa1200_reg_read(pIsa1200, ISA1200_REG_PWMADJ));
    pr_debug("[HPT] 0x%02x: 0x%02x\n", ISA1200_REG_PWMHIGH,
            isa1200_reg_read(pIsa1200, ISA1200_REG_PWMHIGH));
    pr_debug("[HPT] 0x%02x: 0x%02x\n", ISA1200_REG_PWMPERIOD,
            isa1200_reg_read(pIsa1200, ISA1200_REG_PWMPERIOD));
    pr_debug("[HPT] 0x%02x: 0x%02x\n", ISA1200_REG_SEHIGH,
            isa1200_reg_read(pIsa1200, ISA1200_REG_SEHIGH));
    pr_debug("[HPT] 0x%02x: 0x%02x\n", ISA1200_REG_SEPERIOD,
            isa1200_reg_read(pIsa1200, ISA1200_REG_SEPERIOD));
    pr_debug("[HPT] 0x%02x: 0x%02x\n", ISA1200_REG_SEFWRVS,
            isa1200_reg_read(pIsa1200, ISA1200_REG_SEFWRVS));

    pr_debug("[HPT] ** ******* ****** ******** **** **\n");
}

#if 0
int isa1200_extclk_enable(stIsa1200Data_t *pIsa1200, bool enable)
{
    int ret = 0;
#if 0
    struct pinctrl_state *ppin_state;
#endif
    stIsa1200Platform_t *pPlat = &pIsa1200->stPlatform;

    pr_info("[HPT] %s: \n", __func__);
    //mutex_lock(&pIsa1200->clk_lock);

#if 0
    ppin_state = pinctrl_lookup_state(pPlat->clk_pinctrl,
            (enable ? "enable" : "disable"));

    if (IS_ERR(ppin_state)) {
        pr_err("[HPT] cannot get lookup state %d\n", enable);
        return -EINVAL;
    }

    ret = pinctrl_select_state(pPlat->clk_pinctrl, ppin_state);
    if (ret) {
        pr_err("[HPT] cannot set pinctrl %d\n", enable);
        return -EINVAL;
    }
#endif

    pr_info("[HPT] %s, ==> enable:%d\n", __func__, enable);
    if (enable) {
        if (!gClkEn) {
            pr_info("[HPT] %s, ==> clk_prepare_enable(%p)\n", __func__, pPlat->ext_clk);
            ret = clk_prepare_enable(pPlat->ext_clk);
            if (ret) {
                pr_err("[HPT] failed to open isa1200 ext_clk\n");
                return -EINVAL;
            }
            pr_info("[HPT] %s, open ext_clk successful\n", __func__);
            gClkEn = true;
        }
    } else {
        if (gClkEn) {
            pr_info("[HPT] %s, ==> clk_disable_unprepare(%p)\n", __func__, pPlat->ext_clk);
            clk_disable_unprepare(pPlat->ext_clk);
            pr_info("[HPT] %s, close ext_clk successful\n", __func__);
            gClkEn = false;
        }
    }

    //mutex_unlock(&pIsa1200->clk_lock);

    pr_info("[HPT] %s, <== enable:%d\n", __func__, enable);
    return 0;
}
#else
int isa1200_extclk_enable(stIsa1200Data_t *pIsa1200, bool enable)
{
    int ret = 0;
    struct pinctrl_state *ppin_state;
    stIsa1200Platform_t *pPlat = &pIsa1200->stPlatform;

    if (enable == gClkEn) {
        pr_debug("[HPT] %s, same ext_clk\n", __func__);
        return 0;
    }

    ppin_state = pinctrl_lookup_state(pPlat->clk_pinctrl,
            (enable ? "enable" : "disable"));

    if (IS_ERR(ppin_state)) {
        pr_err("[HPT] cannot get lookup state %d\n", enable);
        return -EINVAL;
    }

    ret = pinctrl_select_state(pPlat->clk_pinctrl, ppin_state);
    if (ret) {
        pr_err("[HPT] cannot set pinctrl %d\n", enable);
        return -EINVAL;
    }

    if (enable == true) {
        ret = clk_prepare_enable(pPlat->ext_clk);
        if (ret) {
            pr_err("[HPT] failed to open isa1200 ext_clk\n");
            return -EINVAL;
        }
        pr_debug("[HPT] %s, open ext_clk successful\n", __func__);
    }
    else {
        clk_disable_unprepare(pPlat->ext_clk);
        pr_debug("[HPT] %s, close ext_clk successful\n", __func__);
    }
    gClkEn = enable;

    return 0;
}
#endif

void isa1200_haptic_reset(stIsa1200Data_t *pIsa1200)
{
    isa1200_reg_write(pIsa1200, ISA1200_REG_LCTRL, 0x87);
    mdelay(10);
    isa1200_reg_write(pIsa1200, ISA1200_REG_LCTRL, 0x07);
}

int isa1200_haptic_enable(stIsa1200Data_t *pIsa1200, bool enable)
{
    int ret = 0;

    if (enable == true) {
        if ((gRegHPTDRV & ISA1200_HPTEN_MASK) == ISA1200_HPTEN_MASK)
            return 0;

        gRegHPTDRV |= ISA1200_HPTEN_MASK;
    }
    else {
        if ((gRegHPTDRV & ISA1200_HPTEN_MASK) != ISA1200_HPTEN_MASK)
            return 0;

        gRegHPTDRV &= ~ISA1200_HPTEN_MASK;
    }

    pr_info("[HPT] %s, %d\n", __func__, enable ? 1 : 0);

    if (enable == true)
        isa1200_extclk_enable(pIsa1200, true);

    ret = isa1200_reg_write(pIsa1200, ISA1200_REG_HPTDRV, gRegHPTDRV);
    if (ret < 0) {
        pr_err("[HPT] %s, reg_write fail, - %d\n", __func__, enable);
        return ret;
    }

    if (enable == false)
        isa1200_extclk_enable(pIsa1200, false);

    return 0;
}


int isa1200_set_frequency(stIsa1200Data_t *pIsa1200, uint16_t freq)
{
    int i;
    int ret = 0;
    uint16_t div1, div2;
    uint32_t period = 0;
    uint8_t reg_period = 0;
    uint8_t reg_adj = 0;
    int8_t adj = 0;
    uint64_t diff;
    uint64_t freq1, freq_temp;

    stIsa1200Platform_t *pPlat = &pIsa1200->stPlatform;

    if (gFrequency == freq)
        return ret;

    div1 = div2 = 0;
    if (pPlat->input_freq <= 5500000) {
        div1 = 128;
        div2 = 1;
    } else if (pPlat->input_freq <= 11300000) {
        div1 = 256;
        div2 = 1;
    } else if (pPlat->input_freq <= 22600000) {
        div1 = 256;
        div2 = 2;
    } else if (pPlat->input_freq <= 45000000) {
        div1 = 256;
        div2 = 4;
    } else if (pPlat->input_freq <= 50000000) {
        div1 = 256;
        div2 = 8;
    }

    period = (pPlat->input_freq / freq / div1 / div2) + 1;

    //pr_debug("[HPT] in: %d, div1: %d, div2: %d, period: %d\n", pPlat->input_freq, div1, div2, period);

    if ((period < 100) || (period > 255)) {
        while (period > 255) {
            period >>= 1;
            if (div2 < 128)
                div2 <<= 1;
            else
                div1 <<= 1;
        }

        while (period < 100) {
            if (div2 > 1)
                div2 >>= 1;
            else
                div1 >>= 1;

            period = (pPlat->input_freq / freq / div1 / div2) * 2;
        }
    }

    //pr_debug("[HPT] period: %d, div2: %d\n", period, div2);

    reg_period = (period & 0xFE);
    freq_temp = (1000 * pPlat->input_freq / div2 / reg_period);

    freq1 = 0;
    diff = abs(freq*1000 - freq1);

    for (i = -32; i <= 32; i++) {
        freq1 = freq_temp / ((div1 / 2 + i) * 2);

        if (diff > abs(freq*1000 - freq1)) {
            diff = abs(freq*1000- freq1);
            adj = i;
        }
    }

    reg_adj  = (adj < 0) ? (1 << 7) : 0;
    reg_adj |= abs(adj);
    freq1 = 1000 * pPlat->input_freq / div2 / reg_period / (div1 + adj * 2);

#if 0
    pr_debug("[HPT]  isa1200 settings\n");
    pr_debug("[HPT]  target: %d, in: %d\n", freq, pPlat->input_freq);
    pr_debug("[HPT]  div1: %d, div2: %d\n", div1, div2);
    pr_debug("[HPT]  period: %d, adj: %d\n", reg_period, adj);
    pr_info ("[HPT]  real freq : %d.%d\n",
            (int)(freq1/1000), (int)((freq1/100)%10));
#endif

    gRegHPTDRV &= 0xFC;
    gRegHPTDRV |= (div1 >> 8);

    gRegHptPeriod = reg_period;
    gRegSEHigh = reg_period >> 1;

    ret = isa1200_reg_write(pIsa1200, ISA1200_REG_HPTDRV, gRegHPTDRV);
    if (ret < 0)
        return ret;
    ret = isa1200_reg_write(pIsa1200, ISA1200_REG_PLLDIV, ((div2>>1) << 4));
    if (ret < 0)
        return ret;
#if 0
    ret = isa1200_reg_write(pIsa1200, ISA1200_REG_PWMADJ, reg_adj);
    if (ret < 0)
        goto fail_set_freq;
#endif
    ret = isa1200_reg_write(pIsa1200, ISA1200_REG_PWMHIGH, reg_period >> 1);
    if (ret < 0)
        return ret;
    ret = isa1200_reg_write(pIsa1200, ISA1200_REG_PWMPERIOD, reg_period);
    if (ret < 0)
        return ret;
    ret = isa1200_reg_write(pIsa1200, ISA1200_REG_SEHIGH, gRegSEHigh);
    if (ret < 0)
        return ret;
    ret = isa1200_reg_write(pIsa1200, ISA1200_REG_SEPERIOD, reg_period);
    if (ret < 0)
        return ret;

    //pr_info("[HPT] freq: %d -> %d(0x%02x)\n", gFrequency, freq, reg_period);

    gFrequency = freq;

    return 0;
}

static int16_t isa1200_get_frequency(stIsa1200Data_t *pIsa1200)
{
    int16_t freq = 0;

    /* */

    return freq;
}

int isa1200_set_se(stIsa1200Data_t *pIsa1200, stSimpleEfft_t *pse)
{
    int ret = 0;
    uint8_t reg;
    uint32_t gain = 0;

    //pr_info("[HPT]    amp: %d, fw: %d, rvs: %d\n", pse->amp, pse->fwd, pse->rvs);

    gain = (pse->amp / 2) + 500;
    if (gain <= 0)
        gain = 0;
    else if (gain >= 1000)
        gain = 1000;

    gain = (gain * gRegHptPeriod / 1000);
    reg  = (uint8_t)gain;

    if (gRegSEHigh != reg) {
        gRegSEHigh = reg;
        ret = isa1200_reg_write(pIsa1200, ISA1200_REG_SEHIGH, gRegSEHigh);
        if (ret < 0)
            return ret;
    }

    reg = (pse->fwd << 3) | pse->rvs;
    if (gRegSEFwRvs != reg) {
        gRegSEFwRvs = reg;
        ret = isa1200_reg_write(pIsa1200, ISA1200_REG_SEFWRVS, gRegSEFwRvs);
        if (ret < 0)
            return ret;
    }

    ret = isa1200_haptic_enable(pIsa1200, true);
    if (ret < 0)
        return ret;

    gRegSECFG = isa1200_reg_read(pIsa1200, ISA1200_REG_SECFG);

    if (gRegSECFG & 0x01)
        gRegSECFG &= ~(1 << 0);
    else
        gRegSECFG |= (1 << 0);
    ret = isa1200_reg_write(pIsa1200, ISA1200_REG_SECFG, gRegSECFG);
    if (ret < 0)
        return ret;

    return 0;
}


int isa1200_set_fast_haptic(stIsa1200Data_t *pIsa1200,
        stPheInfo_t *pinfo, stPhe_t *pphe, stSimpleEfft_t *pse)
{
#if 1
    int i;
    int fwd = 0, rvs = 0;

    if ((pinfo->count < 2) || (pinfo->count > 3))
        return -1;

    /* invalid se amp */
    for (i = 0; i < pinfo->count - 1; i++) {
        if (pphe[i].amp == 0)
            return -1;
    }

    if (pinfo->count == 3) {
        fwd = (pphe[1].ms - pphe[0].ms);
        rvs = (pphe[2].ms - pphe[1].ms);
        if ((fwd < 0) || (rvs < 0))
            return -1;

        fwd = fwd * pinfo->freq / 1000;
        rvs = rvs * pinfo->freq / 1000;

        fwd += 1;
        rvs += 1;
    }
    else if (pinfo->count == 2) {
        fwd = (pphe[1].ms - pphe[0].ms);
        if (fwd < 0)
            return -1;

        fwd = fwd * pinfo->freq / 1000;

        fwd += 1;
        rvs = 0;
    }

    pse->amp = (int16_t)pphe[0].amp;
    pse->freq = (uint16_t)pinfo->freq;
    pse->fwd = (uint8_t)fwd;
    pse->rvs = (uint8_t)rvs;

    return 0;
#else
    return -1;
#endif
}

/* set strength : -1000 ~ 1000 */
int isa1200_set_amplitude(stIsa1200Data_t *pIsa1200, int16_t amp)
{
    uint8_t reg;
    uint32_t gain = 0;

    //pr_info("[HPT]    amp: %d\n", amp);

    if (amp == 0) {
        isa1200_haptic_enable(pIsa1200, false);
        return 0;
    }

    gain = (amp / 2) + 500;
    if (gain <= 0)
        gain = 0;
    else if (gain >= 1000)
        gain = 1000;

    gain = (gain * gRegHptPeriod / 1000);
    reg = (uint8_t)gain;

    isa1200_reg_write(pIsa1200, ISA1200_REG_PWMHIGH, reg);

    if (amp == 0) {
        isa1200_haptic_enable(pIsa1200, false);
    } else {
        if ((gRegHPTDRV & (1 << 7)) == 0) {   // Haptic disable
            isa1200_haptic_enable(pIsa1200, true);
        }
    }

    return 0;
}

static int isa1200_get_amplitude(stIsa1200Data_t *pIsa1200)
{
    int16_t amp = 0;

    /* */

    return amp;
}

static bool isa1200_check_haptic_enable(stIsa1200Data_t *pIsa1200)
{
    bool enable = TRUE;

    /* */

    return enable;
}


static void isa1200_set_vpp(stIsa1200Data_t *pIsa1200, int16_t vpp)
{
    /* */
}

static int16_t isa1200_get_vpp(stIsa1200Data_t *pIsa1200)
{
    int16_t vpp = 0;

    /* */

    return vpp;
}


int isa1200_dump_phe_bin(stPheBin_t *pbin, char *pbuf)
{
    int i;
    int count = 0;
    char name[21] = {0, };

    stPheBinHeader_t *pheader = &pbin->header;
    stPheInfo_t *pinfo;

    if (pbin->pbuf == NULL) {
        return sprintf(pbuf, "Err, bin buffer is not allocation\n");
    }

    pr_debug("[HPT] Header info\n");
    pr_debug("[HPT] size: %d, count: %d\n", pheader->size, pheader->count);

    count += sprintf(msg, "Bin Header info\n");
    strcat(pbuf, msg);
    count += sprintf(msg, "size: %d, count: %d\n", pheader->size, pheader->count);
    strcat(pbuf, msg);

    for (i = 0; i < pheader->count; i++) {
        pinfo = &pbin->pinfo[i];
        memcpy(name, pinfo->name, sizeof(pinfo->name));
        pr_debug("[HPT] %2d %s: 0x%d (%d) - %d, %d\n", i + 1,
                name, pinfo->addr, pinfo->count, pinfo->freq, pinfo->status);
        count += sprintf(msg, " %d %s: 0x%d (%d) - %d, %d\n", i + 1, 
                name, pinfo->addr, pinfo->count, pinfo->freq, pinfo->status);
        strcat(pbuf, msg);
    }

    return count;
}

bool isa1200_parse_phe_bin(stPheBin_t *pbin)
{
    int i;
    char name[21] = {0, };

    stPheBinHeader_t *pheader = &pbin->header;
    stPheInfo_t *pinfo;

    if (pbin->pbuf == NULL)
        return false;

    memcpy(pheader, pbin->pbuf, sizeof(pbin->header));
    pr_debug("[HPT] header info\n");
    pr_debug("[HPT] size: %d, count: %d\n", pheader->size, pheader->count);

    pbin->pinfo = (stPheInfo_t *)&pbin->pbuf[sizeof(pbin->header)];

    for (i = 0; i < pheader->count; i++) {
        pinfo = &pbin->pinfo[i];
        memcpy(name, pinfo->name, sizeof(pinfo->name));
        pr_debug("[HPT] %2d %s: 0x%d (%d) - %d, %d\n", i + 1, pinfo->name,
                pinfo->addr, pinfo->count, pinfo->freq, pinfo->status);
    }

    return true;
}


static void isa1200_reg_init(stIsa1200Data_t *pIsa1200)
{
    pr_info("[HPT] %s\n", __func__);
    /*
     * input: 19.8MHz, out: 205.7Hz
     * 0x00 : 0x0f
     * 0x30 : 0x11
     * 0x31 : 0xc0
     * 0x32 : 0x00
     * 0x33 : 0x13
     * 0x34 : 0x00
     * 0x35 : 0x5e
     * 0x36 : 0xbc
     */

    gRegSEHigh = (gRegHptPeriod/2);
    gRegSECFG = 0x02;

    /* Manual initialize */
    isa1200_reg_write(pIsa1200, ISA1200_REG_LCTRL, 0x87);
    isa1200_reg_write(pIsa1200, ISA1200_REG_HPTDRV, gRegHPTDRV);
    isa1200_reg_write(pIsa1200, ISA1200_REG_CLKSEL, 0xc0);
    isa1200_reg_write(pIsa1200, ISA1200_REG_SECFG, gRegSECFG);
    isa1200_reg_write(pIsa1200, ISA1200_REG_PLLDIV, 0x13);
    isa1200_reg_write(pIsa1200, ISA1200_REG_PWMADJ, 0x00);
    isa1200_reg_write(pIsa1200, ISA1200_REG_PWMHIGH,  (gRegHptPeriod/2));
    isa1200_reg_write(pIsa1200, ISA1200_REG_PWMPERIOD, gRegHptPeriod);
    isa1200_reg_write(pIsa1200, ISA1200_REG_SEHIGH  , gRegSEHigh);
    isa1200_reg_write(pIsa1200, ISA1200_REG_SEPERIOD,  gRegHptPeriod);

    isa1200_reg_write(pIsa1200, ISA1200_REG_LCTRL, 0x07);

    pIsa1200->bConfigured = true;
}


static int isa1200_configure(stIsa1200Data_t *pIsa1200)
{
    stIsa1200Platform_t *pPlat = &pIsa1200->stPlatform;

    pr_info("[HPT] isa1200 configure\n");

    if (pPlat->use_en) {
        isa1200_enable(pIsa1200, true);
        mdelay(5);
        //pr_info("[HPT] set isa1200 enable gpio high\n");
    }

    isa1200_reg_init(pIsa1200);
    //isa1200_reg_debug(pIsa1200); // for debug, check i2c write

    pIsa1200->bPlayingHaptic = false;
    pIsa1200->bReadyHaptic = false;

    return 0;
}


/* sysfs : /sys/class/haptic/debug/hen */
ssize_t isa1200_hen_store(struct device *dev, struct device_attribute *attr,
        const char *buf, size_t size)
{
    int32_t enable = 0;

    stIsa1200Data_t *pIsa1200 = dev_get_drvdata(dev);

    if (kstrtoint(buf, 10, &enable) < 0) {
        pr_err("[HPT] %s, kstrtoint fail\n", __func__);
        return size;
    }

    pr_debug("[HPT] hen enable: %d\n", (int)enable);

    mutex_lock(&pIsa1200->lock);

    isa1200_enable(pIsa1200, (enable == 0 ? false : true));

    mutex_unlock(&pIsa1200->lock);

    return size;
}

ssize_t isa1200_hen_show(struct device *dev, struct device_attribute *attr,
        char *buf)
{
    return 0;
}

/* sysfs : /sys/class/haptic/debug/extclk */
ssize_t isa1200_extclk_store(struct device *dev, struct device_attribute *attr,
        const char *buf, size_t size)
{
    int32_t enable = 0;

    stIsa1200Data_t *pIsa1200 = dev_get_drvdata(dev);

    if (kstrtoint(buf, 10, &enable) < 0) {
        pr_err("[HPT] %s, kstrtoint fail\n", __func__);
        return size;
    }

    pr_debug("[HPT] extclk enable: %d\n", (int)enable);

    mutex_lock(&pIsa1200->lock);

    isa1200_extclk_enable(pIsa1200, enable);

    mutex_unlock(&pIsa1200->lock);

    return size;
}

ssize_t isa1200_extclk_show(struct device *dev, struct device_attribute *attr,
        char *buf)
{
    return 0;
}

/* sysfs : /sys/class/haptic/debug/vpp */
ssize_t isa1200_vpp_store(struct device *dev, struct device_attribute *attr,
        const char *buf, size_t size)
{
    int32_t vpp = 0;

    stIsa1200Data_t *pIsa1200 = dev_get_drvdata(dev);

    if (kstrtoint(buf, 10, &vpp) < 0) {
        pr_err("[HPT] %s, kstrtoint fail\n", __func__);
        return size;
    }

    pr_debug("[HPT] Vpp: %d\n", (int16_t)vpp);

    mutex_lock(&pIsa1200->lock);

    isa1200_set_vpp(pIsa1200, (int16_t)vpp);

    mutex_unlock(&pIsa1200->lock);

    return size;
}

ssize_t isa1200_vpp_show(struct device *dev, struct device_attribute *attr,
        char *buf)
{
    int count = 0;
    int16_t vpp = 0;

    stIsa1200Data_t *pIsa1200 = dev_get_drvdata(dev);

    mutex_lock(&pIsa1200->lock);

    vpp = isa1200_get_vpp(pIsa1200);

    mutex_unlock(&pIsa1200->lock);

    count = sprintf(buf, "Vpp: %dV\n", (int)vpp);

    return count;
}

/* sysfs : /sys/class/haptic/debug/reg */
stRegCmd_t gstRegCmd;
ssize_t isa1200_reg_store(struct device *dev, struct device_attribute *attr,
        const char *buf, size_t size)
{
    stRegCmd_t *pReg = &gstRegCmd;

    stIsa1200Data_t *pIsa1200 = dev_get_drvdata(dev);

    mutex_lock(&pIsa1200->lock);

    memset(pReg, 0, sizeof(stRegCmd_t));
    memset(msg, 0, sizeof(msg));

    //sprintf(msg, "%s", buf);

    sscanf(buf, "%c %x %x", &pReg->cmd, &pReg->addr, &pReg->val);

    switch (pReg->cmd) {
        case 'w':
        case 'W':
            isa1200_reg_write(pIsa1200, pReg->addr, pReg->val);
            break;

        case 'r':
        case 'R':
            pReg->val = isa1200_reg_read(pIsa1200, pReg->addr);
            break;
    }

    mutex_unlock(&pIsa1200->lock);

    return size;
}

ssize_t isa1200_reg_show(struct device *dev, struct device_attribute *attr,
        char *buf)
{
    int count = 0;

    stIsa1200Data_t *pIsa1200 = dev_get_drvdata(dev);

    stRegCmd_t *pReg = &gstRegCmd;

    mutex_lock(&pIsa1200->lock);

    switch (pReg->cmd) {
        case 'w':
        case 'W':
            count = sprintf(buf, "w 0x%02x: 0x%02x\n", pReg->addr, pReg->val);
            break;

        case 'r':
        case 'R':
            count = sprintf(buf, "r 0x%02x: 0x%02x\n", pReg->addr, pReg->val);
            break;
        default:
            count = sprintf(buf, "Unknown cmd\n");
    }

    mutex_unlock(&pIsa1200->lock);

    return count;
}

/* sysfs : /sys/class/haptic/debug/reg_init */
ssize_t isa1200_reg_init_store(struct device *dev, struct device_attribute *attr,
        const char *buf, size_t size)
{
    return size;
}

ssize_t isa1200_reg_init_show(struct device *dev, struct device_attribute *attr,
        char *buf)
{
    int count = 0;

    stIsa1200Data_t *pIsa1200 = dev_get_drvdata(dev);

    pr_debug("[HPT] register init\n");

    mutex_lock(&pIsa1200->lock);

    isa1200_reg_init(pIsa1200);
    isa1200_reg_debug(pIsa1200); // for debug, check i2c write

    mutex_unlock(&pIsa1200->lock);

    return count;
}

/* sysfs : /sys/class/haptic/debug/reg_dump */
ssize_t isa1200_reg_dump_store(struct device *dev, struct device_attribute *attr,
        const char *buf, size_t size)
{
    return size;
}

ssize_t isa1200_reg_dump_show(struct device *dev, struct device_attribute *attr,
        char *buf)
{
    int count = 0;

    stIsa1200Data_t *pIsa1200 = dev_get_drvdata(dev);

    pr_info("[HPT] register dump\n");

    mutex_lock(&pIsa1200->lock);

    count = isa1200_reg_dump(pIsa1200, buf);
    if (count > 2048)
        count = 2048;

    mutex_unlock(&pIsa1200->lock);

    return count;
}

/* sysfs : /sys/class/haptic/player/freq */
ssize_t isa1200_freq_store(struct device *dev, struct device_attribute *attr,
        const char *buf, size_t size)
{
    int32_t freq = 0;

    stIsa1200Data_t *pIsa1200 = dev_get_drvdata(dev);

    if (kstrtoint(buf, 10, &freq) < 0) {
        pr_err("[HPT] %s, kstrtoint fail\n", __func__);
        return size;
    }

    mutex_lock(&pIsa1200->lock);

    pr_info("[HPT] set freq: %d\n", (uint16_t)freq);

    isa1200_set_frequency(pIsa1200, (uint16_t)freq);

    mutex_unlock(&pIsa1200->lock);

    return size;
}

ssize_t isa1200_freq_show(struct device *dev, struct device_attribute *attr,
        char *buf)
{
    int count = 0;
    int16_t freq = 0;

    stIsa1200Data_t *pIsa1200 = dev_get_drvdata(dev);

    mutex_lock(&pIsa1200->lock);

    freq = isa1200_get_frequency(pIsa1200);

    count = sprintf(buf, "freq: %d", freq);

    pr_info("[HPT] get freq: %d\n", freq);

    mutex_unlock(&pIsa1200->lock);

    return count;
}

/* sysfs : /sys/class/haptic/player/amp */
ssize_t isa1200_amp_store(struct device *dev, struct device_attribute *attr,
        const char *buf, size_t size)
{
    int32_t amp = 0;

    stIsa1200Data_t *pIsa1200 = dev_get_drvdata(dev);

    if (kstrtoint(buf, 10, &amp) < 0) {
        pr_err("[HPT] %s, kstrtoint fail\n", __func__);
        return size;
    }

    mutex_lock(&pIsa1200->lock);

    pr_info("[HPT] set amp: %d\n", (int16_t)amp);

    isa1200_set_amplitude(pIsa1200, (int16_t)amp);

    mutex_unlock(&pIsa1200->lock);

    return size;
}

ssize_t isa1200_amp_show(struct device *dev, struct device_attribute *attr,
        char *buf)
{
    int count = 0;
    int16_t amp = 0;

    stIsa1200Data_t *pIsa1200 = dev_get_drvdata(dev);

    mutex_lock(&pIsa1200->lock);

    amp = isa1200_get_amplitude(pIsa1200);

    count = sprintf(buf, "amp: %d", amp);

    pr_info("[HPT] get amp: %d\n", amp);

    mutex_unlock(&pIsa1200->lock);

    return count;
}

/* sysfs : /sys/class/haptic/player/play */
ssize_t isa1200_play_store(struct device *dev, struct device_attribute *attr,
        const char *buf, size_t size)
{
    int32_t amp = 0, ms = 0;

    stIsa1200Data_t *pIsa1200 = dev_get_drvdata(dev);

    mutex_lock(&pIsa1200->lock);

    sscanf(buf, "%d %d", &amp, &ms);

    pr_info("[HPT] haptic play - amp: %d, ms: %d\n", amp, ms);

    isa1200_set_amplitude(pIsa1200, (int16_t)amp);
    isa1200_haptic_enable(pIsa1200, true);

    msleep(ms);

    isa1200_haptic_enable(pIsa1200, false);
    isa1200_set_amplitude(pIsa1200, 0);

    mutex_unlock(&pIsa1200->lock);

    return size;
}

ssize_t isa1200_play_show(struct device *dev, struct device_attribute *attr,
        char *buf)
{
    int count = 0;

    stIsa1200Data_t *pIsa1200 = dev_get_drvdata(dev);

    mutex_lock(&pIsa1200->lock);

    isa1200_haptic_enable(pIsa1200, false);

    mutex_unlock(&pIsa1200->lock);

    count = sprintf(buf, "haptic play stop\n");

    pr_info("[HPT] haptic stop\n");

    return count;
}

/* sysfs : /sys/class/haptic/player/se */
ssize_t isa1200_play_se_store(struct device *dev, struct device_attribute *attr,
        const char *buf, size_t size)
{
    stSimpleEfft_t se;
    int32_t amp = 0, fwd = 0, rvs = 0;

    stIsa1200Data_t *pIsa1200 = dev_get_drvdata(dev);

    mutex_lock(&pIsa1200->lock);

    sscanf(buf, "%d %d %d", &amp, &fwd, &rvs);

    pr_info("[HPT] haptic play - amp: %d, fwd: %d, rvs: %d\n", amp, fwd, rvs);

    se.freq = BASE_FREQ;
    se.amp = (int16_t)amp;
    se.fwd = (uint8_t)fwd;
    se.rvs = (uint8_t)rvs;

    isa1200_set_se(pIsa1200, &se);

    mutex_unlock(&pIsa1200->lock);

    return size;
}

ssize_t isa1200_play_se_show(struct device *dev, struct device_attribute *attr,
        char *buf)
{
    return 0;
}


/* sysfs : /sys/class/haptic/player/enable */
ssize_t isa1200_haptic_enable_store(struct device *dev, struct device_attribute *attr,
        const char *buf, size_t size)
{
    int32_t enable = 0;

    stIsa1200Data_t *pIsa1200 = dev_get_drvdata(dev);

    if (kstrtoint(buf, 10, &enable) < 0) {
        pr_err("[HPT] %s, kstrtoint fail\n", __func__);
        return size;
    }

    mutex_lock(&pIsa1200->lock);

    pr_info("[HPT] haptic enable: %d\n", (int)enable);

    isa1200_haptic_enable(pIsa1200, (enable == 0 ? false : true));

    mutex_unlock(&pIsa1200->lock);

    return size;
}

ssize_t isa1200_haptic_enable_show(struct device *dev, struct device_attribute *attr,
        char *buf)
{
    int count = 0;
    bool enable = FALSE;

    stIsa1200Data_t *pIsa1200 = dev_get_drvdata(dev);

    mutex_lock(&pIsa1200->lock);

    enable = isa1200_check_haptic_enable(pIsa1200);

    count = sprintf(buf, "haptic enable: %s", (enable ? "TRUE" : "FALSE"));

    mutex_unlock(&pIsa1200->lock);

    return count;
}

/* sysfs : /sys/class/haptic/player/load_bin */
ssize_t isa1200_load_bin_show(struct device *dev, struct device_attribute *attr,
        char *buf)
{
    int count = 0;
    mm_segment_t old_fs = { 0 };
    struct file *fp = NULL;

    long fsize = 0, rsize = 0;
    char bin_path[MAX_FILE_PATH];

    stIsa1200Data_t *pIsa1200 = dev_get_drvdata(dev);

    stPheBin_t *pbin = &pIsa1200->stBin;

    mutex_lock(&pIsa1200->lock);

    old_fs = get_fs();
    set_fs(get_ds());

    snprintf(bin_path, sizeof(bin_path), "/vendor/etc/effects/%s", PHE_BIN_NAME);
    fp = filp_open(bin_path, O_RDONLY, 0);
    if (IS_ERR(fp)) {
        pr_err("[HPT] err, file %s open - %ld\n", bin_path, PTR_ERR(fp));
        goto err_open_load_bin_show;
    }

    fsize = fp->f_path.dentry->d_inode->i_size;
    if (fsize <= 0) {
        pr_err("[HPT] err, file size: %ld\n", fsize);
        goto err_load_bin_show;
    }

    if (pbin->pbuf != NULL)
        kfree(pbin->pbuf);

    pbin->pbuf = (uint8_t *)kmalloc((int)fsize, GFP_KERNEL);

    rsize = vfs_read(fp, (char __user *)pbin->pbuf, fsize, &fp->f_pos);
    if (rsize != fsize) {
        pr_err("[HPT] err, mismatch size - fsize: %ld, rsize: %ld\n",
                fsize, rsize);
        goto err_load_bin_show;
    }

    filp_close(fp, current->files);

    set_fs(old_fs);

    isa1200_parse_phe_bin(pbin);

    pr_info("[HPT] PHE bin loaded!! - %s (%ld)\n", bin_path, fsize);

    count = sprintf(buf, "PHE bin is loaded!! - %s (%ld)\n", bin_path, fsize);

    mutex_unlock(&pIsa1200->lock);

    return count;

err_load_bin_show:
    filp_close(fp, NULL);
err_open_load_bin_show:
    count = sprintf(buf, "Err(%ld), PHE bin is not loaded!! - %s (%ld)\n", 
            PTR_ERR(fp), bin_path, fsize);
    set_fs(old_fs);

    mutex_unlock(&pIsa1200->lock);

    return  count;
}

/* sysfs : /sys/class/haptic/player/load_bin_sdcard */
ssize_t isa1200_load_bin_sdcard_show(struct device *dev, struct device_attribute *attr,
        char *buf)
{
    int count = 0;
    mm_segment_t old_fs = { 0 };
    struct file *fp = NULL;

    long fsize = 0, rsize = 0;
    char bin_path[MAX_FILE_PATH];

    stIsa1200Data_t *pIsa1200 = dev_get_drvdata(dev);

    stPheBin_t *pbin = &pIsa1200->stBin;

    mutex_lock(&pIsa1200->lock);

    old_fs = get_fs();
    set_fs(get_ds());

    snprintf(bin_path, sizeof(bin_path), "/sdcard/%s", PHE_BIN_NAME);
    fp = filp_open(bin_path, O_RDONLY, 0);
    if (IS_ERR(fp)) {
        pr_err("[HPT] err, file %s open - %ld\n", bin_path, PTR_ERR(fp));
        goto err_open_load_bin_sdcard_show;
    }

    fsize = fp->f_path.dentry->d_inode->i_size;
    if (fsize <= 0) {
        pr_err("[HPT] err, file size: %ld\n", fsize);
        goto err_load_bin_sdcard_show;
    }

    if (pbin->pbuf != NULL)
        kfree(pbin->pbuf);

    pbin->pbuf = (uint8_t *)kmalloc((int)fsize, GFP_KERNEL);

    rsize = vfs_read(fp, (char __user *)pbin->pbuf, fsize, &fp->f_pos);
    if (rsize != fsize) {
        pr_err("[HPT] err, mismatch size - fsize: %ld, rsize: %ld\n",
                fsize, rsize);
        goto err_load_bin_sdcard_show;
    }

    filp_close(fp, current->files);

    set_fs(old_fs);

    isa1200_parse_phe_bin(pbin);

    pr_info("[HPT] PHE bin loaded!! - %s (%ld)\n", bin_path, fsize);

    count = sprintf(buf, "PHE bin is loaded!! - %s (%ld)\n", bin_path, fsize);

    mutex_unlock(&pIsa1200->lock);

    return count;

err_load_bin_sdcard_show:
    filp_close(fp, NULL);
err_open_load_bin_sdcard_show:
    count = sprintf(buf, "Err(%ld), PHE bin is not loaded!! - %s (%ld)\n", 
            PTR_ERR(fp), bin_path, fsize);
    set_fs(old_fs);

    mutex_unlock(&pIsa1200->lock);

    return  count;
}

/* sysfs : /sys/class/haptic/player/load_init_bin */
ssize_t isa1200_load_init_bin_show(struct device *dev, struct device_attribute *attr,
        char *buf)
{
    int ret = 0;
    int count = 0;
    const struct firmware *pfw = NULL;

    stIsa1200Data_t *pIsa1200 = dev_get_drvdata(dev);

    stPheBin_t *pbin = &pIsa1200->stBin;

    mutex_lock(&pIsa1200->lock);

    ret = request_firmware(&pfw, PHE_BIN_NAME, &pIsa1200->client->dev);
    if (ret) {
        pr_err("[HPT] err, no request firmware(%s) - %d\n", PHE_BIN_NAME, ret);
        count = sprintf(buf, "err, no req_firmware!! - %s\n", PHE_BIN_NAME);
        goto err_open_init_bin_show;
    }

    if (pbin->pbuf != NULL)
        kfree(pbin->pbuf);

    pbin->pbuf = (uint8_t *)kmalloc((int)pfw->size, GFP_KERNEL);
    if (unlikely(!pbin->pbuf)) {
        count = sprintf(buf, "err, allocate fw memory!! - %s\n", PHE_BIN_NAME);
        goto err_load_init_bin_show;
    }

    memcpy(pbin->pbuf, pfw->data, (int)pfw->size);

    isa1200_parse_phe_bin(pbin);

    pr_info("[HPT] PHE init bin loaded!! (%ld)\n", pfw->size);

    count = sprintf(buf, "PHE init bin is loaded!! - (%ld)\n", pfw->size);

err_load_init_bin_show:
    release_firmware(pfw);
err_open_init_bin_show:

    mutex_unlock(&pIsa1200->lock);

    return count;
}

/* sysfs : /sys/class/haptic/player/print_bin_info */
ssize_t isa1200_print_bin_info_show(struct device *dev, struct device_attribute *attr,
        char *buf)
{
    int count = 0;

    stIsa1200Data_t *pIsa1200 = dev_get_drvdata(dev);

    mutex_lock(&pIsa1200->lock);

    count = isa1200_dump_phe_bin(&pIsa1200->stBin, buf);
    if (count > 2048)
        count = 2048;

    mutex_unlock(&pIsa1200->lock);

    return count;
}

/* sysfs : /sys/class/haptic/player/phe */
ssize_t isa1200_phe_index_store(struct device *dev,
        struct device_attribute *attr, const char *buf, size_t size)
{
    int ret;
    int idx = 0;
    char name[21] = {0, };

    stIsa1200Data_t *pIsa1200 = dev_get_drvdata(dev);
    stPheBin_t *pbin = &pIsa1200->stBin;
    stPheBinHeader_t *pheader = &pbin->header;
    stPheInfo_t *pinfo;

    ret = kstrtoint(buf, 10, &idx);
    if (ret < 0) {
        pr_err("[HPT] %s, kstrtoint fail\n", __func__);
        return size;
    }

    mutex_lock(&pIsa1200->lock);

    pr_debug("[HPT] phe idx: %d\n", idx);

    if ((pIsa1200 == NULL) || (pbin == NULL) || (pheader == NULL))
        goto end_phe_index_store;

    if ((idx < 1) || (idx > pheader->count))
        goto end_phe_index_store;

    pinfo = &pbin->pinfo[idx - 1];

    strncat(name, pinfo->name, sizeof(pinfo->name));

    pIsa1200->pPheInfo = pinfo;

    pr_info("[HPT] PHE idx %d: %s\n", idx, name);

end_phe_index_store:
    mutex_unlock(&pIsa1200->lock);

    return size;
}
ssize_t isa1200_phe_index_show(struct device *dev,
        struct device_attribute *attr, char *buf)
{
    int count = 0;
    char name[21] = {0, };
    stPheInfo_t *pinfo;

    stIsa1200Data_t *pIsa1200 = dev_get_drvdata(dev);

    mutex_lock(&pIsa1200->lock);

    pinfo = pIsa1200->pPheInfo;
    if (pinfo == NULL) {
        count = sprintf(buf, "Err, PHE is not set!!\n");
        goto end_phe_index_store;
    }

    strncat(name, pinfo->name, sizeof(pinfo->name));

    count += sprintf(buf, "%s", name);

    pr_debug("[HPT] PHE name: %s\n", name);

end_phe_index_store:
    mutex_unlock(&pIsa1200->lock);

    return count;
}

/* sysfs : /sys/class/haptic/player/phe_name */
ssize_t isa1200_phe_name_store(struct device *dev,
        struct device_attribute *attr, const char *buf, size_t size)
{
    int i, ret;
    char name[21] = {0, };
    bool finded = false;

    stIsa1200Data_t *pIsa1200 = dev_get_drvdata(dev);
    stPheBin_t *pbin;
    stPheBinHeader_t *pheader;
    stPheInfo_t *pinfo;
    stPhe_t *pphe;

    stSimpleEfft_t se = {BASE_FREQ, 0, 0, 0};

    mutex_lock(&pIsa1200->lock);

    pIsa1200->bReadyHaptic = false;

    //pr_info("[HPT] name: %s\n", buf);

    if (strlen(buf) > sizeof(name))
        goto end_phe_name_store;

    if (pIsa1200 == NULL)
        goto end_phe_name_store;

    pbin = &pIsa1200->stBin;
    if (pbin == NULL)
        goto end_phe_name_store;

    pheader = &pbin->header;
    if (pheader == NULL)
        goto end_phe_name_store;

    memcpy(name, buf, size);

    for (i = 0; i < pheader->count; i++) {
        pinfo = &pbin->pinfo[i];
#if 0
        pr_info("[HPT] %s(%d), %s(%d)\n", name, (int)strlen(name),
                pinfo->name, (int)strlen(pinfo->name));
#endif
        if ((strlen(name) - 1) != strlen(pinfo->name))
            continue;

        if (!strncmp(name, pinfo->name, strlen(pinfo->name))) {
            finded = true;
            break;
        }
    }

    if (finded == false) {
        pr_err("[HPT] Can not find file: %s !!\n", name);
        goto end_phe_name_store;
    }

    pphe = (stPhe_t *)&pbin->pbuf[pinfo->addr];
    if (pphe[pinfo->count - 1].amp != 0) {
        pr_err("[HPT] Err, PHE buffer is empty!!\n");
        goto end_phe_name_store;
    }

    ret = isa1200_set_fast_haptic(pIsa1200, pinfo, pphe, &se);

    pIsa1200->bPheMode = (ret != 0) ? true : false;
    pIsa1200->pPheInfo = pinfo;
    pIsa1200->pPhe = pphe;
    pIsa1200->stSE = se;

    pIsa1200->bReadyHaptic = true;

    pr_info("[HPT] PHE: %s(%d)\n", name, i+1);

end_phe_name_store:
    mutex_unlock(&pIsa1200->lock);

    return size;
}

/* sysfs : /sys/class/haptic/player/play_phe */
ssize_t isa1200_play_phe_show(struct device *dev,
        struct device_attribute *attr, char *buf)
{
    int count = 0;

    stPheInfo_t *pinfo;
    stPhe_t *pphe;

    stIsa1200Data_t *pIsa1200 = dev_get_drvdata(dev);

    mutex_lock(&pIsa1200->lock);

    pinfo = pIsa1200->pPheInfo;
    if (pinfo == NULL) {
        count = sprintf(buf, "Err, PHE table is not correct!!\n");
        goto end_play_phe_show;
    }

    pphe = pIsa1200->pPhe;
    if (pphe == NULL) {
        count = sprintf(buf, "Err, PHE buffer is not allocated!!\n");
        goto end_play_phe_show;
    }

    /* invalid last */
    if (pphe[pinfo->count - 1].amp != 0) {
        count = sprintf(buf, "Err, PHE buffer is empty (%d)!!\n",
                pphe[pinfo->count - 1].amp);
        goto end_play_phe_show;
    }

    if (pIsa1200->bReadyHaptic == false) {
        count = sprintf(buf, "Err, PHE unknown file name!!\n");
        goto end_play_phe_show;
    }
    pIsa1200->bReadyHaptic = false;

    pr_info("[HPT] Play phe name: %s, playing: %d, phe: %d\n",
            pinfo->name,
            (pIsa1200->bPlayingHaptic ? 1 : 0),
            (pIsa1200->bPheMode ? 1 : 0));

    if (pIsa1200->bConfigured == false)
        isa1200_configure(pIsa1200);

    isa1200_player_start(pIsa1200);

    count = 0;

end_play_phe_show:
    mutex_unlock(&pIsa1200->lock);

    return count;
}

/* sysfs : /sys/class/haptic/vibrator/state */
ssize_t isa1200_state_store(struct device *dev, struct device_attribute *attr,
        const char *buf, size_t size)
{
    int32_t enable = 0;

    //stIsa1200Data_t *pIsa1200 = dev_get_drvdata(dev);

    if (kstrtoint(buf, 10, &enable) < 0) {
        pr_err("[HPT] %s, kstrtoint fail\n", __func__);
    }

    pr_debug("[HPT] %s, enable: %d\n", __func__, enable);
    /* Haptic Digital Mode Selection 0x10 PWM Generation */

    //isa1200_haptic_enable(pIsa1200, false);

    return size;

}

ssize_t isa1200_state_show(struct device *dev, struct device_attribute *attr,
        char *buf)
{

    return 0;

}

/* sysfs : /sys/class/haptic/vibrator/duration */
ssize_t isa1200_duration_store(struct device *dev, struct device_attribute *attr,
        const char *buf, size_t size)
{
    u32 val;
    int rc;

    stIsa1200Data_t *pIsa1200 = dev_get_drvdata(dev);

    rc = kstrtouint(buf, 0, &val);
    if (rc < 0)
        return rc;

    if (val == pIsa1200->play_time_ms)
        return size;

    /* setting 0 on duration is NOP for now */
    if (val <= 0)
        return size;

    if (val > MAX_PLAY_TIME_MS)
        val = MAX_PLAY_TIME_MS;

    mutex_lock(&pIsa1200->lock);

    pIsa1200->play_time_ms = val;

    mutex_unlock(&pIsa1200->lock);

    pr_debug("[HPT] %s, play_time_ms: %d\n", __func__, val);

    return size;
}

ssize_t isa1200_duration_show(struct device *dev, struct device_attribute *attr,
        char *buf)
{

    return 0;
}

/* sysfs : /sys/class/haptic/vibrator/activate */
ssize_t isa1200_activate_store(struct device *dev, struct device_attribute *attr,
        const char *buf, size_t size)
{
    int32_t fwd;
    int32_t enable = 0;

    stIsa1200Data_t *pIsa1200 = dev_get_drvdata(dev);
    stPheInfo_t *pinfo;
    stPhe_t *pphe;

    stSimpleEfft_t se = {BASE_FREQ, VIBRATE_AMP, 0, 0};

    if (kstrtoint(buf, 10, &enable) < 0) {
        pr_err("[HPT] %s, kstrtoint fail\n", __func__);
        return size;
    }

    //pr_debug("[HPT] new %s, enable: %d !!\n", __func__, enable);

    mutex_lock(&pIsa1200->lock);

    pIsa1200->bPheMode = true;
    if (enable) {
        gstPheVibe[1].ms = pIsa1200->play_time_ms;
        pinfo = &gstPheInfoVibe;
        pphe = gstPheVibe;

        fwd = (pphe[1].ms - pphe[0].ms);
        if (fwd < 0) {
            pr_err("[HPT] %s, %d ~ %d ms\n", __func__, pphe[0].ms, pphe[1].ms);
            goto end_activate_store;
        }
        fwd = fwd * pinfo->freq / 1000;
        fwd += 1;

        if (fwd <= MAX_SE_FWD) {
            //pIsa1200->bPheMode = false;
            se.fwd = (uint8_t)fwd;
        }
    }
    else {
        pr_info("[HPT] Activate : stop\n");

	isa1200_player_stop(pIsa1200);
        //pr_info("[HPT] Activate : stop1\n");

	goto end_activate_store;
    }

    if (pIsa1200->bPheMode == false)
        pIsa1200->stSE = se;

    pr_info("[HPT] Activate : %dms, status(playing: %d, phe: %d)\n",
            pIsa1200->play_time_ms,
            (pIsa1200->bPlayingHaptic ? 1 : 0),
            (pIsa1200->bPheMode ? 1 : 0));

    pIsa1200->stSE = se;
    pIsa1200->pPheInfo = pinfo;
    pIsa1200->pPhe = pphe;

    if (pIsa1200->bConfigured == false)
        isa1200_configure(pIsa1200);

    isa1200_player_start(pIsa1200);

end_activate_store:
    mutex_unlock(&pIsa1200->lock);

    return size;
}

ssize_t isa1200_activate_show(struct device *dev, struct device_attribute *attr,
        char *buf)
{

    return 0;

}
/* sysfs : /sys/class/haptic/vibrator/chip */
ssize_t isa1200_chip_store(struct device *dev, struct device_attribute *attr,
        const char *buf, size_t size)
{

    return 0;

}

ssize_t isa1200_chip_show(struct device *dev, struct device_attribute *attr,
        char *buf)
{
    char *str;
    if (gChip)
        str = "pass";
    else
        str = "fail";

    return snprintf(buf, PAGE_SIZE, "%s\n", str);
}


/* sysfs : /sys/class/haptic/debug */
static DEVICE_ATTR(hen, (S_IRUGO | S_IWUSR | S_IWGRP),
        isa1200_hen_show, isa1200_hen_store);
static DEVICE_ATTR(extclk, (S_IRUGO | S_IWUSR | S_IWGRP),
        isa1200_extclk_show, isa1200_extclk_store);
static DEVICE_ATTR(vpp, (S_IRUGO | S_IWUSR | S_IWGRP),
        isa1200_vpp_show, isa1200_vpp_store);
static DEVICE_ATTR(reg, (S_IRUGO | S_IWUSR | S_IWGRP),
        isa1200_reg_show, isa1200_reg_store);
static DEVICE_ATTR(reg_init, (S_IRUGO | S_IWUSR | S_IWGRP),
        isa1200_reg_init_show, isa1200_reg_init_store);
static DEVICE_ATTR(reg_dump, (S_IRUGO | S_IWUSR | S_IWGRP),
        isa1200_reg_dump_show, isa1200_reg_dump_store);

static struct attribute *debug_attributes[] = {
    &dev_attr_hen.attr,
    &dev_attr_extclk.attr,
    &dev_attr_vpp.attr,
    &dev_attr_reg.attr,
    &dev_attr_reg_init.attr,
    &dev_attr_reg_dump.attr,
    NULL,
};

static struct attribute_group debug_attr_group = {
    .attrs	= debug_attributes,
};


/* sysfs : /sys/class/haptic/player */
static DEVICE_ATTR(freq, (S_IRUGO | S_IWUSR | S_IWGRP),
        isa1200_freq_show, isa1200_freq_store);
static DEVICE_ATTR(amp, (S_IRUGO | S_IWUSR | S_IWGRP),
        isa1200_amp_show, isa1200_amp_store);
static DEVICE_ATTR(se, (S_IRUGO | S_IWUSR | S_IWGRP),
        isa1200_play_se_show, isa1200_play_se_store);
static DEVICE_ATTR(play, (S_IRUGO | S_IWUSR | S_IWGRP),
        isa1200_play_show, isa1200_play_store);
static DEVICE_ATTR(hpt_en, (S_IRUGO | S_IWUSR | S_IWGRP),
        isa1200_haptic_enable_show, isa1200_haptic_enable_store);
static DEVICE_ATTR(load_bin, (S_IRUGO | S_IWUSR | S_IWGRP),
        isa1200_load_bin_show, NULL);
static DEVICE_ATTR(load_bin_sdcard, (S_IRUGO | S_IWUSR | S_IWGRP),
        isa1200_load_bin_sdcard_show, NULL);
static DEVICE_ATTR(load_init_bin, (S_IRUGO | S_IWUSR | S_IWGRP),
        isa1200_load_init_bin_show, NULL);
static DEVICE_ATTR(print_bin_info, (S_IRUGO | S_IWUSR | S_IWGRP),
        isa1200_print_bin_info_show, NULL);
static DEVICE_ATTR(phe, (S_IRUGO | S_IWUSR | S_IWGRP),
        isa1200_phe_index_show, isa1200_phe_index_store);
static DEVICE_ATTR(phe_name, (S_IRUGO | S_IWUSR | S_IWGRP),
        NULL, isa1200_phe_name_store);
static DEVICE_ATTR(play_phe, (S_IRUGO | S_IWUSR | S_IWGRP),
        isa1200_play_phe_show, NULL);

static struct attribute *player_attributes[] = {
    &dev_attr_freq.attr,
    &dev_attr_amp.attr,
    &dev_attr_se.attr,
    &dev_attr_play.attr,
    &dev_attr_hpt_en.attr,
    &dev_attr_load_bin.attr,
    &dev_attr_load_bin_sdcard.attr,
    &dev_attr_load_init_bin.attr,
    &dev_attr_print_bin_info.attr,
    &dev_attr_phe.attr,
    &dev_attr_phe_name.attr,
    &dev_attr_play_phe.attr,
    NULL,
};

static struct attribute_group player_attr_group = {
    .attrs	= player_attributes,
};

/* sysfs : /sys/class/haptic/vibrator */
static DEVICE_ATTR(state, (S_IRUGO | S_IWUSR | S_IWGRP),
        isa1200_state_show, isa1200_state_store);
static DEVICE_ATTR(duration, (S_IRUGO | S_IWUSR | S_IWGRP),
        isa1200_duration_show, isa1200_duration_store);
static DEVICE_ATTR(activate, (S_IRUGO | S_IWUSR | S_IWGRP),
        isa1200_activate_show, isa1200_activate_store);
static DEVICE_ATTR(chip, (S_IRUGO | S_IWUSR | S_IWGRP),
        isa1200_chip_show, isa1200_chip_store);

static struct attribute *vibrator_attributes[] = {
    &dev_attr_state.attr,
    &dev_attr_duration.attr,
    &dev_attr_activate.attr,
    &dev_attr_chip.attr,
    NULL,
};

static struct attribute_group vibrator_attr_group = {
    .attrs  = vibrator_attributes,
};

int isa1200_sysfs_init(stIsa1200Data_t *pIsa1200)
{
    pr_debug("[HPT] %s\n", __func__);
    /* /sys/class/haptic */
    pIsa1200->pclass = class_create(THIS_MODULE, "haptic");

    /* /sys/class/haptic/debug */
    pIsa1200->pdevDebug = device_create(pIsa1200->pclass, NULL, 0, pIsa1200, "debug");

    /* /sys/class/haptic/player */
    pIsa1200->pdevPlayer = device_create(pIsa1200->pclass, NULL, 0, pIsa1200, "player");

    /* /sys/class/haptic/vibrator */
    pIsa1200->pdevVibrator = device_create(pIsa1200->pclass, NULL, 0, pIsa1200, "vibrator");

    /* /sys/class/haptic/debug/... */
    if (sysfs_create_group(&pIsa1200->pdevDebug->kobj, &debug_attr_group))
        pr_err("Failed to create sysfs group(%s)!\n", "debug");

    /* /sys/class/haptic/player/... */
    if (sysfs_create_group(&pIsa1200->pdevPlayer->kobj, &player_attr_group))
        pr_err("Failed to create sysfs group(%s)!\n", "player");

    /* /sys/class/haptic/vibrator/... */
    if (sysfs_create_group(&pIsa1200->pdevVibrator->kobj, &vibrator_attr_group))
        pr_err("Failed to create sysfs group(%s)!\n", "vibrator");

    //isa1200_sysfs_effect_init(pIsa1200);

    return 0;
}

#ifdef CONFIG_OF
static int isa1200_parse_dt(struct device *dev, stIsa1200Data_t *pIsa1200)
{
    int ret;
    uint32_t temp = 0;

    stIsa1200Platform_t *pPlat = &pIsa1200->stPlatform;
    struct device_node *np = dev->of_node;

    pr_debug("[HPT] %s\n", __func__);
    if (!np) {
        dev_err(dev, "no device tree or platform data\n");
        return -EINVAL;
    }

    /* parse input frequency */
    ret = of_property_read_u32(np, "isa1200,input-freq", &temp);
    if (!ret) {
        pPlat->input_freq = (uint32_t)temp;
        pr_debug("[HPT] parse input-freq=%d\n", pPlat->input_freq);

    } else if (ret != -EINVAL) {
        pr_err("[HPT] %s : error to get dt node input-freq\n", __func__);
        pPlat->input_freq = 0;
        return ret;
    }

    /* parse resonant frequency of actuator */
    ret = of_property_read_u32(np, "isa1200,resonant-freq", &temp);
    if (!ret) {
        pPlat->stActuator.res_freq = (uint16_t)temp;
        pr_debug("[HPT] parse resonant-freq=%d\n", pPlat->stActuator.res_freq);
    } else if (ret != -EINVAL) {
        pr_err("[HPT] %s : error to get dt node resonant-freq\n", __func__);
        pPlat->stActuator.res_freq = 0;
        return ret;
    }

    /* parse resonant type of actuator */
    ret = of_property_read_u32(np, "isa1200,actuator-type", &temp);
    if (!ret) {
        pPlat->stActuator.actuator_type = (temp == 0) ? ERM : LRA;
        pr_debug("[HPT] parse actuator-type=%d\n", pPlat->stActuator.actuator_type);
    } else if (ret != -EINVAL) {
        pr_err("[HPT] %s : error to get dt node actuator-type\n", __func__);
        pPlat->stActuator.actuator_type = LRA;
        return ret;
    }

    /* parse max driving voltage */
    ret = of_property_read_u32(np, "isa1200,max-voltage", &temp);
    if (!ret) {
        pPlat->max_vpp = (uint16_t)temp;
        pr_debug("[HPT] parse max-voltage=%d\n", pPlat->max_vpp);
    } else if (ret != -EINVAL) {
        pr_err("[HPT] %s : error to get dt node max-voltage\n", __func__);
        pPlat->max_vpp = 3000;
        return ret;
    }

    /* parse enable gpio */
    pPlat->use_en = of_property_read_bool(np, "isa1200,use-enable-gpio");
    if (pPlat->use_en) {
        pr_debug("[HPT] use enable gpio\n");
        pPlat->en_gpio = of_get_named_gpio(np, "isa1200,en-gpio", 0);
        if (!gpio_is_valid(pPlat->en_gpio)) {
            pr_err("[HPT] isa1200 enable gpio is invalue\n");
            return -EINVAL;
        }
        pr_debug("[HPT] parse en-gpio=%d\n", pPlat->en_gpio);
    } else {
        pr_debug("[HPT] unused enable gpio\n");
    }

    return 0;
}
#endif


static int isa1200_suspend(struct device *dev)
{
    struct i2c_client *client = to_i2c_client(dev);

    stIsa1200Data_t *pIsa1200 = i2c_get_clientdata(client);
    stIsa1200Platform_t *pPlat = &pIsa1200->stPlatform;

    pr_info("[HPT] ISA1200 suspend!!\n");

    mutex_lock(&pIsa1200->lock);

    isa1200_player_timer_cancel(pIsa1200);

    if (isDVT2) {
        pr_info("[HPT] is DVT2!!\n");
    } else {
        if (pPlat->use_en) {
            isa1200_enable(pIsa1200, false);
            pIsa1200->bConfigured = false;
            //pr_debug("[HPT] set isa1200 enable gpio low\n");
        }
    }

    isa1200_extclk_enable(pIsa1200, false);

    mutex_unlock(&pIsa1200->lock);

    return 0;
}

static int isa1200_resume(struct device *dev)
{
#if 0
    struct i2c_client *client = to_i2c_client(dev);

    stIsa1200Data_t *pIsa1200 = i2c_get_clientdata(client);
    stIsa1200Platform_t *pPlat = &pIsa1200->stPlatform;

    pr_info("[HPT] ISA1200 resume!!\n");

    mutex_lock(&pIsa1200->lock);

    if (isDVT2) {
        pr_info("[HPT] is DVT2!!\n");
    } else {
        if (pPlat->use_en) {
            isa1200_enable(pIsa1200, true);
            pr_info("[HPT] set isa1200 enable gpio high\n");
        }

        isa1200_reg_init(pIsa1200);
        isa1200_reg_debug(pIsa1200); // for debug, check i2c write
    }

    isa1200_extclk_enable(pIsa1200, true);

    pIsa1200->bPlayingHaptic = false;
    pIsa1200->bReadyHaptic = false;

    mutex_unlock(&pIsa1200->lock);
#else
    pr_info("[HPT] ISA1200 resume!!\n");
#endif

    return 0;
}

#ifdef CONFIG_HAS_EARLYSUSPEND
static void isa1200_early_suspend(struct early_suspend *h)
{
    struct isa1200_data *data = container_of(h, struct isa1200_data,
            early_suspend);

    isa1200_suspend(&data->client->dev);
}

static void isa1200_late_resume(struct early_suspend *h)
{
    struct isa1200_data *data = container_of(h, struct isa1200_data,
            early_suspend);

    isa1200_resume(&data->client->dev);
}
#endif


extern int get_hw_version_id(void);
static int isa1200_probe(struct i2c_client* client, const struct i2c_device_id* id)
{
    int ret = 0;
    uint32_t val = 0;
    int hw_version = -1;

    stIsa1200Data_t *pIsa1200;
    stIsa1200Platform_t *pPlat;

    pr_info("[HPT] %s\n", __func__);

    if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
        dev_err(&client->dev, "%s:I2C check failed\n", __FUNCTION__);
        ret = -ENODEV;
        goto exit_probe_fail;
    }

    pIsa1200 = devm_kzalloc(&client->dev, sizeof(stIsa1200Data_t), GFP_KERNEL);
    if (pIsa1200 == NULL) {
        dev_err(&client->dev, "%s:no memory\n", __FUNCTION__);
        ret = -ENOMEM;
        goto exit_probe_fail;
    }
    pIsa1200->pdev = &client->dev;

    pIsa1200->client = client;
    pIsa1200->pRegmap = devm_regmap_init_i2c(client, &isa1200_i2c_regmap);
    if (IS_ERR(pIsa1200->pRegmap)) {
        ret = PTR_ERR(pIsa1200->pRegmap);
        dev_err(pIsa1200->pdev, 
                "%s:Failed to allocate register map: %d\n", __FUNCTION__, ret);
        goto exit_probe_fail;
    }

#ifdef CONFIG_OF
    ret = isa1200_parse_dt(&client->dev, pIsa1200);
    if (ret) {
        pr_err("[HPT] isa1200 parse dt failed\n");
        goto exit_probe_fail;
    }
#endif

#ifdef CONFIG_HAS_EARLYSUSPEND
    pIsa1200->early_suspend.level = EARLY_SUSPEND_LEVEL_BLANK_SCREEN + 1;
    pIsa1200->early_suspend.suspend = isa1200_early_suspend;
    pIsa1200->early_suspend.resume = isa1200_late_resume;
    register_early_suspend(&pIsa1200->early_suspend);
#endif

    pPlat = &pIsa1200->stPlatform;

    if (pPlat->use_en) {
        ret = devm_gpio_request(&client->dev, pPlat->en_gpio, "isa1200_en_gpio");
        if (ret) {
            pr_err("[HPT] unable to request isa1200 enable gpio\n");
            goto exit_probe_fail; 
        }
        pr_debug("[HPT] get enable gpio\n");
        gpio_direction_output(pPlat->en_gpio, 0);
    }

    pPlat->clk_pinctrl = devm_pinctrl_get(&client->dev);
    if (IS_ERR(pPlat->clk_pinctrl)) {
        pr_err("[HPT] failed to get clk_pinctrl\n");
        ret = PTR_ERR(pPlat->clk_pinctrl);
        goto exit_probe_fail;
    }

    pPlat->pin_enable_state = pinctrl_lookup_state(pPlat->clk_pinctrl, "enable");
    if (IS_ERR(pPlat->pin_enable_state)) {
        pr_err("[HPT] cannot get lookup enable state\n");
	goto exit_probe_fail;
    }

    pPlat->pin_disable_state = pinctrl_lookup_state(pPlat->clk_pinctrl, "disable");
    if (IS_ERR(pPlat->pin_disable_state)) {
        pr_err("[HPT] cannot get lookup disable state\n");
	goto exit_probe_fail;
    }

    pr_debug("[HPT] get clk_pinctrl\n");

    pPlat->ext_clk = devm_clk_get(&client->dev, "isa1200_ext_clk");
    if (IS_ERR(pPlat->ext_clk)) {
        pr_err("[HPT] failed to get ext_clk\n");
        ret = PTR_ERR(pPlat->ext_clk);
        goto exit_probe_fail;
    }
    pr_debug("[HPT] get ext_clk\n");

    i2c_set_clientdata(client, pIsa1200);

    /* IC initialize */
    if (pPlat->use_en) {
        isa1200_enable(pIsa1200, true);
        pr_debug("[HPT] set isa1200 enable gpio high\n");
    }
    ret = pinctrl_select_state(pPlat->clk_pinctrl, pPlat->pin_enable_state);
    if (ret) {
        pr_err("[HPT] cannot set pinctrl state enable\n");
	goto exit_probe_fail;
    }

    mutex_init(&pIsa1200->lock);

    isa1200_reg_init(pIsa1200);
    isa1200_reg_debug(pIsa1200); // for debug, check i2c write

    /* check ISA1200_REG_LCTRL */
    val = isa1200_reg_read(pIsa1200, ISA1200_REG_LCTRL);
    pr_info("[HPT] ISA1200_REG_LCTRL = %d\n", val);

    if (val == 7) {
        smartisan_hwstate_set("vibrator", "ok");
        gChip = true;
    } else {
        pr_err("[HPT] isa1200 0x00 reg check failed\n");
        gChip = false;
        ret = -ENODEV;
        goto exit_probe_fail;
    }

    isa1200_sysfs_init(pIsa1200);

    haptic_player_init(pIsa1200);

    hw_version = get_hw_version_id();
    if (hw_version == 1)
        isDVT2 = true;
    else
        isDVT2 = false;

    dev_info(pIsa1200->pdev, "[HPT] isa1200_probe succeeded, Version: 0x%x\n", hw_version);
    return 0;

exit_probe_fail:
#ifdef CONFIG_HAS_EARLYSUSPEND
    unregister_early_suspend(&pIsa1200->early_suspend);
#endif

    pr_err("[HPT] isa1200_probe failed %d\n", ret);
    return ret;
}

static int isa1200_remove(struct i2c_client* client)
{
    stIsa1200Data_t *pIsa1200 = i2c_get_clientdata(client);
    stIsa1200Platform_t *pPlat = &pIsa1200->stPlatform;

    pr_info("[HPT] %s\n", __func__);

    if (pPlat->use_en) {
        isa1200_enable(pIsa1200, false);
        pr_info("[HPT] set isa1200 enable gpio low\n");
    }


#ifdef CONFIG_HAS_EARLYSUSPEND
    unregister_early_suspend(&pIsa1200->early_suspend);
#endif

#if 0
    if(pIsa1200->stPlatform.gpio_len)
        gpio_free(pIsa1200->stPlatform.gpio_len);

    if(pIsa1200->stPlatform.gpio_hen)
        gpio_free(pIsa1200->stPlatform.gpio_hen);

    misc_deregister(&isa1200_misc);
#endif

    return 0;
}

static struct i2c_device_id isa1200_id_table[] =
{
    { HAPTICS_DEVICE_NAME, 0 },
    {}
};
MODULE_DEVICE_TABLE(i2c, isa1200_id_table);

#ifdef CONFIG_OF
static struct of_device_id isa1200_dt_ids[] =
{
    { .compatible = "isa1200" },
    { },
};
MODULE_DEVICE_TABLE(of, isa1200_dt_ids);
#endif


//#ifndef CONFIG_HAS_EARLYSUSPEND
static const struct dev_pm_ops isa1200_pm_ops = {
    .suspend    = isa1200_suspend,
    .resume     = isa1200_resume,
};
//#endif


static struct i2c_driver isa1200_driver =
{
    .probe = isa1200_probe,
    .remove = isa1200_remove,
    .id_table = isa1200_id_table,
    .driver = {
        .name = HAPTICS_DEVICE_NAME,
        .owner = THIS_MODULE,
#ifdef CONFIG_OF
        .of_match_table = isa1200_dt_ids,
#endif
        //#ifndef CONFIG_HAS_EARLYSUSPEND
        .pm             = &isa1200_pm_ops,
        //#endif
    },
};

static int __init isa1200_init(void)
{
    pr_debug("[HPT] %s\n", __func__);
    return i2c_add_driver(&isa1200_driver);
}

static void __exit isa1200_exit(void)
{
    i2c_del_driver(&isa1200_driver);
}

module_init(isa1200_init);
module_exit(isa1200_exit);

MODULE_AUTHOR("IMAIGS.,");
MODULE_DESCRIPTION("Haptic driver : "HAPTICS_DEVICE_NAME);
