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
#include <sound/core.h>
#include <sound/soc.h>
#include <sound/soc-dai.h>
#include "debussy.h"
#include "debussy_intf.h"
#include "debussy_snd_ctrl.h"

#define IGO_CH_NO_INVERT (0)
#define IGO_CH_MAX (0xFFFFFFFF)
#define IGO_CH_SHIFT (0)


static const char* const enum_power_mode[] = {
	"POWER_MODE_STANDBY",
	"POWER_MODE_WORKING",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_power_mode, enum_power_mode);


static const char* const enum_op_mode[] = {
	"OP_MODE_CONFIG",
	"OP_MODE_NR",
	"OP_MODE_VAD",
	"OP_MODE_BYPASS",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_op_mode, enum_op_mode);


static const char* const enum_mclk[] = {
	"MCLK_NONE",
	"MCLK_26M",
	"MCLK_24_576M",
	"MCLK_20M",
	"MCLK_19_2M",
	"MCLK_12_288M",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_mclk, enum_mclk);


static const char* const enum_ch0_rx[] = {
	"CH0_RX_DISABLE",
	"CH0_RX_DAI0_RX_L",
	"CH0_RX_DAI0_RX_R",
	"CH0_RX_DAI1_RX_L",
	"CH0_RX_DAI1_RX_R",
	"CH0_RX_DAI2_RX_L",
	"CH0_RX_DAI2_RX_R",
	"CH0_RX_DAI3_RX_L",
	"CH0_RX_DAI3_RX_R",
	"CH0_RX_DMIC_M0_P",
	"CH0_RX_DMIC_M0_N",
	"CH0_RX_DMIC_M1_P",
	"CH0_RX_DMIC_M1_N",
	"CH0_RX_DMIC_COMBO_M0_P",
	"CH0_RX_DMIC_COMBO_M0_N",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_ch0_rx, enum_ch0_rx);


static const char* const enum_ch0_tx[] = {
	"CH0_TX_DISABLE",
	"CH0_TX_DAI0_TX_L",
	"CH0_TX_DAI0_TX_R",
	"CH0_TX_DAI1_TX_L",
	"CH0_TX_DAI1_TX_R",
	"CH0_TX_DAI2_TX_L",
	"CH0_TX_DAI2_TX_R",
	"CH0_TX_DAI3_TX_L",
	"CH0_TX_DAI3_TX_R",
	"CH0_TX_DMIC_S0_P",
	"CH0_TX_DMIC_S0_N",
	"CH0_TX_DMIC_S1_P",
	"CH0_TX_DMIC_S1_N",
	"CH0_TX_DMIC_COMBO_S0_P",
	"CH0_TX_DMIC_COMBO_S0_N",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_ch0_tx, enum_ch0_tx);


static const char* const enum_ch1_rx[] = {
	"CH1_RX_DISABLE",
	"CH1_RX_DAI0_RX_L",
	"CH1_RX_DAI0_RX_R",
	"CH1_RX_DAI1_RX_L",
	"CH1_RX_DAI1_RX_R",
	"CH1_RX_DAI2_RX_L",
	"CH1_RX_DAI2_RX_R",
	"CH1_RX_DAI3_RX_L",
	"CH1_RX_DAI3_RX_R",
	"CH1_RX_DMIC_M0_P",
	"CH1_RX_DMIC_M0_N",
	"CH1_RX_DMIC_M1_P",
	"CH1_RX_DMIC_M1_N",
	"CH1_RX_DMIC_COMBO_M0_P",
	"CH1_RX_DMIC_COMBO_M0_N",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_ch1_rx, enum_ch1_rx);


static const char* const enum_ch1_tx[] = {
	"CH1_TX_DISABLE",
	"CH1_TX_DAI0_TX_L",
	"CH1_TX_DAI0_TX_R",
	"CH1_TX_DAI1_TX_L",
	"CH1_TX_DAI1_TX_R",
	"CH1_TX_DAI2_TX_L",
	"CH1_TX_DAI2_TX_R",
	"CH1_TX_DAI3_TX_L",
	"CH1_TX_DAI3_TX_R",
	"CH1_TX_DMIC_S0_P",
	"CH1_TX_DMIC_S0_N",
	"CH1_TX_DMIC_S1_P",
	"CH1_TX_DMIC_S1_N",
	"CH1_TX_DMIC_COMBO_S0_P",
	"CH1_TX_DMIC_COMBO_S0_N",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_ch1_tx, enum_ch1_tx);


static const char* const enum_dai_0_mode[] = {
	"DAI_0_MODE_DISABLE",
	"DAI_0_MODE_SLAVE",
	"DAI_0_MODE_MASTER",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_dai_0_mode, enum_dai_0_mode);


static const char* const enum_dai_0_clk_src[] = {
	"DAI_0_CLK_SRC_DISABLE",
	"DAI_0_CLK_SRC_MCLK",
	"DAI_0_CLK_SRC_INTERNAL",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_dai_0_clk_src, enum_dai_0_clk_src);


static const char* const enum_dai_0_clk[] = {
	"DAI_0_CLK_16K",
	"DAI_0_CLK_32K",
	"DAI_0_CLK_48K",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_dai_0_clk, enum_dai_0_clk);


static const char* const enum_dai_0_data_bit[] = {
	"DAI_0_DATA_BIT_32",
	"DAI_0_DATA_BIT_16",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_dai_0_data_bit, enum_dai_0_data_bit);


static const char* const enum_dai_1_mode[] = {
	"DAI_1_MODE_DISABLE",
	"DAI_1_MODE_SLAVE",
	"DAI_1_MODE_MASTER",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_dai_1_mode, enum_dai_1_mode);


static const char* const enum_dai_1_clk_src[] = {
	"DAI_1_CLK_SRC_DISABLE",
	"DAI_1_CLK_SRC_MCLK",
	"DAI_1_CLK_SRC_INTERNAL",
	"DAI_1_CLK_SRC_DAI_0",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_dai_1_clk_src, enum_dai_1_clk_src);


static const char* const enum_dai_1_clk[] = {
	"DAI_1_CLK_16K",
	"DAI_1_CLK_32K",
	"DAI_1_CLK_48K",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_dai_1_clk, enum_dai_1_clk);


static const char* const enum_dai_1_data_bit[] = {
	"DAI_1_DATA_BIT_32",
	"DAI_1_DATA_BIT_16",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_dai_1_data_bit, enum_dai_1_data_bit);


static const char* const enum_dai_2_mode[] = {
	"DAI_2_MODE_DISABLE",
	"DAI_2_MODE_SLAVE",
	"DAI_2_MODE_MASTER",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_dai_2_mode, enum_dai_2_mode);


static const char* const enum_dai_2_clk_src[] = {
	"DAI_2_CLK_SRC_DISABLE",
	"DAI_2_CLK_SRC_MCLK",
	"DAI_2_CLK_SRC_INTERNAL",
	"DAI_2_CLK_SRC_DAI_0",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_dai_2_clk_src, enum_dai_2_clk_src);


static const char* const enum_dai_2_clk[] = {
	"DAI_2_CLK_16K",
	"DAI_2_CLK_32K",
	"DAI_2_CLK_48K",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_dai_2_clk, enum_dai_2_clk);


static const char* const enum_dai_2_data_bit[] = {
	"DAI_2_DATA_BIT_32",
	"DAI_2_DATA_BIT_16",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_dai_2_data_bit, enum_dai_2_data_bit);


static const char* const enum_dai_3_mode[] = {
	"DAI_3_MODE_DISABLE",
	"DAI_3_MODE_SLAVE",
	"DAI_3_MODE_MASTER",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_dai_3_mode, enum_dai_3_mode);


static const char* const enum_dai_3_clk_src[] = {
	"DAI_3_CLK_SRC_DISABLE",
	"DAI_3_CLK_SRC_MCLK",
	"DAI_3_CLK_SRC_INTERNAL",
	"DAI_3_CLK_SRC_DAI_0",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_dai_3_clk_src, enum_dai_3_clk_src);


static const char* const enum_dai_3_clk[] = {
	"DAI_3_CLK_16K",
	"DAI_3_CLK_32K",
	"DAI_3_CLK_48K",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_dai_3_clk, enum_dai_3_clk);


static const char* const enum_dai_3_data_bit[] = {
	"DAI_3_DATA_BIT_32",
	"DAI_3_DATA_BIT_16",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_dai_3_data_bit, enum_dai_3_data_bit);


static const char* const enum_dmic_m_clk_src[] = {
	"DMIC_M_CLK_SRC_DMIC_S",
	"DMIC_M_CLK_SRC_MCLK",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_dmic_m_clk_src, enum_dmic_m_clk_src);


static const char* const enum_dmic_m_bclk[] = {
	"DMIC_M_BCLK_3_072M",
	"DMIC_M_BCLK_2_4M",
	"DMIC_M_BCLK_ADAPTIVE",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_dmic_m_bclk, enum_dmic_m_bclk);


static const char* const enum_dmic_s_bclk[] = {
	"DMIC_S_BCLK_3_072M",
	"DMIC_S_BCLK_2_4M",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_dmic_s_bclk, enum_dmic_s_bclk);


static const char* const enum_dmic_m0_p_mode[] = {
	"DMIC_M0_P_MODE_DISABLE",
	"DMIC_M0_P_MODE_ENABLE",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_dmic_m0_p_mode, enum_dmic_m0_p_mode);


static const char* const enum_dmic_m0_n_mode[] = {
	"DMIC_M0_N_MODE_DISABLE",
	"DMIC_M0_N_MODE_ENABLE",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_dmic_m0_n_mode, enum_dmic_m0_n_mode);


static const char* const enum_dmic_m1_p_mode[] = {
	"DMIC_M1_P_MODE_DISABLE",
	"DMIC_M1_P_MODE_ENABLE",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_dmic_m1_p_mode, enum_dmic_m1_p_mode);


static const char* const enum_dmic_m1_n_mode[] = {
	"DMIC_M1_N_MODE_DISABLE",
	"DMIC_M1_N_MODE_ENABLE",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_dmic_m1_n_mode, enum_dmic_m1_n_mode);


static const char* const enum_dmic_m2_p_mode[] = {
	"DMIC_M2_P_MODE_DISABLE",
	"DMIC_M2_P_MODE_ENABLE",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_dmic_m2_p_mode, enum_dmic_m2_p_mode);


static const char* const enum_dmic_m2_n_mode[] = {
	"DMIC_M2_N_MODE_DISABLE",
	"DMIC_M2_N_MODE_ENABLE",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_dmic_m2_n_mode, enum_dmic_m2_n_mode);


static const char* const enum_dmic_m3_p_mode[] = {
	"DMIC_M3_P_MODE_DISABLE",
	"DMIC_M3_P_MODE_ENABLE",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_dmic_m3_p_mode, enum_dmic_m3_p_mode);


static const char* const enum_dmic_m3_n_mode[] = {
	"DMIC_M3_N_MODE_DISABLE",
	"DMIC_M3_N_MODE_ENABLE",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_dmic_m3_n_mode, enum_dmic_m3_n_mode);


static const char* const enum_dmic_s0_p_mode[] = {
	"DMIC_S0_P_MODE_DISABLE",
	"DMIC_S0_P_MODE_ENABLE",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_dmic_s0_p_mode, enum_dmic_s0_p_mode);


static const char* const enum_dmic_s0_n_mode[] = {
	"DMIC_S0_N_MODE_DISABLE",
	"DMIC_S0_N_MODE_ENABLE",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_dmic_s0_n_mode, enum_dmic_s0_n_mode);


static const char* const enum_dmic_s1_p_mode[] = {
	"DMIC_S1_P_MODE_DISABLE",
	"DMIC_S1_P_MODE_ENABLE",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_dmic_s1_p_mode, enum_dmic_s1_p_mode);


static const char* const enum_dmic_s1_n_mode[] = {
	"DMIC_S1_N_MODE_DISABLE",
	"DMIC_S1_N_MODE_ENABLE",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_dmic_s1_n_mode, enum_dmic_s1_n_mode);


static const char* const enum_nr_ch0[] = {
	"NR_CH0_DISABLE",
	"NR_CH0_ENABLE",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_nr_ch0, enum_nr_ch0);


static const char* const enum_nr_ch1[] = {
	"NR_CH1_DISABLE",
	"NR_CH1_ENABLE",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_nr_ch1, enum_nr_ch1);


static const char* const enum_ch1_ref_mode[] = {
	"CH1_REF_MODE_DISABLE",
	"CH1_REF_MODE_MODE0",
	"CH1_REF_MODE_MODE1",
	"CH1_REF_MODE_MODE2",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_ch1_ref_mode, enum_ch1_ref_mode);


static const char* const enum_ch1_ref_rx[] = {
	"CH1_REF_RX_DISABLE",
	"CH1_REF_RX_DAI0_RX_L",
	"CH1_REF_RX_DAI0_RX_R",
	"CH1_REF_RX_DAI1_RX_L",
	"CH1_REF_RX_DAI1_RX_R",
	"CH1_REF_RX_DAI2_RX_L",
	"CH1_REF_RX_DAI2_RX_R",
	"CH1_REF_RX_DAI3_RX_L",
	"CH1_REF_RX_DAI3_RX_R",
	"CH1_REF_RX_DMIC_M0_P",
	"CH1_REF_RX_DMIC_M0_N",
	"CH1_REF_RX_DMIC_M1_P",
	"CH1_REF_RX_DMIC_M1_N",
	"CH1_REF_RX_DMIC_COMBO_M0_P",
	"CH1_REF_RX_DMIC_COMBO_M0_N",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_ch1_ref_rx, enum_ch1_ref_rx);


static const char* const enum_ch0_floor[] = {
	"CH0_FLOOR_LVL_DEFAULT",
	"CH0_FLOOR_LVL_0",
	"CH0_FLOOR_LVL_1",
	"CH0_FLOOR_LVL_2",
	"CH0_FLOOR_LVL_3",
	"CH0_FLOOR_LVL_4",
	"CH0_FLOOR_LVL_5",
	"CH0_FLOOR_LVL_6",
	"CH0_FLOOR_LVL_7",
	"CH0_FLOOR_LVL_8",
	"CH0_FLOOR_LVL_9",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_ch0_floor, enum_ch0_floor);


static const char* const enum_ch1_floor[] = {
	"CH1_FLOOR_LVL_DEFAULT",
	"CH1_FLOOR_LVL_0",
	"CH1_FLOOR_LVL_1",
	"CH1_FLOOR_LVL_2",
	"CH1_FLOOR_LVL_3",
	"CH1_FLOOR_LVL_4",
	"CH1_FLOOR_LVL_5",
	"CH1_FLOOR_LVL_6",
	"CH1_FLOOR_LVL_7",
	"CH1_FLOOR_LVL_8",
	"CH1_FLOOR_LVL_9",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_ch1_floor, enum_ch1_floor);


static const char* const enum_ch0_od[] = {
	"CH0_OD_LVL_DEFAULT",
	"CH0_OD_LVL_0",
	"CH0_OD_LVL_1",
	"CH0_OD_LVL_2",
	"CH0_OD_LVL_3",
	"CH0_OD_LVL_4",
	"CH0_OD_LVL_5",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_ch0_od, enum_ch0_od);


static const char* const enum_ch1_od[] = {
	"CH1_OD_LVL_DEFAULT",
	"CH1_OD_LVL_0",
	"CH1_OD_LVL_1",
	"CH1_OD_LVL_2",
	"CH1_OD_LVL_3",
	"CH1_OD_LVL_4",
	"CH1_OD_LVL_5",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_ch1_od, enum_ch1_od);


static const char* const enum_ch0_thr[] = {
	"CH0_THR_LVL_DEFAULT",
	"CH0_THR_LVL_0",
	"CH0_THR_LVL_1",
	"CH0_THR_LVL_2",
	"CH0_THR_LVL_3",
	"CH0_THR_LVL_4",
	"CH0_THR_LVL_5",
	"CH0_THR_LVL_6",
	"CH0_THR_LVL_7",
	"CH0_THR_LVL_8",
	"CH0_THR_LVL_9",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_ch0_thr, enum_ch0_thr);


static const char* const enum_ch1_thr[] = {
	"CH1_THR_LVL_DEFAULT",
	"CH1_THR_LVL_0",
	"CH1_THR_LVL_1",
	"CH1_THR_LVL_2",
	"CH1_THR_LVL_3",
	"CH1_THR_LVL_4",
	"CH1_THR_LVL_5",
	"CH1_THR_LVL_6",
	"CH1_THR_LVL_7",
	"CH1_THR_LVL_8",
	"CH1_THR_LVL_9",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_ch1_thr, enum_ch1_thr);


static const char* const enum_hw_bypass_dai_0[] = {
	"HW_BYPASS_DAI_0_DISABLE",
	"HW_BYPASS_DAI_0_ENABLE",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_hw_bypass_dai_0, enum_hw_bypass_dai_0);


static const char* const enum_hw_bypass_dmic_s0[] = {
	"HW_BYPASS_DMIC_S0_DISABLE",
	"HW_BYPASS_DMIC_S0_ENABLE",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_hw_bypass_dmic_s0, enum_hw_bypass_dmic_s0);


static const char* const enum_sw_bypass_0_rx[] = {
	"SW_BYPASS_0_RX_DISABLE",
	"SW_BYPASS_0_RX_DAI0_RX_L",
	"SW_BYPASS_0_RX_DAI0_RX_R",
	"SW_BYPASS_0_RX_DAI1_RX_L",
	"SW_BYPASS_0_RX_DAI1_RX_R",
	"SW_BYPASS_0_RX_DAI2_RX_L",
	"SW_BYPASS_0_RX_DAI2_RX_R",
	"SW_BYPASS_0_RX_DAI3_RX_L",
	"SW_BYPASS_0_RX_DAI3_RX_R",
	"SW_BYPASS_0_RX_DMIC_M0_P",
	"SW_BYPASS_0_RX_DMIC_M0_N",
	"SW_BYPASS_0_RX_DMIC_M1_P",
	"SW_BYPASS_0_RX_DMIC_M1_N",
	"SW_BYPASS_0_RX_DMIC_COMBO_M0_P",
	"SW_BYPASS_0_RX_DMIC_COMBO_M0_N",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_sw_bypass_0_rx, enum_sw_bypass_0_rx);


static const char* const enum_sw_bypass_0_tx[] = {
	"SW_BYPASS_0_TX_DISABLE",
	"SW_BYPASS_0_TX_DAI0_TX_L",
	"SW_BYPASS_0_TX_DAI0_TX_R",
	"SW_BYPASS_0_TX_DAI1_TX_L",
	"SW_BYPASS_0_TX_DAI1_TX_R",
	"SW_BYPASS_0_TX_DAI2_TX_L",
	"SW_BYPASS_0_TX_DAI2_TX_R",
	"SW_BYPASS_0_TX_DAI3_TX_L",
	"SW_BYPASS_0_TX_DAI3_TX_R",
	"SW_BYPASS_0_TX_DMIC_S0_P",
	"SW_BYPASS_0_TX_DMIC_S0_N",
	"SW_BYPASS_0_TX_DMIC_S1_P",
	"SW_BYPASS_0_TX_DMIC_S1_N",
	"SW_BYPASS_0_TX_DMIC_COMBO_S0_P",
	"SW_BYPASS_0_TX_DMIC_COMBO_S0_N",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_sw_bypass_0_tx, enum_sw_bypass_0_tx);


static const char* const enum_sw_bypass_1_rx[] = {
	"SW_BYPASS_1_RX_DISABLE",
	"SW_BYPASS_1_RX_DAI0_RX_L",
	"SW_BYPASS_1_RX_DAI0_RX_R",
	"SW_BYPASS_1_RX_DAI1_RX_L",
	"SW_BYPASS_1_RX_DAI1_RX_R",
	"SW_BYPASS_1_RX_DAI2_RX_L",
	"SW_BYPASS_1_RX_DAI2_RX_R",
	"SW_BYPASS_1_RX_DAI3_RX_L",
	"SW_BYPASS_1_RX_DAI3_RX_R",
	"SW_BYPASS_1_RX_DMIC_M0_P",
	"SW_BYPASS_1_RX_DMIC_M0_N",
	"SW_BYPASS_1_RX_DMIC_M1_P",
	"SW_BYPASS_1_RX_DMIC_M1_N",
	"SW_BYPASS_1_RX_DMIC_COMBO_M0_P",
	"SW_BYPASS_1_RX_DMIC_COMBO_M0_N",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_sw_bypass_1_rx, enum_sw_bypass_1_rx);


static const char* const enum_sw_bypass_1_tx[] = {
	"SW_BYPASS_1_TX_DISABLE",
	"SW_BYPASS_1_TX_DAI0_TX_L",
	"SW_BYPASS_1_TX_DAI0_TX_R",
	"SW_BYPASS_1_TX_DAI1_TX_L",
	"SW_BYPASS_1_TX_DAI1_TX_R",
	"SW_BYPASS_1_TX_DAI2_TX_L",
	"SW_BYPASS_1_TX_DAI2_TX_R",
	"SW_BYPASS_1_TX_DAI3_TX_L",
	"SW_BYPASS_1_TX_DAI3_TX_R",
	"SW_BYPASS_1_TX_DMIC_S0_P",
	"SW_BYPASS_1_TX_DMIC_S0_N",
	"SW_BYPASS_1_TX_DMIC_S1_P",
	"SW_BYPASS_1_TX_DMIC_S1_N",
	"SW_BYPASS_1_TX_DMIC_COMBO_S0_P",
	"SW_BYPASS_1_TX_DMIC_COMBO_S0_N",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_sw_bypass_1_tx, enum_sw_bypass_1_tx);


static const char* const enum_aec[] = {
	"AEC_DISABLE",
	"AEC_ENABLE",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_aec, enum_aec);


static const char* const enum_aec_ref_rx[] = {
	"AEC_REF_RX_DISABLE",
	"AEC_REF_RX_CH0_TX",
	"AEC_REF_RX_DAI0_RX_L",
	"AEC_REF_RX_DAI0_RX_R",
	"AEC_REF_RX_DAI1_RX_L",
	"AEC_REF_RX_DAI1_RX_R",
	"AEC_REF_RX_DAI2_RX_L",
	"AEC_REF_RX_DAI2_RX_R",
	"AEC_REF_RX_DAI3_RX_L",
	"AEC_REF_RX_DAI3_RX_R",
	"AEC_REF_RX_DMIC_M0_P",
	"AEC_REF_RX_DMIC_M0_N",
	"AEC_REF_RX_DMIC_M1_P",
	"AEC_REF_RX_DMIC_M1_N",
	"AEC_REF_RX_DMIC_COMBO_M0_P",
	"AEC_REF_RX_DMIC_COMBO_M0_N",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_aec_ref_rx, enum_aec_ref_rx);


static const char* const enum_vad_status[] = {
	"VAD_STATUS_STANDBY",
	"VAD_STATUS_TRIGGERED",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_vad_status, enum_vad_status);


static const char* const enum_vad_clear[] = {
	"VAD_CLEAR_NOP",
	"VAD_CLEAR_ENABLE",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_vad_clear, enum_vad_clear);


static const char* const enum_vad_keyword[] = {
	"VAD_KEYWORD_KEY_0",
	"VAD_KEYWORD_KEY_1",
	"VAD_KEYWORD_KEY_2",
	"VAD_KEYWORD_KEY_3",
	"VAD_KEYWORD_KEY_4",
	"VAD_KEYWORD_KEY_5",
	"VAD_KEYWORD_KEY_6",
	"VAD_KEYWORD_KEY_7",
	"VAD_KEYWORD_",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_vad_keyword, enum_vad_keyword);


static const char* const enum_vad_key_group_sel[] = {
	"VAD_KEY_GROUP_SEL_GROUP_0",
	"VAD_KEY_GROUP_SEL_GROUP_1",
	"VAD_KEY_GROUP_SEL_GROUP_2",
	"VAD_KEY_GROUP_SEL_GROUP_4",
};
static SOC_ENUM_SINGLE_EXT_DECL(soc_enum_vad_key_group_sel, enum_vad_key_group_sel);

static int igo_ch_power_mode_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	//struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	//int status = IGO_CH_STATUS_DONE;

	// struct debussy_priv* debussy;
	// debussy = dev_get_drvdata(codec->dev);
	// mutex_lock(&debussy->igo_ch_lock);
	// status = igo_ch_read(codec->dev, IGO_CH_POWER_MODE_ADDR, (unsigned int*)&ucontrol->value.integer.value[0]);
	// mutex_unlock(&debussy->igo_ch_lock);
	ucontrol->value.integer.value[0] = 0;
	//dev_dbg(codec->dev, "%s: read %s (0x%08x) : %d ret %d\n", __func__, "POWER_MODE", IGO_CH_POWER_MODE_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_power_mode_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_slow_write(codec->dev, IGO_CH_POWER_MODE_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "POWER_MODE", IGO_CH_POWER_MODE_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_fw_ver_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);
	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_read(codec->dev, IGO_CH_FW_VER_ADDR, (unsigned int*)&ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: read %s (0x%08x) : %d ret %d\n", __func__, "FW_VER", IGO_CH_FW_VER_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_fw_ver_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	return 0;
}

static int igo_ch_fw_sub_ver_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);
	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_read(codec->dev, IGO_CH_FW_SUB_VER_ADDR, (unsigned int*)&ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: read %s (0x%08x) : %d ret %d\n", __func__, "FW_SUB_VER", IGO_CH_FW_SUB_VER_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_fw_sub_ver_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	return 0;
}

static int igo_ch_chip_id_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);
	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_read(codec->dev, IGO_CH_CHIP_ID_ADDR, (unsigned int*)&ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: read %s (0x%08x) : %d ret %d\n", __func__, "CHIP_ID", IGO_CH_CHIP_ID_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_chip_id_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	return 0;
}

static int igo_ch_op_mode_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	//struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	//int status = IGO_CH_STATUS_DONE;

	//struct debussy_priv* debussy;
	//debussy = dev_get_drvdata(codec->dev);
	//mutex_lock(&debussy->igo_ch_lock);
	//status = igo_ch_read(codec->dev, IGO_CH_OP_MODE_ADDR, (unsigned int*)&ucontrol->value.integer.value[0]);
	//mutex_unlock(&debussy->igo_ch_lock);
	ucontrol->value.integer.value[0] = 0;
	//dev_dbg(codec->dev, "%s: read %s (0x%08x) : %d ret %d\n", __func__, "OP_MODE", IGO_CH_OP_MODE_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_op_mode_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_OP_MODE_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "OP_MODE", IGO_CH_OP_MODE_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_mclk_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_mclk_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_MCLK_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "MCLK", IGO_CH_MCLK_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_ch0_rx_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_ch0_rx_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_CH0_RX_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "CH0_RX", IGO_CH_CH0_RX_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_ch0_tx_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_ch0_tx_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_CH0_TX_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "CH0_TX", IGO_CH_CH0_TX_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_ch1_rx_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_ch1_rx_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_CH1_RX_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "CH1_RX", IGO_CH_CH1_RX_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_ch1_tx_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_ch1_tx_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_CH1_TX_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "CH1_TX", IGO_CH_CH1_TX_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_dai_0_mode_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_dai_0_mode_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_DAI_0_MODE_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "DAI_0_MODE", IGO_CH_DAI_0_MODE_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_dai_0_clk_src_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_dai_0_clk_src_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_DAI_0_CLK_SRC_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "DAI_0_CLK_SRC", IGO_CH_DAI_0_CLK_SRC_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_dai_0_clk_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_dai_0_clk_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_DAI_0_CLK_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "DAI_0_CLK", IGO_CH_DAI_0_CLK_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_dai_0_data_bit_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_dai_0_data_bit_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_DAI_0_DATA_BIT_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "DAI_0_DATA_BIT", IGO_CH_DAI_0_DATA_BIT_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_dai_1_mode_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_dai_1_mode_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_DAI_1_MODE_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "DAI_1_MODE", IGO_CH_DAI_1_MODE_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_dai_1_clk_src_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_dai_1_clk_src_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_DAI_1_CLK_SRC_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "DAI_1_CLK_SRC", IGO_CH_DAI_1_CLK_SRC_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_dai_1_clk_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_dai_1_clk_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_DAI_1_CLK_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "DAI_1_CLK", IGO_CH_DAI_1_CLK_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_dai_1_data_bit_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_dai_1_data_bit_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_DAI_1_DATA_BIT_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "DAI_1_DATA_BIT", IGO_CH_DAI_1_DATA_BIT_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_dai_2_mode_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_dai_2_mode_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_DAI_2_MODE_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "DAI_2_MODE", IGO_CH_DAI_2_MODE_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_dai_2_clk_src_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_dai_2_clk_src_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_DAI_2_CLK_SRC_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "DAI_2_CLK_SRC", IGO_CH_DAI_2_CLK_SRC_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_dai_2_clk_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_dai_2_clk_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_DAI_2_CLK_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "DAI_2_CLK", IGO_CH_DAI_2_CLK_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_dai_2_data_bit_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_dai_2_data_bit_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_DAI_2_DATA_BIT_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "DAI_2_DATA_BIT", IGO_CH_DAI_2_DATA_BIT_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_dai_3_mode_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_dai_3_mode_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_DAI_3_MODE_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "DAI_3_MODE", IGO_CH_DAI_3_MODE_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_dai_3_clk_src_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_dai_3_clk_src_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_DAI_3_CLK_SRC_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "DAI_3_CLK_SRC", IGO_CH_DAI_3_CLK_SRC_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_dai_3_clk_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_dai_3_clk_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_DAI_3_CLK_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "DAI_3_CLK", IGO_CH_DAI_3_CLK_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_dai_3_data_bit_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_dai_3_data_bit_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_DAI_3_DATA_BIT_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "DAI_3_DATA_BIT", IGO_CH_DAI_3_DATA_BIT_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_dmic_m_clk_src_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_dmic_m_clk_src_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_DMIC_M_CLK_SRC_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "DMIC_M_CLK_SRC", IGO_CH_DMIC_M_CLK_SRC_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_dmic_m_bclk_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_dmic_m_bclk_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_DMIC_M_BCLK_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "DMIC_M_BCLK", IGO_CH_DMIC_M_BCLK_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_dmic_s_bclk_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_dmic_s_bclk_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_DMIC_S_BCLK_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "DMIC_S_BCLK", IGO_CH_DMIC_S_BCLK_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_dmic_m0_p_mode_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_dmic_m0_p_mode_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_DMIC_M0_P_MODE_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "DMIC_M0_P_MODE", IGO_CH_DMIC_M0_P_MODE_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_dmic_m0_n_mode_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_dmic_m0_n_mode_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_DMIC_M0_N_MODE_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "DMIC_M0_N_MODE", IGO_CH_DMIC_M0_N_MODE_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_dmic_m1_p_mode_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_dmic_m1_p_mode_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_DMIC_M1_P_MODE_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "DMIC_M1_P_MODE", IGO_CH_DMIC_M1_P_MODE_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_dmic_m1_n_mode_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_dmic_m1_n_mode_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_DMIC_M1_N_MODE_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "DMIC_M1_N_MODE", IGO_CH_DMIC_M1_N_MODE_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_dmic_m2_p_mode_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_dmic_m2_p_mode_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_DMIC_M2_P_MODE_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "DMIC_M2_P_MODE", IGO_CH_DMIC_M2_P_MODE_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_dmic_m2_n_mode_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_dmic_m2_n_mode_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_DMIC_M2_N_MODE_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "DMIC_M2_N_MODE", IGO_CH_DMIC_M2_N_MODE_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_dmic_m3_p_mode_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_dmic_m3_p_mode_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_DMIC_M3_P_MODE_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "DMIC_M3_P_MODE", IGO_CH_DMIC_M3_P_MODE_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_dmic_m3_n_mode_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_dmic_m3_n_mode_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_DMIC_M3_N_MODE_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "DMIC_M3_N_MODE", IGO_CH_DMIC_M3_N_MODE_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_dmic_s0_p_mode_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_dmic_s0_p_mode_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_DMIC_S0_P_MODE_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "DMIC_S0_P_MODE", IGO_CH_DMIC_S0_P_MODE_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_dmic_s0_n_mode_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_dmic_s0_n_mode_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_DMIC_S0_N_MODE_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "DMIC_S0_N_MODE", IGO_CH_DMIC_S0_N_MODE_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_dmic_s1_p_mode_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_dmic_s1_p_mode_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_DMIC_S1_P_MODE_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "DMIC_S1_P_MODE", IGO_CH_DMIC_S1_P_MODE_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_dmic_s1_n_mode_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_dmic_s1_n_mode_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_DMIC_S1_N_MODE_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "DMIC_S1_N_MODE", IGO_CH_DMIC_S1_N_MODE_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_nr_ch0_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_nr_ch0_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_NR_CH0_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "NR_CH0", IGO_CH_NR_CH0_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_nr_ch1_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_nr_ch1_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_NR_CH1_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "NR_CH1", IGO_CH_NR_CH1_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_ch1_ref_mode_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_ch1_ref_mode_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_CH1_REF_MODE_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "CH1_REF_MODE", IGO_CH_CH1_REF_MODE_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_ch1_ref_rx_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_ch1_ref_rx_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_CH1_REF_RX_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "CH1_REF_RX", IGO_CH_CH1_REF_RX_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_ch0_floor_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_ch0_floor_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_CH0_FLOOR_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "CH0_FLOOR", IGO_CH_CH0_FLOOR_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_ch1_floor_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_ch1_floor_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_CH1_FLOOR_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "CH1_FLOOR", IGO_CH_CH1_FLOOR_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_ch0_od_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_ch0_od_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_CH0_OD_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "CH0_OD", IGO_CH_CH0_OD_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_ch1_od_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_ch1_od_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_CH1_OD_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "CH1_OD", IGO_CH_CH1_OD_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_ch0_thr_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_ch0_thr_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_CH0_THR_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "CH0_THR", IGO_CH_CH0_THR_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_ch1_thr_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_ch1_thr_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_CH1_THR_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "CH1_THR", IGO_CH_CH1_THR_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_hw_bypass_dai_0_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_hw_bypass_dai_0_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_HW_BYPASS_DAI_0_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "HW_BYPASS_DAI_0", IGO_CH_HW_BYPASS_DAI_0_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_hw_bypass_dmic_s0_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_hw_bypass_dmic_s0_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_HW_BYPASS_DMIC_S0_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "HW_BYPASS_DMIC_S0", IGO_CH_HW_BYPASS_DMIC_S0_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_sw_bypass_0_rx_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_sw_bypass_0_rx_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_SW_BYPASS_0_RX_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "SW_BYPASS_0_RX", IGO_CH_SW_BYPASS_0_RX_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_sw_bypass_0_tx_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_sw_bypass_0_tx_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_SW_BYPASS_0_TX_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "SW_BYPASS_0_TX", IGO_CH_SW_BYPASS_0_TX_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_sw_bypass_1_rx_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_sw_bypass_1_rx_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_SW_BYPASS_1_RX_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "SW_BYPASS_1_RX", IGO_CH_SW_BYPASS_1_RX_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_sw_bypass_1_tx_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_sw_bypass_1_tx_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_SW_BYPASS_1_TX_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "SW_BYPASS_1_TX", IGO_CH_SW_BYPASS_1_TX_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_aec_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_aec_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_AEC_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "AEC", IGO_CH_AEC_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_aec_ref_rx_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_aec_ref_rx_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_AEC_REF_RX_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "AEC_REF_RX", IGO_CH_AEC_REF_RX_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_vad_status_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	//struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	//int status = IGO_CH_STATUS_DONE;

	//struct debussy_priv* debussy;
	//debussy = dev_get_drvdata(codec->dev);
	//mutex_lock(&debussy->igo_ch_lock);
	//status = igo_ch_read(codec->dev, IGO_CH_VAD_STATUS_ADDR, (unsigned int*)&ucontrol->value.integer.value[0]);
	//mutex_unlock(&debussy->igo_ch_lock);
	ucontrol->value.integer.value[0] = 0;
	//dev_dbg(codec->dev, "%s: read %s (0x%08x) : %d ret %d\n", __func__, "VAD_STATUS", IGO_CH_VAD_STATUS_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_vad_status_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	return 0;
}

static int igo_ch_vad_clear_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_vad_clear_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_VAD_CLEAR_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "VAD_CLEAR", IGO_CH_VAD_CLEAR_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_vad_keyword_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	//struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	//int status = IGO_CH_STATUS_DONE;

	// struct debussy_priv* debussy;
	// debussy = dev_get_drvdata(codec->dev);
	// mutex_lock(&debussy->igo_ch_lock);
	// status = igo_ch_read(codec->dev, IGO_CH_VAD_KEYWORD_ADDR, (unsigned int*)&ucontrol->value.integer.value[0]);
	// mutex_unlock(&debussy->igo_ch_lock);
	ucontrol->value.integer.value[0] = 0;
	//dev_dbg(codec->dev, "%s: read %s (0x%08x) : %d ret %d\n", __func__, "VAD_KEYWORD", IGO_CH_VAD_KEYWORD_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static int igo_ch_vad_keyword_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	return 0;
}

static int igo_ch_vad_key_group_sel_get(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int igo_ch_vad_key_group_sel_put(struct snd_kcontrol* kcontrol,
	struct snd_ctl_elem_value* ucontrol)
{
	struct snd_soc_codec* codec = snd_soc_kcontrol_codec(kcontrol);
	int status = IGO_CH_STATUS_DONE;

	struct debussy_priv* debussy;
	debussy = dev_get_drvdata(codec->dev);

	mutex_lock(&debussy->igo_ch_lock);
	status = igo_ch_write(codec->dev, IGO_CH_VAD_KEY_GROUP_SEL_ADDR, ucontrol->value.integer.value[0]);
	mutex_unlock(&debussy->igo_ch_lock);
	dev_dbg(codec->dev, "%s: write %s (0x%08x) :%d ret %d\n", __func__, "VAD_KEY_GROUP_SEL", IGO_CH_VAD_KEY_GROUP_SEL_ADDR, (int)ucontrol->value.integer.value[0], status);

	return 0;
}

static const struct snd_kcontrol_new debussy_snd_controls[] = {
	SOC_ENUM_EXT("IGO POWER_MODE", soc_enum_power_mode,
		igo_ch_power_mode_get, igo_ch_power_mode_put),
	SOC_SINGLE_EXT("IGO FW_VER", IGO_CH_FW_VER_ADDR,
		IGO_CH_SHIFT, IGO_CH_MAX, IGO_CH_NO_INVERT,
		igo_ch_fw_ver_get, igo_ch_fw_ver_put),
	SOC_SINGLE_EXT("IGO FW_SUB_VER", IGO_CH_FW_SUB_VER_ADDR,
		IGO_CH_SHIFT, IGO_CH_MAX, IGO_CH_NO_INVERT,
		igo_ch_fw_sub_ver_get, igo_ch_fw_sub_ver_put),
	SOC_SINGLE_EXT("IGO CHIP_ID", IGO_CH_CHIP_ID_ADDR,
		IGO_CH_SHIFT, IGO_CH_MAX, IGO_CH_NO_INVERT,
		igo_ch_chip_id_get, igo_ch_chip_id_put),
	SOC_ENUM_EXT("IGO OP_MODE", soc_enum_op_mode,
		igo_ch_op_mode_get, igo_ch_op_mode_put),
	SOC_ENUM_EXT("IGO MCLK", soc_enum_mclk,
		igo_ch_mclk_get, igo_ch_mclk_put),
	SOC_ENUM_EXT("IGO CH0_RX", soc_enum_ch0_rx,
		igo_ch_ch0_rx_get, igo_ch_ch0_rx_put),
	SOC_ENUM_EXT("IGO CH0_TX", soc_enum_ch0_tx,
		igo_ch_ch0_tx_get, igo_ch_ch0_tx_put),
	SOC_ENUM_EXT("IGO CH1_RX", soc_enum_ch1_rx,
		igo_ch_ch1_rx_get, igo_ch_ch1_rx_put),
	SOC_ENUM_EXT("IGO CH1_TX", soc_enum_ch1_tx,
		igo_ch_ch1_tx_get, igo_ch_ch1_tx_put),
	SOC_ENUM_EXT("IGO DAI_0_MODE", soc_enum_dai_0_mode,
		igo_ch_dai_0_mode_get, igo_ch_dai_0_mode_put),
	SOC_ENUM_EXT("IGO DAI_0_CLK_SRC", soc_enum_dai_0_clk_src,
		igo_ch_dai_0_clk_src_get, igo_ch_dai_0_clk_src_put),
	SOC_ENUM_EXT("IGO DAI_0_CLK", soc_enum_dai_0_clk,
		igo_ch_dai_0_clk_get, igo_ch_dai_0_clk_put),
	SOC_ENUM_EXT("IGO DAI_0_DATA_BIT", soc_enum_dai_0_data_bit,
		igo_ch_dai_0_data_bit_get, igo_ch_dai_0_data_bit_put),
	SOC_ENUM_EXT("IGO DAI_1_MODE", soc_enum_dai_1_mode,
		igo_ch_dai_1_mode_get, igo_ch_dai_1_mode_put),
	SOC_ENUM_EXT("IGO DAI_1_CLK_SRC", soc_enum_dai_1_clk_src,
		igo_ch_dai_1_clk_src_get, igo_ch_dai_1_clk_src_put),
	SOC_ENUM_EXT("IGO DAI_1_CLK", soc_enum_dai_1_clk,
		igo_ch_dai_1_clk_get, igo_ch_dai_1_clk_put),
	SOC_ENUM_EXT("IGO DAI_1_DATA_BIT", soc_enum_dai_1_data_bit,
		igo_ch_dai_1_data_bit_get, igo_ch_dai_1_data_bit_put),
	SOC_ENUM_EXT("IGO DAI_2_MODE", soc_enum_dai_2_mode,
		igo_ch_dai_2_mode_get, igo_ch_dai_2_mode_put),
	SOC_ENUM_EXT("IGO DAI_2_CLK_SRC", soc_enum_dai_2_clk_src,
		igo_ch_dai_2_clk_src_get, igo_ch_dai_2_clk_src_put),
	SOC_ENUM_EXT("IGO DAI_2_CLK", soc_enum_dai_2_clk,
		igo_ch_dai_2_clk_get, igo_ch_dai_2_clk_put),
	SOC_ENUM_EXT("IGO DAI_2_DATA_BIT", soc_enum_dai_2_data_bit,
		igo_ch_dai_2_data_bit_get, igo_ch_dai_2_data_bit_put),
	SOC_ENUM_EXT("IGO DAI_3_MODE", soc_enum_dai_3_mode,
		igo_ch_dai_3_mode_get, igo_ch_dai_3_mode_put),
	SOC_ENUM_EXT("IGO DAI_3_CLK_SRC", soc_enum_dai_3_clk_src,
		igo_ch_dai_3_clk_src_get, igo_ch_dai_3_clk_src_put),
	SOC_ENUM_EXT("IGO DAI_3_CLK", soc_enum_dai_3_clk,
		igo_ch_dai_3_clk_get, igo_ch_dai_3_clk_put),
	SOC_ENUM_EXT("IGO DAI_3_DATA_BIT", soc_enum_dai_3_data_bit,
		igo_ch_dai_3_data_bit_get, igo_ch_dai_3_data_bit_put),
	SOC_ENUM_EXT("IGO DMIC_M_CLK_SRC", soc_enum_dmic_m_clk_src,
		igo_ch_dmic_m_clk_src_get, igo_ch_dmic_m_clk_src_put),
	SOC_ENUM_EXT("IGO DMIC_M_BCLK", soc_enum_dmic_m_bclk,
		igo_ch_dmic_m_bclk_get, igo_ch_dmic_m_bclk_put),
	SOC_ENUM_EXT("IGO DMIC_S_BCLK", soc_enum_dmic_s_bclk,
		igo_ch_dmic_s_bclk_get, igo_ch_dmic_s_bclk_put),
	SOC_ENUM_EXT("IGO DMIC_M0_P_MODE", soc_enum_dmic_m0_p_mode,
		igo_ch_dmic_m0_p_mode_get, igo_ch_dmic_m0_p_mode_put),
	SOC_ENUM_EXT("IGO DMIC_M0_N_MODE", soc_enum_dmic_m0_n_mode,
		igo_ch_dmic_m0_n_mode_get, igo_ch_dmic_m0_n_mode_put),
	SOC_ENUM_EXT("IGO DMIC_M1_P_MODE", soc_enum_dmic_m1_p_mode,
		igo_ch_dmic_m1_p_mode_get, igo_ch_dmic_m1_p_mode_put),
	SOC_ENUM_EXT("IGO DMIC_M1_N_MODE", soc_enum_dmic_m1_n_mode,
		igo_ch_dmic_m1_n_mode_get, igo_ch_dmic_m1_n_mode_put),
	SOC_ENUM_EXT("IGO DMIC_M2_P_MODE", soc_enum_dmic_m2_p_mode,
		igo_ch_dmic_m2_p_mode_get, igo_ch_dmic_m2_p_mode_put),
	SOC_ENUM_EXT("IGO DMIC_M2_N_MODE", soc_enum_dmic_m2_n_mode,
		igo_ch_dmic_m2_n_mode_get, igo_ch_dmic_m2_n_mode_put),
	SOC_ENUM_EXT("IGO DMIC_M3_P_MODE", soc_enum_dmic_m3_p_mode,
		igo_ch_dmic_m3_p_mode_get, igo_ch_dmic_m3_p_mode_put),
	SOC_ENUM_EXT("IGO DMIC_M3_N_MODE", soc_enum_dmic_m3_n_mode,
		igo_ch_dmic_m3_n_mode_get, igo_ch_dmic_m3_n_mode_put),
	SOC_ENUM_EXT("IGO DMIC_S0_P_MODE", soc_enum_dmic_s0_p_mode,
		igo_ch_dmic_s0_p_mode_get, igo_ch_dmic_s0_p_mode_put),
	SOC_ENUM_EXT("IGO DMIC_S0_N_MODE", soc_enum_dmic_s0_n_mode,
		igo_ch_dmic_s0_n_mode_get, igo_ch_dmic_s0_n_mode_put),
	SOC_ENUM_EXT("IGO DMIC_S1_P_MODE", soc_enum_dmic_s1_p_mode,
		igo_ch_dmic_s1_p_mode_get, igo_ch_dmic_s1_p_mode_put),
	SOC_ENUM_EXT("IGO DMIC_S1_N_MODE", soc_enum_dmic_s1_n_mode,
		igo_ch_dmic_s1_n_mode_get, igo_ch_dmic_s1_n_mode_put),
	SOC_ENUM_EXT("IGO NR_CH0", soc_enum_nr_ch0,
		igo_ch_nr_ch0_get, igo_ch_nr_ch0_put),
	SOC_ENUM_EXT("IGO NR_CH1", soc_enum_nr_ch1,
		igo_ch_nr_ch1_get, igo_ch_nr_ch1_put),
	SOC_ENUM_EXT("IGO CH1_REF_MODE", soc_enum_ch1_ref_mode,
		igo_ch_ch1_ref_mode_get, igo_ch_ch1_ref_mode_put),
	SOC_ENUM_EXT("IGO CH1_REF_RX", soc_enum_ch1_ref_rx,
		igo_ch_ch1_ref_rx_get, igo_ch_ch1_ref_rx_put),
	SOC_ENUM_EXT("IGO CH0_FLOOR", soc_enum_ch0_floor,
		igo_ch_ch0_floor_get, igo_ch_ch0_floor_put),
	SOC_ENUM_EXT("IGO CH1_FLOOR", soc_enum_ch1_floor,
		igo_ch_ch1_floor_get, igo_ch_ch1_floor_put),
	SOC_ENUM_EXT("IGO CH0_OD", soc_enum_ch0_od,
		igo_ch_ch0_od_get, igo_ch_ch0_od_put),
	SOC_ENUM_EXT("IGO CH1_OD", soc_enum_ch1_od,
		igo_ch_ch1_od_get, igo_ch_ch1_od_put),
	SOC_ENUM_EXT("IGO CH0_THR", soc_enum_ch0_thr,
		igo_ch_ch0_thr_get, igo_ch_ch0_thr_put),
	SOC_ENUM_EXT("IGO CH1_THR", soc_enum_ch1_thr,
		igo_ch_ch1_thr_get, igo_ch_ch1_thr_put),
	SOC_ENUM_EXT("IGO HW_BYPASS_DAI_0", soc_enum_hw_bypass_dai_0,
		igo_ch_hw_bypass_dai_0_get, igo_ch_hw_bypass_dai_0_put),
	SOC_ENUM_EXT("IGO HW_BYPASS_DMIC_S0", soc_enum_hw_bypass_dmic_s0,
		igo_ch_hw_bypass_dmic_s0_get, igo_ch_hw_bypass_dmic_s0_put),
	SOC_ENUM_EXT("IGO SW_BYPASS_0_RX", soc_enum_sw_bypass_0_rx,
		igo_ch_sw_bypass_0_rx_get, igo_ch_sw_bypass_0_rx_put),
	SOC_ENUM_EXT("IGO SW_BYPASS_0_TX", soc_enum_sw_bypass_0_tx,
		igo_ch_sw_bypass_0_tx_get, igo_ch_sw_bypass_0_tx_put),
	SOC_ENUM_EXT("IGO SW_BYPASS_1_RX", soc_enum_sw_bypass_1_rx,
		igo_ch_sw_bypass_1_rx_get, igo_ch_sw_bypass_1_rx_put),
	SOC_ENUM_EXT("IGO SW_BYPASS_1_TX", soc_enum_sw_bypass_1_tx,
		igo_ch_sw_bypass_1_tx_get, igo_ch_sw_bypass_1_tx_put),
	SOC_ENUM_EXT("IGO AEC", soc_enum_aec,
		igo_ch_aec_get, igo_ch_aec_put),
	SOC_ENUM_EXT("IGO AEC_REF_RX", soc_enum_aec_ref_rx,
		igo_ch_aec_ref_rx_get, igo_ch_aec_ref_rx_put),
	SOC_ENUM_EXT("IGO VAD_STATUS", soc_enum_vad_status,
		igo_ch_vad_status_get, igo_ch_vad_status_put),
	SOC_ENUM_EXT("IGO VAD_CLEAR", soc_enum_vad_clear,
		igo_ch_vad_clear_get, igo_ch_vad_clear_put),
	SOC_ENUM_EXT("IGO VAD_KEYWORD", soc_enum_vad_keyword,
		igo_ch_vad_keyword_get, igo_ch_vad_keyword_put),
	SOC_ENUM_EXT("IGO VAD_KEY_GROUP_SEL", soc_enum_vad_key_group_sel,
		igo_ch_vad_key_group_sel_get, igo_ch_vad_key_group_sel_put),
};

void debussy_add_codec_controls(struct snd_soc_codec* codec)
{
	snd_soc_add_codec_controls(codec,
		debussy_snd_controls,
		ARRAY_SIZE(debussy_snd_controls));
}
