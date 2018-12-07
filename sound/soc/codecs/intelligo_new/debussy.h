#ifndef DEBUSSY_H
#define DEBUSSY_H

#include <sound/soc.h>

#define IGO_CH_ACTION_OFFSET (28)

#define IGO_CH_RSV_ADDR (0x2A0C7EF0)
#define IGO_CH_OPT_ADDR (0x2A0C7EF4)
#define IGO_CH_STATUS_ADDR (0x2A0C7EF8)
#define IGO_CH_CMD_ADDR (0x2A0C7EFC)
#define IGO_CH_BUF_ADDR (0x2A0C7F00)

enum {
	DEBUSSY_RX,
	DEBUSSY_TX,
};

enum {
	DEBUSSY_AIF0,
	DEBUSSY_AIF3,
	DEBUSSY_AIF_DMIC,
	DEBUSSY_MAX
};

struct debussy_vreg {
	struct regulator *reg;
	char name[10];
	bool enabled;
	bool unused;
	int min_uV;
	int max_uV;
	int min_uA;
	int max_uA;
};

struct dai_ref {
	atomic_t ch_ref[2];
};

struct debussy_priv {
	struct device* dev;
	struct snd_soc_codec* codec;
	struct workqueue_struct* debussy_wq;
	struct work_struct fw_work;
	struct work_struct irq_work;
	struct mutex igo_ch_lock;
	struct debussy_vreg dvdd;  // 1.2v
	struct debussy_vreg avdd;  // 2.8v
	struct pinctrl *igo_pinctrl;
	struct pinctrl_state *iovdd_enable;
	struct pinctrl_state *iovdd_disable;
	struct pinctrl_state *mclk_enable;
	struct pinctrl_state *mclk_disable;
	struct regulator *i2c_pull;
	struct dentry *dbg_dir;
	struct miscdevice mdev;
	struct i2c_client *i2c;
	struct clk *mclk;
	struct mutex mclk_lock;
	atomic_t maskConfigCmd;
	atomic_t mclk_on;
	atomic_t ref_count[DEBUSSY_MAX+1];
	atomic_t ref_power_mode;
	struct dai_ref dai_ref[DEBUSSY_MAX+1];
	int reset_gpio;
	int chip_version;
	int fw_version;
	int power_on;
	bool dmic_switch;
	bool force_enable_mclk;
	bool factory_mode;
	bool enable_bias;
};

enum debussy_reset_reason {
	DEBUSSY_RESET_NORMAL,
	DEBUSSY_RESET_CLEAR,
	DEBUSSY_RESET_TIMEOUT,
	DEBUSSY_RESET_RWERROR,
};

void debussy_reset_chip(struct debussy_priv* debussy, enum debussy_reset_reason reason);
void debussy_set_maskconfig(struct debussy_priv *debussy, int value);
int debussy_get_maskconfig(struct debussy_priv *debussy);
int debussy_power_mode_add(struct debussy_priv *debussy);
int debussy_power_mode_sub(struct debussy_priv *debussy);
int debussy_power_mode_get(struct debussy_priv *debussy);

#endif
