#ifndef DEBUSSY_H
#define DEBUSSY_H

#include <sound/soc.h>

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

struct debussy_priv {
	struct device* dev;
	struct snd_soc_codec* codec;
	struct workqueue_struct* debussy_wq;
	struct work_struct init_work;
	struct work_struct new_work;
	struct mutex dsp_state_lock;
	int dsp_state;
	int uplink_nr_state;
	int downlink_nr_state;
	int dmic_bypass_state;
	int reset_gpio;
	int power_on;
	struct debussy_vreg dvdd;  // 1.2v
	struct debussy_vreg avdd;  // 2.8v
	struct pinctrl *iovdd_pinctrl;
	struct pinctrl_state *iovdd_enable;
	struct pinctrl_state *iovdd_disable;
	struct regulator *i2c_pull;
};

enum {
	DEBUSSY_AIF,
};

enum {
	DEBUSSY_NR_OFF,
	DEBUSSY_NR_ON,
};

enum {
	DEBUSSY_DMIC_BYPASS,
	DEBUSSY_DMIC_ON,
};

enum {
	STATE_BOOT,
	STATE_DOWNLOADING,
	STATE_READY,
	STATE_INIT_FAIL,
};
#endif
