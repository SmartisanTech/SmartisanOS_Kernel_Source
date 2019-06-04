#ifndef __SDM845__H__
#define __SDM845__H__

enum pinctrl_pin_state {
	STATE_DISABLE = 0, /* All pins are in sleep state */
	STATE_MI2S_ACTIVE,  /* IS2 = active, TDM = sleep */
	STATE_TDM_ACTIVE,  /* IS2 = sleep, TDM = active */
};

struct msm_pinctrl_info {
	struct pinctrl *pinctrl;
	struct pinctrl_state *mi2s_disable;
	struct pinctrl_state *tdm_disable;
	struct pinctrl_state *mi2s_active;
	struct pinctrl_state *tdm_active;
	enum pinctrl_pin_state curr_state;
};

struct msm_asoc_mach_data {
	u32 mclk_freq;
	int us_euro_gpio; /* used by gpio driver API */
	int usbc_en2_gpio; /* used by gpio driver API */
	struct device_node *us_euro_gpio_p; /* used by pinctrl API */
	struct pinctrl *usbc_en2_gpio_p; /* used by pinctrl API */
	struct device_node *hph_en1_gpio_p; /* used by pinctrl API */
	struct device_node *hph_en0_gpio_p; /* used by pinctrl API */
	struct snd_info_entry *codec_root;
	struct msm_pinctrl_info pinctrl_info;
	struct pinctrl_state *en2_pinctrl_active;
	struct pinctrl_state *en2_pinctrl_sleep;
	struct pinctrl_state *en2_pinctrl_default;
};

#endif
