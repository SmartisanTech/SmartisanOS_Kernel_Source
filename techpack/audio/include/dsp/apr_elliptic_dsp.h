#pragma once

#include <linux/types.h>
#include <linux/delay.h>
#include <dsp/apr_audio-v2.h>
#include <sound/apr_elliptic.h>

/** Sequence of Elliptic Labs Ultrasound module parameters */
struct afe_ultrasound_set_params_t {
	uint32_t  payload[ELLIPTIC_SET_PARAMS_SIZE];
} __packed;

struct afe_ultrasound_config_command {
	struct apr_hdr                      hdr;
	struct afe_port_cmd_set_param_v2    param;
	struct afe_port_param_data_v2       pdata;
	struct afe_ultrasound_set_params_t  prot_config;
} __packed;

/** Sequence of Elliptic Labs Ultrasound module parameters */
struct afe_ultrasound_get_params_t {
	uint32_t payload[ELLIPTIC_GET_PARAMS_SIZE];
} __packed;

struct afe_ultrasound_get_calib {
	struct afe_port_cmd_get_param_v2   get_param;
	struct afe_port_param_data_v2      pdata;
	struct afe_ultrasound_get_params_t res_cfg;
} __packed;

struct afe_ultrasound_calib_get_resp {
	struct afe_ultrasound_get_params_t res_cfg;
} __packed;
