#ifndef __ISA1200_H__
#define __ISA1200_H__
/*
** =============================================================================
** Copyright (c)2017  IMAGIS co.,
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
**     isa1200.h
**
** Description:
**     Header file for isa1200.c
**
** =============================================================================
*/

#define HAPTICS_DEVICE_NAME "isa1200"

#define ISA1200_REG_LCTRL       (0x00)
#define ISA1200_REG_HPTDRV      (0x30)
#define ISA1200_REG_CLKSEL      (0x31)
#define ISA1200_REG_SECFG       (0x32)
#define ISA1200_REG_PLLDIV      (0x33)
#define ISA1200_REG_PWMADJ      (0x34)
#define ISA1200_REG_PWMHIGH     (0x35)
#define ISA1200_REG_PWMPERIOD   (0x36)

#define ISA1200_REG_SEHIGH      (0x3B)
#define ISA1200_REG_SEPERIOD    (0x3C)
#define ISA1200_REG_SEFWRVS     (0x3D)

#define ISA1200_HPTEN_MASK      (1 << 7)

#define TRUE        (1)
#define FALSE       (0)

#define ENABLE      (1)
#define DISABLE     (0)

#define MAX_FILE_PATH   255
#define PHE_BIN_NAME    "imagis_phe.bin"

#define countof(n)  (sizeof(n) / sizeof(n[0]))

#define MAX_AMPLITUDE       (1000)
#define MAX_PLAY_TIME_MS    (1500)

#define VIBRATE_AMP         (666)

#define BASE_FREQ           (195)

#define MIN_FREQ            (BASE_FREQ - 60)
#define MAX_FREQ            (BASE_FREQ + 60)

#define MIN_SE_FWD          (0)
#define MAX_SE_FWD          (0x1F)

#define MIN_SE_RVS          (0)
#define MAX_SE_RVS          (0x07)


typedef struct _stRegCmd_t {
    char cmd;
    uint32_t addr;
    uint32_t val;
} stRegCmd_t;

typedef struct _stSimpleEffect_t {
    uint16_t freq;
    int16_t amp;
    uint8_t fwd;
    uint8_t rvs;
} stSimpleEfft_t;

enum ActuatorType {
    ERM,
    LRA
};

typedef struct _stActuatorData_t {
    enum ActuatorType actuator_type;
    uint16_t res_freq;
} stActuatorData_t;

typedef struct _stHapticEffect_t {
    int16_t amp;
    uint16_t ms;
} stHapticEffect_t;

typedef struct _stHapticEffectInfo_t {
    stHapticEffect_t *pEffect;
    uint16_t frame;
    uint16_t freq;
} stHapticPlayInfo_t;



typedef struct _stPheBinHeader_t {
    uint32_t size;
    uint16_t count;
    uint8_t reserved[10];
} stPheBinHeader_t;

typedef struct _stPheBinInfo_t {
    char name[20];
    uint16_t status;
    uint16_t freq;
    uint32_t addr;
    uint32_t count;
} stPheInfo_t;

#define PHE_STS_QUISCENT    (1 << 15)
#define PHE_STS_LONG_VIBE   (1 << 14)

typedef struct _stPhe_t {
    uint16_t ms;
    int16_t amp;
} stPhe_t;

typedef struct _stPheBin_t {
    stPheBinHeader_t header;
    stPheInfo_t *pinfo;
    uint8_t *pbuf;
} stPheBin_t;


extern stHapticPlayInfo_t caHapticPress[];
extern stHapticPlayInfo_t caHapticRelease[];

typedef struct _stIsa1200Platform_t {
    bool use_en;
    int en_gpio;

    struct pinctrl *clk_pinctrl;
    struct pinctrl_state *pin_enable_state;
    struct pinctrl_state *pin_disable_state;
    struct clk *ext_clk;

    uint32_t input_freq;
    uint16_t max_vpp;

    stActuatorData_t stActuator;
} stIsa1200Platform_t;

typedef struct _stIsa1200Data_t {
    stIsa1200Platform_t stPlatform;

    stHapticPlayInfo_t *pHptPlayInfo;
    stPheInfo_t *pPheInfo;
    stPhe_t *pPhe;
    stSimpleEfft_t stSE;

    volatile bool bPlayingHaptic;
    volatile bool bConfigured;
    volatile bool bReadyHaptic;
    volatile bool bPheMode;;

    stPheBin_t stBin;

    struct device *pdev;
    struct regmap *pRegmap;

    struct i2c_client* client;
#ifdef CONFIG_HAS_EARLYSUSPEND
    struct early_suspend early_suspend;
#endif

    struct class *pclass;
    struct device *pdevDebug;
    struct device *pdevPlayer;
    struct device *pdevVibrator;

    struct hrtimer timer;
    struct hrtimer timer_stop;

    struct kthread_worker kworker;
    struct kthread_work kwork;

    struct mutex lock;
    struct mutex clk_lock;
    u32 play_time_ms;

} stIsa1200Data_t;

void isa1200_player_timer_init(stIsa1200Data_t *pIsa1200);
void isa1200_player_timer_cancel(stIsa1200Data_t *pIsa1200);
bool isa1200_player_start(stIsa1200Data_t *pIsa1200);
bool isa1200_player_stop(stIsa1200Data_t *pIsa1200);

void isa1200_haptic_reset(stIsa1200Data_t *pIsa1200);

int isa1200_haptic_enable(stIsa1200Data_t *pIsa1200, bool enable);
int isa1200_set_frequency(stIsa1200Data_t *pIsa1200, uint16_t freq);
int isa1200_set_amplitude(stIsa1200Data_t *pIsa1200, int16_t amp);
int isa1200_set_se(stIsa1200Data_t *pIsa1200, stSimpleEfft_t *pse);

#endif // __ISA1200_H__
