#ifndef __NVT_UIO_H
#define __NVT_UIO_H

#include "nvt_debug.h"
#include <linux/pinctrl/consumer.h>
#include <linux/workqueue.h>
#include <linux/sched.h>

typedef struct nvt_uio_data {
    struct device           dev;
    int                     rst_gpio;
    int                     irq_gpio;
    int                     v3_gpio;
    int                     switch_irq_gpio;
    struct wakeup_source    nvt_wsrc;
    struct uio_info         *uioInfo;
    struct uio_info         *switchInfo;
    struct pinctrl          *pinctrl;
    struct pinctrl_state    *pins_active;
    struct pinctrl_state    *pins_sleep;
} nvt_uio_data_t;

#endif // __NVT_UIO_H
