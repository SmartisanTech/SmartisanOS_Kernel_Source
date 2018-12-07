#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/delay.h>
#include <asm/uaccess.h>
#include <linux/ioport.h>
#include <asm/io.h>
#include <linux/uio_driver.h>
#include <linux/platform_device.h>
#include <linux/slab.h>

#include <linux/regulator/consumer.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/of_irq.h>

#include "nvt_uio.h"

#include <linux/miscdevice.h>

#define DRV_NAME "nt-fpr-uio"
#define DRV_VERSION "0.0.2"
#define DRV_SWITCH_NAME "nvt-switch"
#define DRV_SWITCH_VERSION "0.0.1"

#define NVT_HOLD_TIME 3000

//#define LEVEL_TRIGGER_ENGINE ENABLE
#define LEVEL_TRIGGER_ENGINE DISABLE

#define FPR_IOC_MAGIC                   'f'
#define FPR_IOC_RST_CTRL                _IOW(FPR_IOC_MAGIC, 5, int)
#define FPR_IOC_ENABLE_INTERRUPT        _IOW(FPR_IOC_MAGIC, 20, int)

#define SWITCH 0
#if SWITCH
struct gpio_switch_data {
    struct uio_info         *uioInfo;
    struct work_struct      work;
    struct timer_list       timer;
    unsigned int            timer_debounce;
    int                     switch_gpio;
    bool                    switch_pressed;
    bool                    active_low;
};
struct gpio_switch_data *sdata;
#endif

nvt_uio_data_t *pdata;
static int interrupt_gpio = 0;
//static int nvt_fpr_irqnum, nvt_switch_irqnum;
static int nvt_fpr_irqnum;
static int rst_gpio = 0;
#if 0
static int v3_gpio = 0;
#endif
static NVT_BOOL bProbeCompleted = FALSE;

NVT_BOOL nvt_fpr_uioProbeCompleted(void)
{
    return bProbeCompleted;
}

int nvt_fpr_readInterrupt(void)
{
    NVT_DBG_DBG("interrupt GPIO %d (status:%d)\n",
                 interrupt_gpio, gpio_get_value(interrupt_gpio));
    return gpio_get_value(interrupt_gpio);
}

void nvt_fpr_reset(int direct)
{
    if (direct == 0 || direct == 1)
    {
        gpio_set_value(rst_gpio, direct);
    }
    else
    {
        NVT_DBG_DBG("Trigger reset pin!!! (Pull LOW then raise to HIGH)\n");
        gpio_set_value(rst_gpio, 0);
        udelay(100);
        gpio_set_value(rst_gpio, 1);
    }
}

void nvt_fpr_enableIRQ(void)
{
//    NVT_DBG_DBG("Enable IRQ\n");
#if (LEVEL_TRIGGER_ENGINE == ENABLE)
    enable_irq(nvt_fpr_irqnum);
#endif
}

static irqreturn_t nvt_fpr_uio_isr(int irqnum, struct uio_info *data)
{
//    NVT_DBG_ERR("nvt_fpr_uio_isr!!!\n");
//    NVT_DBG_ERR("nvt_fpr_uio_isr=%d, irqnum=%d\n", nvt_fpr_irqnum, irqnum);
//    NVT_DBG_DBG("Disable IRQ\n");
    __pm_wakeup_event(&pdata->nvt_wsrc,NVT_HOLD_TIME);
#if (LEVEL_TRIGGER_ENGINE == ENABLE)
    disable_irq_nosync(nvt_fpr_irqnum);
#endif

    return IRQ_HANDLED;
}
#if SWITCH
// work function
static void gpio_swicth_work_func(struct work_struct *work)
{
    struct uio_info *data = sdata->uioInfo;
    uio_event_notify(data);
}
// timer scheduling
static void gpio_swicth_timer(unsigned long _data)
{
    if (!sdata->switch_pressed &&
        (gpio_get_value(sdata->switch_gpio) ^ (sdata->active_low)))
    {
        schedule_work(&sdata->work);
        sdata->switch_pressed = TRUE;
    }
    else if (sdata->switch_pressed &&
        !(gpio_get_value(sdata->switch_gpio) ^ (sdata->active_low)))
    {
        schedule_work(&sdata->work);
        sdata->switch_pressed = FALSE;
    }
}
// switch isr
static irqreturn_t nvt_fpr_switch_isr(int irqnum, struct uio_info *data)
{
//    NVT_DBG_ERR("nvt_fpr_switch_isr!!!\n");
//    NVT_DBG_ERR("nvt_fpr_switch_isr=%d, irqnum=%d\n", nvt_switch_irqnum, irqnum);

    if (sdata->timer_debounce)
    {
        mod_timer(&sdata->timer, jiffies + msecs_to_jiffies(sdata->timer_debounce));
    }
    else
    {
        return IRQ_HANDLED;
    }
    return IRQ_NONE;
}
#endif

static long nvt_gpio_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int val = 0;


    if(_IOC_TYPE(cmd) != FPR_IOC_MAGIC)
    {
        return -ENOTTY;
    }

    switch(cmd)
    {
        case FPR_IOC_RST_CTRL:
            if (copy_from_user(&val, (void __user *)arg, _IOC_SIZE(cmd)))
            {
                NVT_DBG_ERR("copy from user\n");
                return -ENOTTY;
            }
            NVT_DBG_DBG("nvt_gpio_device reset test\n");
            nvt_fpr_reset(val);
            break;

        case FPR_IOC_ENABLE_INTERRUPT:
            NVT_DBG_DBG("nvt_gpio_device enable IRQ\n");
            nvt_fpr_enableIRQ();
            break;

         default:
            NVT_DBG_ERR("Non-support command!!!\n");
            break;
    }

    return 0;
}

#ifdef CONFIG_COMPAT
static long
nvt_gpio_compat_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    return nvt_gpio_ioctl(filp, cmd, (unsigned long)compat_ptr(arg));
}
#else
#define gpiodev_hw_compat_ioctl NULL
#endif /* CONFIG_COMPAT */

static const struct file_operations nvt_gpio_fops = {
    .owner =    THIS_MODULE,
    /* REVISIT switch to aio primitives, so that userspace
     * gets more complete API coverage.  It'll simplify things
     * too, except for the locking.
     */
    .unlocked_ioctl = nvt_gpio_ioctl,
    .compat_ioctl = nvt_gpio_compat_ioctl,
    .llseek = no_llseek,
};

static struct miscdevice nvt_gpio_device = {
    .name = "nvt_gpio_device",
    .minor = MISC_DYNAMIC_MINOR,
    .fops = &nvt_gpio_fops,
    //.mode = S_IWUGO | S_IRUGO, /*S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH, */
};

static int nvt_register_gpiodev(void)
{
    int retval;

    /* Register a misc to handle spi_ioc_transfer */
    nvt_gpio_device.parent = NULL;
    retval = misc_register(&nvt_gpio_device);
    if (retval < 0)
    {
        NVT_DBG_ERR("misc_register failed: %d\n", retval);
        return retval;
    }

    return retval;
}

static int nvt_fpr_uio_probe(struct platform_device *pdev)
{
    struct uio_info *info;
    int ret, retval;
    struct regulator *vreg = NULL;
    struct device *dev = &pdev->dev;

    NVT_DBG_DBG("entry\n");

    pdata = kzalloc(sizeof(nvt_uio_data_t), GFP_KERNEL);
    if (!pdata)
        return -ENOMEM;

    /* Request GPIO */
    pdata->irq_gpio = of_get_named_gpio(pdev->dev.of_node, "nvt_uio,irq_gpio", 0);
#if SWITCH
    pdata->switch_irq_gpio = of_get_named_gpio(pdev->dev.of_node, "nvt_uio,switch_irq_gpio", 0);
#endif
    interrupt_gpio = pdata->irq_gpio;
#if 0
	/* Set 3v3 pin */
    pdata->v3_gpio = of_get_named_gpio(pdev->dev.of_node, "nvt_uio,v3_gpio", 0);
    gpio_request(pdata->v3_gpio, "nvt_fpr_3v3_gpio");
    v3_gpio = pdata->v3_gpio;
    ret = gpio_direction_output(pdata->v3_gpio, 0);
    NVT_DBG_DBG("set 3v3_gpio to gpio_direction_output(0): %d\n", ret);
    udelay(100);
    gpio_set_value(pdata->v3_gpio, 1);
#endif
    /* set regulator 3v3 */
    vreg = regulator_get(dev, "nvt_v3");
    if (IS_ERR(vreg)) {
        NVT_DBG_ERR("Unable to get v3\n");
        return -ENOMEM;
    }
    if (regulator_count_voltages(vreg) > 0){
        ret = regulator_set_voltage(vreg, 2950000UL, 2950000UL);
        if (ret) {
            NVT_DBG_ERR("Unable to set voltage on v3, %d", ret);
        }
    }
    ret = regulator_set_load(vreg, 6000);
    if (ret) {
        NVT_DBG_ERR("Unable to set current on v3, %d", ret);
    }
    ret = regulator_enable(vreg);
    if (ret) {
        NVT_DBG_ERR("error enabling v3: %d\n", ret);
        regulator_put(vreg);
        vreg = NULL;
    }
    /* Set reset pin */
    pdata->rst_gpio = of_get_named_gpio(pdev->dev.of_node, "nvt_uio,rst_gpio", 0);
    gpio_request(pdata->rst_gpio, "nvt_fpr_rst_gpio");
    rst_gpio = pdata->rst_gpio;
    ret = gpio_direction_output(pdata->rst_gpio, 0);
    NVT_DBG_DBG("set rst_gpio to gpio_direction_output(0): %d\n", ret);
    udelay(100);
    gpio_set_value(pdata->rst_gpio, 1);

    /* Set interrupt pin */
    gpio_request(pdata->irq_gpio, "nvt_fpr_irq_gpio");
    ret = gpio_direction_input(pdata->irq_gpio);
    NVT_DBG_DBG("set irq_gpio to gpio_direction_input: %d\n", ret);

    /* Request Interrupt Pin for NVT device */
    nvt_fpr_irqnum = gpio_to_irq(pdata->irq_gpio);

    /* Allocate UIO device */
    info = kzalloc(sizeof(struct uio_info), GFP_KERNEL);
    if (!info)
    {
        NVT_DBG_ERR("Allocate UIO FAILED info\n");
        return -ENOMEM;
    }

    info->name = DRV_NAME;
    info->version = DRV_VERSION;
    info->irq = nvt_fpr_irqnum;
#if (LEVEL_TRIGGER_ENGINE == ENABLE)
    info->irq_flags = IRQF_TRIGGER_HIGH;
#else
    info->irq_flags = IRQF_TRIGGER_RISING;
#endif
    info->handler = nvt_fpr_uio_isr;

    /* Request that the interrupt should be wakeable */
    enable_irq_wake(nvt_fpr_irqnum);
    wakeup_source_init(&pdata->nvt_wsrc, "nvt_fprservice");

// You can also use the request_irq to register irq_handler for test.
//    ret = request_irq(nvt_fpr_irqnum, nvt_fpr_uio_isr, IRQF_TRIGGER_RISING, dev_name(&pdev->dev), NULL);
    NVT_DBG_DBG("request_irq: %d\n", ret);

    if (uio_register_device(&pdev->dev, info))
    {
        kfree(info);
        return -ENODEV;
    }
    NVT_DBG_DBG("GPIO_IRQ register done, irqnum = %d\n", nvt_fpr_irqnum);
    pdata->uioInfo = info;
    bProbeCompleted = TRUE;
#if SWITCH
    /* Set Switch pin */
    gpio_request(pdata->switch_irq_gpio, "nvt_switch_irq_gpio");
    ret = gpio_direction_input(pdata->switch_irq_gpio);
    NVT_DBG_DBG("set switch_irq_gpio to gpio_direction_input: %d\n", ret);
    /* Allocate Switch device */
    nvt_switch_irqnum = gpio_to_irq(pdata->switch_irq_gpio);
    info = kzalloc(sizeof(struct uio_info), GFP_KERNEL);
    if (!info)
    {
        NVT_DBG_ERR("Allocate SWITCH FAILED info\n");
        return -ENOMEM;
    }

    info->name = DRV_SWITCH_NAME;
    info->version = DRV_SWITCH_VERSION;
    info->irq = nvt_switch_irqnum;
    info->irq_flags = IRQF_TRIGGER_RISING|IRQF_TRIGGER_FALLING;
    info->handler = nvt_fpr_switch_isr;

    NVT_DBG_DBG("request_irq: %d\n", ret);
    if (uio_register_device(&pdev->dev, info))
    {
        kfree(info);
        return -ENODEV;
    }

    NVT_DBG_DBG("Switch GPIO_IRQ register done, irqnum = %d\n", nvt_switch_irqnum);
    pdata->switchInfo = info;
    platform_set_drvdata(pdev, pdata);

    // setup debounce timer to avoid switch gpio unstable
    sdata = kzalloc(sizeof(struct gpio_switch_data), GFP_KERNEL);
    INIT_WORK(&sdata->work, gpio_swicth_work_func);
    setup_timer(&sdata->timer,
            gpio_swicth_timer, (unsigned long)sdata);
    sdata->uioInfo = pdata->switchInfo;
    sdata->switch_gpio = pdata->switch_irq_gpio;
    sdata->timer_debounce = 50;
    sdata->switch_pressed = FALSE;
    sdata->active_low = TRUE;

#endif

    /* Register HWRESET DEV for UserSpace ioctl */
    retval = nvt_register_gpiodev();
    if (retval < 0)
    {
        NVT_DBG_ERR("nvt_register_gpiodev failed: %d\n", retval);
        return retval;
    }
    return 0;
}

static int nvt_fpr_uio_remove(struct platform_device *dev)
{
    struct uio_info *info = pdata->uioInfo;
    wakeup_source_trash(&pdata->nvt_wsrc);
    uio_unregister_device(info);
    kfree(info);

#if SWITCH
    info = pdata->switchInfo;
    uio_unregister_device(info);
    platform_set_drvdata(dev, NULL);
    kfree(info);
#endif

    return 0;
}

static struct of_device_id nvt_fpr_dt_match[] = {
    {
        .compatible = "nvt_uio",
    },
    {}
};

static struct platform_driver nvt_fpr_uio_driver = {
    .driver     = {
        .name   = DRV_NAME,
        .owner  = THIS_MODULE,
        .of_match_table = nvt_fpr_dt_match,
    },
    .remove     = nvt_fpr_uio_remove,
    .probe      = nvt_fpr_uio_probe,
};

extern char *fingerprint_id;

static int get_fingerprint_id(char *src)
{
    if (src == NULL)
    {
        NVT_DBG_ERR("src is NULL\n");
        return 0;
    }

    if (!strcmp(src, "nvtfp"))
    {
        fingerprint_id = "nvtfp";
    }
    else if(!strcmp(src, "fpc"))
    {
        fingerprint_id = "fpc";
    }
    else if(!strcmp(src, "goodix"))
    {
        fingerprint_id = "goodix";
    }

    NVT_DBG_DBG("kernel detect fingerprint_id = *%s*\n", fingerprint_id);

    return 1;
}
__setup("androidboot.fingerprint.id=", get_fingerprint_id);

/*
 * Main initialization/remove routines
 */
static int __init nvt_fpr_sdm845_init(void)
{
    int retval = 0;

    if(strcmp(fingerprint_id, "nvtfp")) 
    {
        NVT_DBG_ERR("%s fingerprint_id = %s \n", __func__, fingerprint_id);
        return -1;
    }

    //NVT_DBG_DBG("Register UIO driver\n");
    retval = platform_driver_register(&nvt_fpr_uio_driver);
    if (retval != 0)
    {
        NVT_DBG_ERR("unable to register UIO driver.\n");
        return retval;
    }

    return retval;
}

static void __exit nvt_fpr_sdm845_exit(void)
{
    misc_deregister(&nvt_gpio_device);

    NVT_DBG_DBG("UIO EXIT!\n");
    platform_driver_unregister(&nvt_fpr_uio_driver);
}

late_initcall(nvt_fpr_sdm845_init);
module_exit(nvt_fpr_sdm845_exit);

MODULE_DESCRIPTION("NVT FPR Module");
MODULE_AUTHOR("YuChao Hsu<yuchao_hsu@nvt.com.tw>");
MODULE_LICENSE("GPL");
