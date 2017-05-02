
 /**
 * \addtogroup spi_driver
 *
 * @{ */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/irq.h>
#include <linux/jiffies.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/platform_device.h>
#include <linux/gpio.h>
#include <linux/of_gpio.h>
#include <linux/miscdevice.h>
#include <linux/spinlock.h>
#include <linux/spi/spi.h>
#include <linux/sched.h>
#include <linux/poll.h>
#include <linux/regulator/consumer.h>
#include <linux/nfc/p61.h>
#define DRAGON_P61 1

/* Device driver's configuration macro */
/* Macro to configure poll/interrupt based req*/
//#undef P61_IRQ_ENABLE
#define P61_IRQ_ENABLE

/* Macro to configure Hard/Soft reset to P61 */
//#define P61_HARD_RESET
//#undef P61_HARD_RESET

#ifdef P61_HARD_RESET
static struct regulator *p61_regulator = NULL;
#else
#endif

#define P61_IRQ   33 /* this is the same used in omap3beagle.c */
#define P61_RST  138

/* Macro to define SPI clock frequency */

//#define P61_SPI_CLOCK_7Mzh
#undef P61_SPI_CLOCK_7Mzh

#ifdef P61_SPI_CLOCK_7Mzh
#define P61_SPI_CLOCK     7000000L;
#else
#define P61_SPI_CLOCK     4000000L;
#endif

/* size of maximum read/write buffer supported by driver */
#define MAX_BUFFER_SIZE   256U

/* Different driver debug lever */
enum P61_DEBUG_LEVEL {
    P61_DEBUG_OFF,
    P61_FULL_DEBUG
};

/* Variable to store current debug level request by ioctl */
static unsigned char debug_level=1;

#define P61_DBG_MSG(msg...)  \
        switch(debug_level)      \
        {                        \
        case P61_DEBUG_OFF:      \
        break;                 \
        case P61_FULL_DEBUG:     \
        printk(KERN_INFO "[NXP-P61] :  " msg); \
        break; \
        default:                 \
        printk(KERN_ERR "[NXP-P61] :  Wrong debug level %d", debug_level); \
        break; \
        } \

#define P61_ERR_MSG(msg...) printk(KERN_ERR "[NFC-P61] : " msg );

/* Device specific macro and structure */
struct p61_dev {
    wait_queue_head_t read_wq; /* wait queue for read interrupt */
    struct mutex read_mutex; /* read mutex */
    struct mutex write_mutex; /* write mutex */
    struct spi_device *spi;  /* spi device structure */
    struct miscdevice p61_device; /* char device as misc driver */
    unsigned int hard_rst_gpio;
    //unsigned int rst_gpio; // SW Reset gpio 
    unsigned int irq_gpio; /* P61 will interrupt DH for any ntf */
    bool irq_enabled; /* flag to indicate irq is used */
    unsigned char enable_poll_mode; /* enable the poll mode */
    spinlock_t irq_enabled_lock; /*spin lock for read irq */
};

/* T==1 protocol specific global data */
const unsigned char SOF = 0xA5u;

/**
 * \ingroup spi_driver
 * \brief Called from SPI LibEse to initilaize the P61 device
 *
 * \param[in]       struct inode *
 * \param[in]       struct file *
 *
 * \retval 0 if ok.
 *
*/

static int p61_dev_open(struct inode *inode, struct file *filp) {

    struct p61_dev
    *p61_dev = container_of(filp->private_data,
            struct p61_dev,
            p61_device);

    filp->private_data = p61_dev;
    P61_DBG_MSG(
            "%s : Major No: %d, Minor No: %d\n", __func__, imajor(inode), iminor(inode));

    return 0;
}

/**
 * \ingroup spi_driver
 * \brief To configure the P61_SET_PWR/P61_SET_DBG/P61_SET_POLL
 * \n         P61_SET_PWR - hard reset (arg=2), soft reset (arg=1)
 * \n         P61_SET_DBG - Enable/Disable (based on arg value) the driver logs
 * \n         P61_SET_POLL - Configure the driver in poll (arg = 1), interrupt (arg = 0) based read operation
 * \param[in]       struct file *
 * \param[in]       unsigned int
 * \param[in]       unsigned long
 *
 * \retval 0 if ok.
 *
*/

static long p61_dev_ioctl(struct file *filp, unsigned int cmd,
        unsigned long arg)
{
    int ret = 0;
    struct p61_dev *p61_dev = NULL;

    //unsigned char buf[100];


    P61_DBG_MSG(KERN_ALERT "p61_dev_ioctl-Enter %u arg = %ld\n", cmd, arg);
    p61_dev = filp->private_data;

    switch (cmd) {
    case P61_SET_PWR:
        if (arg == 2)
        {
#ifdef P61_HARD_RESET
            P61_DBG_MSG(KERN_ALERT " Disabling p61_regulator");
            if (p61_regulator != NULL)
            {
                regulator_disable(p61_regulator);
                msleep(50);
                ret=regulator_enable(p61_regulator);
                P61_DBG_MSG(KERN_ALERT " Enabling p61_regulator");
            }
            else
            {
                P61_ERR_MSG(KERN_ALERT " ERROR : p61_regulator is not enabled");
            }
#endif

        }
        else if (arg == 1)
        {
            P61_DBG_MSG(KERN_ALERT " Soft Reset");
            //gpio_set_value(p61_dev->rst_gpio, 1);
            //msleep(20);
            /*
            gpio_set_value(p61_dev->rst_gpio, 0);
            msleep(20);
            gpio_set_value(p61_dev->rst_gpio, 1);
            msleep(20);
            gpio_set_value(p61_dev->rst_gpio, 0);
            msleep(50);
            ret = spi_read (p61_dev -> spi,(void *) buf, sizeof(buf));
            msleep(50);
            gpio_set_value(p61_dev->rst_gpio, 1);
            msleep(20);
            */
        }
        break;

    case P61_SET_HARD_RST:
        printk("---[NXP-P61] -  P61_SET_HARD_RST : hard_rst_gpio=%d ",p61_dev->hard_rst_gpio); 
        gpio_set_value(p61_dev->hard_rst_gpio, 0);
        msleep(10);
        gpio_set_value(p61_dev->hard_rst_gpio, 1); 
        msleep(10);

        break;
    case P61_SET_DBG:
        debug_level = (unsigned char )arg;
        P61_DBG_MSG(KERN_INFO"[NXP-P61] -  Debug level %d", debug_level);
        break;

    case P61_SET_POLL:

        p61_dev-> enable_poll_mode = (unsigned char )arg;
        if (p61_dev-> enable_poll_mode == 0)
        {
            P61_DBG_MSG(KERN_INFO"[NXP-P61] - IRQ Mode is set \n");
        }
        else
        {
            P61_DBG_MSG(KERN_INFO"[NXP-P61] - Poll Mode is set \n");
            p61_dev->enable_poll_mode = 1;
        }
        break;
    default:
        ret = -EINVAL;
    }

    return ret;
}

/**
 * \ingroup spi_driver
 * \brief Write data to P61 on SPI
 *
 * \param[in]       struct file *
 * \param[in]       const char *
 * \param[in]       size_t
 * \param[in]       loff_t *
 *
 * \retval data size
 *
*/

static ssize_t p61_dev_write(struct file *filp, const char *buf, size_t count,
        loff_t *offset)
{

    int ret = -1;
    struct p61_dev *p61_dev;
    unsigned char tx_buffer[MAX_BUFFER_SIZE];

    P61_DBG_MSG(KERN_ALERT "p61_dev_write -Enter count %d\n", (int)count);

    p61_dev = filp->private_data;

    mutex_lock(&p61_dev->write_mutex);
    if (count > MAX_BUFFER_SIZE)
        count = MAX_BUFFER_SIZE;

    memset(&tx_buffer[0], 0, sizeof(tx_buffer));
    if (copy_from_user(&tx_buffer[0], &buf[0], count))
    {
        P61_ERR_MSG("%s : failed to copy from user space\n", __func__);
        mutex_unlock(&p61_dev->write_mutex);
        return -EFAULT;
    }
    /* Write data */
    ret = spi_write(p61_dev->spi, &tx_buffer[0], count);
    if (ret < 0)
    {
        ret = -EIO;
    }
    else
    {
        ret = count;
    }

    mutex_unlock(&p61_dev->write_mutex);
    P61_DBG_MSG(KERN_ALERT "p61_dev_write ret %d- Exit \n", ret);
    return ret;
}

#ifdef P61_IRQ_ENABLE

/**
 * \ingroup spi_driver
 * \brief To disable IRQ
 *
 * \param[in]       struct p61_dev *
 *
 * \retval void
 *
*/

static void p61_disable_irq(struct p61_dev *p61_dev)
{
    unsigned long flags;

    P61_DBG_MSG("Entry : %s\n", __FUNCTION__);

    spin_lock_irqsave(&p61_dev->irq_enabled_lock, flags);
    if (p61_dev->irq_enabled)
    {
        disable_irq_nosync(p61_dev->spi->irq);
        p61_dev->irq_enabled = false;
    }
    spin_unlock_irqrestore(&p61_dev->irq_enabled_lock, flags);

    P61_DBG_MSG("Exit : %s\n", __FUNCTION__);
}

/**
 * \ingroup spi_driver
 * \brief Will get called when interrupt line asserted from P61
 *
 * \param[in]       int
 * \param[in]       void *
 *
 * \retval IRQ handle
 *
*/

static irqreturn_t p61_dev_irq_handler(int irq, void *dev_id)
{
    struct p61_dev *p61_dev = dev_id;

    P61_DBG_MSG("Entry : %s\n", __FUNCTION__);
    p61_disable_irq(p61_dev);

    /* Wake up waiting readers */
    wake_up(&p61_dev->read_wq);

    P61_DBG_MSG("Exit : %s\n", __FUNCTION__);
    return IRQ_HANDLED;
}
#endif

/**
 * \ingroup spi_driver
 * \brief Used to read data from P61 in Poll/interrupt mode configured using ioctl call
 *
 * \param[in]       struct file *
 * \param[in]       char *
 * \param[in]       size_t
 * \param[in]       loff_t *
 *
 * \retval read size
 *
*/

static ssize_t p61_dev_read(struct file *filp, char *buf, size_t count,
        loff_t *offset)
{
    int ret = -EIO;
    struct p61_dev *p61_dev = filp->private_data;
    unsigned char sof = 0x00;
    int total_count = 0;
    unsigned char rx_buffer[MAX_BUFFER_SIZE];

    P61_DBG_MSG("p61_dev_read count %d - Enter \n", (int)count);

    if (count < MAX_BUFFER_SIZE)
    {
        P61_ERR_MSG(KERN_ALERT "Invalid length (min : 258) [%d] \n", (int)count);
        return -EINVAL;
    }
    mutex_lock(&p61_dev->read_mutex);
    if (count > MAX_BUFFER_SIZE)
    {
        count = MAX_BUFFER_SIZE;
    }

    memset(&rx_buffer[0], 0x00, sizeof(rx_buffer));

    if (p61_dev->enable_poll_mode)
    {
        P61_DBG_MSG(" %s Poll Mode Enabled \n", __FUNCTION__);

        do
        {
            sof = 0x00;
            P61_DBG_MSG(KERN_INFO"SPI_READ returned 0x%x", sof);
            ret = spi_read(p61_dev->spi, (void *)&sof, 1);
            if (0 > ret)
            {
                P61_ERR_MSG(KERN_ALERT "spi_read failed [SOF] \n");
                goto fail;
            }
            P61_DBG_MSG(KERN_INFO"SPI_READ returned 0x%x", sof);
            /* if SOF not received, give some time to P61 */
            /* RC put the conditional delay only if SOF not received */
            if (sof != SOF)
            usleep_range(1000,1500);//msleep(5);
        }while(sof != SOF);
    }
    else
    {
#ifdef P61_IRQ_ENABLE
        P61_DBG_MSG(" %s Interrrupt Mode Enabled \n", __FUNCTION__);
        if (!gpio_get_value(p61_dev->irq_gpio))
        {
            if (filp->f_flags & O_NONBLOCK)
            {
                ret = -EAGAIN;
                goto fail;
            }
            while (1)
            {
                ret = 0;
                P61_DBG_MSG(" %s waiting for interrupt \n", __FUNCTION__);
                p61_dev->irq_enabled = true;
                enable_irq(p61_dev->spi->irq);
                /*If IRQ line is already high, which means IRQ was high
                just before enabling the interrupt, skip waiting for interrupt,
                as interrupt would have been disabled by then in the interrupt handler*/
                if (!gpio_get_value(p61_dev->irq_gpio)){
                    ret = wait_event_interruptible(p61_dev->read_wq,!p61_dev->irq_enabled);
                }
                p61_disable_irq(p61_dev);
                if (ret)
                {
                    P61_ERR_MSG("wait_event_interruptible() : Failed\n");
                    goto fail;
                }

                if (gpio_get_value(p61_dev->irq_gpio))
                    break;

                P61_ERR_MSG("%s: spurious interrupt detected\n", __func__);
            }
        }
#else
    P61_ERR_MSG(" %s P61_IRQ_ENABLE not Enabled \n", __FUNCTION__);
#endif
        /* read the SOF */
        sof = 0x00;
        ret = spi_read(p61_dev->spi, (void *)&sof, 1);
        if ((0 > ret) || (sof != SOF))
        {
            P61_DBG_MSG(KERN_INFO"SPI_READ returned 0x%x", sof);
            P61_ERR_MSG(KERN_ALERT "spi_read failed [SOF] 0x%x\n", ret);
            ret = -EIO;
            goto fail;
        }
    }


    total_count = 1;
    rx_buffer[0] = sof;
    /* Read the HEADR of Two bytes*/
    ret = spi_read(p61_dev->spi, (void *)&rx_buffer[1], 2);
    if (ret < 0)
    {
        P61_ERR_MSG(KERN_ALERT "spi_read fails after [PCB] \n");
        ret = -EIO;
        goto fail;
    }

    total_count += 2;
    /* Get the data length */
    count = rx_buffer[2];
    P61_DBG_MSG(KERN_INFO"Data Lenth = %d", (int)count);
    /* Read the availabe data along with one byte LRC */
    ret = spi_read(p61_dev->spi, (void *)&rx_buffer[3], (count+1));
    if (ret < 0)
    {
        P61_ERR_MSG("spi_read failed \n");
        ret = -EIO;
        goto fail;
    }
    total_count = (total_count + (count+1));
    P61_DBG_MSG(KERN_INFO"total_count = %d", total_count);

    if (copy_to_user(buf, &rx_buffer[0], total_count))
    {
        P61_ERR_MSG("%s : failed to copy to user space\n", __func__);
        ret = -EFAULT;
        goto fail;
    }
    ret = total_count;
    P61_DBG_MSG("p61_dev_read ret %d Exit\n", ret);

    mutex_unlock(&p61_dev->read_mutex);

    return ret;

    fail:
    P61_ERR_MSG("Error p61_dev_read ret %d Exit\n", ret);
    mutex_unlock(&p61_dev->read_mutex);
    return ret;
}

/**
 * \ingroup spi_driver
 * \brief It will configure the GPIOs required for soft reset, read interrupt & regulated power supply to P61.
 *
 * \param[in]       struct p61_spi_platform_data *
 * \param[in]       struct p61_dev *
 * \param[in]       struct spi_device *
 *
 * \retval 0 if ok.
 *
*/

static int p61_hw_setup(struct p61_spi_platform_data *platform_data,
       struct p61_dev *p61_dev, struct spi_device *spi)
{
    int ret = -1;

    P61_DBG_MSG("Entry : %s\n", __FUNCTION__);
#ifdef P61_IRQ_ENABLE
    ret = gpio_request(platform_data->irq_gpio, "p61 irq");
    if (ret < 0)
    {
        P61_ERR_MSG("gpio request failed gpio = 0x%x\n", platform_data->irq_gpio);
        goto fail;
    }

    ret = gpio_direction_input(platform_data->irq_gpio);
    if (ret < 0)
    {
        P61_ERR_MSG("gpio request failed gpio = 0x%x\n", platform_data->irq_gpio);
        goto fail_irq;
    }
#endif

#ifdef P61_HARD_RESET
    /* RC : platform specific settings need to be declare */
#if !DRAGON_P61
    p61_regulator = regulator_get( &spi->dev, "vaux3");
#else
    p61_regulator = regulator_get( &spi->dev, "8941_l18");
#endif
    if (IS_ERR(p61_regulator))
    {
        ret = PTR_ERR(p61_regulator);
#if !DRAGON_P61
        P61_ERR_MSG(" Error to get vaux3 (error code) = %d\n", ret);
#else
        P61_ERR_MSG(" Error to get 8941_l18 (error code) = %d\n", ret);
#endif
        return  -ENODEV;
    }
    else
    {
        P61_DBG_MSG("successfully got regulator\n");
    }

    ret = regulator_set_voltage(p61_regulator, 1800000, 1800000);
    if (ret != 0)
    {
        P61_ERR_MSG("Error setting the regulator voltage %d\n", ret);
        regulator_put(p61_regulator);
        return ret;
    }
    else
    {
        ret=regulator_enable(p61_regulator);
        P61_DBG_MSG("successfully set regulator voltage\n");

    }
#endif
/*
    ret = gpio_request( platform_data->rst_gpio, "p61 reset");
    if (ret < 0)
    {
        P61_ERR_MSG("gpio reset request failed = 0x%x\n", platform_data->rst_gpio);
        goto fail_gpio;
    }

    ret = gpio_direction_output(platform_data->rst_gpio,0);
    if (ret < 0)
    {
        P61_ERR_MSG("gpio rst request failed gpio = 0x%x\n", platform_data->rst_gpio);
        goto fail_gpio;
    }
*/
     ret = gpio_request( platform_data->hard_rst_gpio, "p61 hard reset");
     
     printk("----P61 p61_hw_setup hard_rst_gpio=%d",platform_data->hard_rst_gpio);
    if (ret < 0)     
     {                
         P61_ERR_MSG("gpio reset request failed = 0x%x\n", platform_data->hard_rst_gpio); 
         goto fail_gpio;
     }
/* 
     ret = gpio_direction_output(platform_data->hard_rst_gpio,1);
     if (ret < 0)
     {
         P61_ERR_MSG("gpio rst request failed gpio = 0x%x\n", platform_data->hard_rst_gpio); 
         goto fail_gpio;
     }
*/


    ret = 0;
    P61_DBG_MSG("Exit : %s\n", __FUNCTION__);
    return ret;


    fail_gpio:
    //gpio_free(platform_data->rst_gpio);

#ifdef P61_IRQ_ENABLE
    fail_irq:
    gpio_free(platform_data->irq_gpio);
    fail:
    P61_ERR_MSG("p61_hw_setup failed\n");
#endif
    return ret;
}

/**
 * \ingroup spi_driver
 * \brief Set the P61 device specific context for future use.
 *
 * \param[in]       struct spi_device *
 * \param[in]       void *
 *
 * \retval void
 *
*/

static inline void p61_set_data(struct spi_device *spi, void *data)
{
    dev_set_drvdata(&spi->dev, data);
}

/**
 * \ingroup spi_driver
 * \brief Get the P61 device specific context.
 *
 * \param[in]       const struct spi_device *
 *
 * \retval Device Parameters
 *
*/

static inline void *p61_get_data(const struct spi_device *spi)
{
    return dev_get_drvdata(&spi->dev);
}

/* possible fops on the p61 device */
static const struct file_operations p61_dev_fops = {
        .owner = THIS_MODULE,
        .read = p61_dev_read,
        .write = p61_dev_write,
        .open = p61_dev_open,
        .unlocked_ioctl = p61_dev_ioctl,
};
#if DRAGON_P61
static int p61_parse_dt(struct device *dev,
    struct p61_spi_platform_data *data)
{
    struct device_node *np = dev->of_node;
    int errorno = 0;

        data->irq_gpio = of_get_named_gpio(np, "qcom,p61-irq", 0);
        if ((!gpio_is_valid(data->irq_gpio)))
                return -EINVAL;
/*
        data->rst_gpio = of_get_named_gpio(np, "qcom,p61-rst", 0);
        if ((!gpio_is_valid(data->rst_gpio)))
                 return -EINVAL;
*/
        data->hard_rst_gpio = of_get_named_gpio(np, "qcom,p61-hard-rst", 0);
        if ((!gpio_is_valid(data->hard_rst_gpio)))
                return -EINVAL;   

    pr_info("%s: %d,hard_rst_gpio= %d,%d\n", __func__,
        data->irq_gpio,data->hard_rst_gpio, errorno);

    return errorno;
}
#endif

/**
 * \ingroup spi_driver
 * \brief To probe for P61 SPI interface. If found initialize the SPI clock, bit rate & SPI mode.
          It will create the dev entry (P61) for user space.
 *
 * \param[in]       struct spi_device *
 *
 * \retval 0 if ok.
 *
*/

static int p61_probe(struct spi_device *spi)
{
    int ret = -1;
    struct p61_spi_platform_data *platform_data = NULL;
    struct p61_spi_platform_data platform_data1;
    struct p61_dev *p61_dev = NULL;
#ifdef P61_IRQ_ENABLE
    unsigned int irq_flags;
#endif

    printk("-----ese p61_probe run!\n");
    P61_DBG_MSG("%s chip select : %d , bus number = %d \n",
            __FUNCTION__, spi->chip_select, spi->master->bus_num);
#if !DRAGON_P61
    platform_data = spi->dev.platform_data;
    if (platform_data == NULL)
    {
        /* RC : rename the platformdata1 name */
        /* TBD: This is only for Panda as we are passing NULL for platform data */
        P61_ERR_MSG("%s : p61 probe fail\n", __func__);
        platform_data1.irq_gpio = P61_IRQ;
        //platform_data1.rst_gpio = P61_RST;
        platform_data = &platform_data1;
        P61_ERR_MSG("%s : p61 probe fail1\n", __func__);
        //return  -ENODEV;
    }
#else
    ret = p61_parse_dt(&spi->dev, &platform_data1);
    if (ret) {
        pr_err("%s - Failed to parse DT\n", __func__);
        goto err_exit;
    }
    platform_data = &platform_data1;
#endif
    p61_dev = kzalloc(sizeof(*p61_dev), GFP_KERNEL);
    if (p61_dev == NULL)
    {
        P61_ERR_MSG("failed to allocate memory for module data\n");
        ret = -ENOMEM;
        goto err_exit;
    }
    ret = p61_hw_setup (platform_data, p61_dev, spi);
    if (ret < 0)
    {
        P61_ERR_MSG("Failed to p61_enable_P61_IRQ_ENABLE\n");
        goto err_exit0;
    }

    spi->bits_per_word = 8;
    spi->mode = SPI_MODE_0;
    spi->max_speed_hz = P61_SPI_CLOCK;
    //spi->chip_select = SPI_NO_CS;
    ret = spi_setup(spi);
    if (ret < 0)
    {
        P61_ERR_MSG("failed to do spi_setup()\n");
        goto err_exit0;
    }

    p61_dev -> spi = spi;
    p61_dev -> p61_device.minor = MISC_DYNAMIC_MINOR;
    p61_dev -> p61_device.name = "p61";
    p61_dev -> p61_device.fops = &p61_dev_fops;
    p61_dev -> p61_device.parent = &spi->dev;
    p61_dev->irq_gpio = platform_data->irq_gpio;
    //p61_dev->rst_gpio  = platform_data->rst_gpio;
    p61_dev->hard_rst_gpio = platform_data->hard_rst_gpio;

    dev_set_drvdata(&spi->dev, p61_dev);

    /* init mutex and queues */
    init_waitqueue_head(&p61_dev->read_wq);
    mutex_init(&p61_dev->read_mutex);
    mutex_init(&p61_dev->write_mutex);


#ifdef P61_IRQ_ENABLE
    spin_lock_init(&p61_dev->irq_enabled_lock);
#endif

    ret = misc_register(&p61_dev->p61_device);
    if (ret < 0)
    {
        P61_ERR_MSG("misc_register failed! %d\n", ret);
        goto err_exit0;
    }

#ifdef P61_IRQ_ENABLE
    p61_dev->spi->irq = gpio_to_irq(platform_data->irq_gpio);

    if ( p61_dev->spi->irq < 0)
    {
        P61_ERR_MSG("gpio_to_irq request failed gpio = 0x%x\n", platform_data->irq_gpio);
        goto err_exit1;
    }
    /* request irq.  the irq is set whenever the chip has data available
         * for reading.  it is cleared when all data has been read.
         */
    p61_dev->irq_enabled = true;
    irq_flags = IRQF_TRIGGER_RISING | IRQF_ONESHOT;

    ret = request_irq(p61_dev->spi->irq, p61_dev_irq_handler,
                          irq_flags, p61_dev -> p61_device.name, p61_dev);
    if (ret)
    {
        P61_ERR_MSG("request_irq failed\n");
        goto err_exit1;
    }
    p61_disable_irq(p61_dev);

#endif

    p61_dev-> enable_poll_mode = 0; /* Default IRQ read mode */
    P61_DBG_MSG("Exit : %s\n", __FUNCTION__);
    return ret;
    err_exit1:
    misc_deregister(&p61_dev->p61_device);
    err_exit0:
    mutex_destroy(&p61_dev->read_mutex);
    mutex_destroy(&p61_dev->write_mutex);
    if(p61_dev != NULL)
        kfree(p61_dev);
    err_exit:
    P61_DBG_MSG("ERROR: Exit : %s ret %d\n", __FUNCTION__, ret);
    return ret;
}

/**
 * \ingroup spi_driver
 * \brief Will get called when the device is removed to release the resources.
 *
 * \param[in]       struct spi_device
 *
 * \retval 0 if ok.
 *
*/

static int p61_remove(struct spi_device *spi)
{
    struct p61_dev *p61_dev = p61_get_data(spi);
    P61_DBG_MSG("Entry : %s\n", __FUNCTION__);

#ifdef P61_HARD_RESET
    if (p61_regulator != NULL)
    {
        regulator_disable(p61_regulator);
        regulator_put(p61_regulator);
    }
    else
    {
        P61_ERR_MSG("ERROR %s p61_regulator not enabled \n", __FUNCTION__);
    }
#endif
    //gpio_free(p61_dev->rst_gpio);


#ifdef P61_IRQ_ENABLE
    free_irq(p61_dev->spi->irq, p61_dev);
    gpio_free(p61_dev->irq_gpio);
#endif

    mutex_destroy(&p61_dev->read_mutex);
    misc_deregister(&p61_dev->p61_device);

    if(p61_dev != NULL)
        kfree(p61_dev);
    P61_DBG_MSG("Exit : %s\n", __FUNCTION__);
    return 0;
}
#if DRAGON_P61
static struct of_device_id p61_dt_match[] = {
    {
        .compatible = "nxp,p61",
    },
    {}
};
#endif
static struct spi_driver p61_driver = {
        .driver = {
                .name = "p61",
                .bus = &spi_bus_type,
                .owner = THIS_MODULE,
#if DRAGON_P61
                .of_match_table = p61_dt_match,
#endif
        },
        .probe =  p61_probe,
        .remove = p61_remove,
};

/**
 * \ingroup spi_driver
 * \brief Module init interface
 *
 * \param[in]       void
 *
 * \retval handle
 *
*/

static int __init p61_dev_init(void)
{
    debug_level = P61_FULL_DEBUG;

    P61_DBG_MSG("Entry : %s\n", __FUNCTION__);

    return spi_register_driver(&p61_driver);

    P61_DBG_MSG("Exit : %s\n", __FUNCTION__);
}
module_init( p61_dev_init);

/**
 * \ingroup spi_driver
 * \brief Module exit interface
 *
 * \param[in]       void
 *
 * \retval void
 *
*/

static void __exit p61_dev_exit(void)
{
    P61_DBG_MSG("Entry : %s\n", __FUNCTION__);

    spi_unregister_driver(&p61_driver);
    P61_DBG_MSG("Exit : %s\n", __FUNCTION__);
}
module_exit( p61_dev_exit);

MODULE_AUTHOR("BHUPENDRA PAWAR");
MODULE_DESCRIPTION("NXP P61 SPI driver");
MODULE_LICENSE("GPL");

/** @} */
