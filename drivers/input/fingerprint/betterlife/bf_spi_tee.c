#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/gpio.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/regulator/consumer.h>
#include <soc/qcom/scm.h>
#include <linux/platform_device.h>
#include <linux/wakelock.h>
#include <linux/input.h>
#include <net/sock.h>
#include <linux/spi/spi.h>
#include <linux/spi/spidev.h>
#include <linux/miscdevice.h>

#if defined(CONFIG_FB)
#include <linux/notifier.h>
#include <linux/fb.h>
#endif

#ifdef CONFIG_HAS_EARLYSUSPEND
#include <linux/earlysuspend.h>
#else
#include <linux/notifier.h>
#endif

#ifdef CONFIG_OF
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/of_gpio.h>
#include <linux/of_platform.h>
#endif

#ifdef CONFIG_COMPAT
#include <linux/compat.h>
#endif

#include "bf_spi_tee.h"

#define BF_IOCTL_MAGIC_NO			0xFC

#define BF_IOCTL_INIT		            _IO(BF_IOCTL_MAGIC_NO,   0)
#define BF_IOCTL_CAPTURE_MODE	            _IOW(BF_IOCTL_MAGIC_NO,  1, uint32_t)
#define BF_IOCTL_INTERRUPT_MODE		    _IOW(BF_IOCTL_MAGIC_NO,  2, uint32_t)
#define BF_IOCTL_CONTRAST_ADJUST            _IOW(BF_IOCTL_MAGIC_NO,  3, uint32_t)
#define BF_IOCTL_POWERDOWN_MODE	            _IO (BF_IOCTL_MAGIC_NO,  4)
#define BF_IOCTL_ENABLE_INTERRUPT           _IOW(BF_IOCTL_MAGIC_NO,  8, uint32_t)
#define BF_IOCTL_DISABLE_INTERRUPT          _IOW(BF_IOCTL_MAGIC_NO,  5, uint32_t)
#define BF_IOCTL_MULTIFUNCTIONAL_KEYCODE    _IOW(BF_IOCTL_MAGIC_NO,  6, uint32_t)
#define BF_IOC_RESET                        _IO(BF_IOCTL_MAGIC_NO, 6)
#define BF_IOCTL_TEST_MODE	            _IOWR(BF_IOCTL_MAGIC_NO, 7, uint32_t)
#define BF_IOCTL_GET_ID	                    _IOWR(BF_IOCTL_MAGIC_NO, 9, uint32_t)
#define BF_IOCTL_INIT_ARGS	            _IOWR(BF_IOCTL_MAGIC_NO, 11,uint32_t)
#define BF_IOCTL_GAIN_ADJUST                _IOWR(BF_IOCTL_MAGIC_NO, 12,uint32_t)
#define BF_IOCTL_ENABLE_POWER               _IOW(BF_IOCTL_MAGIC_NO,  13,uint32_t)
#define BF_IOCTL_DISABLE_POWER              _IOW(BF_IOCTL_MAGIC_NO,  14,uint32_t)
#define BF_IOCTL_ENABLE_SPI_CLOCK           _IOW(BF_IOCTL_MAGIC_NO,  15,uint32_t)
#define BF_IOCTL_DISABLE_SPI_CLOCK          _IOW(BF_IOCTL_MAGIC_NO,  16,uint32_t)
#define BF_IOCTL_INPUT_KEY                  _IOW(BF_IOCTL_MAGIC_NO,  17,uint32_t)
#define BF_IOCTL_NAV_MODE                   _IOW(BF_IOCTL_MAGIC_NO,  18,uint32_t)
#define BF_IOCTL_INIT_REG                   _IOW(BF_IOCTL_MAGIC_NO,  19,uint32_t)
#define BF_IOCTL_IMG_AREA                   _IOW(BF_IOCTL_MAGIC_NO,  20,uint32_t)
#define BF_IOCTL_REMOVE_DEVICE              _IOW(BF_IOCTL_MAGIC_NO,  21,uint32_t)

#define BF_IOCTL_INPUT_KEY_DOWN             _IOW(BF_IOCTL_MAGIC_NO,  22,uint32_t)
#define BF_IOCTL_INPUT_KEY_UP               _IOW(BF_IOCTL_MAGIC_NO,  23,uint32_t)
#define BF_IOCTL_DISPLAY_STATUS             _IOW(BF_IOCTL_MAGIC_NO,  24,uint32_t)

typedef enum bf_key {
    BF_KEY_NONE = 0,
    BF_KEY_POWER,
    BF_KEY_CAMERA,
    BF_KEY_UP,
    BF_KEY_DOWN,
    BF_KEY_RIGHT,
    BF_KEY_LEFT,
    BF_KEY_HOME,
    BF_KEY_F10,
    BF_KEY_F11,

} bf_key_t;


static struct bf_key_map key_maps[] = {

	{ EV_KEY, KEY_HOMEPAGE },
	{ EV_KEY, KEY_MENU },
	{ EV_KEY, KEY_BACK },
	{ EV_KEY, KEY_POWER },
	{ EV_KEY, KEY_PHONE },
	{ EV_KEY, KEY_CAMERA },
	{ EV_KEY, KEY_F1 },
	{ EV_KEY, KEY_F2 },
	{ EV_KEY, KEY_F3 },
	{ EV_KEY, KEY_F4 },
	{ EV_KEY, KEY_F5 },
	{ EV_KEY, KEY_F6 },
	{ EV_KEY, KEY_F7 },
	{ EV_KEY, KEY_F8 },
	{ EV_KEY, KEY_F9 },
	{ EV_KEY, KEY_F10 },
	{ EV_KEY, KEY_F11 },
	{ EV_KEY, KEY_F12 },
#if defined(BF_SUPPORT_NAV_EVENT)
	{ EV_KEY, KEY_SEARCH },
	{ EV_KEY, KEY_APPSELECT },
	{ EV_KEY, KEY_UP },
	{ EV_KEY, KEY_DOWN },
	{ EV_KEY, KEY_LEFT },
	{ EV_KEY, KEY_RIGHT },
#endif
};


static LIST_HEAD (device_list);
static DEFINE_MUTEX (device_list_lock);

/* for netlink use */
#ifdef NEED_NETLINK_OPT
static int g_pid;
#endif
static struct bf_device *g_bf_dev=NULL;
static struct input_dev *bf_inputdev = NULL;
static uint32_t bf_key_need_report = 0;
static int bf_rm_device (struct bf_device *bf_dev);
static int bf_free_named_gpio(struct bf_device *bf_dev, u32 gpio);

#if defined(CONFIG_FB)
static struct notifier_block fb_notif;
#endif

#if defined(CONFIG_FB)
/*----------------------------------------------------------------------------*/
static int fb_notifier_callback(struct notifier_block *self,
                                unsigned long event, void *data)
{
    struct fb_event *evdata = data;
    int *blank =  evdata->data;

    BF_LOG("%s fb notifier callback event = %lu, evdata->data = %d\n",__func__, event, *blank);
    if (evdata && evdata->data){
	    if (event == FB_EVENT_BLANK ){		  
            if (*blank == FB_BLANK_UNBLANK){
                g_bf_dev->need_report = 0;
		    }
            else if (*blank == FB_BLANK_POWERDOWN){
                g_bf_dev->need_report = 1;
		    }
		}
    }	
    return 0;
}
#endif
/*----------------------------------------------------------------------------*/
static int bf_hw_power (struct bf_device *bf_dev, bool enable)
{
#ifdef NEED_OPT_POWER_ON
    if (enable) {
        gpio_set_value(bf_dev->power_gpio, 1);
    } else {
        gpio_set_value(bf_dev->power_gpio, 0);
    }
#endif
    return 0;
}

static int bf_hw_reset(struct bf_device *bf_dev)
{
    gpio_set_value(bf_dev->reset_gpio, 1);
    udelay(100);
    gpio_set_value(bf_dev->reset_gpio, 0);
    udelay(5000);
    gpio_set_value(bf_dev->reset_gpio, 1);

    return 0;
}

static void bf_enable_irq(struct bf_device *bf_dev)
{
    if (1 == bf_dev->irq_count) {
        BF_LOG("irq already enabled\n");
    } else {
        //enable_irq(bf_dev->irq_num);
        enable_irq_wake(bf_dev->irq_num);
        bf_dev->irq_count = 1;
        BF_LOG(" enable interrupt!\n");
    }
}

static void bf_disable_irq(struct bf_device *bf_dev)
{
    if (0 == bf_dev->irq_count) {
        BF_LOG(" irq already disabled\n");
    } else {
        disable_irq(bf_dev->irq_num);
        bf_dev->irq_count = 0;
        BF_LOG(" disable interrupt!\n");
    }
}


static void bf_spi_clk_enable(struct bf_device *bf_dev, u8 bonoff)
{

}


/* -------------------------------------------------------------------- */
/* fingerprint chip hardware configuration								           */
/* -------------------------------------------------------------------- */

static void bf_irq_gpio_cfg(struct bf_device *bf_dev)
{
    int error = 0;

    error = gpio_direction_input(bf_dev->irq_gpio);
    if (error) {
        BF_LOG("setup bf irq gpio for input failed!error[%d]\n", error);
        return ;
    }

    bf_dev->irq_num = gpio_to_irq(bf_dev->irq_gpio);
    BF_LOG("bf irq number[%d]\n", bf_dev->irq_num);
    if (bf_dev->irq_num <= 0) {
        BF_LOG("bf irq gpio to irq failed!\n");
        return ;
    }

    return;
}

static int bf_request_named_gpio(struct bf_device *bf_dev, const char *label, int *gpio)
{
    struct device *dev = &bf_dev->spi->dev;
    struct device_node *np = dev->of_node;
    int ret = of_get_named_gpio(np, label, 0);

    if (ret < 0) {
        BF_LOG("failed to get '%s'\n", label);
        return ret;
    }
    *gpio = ret;
    ret = devm_gpio_request(dev, *gpio, label);
    if (ret) {
        BF_LOG("failed to request gpio %d\n", *gpio);
        return ret;
    }

    BF_LOG("%s %d\n", label, *gpio);
    return ret;
}

static int bf_free_named_gpio(struct bf_device *bf_dev, u32 gpio)
{
    struct device *dev = &bf_dev->spi->dev;
    BF_LOG("%s\n", __func__);
    devm_gpio_free(dev, gpio);
    return 0;
}

int bf_get_irq_gpio(struct bf_device *bf_dev)
{
    int ret = 0;
    // get gpio_irq resource*/
    ret = bf_request_named_gpio(bf_dev, "betterlife,gpio_irq", &bf_dev->irq_gpio);
    if (ret) {
        BF_LOG("Failed to request irq GPIO. ret = %d\n", ret);
        return -1;
    }
    BF_LOG("irq %d\n", bf_dev->irq_gpio);
    return ret;
}


static int bf_get_gpio_info_from_dts (struct bf_device *bf_dev)
{
    int ret = 0;

    // get gpio_reset resourece
    ret = bf_request_named_gpio(bf_dev, "betterlife,gpio_reset", &bf_dev->reset_gpio);
    if (ret) {
        BF_LOG("Failed to request reset GPIO. ret = %d\n", ret);
        return -1;
    }
    BF_LOG("reset %d\n", bf_dev->reset_gpio);
    // get power resourece
    ret = bf_request_named_gpio(bf_dev, "betterlife,gpio_pwr", &bf_dev->power_gpio);
    if (ret) {
        BF_LOG("Failed to request power GPIO. ret = %d\n", ret);
        return -1;
    }
    BF_LOG("power %d\n", bf_dev->power_gpio);
    // set power direction output
    gpio_direction_output(bf_dev->power_gpio, 1);
    gpio_set_value(bf_dev->power_gpio, 1);
    BF_LOG("power %d\n",  gpio_get_value(bf_dev->power_gpio));  // steven


    gpio_direction_output(bf_dev->reset_gpio, 1);

    return ret;
}

/* -------------------------------------------------------------------- */
/* netlink functions                 */
/* -------------------------------------------------------------------- */
#ifdef NEED_NETLINK_OPT
void bf_send_netlink_msg(struct bf_device *bf_dev, const int command)
{
    struct nlmsghdr *nlh = NULL;
    struct sk_buff *skb = NULL;
    int ret;
    char data_buffer[2];

    BF_LOG("enter, send command %d",command);
    memset(data_buffer,0,2);
    data_buffer[0] = (char)command;
    if (NULL == bf_dev->netlink_socket) {
        BF_LOG("invalid socket");
        return;
    }

    if (0 == g_pid) {
        BF_LOG("invalid native process pid");
        return;
    }

    /*alloc data buffer for sending to native*/
    skb = alloc_skb(MAX_NL_MSG_LEN, GFP_ATOMIC);
    if (skb == NULL) {
        return;
    }

    nlh = nlmsg_put(skb, 0, 0, 0, MAX_NL_MSG_LEN, 0);
    if (!nlh) {
        BF_LOG("nlmsg_put failed");
        kfree_skb(skb);
        return;
    }

    NETLINK_CB(skb).portid = 0;
    NETLINK_CB(skb).dst_group = 0;

    *(char *)NLMSG_DATA(nlh) = command;
    *((char *)NLMSG_DATA(nlh)+1) = 0;
    ret = netlink_unicast(bf_dev->netlink_socket, skb, g_pid, MSG_DONTWAIT);
    if (ret < 0) {
        BF_LOG("send failed");
        return;
    }

    BF_LOG("send done, data length is %d",ret);
    return ;
}

static void bf_recv_netlink_msg(struct sk_buff *__skb)
{
    struct sk_buff *skb = NULL;
    struct nlmsghdr *nlh = NULL;
    //char str[128];


    skb = skb_get(__skb);
    if (skb == NULL) {
        BF_LOG("skb_get return NULL");
        return;
    }

    if (skb->len >= NLMSG_SPACE(0)) {
        nlh = nlmsg_hdr(skb);
        //memcpy(str, NLMSG_DATA(nlh), sizeof(str));
        g_pid = nlh->nlmsg_pid;
        //BF_LOG("pid: %d, msg: %s",g_pid, str);

    } else {
        BF_LOG("not enough data length");
    }

    kfree_skb(__skb);

}


static int bf_close_netlink(struct bf_device *bf_dev)
{
    if (bf_dev->netlink_socket != NULL) {
        netlink_kernel_release(bf_dev->netlink_socket);
        bf_dev->netlink_socket = NULL;
        return 0;
    }

    BF_LOG("no netlink socket yet");
    return -1;
}


static int bf_init_netlink(struct bf_device *bf_dev)
{
    struct netlink_kernel_cfg cfg;

    memset(&cfg, 0, sizeof(struct netlink_kernel_cfg));
    cfg.input = bf_recv_netlink_msg;

    bf_dev->netlink_socket = netlink_kernel_create(&init_net, NETLINK_BF, &cfg);
    if (bf_dev->netlink_socket == NULL) {
        BF_LOG("netlink create failed");
        return -1;
    }
    BF_LOG("netlink create success");
    return 0;
}
#endif	//NEED_NETLINK_OPT

static irqreturn_t bf_eint_handler (int irq, void *data)
{
    struct bf_device *bf_dev = (struct bf_device *)data;
  //  BF_LOG("++++irq_handler netlink send+++++");
    wake_lock_timeout(&bf_dev->ttw_wl, msecs_to_jiffies(2000));

#ifdef NEED_NETLINK_OPT
    bf_send_netlink_msg(bf_dev, BF_NETLINK_CMD_IRQ);
#endif

#ifdef NEED_POLL_OPT
    wake_up_interruptible(&bf_dev->wq_irq_return);
    bf_dev->irq_signal=1;
#endif
    bf_dev->sig_count++;
    //BF_LOG("-----irq_handler netlink bf_dev->sig_count=%d-----",bf_dev->sig_count);
    return IRQ_HANDLED;
}


/* -------------------------------------------------------------------- */
/* file operation function                                                                                */
/* -------------------------------------------------------------------- */
static long bf_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int error = 0;
    struct bf_device *bf_dev = NULL;
    bf_key_t bf_input_key = BF_KEY_NONE;
    unsigned int key_event = 0;

    bf_dev = (struct bf_device *)filp->private_data;

    if (_IOC_TYPE(cmd) != BF_IOCTL_MAGIC_NO) {
        BF_LOG("Not blestech fingerprint cmd.");
        return -EINVAL;

    }
    /* Check access direction once here; don't repeat below.
     * IOC_DIR is from the user perspective, while access_ok is
     * from the kernel perspective; so they look reversed.
     */ 

    if (_IOC_DIR(cmd) & _IOC_READ)
        error = !access_ok(VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd));

    if (error == 0 && _IOC_DIR(cmd) & _IOC_WRITE)
        error = !access_ok(VERIFY_READ, (void __user *)arg, _IOC_SIZE(cmd));

    if (error) {
        BF_LOG("Not blestech fingerprint cmd direction.");
        return -EINVAL;
    }

    switch (cmd) {
    case BF_IOCTL_INIT:
 
#if 1  
        BF_LOG("BF_IOCTL_INIT ");
        //register int
        bf_get_irq_gpio(bf_dev);
        bf_irq_gpio_cfg(bf_dev);
        error = request_threaded_irq (bf_dev->irq_num, NULL, bf_eint_handler, IRQ_TYPE_EDGE_RISING | IRQF_ONESHOT, BF_DEV_NAME, bf_dev);
        if (!error)
            BF_LOG("irq thread request success!\n");
        else
            BF_LOG("irq thread request failed, retval=%d\n", error);

        /* netlink interface init */
#ifdef NEED_NETLINK_OPT
        BF_LOG ("bf netlink config");
        if (bf_init_netlink(bf_dev) <0) {
            BF_LOG ("bf_netlink create failed");
        }
#endif

#ifdef NEED_POLL_OPT
        init_waitqueue_head(&bf_dev->wq_irq_return);
        bf_dev->irq_signal=0;
#endif
        bf_dev->irq_count=0;
        bf_dev->sig_count=0;
        bf_hw_power(bf_dev,1);
        bf_hw_reset(bf_dev);

        bf_enable_irq(bf_dev);
        BF_LOG("BF_IOCTL_INIT: chip init command\n");
#endif

        break;
    case BF_IOC_RESET:
        BF_LOG("BF_IOC_RESET: chip reset command\n");
        bf_hw_reset(bf_dev);
        break;

    case BF_IOCTL_ENABLE_INTERRUPT:
        BF_LOG("BF_IOCTL_ENABLE_INTERRUPT:  command\n");
        bf_enable_irq(bf_dev);
        break;

    case BF_IOCTL_DISABLE_INTERRUPT:
        BF_LOG("BF_IOCTL_DISABLE_INTERRUPT:  command\n");
        bf_disable_irq(bf_dev);
        break;

    case BF_IOCTL_ENABLE_SPI_CLOCK:
        BF_LOG("BF_IOCTL_ENABLE_SPI_CLOCK:  command\n");
        bf_spi_clk_enable(bf_dev, 1);
        break;

    case BF_IOCTL_DISABLE_SPI_CLOCK:
        BF_LOG("BF_IOCTL_DISABLE_SPI_CLOCK:  command\n");
        bf_spi_clk_enable(bf_dev, 0);
        break;

    case BF_IOCTL_ENABLE_POWER:
        BF_LOG("BF_IOCTL_ENABLE_POWER:  command\n");
        bf_hw_power(bf_dev,1);
        break;

    case BF_IOCTL_DISABLE_POWER:
        BF_LOG("BF_IOCTL_DISABLE_POWER:  command\n");
        bf_hw_power(bf_dev,0);
        break;

    case BF_IOCTL_REMOVE_DEVICE:
        BF_LOG("BF_IOCTL_REMOVE_DEVICE:  command\n");
        bf_rm_device(bf_dev);
        break;
    case BF_IOCTL_INPUT_KEY:
	bf_input_key = (bf_key_t)arg;
	BF_LOG("key:%d\n",bf_input_key);
	BF_LOG("KEY_HOMEPAGE:%d\n",KEY_HOMEPAGE);
	if (bf_input_key == BF_KEY_HOME) {
		BF_LOG("Send KEY_HOMEPAGE\n");
		key_event = KEY_HOMEPAGE;
	} else if (bf_input_key == BF_KEY_POWER) {
		key_event = KEY_POWER;
	} else if (bf_input_key == BF_KEY_CAMERA) {
		key_event = KEY_CAMERA;
	} else if (bf_input_key == BF_KEY_UP) {
		key_event = KEY_UP;
	} else if (bf_input_key == BF_KEY_DOWN) {
		key_event = KEY_DOWN;
	} else if (bf_input_key == BF_KEY_LEFT) {
		key_event = KEY_LEFT;
	} else if (bf_input_key == BF_KEY_RIGHT) {
		key_event = KEY_RIGHT;
	}
	else if (bf_input_key == BF_KEY_F11){
		BF_LOG("Send F11\n");
		key_event = KEY_F11;
	}
	else {
		BF_LOG("Send F10\n");
		key_event = KEY_F10;
	}

	input_report_key(bf_inputdev, key_event, 1);
	input_sync(bf_inputdev);
	input_report_key(bf_inputdev, key_event, 0);
	input_sync(bf_inputdev);
	break;

			
	case BF_IOCTL_INPUT_KEY_DOWN:
#ifdef FAST_VERSION
	if(g_bl229x_enbacklight && g_bf_dev->need_report == 0){
#else
	if(g_bf_dev->need_report==0){
#endif

		bf_key_need_report = 1;
		key_event = (unsigned int)arg;
		//BF_LOG("key down:%d\n",key_event);
		input_report_key(bf_inputdev, key_event, 1);
		input_sync(bf_inputdev);			
	}			
	break;

	case BF_IOCTL_INPUT_KEY_UP:
	if(bf_key_need_report == 1){

		bf_key_need_report = 0;
		key_event = (unsigned int)arg;
		//BF_LOG("key up:%d\n",key_event);
		input_report_key(bf_inputdev, key_event, 0);
		input_sync(bf_inputdev);
	}			
	break;

    default:
        BF_LOG("Supportn't this command(%x)\n",cmd);
        break;
    }

    return error;

}
#ifdef CONFIG_COMPAT
static long bf_compat_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int retval = 0;

    retval = bf_ioctl(filp, cmd, arg);

    return retval;
}
#endif

#ifdef NEED_POLL_OPT
static unsigned int bf_poll(struct file *filp, struct poll_table_struct *wait)
{
    unsigned int ret = 0;
    struct bf_device *bf_dev = NULL;


    bf_dev = (struct bf_device *)filp->private_data;

    ret |= POLLIN;
    poll_wait(filp, &bf_dev->wq_irq_return, wait);

    if (bf_dev->irq_signal) {
        BF_LOG(" get irq\n");
        ret |= POLLRDNORM;
        bf_dev->irq_signal=0;
    } else {
        BF_LOG(" no signal!.\n");
        ret = 0;
    }
    return ret;
}
#endif	//NEED_POLL_OPT
/*----------------------------------------------------------------------------*/
static int bf_open (struct inode *inode, struct file *filp)
{
    struct bf_device *bf_dev = g_bf_dev;
    int status = 0;

    filp->private_data = bf_dev;
    BF_LOG( " Success to open device.");

    return status;
}


/* -------------------------------------------------------------------- */
static ssize_t bf_write (struct file *file, const char *buff, size_t count, loff_t *ppos)
{
    return -ENOMEM;
}

/* -------------------------------------------------------------------- */
static ssize_t bf_read (struct file *filp, char  *buff, size_t count, loff_t *ppos)
{
    ssize_t status = 0;

    return status;
}

/* -------------------------------------------------------------------- */
static int bf_release (struct inode *inode, struct file *file)
{
    int status = 0 ;
    return status;
}

#if 0
static int bf_suspend(struct platform_device *pdev, pm_message_t state)
{
    BF_LOG("%s++++\n",__func__);
    BF_LOG("%s----\n",__func__);

    return 0;
}

static int bf_resume( struct platform_device *pdev)
{
    BF_LOG("%s++++\n",__func__); 
    BF_LOG("%s----\n",__func__);

    return 0;
}
#endif

static int bf_suspend (struct platform_device *pdev, pm_message_t state)
{
    //struct bl229x_data *bl229x = dev_get_drvdata(dev);
    BF_LOG("  ++\n");
    //atomic_set(&suspended, 1);
	g_bf_dev->need_report = 1;
	BF_LOG("\n");
    return 0;
}

/* -------------------------------------------------------------------- */
static int bf_resume ( struct platform_device *pdev)
{
    //struct bl229x_data *bl229x = dev_get_drvdata(dev);
    //dev_err (&bl229x->spi->dev,"[bl229x]%s\n", __func__);
    BF_LOG("  ++\n");
    //atomic_set(&suspended, 0);
    //wake_up_interruptible(&waiting_spi_prepare);
	BF_LOG("\n");
    return 0;
}
/*----------------------------------------------------------------------------*/
static const struct file_operations bf_fops = {
    .owner = THIS_MODULE,
    .open  = bf_open,
    .write = bf_write,
    .read  = bf_read,
    .release = bf_release,
    .unlocked_ioctl = bf_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = bf_compat_ioctl,
#endif
#ifdef NEED_POLL_OPT
    .poll           = bf_poll,
#endif
};

static struct miscdevice bf_misc_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = BF_DEV_NAME,
    .fops = &bf_fops,
};

static int bf_rm_device (struct bf_device *bf_dev)
{
    BF_LOG(" bf_rm_device\n");
    bf_free_named_gpio(bf_dev,bf_dev->power_gpio);
    bf_free_named_gpio(bf_dev,bf_dev->reset_gpio);
    misc_deregister(&bf_misc_device);
    return 0;
}

static int bf_create_inputdev(void)
{
	int i;

	bf_inputdev = input_allocate_device();
	if (!bf_inputdev) {
		BF_LOG("bf_inputdev create faile!\n");
		return -ENOMEM;
	}

	for (i = 0; i < ARRAY_SIZE(key_maps); i++)
		input_set_capability(bf_inputdev, key_maps[i].type, key_maps[i].code);

#if 0
	__set_bit(EV_KEY,bf_inputdev->evbit);
	__set_bit(KEY_F10,bf_inputdev->keybit);		//68
	__set_bit(KEY_F11,bf_inputdev->keybit);		//88
	__set_bit(KEY_F12,bf_inputdev->keybit);		//88
	__set_bit(KEY_CAMERA,bf_inputdev->keybit);	//212
	__set_bit(KEY_POWER,bf_inputdev->keybit);	//116
	__set_bit(KEY_PHONE,bf_inputdev->keybit);  //call 169
	__set_bit(KEY_BACK,bf_inputdev->keybit);  //call 158
	__set_bit(KEY_HOMEPAGE,bf_inputdev->keybit);  //call 172
	__set_bit(KEY_MENU,bf_inputdev->keybit);  //call 158

	__set_bit(KEY_F1,bf_inputdev->keybit);	//69
	__set_bit(KEY_F2,bf_inputdev->keybit);	//60
	__set_bit(KEY_F3,bf_inputdev->keybit);	//61
	__set_bit(KEY_F4,bf_inputdev->keybit);	//62
	__set_bit(KEY_F5,bf_inputdev->keybit);	//63
	__set_bit(KEY_F6,bf_inputdev->keybit);	//64
	__set_bit(KEY_F7,bf_inputdev->keybit);	//65
	__set_bit(KEY_F8,bf_inputdev->keybit);	//66
	__set_bit(KEY_F9,bf_inputdev->keybit);	//67

	__set_bit(KEY_UP,bf_inputdev->keybit);	//103
	__set_bit(KEY_DOWN,bf_inputdev->keybit);	//108
	__set_bit(KEY_LEFT,bf_inputdev->keybit);	//105
	__set_bit(KEY_RIGHT,bf_inputdev->keybit);	//106

#endif

	bf_inputdev->id.bustype = BUS_HOST;
	bf_inputdev->name = "betterlife-blfp";
	if (input_register_device(bf_inputdev)) {
		BF_LOG("%s, register inputdev failed\n", __func__);
		input_free_device(bf_inputdev);
		return -ENOMEM;
	}
	return 0;
}


static int bf_probe(struct platform_device *pdev)
{
    int status = 0;
    //int error = 0;

    struct bf_device *bf_dev = NULL;
    BF_LOG("%s++++\n",__func__);


    bf_dev = kzalloc(sizeof (struct bf_device), GFP_KERNEL);
    if (NULL == bf_dev) {
        BF_LOG( "kzalloc bf_dev failed.");
        status = -ENOMEM;
        goto err;
    }

    g_bf_dev=bf_dev;
    bf_dev->spi = pdev;

    wake_lock_init(&bf_dev->ttw_wl, WAKE_LOCK_SUSPEND, "blestech_ttw_wl");

    BF_LOG("BF_IOCTL_INIT ");

    bf_get_gpio_info_from_dts(bf_dev);

#if 0
//register int
bf_get_gpio_info_from_dts(bf_dev);
bf_get_irq_gpio(bf_dev);
bf_irq_gpio_cfg(bf_dev);
error = request_threaded_irq (bf_dev->irq_num, NULL, bf_eint_handler, IRQ_TYPE_EDGE_RISING | IRQF_ONESHOT, BF_DEV_NAME, bf_dev);
if (!error)
    BF_LOG("irq thread request success!\n");
else
    BF_LOG("irq thread request failed, retval=%d\n", error);

/* netlink interface init */
#ifdef NEED_NETLINK_OPT
BF_LOG ("bf netlink config");
if (bf_init_netlink(bf_dev) <0) {
    BF_LOG ("bf_netlink create failed");
}
#endif

#ifdef NEED_POLL_OPT
init_waitqueue_head(&bf_dev->wq_irq_return);
bf_dev->irq_signal=0;
#endif
bf_dev->irq_count=0;
bf_dev->sig_count=0;
bf_hw_power(bf_dev,1);
bf_hw_reset(bf_dev);
bf_enable_irq(bf_dev);
#endif

    bf_create_inputdev();

#if defined(CONFIG_FB)
    fb_notif.notifier_call = fb_notifier_callback;
    fb_register_client(&fb_notif);
#endif	

    BF_LOG("BF_IOCTL_INIT: chip init command\n");
    //BF_LOG("power %d\n",  gpio_get_value(bf_dev->power_gpio));  // steven

    status = misc_register(&bf_misc_device);
    if(status) {
        BF_LOG("bl229x_misc_device register failed\n");
        goto err;
    }

    BF_LOG("%s++++ ok \n",__func__);
err:
    return status;
}

static int bf_remove(struct platform_device *pdev)
{

    BF_LOG("%s++++\n",__func__);
#ifdef NEED_NETLINK_OPT
    bf_close_netlink(g_bf_dev);
    wake_lock_destroy(&g_bf_dev->ttw_wl);
#endif
    BF_LOG("%s----\n",__func__);
    return 0;
}

#ifdef CONFIG_OF
static struct of_device_id bf_of_match[] = {
    { .compatible = "betterlife,fingerprint" },
    {}
};
MODULE_DEVICE_TABLE(of, bf_of_match);
#endif

static struct platform_driver bf_driver = {
    .driver = {
        .name = BF_DEV_NAME,
        .owner = THIS_MODULE,
#ifdef CONFIG_OF
        .of_match_table = of_match_ptr(bf_of_match),
#endif
    },
    .probe = bf_probe,
    .remove = bf_remove,
    .suspend = bf_suspend,
    .resume = bf_resume,
};

static int __init bf_init(void)
{
    int status;

    BF_LOG("%s++++\n",__func__);

    status = platform_driver_register(&bf_driver);
    if (status < 0) {
        BF_LOG("%s, Failed to register SPI driver.\n", __func__);
    }
    BF_LOG("%s----\n",__func__);

    return status;
}
module_init(bf_init);


static void __exit bf_exit(void)
{
    BF_LOG("%s++++\n",__func__);
    platform_driver_unregister(&bf_driver);
    BF_LOG("%s----\n",__func__);
}
module_exit(bf_exit);

MODULE_AUTHOR("shizsun");
MODULE_DESCRIPTION(" Blsetech Fingerprint chip TEE driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:blestech-drivers");
