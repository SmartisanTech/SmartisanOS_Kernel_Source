#ifndef __BF_SPI_TEE_H_
#define __BF_SPI_TEE_H_


#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/wait.h>

#define BF_DEV_NAME "blfp"
#define BF_DEV_MAJOR 255	/* assigned */
#define BF_CLASS_NAME "blfp"

/*for power on*/
#define NEED_OPT_POWER_ON
/* for netlink use */
#define NEED_NETLINK_OPT
/*for poll opt*/
//#define NEED_POLL_OPT
/*for kernel log*/
//#define BLESTECH_LOG

//add navigation function //
#define BF_SUPPORT_NAV_EVENT


#ifdef BLESTECH_LOG
#define BF_LOG(fmt,arg...)          do{printk("<blestech_fp>[%s:%d]"fmt" ",__func__, __LINE__, ##arg);}while(0)
#else
#define BF_LOG(fmt,arg...)
#endif


/* for netlink use */
#define MAX_NL_MSG_LEN 16
#define NETLINK_BF  29

struct bf_key_map {
    unsigned int type;
    unsigned int code;
};


typedef enum {
    BF_NETLINK_CMD_BASE = 100,

    BF_NETLINK_CMD_TEST  = BF_NETLINK_CMD_BASE+1,
    BF_NETLINK_CMD_IRQ = BF_NETLINK_CMD_BASE+2,
    BF_NETLINK_CMD_SCREEN_OFF = BF_NETLINK_CMD_BASE+3,
    BF_NETLINK_CMD_SCREEN_ON = BF_NETLINK_CMD_BASE+4
} fingerprint_socket_cmd_t;

struct bf_device {
    dev_t devno;
    struct cdev cdev;
    struct device *device;
    struct class *class;
    int device_count;
    struct platform_device *spi;
    struct list_head device_entry;
    u32 reset_gpio;
    u32 irq_gpio;
    u32 irq_num;
    u8 irq_count;
    u8 sig_count;
    s32 report_key;
    u8 need_report;
    u32 power_gpio;
#ifdef CONFIG_HAS_EARLYSUSPEND
    struct early_suspend early_suspend;
#else
    struct notifier_block fb_notify;
#endif
#ifdef NEED_NETLINK_OPT
    /* for netlink use */
    struct sock *netlink_socket;
#endif

#ifdef NEED_POLL_OPT
    //wait queue
    wait_queue_head_t wq_irq_return;
    u8 irq_signal;
#endif
    struct wake_lock ttw_wl;
};


#endif //__BF_SPI_TEE_H_
