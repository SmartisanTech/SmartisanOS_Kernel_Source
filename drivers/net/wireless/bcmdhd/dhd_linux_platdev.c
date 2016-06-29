/*
 * Linux platform device for DHD WLAN adapter
 *
 * $Copyright Open Broadcom Corporation$
 *
 * $Id: dhd_linux_platdev.c 401742 2013-05-13 15:03:21Z $
 */
#include <typedefs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <bcmutils.h>
#include <linux_osl.h>
#include <dhd_dbg.h>
#include <dngl_stats.h>
#include <dhd.h>
#include <dhd_bus.h>
#include <dhd_linux.h>
#include <wl_android.h>
#if defined(CONFIG_WIFI_CONTROL_FUNC)
#include <linux/wlan_plat.h>
#endif
#ifdef CONFIG_DTS
#include<linux/regulator/consumer.h>
#include<linux/of_gpio.h>
#include<linux/msm_pcie.h>
#include<soc/qcom/socinfo.h>
#endif /* CONFIG_DTS */

#if !defined(CONFIG_WIFI_CONTROL_FUNC)
struct wifi_platform_data {
	int (*set_power)(int val);
	int (*set_reset)(int val);
	int (*set_carddetect)(int val);
	void *(*mem_prealloc)(int section, unsigned long size);
	int (*get_mac_addr)(unsigned char *buf);
	void *(*get_country_code)(char *ccode);
};
#endif /* CONFIG_WIFI_CONTROL_FUNC */

#define WIFI_PLAT_NAME		"bcmdhd_wlan"
#define WIFI_PLAT_NAME2		"bcm4329_wlan"
#define WIFI_PLAT_EXT		"bcmdhd_wifi_platform"

#ifdef CONFIG_DHD_USE_STATIC_BUF
static int wlan_mem_init = 0;

//#define STATIC_BUF_MAX_NUM	16
#define STATIC_BUF_MAX_NUM	20
#define STATIC_BUF_SIZE	(PAGE_SIZE*2)

#define DHD_PREALLOC_PROT_SIZE   	(512)
#define DHD_PREALLOC_WIPHY_ESCAN0_SIZE	(64 * 1024)
#define DHD_PREALLOC_DHD_INFO_SIZE		(24 * 1024)
#define DHD_PREALLOC_IF_FLOW_LKUP_SIZE      (40 * 1024)
#define DHD_PREALLOC_OSL_BUF_SIZE      (STATIC_BUF_MAX_NUM * STATIC_BUF_SIZE)

#define DHD_SKB_1PAGE_BUFSIZE	(PAGE_SIZE*1)
#define DHD_SKB_2PAGE_BUFSIZE	(PAGE_SIZE*2)
#define DHD_SKB_4PAGE_BUFSIZE	(PAGE_SIZE*4)

#define DHD_SKB_1PAGE_BUF_NUM	0
#define DHD_SKB_2PAGE_BUF_NUM	64
#define DHD_SKB_4PAGE_BUF_NUM	0

#define WLAN_SKB_1_2PAGE_BUF_NUM	((DHD_SKB_1PAGE_BUF_NUM) + \
		(DHD_SKB_2PAGE_BUF_NUM))
#define WLAN_SKB_BUF_NUM	((WLAN_SKB_1_2PAGE_BUF_NUM) + \
		(DHD_SKB_4PAGE_BUF_NUM))

void *wlan_static_prot = NULL;
void *wlan_static_scan_buf0 = NULL;
void *wlan_static_scan_buf1 = NULL;
void *wlan_static_dhd_info_buf = NULL;
void *wlan_static_if_flow_lkup = NULL;
void *wlan_static_osl_buf = NULL;

static struct sk_buff *wlan_static_skb[WLAN_SKB_BUF_NUM];

static int dhd_init_wlan_mem(void)
{
	int i;
	int j;

	for (i = 0; i < DHD_SKB_1PAGE_BUF_NUM; i++) {
		wlan_static_skb[i] = dev_alloc_skb(DHD_SKB_1PAGE_BUFSIZE);
		if (!wlan_static_skb[i]) {
			goto err_skb_alloc;
		}
	}

	for (i = DHD_SKB_1PAGE_BUF_NUM; i < WLAN_SKB_1_2PAGE_BUF_NUM; i++) {
		wlan_static_skb[i] = dev_alloc_skb(DHD_SKB_2PAGE_BUFSIZE);
		if (!wlan_static_skb[i]) {
			goto err_skb_alloc;
		}
	}

#if !defined(CONFIG_BCMDHD_PCIE)
	wlan_static_skb[i] = dev_alloc_skb(DHD_SKB_4PAGE_BUFSIZE);
	if (!wlan_static_skb[i]) {
		goto err_skb_alloc;
	}
#endif /* !CONFIG_BCMDHD_PCIE */

	wlan_static_prot = kmalloc(DHD_PREALLOC_PROT_SIZE, GFP_KERNEL);
	if (!wlan_static_prot) {
		pr_err("Failed to alloc wlan_static_prot\n");
		goto err_mem_alloc;
	}

	wlan_static_osl_buf = kmalloc(DHD_PREALLOC_OSL_BUF_SIZE, GFP_KERNEL);
	if (!wlan_static_osl_buf) {
		pr_err("Failed to alloc wlan_static_osl_buf\n");
		goto err_mem_alloc;
	}

	wlan_static_scan_buf0 = kmalloc(DHD_PREALLOC_WIPHY_ESCAN0_SIZE, GFP_KERNEL);
	if (!wlan_static_scan_buf0) {
		pr_err("Failed to alloc wlan_static_scan_buf0\n");
		goto err_mem_alloc;
	}

	wlan_static_dhd_info_buf = kmalloc(DHD_PREALLOC_DHD_INFO_SIZE, GFP_KERNEL);
	if (!wlan_static_dhd_info_buf) {
		pr_err("Failed to alloc wlan_static_dhd_info_buf\n");
		goto err_mem_alloc;
	}
#ifdef CONFIG_BCMDHD_PCIE
	wlan_static_if_flow_lkup = kmalloc(DHD_PREALLOC_IF_FLOW_LKUP_SIZE, GFP_KERNEL);
	if (!wlan_static_if_flow_lkup) {
		pr_err("Failed to alloc wlan_static_if_flow_lkup\n");
		goto err_mem_alloc;
	}
#endif /* CONFIG_BCMDHD_PCIE */

	return 0;

err_mem_alloc:

	if (wlan_static_prot)
		kfree(wlan_static_prot);

	if (wlan_static_dhd_info_buf)
		kfree(wlan_static_dhd_info_buf);

	if (wlan_static_scan_buf1)
		kfree(wlan_static_scan_buf1);

	if (wlan_static_scan_buf0)
		kfree(wlan_static_scan_buf0);

	if (wlan_static_osl_buf)
		kfree(wlan_static_osl_buf);

#ifdef CONFIG_BCMDHD_PCIE
	if (wlan_static_if_flow_lkup)
		kfree(wlan_static_if_flow_lkup);
#endif

	pr_err("Failed to mem_alloc for WLAN\n");

	i = WLAN_SKB_BUF_NUM;

err_skb_alloc:
	pr_err("Failed to skb_alloc for WLAN\n");
	for (j = 0; j < i; j++) {
		dev_kfree_skb(wlan_static_skb[j]);
	}

	return -ENOMEM;
}

static void *dhd_wlan_mem_prealloc(int section, unsigned long size)
{
	if(!wlan_mem_init)
		dhd_init_wlan_mem();
	wlan_mem_init = 1;

	if (section == DHD_PREALLOC_PROT)
		return wlan_static_prot;

	if (section == DHD_PREALLOC_SKB_BUF)
		return wlan_static_skb;

	if (section == DHD_PREALLOC_WIPHY_ESCAN0)
		return wlan_static_scan_buf0;

	if (section == DHD_PREALLOC_WIPHY_ESCAN1)
		return wlan_static_scan_buf1;

	if (section == DHD_PREALLOC_OSL_BUF) {
		if (size > DHD_PREALLOC_OSL_BUF_SIZE) {
			pr_err("request OSL_BUF(%lu) is bigger than static size(%ld).\n",
				size, DHD_PREALLOC_OSL_BUF_SIZE);
			return NULL;
		}
		return wlan_static_osl_buf;
	}

	if (section == DHD_PREALLOC_DHD_INFO) {
		if (size > DHD_PREALLOC_DHD_INFO_SIZE) {
			pr_err("request DHD_INFO size(%lu) is bigger than static size(%d).\n",
				size, DHD_PREALLOC_DHD_INFO_SIZE);
			return NULL;
		}
		return wlan_static_dhd_info_buf;
	}
	if (section == DHD_PREALLOC_IF_FLOW_LKUP)  {
		if (size > DHD_PREALLOC_IF_FLOW_LKUP_SIZE) {
			pr_err("request DHD_IF_FLOW_LKUP size(%lu) is bigger than static size(%d).\n",
				size, DHD_PREALLOC_IF_FLOW_LKUP_SIZE);
			return NULL;
		}

		return wlan_static_if_flow_lkup;
	}
	if ((section < 0) || (section > DHD_PREALLOC_MAX))
		pr_err("request section id(%d) is out of max index %d\n",
				section, DHD_PREALLOC_MAX);
		return NULL;
}
#endif /* CONFIG_DHD_USE_STATIC_BUF */

#ifdef CONFIG_DTS
int wifi_power_on = 0;
#endif /* CONFIG_DTS */

bool cfg_multichip = FALSE;
bcmdhd_wifi_platdata_t *dhd_wifi_platdata = NULL;
static int wifi_plat_dev_probe_ret = 0;
static bool is_power_on = FALSE;
#if !defined(CONFIG_DTS)
#if defined(DHD_OF_SUPPORT)
static bool dts_enabled = TRUE;
extern struct resource dhd_wlan_resources;
extern struct wifi_platform_data dhd_wlan_control;
#else
static bool dts_enabled = FALSE;
struct resource dhd_wlan_resources = {0};
struct wifi_platform_data dhd_wlan_control = {0};
#endif /* CONFIG_OF && !defined(CONFIG_ARCH_MSM) */
#endif /* !defind(CONFIG_DTS) */

static int dhd_wifi_platform_load(void);

extern void* wl_cfg80211_get_dhdp(void);

#ifdef ENABLE_4335BT_WAR
extern int bcm_bt_lock(int cookie);
extern void bcm_bt_unlock(int cookie);
static int lock_cookie_wifi = 'W' | 'i'<<8 | 'F'<<16 | 'i'<<24;	/* cookie is "WiFi" */
#endif /* ENABLE_4335BT_WAR */

wifi_adapter_info_t* dhd_wifi_platform_get_adapter(uint32 bus_type, uint32 bus_num, uint32 slot_num)
{
	int i;

	if (dhd_wifi_platdata == NULL)
		return NULL;

	for (i = 0; i < dhd_wifi_platdata->num_adapters; i++) {
		wifi_adapter_info_t *adapter = &dhd_wifi_platdata->adapters[i];
		if ((adapter->bus_type == -1 || adapter->bus_type == bus_type) &&
			(adapter->bus_num == -1 || adapter->bus_num == bus_num) &&
			(adapter->slot_num == -1 || adapter->slot_num == slot_num)) {
			DHD_TRACE(("found adapter info '%s'\n", adapter->name));
			return adapter;
		}
	}
	return NULL;
}

void* wifi_platform_prealloc(wifi_adapter_info_t *adapter, int section, unsigned long size)
{
	void *alloc_ptr = NULL;
#ifdef CONFIG_DTS
	alloc_ptr = dhd_wlan_mem_prealloc(section, size);
	if (alloc_ptr) {
		DHD_INFO(("success alloc section %d\n", section));
		if (size != 0L)
			bzero(alloc_ptr, size);
		return alloc_ptr;
	}
#else
	struct wifi_platform_data *plat_data;

	if (!adapter || !adapter->wifi_plat_data)
		return NULL;
	plat_data = adapter->wifi_plat_data;
	if (plat_data->mem_prealloc) {
		alloc_ptr = plat_data->mem_prealloc(section, size);
		if (alloc_ptr) {
			DHD_INFO(("success alloc section %d\n", section));
			if (size != 0L)
				bzero(alloc_ptr, size);
			return alloc_ptr;
		}
	}
#endif
	DHD_ERROR(("%s: failed to alloc static mem section %d\n", __FUNCTION__, section));
	return NULL;
}

void* wifi_platform_get_prealloc_func_ptr(wifi_adapter_info_t *adapter)
{
	struct wifi_platform_data *plat_data;

	if (!adapter || !adapter->wifi_plat_data)
		return NULL;
	plat_data = adapter->wifi_plat_data;
	return plat_data->mem_prealloc;
}

int wifi_platform_get_irq_number(wifi_adapter_info_t *adapter, unsigned long *irq_flags_ptr)
{
	if (adapter == NULL)
		return -1;
	if (irq_flags_ptr)
		*irq_flags_ptr = adapter->intr_flags;
	return adapter->irq_num;
}

int wifi_platform_set_power(wifi_adapter_info_t *adapter, bool on, unsigned long msec)
{
	int err = 0;
#ifdef CONFIG_DTS
	if (on) {
		DHD_INFO(("\n\nerr is %d\n\n", err));
		if ((gpio_request(wifi_power_on,"wifi_power_on")) < 0) {
			DHD_ERROR(("request fail\n"));
		} else {
			DHD_INFO(("GPIO wifi_power_on request reg_on success\n"));
			gpio_direction_output(wifi_power_on, 0);
			mdelay(10);
			gpio_direction_output(wifi_power_on, 1);
			mdelay(200);
			DHD_INFO(("wifi_power_on value is %d\n", gpio_get_value(wifi_power_on)));
			gpio_free(wifi_power_on);
		}
		is_power_on = TRUE;
	}
	else {
		if ((gpio_request(wifi_power_on,"wifi_power_on")) < 0) {
			DHD_ERROR(("request fail\n"));
		} else {
			DHD_INFO(("GPIO wifi_power_on request reg_on success\n"));
			gpio_direction_output(wifi_power_on, 0);
			DHD_INFO(("wifi_power_on value is %d\n", gpio_get_value(wifi_power_on)));
			gpio_free(wifi_power_on);
		}
		is_power_on = FALSE;
	}
	if (err < 0)
		DHD_ERROR(("%s: regulator enable/disable failed", __FUNCTION__));
#else
	struct wifi_platform_data *plat_data;

	if (!adapter || !adapter->wifi_plat_data)
		return -EINVAL;
	plat_data = adapter->wifi_plat_data;

	DHD_ERROR(("%s = %d\n", __FUNCTION__, on));
	if (plat_data->set_power) {
#ifdef ENABLE_4335BT_WAR
		if (on) {
			printk("WiFi: trying to acquire BT lock\n");
			if (bcm_bt_lock(lock_cookie_wifi) != 0)
				printk("** WiFi: timeout in acquiring bt lock**\n");
			printk("%s: btlock acquired\n", __FUNCTION__);
		}
		else {
			/* For a exceptional case, release btlock */
			bcm_bt_unlock(lock_cookie_wifi);
		}
#endif /* ENABLE_4335BT_WAR */

		err = plat_data->set_power(on);
	}

	if (msec && !err)
		OSL_SLEEP(msec);

	if (on && !err)
		is_power_on = TRUE;
	else
		is_power_on = FALSE;

#endif /* CONFIG_DTS */

	return err;
}

int wifi_platform_bus_enumerate(wifi_adapter_info_t *adapter, bool device_present)
{
	int err = 0;
	if(machine_is_msm8992())
		err = msm_pcie_enumerate(0);
	else if (machine_is_msm8994())
		err = msm_pcie_enumerate(1);
	else {
		DHD_ERROR(("%s: no soc type\n", __FUNCTION__));
		err = -EOPNOTSUPP;
	}
	return err;

}

#ifndef DHD_SET_RANDOM_MAC_VAL
#define DHD_SET_RANDOM_MAC_VAL	0xB40B44
#endif
#ifndef DHD_SET_MAC_FILE_PATH
#define DHD_SET_MAC_FILE_PATH	"/persist/wlan_mac.txt"
#endif

static char mac_mem[256];
static int vendor_oui = DHD_SET_RANDOM_MAC_VAL;
static int rand_mac = 0x0;

int wifi_platform_get_mac_addr(wifi_adapter_info_t *adapter, unsigned char *buf)
{

	void *mac_file = NULL;
	char *mac_str = NULL;

	mac_file = dhd_os_open_image(DHD_SET_MAC_FILE_PATH);
	if (mac_file == NULL) {
		if(!rand_mac) {
			SRANDOM32((uint)jiffies);
			rand_mac = RANDOM32();
		}
		buf[0] = (unsigned char)(vendor_oui >> 16) ;
		buf[1] = (unsigned char)(vendor_oui >> 8);
		buf[2] = (unsigned char)vendor_oui;
		buf[3] = (unsigned char)(rand_mac & 0x0F) | 0xF0;
		buf[4] = (unsigned char)(rand_mac >> 8);
		buf[5] = (unsigned char)(rand_mac >> 16);

		DHD_ERROR(("%s: Rand Mac: %02X:%02X:%02X:%02X:%02X:%02X\n", __FUNCTION__,
			buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]));
		return 0;
	} else {
		dhd_os_get_image_block(mac_mem, sizeof(mac_mem), mac_file);

		if (strncmp(mac_mem, "sta=", strlen("sta=")) == 0) {
			mac_str = strstr(mac_mem, "sta=") + strlen("sta=");

			buf[0] = (unsigned char)simple_strtol(mac_str+0, NULL, 16);
			buf[1] = (unsigned char)simple_strtol(mac_str+3, NULL, 16);
			buf[2] = (unsigned char)simple_strtol(mac_str+6, NULL, 16);
			buf[3] = (unsigned char)simple_strtol(mac_str+9, NULL, 16);
			buf[4] = (unsigned char)simple_strtol(mac_str+12, NULL, 16);
			buf[5] = (unsigned char)simple_strtol(mac_str+15, NULL, 16);

			DHD_ERROR(("%s: Get  Mac: %02X:%02X:%02X:%02X:%02X:%02X\n", __FUNCTION__,
				buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]));
		} else {
			if(!rand_mac) {
				SRANDOM32((uint)jiffies);
				rand_mac = RANDOM32();
			}
			buf[0] = (unsigned char)(vendor_oui >> 16) ;
			buf[1] = (unsigned char)(vendor_oui >> 8);
			buf[2] = (unsigned char)vendor_oui;
			buf[3] = (unsigned char)(rand_mac & 0x0F) | 0xF0;
			buf[4] = (unsigned char)(rand_mac >> 8);
			buf[5] = (unsigned char)(rand_mac >> 16);

			DHD_ERROR(("%s: Rand Mac: %02X:%02X:%02X:%02X:%02X:%02X\n", __FUNCTION__,
				buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]));
		}
		dhd_os_close_image(mac_file);

		return 0;		
	}
}

void *wifi_platform_get_country_code(wifi_adapter_info_t *adapter, char *ccode)
{
	/* get_country_code was added after 2.6.39 */
#if	(LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39))
	struct wifi_platform_data *plat_data;

	if (!ccode || !adapter || !adapter->wifi_plat_data)
		return NULL;
	plat_data = adapter->wifi_plat_data;

	DHD_TRACE(("%s\n", __FUNCTION__));
	if (plat_data->get_country_code) {
		return plat_data->get_country_code(ccode);
	}
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)) */

	return NULL;
}

static int wifi_plat_dev_drv_probe(struct platform_device *pdev)
{
	struct resource *resource;
	wifi_adapter_info_t *adapter;
#ifdef CONFIG_DTS
	int irq, gpio;
#endif /* CONFIG_DTS */

	/* Android style wifi platform data device ("bcmdhd_wlan" or "bcm4329_wlan")
	 * is kept for backward compatibility and supports only 1 adapter
	 */
	ASSERT(dhd_wifi_platdata != NULL);
	ASSERT(dhd_wifi_platdata->num_adapters == 1);
	adapter = &dhd_wifi_platdata->adapters[0];
	adapter->wifi_plat_data = (struct wifi_platform_data *)(pdev->dev.platform_data);

	resource = platform_get_resource_byname(pdev, IORESOURCE_IRQ, "bcmdhd_wlan_irq");
	if (resource == NULL)
		resource = platform_get_resource_byname(pdev, IORESOURCE_IRQ, "bcm4329_wlan_irq");
	if (resource) {
		adapter->irq_num = resource->start;
		adapter->intr_flags = resource->flags & IRQF_TRIGGER_MASK;
	}

#ifdef CONFIG_DTS
	wifi_power_on = of_get_named_gpio(pdev->dev.of_node, "wlpower_on", 0);
	DHD_ERROR(("%s wifi power on is %d\n", __FUNCTION__, wifi_power_on));

	/* This is to get the irq for the OOB */
	gpio = of_get_gpio(pdev->dev.of_node, 0);

	if (gpio < 0) {
		DHD_ERROR(("%s gpio information is incorrect\n", __FUNCTION__));
		return -1;
	}
	irq = gpio_to_irq(gpio);
	if (irq < 0) {
		DHD_ERROR(("%s irq information is incorrect\n", __FUNCTION__));
		return -1;
	}
	adapter->irq_num = irq;

	/* need to change the flags according to our requirement */
	adapter->intr_flags = IORESOURCE_IRQ | IORESOURCE_IRQ_HIGHLEVEL |
		IORESOURCE_IRQ_SHAREABLE;
#endif /* CONFIG_DTS */

	wifi_plat_dev_probe_ret = dhd_wifi_platform_load();
	return wifi_plat_dev_probe_ret;
}

static int wifi_plat_dev_drv_remove(struct platform_device *pdev)
{
	wifi_adapter_info_t *adapter;

	/* Android style wifi platform data device ("bcmdhd_wlan" or "bcm4329_wlan")
	 * is kept for backward compatibility and supports only 1 adapter
	 */
	ASSERT(dhd_wifi_platdata != NULL);
	ASSERT(dhd_wifi_platdata->num_adapters == 1);
	adapter = &dhd_wifi_platdata->adapters[0];
	if (is_power_on) {
#ifdef BCMPCIE
		wifi_platform_bus_enumerate(adapter, FALSE);
		OSL_SLEEP(100);
		wifi_platform_set_power(adapter, FALSE, WIFI_TURNOFF_DELAY);
#else
		wifi_platform_set_power(adapter, FALSE, WIFI_TURNOFF_DELAY);
		wifi_platform_bus_enumerate(adapter, FALSE);
#endif /* BCMPCIE */
	}

	return 0;
}

static int wifi_plat_dev_drv_suspend(struct platform_device *pdev, pm_message_t state)
{
	DHD_TRACE(("##> %s\n", __FUNCTION__));
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 39)) && defined(OOB_INTR_ONLY) && \
	defined(BCMSDIO)
	bcmsdh_oob_intr_set(0);
#endif /* (OOB_INTR_ONLY) */
	return 0;
}

static int wifi_plat_dev_drv_resume(struct platform_device *pdev)
{
	DHD_TRACE(("##> %s\n", __FUNCTION__));
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 39)) && defined(OOB_INTR_ONLY) && \
	defined(BCMSDIO)
	if (dhd_os_check_if_up(wl_cfg80211_get_dhdp()))
		bcmsdh_oob_intr_set(1);
#endif /* (OOB_INTR_ONLY) */
	return 0;
}

#ifdef CONFIG_DTS
static const struct of_device_id wifi_device_dt_match[] = {
	{ .compatible = "android,bcmdhd_wlan", },
	{},
};
#endif /* CONFIG_DTS */
static struct platform_driver wifi_platform_dev_driver = {
	.probe          = wifi_plat_dev_drv_probe,
	.remove         = wifi_plat_dev_drv_remove,
	.suspend        = wifi_plat_dev_drv_suspend,
	.resume         = wifi_plat_dev_drv_resume,
	.driver         = {
	.name   = WIFI_PLAT_NAME,
#ifdef CONFIG_DTS
	.of_match_table = wifi_device_dt_match,
#endif /* CONFIG_DTS */
	}
};

static struct platform_driver wifi_platform_dev_driver_legacy = {
	.probe          = wifi_plat_dev_drv_probe,
	.remove         = wifi_plat_dev_drv_remove,
	.suspend        = wifi_plat_dev_drv_suspend,
	.resume         = wifi_plat_dev_drv_resume,
	.driver         = {
	.name	= WIFI_PLAT_NAME2,
	}
};

static int wifi_platdev_match(struct device *dev, void *data)
{
	char *name = (char*)data;
	struct platform_device *pdev = to_platform_device(dev);

	if (strcmp(pdev->name, name) == 0) {
		DHD_ERROR(("found wifi platform device %s\n", name));
		return TRUE;
	}

	return FALSE;
}

static int wifi_ctrlfunc_register_drv(void)
{
	int err = 0;
	struct device *dev1, *dev2;
	wifi_adapter_info_t *adapter;

	dev1 = bus_find_device(&platform_bus_type, NULL, WIFI_PLAT_NAME, wifi_platdev_match);
	dev2 = bus_find_device(&platform_bus_type, NULL, WIFI_PLAT_NAME2, wifi_platdev_match);

#if !defined(CONFIG_DTS)
	if (!dts_enabled) {
		if (dev1 == NULL && dev2 == NULL) {
			DHD_ERROR(("no wifi platform data, skip\n"));
			return -ENXIO;
		}
	}
#endif /* !defined(CONFIG_DTS) */

	/* multi-chip support not enabled, build one adapter information for
	 * DHD (either SDIO, USB or PCIe)
	 */
	adapter = kzalloc(sizeof(wifi_adapter_info_t), GFP_KERNEL);
	adapter->name = "DHD generic adapter";
	adapter->bus_type = -1;
	adapter->bus_num = -1;
	adapter->slot_num = -1;
	adapter->irq_num = -1;
	is_power_on = FALSE;
	wifi_plat_dev_probe_ret = 0;
	dhd_wifi_platdata = kzalloc(sizeof(bcmdhd_wifi_platdata_t), GFP_KERNEL);
	dhd_wifi_platdata->num_adapters = 1;
	dhd_wifi_platdata->adapters = adapter;

	if (dev1) {
		err = platform_driver_register(&wifi_platform_dev_driver);
		if (err) {
			DHD_ERROR(("%s: failed to register wifi ctrl func driver\n",
				__FUNCTION__));
			return err;
		}
	}
	if (dev2) {
		err = platform_driver_register(&wifi_platform_dev_driver_legacy);
		if (err) {
			DHD_ERROR(("%s: failed to register wifi ctrl func legacy driver\n",
				__FUNCTION__));
			return err;
		}
	}

#if !defined(CONFIG_DTS)
	if (dts_enabled) {
		struct resource *resource;
		adapter->wifi_plat_data = (void *)&dhd_wlan_control;
		resource = &dhd_wlan_resources;
		adapter->irq_num = resource->start;
		adapter->intr_flags = resource->flags & IRQF_TRIGGER_MASK;
		wifi_plat_dev_probe_ret = dhd_wifi_platform_load();
	}
#endif /* !defined(CONFIG_DTS) */


#ifdef CONFIG_DTS
	wifi_plat_dev_probe_ret = platform_driver_register(&wifi_platform_dev_driver);
#endif /* CONFIG_DTS */

	/* return probe function's return value if registeration succeeded */
	return wifi_plat_dev_probe_ret;
}

void wifi_ctrlfunc_unregister_drv(void)
{

#ifdef CONFIG_DTS
	DHD_ERROR(("unregister wifi platform drivers\n"));
	platform_driver_unregister(&wifi_platform_dev_driver);
#else
	struct device *dev1, *dev2;
	dev1 = bus_find_device(&platform_bus_type, NULL, WIFI_PLAT_NAME, wifi_platdev_match);
	dev2 = bus_find_device(&platform_bus_type, NULL, WIFI_PLAT_NAME2, wifi_platdev_match);
	if (!dts_enabled)
		if (dev1 == NULL && dev2 == NULL)
			return;

	DHD_ERROR(("unregister wifi platform drivers\n"));
	if (dev1)
		platform_driver_unregister(&wifi_platform_dev_driver);
	if (dev2)
		platform_driver_unregister(&wifi_platform_dev_driver_legacy);
	if (dts_enabled) {
		wifi_adapter_info_t *adapter;
		adapter = &dhd_wifi_platdata->adapters[0];
		if (is_power_on) {
			wifi_platform_set_power(adapter, FALSE, WIFI_TURNOFF_DELAY);
			wifi_platform_bus_enumerate(adapter, FALSE);
		}
	}
#endif /* !defined(CONFIG_DTS) */

	kfree(dhd_wifi_platdata->adapters);
	dhd_wifi_platdata->adapters = NULL;
	dhd_wifi_platdata->num_adapters = 0;
	kfree(dhd_wifi_platdata);
	dhd_wifi_platdata = NULL;
}

static int bcmdhd_wifi_plat_dev_drv_probe(struct platform_device *pdev)
{
	dhd_wifi_platdata = (bcmdhd_wifi_platdata_t *)(pdev->dev.platform_data);

	return dhd_wifi_platform_load();
}

static int bcmdhd_wifi_plat_dev_drv_remove(struct platform_device *pdev)
{
	int i;
	wifi_adapter_info_t *adapter;
	ASSERT(dhd_wifi_platdata != NULL);

	/* power down all adapters */
	for (i = 0; i < dhd_wifi_platdata->num_adapters; i++) {
		adapter = &dhd_wifi_platdata->adapters[i];
		wifi_platform_set_power(adapter, FALSE, WIFI_TURNOFF_DELAY);
		wifi_platform_bus_enumerate(adapter, FALSE);
	}
	return 0;
}

static struct platform_driver dhd_wifi_platform_dev_driver = {
	.probe          = bcmdhd_wifi_plat_dev_drv_probe,
	.remove         = bcmdhd_wifi_plat_dev_drv_remove,
	.driver         = {
	.name   = WIFI_PLAT_EXT,
	}
};

int dhd_wifi_platform_register_drv(void)
{
	int err = 0;
	struct device *dev;

	/* register Broadcom wifi platform data driver if multi-chip is enabled,
	 * otherwise use Android style wifi platform data (aka wifi control function)
	 * if it exists
	 *
	 * to support multi-chip DHD, Broadcom wifi platform data device must
	 * be added in kernel early boot (e.g. board config file).
	 */
	if (cfg_multichip) {
		dev = bus_find_device(&platform_bus_type, NULL, WIFI_PLAT_EXT, wifi_platdev_match);
		if (dev == NULL) {
			DHD_ERROR(("bcmdhd wifi platform data device not found!!\n"));
			return -ENXIO;
		}
		err = platform_driver_register(&dhd_wifi_platform_dev_driver);
	} else {
		err = wifi_ctrlfunc_register_drv();

		/* no wifi ctrl func either, load bus directly and ignore this error */
		if (err) {
			if (err == -ENXIO) {
				/* wifi ctrl function does not exist */
				err = dhd_wifi_platform_load();
			} else {
				/* unregister driver due to initialization failure */
				wifi_ctrlfunc_unregister_drv();
			}
		}
	}

	return err;
}
#if (defined(BCMLXSDMMC) || defined(BCMPCIE))
extern struct semaphore dhd_registration_sem;
#endif

#ifdef BCMPCIE
static int dhd_wifi_platform_load_pcie(void)
{
	int err = 0;
	int i;
	wifi_adapter_info_t *adapter;

	BCM_REFERENCE(i);
	BCM_REFERENCE(adapter);

	if (dhd_wifi_platdata == NULL) {
		err = dhd_bus_register();
	} else {
			/* power up all adapters */
			sema_init(&dhd_registration_sem, 0);
			for (i = 0; i < dhd_wifi_platdata->num_adapters; i++) {
				bool chip_up = FALSE;
				int retry = POWERUP_MAX_RETRY;
				struct semaphore dhd_chipup_sem;

				adapter = &dhd_wifi_platdata->adapters[i];

				DHD_ERROR(("Power-up adapter '%s'\n", adapter->name));
				DHD_INFO((" - irq %d [flags %d], firmware: %s, nvram: %s\n",
					adapter->irq_num, adapter->intr_flags, adapter->fw_path,
					adapter->nv_path));
				DHD_INFO((" - bus type %d, bus num %d, slot num %d\n\n",
					adapter->bus_type, adapter->bus_num, adapter->slot_num));

				do {
					sema_init(&dhd_chipup_sem, 0);
					err = dhd_bus_reg_pcie_notify(&dhd_chipup_sem);
					if (err) {
						DHD_ERROR(("%s dhd_bus_reg_pcie_notify fail(%d)\n",
							__FUNCTION__, err));
						return err;
					}
					err = wifi_platform_set_power(adapter,
						TRUE, WIFI_TURNON_DELAY);
					if (err) {
						DHD_ERROR(("failed to power up %s,"
							" %d retry left\n",
							adapter->name, retry));
						/* WL_REG_ON state unknown, Power off forcely */
						wifi_platform_set_power(adapter,
							FALSE, WIFI_TURNOFF_DELAY);
						continue;
					} else {
						err = wifi_platform_bus_enumerate(adapter, TRUE);
						if (err) {
							DHD_ERROR(("failed to enumerate bus %s, "
								"%d retry left\n",
								adapter->name, retry));
							wifi_platform_set_power(adapter, FALSE,
								WIFI_TURNOFF_DELAY);
						}
					}
					if (down_timeout(&dhd_chipup_sem,
							msecs_to_jiffies(POWERUP_WAIT_MS)) == 0) {
						dhd_bus_unreg_pcie_notify();
						chip_up = TRUE;
						break;
					}
					DHD_ERROR(("failed to power up %s, %d retry left\n",
						adapter->name, retry));
					dhd_bus_unreg_pcie_notify();
					wifi_platform_set_power(adapter, FALSE, WIFI_TURNOFF_DELAY);
					wifi_platform_bus_enumerate(adapter, FALSE);
				} while (retry--);

				if (!chip_up) {
					DHD_ERROR(("failed to power up %s, max retry reached**\n",
						adapter->name));
					return -ENODEV;
				}
			}

		err = dhd_bus_register();

		if (err) {
			DHD_ERROR(("%s: pci_register_driver failed\n", __FUNCTION__));
			goto fail;
		}
		err = down_timeout(&dhd_registration_sem,
			msecs_to_jiffies(DHD_REGISTRATION_TIMEOUT));
		if (err) {
			DHD_ERROR(("%s: pci_register_driver timeout or error \n", __FUNCTION__));
			dhd_bus_unregister();
			goto fail;
		}
fail:
		if (err) {
			DHD_ERROR(("%s: pci_register_driver failed\n", __FUNCTION__));
				for (i = 0; i < dhd_wifi_platdata->num_adapters; i++) {
					adapter = &dhd_wifi_platdata->adapters[i];
					wifi_platform_bus_enumerate(adapter, FALSE);
					wifi_platform_set_power(adapter,
						FALSE, WIFI_TURNOFF_DELAY);
			}
		}
	}

	return err;
}
#else
static int dhd_wifi_platform_load_pcie(void)
{
	return 0;
}
#endif /* BCMPCIE  */


void dhd_wifi_platform_unregister_drv(void)
{
	if (cfg_multichip)
		platform_driver_unregister(&dhd_wifi_platform_dev_driver);
	else
		wifi_ctrlfunc_unregister_drv();
}

extern int dhd_watchdog_prio;
extern int dhd_dpc_prio;
extern uint dhd_deferred_tx;

#ifdef BCMSDIO
static int dhd_wifi_platform_load_sdio(void)
{
	int i;
	int err = 0;
	wifi_adapter_info_t *adapter;

	BCM_REFERENCE(i);
	BCM_REFERENCE(adapter);
	/* Sanity check on the module parameters
	 * - Both watchdog and DPC as tasklets are ok
	 * - If both watchdog and DPC are threads, TX must be deferred
	 */
	if (!(dhd_watchdog_prio < 0 && dhd_dpc_prio < 0) &&
		!(dhd_watchdog_prio >= 0 && dhd_dpc_prio >= 0 && dhd_deferred_tx))
		return -EINVAL;

#if defined(BCMLXSDMMC)
	if (dhd_wifi_platdata == NULL) {
		DHD_ERROR(("DHD wifi platform data is required for Android build\n"));
		return -EINVAL;
	}

	sema_init(&dhd_registration_sem, 0);
	/* power up all adapters */
	for (i = 0; i < dhd_wifi_platdata->num_adapters; i++) {
		bool chip_up = FALSE;
		int retry = POWERUP_MAX_RETRY;
		struct semaphore dhd_chipup_sem;

		adapter = &dhd_wifi_platdata->adapters[i];

		DHD_ERROR(("Power-up adapter '%s'\n", adapter->name));
		DHD_INFO((" - irq %d [flags %d], firmware: %s, nvram: %s\n",
			adapter->irq_num, adapter->intr_flags, adapter->fw_path, adapter->nv_path));
		DHD_INFO((" - bus type %d, bus num %d, slot num %d\n\n",
			adapter->bus_type, adapter->bus_num, adapter->slot_num));

		do {
			sema_init(&dhd_chipup_sem, 0);
			err = dhd_bus_reg_sdio_notify(&dhd_chipup_sem);
			if (err) {
				DHD_ERROR(("%s dhd_bus_reg_sdio_notify fail(%d)\n\n",
					__FUNCTION__, err));
				return err;
			}
			err = wifi_platform_set_power(adapter, TRUE, WIFI_TURNON_DELAY);
			if (err) {
				/* WL_REG_ON state unknown, Power off forcely */
				wifi_platform_set_power(adapter, FALSE, WIFI_TURNOFF_DELAY);
				continue;
			} else {
				wifi_platform_bus_enumerate(adapter, TRUE);
				err = 0;
			}

			if (down_timeout(&dhd_chipup_sem, msecs_to_jiffies(POWERUP_WAIT_MS)) == 0) {
				dhd_bus_unreg_sdio_notify();
				chip_up = TRUE;
				break;
			}

			DHD_ERROR(("failed to power up %s, %d retry left\n", adapter->name, retry));
			dhd_bus_unreg_sdio_notify();
			wifi_platform_set_power(adapter, FALSE, WIFI_TURNOFF_DELAY);
			wifi_platform_bus_enumerate(adapter, FALSE);
		} while (retry--);

		if (!chip_up) {
			DHD_ERROR(("failed to power up %s, max retry reached**\n", adapter->name));
			return -ENODEV;
		}

	}

	err = dhd_bus_register();

	if (err) {
		DHD_ERROR(("%s: sdio_register_driver failed\n", __FUNCTION__));
		goto fail;
	}


	/*
	 * Wait till MMC sdio_register_driver callback called and made driver attach.
	 * It's needed to make sync up exit from dhd insmod  and
	 * Kernel MMC sdio device callback registration
	 */
	err = down_timeout(&dhd_registration_sem, msecs_to_jiffies(DHD_REGISTRATION_TIMEOUT));
	if (err) {
		DHD_ERROR(("%s: sdio_register_driver timeout or error \n", __FUNCTION__));
		dhd_bus_unregister();
		goto fail;
	}

	return err;

fail:
	/* power down all adapters */
	for (i = 0; i < dhd_wifi_platdata->num_adapters; i++) {
		adapter = &dhd_wifi_platdata->adapters[i];
		wifi_platform_set_power(adapter, FALSE, WIFI_TURNOFF_DELAY);
		wifi_platform_bus_enumerate(adapter, FALSE);
	}
#else

	/* x86 bring-up PC needs no power-up operations */
	err = dhd_bus_register();

#endif 

	return err;
}
#else /* BCMSDIO */
static int dhd_wifi_platform_load_sdio(void)
{
	return 0;
}
#endif /* BCMSDIO */

static int dhd_wifi_platform_load_usb(void)
{
	return 0;
}

static int dhd_wifi_platform_load()
{
	int err = 0;

		wl_android_init();

	if ((err = dhd_wifi_platform_load_usb()))
		goto end;
	else if ((err = dhd_wifi_platform_load_sdio()))
		goto end;
	else
		err = dhd_wifi_platform_load_pcie();

end:
	if (err)
		wl_android_exit();
	else
		wl_android_post_init();

	return err;
}
