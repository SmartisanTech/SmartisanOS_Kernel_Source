#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/device.h>
#include <linux/timer.h>
#include <linux/err.h>
#include <linux/kobject.h>
#include <soc/qcom/smem.h>
#include <soc/qcom/socinfo.h>
#include <soc/qcom/boot_stats.h>
#include <asm-generic/bug.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/gpio.h>
#include <linux/of.h>

#include <linux/fs.h>
#include <asm/system_misc.h>

typedef struct mid_match {
	int index;
	const char *name;
} mid_match_t;

typedef struct board_id {
	int index;
	const char *hw_version;
	const char *qcn_type;
	const char *model;
} boardid_match_t;
extern int  synaptics_get_device_config_id(unsigned char *str);
static boardid_match_t board_table[] = {
	{ .index = 0,  .hw_version = "PVT",  .qcn_type = "no-ca", .model = "advanced"  },
	{ .index = 1,  .hw_version = "DVT",  .qcn_type = "ca",    .model = "primary"   },
};

static mid_match_t emmc_table[] = {
	{
		.index = 17,
		.name = "Toshiba"
	},
	{
		.index = 19,
		.name = "Micron"
	},
	{
		.index = 69,
		.name = "Sandisk"
	},
	{
		.index = 21,
		.name = "Samsung"
	},
	{
		.index = 0x90,
		.name = "Hynix"
	},
	/*UFS*/
	{
		.index = 0xCE,
		.name = "Samsung"
	},
	{
		.index = 0xAD,
		.name = "Hynix"
	},
	{
		.index = 0x98,
		.name = "Toshiba"
	},
};

static mid_match_t lpddr_table[] = {
	{
		.index = 0xff,
		.name = "Micron"
	},
	{
		.index = 6,
		.name = "Hynix"
	},
	{
		.index = 1,
		.name = "Samsung"
	},
	{
		.index = 3,
		.name = "Micron"
	},
};

#define MAX_HWINFO_SIZE 64
#include <smartisan/hwinfo.h>
typedef struct {
	char *hwinfo_name;
	char hwinfo_buf[MAX_HWINFO_SIZE];
} hwinfo_t;

#define KEYWORD(_name) \
	[_name] = {.hwinfo_name = __stringify(_name), \
		   .hwinfo_buf = {0}},

static hwinfo_t hwinfo[HWINFO_MAX] =
{
#include <smartisan/hwinfo.h>
};
#undef KEYWORD

static const char *foreach_lpddr_table(int index)
{
	int i = 0;

	for (; i < sizeof(lpddr_table) / sizeof(mid_match_t); i++) {
		if (index == lpddr_table[i].index)
			return lpddr_table[i].name;
	}

	return NULL;
}

static const char *foreach_emmc_table(int index)
{
	int i = 0;

	for (; i < sizeof(emmc_table) / sizeof(mid_match_t); i++) {
		if (index == emmc_table[i].index)
			return emmc_table[i].name;
	}

	return NULL;
}
static int hwinfo_read_file(char *file_name, char buf[], int buf_size)
{
	struct file *fp;
	mm_segment_t fs;
	loff_t pos = 0;
	ssize_t len = 0;

	if (file_name == NULL || buf == NULL)
		return -1;

	fp = filp_open(file_name, O_RDONLY, 0);
	if (IS_ERR(fp)) {
		printk(KERN_CRIT "file not found/n");
		return -1;
	}

	fs = get_fs();
	set_fs(KERNEL_DS);
	len = vfs_read(fp, buf, buf_size, &pos);
	printk(KERN_INFO "buf= %s,size = %ld \n", buf, len);
	filp_close(fp, NULL);
	set_fs(fs);

	return 0;
}

#define CPU_MAX_FREQ_FILE "/sys/bus/cpu/devices/cpu0/cpufreq/cpuinfo_max_freq"
#define CPU_PRO_FREQ "2208000"
static int  get_cpu_type(void)
{
	int ret = -1;

	ret = hwinfo_read_file(CPU_MAX_FREQ_FILE, hwinfo[CPU_TYPE].hwinfo_buf, \
	                       sizeof(hwinfo[CPU_TYPE].hwinfo_buf));
	if (ret != 0)
	{
		sprintf(hwinfo[CPU_TYPE].hwinfo_buf, "%s", "Unknow");
		printk(KERN_ERR "get cpu type failed.\n");
		return -1;
	}
	sprintf(hwinfo[CPU_TYPE].hwinfo_buf, "%s", \
	        (strncmp(hwinfo[CPU_TYPE].hwinfo_buf, CPU_PRO_FREQ, strlen(CPU_PRO_FREQ)) ? "MSM8953" : "MSM8953Pro"));
	return 0;
}

#define LCD_INFO_FILE "/sys/class/graphics/fb0/msm_fb_panel_info"
static int get_lcd_type(void)
{
	char buf[200] = {0};
	int  ret = 0;
	char *p1 =  NULL, *p2 = NULL;

	ret = hwinfo_read_file(LCD_INFO_FILE, buf, sizeof(buf));
	if (ret != 0)
	{
		printk(KERN_CRIT "get lcd_type read file failed.\n");
		return -1;
	}
	p1 = strstr(buf, "panel_name=");
	if (p1 == NULL)
	{
		printk(KERN_CRIT "no found panel_name.\n");
		return -1;
	}
	p2 = strstr(p1, " ");
	if (p2 == NULL)
	{
		printk(KERN_CRIT "get lcd panel_name failed.\n");
		return -1;
	}

	memcpy(hwinfo[LCD_MFR].hwinfo_buf, p1 + strlen("panel_name="), abs(p2 - p1) - strlen("panel_name"));

	return 0;
}
static int get_TP_info(void)
{
	char buf[25] = {0};
	unsigned char buf2[4]={0};
	int  ret = 0;
	memset(hwinfo[TP_MFR].hwinfo_buf,0,MAX_HWINFO_SIZE);
	 ret=synaptics_get_device_config_id(buf2);
	if (ret != 0)
	{
		printk(KERN_CRIT "get TP info read file failed.\n");
		sprintf(buf,"unknow");
		memcpy(hwinfo[TP_MFR].hwinfo_buf,buf , strlen(buf));
		return -1;
	}
	sprintf(buf,"synaptics FW:%02x",buf2[3]);
	memcpy(hwinfo[TP_MFR].hwinfo_buf,buf , strlen(buf));

	return 0;
}
#define BATTARY_RESISTANCE_FILE "/sys/class/power_supply/battery/resistance_id"
/*
 * 10000 +- 15% ALT
 *100000 +- 15% SCUD
 */
static int get_battary_mfr(void)
{
	char buf[20] = {0};
	int ret = 0;
	int resistance_value = 0;

	ret = hwinfo_read_file(BATTARY_RESISTANCE_FILE, buf, sizeof(buf));
	if (ret != 0)
	{
		printk(KERN_CRIT "get_battary_mfr failed.");
		return -1;
	}
	printk(KERN_INFO "Battary %s\n", buf);
	sscanf(buf, "%d", &resistance_value);

	strcpy(hwinfo[BATTARY_MFR].hwinfo_buf, (resistance_value >= 85000) ? "SCUD" : "ATL");

	return 0;
}

#define TYPEC_VENDOR_FILE "/sys/class/dual_role_usb/otg_default/cc_vendor"
static ssize_t get_typec_vendor(void)
{
	char buf[16] = {};
	int ret = 0;

	ret = hwinfo_read_file(TYPEC_VENDOR_FILE, buf, sizeof(buf));
	if (ret != 0) {
		printk(KERN_CRIT "get_typec_vendor failed.");
		return -1;
	}
	printk(KERN_INFO "Typec vendor: %s\n", buf);
	if (buf[strlen(buf) - 1] == '\n')
		buf[strlen(buf) - 1] = '\0';

	strcpy(hwinfo[TYPEC_MFR].hwinfo_buf, buf);

	return 0;
}

#define SPEAKER_MFR_FILE "/proc/asound/speaker_id"
/*
 *none
 *aoyin
 *yucheng
 */
static int get_speaker_mfr(void)
{
	char buf[20] = {0};
	int ret = 20;

	ret = hwinfo_read_file(SPEAKER_MFR_FILE, buf, sizeof(buf));
	if (ret != 0)
	{
		printk(KERN_CRIT "get_speaker_mfr failed.");
		return -1;
	}
	printk(KERN_INFO "speaker %s\n", buf);
	if (buf[strlen(buf) - 1] == '\n')
		buf[strlen(buf) - 1] = '\0';

	strcpy(hwinfo[SPEAKER_MFR].hwinfo_buf, buf);
	return 0;
}
//extern char *fingerprint_id;
#define FINGERPRINT_VENDOR_FILE "/data/data/fingerprint"
static int get_fingerprint_id(void)
{
/*
	if (fingerprint_id != NULL)
		strncpy(hwinfo[FP_MFR].hwinfo_buf, fingerprint_id,
		        ((strlen(fingerprint_id) >= sizeof(hwinfo[FP_MFR].hwinfo_buf) ?
		          sizeof(hwinfo[FP_MFR].hwinfo_buf) : strlen(fingerprint_id))));
*/

	char buf[20] = {0};
	int ret = 20;

	ret = hwinfo_read_file(FINGERPRINT_VENDOR_FILE, buf, sizeof(buf));
	if (ret != 0)
	{
		printk(KERN_CRIT "get_fingerprint_mfr failed.");
		return -1;
	}
	printk(KERN_INFO "fingerprint %s\n", buf);
	if (buf[strlen(buf) - 1] == '\n')
		buf[strlen(buf) - 1] = '\0';

	strcpy(hwinfo[FP_MFR].hwinfo_buf, buf);
	return 0;

}
extern char front_cam_name[64];
extern char back_cam_name[64];
extern char backaux_cam_name[64];

static void get_front_camera_id(void)
{
	if (front_cam_name != NULL)
		strncpy(hwinfo[FRONT_CAM_MFR].hwinfo_buf, front_cam_name,
		        ((strlen(front_cam_name) >= sizeof(hwinfo[FRONT_CAM_MFR].hwinfo_buf) ?
		          sizeof(hwinfo[FRONT_CAM_MFR].hwinfo_buf) : strlen(front_cam_name))));
}
static void get_back_camera_id(void)
{
	if (back_cam_name != NULL)
		strncpy(hwinfo[BACK_CAM_MFR].hwinfo_buf, back_cam_name,
		        ((strlen(back_cam_name) >= sizeof(hwinfo[BACK_CAM_MFR].hwinfo_buf) ?
		          sizeof(hwinfo[BACK_CAM_MFR].hwinfo_buf) : strlen(back_cam_name))));
}
static void get_backaux_camera_id(void)
{
	if (backaux_cam_name != NULL)
		strncpy(hwinfo[BACKAUX_CAM_MFR].hwinfo_buf, backaux_cam_name,
		        ((strlen(backaux_cam_name) >= sizeof(hwinfo[BACKAUX_CAM_MFR].hwinfo_buf) ?
		          sizeof(hwinfo[BACKAUX_CAM_MFR].hwinfo_buf) : strlen(backaux_cam_name))));
}

static ssize_t hwinfo_show(struct kobject *kobj, struct kobj_attribute *attr, char * buf)
{
	int i = 0;
	printk(KERN_INFO "hwinfo sys node %s \n", attr->attr.name);

	for (; i < HWINFO_MAX && strcmp(hwinfo[i].hwinfo_name, attr->attr.name) && ++i;);

	switch (i)
	{
	case CPU_TYPE:
		get_cpu_type();
		break;
	case SPEAKER_MFR:
		get_speaker_mfr();
		break;
	case BATTARY_MFR:
		get_battary_mfr();
		break;
	case version_id:
	case qcn_type:
		break;
	case LCD_MFR:
		get_lcd_type();
		//i = LCD_MFR;
		break;
	case TP_MFR:
		get_TP_info();
		break;
	case TYPEC_MFR:
		get_typec_vendor();
		break;
	case FRONT_CAM_MFR:
		get_front_camera_id();
		break;
	case BACK_CAM_MFR:
		get_back_camera_id();
		break;
	case BACKAUX_CAM_MFR:
		get_backaux_camera_id();
		break;
	case FP_MFR:
		get_fingerprint_id();
		break;
	default:
		break;
	}
	return sprintf(buf, "%s=%s \n",  attr->attr.name, ((i >= HWINFO_MAX || hwinfo[i].hwinfo_buf[0] == '\0') ? "unknow" : hwinfo[i].hwinfo_buf));
}

static ssize_t hwinfo_store(struct kobject *kobj, struct kobj_attribute *attr, const char * buf, size_t n)
{
	return n;
}
#define KEYWORD(_name) \
    static struct kobj_attribute hwinfo##_name##_attr = {   \
                .attr   = {                             \
                        .name = __stringify(_name),     \
                        .mode = 0444,                   \
                },                                      \
            .show   = hwinfo_show,                 \
            .store  = hwinfo_store,                \
        };

#include <smartisan/hwinfo.h>
#undef KEYWORD

#define KEYWORD(_name)\
    [_name] = &hwinfo##_name##_attr.attr,

static struct attribute * g[] = {
#include <smartisan/hwinfo.h>
	NULL
};
#undef KEYWORD

static struct attribute_group attr_group = {
	.attrs = g,
};

static int get_pon_reason(void)
{
	char *pon_reason_info = NULL;

	switch ((get_boot_reason() & 0xFF))
	{
	case 0x20:
		pon_reason_info = "usb charger";
		break;
	case 0x21:
		pon_reason_info = "soft reboot";
		break;
	case 0xa0:
		pon_reason_info = "power key";
		break;
	case 0xa1:
		pon_reason_info = "hard reset";
		break;
	default:
		pon_reason_info = "unknow";
		break;
	}

	return sprintf(hwinfo[pon_reason].hwinfo_buf, "%s", pon_reason_info);
}

static int get_secure_boot_version(void)
{
	char *is_secureboot = NULL;
	if (get_secure_boot_value())
		is_secureboot = "SE";
	else
		is_secureboot = "NSE";

	return sprintf(hwinfo[secboot_version].hwinfo_buf, "%s", is_secureboot);
}

extern unsigned int platform_board_id;
static int set_version_id(void)
{
	int id = platform_board_id;
	return sprintf(hwinfo[version_id].hwinfo_buf, "%03d", board_table[id].index);
}

static int set_qcn_type(void)
{
	int id = platform_board_id;
	return sprintf(hwinfo[qcn_type].hwinfo_buf, "%s", board_table[id].qcn_type);
}

static int set_emmc_sn(char *src)
{
	if (src == NULL)
		return 0;
	sprintf(hwinfo[emmc_sn].hwinfo_buf, "%s", src);
	return 1;
}
__setup("androidboot.serialno=", set_emmc_sn);

char pMeminfo[8];
static int set_memory_info(char *src)
{
	if (src == NULL)
		return 0;
	sprintf(pMeminfo, "%s", src);
	return 1;
}
__setup("memory_info=", set_memory_info);

int on_atoi(char* v)
{
    int Rint = 0;

    if(v == NULL)
        return 0;

    if(*v == ' ')
        v++;
    while(*v >= '0' && *v <= '9')
    {
        Rint = Rint*10 + (*v -'0');
        v++;
    }
    return Rint;
}

int smartisan_hwinfo_register(enum HWINFO_E e_hwinfo, char *hwinfo_name)
{
	if ((e_hwinfo >= HWINFO_MAX) || (hwinfo_name == NULL))
		return -1;
	strncpy(hwinfo[e_hwinfo].hwinfo_buf, hwinfo_name, \
	        (strlen(hwinfo_name) >= 20 ? 19 : strlen(hwinfo_name)));
	return 0;
}
EXPORT_SYMBOL(smartisan_hwinfo_register);

/*Android:Settings->About phone->CPU  register function to distinguish the CPU model*/
static char *msm_read_hardware_id(void)
{
	static char msm_soc_str[256] = "Qualcomm Technologies, Inc ";
	static bool string_generated;
	int ret = 0;

	if (string_generated)
		return msm_soc_str;

	ret = get_cpu_type();
	if (ret != 0)
		goto err_path;

	ret = strlcat(msm_soc_str, hwinfo[CPU_TYPE].hwinfo_buf,
	              sizeof(msm_soc_str));
	if (ret > sizeof(msm_soc_str))
		goto err_path;

	string_generated = true;
	return msm_soc_str;
err_path:
	printk(KERN_CRIT "UNKNOWN SOC TYPE, Using defaults.\n");
	return "Qualcomm Technologies, Inc MSM8953";
}

#define BYTE(_x) (_x<<0x03)
static int __init hwinfo_init(void)
{
	struct kobject *k_hwinfo = NULL;
	unsigned int  hwinfo_value = 0;
	//unsigned int *ptr_hv;
	unsigned char emmc_mid, emmc_cap, lpddr_mid;
	const char *emmc_mid_name, *lpddr_mid_name;

	if ( (k_hwinfo = kobject_create_and_add("hwinfo", NULL)) == NULL ) {
		printk(KERN_ERR "%s:hwinfo sys node create error \n", __func__);
	}

	if ( sysfs_create_group(k_hwinfo, &attr_group) ) {
		printk(KERN_ERR "%s: sysfs_create_group failed\n", __func__);
	}
#if 0
	ptr_hv = (unsigned int *)smem_get_entry(SMEM_ID_VENDOR2, &len, \
	                                        0, SMEM_ANY_HOST_FLAG);

	if (ptr_hv == NULL) {
		printk(KERN_ERR "%s: smem_get_entry error \n", __func__);
		WARN((ptr_hv == NULL), "hwinfo_init, smem_get_entry SMEM_ID_VENDOR2 failed");
		return -EFAULT;
	}

	hwinfo_value = *(unsigned int *)ptr_hv;
#endif
        hwinfo_value = on_atoi(pMeminfo);
	lpddr_mid = hwinfo_value >> BYTE(0) & 0xFF;
	emmc_cap = hwinfo_value >> BYTE(1) & 0xFF;
	emmc_mid = hwinfo_value >> BYTE(2) & 0xFF;

	printk(KERN_INFO "%s:hwinfo_value=0x%08x, lpddr_mid=%#x emmc_cap=%#x emmc_mid=%#x\n", \
	       __func__, hwinfo_value, lpddr_mid, emmc_cap, emmc_mid);

	lpddr_mid_name = foreach_lpddr_table(lpddr_mid);
	WARN((lpddr_mid_name == NULL), "cannot recognize lpddr mid=0x%x", lpddr_mid);
	if (lpddr_mid_name == NULL)
		lpddr_mid_name = "Unknown";

	strncpy(hwinfo[lpddr_manufacturer].hwinfo_buf, lpddr_mid_name, strlen(lpddr_mid_name));

	emmc_mid_name = foreach_emmc_table(emmc_mid);
	WARN((emmc_mid_name == NULL), "cannot recognize emmc mid=0x%x", emmc_mid);
	if (emmc_mid_name == NULL)
		emmc_mid_name = "Unknown";

	strncpy(hwinfo[emmc_manufacturer].hwinfo_buf, emmc_mid_name, strlen(emmc_mid_name));
	sprintf(hwinfo[emmc_capacity].hwinfo_buf, "%dGb", emmc_cap);

	set_qcn_type();

	set_version_id();

	get_pon_reason();

	get_secure_boot_version();

	arch_read_hardware_id = msm_read_hardware_id;
	return 0;
}

static void __exit hwinfo_exit(void)
{
	return ;
}

late_initcall_sync(hwinfo_init);
module_exit(hwinfo_exit);
MODULE_AUTHOR("lvfeng@smartisan.com");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Product Hardward Info Exposure");
