#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/device.h>
#include <linux/timer.h>
#include <linux/err.h>
#include <linux/kobject.h>
#include <soc/qcom/socinfo.h>
#include <soc/qcom/boot_stats.h>
#include <asm-generic/bug.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/gpio.h>
#include <linux/of.h>

#include <asm/system_misc.h>

#define MAX_HWINFO_SIZE 100
#include <smartisan/hwinfo.h>
typedef struct{
    char *hwinfo_name;
    char hwinfo_buf[MAX_HWINFO_SIZE];
	int  init_flag;
}hwinfo_t;

#define KEYWORD(_name) \
	[_name] = {.hwinfo_name = __stringify(_name), \
		   .hwinfo_buf = {0}, \
		   .init_flag = 0,},

static hwinfo_t hwinfo[HWINFO_MAX] =
{
#include <smartisan/hwinfo.h>
};
#undef KEYWORD

typedef struct mid_match {
	int index;
	const char *name;
}mid_match_t;


/**************************************
			 gpio35   gpio104
primary			0		0
basic			0		1
advanced		1		0
special			1		1

			 gpio129  gpio122  gpio43
DVT1			0		0		0
DVT2			0		0		1
PVT 			0		1		0
MP  			0		1		1
unknown			1		0		0
unknown			1		0		1
unknown      	1		1		0
unknown     	1		1		1
***************************************/

#define PRODUCT_VERSION_0  35     //gpio 35
#define PRODUCT_VERSION_1  104    //gpio 104
#define HW_VERSION_0       129    //gpio 129
#define HW_VERSION_1       122    //gpio 122
#define HW_VERSION_2       43     //gpio 43
#define GPIO_VALUE_GET(v) gpiod_get_value_cansleep(gpio_to_desc(v))
#define	PRODUCT_VERSION_ID  ((GPIO_VALUE_GET(PRODUCT_VERSION_0) << 1) | (GPIO_VALUE_GET(PRODUCT_VERSION_1)))
#define	HW_VERSION_ID  ((GPIO_VALUE_GET(HW_VERSION_0) << 2) | (GPIO_VALUE_GET(HW_VERSION_1) << 1) | (GPIO_VALUE_GET(HW_VERSION_2)))
int nfc_support_value = -1;
int ufs2_support_value = -1;


typedef struct product_version {
    int index;
    const char *product_version;
} product_version_t;

typedef struct hw_version {
    int index;
    const char *hw_version;
} hw_version_t;


static product_version_t product_version_table[] = {
    { .index = 0x0,  .product_version = "000"	},
    { .index = 0x1,  .product_version = "001"	},
    { .index = 0x2,  .product_version = "002"	},
    { .index = 0x3,  .product_version = "003"	},
};

static hw_version_t hw_version_table[] = {
    { .index = 0x0,  .hw_version = "DVT1"	},
    { .index = 0x1,  .hw_version = "DVT2"	},
    { .index = 0x2,  .hw_version = "PVT"	},
    { .index = 0x3,  .hw_version = "MP"	},
    { .index = 0x4,  .hw_version = "unknown"	},
    { .index = 0x5,  .hw_version = "unknown"	},
    { .index = 0x6,  .hw_version = "unknown"	},
    { .index = 0x7,  .hw_version = "unknown"	},
};

#if USE_EMMC
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
#endif

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

static const char *foreach_lpddr_table(int index)
{
	int i = 0;

	for(; i<sizeof(lpddr_table)/sizeof(mid_match_t); i++) {
		if (index == lpddr_table[i].index)
			return lpddr_table[i].name;
	}

	return NULL;
}
#if USE_EMMC
static const char *foreach_emmc_table(int index)
{
	int i = 0;

	for(; i<sizeof(emmc_table)/sizeof(mid_match_t); i++) {
		if (index == emmc_table[i].index)
			return emmc_table[i].name;
	}

	return NULL;
}
#endif
static int hwinfo_read_file(char *file_name,char buf[],int buf_size)
{
	struct file *fp;
    mm_segment_t fs;
    loff_t pos = 0;
    ssize_t len = 0;

    if(file_name == NULL || buf == NULL)
    	return -1;

    fp =filp_open(file_name,O_RDONLY, 0);
    if(IS_ERR(fp)){
//        printk(KERN_CRIT "file not found\n");
        return -1;
    }

    fs =get_fs();
    set_fs(KERNEL_DS);
    len = vfs_read(fp,buf, buf_size, &pos);
//    printk(KERN_INFO "buf= %s,size = %ld \n", buf, len);
    filp_close(fp,NULL);
    set_fs(fs);

    return 0;
}

static int get_lcd_type(void)
{
    if(hwinfo[LCD_MFR].init_flag == 1 || hwinfo[TP_MFR].init_flag == 1)
	return 0;

    hwinfo[LCD_MFR].init_flag = 1;
    hwinfo[TP_MFR].init_flag = 1;
    memset(hwinfo[LCD_MFR].hwinfo_buf, 0, MAX_HWINFO_SIZE);

    memcpy(hwinfo[LCD_MFR].hwinfo_buf, "synaptics td4762", strlen("synaptics td4762"));

    return 0;
}

#define BATTARY_RESISTANCE_FILE "/sys/class/power_supply/bms/resistance_id"
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
	if(ret !=0)
	{
		printk(KERN_CRIT "get_battary_mfr failed.");
		return -1;
	}
//	printk(KERN_INFO "Battary %s\n", buf);
	sscanf(buf,"%d", &resistance_value);

	strcpy(hwinfo[BATTARY_MFR].hwinfo_buf, (resistance_value >= 85000)? "JIADE": "ATL");

	return 0;
}

extern char *fingerprint_id;
static void get_fingerprint_id(void)
{
    if(fingerprint_id != NULL)
        strncpy(hwinfo[FP_MFR].hwinfo_buf, fingerprint_id,
                ((strlen(fingerprint_id) >= sizeof(hwinfo[FP_MFR].hwinfo_buf)? sizeof(hwinfo[FP_MFR].hwinfo_buf):strlen(fingerprint_id))));
}


typedef struct hw_info {
    int index;
    char *file_name;
} hw_info_t;

hw_info_t hw_info_arrary[] =
{
    { .index = ufs_capacity      , .file_name = "/sys/block/sda/size" },
    { .index = ufs_manufacturer  , .file_name = "/sys/block/sda/device/vendor" },
    { .index = ufs_version       , .file_name = "/sys/block/sda/device/rev" },
    { .index = ufs1_capacity     , .file_name = "/sys/block/sua/size" },
    { .index = ufs1_manufacturer , .file_name = "/sys/block/sua/device/vendor" },
    { .index = ufs1_version      , .file_name = "/sys/block/sua/device/rev" },
};

static void get_ufs_info(void)
{
	char buf[30] = {0};
    int ret = 0;
	unsigned long long  ufs_size = 0;
	char *ptr = NULL;
    int i = 0;

	if(hwinfo[ufs_capacity].init_flag == 1)
		return;

    for(i = 0; i < sizeof(hw_info_arrary)/sizeof(hw_info_t); i++)
    {
    	memset(buf, 0, sizeof(buf));
        ret = hwinfo_read_file(hw_info_arrary[i].file_name, buf, sizeof(buf));
        if(ret != 0)
        {
		//printk(KERN_CRIT "hwinfo:no found %s", UFS_SIZE_FILE);
            continue;
        }

        switch(hw_info_arrary[i].index)
        {
            case ufs_capacity:
            case ufs1_capacity:
                sscanf(buf,"%llu", &ufs_size);
                sprintf(hwinfo[hw_info_arrary[i].index].hwinfo_buf, "%lluGB", ufs_size>>21);
                break;
            default:
	            for(ptr=buf; (ptr-buf)<sizeof(buf) && *ptr!='\n'; ptr++);
	            if(*ptr == '\n')
		            *ptr = '\0';
            //	printk(KERN_INFO "\n manufacturer: %s\n", buf);
                sprintf(hwinfo[hw_info_arrary[i].index].hwinfo_buf, "%s", buf);
                break;
        }
    }
	hwinfo[ufs_capacity].init_flag = 1;

    return;
}

//Don't need emmc info
#if USE_EMMC
#define EMMC_MAX_NUM     1
#define EMMC_SIZE_FILE   "/sys/block/mmcblkX/size"
#define EMMC_MANFID_FILE "/sys/block/mmcblkX/device/manfid"

static void get_emmc_info(void)
{
	int i = 0;
	char buf[30] = {0};
    int ret = 0;
	char file_name[35] = {0};
	unsigned long long  emmc_size = 0;
	const char *emmc_mid_name;

	if(hwinfo[emmc_capacity].init_flag == 1 || hwinfo[emmc_manufacturer].init_flag == 1)
		return;

	hwinfo[emmc_capacity].init_flag = 1;
	hwinfo[emmc_manufacturer].init_flag = 1;

	memset(hwinfo[emmc_capacity].hwinfo_buf, 0, MAX_HWINFO_SIZE);
	memset(hwinfo[emmc_manufacturer].hwinfo_buf, 0, MAX_HWINFO_SIZE);
	for(i = 0; i < EMMC_MAX_NUM; i++)
	{
	  /*read emmc emmc_capacity*/
	  memset(file_name, 0, sizeof(file_name));
	  strcpy(file_name, EMMC_SIZE_FILE);
	  file_name[strstr(file_name, "X")-file_name] = i + '0';

//	  printk(KERN_INFO "EMMC%d: file_name: %s\n", i, file_name);
	  ret = hwinfo_read_file(file_name, buf, sizeof(buf));
      if(ret != 0)
      {
          printk(KERN_CRIT "hwinfo:no found %s", file_name);
          return;
      }
//	  printk(KERN_INFO "hwinfo:EMMC%d: size: %s\n", i, buf);

	  sscanf(buf,"%llu", &emmc_size);
	  sprintf(hwinfo[emmc_capacity].hwinfo_buf + strlen(hwinfo[emmc_capacity].hwinfo_buf),
				"%lluGB", emmc_size>>21);

	  /*read emmc manufacturer*/
	  memset(file_name, 0, sizeof(file_name));
	  strcpy(file_name, EMMC_MANFID_FILE);
	  file_name[strstr(file_name, "X")-file_name] = i + '0';

//	  printk(KERN_INFO "EMMC%d: file_name: %s\n", i, file_name);
	  ret = hwinfo_read_file(file_name, buf, sizeof(buf));
      if(ret != 0)
      {
          printk(KERN_CRIT "hwinfo:no found %s", file_name);
          return;
      }
//	  printk(KERN_INFO "\n hwinfo:EMMC%d: manufacturer: %s\n", i, buf);

	  emmc_mid_name = foreach_emmc_table((int) simple_strtol(buf, NULL, 16));
      WARN((emmc_mid_name==NULL), "cannot recognize emmc mid\n");
	  if (emmc_mid_name==NULL)
		  emmc_mid_name = "Unknown";

	  sprintf(hwinfo[emmc_manufacturer].hwinfo_buf + strlen(hwinfo[emmc_manufacturer].hwinfo_buf),
				"%s", emmc_mid_name);
	}

	return;
}
#endif

static ssize_t hwinfo_show(struct kobject *kobj, struct kobj_attribute *attr, char * buf)
{
    int i = 0;
//    printk(KERN_INFO "hwinfo sys node %s \n", attr->attr.name);

    for(; i < HWINFO_MAX && strcmp(hwinfo[i].hwinfo_name, attr->attr.name)&&++i;);

    switch(i)
    {
        case BATTARY_MFR:
            get_battary_mfr();
            break;
        case LCD_MFR:
        case TP_MFR:
            get_lcd_type();
            i = LCD_MFR;
            break;
		case ufs_capacity:
		case ufs_manufacturer:
        case ufs_version:
        case ufs1_capacity:
        case ufs1_manufacturer:
        case ufs1_version:
			get_ufs_info();
			break;
		default:
            break;
    }
    return sprintf(buf, "%s=%s \n", attr->attr.name, ((i>=HWINFO_MAX || hwinfo[i].hwinfo_buf[0]=='\0')?"unknown":hwinfo[i].hwinfo_buf));
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

	switch((get_boot_reason() & 0xFF))
	{
		case 0x10:
			pon_reason_info = "usb charger";
			break;
		case 0x01:
			pon_reason_info = "soft reboot";
			break;
		case 0x11:
			pon_reason_info = "usb + reboot";
			break;
		case 0x80:
			pon_reason_info = "power key";
			break;
		case 0x81:
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

static int get_version_id(void)
{
    int product_version_id = PRODUCT_VERSION_ID;
	int hw_version_id = HW_VERSION_ID;

//	printk(KERN_INFO "get_version_id  product_version_id=%d hw_version_id=%d\n", product_version_id, hw_version_id);

	nfc_support_value = 1;     		//trident support nfc
	sprintf(hwinfo[nfc_support].hwinfo_buf,"%d", nfc_support_value);

    if( product_version_id < 0x03 )
        ufs2_support_value = 0;
    else
        ufs2_support_value = 1;

    return sprintf(hwinfo[version_id].hwinfo_buf, "%s:%s:0x%x", product_version_table[product_version_id].product_version,
            hw_version_table[hw_version_id].hw_version, product_version_id << 4 | hw_version_id );
}

int get_ufs2_support(void)
{
	if ( ufs2_support_value == -1 )
		get_version_id();
 
    return ufs2_support_value;
}
EXPORT_SYMBOL(get_ufs2_support);

int get_nfc_support(void)
{
	if ( nfc_support_value == -1 )
		get_version_id();

    return nfc_support_value;
}
EXPORT_SYMBOL(get_nfc_support);

int get_hw_version_id(void)
{
	return HW_VERSION_ID & 0x7;
}
EXPORT_SYMBOL(get_hw_version_id);

static int set_emmc_sn(char *src)
{
	if(src == NULL)
		return 0;
	sprintf(hwinfo[emmc_sn].hwinfo_buf, "%s", src);
	return 1;
}
__setup("androidboot.serialno=", set_emmc_sn);

int smartisan_hwinfo_register(enum HWINFO_E e_hwinfo,char *hwinfo_name)
{
	if((e_hwinfo >= HWINFO_MAX) || (hwinfo_name == NULL))
		return -1;
	strncpy(hwinfo[e_hwinfo].hwinfo_buf, hwinfo_name, \
	 	(strlen(hwinfo_name)>=20? 19:strlen(hwinfo_name)));
	return 0;
}
EXPORT_SYMBOL(smartisan_hwinfo_register);

static int __init hwinfo_init(void)
{
	struct kobject *k_hwinfo = NULL;
    const char *lpddr_mid_name = NULL;
	uint32_t lpddr_vender_id = 0;

    if ( (k_hwinfo = kobject_create_and_add("hwinfo", NULL)) == NULL ) {
		printk(KERN_CRIT "%s:hwinfo sys node create error \n", __func__);
	}

	if( sysfs_create_group(k_hwinfo, &attr_group) ) {
		printk(KERN_CRIT "%s:sysfs_create_group failed\n", __func__);
	}

	lpddr_vender_id = get_lpddr_vendor_id(); 
	lpddr_mid_name = foreach_lpddr_table(lpddr_vender_id);
    WARN((lpddr_mid_name==NULL), "hwinfo:cannot recognize lpddr");
    if (lpddr_mid_name==NULL)
        lpddr_mid_name = "Unknown";

	sprintf(hwinfo[lpddr_manufacturer].hwinfo_buf,"%s", lpddr_mid_name);
	/*cpu_type*/
	sprintf(hwinfo[CPU_TYPE].hwinfo_buf,"%s", "sdm845");

	get_version_id();

	get_secure_boot_version();

	get_pon_reason();

    get_fingerprint_id();
    return 0;
}

static void __exit hwinfo_exit(void)
{
	return ;
}

late_initcall_sync(hwinfo_init);
module_exit(hwinfo_exit);
MODULE_AUTHOR("bsp-system");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Product Hardward Info Exposure");
