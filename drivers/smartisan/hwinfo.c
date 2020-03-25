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
#include <linux/cpufreq.h>

#include <asm/system_misc.h>
extern void fts_tp_version_get(char *buf, int buf_size);

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


#define FACTORY_INFO    1

#ifdef FACTORY_INFO
#define  FACTORY_FILE "/dev/block/by-name/factory"

typedef struct {
    int type;
    int start;
    int end;
    char buf[32];
}factory_info;

static factory_info factory_data[] = {
    //{
    //    .type = housing_color,        //Phone's color config
    //    .start = 32 + 17,
    //    .end = 80,
    //    .buf = {0}
    //},
    {
        .type = flash_light,            //flash light config
        .start = 246,
        .end = 250,
        .buf = {0}
    }
};

static void get_factory_info(int flag)
{
    struct file *fp;
    mm_segment_t fs;
    loff_t pos = 0;
    int buf_size;
    int len;
    int i = 0;

    printk("%s(): enter!\n", __func__);

    for(i = 0; i < sizeof(factory_data)/sizeof(factory_info); i++)
    {
        if(flag == factory_data[i].type)
        {
            fp =filp_open( FACTORY_FILE,O_RDONLY, 0);
            if(IS_ERR(fp)){
                printk(KERN_CRIT "file not found\n");
                return;
            }

            fs =get_fs();
            set_fs(KERNEL_DS);

            pos = factory_data[i].start;
            buf_size = factory_data[i].end - factory_data[i].start + 1;
            printk("%s:() pos=%d, size=%d\n", __func__, pos, buf_size);
            len = vfs_read(fp, factory_data[i].buf, buf_size, &pos);
            printk("%s:() buf= %s,size = %ld \n", __func__, factory_data[i].buf, len);

            filp_close(fp,NULL);
            set_fs(fs);

            for(int j = 0; j < len ; j++)
            {
                if(factory_data[i].buf[j] != 0x00)
                    hwinfo[factory_data[i].type].hwinfo_buf[j] = factory_data[i].buf[j];
            }
        }
    }
}
#endif

#if USE_MEMINFO
extern void si_meminfo(struct sysinfo *val);
static unsigned long long get_mem_total(void)
{
    struct sysinfo meminfo;

    si_meminfo(&meminfo);

    printk("MemTotal: %u\n", meminfo.totalram << (PAGE_SHIFT -10));

    return meminfo.totalram;
}
#endif

#if USE_PRODUCT_VERSION
/**************************************
  gpio80   gpio76
  primary       0       0
  basic         0       1
  advanced      1       0
  special       1       1

  gpio126  gpio14   gpio90
  DVT1          0       0       0
  unknown       0       0       1
  unknown       0       1       0
  unknown       0       1       1
  unknown       1       0       0
  unknown       1       0       1
  unknown       1       1       0
  unknown       1       1       1
 ***************************************/

#define PRODUCT_VERSION_0   80      //gpio 80
#define PRODUCT_VERSION_1   76      //gpio 76
#define HW_VERSION_0        126     //gpio 126
#define HW_VERSION_1        14      //gpio 14
#define HW_VERSION_2        90      //gpio 90

#define GPIO_NO_PULL        0
#define GPIO_PULL_DOWN      1
#define GPIO_KEEPER         2
#define GPIO_PULL_UP        3

#define TLMM_GPIO_CFG24     0x3518000
#define TLMM_GPIO_CFG35     0x3923000
#define TLMM_GPIO_CFG37     0x3925000
#define TLMM_GPIO_CFG49     0x3531000
#define TLMM_GPIO_CFG53     0x3D35000

#define BOARD_ID0           TLMM_GPIO_CFG24
#define BOARD_ID1           TLMM_GPIO_CFG37
#define BOARD_ID2           TLMM_GPIO_CFG49
#define BOARD_ID3           TLMM_GPIO_CFG53
#define BOARD_ID4           TLMM_GPIO_CFG35

typedef struct{
	resource_size_t     addr;
	unsigned int gpio;
	int                 value;
	int                 pull_status;
} _i;

static _i board_info[] = {
	{
		.addr = BOARD_ID0,
		.gpio = 24
	},
	{
		.addr = BOARD_ID1,
		.gpio = 37
	},
	{
		.addr = BOARD_ID2,
		.gpio = 49
	},
	{
		.addr = BOARD_ID3,
		.gpio = 53
	},
	{
		.addr = BOARD_ID4,
		.gpio = 35
	}
};

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
	{ .index = 0x3,  .hw_version = "unknown"	},
	{ .index = 0x4,  .hw_version = "unknown"	},
	{ .index = 0x5,  .hw_version = "unknown"	},
	{ .index = 0x6,  .hw_version = "unknown"	},
	{ .index = 0x7,  .hw_version = "unknown"	},
};

static void detect_gpio_status(void)
{
	int ret = 0;
	void __iomem *gpio_cfg;
	u32 value;
	u32 restore;
	int i = 0;

	for (i = 0; i < sizeof(board_info)/sizeof(_i); i++) {
		gpio_cfg = ioremap(board_info[i].addr, 4);
		if (!gpio_cfg)
			printk(KERN_ERR "GPIO%d ioremap error!\n", board_info[i].gpio);
		value = readl(gpio_cfg);
		restore = value;
		value &= ~0x3;
		value |= GPIO_PULL_DOWN;
		writel_relaxed(value, gpio_cfg);
		ret = gpio_get_value(board_info[i].gpio);
		/* The gpio pull up */
		if (ret == 1) {
			board_info[i].value = ret;
			board_info[i].pull_status = GPIO_PULL_UP;
			goto restore;
		}

		value = readl(gpio_cfg);
		value &= ~0x3;
		value |= GPIO_PULL_UP;
		writel_relaxed(value, gpio_cfg);
		ret = gpio_get_value(board_info[i].gpio);
		/* The gpio pull down */
		if (ret == 0) {
			board_info[i].value = ret;
			board_info[i].pull_status = GPIO_PULL_DOWN;
			goto restore;
		}
		/* The gpio no pull */
		board_info[i].value = -1;    // Not define
		board_info[i].pull_status = GPIO_NO_PULL;

	restore:
		//printk("%s(): gpio%d() status:0x%x\n", __func__, board_info[i].gpio, ret);
		/* Restore gpio */
		writel_relaxed(restore, gpio_cfg);

		iounmap(gpio_cfg);
	}
}

int get_hw_version_id(void)
{
	unsigned char hw_version_id = 0;        //HW_VERSION_ID;

	/* Config the hw_version_id */
	detect_gpio_status();
	/* Config the hw_version_id base BOARD_ID4 */
	switch (board_info[4].pull_status) {
	case GPIO_NO_PULL:
		hw_version_id += 1;
		break;
	case GPIO_PULL_DOWN:
		hw_version_id += 0;
		break;
	case GPIO_PULL_UP:
		/* TO-DO: config the hw_version_id */
		break;
	default:
		break;
	}

	switch (board_info[3].pull_status) {
	case GPIO_NO_PULL:
		hw_version_id += 1;
		break;
	case GPIO_PULL_DOWN:
		hw_version_id += 0;
		break;
	case GPIO_PULL_UP:
		/* TO-DO: config the hw_version_id */
		break;
	default:
		break;
	}

	hw_version_id &= 0x7;
	printk(KERN_INFO "%s(): hw_version_id:%d\n", __func__, hw_version_id);

	return hw_version_id;
}
EXPORT_SYMBOL(get_hw_version_id);

#define MEM_4G      4*1024*1024
#define MEM_6G      6*1024*1024
#define MEM_8G      8*1024*1024
#define MEM_12G     12*1024*1024

#define UFS_64G     64
#define UFS_128G    128
#define UFS_256G    256

#define UFS_SIZE_FILE   "/sys/block/sda/size"

static int get_ufs_size()
{
	char buf[32] = {0};
	unsigned long long  ufs_size = 0;
	int ret = 0;

	ret = hwinfo_read_file(UFS_SIZE_FILE, buf, sizeof(buf));
	if(ret != 0)
	{
		printk(KERN_ERR "hwinfo:no found %s", UFS_SIZE_FILE);
	}else{
		sscanf(buf,"%llu", &ufs_size);
		ret = ufs_size >> 21;
		printk(KERN_INFO "%s(): ufs-size:%llu: size: %d\n", __func__, ufs_size, ret);
	}
	return ret;
}

static int get_version_id(void)
{
	int product_version_id = 0;     //PRODUCT_VERSION_ID;
	int hw_version_id = 0;          //HW_VERSION_ID;
	unsigned long long memtotal;
	int ufs_size = 0;

	/* Config the hw_version_id */
	hw_version_id = get_hw_version_id();

	/* Config the product_version_id */
	ufs_size = get_ufs_size();
	printk(KERN_INFO "UFS size:%d\n", ufs_size);

	memtotal = get_mem_total();
	memtotal = memtotal << (PAGE_SHIFT -10);

	if(((memtotal > MEM_4G) && (memtotal < MEM_6G)) && ((ufs_size > UFS_64G) && (ufs_size < UFS_128G)))
		product_version_id = 0;

	if(((memtotal > MEM_6G) && (memtotal < MEM_8G)) && ((ufs_size > UFS_64G) && (ufs_size < UFS_128G)))
		product_version_id = 1;

	if(((memtotal > MEM_6G) && (memtotal < MEM_8G)) && ((ufs_size > UFS_128G) && (ufs_size < UFS_256G)))
		product_version_id = 2;

	if(((memtotal > MEM_8G) && (memtotal < MEM_12G)) && ((ufs_size > UFS_128G) && (ufs_size < UFS_256G)))
		product_version_id = 3;

	nfc_support_value = 0;          //trident support nfc
	sprintf(hwinfo[nfc_support].hwinfo_buf,"%d", nfc_support_value);

#if USE_UFS2
	if( product_version_id < 0x03 )
		ufs2_support_value = 0;
	else
		ufs2_support_value = 1;
#endif

	return sprintf(hwinfo[version_id].hwinfo_buf, "%s:%s:0x%x", product_version_table[product_version_id].product_version,
			hw_version_table[hw_version_id].hw_version, product_version_id << 4 | hw_version_id );
}
#endif

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

static const char *foreach_emmc_table(int index)
{
	int i = 0;

	for(; i<sizeof(emmc_table)/sizeof(mid_match_t); i++) {
		if (index == emmc_table[i].index)
			return emmc_table[i].name;
	}

	return NULL;
}

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

#if USE_LCD
#define LCD_INFO_FILE "/sys/class/graphics/fb0/msm_fb_panel_info"
static int get_lcd_type(void)
{
	char buf[200] = {0};
	int  ret = 0;
	char *p1 =  NULL,*p2 = NULL;

	if(hwinfo[LCD_MFR].init_flag == 1 || hwinfo[TP_MFR].init_flag == 1)
		return 0;

	hwinfo[LCD_MFR].init_flag = 1;
#if USE_TP
	hwinfo[TP_MFR].init_flag = 1;
#endif

	memset(hwinfo[LCD_MFR].hwinfo_buf, 0, MAX_HWINFO_SIZE);
	ret = hwinfo_read_file(LCD_INFO_FILE, buf, sizeof(buf));
	if(ret != 0)
	{
		printk(KERN_CRIT "hwinfo:get lcd_type read file failed.\n");
		return -1;
	}
	p1 = strstr(buf, "panel_name=");
	if(p1 == NULL)
	{
		printk(KERN_CRIT "hwinfo:no found panel_name.\n");
		return -1;
	}
	p2 = strstr(p1, " ");
	if(p2 == NULL)
	{
		printk(KERN_CRIT "hwinfo:get lcd panel_name failed.\n");
		return -1;
	}

	memcpy(hwinfo[LCD_MFR].hwinfo_buf, p1+strlen("panel_name="), abs(p2-p1)-strlen("panel_name"));

	return 0;
}
#endif

#if USE_TP_VERSION
static int get_tp_version(void)
{
	char buf[200] = {0};
	int fw_version = 0;

	printk("%s(): enter!\n", __func__);

	hwinfo[tp_version].init_flag = 1;
	memset(hwinfo[tp_version].hwinfo_buf, 0, MAX_HWINFO_SIZE);
	fts_tp_version_get(buf, sizeof(buf));

	sscanf(buf,"%x", &fw_version);
	sprintf(hwinfo[tp_version].hwinfo_buf + strlen(hwinfo[tp_version].hwinfo_buf),
				"0x%x", fw_version);

	return 0;
}
#endif

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

	strcpy(hwinfo[BATTARY_MFR].hwinfo_buf, (resistance_value >= 85000)? "SCUD": "ATL");

	return 0;
}

#if USE_FP
extern char *fingerprint_id;
static void get_fingerprint_id(void)
{
	if(fingerprint_id != NULL)
		strncpy(hwinfo[FP_MFR].hwinfo_buf, fingerprint_id,
				((strlen(fingerprint_id) >= sizeof(hwinfo[FP_MFR].hwinfo_buf)? sizeof(hwinfo[FP_MFR].hwinfo_buf):strlen(fingerprint_id))));
}
#endif

#if USE_UFS
typedef struct hw_info {
	int index;
	char *file_name;
} hw_info_t;

hw_info_t hw_info_arrary[] =
{
	{ .index = ufs_capacity      , .file_name = "/sys/block/sda/size" },
	{ .index = ufs_manufacturer  , .file_name = "/sys/block/sda/device/vendor" },
	{ .index = ufs_version       , .file_name = "/sys/block/sda/device/rev" },
#if USE_UFS2
	{ .index = ufs1_capacity     , .file_name = "/sys/block/sua/size" },
	{ .index = ufs1_manufacturer , .file_name = "/sys/block/sua/device/vendor" },
	{ .index = ufs1_version      , .file_name = "/sys/block/sua/device/rev" },
#endif
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
			printk(KERN_CRIT "hwinfo:no found %s", UFS_SIZE_FILE);
			continue;
		}

		switch(hw_info_arrary[i].index)
		{
			case ufs_capacity:
# if USE_UFS2
			case ufs1_capacity:
#endif
				sscanf(buf,"%llu", &ufs_size);
				sprintf(hwinfo[hw_info_arrary[i].index].hwinfo_buf, "%lluGB", ufs_size>>21);
				printk("%s() UFS CAPACITY:%s\n", __func__, hwinfo[hw_info_arrary[i].index].hwinfo_buf);
				break;
			default:
				for(ptr=buf; (ptr-buf)<sizeof(buf) && *ptr!='\n'; ptr++);
				if(*ptr == '\n')
					*ptr = '\0';
				printk(KERN_INFO "\n manufacturer: %s\n", buf);
				sprintf(hwinfo[hw_info_arrary[i].index].hwinfo_buf, "%s", buf);
				break;
		}
		hwinfo[ufs_capacity].init_flag = 1;
	}

	return;
}
#if USE_UFS2
int get_ufs2_support(void)
{
	if ( ufs2_support_value == -1 )
		get_version_id();

	return ufs2_support_value;
}
EXPORT_SYMBOL(get_ufs2_support);
#endif
#endif

#if USE_CPUTYPE
extern int cpufreq_get_policy(struct cpufreq_policy *policy, unsigned int cpu);

static int get_cpu_freq(void)
{
	int ret = 0;
	struct cpufreq_policy policy;
	unsigned int cpu = 7;

	ret = cpufreq_get_policy(&policy, cpu);
	printk(KERN_ERR "cpufreq max:%d, min:%d, cur:%d\n", policy.max, policy.min, policy.cur);
	if(ret)
	{
		printk(KERN_ERR "get cpufreq error!\n");
		return ret;
	}

	return policy.max;
}

/* Set the CPU Type */
static void set_cpu_type(void)
{
	int cpufreq_max;
//	const char *machine_name;

//	machine_name = get_cpu_type();
//	if(!machine_name)
//		return;

	cpufreq_max = get_cpu_freq();

	if(cpufreq_max == 2841600)
		sprintf(hwinfo[CPU_TYPE].hwinfo_buf,"SM8150");
	if(cpufreq_max == 2956800)
		sprintf(hwinfo[CPU_TYPE].hwinfo_buf,"SM8150P");
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
#if USE_LCD
		case LCD_MFR:
#if USE_TP
		case TP_MFR:
#endif
			get_lcd_type();
			i = LCD_MFR;
			break;
#endif
#if USE_TP_VERSION
		case tp_version:
			get_tp_version();
			break;
#endif
#if USE_UFS
		case ufs_capacity:
		case ufs_manufacturer:
		case ufs_version:
#if USE_UFS2
		case ufs1_capacity:
		case ufs1_manufacturer:
		case ufs1_version:
#endif
			get_ufs_info();
			break;
#endif
#if USE_EMMC
		case emmc_manufacturer:
		case emmc_capacity:
			get_emmc_info();
			break;
#endif
		case housing_color:
			break;
		case flash_light:
#ifdef FACTORY_INFO
			get_factory_info(i);
#endif
			break;
#if USE_PRODUCT_VERSION
		case version_id:
			get_version_id();
			break;
#endif
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
		case 0x40:
			pon_reason_info = "usb charger";
			break;
		case 0x01:
			pon_reason_info = "soft reboot";
			break;
		case 0x41:
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

#if USE_NFC
int get_nfc_support(void)
{
#if USE_PRODUCT_VERSION
	if ( nfc_support_value == -1 )
		get_version_id();
#endif
	return nfc_support_value;
}
EXPORT_SYMBOL(get_nfc_support);
#endif

static int set_emmc_sn(char *src)
{
	if(src == NULL)
		return 0;
	sprintf(hwinfo[emmc_sn].hwinfo_buf, "%s", src);
	return 1;
}
__setup("androidboot.serialno=", set_emmc_sn);

static int set_qchip_id(char *src)
{
	if (src == NULL)
		return 0;
	sprintf(hwinfo[qchip_id].hwinfo_buf, "%s", src);
	return 1;
}
__setup("qchip.id=", set_qchip_id);

static int set_housing_color(char *src)
{
	if(src == NULL)
		return 0;
	sprintf(hwinfo[housing_color].hwinfo_buf, "%s", src);
	return 1;
}
__setup("housing.color=", set_housing_color);

static int set_flash_light(char *src)
{
	if(src == NULL)
		return 0;
	sprintf(hwinfo[flash_light].hwinfo_buf, "%s", src);
	return 1;
}
__setup("flash.light=", set_flash_light);

int get_flash_version(void)
{
    int flash_version = 0;
    if(0 == strncmp(hwinfo[flash_light].hwinfo_buf, "FLLBC", 5))
    {
        flash_version = 1;  //high version of mahjong for delta which has three flash
    }
    return flash_version;
}
EXPORT_SYMBOL(get_flash_version);

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
	set_cpu_type();

	get_secure_boot_version();

	get_pon_reason();

#if USE_FP
	get_fingerprint_id();
#endif

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
