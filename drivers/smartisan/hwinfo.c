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
#include <asm-generic/bug.h>

#define GET_BIT_VAL(V, POS) ( (V & (1<<POS)) >> POS )

unsigned int get_vddcx(unsigned int fuse)
{
	unsigned int vddcx = 0;
	vddcx |= GET_BIT_VAL(fuse, 26) << 2;
	vddcx |= GET_BIT_VAL(fuse, 23) << 1;
	vddcx |= GET_BIT_VAL(fuse, 22);

	return vddcx;
}

unsigned int get_vddmx(unsigned int fuse)
{
	unsigned int vddmx = 0;
	vddmx |= GET_BIT_VAL(fuse, 28) << 1;
	vddmx |= GET_BIT_VAL(fuse, 27);

	return vddmx;
}

typedef struct mid_match {
	int index;
	const char *name;
}mid_match_t;

static mid_match_t emmc_table[] = {
	[0] = {
		.index = 17,
		.name = "Toshiba"
	},
	[1] = {
		.index = 69,
		.name = "Sandisk"
	},
	[2] = {
		.index = 21,
		.name = "Samsung"
	},
	[3] = {
		.index = 0x90,
		.name = "Hynix"
	},
};

static mid_match_t lpddr_table[] = {
	[0] = {
		.index = 0xff,
		.name = "Micron"
	},
	[1] = {
		.index = 6,
		.name = "Hynix"
	},
	[2] = {
		.index = 1,
		.name = "Samsung"
	},
	[3] = {
		.index = 3,
		.name = "Micron"
	},
};

unsigned char emmc_mid, emmc_cap, lpddr_mid;
const char *emmc_mid_name, *lpddr_mid_name, *cpu_type_name, *hardware_id_name;
unsigned int fuse_value = 0;
//unsigned int fuse_reg = 0xFC4B80B4;
unsigned int vddcx, vddmx;
char sn_buf[13];
unsigned char psn_msg[20];

static const char *foreach_lpddr_table(int index)
{
	int i = 0;

	for(; i<sizeof(lpddr_table)/sizeof(mid_match_t); i++) {
		if (index == lpddr_table[i].index)
			return lpddr_table[i].name;
	}

	return NULL;
}

static const char *foreach_emmc_table(int index)
{
	int i = 0;

	for(; i<sizeof(emmc_table)/sizeof(mid_match_t); i++) {
		if (index == emmc_table[i].index)
			return emmc_table[i].name;
	}

	return NULL;
}

#define MAJOR_NUM 4
static char* format_hw_version(uint32_t ver) {
	char *major_str[MAJOR_NUM] = {
	"EVT",
	"DVT",
	"PVT",
	"MP",
	};
	static char ver_str[20];
	uint8_t minor1, minor2, major;
	uint8_t major0;

// add for 8115 cdma
	major0 = (uint8_t)(ver >> 8 & 0xff) - 1;
	if (major0 < 10) {
		major = major0;
	} else if (major0 < 20) {
		major = major0 % 10;
	} else {
		major = major0 % 20;
	}
	minor1 = (uint8_t)(ver >> 4 & 0xf) + 1;
	minor2 = (uint8_t)(ver & 0xf);

	if (MAJOR_NUM > major) {
		sprintf(ver_str, "%s%d.%d(%05x)", major_str[major], minor1, minor2, ver);
	} else {
		sprintf(ver_str, "UNKNOW(%05x)", ver);
	}
	return ver_str;
}

static ssize_t emmc_manufacturer_show(struct kobject *kobj, struct kobj_attribute *attr, char * buf)
{

	return sprintf(buf, "emmc_manufacture=%s \n",  emmc_mid_name);
}

static ssize_t emmc_manufacturer_store(struct kobject *kobj, struct kobj_attribute *attr, const char * buf, size_t n)
{
	return n;
}

static ssize_t emmc_capacity_show(struct kobject *kobj, struct kobj_attribute *attr, char * buf)
{

	return sprintf(buf, "emmc_capacity=%dGb \n",  emmc_cap);
}

static ssize_t emmc_capacity_store(struct kobject *kobj, struct kobj_attribute *attr, const char * buf, size_t n)
{
	return n;
}

static ssize_t lpddr_manufacturer_show(struct kobject *kobj, struct kobj_attribute *attr, char * buf)
{

	return sprintf(buf, "lpddr_manufacture=%s \n",  lpddr_mid_name);
}

static ssize_t lpddr_manufacturer_store(struct kobject *kobj, struct kobj_attribute *attr, const char * buf, size_t n)
{
	return n;
}

static ssize_t cpu_type_show(struct kobject *kobj, struct kobj_attribute *attr, char * buf)
{

	return sprintf(buf, "cpu_type=%s \n",  cpu_type_name);
}

static ssize_t cpu_type_store(struct kobject *kobj, struct kobj_attribute *attr, const char * buf, size_t n)
{
	return n;
}

static ssize_t hardware_id_show(struct kobject *kobj, struct kobj_attribute *attr, char * buf)
{

	return sprintf(buf, "hardware_id=%s \n",  hardware_id_name);
}

static ssize_t hardware_id_store(struct kobject *kobj, struct kobj_attribute *attr, const char * buf, size_t n)
{
	return n;
}

static ssize_t fuse_value_show(struct kobject *kobj, struct kobj_attribute *attr, char * buf)
{

	return sprintf(buf, "fuse_value=%#x vddcx=%#x vddmx=%#x\n",  fuse_value, vddcx, vddmx);
}

static ssize_t fuse_value_store(struct kobject *kobj, struct kobj_attribute *attr, const char * buf, size_t n)
{
	return n;
}

static ssize_t emmc_sn_show(struct kobject *kobj, struct kobj_attribute *attr, char * buf)
{

	return sprintf(buf, "emmc_serialno=%s\n",  sn_buf);
}

static ssize_t emmc_sn_store(struct kobject *kobj, struct kobj_attribute *attr, const char * buf, size_t n)
{
	return n;
}

static ssize_t psn_msg_show(struct kobject *kobj, struct kobj_attribute *attr, char * buf)
{

	return sprintf(buf, "psn message=%s\n",  psn_msg);
}

static ssize_t psn_msg_store(struct kobject *kobj, struct kobj_attribute *attr, const char * buf, size_t n)
{
	return n;
}

static ssize_t platform_version_show(struct kobject *kobj, struct kobj_attribute *attr, char * buf)
{
	return snprintf(buf, PAGE_SIZE, "%s\n", format_hw_version(socinfo_get_platform_version()));
}

static ssize_t platform_version_store(struct kobject *kobj, struct kobj_attribute *attr, const char * buf, size_t n)
{
    return n;
}

#define hwinfo_attr(_name) \
        static struct kobj_attribute _name##_attr = {   \
                .attr   = {                             \
                        .name = __stringify(_name),     \
                        .mode = 0444,                   \
                },                                      \
                .show   = _name##_show,                 \
                .store  = _name##_store,                \
        }

hwinfo_attr(emmc_manufacturer);
hwinfo_attr(emmc_capacity);
hwinfo_attr(lpddr_manufacturer);
hwinfo_attr(cpu_type);
hwinfo_attr(hardware_id);
hwinfo_attr(fuse_value);
hwinfo_attr(emmc_sn);
hwinfo_attr(psn_msg);
hwinfo_attr(platform_version);

static struct attribute * g[] = {
		&emmc_manufacturer_attr.attr,
		&emmc_capacity_attr.attr,
		&lpddr_manufacturer_attr.attr,
		&cpu_type_attr.attr,
		&hardware_id_attr.attr,
		&fuse_value_attr.attr,
		&emmc_sn_attr.attr,
		&psn_msg_attr.attr,
		&platform_version_attr.attr,
		NULL,
};

static struct attribute_group attr_group = {
        .attrs = g,
};


static int set_emmc_sn(char *src)
{
	if(src == NULL)
		return 0;
	memcpy(sn_buf, src, sizeof(sn_buf));

	return 1;
}
__setup("androidboot.serialno=", set_emmc_sn);

static int set_psn_msg(char *src)
{

	if(src == NULL)
		return 0;
	memcpy(psn_msg, src, sizeof(psn_msg));

	return 1;
}
__setup("ro.psnmsg=", set_psn_msg);

#define BYTE(_x) (_x<<0x03)
static int __init hwinfo_init(void)
{
	struct kobject *hwinfo = NULL;
//	unsigned int hwinfo_value = 0;
	unsigned int len, hwinfo_value;
	unsigned int *ptr_hv;
//	unsigned int *ptr_fuse;

	if ( (hwinfo = kobject_create_and_add("hwinfo", NULL)) == NULL ) {
		printk(KERN_CRIT "hwinfo sys node create error \n");
	}

	if( sysfs_create_group(hwinfo, &attr_group) ) {
		printk(KERN_CRIT " sysfs_create_group failed\n");
	}

	ptr_hv = (unsigned int *)smem_get_entry(SMEM_ID_VENDOR2, &len, 0, SMEM_ANY_HOST_FLAG);

	if (ptr_hv == NULL) {
		printk(KERN_CRIT "%s: smem_get_entry error \n", __func__);
		WARN((ptr_hv==NULL), "hwinfo_init, smem_get_entry SMEM_ID_VENDOR2 failed");
		return -EFAULT;
	}

	hwinfo_value = *(unsigned int *)ptr_hv;
	lpddr_mid = hwinfo_value>>BYTE(0) & 0xFF;
	emmc_cap = hwinfo_value>>BYTE(1) & 0xFF;
	emmc_mid = hwinfo_value>>BYTE(2) & 0xFF;

	printk(KERN_CRIT "hwinfo_value=0x%08x, lpddr_mid=%#x emmc_cap=%#x emmc_mid=%#x\n", \
			hwinfo_value, lpddr_mid, emmc_cap, emmc_mid);

	lpddr_mid_name = foreach_lpddr_table(lpddr_mid);
	WARN((lpddr_mid_name==NULL), "cannot recognize lpddr mid");

	emmc_mid_name = foreach_emmc_table(emmc_mid);
	WARN((emmc_mid_name==NULL), "cannot recognize emmc mid");

	if(machine_is_msm8939())
		cpu_type_name = "msm8939";
	else
		cpu_type_name = "unknown";

	if (of_board_is_u1())
		hardware_id_name = "u1";
	else
		hardware_id_name = "unknown";

//	ptr_fuse = ioremap(fuse_reg, 4);
//	if( ptr_fuse == NULL) {
//		printk(KERN_CRIT "read fuse's phy address %#x error!\n", fuse_reg);
//		return -EFAULT;
//	}
//	printk(KERN_CRIT "read fuse's phy address %#x, it's value is %#x\n", fuse_reg, *ptr_fuse);
//	fuse_value = *ptr_fuse;
//	iounmap(ptr_fuse);

	vddcx = get_vddcx(fuse_value);
	vddmx = get_vddmx(fuse_value);

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
