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
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/gpio.h>
#include <linux/of.h>

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
	/*UFS*/
	[3] = {
		.index = 0xCE,
		.name = "Samsung"
	},
	[4] = {
		.index = 0xAD,
		.name = "Hynix"
	},
	[5] = {
		.index = 0x98,
		.name = "Toshiba"
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
char sn_buf[13];
char lcd_buf[10] = {0};

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
	return sprintf(buf, "emmc_capacity=%dGb\n",  emmc_cap);
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

static ssize_t hardware_id_show(struct kobject *kobj, struct kobj_attribute *attr, char * buf)
{

	return sprintf(buf, "hardware_id=%s \n",  hardware_id_name);
}

static ssize_t hardware_id_store(struct kobject *kobj, struct kobj_attribute *attr, const char * buf, size_t n)
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

static ssize_t emmc_sn_show(struct kobject *kobj, struct kobj_attribute *attr, char * buf)
{

	return sprintf(buf, "emmc_serialno=%s\n",  sn_buf);
}

static ssize_t emmc_sn_store(struct kobject *kobj, struct kobj_attribute *attr, const char * buf, size_t n)
{
	return n;
}

extern char *fingerprint_id;
static ssize_t fingerprint_manufacturer_show(struct kobject *kobj, struct kobj_attribute *attr, char * buf)
{

	return sprintf(buf, "fingerprint_manufacturer=%s\n",  fingerprint_id);
}

static ssize_t fingerprint_manufacturer_store(struct kobject *kobj, struct kobj_attribute *attr, const char * buf, size_t n)
{
	return n;
}

static ssize_t nfc_manufacturer_show(struct kobject *kobj, struct kobj_attribute *attr, char * buf)
{

	return sprintf(buf, "nfc_manufacturer=%s\n",  "NXP");
}

static ssize_t nfc_manufacturer_store(struct kobject *kobj, struct kobj_attribute *attr, const char * buf, size_t n)
{
	return n;
}

static ssize_t lcd_manufacturer_show(struct kobject *kobj, struct kobj_attribute *attr, char * buf)
{

	return sprintf(buf, "lcd_manufacturer=%s\n",  lcd_buf);
}

static ssize_t lcd_manufacturer_store(struct kobject *kobj, struct kobj_attribute *attr, const char * buf, size_t n)
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

#define hwinfo_root_attr(_name) \
        static struct kobj_attribute _name##_root_attr = {   \
                .attr   = {                             \
                        .name = __stringify(_name),     \
                        .mode = 0400,                   \
                },                                      \
                .show   = _name##_show,                 \
                .store  = _name##_store,                \
        }

hwinfo_attr(emmc_manufacturer);
hwinfo_attr(emmc_capacity);
hwinfo_attr(lpddr_manufacturer);
hwinfo_attr(hardware_id);
hwinfo_attr(cpu_type);
hwinfo_attr(emmc_sn);
hwinfo_attr(fingerprint_manufacturer);
hwinfo_attr(nfc_manufacturer);
hwinfo_root_attr(lcd_manufacturer);

static struct attribute * g[] = {
		&emmc_manufacturer_attr.attr,
		&emmc_capacity_attr.attr,
		&lpddr_manufacturer_attr.attr,
		&hardware_id_attr.attr,
		&cpu_type_attr.attr,
		&emmc_sn_attr.attr,
		&fingerprint_manufacturer_attr.attr,
		&nfc_manufacturer_attr.attr,
		&lcd_manufacturer_root_attr.attr,
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

static void set_lcd_manufacturer(void)
{
	char *lcd_ptr = "unknown";

	if(of_machine_is_compatible("qcom,surabaya"))
		lcd_ptr = "JDI";
	else
	{
		if(gpio_get_value(50))
			lcd_ptr = "BOE";
		else
			lcd_ptr = "Sharp";
	}
	memcpy(lcd_buf, lcd_ptr, strlen(lcd_ptr));
}

#define BYTE(_x) (_x<<0x03)
static int __init hwinfo_init(void)
{
	struct kobject *hwinfo = NULL;
	unsigned int len, hwinfo_value;
	unsigned int *ptr_hv;

	if ( (hwinfo = kobject_create_and_add("hwinfo", NULL)) == NULL ) {
		printk(KERN_CRIT "hwinfo sys node create error \n");
	}

	if( sysfs_create_group(hwinfo, &attr_group) ) {
		printk(KERN_CRIT " sysfs_create_group failed\n");
	}

	ptr_hv = (unsigned int *)smem_get_entry(SMEM_ID_VENDOR2, &len, \
		0, SMEM_ANY_HOST_FLAG);

	if (ptr_hv == NULL) {
		printk(KERN_CRIT "%s: smem_get_entry error \n", __func__);
		WARN((ptr_hv==NULL), "hwinfo_init, smem_get_entry SMEM_ID_VENDOR2 failed");
		return -EFAULT;
	}

	set_lcd_manufacturer();

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

	if(machine_is_msm8996())
		cpu_type_name = "msm8996";
	else
		cpu_type_name = "unknown";

	if (of_board_is_colombo_p1())
		hardware_id_name = "p1";
	else if (of_board_is_colombo_p2_6())
		hardware_id_name = "p2.6";
	else if (of_board_is_colombo_p2())
		hardware_id_name = "p2";
	else if (of_board_is_colombo_p3())
		hardware_id_name = "p3";
	else if (of_board_is_surabaya_p1())
		hardware_id_name = "p1";
	else if (of_board_is_surabaya_p2())
		hardware_id_name = "p2";
	else if (of_board_is_surabaya_p3())
		hardware_id_name = "p3";
	else
		hardware_id_name = "unknown";

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
