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

#define MAX_HWSTATE_SIZE 20
#include <smartisan/hwstate.h>

typedef struct{
	char *hwstate_name;
	char hwstate_buf[MAX_HWSTATE_SIZE];
}hwstate_t;

#define KEYWORD(_name) \
	[_name] = {.hwstate_name = __stringify(_name), \
		.hwstate_buf = {"driver not ready"}, },

static hwstate_t hwstate[HWSTATE_MAX] =
{
#include <smartisan/hwstate.h>
};
#undef KEYWORD

static ssize_t hwstate_show(struct kobject *kobj, struct kobj_attribute *attr, char * buf)
{
	int i = 0;
	int j = 0;
	//    printk(KERN_INFO "hwstate sys node %s \n", attr->attr.name);

	for(; i < HWSTATE_MAX && strcmp(hwstate[i].hwstate_name, attr->attr.name)&&++i;);

	switch (i) {
	case i2cspi_state:
	{
		memset(hwstate[i2cspi_state].hwstate_buf, 0, MAX_HWSTATE_SIZE);
		for(j = 1; j < HWSTATE_MAX && (strncmp(hwstate[j].hwstate_buf, "fail", 4)); j++);
		if (j >= HWSTATE_MAX)
			sprintf(hwstate[0].hwstate_buf, "ok");
		else
			strncpy(hwstate[0].hwstate_buf, hwstate[j].hwstate_buf, MAX_HWSTATE_SIZE);
		if (!strncmp(hwstate[fingerprint].hwstate_buf, "driver not ready", 16))
			sprintf(hwstate[0].hwstate_buf, "driver not ready");
		break;
	}
	case audio_receiver_l:
	case audio_speaker_r:
	{
		unsigned int status;
		status = max98927_get_i2c_states();
		if ((i == audio_receiver_l && status & 0x1) || (i == audio_speaker_r && status & 0x2))
			sprintf(hwstate[i].hwstate_buf, "ok");
		else
			sprintf(hwstate[i].hwstate_buf, "fail");
		break;
	}
	case audio_intelligo:
	{
		if (debussy_get_presence())
			sprintf(hwstate[i].hwstate_buf, "ok");
		else
			sprintf(hwstate[i].hwstate_buf, "fail");
		break;
	}
	default:
		break;
	}

	return sprintf(buf, "%s\n", (hwstate[i].hwstate_buf));
}

static ssize_t hwstate_store(struct kobject *kobj, struct kobj_attribute *attr, const char * buf, size_t n)
{
	int i = 0;
	//    printk(KERN_INFO "hwstate sys node %s \n", attr->attr.name);

	for(; i < HWSTATE_MAX && strcmp(hwstate[i].hwstate_name, attr->attr.name)&&++i;);

	memset(hwstate[i].hwstate_buf, 0, MAX_HWSTATE_SIZE);
	strncpy(hwstate[i].hwstate_buf, buf, n);

	return n;
}
#define KEYWORD(_name) \
	static struct kobj_attribute hwstate##_name##_attr = {   \
		.attr   = {                             \
			.name = __stringify(_name),     \
			.mode = 0644,                   \
		},                                      \
		.show   = hwstate_show,                 \
		.store  = hwstate_store,                \
	};

#include <smartisan/hwstate.h>
#undef KEYWORD

#define KEYWORD(_name)\
	[_name] = &hwstate##_name##_attr.attr,

static struct attribute * g[] = {
#include <smartisan/hwstate.h>
	NULL
};
#undef KEYWORD

static struct attribute_group attr_group = {
	.attrs = g,
};

int smartisan_hwstate_set(char *hwstate_name, char *module_state)
{
	int i = 0;

	for(; i < HWSTATE_MAX && strcmp(hwstate[i].hwstate_name, hwstate_name)&&++i;);
	if((i >= HWSTATE_MAX) || (hwstate_name == NULL))
		return -1;
	memset(hwstate[i].hwstate_buf, 0, MAX_HWSTATE_SIZE);
	strncpy(hwstate[i].hwstate_buf, module_state, \
		(strlen(module_state)>=20? 19:strlen(module_state)));
	return 0;
}
EXPORT_SYMBOL(smartisan_hwstate_set);

static int __init hwstate_init(void)
{
	struct kobject *k_hwstate = NULL;

	if ( (k_hwstate = kobject_create_and_add("factoryTest", NULL)) == NULL ) {
		printk(KERN_CRIT "%s:hwstate sys node create error \n", __func__);
	}

	if( sysfs_create_group(k_hwstate, &attr_group) ) {
		printk(KERN_CRIT "%s:sysfs_create_group failed\n", __func__);
	}

	return 0;
}

static void __exit hwstate_exit(void)
{
	return ;
}

fs_initcall(hwstate_init);
module_exit(hwstate_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Product Hardward I2C/SPI state Exposure");
