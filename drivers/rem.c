#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/device.h>
#include <linux/timer.h>
#include <linux/err.h>
#include <linux/ctype.h>
#include <linux/init.h>
#include <linux/ioport.h>
#include <mach/board.h>
#include <mach/gpio.h>
#include <mach/gpiomux.h>
#include <mach/socinfo.h>
#include <mach/msm_smem.h>
#include <mach/subsystem_notif.h>

struct restart_notifier_block {
	unsigned processor;
	char *name;
	struct notifier_block nb;
};

static int restart_notifier_cb(struct notifier_block *this,
				unsigned long code,
				void *data);

static struct restart_notifier_block restart_notifiers[] = {
	{SMEM_MODEM, "modem", .nb.notifier_call = restart_notifier_cb},
	{SMEM_Q6, "lpass", .nb.notifier_call = restart_notifier_cb},
	{SMEM_WCNSS, "wcnss", .nb.notifier_call = restart_notifier_cb},
	{SMEM_DSPS, "dsps", .nb.notifier_call = restart_notifier_cb},
	{SMEM_MODEM, "gss", .nb.notifier_call = restart_notifier_cb},
	{SMEM_Q6, "adsp", .nb.notifier_call = restart_notifier_cb},
};

static DEFINE_MUTEX(rem_mutex);
static char restarted_subsys[128] = "";
static struct kobject *rem_obj;

static int restart_notifier_cb(struct notifier_block *this,
				unsigned long code,
				void *data)
{
	if (code == SUBSYS_AFTER_POWERUP) {
		struct restart_notifier_block *notifier;
		notifier = container_of(this,
					struct restart_notifier_block, nb);
		mutex_lock(&rem_mutex);
		snprintf(restarted_subsys, sizeof(restarted_subsys), "%s restarted\n", notifier->name);
		mutex_unlock(&rem_mutex);
		sysfs_notify(rem_obj, NULL, "last_subsys_restart");
	}
	return NOTIFY_DONE;
}

static ssize_t last_subsys_restart_show(struct kobject *kobj, struct kobj_attribute *attr, char * buf)
{
	int n;
	mutex_lock(&rem_mutex);
	n = sprintf(buf, "%s", restarted_subsys);

	// make sure the next read will be empty again if no restart.
	restarted_subsys[0] = 0; 
	mutex_unlock(&rem_mutex);
	return n;
}

static ssize_t last_subsys_restart_store(struct kobject *kobj, struct kobj_attribute *attr, const char * buf, size_t n)
{
	if (rem_obj) {
		sysfs_notify(rem_obj, NULL, "last_subsys_restart");
	}
	return n;
}

#define rem_attr(_name)					\
        static struct kobj_attribute _name##_attr = {   \
                .attr   = {                             \
                        .name = __stringify(_name),     \
                        .mode = 0664,                   \
                },                                      \
                .show   = _name##_show,                 \
                .store  = _name##_store,                \
        }


rem_attr(last_subsys_restart);

static struct attribute * rem_attrs[] = {
        &last_subsys_restart_attr.attr,
        NULL,
};

static struct attribute_group attr_group = {
        .attrs = rem_attrs,
};

static int __init rem_init(void)
{
	int i;
	void *handle;
	struct restart_notifier_block *nb;

	if ( (rem_obj = kobject_create_and_add("rem_info", NULL)) == NULL ) {
		printk(KERN_CRIT "rem_info sys node create error \n");
		return 1;
	}

	if( sysfs_create_group(rem_obj, &attr_group) ) {
		printk(KERN_CRIT " sysfs_create_group failed\n");
		return 1;
	}

	for (i = 0; i < ARRAY_SIZE(restart_notifiers); i++) {
		nb = &restart_notifiers[i];
		handle = subsys_notif_register_notifier(nb->name, &nb->nb);
		pr_debug("%s: registering notif for '%s', handle=%p\n",
			 __func__, nb->name, handle);
	}

	return 0;
}

static void __exit rem_exit(void)
{
}

late_initcall(rem_init);
module_exit(rem_exit);

MODULE_AUTHOR("baohaojun@smartisan.cn ");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SREM Interface");
