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

//define ddr manufacture id
#define DDR_MANUFACTURE_ELPIDA_ID   0x03
#define DDR_MANUFACTURE_SAMSUNG_ID  0x01
#define DDR_MANUFACTURE_HYNIX_ID    0x06
static int hardware_info = 0 ;
static uint32_t emmc_menufacture_id_info = 0 ;
static unsigned char cpu_id[4];
static unsigned char cpu_v = 0 ;
static unsigned char emmc_capacity_manufacture[3];

static ssize_t cpu_id_show(struct kobject *kobj, struct kobj_attribute *attr, char * buf)
{
	if(cpu_v == 1)
		return sprintf(buf, "cpu=8x74AB ,cpu_id=%s\n",cpu_id);
	if(cpu_v == 2)
		return sprintf(buf, "cpu=8x74AC ,cpu_id=%s\n",cpu_id);

	return sprintf(buf, "cpu not 8x74AC or 8x74AB, cpu_id=%s \n",cpu_id);
}

static ssize_t cpu_id_store(struct kobject *kobj, struct kobj_attribute *attr, const char * buf, size_t n)
{
	return n;
}

static ssize_t emmc_menufacture_id_show(struct kobject *kobj, struct kobj_attribute *attr, char * buf)
{
	if(emmc_menufacture_id_info == 17)
		return sprintf(buf, "emmc_menufacture_id=%d , TOSHIBA \n",emmc_menufacture_id_info);
	else if(emmc_menufacture_id_info == 69)
		return sprintf(buf, "emmc_menufacture_id=%d , Sandisk \n",emmc_menufacture_id_info);
	else if(emmc_menufacture_id_info == 21)
		return sprintf(buf, "emmc_menufacture_id=%d , Samsung \n",emmc_menufacture_id_info);

	return sprintf(buf, "emmc_menufacture_id_info=%d \n",emmc_menufacture_id_info);
}

static ssize_t emmc_menufacture_id_store(struct kobject *kobj, struct kobj_attribute *attr, const char * buf, size_t n)
{
	return n;
}

static ssize_t hardware_id_show(struct kobject *kobj, struct kobj_attribute *attr, char * buf)
{
	return sprintf(buf, "hardware_version=P%d \n",hardware_info);
}

static ssize_t hardware_id_store(struct kobject *kobj, struct kobj_attribute *attr, const char * buf, size_t n)
{
	return n;
}

static ssize_t ddr_manufacture_id_show(struct kobject *kobj, struct kobj_attribute *attr, char * buf)
{
        unsigned int  ddr_id=0;
        int ret=0;
        ddr_id = *(unsigned int *)smem_get_entry(SMEM_ID_VENDOR2,&ddr_id);
        if(ddr_id == DDR_MANUFACTURE_ELPIDA_ID)
        {
           ret = sprintf(buf, "ddr_manufacture_id=%d,ELPIDA \n",ddr_id);
        }
        else if(ddr_id == DDR_MANUFACTURE_HYNIX_ID)
        {
		  ret = sprintf(buf, "ddr_manufacture_id=%d,HYNIX \n",ddr_id);
        }
        else if(ddr_id == DDR_MANUFACTURE_SAMSUNG_ID)
        {
          ret = sprintf(buf, "ddr_manufacture_id=%d,SAMSUNG \n",ddr_id);
        }
        else
        {
          ret = sprintf(buf, "  don't match ddr_manufacture_id  ddr_id=%d \n",ddr_id);
        }

        return ret;

}

static ssize_t ddr_manufacture_id_store(struct kobject *kobj, struct kobj_attribute *attr, const char * buf, size_t n)
{
	return n;
}

static ssize_t emmc_capacity_manufacture_show(struct kobject *kobj, struct kobj_attribute *attr, char * buf)
{
	return sprintf(buf, "emmc_capacity=%s \n",emmc_capacity_manufacture);
}

static ssize_t emmc_capacity_manufacture_store(struct kobject *kobj, struct kobj_attribute *attr, const char * buf, size_t n)
{
	return n;
}
#define pversion_attr(_name) \
        static struct kobj_attribute _name##_attr = {   \
                .attr   = {                             \
                        .name = __stringify(_name),     \
                        .mode = 0664,                   \
                },                                      \
                .show   = _name##_show,                 \
                .store  = _name##_store,                \
        }


pversion_attr(hardware_id);
pversion_attr(emmc_menufacture_id);
pversion_attr(cpu_id);
pversion_attr(ddr_manufacture_id);
pversion_attr(emmc_capacity_manufacture);

static struct attribute * g[] = {
        &hardware_id_attr.attr,
        &emmc_menufacture_id_attr.attr,
        &cpu_id_attr.attr,
        &ddr_manufacture_id_attr.attr,
        &emmc_capacity_manufacture_attr.attr,
        NULL,
};

static struct attribute_group attr_group = {
        .attrs = g,
};

int string_to_longlong(char *str)
{
	int i = 0;
	int n = 0;
	for (n=0; str[i]!=0; i++) {
		n = 10*n + (str[i]-'0');
	}

	return n;
}

static int __init emmc_mid_setup(char *str)
{
	char * tmp = str;

	if (str == NULL)
		return 0;

	emmc_menufacture_id_info = string_to_longlong(tmp);

	return 1;
}

__setup("emmc_mid=", emmc_mid_setup);

static int __init cpu_id_setup(char *str)
{
	if (str == NULL)
		return 0;

	memcpy(cpu_id, str, sizeof(cpu_id));

	return 1;
}

__setup("cpu_id=", cpu_id_setup);


static int  set_emmc_capacity(char *src)
{
	if (src == NULL)
		return 0;

	memcpy(emmc_capacity_manufacture, src, sizeof(emmc_capacity_manufacture));

    return 1;
}
__setup("emmc_capacity=", set_emmc_capacity);

static int __init pversion_init(void)
{
	struct kobject *pversion_obj = NULL;

	if ( (pversion_obj = kobject_create_and_add("pversion_info", NULL)) == NULL ) {
		printk(KERN_CRIT "pversion_info sys node create error \n");
	}

	if( sysfs_create_group(pversion_obj, &attr_group) ) {
		printk(KERN_CRIT " sysfs_create_group failed\n");
	}

	if(of_machine_is_compatible("qcom,8x74AB"))
			cpu_v = 1;
	if(of_machine_is_compatible("qcom,8x74AC"))
			cpu_v = 2;

	if (of_board_is_sfo_v10())
		hardware_info = 1;
	else if (of_board_is_sfo_v20())
		hardware_info = 2;
	else if (of_board_is_sfo_v30())
		hardware_info = 3;
	else if  (of_board_is_sfo_v40())
		hardware_info = 4;

	return 0;
}

static void __exit pversion_exit(void)
{
;
}

subsys_initcall(pversion_init);
module_exit(pversion_exit);

MODULE_AUTHOR("zhaojun@smartisan.cn ");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Product version Interface");
