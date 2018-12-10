/* Copyright (c) 2013-2014,2016, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/clk.h>
#include <linux/cpu.h>
#include <linux/sched.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/export.h>
#include <linux/types.h>
#include <soc/qcom/boot_stats.h>

static void __iomem *mpm_counter_base;
static uint32_t mpm_counter_freq;
struct boot_stats __iomem *boot_stats;
struct boot_shared_imem_cookie_type __iomem *boot_imem;
extern u32* log_first_idx_get(void);
extern u32* log_next_idx_get(void);

static int mpm_parse_dt(void)
{
	struct device_node *np;
	u32 freq;

	np = of_find_compatible_node(NULL, NULL, "qcom,msm-imem-boot_stats");
	if (!np) {
		pr_err("can't find qcom,msm-imem node\n");
		return -ENODEV;
	}
	boot_stats = of_iomap(np, 0);
	if (!boot_stats) {
		pr_err("boot_stats: Can't map imem\n");
		return -ENODEV;
	}

	np = of_find_compatible_node(NULL, NULL, "qcom,mpm2-sleep-counter");
	if (!np) {
		pr_err("mpm_counter: can't find DT node\n");
		return -ENODEV;
	}

	if (!of_property_read_u32(np, "clock-frequency", &freq))
		mpm_counter_freq = freq;
	else
		return -ENODEV;

	if (of_get_address(np, 0, NULL, NULL)) {
		mpm_counter_base = of_iomap(np, 0);
		if (!mpm_counter_base) {
			pr_err("mpm_counter: cant map counter base\n");
			return -ENODEV;
		}
	}

	return 0;
}

static void print_boot_stats(void)
{
	pr_info("KPI: Bootloader start count = %u\n",
		readl_relaxed(&boot_stats->bootloader_start));
	pr_info("KPI: Bootloader end count = %u\n",
		readl_relaxed(&boot_stats->bootloader_end));
	pr_info("KPI: Bootloader display count = %u\n",
		readl_relaxed(&boot_stats->bootloader_display));
	pr_info("KPI: Bootloader load kernel count = %u\n",
		readl_relaxed(&boot_stats->bootloader_load_kernel));
	pr_info("KPI: Kernel MPM timestamp = %u\n",
		readl_relaxed(mpm_counter_base));
	pr_info("KPI: Kernel MPM Clock frequency = %u\n",
		mpm_counter_freq);
	
	printk(KERN_CRIT"KPI: kernel_log_buf_addr = 0x%llx\n",boot_imem->kernel_log_buf_addr);
	printk(KERN_CRIT"KPI: log_first_idx = 0x%x\n",(uint32_t)(boot_imem->log_first_idx_addr));
	printk(KERN_CRIT"KPI: log_next_idx = 0x%x\n",(uint32_t)boot_imem->log_next_idx_addr);
	printk(KERN_CRIT"KPI: offline_dump_flag = 0x%x\n",(uint32_t)boot_imem->offline_dump_flag);
	printk(KERN_CRIT"KPI: pon_reason = 0x%llx\n", (uint64_t)boot_imem->pon_reason);
	printk(KERN_CRIT"KPI: is_enable_secure_boot = 0x%x\n",(uint32_t)boot_imem->is_enable_secure_boot);
}

unsigned long long int msm_timer_get_sclk_ticks(void)
{
	unsigned long long int t1, t2;
	int loop_count = 10;
	int loop_zero_count = 3;
	int tmp = USEC_PER_SEC;
	void __iomem *sclk_tick;

	do_div(tmp, TIMER_KHZ);
	tmp /= (loop_zero_count-1);
	sclk_tick = mpm_counter_base;
	if (!sclk_tick)
		return -EINVAL;
	while (loop_zero_count--) {
		t1 = __raw_readl_no_log(sclk_tick);
		do {
			udelay(1);
			t2 = t1;
			t1 = __raw_readl_no_log(sclk_tick);
		} while ((t2 != t1) && --loop_count);
		if (!loop_count) {
			pr_err("boot_stats: SCLK  did not stabilize\n");
			return 0;
		}
		if (t1)
			break;

		udelay(tmp);
	}
	if (!loop_zero_count) {
		pr_err("boot_stats: SCLK reads zero\n");
		return 0;
	}
	return t1;
}

ssize_t show_offline_dump(struct kobject *kobj, struct attribute *attr,char *buf)
{
	uint32_t show_val;
	
	show_val = boot_imem->offline_dump_flag;	

	return snprintf(buf, sizeof(show_val), "%u\n", show_val);
}

size_t store_offline_dump(struct kobject *kobj, struct attribute *attr,const char *buf, size_t count)
{
	uint32_t enabled;
	int ret;

	ret = kstrtouint(buf, 0, &enabled);
	if (ret < 0)
		return ret;

	if (!((enabled == 0) || (enabled == 1)))
		return -EINVAL;

	if (enabled == 1)
		boot_imem->offline_dump_flag = 1;
	else
		boot_imem->offline_dump_flag = 0;

	return count;
}

static uint32_t ddr_freq_en_mask_init_value = 0;
struct ddr_freq_kobj_attr{
	struct kobj_attribute ka;
	int version;
};

struct ddr_freq_map_entry{
	uint32_t mask;
	char name[16];
};

struct ddr_freq_map_entry ddr_freq_map[12]={
	{ DDR_FREQ_EN_019MHZ_MASK, "19200" },
	{ DDR_FREQ_EN_100MHZ_MASK, "100800"},
	{ DDR_FREQ_EN_211MHZ_MASK, "211200"},
	{ DDR_FREQ_EN_278MHZ_MASK, "278400"},
	{ DDR_FREQ_EN_384MHZ_MASK, "384000"},
	{ DDR_FREQ_EN_422MHZ_MASK, "422400"},
	{ DDR_FREQ_EN_556MHZ_MASK, "556800"},
	{ DDR_FREQ_EN_672MHZ_MASK, "672000"},
	{ DDR_FREQ_EN_768MHZ_MASK, "768000"},
	{ DDR_FREQ_EN_806MHZ_MASK, "806000"},
	{ DDR_FREQ_EN_844MHZ_MASK, "844800"},
	{ DDR_FREQ_EN_933MHZ_MASK, "931200"},
};

static ssize_t ddr_freq_en_show(struct kobject *kobj, 
			struct kobj_attribute *attr, char *buf)
{
	int pos=0;
	int i;
	uint32_t ddr_freq_en_mask;

	if(!boot_imem)
		return 0;

	ddr_freq_en_mask = boot_imem->ddr_freq_en_mask;

	for (i=0;i<12;i++)
	{
		pos += snprintf(buf+pos, PAGE_SIZE-pos, "%c%s\n", 
			(ddr_freq_en_mask & ddr_freq_map[i].mask)?'+':'-',
			ddr_freq_map[i].name);
	}

	return pos;
}

static ssize_t ddr_freq_en_store(struct kobject *kobj,
			struct kobj_attribute *attr, const char *buf, size_t count)
{
	const char *p;
	int i;
	uint32_t ddr_freq_en_mask;

	if(!boot_imem)
		return 0;

	ddr_freq_en_mask = boot_imem->ddr_freq_en_mask;
	if (strncmp(buf, "reset", 5)==0)
	{
		boot_imem->ddr_freq_en_mask = ddr_freq_en_mask_init_value;
		return count;
	}
	if (buf[0]=='+' || buf[0]=='-')
	{
		p=buf+1;

		for (i=0;i<12;i++)
		{
			if (strncmp(ddr_freq_map[i].name, p, strlen(ddr_freq_map[i].name))==0)
			{
				if(buf[0]=='+')
					ddr_freq_en_mask |= ddr_freq_map[i].mask;
				else
					ddr_freq_en_mask &= ~ddr_freq_map[i].mask;


				boot_imem->ddr_freq_en_mask = ddr_freq_en_mask;
				return count;
			}
		}
	}

	return count;
}

static int ddr_freq_sysfs_init(void)
{
	struct kobject *module_kobj = NULL;
	struct kobject *ddr_freq_kobj = NULL;
	struct ddr_freq_kobj_attr *ddr_freq_attr = NULL;
	int ret = 0;

	ddr_freq_en_mask_init_value = boot_imem->ddr_freq_en_mask;

	module_kobj = kset_find_obj(module_kset, "kernel");
	if (!module_kobj) {
		pr_err("%s: Cannot find module_kset\n", __func__);
		return -ENODEV;
	}
	ddr_freq_kobj = kobject_create_and_add("ddr_freq_en", module_kobj);
	if (!ddr_freq_kobj) {
		pr_err("%s: Cannot create ddr_freq_en kobject\n", __func__);
		return -ENOMEM;
	}

	ddr_freq_attr = kzalloc(sizeof(*ddr_freq_attr), GFP_KERNEL);
	if (!ddr_freq_attr) {
		pr_err("%s:Cannot allocate mem for ddr_freq_en kobj attr\n", __func__);
		kobject_put(ddr_freq_kobj);
		return -ENOMEM;
	}

	sysfs_attr_init(&ddr_freq_attr->ka.attr);
	ddr_freq_attr->ka.attr.mode = 0664;
	ddr_freq_attr->ka.attr.name = "ddr_freq_en";
	ddr_freq_attr->ka.show = ddr_freq_en_show;
	ddr_freq_attr->ka.store = ddr_freq_en_store;

	ret = sysfs_create_file(ddr_freq_kobj, &ddr_freq_attr->ka.attr);
	if (ret) {
		kfree(ddr_freq_attr);
		kobject_put(ddr_freq_kobj);
		pr_err("%s: Failed to create ddr_freq_en node\n", __func__);
	}
	return ret;
}

uint64_t get_boot_reason(void)
{
	if (boot_imem == NULL) 
		boot_stats_init();
	return (uint64_t)boot_imem->pon_reason;
}

uint32_t get_secure_boot_value(void)
{
		if (boot_imem == NULL) 
			boot_stats_init();
		
		return (uint32_t)boot_imem->is_enable_secure_boot;	
}


int boot_stats_init(void)
{
	int ret;
	struct device_node *np;

	ret = mpm_parse_dt();
	if (ret < 0)
		return -ENODEV;

	np = of_find_compatible_node(NULL, NULL, "qcom,msm-imem");
	if (!np) {
		pr_err("can't find qcom,msm-imem node\n");
		return -ENODEV;
	}
	
	boot_imem = of_iomap(np, 0);

	boot_imem->kernel_log_buf_addr = virt_to_phys(log_buf_addr_get());
	boot_imem->log_first_idx_addr = (uint32_t)virt_to_phys(log_first_idx_get());
	boot_imem->log_next_idx_addr = (uint32_t)virt_to_phys(log_next_idx_get());

	
	if(boot_imem->offline_dump_happen==1){
	    printk(KERN_CRIT"-----------------KPI:  offline_dump_happen = 0x%x\n",(uint32_t)boot_imem->offline_dump_happen);
	    boot_imem->offline_dump_happen = 0;
	}
#ifdef _BUILD_USER
	boot_imem->offline_dump_mol = 1;
#endif

	if (ddr_freq_sysfs_init()<0)
		pr_err("Failed to initialize ddr_freq_en sysfs interface\n");

	print_boot_stats();

	if (!(boot_marker_enabled()))
		boot_stats_exit();
	return 0;
}

int boot_stats_exit(void)
{
	iounmap(boot_stats);
	iounmap(mpm_counter_base);
	return 0;
}
