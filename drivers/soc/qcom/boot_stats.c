/* Copyright (c) 2013-2014, The Linux Foundation. All rights reserved.
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
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/clk.h>
#include <linux/cpu.h>
#include <linux/sched.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <soc/qcom/boot_stats.h>

struct boot_stats {
	uint32_t bootloader_start;
	uint32_t bootloader_end;
	uint32_t bootloader_display;
	uint32_t bootloader_load_kernel;
};

static void __iomem *mpm_counter_base;
static uint32_t mpm_counter_freq;
static struct boot_stats __iomem *boot_stats;
static uint32_t dump_happened=0;

struct boot_shared_imem_cookie_type __iomem *boot_imem = NULL;
extern char * log_first_idx_get(void);
extern char * log_next_idx_get(void);

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

uint64_t get_boot_reason(void)
{
	if (boot_imem == NULL)
		boot_stats_init();
	return (uint64_t)boot_imem->pon_reason;
}

uint64_t get_poff_fault_reason(void)
{
	if (boot_imem == NULL)
		boot_stats_init();
	return (uint64_t)boot_imem->fault_reason;
}

uint32_t get_secure_boot_value(void)
{
	if (boot_imem == NULL)
		boot_stats_init();

	return (uint32_t)boot_imem->is_enable_secure_boot;
}

uint32_t get_lpddr_vendor_id(void)
{
	if (boot_imem == NULL)
		boot_stats_init();

	return (uint32_t)boot_imem->lpddr_vendor_id;
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

	printk(KERN_CRIT"KPI: kernel_log_buf_addr = 0x%llx , offset %lu ,0x%llx\n",boot_imem->kernel_log_buf_addr,offsetof(struct boot_shared_imem_cookie_type,kernel_log_buf_addr),(uint64_t)virt_to_phys((uint64_t *)0xffffff800a7c0510));
	printk(KERN_CRIT"KPI: log_first_idx = 0x%llx , offset %lu\n",(boot_imem->log_first_idx_addr),offsetof(struct boot_shared_imem_cookie_type,log_first_idx_addr));
	printk(KERN_CRIT"KPI: log_next_idx = 0x%llx , offset %lu \n",boot_imem->log_next_idx_addr,offsetof(struct boot_shared_imem_cookie_type,log_next_idx_addr));
	printk(KERN_CRIT"KPI: offline_dump_flag = 0x%x\n",(uint32_t)boot_imem->offline_dump_flag);
	printk(KERN_CRIT"KPI: pon_reason = 0x%llx\n", (uint64_t)boot_imem->pon_reason);
	printk(KERN_CRIT"KPI: fault_reason = 0x%llx\n", (uint64_t)boot_imem->fault_reason);
	printk(KERN_CRIT"KPI: is_enable_secure_boot = 0x%x\n",(uint32_t)boot_imem->is_enable_secure_boot);
	printk(KERN_CRIT"KPI: lpddr_vendor_id = 0x%x\n",(uint32_t)boot_imem->lpddr_vendor_id);

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
	printk(KERN_CRIT"KPI: store_offline_dump ,  enabled %d\n",enabled);

	if (!((enabled == 0) || (enabled == 1)))
		return -EINVAL;

	if (enabled == 1)
		boot_imem->offline_dump_flag = 1;
	else
		boot_imem->offline_dump_flag = 0;

	return count;
}

ssize_t show_offline_dump_happen(struct kobject *kobj, struct attribute *attr,char *buf)
{
	uint32_t show_val;
	show_val = boot_imem->offline_dump_happen;

	if (dump_happened != 1)
		dump_happened = show_val;

	printk(KERN_CRIT"KPI: show_offline_dump_happen  %d\n",show_val);

	if(boot_imem->offline_dump_happen==1){
	    boot_imem->offline_dump_happen = 0;
	}
	return snprintf(buf, sizeof(show_val), "%u\n", show_val);
}

size_t store_offline_dump_happen(struct kobject *kobj, struct attribute *attr,const char *buf, size_t count)
{
	uint32_t enabled;
	int ret;

	ret = kstrtouint(buf, 0, &enabled);
	if (ret < 0)
		return ret;

	if (!((enabled == 0) || (enabled == 1)))
		return -EINVAL;

	if (enabled == 1)
		boot_imem->offline_dump_happen = 1;
	else
		boot_imem->offline_dump_happen = 0;

	return count;
}

ssize_t show_dump_happen(struct kobject *kobj, struct attribute *attr,char *buf)
{
	if (dump_happened != 1)
		dump_happened = boot_imem->offline_dump_happen;

	return snprintf(buf, sizeof(dump_happened), "%u\n", dump_happened);
}

size_t store_dump_happen(struct kobject *kobj, struct attribute *attr,const char *buf, size_t count)
{

	return 0;

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
	boot_imem->log_first_idx_addr = virt_to_phys(log_first_idx_get());
	boot_imem->log_next_idx_addr = virt_to_phys(log_next_idx_get());
	printk(KERN_CRIT"boot_stats_init:  log_first_idx_get() = 0x%llu\n",(u64)log_first_idx_get());
	printk(KERN_CRIT"boot_stats_init:  log_next_idx_get() = 0x%llu\n",(u64)log_next_idx_get());

	if(boot_imem->offline_dump_happen==1){
	    printk(KERN_CRIT"-----------------KPI:  offline_dump_happen = 0x%x\n",(uint32_t)boot_imem->offline_dump_happen);
	    //boot_imem->offline_dump_happen = 0;
	}
#ifdef _BUILD_USER
	boot_imem->offline_dump_mol = 1;
#endif
	print_boot_stats();

	iounmap(boot_stats);
	iounmap(mpm_counter_base);

	return 0;
}

