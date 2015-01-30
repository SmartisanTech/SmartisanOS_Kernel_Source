#ifndef __LINUX_BATTERY_COMMON_H__
#define __LINUX_BATTERY_COMMON_H__

extern int charging_enabled;
extern int current_used_batt;
extern int g_main_voltage;
extern int g_back_voltage;
extern int main_to_bak;
extern int bak_to_main;
extern bool is_batt_present;
extern struct atomic_notifier_head switch_notifier_list;
extern struct atomic_notifier_head batt_state_chg_notifier_list;

/* Console batt events, with the same priority */
#define CHARGE_PLUGIN_EVENT		0x0001
#define CHARGE_PLUGOUT_EVENT    0x0002
#define CHARGE_TRKL_EVENT       0x0003
#define CHARGE_FAST_EVENT       0x0004
#define CHARGE_DONE_EVENT       0x0005
#define BAKBATT_PLUGIN_EVENT    0x0006
#define BAKBATT_PLUGOUT_EVENT   0x0007


#endif
