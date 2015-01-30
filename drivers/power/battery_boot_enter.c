#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/power/battery_state_machine.h>

BAT_STATE_T bat_boot_firsttime_entry()
{
	int main_batt_vol_now;
	int backup_batt_vol_now;
	
	printk("%s\n", __func__);
	
	/* init boot state here */
	main_batt_vol_now = get_main_batt_voltage();
    backup_batt_vol_now = get_backup_batt_voltage();
	printk("main_batt_vol_now: %d, backup_batt_vol_now: %d\n", main_batt_vol_now, backup_batt_vol_now);
	/* Must check battery power supply voltage before bb_lock */
	#if 1 // Start on main battery will simplify the state machine initialization
	if (main_batt_vol_now / 1000 >= 3600) {
		set_sw_ctrl_2nd_batt_switch("off");
		msleep(1);
        set_bb_lock_switch("lock");
		return BAT_STATE_MAIN_NOCHG;
	} else {
		if (main_batt_vol_now  >= backup_batt_vol_now) {
            set_sw_ctrl_2nd_batt_switch("off");
			msleep(1);
            set_bb_lock_switch("lock");
			return BAT_STATE_MAIN_NOCHG;
		} else {
        set_sw_ctrl_2nd_batt_switch("on");
		msleep(1);
        set_bb_lock_switch("lock");
		/* Workaround: because backup battery fuel notify delay 
		   we have to initialize here. */
		is_batt_present = true;
		return BAT_STATE_BAK_NOCHG;
		}
	}
	#else
	if (backup_batt_vol_now / 1000 >= 3600) {
		set_sw_ctrl_2nd_batt_switch("on");
		msleep(1);
        set_bb_lock_switch("lock");
		return BAT_STATE_BAK_NOCHG;
	} else {
		if (backup_batt_vol_now  >= main_batt_vol_now) {
            set_sw_ctrl_2nd_batt_switch("on");
			msleep(1);
            set_bb_lock_switch("lock");
			return BAT_STATE_BAK_NOCHG;
		} else {
        set_sw_ctrl_2nd_batt_switch("off");
		msleep(1);
        set_bb_lock_switch("lock");
		return BAT_STATE_MAIN_NOCHG;
		}
	}
	#endif
}
