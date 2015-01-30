#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/power/battery_state_machine.h>

#if BATT_DEBUG
extern wait_queue_head_t bat_state_q;
extern int bat_state_change_pending;
#endif

static bool is_main_soc_done = false;
static bool is_back_soc_done = false;
static bool is_back_vol_toolow= false;
/* Battery capacity work schedule */
struct delayed_work		batt_capacity_d_work;   /*backbat_charging*/
/* Check battery capacity every 10 seconds */
#define CAPACITY_CHECK_PERIOD_MS	10000

/* Conditions from backup_batt_charging to backup_batt_no_charging */
static int sync_bak_to_bak_no_chg_pending(void)
{
	return !is_chg_enabled || 
		(is_back_soc_done && !is_chg_enabled) || 
		(is_chg_done && !is_chg_enabled);
}

/* Conditions from backup_batt_charging to main_batt_charging */
static int sync_bak_to_main_chg_pending(void)
{
	return (!is_batt_present) ||
			(((is_main_soc_done && !is_chg_done) || is_back_vol_toolow) && is_chg_enabled);
}

#if 0
/* Conditions for stoping main battery trickle charge */
static int sync_main_stop_trickle_chg_pending(void)
{
	//int main_capacity;
	//main_capacity = get_main_batt_capacity();
	
	return (!is_batt_present) || (!is_chg_enabled);/*|| (main_capacity >= 40)*/
}
#endif

static void batt_capacity_monitor_work(struct work_struct *work)
{
	int main_capacity, back_capacity, back_voltage;

	main_capacity = get_main_batt_capacity();
	back_capacity = get_backup_batt_capacity();
	g_main_voltage = get_main_batt_voltage();
		
	g_main_capacity = main_capacity;
	g_back_capacity = back_capacity;

    if ((g_main_voltage / 1000 >= 3500) && (main_capacity < 100)) {
		if (!is_main_soc_done) {
			is_main_soc_done = true;
			wake_up(&sync_batt_state_wq);
		}
	} else {
		is_main_soc_done = false;
	}

	if (back_capacity == 100) {
		if (!is_back_soc_done) {
			is_back_soc_done = true;
			wake_up(&sync_batt_state_wq);  
		}
	} else {
		is_back_soc_done = false;
	}

	if (back_capacity <= 0) {
		back_voltage = get_backup_batt_voltage();
		if (( back_voltage / 1000 < 3500) && ( back_voltage < g_main_voltage)) {
			if (!is_back_vol_toolow) {
				is_back_vol_toolow = true;
				wake_up(&sync_batt_state_wq);
				pr_info("%s back battery vol too low: %dmV main vol: %dmV Switch to main charging state.\n",
						__func__, back_voltage / 1000, g_main_voltage / 1000);
			}
		} else {
			is_back_vol_toolow = false;
		}
	} else {
		is_back_vol_toolow = false;
	}


	if ((g_main_voltage / 1000) < 3600)
		if (!get_trcc_en_2nd_switch_status())
			set_trcc_en_2nd_switch("on");

	/* It's ugly, but we have to.*/
	if (get_trcc_en_2nd_switch_status())
		if ((g_main_voltage / 1000 >= 3600) || !is_batt_present || !is_chg_enabled)
			set_trcc_en_2nd_switch("off");
		
	pr_debug("backbat_charging work, main_capacity: %d  back_capacity: %d\n", main_capacity, back_capacity);

	schedule_delayed_work(&batt_capacity_d_work,
		msecs_to_jiffies(CAPACITY_CHECK_PERIOD_MS));
}

BAT_STATE_T backbat_charging_entry(BAT_STATE_T *prev_state)
{
	BAT_STATE_T bat_state = BAT_STATE_BAK_CHG;
	/* FIRST TO DO:
	 * init mainbat_nocharging state
	 * sw_ctl = ?; bb_lock = ?
	 * ...
	 */
	if (!get_backup_batt_switch_status())
		set_sw_ctrl_2nd_batt_switch("on");

	/* SECOND TO DO:
	 * Judge state change ? If changed, change bat_state
	 * bat_state = BAT_STATE_?
	 */
	pr_debug("%s enter\n", __func__);

	/* Init is_soc_done in case of full capacity switch error */
	is_main_soc_done = false;
	is_back_soc_done = false;
	is_back_vol_toolow= false;

	/* Record the main battery voltage for bms after switch to backup battery */
	g_main_voltage = get_main_batt_voltage();
	
	/* Init a work for battery capacity monitor. */
	INIT_DELAYED_WORK(&batt_capacity_d_work, batt_capacity_monitor_work);
	schedule_delayed_work(&batt_capacity_d_work,
		msecs_to_jiffies(CAPACITY_CHECK_PERIOD_MS));
#if BATT_DEBUG
	bat_state_change_pending = 0;
	wait_event(bat_state_q, bat_state_change_pending);
	if (bat_state_change_pending == (BAT_STATE_BAK_NOCHG + 1))
		bat_state = BAT_STATE_BAK_NOCHG;
	else if (bat_state_change_pending == (BAT_STATE_MAIN_CHG + 1))
		bat_state = BAT_STATE_MAIN_CHG;
#endif
	pr_debug("%s exit, enter bat_state: %d\n", __func__, bat_state);
	return bat_state;
}

BAT_STATE_T backbat_charging_handle(BAT_STATE_T *prev_state)
{
	BAT_STATE_T bat_state = BAT_STATE_BAK_CHG;
	/* Judge ACTION:
	 * 1.   Charging plugout
	 *   or Electricity(back = 100%)
	 *   or battery cold or hot
	 *
	 *   ENTER state BAT_STATE_BAK_NOCHG
	 *
	 * 2.   (Backbat plugout) & (Electricity(main > 100%))
	 *   or Electricity(main = 100% & back = 100%))
	 *   or Electricity(0% < main < 100%)
	 *
	 *   ENTER state BAT_STATE_MAIN_CHG
	 */
	pr_debug("%s enter\n", __func__);
#if BATT_DEBUG
wait_change:
	bat_state_change_pending = 0;
	wait_event(bat_state_q, bat_state_change_pending);
	if (bat_state_change_pending == (BAT_STATE_BAK_NOCHG + 1))
		bat_state = BAT_STATE_BAK_NOCHG;
	else if (bat_state_change_pending == (BAT_STATE_MAIN_CHG + 1))
		bat_state = BAT_STATE_MAIN_CHG;
	else
		goto wait_change;
#endif 
	if ((get_main_batt_voltage() / 1000) < 3600)
		if (!get_trcc_en_2nd_switch_status())
			set_trcc_en_2nd_switch("on");
wait_change:
	wait_event(sync_batt_state_wq, 
		sync_bak_to_bak_no_chg_pending()  
		|| sync_bak_to_main_chg_pending()
		/*|| sync_main_stop_trickle_chg_pending()*/
		|| exit_batt_machine_thread);
    /*
	if (sync_main_stop_trickle_chg_pending())
		if (get_trcc_en_2nd_switch_status())
			set_trcc_en_2nd_switch("off");
	*/
	if (sync_bak_to_bak_no_chg_pending())
		bat_state = BAT_STATE_BAK_NOCHG;
	else if (sync_bak_to_main_chg_pending()) {
		bat_state = BAT_STATE_MAIN_CHG;
		g_main_voltage = get_main_batt_voltage();
		bak_to_main = 1;
		main_to_bak = 0;
	}
	else if (exit_batt_machine_thread)
		bat_state = BAT_STATE_BAK_CHG;
	else
		goto wait_change;
	pr_debug("%s exit\n", __func__);
	return bat_state;
}

BAT_STATE_T backbat_charging_exit(BAT_STATE_T *prev_state)
{
	BAT_STATE_T bat_state = BAT_STATE_BAK_CHG;

	cancel_delayed_work_sync(&batt_capacity_d_work);

	/* Stop Tickel charging */
	if (get_trcc_en_2nd_switch_status())
		set_trcc_en_2nd_switch("off");

	pr_debug("%s\n", __func__);
	return bat_state;
}
