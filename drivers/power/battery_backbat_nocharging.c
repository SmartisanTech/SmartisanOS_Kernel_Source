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

static int g_count = 0;
static bool is_main_soc_done = false;
static bool is_back_soc_done = false;
/* Battery capacity work schedule */
struct delayed_work		batt_capacity_c_work;   /*backbat_nocharging*/
/* Check battery capacity every 10 seconds */
#define CAPACITY_CHECK_PERIOD_MS	10000

/* Conditions from backup_batt_no_charging to backup_batt_charging */
static int sync_bak_to_bak_chg_pending(void)
{
	return is_chg_enabled && (g_back_capacity <= 100);
}

/* Conditions from backup_batt_no_charging to main_batt_no_charging */
static int sync_bak_to_main_no_chg_pending(void)
{
	return (!is_batt_present || is_main_soc_done);
}

static void batt_capacity_monitor_work(struct work_struct *work)
{
	int main_capacity, back_capacity;

	main_capacity = get_main_batt_capacity();
	back_capacity = get_backup_batt_capacity();
	if (g_count == 1) {
		g_main_voltage = get_main_batt_voltage();
		g_count++;
	}

	g_main_capacity = main_capacity;
	g_back_capacity = back_capacity;
	
	if ((main_capacity > 0) && (back_capacity <= 5)) {
		if (!is_main_soc_done) {
			is_main_soc_done = true;
			wake_up(&sync_batt_state_wq); 
		}
	} else {
		is_main_soc_done = false;
	}

	if ((back_capacity > 0) && (back_capacity < 100)) {
		if (!is_back_soc_done) {
			is_back_soc_done = true;
			wake_up(&sync_batt_state_wq);  
		}
	} else {
		is_back_soc_done = false;
	}
	
	pr_debug("backbat_nocharging work, main_capacity: %d  back_capacity: %d  g_main_voltage: %d\n", main_capacity, back_capacity, g_main_voltage);

	schedule_delayed_work(&batt_capacity_c_work,
		msecs_to_jiffies(CAPACITY_CHECK_PERIOD_MS));
}

BAT_STATE_T backbat_nocharging_entry(BAT_STATE_T *prev_state)
{
	BAT_STATE_T bat_state = BAT_STATE_BAK_NOCHG;
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

	/* Just for first boost status */
	if (boost_flag) {
		boost_flag = false;
		if (is_chg_enabled) {
			bat_state = BAT_STATE_BAK_CHG;
			printk("%s boost to back charging\n", __func__);
			return bat_state;
		}
	}

    /* Init is_soc_done in case of capacity condition switch error */
	is_main_soc_done = false;
	is_back_soc_done = false;

	/* Record the main battery voltage for bms after switch to backup battery */
	g_count = 1;
	g_main_voltage = get_main_batt_voltage();
	
	/* Init a work for battery capacity monitor. */
	INIT_DELAYED_WORK(&batt_capacity_c_work, batt_capacity_monitor_work);
	schedule_delayed_work(&batt_capacity_c_work,
		msecs_to_jiffies(CAPACITY_CHECK_PERIOD_MS));
#if BATT_DEBUG
	bat_state_change_pending = 0;
	wait_event(bat_state_q, bat_state_change_pending);
	if (bat_state_change_pending == (BAT_STATE_BAK_CHG + 1))
		bat_state = BAT_STATE_BAK_CHG;
	else if (bat_state_change_pending == (BAT_STATE_MAIN_NOCHG + 1))
		bat_state = BAT_STATE_MAIN_NOCHG;
#endif
	pr_debug("%s exit, enter bat_state: %d\n", __func__, bat_state);
	return bat_state;
}

BAT_STATE_T backbat_nocharging_handle(BAT_STATE_T *prev_state)
{
	BAT_STATE_T bat_state = BAT_STATE_BAK_CHG;
	/* Judge ACTION:
	 * 1.   Charging plugin
	 *
	 *   ENTER state BAT_STATE_BAK_CHG
	 *
	 * 2.   (Backbat plugout)
	 *   or Electricity((main > back) & (back < 40%))
	 *
	 *   ENTER state BAT_STATE_MAIN_NOCHG
	 */
	pr_debug("%s enter\n", __func__);
#if BATT_DEBUG
wait_change:
	bat_state_change_pending = 0;
	wait_event(bat_state_q, bat_state_change_pending);
	if (bat_state_change_pending == (BAT_STATE_BAK_CHG + 1))
		bat_state = BAT_STATE_BAK_CHG;
	else if (bat_state_change_pending == (BAT_STATE_MAIN_NOCHG + 1))
		bat_state = BAT_STATE_MAIN_NOCHG;
	else
		goto wait_change;
#endif
wait_change:
	wait_event(sync_batt_state_wq, 
		sync_bak_to_bak_chg_pending() || 
		sync_bak_to_main_no_chg_pending() ||
		exit_batt_machine_thread);
	if (sync_bak_to_bak_chg_pending())
		bat_state = BAT_STATE_BAK_CHG;
	else if (sync_bak_to_main_no_chg_pending()) {
		bat_state = BAT_STATE_MAIN_NOCHG;
		bak_to_main = 1;
		main_to_bak = 0;
	}
	else if (exit_batt_machine_thread)
		bat_state = BAT_STATE_BAK_NOCHG;
	else
		goto wait_change;
	pr_debug("%s exit\n", __func__);
	return bat_state;
}

BAT_STATE_T backbat_nocharging_exit(BAT_STATE_T *prev_state)
{
	BAT_STATE_T bat_state = BAT_STATE_BAK_NOCHG;
	/* Stop Tickel charging */
	
    cancel_delayed_work_sync(&batt_capacity_c_work);
	pr_debug("%s\n", __func__);
	return bat_state;
}
