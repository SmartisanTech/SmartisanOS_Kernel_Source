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

#define DELAY_SOC 0

static bool is_main_soc_done = false;
static bool is_back_soc_done = false;
/* Battery capacity work schedule */
struct delayed_work		batt_capacity_a_work;   /*mainbat_nocharging*/
/* Check battery capacity every 10 seconds */
#define CAPACITY_CHECK_PERIOD_MS	10000

/* Conditions from main_batt_no_charging to backup_no_charging */
static int sync_main_to_bak_nochg_pending(void)
{
	return is_batt_present && is_back_soc_done;
}

/* Conditions from main_batt_no_charging to main_batt_charging */
static int sync_main_to_main_chg_pending(void)
{
	return (is_chg_enabled && (g_main_capacity <= 100)) ||
		(is_main_soc_done && !is_chg_done && is_chg_enabled);
}

static void batt_capacity_monitor_work(struct work_struct *work)
{
	int main_capacity, back_capacity;

	main_capacity = get_main_batt_capacity();
	back_capacity = get_backup_batt_capacity();

	g_main_capacity = main_capacity;
	g_back_capacity = back_capacity;
	
	if ((main_capacity > 0) && (main_capacity < 100)) {
		if (!is_main_soc_done) {
			is_main_soc_done = true;
			wake_up(&sync_batt_state_wq);
		}
	} else {
		is_main_soc_done = false;
	}
	
	if (back_capacity > 5) {
		if (!is_back_soc_done) {
			is_back_soc_done = true;
			wake_up(&sync_batt_state_wq);
		}
	} else {
		is_back_soc_done = false;
	}

	pr_debug("mainbat_nocharging work, main_capacity: %d  back_capacity: %d\n", main_capacity, back_capacity);

	schedule_delayed_work(&batt_capacity_a_work,
		msecs_to_jiffies(CAPACITY_CHECK_PERIOD_MS)); 
}

BAT_STATE_T mainbat_nocharging_entry(BAT_STATE_T *prev_state)
{
	BAT_STATE_T bat_state = BAT_STATE_MAIN_NOCHG;
	/* FIRST TO DO:
	 * init mainbat_nocharging state
	 * sw_ctl = ?; bb_lock = ?
	 * ...
	 */
	if (get_backup_batt_switch_status())
		set_sw_ctrl_2nd_batt_switch("off");

	/* SECOND TO DO:
	 * Judge state change ? If changed, change bat_state
	 * bat_state = BAT_STATE_?
	 */
	pr_debug("%s enter\n", __func__);
	/* Just for first boost status */
	if (boost_flag) {
		boost_flag = false;
		if (is_chg_enabled) {
			bat_state = BAT_STATE_MAIN_CHG;
			printk("%s boost to main charging\n", __func__);
			return bat_state;
		}
	}

	/* Init is_soc_done in case of capacity condition switch error */
	is_main_soc_done = false;
	is_back_soc_done = false;
	
	/* Init a work for battery capacity monitor. */
	INIT_DELAYED_WORK(&batt_capacity_a_work, batt_capacity_monitor_work);
	schedule_delayed_work(&batt_capacity_a_work,
		msecs_to_jiffies(CAPACITY_CHECK_PERIOD_MS));
#if BATT_DEBUG
	bat_state_change_pending = 0;
	wait_event(bat_state_q, bat_state_change_pending);
	if (bat_state_change_pending == (BAT_STATE_BAK_NOCHG + 1))
		bat_state = BAT_STATE_BAK_NOCHG;
	else if (bat_state_change_pending == (BAT_STATE_MAIN_CHG + 1))
		bat_state = BAT_STATE_MAIN_CHG;
#endif
	pr_debug("%s exit\n", __func__);
	return bat_state;
}

BAT_STATE_T mainbat_nocharging_handle(BAT_STATE_T *prev_state)
{
	BAT_STATE_T bat_state = BAT_STATE_MAIN_NOCHG;
	/* Judge ACTION:
	 * 1.   (Charging plugin) & (Electricity(main < full))
	 *
	 *   ENTER state BAT_STATE_MAIN_CHG
	 *
	 * 2.   (Backbat plugin) & (Electricity(back > 40%))
	 *   or (backbat plugin) & (Electricity(main < back))
	 *
	 *   ENTER state BAT_STATE_BAK_NOCHG
	 */
	pr_debug("%s enter\n", __func__);
#if BATT_DEBUG
wait_change:
	bat_state_change_pending = 0;
	wait_event(bat_state_q, bat_state_change_pending);
	if (bat_state_change_pending == (BAT_STATE_MAIN_CHG + 1))
		bat_state = BAT_STATE_MAIN_CHG;
	else if (bat_state_change_pending == (BAT_STATE_BAK_NOCHG + 1))
		bat_state = BAT_STATE_BAK_NOCHG;
	else
		goto wait_change;
#endif
wait_change:
	wait_event(sync_batt_state_wq, 
		sync_main_to_main_chg_pending() || 
		sync_main_to_bak_nochg_pending() ||
		exit_batt_machine_thread);
	if (sync_main_to_main_chg_pending())
		bat_state = BAT_STATE_MAIN_CHG;
	else if (sync_main_to_bak_nochg_pending()) {
		bat_state = BAT_STATE_BAK_NOCHG;
		main_to_bak = 1;
		bak_to_main = 0;
	}
	else if (exit_batt_machine_thread)
		bat_state = BAT_STATE_MAIN_NOCHG;
	else
		goto wait_change;
	pr_debug("%s exit, enter bat_state: %d\n", __func__, bat_state);
	return bat_state;
}

BAT_STATE_T mainbat_nocharging_exit(BAT_STATE_T *prev_state)
{
	BAT_STATE_T bat_state = BAT_STATE_MAIN_NOCHG;
	/* Stop Tickel charging */

	cancel_delayed_work_sync(&batt_capacity_a_work);
	pr_debug("%s\n", __func__);
	return bat_state;
}
