#ifndef __BAT_H__
#define __BAT_H__

/*
 * @file battery_state_machine.h
 *
 * @brief This file contains defines, macros and prototypes for the BAT
 * detection state machine.
 *
 */ 
#include <linux/sched.h>
#include <linux/power/battery_common.h>
#include <linux/power/battery_switch.h>

#define BATT_DEBUG  0

/* Defines all available BAT detection states */
typedef enum
{
	BAT_STATE_MAIN_NOCHG,    /*0*/
	BAT_STATE_BAK_NOCHG,     /*1*/ 
	BAT_STATE_MAIN_CHG,      /*2*/
	BAT_STATE_BAK_CHG,       /*3*/
	BAT_STATE__NUM_STATES
} BAT_STATE_T;

/* Available about status switch condition */
extern bool is_chg_enabled;
extern bool is_batt_present;
extern bool is_chg_done;
extern int exit_batt_machine_thread;
extern int g_main_capacity;
extern int g_back_capacity;
extern bool boost_flag;

extern wait_queue_head_t sync_batt_state_wq;

/***************************** BATT PROPERTY STATE FUNTIONS ****************************/
int get_main_batt_voltage(void);
int get_backup_batt_voltage(void);
int get_main_batt_capacity(void);
int get_backup_batt_capacity(void);

/************************** BACK BAT CONNECTED STATE FUNTIONS **************************/
BAT_STATE_T bat_first_time_entry(BAT_STATE_T *prev_state);

/************************** BACK BAT CONNECTED STATE FUNTIONS **************************/
BAT_STATE_T mainbat_nocharging_entry(BAT_STATE_T *prev_state);
BAT_STATE_T mainbat_nocharging_handle(BAT_STATE_T *prev_state);
BAT_STATE_T mainbat_nocharging_exit(BAT_STATE_T *prev_state);

/************************** BACK BAT CONNECTED STATE FUNTIONS **************************/
BAT_STATE_T backbat_nocharging_entry(BAT_STATE_T *prev_state);
BAT_STATE_T backbat_nocharging_handle(BAT_STATE_T *prev_state);
BAT_STATE_T backbat_nocharging_exit(BAT_STATE_T *prev_state);

/************************** BACK BAT CONNECTED STATE FUNTIONS **************************/
BAT_STATE_T mainbat_charging_entry(BAT_STATE_T *prev_state);
BAT_STATE_T mainbat_charging_handle(BAT_STATE_T *prev_state);
BAT_STATE_T mainbat_charging_exit(BAT_STATE_T *prev_state);

/************************** BACK BAT CONNECTED STATE FUNTIONS **************************/
BAT_STATE_T backbat_charging_entry(BAT_STATE_T *prev_state);
BAT_STATE_T backbat_charging_handle(BAT_STATE_T *prev_state);
BAT_STATE_T backbat_charging_exit(BAT_STATE_T *prev_state);

/************************** BOOT STATE FUNTIONS **************************/
BAT_STATE_T bat_boot_firsttime_entry(void);
#endif /* __BAT_H__ */
