#ifndef __LINUX_BATTERY_SWITCH_H__
#define __LINUX_BATTERY_SWITCH_H__

extern int get_backup_batt_switch_status(void);
extern int set_bb_lock_switch(char *status);
extern int set_sw_ctrl_2nd_batt_switch(char *status);
extern int set_trcc_en_switch(char *status);
extern int set_trcc_en_2nd_switch(char *status);
extern int get_trcc_en_switch_status(void);
extern int get_trcc_en_2nd_switch_status(void);

#endif
