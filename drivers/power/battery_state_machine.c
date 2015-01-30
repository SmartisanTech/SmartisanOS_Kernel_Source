/*
 * drivers/power/module/battery_state_machine.c
 *
 *
 */

#include <linux/err.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/device.h>
#include <linux/notifier.h>
#include <linux/power_supply.h>
#include <linux/power/battery_state_machine.h>

#define BATT_BUFF_SIZE 50
static char state_buf[50];
static BAT_STATE_T batt_cur_state = BAT_STATE__NUM_STATES;
static struct class *bat_class;
static struct task_struct *battery_task;

#if BATT_DEBUG
/* Debug available */
wait_queue_head_t bat_state_q;
int bat_state_change_pending = 0;
#endif

/* Available about status switch condition */
bool is_chg_enabled = false;
bool is_batt_present = false;
bool is_chg_done = false;
int exit_batt_machine_thread = 0;
int g_main_capacity = 0;
int g_back_capacity = 0;
int g_main_voltage = 0;
int g_back_voltage = 0;
int main_to_bak = 0;
int bak_to_main = 0;
bool boost_flag = true;
#if 0
/* State machine delay 10s work*/
#define STATE_MACHINE_DELAY_MS	10000
/* Battery state machine work schedule */
struct delayed_work		batt_state_machine_work; 
#endif
/* Notifier and wait queue */
wait_queue_head_t sync_batt_state_wq;
ATOMIC_NOTIFIER_HEAD(batt_state_chg_notifier_list);

/* Structure defining format of state table entries */
typedef struct
{
    /* Pointer to state event/timeout handler function */
    BAT_STATE_T (*handler)(BAT_STATE_T *state);

    /* Pointer to state entry function */
    BAT_STATE_T (*entry_function)(BAT_STATE_T *prev_state);

    /* Pointer to state exit function */
    BAT_STATE_T (*exit_function)(BAT_STATE_T *next_state);
} STATE_TABLE_ENTRY_T;

/* BAT accessory detection state table */
static const STATE_TABLE_ENTRY_T state_table[BAT_STATE__NUM_STATES] =
{
    /*Handler Function               Entry Function            Exit Function           */
    /**************************only main battery online**********************/
    { mainbat_nocharging_handle,     mainbat_nocharging_entry, mainbat_nocharging_exit },
    /**************************main and back battery online******************/
    { backbat_nocharging_handle,     backbat_nocharging_entry, backbat_nocharging_exit },
    /**************************charging state********************************/
	{ mainbat_charging_handle,       mainbat_charging_entry,   mainbat_charging_exit },
	{ backbat_charging_handle,       backbat_charging_entry,   backbat_charging_exit },
};

/***************** Get main battery and backup battery property functions *****************/
int get_main_batt_voltage(void)
{
	union power_supply_propval ret = {0,};
	struct power_supply		*main_batt_psy;
	
	main_batt_psy = power_supply_get_by_name("main_battery");
	if (!main_batt_psy) {
		pr_err("main_battery supply not found deferring probe\n");
		return -EINVAL;
	}	

	main_batt_psy->get_property(main_batt_psy,
			  POWER_SUPPLY_PROP_VOLTAGE_NOW, &ret);
	
	return ret.intval;
}

int get_backup_batt_voltage(void)
{
	union power_supply_propval ret = {0,};
	struct power_supply		*back_batt_psy;
	
	back_batt_psy = power_supply_get_by_name("back_battery");
	if (!back_batt_psy) {
		pr_err("back_battery supply not found.\n");
		return -EINVAL;
	}	

	back_batt_psy->get_property(back_batt_psy,
			  POWER_SUPPLY_PROP_VOLTAGE_NOW, &ret);
	
	return ret.intval;
}

int get_main_batt_capacity(void)
{
	union power_supply_propval ret = {0,};
	struct power_supply		*main_batt_psy;
	
	main_batt_psy = power_supply_get_by_name("main_battery");
	if (!main_batt_psy) {
		pr_err("main_battery supply not found.\n");
		return -EINVAL;
	}	

	main_batt_psy->get_property(main_batt_psy,
			  POWER_SUPPLY_PROP_CAPACITY, &ret);
	
	return ret.intval;
}

int get_backup_batt_capacity(void)
{
	union power_supply_propval ret = {0,};
	struct power_supply		*back_batt_psy;
	
	back_batt_psy = power_supply_get_by_name("back_battery");
	if (!back_batt_psy) {
		pr_err("back_battery supply not found.\n");
		return -EINVAL;
	}	

	back_batt_psy->get_property(back_batt_psy,
			  POWER_SUPPLY_PROP_CAPACITY, &ret);
	
	return ret.intval;
}

int get_main_batt_health(void)
{
	union power_supply_propval ret = {0,};
	struct power_supply		*main_batt_psy;
	
	main_batt_psy = power_supply_get_by_name("main_battery");
	if (!main_batt_psy) {
		pr_err("main_battery supply not found.\n");
		return -EINVAL;
	}	

	main_batt_psy->get_property(main_batt_psy,
			  POWER_SUPPLY_PROP_HEALTH, &ret);
	
	return ret.intval;
}

int get_backup_batt_health(void)
{
	union power_supply_propval ret = {0,};
	struct power_supply		*back_batt_psy;
	
	back_batt_psy = power_supply_get_by_name("back_battery");
	if (!back_batt_psy) {
		pr_err("backup_battery supply not found.\n");
		return -EINVAL;
	}	

	back_batt_psy->get_property(back_batt_psy,
			  POWER_SUPPLY_PROP_HEALTH, &ret);
	
	return ret.intval;
}

static int get_batt_machine_state(void)
{
	switch (batt_cur_state)
    {
		case BAT_STATE_MAIN_NOCHG:
            strcpy(state_buf, "main_nocharging");
			break;
        case BAT_STATE_BAK_NOCHG:
            strcpy(state_buf, "back_nocharging");
			break;
        case BAT_STATE_MAIN_CHG:
            strcpy(state_buf, "main_charging");
			break;
  	    case BAT_STATE_BAK_CHG:
			strcpy(state_buf, "back_charging");
			break;
		default:
            strcpy(state_buf, "unknown_state");
            break;
    }
	return 0;
}

/******************** Battery state machine main thread ********************/
static int battery_state_machine_thread(void *unused)
//static void battery_state_machine_work(struct work_struct *work)
{
	BAT_STATE_T current_state;
    BAT_STATE_T next_state;
	BAT_STATE_T prev_state;
#if BATT_DEBUG
	init_waitqueue_head(&bat_state_q);
#endif
    init_waitqueue_head(&sync_batt_state_wq);
    current_state = BAT_STATE__NUM_STATES;
	prev_state = BAT_STATE__NUM_STATES;

	/* Workaround: we have to wait here for correct ocv */
	msleep(30000);
    /* first time enter, get battery boot state */
	current_state = bat_boot_firsttime_entry();
	printk("Enter battery_state_machine_thread.\n");
	//return 0;
	while ( 1 )
	{
		/* Update the global variable */
		batt_cur_state = current_state;
		printk("%s: current_state = %x\n", __func__, current_state);
		if (state_table[current_state].entry_function != NULL)
			next_state = state_table[current_state].entry_function(&prev_state);
		if (next_state != current_state)
		{ 
			/* state changed in entry */
            /* Store the previous state */
            prev_state = current_state;
            
            /* Update the state variable */
            current_state = next_state;
        }
		else
		{
			/* state no change in entry */
            if (state_table[current_state].handler != NULL)
            {
                /* handle sys message */
                next_state = state_table[current_state].handler(&prev_state);
		pr_debug("%s: next_state = %x\n", __func__, next_state);
            }

            if (state_table[current_state].exit_function != NULL)
            {
                /* Exit the current state and stop trickle charger */
                state_table[current_state].exit_function(&prev_state);
            }

            /* Update the state variable */
            current_state = next_state;		
		}
		if (kthread_should_stop() || exit_batt_machine_thread) {
			printk("Exit %s\n", __func__);
			break;
		}
	}
	/* Should never reach this point */
	return 0;
}

/*************************** Debug sysfs interface ********************************/
static ssize_t battery_sysfs_state_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	int ret;
	unsigned int input;

	if (sscanf(buf, "%u", &input) != 1) {
		ret = -EINVAL;
		return ret;
	}

#if BATT_DEBUG
	bat_state_change_pending = input;
	printk("%s: input = %x\n", __func__, input);
	wake_up(&bat_state_q);
#endif
	ret = count;

	return ret;
}

static struct device_attribute attrs[] = {
	__ATTR(battery_state, S_IWUGO, NULL, battery_sysfs_state_store),
};

static ssize_t batt_machine_state_show(struct device *dev, 
		struct device_attribute *attr, char *buf)
{
	get_batt_machine_state();
	return snprintf(buf, BATT_BUFF_SIZE, "%s\n", state_buf);
}

static ssize_t batt_current_used_show(struct device *dev, 
		struct device_attribute *attr, char *buf)
{
	char batt_name[BATT_BUFF_SIZE];

	if (current_used_batt)
		strcpy(batt_name, "Main_battery");
	else
		strcpy(batt_name, "Back_battery");

	return snprintf(buf, BATT_BUFF_SIZE, "%s\n", batt_name);
}

/* Use below sysfs carefully, just be opened during debugging */
static ssize_t batt_machine_thread_show(struct device *dev, 
		struct device_attribute *attr, char *buf)
{
	char batt_thread_state[BATT_BUFF_SIZE];

	if (exit_batt_machine_thread)
		strcpy(batt_thread_state, "killed");
	else
		strcpy(batt_thread_state, "alive");
	
	return snprintf(buf, BATT_BUFF_SIZE, "%s\n", batt_thread_state);
}

static ssize_t batt_machine_thread_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	if (!strncmp(buf, "kill", 4)) {
		//kthread_stop(battery_task);
		exit_batt_machine_thread = 1;
	    wake_up(&sync_batt_state_wq);
	}
    else 
		printk("Error command, please input 'kill' to kill the main thread.\n");

	return count;
}
//Just for test
#if 0
static ssize_t batt_machine_main_batt_vol_show(struct device *dev, 
		struct device_attribute *attr, char *buf)
{
	int main_batt_vol_now;
	main_batt_vol_now = get_main_batt_voltage();
	
	return snprintf(buf, BATT_BUFF_SIZE, "%d\n", main_batt_vol_now);
}

static ssize_t batt_machine_main_batt_soc_show(struct device *dev, 
		struct device_attribute *attr, char *buf)
{
	int main_batt_soc_now;
	main_batt_soc_now = get_main_batt_capacity();
		
	return snprintf(buf, BATT_BUFF_SIZE, "%s\n", main_batt_soc_now);
}
#endif 
static struct device_attribute battery_class_attrs[] = {
	__ATTR(batt_machine_state, 0444, batt_machine_state_show, NULL),
	__ATTR(batt_current_used, 0444, batt_current_used_show, NULL),
	//__ATTR(main_voltage, 0444, batt_machine_main_batt_vol_show, NULL),
	//__ATTR(main_capacity, 0444, batt_machine_main_batt_soc_show, NULL),
	__ATTR(batt_machine_thread, 0644, batt_machine_thread_show, batt_machine_thread_store),
	__ATTR_NULL,
};

/************************ External notifications parse functions *******************/
static int parse_state_chg_block(struct notifier_block *this,
		unsigned long event, void *ptr)
{
	int ret = NOTIFY_OK;
	/* Once charge state change or back battery is pluged in or pluged out,
	 * we should receive all these notifications. 
	 */
    switch (event)
    {
	case CHARGE_PLUGIN_EVENT:
			is_chg_enabled = true;
			wake_up(&sync_batt_state_wq);
			break;
        case CHARGE_PLUGOUT_EVENT:
			is_chg_enabled = false;
			is_chg_done = false;
			wake_up(&sync_batt_state_wq);
			break;
        case CHARGE_TRKL_EVENT:
        case CHARGE_FAST_EVENT:
			is_chg_done = false;
			wake_up(&sync_batt_state_wq);
			break;
        case CHARGE_DONE_EVENT:
			is_chg_done = true;
			wake_up(&sync_batt_state_wq);
			break;
        case BAKBATT_PLUGIN_EVENT:
			is_batt_present = true;
			if (is_chg_enabled)
				atomic_notifier_call_chain(&switch_notifier_list, 0, "back-bat-on");
			wake_up(&sync_batt_state_wq);
			break;
        case BAKBATT_PLUGOUT_EVENT:
			is_batt_present = false;
			wake_up(&sync_batt_state_wq);
			break;
	default:
			pr_err("Invalid batt change event, do nothing.\n");
			ret = NOTIFY_DONE;
			break;
    }

    pr_info("%s Received event type: %d\n", __func__, (int)event);
    return ret;
}


static struct notifier_block parse_state_chg_blk = {
	.notifier_call = parse_state_chg_block,
};

/*!
 * @brief Initializes the battery accessory detection state machine
 *
 * The function performs any initialization required to get the battery
 * accessory detection state machine running.  This includes registering
 * for the required power IC events and starting the kernel thread.
 */
int __init battery_init(void)
{
	int ret = 0;

	printk("battery_init\n");
	bat_class = class_create(THIS_MODULE, "battery");
	bat_class->dev_attrs = battery_class_attrs;
	//bat_class->dev_attrs = attrs[0];
	device_create(bat_class, NULL, 1000, NULL, "battery_state_dev");
	printk("add init code if need\n");
	/* Create sys node */
	ret = sysfs_create_file(bat_class->dev_kobj, &attrs[0].attr);
	if (ret) {
		printk("bat sysfs_create_file failed\n");
	}
	
	/* Register a call for charger enable or back battery remove conditions. */
	atomic_notifier_chain_register(&batt_state_chg_notifier_list, &parse_state_chg_blk);
#if 0
	/* Init a work for battery state machine. */
	INIT_DELAYED_WORK(&batt_state_machine_work, battery_state_machine_work);
	schedule_delayed_work(&batt_state_machine_work,
		msecs_to_jiffies(STATE_MACHINE_DELAY_MS));
#else
	/* Create thread */
	battery_task = kthread_run(battery_state_machine_thread, NULL, "bat_state_thread");
	if(IS_ERR(battery_task)){  
		printk("Unable to start battery thread\n");  
		ret = PTR_ERR(battery_task);  
		battery_task = NULL;  
		return ret;  
	} 
#endif
	return ret;
}

void __exit battery_exit(void)
{
	printk("add exit code if need\n");
	kthread_stop(battery_task);
	atomic_notifier_chain_unregister(&batt_state_chg_notifier_list,&parse_state_chg_blk);
	device_destroy(bat_class, 0);
	class_destroy(bat_class);
	//cancel_delayed_work_sync(&batt_state_machine_work);
    /* Create thread */
    //kernel_thread(battery_state_machine_thread, NULL, 0);
}

module_init(battery_init);
module_exit(battery_exit);
MODULE_LICENSE("GPL v2");
