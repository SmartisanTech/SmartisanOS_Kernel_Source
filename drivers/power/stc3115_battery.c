/*
 *  stc3115_battery.c 
 *  fuel-gauge systems for lithium-ion (Li+) batteries
 *
 *  Copyright (C) 2011 STMicroelectronics.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/mutex.h>
#include <linux/err.h>
#include <linux/i2c.h>
#include <linux/irq.h>
#include <linux/delay.h>
#include <linux/power_supply.h>
#include <linux/slab.h>
#include <linux/gpio.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/of_device.h>
#include <mach/socinfo.h>
#include <linux/power/battery_common.h>
#include <linux/power/battery_switch.h>


#define USE_WAKE_LOCK

#ifdef USE_WAKE_LOCK
#include <linux/wakelock.h>
#endif

#define GG_VERSION "2.00a"

/*Function declaration*/
int STC31xx_SetPowerSavingMode(void);
int STC31xx_StopPowerSavingMode(void);
int STC31xx_AlarmSet(void);
int STC31xx_AlarmStop(void);
int STC31xx_AlarmGet(void);
int STC31xx_AlarmClear(void);
int STC31xx_AlarmSetVoltageThreshold(int VoltThresh);
int STC31xx_AlarmSetSOCThreshold(int SOCThresh);
int STC31xx_RelaxTmrSet(int CurrentThreshold);
int STC31xx_ForceCC(void);



/* ******************************************************************************** */
/*        STC311x DEVICE SELECTION                                                  */
/* STC3115 version only                                                             */
/* -------------------------------------------------------------------------------- */
#define STC3115 
#define BATD_UC8
/* ******************************************************************************** */




/* Private define ------------------------------------------------------------*/


/* ******************************************************************************** */
/*        SPECIAL FUNCTIONS                                                         */
/* -------------------------------------------------------------------------------- */
/*                                                                                  */
/* define TEMPCOMP_SOC to enable SOC temperature compensation */
#define TEMPCOMP_SOC

/* ******************************************************************************** */


/* ******************************************************************************** */
/*        INTERNAL PARAMETERS                                                       */
/*   TO BE ADJUSTED ACCORDING TO BATTERY/APPLICATION CHARACTERISTICS                */
/* -------------------------------------------------------------------------------- */
/*                                                                                  */
#define BATT_CHG_VOLTAGE   (4350 - 45)   /* min voltage at the end of the charge (mV)      */
#define BATT_MIN_VOLTAGE   3400   /* nearly empty battery detection level (mV)      */
#define MAX_HRSOC          51200  /* 100% in 1/512% units*/
#define MAX_SOC            1000   /* 100% in 0.1% units */
/*                                                                                  */
#define CHG_MIN_CURRENT     200   /* min charge current in mA                       */
#define CHG_END_CURRENT     125   /* end charge current in mA                       */
#define APP_MIN_CURRENT     (-5)  /* minimum application current consumption in mA ( <0 !) */
#define APP_MIN_VOLTAGE	    3000  /* application cut-off voltage                    */
#define TEMP_MIN_ADJ		 (-5) /* minimum temperature for gain adjustment */

#define VMTEMPTABLE        { 85, 90, 100, 160, 320, 440, 840 }  /* normalized VM_CNF at 60, 40, 25, 10, 0, -10?C, -20?C */

#define AVGFILTER           4  /* average filter constant */

/* ******************************************************************************** */



/* Private define ------------------------------------------------------------*/

#define STC31xx_SLAVE_ADDRESS            0xE0   /* STC31xx 8-bit address byte */

/*Address of the STC311x register --------------------------------------------*/
#define STC311x_REG_MODE                 0x00    /* Mode Register             */
#define STC311x_REG_CTRL                 0x01    /* Control and Status Register */
#define STC311x_REG_SOC                  0x02    /* SOC Data (2 bytes) */
#define STC311x_REG_COUNTER              0x04    /* Number of Conversion (2 bytes) */
#define STC311x_REG_CURRENT              0x06    /* Battery Current (2 bytes) */
#define STC311x_REG_VOLTAGE              0x08    /* Battery Voltage (2 bytes) */
#define STC311x_REG_TEMPERATURE          0x0A    /* Temperature               */
#define STC311x_REG_CC_ADJ_HIGH          0x0B    /* CC adjustement     */
#define STC311x_REG_VM_ADJ_HIGH          0x0C    /* VM adjustement     */
#define STC311x_REG_CC_ADJ_LOW           0x19    /* CC adjustement     */
#define STC311x_REG_VM_ADJ_LOW           0x1A    /* VM adjustement     */
#define STC311x_ACC_CC_ADJ_HIGH          0x1B    /* CC accumulator     */
#define STC311x_ACC_CC_ADJ_LOW           0x1C    /* CC accumulator     */
#define STC311x_ACC_VM_ADJ_HIGH          0x1D    /* VM accumulator     */
#define STC311x_ACC_VM_ADJ_LOW           0x1E    /* VM accumulator     */
#define STC311x_REG_OCV                  0x0D    /* Battery OCV (2 bytes) */
#define STC311x_REG_CC_CNF               0x0F    /* CC configuration (2 bytes)    */
#define STC311x_REG_VM_CNF               0x11    /* VM configuration (2 bytes)    */
#define STC311x_REG_ALARM_SOC            0x13    /* SOC alarm level         */
#define STC311x_REG_ALARM_VOLTAGE        0x14    /* Low voltage alarm level */
#define STC311x_REG_CURRENT_THRES        0x15    /* Current threshold for relaxation */
#define STC311x_REG_RELAX_COUNT          0x16    /* Voltage relaxation counter   */
#define STC311x_REG_RELAX_MAX            0x17    /* Voltage relaxation max count */

/*Bit mask definition*/
#define STC311x_VMODE   		 0x01	 /* Voltage mode bit mask     */
#define STC311x_ALM_ENA			 0x08	 /* Alarm enable bit mask     */
#define STC311x_ALM_ACTIVE		 0x01	 /* Reg Ctrl IO0DATA: Alarm is driver by the alarm conditions */
#define STC311x_ALM_INT_CLR	         0x60	 /* Alarm interrupts clear bits */
#define STC311x_GG_RUN			 0x10	 /* Set 1: Operating mode; set 0: Standby mode */
#define STC311x_FORCE_CC		 0x20	 /* Force CC bit mask     */
#define STC311x_FORCE_VM		 0x40	 /* Force VM bit mask     */
#define STC311x_SOFTPOR 		 0x11	 /* soft reset     */
#define STC311x_CLR_VM_ADJ   0x02  /* Clear VM ADJ register bit mask */
#define STC311x_CLR_CC_ADJ   0x04  /* Clear CC ADJ register bit mask */

#define STC311x_REG_ID                   0x18    /* Chip ID (1 byte)       */
#define STC311x_ID                       0x13    /* STC3115 ID */
#define STC311x_ID_2                     0x14    /* STC3115 ID */

#define STC311x_REG_RAM                  0x20    /* General Purpose RAM Registers */
#define RAM_SIZE                         16      /* Total RAM size of STC3115 in bytes */

#define STC311x_REG_OCVTAB               0x30
#define OCVTAB_SIZE                      16      /* OCVTAB size of STC3115 in bytes */

#define VCOUNT				 4       /* counter value for 1st current/temp measurements */


#define M_STAT 0x1010       /* GG_RUN & PORDET mask in STC311x_BattDataTypeDef status word */
#define M_RST  0x1800       /* BATFAIL & PORDET mask */
#define M_RUN  0x0010       /* GG_RUN mask in STC311x_BattDataTypeDef status word */
#define M_GGVM 0x0400       /* GG_VM mask */
#define M_BATFAIL 0x0800    /* BATFAIL mask*/
#define M_VMOD 0x0001       /* VMODE mask */

#define OK 0

/* Battery charge state definition for BattState */
#define  BATT_CHARGING  3
#define  BATT_ENDCHARG  2
#define  BATT_FULCHARG  1
#define  BATT_IDLE      0
#define  BATT_DISCHARG (-1)
#define  BATT_LOWBATT  (-2)

/* STC311x RAM test word */
#define RAM_TSTWORD 0x53A9

/* Gas gauge states */
#define GG_INIT     'I'
#define GG_RUNNING  'R'
#define GG_POWERDN  'D'

#define VM_MODE 1
#define CC_MODE 0



/* gas gauge structure definition ------------------------------------*/

/* Private constants ---------------------------------------------------------*/

#define NTEMP 7
static const int TempTable[NTEMP] = {60, 40, 25, 10, 0, -10, -20} ;   /* temperature table from 60?C to -20?C (descending order!) */
static const int DefVMTempTable[NTEMP] = VMTEMPTABLE;

/* Private variables ---------------------------------------------------------*/

/* structure of the STC311x battery monitoring parameters */
typedef struct  {
  int Voltage;        /* battery voltage in mV */
  int Current;        /* battery current in mA */
  int Temperature;    /* battery temperature in 0.1?C */
  int SOC;            /* battery relative SOC (%) in 0.1% */
  int OCV;
  int AvgSOC;
  int AvgCurrent;
  int AvgVoltage;
  int AvgTemperature;
  int ChargeValue;    /* remaining capacity in mAh */
  int RemTime;        /* battery remaining operating time during discharge (min) */
  int State;          /* charge (>0)/discharge(<0) state */
  int CalStat;        /* Internal status */
  /* -- parameters -- */
  int Vmode;       /* 1=Voltage mode, 0=mixed mode */
  int Alm_SOC;     /* SOC alm level */
  int Alm_Vbat;    /* Vbat alm level */
  int CC_cnf;      /* nominal CC_cnf */
  int VM_cnf;      /* nominal VM cnf */
  int Cnom;        /* nominal capacity in mAh */
  int Rsense;      /* sense resistor */
  int RelaxCurrent; /* current for relaxation (< C/20) */
  int Adaptive;     /* adaptive mode */
  int CapDerating[NTEMP];   /* capacity derating in 0.1%, for temp = 60, 40, 25, 10,   0, -10 ?C */
  int OCVOffset[OCVTAB_SIZE];    /* OCV curve adjustment */
  int ExternalTemperature;
  int ForceExternalTemperature;
} GasGauge_DataTypeDef;

/* structure of the STC311x battery monitoring data */
typedef struct  {
  /* STC311x data */
  int STC_Status;  /* status word  */
  int Vmode;       /* 1=Voltage mode, 0=mixed mode */
  int Voltage;     /* voltage in mV            */
  int Current;     /* current in mA            */
  int Temperature; /* temperature in 0.1?C     */
  int HRSOC;       /* uncompensated SOC in 1/512%   */
  int OCV;         /* OCV in mV*/
  int ConvCounter; /* convertion counter       */
  int RelaxTimer;  /* current relax timer value */
  int CC_adj;      /* CC adj */
  int VM_adj;      /* VM adj */
  /* results & internals */
  int SOC;         /* compensated SOC in 0.1% */
  int AvgSOC;      /* in 0.1% */
  int AvgVoltage;
  int AvgCurrent;
  int AvgTemperature;
  int AccSOC;
  int AccVoltage;
  int AccCurrent;
  int AccTemperature;
  int BattState;
  int GG_Mode;     /* 1=VM active, 0=CC active */
  int LastMode;
  int LastSOC;
  int LastTemperature;
  int BattOnline;	// BATD
  int IDCode;
  /* parameters */
  int Alm_SOC;     /* SOC alm level in % */
  int Alm_Vbat;    /* Vbat alm level in mV */
  int CC_cnf;      /* nominal CC_cnf */
  int VM_cnf;      /* nominal VM cnf */
  int Cnom;        /* nominal capacity is mAh */
  int Rsense;      /* sense resistor in milliOhms */
  int CurrentFactor;
  int RelaxThreshold;   /* current threshold for VM (mA)  */
  int Adaptive;     /* adaptive mode */
  int VM_TempTable[NTEMP];
  int CapacityDerating[NTEMP];
  char OCVOffset[OCVTAB_SIZE];
} STC311x_BattDataTypeDef;

static STC311x_BattDataTypeDef BattData;   /* STC311x data */

/* structure of the STC311x RAM registers for the Gas Gauge algorithm data */
static union {
  unsigned char db[RAM_SIZE];  /* last byte holds the CRC */
  struct {
    short int TstWord;     /* 0-1 */
    short int HRSOC;       /* 2-3 SOC backup */
    short int CC_cnf;      /* 4-5 current CC_cnf */
    short int VM_cnf;      /* 6-7 current VM_cnf */
    char SOC;              /* 8 SOC for trace (in %) */
    char GG_Status;        /* 9  */
    /* bytes ..RAM_SIZE-2 are free, last byte RAM_SIZE-1 is the CRC */
  } reg;
} GG_Ram;


int Capacity_Adjust;
static struct wake_lock bat_wake_lock;

/* -------------------------------------------------------------------------------- */
/*        INTERNAL ANDROID DRIVER PARAMETERS                                        */
/*   TO BE ADJUSTED ACCORDING TO BATTERY/APPLICATION CHARACTERISTICS                */
/* -------------------------------------------------------------------------------- */

#define STC3100_BATTERY_FULL 95
#define STC311x_DELAY	(5 * HZ)
#define CAP_DERATE_MAX_NUM  7
#define OCV_CUREE_MAX_NUM   16
// wakelock timeout in second when battery plugged/unplugged occurs.
#define BAT_WAKE_LOCK_TIMEOUT 	30
#define BAT_POOR_CONNECTION_CHECK_COUNT		5
// Time interval in minutes during two bat_poor_connection_reports.
#define BAT_POOR_CONNECTION_REPORT_MINUTE		5
#define BAT_POOR_CONNECTION_REPORT_COUNTER  \
		((BAT_POOR_CONNECTION_REPORT_MINUTE * 60) / (STC311x_DELAY / HZ))
/*
  * Back Battery poor connection threshold current in mA:
  *
  * When the back battery is on and mainly used(Switch is on back battery I mean.), 
  * if the battery current is less than the threshold, we think the battery is in poor connection state.
  */
#define BAT_POOR_CONNECTION_THRES_CURRENT		10
int bat_check_counter = 0;

/* OCV adjustment and correction */
#define Ri   	181	// internal resistance(mohm)
#define MAX_BOOT_OCV_DELTA	50	// Max allowed ocv delta in mV when bootup.
#define MAX_OCV_DELTA_WITH_LOW_CURRENT	25	// Max allowed ocv delta in mV when in low current.
#define MAX_OCV_DELTA_WITH_HIGH_CURRENT	150	// Max allowed ocv delta in mV when in high current.
#define CHECK_LOW_CURRENT_THRESH	25	// Check low current thresh in mA.
#define CORRECT_OCV_CHECK_COUNT	5
static int ocv_check_count = 0;

/* ******************************************************************************** */

static struct i2c_client *sav_client;

struct stc311x_chip {
	struct i2c_client		*client;
	struct delayed_work		work;  
	struct power_supply		stc3115_psy;

	/* stc311x platform data */
	int Vmode;       /* 1=Voltage mode, 0=mixed mode */
  	int Alm_SOC;     /* SOC alm level %*/
  	int Alm_Vbat;    /* Vbat alm level mV*/
  	int CC_cnf;      /* nominal CC_cnf */
  	int VM_cnf;      /* nominal VM cnf */
  	int Cnom;        /* nominal capacity in mAh */
  	int Rsense;      /* sense resistor mOhms*/
  	int RelaxCurrent; /* current for relaxation in mA (< C/20) */
  	int Adaptive;     /* 1=Adaptive mode enabled, 0=Adaptive mode disabled */
  	int CapDerating[CAP_DERATE_MAX_NUM];   /* capacity derating in 0.1%, for temp = 60, 40, 25, 10,   0, -10 ?C,-20?C */
  	int OCVOffset[OCV_CUREE_MAX_NUM];    /* OCV curve adjustment */
  	int ForceExternalTemperature; /* 1=External temperature, 0=STC3115 temperature */
	

	/* State Of Connect */
	int online;
	/* battery SOC (capacity) */
	int batt_soc;
	/* battery voltage */
	int batt_voltage;
	/* Current */
	int batt_current;
	/* State Of Charge */
	int status;
	/* battery health */
	int health;
    /* Alarm irq gpio */
    unsigned int alm_irq;

	int (*battery_online)(void);
	int (*charger_online)(void);
	int (*charger_enable)(void);
	int (*ExternalTemperature) (void); /*External temperature fonction, return ?C*/

};

static char *stc3115_supplicants[] = {
	"back_battery"
};

static int Temperature_fn(void);

static int STC311x_ReadBatteryData(STC311x_BattDataTypeDef *BattData);

static int conv(short value, unsigned short factor);

static void stc3115_external_power_changed(struct power_supply *psy)
{
}

static int stc311x_get_property(struct power_supply *psy,
			    enum power_supply_property psp,
			    union power_supply_propval *val)
{
	struct stc311x_chip *chip = container_of(psy,
				struct stc311x_chip, stc3115_psy);

/* from power_supply.h:
 * All voltages, currents, charges, energies, time and temperatures in uV,
 * µA, µAh, µWh, seconds and tenths of degree Celsius unless otherwise
 * stated. It's driver's job to convert its raw values to units in which
 * this class operates.
 */

	switch (psp) {
	case POWER_SUPPLY_PROP_STATUS:
		val->intval = chip->status;
		break;
	case POWER_SUPPLY_PROP_HEALTH:
		val->intval = chip->health;
		break;
	case POWER_SUPPLY_PROP_ONLINE:
		val->intval = chip->online; //battery present
		break;
	case POWER_SUPPLY_PROP_VOLTAGE_NOW:
		val->intval = chip->batt_voltage * 1000;  /* in uV */
		break;
	case POWER_SUPPLY_PROP_CURRENT_NOW:
		val->intval = -(chip->batt_current * 1000);  /* in uA */
		break;
	case POWER_SUPPLY_PROP_CAPACITY:
		val->intval = chip->batt_soc;
		break;
	case POWER_SUPPLY_PROP_PRESENT:
		val->intval = chip->online;
        break;
	case POWER_SUPPLY_PROP_TEMP:
		val->intval = Temperature_fn();   /* in ?C */
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static void stc311x_get_version(struct i2c_client *client)
{
    dev_info(&client->dev, "STC3115 Fuel-Gauge Ver %s\n", GG_VERSION);
}

static void stc311x_get_online(struct i2c_client *client)
{
	struct stc311x_chip *chip = i2c_get_clientdata(client);

	
	if (chip->battery_online)
		chip->online = chip->battery_online();
	else
		chip->online = BattData.BattOnline;
}

static void stc311x_get_status(struct i2c_client *client)
{
	#if 0
	struct stc311x_chip *chip = i2c_get_clientdata(client);
    /*
	if (!chip->charger_online || !chip->charger_enable) {
		chip->status = POWER_SUPPLY_STATUS_UNKNOWN;
		return;
	}*/

	if (chip->charger_online && chip->charger_enable && !current_used_batt) {
		if (chip->batt_soc < MAX_SOC)
			chip->status = POWER_SUPPLY_STATUS_CHARGING;
		//Full status changed
	    if (chip->batt_soc == MAX_SOC && BattData.AvgVoltage > BATT_CHG_VOLTAGE && BattData.AvgCurrent < CHG_END_CURRENT) 
			chip->status = POWER_SUPPLY_STATUS_FULL;
	} else {
		chip->status = POWER_SUPPLY_STATUS_DISCHARGING;
	}
	#else
	static struct power_supply *backup_batt_psy;
	union power_supply_propval ret = {0,};
	struct stc311x_chip *chip = i2c_get_clientdata(client);
	
	backup_batt_psy = power_supply_get_by_name("back_battery");
	
	if (backup_batt_psy) {
		backup_batt_psy->get_property(backup_batt_psy,
			        POWER_SUPPLY_PROP_STATUS, &ret);
		chip->status = ret.intval;
		return;
		}

	pr_err("back_battery power supply is not registered.\n");
	#endif
}

static int charger_is_online(void)
{
	static struct power_supply *psy;
	union power_supply_propval ret = {0,};

	if (psy == NULL) {
		psy = power_supply_get_by_name("usb");
		if (psy  == NULL) {
			pr_err("failed to get ps usb\n");
			return -EINVAL;
		}
	}

	if (psy->get_property(psy, POWER_SUPPLY_PROP_ONLINE, &ret))
		return -EINVAL;

	if (ret.intval <= 0)
		return -EINVAL;

	return ((ret.intval == 1) ? 1: 0);
}

static int charger_is_enable(void)
{
#if 1
	static struct power_supply *backup_batt_psy;
	union power_supply_propval ret = {0,};
	backup_batt_psy = power_supply_get_by_name("back_battery");
	
	if (backup_batt_psy) {
		backup_batt_psy->get_property(backup_batt_psy,
			        POWER_SUPPLY_PROP_CHARGING_ENABLED, &ret);
		return ((ret.intval == 1) ? 1: 0);
		}

	pr_err("back_battery power supply is not registered.\n");
	return 0;
#else
	return 1;
#endif
}

static int Temperature_fn(void)
{
	struct power_supply		*backup_batt_psy;
	union power_supply_propval ret = {0,};
	backup_batt_psy = power_supply_get_by_name("back_battery");

	if (backup_batt_psy) {
			/* if battery has been registered, use the status property */
			backup_batt_psy->get_property(backup_batt_psy,
						POWER_SUPPLY_PROP_TEMP, &ret);
			return ret.intval;
		}
		/* Default to false if the bms_charging battery power supply is not registered. */
		pr_debug("back_battery power supply is not registered\n");
		return (250);
}

/* -------------------------------------------------------------------------- */
/* I2C interface */

/* -----------------------------------------------------------------
 The following routines interface with the I2C primitives 
   I2C_Read(u8_I2C_address, u8_NumberOfBytes, u8_RegAddress, pu8_RxBuffer);
   I2C_Write(u8_I2C_address, u8_NumberOfBytes, u8_RegAddress, pu8_TxBuffer);
  note: here I2C_Address is the 8-bit address byte
 ----------------------------------------------------------------- */

#define NBRETRY 5 


/*******************************************************************************
* Function Name  : STC31xx_Write
* Description    : utility function to write several bytes to STC311x registers
* Input          : NumberOfBytes, RegAddress, TxBuffer
* Return         : error status
* Note: Recommended implementation is to used I2C block write. If not available,
* STC311x registers can be written by 2-byte words (unless NumberOfBytes=1)
* or byte per byte.
*******************************************************************************/
static int STC31xx_Write(int length, int reg , unsigned char *values)
{
	int ret;

    ret = i2c_smbus_write_i2c_block_data(sav_client, reg, length, values);
	if (ret < 0)
		dev_err(&sav_client->dev, "%s: err %d\n", __func__, ret);

	return ret;
}

/*******************************************************************************
* Function Name  : STC31xx_Read
* Description    : utility function to read several bytes from STC311x registers
* Input          : NumberOfBytes, RegAddress, , RxBuffer
* Return         : error status
* Note: Recommended implementation is to used I2C block read. If not available,
* STC311x registers can be read by 2-byte words (unless NumberOfBytes=1)
* Using byte per byte read is not recommended since it doesn't ensure register data integrity
*******************************************************************************/
static int STC31xx_Read(int length, int reg , unsigned char *values)
{
	int ret;

    ret = i2c_smbus_read_i2c_block_data(sav_client, reg, length, values);
	if (ret < 0)
		dev_err(&sav_client->dev, "%s: err %d\n", __func__, ret);
	return ret;
}



/* ---- end of I2C primitive interface --------------------------------------------- */


/*******************************************************************************
* Function Name  : STC31xx_ReadByte
* Description    : utility function to read the value stored in one register
* Input          : RegAddress: STC311x register,
* Return         : 8-bit value, or 0 if error
*******************************************************************************/
static int STC31xx_ReadByte(int RegAddress)
{
  int value;
  unsigned char data[2];
  int res;

  res=STC31xx_Read(1, RegAddress, data);

  if (res >= 0)
  {
    /* no error */
    value = data[0];
  }
  else
    value=0;

  return(value);
}



/*******************************************************************************
* Function Name  : STC31xx_WriteByte
* Description    : utility function to write a 8-bit value into a register
* Input          : RegAddress: STC311x register, Value: 8-bit value to write
* Return         : error status (OK, !OK)
*******************************************************************************/
static int STC31xx_WriteByte(int RegAddress, unsigned char Value)
{
  int res;
  unsigned char data[2];

  data[0]= Value; 
  res = STC31xx_Write(1, RegAddress, data);

  return(res);

}


/*******************************************************************************
* Function Name  : STC31xx_ReadWord
* Description    : utility function to read the value stored in one register pair
* Input          : RegAddress: STC311x register,
* Return         : 16-bit value, or 0 if error
*******************************************************************************/
static int STC31xx_ReadWord(int RegAddress)
{
  int value;
  unsigned char data[2];
  int res;

  res=STC31xx_Read(2, RegAddress, data);

  if (res >= 0)
  {
    /* no error */
    value = data[1];
    value = (value <<8) + data[0];
  }
  else
    value=0;

  return(value);
}


/*******************************************************************************
* Function Name  : STC31xx_WriteWord
* Description    : utility function to write a 16-bit value into a register pair
* Input          : RegAddress: STC311x register, Value: 16-bit value to write
* Return         : error status (OK, !OK)
*******************************************************************************/
static int STC31xx_WriteWord(int RegAddress, int Value)
{
  int res;
  unsigned char data[2];

  data[0]= Value & 0xff; 
  data[1]= (Value>>8) & 0xff; 
  res = STC31xx_Write(2, RegAddress, data);

  return(res);

}



/* ---- end of I2C R/W interface --------------------------------------------- */


/* -------------------------------------------------------------------------- */

/* #define CurrentFactor  (24084/SENSERESISTOR)         LSB=5.88uV/R= ~24084/R/4096 - convert to mA  */
#define VoltageFactor  9011                          /* LSB=2.20mV ~9011/4096 - convert to mV         */



/*******************************************************************************
* Function Name  : STC311x_Status
* Description    :  Read the STC311x status
* Input          : None
* Return         : status word (REG_MODE / REG_CTRL), -1 if error
*******************************************************************************/
static int STC311x_Status(void)
{
  int value;

  /* first, check the presence of the STC311x by reading first byte of dev. ID */
  BattData.IDCode = STC31xx_ReadByte(STC311x_REG_ID);
  if (BattData.IDCode!= STC311x_ID && BattData.IDCode!= STC311x_ID_2) {
	printk("STC311x_Status err, return -1.\n");
	return (-1);
  }

  /* read REG_MODE and REG_CTRL */
  value = STC31xx_ReadWord(STC311x_REG_MODE);
  value &= 0x7fff;   

  return (value);
}


/*******************************************************************************
* Function Name  : STC311x_SetParam
* Description    :  initialize the STC311x parameters
* Input          : rst: init algo param
* Return         : 0
*******************************************************************************/
static void STC311x_SetParam(void)
{
  int value;
  
  STC31xx_WriteByte(STC311x_REG_MODE,0x01);  /*   set GG_RUN=0 before changing algo parameters */

  /* init OCV curve */
    STC31xx_Write(OCVTAB_SIZE, STC311x_REG_OCVTAB, (unsigned char *) BattData.OCVOffset);
  
  /* set alm level if different from default */
  if (BattData.Alm_SOC !=0 )   
     STC31xx_WriteByte(STC311x_REG_ALARM_SOC,BattData.Alm_SOC*2); 
  if (BattData.Alm_Vbat !=0 ) 
  {
    value= ((BattData.Alm_Vbat << 9) / VoltageFactor); /* LSB=8*2.44mV */
    STC31xx_WriteByte(STC311x_REG_ALARM_VOLTAGE, value);
  }
    
  /* relaxation timer */
  if (BattData.RelaxThreshold !=0 )  
  {
    value= ((BattData.RelaxThreshold << 9) / BattData.CurrentFactor);   /* LSB=8*5.88uV/Rsense */
    STC31xx_WriteByte(STC311x_REG_CURRENT_THRES,value); 
  }
  
  /* set parameters if different from default, only if a restart is done (battery change) */
  if (GG_Ram.reg.CC_cnf !=0 ) STC31xx_WriteWord(STC311x_REG_CC_CNF,GG_Ram.reg.CC_cnf); 
  if (GG_Ram.reg.VM_cnf !=0 ) STC31xx_WriteWord(STC311x_REG_VM_CNF,GG_Ram.reg.VM_cnf); 

  STC31xx_WriteByte(STC311x_REG_CTRL,0x03);  /*   clear PORDET, BATFAIL, free ALM pin, reset conv counter */
  if (BattData.Vmode)
    STC31xx_WriteByte(STC311x_REG_MODE,0x19);  /*   set GG_RUN=1, voltage mode, alm enabled */
  else
    STC31xx_WriteByte(STC311x_REG_MODE,0x18);  /*   set GG_RUN=1, mixed mode, alm enabled */

  return;
}  




/*******************************************************************************
* Function Name  : STC311x_Startup
* Description    :  initialize and start the STC311x at application startup
* Input          : None
* Return         : 0 if ok, -1 if error
*******************************************************************************/
static int STC311x_Startup(void)
{
  int res;
  int ocv;
  
  /* check STC310x status */
  res = STC311x_Status();
  if (res<0) return(res);

  /* read OCV */
  ocv=STC31xx_ReadWord(STC311x_REG_OCV);

  STC311x_SetParam();  /* set parameters  */
  
  /* rewrite ocv to start SOC with updated OCV curve */
  STC31xx_WriteWord(STC311x_REG_OCV,ocv);
  printk("STC311x_Startup ocv %d\n", ocv*55/100);
  return(0);
}


/*******************************************************************************
* Function Name  : STC311x_OCVAdj_ReStartup
* Description    :  OCV adjust and restart the STC311x at application startup
* Input          : None
* Return         : 0 if ok, -1 if abnormal
*******************************************************************************/
static int STC311x_OCVAdj_ReStartup(void)
{
  int res;
  int ocv,ocv_est_mv;

  pr_info("Enter STC311x_OCVAdj_ReStartup!\n");
  /* check STC310x status */
  res = STC311x_Status();
  if (res<0) return(res);

  STC311x_ReadBatteryData(&BattData);
  ocv_est_mv = BattData.Voltage - (BattData.Current * Ri)/1000;

  pr_info("%s ocv_est_mv: %d, vol: %d, cur: %d soc: %d ocv: %d delta=%d\n", __func__,
		ocv_est_mv, BattData.Voltage, BattData.Current, BattData.SOC, BattData.OCV, BattData.OCV-ocv_est_mv);

  if (ocv_est_mv < 3000) {
	  pr_info("%s ocv_est_mv < 3V, maybe no back battery is on, return directly.", __func__);
	  return -1;
  }

  if (abs(BattData.OCV-ocv_est_mv) > MAX_BOOT_OCV_DELTA) {
	pr_info("%s update ocv=%d\n", __func__, ocv_est_mv);
	/* rewrite ocv to start SOC with updated OCV curve */
	ocv = ocv_est_mv*100/55;
	STC31xx_WriteWord(STC311x_REG_OCV,ocv);
  }

  return 0;
}


/*******************************************************************************
* Function Name  : STC311x_OCV_Correct
* Description    : Correct OCV when it is abnormal, such as when changing back battery quickly, etc.
* Input          : None
* Return         : 0 if ok, -1 if abnormal
*******************************************************************************/
static int STC311x_OCV_Correct(void)
{
	bool should_correct_ocv = false;
	static bool is_check_low_current = true;
	int ocv_est_mv = 0;

	ocv_est_mv = BattData.Voltage - (BattData.Current * Ri)/1000;

	if (ocv_est_mv < 2500) {
		printk("%s ocv_est_mv < 2.5V, no need to correct", __func__);
		ocv_check_count = 0;
		return -1;
	}

	if (abs(BattData.Current) <= CHECK_LOW_CURRENT_THRESH) {
		if (0== current_used_batt) {
			pr_info("%s currently used back battery has low current, skip checking.\n", __func__);
			ocv_check_count = 0;
			return -1;
		} else if (abs(BattData.OCV-ocv_est_mv) > MAX_OCV_DELTA_WITH_LOW_CURRENT) {
			pr_info("%s need correct: ocv=%d ocv_est_mv=%d vol: %d, cur: %d soc: %d\n", __func__,
					BattData.OCV, ocv_est_mv, BattData.Voltage, BattData.Current, BattData.SOC);

			if (!is_check_low_current)
				ocv_check_count = 0;

			ocv_check_count++;
			should_correct_ocv = true;
		} else
			ocv_check_count = 0;

		is_check_low_current = true;
	 } else {
		if (abs(BattData.OCV-ocv_est_mv) > MAX_OCV_DELTA_WITH_HIGH_CURRENT) {
			pr_info("%s need correct: ocv=%d ocv_est_mv=%d vol: %d, cur: %d soc: %d\n", __func__,
					BattData.OCV, ocv_est_mv, BattData.Voltage, BattData.Current, BattData.SOC);

			if (is_check_low_current)
				ocv_check_count = 0;

			ocv_check_count++;
			should_correct_ocv = true;
		} else
			ocv_check_count = 0;

		is_check_low_current = false;
	}

	if (should_correct_ocv && (ocv_check_count > CORRECT_OCV_CHECK_COUNT)) {
		pr_info("%s update ocv=%d\n", __func__, ocv_est_mv);
		/* rewrite ocv to start SOC with updated OCV curve */
		STC31xx_WriteWord(STC311x_REG_OCV,ocv_est_mv*100/55);
	}

	return 0;
}

/*******************************************************************************
* Function Name  : STC311x_Restore
* Description    :  Restore STC311x state
* Input          : None
* Return         : 
*******************************************************************************/
static int STC311x_Restore(void)
{
  int res;
  int ocv;

  /* check STC310x status */
  res = STC311x_Status();
  if (res<0) return(res);
 
  /* read OCV */
  ocv=STC31xx_ReadWord(STC311x_REG_OCV);
  printk("STC311x_Restore ocv %d\n", ocv);
  STC311x_SetParam();  /* set parameters  */
  
#if 1
  /* if restore from unexpected reset, restore SOC (system dependent) */
  if (GG_Ram.reg.GG_Status == GG_RUNNING)
    if (GG_Ram.reg.SOC != 0)
      STC31xx_WriteWord(STC311x_REG_SOC,GG_Ram.reg.SOC*512);  /*   restore SOC */
#else  
  /* rewrite ocv to start SOC with updated OCV curve */
  STC31xx_WriteWord(STC311x_REG_OCV,ocv);
#endif  
  return(0);
}




/*******************************************************************************
* Function Name  : STC311x_Powerdown
* Description    :  stop the STC311x at application power down
* Input          : None
* Return         : error status (OK, !OK)
*******************************************************************************/
static int STC311x_Powerdown(void)
{
  int res;
  
  /* write 0x01 into the REG_CTRL to release IO0 pin open, */
  STC31xx_WriteByte(STC311x_REG_CTRL, 0x01);

  /* write 0 into the REG_MODE register to put the STC311x in standby mode */
   res = STC31xx_WriteByte(STC311x_REG_MODE, 0);
   if (res!= OK) return (res);

   return (OK);
}


/*******************************************************************************
* Function Name  : STC311x_xxxx
* Description    :  misc STC311x utility functions
* Input          : None
* Return         : None
*******************************************************************************/
static void STC311x_Reset(void)
{
  STC31xx_WriteByte(STC311x_REG_CTRL, STC311x_SOFTPOR);  /*   set soft POR */
}

static void STC311x_Reset_VM_Adj(void)
{
  int value;

  if(BattData.IDCode == STC311x_ID)
    STC31xx_WriteByte(STC311x_REG_VM_ADJ_HIGH,0);
  else
  { 
    value=STC31xx_ReadByte(STC311x_REG_MODE);
    STC31xx_WriteByte(STC311x_REG_MODE,value | STC311x_CLR_VM_ADJ);
  }
}

static void STC311x_Reset_CC_Adj(void)
{
  int value;

  if(BattData.IDCode == STC311x_ID)
    STC31xx_WriteByte(STC311x_REG_CC_ADJ_HIGH,0);
  else
  { 
    value=STC31xx_ReadByte(STC311x_REG_MODE);
    STC31xx_WriteByte(STC311x_REG_MODE,value | STC311x_CLR_CC_ADJ);
  }
}

static void STC311x_SetSOC(int SOC)
{
  pr_info("%s: soc=%d\n", __func__, SOC);
  STC31xx_WriteWord(STC311x_REG_SOC,SOC);   /* 100% */
}

#if 0
static void STC311x_ForceVM(void)
{
  int value;
 
  value=STC31xx_ReadByte(STC311x_REG_MODE);
  STC31xx_WriteByte(STC311x_REG_MODE,value | STC311x_FORCE_VM);   /*   force VM mode */
}
#endif
	
static void STC311x_ForceCC(void)
{
  int value;
 
  value=STC31xx_ReadByte(STC311x_REG_MODE);
  value |= STC311x_FORCE_CC;
  STC31xx_WriteByte(STC311x_REG_MODE,value);  /* force CC mode */
  pr_info("%s: set mode = 0x%x\n", __func__, value);
}


#if 0
static int STC311x_SaveCnf(void)
{
  int reg_mode,value;
 
  /* mode register*/
  reg_mode = BattData.STC_Status & 0xff;

  reg_mode &= ~STC311x_GG_RUN;  /*   set GG_RUN=0 before changing algo parameters */
  STC31xx_WriteByte(STC311x_REG_MODE, reg_mode);  
 
  STC31xx_ReadByte(STC311x_REG_ID);

  STC31xx_WriteWord(STC311x_REG_VM_CNF,GG_Ram.reg.VM_cnf); 
  if(BattData.IDCode == STC311x_ID_2)
  {
    value = STC31xx_ReadWord(STC311x_REG_SOC); 
    STC31xx_WriteWord(STC311x_REG_SOC,value); 
  }
  STC31xx_WriteWord(STC311x_REG_CC_CNF,GG_Ram.reg.CC_cnf); 
  
  if (BattData.Vmode)
  {
    STC31xx_WriteByte(STC311x_REG_MODE,0x19);  /*   set GG_RUN=1, voltage mode, alm enabled */
  }
  else
  {
    STC31xx_WriteByte(STC311x_REG_MODE,0x18);  /*   set GG_RUN=1, mixed mode, alm enabled */
    if (BattData.GG_Mode == CC_MODE)
       STC31xx_WriteByte(STC311x_REG_MODE,0x38);  /*   force CC mode */   
    else
       STC31xx_WriteByte(STC311x_REG_MODE,0x58);  /*   force VM mode */
  }
  
  return(0);
}
#endif

static int STC311x_SaveVMCnf(void)
{
  int reg_mode;
 
  /* mode register*/
  reg_mode = BattData.STC_Status & 0xff;

  reg_mode &= ~STC311x_GG_RUN;  /*   set GG_RUN=0 before changing algo parameters */
  STC31xx_WriteByte(STC311x_REG_MODE, reg_mode);  
 
  STC31xx_ReadByte(STC311x_REG_ID);

  STC31xx_WriteWord(STC311x_REG_VM_CNF,GG_Ram.reg.VM_cnf); 
  
  if (BattData.Vmode)
  {
    STC31xx_WriteByte(STC311x_REG_MODE,0x19);  /*   set GG_RUN=1, voltage mode, alm enabled */
  }
  else
  {
    STC31xx_WriteByte(STC311x_REG_MODE,0x18);  /*   set GG_RUN=1, mixed mode, alm enabled */
    if (BattData.GG_Mode == CC_MODE)
       STC31xx_WriteByte(STC311x_REG_MODE,0x38);  /*   force CC mode */   
    else
       STC31xx_WriteByte(STC311x_REG_MODE,0x58);  /*   force VM mode */
  }
  
  return(0);
}





/*******************************************************************************
* Function Name  : conv
* Description    : conversion utility 
*  convert a raw 16-bit value from STC311x registers into user units (mA, mAh, mV, ?C)
*  (optimized routine for efficient operation on 8-bit processors such as STM8)
* Input          : value, factor
* Return         : result = value * factor / 4096
*******************************************************************************/
static int conv(short value, unsigned short factor)
{
  int v;
  
  v= ( (long) value * factor ) >> 11;
  v= (v+1)/2;
  
  return (v);
}

/*******************************************************************************
* Function Name  : STC311x_ReadBatteryData
* Description    :  utility function to read the battery data from STC311x
*                  to be called every 5s or so
* Input          : ref to BattData structure
* Return         : error status (OK, !OK)
*******************************************************************************/
static int STC311x_ReadBatteryData(STC311x_BattDataTypeDef *BattData)
{
  unsigned char data[16];
  int res;
  int value;
  //int i;

  pr_debug("STC311x_ReadBatteryData.\n");
  res=STC311x_Status();
  if (res<0) return(res);  /* return if I2C error or STC3115 not responding */
  
  /* STC311x status */
  BattData->STC_Status = res;
  if (BattData->STC_Status & M_GGVM)
    BattData->GG_Mode = VM_MODE;   /* VM active */
  else 
    BattData->GG_Mode = CC_MODE;   /* CC active */

  pr_debug("STC311x STC status: 0x%x  GG Mode: 0x%x \n", BattData->STC_Status, BattData->GG_Mode);
  /* read STC311x registers 0 to 14 */
  res=STC31xx_Read(15, 0, data);
  if (res<0) {
  	pr_err("read failed in STC311x_ReadBatteryData.\n");
  	return(res);  /* read failed */
  }
  /* dump registers 0 to 14 */
  #if 0
  printk("**************STC311x registers begin***************\n");
  for (i=0;i<15;i++)
  	printk("register[%d]: %x\n", i, data[i]);
  printk("**************STC311x registers end***************\n");
  #endif
  
  /* fill the battery status data */
  /* SOC */
  value=data[3]; value = (value<<8) + data[2];
  BattData->HRSOC = value;     /* result in 1/512% */
  pr_debug("BattData->HRSOC: %d\n", BattData->HRSOC);
  /* conversion counter */
  value=data[5]; value = (value<<8) + data[4];
  BattData->ConvCounter = value;
  pr_debug("BattData->ConvCounter: %d\n", BattData->ConvCounter);
  
  /* current */
  value=data[7]; value = (value<<8) + data[6];
  value &= 0x3fff;   /* mask unused bits */
  if (value>=0x2000) value -= 0x4000;  /* convert to signed value */
  BattData->Current = conv(value, BattData->CurrentFactor);  /* result in mA */
  pr_debug("BattData->Current: %d\n", BattData->Current);
  
  /* voltage */
  value=data[9]; value = (value<<8) + data[8];
  value &= 0x0fff; /* mask unused bits */
  if (value>=0x0800) value -= 0x1000;  /* convert to signed value */
  value = conv(value,VoltageFactor);  /* result in mV */
  BattData->Voltage = value;  /* result in mV */
  pr_debug("BattData->Voltage: %d\n", BattData->Voltage);
  
  /* temperature */
  value=data[10]; 
  if (value>=0x80) value -= 0x100;  /* convert to signed value */
  BattData->Temperature = value*10;  /* result in 0.1?C */
  pr_debug("BattData->Temperature: %d\n", BattData->Temperature);
  
  /* CC & VM adjustment counters */
  BattData->CC_adj = data[11];  /* result in 0.5% */
  if (BattData->CC_adj>=0x80)   BattData->CC_adj -= 0x100;  /* convert to signed value, result in 0.5% */
  BattData->VM_adj = data[12];  /* result in 0.5% */
  if (BattData->VM_adj>=0x80)   BattData->VM_adj -= 0x100;  /* convert to signed value, result in 0.5% */

  /* OCV */
  value=data[14]; value = (value<<8) + data[13];
  value &= 0x3fff; /* mask unused bits */
  if (value>=0x02000) value -= 0x4000;  /* convert to signed value */
  value = conv(value,VoltageFactor);  
  value = (value+2) / 4;  /* divide by 4 with rounding */
  BattData->OCV = value;  /* result in mV */
  pr_debug("BattData->OCV: %d\n", BattData->OCV);
  
  res=STC31xx_Read(1, STC311x_REG_RELAX_COUNT, data);
  if (res<0) return(res);  /* read failed */
  BattData->RelaxTimer = data[0];

  
  return(OK);
}


/*******************************************************************************
* Function Name  : STC311x_ReadRamData
* Description    : utility function to read the RAM data from STC311x
* Input          : ref to RAM data array
* Return         : error status (OK, !OK)
*******************************************************************************/
static int STC311x_ReadRamData(unsigned char *RamData)
{
  return(STC31xx_Read(RAM_SIZE, STC311x_REG_RAM, RamData));
}


/*******************************************************************************
* Function Name  : STC311x_WriteRamData
* Description    : utility function to write the RAM data into STC311x
* Input          : ref to RAM data array
* Return         : error status (OK, !OK)
*******************************************************************************/
static int STC311x_WriteRamData(unsigned char *RamData)
{
  return(STC31xx_Write(RAM_SIZE, STC311x_REG_RAM, RamData));
}

/******************************************************************************* 
* Function Name  : Interpolate
* Description    : interpolate a Y value from a X value and X, Y tables (n points)
* Input          : x
* Return         : y
*******************************************************************************/
static int interpolate(int x, int n, int const *tabx, int const *taby )
{  
  int index;
  int y;
  
  if (x >= tabx[0])
    y = taby[0];
  else if (x <= tabx[n-1])
    y = taby[n-1];
  else
  {
    /*  find interval */
    for (index= 1;index<n;index++)
      if (x > tabx[index]) break;
    /*  interpolate */
    y = (taby[index-1] - taby[index]) * (x - tabx[index]) * 2 / (tabx[index-1] - tabx[index]);
    y = (y+1) / 2;
    y += taby[index];
  }    
  return y;
}



/*******************************************************************************
* Function Name  : calcCRC8
* Description    : calculate the CRC8
* Input          : data: pointer to byte array, n: number of vytes
* Return         : CRC calue
*******************************************************************************/
static int calcCRC8(unsigned char *data, int n)
{
  int crc=0;   /* initial value */
  int i, j;

  for (i=0;i<n;i++)
  {
    crc ^= data[i];
    for (j=0;j<8;j++) 
    {
      crc <<= 1;
      if (crc & 0x100)  crc ^= 7;
    }
  }
  return(crc & 255);

}


/*******************************************************************************
* Function Name  : UpdateRamCrc
* Description    : calculate the RAM CRC
* Input          : none
* Return         : CRC value
*******************************************************************************/
static int UpdateRamCrc(void)
{
  int res;
  
  res=calcCRC8(GG_Ram.db,RAM_SIZE-1);
  GG_Ram.db[RAM_SIZE-1] = res;   /* last byte holds the CRC */
  return(res);
}

/*******************************************************************************
* Function Name  : Init_RAM
* Description    : Init the STC311x RAM registers with valid test word and CRC
* Input          : none
* Return         : none
*******************************************************************************/
static void Init_RAM(void)
{
  int index;

  for (index=0;index<RAM_SIZE;index++) 
    GG_Ram.db[index]=0;
  GG_Ram.reg.TstWord=RAM_TSTWORD;  /* id. to check RAM integrity */
  GG_Ram.reg.CC_cnf = BattData.CC_cnf;
  GG_Ram.reg.VM_cnf = BattData.VM_cnf;
  /* update the crc */
  UpdateRamCrc();
}



/*******************************************************************************
* Function Name  : UpdateParam
* Description    : update the algo parameters
* Use            : BattData structure
* Affect         : VM_cnf, CC_cnf
*******************************************************************************/
static void UpdateParam(void)
{
  
  /* adaptive algorithm at each mode change */
  if ( BattData.GG_Mode != BattData.LastMode )
  {
    /* mode change detected */
    if ( BattData.GG_Mode == CC_MODE)
    {
       /* switch to CC mode, update both VM_Coeff and CC_Coeff gains */
       if (BattData.CC_adj<(-20)) BattData.CC_adj=-20;
       if (BattData.CC_adj>20) BattData.CC_adj=20;
       if ( (BattData.CC_adj<(-2)) || (BattData.CC_adj>2) ) 
       {
         if ((BattData.AvgTemperature/10)>TEMP_MIN_ADJ) 
           {
             if (BattData.LastSOC<BattData.HRSOC)
             {
               GG_Ram.reg.VM_cnf -= (GG_Ram.reg.VM_cnf*BattData.CC_adj)/200;
               GG_Ram.reg.CC_cnf -= (GG_Ram.reg.CC_cnf*BattData.CC_adj)/200;
               BattData.Cnom -= (BattData.Cnom*BattData.CC_adj)/200;
             }
             else
             {
               GG_Ram.reg.VM_cnf += (GG_Ram.reg.VM_cnf*BattData.CC_adj)/200;
               GG_Ram.reg.CC_cnf += (GG_Ram.reg.CC_cnf*BattData.CC_adj)/200;
               BattData.Cnom += (BattData.Cnom*BattData.CC_adj)/200;
             }
          }
          STC311x_Reset_CC_Adj();
          STC311x_Reset_VM_Adj();
          BattData.LastSOC=BattData.HRSOC;  
       }
    }
    BattData.LastMode=BattData.GG_Mode;
  }
}
 

/* compensate SOC with temperature, SOC in 0.1% units */
static int CompensateSOC(int value, int temp)
{
    int r, v;
    
     r=0;    
#ifdef TEMPCOMP_SOC
    r=interpolate(temp/10,NTEMP,TempTable,BattData.CapacityDerating);  /* for APP_TYP_CURRENT */
#endif       
    v = (long) (value-r) * MAX_SOC * 2 / (MAX_SOC-r);   /* compensate */
    v = (v+1)/2;  /* rounding */
    if (v < 0) v = 0;
    if (v > MAX_SOC) v = MAX_SOC;
    
    return(v);
}






/*******************************************************************************
* Function Name  : MM_FSM
* Description    : process the Gas Gauge state machine in mixed mode
* Input          : BattData
* Return         : 
* Affect         : Global Gas Gauge data
*******************************************************************************/
static void MM_FSM(void)
{
  
  switch (BattData.BattState)
  {
    case BATT_CHARGING:
      if (BattData.AvgCurrent < CHG_MIN_CURRENT)
        BattData.BattState = BATT_ENDCHARG;        /* end of charge */
      break;
    case BATT_ENDCHARG:  /* end of charge state. check if fully charged or charge interrupted */
      if ( BattData.Current > CHG_MIN_CURRENT ) 
        BattData.BattState = BATT_CHARGING;
      else if (BattData.AvgCurrent < CHG_END_CURRENT )
        BattData.BattState = BATT_IDLE;     /* charge interrupted */
      else if ( (BattData.Current > CHG_END_CURRENT ) && ( BattData.Voltage > BATT_CHG_VOLTAGE ) )
        BattData.BattState = BATT_FULCHARG;  /* end of charge */
      break;
    case BATT_FULCHARG:  /* full charge state. wait for actual end of charge current */
      if ( (BattData.Current > CHG_MIN_CURRENT)) 
        BattData.BattState = BATT_CHARGING;  /* charge again */
      else if ( BattData.AvgCurrent < CHG_END_CURRENT ) 
      {
        if ( BattData.AvgVoltage > BATT_CHG_VOLTAGE )
        {
          /* end of charge detected */
           STC311x_SetSOC(MAX_HRSOC);
           STC311x_Reset_VM_Adj();
           STC311x_Reset_CC_Adj();
           BattData.SOC=MAX_SOC;  /* 100% */
           BattData.LastSOC=MAX_HRSOC;
        }
/*        if (BattData.Vmode==0) STC311x_ForceVM(); */
	BattData.BattState = BATT_IDLE;     /* end of charge cycle */
      }
      break;
    case BATT_IDLE:  /* no charging, no discharging */
      if (BattData.Current > CHG_END_CURRENT)
      {
/*        if (BattData.Vmode==0) STC311x_ForceVM(); */
        BattData.BattState = BATT_CHARGING; /* charging again */
      }
      else if (BattData.Current < APP_MIN_CURRENT) 
        BattData.BattState = BATT_DISCHARG; /* discharging again */
      break;
    case BATT_DISCHARG:
      if (BattData.Current > APP_MIN_CURRENT) 
        BattData.BattState = BATT_IDLE;
      else if (BattData.AvgVoltage < BATT_MIN_VOLTAGE) 
        BattData.BattState = BATT_LOWBATT;
      break;
    case BATT_LOWBATT:  /* battery nearly empty... */
      if ( BattData.AvgVoltage > (BATT_MIN_VOLTAGE+50) )
        BattData.BattState = BATT_IDLE;   /* idle */
      else
/*        if (BattData.Vmode==0) STC311x_ForceVM(); */
      break;
    default:
        BattData.BattState = BATT_IDLE;   /* idle */
   
  } /* end switch */

  if (BattData.Adaptive) UpdateParam();
  
}


static void CompensateVM(int temp)
{
    int r;

#ifdef TEMPCOMP_SOC
    r=interpolate(temp/10,NTEMP,TempTable,BattData.VM_TempTable);
    GG_Ram.reg.VM_cnf = (BattData.VM_cnf * r) / 100;
    STC311x_SaveVMCnf();  /* save new VM cnf values to STC311x */
#endif    
}


/*******************************************************************************
* Function Name  : VM_FSM
* Description    : process the Gas Gauge machine in voltage mode
* Input          : BattData
* Return         : 
* Affect         : Global Gas Gauge data
*******************************************************************************/
static void VM_FSM(void)
{
  
#define DELTA_TEMP 30   /* 3 ?C */

  /* in voltage mode, monitor temperature to compensate voltage mode gain */

  if ( ( BattData.AvgTemperature > (BattData.LastTemperature+DELTA_TEMP)) || 
       ( BattData.AvgTemperature < (BattData.LastTemperature-DELTA_TEMP)) )
  {
    BattData.LastTemperature = BattData.AvgTemperature;
    CompensateVM(BattData.AvgTemperature);
  }
  
}




/*******************************************************************************
* Function Name  : Reset_FSM_GG
* Description    : reset the gas gauge state machine and flags
* Input          : None
* Return         : None
*******************************************************************************/
static void Reset_FSM_GG(void)
{
  BattData.BattState = BATT_IDLE;
  if (BattData.Adaptive) Capacity_Adjust=0;
}



/* -------------------- firmware interface functions ------------------------------------------- */




/*******************************************************************************
* Function Name  : GasGauge_Start
* Description    : Start the Gas Gauge system
* Input          : algo parameters in GG structure
* Return         : 0 is ok, -1 if STC310x not found or I2C error
* Affect         : global STC310x data and gas gauge variables
*******************************************************************************/
int GasGauge_Start(GasGauge_DataTypeDef *GG)
{
  int res = 0, i;
   
  BattData.Cnom = GG->Cnom;
  BattData.Rsense = GG->Rsense;
  BattData.Vmode = GG->Vmode;
  BattData.CC_cnf = GG->CC_cnf; 
  BattData.VM_cnf = GG->VM_cnf; 
  BattData.Alm_SOC = GG->Alm_SOC; 
  BattData.Alm_Vbat = GG->Alm_Vbat; 
  BattData.RelaxThreshold = GG->RelaxCurrent;
  BattData.Adaptive = GG->Adaptive;

  // BATD
  BattData.BattOnline = 1;
  if (BattData.Rsense==0) BattData.Rsense=10;  /* default value in case, to avoid divide by 0 */
  BattData.CurrentFactor=24084/BattData.Rsense;        /* LSB=5.88uV/R= ~24084/R/4096 - convert to mA  */

  if (BattData.CC_cnf==0) BattData.CC_cnf=395;  /* Rsense ? Cnom / 49.556, Cnom = 2522 */
  if (BattData.VM_cnf==0) BattData.VM_cnf=321;  /* Ri ? Cnom / 977.78, Ri = 181 */
  
  for (i=0;i<NTEMP;i++)
    BattData.CapacityDerating[i] = GG->CapDerating[i]; 
  for (i=0;i<OCVTAB_SIZE;i++)
    BattData.OCVOffset[i] = GG->OCVOffset[i]; 
  for (i=0;i<NTEMP;i++)
    BattData.VM_TempTable[i] = DefVMTempTable[i];    

  /* check RAM valid */
  STC311x_ReadRamData(GG_Ram.db);
#if 0
  if (of_board_is_sfo_v40()) 
      STC311x_Reset();
#endif
//  if ( (GG_Ram.reg.TstWord != RAM_TSTWORD) || (calcCRC8(GG_Ram.db,RAM_SIZE)!=0) )
//  {
    /* Consider of M_RST siginal cannot be detected because of BATD is connected to ground, 
     * that cause the battery status is unknown before stc3115 work start, at the same time, 
     * backup battery can be replaced during the system shutdown, so we cannot restore RAM data,
     * and have to init RAM and startup chip every boot. 
     */
    Init_RAM(); /* RAM invalid */
    res=STC311x_Startup();  /* return -1 if I2C error or STC3115 not present */
	if (res < 0) {
		BattData.BattOnline = 1;
		return (res);
	}
	printk("GasGauge_Start RAM invalid and STC311x_Startup\n");
#if 0
  }
  else
  {
      /* check STC3115 status */
      if ((STC311x_Status() & M_RST) != 0 )
      {
          res=STC311x_Startup();  /* return -1 if I2C error or STC3115 not present */
		  printk("GasGauge_Start check STC3115 statusand STC311x_Startup\n");
      }
      else
      { 
          res=STC311x_Restore(); /* recover from last SOC */
		  printk("GasGauge_Start check STC3115 STC311x_Restore\n");
      }
  }
#endif

  /* Because of hardware design, we have to compensate OCV by software, 
   * OCV will have an offset equal to the internal battery impedance*charging current.
   */
  msleep(1000);
  STC311x_OCVAdj_ReStartup();

  GG_Ram.reg.GG_Status = GG_INIT;
  /* update the crc */
  UpdateRamCrc();
  STC311x_WriteRamData(GG_Ram.db);

  Reset_FSM_GG();
  
  return(res);    /* return -1 if I2C error or STC3115 not present */
}


  


/*******************************************************************************
Restart sequence:
Usage: 
  call GasGaugeReset()
  powerdown everything
  wait 500ms
  call GasGaugeStart(GG)
  continue 
*******************************************************************************/


/*******************************************************************************
* Function Name  : GasGauge_Reset
* Description    : Reset the Gas Gauge system
* Input          : None
* Return         : 0 is ok, -1 if I2C error
*******************************************************************************/
void GasGauge_Reset(void)  
{
  GG_Ram.reg.TstWord=0;  /* reset RAM */
  GG_Ram.reg.GG_Status = 0;
  STC311x_WriteRamData(GG_Ram.db);

  STC311x_Reset();
}



/*******************************************************************************
* Function Name  : GasGauge_Stop
* Description    : Stop the Gas Gauge system
* Input          : None
* Return         : 0 is ok, -1 if I2C error
*******************************************************************************/
int GasGauge_Stop(void)
{
  int res;
  
  STC311x_ReadRamData(GG_Ram.db);
  GG_Ram.reg.GG_Status= GG_POWERDN;
  /* update the crc */
  UpdateRamCrc();
  STC311x_WriteRamData(GG_Ram.db);
      
  res=STC311x_Powerdown();
  if (res!=0) return (-1);  /* error */

  return(0);  
}



/*******************************************************************************
* Function Name  : GasGauge_Task
* Description    : Periodic Gas Gauge task, to be called e.g. every 5 sec.
* Input          : pointer to gas gauge data structure
* Return         : 1 if data available, 0 si no data, -1 if error
* Affect         : global STC310x data and gas gauge variables
*******************************************************************************/
int GasGauge_Task(GasGauge_DataTypeDef *GG)
{
  int res, value;
  bool is_batt_removed = false;
  static bool is_health_poor_reported = false;
  struct stc311x_chip *chip = i2c_get_clientdata(sav_client);

  BattData.Rsense = GG->Rsense;
  BattData.Vmode = GG->Vmode;
  BattData.Alm_SOC = GG->Alm_SOC;
  BattData.Alm_Vbat = GG->Alm_Vbat; 
  BattData.RelaxThreshold = GG->RelaxCurrent;
  BattData.Adaptive = GG->Adaptive;

  res=STC311x_ReadBatteryData(&BattData);  /* read battery data into global variables */
  if (res!=0) return(-1); /* abort in case of I2C failure */
   
  /* check if RAM data is ok (battery has not been changed) */
  STC311x_ReadRamData(GG_Ram.db);
  if ( (GG_Ram.reg.TstWord!= RAM_TSTWORD) || (calcCRC8(GG_Ram.db,RAM_SIZE)!=0) )
  {
    /* if RAM non ok, reset it and set init state */
    Init_RAM(); 
    GG_Ram.reg.GG_Status = GG_INIT;
  }    

  //Force an external temperature
  if(GG->ForceExternalTemperature == 1)
  	BattData.Temperature = GG->ExternalTemperature;

  if (of_board_is_sfo_v40())
      is_batt_removed = BattData.Temperature == (-300);
  else
      is_batt_removed = true;  //(BattData.STC_Status & M_BATFAIL) != 0;
  //Check battery presence
  if (is_batt_removed)
  {
      if (BattData.BattOnline == 1)
      { 
		wake_lock_timeout(&bat_wake_lock, BAT_WAKE_LOCK_TIMEOUT*HZ);
		BattData.BattOnline = 0;
		atomic_notifier_call_chain(&batt_state_chg_notifier_list, BAKBATT_PLUGOUT_EVENT, NULL);
		printk("BattData.BattOnline = 0 Notify BAKBATT_PLUGOUT_EVENT\n");
		bat_check_counter = 0;
		if (is_health_poor_reported) {
			is_health_poor_reported = false;
			chip->health = POWER_SUPPLY_HEALTH_GOOD;
			power_supply_changed(&chip->stc3115_psy);
			pr_info("Battery: %s report back battery good connection.\n", __func__);
		}
		ocv_check_count = 0;
      }
  }
  /* check STC3115 status */
#ifdef BATD_UC8
  /* check STC3115 status */
  if (is_batt_removed)
  {
      /* BATD or UVLO detected */
      if(BattData.ConvCounter > 0)
      {
          GG->Voltage=BattData.Voltage;
          GG->SOC=(BattData.HRSOC*10+256)/512;
      }

      /* BATD or UVLO detected */
	if (of_board_is_sfo_v40()) {
		STC311x_Reset();
		GasGauge_Stop();
	}

      return (-1);
  }
#endif

  if ((BattData.STC_Status & M_RUN) == 0)
  {
    /* if not running, restore STC3115 */
    STC311x_Restore();  
    GG_Ram.reg.GG_Status = GG_INIT;
  }

  BattData.SOC = (BattData.HRSOC*10+256)/512;  /* in 0.1% unit  */
  /* corrects 3% - 0.5% values to 3% - 0% */
  if (BattData.SOC<5) BattData.SOC=0;
  else if (BattData.SOC<30) BattData.SOC=(BattData.SOC-5)*30/25;
#if 0  
  //Force an external temperature
  if(GG->ForceExternalTemperature == 1)
    BattData.Temperature = GG->ExternalTemperature;
#endif
  /* check INIT state */
  if (GG_Ram.reg.GG_Status == GG_INIT)
  {
    /* INIT state, wait for current & temperature value available: */
    if (BattData.ConvCounter>VCOUNT) 
    {
	if (BattData.Vmode) {
	          /* update VM_cnf */
	          CompensateVM(BattData.Temperature);
	} else {
		STC31xx_ForceCC();
	}
          BattData.LastTemperature=BattData.Temperature;

          /* Init averaging */
          BattData.AvgVoltage = BattData.Voltage;
          BattData.AvgCurrent = BattData.Current;
          BattData.AvgTemperature = BattData.Temperature;
          BattData.AvgSOC = CompensateSOC(BattData.SOC,BattData.Temperature);  /* in 0.1% unit  */
          BattData.AccVoltage = BattData.AvgVoltage*AVGFILTER;
          BattData.AccCurrent = BattData.AvgCurrent*AVGFILTER;
          BattData.AccTemperature = BattData.AvgTemperature*AVGFILTER;
          BattData.AccSOC = BattData.AvgSOC*AVGFILTER;
          
          /* init adaptive algo */
          BattData.LastSOC=BattData.HRSOC;
          BattData.LastMode=BattData.GG_Mode;

          GG_Ram.reg.GG_Status = GG_RUNNING;
    }
  }

  
  if (GG_Ram.reg.GG_Status != GG_RUNNING)
  {
    GG->SOC = CompensateSOC(BattData.SOC,250);
    GG->Voltage=BattData.Voltage;
    GG->OCV = BattData.OCV;
    GG->Current=0;
    GG->Temperature=250;
  }
  else
  {
    //Check battery presence
    if (!is_batt_removed)
    {
        if (BattData.BattOnline == 0) {
			wake_lock_timeout(&bat_wake_lock, BAT_WAKE_LOCK_TIMEOUT*HZ);
            BattData.BattOnline = 1;
            /* notify batt state machine */
	        atomic_notifier_call_chain(&batt_state_chg_notifier_list, BAKBATT_PLUGIN_EVENT, NULL);
			printk("BattData.BattOnline = 1 Notify BAKBATT_PLUGIN_EVENT, BattData.Temperature = %d\n", BattData.Temperature);
            return (0);
        }

	if (!is_batt_present) {
		wake_lock_timeout(&bat_wake_lock, BAT_WAKE_LOCK_TIMEOUT*HZ);
		 atomic_notifier_call_chain(&batt_state_chg_notifier_list, BAKBATT_PLUGIN_EVENT, NULL);
	}
    }

	/*
	  * If back battery is in poor connection state, report the event to userspace via sysfs 'health' prop.
	  * 
	  * When the back battery is on and mainly used(Switch is on back battery I mean.), 
	  * and we check that its current is smaller than BAT_POOR_CONNECTION_THRES_CURRENT
	  * for BAT_POOR_CONNECTION_CHECK_COUNT consecutive times, we think it is in poor 
	  * connection state. Then we will notify userspace its poor connection health state.
	  * And if the state lasts continuously, we will notify userspace every 
	  * BAT_POOR_CONNECTION_REPORT_MINUTE minutes.
	  *
	  * Once battery connection gets back good from poor connection state, we will report userspace 
	  * the good connection health state.
	  */
	if ((0== current_used_batt) &&
	     (chip->status != POWER_SUPPLY_STATUS_FULL) &&
	     (abs(BattData.Current) <= BAT_POOR_CONNECTION_THRES_CURRENT)) {
		if (++bat_check_counter >= BAT_POOR_CONNECTION_CHECK_COUNT) {
			is_health_poor_reported = true;
			bat_check_counter = BAT_POOR_CONNECTION_CHECK_COUNT
								- BAT_POOR_CONNECTION_REPORT_COUNTER;
			chip->health = POWER_SUPPLY_HEALTH_BACK_BAT_POOR_CONNECTION;
			power_supply_changed(&chip->stc3115_psy);
			pr_info("Battery: %s report back battery poor connection.\n", __func__);
		}
	} else {
		bat_check_counter = 0;
		if (is_health_poor_reported) {
			is_health_poor_reported = false;
			chip->health = POWER_SUPPLY_HEALTH_GOOD;
			power_supply_changed(&chip->stc3115_psy);
			pr_info("Battery: %s report back battery good connection.\n", __func__);
		}
	}

    /* SOC derating with temperature */
    BattData.SOC = CompensateSOC(BattData.SOC,BattData.Temperature);

    //early empty compensation
 if (BattData.AvgVoltage<APP_MIN_VOLTAGE)
           BattData.SOC = 0;
    else
		if (BattData.AvgVoltage<(APP_MIN_VOLTAGE+200))
		  BattData.SOC = BattData.SOC * (BattData.AvgVoltage - APP_MIN_VOLTAGE) / 200;

	
    BattData.AccVoltage += (BattData.Voltage - BattData.AvgVoltage);
    BattData.AccCurrent += (BattData.Current - BattData.AvgCurrent);
    BattData.AccTemperature += (BattData.Temperature - BattData.AvgTemperature);
    BattData.AccSOC +=  (BattData.SOC - BattData.AvgSOC);
  
    BattData.AvgVoltage = (BattData.AccVoltage+AVGFILTER/2)/AVGFILTER;
    BattData.AvgCurrent = (BattData.AccCurrent+AVGFILTER/2)/AVGFILTER;
    BattData.AvgTemperature = (BattData.AccTemperature+AVGFILTER/2)/AVGFILTER;
    BattData.AvgSOC = (BattData.AccSOC+AVGFILTER/2)/AVGFILTER;
  
    /* ---------- process the Gas Gauge algorithm -------- */

    if (BattData.Vmode) 
      VM_FSM();  /* in voltage mode */
    else
      MM_FSM();  /* in mixed mode */
    
	//Lately fully compensation
    if(BattData.BattState > BATT_IDLE && BattData.SOC >= 990 && BattData.SOC <= MAX_SOC && BattData.AvgCurrent > CHG_END_CURRENT)
    {
        BattData.SOC = 990;
        pr_debug("Lately fully compensate soc to 99\n");
    }

    STC311x_OCV_Correct();

    /* -------- APPLICATION RESULTS ------------ */
    
    /* fill gas gauge data with battery data */
    GG->Voltage=BattData.Voltage;
    GG->Current=BattData.Current;
    GG->Temperature=BattData.Temperature;
    GG->SOC = BattData.SOC;
    GG->OCV = BattData.OCV;
    
    GG->AvgVoltage = BattData.AvgVoltage;
    GG->AvgCurrent = BattData.AvgCurrent;
    GG->AvgTemperature = BattData.AvgTemperature;
    GG->AvgSOC = BattData.AvgSOC;

    if (BattData.Vmode) 
    {
      /* no current value in voltage mode */
      GG->Current = 0;
      GG->AvgCurrent = 0;
    }
    
    GG->ChargeValue = (long) BattData.Cnom * BattData.AvgSOC / MAX_SOC;
    if (GG->Current<APP_MIN_CURRENT && BattData.AvgCurrent != 0)
    {
      GG->State=BATT_DISCHARG;
      value = GG->ChargeValue * 60 / (-BattData.AvgCurrent);  /* in minutes */
      if (value<0) value=0;
      GG->RemTime = value; 
    }
    else 
    {
      GG->RemTime = -1;   /* means no estimated time available */
      if (GG->AvgCurrent>CHG_END_CURRENT)
        GG->State=BATT_CHARGING;
      else
        GG->State=BATT_IDLE;
    }
  }
      
  /* save SOC */
  GG_Ram.reg.HRSOC = BattData.HRSOC;
  GG_Ram.reg.SOC = (GG->SOC+5)/10;    /* trace SOC in % */
  UpdateRamCrc();
  STC311x_WriteRamData(GG_Ram.db);

  //power_supply_changed(&chip->stc3115_psy);

  if (GG_Ram.reg.GG_Status==GG_RUNNING)
    return(1);
  else
    return(0);  /* only SOC, OCV and voltage are valid */
}




/*******************************************************************************
* Function Name  : STC31xx_SetPowerSavingMode
* Description    :  Set the power saving mode
* Input          : None
* Return         : error status (OK, !OK)
*******************************************************************************/
int STC31xx_SetPowerSavingMode(void)
{
  int res;
  
  /* Read the mode register*/
  res = STC31xx_ReadByte(STC311x_REG_MODE);

  /* Set the VMODE bit to 1 */
  res = STC31xx_WriteByte(STC311x_REG_MODE, (res | STC311x_VMODE));
  if (res!= OK) return (res);

   return (OK);
}


/*******************************************************************************
* Function Name  : STC31xx_StopPowerSavingMode
* Description    :  Stop the power saving mode
* Input          : None
* Return         : error status (OK, !OK)
*******************************************************************************/
int STC31xx_StopPowerSavingMode(void)
{
  int res;
  
  /* Read the mode register*/
  res = STC31xx_ReadByte(STC311x_REG_MODE);

  /* Set the VMODE bit to 0 */
  res = STC31xx_WriteByte(STC311x_REG_MODE, (res & ~STC311x_VMODE));
  if (res!= OK) return (res);

   return (OK);
}


/*******************************************************************************
* Function Name  : STC31xx_AlarmSet
* Description    :  Set the alarm function and set the alarm threshold
* Input          : None
* Return         : error status (OK, !OK)
*******************************************************************************/
int STC31xx_AlarmSet(void)
{
  int res;

  /* Read the mode register*/
  res = STC31xx_ReadByte(STC311x_REG_MODE);

  /* Set the ALM_ENA bit to 1 */
  res = STC31xx_WriteByte(STC311x_REG_MODE, (res | STC311x_ALM_ENA));
  if (res!= OK) return (res);

  return (OK);
}


/*******************************************************************************
* Function Name  : STC31xx_AlarmStop
* Description    :  Stop the alarm function
* Input          : None
* Return         : error status (OK, !OK)
*******************************************************************************/
int STC31xx_AlarmStop(void)
{
  int res;
  
  /* Read the mode register*/
  res = STC31xx_ReadByte(STC311x_REG_MODE);

  /* Set the ALM_ENA bit to 0 */
  res = STC31xx_WriteByte(STC311x_REG_MODE, (res & ~STC311x_ALM_ENA));
  if (res!= OK) return (res);

   return (OK);
}


/*******************************************************************************
* Function Name  : STC31xx_AlarmGet
* Description    : Return the ALM status
* Input          : None
* Return         : ALM status 00 : no alarm 
*                             01 : SOC alarm
*                             10 : Voltage alarm
*                             11 : SOC and voltage alarm
*******************************************************************************/
int STC31xx_AlarmGet(void)
{
  int res;
  
  /* Read the mode register*/
  res = STC31xx_ReadByte(STC311x_REG_CTRL);
  res = res >> 5;

   return (res);
}


/*******************************************************************************
* Function Name  : STC31xx_AlarmClear
* Description    :  Clear the alarm signal
* Input          : None
* Return         : error status (OK, !OK)
*******************************************************************************/
int STC31xx_AlarmClear(void)
{
  int res = OK;
  int value=STC31xx_ReadByte(STC311x_REG_CTRL);
  /* clear ALM interrupt bits */
  res = STC31xx_WriteByte(STC311x_REG_CTRL, (value & ~STC311x_ALM_INT_CLR) | STC311x_ALM_ACTIVE);
  if (res!= OK) return (res);

  return (res);
}


/*******************************************************************************
* Function Name  : STC31xx_AlarmSetVoltageThreshold
* Description    : Set the alarm threshold
* Input          : int voltage threshold
* Return         : error status (OK, !OK)
*******************************************************************************/
int STC31xx_AlarmSetVoltageThreshold(int VoltThresh)
{
  int res;
  int value;
  
  BattData.Alm_Vbat =VoltThresh;
    
  value= ((BattData.Alm_Vbat << 9) / VoltageFactor); /* LSB=8*2.44mV */
  res = STC31xx_WriteByte(STC311x_REG_ALARM_VOLTAGE, value);
  if (res!= OK) return (res);

   return (OK);
}




/*******************************************************************************
* Function Name  : STC31xx_AlarmSetSOCThreshold
* Description    : Set the alarm threshold
* Input          : int voltage threshold
* Return         : error status (OK, !OK)
*******************************************************************************/
int STC31xx_AlarmSetSOCThreshold(int SOCThresh)
{
  int res;

  BattData.Alm_SOC = SOCThresh;
  res = STC31xx_WriteByte(STC311x_REG_ALARM_SOC, BattData.Alm_SOC*2);
  if (res!= OK) return (res);
  
  return (OK);
}




/*******************************************************************************
* Function Name  : STC31xx_RelaxTmrSet
* Description    :  Set the current threshold register to the passed value in mA
* Input          : int current threshold
* Return         : error status (OK, !OK)
*******************************************************************************/
int STC31xx_RelaxTmrSet(int CurrentThreshold)
{
  int res, value;
  
  BattData.RelaxThreshold = CurrentThreshold;
  if (BattData.CurrentFactor!=0) 
  {
    value= ((BattData.RelaxThreshold << 9) / BattData.CurrentFactor);   /* LSB=8*5.88uV/Rsense */
    res=STC31xx_WriteByte(STC311x_REG_CURRENT_THRES,value);     
    if (res!= OK) return (res);
  }

  return (OK);
}

/*******************************************************************************
* Function Name  : STC31xx_ForceCC
* Description    :  Force the CC mode for CC eval
* Input          : 
* Return         : error status (OK, !OK)
*******************************************************************************/
int STC31xx_ForceCC(void)
{
  STC311x_ForceCC();

  return (OK);
}

static irqreturn_t stc3115_battery_irq_thread_fn(int irq, void *dev_id)
{
	int i = 0;
	wake_lock_timeout(&bat_wake_lock, BAT_WAKE_LOCK_TIMEOUT*HZ);
	atomic_notifier_call_chain(&batt_state_chg_notifier_list, BAKBATT_PLUGOUT_EVENT, NULL);
	while (i++ <5) {
		msleep(200);
		if (OK == STC31xx_AlarmClear())
			break;
	}
	pr_info("Battery: %s\n", __func__);
	return IRQ_HANDLED;
}

/* -------------------------------------------------------------------------- */
#define OF_PROP_READ(chip, prop, stc311x_dt_property, retval, optional)	\
do {									\
	if (retval)							\
		break;							\
									\
	retval = of_property_read_u32(chip->client->dev.of_node,		\
					"qcom," stc311x_dt_property,	\
					&chip->prop);			\
									\
	if ((retval == -EINVAL) && optional)				\
		retval = 0;						\
	else if (retval)						\
		pr_err("Error reading " #stc311x_dt_property		\
				" property rc = %d\n", rc);		\
} while (0)

static int
stc311x_read_dt_props(struct stc311x_chip *chip)
{
	int rc = 0;
	//struct property *prop;

	OF_PROP_READ(chip, Vmode, "vmode", rc, 0);
	OF_PROP_READ(chip, Alm_SOC, "alm-soc", rc, 0);
	OF_PROP_READ(chip, Alm_Vbat, "alm-vbat", rc, 0);
	OF_PROP_READ(chip, CC_cnf, "cc-cnf", rc, 0);
	OF_PROP_READ(chip, VM_cnf, "vm-cnf", rc, 0);
	OF_PROP_READ(chip, Cnom, "cnom", rc, 0);
	OF_PROP_READ(chip, Rsense, "rsense", rc, 0);
    OF_PROP_READ(chip, RelaxCurrent, "relax-current", rc, 0);
	OF_PROP_READ(chip, Adaptive, "adaptive", rc, 0);
	OF_PROP_READ(chip, ForceExternalTemperature, "external-temp", rc, 0);

#if 0 //CapDerating should be defined int *CapDerating, so still need to modify following code
	prop = of_find_property(chip->client->dev.of_node, "qcom,cap-deratings", NULL);
	if (prop) {
		chip->CapDerating = devm_kzalloc(&chip->client->dev,
				sizeof(int) * CAP_DERATE_MAX_NUM,
				GFP_KERNEL);
		if (!chip->CapDerating)
			return -ENOMEM;
		if ((prop->length/sizeof(u32)) == CAP_DERATE_MAX_NUM) {
			rc = of_property_read_u32_array(chip->client->dev.of_node, "qcom,cap-deratings",
				chip->CapDerating, CAP_DERATE_MAX_NUM);
			if (rc) {
				pr_err("Unable to read cap derating\n");
				return rc;
			}
		} else
			return -EINVAL;
	}

	prop = of_find_property(chip->client->dev.of_node, "qcom,ocv-offset", NULL);
	if (prop) {
		chip->OCVOffset = devm_kzalloc(&chip->client->dev,
				sizeof(int) * OCV_CUREE_MAX_NUM,
				GFP_KERNEL);
		if (!chip->OCVOffset)
			return -ENOMEM;
		if ((prop->length/sizeof(u32)) == OCV_CUREE_MAX_NUM) {
			rc = of_property_read_u32_array(chip->client->dev.of_node, "qcom,ocv-offset",
				chip->OCVOffset, OCV_CUREE_MAX_NUM);
			if (rc) {
				pr_err("Unable to read ocv offset\n");
				return rc;
			}
		} else
			return -EINVAL;
	}
/*	
	rc = of_property_read_u32_array(chip->client->dev.of_node, "qcom,cap-derating",  
                                   chip->CapDerating, ARRAY_SIZE(chip->CapDerating));
	
	rc = of_property_read_u32_array(chip->client->dev.of_node, "qcom,ocv-offset",  
                                   chip->OCVOffset, ARRAY_SIZE(chip->OCVOffset));
*/
#else
	/* Elentec Co Ltd Battery pack - 80 means 8% */
	chip->CapDerating[6] = 250;   /* capacity derating in 0.1%, for temp = -20?C */
    chip->CapDerating[5] = 150;  /* capacity derating in 0.1%, for temp = -10?C */
	chip->CapDerating[4] = 80;    /* capacity derating in 0.1%, for temp = 0?C */
	chip->CapDerating[3] = 30;  /* capacity derating in 0.1%, for temp = 10?C */
	chip->CapDerating[2] = 0;  /* capacity derating in 0.1%, for temp = 25?C */
	chip->CapDerating[1] = 0;  /* capacity derating in 0.1%, for temp = 40?C */
	chip->CapDerating[0] = 0;  /* capacity derating in 0.1%, for temp = 60?C */

    chip->OCVOffset[15] = -11;    /* OCV curve adjustment */
	chip->OCVOffset[14] = -10;   /* OCV curve adjustment */
	chip->OCVOffset[13] = 0;    /* OCV curve adjustment */
	chip->OCVOffset[12] = -3;    /* OCV curve adjustment */
	chip->OCVOffset[11] = -1;    /* OCV curve adjustment */
	chip->OCVOffset[10] = -8;    /* OCV curve adjustment */
	chip->OCVOffset[9] = 11;     /* OCV curve adjustment */
	chip->OCVOffset[8] = 9;      /* OCV curve adjustment */
	chip->OCVOffset[7] = -4;      /* OCV curve adjustment */
	chip->OCVOffset[6] = -16;    /* OCV curve adjustment */
	chip->OCVOffset[5] = -16;    /* OCV curve adjustment */
	chip->OCVOffset[4] = -31;     /* OCV curve adjustment */
	chip->OCVOffset[3] = 5;    /* OCV curve adjustment */
	chip->OCVOffset[2] = 30;     /* OCV curve adjustment */
	chip->OCVOffset[1] = -8;    /* OCV curve adjustment */
	chip->OCVOffset[0] = 0;    /* OCV curve adjustment */
#endif
    if(chip->client->dev.of_node){
		chip->alm_irq = of_get_named_gpio(chip->client->dev.of_node, "qcom,alm-irq-gpio", 0);
	} else {
		pr_err("stc3115 probe of_node fail\n");
		return -ENODEV;
	}
	
	if (rc)
		pr_err("failed to read required dt parameters %d\n", rc);
	return rc;
}
/* -------------------------------------------------------------- */



static void stc311x_work(struct work_struct *work)
{
	struct stc311x_chip *chip;
	GasGauge_DataTypeDef GasGaugeData;
	int old_status, old_online, old_soc;
    int res, Loop;

	chip = container_of(work, struct stc311x_chip, work.work);

	sav_client = chip->client;

	// If force using an external temperature
	if(chip->ForceExternalTemperature == 1)
		// If Battery is still removed and related work, such as bat remove notify, etc. have been done.
		if (!BattData.BattOnline && chip->ExternalTemperature() == (-300)) {
			schedule_delayed_work(&chip->work, STC311x_DELAY);
			return;
		}

    /* we have to init again ? */
	GasGaugeData.Vmode = chip->Vmode;       /* 1=Voltage mode, 0=mixed mode */
	GasGaugeData.Alm_SOC = chip->Alm_SOC;     /* SOC alm level %*/
	GasGaugeData.Alm_Vbat = chip->Alm_Vbat;    /* Vbat alm level mV*/
	GasGaugeData.CC_cnf = chip->CC_cnf;      /* nominal CC_cnf */
	GasGaugeData.VM_cnf = chip->VM_cnf;      /* nominal VM cnf */
	GasGaugeData.Cnom = chip->Cnom;        /* nominal capacity in mAh */
	GasGaugeData.Rsense = chip->Rsense;      /* sense resistor mOhms*/
	GasGaugeData.RelaxCurrent = chip->RelaxCurrent; /* current for relaxation in mA (< C/20) */
	GasGaugeData.Adaptive = chip->Adaptive;     /* 1=Adaptive mode enabled, 0=Adaptive mode disabled */
	/* capacity derating in 0.1%, for temp = 60, 40, 25, 10,   0, -10 ?C */
    for(Loop=0;Loop<NTEMP;Loop++)
		GasGaugeData.CapDerating[Loop] = chip->CapDerating[Loop];   
	/* OCV curve adjustment */
	for(Loop=0;Loop<16;Loop++)
	  	GasGaugeData.OCVOffset[Loop] = chip->OCVOffset[Loop];    
	GasGaugeData.ExternalTemperature = chip->ExternalTemperature(); /*External temperature fonction, return ?C*/
	GasGaugeData.ForceExternalTemperature = chip->ForceExternalTemperature; /* 1=External temperature, 0=STC3115 temperature */

	old_status = chip->status;
	old_online = chip->online;
	old_soc = chip->batt_soc;
	
    res=GasGauge_Task(&GasGaugeData);  /* process gas gauge algorithm, returns results */
    if (res>0)
    {
        /* results available */
        chip->batt_soc = (GasGaugeData.SOC+5)/10;
        chip->batt_voltage = GasGaugeData.Voltage;
        chip->batt_current = GasGaugeData.Current;
    }
	else if(res == 0)
	{
		chip->batt_voltage = GasGaugeData.Voltage;
        chip->batt_soc = (GasGaugeData.SOC+5)/10;
		chip->batt_current = 0;
	}
	else if(res == -1)
	{
		chip->batt_voltage = GasGaugeData.Voltage;
        chip->batt_soc = (GasGaugeData.SOC+5)/10;
	}

	if (BattData.BattOnline == 0)
    {
         /* battery is removed, results clear */
	    chip->batt_soc = 0;
        chip->batt_voltage = 0;
        chip->batt_current = 0;
		 
	}

	/* bad batt_soc discard */
	if (chip->batt_soc < 0)
		chip->batt_soc = 0;
	/* bad batt_voltage discard */
	if (chip->batt_voltage < 0) 
		chip->batt_voltage = 0;

	stc311x_get_status(sav_client);
	stc311x_get_online(sav_client);
	
    if ((chip->status != old_status)
        || (chip->online != old_online)
        || (chip->batt_soc != old_soc))
        power_supply_changed(&chip->stc3115_psy);

	schedule_delayed_work(&chip->work, STC311x_DELAY);
}


static enum power_supply_property stc311x_battery_props[] = {
	POWER_SUPPLY_PROP_STATUS,
	POWER_SUPPLY_PROP_HEALTH,
	POWER_SUPPLY_PROP_ONLINE,
	POWER_SUPPLY_PROP_VOLTAGE_NOW,
	POWER_SUPPLY_PROP_CURRENT_NOW,  
	POWER_SUPPLY_PROP_CAPACITY,
	POWER_SUPPLY_PROP_PRESENT,
	POWER_SUPPLY_PROP_TEMP,
};



static int __devinit stc311x_probe(struct i2c_client *client,
			const struct i2c_device_id *id)
{
  struct i2c_adapter *adapter = to_i2c_adapter(client->dev.parent);
  struct stc311x_chip *chip;
  int ret,res,Loop,irq;

  GasGauge_DataTypeDef GasGaugeData;

  /*First check the functionality supported by the host*/
  if (!i2c_check_functionality(adapter, I2C_FUNC_SMBUS_READ_I2C_BLOCK))
    return -EIO;
  if (!i2c_check_functionality(adapter, I2C_FUNC_SMBUS_WRITE_I2C_BLOCK))
    return -EIO;
  
  /*OK. For now, we presume we have a valid client. We now create the
  client structure*/
  chip = kzalloc(sizeof(struct stc311x_chip), GFP_KERNEL);
  if (!chip)
  {
    printk("Out of memory to create client structure for stc311x\n");
    return -ENOMEM;  /*Out of memory*/
  }

  printk("\n\nstc311x probe started\n\n");
  
  /* The common I2C client data is placed right specific data. */
  chip->client = client;

  /* Get all device tree properties */
  ret = stc311x_read_dt_props(chip);

  chip->health = POWER_SUPPLY_HEALTH_GOOD;
  chip->battery_online = NULL;
  chip->charger_online = charger_is_online;		// used in stc311x_get_status() need defined by ourselves
  chip->charger_enable = charger_is_enable;		// used in stc311x_get_status()
  chip->ExternalTemperature = Temperature_fn;
               
  i2c_set_clientdata(client, chip);
  
  chip->stc3115_psy.name		= "stc3115";
  chip->stc3115_psy.type		= POWER_SUPPLY_TYPE_BMS;
  chip->stc3115_psy.get_property	= stc311x_get_property;
  chip->stc3115_psy.properties	= stc311x_battery_props;
  chip->stc3115_psy.num_properties	= ARRAY_SIZE(stc311x_battery_props);
  chip->stc3115_psy.external_power_changed = stc3115_external_power_changed;
  chip->stc3115_psy.supplied_to = stc3115_supplicants;
  chip->stc3115_psy.num_supplicants = ARRAY_SIZE(stc3115_supplicants);

  ret = power_supply_register(&client->dev, &chip->stc3115_psy);
  if (ret)
  {
	//dev_err(&client->dev, "failed: power supply register\n");

	kfree(chip);
	return ret;
  }

	dev_info(&client->dev, "power supply register,%d\n",ret);

	wake_lock_init(&bat_wake_lock , WAKE_LOCK_SUSPEND, "back_battery_wakelock" );

	stc311x_get_version(client);

	/* init gas gauge system */
	sav_client = chip->client;

	/* init STC311x battery monitoring parameters */
	GasGaugeData.Vmode = chip->Vmode;       /* 1=Voltage mode, 0=mixed mode */
	GasGaugeData.Alm_SOC = chip->Alm_SOC;     /* SOC alm level %*/
	GasGaugeData.Alm_Vbat = chip->Alm_Vbat;    /* Vbat alm level mV*/
	GasGaugeData.CC_cnf = chip->CC_cnf;      /* nominal CC_cnf */
	GasGaugeData.VM_cnf = chip->VM_cnf;      /* nominal VM cnf */
	GasGaugeData.Cnom = chip->Cnom;        /* nominal capacity in mAh */
	GasGaugeData.Rsense = chip->Rsense;      /* sense resistor mOhms*/
	GasGaugeData.RelaxCurrent = chip->RelaxCurrent; /* current for relaxation in mA (< C/20) */
	GasGaugeData.Adaptive = chip->Adaptive;     /* 1=Adaptive mode enabled, 0=Adaptive mode disabled */
	/* capacity derating in 0.1%, for temp = 60, 40, 25, 10, 0, -10 ?C */
	for(Loop=0;Loop<NTEMP;Loop++)
		GasGaugeData.CapDerating[Loop] = chip->CapDerating[Loop];   
	/* OCV curve adjustment */
	for(Loop=0;Loop<OCVTAB_SIZE;Loop++)
		GasGaugeData.OCVOffset[Loop] = chip->OCVOffset[Loop];    
	GasGaugeData.ExternalTemperature = chip->ExternalTemperature(); /*External temperature fonction, return ?C*/
	GasGaugeData.ForceExternalTemperature = chip->ForceExternalTemperature; /* 1=External temperature, 0=STC3115 temperature */


	res=GasGauge_Start(&GasGaugeData);
	if (res < 0)
		goto err_status;
	msleep(200);
	res=GasGauge_Task(&GasGaugeData);  /* process gas gauge algorithm, returns results */
    if (res>0) 
    {
        /* results available */
        chip->batt_soc = (GasGaugeData.SOC+5)/10;
        chip->batt_voltage = GasGaugeData.Voltage;
        chip->batt_current = GasGaugeData.Current;
    }
	else if(res==0)
	{
		/* SOC and Voltage  available */
        chip->batt_soc = (GasGaugeData.SOC+5)/10;
        chip->batt_voltage = GasGaugeData.Voltage;
        chip->batt_current = 0;
	}
	else if(res == -1)
	{
		chip->batt_voltage = GasGaugeData.Voltage;
		chip->batt_soc = (GasGaugeData.SOC+5)/10;
	}

	if (BattData.BattOnline == 0) {
		/* battery is removed, results clear */
		chip->batt_soc = 0;
		chip->batt_voltage = 0;
		chip->batt_current = 0;
	}

	printk("STC3115 Init soc: %d, voltage: %d, current: %d\n", chip->batt_soc, chip->batt_voltage, chip->batt_current);
	
	INIT_DELAYED_WORK_DEFERRABLE(&chip->work, stc311x_work);

	//The fallow scheduled task is using specific delay to improve measurement accuracy. 
	//This delay should be set between 1.2 or 1.3 seconds. I2C signals can help do debug the good behavior of the delay
	schedule_delayed_work(&chip->work, STC311x_DELAY); 
	//The specified delay depends of every platform and Linux kernel. It has to be checked physically during the driver integration

	ret = gpio_request(chip->alm_irq, "alm_int");
	if (ret){
		dev_err(&client->dev, "stc3115 alm_int request fail\n");
		return -ENODEV;
	}
	gpio_direction_input(chip->alm_irq);
	irq = gpio_to_irq(chip->alm_irq);
	if (irq < 0) {
		goto err_irq_fail;
	}
	client->irq = irq;
	ret = request_threaded_irq(client->irq, NULL, stc3115_battery_irq_thread_fn,
			  IRQF_TRIGGER_FALLING|IRQF_NO_SUSPEND|IRQF_ONESHOT, client->name, chip);
	if (ret) {
		dev_err(&client->dev, "stc3115 request_irq failed\n");
		goto err_irq_fail;
	}
	enable_irq_wake(client->irq);

	return 0;

err_irq_fail:
	gpio_free(chip->alm_irq);
	cancel_delayed_work_sync(&chip->work);
err_status:
	wake_lock_destroy(&bat_wake_lock);
	power_supply_unregister(&chip->stc3115_psy);
	kfree(chip);
	return ret;
}



static int __devexit stc311x_remove(struct i2c_client *client)
{
	struct stc311x_chip *chip = i2c_get_clientdata(client);

	disable_irq_wake(chip->client->irq);
	free_irq(client->irq, chip);
	gpio_free(chip->alm_irq);

	/* stop gas gauge system */
	sav_client = chip->client;
	GasGauge_Stop();
	
	cancel_delayed_work_sync(&chip->work);
	wake_lock_destroy(&bat_wake_lock);
	power_supply_unregister(&chip->stc3115_psy);

	kfree(chip);
	
	return 0;
}



#ifdef CONFIG_PM

static int stc311x_suspend(struct i2c_client *client,
		pm_message_t state)
{
	struct stc311x_chip *chip = i2c_get_clientdata(client);

	bat_check_counter = 0;
	cancel_delayed_work_sync(&chip->work);
	return 0;
}

static int stc311x_resume(struct i2c_client *client)
{
	struct stc311x_chip *chip = i2c_get_clientdata(client);

	schedule_delayed_work(&chip->work, 0);
	bat_check_counter = 0;
	return 0;
}

#else

#define stc311x_suspend NULL
#define stc311x_resume NULL

#endif /* CONFIG_PM */



static struct of_device_id stc311x_match_table[] = {	
	{ .compatible = "qcom,stc3115",},	
    { },	
	};	

/* Every chip have a unique id */
static const struct i2c_device_id stc311x_id[] = {
	{ "stc3115", 0 },
	{ }
};

/* Every chip have a unique id and we need to register this ID using MODULE_DEVICE_TABLE*/
MODULE_DEVICE_TABLE(i2c, stc311x_id);

static struct i2c_driver stc311x_i2c_driver = {
    .driver	= {
		.name	= "stc3115",
		.owner	= THIS_MODULE,
		.of_match_table = stc311x_match_table,
	},
    .probe		= stc311x_probe,
	.remove		= __devexit_p(stc311x_remove),
    .suspend     = stc311x_suspend,
    .resume     = stc311x_resume,
    .id_table	= stc311x_id,
};

/*To register this I2C chip driver, the function i2c_add_driver should be called 
with a pointer to the struct i2c_driver*/
static int __init stc311x_init(void)
{
	return i2c_add_driver(&stc311x_i2c_driver);
}
module_init(stc311x_init);

/*To unregister the I2C chip driver, the i2c_del_driver function should be called
with the same pointer to the struct i2c_driver*/
static void __exit stc311x_exit(void)
{
	i2c_del_driver(&stc311x_i2c_driver);
}
module_exit(stc311x_exit);

MODULE_AUTHOR("ST IMS SYSTEMS LAB");
MODULE_DESCRIPTION("STC311x Fuel Gauge");
MODULE_LICENSE("GPL");


