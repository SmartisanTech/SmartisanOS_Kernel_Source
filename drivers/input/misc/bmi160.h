/*
****************************************************************************
* Copyright (C) 2014 Bosch Sensortec GmbH
*
* bmi160.h
* Date: 2014/08/28
* @id       "b3ccb9e"
* Revision: 2.0 $
* @brief
* The head file of BMI160API
*/
/*! \file bmi160.h
    \brief BMI160 Sensor Driver Support Header File */
/* user defined code to be added here ... */
#ifndef __BMI160_H__
#define __BMI160_H__

/*******************************************************
* These definition uses for define the data types
********************************************************
* While porting the API please consider the following
* Please check the version of C standard
* Are you using Linux platform
*******************************************************/

/*********************************************************
* This definition uses for the Linux platform support
* Please use the types.h for your data types definitions
*********************************************************/
#ifdef	__KERNEL__

#include <linux/types.h>

#else /* ! __KERNEL__ */
/**********************************************************
* These definition uses for define the C
* standard version data types
***********************************************************/
# if !defined(__STDC_VERSION__)

/************************************************
 * compiler is C11 C standard
************************************************/
#if (__STDC_VERSION__ == 201112L)

/************************************************/
#include <stdint.h>
/************************************************/

/*unsigned integer types*/
#define	u8	uint8_t
#define	u16	uint16_t
#define	u32	uint32_t
#define	u64	uint64_t

/*signed integer types*/
#define	s8	int8_t
#define	s16	int16_t
#define	s32	int32_t
#define	s64	int64_t
/************************************************
 * compiler is C99 C standard
************************************************/

#elif (__STDC_VERSION__ == 199901L)

/* stdint.h is a C99 supported c library.
which is used to fixed the integer size*/
/************************************************/
#include <stdint.h>
/************************************************/

/*unsigned integer types*/
#define	u8	uint8_t
#define	u16	uint16_t
#define	u32	uint32_t
#define	u64	uint64_t

/*signed integer types*/
#define s8	int8_t
#define	s16	int16_t
#define	s32	int32_t
#define	s64	int64_t
/************************************************
 * compiler is C89 or other C standard
************************************************/
#else /*  !defined(__STDC_VERSION__) */
/*	By default it is defined as 32 bit machine configuration*/
/*	define the definition based on your machine configuration*/
/*	define the data types based on your
	machine/compiler/controller configuration*/
#define  MACHINE_32_BIT

/* If your machine support 16 bit
define the MACHINE_16_BIT*/
#ifdef MACHINE_16_BIT
#include <limits.h>
/*signed integer types*/
#define	s8	signed char
#define	s16	signed short int
#define	s32	signed long int

#if defined(LONG_MAX) && LONG_MAX == 0x7fffffffffffffffL
#define s64 long int
#define u64 unsigned long int
#elif defined(LLONG_MAX) && (LLONG_MAX == 0x7fffffffffffffffLL)
#define s64 long long int
#define u64 unsigned long long int
#else
#warning Either the correct data type for signed 64 bit integer \
could not be found, or 64 bit integers are not supported in your environment.
#warning If 64 bit integers are supported on your platform, \
please set s64 manually.
#endif

/*unsigned integer types*/
#define	u8	unsigned char
#define	u16	unsigned short int
#define	u32	unsigned long int

/* If your machine support 32 bit
define the MACHINE_32_BIT*/
#elif defined MACHINE_32_BIT
/*signed integer types*/
#define	s8	signed char
#define	s16	signed short int
#define	s32	signed int
#define	s64	signed long long int

/*unsigned integer types*/
#define	u8	unsigned char
#define	u16	unsigned short int
#define	u32	unsigned int
#define	u64	unsigned long long int

/* If your machine support 64 bit
define the MACHINE_64_BIT*/
#elif defined MACHINE_64_BIT
/*signed integer types*/
#define	s8	signed char
#define	s16	signed short int
#define	s32	signed int
#define	s64	signed long int

/*unsigned integer types*/
#define	u8	unsigned char
#define	u16	unsigned short int
#define	u32	unsigned int
#define	u64	unsigned long int

#else
#warning The data types defined above which not supported \
define the data types manually
#endif
#endif

/*** This else will execute for the compilers
 *	which are not supported the C standards
 *	Like C89/C99/C11***/
#else
/*	By default it is defined as 32 bit machine configuration*/
/*	define the definition based on your machine configuration*/
/*	define the data types based on your
	machine/compiler/controller configuration*/
#define  MACHINE_32_BIT

/* If your machine support 16 bit
define the MACHINE_16_BIT*/
#ifdef MACHINE_16_BIT
#include <limits.h>
/*signed integer types*/
#define	s8	signed char
#define	s16	signed short int
#define	s32	signed long int

#if defined(LONG_MAX) && LONG_MAX == 0x7fffffffffffffffL
#define s64 long int
#define u64 unsigned long int
#elif defined(LLONG_MAX) && (LLONG_MAX == 0x7fffffffffffffffLL)
#define s64 long long int
#define u64 unsigned long long int
#else
#warning Either the correct data type for signed 64 bit integer \
could not be found, or 64 bit integers are not supported in your environment.
#warning If 64 bit integers are supported on your platform, \
please set s64 manually.
#endif

/*unsigned integer types*/
#define	u8	unsigned char
#define	u16	unsigned short int
#define	u32	unsigned long int

/* If your machine support 32 bit
define the MACHINE_32_BIT*/
#elif defined MACHINE_32_BIT
/*signed integer types*/
#define	s8	signed char
#define	s16	signed short int
#define	s32	signed int
#define	s64	signed long long int

/*unsigned integer types*/
#define	u8	unsigned char
#define	u16	unsigned short int
#define	u32	unsigned int
#define	u64	unsigned long long int

/* If your machine support 64 bit
define the MACHINE_64_BIT*/
#elif defined  MACHINE_64_BIT
/*signed integer types*/
#define	s8	signed char
#define	s16	signed short int
#define	s32	signed int
#define	s64	signed long int

/*unsigned integer types*/
#define	u8	unsigned char
#define	u16	unsigned short int
#define	u32	unsigned int
#define	u64	unsigned long int

#else
#warning The data types defined above which not supported \
define the data types manually
#endif
#endif
#endif
/*Example....*/
/*#define YOUR_H_DEFINE */ /**< <Doxy Comment for YOUR_H_DEFINE> */
/** Define the calling convention of YOUR bus communication routine.
	\note This includes types of parameters. This example shows the
	configuration for an SPI bus link.

    If your communication function looks like this:

    write_my_bus_xy(u8 device_addr, u8 register_addr,
    u8 * data, u8 length);

    The BMI160_WR_FUNC_PTR would equal:

    #define     BMI160_WR_FUNC_PTR s8 (* bus_write)(u8,
    u8, u8 *, u8)

    Parameters can be mixed as needed refer to the
    \ref BMI160_BUS_WRITE_FUNC  macro.


*/
#define BMI160_WR_FUNC_PTR s8 (*bus_write)(u8, u8 ,\
u8 *, u8)



/** link macro between API function calls and bus write function
	\note The bus write function can change since this is a
	system dependant issue.

    If the bus_write parameter calling order is like: reg_addr,
    reg_data, wr_len it would be as it is here.

    If the parameters are differently ordered or your communication
    function like I2C need to know the device address,
    you can change this macro accordingly.


    define BMI160_BUS_WRITE_FUNC(dev_addr, reg_addr, reg_data, wr_len)\
    bus_write(dev_addr, reg_addr, reg_data, wr_len)

    This macro lets all API functions call YOUR communication routine in a
    way that equals your definition in the
    \ref BMI160_WR_FUNC_PTR definition.

*/
#define BMI160_BUS_WRITE_FUNC(dev_addr, reg_addr, reg_data, wr_len)\
				bus_write(dev_addr, reg_addr, reg_data, wr_len)


/** Define the calling convention of YOUR bus communication routine.
	\note This includes types of parameters. This example shows the
	configuration for an SPI bus link.

    If your communication function looks like this:

    read_my_bus_xy(u8 device_addr, u8 register_addr,
    u8 * data, u8 length);

    The BMI160_RD_FUNC_PTR would equal:

    #define     BMI160_RD_FUNC_PTR s8 (* bus_read)(u8,
    u8, u8 *, u8)

    Parameters can be mixed as needed refer to the
    \ref BMI160_BUS_READ_FUNC  macro.


*/

#define BMI160_SPI_RD_MASK 0x80   /* for spi read transactions on SPI the
			MSB has to be set */
#define BMI160_RD_FUNC_PTR s8 (*bus_read)(u8,\
			u8 , u8 *, u8)

#define BMI160_BRD_FUNC_PTR s8 \
(*burst_read)(u8, u8, u8 *, u32)

/** link macro between API function calls and bus read function
	\note The bus write function can change since this is a
	system dependant issue.

    If the bus_read parameter calling order is like: reg_addr,
    reg_data, wr_len it would be as it is here.

    If the parameters are differently ordered or your communication
    function like I2C need to know the device address,
    you can change this macro accordingly.


    define BMI160_BUS_READ_FUNC(dev_addr, reg_addr, reg_data, wr_len)\
    bus_read(dev_addr, reg_addr, reg_data, wr_len)

    This macro lets all API functions call YOUR communication routine in a
    way that equals your definition in the
    \ref BMI160_WR_FUNC_PTR definition.

    \note: this macro also includes the "MSB='1'"
    for reading BMI160 addresses.

*/
#define BMI160_BUS_READ_FUNC(dev_addr, reg_addr, reg_data, r_len)\
				bus_read(dev_addr, reg_addr, reg_data, r_len)

#define BMI160_BURST_READ_FUNC(device_addr, \
register_addr, register_data, rd_len)\
burst_read(device_addr, register_addr, register_data, rd_len)


#define BMI160_MDELAY_DATA_TYPE                 u32

/** BMI160 I2C Address
*/
#define BMI160_I2C_ADDR1	0x68 /* I2C Address needs to be changed */
#define BMI160_I2C_ADDR2    0x69 /* I2C Address needs to be changed */

#define         C_BMI160_ZERO_U8X                       ((u8)0)
#define         C_BMI160_ONE_U8X                        ((u8)1)
#define         C_BMI160_TWO_U8X                        ((u8)2)
#define         C_BMI160_THREE_U8X                      ((u8)3)
#define         C_BMI160_FOUR_U8X                       ((u8)4)
#define         C_BMI160_FIVE_U8X                       ((u8)5)
#define         C_BMI160_SIX_U8X                        ((u8)6)
#define         C_BMI160_SEVEN_U8X                      ((u8)7)
#define         C_BMI160_EIGHT_U8X                      ((u8)8)
#define         C_BMI160_NINE_U8X                       ((u8)9)
#define         C_BMI160_ELEVEN_U8X                     ((u8)11)
#define         C_BMI160_TWELVE_U8X                     ((u8)12)
#define         C_BMI160_FOURTEEN_U8X                   ((u8)14)

#define         C_BMI160_FIFTEEN_U8X                    ((u8)15)
#define         C_BMI160_SIXTEEN_U8X                    ((u8)16)
#define         C_BMI160_THIRTYONE_U8X                  ((u8)31)
#define         C_BMI160_THIRTYTWO_U8X                  ((u8)32)
#define         BMI160_MAXIMUM_TIMEOUT                  ((u8)10)

/*  BMI160 API error codes */

#define E_BMI160_NULL_PTR              ((s8)-127)
#define E_BMI160_COMM_RES              ((s8)-1)
#define E_BMI160_OUT_OF_RANGE          ((s8)-2)
#define E_BMI160_EEPROM_BUSY           ((s8)-3)

/* Constants */
#define BMI160_NULL                          0
/*This refers BMI160 return type as s8 */
#define BMI160_RETURN_FUNCTION_TYPE        s8
/*------------------------------------------------------------------------
* Register Definitions of User start
*------------------------------------------------------------------------*/
#define BMI160_USER_CHIP_ID_ADDR				0x00
#define BMI160_USER_ERROR_ADDR					0X02
#define BMI160_USER_PMU_STATUS_ADDR				0X03
#define BMI160_USER_DATA_0_ADDR					0X04
#define BMI160_USER_DATA_1_ADDR					0X05
#define BMI160_USER_DATA_2_ADDR					0X06
#define BMI160_USER_DATA_3_ADDR					0X07
#define BMI160_USER_DATA_4_ADDR					0X08
#define BMI160_USER_DATA_5_ADDR					0X09
#define BMI160_USER_DATA_6_ADDR					0X0A
#define BMI160_USER_DATA_7_ADDR					0X0B
#define BMI160_USER_DATA_8_ADDR					0X0C
#define BMI160_USER_DATA_9_ADDR					0X0D
#define BMI160_USER_DATA_10_ADDR				0X0E
#define BMI160_USER_DATA_11_ADDR				0X0F
#define BMI160_USER_DATA_12_ADDR				0X10
#define BMI160_USER_DATA_13_ADDR				0X11
#define BMI160_USER_DATA_14_ADDR				0X12
#define BMI160_USER_DATA_15_ADDR				0X13
#define BMI160_USER_DATA_16_ADDR				0X14
#define BMI160_USER_DATA_17_ADDR				0X15
#define BMI160_USER_DATA_18_ADDR				0X16
#define BMI160_USER_DATA_19_ADDR				0X17
#define BMI160_USER_SENSORTIME_0_ADDR			0X18
#define BMI160_USER_SENSORTIME_1_ADDR			0X19
#define BMI160_USER_SENSORTIME_2_ADDR			0X1A
#define BMI160_USER_STATUS_ADDR					0X1B
#define BMI160_USER_INT_STATUS_0_ADDR			0X1C
#define BMI160_USER_INT_STATUS_1_ADDR			0X1D
#define BMI160_USER_INT_STATUS_2_ADDR			0X1E
#define BMI160_USER_INT_STATUS_3_ADDR			0X1F
#define BMI160_USER_TEMPERATURE_0_ADDR			0X20
#define BMI160_USER_TEMPERATURE_1_ADDR			0X21
#define BMI160_USER_FIFO_LENGTH_0_ADDR			0X22
#define BMI160_USER_FIFO_LENGTH_1_ADDR			0X23
#define BMI160_USER_FIFO_DATA_ADDR				0X24
#define BMI160_USER_ACC_CONF_ADDR				0X40
#define BMI160_USER_ACC_RANGE_ADDR              0X41
#define BMI160_USER_GYR_CONF_ADDR               0X42
#define BMI160_USER_GYR_RANGE_ADDR              0X43
#define BMI160_USER_MAG_CONF_ADDR				0X44
#define BMI160_USER_FIFO_DOWNS_ADDR             0X45
#define BMI160_USER_FIFO_CONFIG_0_ADDR          0X46
#define BMI160_USER_FIFO_CONFIG_1_ADDR          0X47
#define BMI160_USER_MAG_IF_0_ADDR				0X4B
#define BMI160_USER_MAG_IF_1_ADDR				0X4C
#define BMI160_USER_MAG_IF_2_ADDR				0X4D
#define BMI160_USER_MAG_IF_3_ADDR				0X4E
#define BMI160_USER_MAG_IF_4_ADDR				0X4F
#define BMI160_USER_INT_EN_0_ADDR				0X50
#define BMI160_USER_INT_EN_1_ADDR               0X51
#define BMI160_USER_INT_EN_2_ADDR               0X52
#define BMI160_USER_INT_OUT_CTRL_ADDR			0X53
#define BMI160_USER_INT_LATCH_ADDR				0X54
#define BMI160_USER_INT_MAP_0_ADDR				0X55
#define BMI160_USER_INT_MAP_1_ADDR				0X56
#define BMI160_USER_INT_MAP_2_ADDR				0X57
#define BMI160_USER_INT_DATA_0_ADDR				0X58
#define BMI160_USER_INT_DATA_1_ADDR				0X59
#define BMI160_USER_INT_LOWHIGH_0_ADDR			0X5A
#define BMI160_USER_INT_LOWHIGH_1_ADDR			0X5B
#define BMI160_USER_INT_LOWHIGH_2_ADDR			0X5C
#define BMI160_USER_INT_LOWHIGH_3_ADDR			0X5D
#define BMI160_USER_INT_LOWHIGH_4_ADDR			0X5E
#define BMI160_USER_INT_MOTION_0_ADDR			0X5F
#define BMI160_USER_INT_MOTION_1_ADDR			0X60
#define BMI160_USER_INT_MOTION_2_ADDR			0X61
#define BMI160_USER_INT_MOTION_3_ADDR			0X62
#define BMI160_USER_INT_TAP_0_ADDR				0X63
#define BMI160_USER_INT_TAP_1_ADDR				0X64
#define BMI160_USER_INT_ORIENT_0_ADDR			0X65
#define BMI160_USER_INT_ORIENT_1_ADDR			0X66
#define BMI160_USER_INT_FLAT_0_ADDR				0X67
#define BMI160_USER_INT_FLAT_1_ADDR				0X68
#define BMI160_USER_FOC_CONF_ADDR				0X69
#define BMI160_USER_CONF_ADDR					0X6A
#define BMI160_USER_IF_CONF_ADDR				0X6B
#define BMI160_USER_PMU_TRIGGER_ADDR			0X6C
#define BMI160_USER_SELF_TEST_ADDR				0X6D
#define BMI160_USER_NV_CONF_ADDR				0x70
#define BMI160_USER_OFFSET_0_ADDR				0X71
#define BMI160_USER_OFFSET_1_ADDR				0X72
#define BMI160_USER_OFFSET_2_ADDR				0X73
#define BMI160_USER_OFFSET_3_ADDR				0X74
#define BMI160_USER_OFFSET_4_ADDR				0X75
#define BMI160_USER_OFFSET_5_ADDR				0X76
#define BMI160_USER_OFFSET_6_ADDR				0X77
#define BMI160_USER_STEP_CNT_0_ADDR				0X78
#define BMI160_USER_STEP_CNT_1_ADDR				0X79
#define BMI160_USER_STEP_CONF_0_ADDR			0X7A
#define BMI160_USER_STEP_CONF_1_ADDR			0X7B
/*------------------------------------------------------------------------
* End of Register Definitions of User
*------------------------------------------------------------------------*/
/*------------------------------------------------------------------------
* Start of Register Definitions of CMD
*------------------------------------------------------------------------*/
 #define BMI160_CMD_COMMANDS_ADDR				0X7E
 #define BMI160_CMD_EXT_MODE_ADDR				0X7F

 #define BMI160_COM_C_TRIM_FIVE_ADDR		0X85
/*------------------------------------------------------------------------
* End of Register Definitions of CMD
*------------------------------------------------------------------------*/

#define BMI160_SHIFT_1_POSITION                 1
#define BMI160_SHIFT_2_POSITION                 2
#define BMI160_SHIFT_3_POSITION                 3
#define BMI160_SHIFT_4_POSITION                 4
#define BMI160_SHIFT_5_POSITION                 5
#define BMI160_SHIFT_6_POSITION                 6
#define BMI160_SHIFT_7_POSITION                 7
#define BMI160_SHIFT_8_POSITION                 8
#define BMI160_SHIFT_12_POSITION                12
#define BMI160_SHIFT_16_POSITION                16

#define	SUCCESS						((u8)0)
#define	ERROR						((s8)-1)
/** bmi160 magnetometer data
* brief Structure containing magnetometer values for x,y and
* z-axis in s16
*/

#define BMI160_DELAY_SETTLING_TIME         5

struct bmi160mag_t {
s16 x;
s16 y;
s16 z;
u16 r;
};

/** bmi160 gyro data
* brief Structure containing gyro values for x,y and
* z-axis in s16
*/
struct bmi160gyro_t {
s16 x,
y,
z;
};

/** bmi160 accelerometer data
* brief Structure containing accelerometer values for x,y and
* z-axis in s16
*/
struct bmi160acc_t {
s16 x,
y,
z;
};
/* used to read the mag compensated values*/
struct bmi160_mag_xyz {
s16 x;
s16 y;
s16 z;
};
/* struct used for read the value
of mag trim values*/
struct trim_data {
s8 dig_x1;
s8 dig_y1;

s8 dig_x2;
s8 dig_y2;

u16 dig_z1;
s16 dig_z2;
s16 dig_z3;
s16 dig_z4;

u8 dig_xy1;
u8 dig_xy2;

u16 dig_xyz1;
};
/* bmi160 structure
* This structure holds all relevant information about bmi160
*/
struct bmi160_t {
u8 chip_id;
u8 dev_addr;
BMI160_WR_FUNC_PTR;
BMI160_RD_FUNC_PTR;
BMI160_BRD_FUNC_PTR;
void (*delay_msec)(BMI160_MDELAY_DATA_TYPE);
};

/* USER DATA REGISTERS DEFINITION START */
/* Chip ID Description - Reg Addr --> 0x00, Bit --> 0...7 */
#define BMI160_USER_CHIP_ID__POS             0
#define BMI160_USER_CHIP_ID__MSK            0xFF
#define BMI160_USER_CHIP_ID__LEN             8
#define BMI160_USER_CHIP_ID__REG             BMI160_USER_CHIP_ID_ADDR

/* Error Description - Reg Addr --> 0x02, Bit --> 0 */
#define BMI160_USER_ERROR_STATUS__POS               0
#define BMI160_USER_ERROR_STATUS__LEN               8
#define BMI160_USER_ERROR_STATUS__MSK               0xFF
#define BMI160_USER_ERROR_STATUS__REG               BMI160_USER_ERROR_ADDR

#define BMI160_USER_FATAL_ERR__POS               0
#define BMI160_USER_FATAL_ERR__LEN               1
#define BMI160_USER_FATAL_ERR__MSK               0x01
#define BMI160_USER_FATAL_ERR__REG               BMI160_USER_ERROR_ADDR

/* Error Description - Reg Addr --> 0x02, Bit --> 1...4 */
#define BMI160_USER_ERROR_CODE__POS               1
#define BMI160_USER_ERROR_CODE__LEN               4
#define BMI160_USER_ERROR_CODE__MSK               0x1E
#define BMI160_USER_ERROR_CODE__REG               BMI160_USER_ERROR_ADDR

/* Error Description - Reg Addr --> 0x02, Bit --> 5 */
#define BMI160_USER_I2C_FAIL_ERR__POS               5
#define BMI160_USER_I2C_FAIL_ERR__LEN               1
#define BMI160_USER_I2C_FAIL_ERR__MSK               0x20
#define BMI160_USER_I2C_FAIL_ERR__REG               BMI160_USER_ERROR_ADDR

/* Error Description - Reg Addr --> 0x02, Bit --> 6 */
#define BMI160_USER_DROP_CMD_ERR__POS              6
#define BMI160_USER_DROP_CMD_ERR__LEN              1
#define BMI160_USER_DROP_CMD_ERR__MSK              0x40
#define BMI160_USER_DROP_CMD_ERR__REG              BMI160_USER_ERROR_ADDR

/* Error Description - Reg Addr --> 0x02, Bit --> 7 */
#define BMI160_USER_MAG_DRDY_ERR__POS               7
#define BMI160_USER_MAG_DRDY_ERR__LEN               1
#define BMI160_USER_MAG_DRDY_ERR__MSK               0x80
#define BMI160_USER_MAG_DRDY_ERR__REG               BMI160_USER_ERROR_ADDR

/* PMU_Status Description of MAG - Reg Addr --> 0x03, Bit --> 1..0 */
#define BMI160_USER_MAG_PMU_STATUS__POS		0
#define BMI160_USER_MAG_PMU_STATUS__LEN		2
#define BMI160_USER_MAG_PMU_STATUS__MSK		0x03
#define BMI160_USER_MAG_PMU_STATUS__REG		BMI160_USER_PMU_STATUS_ADDR

/* PMU_Status Description of GYRO - Reg Addr --> 0x03, Bit --> 3...2 */
#define BMI160_USER_GYR_PMU_STATUS__POS               2
#define BMI160_USER_GYR_PMU_STATUS__LEN               2
#define BMI160_USER_GYR_PMU_STATUS__MSK               0x0C
#define BMI160_USER_GYR_PMU_STATUS__REG		BMI160_USER_PMU_STATUS_ADDR

/* PMU_Status Description of ACCEL - Reg Addr --> 0x03, Bit --> 5...4 */
#define BMI160_USER_ACC_PMU_STATUS__POS               4
#define BMI160_USER_ACC_PMU_STATUS__LEN               2
#define BMI160_USER_ACC_PMU_STATUS__MSK               0x30
#define BMI160_USER_ACC_PMU_STATUS__REG		BMI160_USER_PMU_STATUS_ADDR

/* Mag_X(LSB) Description - Reg Addr --> 0x04, Bit --> 0...7 */
#define BMI160_USER_DATA_0_MAG_X_LSB__POS           0
#define BMI160_USER_DATA_0_MAG_X_LSB__LEN           8
#define BMI160_USER_DATA_0_MAG_X_LSB__MSK          0xFF
#define BMI160_USER_DATA_0_MAG_X_LSB__REG           BMI160_USER_DATA_0_ADDR

/* Mag_X(LSB) Description - Reg Addr --> 0x04, Bit --> 3...7 */
#define BMI160_USER_DATA_MAG_X_LSB__POS           3
#define BMI160_USER_DATA_MAG_X_LSB__LEN           5
#define BMI160_USER_DATA_MAG_X_LSB__MSK          0xF8
#define BMI160_USER_DATA_MAG_X_LSB__REG          BMI160_USER_DATA_0_ADDR

/* Mag_X(MSB) Description - Reg Addr --> 0x05, Bit --> 0...7 */
#define BMI160_USER_DATA_1_MAG_X_MSB__POS           0
#define BMI160_USER_DATA_1_MAG_X_MSB__LEN           8
#define BMI160_USER_DATA_1_MAG_X_MSB__MSK          0xFF
#define BMI160_USER_DATA_1_MAG_X_MSB__REG          BMI160_USER_DATA_1_ADDR

/* Mag_Y(LSB) Description - Reg Addr --> 0x06, Bit --> 0...7 */
#define BMI160_USER_DATA_2_MAG_Y_LSB__POS           0
#define BMI160_USER_DATA_2_MAG_Y_LSB__LEN           8
#define BMI160_USER_DATA_2_MAG_Y_LSB__MSK          0xFF
#define BMI160_USER_DATA_2_MAG_Y_LSB__REG          BMI160_USER_DATA_2_ADDR

/* Mag_Y(LSB) Description - Reg Addr --> 0x06, Bit --> 3...7 */
#define BMI160_USER_DATA_MAG_Y_LSB__POS           3
#define BMI160_USER_DATA_MAG_Y_LSB__LEN           5
#define BMI160_USER_DATA_MAG_Y_LSB__MSK          0xF8
#define BMI160_USER_DATA_MAG_Y_LSB__REG          BMI160_USER_DATA_2_ADDR

/* Mag_Y(MSB) Description - Reg Addr --> 0x07, Bit --> 0...7 */
#define BMI160_USER_DATA_3_MAG_Y_MSB__POS           0
#define BMI160_USER_DATA_3_MAG_Y_MSB__LEN           8
#define BMI160_USER_DATA_3_MAG_Y_MSB__MSK          0xFF
#define BMI160_USER_DATA_3_MAG_Y_MSB__REG          BMI160_USER_DATA_3_ADDR

/* Mag_Z(LSB) Description - Reg Addr --> 0x08, Bit --> 0...7 */
#define BMI160_USER_DATA_4_MAG_Z_LSB__POS           0
#define BMI160_USER_DATA_4_MAG_Z_LSB__LEN           8
#define BMI160_USER_DATA_4_MAG_Z_LSB__MSK          0xFF
#define BMI160_USER_DATA_4_MAG_Z_LSB__REG          BMI160_USER_DATA_4_ADDR

/* Mag_X(LSB) Description - Reg Addr --> 0x08, Bit --> 3...7 */
#define BMI160_USER_DATA_MAG_Z_LSB__POS           1
#define BMI160_USER_DATA_MAG_Z_LSB__LEN           7
#define BMI160_USER_DATA_MAG_Z_LSB__MSK          0xFE
#define BMI160_USER_DATA_MAG_Z_LSB__REG          BMI160_USER_DATA_4_ADDR

/* Mag_Z(MSB) Description - Reg Addr --> 0x09, Bit --> 0...7 */
#define BMI160_USER_DATA_5_MAG_Z_MSB__POS           0
#define BMI160_USER_DATA_5_MAG_Z_MSB__LEN           8
#define BMI160_USER_DATA_5_MAG_Z_MSB__MSK          0xFF
#define BMI160_USER_DATA_5_MAG_Z_MSB__REG          BMI160_USER_DATA_5_ADDR

/* RHALL(LSB) Description - Reg Addr --> 0x0A, Bit --> 0...7 */
#define BMI160_USER_DATA_6_RHALL_LSB__POS           0
#define BMI160_USER_DATA_6_RHALL_LSB__LEN           8
#define BMI160_USER_DATA_6_RHALL_LSB__MSK          0xFF
#define BMI160_USER_DATA_6_RHALL_LSB__REG          BMI160_USER_DATA_6_ADDR

/* Mag_R(LSB) Description - Reg Addr --> 0x0A, Bit --> 3...7 */
#define BMI160_USER_DATA_MAG_R_LSB__POS           2
#define BMI160_USER_DATA_MAG_R_LSB__LEN           6
#define BMI160_USER_DATA_MAG_R_LSB__MSK          0xFC
#define BMI160_USER_DATA_MAG_R_LSB__REG          BMI160_USER_DATA_6_ADDR

/* RHALL(MSB) Description - Reg Addr --> 0x0B, Bit --> 0...7 */
#define BMI160_USER_DATA_7_RHALL_MSB__POS           0
#define BMI160_USER_DATA_7_RHALL_MSB__LEN           8
#define BMI160_USER_DATA_7_RHALL_MSB__MSK          0xFF
#define BMI160_USER_DATA_7_RHALL_MSB__REG          BMI160_USER_DATA_7_ADDR

/* GYR_X (LSB) Description - Reg Addr --> 0x0C, Bit --> 0...7 */
#define BMI160_USER_DATA_8_GYR_X_LSB__POS           0
#define BMI160_USER_DATA_8_GYR_X_LSB__LEN           8
#define BMI160_USER_DATA_8_GYR_X_LSB__MSK          0xFF
#define BMI160_USER_DATA_8_GYR_X_LSB__REG          BMI160_USER_DATA_8_ADDR

/* GYR_X (MSB) Description - Reg Addr --> 0x0D, Bit --> 0...7 */
#define BMI160_USER_DATA_9_GYR_X_MSB__POS           0
#define BMI160_USER_DATA_9_GYR_X_MSB__LEN           8
#define BMI160_USER_DATA_9_GYR_X_MSB__MSK          0xFF
#define BMI160_USER_DATA_9_GYR_X_MSB__REG          BMI160_USER_DATA_9_ADDR

/* GYR_Y (LSB) Description - Reg Addr --> 0x0E, Bit --> 0...7 */
#define BMI160_USER_DATA_10_GYR_Y_LSB__POS           0
#define BMI160_USER_DATA_10_GYR_Y_LSB__LEN           8
#define BMI160_USER_DATA_10_GYR_Y_LSB__MSK          0xFF
#define BMI160_USER_DATA_10_GYR_Y_LSB__REG          BMI160_USER_DATA_10_ADDR

/* GYR_Y (MSB) Description - Reg Addr --> 0x0F, Bit --> 0...7 */
#define BMI160_USER_DATA_11_GYR_Y_MSB__POS           0
#define BMI160_USER_DATA_11_GYR_Y_MSB__LEN           8
#define BMI160_USER_DATA_11_GYR_Y_MSB__MSK          0xFF
#define BMI160_USER_DATA_11_GYR_Y_MSB__REG          BMI160_USER_DATA_11_ADDR

/* GYR_Z (LSB) Description - Reg Addr --> 0x10, Bit --> 0...7 */
#define BMI160_USER_DATA_12_GYR_Z_LSB__POS           0
#define BMI160_USER_DATA_12_GYR_Z_LSB__LEN           8
#define BMI160_USER_DATA_12_GYR_Z_LSB__MSK          0xFF
#define BMI160_USER_DATA_12_GYR_Z_LSB__REG          BMI160_USER_DATA_12_ADDR

/* GYR_Z (MSB) Description - Reg Addr --> 0x11, Bit --> 0...7 */
#define BMI160_USER_DATA_13_GYR_Z_MSB__POS           0
#define BMI160_USER_DATA_13_GYR_Z_MSB__LEN           8
#define BMI160_USER_DATA_13_GYR_Z_MSB__MSK          0xFF
#define BMI160_USER_DATA_13_GYR_Z_MSB__REG          BMI160_USER_DATA_13_ADDR

/* ACC_X (LSB) Description - Reg Addr --> 0x12, Bit --> 0...7 */
#define BMI160_USER_DATA_14_ACC_X_LSB__POS           0
#define BMI160_USER_DATA_14_ACC_X_LSB__LEN           8
#define BMI160_USER_DATA_14_ACC_X_LSB__MSK          0xFF
#define BMI160_USER_DATA_14_ACC_X_LSB__REG          BMI160_USER_DATA_14_ADDR

/* ACC_X (MSB) Description - Reg Addr --> 0x13, Bit --> 0...7 */
#define BMI160_USER_DATA_15_ACC_X_MSB__POS           0
#define BMI160_USER_DATA_15_ACC_X_MSB__LEN           8
#define BMI160_USER_DATA_15_ACC_X_MSB__MSK          0xFF
#define BMI160_USER_DATA_15_ACC_X_MSB__REG          BMI160_USER_DATA_15_ADDR

/* ACC_Y (LSB) Description - Reg Addr --> 0x14, Bit --> 0...7 */
#define BMI160_USER_DATA_16_ACC_Y_LSB__POS           0
#define BMI160_USER_DATA_16_ACC_Y_LSB__LEN           8
#define BMI160_USER_DATA_16_ACC_Y_LSB__MSK          0xFF
#define BMI160_USER_DATA_16_ACC_Y_LSB__REG          BMI160_USER_DATA_16_ADDR

/* ACC_Y (MSB) Description - Reg Addr --> 0x15, Bit --> 0...7 */
#define BMI160_USER_DATA_17_ACC_Y_MSB__POS           0
#define BMI160_USER_DATA_17_ACC_Y_MSB__LEN           8
#define BMI160_USER_DATA_17_ACC_Y_MSB__MSK          0xFF
#define BMI160_USER_DATA_17_ACC_Y_MSB__REG          BMI160_USER_DATA_17_ADDR

/* ACC_Z (LSB) Description - Reg Addr --> 0x16, Bit --> 0...7 */
#define BMI160_USER_DATA_18_ACC_Z_LSB__POS           0
#define BMI160_USER_DATA_18_ACC_Z_LSB__LEN           8
#define BMI160_USER_DATA_18_ACC_Z_LSB__MSK          0xFF
#define BMI160_USER_DATA_18_ACC_Z_LSB__REG          BMI160_USER_DATA_18_ADDR

/* ACC_Z (MSB) Description - Reg Addr --> 0x17, Bit --> 0...7 */
#define BMI160_USER_DATA_19_ACC_Z_MSB__POS           0
#define BMI160_USER_DATA_19_ACC_Z_MSB__LEN           8
#define BMI160_USER_DATA_19_ACC_Z_MSB__MSK          0xFF
#define BMI160_USER_DATA_19_ACC_Z_MSB__REG          BMI160_USER_DATA_19_ADDR

/* SENSORTIME_0 (LSB) Description - Reg Addr --> 0x18, Bit --> 0...7 */
#define BMI160_USER_SENSORTIME_0_SENSOR_TIME_LSB__POS           0
#define BMI160_USER_SENSORTIME_0_SENSOR_TIME_LSB__LEN           8
#define BMI160_USER_SENSORTIME_0_SENSOR_TIME_LSB__MSK          0xFF
#define BMI160_USER_SENSORTIME_0_SENSOR_TIME_LSB__REG          \
		BMI160_USER_SENSORTIME_0_ADDR

/* SENSORTIME_1 (MSB) Description - Reg Addr --> 0x19, Bit --> 0...7 */
#define BMI160_USER_SENSORTIME_1_SENSOR_TIME_MSB__POS           0
#define BMI160_USER_SENSORTIME_1_SENSOR_TIME_MSB__LEN           8
#define BMI160_USER_SENSORTIME_1_SENSOR_TIME_MSB__MSK          0xFF
#define BMI160_USER_SENSORTIME_1_SENSOR_TIME_MSB__REG          \
		BMI160_USER_SENSORTIME_1_ADDR

/* SENSORTIME_2 (MSB) Description - Reg Addr --> 0x1A, Bit --> 0...7 */
#define BMI160_USER_SENSORTIME_2_SENSOR_TIME_MSB__POS           0
#define BMI160_USER_SENSORTIME_2_SENSOR_TIME_MSB__LEN           8
#define BMI160_USER_SENSORTIME_2_SENSOR_TIME_MSB__MSK          0xFF
#define BMI160_USER_SENSORTIME_2_SENSOR_TIME_MSB__REG          \
		BMI160_USER_SENSORTIME_2_ADDR

/* Status Description - Reg Addr --> 0x1B, Bit --> 1 */
#define BMI160_USER_STATUS_GYR_SELFTEST_OK__POS          1
#define BMI160_USER_STATUS_GYR_SELFTEST_OK__LEN          1
#define BMI160_USER_STATUS_GYR_SELFTEST_OK__MSK          0x02
#define BMI160_USER_STATUS_GYR_SELFTEST_OK__REG         \
		BMI160_USER_STATUS_ADDR

/* Status Description - Reg Addr --> 0x1B, Bit --> 2 */
#define BMI160_USER_STATUS_MAG_MANUAL_OPERATION__POS          2
#define BMI160_USER_STATUS_MAG_MANUAL_OPERATION__LEN          1
#define BMI160_USER_STATUS_MAG_MANUAL_OPERATION__MSK          0x04
#define BMI160_USER_STATUS_MAG_MANUAL_OPERATION__REG          \
		BMI160_USER_STATUS_ADDR

/* Status Description - Reg Addr --> 0x1B, Bit --> 3 */
#define BMI160_USER_STATUS_FOC_RDY__POS          3
#define BMI160_USER_STATUS_FOC_RDY__LEN          1
#define BMI160_USER_STATUS_FOC_RDY__MSK          0x08
#define BMI160_USER_STATUS_FOC_RDY__REG          BMI160_USER_STATUS_ADDR

/* Status Description - Reg Addr --> 0x1B, Bit --> 4 */
#define BMI160_USER_STATUS_NVM_RDY__POS           4
#define BMI160_USER_STATUS_NVM_RDY__LEN           1
#define BMI160_USER_STATUS_NVM_RDY__MSK           0x10
#define BMI160_USER_STATUS_NVM_RDY__REG           BMI160_USER_STATUS_ADDR

/* Status Description - Reg Addr --> 0x1B, Bit --> 5 */
#define BMI160_USER_STATUS_DRDY_MAG__POS           5
#define BMI160_USER_STATUS_DRDY_MAG__LEN           1
#define BMI160_USER_STATUS_DRDY_MAG__MSK           0x20
#define BMI160_USER_STATUS_DRDY_MAG__REG           BMI160_USER_STATUS_ADDR

/* Status Description - Reg Addr --> 0x1B, Bit --> 6 */
#define BMI160_USER_STATUS_DRDY_GYR__POS           6
#define BMI160_USER_STATUS_DRDY_GYR__LEN           1
#define BMI160_USER_STATUS_DRDY_GYR__MSK           0x40
#define BMI160_USER_STATUS_DRDY_GYR__REG           BMI160_USER_STATUS_ADDR

/* Status Description - Reg Addr --> 0x1B, Bit --> 7 */
#define BMI160_USER_STATUS_DRDY_ACC__POS           7
#define BMI160_USER_STATUS_DRDY_ACC__LEN           1
#define BMI160_USER_STATUS_DRDY_ACC__MSK           0x80
#define BMI160_USER_STATUS_DRDY_ACC__REG           BMI160_USER_STATUS_ADDR

/* Int_Status_0 Description - Reg Addr --> 0x1C, Bit --> 0 */
#define BMI160_USER_INT_STATUS_0_STEP_INT__POS           0
#define BMI160_USER_INT_STATUS_0_STEP_INT__LEN           1
#define BMI160_USER_INT_STATUS_0_STEP_INT__MSK          0x01
#define BMI160_USER_INT_STATUS_0_STEP_INT__REG          \
		BMI160_USER_INT_STATUS_0_ADDR

/* Int_Status_0 Description - Reg Addr --> 0x1C, Bit --> 1 */
#define BMI160_USER_INT_STATUS_0_SIGMOT_INT__POS		1
#define BMI160_USER_INT_STATUS_0_SIGMOT_INT__LEN		1
#define BMI160_USER_INT_STATUS_0_SIGMOT_INT__MSK		0x02
#define BMI160_USER_INT_STATUS_0_SIGMOT_INT__REG       \
		BMI160_USER_INT_STATUS_0_ADDR

/* Int_Status_0 Description - Reg Addr --> 0x1C, Bit --> 2 */
#define BMI160_USER_INT_STATUS_0_ANYM__POS           2
#define BMI160_USER_INT_STATUS_0_ANYM__LEN           1
#define BMI160_USER_INT_STATUS_0_ANYM__MSK          0x04
#define BMI160_USER_INT_STATUS_0_ANYM__REG          \
		BMI160_USER_INT_STATUS_0_ADDR

/* Int_Status_0 Description - Reg Addr --> 0x1C, Bit --> 3 */
#define BMI160_USER_INT_STATUS_0_PMU_TRIGGER__POS           3
#define BMI160_USER_INT_STATUS_0_PMU_TRIGGER__LEN           1
#define BMI160_USER_INT_STATUS_0_PMU_TRIGGER__MSK          0x08
#define BMI160_USER_INT_STATUS_0_PMU_TRIGGER__REG          \
		BMI160_USER_INT_STATUS_0_ADDR

/* Int_Status_0 Description - Reg Addr --> 0x1C, Bit --> 4 */
#define BMI160_USER_INT_STATUS_0_D_TAP_INT__POS           4
#define BMI160_USER_INT_STATUS_0_D_TAP_INT__LEN           1
#define BMI160_USER_INT_STATUS_0_D_TAP_INT__MSK          0x10
#define BMI160_USER_INT_STATUS_0_D_TAP_INT__REG          \
		BMI160_USER_INT_STATUS_0_ADDR

/* Int_Status_0 Description - Reg Addr --> 0x1C, Bit --> 5 */
#define BMI160_USER_INT_STATUS_0_S_TAP_INT__POS           5
#define BMI160_USER_INT_STATUS_0_S_TAP_INT__LEN           1
#define BMI160_USER_INT_STATUS_0_S_TAP_INT__MSK          0x20
#define BMI160_USER_INT_STATUS_0_S_TAP_INT__REG          \
		BMI160_USER_INT_STATUS_0_ADDR

/* Int_Status_0 Description - Reg Addr --> 0x1C, Bit --> 6 */
#define BMI160_USER_INT_STATUS_0_ORIENT__POS           6
#define BMI160_USER_INT_STATUS_0_ORIENT__LEN           1
#define BMI160_USER_INT_STATUS_0_ORIENT__MSK          0x40
#define BMI160_USER_INT_STATUS_0_ORIENT__REG          \
		BMI160_USER_INT_STATUS_0_ADDR

/* Int_Status_0 Description - Reg Addr --> 0x1C, Bit --> 7 */
#define BMI160_USER_INT_STATUS_0_FLAT__POS           7
#define BMI160_USER_INT_STATUS_0_FLAT__LEN           1
#define BMI160_USER_INT_STATUS_0_FLAT__MSK          0x80
#define BMI160_USER_INT_STATUS_0_FLAT__REG          \
		BMI160_USER_INT_STATUS_0_ADDR

/* Int_Status_1 Description - Reg Addr --> 0x1D, Bit --> 2 */
#define BMI160_USER_INT_STATUS_1_HIGHG_INT__POS               2
#define BMI160_USER_INT_STATUS_1_HIGHG_INT__LEN               1
#define BMI160_USER_INT_STATUS_1_HIGHG_INT__MSK              0x04
#define BMI160_USER_INT_STATUS_1_HIGHG_INT__REG              \
		BMI160_USER_INT_STATUS_1_ADDR

/* Int_Status_1 Description - Reg Addr --> 0x1D, Bit --> 3 */
#define BMI160_USER_INT_STATUS_1_LOWG_INT__POS               3
#define BMI160_USER_INT_STATUS_1_LOWG_INT__LEN               1
#define BMI160_USER_INT_STATUS_1_LOWG_INT__MSK              0x08
#define BMI160_USER_INT_STATUS_1_LOWG_INT__REG              \
		BMI160_USER_INT_STATUS_1_ADDR

/* Int_Status_1 Description - Reg Addr --> 0x1D, Bit --> 4 */
#define BMI160_USER_INT_STATUS_1_DRDY_INT__POS               4
#define BMI160_USER_INT_STATUS_1_DRDY_INT__LEN               1
#define BMI160_USER_INT_STATUS_1_DRDY_INT__MSK               0x10
#define BMI160_USER_INT_STATUS_1_DRDY_INT__REG               \
		BMI160_USER_INT_STATUS_1_ADDR

/* Int_Status_1 Description - Reg Addr --> 0x1D, Bit --> 5 */
#define BMI160_USER_INT_STATUS_1_FFULL_INT__POS               5
#define BMI160_USER_INT_STATUS_1_FFULL_INT__LEN               1
#define BMI160_USER_INT_STATUS_1_FFULL_INT__MSK               0x20
#define BMI160_USER_INT_STATUS_1_FFULL_INT__REG               \
		BMI160_USER_INT_STATUS_1_ADDR

/* Int_Status_1 Description - Reg Addr --> 0x1D, Bit --> 6 */
#define BMI160_USER_INT_STATUS_1_FWM_INT__POS               6
#define BMI160_USER_INT_STATUS_1_FWM_INT__LEN               1
#define BMI160_USER_INT_STATUS_1_FWM_INT__MSK               0x40
#define BMI160_USER_INT_STATUS_1_FWM_INT__REG               \
		BMI160_USER_INT_STATUS_1_ADDR

/* Int_Status_1 Description - Reg Addr --> 0x1D, Bit --> 7 */
#define BMI160_USER_INT_STATUS_1_NOMO_INT__POS               7
#define BMI160_USER_INT_STATUS_1_NOMO_INT__LEN               1
#define BMI160_USER_INT_STATUS_1_NOMO_INT__MSK               0x80
#define BMI160_USER_INT_STATUS_1_NOMO_INT__REG               \
		BMI160_USER_INT_STATUS_1_ADDR

/* Int_Status_2 Description - Reg Addr --> 0x1E, Bit --> 0 */
#define BMI160_USER_INT_STATUS_2_ANYM_FIRST_X__POS               0
#define BMI160_USER_INT_STATUS_2_ANYM_FIRST_X__LEN               1
#define BMI160_USER_INT_STATUS_2_ANYM_FIRST_X__MSK               0x01
#define BMI160_USER_INT_STATUS_2_ANYM_FIRST_X__REG               \
		BMI160_USER_INT_STATUS_2_ADDR

/* Int_Status_2 Description - Reg Addr --> 0x1E, Bit --> 1 */
#define BMI160_USER_INT_STATUS_2_ANYM_FIRST_Y__POS               1
#define BMI160_USER_INT_STATUS_2_ANYM_FIRST_Y__LEN               1
#define BMI160_USER_INT_STATUS_2_ANYM_FIRST_Y__MSK               0x02
#define BMI160_USER_INT_STATUS_2_ANYM_FIRST_Y__REG               \
		BMI160_USER_INT_STATUS_2_ADDR

/* Int_Status_2 Description - Reg Addr --> 0x1E, Bit --> 2 */
#define BMI160_USER_INT_STATUS_2_ANYM_FIRST_Z__POS               2
#define BMI160_USER_INT_STATUS_2_ANYM_FIRST_Z__LEN               1
#define BMI160_USER_INT_STATUS_2_ANYM_FIRST_Z__MSK               0x04
#define BMI160_USER_INT_STATUS_2_ANYM_FIRST_Z__REG               \
		BMI160_USER_INT_STATUS_2_ADDR

/* Int_Status_2 Description - Reg Addr --> 0x1E, Bit --> 3 */
#define BMI160_USER_INT_STATUS_2_ANYM_SIGN__POS               3
#define BMI160_USER_INT_STATUS_2_ANYM_SIGN__LEN               1
#define BMI160_USER_INT_STATUS_2_ANYM_SIGN__MSK               0x08
#define BMI160_USER_INT_STATUS_2_ANYM_SIGN__REG               \
		BMI160_USER_INT_STATUS_2_ADDR

/* Int_Status_2 Description - Reg Addr --> 0x1E, Bit --> 4 */
#define BMI160_USER_INT_STATUS_2_TAP_FIRST_X__POS               4
#define BMI160_USER_INT_STATUS_2_TAP_FIRST_X__LEN               1
#define BMI160_USER_INT_STATUS_2_TAP_FIRST_X__MSK               0x10
#define BMI160_USER_INT_STATUS_2_TAP_FIRST_X__REG               \
		BMI160_USER_INT_STATUS_2_ADDR

/* Int_Status_2 Description - Reg Addr --> 0x1E, Bit --> 5 */
#define BMI160_USER_INT_STATUS_2_TAP_FIRST_Y__POS               5
#define BMI160_USER_INT_STATUS_2_TAP_FIRST_Y__LEN               1
#define BMI160_USER_INT_STATUS_2_TAP_FIRST_Y__MSK               0x20
#define BMI160_USER_INT_STATUS_2_TAP_FIRST_Y__REG               \
		BMI160_USER_INT_STATUS_2_ADDR

/* Int_Status_2 Description - Reg Addr --> 0x1E, Bit --> 6 */
#define BMI160_USER_INT_STATUS_2_TAP_FIRST_Z__POS               6
#define BMI160_USER_INT_STATUS_2_TAP_FIRST_Z__LEN               1
#define BMI160_USER_INT_STATUS_2_TAP_FIRST_Z__MSK               0x40
#define BMI160_USER_INT_STATUS_2_TAP_FIRST_Z__REG               \
		BMI160_USER_INT_STATUS_2_ADDR

/* Int_Status_2 Description - Reg Addr --> 0x1E, Bit --> 7 */
#define BMI160_USER_INT_STATUS_2_TAP_SIGN__POS               7
#define BMI160_USER_INT_STATUS_2_TAP_SIGN__LEN               1
#define BMI160_USER_INT_STATUS_2_TAP_SIGN__MSK               0x80
#define BMI160_USER_INT_STATUS_2_TAP_SIGN__REG               \
		BMI160_USER_INT_STATUS_2_ADDR

/* Int_Status_2 Description - Reg Addr --> 0x1E, Bit --> 0...7 */
#define BMI160_USER_INT_STATUS_2__POS               0
#define BMI160_USER_INT_STATUS_2__LEN               8
#define BMI160_USER_INT_STATUS_2__MSK               0xFF
#define BMI160_USER_INT_STATUS_2__REG               \
		BMI160_USER_INT_STATUS_2_ADDR

/* Int_Status_3 Description - Reg Addr --> 0x1F, Bit --> 0 */
#define BMI160_USER_INT_STATUS_3_HIGH_FIRST_X__POS               0
#define BMI160_USER_INT_STATUS_3_HIGH_FIRST_X__LEN               1
#define BMI160_USER_INT_STATUS_3_HIGH_FIRST_X__MSK               0x01
#define BMI160_USER_INT_STATUS_3_HIGH_FIRST_X__REG               \
		BMI160_USER_INT_STATUS_3_ADDR

/* Int_Status_3 Description - Reg Addr --> 0x1E, Bit --> 1 */
#define BMI160_USER_INT_STATUS_3_HIGH_FIRST_Y__POS               1
#define BMI160_USER_INT_STATUS_3_HIGH_FIRST_Y__LEN               1
#define BMI160_USER_INT_STATUS_3_HIGH_FIRST_Y__MSK               0x02
#define BMI160_USER_INT_STATUS_3_HIGH_FIRST_Y__REG               \
		BMI160_USER_INT_STATUS_3_ADDR

/* Int_Status_3 Description - Reg Addr --> 0x1F, Bit --> 2 */
#define BMI160_USER_INT_STATUS_3_HIGH_FIRST_Z__POS               2
#define BMI160_USER_INT_STATUS_3_HIGH_FIRST_Z__LEN               1
#define BMI160_USER_INT_STATUS_3_HIGH_FIRST_Z__MSK               0x04
#define BMI160_USER_INT_STATUS_3_HIGH_FIRST_Z__REG               \
		BMI160_USER_INT_STATUS_3_ADDR

/* Int_Status_3 Description - Reg Addr --> 0x1F, Bit --> 3 */
#define BMI160_USER_INT_STATUS_3_HIGH_SIGN__POS               3
#define BMI160_USER_INT_STATUS_3_HIGH_SIGN__LEN               1
#define BMI160_USER_INT_STATUS_3_HIGH_SIGN__MSK               0x08
#define BMI160_USER_INT_STATUS_3_HIGH_SIGN__REG               \
		BMI160_USER_INT_STATUS_3_ADDR

/* Int_Status_3 Description - Reg Addr --> 0x1F, Bit --> 4...5 */
#define BMI160_USER_INT_STATUS_3_ORIENT_XY__POS               4
#define BMI160_USER_INT_STATUS_3_ORIENT_XY__LEN               2
#define BMI160_USER_INT_STATUS_3_ORIENT_XY__MSK               0x30
#define BMI160_USER_INT_STATUS_3_ORIENT_XY__REG               \
		BMI160_USER_INT_STATUS_3_ADDR

/* Int_Status_3 Description - Reg Addr --> 0x1F, Bit --> 6 */
#define BMI160_USER_INT_STATUS_3_ORIENT_Z__POS               6
#define BMI160_USER_INT_STATUS_3_ORIENT_Z__LEN               1
#define BMI160_USER_INT_STATUS_3_ORIENT_Z__MSK               0x40
#define BMI160_USER_INT_STATUS_3_ORIENT_Z__REG               \
		BMI160_USER_INT_STATUS_3_ADDR

/* Int_Status_3 Description - Reg Addr --> 0x1F, Bit --> 7 */
#define BMI160_USER_INT_STATUS_3_FLAT__POS               7
#define BMI160_USER_INT_STATUS_3_FLAT__LEN               1
#define BMI160_USER_INT_STATUS_3_FLAT__MSK               0x80
#define BMI160_USER_INT_STATUS_3_FLAT__REG               \
		BMI160_USER_INT_STATUS_3_ADDR

/* Int_Status_3 Description - Reg Addr --> 0x1F, Bit --> 0...7 */
#define BMI160_USER_INT_STATUS_3__POS               0
#define BMI160_USER_INT_STATUS_3__LEN               8
#define BMI160_USER_INT_STATUS_3__MSK               0xFF
#define BMI160_USER_INT_STATUS_3__REG               \
		BMI160_USER_INT_STATUS_3_ADDR

/* Temperature Description - LSB Reg Addr --> 0x20, Bit --> 0...7 */
#define BMI160_USER_TEMPERATURE_LSB_VALUE__POS               0
#define BMI160_USER_TEMPERATURE_LSB_VALUE__LEN               8
#define BMI160_USER_TEMPERATURE_LSB_VALUE__MSK               0xFF
#define BMI160_USER_TEMPERATURE_LSB_VALUE__REG               \
		BMI160_USER_TEMPERATURE_0_ADDR

/* Temperature Description - LSB Reg Addr --> 0x21, Bit --> 0...7 */
#define BMI160_USER_TEMPERATURE_MSB_VALUE__POS               0
#define BMI160_USER_TEMPERATURE_MSB_VALUE__LEN               8
#define BMI160_USER_TEMPERATURE_MSB_VALUE__MSK               0xFF
#define BMI160_USER_TEMPERATURE_MSB_VALUE__REG               \
		BMI160_USER_TEMPERATURE_1_ADDR

/* Fifo_Length0 Description - Reg Addr --> 0x22, Bit --> 0...7 */
#define BMI160_USER_FIFO_BYTE_COUNTER_LSB__POS           0
#define BMI160_USER_FIFO_BYTE_COUNTER_LSB__LEN           8
#define BMI160_USER_FIFO_BYTE_COUNTER_LSB__MSK          0xFF
#define BMI160_USER_FIFO_BYTE_COUNTER_LSB__REG          \
		BMI160_USER_FIFO_LENGTH_0_ADDR

/*Fifo_Length1 Description - Reg Addr --> 0x23, Bit --> 0...2 */
#define BMI160_USER_FIFO_BYTE_COUNTER_MSB__POS           0
#define BMI160_USER_FIFO_BYTE_COUNTER_MSB__LEN           3
#define BMI160_USER_FIFO_BYTE_COUNTER_MSB__MSK          0x07
#define BMI160_USER_FIFO_BYTE_COUNTER_MSB__REG          \
		BMI160_USER_FIFO_LENGTH_1_ADDR


/* Fifo_Data Description - Reg Addr --> 0x24, Bit --> 0...7 */
#define BMI160_USER_FIFO_DATA__POS           0
#define BMI160_USER_FIFO_DATA__LEN           8
#define BMI160_USER_FIFO_DATA__MSK          0xFF
#define BMI160_USER_FIFO_DATA__REG          BMI160_USER_FIFO_DATA_ADDR


/* Acc_Conf Description - Reg Addr --> 0x40, Bit --> 0...3 */
#define BMI160_USER_ACC_CONF_ODR__POS               0
#define BMI160_USER_ACC_CONF_ODR__LEN               4
#define BMI160_USER_ACC_CONF_ODR__MSK               0x0F
#define BMI160_USER_ACC_CONF_ODR__REG		BMI160_USER_ACC_CONF_ADDR

/* Acc_Conf Description - Reg Addr --> 0x40, Bit --> 4...6 */
#define BMI160_USER_ACC_CONF_ACC_BWP__POS               4
#define BMI160_USER_ACC_CONF_ACC_BWP__LEN               3
#define BMI160_USER_ACC_CONF_ACC_BWP__MSK               0x70
#define BMI160_USER_ACC_CONF_ACC_BWP__REG	BMI160_USER_ACC_CONF_ADDR

/* Acc_Conf Description - Reg Addr --> 0x40, Bit --> 7 */
#define BMI160_USER_ACC_CONF_ACC_UNDER_SAMPLING__POS           7
#define BMI160_USER_ACC_CONF_ACC_UNDER_SAMPLING__LEN           1
#define BMI160_USER_ACC_CONF_ACC_UNDER_SAMPLING__MSK           0x80
#define BMI160_USER_ACC_CONF_ACC_UNDER_SAMPLING__REG	\
BMI160_USER_ACC_CONF_ADDR

/* Acc_Range Description - Reg Addr --> 0x41, Bit --> 0...3 */
#define BMI160_USER_ACC_RANGE__POS               0
#define BMI160_USER_ACC_RANGE__LEN               4
#define BMI160_USER_ACC_RANGE__MSK               0x0F
#define BMI160_USER_ACC_RANGE__REG               BMI160_USER_ACC_RANGE_ADDR

/* Gyro_Conf Description - Reg Addr --> 0x42, Bit --> 0...3 */
#define BMI160_USER_GYR_CONF_ODR__POS               0
#define BMI160_USER_GYR_CONF_ODR__LEN               4
#define BMI160_USER_GYR_CONF_ODR__MSK               0x0F
#define BMI160_USER_GYR_CONF_ODR__REG               BMI160_USER_GYR_CONF_ADDR

/* Gyro_Conf Description - Reg Addr --> 0x42, Bit --> 4...5 */
#define BMI160_USER_GYR_CONF_BWP__POS               4
#define BMI160_USER_GYR_CONF_BWP__LEN               2
#define BMI160_USER_GYR_CONF_BWP__MSK               0x30
#define BMI160_USER_GYR_CONF_BWP__REG               BMI160_USER_GYR_CONF_ADDR

/* Gyr_Range Description - Reg Addr --> 0x43, Bit --> 0...2 */
#define BMI160_USER_GYR_RANGE__POS               0
#define BMI160_USER_GYR_RANGE__LEN               3
#define BMI160_USER_GYR_RANGE__MSK               0x07
#define BMI160_USER_GYR_RANGE__REG               BMI160_USER_GYR_RANGE_ADDR

/* Mag_Conf Description - Reg Addr --> 0x44, Bit --> 0...3 */
#define BMI160_USER_MAG_CONF_ODR__POS               0
#define BMI160_USER_MAG_CONF_ODR__LEN               4
#define BMI160_USER_MAG_CONF_ODR__MSK               0x0F
#define BMI160_USER_MAG_CONF_ODR__REG               BMI160_USER_MAG_CONF_ADDR


/* Fifo_Downs Description - Reg Addr --> 0x45, Bit --> 0...2 */
#define BMI160_USER_FIFO_DOWNS_GYRO__POS               0
#define BMI160_USER_FIFO_DOWNS_GYRO__LEN               3
#define BMI160_USER_FIFO_DOWNS_GYRO__MSK               0x07
#define BMI160_USER_FIFO_DOWNS_GYRO__REG	BMI160_USER_FIFO_DOWNS_ADDR

/* Fifo_filt Description - Reg Addr --> 0x45, Bit --> 3 */
#define BMI160_USER_FIFO_FILT_GYRO__POS               3
#define BMI160_USER_FIFO_FILT_GYRO__LEN               1
#define BMI160_USER_FIFO_FILT_GYRO__MSK               0x08
#define BMI160_USER_FIFO_FILT_GYRO__REG	  BMI160_USER_FIFO_DOWNS_ADDR

/* Fifo_Downs Description - Reg Addr --> 0x45, Bit --> 4...6 */
#define BMI160_USER_FIFO_DOWNS_ACCEL__POS               4
#define BMI160_USER_FIFO_DOWNS_ACCEL__LEN               3
#define BMI160_USER_FIFO_DOWNS_ACCEL__MSK               0x70
#define BMI160_USER_FIFO_DOWNS_ACCEL__REG	BMI160_USER_FIFO_DOWNS_ADDR

/* Fifo_FILT Description - Reg Addr --> 0x45, Bit --> 7 */
#define BMI160_USER_FIFO_FILT_ACCEL__POS               7
#define BMI160_USER_FIFO_FILT_ACCEL__LEN               1
#define BMI160_USER_FIFO_FILT_ACCEL__MSK               0x80
#define BMI160_USER_FIFO_FILT_ACCEL__REG	BMI160_USER_FIFO_DOWNS_ADDR

/* Fifo_Config_0 Description - Reg Addr --> 0x46, Bit --> 0...7 */
#define BMI160_USER_FIFO_WATER_MARK__POS               0
#define BMI160_USER_FIFO_WATER_MARK__LEN               8
#define BMI160_USER_FIFO_WATER_MARK__MSK               0xFF
#define BMI160_USER_FIFO_WATER_MARK__REG	BMI160_USER_FIFO_CONFIG_0_ADDR

/* Fifo_Config_1 Description - Reg Addr --> 0x47, Bit --> 0 */
#define BMI160_USER_FIFO_STOP_ON_FULL__POS		0
#define BMI160_USER_FIFO_STOP_ON_FULL__LEN		1
#define BMI160_USER_FIFO_STOP_ON_FULL__MSK		0x01
#define BMI160_USER_FIFO_STOP_ON_FULL__REG	BMI160_USER_FIFO_CONFIG_1_ADDR

/* Fifo_Config_1 Description - Reg Addr --> 0x47, Bit --> 1 */
#define BMI160_USER_FIFO_TIME_EN__POS               1
#define BMI160_USER_FIFO_TIME_EN__LEN               1
#define BMI160_USER_FIFO_TIME_EN__MSK               0x02
#define BMI160_USER_FIFO_TIME_EN__REG	BMI160_USER_FIFO_CONFIG_1_ADDR

/* Fifo_Config_1 Description - Reg Addr --> 0x47, Bit --> 2 */
#define BMI160_USER_FIFO_TAG_INT2_EN__POS               2
#define BMI160_USER_FIFO_TAG_INT2_EN__LEN               1
#define BMI160_USER_FIFO_TAG_INT2_EN__MSK               0x04
#define BMI160_USER_FIFO_TAG_INT2_EN__REG	BMI160_USER_FIFO_CONFIG_1_ADDR

/* Fifo_Config_1 Description - Reg Addr --> 0x47, Bit --> 3 */
#define BMI160_USER_FIFO_TAG_INT1_EN__POS               3
#define BMI160_USER_FIFO_TAG_INT1_EN__LEN               1
#define BMI160_USER_FIFO_TAG_INT1_EN__MSK               0x08
#define BMI160_USER_FIFO_TAG_INT1_EN__REG	BMI160_USER_FIFO_CONFIG_1_ADDR

/* Fifo_Config_1 Description - Reg Addr --> 0x47, Bit --> 4 */
#define BMI160_USER_FIFO_HEADER_EN__POS               4
#define BMI160_USER_FIFO_HEADER_EN__LEN               1
#define BMI160_USER_FIFO_HEADER_EN__MSK               0x10
#define BMI160_USER_FIFO_HEADER_EN__REG		BMI160_USER_FIFO_CONFIG_1_ADDR

/* Fifo_Config_1 Description - Reg Addr --> 0x47, Bit --> 5 */
#define BMI160_USER_FIFO_MAG_EN__POS               5
#define BMI160_USER_FIFO_MAG_EN__LEN               1
#define BMI160_USER_FIFO_MAG_EN__MSK               0x20
#define BMI160_USER_FIFO_MAG_EN__REG		BMI160_USER_FIFO_CONFIG_1_ADDR

/* Fifo_Config_1 Description - Reg Addr --> 0x47, Bit --> 6 */
#define BMI160_USER_FIFO_ACC_EN__POS               6
#define BMI160_USER_FIFO_ACC_EN__LEN               1
#define BMI160_USER_FIFO_ACC_EN__MSK               0x40
#define BMI160_USER_FIFO_ACC_EN__REG		BMI160_USER_FIFO_CONFIG_1_ADDR

/* Fifo_Config_1 Description - Reg Addr --> 0x47, Bit --> 7 */
#define BMI160_USER_FIFO_GYRO_EN__POS               7
#define BMI160_USER_FIFO_GYRO_EN__LEN               1
#define BMI160_USER_FIFO_GYRO_EN__MSK               0x80
#define BMI160_USER_FIFO_GYRO_EN__REG		BMI160_USER_FIFO_CONFIG_1_ADDR



/* Mag_IF_0 Description - Reg Addr --> 0x4b, Bit --> 1...7 */
#define BMI160_USER_I2C_DEVICE_ADDR__POS               1
#define BMI160_USER_I2C_DEVICE_ADDR__LEN               7
#define BMI160_USER_I2C_DEVICE_ADDR__MSK               0xFE
#define BMI160_USER_I2C_DEVICE_ADDR__REG	BMI160_USER_MAG_IF_0_ADDR

/* Mag_IF_1 Description - Reg Addr --> 0x4c, Bit --> 0...1 */
#define BMI160_USER_MAG_BURST__POS               0
#define BMI160_USER_MAG_BURST__LEN               2
#define BMI160_USER_MAG_BURST__MSK               0x03
#define BMI160_USER_MAG_BURST__REG               BMI160_USER_MAG_IF_1_ADDR

/* Mag_IF_1 Description - Reg Addr --> 0x4c, Bit --> 2...5 */
#define BMI160_USER_MAG_OFFSET__POS               2
#define BMI160_USER_MAG_OFFSET__LEN               4
#define BMI160_USER_MAG_OFFSET__MSK               0x3C
#define BMI160_USER_MAG_OFFSET__REG               BMI160_USER_MAG_IF_1_ADDR

/* Mag_IF_1 Description - Reg Addr --> 0x4c, Bit --> 7 */
#define BMI160_USER_MAG_MANUAL_EN__POS               7
#define BMI160_USER_MAG_MANUAL_EN__LEN               1
#define BMI160_USER_MAG_MANUAL_EN__MSK               0x80
#define BMI160_USER_MAG_MANUAL_EN__REG               BMI160_USER_MAG_IF_1_ADDR

/* Mag_IF_2 Description - Reg Addr --> 0x4d, Bit -->0... 7 */
#define BMI160_USER_READ_ADDR__POS               0
#define BMI160_USER_READ_ADDR__LEN               8
#define BMI160_USER_READ_ADDR__MSK               0xFF
#define BMI160_USER_READ_ADDR__REG               BMI160_USER_MAG_IF_2_ADDR

/* Mag_IF_3 Description - Reg Addr --> 0x4e, Bit -->0... 7 */
#define BMI160_USER_WRITE_ADDR__POS               0
#define BMI160_USER_WRITE_ADDR__LEN               8
#define BMI160_USER_WRITE_ADDR__MSK               0xFF
#define BMI160_USER_WRITE_ADDR__REG               BMI160_USER_MAG_IF_3_ADDR

/* Mag_IF_4 Description - Reg Addr --> 0x4f, Bit -->0... 7 */
#define BMI160_USER_WRITE_DATA__POS               0
#define BMI160_USER_WRITE_DATA__LEN               8
#define BMI160_USER_WRITE_DATA__MSK               0xFF
#define BMI160_USER_WRITE_DATA__REG               BMI160_USER_MAG_IF_4_ADDR

/* Int_En_0 Description - Reg Addr --> 0x50, Bit -->0 */
#define BMI160_USER_INT_EN_0_ANYMO_X_EN__POS               0
#define BMI160_USER_INT_EN_0_ANYMO_X_EN__LEN               1
#define BMI160_USER_INT_EN_0_ANYMO_X_EN__MSK               0x01
#define BMI160_USER_INT_EN_0_ANYMO_X_EN__REG	BMI160_USER_INT_EN_0_ADDR

/* Int_En_0 Description - Reg Addr --> 0x50, Bit -->1 */
#define BMI160_USER_INT_EN_0_ANYMO_Y_EN__POS               1
#define BMI160_USER_INT_EN_0_ANYMO_Y_EN__LEN               1
#define BMI160_USER_INT_EN_0_ANYMO_Y_EN__MSK               0x02
#define BMI160_USER_INT_EN_0_ANYMO_Y_EN__REG	BMI160_USER_INT_EN_0_ADDR

/* Int_En_0 Description - Reg Addr --> 0x50, Bit -->2 */
#define BMI160_USER_INT_EN_0_ANYMO_Z_EN__POS               2
#define BMI160_USER_INT_EN_0_ANYMO_Z_EN__LEN               1
#define BMI160_USER_INT_EN_0_ANYMO_Z_EN__MSK               0x04
#define BMI160_USER_INT_EN_0_ANYMO_Z_EN__REG	BMI160_USER_INT_EN_0_ADDR

/* Int_En_0 Description - Reg Addr --> 0x50, Bit -->4 */
#define BMI160_USER_INT_EN_0_D_TAP_EN__POS               4
#define BMI160_USER_INT_EN_0_D_TAP_EN__LEN               1
#define BMI160_USER_INT_EN_0_D_TAP_EN__MSK               0x10
#define BMI160_USER_INT_EN_0_D_TAP_EN__REG	BMI160_USER_INT_EN_0_ADDR

/* Int_En_0 Description - Reg Addr --> 0x50, Bit -->5 */
#define BMI160_USER_INT_EN_0_S_TAP_EN__POS               5
#define BMI160_USER_INT_EN_0_S_TAP_EN__LEN               1
#define BMI160_USER_INT_EN_0_S_TAP_EN__MSK               0x20
#define BMI160_USER_INT_EN_0_S_TAP_EN__REG	BMI160_USER_INT_EN_0_ADDR

/* Int_En_0 Description - Reg Addr --> 0x50, Bit -->6 */
#define BMI160_USER_INT_EN_0_ORIENT_EN__POS               6
#define BMI160_USER_INT_EN_0_ORIENT_EN__LEN               1
#define BMI160_USER_INT_EN_0_ORIENT_EN__MSK               0x40
#define BMI160_USER_INT_EN_0_ORIENT_EN__REG	BMI160_USER_INT_EN_0_ADDR

/* Int_En_0 Description - Reg Addr --> 0x50, Bit -->7 */
#define BMI160_USER_INT_EN_0_FLAT_EN__POS               7
#define BMI160_USER_INT_EN_0_FLAT_EN__LEN               1
#define BMI160_USER_INT_EN_0_FLAT_EN__MSK               0x80
#define BMI160_USER_INT_EN_0_FLAT_EN__REG	BMI160_USER_INT_EN_0_ADDR

/* Int_En_1 Description - Reg Addr --> 0x51, Bit -->0 */
#define BMI160_USER_INT_EN_1_HIGHG_X_EN__POS               0
#define BMI160_USER_INT_EN_1_HIGHG_X_EN__LEN               1
#define BMI160_USER_INT_EN_1_HIGHG_X_EN__MSK               0x01
#define BMI160_USER_INT_EN_1_HIGHG_X_EN__REG	BMI160_USER_INT_EN_1_ADDR

/* Int_En_1 Description - Reg Addr --> 0x51, Bit -->1 */
#define BMI160_USER_INT_EN_1_HIGHG_Y_EN__POS               1
#define BMI160_USER_INT_EN_1_HIGHG_Y_EN__LEN               1
#define BMI160_USER_INT_EN_1_HIGHG_Y_EN__MSK               0x02
#define BMI160_USER_INT_EN_1_HIGHG_Y_EN__REG	BMI160_USER_INT_EN_1_ADDR

/* Int_En_1 Description - Reg Addr --> 0x51, Bit -->2 */
#define BMI160_USER_INT_EN_1_HIGHG_Z_EN__POS               2
#define BMI160_USER_INT_EN_1_HIGHG_Z_EN__LEN               1
#define BMI160_USER_INT_EN_1_HIGHG_Z_EN__MSK               0x04
#define BMI160_USER_INT_EN_1_HIGHG_Z_EN__REG	BMI160_USER_INT_EN_1_ADDR

/* Int_En_1 Description - Reg Addr --> 0x51, Bit -->3 */
#define BMI160_USER_INT_EN_1_LOW_EN__POS               3
#define BMI160_USER_INT_EN_1_LOW_EN__LEN               1
#define BMI160_USER_INT_EN_1_LOW_EN__MSK               0x08
#define BMI160_USER_INT_EN_1_LOW_EN__REG	BMI160_USER_INT_EN_1_ADDR

/* Int_En_1 Description - Reg Addr --> 0x51, Bit -->4 */
#define BMI160_USER_INT_EN_1_DRDY_EN__POS               4
#define BMI160_USER_INT_EN_1_DRDY_EN__LEN               1
#define BMI160_USER_INT_EN_1_DRDY_EN__MSK               0x10
#define BMI160_USER_INT_EN_1_DRDY_EN__REG	BMI160_USER_INT_EN_1_ADDR

/* Int_En_1 Description - Reg Addr --> 0x51, Bit -->5 */
#define BMI160_USER_INT_EN_1_FFULL_EN__POS               5
#define BMI160_USER_INT_EN_1_FFULL_EN__LEN               1
#define BMI160_USER_INT_EN_1_FFULL_EN__MSK               0x20
#define BMI160_USER_INT_EN_1_FFULL_EN__REG	BMI160_USER_INT_EN_1_ADDR

/* Int_En_1 Description - Reg Addr --> 0x51, Bit -->6 */
#define BMI160_USER_INT_EN_1_FWM_EN__POS               6
#define BMI160_USER_INT_EN_1_FWM_EN__LEN               1
#define BMI160_USER_INT_EN_1_FWM_EN__MSK               0x40
#define BMI160_USER_INT_EN_1_FWM_EN__REG	BMI160_USER_INT_EN_1_ADDR

/* Int_En_2 Description - Reg Addr --> 0x52, Bit -->0 */
#define BMI160_USER_INT_EN_2_NOMO_X_EN__POS               0
#define BMI160_USER_INT_EN_2_NOMO_X_EN__LEN               1
#define BMI160_USER_INT_EN_2_NOMO_X_EN__MSK               0x01
#define BMI160_USER_INT_EN_2_NOMO_X_EN__REG	  BMI160_USER_INT_EN_2_ADDR

/* Int_En_2 Description - Reg Addr --> 0x52, Bit -->1 */
#define BMI160_USER_INT_EN_2_NOMO_Y_EN__POS               1
#define BMI160_USER_INT_EN_2_NOMO_Y_EN__LEN               1
#define BMI160_USER_INT_EN_2_NOMO_Y_EN__MSK               0x02
#define BMI160_USER_INT_EN_2_NOMO_Y_EN__REG	  BMI160_USER_INT_EN_2_ADDR

/* Int_En_2 Description - Reg Addr --> 0x52, Bit -->2 */
#define BMI160_USER_INT_EN_2_NOMO_Z_EN__POS               2
#define BMI160_USER_INT_EN_2_NOMO_Z_EN__LEN               1
#define BMI160_USER_INT_EN_2_NOMO_Z_EN__MSK               0x04
#define BMI160_USER_INT_EN_2_NOMO_Z_EN__REG	  BMI160_USER_INT_EN_2_ADDR

/* Int_En_2 Description - Reg Addr --> 0x52, Bit -->3 */
#define BMI160_USER_INT_EN_2_STEP_DET_EN__POS               3
#define BMI160_USER_INT_EN_2_STEP_DET_EN__LEN               1
#define BMI160_USER_INT_EN_2_STEP_DET_EN__MSK               0x08
#define BMI160_USER_INT_EN_2_STEP_DET_EN__REG	  BMI160_USER_INT_EN_2_ADDR

/* Int_Out_Ctrl Description - Reg Addr --> 0x53, Bit -->0 */
#define BMI160_USER_INT1_EDGE_CTRL__POS               0
#define BMI160_USER_INT1_EDGE_CTRL__LEN               1
#define BMI160_USER_INT1_EDGE_CTRL__MSK               0x01
#define BMI160_USER_INT1_EDGE_CTRL__REG		BMI160_USER_INT_OUT_CTRL_ADDR

/* Int_Out_Ctrl Description - Reg Addr --> 0x53, Bit -->1 */
#define BMI160_USER_INT1_LVL__POS               1
#define BMI160_USER_INT1_LVL__LEN               1
#define BMI160_USER_INT1_LVL__MSK               0x02
#define BMI160_USER_INT1_LVL__REG               BMI160_USER_INT_OUT_CTRL_ADDR

/* Int_Out_Ctrl Description - Reg Addr --> 0x53, Bit -->2 */
#define BMI160_USER_INT1_OD__POS               2
#define BMI160_USER_INT1_OD__LEN               1
#define BMI160_USER_INT1_OD__MSK               0x04
#define BMI160_USER_INT1_OD__REG               BMI160_USER_INT_OUT_CTRL_ADDR

/* Int_Out_Ctrl Description - Reg Addr --> 0x53, Bit -->3 */
#define BMI160_USER_INT1_OUTPUT_EN__POS               3
#define BMI160_USER_INT1_OUTPUT_EN__LEN               1
#define BMI160_USER_INT1_OUTPUT_EN__MSK               0x08
#define BMI160_USER_INT1_OUTPUT_EN__REG		BMI160_USER_INT_OUT_CTRL_ADDR

/* Int_Out_Ctrl Description - Reg Addr --> 0x53, Bit -->4 */
#define BMI160_USER_INT2_EDGE_CTRL__POS               4
#define BMI160_USER_INT2_EDGE_CTRL__LEN               1
#define BMI160_USER_INT2_EDGE_CTRL__MSK               0x10
#define BMI160_USER_INT2_EDGE_CTRL__REG		BMI160_USER_INT_OUT_CTRL_ADDR

/* Int_Out_Ctrl Description - Reg Addr --> 0x53, Bit -->5 */
#define BMI160_USER_INT2_LVL__POS               5
#define BMI160_USER_INT2_LVL__LEN               1
#define BMI160_USER_INT2_LVL__MSK               0x20
#define BMI160_USER_INT2_LVL__REG               BMI160_USER_INT_OUT_CTRL_ADDR

/* Int_Out_Ctrl Description - Reg Addr --> 0x53, Bit -->6 */
#define BMI160_USER_INT2_OD__POS               6
#define BMI160_USER_INT2_OD__LEN               1
#define BMI160_USER_INT2_OD__MSK               0x40
#define BMI160_USER_INT2_OD__REG               BMI160_USER_INT_OUT_CTRL_ADDR

/* Int_Out_Ctrl Description - Reg Addr --> 0x53, Bit -->7 */
#define BMI160_USER_INT2_OUTPUT_EN__POS               7
#define BMI160_USER_INT2_OUTPUT_EN__LEN               1
#define BMI160_USER_INT2_OUTPUT_EN__MSK               0x80
#define BMI160_USER_INT2_OUTPUT_EN__REG		BMI160_USER_INT_OUT_CTRL_ADDR

/* Int_Latch Description - Reg Addr --> 0x54, Bit -->0...3 */
#define BMI160_USER_INT_LATCH__POS               0
#define BMI160_USER_INT_LATCH__LEN               4
#define BMI160_USER_INT_LATCH__MSK               0x0F
#define BMI160_USER_INT_LATCH__REG               BMI160_USER_INT_LATCH_ADDR

/* Int_Latch Description - Reg Addr --> 0x54, Bit -->4 */
#define BMI160_USER_INT1_INPUT_EN__POS               4
#define BMI160_USER_INT1_INPUT_EN__LEN               1
#define BMI160_USER_INT1_INPUT_EN__MSK               0x10
#define BMI160_USER_INT1_INPUT_EN__REG               BMI160_USER_INT_LATCH_ADDR

/* Int_Latch Description - Reg Addr --> 0x54, Bit -->5*/
#define BMI160_USER_INT2_INPUT_EN__POS               5
#define BMI160_USER_INT2_INPUT_EN__LEN               1
#define BMI160_USER_INT2_INPUT_EN__MSK               0x20
#define BMI160_USER_INT2_INPUT_EN__REG              BMI160_USER_INT_LATCH_ADDR

/* Int_Map_0 Description - Reg Addr --> 0x55, Bit -->0 */
#define BMI160_USER_INT_MAP_0_INT1_LOWG__POS               0
#define BMI160_USER_INT_MAP_0_INT1_LOWG__LEN               1
#define BMI160_USER_INT_MAP_0_INT1_LOWG__MSK               0x01
#define BMI160_USER_INT_MAP_0_INT1_LOWG__REG	BMI160_USER_INT_MAP_0_ADDR

/* Int_Map_0 Description - Reg Addr --> 0x55, Bit -->1 */
#define BMI160_USER_INT_MAP_0_INT1_HIGHG__POS               1
#define BMI160_USER_INT_MAP_0_INT1_HIGHG__LEN               1
#define BMI160_USER_INT_MAP_0_INT1_HIGHG__MSK               0x02
#define BMI160_USER_INT_MAP_0_INT1_HIGHG__REG	BMI160_USER_INT_MAP_0_ADDR

/* Int_Map_0 Description - Reg Addr --> 0x55, Bit -->2 */
#define BMI160_USER_INT_MAP_0_INT1_ANYMOTION__POS               2
#define BMI160_USER_INT_MAP_0_INT1_ANYMOTION__LEN               1
#define BMI160_USER_INT_MAP_0_INT1_ANYMOTION__MSK               0x04
#define BMI160_USER_INT_MAP_0_INT1_ANYMOTION__REG BMI160_USER_INT_MAP_0_ADDR

/* Int_Map_0 Description - Reg Addr --> 0x55, Bit -->3 */
#define BMI160_USER_INT_MAP_0_INT1_NOMOTION__POS               3
#define BMI160_USER_INT_MAP_0_INT1_NOMOTION__LEN               1
#define BMI160_USER_INT_MAP_0_INT1_NOMOTION__MSK               0x08
#define BMI160_USER_INT_MAP_0_INT1_NOMOTION__REG BMI160_USER_INT_MAP_0_ADDR

/* Int_Map_0 Description - Reg Addr --> 0x55, Bit -->4 */
#define BMI160_USER_INT_MAP_0_INT1_D_TAP__POS               4
#define BMI160_USER_INT_MAP_0_INT1_D_TAP__LEN               1
#define BMI160_USER_INT_MAP_0_INT1_D_TAP__MSK               0x10
#define BMI160_USER_INT_MAP_0_INT1_D_TAP__REG	BMI160_USER_INT_MAP_0_ADDR

/* Int_Map_0 Description - Reg Addr --> 0x55, Bit -->5 */
#define BMI160_USER_INT_MAP_0_INT1_S_TAP__POS               5
#define BMI160_USER_INT_MAP_0_INT1_S_TAP__LEN               1
#define BMI160_USER_INT_MAP_0_INT1_S_TAP__MSK               0x20
#define BMI160_USER_INT_MAP_0_INT1_S_TAP__REG	BMI160_USER_INT_MAP_0_ADDR

/* Int_Map_0 Description - Reg Addr --> 0x55, Bit -->6 */
#define BMI160_USER_INT_MAP_0_INT1_ORIENT__POS               6
#define BMI160_USER_INT_MAP_0_INT1_ORIENT__LEN               1
#define BMI160_USER_INT_MAP_0_INT1_ORIENT__MSK               0x40
#define BMI160_USER_INT_MAP_0_INT1_ORIENT__REG	BMI160_USER_INT_MAP_0_ADDR

/* Int_Map_0 Description - Reg Addr --> 0x56, Bit -->7 */
#define BMI160_USER_INT_MAP_0_INT1_FLAT__POS               7
#define BMI160_USER_INT_MAP_0_INT1_FLAT__LEN               1
#define BMI160_USER_INT_MAP_0_INT1_FLAT__MSK               0x80
#define BMI160_USER_INT_MAP_0_INT1_FLAT__REG	BMI160_USER_INT_MAP_0_ADDR

/* Int_Map_1 Description - Reg Addr --> 0x56, Bit -->0 */
#define BMI160_USER_INT_MAP_1_INT2_PMU_TRIG__POS               0
#define BMI160_USER_INT_MAP_1_INT2_PMU_TRIG__LEN               1
#define BMI160_USER_INT_MAP_1_INT2_PMU_TRIG__MSK               0x01
#define BMI160_USER_INT_MAP_1_INT2_PMU_TRIG__REG BMI160_USER_INT_MAP_1_ADDR

/* Int_Map_1 Description - Reg Addr --> 0x56, Bit -->1 */
#define BMI160_USER_INT_MAP_1_INT2_FFULL__POS               1
#define BMI160_USER_INT_MAP_1_INT2_FFULL__LEN               1
#define BMI160_USER_INT_MAP_1_INT2_FFULL__MSK               0x02
#define BMI160_USER_INT_MAP_1_INT2_FFULL__REG	BMI160_USER_INT_MAP_1_ADDR

/* Int_Map_1 Description - Reg Addr --> 0x56, Bit -->2 */
#define BMI160_USER_INT_MAP_1_INT2_FWM__POS               2
#define BMI160_USER_INT_MAP_1_INT2_FWM__LEN               1
#define BMI160_USER_INT_MAP_1_INT2_FWM__MSK               0x04
#define BMI160_USER_INT_MAP_1_INT2_FWM__REG	BMI160_USER_INT_MAP_1_ADDR

/* Int_Map_1 Description - Reg Addr --> 0x56, Bit -->3 */
#define BMI160_USER_INT_MAP_1_INT2_DRDY__POS               3
#define BMI160_USER_INT_MAP_1_INT2_DRDY__LEN               1
#define BMI160_USER_INT_MAP_1_INT2_DRDY__MSK               0x08
#define BMI160_USER_INT_MAP_1_INT2_DRDY__REG	BMI160_USER_INT_MAP_1_ADDR

/* Int_Map_1 Description - Reg Addr --> 0x56, Bit -->4 */
#define BMI160_USER_INT_MAP_1_INT1_PMU_TRIG__POS               4
#define BMI160_USER_INT_MAP_1_INT1_PMU_TRIG__LEN               1
#define BMI160_USER_INT_MAP_1_INT1_PMU_TRIG__MSK               0x10
#define BMI160_USER_INT_MAP_1_INT1_PMU_TRIG__REG BMI160_USER_INT_MAP_1_ADDR

/* Int_Map_1 Description - Reg Addr --> 0x56, Bit -->5 */
#define BMI160_USER_INT_MAP_1_INT1_FFULL__POS               5
#define BMI160_USER_INT_MAP_1_INT1_FFULL__LEN               1
#define BMI160_USER_INT_MAP_1_INT1_FFULL__MSK               0x20
#define BMI160_USER_INT_MAP_1_INT1_FFULL__REG	BMI160_USER_INT_MAP_1_ADDR

/* Int_Map_1 Description - Reg Addr --> 0x56, Bit -->6 */
#define BMI160_USER_INT_MAP_1_INT1_FWM__POS               6
#define BMI160_USER_INT_MAP_1_INT1_FWM__LEN               1
#define BMI160_USER_INT_MAP_1_INT1_FWM__MSK               0x40
#define BMI160_USER_INT_MAP_1_INT1_FWM__REG	BMI160_USER_INT_MAP_1_ADDR

/* Int_Map_1 Description - Reg Addr --> 0x56, Bit -->7 */
#define BMI160_USER_INT_MAP_1_INT1_DRDY__POS               7
#define BMI160_USER_INT_MAP_1_INT1_DRDY__LEN               1
#define BMI160_USER_INT_MAP_1_INT1_DRDY__MSK               0x80
#define BMI160_USER_INT_MAP_1_INT1_DRDY__REG	BMI160_USER_INT_MAP_1_ADDR

/* Int_Map_2 Description - Reg Addr --> 0x57, Bit -->0 */
#define BMI160_USER_INT_MAP_2_INT2_LOWG__POS               0
#define BMI160_USER_INT_MAP_2_INT2_LOWG__LEN               1
#define BMI160_USER_INT_MAP_2_INT2_LOWG__MSK               0x01
#define BMI160_USER_INT_MAP_2_INT2_LOWG__REG	BMI160_USER_INT_MAP_2_ADDR

/* Int_Map_2 Description - Reg Addr --> 0x57, Bit -->1 */
#define BMI160_USER_INT_MAP_2_INT2_HIGHG__POS               1
#define BMI160_USER_INT_MAP_2_INT2_HIGHG__LEN               1
#define BMI160_USER_INT_MAP_2_INT2_HIGHG__MSK               0x02
#define BMI160_USER_INT_MAP_2_INT2_HIGHG__REG	BMI160_USER_INT_MAP_2_ADDR

/* Int_Map_2 Description - Reg Addr --> 0x57, Bit -->2 */
#define BMI160_USER_INT_MAP_2_INT2_ANYMOTION__POS               2
#define BMI160_USER_INT_MAP_2_INT2_ANYMOTION__LEN               1
#define BMI160_USER_INT_MAP_2_INT2_ANYMOTION__MSK               0x04
#define BMI160_USER_INT_MAP_2_INT2_ANYMOTION__REG BMI160_USER_INT_MAP_2_ADDR

/* Int_Map_2 Description - Reg Addr --> 0x57, Bit -->3 */
#define BMI160_USER_INT_MAP_2_INT2_NOMOTION__POS               3
#define BMI160_USER_INT_MAP_2_INT2_NOMOTION__LEN               1
#define BMI160_USER_INT_MAP_2_INT2_NOMOTION__MSK               0x08
#define BMI160_USER_INT_MAP_2_INT2_NOMOTION__REG BMI160_USER_INT_MAP_2_ADDR

/* Int_Map_2 Description - Reg Addr --> 0x57, Bit -->4 */
#define BMI160_USER_INT_MAP_2_INT2_D_TAP__POS               4
#define BMI160_USER_INT_MAP_2_INT2_D_TAP__LEN               1
#define BMI160_USER_INT_MAP_2_INT2_D_TAP__MSK               0x10
#define BMI160_USER_INT_MAP_2_INT2_D_TAP__REG	BMI160_USER_INT_MAP_2_ADDR

/* Int_Map_2 Description - Reg Addr --> 0x57, Bit -->5 */
#define BMI160_USER_INT_MAP_2_INT2_S_TAP__POS               5
#define BMI160_USER_INT_MAP_2_INT2_S_TAP__LEN               1
#define BMI160_USER_INT_MAP_2_INT2_S_TAP__MSK               0x20
#define BMI160_USER_INT_MAP_2_INT2_S_TAP__REG	BMI160_USER_INT_MAP_2_ADDR

/* Int_Map_2 Description - Reg Addr --> 0x57, Bit -->6 */
#define BMI160_USER_INT_MAP_2_INT2_ORIENT__POS               6
#define BMI160_USER_INT_MAP_2_INT2_ORIENT__LEN               1
#define BMI160_USER_INT_MAP_2_INT2_ORIENT__MSK               0x40
#define BMI160_USER_INT_MAP_2_INT2_ORIENT__REG	BMI160_USER_INT_MAP_2_ADDR

/* Int_Map_2 Description - Reg Addr --> 0x57, Bit -->7 */

#define BMI160_USER_INT_MAP_2_INT2_FLAT__POS               7
#define BMI160_USER_INT_MAP_2_INT2_FLAT__LEN               1
#define BMI160_USER_INT_MAP_2_INT2_FLAT__MSK               0x80
#define BMI160_USER_INT_MAP_2_INT2_FLAT__REG	BMI160_USER_INT_MAP_2_ADDR


/* Int_Data_0 Description - Reg Addr --> 0x58, Bit --> 3 */
#define BMI160_USER_INT_DATA_0_INT_TAP_SRC__POS               3
#define BMI160_USER_INT_DATA_0_INT_TAP_SRC__LEN               1
#define BMI160_USER_INT_DATA_0_INT_TAP_SRC__MSK               0x08
#define BMI160_USER_INT_DATA_0_INT_TAP_SRC__REG	BMI160_USER_INT_DATA_0_ADDR


/* Int_Data_0 Description - Reg Addr --> 0x58, Bit --> 7 */
#define BMI160_USER_INT_DATA_0_INT_LOW_HIGH_SRC__POS               7
#define BMI160_USER_INT_DATA_0_INT_LOW_HIGH_SRC__LEN               1
#define BMI160_USER_INT_DATA_0_INT_LOW_HIGH_SRC__MSK               0x80
#define BMI160_USER_INT_DATA_0_INT_LOW_HIGH_SRC__REG BMI160_USER_INT_DATA_0_ADDR


/* Int_Data_1 Description - Reg Addr --> 0x59, Bit --> 7 */
#define BMI160_USER_INT_DATA_1_INT_MOTION_SRC__POS               7
#define BMI160_USER_INT_DATA_1_INT_MOTION_SRC__LEN               1
#define BMI160_USER_INT_DATA_1_INT_MOTION_SRC__MSK               0x80
#define BMI160_USER_INT_DATA_1_INT_MOTION_SRC__REG               \
		BMI160_USER_INT_DATA_1_ADDR

/* Int_LowHigh_0 Description - Reg Addr --> 0x5a, Bit --> 0...7 */
#define BMI160_USER_INT_LOWHIGH_0_INT_LOW_DUR__POS               0
#define BMI160_USER_INT_LOWHIGH_0_INT_LOW_DUR__LEN               8
#define BMI160_USER_INT_LOWHIGH_0_INT_LOW_DUR__MSK               0xFF
#define BMI160_USER_INT_LOWHIGH_0_INT_LOW_DUR__REG               \
		BMI160_USER_INT_LOWHIGH_0_ADDR

/* Int_LowHigh_1 Description - Reg Addr --> 0x5b, Bit --> 0...7 */
#define BMI160_USER_INT_LOWHIGH_1_INT_LOW_TH__POS               0
#define BMI160_USER_INT_LOWHIGH_1_INT_LOW_TH__LEN               8
#define BMI160_USER_INT_LOWHIGH_1_INT_LOW_TH__MSK               0xFF
#define BMI160_USER_INT_LOWHIGH_1_INT_LOW_TH__REG               \
		BMI160_USER_INT_LOWHIGH_1_ADDR

/* Int_LowHigh_2 Description - Reg Addr --> 0x5c, Bit --> 0...1 */
#define BMI160_USER_INT_LOWHIGH_2_INT_LOW_HY__POS               0
#define BMI160_USER_INT_LOWHIGH_2_INT_LOW_HY__LEN               2
#define BMI160_USER_INT_LOWHIGH_2_INT_LOW_HY__MSK               0x03
#define BMI160_USER_INT_LOWHIGH_2_INT_LOW_HY__REG               \
		BMI160_USER_INT_LOWHIGH_2_ADDR

/* Int_LowHigh_2 Description - Reg Addr --> 0x5c, Bit --> 2 */
#define BMI160_USER_INT_LOWHIGH_2_INT_LOW_MODE__POS               2
#define BMI160_USER_INT_LOWHIGH_2_INT_LOW_MODE__LEN               1
#define BMI160_USER_INT_LOWHIGH_2_INT_LOW_MODE__MSK               0x04
#define BMI160_USER_INT_LOWHIGH_2_INT_LOW_MODE__REG               \
		BMI160_USER_INT_LOWHIGH_2_ADDR

/* Int_LowHigh_2 Description - Reg Addr --> 0x5c, Bit --> 6...7 */
#define BMI160_USER_INT_LOWHIGH_2_INT_HIGH_HY__POS               6
#define BMI160_USER_INT_LOWHIGH_2_INT_HIGH_HY__LEN               2
#define BMI160_USER_INT_LOWHIGH_2_INT_HIGH_HY__MSK               0xC0
#define BMI160_USER_INT_LOWHIGH_2_INT_HIGH_HY__REG               \
		BMI160_USER_INT_LOWHIGH_2_ADDR

/* Int_LowHigh_3 Description - Reg Addr --> 0x5d, Bit --> 0...7 */
#define BMI160_USER_INT_LOWHIGH_3_INT_HIGH_DUR__POS               0
#define BMI160_USER_INT_LOWHIGH_3_INT_HIGH_DUR__LEN               8
#define BMI160_USER_INT_LOWHIGH_3_INT_HIGH_DUR__MSK               0xFF
#define BMI160_USER_INT_LOWHIGH_3_INT_HIGH_DUR__REG               \
		BMI160_USER_INT_LOWHIGH_3_ADDR

/* Int_LowHigh_4 Description - Reg Addr --> 0x5e, Bit --> 0...7 */
#define BMI160_USER_INT_LOWHIGH_4_INT_HIGH_TH__POS               0
#define BMI160_USER_INT_LOWHIGH_4_INT_HIGH_TH__LEN               8
#define BMI160_USER_INT_LOWHIGH_4_INT_HIGH_TH__MSK               0xFF
#define BMI160_USER_INT_LOWHIGH_4_INT_HIGH_TH__REG               \
		BMI160_USER_INT_LOWHIGH_4_ADDR

/* Int_Motion_0 Description - Reg Addr --> 0x5f, Bit --> 0...1 */
#define BMI160_USER_INT_MOTION_0_INT_ANYMO_DUR__POS               0
#define BMI160_USER_INT_MOTION_0_INT_ANYMO_DUR__LEN               2
#define BMI160_USER_INT_MOTION_0_INT_ANYMO_DUR__MSK               0x03
#define BMI160_USER_INT_MOTION_0_INT_ANYMO_DUR__REG               \
		BMI160_USER_INT_MOTION_0_ADDR

	/* Int_Motion_0 Description - Reg Addr --> 0x5f, Bit --> 2...7 */
#define BMI160_USER_INT_MOTION_0_INT_SLO_NOMO_DUR__POS               2
#define BMI160_USER_INT_MOTION_0_INT_SLO_NOMO_DUR__LEN               6
#define BMI160_USER_INT_MOTION_0_INT_SLO_NOMO_DUR__MSK               0xFC
#define BMI160_USER_INT_MOTION_0_INT_SLO_NOMO_DUR__REG               \
		BMI160_USER_INT_MOTION_0_ADDR

/* Int_Motion_1 Description - Reg Addr --> 0x60, Bit --> 0...7 */
#define BMI160_USER_INT_MOTION_1_INT_ANYMOTION_TH__POS               0
#define BMI160_USER_INT_MOTION_1_INT_ANYMOTION_TH__LEN               8
#define BMI160_USER_INT_MOTION_1_INT_ANYMOTION_TH__MSK               0xFF
#define BMI160_USER_INT_MOTION_1_INT_ANYMOTION_TH__REG               \
		BMI160_USER_INT_MOTION_1_ADDR

/* Int_Motion_2 Description - Reg Addr --> 0x61, Bit --> 0...7 */
#define BMI160_USER_INT_MOTION_2_INT_SLO_NOMO_TH__POS               0
#define BMI160_USER_INT_MOTION_2_INT_SLO_NOMO_TH__LEN               8
#define BMI160_USER_INT_MOTION_2_INT_SLO_NOMO_TH__MSK               0xFF
#define BMI160_USER_INT_MOTION_2_INT_SLO_NOMO_TH__REG               \
		BMI160_USER_INT_MOTION_2_ADDR

/* Int_Motion_3 Description - Reg Addr --> 0x62, Bit --> 0 */
#define BMI160_USER_INT_MOTION_3_INT_SLO_NOMO_SEL__POS		0
#define BMI160_USER_INT_MOTION_3_INT_SLO_NOMO_SEL__LEN		1
#define BMI160_USER_INT_MOTION_3_INT_SLO_NOMO_SEL__MSK		0x01
#define BMI160_USER_INT_MOTION_3_INT_SLO_NOMO_SEL__REG               \
		BMI160_USER_INT_MOTION_3_ADDR

/* Int_Motion_3 Description - Reg Addr --> 0x62, Bit --> 1 */
#define BMI160_USER_INT_SIG_MOT_SEL__POS	1
#define BMI160_USER_INT_SIG_MOT_SEL__LEN		1
#define BMI160_USER_INT_SIG_MOT_SEL__MSK		0x02
#define BMI160_USER_INT_SIG_MOT_SEL__REG		\
		BMI160_USER_INT_MOTION_3_ADDR

/* Int_Motion_3 Description - Reg Addr --> 0x62, Bit --> 3..2 */
#define BMI160_USER_INT_SIG_MOT_SKIP__POS		2
#define BMI160_USER_INT_SIG_MOT_SKIP__LEN		2
#define BMI160_USER_INT_SIG_MOT_SKIP__MSK		0x0C
#define BMI160_USER_INT_SIG_MOT_SKIP__REG		\
		BMI160_USER_INT_MOTION_3_ADDR

/* Int_Motion_3 Description - Reg Addr --> 0x62, Bit --> 5..4 */
#define BMI160_USER_INT_SIG_MOT_PROOF__POS		4
#define BMI160_USER_INT_SIG_MOT_PROOF__LEN		2
#define BMI160_USER_INT_SIG_MOT_PROOF__MSK		0x30
#define BMI160_USER_INT_SIG_MOT_PROOF__REG		\
		BMI160_USER_INT_MOTION_3_ADDR

/* INT_TAP_0 Description - Reg Addr --> 0x63, Bit --> 0..2*/
#define BMI160_USER_INT_TAP_0_INT_TAP_DUR__POS               0
#define BMI160_USER_INT_TAP_0_INT_TAP_DUR__LEN               3
#define BMI160_USER_INT_TAP_0_INT_TAP_DUR__MSK               0x07
#define BMI160_USER_INT_TAP_0_INT_TAP_DUR__REG	BMI160_USER_INT_TAP_0_ADDR

/* Int_Tap_0 Description - Reg Addr --> 0x63, Bit --> 6 */
#define BMI160_USER_INT_TAP_0_INT_TAP_SHOCK__POS               6
#define BMI160_USER_INT_TAP_0_INT_TAP_SHOCK__LEN               1
#define BMI160_USER_INT_TAP_0_INT_TAP_SHOCK__MSK               0x40
#define BMI160_USER_INT_TAP_0_INT_TAP_SHOCK__REG BMI160_USER_INT_TAP_0_ADDR

/* Int_Tap_0 Description - Reg Addr --> 0x63, Bit --> 7 */
#define BMI160_USER_INT_TAP_0_INT_TAP_QUIET__POS               7
#define BMI160_USER_INT_TAP_0_INT_TAP_QUIET__LEN               1
#define BMI160_USER_INT_TAP_0_INT_TAP_QUIET__MSK               0x80
#define BMI160_USER_INT_TAP_0_INT_TAP_QUIET__REG BMI160_USER_INT_TAP_0_ADDR

/* Int_Tap_1 Description - Reg Addr --> 0x64, Bit --> 0...4 */
#define BMI160_USER_INT_TAP_1_INT_TAP_TH__POS               0
#define BMI160_USER_INT_TAP_1_INT_TAP_TH__LEN               5
#define BMI160_USER_INT_TAP_1_INT_TAP_TH__MSK               0x1F
#define BMI160_USER_INT_TAP_1_INT_TAP_TH__REG BMI160_USER_INT_TAP_1_ADDR

/* Int_Orient_0 Description - Reg Addr --> 0x65, Bit --> 0...1 */
#define BMI160_USER_INT_ORIENT_0_INT_ORIENT_MODE__POS               0
#define BMI160_USER_INT_ORIENT_0_INT_ORIENT_MODE__LEN               2
#define BMI160_USER_INT_ORIENT_0_INT_ORIENT_MODE__MSK               0x03
#define BMI160_USER_INT_ORIENT_0_INT_ORIENT_MODE__REG               \
		BMI160_USER_INT_ORIENT_0_ADDR

/* Int_Orient_0 Description - Reg Addr --> 0x65, Bit --> 2...3 */
#define BMI160_USER_INT_ORIENT_0_INT_ORIENT_BLOCKING__POS               2
#define BMI160_USER_INT_ORIENT_0_INT_ORIENT_BLOCKING__LEN               2
#define BMI160_USER_INT_ORIENT_0_INT_ORIENT_BLOCKING__MSK               0x0C
#define BMI160_USER_INT_ORIENT_0_INT_ORIENT_BLOCKING__REG               \
		BMI160_USER_INT_ORIENT_0_ADDR

/* Int_Orient_0 Description - Reg Addr --> 0x65, Bit --> 4...7 */
#define BMI160_USER_INT_ORIENT_0_INT_ORIENT_HY__POS               4
#define BMI160_USER_INT_ORIENT_0_INT_ORIENT_HY__LEN               4
#define BMI160_USER_INT_ORIENT_0_INT_ORIENT_HY__MSK               0xF0
#define BMI160_USER_INT_ORIENT_0_INT_ORIENT_HY__REG               \
		BMI160_USER_INT_ORIENT_0_ADDR

/* Int_Orient_1 Description - Reg Addr --> 0x66, Bit --> 0...5 */
#define BMI160_USER_INT_ORIENT_1_INT_ORIENT_THETA__POS               0
#define BMI160_USER_INT_ORIENT_1_INT_ORIENT_THETA__LEN               6
#define BMI160_USER_INT_ORIENT_1_INT_ORIENT_THETA__MSK               0x3F
#define BMI160_USER_INT_ORIENT_1_INT_ORIENT_THETA__REG               \
		BMI160_USER_INT_ORIENT_1_ADDR

/* Int_Orient_1 Description - Reg Addr --> 0x66, Bit --> 6 */
#define BMI160_USER_INT_ORIENT_1_INT_ORIENT_UD_EN__POS               6
#define BMI160_USER_INT_ORIENT_1_INT_ORIENT_UD_EN__LEN               1
#define BMI160_USER_INT_ORIENT_1_INT_ORIENT_UD_EN__MSK               0x40
#define BMI160_USER_INT_ORIENT_1_INT_ORIENT_UD_EN__REG               \
		BMI160_USER_INT_ORIENT_1_ADDR

/* Int_Orient_1 Description - Reg Addr --> 0x66, Bit --> 7 */
#define BMI160_USER_INT_ORIENT_1_INT_ORIENT_AXES_EX__POS               7
#define BMI160_USER_INT_ORIENT_1_INT_ORIENT_AXES_EX__LEN               1
#define BMI160_USER_INT_ORIENT_1_INT_ORIENT_AXES_EX__MSK               0x80
#define BMI160_USER_INT_ORIENT_1_INT_ORIENT_AXES_EX__REG               \
		BMI160_USER_INT_ORIENT_1_ADDR

/* Int_Flat_0 Description - Reg Addr --> 0x67, Bit --> 0...5 */
#define BMI160_USER_INT_FLAT_0_INT_FLAT_THETA__POS               0
#define BMI160_USER_INT_FLAT_0_INT_FLAT_THETA__LEN               6
#define BMI160_USER_INT_FLAT_0_INT_FLAT_THETA__MSK               0x3F
#define BMI160_USER_INT_FLAT_0_INT_FLAT_THETA__REG  \
		BMI160_USER_INT_FLAT_0_ADDR

/* Int_Flat_1 Description - Reg Addr --> 0x68, Bit --> 0...3 */
#define BMI160_USER_INT_FLAT_1_INT_FLAT_HY__POS		0
#define BMI160_USER_INT_FLAT_1_INT_FLAT_HY__LEN		4
#define BMI160_USER_INT_FLAT_1_INT_FLAT_HY__MSK		0x0F
#define BMI160_USER_INT_FLAT_1_INT_FLAT_HY__REG	 BMI160_USER_INT_FLAT_1_ADDR

/* Int_Flat_1 Description - Reg Addr --> 0x68, Bit --> 4...5 */
#define BMI160_USER_INT_FLAT_1_INT_FLAT_HOLD__POS                4
#define BMI160_USER_INT_FLAT_1_INT_FLAT_HOLD__LEN                2
#define BMI160_USER_INT_FLAT_1_INT_FLAT_HOLD__MSK                0x30
#define BMI160_USER_INT_FLAT_1_INT_FLAT_HOLD__REG  \
		BMI160_USER_INT_FLAT_1_ADDR

/* Foc_Conf Description - Reg Addr --> 0x69, Bit --> 0...1 */
#define BMI160_USER_FOC_ACC_Z__POS               0
#define BMI160_USER_FOC_ACC_Z__LEN               2
#define BMI160_USER_FOC_ACC_Z__MSK               0x03
#define BMI160_USER_FOC_ACC_Z__REG               BMI160_USER_FOC_CONF_ADDR

/* Foc_Conf Description - Reg Addr --> 0x69, Bit --> 2...3 */
#define BMI160_USER_FOC_ACC_Y__POS               2
#define BMI160_USER_FOC_ACC_Y__LEN               2
#define BMI160_USER_FOC_ACC_Y__MSK               0x0C
#define BMI160_USER_FOC_ACC_Y__REG               BMI160_USER_FOC_CONF_ADDR

/* Foc_Conf Description - Reg Addr --> 0x69, Bit --> 4...5 */
#define BMI160_USER_FOC_ACC_X__POS               4
#define BMI160_USER_FOC_ACC_X__LEN               2
#define BMI160_USER_FOC_ACC_X__MSK               0x30
#define BMI160_USER_FOC_ACC_X__REG               BMI160_USER_FOC_CONF_ADDR

/* Foc_Conf Description - Reg Addr --> 0x69, Bit --> 6 */
#define BMI160_USER_FOC_GYR_EN__POS               6
#define BMI160_USER_FOC_GYR_EN__LEN               1
#define BMI160_USER_FOC_GYR_EN__MSK               0x40
#define BMI160_USER_FOC_GYR_EN__REG               BMI160_USER_FOC_CONF_ADDR

/* CONF Description - Reg Addr --> 0x6A, Bit --> 1 */
#define BMI160_USER_CONF_NVM_PROG_EN__POS               1
#define BMI160_USER_CONF_NVM_PROG_EN__LEN               1
#define BMI160_USER_CONF_NVM_PROG_EN__MSK               0x02
#define BMI160_USER_CONF_NVM_PROG_EN__REG               BMI160_USER_CONF_ADDR

/*IF_CONF Description - Reg Addr --> 0x6B, Bit --> 0 */

#define BMI160_USER_IF_CONF_SPI3__POS               0
#define BMI160_USER_IF_CONF_SPI3__LEN               1
#define BMI160_USER_IF_CONF_SPI3__MSK               0x01
#define BMI160_USER_IF_CONF_SPI3__REG               BMI160_USER_IF_CONF_ADDR

/*IF_CONF Description - Reg Addr --> 0x6B, Bit --> 5..4 */
#define BMI160_USER_IF_CONF_IF_MODE__POS               4
#define BMI160_USER_IF_CONF_IF_MODE__LEN               2
#define BMI160_USER_IF_CONF_IF_MODE__MSK               0x30
#define BMI160_USER_IF_CONF_IF_MODE__REG		BMI160_USER_IF_CONF_ADDR

/* Pmu_Trigger Description - Reg Addr --> 0x6c, Bit --> 0...2 */
#define BMI160_USER_GYRO_SLEEP_TRIGGER__POS               0
#define BMI160_USER_GYRO_SLEEP_TRIGGER__LEN               3
#define BMI160_USER_GYRO_SLEEP_TRIGGER__MSK               0x07
#define BMI160_USER_GYRO_SLEEP_TRIGGER__REG	BMI160_USER_PMU_TRIGGER_ADDR

/* Pmu_Trigger Description - Reg Addr --> 0x6c, Bit --> 3...4 */
#define BMI160_USER_GYRO_WAKEUP_TRIGGER__POS               3
#define BMI160_USER_GYRO_WAKEUP_TRIGGER__LEN               2
#define BMI160_USER_GYRO_WAKEUP_TRIGGER__MSK               0x18
#define BMI160_USER_GYRO_WAKEUP_TRIGGER__REG	BMI160_USER_PMU_TRIGGER_ADDR

/* Pmu_Trigger Description - Reg Addr --> 0x6c, Bit --> 5 */
#define BMI160_USER_GYRO_SLEEP_STATE__POS               5
#define BMI160_USER_GYRO_SLEEP_STATE__LEN               1
#define BMI160_USER_GYRO_SLEEP_STATE__MSK               0x20
#define BMI160_USER_GYRO_SLEEP_STATE__REG	BMI160_USER_PMU_TRIGGER_ADDR

/* Pmu_Trigger Description - Reg Addr --> 0x6c, Bit --> 6 */
#define BMI160_USER_GYRO_WAKEUP_INT__POS               6
#define BMI160_USER_GYRO_WAKEUP_INT__LEN               1
#define BMI160_USER_GYRO_WAKEUP_INT__MSK               0x40
#define BMI160_USER_GYRO_WAKEUP_INT__REG	BMI160_USER_PMU_TRIGGER_ADDR

/* Self_Test Description - Reg Addr --> 0x6d, Bit --> 0...1 */
#define BMI160_USER_ACC_SELF_TEST_AXIS__POS               0
#define BMI160_USER_ACC_SELF_TEST_AXIS__LEN               2
#define BMI160_USER_ACC_SELF_TEST_AXIS__MSK               0x03
#define BMI160_USER_ACC_SELF_TEST_AXIS__REG	BMI160_USER_SELF_TEST_ADDR

/* Self_Test Description - Reg Addr --> 0x6d, Bit --> 2 */
#define BMI160_USER_ACC_SELF_TEST_SIGN__POS               2
#define BMI160_USER_ACC_SELF_TEST_SIGN__LEN               1
#define BMI160_USER_ACC_SELF_TEST_SIGN__MSK               0x04
#define BMI160_USER_ACC_SELF_TEST_SIGN__REG	BMI160_USER_SELF_TEST_ADDR

/* Self_Test Description - Reg Addr --> 0x6d, Bit --> 3 */
#define BMI160_USER_SELF_TEST_AMP__POS               3
#define BMI160_USER_SELF_TEST_AMP__LEN               1
#define BMI160_USER_SELF_TEST_AMP__MSK               0x08
#define BMI160_USER_SELF_TEST_AMP__REG		BMI160_USER_SELF_TEST_ADDR

/* Self_Test Description - Reg Addr --> 0x6d, Bit --> 4 */
#define BMI160_USER_GYRO_SELF_TEST_START__POS               4
#define BMI160_USER_GYRO_SELF_TEST_START__LEN               1
#define BMI160_USER_GYRO_SELF_TEST_START__MSK               0x10
#define BMI160_USER_GYRO_SELF_TEST_START__REG		    \
BMI160_USER_SELF_TEST_ADDR

/* NV_CONF Description - Reg Addr --> 0x70, Bit --> 0 */
#define BMI160_USER_NV_CONF_SPI_EN__POS               0
#define BMI160_USER_NV_CONF_SPI_EN__LEN               1
#define BMI160_USER_NV_CONF_SPI_EN__MSK               0x01
#define BMI160_USER_NV_CONF_SPI_EN__REG	 BMI160_USER_NV_CONF_ADDR

/*IF_CONF Description - Reg Addr --> 0x70, Bit --> 1 */
#define BMI160_USER_IF_CONF_I2C_WDT_SEL__POS               1
#define BMI160_USER_IF_CONF_I2C_WDT_SEL__LEN               1
#define BMI160_USER_IF_CONF_I2C_WDT_SEL__MSK               0x02
#define BMI160_USER_IF_CONF_I2C_WDT_SEL__REG		BMI160_USER_NV_CONF_ADDR

/*IF_CONF Description - Reg Addr --> 0x70, Bit --> 2 */
#define BMI160_USER_IF_CONF_I2C_WDT_EN__POS               2
#define BMI160_USER_IF_CONF_I2C_WDT_EN__LEN               1
#define BMI160_USER_IF_CONF_I2C_WDT_EN__MSK               0x04
#define BMI160_USER_IF_CONF_I2C_WDT_EN__REG		BMI160_USER_NV_CONF_ADDR

/* NV_CONF Description - Reg Addr --> 0x70, Bit --> 3 */
#define BMI160_USER_NV_CONF_SPARE0__POS               3
#define BMI160_USER_NV_CONF_SPARE0__LEN               1
#define BMI160_USER_NV_CONF_SPARE0__MSK               0x08
#define BMI160_USER_NV_CONF_SPARE0__REG	BMI160_USER_NV_CONF_ADDR

/* NV_CONF Description - Reg Addr --> 0x70, Bit --> 4...7 */
#define BMI160_USER_NV_CONF_NVM_COUNTER__POS               4
#define BMI160_USER_NV_CONF_NVM_COUNTER__LEN               4
#define BMI160_USER_NV_CONF_NVM_COUNTER__MSK               0xF0
#define BMI160_USER_NV_CONF_NVM_COUNTER__REG	BMI160_USER_NV_CONF_ADDR

/* Offset_0 Description - Reg Addr --> 0x71, Bit --> 0...7 */
#define BMI160_USER_OFFSET_0_ACC_OFF_X__POS               0
#define BMI160_USER_OFFSET_0_ACC_OFF_X__LEN               8
#define BMI160_USER_OFFSET_0_ACC_OFF_X__MSK               0xFF
#define BMI160_USER_OFFSET_0_ACC_OFF_X__REG	BMI160_USER_OFFSET_0_ADDR

/* Offset_1 Description - Reg Addr --> 0x72, Bit --> 0...7 */
#define BMI160_USER_OFFSET_1_ACC_OFF_Y__POS               0
#define BMI160_USER_OFFSET_1_ACC_OFF_Y__LEN               8
#define BMI160_USER_OFFSET_1_ACC_OFF_Y__MSK               0xFF
#define BMI160_USER_OFFSET_1_ACC_OFF_Y__REG	BMI160_USER_OFFSET_1_ADDR

/* Offset_2 Description - Reg Addr --> 0x73, Bit --> 0...7 */
#define BMI160_USER_OFFSET_2_ACC_OFF_Z__POS               0
#define BMI160_USER_OFFSET_2_ACC_OFF_Z__LEN               8
#define BMI160_USER_OFFSET_2_ACC_OFF_Z__MSK               0xFF
#define BMI160_USER_OFFSET_2_ACC_OFF_Z__REG	BMI160_USER_OFFSET_2_ADDR

/* Offset_3 Description - Reg Addr --> 0x74, Bit --> 0...7 */
#define BMI160_USER_OFFSET_3_GYR_OFF_X__POS               0
#define BMI160_USER_OFFSET_3_GYR_OFF_X__LEN               8
#define BMI160_USER_OFFSET_3_GYR_OFF_X__MSK               0xFF
#define BMI160_USER_OFFSET_3_GYR_OFF_X__REG	BMI160_USER_OFFSET_3_ADDR

/* Offset_4 Description - Reg Addr --> 0x75, Bit --> 0...7 */
#define BMI160_USER_OFFSET_4_GYR_OFF_Y__POS               0
#define BMI160_USER_OFFSET_4_GYR_OFF_Y__LEN               8
#define BMI160_USER_OFFSET_4_GYR_OFF_Y__MSK               0xFF
#define BMI160_USER_OFFSET_4_GYR_OFF_Y__REG	BMI160_USER_OFFSET_4_ADDR

/* Offset_5 Description - Reg Addr --> 0x76, Bit --> 0...7 */
#define BMI160_USER_OFFSET_5_GYR_OFF_Z__POS               0
#define BMI160_USER_OFFSET_5_GYR_OFF_Z__LEN               8
#define BMI160_USER_OFFSET_5_GYR_OFF_Z__MSK               0xFF
#define BMI160_USER_OFFSET_5_GYR_OFF_Z__REG	BMI160_USER_OFFSET_5_ADDR


/* Offset_6 Description - Reg Addr --> 0x77, Bit --> 0..1 */
#define BMI160_USER_OFFSET_6_GYR_OFF_X__POS               0
#define BMI160_USER_OFFSET_6_GYR_OFF_X__LEN               2
#define BMI160_USER_OFFSET_6_GYR_OFF_X__MSK               0x03
#define BMI160_USER_OFFSET_6_GYR_OFF_X__REG	BMI160_USER_OFFSET_6_ADDR

/* Offset_6 Description - Reg Addr --> 0x77, Bit --> 2...3 */
#define BMI160_USER_OFFSET_6_GYR_OFF_Y__POS               2
#define BMI160_USER_OFFSET_6_GYR_OFF_Y__LEN               2
#define BMI160_USER_OFFSET_6_GYR_OFF_Y__MSK               0x0C
#define BMI160_USER_OFFSET_6_GYR_OFF_Y__REG	BMI160_USER_OFFSET_6_ADDR

/* Offset_6 Description - Reg Addr --> 0x77, Bit --> 4...5 */
#define BMI160_USER_OFFSET_6_GYR_OFF_Z__POS               4
#define BMI160_USER_OFFSET_6_GYR_OFF_Z__LEN               2
#define BMI160_USER_OFFSET_6_GYR_OFF_Z__MSK               0x30
#define BMI160_USER_OFFSET_6_GYR_OFF_Z__REG	 BMI160_USER_OFFSET_6_ADDR

/* Offset_6 Description - Reg Addr --> 0x77, Bit --> 6 */
#define BMI160_USER_OFFSET_6_ACC_OFF_EN__POS               6
#define BMI160_USER_OFFSET_6_ACC_OFF_EN__LEN               1
#define BMI160_USER_OFFSET_6_ACC_OFF_EN__MSK               0x40
#define BMI160_USER_OFFSET_6_ACC_OFF_EN__REG	 BMI160_USER_OFFSET_6_ADDR

/* Offset_6 Description - Reg Addr --> 0x77, Bit -->  7 */
#define BMI160_USER_OFFSET_6_GYR_OFF_EN__POS               7
#define BMI160_USER_OFFSET_6_GYR_OFF_EN__LEN               1
#define BMI160_USER_OFFSET_6_GYR_OFF_EN__MSK               0x80
#define BMI160_USER_OFFSET_6_GYR_OFF_EN__REG	 BMI160_USER_OFFSET_6_ADDR

/* STEP_CNT_0  Description - Reg Addr --> 0x78, Bit -->  0 to 7 */
#define BMI160_USER_STEP_COUNT_LSB__POS               0
#define BMI160_USER_STEP_COUNT_LSB__LEN               7
#define BMI160_USER_STEP_COUNT_LSB__MSK               0xFF
#define BMI160_USER_STEP_COUNT_LSB__REG	 BMI160_USER_STEP_CNT_0_ADDR

/* STEP_CNT_1  Description - Reg Addr --> 0x79, Bit -->  0 to 7 */
#define BMI160_USER_STEP_COUNT_MSB__POS               0
#define BMI160_USER_STEP_COUNT_MSB__LEN               7
#define BMI160_USER_STEP_COUNT_MSB__MSK               0xFF
#define BMI160_USER_STEP_COUNT_MSB__REG	 BMI160_USER_STEP_CNT_1_ADDR

/* STEP_CONF_0  Description - Reg Addr --> 0x7A, Bit -->  0 to 7 */
#define BMI160_USER_STEP_CONF_ZERO__POS               0
#define BMI160_USER_STEP_CONF_ZERO__LEN               7
#define BMI160_USER_STEP_CONF_ZERO__MSK               0xFF
#define BMI160_USER_STEP_CONF_ZERO__REG	 BMI160_USER_STEP_CONF_0_ADDR


/* STEP_CONF_1  Description - Reg Addr --> 0x7B, Bit -->  0 to 2 and
4 to 7 */
#define BMI160_USER_STEP_CONF_ONE_CNF1__POS               0
#define BMI160_USER_STEP_CONF_ONE_CNF1__LEN               3
#define BMI160_USER_STEP_CONF_ONE_CNF1__MSK               0x07
#define BMI160_USER_STEP_CONF_ONE_CNF1__REG	 BMI160_USER_STEP_CONF_1_ADDR

#define BMI160_USER_STEP_CONF_ONE_CNF2__POS               4
#define BMI160_USER_STEP_CONF_ONE_CNF2__LEN               4
#define BMI160_USER_STEP_CONF_ONE_CNF2__MSK               0xF0
#define BMI160_USER_STEP_CONF_ONE_CNF2__REG	 BMI160_USER_STEP_CONF_1_ADDR

/* STEP_CONF_1  Description - Reg Addr --> 0x7B, Bit -->  0 to 2 */
#define BMI160_USER_STEP_CONF_1_STEP_CNT_EN__POS		3
#define BMI160_USER_STEP_CONF_1_STEP_CNT_EN__LEN		1
#define BMI160_USER_STEP_CONF_1_STEP_CNT_EN__MSK		0x08
#define BMI160_USER_STEP_CONF_1_STEP_CNT_EN__REG	\
BMI160_USER_STEP_CONF_1_ADDR

/* USER REGISTERS DEFINITION END */
/**************************************************************************/
/* CMD REGISTERS DEFINITION START */
/* Command description address - Reg Addr --> 0x7E, Bit -->  0....7 */
#define BMI160_CMD_COMMANDS__POS              0
#define BMI160_CMD_COMMANDS__LEN              8
#define BMI160_CMD_COMMANDS__MSK              0xFF
#define BMI160_CMD_COMMANDS__REG	 BMI160_CMD_COMMANDS_ADDR

/* Target page address - Reg Addr --> 0x7F, Bit -->  4....5 */
#define BMI160_CMD_TARGET_PAGE__POS           4
#define BMI160_CMD_TARGET_PAGE__LEN           2
#define BMI160_CMD_TARGET_PAGE__MSK           0x30
#define BMI160_CMD_TARGET_PAGE__REG	  BMI160_CMD_EXT_MODE_ADDR

/* Target page address - Reg Addr --> 0x7F, Bit -->  4....5 */
#define BMI160_CMD_PAGING_EN__POS           7
#define BMI160_CMD_PAGING_EN__LEN           1
#define BMI160_CMD_PAGING_EN__MSK           0x80
#define BMI160_CMD_PAGING_EN__REG		BMI160_CMD_EXT_MODE_ADDR

/* Target page address - Reg Addr --> 0x85, Bit -->  4....5 */
#define BMI160_COM_C_TRIM_FIVE__POS           4
#define BMI160_COM_C_TRIM_FIVE__LEN           2
#define BMI160_COM_C_TRIM_FIVE__MSK           0x30
#define BMI160_COM_C_TRIM_FIVE__REG		BMI160_COM_C_TRIM_FIVE_ADDR



/**************************************************************************/
/* CMD REGISTERS DEFINITION END */

/* CONSTANTS */
#define FIFO_FRAME		1024
/* Accel Range */
#define BMI160_ACCEL_RANGE_2G           0X03
#define BMI160_ACCEL_RANGE_4G           0X05
#define BMI160_ACCEL_RANGE_8G           0X08
#define BMI160_ACCELRANGE_16G           0X0C

/* BMI160 Accel ODR */
#define BMI160_ACCEL_ODR_RESERVED       0x00
#define BMI160_ACCEL_ODR_0_78HZ         0x01
#define BMI160_ACCEL_ODR_1_56HZ         0x02
#define BMI160_ACCEL_ODR_3_12HZ         0x03
#define BMI160_ACCEL_ODR_6_25HZ         0x04
#define BMI160_ACCEL_ODR_12_5HZ         0x05
#define BMI160_ACCEL_ODR_25HZ           0x06
#define BMI160_ACCEL_ODR_50HZ           0x07
#define BMI160_ACCEL_ODR_100HZ          0x08
#define BMI160_ACCEL_ODR_200HZ          0x09
#define BMI160_ACCEL_ODR_400HZ          0x0A
#define BMI160_ACCEL_ODR_800HZ          0x0B
#define BMI160_ACCEL_ODR_1600HZ         0x0C
#define BMI160_ACCEL_ODR_RESERVED0      0x0D
#define BMI160_ACCEL_ODR_RESERVED1      0x0E
#define BMI160_ACCEL_ODR_RESERVED2      0x0F

/* Accel bandwidth parameter */
#define BMI160_ACCEL_OSR4_AVG1			0x00
#define BMI160_ACCEL_OSR2_AVG2			0x01
#define BMI160_ACCEL_NORMAL_AVG4		0x02
#define BMI160_ACCEL_CIC_AVG8			0x03
#define BMI160_ACCEL_RES_AVG16			0x04
#define BMI160_ACCEL_RES_AVG32			0x05
#define BMI160_ACCEL_RES_AVG64			0x06
#define BMI160_ACCEL_RES_AVG128			0x07

/* BMI160 Gyro ODR */
#define BMI160_GYRO_ODR_RESERVED		0x00
#define BMI160_GYRO_ODR_25HZ			0x06
#define BMI160_GYRO_ODR_50HZ			0x07
#define BMI160_GYRO_ODR_100HZ			0x08
#define BMI160_GYRO_ODR_200HZ			0x09
#define BMI160_GYRO_ODR_400HZ			0x0A
#define BMI160_GYRO_ODR_800HZ			0x0B
#define BMI160_GYRO_ODR_1600HZ			0x0C
#define BMI160_GYRO_ODR_3200HZ			0x0D

/*Gyroscope bandwidth parameter */
#define BMI160_GYRO_OSR4_MODE		0x00
#define BMI160_GYRO_OSR2_MODE		0x01
#define BMI160_GYRO_NORMAL_MODE		0x02
#define BMI160_GYRO_CIC_MODE		0x03

/* BMI160 Mag ODR */
#define BMI160_MAG_ODR_RESERVED       0x00
#define BMI160_MAG_ODR_0_78HZ         0x01
#define BMI160_MAG_ODR_1_56HZ         0x02
#define BMI160_MAG_ODR_3_12HZ         0x03
#define BMI160_MAG_ODR_6_25HZ         0x04
#define BMI160_MAG_ODR_12_5HZ         0x05
#define BMI160_MAG_ODR_25HZ           0x06
#define BMI160_MAG_ODR_50HZ           0x07
#define BMI160_MAG_ODR_100HZ          0x08
#define BMI160_MAG_ODR_200HZ          0x09
#define BMI160_MAG_ODR_400HZ          0x0A
#define BMI160_MAG_ODR_800HZ          0x0B
#define BMI160_MAG_ODR_1600HZ         0x0C
#define BMI160_MAG_ODR_RESERVED0      0x0D
#define BMI160_MAG_ODR_RESERVED1      0x0E
#define BMI160_MAG_ODR_RESERVED2      0x0F

/*Reserved*/

/* Enable accel and gyro offset */
#define ACCEL_OFFSET_ENABLE		0x01
#define GYRO_OFFSET_ENABLE		0x01

/* command register definition */
#define START_FOC_ACCEL_GYRO	0X03

 /* INT ENABLE 1 */
#define BMI160_ANYMO_X_EN       0
#define BMI160_ANYMO_Y_EN       1
#define BMI160_ANYMO_Z_EN       2
#define BMI160_D_TAP_EN         4
#define BMI160_S_TAP_EN         5
#define BMI160_ORIENT_EN        6
#define BMI160_FLAT_EN          7

/* INT ENABLE 1 */
#define BMI160_HIGH_X_EN       0
#define BMI160_HIGH_Y_EN       1
#define BMI160_HIGH_Z_EN       2
#define BMI160_LOW_EN          3
#define BMI160_DRDY_EN         4
#define BMI160_FFULL_EN        5
#define BMI160_FWM_EN          6

/* INT ENABLE 2 */
#define  BMI160_NOMOTION_X_EN	0
#define  BMI160_NOMOTION_Y_EN	1
#define  BMI160_NOMOTION_Z_EN	2

/* FOC axis selection for accel*/
#define	FOC_X_AXIS		0
#define	FOC_Y_AXIS		1
#define	FOC_Z_AXIS		2

/* IN OUT CONTROL */
#define BMI160_INT1_EDGE_CTRL		0
#define BMI160_INT2_EDGE_CTRL		1
#define BMI160_INT1_LVL				0
#define BMI160_INT2_LVL				1
#define BMI160_INT1_OD				0
#define BMI160_INT2_OD				1
#define BMI160_INT1_OUTPUT_EN		0
#define BMI160_INT2_OUTPUT_EN		1

#define BMI160_INT1_INPUT_EN		0
#define BMI160_INT2_INPUT_EN		1

/*  INTERRUPT MAPS    */
#define BMI160_INT1_MAP_LOW_G		0
#define BMI160_INT2_MAP_LOW_G		1
#define BMI160_INT1_MAP_HIGH_G		0
#define BMI160_INT2_MAP_HIGH_G		1
#define BMI160_INT1_MAP_ANYMO		0
#define BMI160_INT2_MAP_ANYMO		1
#define BMI160_INT1_MAP_NOMO		0
#define BMI160_INT2_MAP_NOMO		1
#define BMI160_INT1_MAP_DTAP		0
#define BMI160_INT2_MAP_DTAP		1
#define BMI160_INT1_MAP_STAP		0
#define BMI160_INT2_MAP_STAP		1
#define BMI160_INT1_MAP_ORIENT		0
#define BMI160_INT2_MAP_ORIENT		1
#define BMI160_INT1_MAP_FLAT		0
#define BMI160_INT2_MAP_FLAT		1
#define BMI160_INT1_MAP_DRDY		0
#define BMI160_INT2_MAP_DRDY		1
#define BMI160_INT1_MAP_FWM			0
#define BMI160_INT2_MAP_FWM			1
#define BMI160_INT1_MAP_FFULL       0
#define BMI160_INT2_MAP_FFULL       1
#define BMI160_INT1_MAP_PMUTRIG     0
#define BMI160_INT2_MAP_PMUTRIG		1

/*  TAP DURATION */
#define BMI160_TAP_DUR_50MS     0x00
#define BMI160_TAP_DUR_100MS	0x01
#define BMI160_TAP_DUR_150MS    0x02
#define BMI160_TAP_DUR_200MS    0x03
#define BMI160_TAP_DUR_250MS    0x04
#define BMI160_TAP_DUR_375MS    0x05
#define BMI160_TAP_DUR_500MS    0x06
#define BMI160_TAP_DUR_700MS    0x07

/* Interrupt mapping*/
#define	BMI160_MAP_INT1		0
#define	BMI160_MAP_INT2		1

/* step detection selection modes */
#define	BMI160_STEP_NORMAL_MODE			0
#define	BMI160_STEP_SENSITIVE_MODE		1
#define	BMI160_STEP_ROBUST_MODE			2

/*Mag bmm150 register adress*/
#define BMM050_CHIP_ID                     0x40

#define BMM050_DATAX_LSB                   0x42
#define BMM050_DATAX_MSB                   0x43
#define BMM050_DATAY_LSB                   0x44
#define BMM050_DATAY_MSB                   0x45
#define BMM050_DATAZ_LSB                   0x46
#define BMM050_DATAZ_MSB                   0x47
#define BMM050_R_LSB                       0x48
#define BMM050_R_MSB                       0x49



/* Mag trim data definitions*/
#define BMI160_MAG_DIG_X1                      0x5D
#define BMI160_MAG_DIG_Y1                      0x5E
#define BMI160_MAG_DIG_Z4_LSB                  0x62
#define BMI160_MAG_DIG_Z4_MSB                  0x63
#define BMI160_MAG_DIG_X2                      0x64
#define BMI160_MAG_DIG_Y2                      0x65
#define BMI160_MAG_DIG_Z2_LSB                  0x68
#define BMI160_MAG_DIG_Z2_MSB                  0x69
#define BMI160_MAG_DIG_Z1_LSB                  0x6A
#define BMI160_MAG_DIG_Z1_MSB                  0x6B
#define BMI160_MAG_DIG_XYZ1_LSB                0x6C
#define BMI160_MAG_DIG_XYZ1_MSB                0x6D
#define BMI160_MAG_DIG_Z3_LSB                  0x6E
#define BMI160_MAG_DIG_Z3_MSB                  0x6F
#define BMI160_MAG_DIG_XY2                     0x70
#define BMI160_MAG_DIG_XY1                     0x71

/* Mag pre-set mode definitions*/
#define BMI160_MAG_PRESETMODE_LOWPOWER                  1
#define BMI160_MAG_PRESETMODE_REGULAR                   2
#define BMI160_MAG_PRESETMODE_HIGHACCURACY              3
#define BMI160_MAG_PRESETMODE_ENHANCED                  4

/* PRESET MODES - DATA RATES */
#define BMI160_MAG_LOWPOWER_DR                       0x02
#define BMI160_MAG_REGULAR_DR                        0x02
#define BMI160_MAG_HIGHACCURACY_DR                   0x2A
#define BMI160_MAG_ENHANCED_DR                       0x02

/* PRESET MODES - REPETITIONS-XY RATES */
#define BMI160_MAG_LOWPOWER_REPXY                     1
#define BMI160_MAG_REGULAR_REPXY                      9
#define BMI160_MAG_HIGHACCURACY_REPXY                23
#define BMI160_MAG_ENHANCED_REPXY                     7

/* PRESET MODES - REPETITIONS-Z RATES */
#define BMI160_MAG_LOWPOWER_REPZ                      2
#define BMI160_MAG_REGULAR_REPZ                      15
#define BMI160_MAG_HIGHACCURACY_REPZ                 82
#define BMI160_MAG_ENHANCED_REPZ                     26

/* Secondary_Mag power mode selection*/
#define BMI160_MAG_FORCE_MODE		0
#define BMI160_MAG_SUSPEND_MODE		1

/* Mag power mode selection*/
#define	FORCE_MODE		0
#define	SUSPEND_MODE	1
#define	NORMAL_MODE		2
/* step configuration select mode*/
#define	STEP_CONF_NORMAL		0X315
#define	STEP_CONF_SENSITIVE		0X2D
#define	STEP_CONF_ROBUST		0X71D


/* Used for mag overflow check*/
#define BMI160_MAG_OVERFLOW_OUTPUT			((s16)-32768)
#define BMI160_MAG_NEGATIVE_SATURATION_Z   ((s16)-32767)
#define BMI160_MAG_POSITIVE_SATURATION_Z   ((u16)32767)
#define BMI160_MAG_FLIP_OVERFLOW_ADCVAL		((s16)-4096)
#define BMI160_MAG_HALL_OVERFLOW_ADCVAL		((s16)-16384)

/* Loop for check writing MAG data address time*/
#define MAG_DATA_ADD_WRITE     10


 /* BIT SLICE */
#define BMI160_GET_BITSLICE(regvar, bitname)\
		((regvar & bitname##__MSK) >> bitname##__POS)


#define BMI160_SET_BITSLICE(regvar, bitname, val)\
		((regvar & ~bitname##__MSK) | \
		((val<<bitname##__POS)&bitname##__MSK))

/********************* Function Declarations***************************/
/*************************************************************************
 * Description: *//**brief
 *        This function initialises the structure pointer and assigns the
 * I2C address.
 *
 *
 *
 *
 *
 *  \param  bmi160_t *bmi160 structure pointer.
 *
 *
 *
 *  \return communication results.
 *
 *
 **************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_init(struct bmi160_t *bmi160);
/****************************************************************************
 * Description: *//**brief This API gives data to the given register and
 *                          the data is written in the corresponding register
 *  address
 *
 *
 *
 *  \param u8 addr, u8 data, u8 len
 *          addr -> Address of the register
 *          data -> Data to be written to the register
 *          len  -> Length of the Data
 *
 *
 *
 *  \return communication results.
 *
 *
 ***************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 *****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_write_reg(u8 addr,
u8 *data, u8 len);
/*****************************************************************************
 * Description: *//**brief This API reads the data from the given register
 * address
 *
 *
 *
 *
 *  \param u8 addr, u8 *data, u8 len
 *         addr -> Address of the register
 *         data -> address of the variable, read value will be kept
 *         len  -> Length of the data
 *
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_read_reg(u8 addr,
u8 *data, u8 len);
/*****************************************************************************
 *	Description: *//**brief This API used to reads the fatal error
 *	from the Register 0x02 bit 0
 *
 *
 *  \param u8 * fatal_error : Pointer to the value of fatal_error
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_fatal_err(u8
*fatal_error);
/*************************************************************************
 *	Description: *//**brief This API used to read the error code
 *	Register 0x02 bit 1 to 4
 *
 *
 *  \param u8 * error_code : Pointer to the value of error_code
 *	error_code
 *	0x00	no error
 *	0x01	ACC_CONF error (Accelerometer ODR and BWP not compatible)
 *	0x02	GYR_CONF error (Gyroscope ODR and BWP not compatible)
 *	0x03	Under sampling mode and interrupt uses pre filtered data
 *	0x04	reserved
 *	0x05	Selected trigger-readout offset
 *			in MAG_IF greater than selected ODR
 *	0x06	FIFO configuration error for headerless mode
 *	0x07	Under sampling mode and pre filtered data as FIFO source
 *
 *
 *  \return results of communication routine
 *
 *
 **************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 **************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_err_code(u8
*error_code);
/*****************************************************************************
 *	Description: *//**brief This API Reads the i2c error code from the
 *	Register 0x02 bit 5
 *
 *  \param u8 * i2c_error_code : Pointer to the error in I2C-Master detected
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_i2c_fail_err(u8
*i2c_error_code);
 /****************************************************************************
 *	Description: *//**brief This API Reads the dropped command error
 *	from the register 0x02 bit 6
 *
 *
 *  \param u8 * drop_cmd_err : Pointer holding the
 *				dropped command to register CMD error
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_drop_cmd_err(u8
*drop_cmd_err);
 /**************************************************************************
 *	Description: *//**brief This API Reads the magnetometer data ready
 *	interrupt not active from the error register 0x0x2 bit 7
 *
 *
 *
 *
 *  \param u8 * mag_drdy_err : Pointer to holding the value of mag_drdy_err
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_mag_drdy_err(u8
*drop_cmd_err);
 /**************************************************************************
 *	Description: *//**brief This API Reads the error status
 *	from the error register 0x02 bit 0 to 7
 *
 *
 *
 *
 *	\param u8 * mag_drdy_err, *fatal_err, *err_code
 *   *i2c_fail_err, *drop_cmd_err:
 *   Pointer to the value of mag_drdy_err, fatal_err, err_code,
 *   i2c_fail_err, drop_cmd_err
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_error_status(u8 *fatal_err,
u8 *err_code, u8 *i2c_fail_err,
u8 *drop_cmd_err, u8 *mag_drdy_err);
/*****************************************************************************
 *	Description: *//**brief This API reads the magnetometer power mode from
 *	PMU status register 0x03 bit 0 and 1
 *
 *  \param u8 * mag_pmu_status :	pointer holding the power mode status of
 *	magnetometer
 *	mag_pmu_status:
 *	0X00	-	Suspend
 *	0X01	-	Normal
 *	0X10	-	Low power
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 *****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_mag_pmu_status(u8
*mag_pmu_status);
/*****************************************************************************
 *	Description: *//**brief This API reads the gyroscope power mode from
 *	PMU status register 0x03 bit 2 and 3
 *
 *  \param u8 * gyro_pmu_status :	Pointer holding the value of
 *	gyroscope power mode status
 *	gyro_pmu_status:
 *	0X00	- Suspend
 *	0X01	- Normal
 *	0X10	- Reserved
 *	0X11	- Fast start-up
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 *****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_gyro_pmu_status(u8
*gyro_pmu_status);
/*****************************************************************************
 *	Description: *//**brief This API reads the accelerometer power mode from
 *	PMU status register 0x03 bit 4 and 5
 *
 *
 *  \param u8 * accel_pmu_status :	Pointer holding the accelerometer power
 *	mode status
 *	accel_pmu_status
 *	0X00 -	Suspend
 *	0X01 -	Normal
 *	0X10 -	Low power
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 *****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_accel_pmu_status(u8
*accel_pmu_status);
/******************************************************************************
 *	Description: *//**brief This API reads magnetometer data X values
 *	from the register 0x04 and 0x05
 *
 *
 *
 *
 *  \param structure s16 * mag_x : Pointer holding the value of mag_x
 *
 *
 *
 *  \return results of communication routine
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 *****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_read_mag_x(s16 *mag_x);
/*****************************************************************************
 *	Description: *//**brief This API reads magnetometer data Y values
 *	from the register 0x06 and 0x07
 *
 *
 *
 *
 *  \param structure s16 * mag_y : Pointer holding the value of mag_y
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_read_mag_y(
s16 *mag_y);
/*****************************************************************************
 *	Description: *//**brief This API reads magnetometer data Z values
 *	from the register 0x08 and 0x09
 *
 *
 *
 *
 *  \param structure s16 * mag_z : Pointer to the mag_z
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 *****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_read_mag_z(
s16 *mag_z);
/*****************************************************************************
 *	Description: *//**brief This API reads magnetometer data RHALL values
 *	from the register 0x0A and 0x0B
 *
 *
 *
 *
 *  \param structure s16 * mag_r : Pointer holding the value of mag_r
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_read_mag_r(
s16 *mag_r);
/*****************************************************************************
 *	Description: *//**brief This API reads magnetometer data X,Y,Z values
 *	from the register 0x04 to 0x09
 *
 *
 *
 *
 *  \param structure bmi160mag_t * mag : Pointer holding the value of mag xyz
 *
 *
 *  \return results of communication routine *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_read_mag_xyz(
struct bmi160mag_t *mag);
/*******************************************************************************
 *	Description: *//**brief This API reads magnetometer data X,Y,Z,r
 *	values from the register 0x04 to 0x0B
 *
 *
 *
 *
 *  \param structure bmi160mag_t * mag : Pointer holding the value of
 *	mag xyz and r
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_read_mag_xyzr(
struct bmi160mag_t *mag);
/*****************************************************************************
 *	Description: *//**brief This API reads gyro data X values
 *	form the register 0x0C and 0x0D
 *
 *
 *
 *
 *  \param structure s16 * gyro_x : Pointer holding the value of gyro_x
 *
 *
 *
 *  \return results of communication routine
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_read_gyr_x(
s16 *gyro_x);
/*******************************************************************************
 *	Description: *//**brief This API reads gyro data Y values
 *	form the register 0x0E and 0x0F
 *
 *
 *
 *
 *  \param s16 * gyro_y : Pointer holding the value of gyro_y
 *
 *
 *
 *  \return results of communication routine result of communication routines
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_read_gyr_y(
s16 *gyro_y);
/*******************************************************************************
 *	Description: *//**brief This API reads gyro data Z values
 *	form the register 0x10 and 0x11
 *
 *
 *
 *
 *  \param s16 * gyro_z : Pointer holding the value of gyro_z
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_read_gyr_z(
s16 *gyro_z);
/*******************************************************************************
 *	Description: *//**brief This API reads gyro data X,Y,Z values
 *	from the register 0x0C to 0x11
 *
 *
 *
 *
 *  \param struct bmi160mag_t * gyro : Pointer holding the value of gyro - xyz
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_read_gyro_xyz(
struct bmi160gyro_t *gyro);
/*****************************************************************************
 *	Description: *//**brief This API reads accelerometer data X values
 *	form the register 0x12 and 0x13
 *
 *
 *
 *
 *  \param s16 * acc_x : Pointer holding the value of acc_x
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_read_acc_x(
s16 *acc_x);
/******************************************************************************
 *	Description: *//**brief This API reads accelerometer data Y values
 *	form the register 0x14 and 0x15
 *
 *
 *
 *
 *  \param s16 * acc_y : Pointer holding the value of acc_y
 *
 *
 *
 *  \return results of communication routine
 *
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 *****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_read_acc_y(
s16 *acc_y);
/*****************************************************************************
 *	Description: *//**brief This API reads accelerometer data Z values
 *	form the register 0x16 and 0x17
 *
 *
 *
 *
 *  \param s16 * acc_z : Pointer holding the value of acc_z
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_read_acc_z(
s16 *acc_z);
/*****************************************************************************
 *	Description: *//**brief This API reads accelerometer data X,Y,Z values
 *	from the register 0x12 to 0x17
 *
 *
 *
 *
 *  \param bmi160acc_t * acc : Pointer holding the value of acc-xyz
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_read_acc_xyz(
struct bmi160acc_t *acc);
/******************************************************************************
 *	Description: *//**brief This API reads sensor_time from the register
 *	0x18 to 0x1A
 *
 *
 *  \param u32 * sensor_time : Pointer holding the value of sensor_time
 *
 *
 *
 *  \return results of communication routine
 *
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 *****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_sensor_time(
u32 *sensor_time);
/*****************************************************************************
 *	Description: *//**brief This API reads the Gyroscope self test
 *	status from the register 0x1B bit 1
 *
 *
 *  \param u8 * gyr_self_test_ok : Pointer holding the value of gyro self test
 *	gyr_self_test_ok ->
 *	0 -	Gyroscope self test is running or failed
 *	1 -	Gyroscope self test completed successfully
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_gyr_self_test(u8
*gyr_self_test_ok);
 /*****************************************************************************
 *	Description: *//**brief This API reads the status of
 *	mag manual interface operation form the register 0x1B bit 2
 *
 *
 *
 *  \param u8 * mag_man_op : Pointer holding the value of mag_man_op
 *	mag_man_op ->
 *	1 ->	Indicates manual magnetometer interface operation is ongoing
 *	0 ->	Indicates no manual magnetometer interface operation is ongoing
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_mag_man_op(u8
*mag_man_op);
/*****************************************************************************
 *	Description: *//**brief This API reads the fast offset compensation
 *	status form the register 0x1B bit 3
 *
 *
 *  \param u8 * foc_rdy : Pointer holding the value of foc_rdy
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_foc_rdy(u8
*foc_rdy);
 /*****************************************************************************
 * Description: *//**brief This APIrReads the nvm_rdy status from the
 *	resister 0x1B bit 4
 *
 *
 *  \param u8 * nvm_rdy : Pointer holding the value of nvm_rdy
 *	nvm_rdy ->
 *	0 ->	NVM write operation in progress
 *	1 ->	NVM is ready to accept a new write trigger
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_nvm_rdy(u8
*nvm_rdy);
/*****************************************************************************
 *	Description: *//**brief This API reads the status of drdy_mag
 *	from the register 0x1B bit 5
 *	The status get reset when one magneto DATA register is read out
 *
 *  \param u8 * drdy_mag : Pointer holding the value of drdy_mag
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_drdy_mag(u8
*drdy_mag);
/*****************************************************************************
 *	Description: *//**brief This API reads the status of drdy_gyr form the
 *	register 0x1B bit 6
 *	The status get reset when Gyroscope DATA register read out
 *
 *
 *	\param u8 * drdy_gyr : Pointer holding the value of drdy_gyr
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_drdy_gyr(u8
*drdy_gyr);
 /*****************************************************************************
 *	Description: *//**brief This API reads the status of drdy_acc form the
 *	register 0x1B bit 7
 *	The status get reset when Accel DATA register read out
 *
 *
 *	\param u8 * drdy_acc :	Pointer holding the value of drdy_acc
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_drdy_acc(u8
*drdy_acc);
 /*****************************************************************************
 *	Description: *//**brief This API reads the step interrupt status
 *	from the register 0x1C bit 0
 *	flag is associated with a specific interrupt function.
 *	It is set when the  data ready  interrupt triggers. The
 *	setting of INT_LATCH controls if
 *	the interrupt signal and hence the
 *	respective interrupt flag will be
 *	permanently latched, temporarily latched
 *	or not latched.
 *
 *
 *
 *
 *
 *  \param u8 * step_int : Pointer holding the status of step interrupt
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_status0_step_int(u8
*step_int);
/*****************************************************************************
 *	Description: *//**brief This API reads the
 *	significant motion interrupt status
 *	from the register 0x1C bit 1
 *	flag is associated with a specific interrupt function.
 *	It is set when the  data ready  interrupt triggers. The
 *	setting of INT_LATCH controls if
 *	the interrupt signal and hence the
 *	respective interrupt flag will be
 *	permanently latched, temporarily latched
 *	or not latched.
 *
 *
 *
 *
 *
 *  \param u8 * sigmot_int  : Pointer holding the status of step interrupt
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_status0_significant_int(u8
*sigmot_int);
 /*****************************************************************************
 *	Description: *//**brief This API reads the anym_int status
 *	from the register 0x1C bit 2
 *	flag is associated with a specific interrupt function.
 *	It is set when the  data ready  interrupt triggers. The
 *	setting of INT_LATCH controls if
 *	the interrupt signal and hence the
 *	respective interrupt flag will be
 *	permanently latched, temporarily latched
 *	or not latched.
 *
 *
 *
 *
 *  \param u8 * anym_int : Pointer holding the status of any-motion interrupt
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_status0_anym_int(u8
*anym_int);
/*****************************************************************************
 *	Description: *//**brief This API reads the pmu_trigger_int status
 *	from the register 0x1C bit 3
 *	flag is associated with a specific interrupt function.
 *	It is set when the  data ready  interrupt triggers. The
 *	setting of INT_LATCH controls if
 *	the interrupt signal and hence the
 *	respective interrupt flag will be
 *	permanently latched, temporarily latched
 *	or not latched.
 *
 *
 *
 *
 *
 *  \param u8 * pmu_trigger_int : Pointer holding the status of
 *					pmu_trigger_int interrupt
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_status0_pmu_trigger_int(u8
*pmu_trigger_int);
/*****************************************************************************
 *	Description: *//**brief This API reads the double tab status
 *	from the register 0x1C bit 4
 *	flag is associated with a specific interrupt function.
 *	It is set when the  data ready  interrupt triggers. The
 *	setting of INT_LATCH controls if
 *	the interrupt signal and hence the
 *	respective interrupt flag will be
 *	permanently latched, temporarily latched
 *	or not latched.
 *
 *
 *
 *
 *
 *  \param u8 * d_tap_int : Pointer holding the status of d_tap_int
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_status0_d_tap_int(u8
*d_tap_int);
/*****************************************************************************
 *	Description: *//**brief This API reads the single tab status
 *	from the register 0x1C bit 5
 *	flag is associated with a specific interrupt function.
 *	It is set when the  data ready  interrupt triggers. The
 *	setting of INT_LATCH controls if
 *	the interrupt signal and hence the
 *	respective interrupt flag will be
 *	permanently latched, temporarily latched
 *	or not latched.
 *
 *
 *
 *
 *
 *  \param u8 * s_tap_int : Pointer holding the status of s_tap_int
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_status0_s_tap_int(u8
*s_tap_int);
/*****************************************************************************
 *	Description: *//**brief This API reads the orient status
 *	from the register 0x1C bit 6
 *	flag is associated with a specific interrupt function.
 *	It is set when the  data ready  interrupt triggers. The
 *	setting of INT_LATCH controls if
 *	the interrupt signal and hence the
 *	respective interrupt flag will be
 *	permanently latched, temporarily latched
 *	or not latched.
 *
 *
 *
 *
 *
 *  \param u8 * orient_int :  Pointer holding the status of orient_int
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_status0_orient_int(u8
*orient_int);
/*****************************************************************************
 *	Description: *//**brief This API reads the flat interrupt status
 *	from the register 0x1C bit 7
 *	flag is associated with a specific interrupt function.
 *	It is set when the  data ready  interrupt triggers. The
 *	setting of INT_LATCH controls if
 *	the interrupt signal and hence the
 *	respective interrupt flag will be
 *	permanently latched, temporarily latched
 *	or not latched.
 *
 *
 *
 *
 *  \param u8 * flat_int : Pointer holding the status of flat_int
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_status0_flat_int(u8
*flat_int);
/*****************************************************************************
 *	Description: *//**brief This API reads the high g interrupt status
 *	from the register 0x1D bit 2
 *	flag is associated with a specific interrupt function.
 *	It is set when the  data ready  interrupt triggers. The
 *	setting of INT_LATCH controls if
 *	the interrupt signal and hence the
 *	respective interrupt flag will be
 *	permanently latched, temporarily latched
 *	or not latched.
 *
 *
 *
 *
 *
 *  \param u8 * highg_int : Pointer holding the status of highg_int
 *
 *
 *
 *  \return results of communication routine
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_status1_highg_int(u8
*highg_int);
/*****************************************************************************
 *	Description: *//**brief This API reads the low g interrupt status
 *	from the register 0x1D bit 3
 *	flag is associated with a specific interrupt function.
 *	It is set when the  data ready  interrupt triggers. The
 *	setting of INT_LATCH controls if
 *	the interrupt signal and hence the
 *	respective interrupt flag will be
 *	permanently latched, temporarily latched
 *	or not latched.
 *
 *
 *
 *
 *
 *  \param u8 * lowg_int : Pointer holding the status of lowg_int
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_status1_lowg_int(u8
*lowg_int);
/*****************************************************************************
 *	Description: *//**brief This API reads data
 *	ready low g interrupt status
 *	from the register 0x1D bit 4
 *	flag is associated with a specific interrupt function.
 *	It is set when the  data ready  interrupt triggers. The
 *	setting of INT_LATCH controls if
 *	the interrupt signal and hence the
 *	respective interrupt flag will be
 *	permanently latched, temporarily latched
 *	or not latched.
 *
 *
 *
 *
 *  \param u8 * drdy_int : Pointer holding the status of drdy_int
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_status1_drdy_int(u8
*drdy_int);
/*****************************************************************************
 *	Description: *//**brief This API reads data ready
 *	FIFO full interrupt status
 *	from the register 0x1D bit 5
 *	flag is associated with a specific interrupt function.
 *	It is set when the FIFO full interrupt triggers. The
 *	setting of INT_LATCH controls if the interrupt signal and hence the
 *	respective interrupt flag will be permanently
 *	latched, temporarily latched
 *	or not latched.
 *
 *
 *
 *
 *  \param u8 * ffull_int : Pointer holding the status of ffull_int
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_status1_ffull_int(u8
*ffull_int);
/*****************************************************************************
 *	Description: *//**brief This API reads data
 *	ready FIFO watermark interrupt status
 *	from the register 0x1D bit 6
 *	flag is associated with a specific interrupt function.
 *	It is set when the FIFO watermark interrupt triggers. The
 *	setting of INT_LATCH controls if the interrupt signal and hence the
 *	respective interrupt flag will be
 *	permanently latched, temporarily latched
 *	or not latched.
 *
 *
 *
 *
 *  \param u8 * fwm_int : Pointer holding the status of fwm_int
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_status1_fwm_int(u8
*fwm_int);
/*****************************************************************************
 *	Description: *//**brief This API reads data ready no motion interrupt status
 *	from the register 0x1D bit 7
 *	flag is associated with a specific interrupt function.
 *	It is set when the no motion  interrupt triggers. The
 *	setting of INT_LATCH controls if the interrupt signal and hence the
 *	respective interrupt flag will be permanently
 *	latched, temporarily latched
 *	or not latched.
 *
 *
 *
 *
 *  \param u8 * nomo_int : Pointer holding the status of nomo_int
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_status1_nomo_int(u8
*nomo_int);
/*****************************************************************************
 *	Description: *//**brief This API reads the status of anym_first_x
 *	from the register 0x1E bit 0
 *
 *
 *
 *
 *  \param u8 * anym_first_x : pointer holding the status of anym_first_x
 *	anym_first_x ->
 *	0	-	not triggered
 *	1	-	triggered by x axis
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_status2_anym_first_x(u8
*anym_first_x);
/*****************************************************************************
 *	Description: *//**brief This API reads the status of anym_first_y
 *	from the register 0x1E bit 1
 *
 *
 *
 *
 *  \param u8 * anym_first_y : pointer holding the status of anym_first_y
 *	anym_first_y ->
 *	0	-	not triggered
 *	1	-	triggered by y axis
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_status2_anym_first_y(u8
*anym_first_y);
 /*****************************************************************************
 *	Description: *//**brief This API reads the status of anym_first_z
 *	from the register 0x1E bit 2
 *
 *
 *
 *
 *  \param u8 * anym_first_z : pointer holding the status of anym_first_z
 *	anym_first_z ->
 *	0	-	not triggered
 *	1	-	triggered by z axis
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_status2_anym_first_z(u8
*anym_first_z);
 /*****************************************************************************
 *	Description: *//**brief This API reads the anym_sign status from the
 *	register 0x1E bit 3
 *
 *
 *
 *
 *  \param u8 * anym_sign : Pointer holding the status of anym_sign
 *	anym_sign ->
 *	0	-	positive
 *	1	-	negative
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_status2_anym_sign(u8
*anym_sign);
/*****************************************************************************
 *	Description: *//**brief This API reads the tap_first_x status from the
 *	register 0x1E bit 4
 *
 *
 *
 *
 *  \param u8 * tap_first_x : Pointer holding the status of tap_first_x
 *	tap_first_x ->
 *	0	-	not triggered
 *	1	-	triggered by x axis
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_status2_anym_tap_first_x(u8
*tap_first_x);
/*****************************************************************************
 *	Description: *//**brief This API reads the tap_first_y status from the
 *	register 0x1E bit 5
 *
 *
 *
 *
 *  \param u8 * tap_first_y : Pointer holding the status of tap_first_x
 *	tap_first_y ->
 *	0	-	not triggered
 *	1	-	triggered by y axis
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_status2_anym_tap_first_y(u8
*tap_first_y);
/*****************************************************************************
 *	Description: *//**brief This API reads the tap_first_z status from the
 *	register 0x1E bit 6
 *
 *
 *
 *
 *  \param u8 * tap_first_z : Pointer holding the status of tap_first_x
 *	tap_first_z ->
 *	0	-	not triggered
 *	1	-	triggered by z axis
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_status2_anym_tap_first_z(u8
*tap_first_z);

/*****************************************************************************
 *	Description: *//**brief This API reads the tap_sign status from the
 *	register 0x1E bit 7
 *
 *
 *
 *
 *  \param u8 * tap_sign : Pointer holding the status of tap_sign
 *	tap_sign ->
 *	0	-	positive
 *	1	-	negative
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_status2_tap_sign(u8
*tap_sign);
/*****************************************************************************
 *	Description: *//**brief This API reads the high_first_x status from the
 *	register 0x1F bit 0
 *
 *
 *
 *
 *  \param u8 * high_first_x : Pointer holding the status of high_first_x
 *	high_first_x ->
 *	0	-	not triggered
 *	1	-	triggered by x axis
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_status3_high_first_x(u8
*high_first_x);
/*****************************************************************************
 *	Description: *//**brief This API reads the high_first_y status from the
 *	register 0x1F bit 1
 *
 *
 *
 *
 *  \param u8 * high_first_y : Pointer holding the status of high_first_y
 *	high_first_y ->
 *	0	-	not triggered
 *	1	-	triggered by y axis
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_status3_high_first_y(u8
*high_first_y);
/*****************************************************************************
 *	Description: *//**brief This API reads the high_first_z status from the
 *	register 0x1F bit 3
 *
 *
 *
 *
 *  \param u8 * high_first_z : Pointer holding the status of high_first_z
 *	high_first_z ->
 *	0	-	not triggered
 *	1	-	triggered by z axis
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_status3_high_first_z(u8
*high_first_z);
/*****************************************************************************
 *	Description: *//**brief This API reads the high_sign status from the
 *	register 0x1F bit 3
 *
 *
 *
 *
 *  \param u8 * high_sign : Pointer holding the status of high_sign
 *	high_sign ->
 *	0	-	positive
 *	1	-	negative
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_status3_high_sign(u8
*high_sign);
/*****************************************************************************
 *	Description: *//**brief This API reads the status of orient_x_y plane
 *	from the register 0x1F bit 4 and 5
 *
 *
 *  \param u8 * orient_x_y : Pointer holding the status of orient_x_y
 *	orient_x_y ->
 *	00	-	portrait upright
 *	01	-	portrait upside down
 *	10	-	landscape left
 *	11	-	landscape right
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_status3_orient_x_y(u8
*orient_x_y);
/*****************************************************************************
 *	Description: *//**brief This API reads the status of orient_z plane
 *	from the register 0x1F bit 6
 *
 *
 *  \param u8 * orient_z : Pointer holding the status of orient_z
 *	orient_z ->
 *	0	-	upward looking
 *	1	-	downward looking
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_status3_orient_z(u8
*orient_z);
/*****************************************************************************
 *	Description: *//**brief This API reads the flat status from the register
 *	0x1F bit 7
 *
 *
 *  \param u8 * flat : Pointer holding the status of flat
 *	flat ->
 *	0	-	non flat
 *	1	-	flat position
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_status3_flat(u8
*flat);
/*****************************************************************************
 *	Description: *//**brief This API reads the temperature of the sensor
 *	from the register 0x21 bit 0 to 7
 *
 *
 *
 *  \param u8 * temperature : Pointer holding the value of temperature
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_temperature(s16
*temperature);
/*****************************************************************************
 *	Description: *//**brief This API reads the  of the sensor
 *	form the register 0x23 and 0x24 bit 0 to 7 and 0 to 2
 *
 *
 *  \param u8 * Fifo_length :  Pointer holding the Fifo_length
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_fifo_length(
u32 *fifo_length);
 /*****************************************************************************
 *	Description: *//**brief This API reads the fifodata of the sensor
 *	from the register 0x24
 *
 *
 *
 *  \param u8 * fifodata : Pointer holding the fifodata
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_fifo_data(
u8 *fifo_data);
/*************************************************************************
 *	Description: *//**brief This API is used to get the
 *	accel output date rate form the register 0x40 bit 0 to 3
 *
 *
 *  \param  u8 * BW : pointer holding the value of accel output date rate
 *	0	-	BMI160_ACCEL_ODR_RESERVED
 *	1	-	BMI160_ACCEL_ODR_0_78HZ
 *	2	-	BMI160_ACCEL_ODR_1_56HZ
 *	3	-	BMI160_ACCEL_ODR_3_12HZ
 *	4	-	BMI160_ACCEL_ODR_6_25HZ
 *	5	-	BMI160_ACCEL_ODR_12_5HZ
 *	6	-	BMI160_ACCEL_ODR_25HZ
 *	7	-	BMI160_ACCEL_ODR_50HZ
 *	8	-	BMI160_ACCEL_ODR_100HZ
 *	9	-	BMI160_ACCEL_ODR_200HZ
 *	10	-	BMI160_ACCEL_ODR_400HZ
 *	11	-	BMI160_ACCEL_ODR_800HZ
 *	12	-	BMI160_ACCEL_ODR_1600HZ
 *
 *
 *  \return results of communication routine
 *
 *
 ***********************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_acc_outputdatarate(u8 *odr);
 /****************************************************************************
 *	Description: *//**brief This API is used to set the
 *	accel output date rate form the register 0x40 bit 0 to 3
 *
 *
 *
 *
 *  \param u8 BW : The value of accel output date rate
 *
 *	0	-	BMI160_ACCEL_ODR_RESERVED
 *	1	-	BMI160_ACCEL_ODR_0_78HZ
 *	2	-	BMI160_ACCEL_ODR_1_56HZ
 *	3	-	BMI160_ACCEL_ODR_3_12HZ
 *	4	-	BMI160_ACCEL_ODR_6_25HZ
 *	5	-	BMI160_ACCEL_ODR_12_5HZ
 *	6	-	BMI160_ACCEL_ODR_25HZ
 *	7	-	BMI160_ACCEL_ODR_50HZ
 *	8	-	BMI160_ACCEL_ODR_100HZ
 *	9	-	BMI160_ACCEL_ODR_200HZ
 *	10	-	BMI160_ACCEL_ODR_400HZ
 *	11	-	BMI160_ACCEL_ODR_800HZ
 *	12	-	BMI160_ACCEL_ODR_1600HZ
 *
 *
 *
 *  \return results of communication routine communication results
 *
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_acc_outputdatarate(u8 odr);
/***********************************************************************
 *	Description: *//**brief This API is used to get the
 *	accel bandwidth from the register 0x40 bit 4 to 6
 *
 *
 *
 *
 *  \param  u8 * bwp : Pointer holding the value of accel bandwidth
 *	0b000 acc_us = 0 -> OSR4 mode; acc_us = 1 -> no averaging
 *	0b001 acc_us = 0 -> OSR2 mode; acc_us = 1 -> average 2 samples
 *	0b010 acc_us = 0 -> normal mode; acc_us = 1 -> average 4 samples
 *	0b011 acc_us = 0 -> CIC mode; acc_us = 1 -> average 8 samples
 *	0b100 acc_us = 0 -> Reserved; acc_us = 1 -> average 16 samples
 *	0b101 acc_us = 0 -> Reserved; acc_us = 1 -> average 32 samples
 *	0b110 acc_us = 0 -> Reserved; acc_us = 1 -> average 64 samples
 *	0b111 acc_us = 0 -> Reserved; acc_us = 1 -> average 128 samples
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ***********************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_acc_bandwidth(u8 *bwp);
/*******************************************************************************
 *	Description: *//**brief This API is used to set the
 *	accel bandwidth from the register 0x40 bit 4 to 6
 *
 *
 *
 *
 *  \param u8 BW : the value of accel bandwidth
 *	Value Description
 *	0b000 acc_us = 0 -> OSR4 mode; acc_us = 1 -> no averaging
 *	0b001 acc_us = 0 -> OSR2 mode; acc_us = 1 -> average 2 samples
 *	0b010 acc_us = 0 -> normal mode; acc_us = 1 -> average 4 samples
 *	0b011 acc_us = 0 -> CIC mode; acc_us = 1 -> average 8 samples
 *	0b100 acc_us = 0 -> Reserved; acc_us = 1 -> average 16 samples
 *	0b101 acc_us = 0 -> Reserved; acc_us = 1 -> average 32 samples
 *	0b110 acc_us = 0 -> Reserved; acc_us = 1 -> average 64 samples
 *	0b111 acc_us = 0 -> Reserved; acc_us = 1 -> average 128 samples
 *
 *
 *
 *
 *
 *  \return results of communication routine communication results
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_acc_bandwidth(u8 bwp);
/*************************************************************************
 *	Description: *//**brief This API is used to get the accel
 *	under sampling parameter form the register 0x40 bit 7
 *
 *
 *
 *
 *	\param  u8 * accel_undersampling_parameter : pointer holding the
 *						value of accel under sampling
 *
 *	0	-	enable
 *	1	-	disable
 *
 *
 *  \return results of communication routine
 *
 *
 ***********************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_accel_undersampling_parameter(
u8 *accel_undersampling_parameter);
 /*************************************************************************
 *	Description: *//**brief This API is used to set the accel
 *	under sampling parameter form the register 0x40 bit 7
 *
 *
 *
 *	\param accel_undersampling_parameter : the value of accel under sampling
 *	0	-	enable
 *	1	-	disable
 *
 *
 *  \return results of communication routine
 *
 *
 ***********************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_accel_undersampling_parameter(
u8 accel_undersampling_parameter);
/*************************************************************************
 *	Description: *//**brief This API is used to get the ranges
 *	(g values) of the accel from the register 0x41 bit 0 to 3
 *
 *
 *
 *
 *  \param u8 * Range : Pointer holding the accel range
 *	3 -> BMI160_ACCEL_RANGE_2G
 *	5 -> BMI160_ACCEL_RANGE_4G
 *	8 -> BMI160_ACCEL_RANGE_8G
 *	12 -> BMI160_ACCEL_RANGE_16G
 *
 *
 *
 *  \return results of communication routine
 *
 *
 **************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_acc_range(
u8 *range);
 /**********************************************************************
 *	Description: *//**brief This API is used to set the range
 *	(g values) of the accel from the register 0x41 bit 0 to 3
 *
 *
 *
 *
 *  \param u8 * Range : The value of accel range
 *	3 -> BMI160_ACCEL_RANGE_2G
 *	5 -> BMI160_ACCEL_RANGE_4G
 *	8 -> BMI160_ACCEL_RANGE_8G
 *	12 -> BMI160_ACCEL_RANGE_16G
 *
 *  \return results of communication routine
 *
 *
 **********************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_acc_range(
u8 range);
/**************************************************************************
 *	Description: *//**brief This API is used to get the
 *	gyroscope output data rate from the register 0x42 bit 0 to 3
 *
 *
 *
 *
 *  \param  u8 * gyro_ODR : Pointer holding the value of output data rate
 *	gyro_ODR	->
 *	0b0000 - BMI160_GYRO_ODR_RESERVED
 *	0b0001 - BMI160_GYRO_ODR_RESERVED
 *	0b0010 - BMI160_GYRO_ODR_RESERVED
 *	0b0011 - BMI160_GYRO_ODR_RESERVED
 *	0b0100 - BMI160_GYRO_ODR_RESERVED
 *	0b0101 - BMI160_GYRO_ODR_RESERVED
 *	0b0110 - BMI160_GYOR_ODR_25HZ
 *	0b0111 - BMI160_GYOR_ODR_50HZ
 *	0b1000 - BMI160_GYOR_ODR_100HZ
 *	0b1001 - BMI160_GYOR_ODR_200HZ
 *	0b1010 - BMI160_GYOR_ODR_400HZ
 *	0b1011 - BMI160_GYOR_ODR_800HZ
 *	0b1100 - BMI160_GYOR_ODR_1600HZ
 *	0b1101 - BMI160_GYOR_ODR_3200HZ
 *	0b1110 - BMI160_GYRO_ODR_RESERVED
 *	0b1111 - BMI160_GYRO_ODR_RESERVED
 *
 *  \return results of communication routine
 *
 *
 **************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_gyro_outputdatarate(
u8 *gyro_odr);
/************************************************************************
 * Description: *//**brief This API is used to set the
 *	gyroscope output data rate from the register 0x42 bit 0 to 3
 *
 *
 *
 *  \param  u8 gyro_ODR : The value of gyro output data rate
 *
 *	0b0000 - BMI160_GYRO_ODR_RESERVED
 *	0b0001 - BMI160_GYRO_ODR_RESERVED
 *	0b0010 - BMI160_GYRO_ODR_RESERVED
 *	0b0011 - BMI160_GYRO_ODR_RESERVED
 *	0b0100 - BMI160_GYRO_ODR_RESERVED
 *	0b0101 - BMI160_GYRO_ODR_RESERVED
 *	0b0110 - BMI160_GYOR_ODR_25HZ
 *	0b0111 - BMI160_GYOR_ODR_50HZ
 *	0b1000 - BMI160_GYOR_ODR_100HZ
 *	0b1001 - BMI160_GYOR_ODR_200HZ
 *	0b1010 - BMI160_GYOR_ODR_400HZ
 *	0b1011 - BMI160_GYOR_ODR_800HZ
 *	0b1100 - BMI160_GYOR_ODR_1600HZ
 *	0b1101 - BMI160_GYOR_ODR_3200HZ
 *	0b1110 - BMI160_GYRO_ODR_RESERVED
 *	0b1111 - BMI160_GYRO_ODR_RESERVED
 *
 *
 *
 *  \return results of communication routine
 *
 *
 *************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***********************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_gyro_outputdatarate(
u8 gyro_odr);
/***********************************************************************
 *	Description: *//**brief This API is used to get the
 *	bandwidth of gyro from the register 0x42 bit 4 to 5
 *
 *
 *
 *
 *  \param  u8 * bwp : Pointer holding the value of gyro bandwidth
 *
 *	Value	Description
 *	00 -	BMI160_GYRO_OSR4_MODE
 *	01 -	BMI160_GYRO_OSR2_MODE
 *	10 -	BMI160_GYRO_NORMAL_MODE
 *	11 -	BMI160_GYRO_CIC_MODE
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ***********************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_gyro_bandwidth(u8 *bwp);
/**************************************************************************
 * Description: *//**brief This API is used to set the
 *	bandwidth of gyro from the register 0x42 bit 4 to 5
 *
 *
 *
 *
 *  \param  u8 bwp : the value of gyro bandwidth
 *
 *	Value Description
 *	00 -	BMI160_GYRO_OSR4_MODE
 *	01 -	BMI160_GYRO_OSR2_MODE
 *	10 -	BMI160_GYRO_NORMAL_MODE
 *	11 -	BMI160_GYRO_CIC_MODE
 *
 *
 *
 *
 *  \return results of communication routine communication results
 *
 *
 **************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_gyro_bandwidth(u8 bwp);
/*****************************************************************************
 *	Description: *//**brief This API reads the range from
 *	of gyro from the register 0x43 bit 0 to 2
 *
 *  \param u8 *range : Pointer holding the value of gyro range
 *	Range[0....7]
 *	0 - 2000/s
 *	1 - 1000/s
 *	2 - 500/s
 *	3 - 250/s
 *	4 - 125/s
 *
 *
 *  \return results of communication routine
 *
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_gyr_range(
u8 *range);
/****************************************************************************
 * Description: *//**brief This API sets the range from
 *	of gyro from the register 0x43 bit 0 to 2
 *
 *  \param u8 range : The value of gyro range
 *	Range[0....7]
 *	0 - 2000/s
 *	1 - 1000/s
 *	2 - 500/s
 *	3 - 250/s
 *	4 - 125/s
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_gyr_range(
u8 range);
/***************************************************************************
 *	Description: *//**brief This API is used to get the
 *	output data rate of magnetometer from the register 0x44 bit 0 to 3
 *
 *
 *
 *
 *  \param  u8 * odr : The pointer holding the value of mag bandwidth
 *                       0 -> Reserved
 *                       1 -> 0.78HZ
 *                       2 -> 1.56HZ
 *                       3 -> 3.12HZ
 *                       4 -> 6.25HZ
 *                       5 -> 12.5HZ
 *                       6 -> 25HZ
 *                       7 -> 50HZ
 *                       8 -> 100HZ
 *                       9 -> 200HZ
 *                       10 -> 400HZ
  *                      11->    800Hz
 *                       12->    1600hz
 *                       13->    Reserved
 *                       14->    Reserved
 *                       15->    Reserved
 *
 *
 *  \return results of communication routine
 *
 *
 **************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_mag_outputdatarate(u8 *odr);
/*******************************************************************************
 *	Description: *//**brief This API is used to set the value of mag bandwidth
 *	from the register 0x44 bit 0 to 3
 *
 *
 *
 *
 *  \param u8 odr : The value of mag bandwidth
 *                       0 -> Reserved
 *                       1 -> 0.78HZ
 *                       2 -> 1.56HZ
 *                       3 -> 3.12HZ
 *                       4 -> 6.25HZ
 *                       5 -> 12.5HZ
 *                       6 -> 25HZ
 *                       7 -> 50HZ
 *                       8 -> 100HZ
 *                       9 -> 200HZ
 *                       10-> 400HZ
  *                      11-> 800Hz
 *                       12-> 1600hz
 *                       13-> Reserved
 *                       14-> Reserved
 *                       15-> Reserved
 *
 *
 *
 *
 *  \return results of communication routine communication results
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_mag_outputdatarate(u8 odr);
/*******************************************************************************
 *	Description: *//**brief This API is used to read Down sampling
 *	for gyro (2**downs_gyro) in the register 0x45 bit 0 to 2
 *
 *
 *
 *
 *  \param u8 * fifo_downs_gyro :Pointer to the fifo_downs_gyro
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_fifo_downs_gyro(
u8 *fifo_downs_gyro);
/*******************************************************************************
 *	Description: *//**brief This API is used to set Down sampling
 *	for gyro (2**downs_gyro) from the register 0x45 bit 0 to 5
 *
 *
 *
 *
 *  \param u8 fifo_downs_gyro : Value of the fifo_downs_gyro
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_fifo_downs_gyro(
u8 fifo_downs_gyro);
/*******************************************************************************
 *	Description: *//**brief This API is used to read gyr_fifo_filt_data
 *	from the register 0x45 bit 3
 *
 *
 *
 *  \param u8 * gyr_fifo_filt_data :Pointer to the gyr_fifo_filt_data
 *	gyr_fifo_filt_data ->
 *	0	-	Unfiltered data
 *	1	-	Filtered data
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_gyr_fifo_filt_data(
u8 *gyr_fifo_filt_data);
/*******************************************************************************
 *	Description: *//**brief This API is used to write filtered or unfiltered
 *	from the register 0x45 bit 3
 *
 *
 *
 *  \param u8 gyr_fifo_filt_data : The value ofS gyr_fifo_filt_data
 *	gyr_fifo_filt_data ->
 *	0	-	Unfiltered data
 *	1	-	Filtered data
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_gyr_fifo_filt_data(
u8 gyr_fifo_filt_data);
/*****************************************************************************
 *	Description: *//**brief This API is used to read Down sampling
 *	for accel (2**downs_accel) from the register 0x45 bit 4 to 6
 *
 *
 *
 *
 *  \param u8 * fifo_downs_acc :Pointer to the fifo_downs_acc
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_fifo_downs_acc(
u8 *fifo_downs_acc);
/*******************************************************************************
 *	Description: *//**brief This API is used to write Downsampling
 *	for accel (2**downs_accel) from the register 0x45 bit 4 to 6
 *
 *
 *
 *
 *  \param u8 fifo_downs_acc : Value of the fifo_downs_acc
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_fifo_downs_acc(
u8 fifo_downs_acc);
/*******************************************************************************
 *	Description: *//**brief This API is used to read accel_fifo_filt_data
 *	from the register 0x45 bit 7
 *
 *
 *
 *  \param u8 * accel_fifo_filt_data :Pointer to the accel_fifo_filt_data
 *	accel_fifo_filt_data ->
 *	0	-	Unfiltered data
 *	1	-	Filtered data
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_accel_fifo_filt_data(
u8 *accel_fifo_filt_data);
/*******************************************************************************
 *	Description: *//**brief  API is used to write filtered or unfiltered
 *	from the register 0x45 bit 7
 *
 *
 *
 *  \param u8 accel_fifo_filt_data : The value of accel_fifo_filt_data
 *	accel_fifo_filt_data ->
 *	0	-	Unfiltered data
 *	1	-	Filtered data
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_accel_fifo_filt_data(
u8 accel_fifo_filt_data);
/*******************************************************************************
 *	Description: *//**brief This API is used to Trigger an interrupt
 *	when FIFO contains fifo_water_mark from the register 0x46 bit 0 to 7
 *
 *
 *
 *  \param u8 fifo_watermark : Pointer to fifo_watermark
 *
 *
 *
 *  \return results of communication
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_fifo_watermark(
u8 *fifo_watermark);
/*******************************************************************************
 *	Description: *//**brief This API is used to Trigger an interrupt
 *	when FIFO contains fifo_water_mark*4 bytes form the resister 0x46
 *
 *
 *
 *
 *  \param u8 fifo_watermark : Value of the fifo_watermark
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_fifo_watermark(
u8 fifo_watermark);
/****************************************************************************
 * Description: *//**brief This API Reads the fifo_stop_on_full in
 * FIFO_CONFIG_1
 * Stop writing samples into FIFO when FIFO is full
 * from the register 0x47 bit 0
 *
 *
 *
 *  \param u8 * fifo_stop_on_full :Pointer to the fifo_stop_on_full
 *	fifo_stop_on_full ->
 *	0	-	do not stop writing to FIFO when full
 *	1	-	Stop writing into FIFO when full
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_fifo_stop_on_full(
u8 *fifo_stop_on_full);
/*******************************************************************************
 * Description: *//**brief  This API writes the fifo_stop_on_full in
 * FIFO_CONFIG_1
 * Stop writing samples into FIFO when FIFO is full
 * from the register 0x47 bit 0
 *
 *  \param u8 fifo_stop_on_full : Value of the fifo_stop_on_full
 *	fifo_stop_on_full
 *  0	-	 do not stop writing to FIFO when full
 *  1	-	 Stop writing into FIFO when full.
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_fifo_stop_on_full(
u8 fifo_stop_on_full);
/******************************************************************************
 *	Description: *//**brief This API Reads fifo sensor time
 *	frame after the last valid data frame form the register  0x47 bit 1
 *
 *
 *
 *
 *  \param u8 * fifo_time_en :Pointer to the fifo_time_en
 *	fifo_time_en
 *	0	-  do not return sensortime frame
 *	1	-  return sensortime frame
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_fifo_time_en(
u8 *fifo_time_en);
/*****************************************************************************
 *	Description: *//**brief This API writes sensortime
 *	frame after the last valid data frame form the register  0x47 bit 1
 *
 *
 *
 *
 *  \param u8 fifo_time_en : The value of fifo_time_en
 *	fifo_time_en
 *	0	-  do not return sensortime frame
 *	1	-  return sensortime frame
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_fifo_time_en(
u8 fifo_time_en);
/*****************************************************************************
 *	Description: *//**brief This API Reads FIFO interrupt 2
 *	tag enable from the resister 0x47 bit 2
 *
 *  \param u8 * fifo_tag_int2_en :
 *                 Pointer to the fifo_tag_int2_en
 *	fifo_tag_int2_en ->
 *                 0    disable tag
 *                 1    enable tag
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_fifo_tag_int2_en(
u8 *fifo_tag_int2_en);
/*****************************************************************************
 *	Description: *//**brief This API writes FIFO interrupt 2
 *	tag enable from the resister 0x47 bit 2
 *
 *  \param u8 fifo_tag_int2_en :
 *               Value of the fifo_tag_int2_en
 *	fifo_tag_int2_en ->
 *                 0    disable tag
 *                 1    enable tag
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_fifo_tag_int2_en(
u8 fifo_tag_int2_en);
/*****************************************************************************
 *	Description: *//**brief This API Reads FIFO interrupt 1
 *	tag enable from the resister 0x47 bit 3
 *
 *  \param u8 * fifo_tag_int1_en :
 *                 Pointer to the fifo_tag_int1_en
 *	fifo_tag_int1_en ->
 *	0    disable tag
 *	1    enable tag
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_fifo_tag_int1_en(
u8 *fifo_tag_int1_en);
/*****************************************************************************
 * Description: *//**brief This API writes FIFO interrupt 1
 *	tag enable from the resister 0x47 bit 3
 *
 *  \param u8 * fifo_tag_int1_en :
 *                 The value of fifo_tag_int1_en
 *	fifo_tag_int1_en ->
 *	0    disable tag
 *	1    enable tag
 *
 *
 *
 *  \return results of communication routine
 *
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 *****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_fifo_tag_int1_en(
u8 fifo_tag_int1_en);
/*****************************************************************************
 *	Description: *//**brief This API Reads FIFO frame
 *	header enable from the register 0x47 bit 4
 *
 *  \param u8 * fifo_header_en :
 *                 Pointer to the fifo_header_en
 *	fifo_header_en ->
 *	0    no header is stored
 *	1    header is stored
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_fifo_header_en(
u8 *fifo_header_en);
/*****************************************************************************
 *	Description: *//**brief This API writes FIFO frame
 *	header enable from the register 0x47 bit 4
 *
 *
 *  \param u8 fifo_header_en :
 *               Value of the fifo_header_en
 *	fifo_header_en ->
 *	0    no header is stored
 *	1    header is stored
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_fifo_header_en(
u8 fifo_header_en);
/*****************************************************************************
 *	Description: *//**brief This API is used to read stored
 *	magnetometer data in FIFO (all 3 axes) from the register 0x47 bit 5
 *
 *  \param u8 * fifo_mag_en :
 *                 Pointer to the fifo_mag_en
 *	fifo_mag_en ->
 *	0   no magnetometer data is stored
 *	1   magnetometer data is stored
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_fifo_mag_en(
u8 *fifo_mag_en);
/*****************************************************************************
 *	Description: *//**brief This API is used to write stored
 *	magnetometer data in FIFO (all 3 axes) from the register 0x47 bit 5
 *
 *  \param u8 fifo_mag_en :
 *                 The value of fifo_mag_en
 *	fifo_mag_en ->
 *	0   no magnetometer data is stored
 *	1   magnetometer data is stored
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_fifo_mag_en(
u8 fifo_mag_en);
/*****************************************************************************
 *	Description: *//**brief This API is used to read stored
 *	accel data in FIFO (all 3 axes) from the register 0x47 bit 6
 *
 *
 *  \param u8 * fifo_acc_en :
 *                 Pointer to the fifo_acc_en
 *	fifo_acc_en ->
 *	0   no accel data is stored
 *	1   accel data is stored
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_fifo_acc_en(
u8 *fifo_acc_en);
/*****************************************************************************
 *	Description: *//**brief This API is used to write stored
 *	accel data in FIFO (all 3 axes) from the register 0x47 bit 6
 *
 *
 *  \param u8 * fifo_acc_en :
 *                 The value of fifo_acc_en
 *	fifo_acc_en ->
 *	0   no accel data is stored
 *	1   accel data is stored
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_fifo_acc_en(
u8 fifo_acc_en);
/*****************************************************************************
 *	Description: *//**brief This API is used to read stored
 *	 gyro data in FIFO (all 3 axes) from the resister 0x47 bit 7
 *
 *
 *  \param u8 * fifo_gyro_en :
 *                 Pointer to the fifo_gyro_en
 *	fifo_gyro_en ->
 *	0   no gyro data is stored
 *	1   gyro data is stored
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_fifo_gyro_en(
u8 *fifo_gyro_en);
/*****************************************************************************
 *	Description: *//**brief This API is used to write stored
 *  gyro data in FIFO (all 3 axes) from the register 0x47 bit 7
 *
 *
 *
 *  \param u8 fifo_gyro_en :
 *               Value of the fifo_gyro_en
 *	fifo_gyro_en ->
 *	0   no gyro data is stored
 *	1   gyro data is stored
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_fifo_gyro_en(
u8 fifo_gyro_en);
/*****************************************************************************
 *	Description: *//**brief This API is used to read
 *	I2C device address of magnetometer from the register 0x4B bit 1 to 7
 *
 *
 *
 *
 *  \param u8 * i2c_device_addr :
 *                 Pointer to the i2c_device_addr
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_i2c_device_addr(
u8 *i2c_device_addr);
/*****************************************************************************
 *	Description: *//**brief This API is used to write
 *	I2C device address of magnetometer from the register 0x4B bit 1 to 7
 *
 *
 *
 *  \param u8 i2c_device_addr :
 *               Value of the i2c_device_addr
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_i2c_device_addr(
u8 i2c_device_addr);
 /*****************************************************************************
 *	Description: *//**brief This API is used to read
 *	Burst data length (1,2,6,8 byte) from the register 0x4C bit 0 to 1
 *
 *
 *
 *
 *  \param u8 * mag_burst :
 *                 Pointer to the mag_burst
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 *****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_mag_burst(
u8 *mag_burst);
/*****************************************************************************
 *	Description: *//**brief This API is used to write
 *	Burst data length (1,2,6,8 byte) from the register 0x4C bit 0 to 1
 *
 *
 *
 *  \param u8 mag_burst :
 *               Value of the mag_burst
 *
 *
 *
 *  \return results of communication routine
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_mag_burst(
u8 mag_burst);
/******************************************************************************
 *	Description: *//**brief This API is used to read
 *	trigger-readout offset in units of 2.5 ms. If set to zero,
 *	the offset is maximum, i.e. after readout a trigger
 *	is issued immediately. from the register 0x4C bit 2 to 5
 *
 *
 *
 *
 *  \param u8 * mag_offset :
 *                 Pointer to the mag_offset
 *
 *
 *
 *  \return results of communication routine
 *
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_mag_offset(
u8 *mag_offset);
/*******************************************************************************
 *	Description: *//**brief This API is used to write
 *	trigger-readout offset in units of 2.5 ms. If set to zero,
 *	the offset is maximum, i.e. after readout a trigger
 *	is issued immediately. from the register 0x4C bit 2 to 5
 *
 *
 *
 *  \param u8 mag_offset :
 *               Value of the mag_offset
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_mag_offset(
u8 mag_offset);
/*******************************************************************************
 *	Description: *//**brief This API is used to read
 *	Enable register access on MAG_IF[2] or MAG_IF[3] writes.
 *	This implies that the DATA registers are not updated with
 *	magnetometer values. Accessing magnetometer requires
 *	the magnetometer in normal mode in PMU_STATUS.
 *	from the register 0x4C bit 7
 *
 *
 *
 *  \param u8 * mag_manual_en :
 *                 Pointer to the mag_manual_en
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_mag_manual_en(
u8 *mag_manual_en);
/*******************************************************************************
 *	Description: *//**brief This API is used to write
 *	Enable register access on MAG_IF[2] or MAG_IF[3] writes.
 *	This implies that the DATA registers are not updated with
 *	magnetometer values. Accessing magnetometer requires
 *	the magnetometer in normal mode in PMU_STATUS.
 *	from the register 0x4C bit 7
 *
 *
 *  \param u8 mag_manual_en :
 *               Value of the mag_manual_en
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_mag_manual_en(
u8 mag_manual_en);
/*******************************************************************************
 *	Description: *//**brief This API is used to read data
 *	magnetometer address to read from the register 0x4D bit 0 to 7
 *
 *
 *
 *
 *  \param u8 mag_read_addr :
 *                 Pointer holding the value of mag_read_addr
 *
 *
 *
 *  \return results of communication
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_mag_read_addr(
u8 *mag_read_addr);
/*******************************************************************************
 *	Description: *//**brief This API is used to write data
 *	magnetometer address to read from the register 0x4D bit 0 to 7
 *
 *
 *
 *
 *  \param u8 mag_read_addr :
 *               Value of the mag_read_addr
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_mag_read_addr(
u8 mag_read_addr);
/*****************************************************************************
 *	Description: *//**brief This API is used to read
 *	magnetometer write address from the register 0x4E bit 0 to 7
 *
 *
 *
 *
 *  \param u8 mag_write_addr
 *                 Pointer to mag_write_addr
 *
 *
 *
 *  \return results of communication
 *
 *
 ***************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 * *
 * Remarks:
 *
 ****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_mag_write_addr(
u8 *mag_write_addr);
/*****************************************************************************
 *	Description: *//**brief This API is used to write
 *	magnetometer write address from the resister 0x4E bit 0 to 7
 *
 *
 *
 *
 *  \param u8 mag_write_addr :
 *               Value of the mag_write_addr
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_mag_write_addr(
u8 mag_write_addr);
/*****************************************************************************
 *	Description: *//**brief This API is used to read magnetometer write data
 *	form the resister 0x4F bit 0 to 7
 *
 *
 *
 *
 *  \param u8 mag_write_data
 *                 Pointer to mag_write_data
 *
 *
 *
 *  \return results of communication
 *
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 *****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_mag_write_data(
u8 *mag_write_data);
/*******************************************************************************
 *	Description: *//**brief This API is used to write magnetometer write data
 *	form the resister 0x4F bit 0 to 7
 *
 *
 *
 *
 *  \param u8 mag_write_data :
 *               Value of the mag_write_data
 *
 *
 *
 *  \return results of communication routine
 *
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 *****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_mag_write_data(
u8 mag_write_data);
/*************************************************************************
 *	Description: *//**brief  This API is used to read
 *	interrupt enable from the register 0x50 bit 0 to 7
 *
 *
 *
 *
 *	\param u8 enable,u8 *int_en_0 : The value of interrupt enable
 *	enable -->
 *	BMI160_ANYMO_X_EN       0
 *	BMI160_ANYMO_Y_EN       1
 *	BMI160_ANYMO_Z_EN       2
 *	BMI160_D_TAP_EN         4
 *	BMI160_S_TAP_EN         5
 *	BMI160_ORIENT_EN        6
 *	BMI160_FLAT_EN          7
 *	int_en_0 --> 1
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 **************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_en_0(
u8 enable, u8 *int_en_0);
/***************************************************************************
 *	Description: *//**brief This API is used to write
 *	interrupt enable byte0 from the register 0x50 bit 0 to 7
 *
 *	\param u8 enable,u8 *int_en_0 : The value of interrupt enable
 *	enable -->
 *	BMI160_ANYMO_X_EN       0
 *	BMI160_ANYMO_Y_EN       1
 *	BMI160_ANYMO_Z_EN       2
 *	BMI160_D_TAP_EN         4
 *	BMI160_S_TAP_EN         5
 *	BMI160_ORIENT_EN        6
 *	BMI160_FLAT_EN          7
 *	int_en_0 --> 1
 *
 *
 *
 *  \return results of communication
 *
 *
 ***************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 *********************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_en_0(
u8 enable, u8 int_en_0);
/************************************************************************
 *	Description: *//**brief  This API is used to read
 *	interrupt enable byte1 from the register 0x51 bit 0 to 6
 *
 *
 *
 *
 *  \param u8 enable,u8 *int_en_1 : The value of interrupt enable
 *	enable -->
 *	BMI160_HIGH_X_EN       0
 *	BMI160_HIGH_Y_EN       1
 *	BMI160_HIGH_Z_EN       2
 *	BMI160_LOW_EN          3
 *	BMI160_DRDY_EN         4
 *	BMI160_FFULL_EN        5
 *	BMI160_FWM_EN          6
 *	int_en_1 --> 1
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 **********************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_en_1(
u8 enable, u8 *int_en_1);
/**************************************************************************
 *	Description: *//**brief This API is used to write
 *	interrupt enable byte1 from the register 0x51 bit 0 to 6
 *
 *
 *
 *  \param u8 enable,u8 *int_en_1 : The value of interrupt enable
 *	enable -->
 *	BMI160_HIGH_X_EN       0
 *	BMI160_HIGH_Y_EN       1
 *	BMI160_HIGH_Z_EN       2
 *	BMI160_LOW_EN          3
 *	BMI160_DRDY_EN         4
 *	BMI160_FFULL_EN        5
 *	BMI160_FWM_EN          6
 *	int_en_1 --> 1
 *
 *
 *
 *  \return results of communication
 *
 *
 **************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 *************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_en_1(
u8 enable, u8 int_en_1);
/************************************************************************
 *	Description: *//**brief  This API is used to read
 *	interrupt enable byte2 from the register bit 0x52 bit 0 to 3
 *
 *
 *
 *
 *	\param u8 enable,u8 *int_en_2 : The value of interrupt enable
 *	enable -->
 *	BMI160_NOMOTION_X_EN	0
 *	BMI160_NOMOTION_Y_EN	1
 *	BMI160_NOMOTION_Z_EN	2
 *
 *	int_en_2 --> 1
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 **********************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_en_2(
u8 enable, u8 *int_en_2);
/************************************************************************
 *	Description: *//**brief This API is used to read
 *	interrupt enable step detector interrupt from
 *	the register bit 0x52 bit 3
 *
 *
 *
 *
 *	\param u8 step_int : Pointer holding the value of interrupt enable
 *
 *
 *
 *  \return results of communication
 *
 *
 ************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 **********************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_stepdetector_enable(
u8 *step_int);
/**************************************************************************
 *	Description: *//**brief This API is used to write
 *	interrupt enable step detector interrupt from
 *	the register bit 0x52 bit 3
 *
 *
 *
 *
 *	\param u8 step_int : The value of interrupt enable
 *
 *
 *
 *  \return results of communication
 *
 *
**************************************************************************/
/* Scheduling:
*
*
*
* Usage guide:
*
*
* Remarks:
*
*************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_stepdetector_enable(
u8 step_int);
/**************************************************************************
 *	Description: *//**brief This API is used to write
 *	interrupt enable byte2 from the register bit 0x52 bit 0 to 3
 *
 *
 *
 *
 *	\param u8 enable,u8 *int_en_2 : The value of interrupt enable
 *	enable -->
 *	BMI160_NOMOTION_X_EN	0
 *	BMI160_NOMOTION_Y_EN	1
 *	BMI160_NOMOTION_Z_EN	2
 *
 *	int_en_2 --> 1
 *
 *
 *
 *  \return results of communication
 *
 *
**************************************************************************/
/* Scheduling:
*
*
*
* Usage guide:
*
*
* Remarks:
*
*************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_en_2(
u8 enable, u8 int_en_2);
/**************************************************************************
 *	Description: *//**brief  Configure trigger condition of INT1
 *	and INT2 pin from the register 0x53 bit 0
 *
 *
 *  \param u8 channel,u8 *int_edge_ctrl : The value of interrupt enable
 *	channel -->
 *	BMI160_INT1_EDGE_CTRL         0
 *	BMI160_INT2_EDGE_CTRL         1
 *	int_edge_ctrl -->
 *	0            Level
 *	1            Edge
 *
 *
 *  \return results of communication routine
 *
 *
 *************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_edge_ctrl(
u8 channel, u8 *int_edge_ctrl);
/**************************************************************************
 *	Description: *//**brief  Configure trigger condition of INT1
 *	and INT2 pin from the register 0x53 bit 0
 *
 *
 *  \param u8 channel,u8 *int_edge_ctrl : The value of interrupt enable
 *	channel -->
 *	BMI160_INT1_EDGE_CTRL         0
 *	BMI160_INT2_EDGE_CTRL         1
 *	int_edge_ctrl -->
 *	0            Level
 *	1            Edge
 *
 *
 *
 *
 *  \return results of communication
 *
 *
 *************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***********************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_edge_ctrl(
u8 channel, u8 int_edge_ctrl);
/**************************************************************************
 *	Description: *//**brief  Configure trigger condition of INT1
 *	and INT2 pin form the register 0x53 bit 1
 *
 *  \param u8 channel,u8 *int_lvl
 *	channel -->
 *	BMI160_INT1_LVL         0
 *	BMI160_INT2_LVL         1
 *	int_lvl -->
 *	0            active low
 *	1            active high
 *
 *
 *  \return results of communication routine
 *
 *
 ************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 *************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_lvl(
u8 channel, u8 *int_lvl);
/**************************************************************************
 *	Description: *//**brief  Configure set the trigger condition of INT1
 *	and INT2 pin form the register 0x53 bit 1 and 5
 *
 *  \param u8 channel,u8  int_lvl : The value of interrupt level
 *	channel -->
 *	BMI160_INT1_LVL         0
 *	BMI160_INT2_LVL         1
 *	int_lvl -->
 *	0            active low
 *	1            active high
 *
 *
 *  \return results of communication routine
 *
 *
 ************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 *************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_lvl(
u8 channel, u8 int_lvl);
/*************************************************************************
 *	Description: *//**brief  Configure trigger condition of INT1
 *	from the register 0x53 bit 2 and 6
 *
 *  \param u8 channel,u8 *int_od : The interrupt output enable
 *	channel -->
 *	BMI160_INT1_OD         0
 *	BMI160_INT2_OD         1
 *	int_od -->
 *	0            push-pull
 *	1            open drain
 *
 *
 *  \return results of communication routine
 *
 *
 **************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***********************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_od(
u8 channel, u8 *int_od);
/**************************************************************************
 *	Description: *//**brief Configure trigger condition of INT1
 *	from the register 0x53 bit 2 and 6
 *
 *  \param u8 channel,u8 *int_od : The interrupt output enable
 *	channel -->
 *	BMI160_INT1_OD         0
 *	BMI160_INT2_OD         1
 *	int_od -->
 *	0            push-pull
 *	1            open drain
 *
 *
 *
 *  \return results of communication routine communication results
 *
 *
 *************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 *************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_od(
u8 channel, u8 int_od);
/**************************************************************************
 *	Description: *//**brief Output enable for INT1
 *	and INT2 pin from the register 0x53 bit 3 and 7
 *
 *
 *  \param u8 channel,u8 *output_en : The value of output enable
 *	channel -->
 *	BMI160_INT1_OUTPUT_EN         0
 *	BMI160_INT2_OUTPUT_EN         1
 *	output_en -->
 *	0           Output
 *	1            Input
 *
 *
 *  \return results of communication routine
 *
 *
 ************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_output_en(
u8 channel, u8 *output_en);
/**************************************************************************
 *	Description: *//**brief Output enable for INT1
 *	and INT2 pin from the register 0x53 bit 3 and 7
 *
 *
 *  \param u8 channel,u8 *output_en : The value of output enable
 *	channel -->
 *	BMI160_INT1_OUTPUT_EN         0
 *	BMI160_INT2_OUTPUT_EN         1
 *	output_en -->
 *	0           Output
 *	1            Input
 *
 *
 *  \return results of communication routine
 *
 *
 ************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_output_en(
u8 channel, u8 output_en);
/************************************************************************
*	Description: *//**brief This API is used to get the latch duration
*	from the register 0x54 bit 0 to 3
*
*
*
*  \param u8 *latch_int : Pointer holding the value of latch duration
*	0 -> NON_LATCH
*	1 -> temporary, 312.5 us
*	2 -> temporary, 625 us
*	3 -> temporary, 1.25 ms
*	4 -> temporary, 2.5 ms
*	5 -> temporary, 5 ms
*	6 -> temporary, 10 ms
*	7 -> temporary, 20 ms
*	8 -> temporary, 40 ms
*	9 -> temporary, 80 ms
*	10 -> temporary, 160 ms
*	11 -> temporary, 320 ms
*	12 -> temporary, 640 ms
*	13 ->  temporary, 1.28 s
*	14 -> temporary, 2.56 s
*	15 -> LATCHED
*
*
*
*  \return results of communication routine
*
*
 **************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_latch_int(
u8 *latch_int);
/***************************************************************************
*	Description: *//**brief This API is used to get the latch duration
*	from the register 0x54 bit 0 to 3
*
*
*
*  \param u8 *latch_int : Pointer holding the value of latch duration
*	0 -> NON_LATCH
*	1 -> temporary, 312.5 us
*	2 -> temporary, 625 us
*	3 -> temporary, 1.25 ms
*	4 -> temporary, 2.5 ms
*	5 -> temporary, 5 ms
*	6 -> temporary, 10 ms
*	7 -> temporary, 20 ms
*	8 -> temporary, 40 ms
*	9 -> temporary, 80 ms
*	10 -> temporary, 160 ms
*	11 -> temporary, 320 ms
*	12 -> temporary, 640 ms
*	13 ->  temporary, 1.28 s
*	14 -> temporary, 2.56 s
*	15 -> LATCHED
*
*  \return results of communication
*
*************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
**************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_latch_int(
u8 latch_int);
/**************************************************************************
 *	Description: *//**brief input enable for INT1
 *	and INT2 pin from the register 0x54 bit 4 and 5
 *
 *
 *
 *  \param u8 channel,u8 *input_en : The value of interrupt enable
 *	channel -->
 *	BMI160_INT1_INPUT_EN         0
 *	BMI160_INT2_INPUT_EN         1
 *	input_en -->
 *	Value        Description
 *	0            output
 *	1            Input
 *
 *
 *  \return results of communication routine
 *
 *
 ************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_input_en(
u8 channel, u8 *input_en);
/**************************************************************************
 *	Description: *//**brief input enable for INT1
 *	and INT2 pin from the register 0x54 bit 4 and 5
 *
 *
 *
 *  \param u8 channel,u8 input_en : The value of interrupt enable
 *	channel -->
 *	BMI160_INT1_INPUT_EN         0
 *	BMI160_INT2_INPUT_EN         1
 *	input_en -->
 *	Value        Description
 *	0            output
 *	1            Input
 *
 *  \return results of communication routine
 *
 *
 ************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_input_en(
u8 channel, u8 input_en);
/**************************************************************************
 *	Description: *//**brief Reads the Low g interrupt mapped to INT1
 *	and INT2 from the register 0x55 and 0x57
 *	INT1 bit 0 in the register 0x55
 *	INT2 bit 0 in the register 0x57
 *
 *  \param u8 channel,u8 *int_lowg : The value of lowg enable
 *	channel -->
 *	BMI160_INT1_MAP_LOW_G         0
 *	BMI160_INT2_MAP_LOW_G         1
 *
 *
 *
 *  \return results of communication routine
 *
 *
 **************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 *************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_lowg(
u8 channel, u8 *int_lowg);
/************************************************************************
 *	Description: *//**brief Write the Low g interrupt mapped to INT1
 *	and INT2 from the register 0x55 and 0x57
 *	INT1 bit 0 in the register 0x55
 *	INT2 bit 0 in the register 0x57
 *
 *  \param u8 channel,u8 int_lowg : The value of lowg enable
 *	channel -->
 *	BMI160_INT1_MAP_LOW_G         0
 *	BMI160_INT2_MAP_LOW_G         1
 *
 *
 *
 *  \return results of communication
 *
 *
 **************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 **************************************************************************/

BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_lowg(
u8 channel, u8 int_lowg);
/**************************************************************************
 *	Description: *//**brief Reads the HIGH g interrupt mapped to INT1
 *	and INT2 from the register 0x55 and 0x57
 *	INT1 bit 1 in the register 0x55
 *	INT2 bit 1 in the register 0x57
 *
 *  \param u8 channel,u8 int_highg : The value of highg enable
 *	channel -->
 *	BMI160_INT1_MAP_HIGH_G         0
 *	BMI160_INT2_MAP_HIGH_G         1
 *
 *
 *
 *  \return results of communication routine
 *
 *
 *************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_highg(
u8 channel, u8 *int_highg);
/****************************************************************************
 *	Description: *//**brief Write the HIGH g interrupt mapped to INT1
 *	and INT2 from the register 0x55 and 0x57
 *	INT1 bit 1 in the register 0x55
 *	INT2 bit 1 in the register 0x57
 *
 *  \param u8 channel,u8 int_highg : The value of highg enable
 *	channel -->
 *	BMI160_INT1_MAP_HIGH_G         0
 *	BMI160_INT2_MAP_HIGH_G         1
 *
 *
 *
 *  \return results of communication routine
 *
 *
 *************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 **************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_highg(
u8 channel, u8 int_highg);
/****************************************************************************
 *	Description: *//**brief Reads the Any motion interrupt
 *	interrupt mapped to INT1
 *	and INT2 from the register 0x55 and 0x57
 *	INT1 bit 2 in the register 0x55
 *	INT2 bit 2 in the register 0x57
 *
 *  \param u8 channel,u8 int_anymo : The value of any motion interrupt enable
 *	channel -->
 *	BMI160_INT1_MAP_ANYMO         0
 *	BMI160_INT2_MAP_ANYMO         1
 *
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ***************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 *************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_anymo(
u8 channel, u8 *int_anymo);
/****************************************************************************
 *	Description: *//**brief Write the Any motion interrupt
 *	interrupt mapped to INT1
 *	and INT2 from the register 0x55 and 0x57
 *	INT1 bit 2 in the register 0x55
 *	INT2 bit 2 in the register 0x57
 *
 *  \param u8 channel,u8 int_anymo : The value of any motion interrupt enable
 *	channel -->
 *	BMI160_INT1_MAP_ANYMO         0
 *	BMI160_INT2_MAP_ANYMO         1
 *
 *
 *
 *  \return results of communication routine
 *
 *************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 **************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_anymo(
u8 channel, u8 int_anymo);
/****************************************************************************
 *	Description: *//**brief Write the No motion interrupt
 *	interrupt mapped to INT1
 *	and INT2 from the register 0x55 and 0x57
 *	INT1 bit 3 in the register 0x55
 *	INT2 bit 3 in the register 0x57
 *
 *  \param u8 channel,u8 int_nomo : The value of any motion interrupt enable
 *	channel -->
 *	BMI160_INT1_MAP_NOMO         0
 *	BMI160_INT2_MAP_NOMO         1
 *
 *
 *  \return results of communication routine
 *
 *
 ***************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 *************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_nomotion(
u8 channel, u8 *int_nomo);
/****************************************************************************
 *	Description: *//**brief Write the No motion interrupt
 *	interrupt mapped to INT1
 *	and INT2 from the register 0x55 and 0x57
 *	INT1 bit 3 in the register 0x55
 *	INT2 bit 3 in the register 0x57
 *
 *  \param u8 channel,u8 int_nomo : The value of any motion interrupt enable
 *	channel -->
 *	BMI160_INT1_MAP_NOMO         0
 *	BMI160_INT2_MAP_NOMO         1
 *
 *
 *
 *  \return results of communication routine
 *
 *
 *************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 **************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_nomotion(
u8 channel, u8 int_nomo);
/****************************************************************************
 *	Description: *//**brief Reads the Double Tap interrupt
 *	interrupt mapped to INT1
 *	and INT2 from the register 0x55 and 0x57
 *	INT1 bit 3 in the register 0x55
 *	INT2 bit 3 in the register 0x57
 *
 *  \param u8 channel,u8 int_dtap : The value of any motion interrupt enable
 *	channel -->
 *	BMI160_INT1_MAP_DTAP         0
 *	BMI160_INT2_MAP_DTAP         1
 *
 *  \return results of communication routine
 *
 *
 ***************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 **************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_dtap(
u8 channel, u8 *int_dtap);
/****************************************************************************
 *	Description: *//**brief Write the Double Tap interrupt
 *	interrupt mapped to INT1
 *	and INT2 from the register 0x55 and 0x57
 *	INT1 bit 3 in the register 0x55
 *	INT2 bit 3 in the register 0x57
 *
 *  \param u8 channel,u8 int_dtap : The value of double tap interrupt enable
 *	channel -->
 *	BMI160_INT1_MAP_DTAP         0
 *	BMI160_INT2_MAP_DTAP         1
 *
 *
 *
 *  \return results of communication routine
 *
 **************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 *************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_dtap(
u8 channel, u8 int_dtap);
/***************************************************************************
 *	Description: *//**brief Reads the Single Tap interrupt
 *	interrupt mapped to INT1
 *	and INT2 from the register 0x55 and 0x57
 *	INT1 bit 4 in the register 0x55
 *	INT2 bit 4 in the register 0x57
 *
 *  \param u8 channel,u8 int_stap : The value of single tap interrupt enable
 *	channel -->
 *	BMI160_INT1_MAP_STAP         0
 *	BMI160_INT2_MAP_STAP         1
 *
 *
 *  \return results of communication routine
 *
 *
 *************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_stap(
u8 channel, u8 *int_stap);
/**************************************************************************
 *	Description: *//**brief Write the Single Tap interrupt
 *	interrupt mapped to INT1
 *	and INT2 from the register 0x55 and 0x57
 *	INT1 bit 4 in the register 0x55
 *	INT2 bit 4 in the register 0x57
 *
 *  \param u8 channel,u8 int_stap : The value of single tap interrupt enable
 *	channel -->
 *	BMI160_INT1_MAP_STAP         0
 *	BMI160_INT2_MAP_STAP         1
 *
 *
 *
 *  \return results of communication routine
 *
 *
 *************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_stap(
u8 channel, u8 int_stap);
/***************************************************************************
 *	Description: *//**brief Reads the Orient interrupt
 *	interrupt mapped to INT1
 *	and INT2 from the register 0x55 and 0x57
 *	INT1 bit 6 in the register 0x55
 *	INT2 bit 6 in the register 0x57
 *
 *  \param u8 channel,u8 int_orient : The value of orient interrupt enable
 *	channel -->
 *	BMI160_INT1_MAP_ORIENT         0
 *	BMI160_INT2_MAP_ORIENT         1
 *
 *
 *
 *  \return results of communication routine
 *
 *
 *************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***********************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_orient(
u8 channel, u8 *int_orient);
/**************************************************************************
 *	Description: *//**brief Write the Orient interrupt
 *	interrupt mapped to INT1
 *	and INT2 from the register 0x55 and 0x57
 *	INT1 bit 6 in the register 0x55
 *	INT2 bit 6 in the register 0x57
 *
 *  \param u8 channel,u8 int_orient : The value of orient interrupt enable
 *	channel -->
 *	BMI160_INT1_MAP_ORIENT         0
 *	BMI160_INT2_MAP_ORIENT         1
 *
 *
 *
 *  \return results of communication routine
 *
 *
 *************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 *************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_orient(
u8 channel, u8 int_orient);
/****************************************************************************
 *	Description: *//**brief Reads the Flat interrupt
 *	interrupt mapped to INT1
 *	and INT2 from the register 0x55 and 0x57
 *	INT1 bit 6 in the register 0x55
 *	INT2 bit 6 in the register 0x57
 *
 *  \param u8 channel,u8 int_flat : The value of Flat interrupt enable
 *	channel -->
 *	BMI160_INT1_MAP_FLAT		0
 *	BMI160_INT2_MAP_FLAT		1
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 *************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_flat(
u8 channel, u8 *int_flat);
/**************************************************************************
 *	Description: *//**brief Writes the Flat interrupt
 *	interrupt mapped to INT1
 *	and INT2 from the register 0x55 and 0x57
 *	INT1 bit 6 in the register 0x55
 *	INT2 bit 6 in the register 0x57
 *
 *  \param u8 channel,u8 int_flat : The value of Flat interrupt enable
 *	channel -->
 *	BMI160_INT1_MAP_FLAT		0
 *	BMI160_INT2_MAP_FLAT		1
 *
 *
 *
 *  \return results of communication routine
 *
 *
 *************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***********************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_flat(
u8 channel, u8 int_flat);
/****************************************************************************
 *	Description: *//**brief Reads PMU trigger interrupt mapped to INT1
 *	and INT2 form the register 0x56 bit 0 and 4
 *
 *
 *
 *
 *  \param u8 channel,u8 *int_pmutrig : The value of PMU trigger
 *	channel -->
 *	BMI160_INT1_MAP_PMUTRIG         0
 *	BMI160_INT2_MAP_PMUTRIG         1
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ***************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 *************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_pmutrig(
u8 channel, u8 *int_pmutrig);
/****************************************************************************
 *	Description: *//**brief Write PMU trigger interrupt mapped to INT1
 *	and INT2 form the register 0x56 bit 0 and 4
 *
 *
 *
 *
 *  \param u8 channel,u8 int_pmutrig : The value of PMU trigger
 *	channel -->
 *	BMI160_INT1_MAP_PMUTRIG         0
 *	BMI160_INT2_MAP_PMUTRIG         1
 *
 *
 *  \return results of communication routine
 *
 *
 ***************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 *************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_pmutrig(
u8 channel, u8 int_pmutrig);
/****************************************************************************
 *	Description: *//**brief Reads FIFO Full interrupt mapped to INT1
 *	and INT2 form the register 0x56 bit 5 and 1
 *
 *
 *
 *
 *  \param u8 channel,u8 *int_ffull : The value of FIFO Full
 *	channel -->
 *	BMI160_INT1_MAP_FFULL         0
 *	BMI160_INT2_MAP_FFULL         1
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 *************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_ffull(
u8 channel, u8 *int_ffull);
/****************************************************************************
 *	Description: *//**brief Write FIFO Full interrupt mapped to INT1
 *	and INT2 form the register 0x56 bit 5 and 1
 *
 *
 *
 *
 *  \param u8 channel,u8 int_ffull : The value of FIFO Full
 *	channel -->
 *	BMI160_INT1_MAP_FFULL         0
 *	BMI160_INT2_MAP_FFULL         1
 *
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 **************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_ffull(
u8 channel, u8 int_ffull);
/***************************************************************************
 *	Description: *//**brief Reads FIFO Watermark interrupt mapped to INT1
 *	and INT2 form the register 0x56 bit 6 and 2
 *
 *
 *
 *
 *  \param u8 channel,u8 *int_fwm : The value of FIFO Full
 *	channel -->
 *	BMI160_INT1_MAP_FWM         0
 *	BMI160_INT2_MAP_FWM         1
 *
 *
 *
 *  \return results of communication routine
 *
 *
 **************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 **************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_fwm(
u8 channel, u8 *int_fwm);
/***************************************************************************
 *	Description: *//**brief Write FIFO Watermark interrupt mapped to INT1
 *	and INT2 form the register 0x56 bit 6 and 2
 *
 *
 *
 *
 *  \param u8 channel,u8 int_fwm : The value of FIFO Full
 *	channel -->
 *	BMI160_INT1_MAP_FWM         0
 *	BMI160_INT2_MAP_FWM         1
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ***************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 *************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_fwm(
u8 channel, u8 int_fwm);
/****************************************************************************
 *	Description: *//**brief Reads Data Ready interrupt mapped to INT1
 *	and INT2 form the register 0x56 bit 7 and 3
 *
 *
 *
 *
 *  \param u8 channel,u8 *int_drdy : The value of data ready
 *	channel -->
 *	BMI160_INT1_MAP_DRDY         0
 *	BMI160_INT2_MAP_DRDY         1
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ***************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 **************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_drdy(
u8 channel, u8 *int_drdy);
/****************************************************************************
 *	Description: *//**brief Write Data Ready interrupt mapped to INT1
 *	and INT2 form the register 0x56 bit 7 and 3
 *
 *
 *
 *
 *  \param u8 channel,u8 int_drdy : The value of data ready
 *	channel -->
 *	BMI160_INT1_MAP_DRDY         0
 *	BMI160_INT2_MAP_DRDY         1
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ***************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_drdy(
u8 channel, u8 int_drdy);
/***************************************************************************
 *	Description: *//**brief This API Reads Data source for the interrupt
 *	engine for the single and double tap interrupts from the register
 *	0x58 bit 3
 *
 *
 *  \param u8 * tap_src : Pointer holding the value of the tap_src
 *	Value         Description
 *	1             unfiltered data
 *	0             filtered data
 *
 *
 *  \return results of communication routine
 *
 *
 **************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ***************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_tap_src(
u8 *tap_src);
/***************************************************************************
 *	Description: *//**brief This API Write Data source for the interrupt
 *	engine for the single and double tap interrupts from the register
 *	0x58 bit 3
 *
 *
 *  \param u8  tap_src :  The value of the tap_src
 *	Value         Description
 *	1             unfiltered data
 *	0             filtered data
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 *************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_tap_src(
u8 tap_src);
/***************************************************************************
 *	Description: *//**brief This API Reads Data source for the
 *	interrupt engine for the low and high g interrupts
 *	from the register 0x58 bit 7
 *
 *  \param u8 * lowhigh_src : Pointer holding the value of lowhigh_src
 *	Value        Description
 *	1      unfiltered data
 *	0      filtered data
 *
 *
 *  \return results of communication routine
 *
 *
 *************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 **************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_lowhigh_src(
u8 *lowhigh_src);
/***************************************************************************
 *	Description: *//**brief This API Write Data source for the
 *	interrupt engine for the low and high g interrupts
 *	from the register 0x58 bit 7
 *
 *  \param u8 * lowhigh_src : Pointer holding the value of lowhigh_src
 *	Value        Description
 *	1      unfiltered data
 *	0      filtered data
 *
 *
 *
 *  \return results of communication routine
 *
 *
 **************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 **************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_lowhigh_src(
u8 lowhigh_src);
/*******************************************************************************
 *	Description: *//**brief This API Reads Data source for the
 *	interrupt engine for the nomotion and anymotion interrupts
 *	from the register 0x59 bit 7
 *
 *  \param u8 * motion_src : Pointer holding the value of motion_src
 *
 *	Value   Description
 *	1   unfiltered data
 *	0   filtered data
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_motion_src(
u8 *motion_src);
/*******************************************************************************
 *	Description: *//**brief This API Write Data source for the
 *	interrupt engine for the nomotion and anymotion interrupts
 *	from the register 0x59 bit 7
 *
 *  \param u8 * motion_src : Pointer holding the value of motion_src
 *
 *	Value   Description
 *	1   unfiltered data
 *	0   filtered data
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_motion_src(
u8 motion_src);
/*******************************************************************************
 *	Description: *//**brief This API is used to read Delay
 *	time definition for the low-g interrupt from the register 0x5A bit 0 to 7
 *
 *
 *
 *
 *  \param u8 *low_dur : Pointer holding the value low_dur
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_low_dur(
u8 *low_dur);
/*******************************************************************************
 *	Description: *//**brief This API is used to write Delay
 *	time definition for the low-g interrupt from the register 0x5A bit 0 to 7
 *
 *
 *
 *
 *  \param u8 low_dur : the value of low_dur
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_low_dur(
u8 low_dur);
/*******************************************************************************
 *	Description: *//**brief This API is used to read Threshold
 *	definition for the low-g interrupt from the register 0x5B bit 0 to 7
 *
 *
 *
 *
 *  \param u8 *low_threshold : Pointer holding the value of low_threshold
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_low_threshold(
u8 *low_threshold);
/*******************************************************************************
 *	Description: *//**brief This API is used to write Threshold
 *	definition for the low-g interrupt from the register 0x5B bit 0 to 7
 *
 *
 *
 *
 *  \param u8 *low_threshold :  the value of low_threshold
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_low_threshold(
u8 low_threshold);
/*******************************************************************************
 *	Description: *//**brief This API Reads Low-g interrupt hysteresis;
 *	according to int_low_hy*125 mg, irrespective of the selected g-range.
 *	from the register 0x5c bit 0 to 1
 *
 *  \param u8 * low_hysteresis : Pointer holding the value of low_hysteresis
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_low_hysteresis(
u8 *low_hysteresis);
/*******************************************************************************
 *	Description: *//**brief This API write Low-g interrupt hysteresis;
 *	according to int_low_hy*125 mg, irrespective of the selected g-range.
 *	from the register 0x5c bit 0 to 1
 *
 *  \param u8 * low_hysteresis : Pointer holding the value of low_hysteresis
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_low_hysteresis(
u8 low_hysteresis);
/*******************************************************************************
 *	Description: *//**brief This API Reads Low-g interrupt mode:
 *	from the register 0x5C bit 2
 *
 *  \param u8 * low_mode : Pointer holding the value of low_mode
 *	Value      Description
 *	0      single-axis
 *	1     axis-summing
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_low_mode(
u8 *low_mode);
/*******************************************************************************
 *	Description: *//**brief This API write Low-g interrupt mode:
 *	from the register 0x5C bit 2
 *
 *  \param u8 low_mode : the value of low_mode
 *	Value      Description
 *	0      single-axis
 *	1     axis-summing
 *
 *
 *  \return results of communication routine
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_low_mode(
u8 low_mode);
/*******************************************************************************
 *	Description: *//**brief This API Reads High-g interrupt hysteresis;
 *	according to int_high_hy*125 mg (2 g range)
 *	int_high_hy*250 mg (4 g range)
 *	int_high_hy*500 mg (8 g range)
 *	int_high_hy*1000 mg (16 g range)
 *	from the register 0x5C bit 6 and 7
 *
 *  \param u8 * high_hysteresis : Pointer holding the value of high_hysteresis
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_high_hysteresis(
u8 *high_hysteresis);
/*******************************************************************************
 *	Description: *//**brief This API Write High-g interrupt hysteresis;
 *	according to int_high_hy*125 mg (2 g range)
 *	int_high_hy*250 mg (4 g range)
 *	int_high_hy*500 mg (8 g range)
 *	int_high_hy*1000 mg (16 g range)
 *	from the register 0x5C bit 6 and 7
 *
 *  \param u8 * high_hysteresis : The value of high_hysteresis
 *
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_high_hysteresis(
u8 high_hysteresis);
/*******************************************************************************
 *	Description: *//**brief This API is used to read Delay
 *	time definition for the high-g interrupt from the register
 *	0x5D bit 0 to 7
 *
 *
 *
 *  \param u8 high_duration : Pointer holding the value of high_duration
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_high_duration(
u8 *high_duration);
/*******************************************************************************
 *	Description: *//**brief This API is used to write Delay
 *	time definition for the high-g interrupt from the register
 *	0x5D bit 0 to 7
 *
 *
 *
 *  \param u8 high_duration :  The value of high_duration
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_high_duration(
u8 high_duration);
/*******************************************************************************
 *	Description: *//**brief This API is used to read Threshold
 *	definition for the high-g interrupt from the register 0x5E 0 to 7
 *
 *
 *
 *
 *  \param u8 high_threshold : Pointer holding the value of high_threshold
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_high_threshold(
u8 *high_threshold);
/*******************************************************************************
 *	Description: *//**brief This API is used to write Threshold
 *	definition for the high-g interrupt from the register 0x5E 0 to 7
 *
 *
 *
 *
 *  \param u8 high_threshold : The value of high_threshold
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_high_threshold(
u8 high_threshold);
/******************************************************************************
 *	Description: *//**brief This API Reads no-motion duration
 *	from the register 0x5F bit 0 and 1
 *
 *  \param u8 * anymotion_dur :  Pointer holding the value of anymotion
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_anymotion_duration(
u8 *anymotion_dur);
/*******************************************************************************
 *	Description: *//**brief This API write no-motion duration
 *	from the register 0x5F bit 0 and 1
 *
 *  \param u8 * anymotion_dur :  The value of anymotion
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_anymotion_duration(
u8 nomotion);
/*******************************************************************************
 *	Description: *//**brief This API Reads Slow/no-motion
 *	interrupt trigger delay duration from the register 0x5F bit 0 to 7
 *
 *  \param u8 * slow_nomotion : Pointer holding the value of slow_nomotion
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_slow_nomotion_duration(
u8 *slow_nomotion);
/*******************************************************************************
 *	Description: *//**brief This API Write Slow/no-motion
 *	interrupt trigger delay duration from the register 0x5F bit 0 to 7
 *
 *  \param u8 * slow_nomotion : The value of slow_nomotion
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_slow_nomotion_duration(
u8 slow_nomotion);
/*****************************************************************************
 *	Description: *//**brief This API is used to read Threshold
 *	definition for the any-motion interrupt from the register 0x60 bit
 *	0 to 7
 *
 *
 *  \param u8 anymotion_threshold : Pointer holding
 *		the value of anymotion_threshold
 *
 *
 *
 *  \return results of communication routine
 *
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 *****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_anymotion_threshold(
u8 *anymotion_threshold);
/******************************************************************************
 *	Description: *//**brief This API is used to write Threshold
 *	definition for the any-motion interrupt from the register 0x60 bit
 *	0 to 7
 *
 *
 *  \param u8 anymotion_threshold : The value of anymotion_threshold
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_anymotion_threshold(
u8 anymotion_threshold);
/*******************************************************************************
 *	Description: *//**brief This API is used to read Threshold
 *	definition for the slow/no-motion interrupt
 *	from the register 0x61 bit 0 to 7
 *
 *
 *
 *
 *  \param u8 slo_nomo_threshold : Pointer holding
 *			the value of slo_nomo_threshold
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_slo_nomo_threshold(
u8 *slo_nomo_threshold);
/*******************************************************************************
 *	Description: *//**brief This API is used to write Threshold
 *	definition for the slow/no-motion interrupt
 *	from the register 0x61 bit 0 to 7
 *
 *
 *
 *
 *  \param u8 slo_nomo_threshold : The value of slo_nomo_threshold
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_slo_nomo_threshold(
u8 slo_nomo_threshold);
/*******************************************************************************
 *	Description: *//**brief This API is used to select
 *	the slow/no-motion interrupt from the register 0x62 bit 1
 *
 *
 *
 *
 *  \param u8 int_slo_nomo_sel : Pointer holding
 *		the value of int_slo_nomo_sel
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_slo_nomo_sel(
u8 *int_slo_nomo_sel);
/*******************************************************************************
 *	Description: *//**brief This API is used to write
 *	the slow/no-motion interrupt from the register 0x62 bit 1
 *
 *
 *
 *
 *  \param u8 int_slo_nomo_sel : The value of int_slo_nomo_sel
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_slo_nomo_sel(
u8 int_slo_nomo_sel);
/*******************************************************************************
 *	Description: *//**brief This API is used to select
 *	the significant/ any motion  interrupt from the register 0x62 bit 1
 *
 *
 *
 *
 *  \param u8 int_sig_mot_sel : Pointer holding
 *		the value of int_sig_mot_sel
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_significant_motion_select(
u8 *int_sig_mot_sel);
/*******************************************************************************
 *	Description: *//**brief This API is used to select
 *	the significant/ any motion  interrupt from the register 0x62 bit 1
 *
 *
 *
 *
 *  \param u8 int_sig_mot_sel :
 *	the value of int_sig_mot_sel
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_significant_motion_select(
u8 int_sig_mot_sel);
/*******************************************************************************
 *	Description: *//**brief This API is used to select
 *	the significant/ any motion skip time from the register 0x62 bit  2 and 3
 *
 *
 *
 *
 *  \param u8 int_sig_mot_skip : Pointer holding
 *		the value of int_sig_mot_skip
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_significant_motion_skip(
u8 *int_sig_mot_skip);
/*******************************************************************************
 *	Description: *//**brief This API is used to select
 *	the significant/ any motion skip time from the register 0x62 bit  2 and 3
 *
 *
 *
 *
 *  \param u8 int_sig_mot_skip :
 *	the value of int_sig_mot_skip
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_significant_motion_skip(
u8 int_sig_mot_skip);
/*******************************************************************************
 *	Description: *//**brief This API is used to select
 *	the significant/ any motion proof time from the register 0x62 bit  4 and 5
 *
 *
 *
 *
 *  \param u8 int_sig_mot_proof : Pointer holding
 *		the value of int_sig_mot_proof
 *	Value  Name/Description
 *	0 -  proof_0_25s proof time 0.25 seconds
 *	1 -  proof_0_5s proof time 0.5 seconds
 *	2 -  proof_1s proof time 1 seconds
 *	3 -  proof_2s proof time 2 seconds
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_significant_motion_proof(
u8 *int_sig_mot_proof);
/*******************************************************************************
 *	Description: *//**brief This API is used to select
 *	the significant/ any motion proof time from the register 0x62 bit  4 and 5
 *
 *
 *
 *
 *  \param u8 int_sig_mot_proof : The value of int_sig_mot_proof
 *	Value  Name/Description
 *	0 -  proof_0_25s proof time 0.25 seconds
 *	1 -  proof_0_5s proof time 0.5 seconds
 *	2 -  proof_1s proof time 1 seconds
 *	3 -  proof_2s proof time 2 seconds
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_significant_motion_proof(
u8 int_sig_mot_proof);
/*******************************************************************************
 *	Description: *//**brief This API is used to get the tap duration
 *	from the register 0x63 bit 0 to 2
 *
 *
 *
 *  \param u8 *tap_duration : Pointer holding the value of tap_duration
 *                  0 -> 50ms
 *                  1 -> 100mS
 *                  2 -> 150mS
 *                  3 -> 200mS
 *                  4 -> 250mS
 *                  5 -> 375mS
 *                  6 -> 500mS
 *                  7 -> 700mS
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_tap_duration(
u8 *tap_duration);
/*******************************************************************************
 *	Description: *//**brief This API is used to set the tap duration
 *	from the register 0x63 bit 0 to 2
 *
 *
 *
 *  \param u8 *tap_duration :  the value of tap_duration
 *                  0 -> 50ms
 *                  1 -> 100mS
 *                  2 -> 150mS
 *                  3 -> 200mS
 *                  4 -> 250mS
 *                  5 -> 375mS
 *                  6 -> 500mS
 *                  7 -> 700mS
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_tap_duration(
u8 tap_duration);
/*******************************************************************************
 *	Description: *//**brief This API Reads the
 *	tap shock duration from the register 0x63 bit 2
 *
 *  \param u8 * tap_shock : Pointer holding
 *	the value of tap_shock
 *	Value	Description
 *	0		50 ms
 *	1		75 ms
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_tap_shock(
u8 *tap_shock);
/*******************************************************************************
 *	Description: *//**brief This API Write the
 *	tap shock duration from the register 0x63 bit 2
 *
 *  \param u8 * tap_shock : Pointer holding
 *	the value of tap_shock
 *	Value	Description
 *	0		50 ms
 *	1		75 ms
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_tap_shock(
u8 tap_shock);
/*******************************************************************************
 *	Description: *//**brief This API Reads Selects
 *	tap quiet duration from the register 0x63 bit 7
 *
 *
 *  \param u8 * tap_quiet : Pointer holding the value of tap_quiet
 *	Value  Description
 *	0         30 ms
 *	1         20 ms
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 **************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_tap_quiet(
u8 *tap_quiet);
/**************************************************************************
 *	Description: *//**brief This API Write Selects
 *	tap quiet duration from the register 0x63 bit 7
 *
 *
 *  \param u8  tap_quiet : The value of tap_quiet
 *	Value  Description
 *	0         30 ms
 *	1         20 ms
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_tap_quiet(
u8 tap_quiet);
/*******************************************************************************
 *	Description: *//**brief This API Reads Threshold of the
 *	single/double tap interrupt corresponding to
 *	int_tap_th - 62.5 mg (2 g range)
 *	int_tap_th - 125 mg (4 g range)
 *	int_tap_th - 250 mg (8 g range)
 *	int_tap_th - 500 mg (16 g range)
 *	from the register 0x64 bit 0 to 4
 *
 *	\param u8 * tap_threshold : Pointer holding the value of tap_threshold
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_tap_threshold(
u8 *tap_threshold);
/*******************************************************************************
 *	Description: *//**brief This API write Threshold of the
 *	single/double tap interrupt corresponding to
 *	int_tap_th - 62.5 mg (2 g range)
 *	int_tap_th - 125 mg (4 g range)
 *	int_tap_th - 250 mg (8 g range)
 *	int_tap_th - 500 mg (16 g range)
 *	from the register 0x64 bit 0 to 4
 *
 *	\param u8 tap_threshold : The value of tap_threshold
 *
 *
 *
 *  \return results of communication routine
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_tap_threshold(
u8 tap_threshold);
/*******************************************************************************
 *	Description: *//**brief This API Reads the threshold for
 *	switching between different orientations.
 *	from the register 0x65 bit 0 and 1
 *
 *  \param u8 * orient_mode : Pointer holding the value of orient_mode
 *                           Value      Description
 *                           0b00       symmetrical
 *                           0b01       high-asymmetrical
 *                           0b10       low-asymmetrical
 *                           0b11       symmetrical
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/

BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_orient_mode(
u8 *orient_mode);
/*******************************************************************************
 *	Description: *//**brief This API write the threshold for
 *	switching between different orientations.
 *	from the register 0x65 bit 0 and 1
 *
 *  \param u8  orient_mode : the value of orient_mode
 *                           Value      Description
 *                           0b00       symmetrical
 *                           0b01       high-asymmetrical
 *                           0b10       low-asymmetrical
 *                           0b11       symmetrical
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_orient_mode(
u8 orient_mode);
/*******************************************************************************
 *	Description: *//**brief This API Reads Sets the blocking mode
 *	that is used for the generation of the orientation interrupt.
 *	from the register 0x65 bit 2 and 3
 *
 *  \param u8 * orient_blocking : Pointer holding the value of orient_blocking
 *                 Value   Description
 *                 0b00    no blocking
 *                 0b01    theta blocking or acceleration in any axis > 1.5g
 *                 0b10    theta blocking or acceleration slope in any axis >
 *                             0.2g or acceleration in any axis > 1.5g
 *                 0b11    theta blocking or acceleration slope in any axis >
 *                             0.4g or acceleration in any axis >
 *                             1.5g and value of orient is not stable
 *                             for at least 100 ms
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_orient_blocking(
u8 *orient_blocking);
/*******************************************************************************
 *	Description: *//**brief This API write Sets the blocking mode
 *	that is used for the generation of the orientation interrupt.
 *	from the register 0x65 bit 2 and 3
 *
 *  \param u8 orient_blocking : the value of orient_blocking
 *                 Value   Description
 *                 0b00    no blocking
 *                 0b01    theta blocking or acceleration in any axis > 1.5g
 *                 0b10    theta blocking or acceleration slope in any axis >
 *                             0.2g or acceleration in any axis > 1.5g
 *                 0b11    theta blocking or acceleration slope in any axis >
 *                             0.4g or acceleration in any axis >
 *                             1.5g and value of orient is not stable
 *                             for at least 100 ms
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_orient_blocking(
u8 orient_blocking);
/*******************************************************************************
 *	Description: *//**brief This API Reads Orient interrupt
 *	hysteresis; 1 LSB corresponds to 62.5 mg,
 *	irrespective of the selected g-range.
 *	from the register 0x64 bit 4 to 7
 *
 *  \param u8 * orient_hysteresis : Pointer holding
 *	the value of orient_hysteresis
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_orient_hysteresis(
u8 *orient_hysteresis);
/*******************************************************************************
 *	Description: *//**brief This API write Orient interrupt
 *	hysteresis; 1 LSB corresponds to 62.5 mg,
 *	irrespective of the selected g-range.
 *	from the register 0x64 bit 4 to 7
 *
 *  \param u8 * orient_hysteresis : The value of orient_hysteresis
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_orient_hysteresis(
u8 orient_hysteresis);
/*******************************************************************************
 *	Description: *//**brief This API Reads Orient
 *	blocking angle (0 to 44.8) from the register 0x66 bit 0 to 5
 *
 *  \param u8 * orient_theta : Pointer holding
 *	the value of orient_theta
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_orient_theta(
u8 *orient_theta);
/*******************************************************************************
 *	Description: *//**brief This API write Orient
 *	blocking angle (0 to 44.8) from the register 0x66 bit 0 to 5
 *
 *  \param u8 orient_theta : the value of orient_theta
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_orient_theta(
u8 orient_theta);
/*******************************************************************************
 *	Description: *//**brief This API Reads Change
 *	of up/down bit from the register 0x66 bit 6
 *
 *  \param u8 * orient_ud_en : Pointer holding
 *	the value of orient_ud_en
 *                  Value       Description
 *                         0    is ignored
 *                         1    generates orientation interrupt
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_orient_ud_en(
u8 *orient_ud_en);
/*******************************************************************************
 *	Description: *//**brief This API write Change
 *	of up/down bit from the register 0x66 bit 6
 *
 *  \param u8  orient_ud_en : the value of orient_ud_en
 *                  Value       Description
 *                         0    is ignored
 *                         1    generates orientation interrupt
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_orient_ud_en(
u8 orient_ud_en);
/*******************************************************************************
 *	Description: *//**brief This API Reads Change
 *	of up/down bit
 *	exchange x- and z-axis in algorithm, i.e x or z is relevant axis for
 *	upward/downward looking recognition (0=z, 1=x)
 *	from the register 0x66 bit 7
 *
 *  \param u8 * orient_axes_ex : Pointer holding
 *	the value of orient_axes_ex
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_orient_axes_ex(
u8 *orient_axes_ex);
/*******************************************************************************
 *	Description: *//**brief This API write Change
 *	of up/down bit
 *	exchange x- and z-axis in algorithm, i.e x or z is relevant axis for
 *	upward/downward looking recognition (0=z, 1=x)
 *	from the register 0x66 bit 7
 *
 *  \param u8 orient_axes_ex : the value of orient_axes_ex
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_orient_axes_ex(
u8 orient_axes_ex);
/*******************************************************************************
 *	Description: *//**brief This API Reads Flat
 *	threshold angle (0 to 44.8) for flat interrupt
 *	from the register 0x67 bit 0 to 5
 *
 *  \param u8 * flat_theta : Pointer holding
 *	the value of flat_theta
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_flat_theta(
u8 *flat_theta);
/*******************************************************************************
 *	Description: *//**brief This API write Flat
 *	threshold angle (0 to 44.8) for flat interrupt
 *	from the register 0x67 bit 0 to 5
 *
 *  \param u8 flat_theta : the value of flat_theta
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_flat_theta(
u8 flat_theta);
/*******************************************************************************
 *	Description: *//**brief This API Reads Flat interrupt hold time;
 *	delay time for which the flat value must remain stable for
 *	the flat interrupt to be generated.
 *	from the register 0x68 bit 4 and 5
 *
 *  \param u8 * flat_hold : Pointer holding the value of flat_hold
 *                      Value   Description
 *                      0b00    0 ms
 *                      0b01    512 ms
 *                      0b10    1024 ms
 *                      0b11    2048 ms
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_flat_hold(
u8 *flat_hold);
/*******************************************************************************
 *	Description: *//**brief This API write Flat interrupt hold time;
 *	delay time for which the flat value must remain stable for
 *	the flat interrupt to be generated.
 *	from the register 0x68 bit 4 and 5
 *
 *  \param u8 flat_hold : the value of flat_hold
 *                      Value   Description
 *                      0b00    0 ms
 *                      0b01    512 ms
 *                      0b10    1024 ms
 *                      0b11    2048 ms
 *
 *
 *
 *  \return results of communication routine
***************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_flat_hold(
u8 flat_hold);
/*******************************************************************************
 *	Description: *//**brief This API Reads Flat interrupt hysteresis;
 *	flat value must change by more than twice the value of
 *	int_flat_hy to detect a state change.
 *	from the register 0x68 bit 0 to 3
 *
 *  \param u8 * flat_hysteresis : Pointer holding
 *	the value of flat_hysteresis
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_flat_hysteresis(
u8 *flat_hysteresis);
/*******************************************************************************
 *	Description: *//**brief This API write Flat interrupt hysteresis;
 *	flat value must change by more than twice the value of
 *	int_flat_hy to detect a state change.
 *	from the register 0x68 bit 0 to 3
 *
 *  \param u8 flat_hysteresis : the value of flat_hysteresis
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_flat_hysteresis(
u8 flat_hysteresis);
/******************************************************************************
 *	Description: *//**brief This API Reads offset compensation
 *	target value for z-axis is:
 *	from the register 0x69 bit 0 and 1
 *
 *  \param u8 * foc_acc_z :
 *      Pointer to the foc_acc_z
 *                      Value    Description
 *                      0b00    disabled
 *                      0b01    +1 g
 *                      0b10    -1 g
 *                      0b11    0 g
 *
 *
 *  \return results of communication routine
 *
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_foc_acc_z(
u8 *foc_acc_z);
/*******************************************************************************
 *	Description: *//**brief This API Writes offset compensation
 *	target value for z-axis is:
 *	from the register 0x69 bit 0 and 1
 *
 *  \param u8 foc_acc_z :
 *    Value of the foc_acc_z
 *                     Value    Description
 *                      0b00    disabled
 *                      0b01    +1 g
 *                      0b10    -1 g
 *                      0b11    0 g
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_foc_acc_z(
u8 foc_acc_z);
/*******************************************************************************
 *	Description: *//**brief This API Reads offset compensation
 *	target value for y-axis is:
 *	from the register 0x69 bit 2 and 3
 *
 *  \param u8 * foc_acc_y :
 *      Pointer to the foc_acc_y
 *                     Value    Description
 *                      0b00    disabled
 *                      0b01    +1 g
 *                      0b10    -1 g
 *                      0b11    0 g
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_foc_acc_y(
u8 *foc_acc_y);
/*******************************************************************************
 *	Description: *//**brief This API Writes offset compensation
 *	target value for y-axis is:
 *	from the register 0x69 bit 2 and 3
 *
 *  \param u8 foc_acc_y :
 *    Value of the foc_acc_y
 *					 Value    Description
 *                      0b00    disabled
 *                      0b01    +1 g
 *                      0b10    -1 g
 *                      0b11    0 g
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_foc_acc_y(
u8 foc_acc_y);
/*******************************************************************************
 *	Description: *//**brief This API Reads offset compensation
 *	target value for x-axis is:
 *	from the register 0x69 bit 4 and 5
 *
 *  \param u8 * foc_acc_x :
 *      Pointer to the foc_acc_x
 *                     Value    Description
 *                      0b00    disabled
 *                      0b01    +1 g
 *                      0b10    -1 g
 *                      0b11    0 g
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_foc_acc_x(
u8 *foc_acc_x);
/*******************************************************************************
 *	Description: *//**brief This API Writes offset compensation
 *	target value for x-axis is:
 *	from the register 0x69 bit 4 and 5
 *
 *  \param u8 foc_acc_x :
 *    Value of the foc_acc_x
 *                     Value    Description
 *                      0b00    disabled
 *                      0b01    +1 g
 *                      0b10    -1 g
 *                      0b11    0 g
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_foc_acc_x(
u8 foc_acc_x);
/*******************************************************************************
 * Description: *//**brief This API Writes Enables fast offset
 * compensation for all three axis of the gyro
 *                          Value       Description
 *                              0       fast offset compensation disabled
 *                              1       fast offset compensation enabled
 *
 *  \param u8 foc_gyr_en :
 *    Value of the foc_gyr_en
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_foc_gyr_en(
u8 foc_gyr_en, s16 *gyr_off_x, s16 *gyr_off_y, s16 *gyr_off_z);
/*******************************************************************************
 * Description: *//**brief This API Reads Enable
 * NVM programming form the register 0x6A bit 1
 *             Value    Description
 *                0     disable
 *                1     enable
 *
 *  \param u8 * nvm_prog_en :
 *      Pointer to the nvm_prog_en
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_nvm_prog_en(
u8 *nvm_prog_en);
/*******************************************************************************
 * Description: *//**brief This API Writes Enable
 * NVM programming from the register 0x6A bit 1
 *             Value    Description
 *                0     disable
 *                1     enable
 *
 *  \param u8 nvm_prog_en :
 *    Value of the nvm_prog_en
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_nvm_prog_en(
u8 nvm_prog_en);
/*******************************************************************************
 * Description: *//**brief This API Reads to Configure SPI
 * Interface Mode for primary and OIS interface
 * from the register 0x6B bit 0
 *                     Value    Description
 *                         0    SPI 4-wire mode
 *                         1    SPI 3-wire mode
 *
 *  \param u8 * spi3 :
 *      Pointer to the spi3
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/

BMI160_RETURN_FUNCTION_TYPE bmi160_get_spi3(
u8 *spi3);
/*******************************************************************************
 * Description: *//**brief This API Writes  to Configure SPI
 * Interface Mode for primary and OIS interface
 * from the register 0x6B bit 0
 *                     Value    Description
 *                         0    SPI 4-wire mode
 *                         1    SPI 3-wire mode
 *
 *  \param u8 spi3 :
 *    Value of the spi3
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_spi3(
u8 spi3);
/*******************************************************************************
 * Description: *//**brief This API Reads Enables fast offset
 * compensation for all three axis of the gyro
 *                          Value       Description
 *                              0       fast offset compensation disabled
 *                              1       fast offset compensation enabled
 *
 *  \param u8 * foc_gyr_en :
 *      Pointer to the foc_gyr_en
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_foc_gyr_en(
u8 *foc_gyr_en);
/*******************************************************************************
 * Description: *//**brief This API Reads Select timer
 * period for I2C Watchdog from the register 0x70 bit 1
 *            Value     Description
 *              0       I2C watchdog timeout after 1 ms
 *              1       I2C watchdog timeout after 50 ms
 *
 *  \param u8 * i2c_wdt_sel :
 *      Pointer to the i2c_wdt_sel
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_i2c_wdt_sel(
u8 *i2c_wdt_sel);
/*******************************************************************************
 * Description: *//**brief This API Writes  Select timer
 * period for I2C Watchdog from the register 0x70 bit 1
 *            Value     Description
 *              0       I2C watchdog timeout after 1 ms
 *              1       I2C watchdog timeout after 50 ms
 *
 *  \param u8 i2c_wdt_sel :
 *    Value of the i2c_wdt_sel
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE
bmi160_set_i2c_wdt_sel(u8 i2c_wdt_sel);
/*******************************************************************************
 * Description: *//**brief This API Reads I2C Watchdog
 * at the SDI pin in I2C interface mode
 * from the register 0x70 bit 2
 *                 Value        Description
 *                   0  Disable I2C watchdog
 *                   1  Enable I2C watchdog
 *
 *  \param u8 * i2c_wdt_en :
 *      Pointer to the i2c_wdt_en
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_i2c_wdt_en(
u8 *i2c_wdt_en);
/*******************************************************************************
 * Description: *//**brief This API Reads I2C Watchdog
 * at the SDI pin in I2C interface mode
 * from the register 0x70 bit 2
 *                 Value        Description
 *                   0  Disable I2C watchdog
 *                   1  Enable I2C watchdog
 *
 *  \param u8 * i2c_wdt_en :
 *      Pointer to the i2c_wdt_en
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_i2c_wdt_en(
u8 i2c_wdt_en);
/*******************************************************************************
 * Description: *//**brief This API Reads I2C Watchdog
 * at the SDI pin in I2C interface mode
 * from the register 0x6B bit 4 and 5
 *          Value        Description
 *          0b00 Primary interface:autoconfig / secondary interface:off
 *          0b01 Primary interface:I2C / secondary interface:OIS
 *          0b10 Primary interface:autoconfig/secondary interface:Magnetometer
 *          0b11 Reserved
 *  \param u8 if_mode :
 *    Value of the if_mode
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_if_mode(
u8 *if_mode);
/******************************************************************************
 * Description: *//**brief This API Writes   I2C Watchdog
 * at the SDI pin in I2C interface mode
 * from the register 0x6B bit 4 and 5
 *          Value        Description
 *          0b00 Primary interface:autoconfig / secondary interface:off
 *          0b01 Primary interface:I2C / secondary interface:OIS
 *          0b10 Primary interface:autoconfig/secondary interface:Magnetometer
 *          0b11 Reserved
 *  \param u8 if_mode :
 *    Value of the if_mode
 *
 *
 *
 *  \return results of communication routine
 *
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_if_mode(
u8 if_mode);
/*******************************************************************************
 * Description: *//**brief This API Reads
 *           Gyro sleep trigger. when both trigger conditions are enabled,
 *           one is sufficient to trigger the transition.
 *			 from the register 0x6C bit 0 to 2
 *            Value     Description
 *            0b000     nomotion: no / Not INT1 pin: no / INT2 pin: no
 *            0b001     nomotion: no / Not INT1 pin: no / INT2 pin: yes
 *            0b010     nomotion: no / Not INT1 pin: yes / INT2 pin: no
 *            0b011     nomotion: no / Not INT1 pin: yes / INT2 pin: yes
 *            0b100     nomotion: yes / Not INT1 pin: no / INT2 pin: no
 *            0b001     anymotion: yes / Not INT1 pin: no / INT2 pin: yes
 *            0b010     anymotion: yes / Not INT1 pin: yes / INT2 pin: no
 *            0b011     anymotion: yes / Not INT1 pin: yes / INT2 pin: yes
 *
 *  \param u8 * gyro_sleep_trigger :
 *      Pointer to the gyro_sleep_trigger
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_gyro_sleep_trigger(
u8 *gyro_sleep_trigger);
/*******************************************************************************
 * Description: *//**brief This API Writes
 *           Gyro sleep trigger. when both trigger conditions are enabled,
 *           one is sufficient to trigger the transition.
 *			 from the register 0x6C bit 0 to 2
 *            Value     Description
 *            0b000     nomotion: no / Not INT1 pin: no / INT2 pin: no
 *            0b001     nomotion: no / Not INT1 pin: no / INT2 pin: yes
 *            0b010     nomotion: no / Not INT1 pin: yes / INT2 pin: no
 *            0b011     nomotion: no / Not INT1 pin: yes / INT2 pin: yes
 *            0b100     nomotion: yes / Not INT1 pin: no / INT2 pin: no
 *            0b001     anymotion: yes / Not INT1 pin: no / INT2 pin: yes
 *            0b010     anymotion: yes / Not INT1 pin: yes / INT2 pin: no
 *            0b011     anymotion: yes / Not INT1 pin: yes / INT2 pin: yes
 *
 *  \param u8 gyro_sleep_trigger :
 *    Value of the gyro_sleep_trigger
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_gyro_sleep_trigger(
u8 gyro_sleep_trigger);
/*******************************************************************************
 * Description: *//**brief This API Reads
 *           Gyro wakeup trigger. When both trigger conditions are enabled,
 *           both conditions must be active to trigger the transition
 *			from the register 0x6C bit 3 and 4
 *             Value    Description
 *             0b00     anymotion: no / INT1 pin: no
 *             0b01     anymotion: no / INT1 pin: yes
 *             0b10     anymotion: yes / INT1 pin: no
 *             0b11     anymotion: yes / INT1 pin: yes
 *
 *  \param u8 * gyro_wakeup_trigger :
 *      Pointer to the gyro_wakeup_trigger
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_gyro_wakeup_trigger(
u8 *gyro_wakeup_trigger);
/*******************************************************************************
 * Description: *//**brief This API Writes
 *           Gyro wakeup trigger. When both trigger conditions are enabled,
 *           both conditions must be active to trigger the
 *			from the register 0x6C bit 3 and 4
 *             Value    Description
 *             0b00     anymotion: no / INT1 pin: no
 *             0b01     anymotion: no / INT1 pin: yes
 *             0b10     anymotion: yes / INT1 pin: no
 *             0b11     anymotion: yes / INT1 pin: yes
 *
 *  \param u8 gyro_wakeup_trigger :
 *    Value of the gyro_wakeup_trigger
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_gyro_wakeup_trigger(
u8 gyro_wakeup_trigger);
/*******************************************************************************
 * Description: *//**brief This API Reads
 *           Target state for gyro sleep mode
 *			from the register 0x6C bit 5
 *            Value     Description
 *               0      Sleep transition to fast wake up state
 *               1      Sleep transition to suspend state
 *
 *  \param u8 * gyro_sleep_state :
 *      Pointer to the gyro_sleep_state
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_gyro_sleep_state(
u8 *gyro_sleep_state);
/*******************************************************************************
 * Description: *//**brief This API Writes
 *           Target state for gyro sleep mode
 *			from the register 0x6C bit 5
 *            Value     Description
 *               0      Sleep transition to fast wake up state
 *               1      Sleep transition to suspend state
 *
 *  \param u8 gyro_sleep_state :
 *    Value of the gyro_sleep_state
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_gyro_sleep_state(
u8 gyro_sleep_state);
/*******************************************************************************
 * Description: *//**brief This API Reads
 *           Trigger an interrupt when a gyro wakeup
 *			from the register 0x6C bit 6
 *           is triggered
 *            Value     Description
 *                0     Disabled
 *                1     Enabled
 *
 *  \param u8 * gyro_wakeup_int :
 *      Pointer to the gyro_wakeup_int
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_gyro_wakeup_int(
u8 *gyro_wakeup_int);
/*******************************************************************************
 * Description: *//**brief This API Writes
 *           Trigger an interrupt when a gyro wakeup
 *           is triggered
 *			from the register 0x6C bit 6
 *            Value     Description
 *                0     Disabled
 *                1     Enabled
 *
 *  \param u8 gyro_wakeup_int :
 *    Value of the gyro_wakeup_int
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_gyro_wakeup_int(
u8 gyro_wakeup_int);
/*******************************************************************************
 * Description: *//**brief This API Reads
 *          select axis to be self-tested:
 *             Value    Description
 *              0b00    disabled
 *              0b01    x-axis
 *              0b10    y-axis
 *              0b10    z-axis
 *		from the register 0x6D bit 0 and 1
 *
 *  \param u8 * acc_selftest_axis :
 *      Pointer to the acc_selftest_axis
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_acc_selftest_axis(
u8 *acc_selftest_axis);
/*******************************************************************************
 * Description: *//**brief This API Writes
 *          select axis to be self-tested:
 *             Value    Description
 *              0b00    disabled
 *              0b01    x-axis
 *              0b10    y-axis
 *              0b10    z-axis
 *		from the register 0x6D bit 0 and 1
 *
 *  \param u8 acc_selftest_axis :
 *    Value of the acc_selftest_axis
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_acc_selftest_axis(
u8 acc_selftest_axis);
/*******************************************************************************
 * Description: *//**brief This API Reads
 *          select sign of self-test excitation as
 *            Value     Description
 *              0       negative
 *              1       positive
 *		from the register 0x6D bit 2
 *
 *  \param u8 * acc_selftest_sign :
 *      Pointer to the acc_selftest_sign
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_acc_selftest_sign(
u8 *acc_selftest_sign);
/*******************************************************************************
 * Description: *//**brief This API Writes
 *          select sign of self-test excitation as
 *            Value     Description
 *              0       negative
 *              1       positive
 *		from the register 0x6D bit 2
 *
 *  \param u8 acc_selftest_sign :
 *    Value of the acc_selftest_sign
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_acc_selftest_sign(
u8 acc_selftest_sign);
/*******************************************************************************
 * Description: *//**brief This API Reads
 *        select amplitude of the selftest deflection:
 *                    Value     Description
 *                           0  low
 *                           1  high
 *		from the register 0x6D bit 3
 *
 *  \param u8 * acc_selftest_amp :
 *      Pointer to the acc_selftest_amp
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_acc_selftest_amp(
u8 *acc_selftest_amp);
/*******************************************************************************
 * Description: *//**brief This API Writes
  *        select amplitude of the selftest deflection:
 *                    Value     Description
 *                           0  low
 *                           1  high
 *		from the register 0x6D bit 3
 *
 *
 *  \param u8 acc_selftest_amp :
 *    Value of the acc_selftest_amp
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_acc_selftest_amp(
u8 acc_selftest_amp);
/******************************************************************************
 * Description: *//**brief This API Reads
 *        gyr_self_test_star
 *                    Value     Description
 *                           0  low
 *                           1  high
 *		from the register 0x6D bit 4
 *
 *  \param u8 * gyr_self_test_start:
 *      Pointer to the gyr_self_test_start
 *
 *
 *
 *  \return results of communication routine
 *
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_gyr_self_test_start(
u8 *gyr_self_test_start);
/*******************************************************************************
 * Description: *//**brief This API Writes
 *        select amplitude of the selftest deflection:
 *                    Value     Description
 *                           0  low
 *                           1  high
 *		from the register 0x6D bit 4
 *
 *
 *  \param u8 gyr_self_test_start :
 *    Value of the gyr_self_test_start
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_gyr_self_test_start(
u8 gyr_self_test_start);
/******************************************************************************
 * Description: *//**brief This API Reads
 *        spi_en
 *                    Value     Description
 *                           0  I2C Enable
 *                           1  I2C Disable
 *		from the register 0x70 bit 0
 *
 *  \param u8 * spi_en:
 *      Pointer to the spi_en
 *
 *
 *
 *  \return results of communication routine
 *
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/

BMI160_RETURN_FUNCTION_TYPE bmi160_get_spi_enable(
u8 *spi_en);
/*******************************************************************************
 * Description: *//**brief This API Writes spi enable
 *		from the register 0x70 bit 0
 *
 *
 *  \param u8 spi_en :
 *    Value of the spi_en
 *
 *                  Value     Description
 *                           0  SPI Enable
 *                           1  SPI Disable
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_spi_enable(
u8 spi_en);
/******************************************************************************
 * Description: *//**brief This API Reads
 *	spare0_trim from the register 0x70 bit 3
 *
 *
 *
 *  \param u8 * spare0_trim:
 *      Pointer to the spare0_trim
 *
 *
 *
 *  \return results of communication routine
 *
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_spare0_trim
(u8 *spare0_trim);
/*******************************************************************************
 * Description: *//**brief This API Writes
 *	spare0_trim from the register 0x70 bit 3
 *
 *  \param u8 spare0_trim :
 *    Value of the spare0_trim
 *
 *
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_spare0_trim
(u8 spare0_trim);
/******************************************************************************
 *	Description: *//**brief This API Reads
 *	nvm_counter from the register 0x70 bit 4 to 7
 *
 *
 *
 *  \param u8 * nvm_counter:
 *      Pointer to the nvm_counter
 *
 *
 *
 *  \return results of communication routine
 *
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_nvm_counter(
u8 *nvm_counter);
/*******************************************************************************
 *	Description: *//**brief This API Writes
 *	nvm_counter from the register 0x70 bit 4
 *
 *
 *  \param u8 nvm_counter :
 *    Value of the nvm_counter
 *
 *
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_nvm_counter(
u8 nvm_counter);
/******************************************************************************
 *	Description: *//**brief This API Reads
 *	acc_off_x from the register 0x71 bit 0 to 7
 *
 *
 *
 *  \param s8 * acc_off_x:
 *      Pointer to the acc_off_x
 *
 *
 *
 *  \return results of communication routine
 *
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_acc_off_comp_xaxis(
s8 *acc_off_x);
/*******************************************************************************
 *	Description: *//**brief This API Writes
 *	acc_off_x from the register 0x71 bit 0 to 7
 *
 *  \param s8 acc_off_x :
 *    Value of the acc_off_x
 *
 *
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_accel_offset_compensation_xaxis(
s8 acc_off_x);
/******************************************************************************
 *	Description: *//**brief This API Reads
 *	acc_off_y from the register 0x72 bit 0 to 7
 *
 *
 *
 *  \param s8 * acc_off_y:
 *      Pointer to the acc_off_y
 *
 *
 *
 *  \return results of communication routine
 *
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_acc_off_comp_yaxis(
s8 *acc_off_x);
/*******************************************************************************
 *	Description: *//**brief This API Writes
 *	acc_off_y from the register 0x72 bit 0 to 7
 *
 *  \param s8 acc_off_y :
 *    Value of the acc_off_y
 *
 *
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_accel_offset_compensation_yaxis(
s8 acc_off_y);
/******************************************************************************
 *	Description: *//**brief This API Reads
 *	acc_off_z from the register 0x73 bit 0 to 7
 *
 *
 *
 *  \param s8 * acc_off_z:
 *      Pointer to the acc_off_z
 *
 *
 *
 *  \return results of communication routine
 *
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_acc_off_comp_zaxis(
s8 *acc_off_z);
/*******************************************************************************
 *	Description: *//**brief This API Writes
 *	acc_off_z from the register 0x73 bit 0 to 7
 *
 *  \param s8 acc_off_z :
 *    Value of the acc_off_z
 *
 *
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_accel_offset_compensation_zaxis(
s8 acc_off_z);
/******************************************************************************
 *	Description: *//**brief This API Reads
 *	gyr_off_x from the register 0x74 bit 0 to 7
 *
 *
 *
 *
 *  \param s16 * gyr_off_x:
 *      Pointer to the gyr_off_x
 *
 *
 *
 *  \return results of communication routine
 *
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_gyro_off_comp_xaxis(
s16 *gyr_off_x);
/*******************************************************************************
 *	Description: *//**brief This API Writes
 *	gyr_off_x from the register 0x74 bit 0 to 7
 *
 *  \param s16 gyr_off_x :
 *    Value of the gyr_off_x
 *
 *
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_gyro_offset_compensation_xaxis(
s16 gyr_off_x);
/******************************************************************************
 *	Description: *//**brief This API Reads
 *	gyr_off_y from the register 0x75 bit 0 to 7
 *
 *
 *
 *  \param s16 * gyr_off_y:
 *      Pointer to the gyr_off_y
 *
 *
 *
 *  \return results of communication routine
 *
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_gyro_off_comp_yaxis(
s16 *gyr_off_y);
/*******************************************************************************
 *	Description: *//**brief This API Writes
 *	gyr_off_y from the register 0x75 bit 0 to 7
 *
 *  \param s16 gyr_off_y :
 *    Value of the gyr_off_y
 *
 *
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_gyro_offset_compensation_yaxis(
s16 gyr_off_y);
/******************************************************************************
 *	Description: *//**brief This API Reads
 *	gyr_off_z from the register 0x76 bit 0 to 7
 *
 *
 *
 *  \param s16 * gyr_off_z:
 *      Pointer to the gyr_off_z
 *
 *
 *
 *  \return results of communication routine
 *
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_gyro_off_comp_zaxis(
s16 *gyr_off_z);
/*******************************************************************************
 *	Description: *//**brief This API Writes
 *	gyr_off_z from the register 0x76 bit 0 to 7
 *
 *  \param s16 gyr_off_z :
 *    Value of the gyr_off_z
 *
 *
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_gyro_offset_compensation_zaxis(
s16 gyr_off_z);
/*******************************************************************************
 *	Description: *//**brief This API Writes fast offset compensation
 *	target value for foc_acc \
 *	from the register 0x69 bit 6
 *
 *  \param u8 foc_acc_z:
 *    Value of the foc_acc_z
 *	Value    Description
 *	0b00    disabled
 *	0b01    +1 g
 *	0b10    -1 g
 *	0b11    0 g
 *  \param u8 axis:
 *	Value    Description
 *	0		FOC_X_AXIS
 *	1		FOC_Y_AXIS
 *	2		FOC_Z_AXIS
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_accel_foc_trigger(u8 axis,
u8 foc_acc, s8 *accel_offset);
/*******************************************************************************
 * Description: *//**brief This API Writes fast offset compensation
 * target value for z-foc_accx, foc_accx and foc_accx.
 *                     Value    Description
 *                      0b00    disabled
 *                      0b01	+1g
 *                      0b10	-1g
 *                      0b11	0g
 *
 *  \param u8 foc_accx, foc_accy, foc_accz :
 *    Value of the foc_accx, foc_accy, foc_accz
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_accel_foc_trigger_xyz(u8 foc_accx,
u8 foc_accy, u8 foc_accz, s8 *acc_off_x, s8 *acc_off_y, s8 *acc_off_z);
/******************************************************************************
 *	Description: *//**brief This API Reads
 *	cc_off_en from the register 0x77 bit 6
 *
 *
 *
 *  \param u8 * acc_off_en:
 *      Pointer to the acc_off_en
 *                   0 - Disabled
 *                   1 - Enabled
 *
 *
 *
 *  \return results of communication routine
 *
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_accel_offset_enable(
u8 *acc_off_en);
/*******************************************************************************
 * Description: *//**brief This API Writes
 *	cc_off_en from the register 0x77 bit 6
 *
 *  \param u8 acc_off_en :
 *    Value of the acc_off_en
 *
 *
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_accel_offset_enable(
u8 acc_off_en);
/******************************************************************************
 * Description: *//**brief This API Reads
 *	gyr_off_en from the register 0x77 bit 7
 *
 *
 *
 *  \param u8 * gyr_off_en:
 *      Pointer to the gyr_off_en
 *                   0 - Disabled
 *                   1 - Enabled
 *
 *
 *
 *  \return results of communication routine
 *
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_gyro_offset_enable(
u8 *gyr_off_en);
/*******************************************************************************
 *	Description: *//**brief This API Writes
 *	gyr_off_en from the register 0x77 bit 7
 *
 *  \param u8 gyr_off_en :
 *    Value of the gyr_off_en
 *
 *
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_gyro_offset_enable(
u8 gyr_off_en);
/*****************************************************************************
 *	Description: *//**brief This API reads step counter value
 *	form the register 0x78 and 0x79
 *
 *
 *
 *
 *  \param s16 * step_cnt : Pointer holding the value of step_cnt
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_read_step_count(s16 *step_cnt);
/******************************************************************************
 *	Description: *//**brief This API Reads
 *	step counter configuration
 *	from the register 0x7A bit 0 to 7
 *	and from the register 0x7B bit 0 to 2 and 4 to 7
 *
 *
 *  \param u16 * step_conf   :
 *      Pointer holding the value of  step configuration
 *
 *  \return results of communication routine
 *
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_step_configuration(
u16 *step_conf);
/******************************************************************************
 *	Description: *//**brief This API Reads
 *	step counter configuration
 *	from the register 0x7A bit 0 to 7
 *	and from the register 0x7B bit 0 to 2 and 4 to 7
 *
 *
 *  \param u8  step_conf   :
 *      the value of  Enable step configuration
 *
 *  \return results of communication routine
 *
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_step_configuration(
u16 step_conf);
/******************************************************************************
 *	Description: *//**brief This API Reads
 *	Enable step counter
 *	from the register 0x7B bit 3
 *
 *
 *  \param u8 * step_cnt_en   :
 *      Pointer holding the value of  Enable step counter
 *
 *  \return results of communication routine
 *
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_step_counter_enable(u8 *step_cnt_en);
/******************************************************************************
 *	Description: *//**brief This API Reads
 *	Enable step counter
 *	from the register 0x7B bit 3
 *
 *
 *  \param u8 * step_cnt_en   :
 *      Pointer holding the value of  Enable step counter
 *
 *  \return results of communication routine
 *
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_step_counter_enable(u8 step_cnt_en);
/******************************************************************************
 *	Description: *//**brief This API get
 *	Step counter modes
 *
 *
 *  \param u8 step_mode   :
 *      The value of step counter mode
 *
 *  \return results of communication routine
 *
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_step_mode(u8 step_mode);
/******************************************************************************
 *	Description: *//**brief This API used to trigger the  signification motion
 *	interrupt
 *
 *
 *  \param u8 sig_map_interrupt   : The value of interrupt selection
 *
 *      BMI160_MAP_INT1	0
 *      BMI160_MAP_INT2	1
 *
 *  \return results of communication routine
 *
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_map_significant_motion_interrupt(
u8 sig_map_interrupt);
/******************************************************************************
 *	Description: *//**brief This API used to trigger the  step detector
 *	interrupt
 *
 *
 *  \param u8 step_det_map   : The value of interrupt selection
 *
 *      BMI160_MAP_INT1	0
 *      BMI160_MAP_INT2	1
 *
 *  \return results of communication routine
 *
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_map_step_detector_interrupt(
u8 step_det_map);
/******************************************************************************
 *	Description: *//**brief This API used to clear the step counter interrupt
 *	interrupt
 *
 *
 *  \param  : None
 *
 *
 *  \return results of communication routine
 *
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_clear_step_counter(void);
/*******************************************************************************
 *	Description: *//**brief This API Writes
 *	from the register 0x7E bit 0 to 7
 *
 *
 *  \param u8 cmd_reg :
 *    Value of the cmd_reg
 *
 *
 *	0x00	-	Reserved
 *  0x03	-	Starts fast offset calibration for the accel and gyro
 *	0x10	-	Sets the PMU mode for the Accelerometer to suspend
 *	0x11	-	Sets the PMU mode for the Accelerometer to normal
 *	0x12	-	Sets the PMU mode for the Accelerometer to Lowpower
 *  0x14	-	Sets the PMU mode for the Gyroscope to suspend
 *	0x15	-	Sets the PMU mode for the Gyroscope to normal
 *	0x16	-	Reserved
 *	0x17	-	Sets the PMU mode for the Gyroscope to fast start-up
 *  0x18	-	Sets the PMU mode for the Magnetometer to suspend
 *	0x19	-	Sets the PMU mode for the Magnetometer to normal
 *	0x1A	-	Sets the PMU mode for the Magnetometer to Lowpower
 *	0xB0	-	Clears all data in the FIFO
 *  0xB1	-	Resets the interrupt engine
 *	0xB6	-	Triggers a reset
 *	0x37	-	See extmode_en_last
 *	0x9A	-	See extmode_en_last
 *	0xC0	-	Enable the extended mode
 *  0xC4	-	Erase NVM cell
 *	0xC8	-	Load NVM cell
 *	0xF0	-	Reset acceleration data path
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_command_register(
u8 cmd_reg);
/******************************************************************************
 *	Description: *//**brief This API Reads
 *	target page from the register 0x7F bit 4 and 5
 *
 *
 *
 *  \param u8 * tar_pg:
 *      Pointer to the tar_pg
 *                   00 - User data/configure page
 *                   01 - Chip level trim/test page
 *					 10	- Accelerometer trim
 *					 11 - Gyroscope trim
 *
 *  \return results of communication routine
 *
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_target_page(
u8 *tar_pg);
/*******************************************************************************
 *	Description: *//**brief This API Writes
 *	target page from the register 0x7F bit 4 and 5
 *
 *  \param u8 tar_pg :
 *    Value of the tar_pg
 *
 *
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_target_page(
u8 tar_pg);
/******************************************************************************
 *	Description: *//**brief This API Reads
 *	page enable from the register 0x7F bit 7
 *
 *
 *
 *  \param u8 * pg_en:
 *      Pointer to the pg_en
 *                   0 - Disabled
 *                   1 - Enabled
 *
 *
 *
 *  \return results of communication routine
 *
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_paging_enable(
u8 *pg_en);
/*******************************************************************************
 *	Description: *//**brief This API Writes
 *	page enable from the register 0x7F bit 7
 *
 *  \param u8 pg_en :
 *    Value of the pg_en
 *
 *				     0 - Disabled
 *                   1 - Enabled
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_paging_enable(
u8 pg_en);
/******************************************************************************
 *	Description: *//**brief This API Reads
 *	pull up configuration from the register 0X85 bit 4 an 5
 *
 *
 *
 *  \param u8 * control_pullup:
 *      Pointer to the control_pullup
 *                   0 - Disabled
 *                   1 - Enabled
 *
 *
 *
 *  \return results of communication routine
 *
 *
 *****************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_pullup_configuration(
u8 *control_pullup);
/*******************************************************************************
 *	Description: *//**brief This API Writes
 *	pull up configuration from the register 0X85 bit 4 an 5
 *
 *  \param u8 control_pullup :
 *    Value of the control_pullup
 *
 *				     0 - Disabled
 *                   1 - Enabled
 *
 *
 *
 *  \return results of communication routine
 *
 *
 ******************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_pullup_configuration(
u8 control_pullup);
/***************************************************************************
 *	Description: This function used for initialize the magnetometer
 *
 *
 *  \return results of communication routine
 *
 *
 ***************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 *************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_magnetometer_interface_init(void);
/***************************************************************************
 *	Description: This function used for read the trim values of magnetometer
 *
 *	Before reading the mag trimming values
 *	make sure the following two points are addressed
 *	1.	Make sure the mag interface is enabled or not,
 *		by using the bmi160_get_if_mode() function.
 *		If mag interface is not enabled set the value of 0x02
 *		to the function bmi160_get_if_mode(0x02)
 *	2.	And also confirm the secondary-interface power mode
 *		is not in the SUSPEND mode.
 *		by using the function bmi160_get_mag_pmu_status().
 *		If the secondary-interface power mode is in SUSPEND mode
 *		set the value of 0x19(NORMAL mode)/0x1A(LOWPOWER) by using the
 *		bmi160_set_command_register(0x19) function.
 *
 *  \return results of communication routine
 *
 *
 ***************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 *************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_read_mag_trim(
void);
/***************************************************************************
 *	Description: This function used for read the compensated value of mag
 *	Before start reading the mag compensated data's
 *	make sure the following two points are addressed
 *	1.	Make sure the mag interface is enabled or not,
 *		by using the bmi160_get_if_mode() function.
 *		If mag interface is not enabled set the value of 0x02
 *		to the function bmi160_get_if_mode(0x02)
 *	2.	And also confirm the secondary-interface power mode
 *		is not in the SUSPEND mode.
 *		by using the function bmi160_get_mag_pmu_status().
 *		If the secondary-interface power mode is in SUSPEND mode
 *		set the value of 0x19(NORMAL mode)/0x1A(LOWPOWER) by using the
 *		bmi160_set_command_register(0x19) function.
 *
 *  \return results of communication routine
 *
 *
 ***************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 *************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_mag_compensate_xyz(
struct bmi160_mag_xyz *mag_comp_xyz);
/*****************************************************************************
 *	Description: *//**\brief This API used to get the compensated Z data
 *	the out put of Z as s16
 *	Before start reading the mag compensated X data
 *	make sure the following two points are addressed
 *	1.	Make sure the mag interface is enabled or not,
 *		by using the bmi160_get_if_mode() function.
 *		If mag interface is not enabled set the value of 0x02
 *		to the function bmi160_get_if_mode(0x02)
 *	2.	And also confirm the secondary-interface power mode
 *		is not in the SUSPEND mode.
 *		by using the function bmi160_get_mag_pmu_status().
 *		If the secondary-interface power mode is in SUSPEND mode
 *		set the value of 0x19(NORMAL mode)/0x1A(LOWPOWER) by using the
 *		bmi160_set_command_register(0x19) function.
 *
 *
 *  \param s16 mdata_z : The value of Z data
 *			u16 data_r : The value of R data
 *
 *	\return results of compensated Z data value output as s16
 *
 ***************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
s16 bmi160_mag_compensate_X(s16 mdata_x, u16 data_r);
/*****************************************************************************
 *	Description: *//**\brief This API used to get the compensated Z data
 *	the out put of Z as s16
 *	Before start reading the mag compensated Y data
 *	make sure the following two points are addressed
 *	1.	Make sure the mag interface is enabled or not,
 *		by using the bmi160_get_if_mode() function.
 *		If mag interface is not enabled set the value of 0x02
 *		to the function bmi160_get_if_mode(0x02)
 *	2.	And also confirm the secondary-interface power mode
 *		is not in the SUSPEND mode.
 *		by using the function bmi160_get_mag_pmu_status().
 *		If the secondary-interface power mode is in SUSPEND mode
 *		set the value of 0x19(NORMAL mode)/0x1A(LOWPOWER) by using the
 *		bmi160_set_command_register(0x19) function.
 *
 *
 *  \param s16 mdata_z : The value of Z data
 *			u16 data_r : The value of R data
 *
 *	\return results of compensated Z data value output as s16
 *
 ***************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
s16 bmi160_mag_compensate_Y(s16 mdata_y, u16 data_r);
/*****************************************************************************
 *	Description: *//**\brief This API used to get the compensated Z data
 *	the out put of Z as s16
 *	Before start reading the mag compensated Z data
 *	make sure the following two points are addressed
 *	1.	Make sure the mag interface is enabled or not,
 *		by using the bmi160_get_if_mode() function.
 *		If mag interface is not enabled set the value of 0x02
 *		to the function bmi160_get_if_mode(0x02)
 *	2.	And also confirm the secondary-interface power mode
 *		is not in the SUSPEND mode.
 *		by using the function bmi160_get_mag_pmu_status().
 *		If the secondary-interface power mode is in SUSPEND mode
 *		set the value of 0x19(NORMAL mode)/0x1A(LOWPOWER) by using the
 *		bmi160_set_command_register(0x19) function.
 *
 *
 *  \param s16 mdata_z : The value of Z data
 *			u16 data_r : The value of R data
 *
 *	\return results of compensated Z data value output as s16
 *
 ***************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
s16 bmi160_mag_compensate_Z(s16 mdata_z, u16 data_r);
/*****************************************************************************
 *	Description: *//**\brief This API used to set the pre-set modes
 *	The pre-set mode setting is depend on data rate, xy and z repetitions
 *
 *	Before set the mag preset mode
 *	make sure the following two points are addressed
 *	1.	Make sure the mag interface is enabled or not,
 *		by using the bmi160_get_if_mode() function.
 *		If mag interface is not enabled set the value of 0x02
 *		to the function bmi160_get_if_mode(0x02)
 *	2.	And also confirm the secondary-interface power mode
 *		is not in the SUSPEND mode.
 *		by using the function bmi160_get_mag_pmu_status().
 *		If the secondary-interface power mode is in SUSPEND mode
 *		set the value of 0x19(NORMAL mode)/0x1A(LOWPOWER) by using the
 *		bmi160_set_command_register(0x19) function.
 *
 *
 *  \param u8 mode: The value of pre-set mode selection value
 *
 *	BMI160_MAG_PRESETMODE_LOWPOWER                  1
 *	BMI160_MAG_PRESETMODE_REGULAR                   2
 *	BMI160_MAG_PRESETMODE_HIGHACCURACY              3
 *	BMI160_MAG_PRESETMODE_ENHANCED                  4
 *
 *	\return results of bus communication function
 *
 ***************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 ******************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_mag_presetmode(u8 mode);
/***************************************************************************
 *	Description: This function used for set the magnetometer
 *	power mode.
 *	Before set the mag power mode
 *	make sure the following point is addressed
 *	1.	Make sure the mag interface is enabled or not,
 *		by using the bmi160_get_if_mode() function.
 *		If mag interface is not enabled set the value of 0x02
 *		to the function bmi160_get_if_mode(0x02)
 *
 *	\param mag_pow_mode : The value of mag power mode
 *
 *	FORCE_MODE		0
 *	SUSPEND_MODE	1
 *
 *
 *  \return results of communication routine
 *
 *
 ***************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 *************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_mag_set_powermode(u8 mag_pow_mode);
/***************************************************************************
 *	Description: This function used for set the magnetometer
 *	power mode.
 *	Before set the mag power mode
 *	make sure the following point is addressed
 *	1.	Make sure the mag interface is enabled or not,
 *		by using the bmi160_get_if_mode() function.
 *		If mag interface is not enabled set the value of 0x02
 *		to the function bmi160_get_if_mode(0x02)
 *
 *	\param mag_sec_if_pow_mode : The value of mag power mode
 *
 *	BMI160_MAG_FORCE_MODE		0
 *	BMI160_MAG_SUSPEND_MODE		1
 *
 *
 *  \return results of communication routine
 *
 *
 ***************************************************************************/
/* Scheduling:
 *
 *
 *
 * Usage guide:
 *
 *
 * Remarks:
 *
 *************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_set_mag_and_secondary_if_powermode(
u8 mag_sec_if_pow_mode);

BMI160_RETURN_FUNCTION_TYPE bmi160_mag_compensate_xyz_raw(
struct bmi160_mag_xyz *mag_comp_xyz, struct bmi160mag_t mag_xyzr);

#endif
