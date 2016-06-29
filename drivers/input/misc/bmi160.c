/*
* @section LICENSE
 * (C) Copyright 2011~2015 Bosch Sensortec GmbH All Rights Reserved
 *
 * This software program is licensed subject to the GNU General
 * Public License (GPL).Version 2,June 1991,
 * available at http://www.fsf.org/copyleft/gpl.html
*
* @filename bmi160.c
* @Date: 2014/08/28
* @id       "b3ccb9e"
* @Revision: 2.0 $
*
* Usage: Sensor API for BMI160 sensor
*/
/*! file <BMI160 >
    brief <Sensor driver for BMI160> */
#include "bmi160.h"
#include <linux/kernel.h>
/* user defined code to be added here ... */
static struct bmi160_t *p_bmi160;
/* used for reading the mag trim values for compensation*/
static struct trim_data mag_trim;
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
BMI160_RETURN_FUNCTION_TYPE bmi160_init(struct bmi160_t *bmi160)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	/* assign bmi160 ptr */
	p_bmi160 = bmi160;
	comres +=
	p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
	BMI160_USER_CHIP_ID__REG,
	&v_data_u8r, 1);     /* read Chip Id */
	p_bmi160->chip_id = v_data_u8r;
	return comres;
}
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
u8 *data, u8 len)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
			comres +=
			p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->dev_addr,
			addr, data, len);
		}
	return comres;
}
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
u8 *data, u8 len)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			addr, data, len);
		}
	return comres;
}
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
*fatal_error)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_FATAL_ERR__REG,
			&v_data_u8r, 1);
			*fatal_error = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_FATAL_ERR);
		}
	return comres;
}
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
*error_code)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_ERROR_CODE__REG,
			&v_data_u8r, 1);
			*error_code = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_ERROR_CODE);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
*i2c_error_code)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_I2C_FAIL_ERR__REG,
			&v_data_u8r, 1);
			*i2c_error_code = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_I2C_FAIL_ERR);
		}
	return comres;
}
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
*drop_cmd_err)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_DROP_CMD_ERR__REG,
			&v_data_u8r, 1);
			*drop_cmd_err = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_DROP_CMD_ERR);
		}
	return comres;
}

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
BMI160_RETURN_FUNCTION_TYPE bmi160_get_mag_drdy_err(
u8 *drop_cmd_err)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_MAG_DRDY_ERR__REG,
			&v_data_u8r, 1);
			*drop_cmd_err = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_MAG_DRDY_ERR);
		}
	return comres;
}

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
u8 *drop_cmd_err, u8 *mag_drdy_err)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_ERROR_STATUS__REG,
			&v_data_u8r, 1);

			*fatal_err = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_FATAL_ERR);

			*err_code = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_ERROR_CODE);

			*i2c_fail_err = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_I2C_FAIL_ERR);


			*drop_cmd_err = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_DROP_CMD_ERR);


			*mag_drdy_err = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_MAG_DRDY_ERR);
		}
	return comres;
}
/*****************************************************************************
 *	Description: *//**brief This API reads the magnetometer power mode from
 *	PMU status register 0x03 bit 0 and 1
 *
 *  \param u8 * mag_pmu_status : pointer holding the power mode status of
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
*mag_pmu_status)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_MAG_PMU_STATUS__REG,
			&v_data_u8r, 1);
			*mag_pmu_status = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_MAG_PMU_STATUS);
		}
	return comres;
}
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
*gyro_pmu_status)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_GYR_PMU_STATUS__REG,
			&v_data_u8r, 1);
			*gyro_pmu_status = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_GYR_PMU_STATUS);
		}
	return comres;
}
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
*accel_pmu_status)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_ACC_PMU_STATUS__REG,
			&v_data_u8r, 1);
			*accel_pmu_status = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_ACC_PMU_STATUS);
		}
	return comres;
}

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
BMI160_RETURN_FUNCTION_TYPE bmi160_read_mag_x(s16 *mag_x)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r[2] = {0, 0};
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_DATA_0_MAG_X_LSB__REG,
			v_data_u8r, 2);
			/* X aixs*/
			v_data_u8r[0] = BMI160_GET_BITSLICE(v_data_u8r[0],
			BMI160_USER_DATA_MAG_X_LSB);
			*mag_x = (s16)
			((((s32)((s8)v_data_u8r[1]))
			<< BMI160_SHIFT_5_POSITION) | (v_data_u8r[0]));
		}
	return comres;
}
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
BMI160_RETURN_FUNCTION_TYPE bmi160_read_mag_y(s16 *mag_y)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r[2] = {0, 0};
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_DATA_2_MAG_Y_LSB__REG,
			v_data_u8r, 2);
			/*Y-axis lsb value shifting*/
			v_data_u8r[0] = BMI160_GET_BITSLICE(v_data_u8r[0],
			BMI160_USER_DATA_MAG_Y_LSB);
			*mag_y = (s16)
			((((s32)((s8)v_data_u8r[1]))
			<< BMI160_SHIFT_5_POSITION) | (v_data_u8r[0]));
		}
	return comres;
}
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
BMI160_RETURN_FUNCTION_TYPE bmi160_read_mag_z(s16 *mag_z)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r[2] = {0, 0};
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_DATA_4_MAG_Z_LSB__REG,
			v_data_u8r, 2);
			/*Z-axis lsb value shifting*/
			v_data_u8r[0] = BMI160_GET_BITSLICE(v_data_u8r[0],
			BMI160_USER_DATA_MAG_Z_LSB);
			*mag_z = (s16)
			((((s32)((s8)v_data_u8r[1]))
			<< BMI160_SHIFT_7_POSITION) | (v_data_u8r[0]));
		}
	return comres;
}
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
BMI160_RETURN_FUNCTION_TYPE bmi160_read_mag_r(s16 *mag_r)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r[2] = {0, 0};
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_DATA_6_RHALL_LSB__REG,
			v_data_u8r, 2);
			/*R-axis lsb value shifting*/
			v_data_u8r[0] = BMI160_GET_BITSLICE(v_data_u8r[0],
			BMI160_USER_DATA_MAG_R_LSB);
			*mag_r = (s16)
			((((s32)((s8)v_data_u8r[1]))
			<< BMI160_SHIFT_6_POSITION) | (v_data_u8r[0]));
		}
	return comres;
}
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
struct bmi160mag_t *mag)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r[6] = {0, 0, 0, 0, 0, 0};
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_DATA_0_MAG_X_LSB__REG,
			v_data_u8r, 6);
			/*X-axis lsb value shifting*/
			v_data_u8r[0] = BMI160_GET_BITSLICE(v_data_u8r[0],
			BMI160_USER_DATA_MAG_X_LSB);
			/* Data X */
			mag->x = (s16)
			((((s32)((s8)v_data_u8r[1]))
			<< BMI160_SHIFT_5_POSITION) | (v_data_u8r[0]));
			/* Data Y */
			/*Y-axis lsb value shifting*/
			v_data_u8r[2] = BMI160_GET_BITSLICE(v_data_u8r[2],
			BMI160_USER_DATA_MAG_Y_LSB);
			mag->y = (s16)
			((((s32)((s8)v_data_u8r[3]))
			<< BMI160_SHIFT_5_POSITION) | (v_data_u8r[2]));

			/* Data Z */
			/*Z-axis lsb value shifting*/
			v_data_u8r[4] = BMI160_GET_BITSLICE(v_data_u8r[4],
			BMI160_USER_DATA_MAG_Z_LSB);
			mag->z = (s16)
			((((s32)((s8)v_data_u8r[5]))
			<< BMI160_SHIFT_7_POSITION) | (v_data_u8r[4]));
		}
	return comres;
}
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
struct bmi160mag_t *mag)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r[8] = {0, 0, 0, 0, 0, 0, 0, 0};
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_DATA_0_MAG_X_LSB__REG,
			v_data_u8r, 8);

			/* Data X */
			/*X-axis lsb value shifting*/
			v_data_u8r[0] = BMI160_GET_BITSLICE(v_data_u8r[0],
			BMI160_USER_DATA_MAG_X_LSB);
			mag->x = (s16)
			((((s16)((s8)v_data_u8r[1]))
			<< BMI160_SHIFT_5_POSITION) | (v_data_u8r[0]));
			/* Data Y */
			/*Y-axis lsb value shifting*/
			v_data_u8r[2] = BMI160_GET_BITSLICE(v_data_u8r[2],
			BMI160_USER_DATA_MAG_Y_LSB);
			mag->y = (s16)
			((((s16)((s8)v_data_u8r[3]))
			<< BMI160_SHIFT_5_POSITION) | (v_data_u8r[2]));

			/* Data Z */
			/*Z-axis lsb value shifting*/
			v_data_u8r[4] = BMI160_GET_BITSLICE(v_data_u8r[4],
			BMI160_USER_DATA_MAG_Z_LSB);
			mag->z = (s16)
			((((s16)((s8)v_data_u8r[5]))
			<< BMI160_SHIFT_7_POSITION) | (v_data_u8r[4]));

			/* RHall */
			/*R-axis lsb value shifting*/
			v_data_u8r[6] = BMI160_GET_BITSLICE(v_data_u8r[6],
			BMI160_USER_DATA_MAG_R_LSB);
			mag->r = (u16)
			((((u16)(v_data_u8r[7]))
			<< BMI160_SHIFT_6_POSITION) | (v_data_u8r[6]));
			printk(KERN_INFO "mag_raw:%d,%d,%d,%d\n", mag->x,
					mag->y, mag->z, mag->r);
			if ((mag->x == 0) && (mag->y == 0) && (mag->z == 0))
				comres = E_BMI160_COMM_RES;

		}
	return comres;
}
/*****************************************************************************
 *	Description: *//**brief This API reads gyro data X values
 *	form the register 0x0C and 0x0D
 *
 *
 *
 *
 *  \param s16 * gyro_x : Pointer holding the value of gyro_x
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
BMI160_RETURN_FUNCTION_TYPE bmi160_read_gyr_x(s16 *gyro_x)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 g_data_u8r[2] = {0, 0};
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_DATA_8_GYR_X_LSB__REG,
			g_data_u8r, 2);

			*gyro_x = (s16)
			((((s32)((s8)g_data_u8r[1]))
			<< BMI160_SHIFT_8_POSITION) | (g_data_u8r[0]));
		}
	return comres;
}
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
BMI160_RETURN_FUNCTION_TYPE bmi160_read_gyr_y(s16 *gyro_y)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 g_data_u8r[2] = {0, 0};
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_DATA_10_GYR_Y_LSB__REG,
			g_data_u8r, 2);

			*gyro_y = (s16)
			((((s32)((s8)g_data_u8r[1]))
			<< BMI160_SHIFT_8_POSITION) | (g_data_u8r[0]));
		}
	return comres;
}
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
BMI160_RETURN_FUNCTION_TYPE bmi160_read_gyr_z(s16 *gyro_z)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 g_data_u8r[2] = {0, 0};
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_DATA_12_GYR_Z_LSB__REG,
			g_data_u8r, 2);

			*gyro_z = (s16)
			((((s32)((s8)g_data_u8r[1]))
			<< BMI160_SHIFT_8_POSITION) | (g_data_u8r[0]));
		}
	return comres;
}
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
BMI160_RETURN_FUNCTION_TYPE bmi160_read_gyro_xyz(struct bmi160gyro_t *gyro)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 g_data_u8r[6] = {0, 0, 0, 0, 0, 0};
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_DATA_8_GYR_X_LSB__REG,
			g_data_u8r, 6);

			/* Data X */
			gyro->x = (s16)
			((((s32)((s8)g_data_u8r[1]))
			<< BMI160_SHIFT_8_POSITION) | (g_data_u8r[0]));
			/* Data Y */
			gyro->y = (s16)
			((((s32)((s8)g_data_u8r[3]))
			<< BMI160_SHIFT_8_POSITION) | (g_data_u8r[2]));

			/* Data Z */
			gyro->z = (s16)
			((((s32)((s8)g_data_u8r[5]))
			<< BMI160_SHIFT_8_POSITION) | (g_data_u8r[4]));
		}
	return comres;
}
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
BMI160_RETURN_FUNCTION_TYPE bmi160_read_acc_x(s16 *acc_x)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r[2] = {0, 0};
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_DATA_14_ACC_X_LSB__REG,
			v_data_u8r, 2);

			*acc_x = (s16)
			((((s32)((s8)v_data_u8r[1]))
			<< BMI160_SHIFT_8_POSITION) | (v_data_u8r[0]));
		}
	return comres;
}
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
BMI160_RETURN_FUNCTION_TYPE bmi160_read_acc_y(s16 *acc_y)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r[2] = {0, 0};
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_DATA_16_ACC_Y_LSB__REG,
			v_data_u8r, 2);

			*acc_y = (s16)
			((((s32)((s8)v_data_u8r[1]))
			<< BMI160_SHIFT_8_POSITION) | (v_data_u8r[0]));
		}
	return comres;
}
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
BMI160_RETURN_FUNCTION_TYPE bmi160_read_acc_z(s16 *acc_z)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 a_data_u8r[2] = {0, 0};
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_DATA_18_ACC_Z_LSB__REG,
			a_data_u8r, 2);

			*acc_z = (s16)
			((((s32)((s8)a_data_u8r[1]))
			<< BMI160_SHIFT_8_POSITION) | (a_data_u8r[0]));
		}
	return comres;
}
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
BMI160_RETURN_FUNCTION_TYPE bmi160_read_acc_xyz(struct bmi160acc_t *acc)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 a_data_u8r[6] = {0, 0, 0, 0, 0, 0};
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_DATA_14_ACC_X_LSB__REG,
			a_data_u8r, 6);

			/* Data X */
			acc->x = (s16)
			((((s32)((s8)a_data_u8r[1]))
			<< BMI160_SHIFT_8_POSITION) | (a_data_u8r[0]));
			/* Data Y */
			acc->y = (s16)
			((((s32)((s8)a_data_u8r[3]))
			<< BMI160_SHIFT_8_POSITION) | (a_data_u8r[2]));

			/* Data Z */
			acc->z = (s16)
			((((s32)((s8)a_data_u8r[5]))
			<< BMI160_SHIFT_8_POSITION) | (a_data_u8r[4]));
		}
	return comres;
}

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
BMI160_RETURN_FUNCTION_TYPE bmi160_get_sensor_time(u32 *sensor_time)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 a_data_u8r[3] = {0, 0, 0};
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_SENSORTIME_0_SENSOR_TIME_LSB__REG,
			a_data_u8r, 3);

			*sensor_time = (u32)
			((((u32)a_data_u8r[2]) << BMI160_SHIFT_16_POSITION)
			|(((u32)a_data_u8r[1]) << BMI160_SHIFT_8_POSITION)
			| (a_data_u8r[0]));
		}
	return comres;
}
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
*gyr_self_test_ok)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_STATUS_GYR_SELFTEST_OK__REG,
			&v_data_u8r, 1);
			*gyr_self_test_ok = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_STATUS_GYR_SELFTEST_OK);
		}
	return comres;
}
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
*mag_man_op)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_STATUS_MAG_MANUAL_OPERATION__REG,
			&v_data_u8r, 1);
			*mag_man_op = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_STATUS_MAG_MANUAL_OPERATION);
		}
	return comres;
}
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
*foc_rdy)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_STATUS_FOC_RDY__REG, &v_data_u8r, 1);
			*foc_rdy = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_STATUS_FOC_RDY);
		}
	return comres;
}
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
*nvm_rdy)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_STATUS_NVM_RDY__REG, &v_data_u8r, 1);
			*nvm_rdy = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_STATUS_NVM_RDY);
		}
	return comres;
}
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
*drdy_mag)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_STATUS_DRDY_MAG__REG, &v_data_u8r, 1);
			*drdy_mag = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_STATUS_DRDY_MAG);
		}
	return comres;
}
/*****************************************************************************
 *	Description: *//**brief This API reads the status of drdy_gyr form the
 *	register 0x1B bit 6
 *	The status get reset when Gyroscope DATA register read out
 *
 *
 *	\param u8 * drdy_gyr :	Pointer holding the value of drdy_gyr
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
*drdy_gyr)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_STATUS_DRDY_GYR__REG, &v_data_u8r, 1);
			*drdy_gyr = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_STATUS_DRDY_GYR);
		}
	return comres;
}
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
*drdy_acc)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_STATUS_DRDY_ACC__REG, &v_data_u8r, 1);
			*drdy_acc = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_STATUS_DRDY_ACC);
		}
	return comres;
}
/*****************************************************************************
 *	Description: *//**brief This API reads the step interrupt status
 *	from the register 0x1C bit 0
 *	flag is associated with a specific interrupt function.
 *	It is set when the single tab interrupt triggers. The
 *	setting of INT_LATCH controls if the interrupt
 *	signal and hence the
 *	respective interrupt flag will be
 *	permanently latched, temporarily latched
 *	or not latched.
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
*step_int)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_INT_STATUS_0_STEP_INT__REG, &v_data_u8r, 1);
			*step_int = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_STATUS_0_STEP_INT);
		}
	return comres;
}
/*****************************************************************************
 *	Description: *//**brief This API reads the
 *	significant motion interrupt status
 *	from the register 0x1C bit 1
 *	flag is associated with a specific interrupt function.
 *	It is set when the single tab interrupt triggers. The
 *	setting of INT_LATCH controls if the interrupt
 *	signal and hence the
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
*sigmot_int)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_INT_STATUS_0_SIGMOT_INT__REG,
			&v_data_u8r, 1);
			*sigmot_int  = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_STATUS_0_SIGMOT_INT);
		}
	return comres;
}
 /*****************************************************************************
 *	Description: *//**brief This API reads the anym_int status
 *	from the register 0x1C bit 2
 *	flag is associated with a specific interrupt function.
 *	It is set when the single tab interrupt triggers. The
 *	setting of INT_LATCH controls if the interrupt
 *	signal and hence the
 *	respective interrupt flag will be
 *	permanently latched, temporarily latched
 *	or not latched.
 *
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
*anym_int)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_INT_STATUS_0_ANYM__REG, &v_data_u8r, 1);
			*anym_int = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_STATUS_0_ANYM);
		}
	return comres;
}
/*****************************************************************************
 *	Description: *//**brief This API reads the pmu_trigger_int status
 *	from the register 0x1C bit 3
 *	flag is associated with a specific interrupt function.
 *	It is set when the single tab interrupt triggers. The
 *	setting of INT_LATCH controls if the interrupt
 *	signal and hence the
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
*pmu_trigger_int)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_INT_STATUS_0_PMU_TRIGGER__REG,
			&v_data_u8r, 1);
			*pmu_trigger_int = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_STATUS_0_PMU_TRIGGER);
		}
	return comres;
}
/*****************************************************************************
 *	Description: *//**brief This API reads the double tab status
 *	from the register 0x1C bit 4
 *	flag is associated with a specific interrupt function.
 *	It is set when the single tab interrupt triggers. The
 *	setting of INT_LATCH controls if the interrupt
 *	signal and hence the
 *	respective interrupt flag will be
 *	permanently latched, temporarily latched
 *	or not latched.
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
*d_tap_int)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_INT_STATUS_0_D_TAP_INT__REG,
			&v_data_u8r, 1);
			*d_tap_int = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_STATUS_0_D_TAP_INT);
		}
	return comres;
}
/*****************************************************************************
 *	Description: *//**brief This API reads the single tab status
 *	from the register 0x1C bit 5
 *	flag is associated with a specific interrupt function.
 *	It is set when the single tab interrupt triggers. The
 *	setting of INT_LATCH controls if the interrupt
 *	signal and hence the
 *	respective interrupt flag will be
 *	permanently latched, temporarily latched
 *	or not latched.
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
*s_tap_int)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_INT_STATUS_0_S_TAP_INT__REG,
			&v_data_u8r, 1);
			*s_tap_int =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_STATUS_0_S_TAP_INT);
		}
	return comres;
}
/*****************************************************************************
 *	Description: *//**brief This API reads the orient status
 *	from the register 0x1C bit 6
 *	flag is associated with a specific interrupt function.
 *	It is set when the orient interrupt triggers. The
 *	setting of INT_LATCH controls if the
 *	interrupt signal and hence the
 *	respective interrupt flag will be
 *	permanently latched, temporarily latched
 *	or not latched.
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
*orient_int)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_INT_STATUS_0_ORIENT__REG, &v_data_u8r, 1);
			*orient_int =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_STATUS_0_ORIENT);
		}
	return comres;
}
/*****************************************************************************
 *	Description: *//**brief This API reads the flat interrupt status
 *	from the register 0x1C bit 7
 *	flag is associated with a specific interrupt function.
 *	It is set when the flat interrupt triggers. The
 *	setting of INT_LATCH controls if the
 *	interrupt signal and hence the
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
*flat_int)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_INT_STATUS_0_FLAT__REG, &v_data_u8r, 1);
			*flat_int =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_STATUS_0_FLAT);
		}
	return comres;
}
/*****************************************************************************
 *	Description: *//**brief This API reads the high g interrupt status
 *	from the register 0x1D bit 2
 *	flag is associated with a specific interrupt function.
 *	It is set when the high g  interrupt triggers. The
 *	setting of INT_LATCH controls if the interrupt signal and hence the
 *	respective interrupt flag will be permanently
 *	latched, temporarily latched
 *	or not latched.
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
*highg_int)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_INT_STATUS_1_HIGHG_INT__REG,
			&v_data_u8r, 1);
			*highg_int =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_STATUS_1_HIGHG_INT);
		}
	return comres;
}
/*****************************************************************************
 *	Description: *//**brief This API reads the low g interrupt status
 *	from the register 0x1D bit 3
 *	flag is associated with a specific interrupt function.
 *	It is set when the low g  interrupt triggers. The
 *	setting of INT_LATCH controls if the interrupt signal and hence the
 *	respective interrupt flag will be
 *	permanently latched, temporarily latched
 *	or not latched.
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
*lowg_int)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_INT_STATUS_1_LOWG_INT__REG, &v_data_u8r, 1);
			*lowg_int =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_STATUS_1_LOWG_INT);
		}
	return comres;
}
/*****************************************************************************
 *	Description: *//**brief This API reads data ready low g interrupt status
 *	from the register 0x1D bit 4
 *	flag is associated with a specific interrupt function.
 *	It is set when the  data ready  interrupt triggers. The
 *	setting of INT_LATCH controls if the interrupt signal and hence the
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
*drdy_int)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_INT_STATUS_1_DRDY_INT__REG, &v_data_u8r, 1);
			*drdy_int = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_STATUS_1_DRDY_INT);
		}
	return comres;
}

/*****************************************************************************
 *	Description: *//**brief This API reads data ready FIFO full interrupt status
 *	from the register 0x1D bit 5
 *	flag is associated with a specific interrupt function.
 *	It is set when the FIFO full interrupt triggers. The
 *	setting of INT_LATCH controls if the
 *	interrupt signal and hence the
 *	respective interrupt flag will
 *	be permanently latched, temporarily latched
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
*ffull_int)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_INT_STATUS_1_FFULL_INT__REG,
			&v_data_u8r, 1);
			*ffull_int =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_STATUS_1_FFULL_INT);
		}
	return comres;
}
/*****************************************************************************
 *	Description: *//**brief This API reads data
 *	 ready FIFO watermark interrupt status
 *	from the register 0x1D bit 6
 *	flag is associated with a specific interrupt function.
 *	It is set when the FIFO watermark interrupt triggers. The
 *	setting of INT_LATCH controls if the
 *	interrupt signal and hence the
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
*fwm_int)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_INT_STATUS_1_FWM_INT__REG, &v_data_u8r, 1);
			*fwm_int =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_STATUS_1_FWM_INT);
		}
	return comres;
}
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
*nomo_int)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_INT_STATUS_1_NOMO_INT__REG, &v_data_u8r, 1);
			*nomo_int =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_STATUS_1_NOMO_INT);
		}
	return comres;
}
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
*anym_first_x)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_INT_STATUS_2_ANYM_FIRST_X__REG,
			&v_data_u8r, 1);
			*anym_first_x =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_STATUS_2_ANYM_FIRST_X);
		}
	return comres;
}

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
*anym_first_y)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_INT_STATUS_2_ANYM_FIRST_Y__REG,
			&v_data_u8r, 1);
			*anym_first_y =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_STATUS_2_ANYM_FIRST_Y);
		}
	return comres;
}

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
*anym_first_z)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_INT_STATUS_2_ANYM_FIRST_Z__REG,
			&v_data_u8r, 1);
			*anym_first_z =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_STATUS_2_ANYM_FIRST_Z);
		}
	return comres;
}
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
*anym_sign)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_INT_STATUS_2_ANYM_SIGN__REG,
			&v_data_u8r, 1);
			*anym_sign =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_STATUS_2_ANYM_SIGN);
		}
	return comres;
}
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
*tap_first_x)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_INT_STATUS_2_TAP_FIRST_X__REG,
			&v_data_u8r, 1);
			*tap_first_x =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_STATUS_2_TAP_FIRST_X);
		}
	return comres;
}


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
*tap_first_y)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_INT_STATUS_2_TAP_FIRST_Y__REG,
			&v_data_u8r, 1);
			*tap_first_y =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_STATUS_2_TAP_FIRST_Y);
		}
	return comres;
}

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
*tap_first_z)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_INT_STATUS_2_TAP_FIRST_Z__REG,
			&v_data_u8r, 1);
			*tap_first_z =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_STATUS_2_TAP_FIRST_Z);
		}
	return comres;
}

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
*tap_sign)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_INT_STATUS_2_TAP_SIGN__REG, &v_data_u8r, 1);
			*tap_sign =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_STATUS_2_TAP_SIGN);
		}
	return comres;
}

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
*high_first_x)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_INT_STATUS_3_HIGH_FIRST_X__REG,
			&v_data_u8r, 1);
			*high_first_x =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_STATUS_3_HIGH_FIRST_X);
		}
	return comres;
}

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
*high_first_y)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_INT_STATUS_3_HIGH_FIRST_Y__REG,
			&v_data_u8r, 1);
			*high_first_y =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_STATUS_3_HIGH_FIRST_Y);
		}
	return comres;
}

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
*high_first_z)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_INT_STATUS_3_HIGH_FIRST_Z__REG,
			&v_data_u8r, 1);
			*high_first_z =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_STATUS_3_HIGH_FIRST_Z);
		}
	return comres;
}

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
*high_sign)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_INT_STATUS_3_HIGH_SIGN__REG,
			&v_data_u8r, 1);
			*high_sign =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_STATUS_3_HIGH_SIGN);
		}
	return comres;
}
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
*orient_x_y)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_INT_STATUS_3_ORIENT_XY__REG,
			&v_data_u8r, 1);
			*orient_x_y =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_STATUS_3_ORIENT_XY);
		}
	return comres;
}
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
*orient_z)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_INT_STATUS_3_ORIENT_Z__REG, &v_data_u8r, 1);
			*orient_z =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_STATUS_3_ORIENT_Z);
		}
	return comres;
}
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
*flat)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_INT_STATUS_3_FLAT__REG, &v_data_u8r, 1);
			*flat = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_STATUS_3_FLAT);
		}
	return comres;
}

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
*temperature)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r[2] = {0, 0};
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_TEMPERATURE_LSB_VALUE__REG, v_data_u8r, 2);
			*temperature =
			(s16)(((s32)((s8) (v_data_u8r[1]) <<
			BMI160_SHIFT_8_POSITION))|v_data_u8r[0]);
		}
	return comres;
}
/*****************************************************************************
 *	Description: *//**brief This API reads the  of the sensor
 *	form the register 0x23 and 0x24 bit 0 to 7 and 0 to 2
 *
 *
 *  \param u8 * Fifo_length :  Pointer holding the fifo_length
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
BMI160_RETURN_FUNCTION_TYPE bmi160_fifo_length(u32 *fifo_length)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 a_data_u8r[2] = {0, 0};
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_FIFO_BYTE_COUNTER_LSB__REG, a_data_u8r, 2);

			a_data_u8r[1] =
			BMI160_GET_BITSLICE(a_data_u8r[1],
			BMI160_USER_FIFO_BYTE_COUNTER_MSB);

			*fifo_length = (u32)(((u32)((u8) (a_data_u8r[1]) <<
			BMI160_SHIFT_8_POSITION))|a_data_u8r[0]);
		}
	return comres;
}
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
u8 *fifo_data)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BURST_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_FIFO_DATA__REG, fifo_data, FIFO_FRAME);
		}
	return comres;
}

/*************************************************************************
 *	Description: *//**brief This API is used to get the
 *	accel output date rate form the register 0x40 bit 0 to 3
 *
 *
 *  \param  u8 * odr : pointer holding the value of accel output date rate
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
BMI160_RETURN_FUNCTION_TYPE bmi160_get_acc_outputdatarate(u8 *odr)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_ACC_CONF_ODR__REG, &v_data_u8r, 1);
			*odr = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_ACC_CONF_ODR);
		}
	return comres;
}
 /****************************************************************************
 *	Description: *//**brief This API is used to set the
 *	accel output date rate form the register 0x40 bit 0 to 3
 *
 *
 *
 *
 *  \param u8 odr : The value of accel output date rate
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
BMI160_RETURN_FUNCTION_TYPE bmi160_set_acc_outputdatarate(u8 odr)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	u8 output_datarate = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (odr <= C_BMI160_SIXTEEN_U8X) {
			switch (odr) {
			case BMI160_ACCEL_ODR_RESERVED:
				output_datarate = BMI160_ACCEL_ODR_RESERVED;
				break;
			case BMI160_ACCEL_ODR_0_78HZ:
				output_datarate = BMI160_ACCEL_ODR_0_78HZ;
				break;
			case BMI160_ACCEL_ODR_1_56HZ:
				output_datarate = BMI160_ACCEL_ODR_1_56HZ;
				break;
			case BMI160_ACCEL_ODR_3_12HZ:
				output_datarate = BMI160_ACCEL_ODR_3_12HZ;
				break;
			case BMI160_ACCEL_ODR_6_25HZ:
				output_datarate = BMI160_ACCEL_ODR_6_25HZ;
				break;
			case BMI160_ACCEL_ODR_12_5HZ:
				output_datarate = BMI160_ACCEL_ODR_12_5HZ;
				break;
			case BMI160_ACCEL_ODR_25HZ:
				output_datarate = BMI160_ACCEL_ODR_25HZ;
				break;
			case BMI160_ACCEL_ODR_50HZ:
				output_datarate = BMI160_ACCEL_ODR_50HZ;
				break;
			case BMI160_ACCEL_ODR_100HZ:
				output_datarate = BMI160_ACCEL_ODR_100HZ;
				break;
			case BMI160_ACCEL_ODR_200HZ:
				output_datarate = BMI160_ACCEL_ODR_200HZ;
				break;
			case BMI160_ACCEL_ODR_400HZ:
				output_datarate = BMI160_ACCEL_ODR_400HZ;
				break;
			case BMI160_ACCEL_ODR_800HZ:
				output_datarate = BMI160_ACCEL_ODR_800HZ;
				break;
			case BMI160_ACCEL_ODR_1600HZ:
				output_datarate = BMI160_ACCEL_ODR_1600HZ;
				break;
			case BMI160_ACCEL_ODR_RESERVED0:
				output_datarate = BMI160_ACCEL_ODR_RESERVED0;
				break;
			case BMI160_ACCEL_ODR_RESERVED1:
				output_datarate = BMI160_ACCEL_ODR_RESERVED1;
				break;
			case BMI160_ACCEL_ODR_RESERVED2:
				output_datarate = BMI160_ACCEL_ODR_RESERVED2;
				break;
			default:
				break;
			}
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_ACC_CONF_ODR__REG, &v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_ACC_CONF_ODR, output_datarate);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_ACC_CONF_ODR__REG, &v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
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
BMI160_RETURN_FUNCTION_TYPE bmi160_get_acc_bandwidth(u8 *bwp)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_ACC_CONF_ACC_BWP__REG, &v_data_u8r, 1);
			*bwp = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_ACC_CONF_ACC_BWP);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
BMI160_RETURN_FUNCTION_TYPE bmi160_set_acc_bandwidth(u8 bwp)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	BMI160_RETURN_FUNCTION_TYPE bandwidth = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (bwp < C_BMI160_EIGHT_U8X) {
			switch (bwp) {
			case BMI160_ACCEL_OSR4_AVG1:
				bandwidth = BMI160_ACCEL_OSR4_AVG1;
				break;
			case BMI160_ACCEL_OSR2_AVG2:
				bandwidth = BMI160_ACCEL_OSR2_AVG2;
				break;
			case BMI160_ACCEL_NORMAL_AVG4:
				bandwidth = BMI160_ACCEL_NORMAL_AVG4;
				break;
			case BMI160_ACCEL_CIC_AVG8:
				bandwidth = BMI160_ACCEL_CIC_AVG8;
				break;
			case BMI160_ACCEL_RES_AVG16:
				bandwidth = BMI160_ACCEL_RES_AVG16;
				break;
			case BMI160_ACCEL_RES_AVG32:
				bandwidth = BMI160_ACCEL_RES_AVG32;
				break;
			case BMI160_ACCEL_RES_AVG64:
				bandwidth = BMI160_ACCEL_RES_AVG64;
				break;
			case BMI160_ACCEL_RES_AVG128:
				bandwidth = BMI160_ACCEL_RES_AVG128;
				break;
			default:
				break;
			}
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_ACC_CONF_ACC_BWP__REG, &v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_ACC_CONF_ACC_BWP, bandwidth);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_ACC_CONF_ACC_BWP__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
/*************************************************************************
 *	Description: *//**brief This API is used to get the accel
 *	under sampling parameter form the register 0x40 bit 7
 *
 *
 *
 *
 *	\param  u8 * accel_undersampling_parameter : pointer holding the
 *						value of accel under sampling
 *	0	-	enable
 *	1	-	disable
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
BMI160_RETURN_FUNCTION_TYPE bmi160_get_accel_undersampling_parameter(
u8 *accel_undersampling_parameter)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_ACC_CONF_ACC_UNDER_SAMPLING__REG,
			&v_data_u8r, 1);
			*accel_undersampling_parameter =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_ACC_CONF_ACC_UNDER_SAMPLING);
		}
	return comres;
}

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
u8 accel_undersampling_parameter)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (accel_undersampling_parameter < C_BMI160_EIGHT_U8X) {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_ACC_CONF_ACC_UNDER_SAMPLING__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_ACC_CONF_ACC_UNDER_SAMPLING,
				accel_undersampling_parameter);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_ACC_CONF_ACC_UNDER_SAMPLING__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
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
u8 *range)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_ACC_RANGE__REG, &v_data_u8r, 1);
			*range = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_ACC_RANGE);
		}
	return comres;
}
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
BMI160_RETURN_FUNCTION_TYPE bmi160_set_acc_range(u8 range)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if ((range == C_BMI160_THREE_U8X) ||
			(range == C_BMI160_FIVE_U8X) ||
			(range == C_BMI160_EIGHT_U8X) ||
			(range == C_BMI160_TWELVE_U8X)) {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_ACC_RANGE__REG, &v_data_u8r, 1);
			if (comres == SUCCESS) {
				switch (range) {
				case BMI160_ACCEL_RANGE_2G:
					v_data_u8r  = BMI160_SET_BITSLICE(
					v_data_u8r,
					BMI160_USER_ACC_RANGE,
					C_BMI160_THREE_U8X);
					break;
				case BMI160_ACCEL_RANGE_4G:
					v_data_u8r  = BMI160_SET_BITSLICE(
					v_data_u8r,
					BMI160_USER_ACC_RANGE,
					C_BMI160_FIVE_U8X);
					break;
				case BMI160_ACCEL_RANGE_8G:
					v_data_u8r  = BMI160_SET_BITSLICE(
					v_data_u8r,
					BMI160_USER_ACC_RANGE,
					C_BMI160_EIGHT_U8X);
					break;
				case BMI160_ACCELRANGE_16G:
					v_data_u8r  = BMI160_SET_BITSLICE(
					v_data_u8r,
					BMI160_USER_ACC_RANGE,
					C_BMI160_TWELVE_U8X);
					break;
				default:
					break;
				}
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_ACC_RANGE__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
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
 *	0b0110 - BMI160_GYRO_ODR_25HZ
 *	0b0111 - BMI160_GYRO_ODR_50HZ
 *	0b1000 - BMI160_GYRO_ODR_100HZ
 *	0b1001 - BMI160_GYRO_ODR_200HZ
 *	0b1010 - BMI160_GYRO_ODR_400HZ
 *	0b1011 - BMI160_GYRO_ODR_800HZ
 *	0b1100 - BMI160_GYRO_ODR_1600HZ
 *	0b1101 - BMI160_GYRO_ODR_3200HZ
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
u8 *gyro_odr)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_GYR_CONF_ODR__REG, &v_data_u8r, 1);
			*gyro_odr = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_GYR_CONF_ODR);
		}
	return comres;
}
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
 *	0b0110 - BMI160_GYRO_ODR_25HZ
 *	0b0111 - BMI160_GYRO_ODR_50HZ
 *	0b1000 - BMI160_GYRO_ODR_100HZ
 *	0b1001 - BMI160_GYRO_ODR_200HZ
 *	0b1010 - BMI160_GYRO_ODR_400HZ
 *	0b1011 - BMI160_GYRO_ODR_800HZ
 *	0b1100 - BMI160_GYRO_ODR_1600HZ
 *	0b1101 - BMI160_GYRO_ODR_3200HZ
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
u8 gyro_odr)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	BMI160_RETURN_FUNCTION_TYPE output_datarate = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (gyro_odr < C_BMI160_FOURTEEN_U8X) {
			switch (gyro_odr) {
			case BMI160_GYRO_ODR_RESERVED:
				output_datarate = BMI160_GYRO_ODR_RESERVED;
				break;
			case BMI160_GYRO_ODR_25HZ:
				output_datarate = BMI160_GYRO_ODR_25HZ;
				break;
			case BMI160_GYRO_ODR_50HZ:
				output_datarate = BMI160_GYRO_ODR_50HZ;
				break;
			case BMI160_GYRO_ODR_100HZ:
				output_datarate = BMI160_GYRO_ODR_100HZ;
				break;
			case BMI160_GYRO_ODR_200HZ:
				output_datarate = BMI160_GYRO_ODR_200HZ;
				break;
			case BMI160_GYRO_ODR_400HZ:
				output_datarate = BMI160_GYRO_ODR_400HZ;
				break;
			case BMI160_GYRO_ODR_800HZ:
				output_datarate = BMI160_GYRO_ODR_800HZ;
				break;
			case BMI160_GYRO_ODR_1600HZ:
				output_datarate = BMI160_GYRO_ODR_1600HZ;
				break;
			case BMI160_GYRO_ODR_3200HZ:
				output_datarate = BMI160_GYRO_ODR_3200HZ;
				break;
			default:
				break;
			}
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_GYR_CONF_ODR__REG, &v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_GYR_CONF_ODR, output_datarate);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC
				(p_bmi160->dev_addr,
				BMI160_USER_GYR_CONF_ODR__REG, &v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
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
BMI160_RETURN_FUNCTION_TYPE bmi160_get_gyro_bandwidth(u8 *bwp)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_GYR_CONF_BWP__REG, &v_data_u8r, 1);
			*bwp = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_GYR_CONF_BWP);
		}
	return comres;
}
/**************************************************************************
 * Description: *//**brief This API is used to set the
 *	bandwidth of gyro from the register 0x42 bit 4 to 5
 *
 *
 *
 *
 *  \param  u8 bwp : the value of gyro bandwidth
 *
 *	Value	Description
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
BMI160_RETURN_FUNCTION_TYPE bmi160_set_gyro_bandwidth(u8 bwp)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	BMI160_RETURN_FUNCTION_TYPE bandwidth = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (bwp < C_BMI160_FOUR_U8X) {
			switch (bwp) {
			case BMI160_GYRO_OSR4_MODE:
				bandwidth = BMI160_GYRO_OSR4_MODE;
				break;
			case BMI160_GYRO_OSR2_MODE:
				bandwidth = BMI160_GYRO_OSR2_MODE;
				break;
			case BMI160_GYRO_NORMAL_MODE:
				bandwidth = BMI160_GYRO_NORMAL_MODE;
				break;
			case BMI160_GYRO_CIC_MODE:
				bandwidth = BMI160_GYRO_CIC_MODE;
				break;
			default:
				break;
			}
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_GYR_CONF_BWP__REG, &v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_GYR_CONF_BWP, bandwidth);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_GYR_CONF_BWP__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
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
BMI160_RETURN_FUNCTION_TYPE bmi160_get_gyr_range(u8 *range)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_GYR_RANGE__REG, &v_data_u8r, 1);
			*range =
			BMI160_GET_BITSLICE(v_data_u8r, BMI160_USER_GYR_RANGE);
		}
	return comres;
}
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
BMI160_RETURN_FUNCTION_TYPE bmi160_set_gyr_range(u8 range)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (range < C_BMI160_FIVE_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_GYR_RANGE__REG, &v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_GYR_RANGE,
				range);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC
				(p_bmi160->dev_addr,
				BMI160_USER_GYR_RANGE__REG, &v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
/***************************************************************************
 *	Description: *//**brief This API is used to get the
 *	output data rate of magnetometer from the register 0x44 bit 0 to 3
 *
 *
 *
 *
 *  \param  u8 * BW : The pointer holding the value of mag bandwidth
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
BMI160_RETURN_FUNCTION_TYPE bmi160_get_mag_outputdatarate(u8 *odr)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_MAG_CONF_ODR__REG, &v_data_u8r, 1);
			*odr = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_MAG_CONF_ODR);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
BMI160_RETURN_FUNCTION_TYPE bmi160_set_mag_outputdatarate(u8 odr)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	BMI160_RETURN_FUNCTION_TYPE bandwidth = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (odr < C_BMI160_SIXTEEN_U8X) {
			switch (odr) {
			case BMI160_MAG_ODR_RESERVED:
				bandwidth = BMI160_MAG_ODR_RESERVED;
				break;
			case BMI160_MAG_ODR_0_78HZ:
				bandwidth = BMI160_MAG_ODR_0_78HZ;
				break;
			case BMI160_MAG_ODR_1_56HZ:
				bandwidth = BMI160_MAG_ODR_1_56HZ;
				break;
			case BMI160_MAG_ODR_3_12HZ:
				bandwidth = BMI160_MAG_ODR_3_12HZ;
				break;
			case BMI160_MAG_ODR_6_25HZ:
				bandwidth = BMI160_MAG_ODR_6_25HZ;
				break;
			case BMI160_MAG_ODR_12_5HZ:
				bandwidth = BMI160_MAG_ODR_12_5HZ;
				break;
			case BMI160_MAG_ODR_25HZ:
				bandwidth = BMI160_MAG_ODR_25HZ;
				break;
			case BMI160_MAG_ODR_50HZ:
				bandwidth = BMI160_MAG_ODR_50HZ;
				break;
			case BMI160_MAG_ODR_100HZ:
				bandwidth = BMI160_MAG_ODR_100HZ;
				break;
			case BMI160_MAG_ODR_200HZ:
				bandwidth = BMI160_MAG_ODR_200HZ;
				break;
			case BMI160_MAG_ODR_400HZ:
				bandwidth = BMI160_MAG_ODR_400HZ;
				break;
			case BMI160_MAG_ODR_800HZ:
				bandwidth = BMI160_MAG_ODR_800HZ;
				break;
			case BMI160_MAG_ODR_1600HZ:
				bandwidth = BMI160_MAG_ODR_1600HZ;
				break;
			case BMI160_MAG_ODR_RESERVED0:
				bandwidth = BMI160_MAG_ODR_RESERVED0;
				break;
			case BMI160_MAG_ODR_RESERVED1:
				bandwidth = BMI160_MAG_ODR_RESERVED1;
				break;
			case BMI160_MAG_ODR_RESERVED2:
				bandwidth = BMI160_MAG_ODR_RESERVED2;
				break;
			default:
				break;
			}
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_MAG_CONF_ODR__REG, &v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_MAG_CONF_ODR,
				bandwidth);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_MAG_CONF_ODR__REG, &v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
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
u8 *fifo_downs_gyro)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_FIFO_DOWNS_GYRO__REG, &v_data_u8r, 1);
			*fifo_downs_gyro = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_FIFO_DOWNS_GYRO);
		}
	return comres;
}
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
u8 fifo_downs_gyro)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_FIFO_DOWNS_GYRO__REG, &v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(
				v_data_u8r,
				BMI160_USER_FIFO_DOWNS_GYRO,
				fifo_downs_gyro);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_FIFO_DOWNS_GYRO__REG,
				&v_data_u8r, 1);
			}
		}
	return comres;
}
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
u8 *gyr_fifo_filt_data)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_FIFO_FILT_GYRO__REG, &v_data_u8r, 1);
			*gyr_fifo_filt_data = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_FIFO_FILT_GYRO);
		}
	return comres;
}
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
u8 gyr_fifo_filt_data)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (gyr_fifo_filt_data < C_BMI160_TWO_U8X) {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_FIFO_FILT_GYRO__REG, &v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(
				v_data_u8r,
				BMI160_USER_FIFO_FILT_GYRO,
				gyr_fifo_filt_data);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_FIFO_FILT_GYRO__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
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
u8 *fifo_downs_acc)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_FIFO_DOWNS_ACCEL__REG, &v_data_u8r, 1);
			*fifo_downs_acc = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_FIFO_DOWNS_ACCEL);
		}
	return comres;
}
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
u8 fifo_downs_acc)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_FIFO_DOWNS_ACCEL__REG, &v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_FIFO_DOWNS_ACCEL, fifo_downs_acc);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_FIFO_DOWNS_ACCEL__REG,
				&v_data_u8r, 1);
			}
		}
	return comres;
}
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
u8 *accel_fifo_filt_data)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_FIFO_FILT_ACCEL__REG, &v_data_u8r, 1);
			*accel_fifo_filt_data = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_FIFO_FILT_ACCEL);
		}
	return comres;
}
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
u8 accel_fifo_filt_data)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (accel_fifo_filt_data < C_BMI160_TWO_U8X) {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_FIFO_FILT_ACCEL__REG, &v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_FIFO_FILT_ACCEL,
				accel_fifo_filt_data);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_FIFO_FILT_ACCEL__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
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
u8 *fifo_watermark)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_FIFO_WATER_MARK__REG,
			&v_data_u8r, 1);
			*fifo_watermark = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_FIFO_WATER_MARK);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
/*******************************************************************************
 *	Description: *//**brief This API is used to Trigger an interrupt
 *	when FIFO contains fifo_water_mark*4 bytes form the resister 0x46
 *
 *
 *
 *
 *  \param u8 fifo_watermark : Value of the fifo_watermark
 *	0	-	do not stop writing to FIFO when full
 *	1	-	Stop writing into FIFO when full.
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
u8 fifo_watermark)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->dev_addr,
			BMI160_USER_FIFO_WATER_MARK__REG,
			&fifo_watermark, 1);
		}
	return comres;
}
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
 *	1	-	Stop writing into FIFO when full.
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
u8 *fifo_stop_on_full)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_FIFO_STOP_ON_FULL__REG, &v_data_u8r, 1);
			*fifo_stop_on_full = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_FIFO_STOP_ON_FULL);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 fifo_stop_on_full)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (fifo_stop_on_full < C_BMI160_TWO_U8X) {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_FIFO_STOP_ON_FULL__REG, &v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r =
				BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_FIFO_STOP_ON_FULL,
				fifo_stop_on_full);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC
				(p_bmi160->dev_addr,
				BMI160_USER_FIFO_STOP_ON_FULL__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
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
u8 *fifo_time_en)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_FIFO_TIME_EN__REG, &v_data_u8r, 1);
			*fifo_time_en = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_FIFO_TIME_EN);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 fifo_time_en)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (fifo_time_en < C_BMI160_TWO_U8X) {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_FIFO_TIME_EN__REG, &v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_FIFO_TIME_EN, fifo_time_en);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_FIFO_TIME_EN__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 *fifo_tag_int2_en)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_FIFO_TAG_INT2_EN__REG, &v_data_u8r, 1);
			*fifo_tag_int2_en = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_FIFO_TAG_INT2_EN);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 fifo_tag_int2_en)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (fifo_tag_int2_en < C_BMI160_TWO_U8X) {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_FIFO_TAG_INT2_EN__REG, &v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_FIFO_TAG_INT2_EN, fifo_tag_int2_en);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_FIFO_TAG_INT2_EN__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 *fifo_tag_int1_en)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_FIFO_TAG_INT1_EN__REG, &v_data_u8r, 1);
			*fifo_tag_int1_en = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_FIFO_TAG_INT1_EN);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 fifo_tag_int1_en)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (fifo_tag_int1_en < C_BMI160_TWO_U8X) {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_FIFO_TAG_INT1_EN__REG, &v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_FIFO_TAG_INT1_EN, fifo_tag_int1_en);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_FIFO_TAG_INT1_EN__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 *fifo_header_en)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_FIFO_HEADER_EN__REG, &v_data_u8r, 1);
			*fifo_header_en = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_FIFO_HEADER_EN);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 fifo_header_en)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (fifo_header_en < C_BMI160_TWO_U8X) {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_FIFO_HEADER_EN__REG, &v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_FIFO_HEADER_EN, fifo_header_en);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_FIFO_HEADER_EN__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 *fifo_mag_en)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_FIFO_MAG_EN__REG, &v_data_u8r, 1);
			*fifo_mag_en = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_FIFO_MAG_EN);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 fifo_mag_en)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			if (fifo_mag_en < C_BMI160_TWO_U8X) {
				comres +=
				p_bmi160->BMI160_BUS_READ_FUNC
				(p_bmi160->dev_addr,
				BMI160_USER_FIFO_MAG_EN__REG, &v_data_u8r, 1);
				if (comres == SUCCESS) {
					v_data_u8r =
					BMI160_SET_BITSLICE(v_data_u8r,
					BMI160_USER_FIFO_MAG_EN, fifo_mag_en);
					comres +=
					p_bmi160->BMI160_BUS_WRITE_FUNC
					(p_bmi160->dev_addr,
					BMI160_USER_FIFO_MAG_EN__REG,
					&v_data_u8r, 1);
				}
			} else {
			comres = E_BMI160_OUT_OF_RANGE;
			}
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 *fifo_acc_en)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_FIFO_ACC_EN__REG, &v_data_u8r, 1);
			*fifo_acc_en =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_FIFO_ACC_EN);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 fifo_acc_en)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (fifo_acc_en < C_BMI160_TWO_U8X) {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_FIFO_ACC_EN__REG, &v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_FIFO_ACC_EN, fifo_acc_en);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_FIFO_ACC_EN__REG, &v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 *fifo_gyro_en)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_FIFO_GYRO_EN__REG, &v_data_u8r, 1);
			*fifo_gyro_en = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_FIFO_GYRO_EN);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 fifo_gyro_en)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (fifo_gyro_en < C_BMI160_TWO_U8X) {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_FIFO_GYRO_EN__REG, &v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_FIFO_GYRO_EN, fifo_gyro_en);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_FIFO_GYRO_EN__REG, &v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
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
u8 *i2c_device_addr)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_I2C_DEVICE_ADDR__REG, &v_data_u8r, 1);
			*i2c_device_addr = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_I2C_DEVICE_ADDR);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 i2c_device_addr)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_I2C_DEVICE_ADDR__REG, &v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_I2C_DEVICE_ADDR, i2c_device_addr);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_I2C_DEVICE_ADDR__REG,
				&v_data_u8r, 1);
			}
		}
	return comres;
}
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
u8 *mag_burst)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_MAG_BURST__REG, &v_data_u8r, 1);
			*mag_burst = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_MAG_BURST);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 mag_burst)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_MAG_BURST__REG, &v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r =
				BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_MAG_BURST, mag_burst);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_MAG_BURST__REG, &v_data_u8r, 1);
			}
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 *mag_offset)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_MAG_OFFSET__REG, &v_data_u8r, 1);
			*mag_offset =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_MAG_OFFSET);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 mag_offset)
{
BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
u8 v_data_u8r = C_BMI160_ZERO_U8X;
if (p_bmi160 == BMI160_NULL) {
	return E_BMI160_NULL_PTR;
	} else {
		comres +=
		p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
		BMI160_USER_MAG_OFFSET__REG, &v_data_u8r, 1);
		if (comres == SUCCESS) {
			v_data_u8r =
			BMI160_SET_BITSLICE(v_data_u8r,
			BMI160_USER_MAG_OFFSET, mag_offset);
			comres +=
			p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->dev_addr,
			BMI160_USER_MAG_OFFSET__REG, &v_data_u8r, 1);
		}
	}
return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
/*******************************************************************************
 *	Description: *//**brief This API is used to read
 *	Enable register access on MAG_IF[2] or MAG_IF[3] writes.
 *	This implies that the DATA registers are not updated with
 *	magnetometer values. Accessing magnetometer requires
 *	the magnetometer in normal mode in PMU_STATUS.
 *	from the register 0c4C bit 7
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
u8 *mag_manual_en)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_MAG_MANUAL_EN__REG, &v_data_u8r, 1);
			*mag_manual_en =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_MAG_MANUAL_EN);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 mag_manual_en)
{
BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
u8 v_data_u8r = C_BMI160_ZERO_U8X;
if (p_bmi160 == BMI160_NULL) {
	return E_BMI160_NULL_PTR;
	} else {
		if (comres == SUCCESS) {
			v_data_u8r = 0X80 & (mag_manual_en << 7);
			comres +=
			p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->dev_addr,
			BMI160_USER_MAG_MANUAL_EN__REG, &v_data_u8r, 1);
		}
		if (comres)
			printk(KERN_ERR
			"err bmi160_set_mag_manual_en bmm:%d\n", comres);
	}
return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 *mag_read_addr)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_READ_ADDR__REG, &v_data_u8r, 1);
			*mag_read_addr =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_READ_ADDR);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 mag_read_addr)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->dev_addr,
			BMI160_USER_READ_ADDR__REG, &mag_read_addr, 1);
		}
	return comres;
}
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
 *
 *
 * Remarks:
 *
 ****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_mag_write_addr(
u8 *mag_write_addr)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_WRITE_ADDR__REG, &v_data_u8r, 1);
			*mag_write_addr =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_WRITE_ADDR);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 mag_write_addr)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->dev_addr,
			BMI160_USER_WRITE_ADDR__REG, &mag_write_addr, 1);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 *mag_write_data)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_WRITE_DATA__REG, &v_data_u8r, 1);
			*mag_write_data =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_WRITE_DATA);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 mag_write_data)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->dev_addr,
			BMI160_USER_WRITE_DATA__REG, &mag_write_data, 1);
		}
	return comres;
}
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
u8 enable, u8 *int_en_0)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		switch (enable) {
		case BMI160_ANYMO_X_EN:
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_0_ANYMO_X_EN__REG,
			&v_data_u8r, 1);
			*int_en_0 =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_EN_0_ANYMO_X_EN);
		break;
		case BMI160_ANYMO_Y_EN:
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_0_ANYMO_Y_EN__REG,
			&v_data_u8r, 1);
			*int_en_0 =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_EN_0_ANYMO_Y_EN);
		break;
		case BMI160_ANYMO_Z_EN:
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_0_ANYMO_Z_EN__REG,
			&v_data_u8r, 1);
			*int_en_0 =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_EN_0_ANYMO_Z_EN);
		break;
		case BMI160_D_TAP_EN:
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_0_D_TAP_EN__REG,
			&v_data_u8r, 1);
			*int_en_0 =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_EN_0_D_TAP_EN);
		break;
		case BMI160_S_TAP_EN:
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_0_S_TAP_EN__REG,
			&v_data_u8r, 1);
			*int_en_0 =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_EN_0_S_TAP_EN);
		break;
		case BMI160_ORIENT_EN:
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_0_ORIENT_EN__REG,
			&v_data_u8r, 1);
			*int_en_0 =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_EN_0_ORIENT_EN);
		break;
		case BMI160_FLAT_EN:
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_0_FLAT_EN__REG,
			&v_data_u8r, 1);
			*int_en_0 =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_EN_0_FLAT_EN);
		break;
		default:
			comres = E_BMI160_OUT_OF_RANGE;
		break;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 enable, u8 int_en_0)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		switch (enable) {
		case BMI160_ANYMO_X_EN:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_0_ANYMO_X_EN__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_EN_0_ANYMO_X_EN, int_en_0);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
				dev_addr, BMI160_USER_INT_EN_0_ANYMO_X_EN__REG,
				&v_data_u8r, 1);
			}
			break;
		case BMI160_ANYMO_Y_EN:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_0_ANYMO_Y_EN__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_EN_0_ANYMO_Y_EN, int_en_0);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
				dev_addr, BMI160_USER_INT_EN_0_ANYMO_Y_EN__REG,
				&v_data_u8r, 1);
			}
			break;
		case BMI160_ANYMO_Z_EN:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_0_ANYMO_Z_EN__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_EN_0_ANYMO_Z_EN, int_en_0);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
				dev_addr, BMI160_USER_INT_EN_0_ANYMO_Z_EN__REG,
				&v_data_u8r, 1);
			}
			break;
		case BMI160_D_TAP_EN:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_0_D_TAP_EN__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_EN_0_D_TAP_EN, int_en_0);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
				dev_addr, BMI160_USER_INT_EN_0_D_TAP_EN__REG,
				&v_data_u8r, 1);
			}
			break;
		case BMI160_S_TAP_EN:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_0_S_TAP_EN__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_EN_0_S_TAP_EN, int_en_0);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
				dev_addr, BMI160_USER_INT_EN_0_S_TAP_EN__REG,
				&v_data_u8r, 1);
			}
			break;
		case BMI160_ORIENT_EN:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_0_ORIENT_EN__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_EN_0_ORIENT_EN, int_en_0);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
				dev_addr, BMI160_USER_INT_EN_0_ORIENT_EN__REG,
				&v_data_u8r, 1);
			}
			break;
		case BMI160_FLAT_EN:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_0_FLAT_EN__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_EN_0_FLAT_EN, int_en_0);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
				dev_addr, BMI160_USER_INT_EN_0_FLAT_EN__REG,
				&v_data_u8r, 1);
			}
			break;
		default:
			comres = E_BMI160_OUT_OF_RANGE;
			break;
		}
	}
	return comres;
}
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
u8 enable, u8 *int_en_1)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		switch (enable) {
		case BMI160_HIGH_X_EN:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_1_HIGHG_X_EN__REG,
			&v_data_u8r, 1);
			*int_en_1 = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_EN_1_HIGHG_X_EN);
			break;
		case BMI160_HIGH_Y_EN:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_1_HIGHG_Y_EN__REG,
			&v_data_u8r, 1);
			*int_en_1 = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_EN_1_HIGHG_Y_EN);
			break;
		case BMI160_HIGH_Z_EN:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_1_HIGHG_Z_EN__REG,
			&v_data_u8r, 1);
			*int_en_1 = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_EN_1_HIGHG_Z_EN);
			break;
		case BMI160_LOW_EN:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_1_LOW_EN__REG,
			&v_data_u8r, 1);
			*int_en_1 = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_EN_1_LOW_EN);
			break;
		case BMI160_DRDY_EN:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_1_DRDY_EN__REG,
			&v_data_u8r, 1);
			*int_en_1 = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_EN_1_DRDY_EN);
			break;
		case BMI160_FFULL_EN:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_1_FFULL_EN__REG,
			&v_data_u8r, 1);
			*int_en_1 = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_EN_1_FFULL_EN);
			break;
		case BMI160_FWM_EN:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_1_FWM_EN__REG,
			&v_data_u8r, 1);
			*int_en_1 = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_EN_1_FWM_EN);
			break;
		default:
			comres = E_BMI160_OUT_OF_RANGE;
			break;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 enable, u8 int_en_1)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		switch (enable) {
		case BMI160_HIGH_X_EN:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_1_HIGHG_X_EN__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_EN_1_HIGHG_X_EN, int_en_1);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
				dev_addr, BMI160_USER_INT_EN_1_HIGHG_X_EN__REG,
				&v_data_u8r, 1);
			}
		break;
		case BMI160_HIGH_Y_EN:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_1_HIGHG_Y_EN__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_EN_1_HIGHG_Y_EN, int_en_1);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
				dev_addr, BMI160_USER_INT_EN_1_HIGHG_Y_EN__REG,
				&v_data_u8r, 1);
			}
		break;
		case BMI160_HIGH_Z_EN:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_1_HIGHG_Z_EN__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_EN_1_HIGHG_Z_EN, int_en_1);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
				dev_addr, BMI160_USER_INT_EN_1_HIGHG_Z_EN__REG,
				&v_data_u8r, 1);
			}
		break;
		case BMI160_LOW_EN:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_1_LOW_EN__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_EN_1_LOW_EN, int_en_1);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
				dev_addr, BMI160_USER_INT_EN_1_LOW_EN__REG,
				&v_data_u8r, 1);
			}
		break;
		case BMI160_DRDY_EN:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_1_DRDY_EN__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_EN_1_DRDY_EN, int_en_1);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
				dev_addr, BMI160_USER_INT_EN_1_DRDY_EN__REG,
				&v_data_u8r, 1);
			}
		break;
		case BMI160_FFULL_EN:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_1_FFULL_EN__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_EN_1_FFULL_EN, int_en_1);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
				dev_addr, BMI160_USER_INT_EN_1_FFULL_EN__REG,
				&v_data_u8r, 1);
			}
		break;
		case BMI160_FWM_EN:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_1_FWM_EN__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_EN_1_FWM_EN, int_en_1);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
				dev_addr, BMI160_USER_INT_EN_1_FWM_EN__REG,
				&v_data_u8r, 1);
			}
		break;
		default:
			comres = E_BMI160_OUT_OF_RANGE;
		break;
		}
	}
	return comres;
}
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
u8 enable, u8 *int_en_2)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		switch (enable) {
		case BMI160_NOMOTION_X_EN:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_2_NOMO_X_EN__REG,
			&v_data_u8r, 1);
			*int_en_2 = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_EN_2_NOMO_X_EN);
			break;
		case BMI160_NOMOTION_Y_EN:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_2_NOMO_Y_EN__REG,
			&v_data_u8r, 1);
			*int_en_2 = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_EN_2_NOMO_Y_EN);
			break;
		case BMI160_NOMOTION_Z_EN:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_2_NOMO_Z_EN__REG,
			&v_data_u8r, 1);
			*int_en_2 = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_EN_2_NOMO_Z_EN);
			break;
		default:
			comres = E_BMI160_OUT_OF_RANGE;
			break;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 enable, u8 int_en_2)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		switch (enable) {
		case BMI160_NOMOTION_X_EN:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_2_NOMO_X_EN__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_EN_2_NOMO_X_EN, int_en_2);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
				dev_addr, BMI160_USER_INT_EN_2_NOMO_X_EN__REG,
				&v_data_u8r, 1);
			}
			break;
		case BMI160_NOMOTION_Y_EN:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_2_NOMO_Y_EN__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_EN_2_NOMO_Y_EN, int_en_2);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
				dev_addr, BMI160_USER_INT_EN_2_NOMO_Y_EN__REG,
				&v_data_u8r, 1);
			}
			break;
		case BMI160_NOMOTION_Z_EN:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_2_NOMO_Z_EN__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_EN_2_NOMO_Z_EN, int_en_2);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
				dev_addr, BMI160_USER_INT_EN_2_NOMO_Z_EN__REG,
				&v_data_u8r, 1);
			}
			break;
		default:
			comres = E_BMI160_OUT_OF_RANGE;
			break;
		}
	}
	return comres;
}
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
u8 *step_int)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_2_STEP_DET_EN__REG,
			&v_data_u8r, 1);
			*step_int = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_EN_2_STEP_DET_EN);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 step_int)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
		dev_addr, BMI160_USER_INT_EN_2_STEP_DET_EN__REG,
		&v_data_u8r, 1);
		if (comres == SUCCESS) {
			v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_EN_2_STEP_DET_EN, step_int);
			comres +=
			p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_EN_2_STEP_DET_EN__REG,
			&v_data_u8r, 1);
		}
	}
	return comres;
}
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
u8 channel, u8 *int_edge_ctrl)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		switch (channel) {
		case BMI160_INT1_EDGE_CTRL:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT1_EDGE_CTRL__REG,
			&v_data_u8r, 1);
			*int_edge_ctrl = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT1_EDGE_CTRL);
			break;
		case BMI160_INT2_EDGE_CTRL:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT2_EDGE_CTRL__REG,
			&v_data_u8r, 1);
			*int_edge_ctrl = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT2_EDGE_CTRL);
			break;
		default:
			comres = E_BMI160_OUT_OF_RANGE;
			break;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 channel, u8 int_edge_ctrl)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		switch (channel) {
		case BMI160_INT1_EDGE_CTRL:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT1_EDGE_CTRL__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT1_EDGE_CTRL, int_edge_ctrl);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
				dev_addr, BMI160_USER_INT1_EDGE_CTRL__REG,
				&v_data_u8r, 1);
			}
			break;
		case BMI160_INT2_EDGE_CTRL:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT2_EDGE_CTRL__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT2_EDGE_CTRL, int_edge_ctrl);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
				dev_addr, BMI160_USER_INT2_EDGE_CTRL__REG,
				&v_data_u8r, 1);
			}
			break;
		default:
			comres = E_BMI160_OUT_OF_RANGE;
			break;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
/**************************************************************************
 *	Description: *//**brief  Configure trigger condition of INT1
 *	and INT2 pin form the register 0x53 bit 1 and 5
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
u8 channel, u8 *int_lvl)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		switch (channel) {
		case BMI160_INT1_LVL:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT1_LVL__REG,
			&v_data_u8r, 1);
			*int_lvl = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT1_LVL);
			break;
		case BMI160_INT2_LVL:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT2_LVL__REG,
			&v_data_u8r, 1);
			*int_lvl = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT2_LVL);
			break;
		default:
			comres = E_BMI160_OUT_OF_RANGE;
			break;
		}
	}
	return comres;
}
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
u8 channel, u8 int_lvl)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		switch (channel) {
		case BMI160_INT1_LVL:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT1_LVL__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT1_LVL, int_lvl);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
				dev_addr, BMI160_USER_INT1_LVL__REG,
				&v_data_u8r, 1);
			}
			break;
		case BMI160_INT2_LVL:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT2_LVL__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT2_LVL, int_lvl);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
				dev_addr, BMI160_USER_INT2_LVL__REG,
				&v_data_u8r, 1);
			}
			break;
		default:
			comres = E_BMI160_OUT_OF_RANGE;
			break;
		}
	}
	return comres;
}
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
u8 channel, u8 *int_od)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		switch (channel) {
		case BMI160_INT1_OD:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT1_OD__REG,
			&v_data_u8r, 1);
			*int_od = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT1_OD);
			break;
		case BMI160_INT2_OD:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT2_OD__REG,
			&v_data_u8r, 1);
			*int_od = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT2_OD);
			break;
		default:
			comres = E_BMI160_OUT_OF_RANGE;
			break;
		}
	}
	return comres;
}
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
u8 channel, u8 int_od)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		switch (channel) {
		case BMI160_INT1_OD:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT1_OD__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT1_OD, int_od);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
				dev_addr, BMI160_USER_INT1_OD__REG,
				&v_data_u8r, 1);
			}
			break;
		case BMI160_INT2_OD:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT2_OD__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT2_OD, int_od);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
				dev_addr, BMI160_USER_INT2_OD__REG,
				&v_data_u8r, 1);
			}
			break;
		default:
			comres = E_BMI160_OUT_OF_RANGE;
			break;
		}
	}
	return comres;
}
/**************************************************************************
 *	Description: *//**brief Output enable for INT1
 *	and INT2 pin from the register 0x53 bit 3 and 7
 *
 *
 *  \param u8 channel,u8 *output_en
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
u8 channel, u8 *output_en)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		switch (channel) {
		case BMI160_INT1_OUTPUT_EN:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT1_OUTPUT_EN__REG,
			&v_data_u8r, 1);
			*output_en = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT1_OUTPUT_EN);
			break;
		case BMI160_INT2_OUTPUT_EN:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT2_OUTPUT_EN__REG,
			&v_data_u8r, 1);
			*output_en = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT2_OUTPUT_EN);
			break;
		default:
			comres = E_BMI160_OUT_OF_RANGE;
			break;
		}
	}
	return comres;
}
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
u8 channel, u8 output_en)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		switch (channel) {
		case BMI160_INT1_OUTPUT_EN:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT1_OUTPUT_EN__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT1_OUTPUT_EN, output_en);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
				dev_addr, BMI160_USER_INT1_OUTPUT_EN__REG,
				&v_data_u8r, 1);
			}
		break;
		case BMI160_INT2_OUTPUT_EN:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT2_OUTPUT_EN__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT2_OUTPUT_EN, output_en);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
				dev_addr, BMI160_USER_INT2_OUTPUT_EN__REG,
				&v_data_u8r, 1);
			}
		break;
		default:
			comres = E_BMI160_OUT_OF_RANGE;
		break;
		}
	}
	return comres;
}
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
u8 *latch_int)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_LATCH__REG,
			&v_data_u8r, 1);
			*latch_int = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_LATCH);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
BMI160_RETURN_FUNCTION_TYPE bmi160_set_latch_int(u8 latch_int)
{
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (latch_int < C_BMI160_SIXTEEN_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_LATCH__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_LATCH, latch_int);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
				dev_addr, BMI160_USER_INT_LATCH__REG,
				&v_data_u8r, 1);
			}
		} else{
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
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
u8 channel, u8 *input_en)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		switch (channel) {
		case BMI160_INT1_INPUT_EN:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT1_INPUT_EN__REG,
			&v_data_u8r, 1);
			*input_en = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT1_INPUT_EN);
			break;
		case BMI160_INT2_INPUT_EN:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT1_INPUT_EN__REG,
			&v_data_u8r, 1);
			*input_en = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT1_INPUT_EN);
			break;
		default:
			comres = E_BMI160_OUT_OF_RANGE;
			break;
		}
	}
	return comres;
}
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
u8 channel, u8 input_en)
{
BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
u8 v_data_u8r = C_BMI160_ZERO_U8X;
if (p_bmi160 == BMI160_NULL) {
	return E_BMI160_NULL_PTR;
	} else {
	switch (channel) {
	case BMI160_INT1_INPUT_EN:
		comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
		dev_addr, BMI160_USER_INT1_INPUT_EN__REG,
		&v_data_u8r, 1);
		if (comres == SUCCESS) {
			v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
			BMI160_USER_INT1_INPUT_EN, input_en);
			comres += p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT1_INPUT_EN__REG,
			&v_data_u8r, 1);
		}
	break;
	case BMI160_INT2_INPUT_EN:
		comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
		dev_addr, BMI160_USER_INT2_INPUT_EN__REG,
		&v_data_u8r, 1);
		if (comres == SUCCESS) {
			v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
			BMI160_USER_INT2_INPUT_EN, input_en);
			comres += p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT2_INPUT_EN__REG,
			&v_data_u8r, 1);
		}
	break;
	default:
		comres = E_BMI160_OUT_OF_RANGE;
	break;
	}
}
return comres;
}
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
u8 channel, u8 *int_lowg)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		switch (channel) {
		case BMI160_INT1_MAP_LOW_G:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_0_INT1_LOWG__REG,
			&v_data_u8r, 1);
			*int_lowg = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_0_INT1_LOWG);
			break;
		case BMI160_INT2_MAP_LOW_G:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_2_INT2_LOWG__REG,
			&v_data_u8r, 1);
			*int_lowg = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_2_INT2_LOWG);
			break;
		default:
			comres = E_BMI160_OUT_OF_RANGE;
			break;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 channel, u8 int_lowg)
{
BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
u8 v_data_u8r = C_BMI160_ZERO_U8X;
u8 step_cnt_stat = C_BMI160_ZERO_U8X;
u8 step_det_stat = C_BMI160_ZERO_U8X;

if (p_bmi160 == BMI160_NULL) {
	return E_BMI160_NULL_PTR;
	} else {

	comres += bmi160_get_stepdetector_enable(&step_det_stat);

	if (step_det_stat != C_BMI160_ZERO_U8X)
		comres += bmi160_set_stepdetector_enable(C_BMI160_ZERO_U8X);

	comres += bmi160_get_step_counter_enable(&step_cnt_stat);
	if (step_cnt_stat != C_BMI160_ZERO_U8X)
			comres += bmi160_set_step_counter_enable(
			C_BMI160_ZERO_U8X);
	switch (channel) {
	case BMI160_INT1_MAP_LOW_G:
		comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
		dev_addr, BMI160_USER_INT_MAP_0_INT1_LOWG__REG,
		&v_data_u8r, 1);
		if (comres == SUCCESS) {
			v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_0_INT1_LOWG, int_lowg);
			comres += p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_0_INT1_LOWG__REG,
			&v_data_u8r, 1);
		}
		break;
	case BMI160_INT2_MAP_LOW_G:
		comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
		dev_addr, BMI160_USER_INT_MAP_2_INT2_LOWG__REG,
		&v_data_u8r, 1);
		if (comres == SUCCESS) {
			v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_2_INT2_LOWG, int_lowg);
			comres += p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_2_INT2_LOWG__REG,
			&v_data_u8r, 1);
		}
		break;
	default:
		comres = E_BMI160_OUT_OF_RANGE;
		break;
	}
}
return comres;
}
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
u8 channel, u8 *int_highg)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		switch (channel) {
		case BMI160_INT1_MAP_HIGH_G:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_0_INT1_HIGHG__REG,
			&v_data_u8r, 1);
			*int_highg = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_0_INT1_HIGHG);
		break;
		case BMI160_INT2_MAP_HIGH_G:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_2_INT2_HIGHG__REG,
			&v_data_u8r, 1);
			*int_highg = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_2_INT2_HIGHG);
		break;
		default:
			comres = E_BMI160_OUT_OF_RANGE;
			break;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 channel, u8 int_highg)
{
BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
u8 v_data_u8r = C_BMI160_ZERO_U8X;
if (p_bmi160 == BMI160_NULL) {
	return E_BMI160_NULL_PTR;
	} else {
	switch (channel) {
	case BMI160_INT1_MAP_HIGH_G:
		comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
		dev_addr, BMI160_USER_INT_MAP_0_INT1_HIGHG__REG,
		&v_data_u8r, 1);
		if (comres == SUCCESS) {
			v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_0_INT1_HIGHG, int_highg);
			comres += p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_0_INT1_HIGHG__REG,
			&v_data_u8r, 1);
		}
	break;
	case BMI160_INT2_MAP_HIGH_G:
		comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
		dev_addr, BMI160_USER_INT_MAP_2_INT2_HIGHG__REG,
		&v_data_u8r, 1);
		if (comres == SUCCESS) {
			v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_2_INT2_HIGHG, int_highg);
			comres += p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_2_INT2_HIGHG__REG,
			&v_data_u8r, 1);
		}
	break;
	default:
		comres = E_BMI160_OUT_OF_RANGE;
	break;
	}
}
return comres;
}
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
u8 channel, u8 *int_anymo)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		switch (channel) {
		case BMI160_INT1_MAP_ANYMO:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_0_INT1_ANYMOTION__REG,
			&v_data_u8r, 1);
			*int_anymo = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_0_INT1_ANYMOTION);
		break;
		case BMI160_INT2_MAP_ANYMO:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_2_INT2_ANYMOTION__REG,
			&v_data_u8r, 1);
			*int_anymo = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_2_INT2_ANYMOTION);
		break;
		default:
			comres = E_BMI160_OUT_OF_RANGE;
		break;
		}
	}
	return comres;
}
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
u8 channel, u8 int_anymo)
{
BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
u8 v_data_u8r = C_BMI160_ZERO_U8X;
u8 sig_mot_stat = C_BMI160_ZERO_U8X;

if (p_bmi160 == BMI160_NULL) {
	return E_BMI160_NULL_PTR;
	} else {
	comres += bmi160_get_int_significant_motion_select(&sig_mot_stat);
	if (sig_mot_stat != C_BMI160_ZERO_U8X)
		comres += bmi160_set_int_significant_motion_select(
		C_BMI160_ZERO_U8X);
	switch (channel) {
	case BMI160_INT1_MAP_ANYMO:
		comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
		dev_addr, BMI160_USER_INT_MAP_0_INT1_ANYMOTION__REG,
		&v_data_u8r, 1);
		if (comres == SUCCESS) {
			v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_0_INT1_ANYMOTION, int_anymo);
			comres += p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_0_INT1_ANYMOTION__REG,
			&v_data_u8r, 1);
		}
	break;
	case BMI160_INT2_MAP_ANYMO:
		comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
		dev_addr, BMI160_USER_INT_MAP_2_INT2_ANYMOTION__REG,
		&v_data_u8r, 1);
		if (comres == SUCCESS) {
			v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_2_INT2_ANYMOTION, int_anymo);
			comres += p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_2_INT2_ANYMOTION__REG,
			&v_data_u8r, 1);
		}
	break;
	default:
		comres = E_BMI160_OUT_OF_RANGE;
	break;
	}
}
return comres;
}
/****************************************************************************
 *	Description: *//**brief Reads the No motion interrupt
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
u8 channel, u8 *int_nomo)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		switch (channel) {
		case BMI160_INT1_MAP_NOMO:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_0_INT1_NOMOTION__REG,
			&v_data_u8r, 1);
			*int_nomo = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_0_INT1_NOMOTION);
			break;
		case BMI160_INT2_MAP_NOMO:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_2_INT2_NOMOTION__REG,
			&v_data_u8r, 1);
			*int_nomo = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_2_INT2_NOMOTION);
			break;
		default:
			comres = E_BMI160_OUT_OF_RANGE;
			break;
		}
	}
	return comres;
}
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
u8 channel, u8 int_nomo)
{
BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
u8 v_data_u8r = C_BMI160_ZERO_U8X;
if (p_bmi160 == BMI160_NULL) {
	return E_BMI160_NULL_PTR;
	} else {
	switch (channel) {
	case BMI160_INT1_MAP_NOMO:
		comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
		dev_addr, BMI160_USER_INT_MAP_0_INT1_NOMOTION__REG,
		&v_data_u8r, 1);
		if (comres == SUCCESS) {
			v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_0_INT1_NOMOTION, int_nomo);
			comres += p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_0_INT1_NOMOTION__REG,
			&v_data_u8r, 1);
		}
		break;
	case BMI160_INT2_MAP_NOMO:
		comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
		dev_addr, BMI160_USER_INT_MAP_2_INT2_NOMOTION__REG,
		&v_data_u8r, 1);
		if (comres == SUCCESS) {
			v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_2_INT2_NOMOTION, int_nomo);
			comres += p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_2_INT2_NOMOTION__REG,
			&v_data_u8r, 1);
		}
		break;
	default:
		comres = E_BMI160_OUT_OF_RANGE;
		break;
	}
}
return comres;
}
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
u8 channel, u8 *int_dtap)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		switch (channel) {
		case BMI160_INT1_MAP_DTAP:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_0_INT1_D_TAP__REG,
			&v_data_u8r, 1);
			*int_dtap = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_0_INT1_D_TAP);
			break;
		case BMI160_INT2_MAP_DTAP:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_2_INT2_D_TAP__REG,
			&v_data_u8r, 1);
			*int_dtap = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_2_INT2_D_TAP);
			break;
		default:
			comres = E_BMI160_OUT_OF_RANGE;
			break;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 channel, u8 int_dtap)
{
BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
u8 v_data_u8r = C_BMI160_ZERO_U8X;
if (p_bmi160 == BMI160_NULL) {
	return E_BMI160_NULL_PTR;
	} else {
	switch (channel) {
	case BMI160_INT1_MAP_DTAP:
		comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
		dev_addr, BMI160_USER_INT_MAP_0_INT1_D_TAP__REG,
		&v_data_u8r, 1);
		if (comres == SUCCESS) {
			v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_0_INT1_D_TAP, int_dtap);
			comres += p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_0_INT1_D_TAP__REG,
			&v_data_u8r, 1);
		}
		break;
	case BMI160_INT2_MAP_DTAP:
		comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
		dev_addr, BMI160_USER_INT_MAP_2_INT2_D_TAP__REG,
		&v_data_u8r, 1);
		if (comres == SUCCESS) {
			v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_2_INT2_D_TAP, int_dtap);
			comres += p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_2_INT2_D_TAP__REG,
			&v_data_u8r, 1);
		}
		break;
	default:
		comres = E_BMI160_OUT_OF_RANGE;
		break;
	}
}
return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 channel, u8 *int_stap)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		switch (channel) {
		case BMI160_INT1_MAP_STAP:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_0_INT1_S_TAP__REG,
			&v_data_u8r, 1);
			*int_stap = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_0_INT1_S_TAP);
			break;
		case BMI160_INT2_MAP_STAP:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_2_INT2_S_TAP__REG,
			&v_data_u8r, 1);
			*int_stap = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_2_INT2_S_TAP);
			break;
		default:
			comres = E_BMI160_OUT_OF_RANGE;
			break;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 channel, u8 int_stap)
{
BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
u8 v_data_u8r = C_BMI160_ZERO_U8X;
if (p_bmi160 == BMI160_NULL) {
	return E_BMI160_NULL_PTR;
	} else {
	switch (channel) {
	case BMI160_INT1_MAP_STAP:
		comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
		dev_addr, BMI160_USER_INT_MAP_0_INT1_S_TAP__REG,
		&v_data_u8r, 1);
		if (comres == SUCCESS) {
			v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_0_INT1_S_TAP, int_stap);
			comres += p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_0_INT1_S_TAP__REG,
			&v_data_u8r, 1);
		}
		break;
	case BMI160_INT2_MAP_STAP:
		comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
		dev_addr, BMI160_USER_INT_MAP_2_INT2_S_TAP__REG,
		&v_data_u8r, 1);
		if (comres == SUCCESS) {
			v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_2_INT2_S_TAP, int_stap);
			comres += p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_2_INT2_S_TAP__REG,
			&v_data_u8r, 1);
		}
		break;
	default:
		comres = E_BMI160_OUT_OF_RANGE;
		break;
	}
}
return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 channel, u8 *int_orient)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		switch (channel) {
		case BMI160_INT1_MAP_ORIENT:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_0_INT1_ORIENT__REG,
			&v_data_u8r, 1);
			*int_orient = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_0_INT1_ORIENT);
			break;
		case BMI160_INT2_MAP_ORIENT:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_2_INT2_ORIENT__REG,
			&v_data_u8r, 1);
			*int_orient = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_2_INT2_ORIENT);
			break;
		default:
			comres = E_BMI160_OUT_OF_RANGE;
			break;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 channel, u8 int_orient)
{
BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
u8 v_data_u8r = C_BMI160_ZERO_U8X;
if (p_bmi160 == BMI160_NULL) {
	return E_BMI160_NULL_PTR;
	} else {
	switch (channel) {
	case BMI160_INT1_MAP_ORIENT:
		comres +=
		p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
		dev_addr, BMI160_USER_INT_MAP_0_INT1_ORIENT__REG,
		&v_data_u8r, 1);
		if (comres == SUCCESS) {
			v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_0_INT1_ORIENT, int_orient);
			comres +=
			p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_0_INT1_ORIENT__REG,
			&v_data_u8r, 1);
		}
		break;
	case BMI160_INT2_MAP_ORIENT:
		comres +=
		p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
		dev_addr, BMI160_USER_INT_MAP_2_INT2_ORIENT__REG,
		&v_data_u8r, 1);
		if (comres == SUCCESS) {
			v_data_u8r =
			BMI160_SET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_2_INT2_ORIENT, int_orient);
			comres +=
			p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_2_INT2_ORIENT__REG,
			&v_data_u8r, 1);
		}
		break;
	default:
		comres = E_BMI160_OUT_OF_RANGE;
		break;
	}
}
return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 channel, u8 *int_flat)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		switch (channel) {
		case BMI160_INT1_MAP_FLAT:
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_0_INT1_FLAT__REG,
			&v_data_u8r, 1);
			*int_flat =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_0_INT1_FLAT);
			break;
		case BMI160_INT2_MAP_FLAT:
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_2_INT2_FLAT__REG,
			&v_data_u8r, 1);
			*int_flat =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_2_INT2_FLAT);
			break;
		default:
			comres = E_BMI160_OUT_OF_RANGE;
			break;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 channel, u8 int_flat)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		switch (channel) {
		case BMI160_INT1_MAP_FLAT:
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_0_INT1_FLAT__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r =
				BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_MAP_0_INT1_FLAT, int_flat);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
				dev_addr, BMI160_USER_INT_MAP_0_INT1_FLAT__REG,
				&v_data_u8r, 1);
			}
			break;
		case BMI160_INT2_MAP_FLAT:
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_2_INT2_FLAT__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_MAP_2_INT2_FLAT, int_flat);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
				dev_addr, BMI160_USER_INT_MAP_2_INT2_FLAT__REG,
				&v_data_u8r, 1);
			}
			break;
		default:
			comres = E_BMI160_OUT_OF_RANGE;
			break;
		}
	}
	return comres;
}
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
u8 channel, u8 *int_pmutrig)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		switch (channel) {
		case BMI160_INT1_MAP_PMUTRIG:
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_1_INT1_PMU_TRIG__REG,
			&v_data_u8r, 1);
			*int_pmutrig =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_1_INT1_PMU_TRIG);
			break;
		case BMI160_INT2_MAP_PMUTRIG:
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_1_INT2_PMU_TRIG__REG,
			&v_data_u8r, 1);
			*int_pmutrig =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_1_INT2_PMU_TRIG);
			break;
		default:
			comres = E_BMI160_OUT_OF_RANGE;
			break;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 channel, u8 int_pmutrig)
{
BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
u8 v_data_u8r = C_BMI160_ZERO_U8X;
if (p_bmi160 == BMI160_NULL) {
	return E_BMI160_NULL_PTR;
	} else {
	switch (channel) {
	case BMI160_INT1_MAP_PMUTRIG:
		comres +=
		p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
		dev_addr, BMI160_USER_INT_MAP_1_INT1_PMU_TRIG__REG,
		&v_data_u8r, 1);
		if (comres == SUCCESS) {
			v_data_u8r =
			BMI160_SET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_1_INT1_PMU_TRIG, int_pmutrig);
			comres +=
			p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_1_INT1_PMU_TRIG__REG,
			&v_data_u8r, 1);
		}
	break;
	case BMI160_INT2_MAP_PMUTRIG:
		comres +=
		p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
		dev_addr, BMI160_USER_INT_MAP_1_INT2_PMU_TRIG__REG,
		&v_data_u8r, 1);
		if (comres == SUCCESS) {
			v_data_u8r =
			BMI160_SET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_1_INT2_PMU_TRIG, int_pmutrig);
			comres +=
			p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_1_INT2_PMU_TRIG__REG,
			&v_data_u8r, 1);
		}
	break;
	default:
		comres = E_BMI160_OUT_OF_RANGE;
	break;
	}
}
return comres;
}
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
u8 channel, u8 *int_ffull)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		switch (channel) {
		case BMI160_INT1_MAP_FFULL:
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_1_INT1_FFULL__REG,
			&v_data_u8r, 1);
			*int_ffull =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_1_INT1_FFULL);
		break;
		case BMI160_INT2_MAP_FFULL:
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_1_INT2_FFULL__REG,
			&v_data_u8r, 1);
			*int_ffull =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_1_INT2_FFULL);
		break;
		default:
			comres = E_BMI160_OUT_OF_RANGE;
		break;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 channel, u8 int_ffull)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		switch (channel) {
		case BMI160_INT1_MAP_FFULL:
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_1_INT1_FFULL__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r =
				BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_MAP_1_INT1_FFULL, int_ffull);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
				dev_addr, BMI160_USER_INT_MAP_1_INT1_FFULL__REG,
				&v_data_u8r, 1);
			}
		break;
		case BMI160_INT2_MAP_FFULL:
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_1_INT2_FFULL__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r =
				BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_MAP_1_INT2_FFULL, int_ffull);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
				dev_addr, BMI160_USER_INT_MAP_1_INT2_FFULL__REG,
				&v_data_u8r, 1);
			}
		break;
		default:
			comres = E_BMI160_OUT_OF_RANGE;
		break;
		}
	}
	return comres;
}
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
u8 channel, u8 *int_fwm)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		switch (channel) {
		case BMI160_INT1_MAP_FWM:
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_1_INT1_FWM__REG,
			&v_data_u8r, 1);
			*int_fwm =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_1_INT1_FWM);
			break;
		case BMI160_INT2_MAP_FWM:
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_1_INT2_FWM__REG,
			&v_data_u8r, 1);
			*int_fwm =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_1_INT2_FWM);
			break;
		default:
			comres = E_BMI160_OUT_OF_RANGE;
			break;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 channel, u8 int_fwm)
{
BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
u8 v_data_u8r = C_BMI160_ZERO_U8X;
if (p_bmi160 == BMI160_NULL) {
	return E_BMI160_NULL_PTR;
		} else {
		switch (channel) {
		case BMI160_INT1_MAP_FWM:
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_1_INT1_FWM__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_MAP_1_INT1_FWM, int_fwm);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
				dev_addr, BMI160_USER_INT_MAP_1_INT1_FWM__REG,
				&v_data_u8r, 1);
			}
			break;
		case BMI160_INT2_MAP_FWM:
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_1_INT2_FWM__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_MAP_1_INT2_FWM, int_fwm);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
				dev_addr, BMI160_USER_INT_MAP_1_INT2_FWM__REG,
				&v_data_u8r, 1);
			}
			break;
		default:
			comres = E_BMI160_OUT_OF_RANGE;
			break;
		}
	}
	return comres;
}
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
u8 channel, u8 *int_drdy)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		switch (channel) {
		case BMI160_INT1_MAP_DRDY:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_1_INT1_DRDY__REG,
			&v_data_u8r, 1);
			*int_drdy = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_1_INT1_DRDY);
			break;
		case BMI160_INT2_MAP_DRDY:
			comres += p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_1_INT2_DRDY__REG,
			&v_data_u8r, 1);
			*int_drdy = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MAP_1_INT2_DRDY);
			break;
		default:
			comres = E_BMI160_OUT_OF_RANGE;
			break;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 channel, u8 int_drdy)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		switch (channel) {
		case BMI160_INT1_MAP_DRDY:
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_1_INT1_DRDY__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_MAP_1_INT1_DRDY, int_drdy);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
				dev_addr, BMI160_USER_INT_MAP_1_INT1_DRDY__REG,
				&v_data_u8r, 1);
			}
		break;
		case BMI160_INT2_MAP_DRDY:
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->
			dev_addr, BMI160_USER_INT_MAP_1_INT2_DRDY__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_MAP_1_INT2_DRDY, int_drdy);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(p_bmi160->
				dev_addr, BMI160_USER_INT_MAP_1_INT2_DRDY__REG,
				&v_data_u8r, 1);
			}
		break;
		default:
		comres = E_BMI160_OUT_OF_RANGE;
		break;
		}
	}
	return comres;
}
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
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_tap_src(u8 *tap_src)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_INT_DATA_0_INT_TAP_SRC__REG,
			&v_data_u8r, 1);
			*tap_src = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_DATA_0_INT_TAP_SRC);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 tap_src)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (tap_src < C_BMI160_TWO_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_INT_DATA_0_INT_TAP_SRC__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_DATA_0_INT_TAP_SRC,
				tap_src);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC
				(p_bmi160->dev_addr,
				BMI160_USER_INT_DATA_0_INT_TAP_SRC__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
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
u8 *lowhigh_src)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_INT_DATA_0_INT_LOW_HIGH_SRC__REG,
			&v_data_u8r, 1);
			*lowhigh_src = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_DATA_0_INT_LOW_HIGH_SRC);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 lowhigh_src)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (lowhigh_src < C_BMI160_TWO_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_INT_DATA_0_INT_LOW_HIGH_SRC__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_DATA_0_INT_LOW_HIGH_SRC,
				lowhigh_src);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC
				(p_bmi160->dev_addr,
				BMI160_USER_INT_DATA_0_INT_LOW_HIGH_SRC__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
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
u8 *motion_src)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_INT_DATA_1_INT_MOTION_SRC__REG,
			&v_data_u8r, 1);
			*motion_src = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_DATA_1_INT_MOTION_SRC);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 motion_src)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (motion_src < C_BMI160_TWO_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_INT_DATA_1_INT_MOTION_SRC__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_DATA_1_INT_MOTION_SRC,
				motion_src);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_INT_DATA_1_INT_MOTION_SRC__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
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
u8 *low_dur)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_INT_LOWHIGH_0_INT_LOW_DUR__REG,
			&v_data_u8r, 1);
			*low_dur =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_LOWHIGH_0_INT_LOW_DUR);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_low_dur(u8 low_dur)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_WRITE_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_INT_LOWHIGH_0_INT_LOW_DUR__REG,
			&low_dur, 1);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 *low_threshold)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_INT_LOWHIGH_1_INT_LOW_TH__REG,
			&v_data_u8r, 1);
			*low_threshold =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_LOWHIGH_1_INT_LOW_TH);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 low_threshold)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_WRITE_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_INT_LOWHIGH_1_INT_LOW_TH__REG,
			&low_threshold, 1);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 *low_hysteresis)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_INT_LOWHIGH_2_INT_LOW_HY__REG,
			&v_data_u8r, 1);
			*low_hysteresis = BMI160_GET_BITSLICE(
			v_data_u8r,
			BMI160_USER_INT_LOWHIGH_2_INT_LOW_HY);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 low_hysteresis)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_INT_LOWHIGH_2_INT_LOW_HY__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_LOWHIGH_2_INT_LOW_HY,
				low_hysteresis);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_INT_LOWHIGH_2_INT_LOW_HY__REG,
				&v_data_u8r, 1);
			}
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_low_mode(u8 *low_mode)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_INT_LOWHIGH_2_INT_LOW_MODE__REG,
			&v_data_u8r, 1);
			*low_mode = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_LOWHIGH_2_INT_LOW_MODE);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 low_mode)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (low_mode < C_BMI160_TWO_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_INT_LOWHIGH_2_INT_LOW_MODE__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_LOWHIGH_2_INT_LOW_MODE,
				low_mode);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_INT_LOWHIGH_2_INT_LOW_MODE__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 *high_hysteresis)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_INT_LOWHIGH_2_INT_HIGH_HY__REG,
			&v_data_u8r, 1);
			*high_hysteresis = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_LOWHIGH_2_INT_HIGH_HY);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 high_hysteresis)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_INT_LOWHIGH_2_INT_HIGH_HY__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_LOWHIGH_2_INT_HIGH_HY,
				high_hysteresis);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_INT_LOWHIGH_2_INT_HIGH_HY__REG,
				&v_data_u8r, 1);
			}
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 *high_duration)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_INT_LOWHIGH_3_INT_HIGH_DUR__REG,
			&v_data_u8r, 1);
			*high_duration =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_LOWHIGH_3_INT_HIGH_DUR);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 high_duration)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_WRITE_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_INT_LOWHIGH_3_INT_HIGH_DUR__REG,
			&high_duration, 1);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 *high_threshold)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_INT_LOWHIGH_4_INT_HIGH_TH__REG,
			&v_data_u8r, 1);
			*high_threshold =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_LOWHIGH_4_INT_HIGH_TH);
	}
	return comres;
}
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
u8 high_threshold)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
	} else {
		comres += p_bmi160->BMI160_BUS_WRITE_FUNC(
		p_bmi160->dev_addr,
		BMI160_USER_INT_LOWHIGH_4_INT_HIGH_TH__REG,
		&high_threshold, 1);
	}
	return comres;
}

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
u8 *anymotion_dur)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
	} else {
		comres += p_bmi160->BMI160_BUS_READ_FUNC
		(p_bmi160->dev_addr,
		BMI160_USER_INT_MOTION_0_INT_ANYMO_DUR__REG,
		&v_data_u8r, 1);
		*anymotion_dur = BMI160_GET_BITSLICE
		(v_data_u8r,
		BMI160_USER_INT_MOTION_0_INT_ANYMO_DUR);
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 nomotion)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
	} else {
		comres += p_bmi160->BMI160_BUS_READ_FUNC
		(p_bmi160->dev_addr,
		BMI160_USER_INT_MOTION_0_INT_ANYMO_DUR__REG,
		&v_data_u8r, 1);
		if (comres == SUCCESS) {
			v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MOTION_0_INT_ANYMO_DUR,
			nomotion);
			comres += p_bmi160->BMI160_BUS_WRITE_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_INT_MOTION_0_INT_ANYMO_DUR__REG,
			&v_data_u8r, 1);
		}
	}
	return comres;
}
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
u8 *slow_nomotion)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_INT_MOTION_0_INT_SLO_NOMO_DUR__REG,
			&v_data_u8r, 1);
			*slow_nomotion = BMI160_GET_BITSLICE
			(v_data_u8r,
			BMI160_USER_INT_MOTION_0_INT_SLO_NOMO_DUR);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 slow_nomotion)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
			} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_INT_MOTION_0_INT_SLO_NOMO_DUR__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE
				(v_data_u8r,
				BMI160_USER_INT_MOTION_0_INT_SLO_NOMO_DUR,
				slow_nomotion);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC
				(p_bmi160->dev_addr,
				BMI160_USER_INT_MOTION_0_INT_SLO_NOMO_DUR__REG,
				&v_data_u8r, 1);
			}
		}
	return comres;
}

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
u8 *anymotion_threshold)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_INT_MOTION_1_INT_ANYMOTION_TH__REG,
			&v_data_u8r, 1);
			*anymotion_threshold =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MOTION_1_INT_ANYMOTION_TH);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 anymotion_threshold)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
	} else {
		comres += p_bmi160->BMI160_BUS_WRITE_FUNC
		(p_bmi160->dev_addr,
		BMI160_USER_INT_MOTION_1_INT_ANYMOTION_TH__REG,
		&anymotion_threshold, 1);
	}
	return comres;
}
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
u8 *slo_nomo_threshold)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_INT_MOTION_2_INT_SLO_NOMO_TH__REG,
			&v_data_u8r, 1);
			*slo_nomo_threshold =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MOTION_2_INT_SLO_NOMO_TH);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 slo_nomo_threshold)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_WRITE_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_INT_MOTION_2_INT_SLO_NOMO_TH__REG,
			&slo_nomo_threshold, 1);
		}
	return comres;
}
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
u8 *int_slo_nomo_sel)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_INT_MOTION_3_INT_SLO_NOMO_SEL__REG,
			&v_data_u8r, 1);
			*int_slo_nomo_sel =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_MOTION_3_INT_SLO_NOMO_SEL);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 int_slo_nomo_sel)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (int_slo_nomo_sel < C_BMI160_TWO_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_INT_MOTION_3_INT_SLO_NOMO_SEL__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_MOTION_3_INT_SLO_NOMO_SEL,
				int_slo_nomo_sel);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC
				(p_bmi160->dev_addr,
				BMI160_USER_INT_MOTION_3_INT_SLO_NOMO_SEL__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
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
u8 *int_sig_mot_sel)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_INT_SIG_MOT_SEL__REG,
			&v_data_u8r, 1);
			*int_sig_mot_sel =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_SIG_MOT_SEL);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 int_sig_mot_sel)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (int_sig_mot_sel < C_BMI160_TWO_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_INT_SIG_MOT_SEL__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_SIG_MOT_SEL,
				int_sig_mot_sel);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC
				(p_bmi160->dev_addr,
				BMI160_USER_INT_SIG_MOT_SEL__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
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
u8 *int_sig_mot_skip)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_INT_SIG_MOT_SKIP__REG,
			&v_data_u8r, 1);
			*int_sig_mot_skip =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_SIG_MOT_SKIP);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 int_sig_mot_skip)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (int_sig_mot_skip < C_BMI160_EIGHT_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_INT_SIG_MOT_SKIP__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_SIG_MOT_SKIP,
				int_sig_mot_skip);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC
				(p_bmi160->dev_addr,
				BMI160_USER_INT_SIG_MOT_SKIP__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
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
u8 *int_sig_mot_proof)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_INT_SIG_MOT_PROOF__REG,
			&v_data_u8r, 1);
			*int_sig_mot_proof =
			BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_SIG_MOT_PROOF);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 int_sig_mot_proof)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (int_sig_mot_proof < C_BMI160_EIGHT_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_INT_SIG_MOT_PROOF__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_SIG_MOT_PROOF,
				int_sig_mot_proof);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC
				(p_bmi160->dev_addr,
				BMI160_USER_INT_SIG_MOT_PROOF__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
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
u8 *tap_duration)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_INT_TAP_0_INT_TAP_DUR__REG,
			&v_data_u8r, 1);
			*tap_duration = BMI160_GET_BITSLICE(
			v_data_u8r,
			BMI160_USER_INT_TAP_0_INT_TAP_DUR);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 tap_duration)
{
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 tap_dur = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (tap_duration < C_BMI160_EIGHT_U8X) {
			switch (tap_duration) {
			case BMI160_TAP_DUR_50MS:
				tap_dur = BMI160_TAP_DUR_50MS;
				break;
			case BMI160_TAP_DUR_100MS:
				tap_dur = BMI160_TAP_DUR_100MS;
				break;
			case BMI160_TAP_DUR_150MS:
				tap_dur = BMI160_TAP_DUR_150MS;
				break;
			case BMI160_TAP_DUR_200MS:
				tap_dur = BMI160_TAP_DUR_200MS;
				break;
			case BMI160_TAP_DUR_250MS:
				tap_dur = BMI160_TAP_DUR_250MS;
				break;
			case BMI160_TAP_DUR_375MS:
				tap_dur = BMI160_TAP_DUR_375MS;
				break;
			case BMI160_TAP_DUR_500MS:
				tap_dur = BMI160_TAP_DUR_500MS;
				break;
			case BMI160_TAP_DUR_700MS:
				tap_dur = BMI160_TAP_DUR_700MS;
				break;
			default:
				break;
			}
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_INT_TAP_0_INT_TAP_DUR__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_TAP_0_INT_TAP_DUR,
				tap_dur);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC
				(p_bmi160->dev_addr,
				BMI160_USER_INT_TAP_0_INT_TAP_DUR__REG,
				&v_data_u8r, 1);
			}
		} else{
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
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
u8 *tap_shock)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_INT_TAP_0_INT_TAP_SHOCK__REG,
			&v_data_u8r, 1);
			*tap_shock = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_TAP_0_INT_TAP_SHOCK);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_tap_shock(u8 tap_shock)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (tap_shock < C_BMI160_TWO_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_INT_TAP_0_INT_TAP_SHOCK__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_TAP_0_INT_TAP_SHOCK,
				tap_shock);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC
				(p_bmi160->dev_addr,
				BMI160_USER_INT_TAP_0_INT_TAP_SHOCK__REG,
				&v_data_u8r, 1);
			}
		} else{
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 *tap_quiet)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_INT_TAP_0_INT_TAP_QUIET__REG,
			&v_data_u8r, 1);
			*tap_quiet = BMI160_GET_BITSLICE(
			v_data_u8r,
			BMI160_USER_INT_TAP_0_INT_TAP_QUIET);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
BMI160_RETURN_FUNCTION_TYPE bmi160_set_int_tap_quiet(u8 tap_quiet)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (tap_quiet < C_BMI160_TWO_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_INT_TAP_0_INT_TAP_QUIET__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_TAP_0_INT_TAP_QUIET,
				tap_quiet);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC
				(p_bmi160->dev_addr,
				BMI160_USER_INT_TAP_0_INT_TAP_QUIET__REG,
				&v_data_u8r, 1);
			}
		} else{
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
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
u8 *tap_threshold)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_INT_TAP_1_INT_TAP_TH__REG,
			&v_data_u8r, 1);
			*tap_threshold = BMI160_GET_BITSLICE
			(v_data_u8r,
			BMI160_USER_INT_TAP_1_INT_TAP_TH);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 tap_threshold)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_INT_TAP_1_INT_TAP_TH__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_TAP_1_INT_TAP_TH,
				tap_threshold);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC
				(p_bmi160->dev_addr,
				BMI160_USER_INT_TAP_1_INT_TAP_TH__REG,
				&v_data_u8r, 1);
			}
		}
	return comres;
}
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
u8 *orient_mode)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_INT_ORIENT_0_INT_ORIENT_MODE__REG,
			&v_data_u8r, 1);
			*orient_mode = BMI160_GET_BITSLICE
			(v_data_u8r,
			BMI160_USER_INT_ORIENT_0_INT_ORIENT_MODE);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
/*******************************************************************************
 *	Description: *//**brief This API write the threshold for
 *	switching between different orientations.
 *	from the register 0x65 bit 0 and 1
 *
 *  \param u8 orient_mode : the value of orient_mode
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
u8 orient_mode)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (orient_mode < C_BMI160_FOUR_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_INT_ORIENT_0_INT_ORIENT_MODE__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_ORIENT_0_INT_ORIENT_MODE,
				orient_mode);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC
				(p_bmi160->dev_addr,
				BMI160_USER_INT_ORIENT_0_INT_ORIENT_MODE__REG,
				&v_data_u8r, 1);
			}
		} else{
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 *orient_blocking)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_INT_ORIENT_0_INT_ORIENT_BLOCKING__REG,
			&v_data_u8r, 1);
			*orient_blocking = BMI160_GET_BITSLICE
			(v_data_u8r,
			BMI160_USER_INT_ORIENT_0_INT_ORIENT_BLOCKING);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 orient_blocking)
{
BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
u8 v_data_u8r = C_BMI160_ZERO_U8X;
if (p_bmi160 == BMI160_NULL) {
	return E_BMI160_NULL_PTR;
	} else {
	if (orient_blocking < C_BMI160_FOUR_U8X) {
		comres += p_bmi160->BMI160_BUS_READ_FUNC
		(p_bmi160->dev_addr,
		BMI160_USER_INT_ORIENT_0_INT_ORIENT_BLOCKING__REG,
		&v_data_u8r, 1);
		if (comres == SUCCESS) {
			v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_ORIENT_0_INT_ORIENT_BLOCKING,
			orient_blocking);
			comres += p_bmi160->BMI160_BUS_WRITE_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_INT_ORIENT_0_INT_ORIENT_BLOCKING__REG,
			&v_data_u8r, 1);
		}
	} else {
	comres = E_BMI160_OUT_OF_RANGE;
	}
}
return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 *orient_hysteresis)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_INT_ORIENT_0_INT_ORIENT_HY__REG,
			&v_data_u8r, 1);
			*orient_hysteresis = BMI160_GET_BITSLICE
			(v_data_u8r,
			BMI160_USER_INT_ORIENT_0_INT_ORIENT_HY);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 orient_hysteresis)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_INT_ORIENT_0_INT_ORIENT_HY__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_ORIENT_0_INT_ORIENT_HY,
				orient_hysteresis);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC
				(p_bmi160->dev_addr,
				BMI160_USER_INT_ORIENT_0_INT_ORIENT_HY__REG,
				&v_data_u8r, 1);
			}
		}
	return comres;
}
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
u8 *orient_theta)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_INT_ORIENT_1_INT_ORIENT_THETA__REG,
			&v_data_u8r, 1);
			*orient_theta = BMI160_GET_BITSLICE
			(v_data_u8r,
			BMI160_USER_INT_ORIENT_1_INT_ORIENT_THETA);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 orient_theta)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
	   if (orient_theta <= C_BMI160_THIRTYONE_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_INT_ORIENT_1_INT_ORIENT_THETA__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_ORIENT_1_INT_ORIENT_THETA,
				orient_theta);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC
				(p_bmi160->dev_addr,
				BMI160_USER_INT_ORIENT_1_INT_ORIENT_THETA__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 *orient_ud_en)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_INT_ORIENT_1_INT_ORIENT_UD_EN__REG,
			&v_data_u8r, 1);
			*orient_ud_en = BMI160_GET_BITSLICE
			(v_data_u8r,
			BMI160_USER_INT_ORIENT_1_INT_ORIENT_UD_EN);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 orient_ud_en)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (orient_ud_en < C_BMI160_TWO_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_INT_ORIENT_1_INT_ORIENT_UD_EN__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_ORIENT_1_INT_ORIENT_UD_EN,
				orient_ud_en);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC
				(p_bmi160->dev_addr,
				BMI160_USER_INT_ORIENT_1_INT_ORIENT_UD_EN__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
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
 *****************************************************************************/
BMI160_RETURN_FUNCTION_TYPE bmi160_get_int_orient_axes_ex(
u8 *orient_axes_ex)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_INT_ORIENT_1_INT_ORIENT_AXES_EX__REG,
			&v_data_u8r, 1);
			*orient_axes_ex = BMI160_GET_BITSLICE
			(v_data_u8r,
			BMI160_USER_INT_ORIENT_1_INT_ORIENT_AXES_EX);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 orient_axes_ex)
{
BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
u8 v_data_u8r = C_BMI160_ZERO_U8X;
if (p_bmi160 == BMI160_NULL) {
	return E_BMI160_NULL_PTR;
	} else {
	if (orient_axes_ex < C_BMI160_TWO_U8X) {
		comres += p_bmi160->BMI160_BUS_READ_FUNC
		(p_bmi160->dev_addr,
		BMI160_USER_INT_ORIENT_1_INT_ORIENT_AXES_EX__REG,
		&v_data_u8r, 1);
		if (comres == SUCCESS) {
			v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_ORIENT_1_INT_ORIENT_AXES_EX,
			orient_axes_ex);
			comres += p_bmi160->BMI160_BUS_WRITE_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_INT_ORIENT_1_INT_ORIENT_AXES_EX__REG,
			&v_data_u8r, 1);
		}
	} else {
	comres = E_BMI160_OUT_OF_RANGE;
	}
}
return comres;
}
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
u8 *flat_theta)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_INT_FLAT_0_INT_FLAT_THETA__REG,
			&v_data_u8r, 1);
			*flat_theta = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_FLAT_0_INT_FLAT_THETA);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 flat_theta)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (flat_theta <= C_BMI160_THIRTYONE_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_INT_FLAT_0_INT_FLAT_THETA__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_FLAT_0_INT_FLAT_THETA,
				flat_theta);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC
				(p_bmi160->dev_addr,
				BMI160_USER_INT_FLAT_0_INT_FLAT_THETA__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 *flat_hold)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_INT_FLAT_1_INT_FLAT_HOLD__REG,
			&v_data_u8r, 1);
			*flat_hold = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_INT_FLAT_1_INT_FLAT_HOLD);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 flat_hold)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
		if (flat_hold < C_BMI160_FOUR_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_INT_FLAT_1_INT_FLAT_HOLD__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_FLAT_1_INT_FLAT_HOLD,
				flat_hold);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC
				(p_bmi160->dev_addr,
				BMI160_USER_INT_FLAT_1_INT_FLAT_HOLD__REG,
				&v_data_u8r, 1);
			}
		} else{
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 *flat_hysteresis)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_INT_FLAT_1_INT_FLAT_HY__REG,
			&v_data_u8r, 1);
			*flat_hysteresis = BMI160_GET_BITSLICE(
			v_data_u8r,
			BMI160_USER_INT_FLAT_1_INT_FLAT_HY);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 flat_hysteresis)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (flat_hysteresis < C_BMI160_SIXTEEN_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_INT_FLAT_1_INT_FLAT_HY__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_INT_FLAT_1_INT_FLAT_HY,
				flat_hysteresis);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC
				(p_bmi160->dev_addr,
				BMI160_USER_INT_FLAT_1_INT_FLAT_HY__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
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
BMI160_RETURN_FUNCTION_TYPE bmi160_get_foc_acc_z(u8 *foc_acc_z)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_FOC_ACC_Z__REG,
			&v_data_u8r, 1);
			*foc_acc_z = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_FOC_ACC_Z);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 foc_acc_z)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_FOC_ACC_Z__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_FOC_ACC_Z,
				foc_acc_z);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC
				(p_bmi160->dev_addr,
				BMI160_USER_FOC_ACC_Z__REG,
				&v_data_u8r, 1);
			}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
BMI160_RETURN_FUNCTION_TYPE bmi160_get_foc_acc_y(u8 *foc_acc_y)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_FOC_ACC_Y__REG,
			&v_data_u8r, 1);
			*foc_acc_y = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_FOC_ACC_Y);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
BMI160_RETURN_FUNCTION_TYPE bmi160_set_foc_acc_y(u8 foc_acc_y)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (foc_acc_y < C_BMI160_FOUR_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_FOC_ACC_Y__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_FOC_ACC_Y,
				foc_acc_y);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC
				(p_bmi160->dev_addr,
				BMI160_USER_FOC_ACC_Y__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
BMI160_RETURN_FUNCTION_TYPE bmi160_get_foc_acc_x(u8 *foc_acc_x)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
	} else {
		comres += p_bmi160->BMI160_BUS_READ_FUNC(
		p_bmi160->dev_addr,
		BMI160_USER_FOC_ACC_X__REG,
		&v_data_u8r, 1);
		*foc_acc_x = BMI160_GET_BITSLICE(v_data_u8r,
		BMI160_USER_FOC_ACC_X);
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
BMI160_RETURN_FUNCTION_TYPE bmi160_set_foc_acc_x(u8 foc_acc_x)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (foc_acc_x < C_BMI160_FOUR_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_FOC_ACC_X__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_FOC_ACC_X,
				foc_acc_x);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_FOC_ACC_X__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 foc_acc, s8 *accel_offset)
{
BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
u8 v_data_u8r = C_BMI160_ZERO_U8X;
u8 status = SUCCESS;
u8 timeout = C_BMI160_ZERO_U8X;
s8 foc_accel_offset_x  = C_BMI160_ZERO_U8X;
s8 foc_accel_offset_y =  C_BMI160_ZERO_U8X;
s8 foc_accel_offset_z =  C_BMI160_ZERO_U8X;
u8 focstatus = C_BMI160_ZERO_U8X;
if (p_bmi160 == BMI160_NULL) {
	return E_BMI160_NULL_PTR;
	} else {
		status = bmi160_set_accel_offset_enable(
		ACCEL_OFFSET_ENABLE);
		if (status == SUCCESS) {
			switch (axis) {
			case FOC_X_AXIS:
				comres +=
				p_bmi160->BMI160_BUS_READ_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_FOC_ACC_X__REG,
				&v_data_u8r, 1);
				if (comres == SUCCESS) {
					v_data_u8r =
					BMI160_SET_BITSLICE(v_data_u8r,
					BMI160_USER_FOC_ACC_X,
					foc_acc);
					comres +=
					p_bmi160->BMI160_BUS_WRITE_FUNC(
					p_bmi160->dev_addr,
					BMI160_USER_FOC_ACC_X__REG,
					&v_data_u8r, 1);
				}

				/* trigger the
				FOC need to write
				0x03 in the register 0x7e*/
				comres +=
				bmi160_set_command_register(
				START_FOC_ACCEL_GYRO);

				comres +=
				bmi160_get_foc_rdy(&focstatus);
				if ((comres != SUCCESS) ||
				(focstatus != C_BMI160_ONE_U8X)) {
					while ((comres != SUCCESS) ||
					(focstatus != C_BMI160_ONE_U8X
					&& timeout < BMI160_MAXIMUM_TIMEOUT)) {
						p_bmi160->delay_msec(
						BMI160_DELAY_SETTLING_TIME);
						comres = bmi160_get_foc_rdy(
						&focstatus);
						timeout++;
					}
				}
				if ((comres == SUCCESS) &&
					(focstatus == C_BMI160_ONE_U8X)) {
					comres +=
					bmi160_get_acc_off_comp_xaxis(
					&foc_accel_offset_x);
					*accel_offset = foc_accel_offset_x;
				}
			break;
			case FOC_Y_AXIS:
				comres +=
				p_bmi160->BMI160_BUS_READ_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_FOC_ACC_Y__REG,
				&v_data_u8r, 1);
				if (comres == SUCCESS) {
					v_data_u8r =
					BMI160_SET_BITSLICE(v_data_u8r,
					BMI160_USER_FOC_ACC_Y,
					foc_acc);
					comres +=
					p_bmi160->BMI160_BUS_WRITE_FUNC(
					p_bmi160->dev_addr,
					BMI160_USER_FOC_ACC_Y__REG,
					&v_data_u8r, 1);
				}

				/* trigger the FOC
				need to write 0x03
				in the register 0x7e*/
				comres +=
				bmi160_set_command_register(
				START_FOC_ACCEL_GYRO);

				comres +=
				bmi160_get_foc_rdy(&focstatus);
				if ((comres != SUCCESS) ||
				(focstatus != C_BMI160_ONE_U8X)) {
					while ((comres != SUCCESS) ||
					(focstatus != C_BMI160_ONE_U8X
					&& timeout < BMI160_MAXIMUM_TIMEOUT)) {
						p_bmi160->delay_msec(
						BMI160_DELAY_SETTLING_TIME);
						comres = bmi160_get_foc_rdy(
						&focstatus);
						timeout++;
					}
				}
				if ((comres == SUCCESS) &&
				(focstatus == C_BMI160_ONE_U8X)) {
					comres +=
					bmi160_get_acc_off_comp_yaxis(
					&foc_accel_offset_y);
					*accel_offset = foc_accel_offset_y;
				}
			break;
			case FOC_Z_AXIS:
				comres +=
				p_bmi160->BMI160_BUS_READ_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_FOC_ACC_Z__REG,
				&v_data_u8r, 1);
				if (comres == SUCCESS) {
					v_data_u8r =
					BMI160_SET_BITSLICE(v_data_u8r,
					BMI160_USER_FOC_ACC_Z,
					foc_acc);
					comres +=
					p_bmi160->BMI160_BUS_WRITE_FUNC(
					p_bmi160->dev_addr,
					BMI160_USER_FOC_ACC_Z__REG,
					&v_data_u8r, 1);
				}

				/* trigger the FOC need to write
				0x03 in the register 0x7e*/
				comres +=
				bmi160_set_command_register(
				START_FOC_ACCEL_GYRO);

				comres +=
				bmi160_get_foc_rdy(&focstatus);
				if ((comres != SUCCESS) ||
				(focstatus != C_BMI160_ONE_U8X)) {
					while ((comres != SUCCESS) ||
					(focstatus != C_BMI160_ONE_U8X
					&& timeout < BMI160_MAXIMUM_TIMEOUT)) {
						p_bmi160->delay_msec(
						BMI160_DELAY_SETTLING_TIME);
						comres = bmi160_get_foc_rdy(
						&focstatus);
						timeout++;
					}
				}
				if ((comres == SUCCESS) &&
				(focstatus == C_BMI160_ONE_U8X)) {
					comres +=
					bmi160_get_acc_off_comp_zaxis(
					&foc_accel_offset_z);
					*accel_offset = foc_accel_offset_z;
				}
			break;
			default:
			break;
			}
		} else {
		return ERROR;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 foc_accy, u8 foc_accz, s8 *acc_off_x, s8 *acc_off_y, s8 *acc_off_z)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 focx = C_BMI160_ZERO_U8X;
	u8 focy = C_BMI160_ZERO_U8X;
	u8 focz = C_BMI160_ZERO_U8X;
	s8 foc_accel_offset_x = C_BMI160_ZERO_U8X;
	s8 foc_accel_offset_y = C_BMI160_ZERO_U8X;
	s8 foc_accel_offset_z = C_BMI160_ZERO_U8X;
	u8 status = SUCCESS;
	u8 timeout = C_BMI160_ZERO_U8X;
	u8 focstatus = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			status = bmi160_set_accel_offset_enable(
			ACCEL_OFFSET_ENABLE);
			if (status == SUCCESS) {
				/* foc x axis*/
				comres +=
				p_bmi160->BMI160_BUS_READ_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_FOC_ACC_X__REG,
				&focx, 1);
				if (comres == SUCCESS) {
					focx = BMI160_SET_BITSLICE(focx,
					BMI160_USER_FOC_ACC_X,
					foc_accx);
					comres +=
					p_bmi160->BMI160_BUS_WRITE_FUNC(
					p_bmi160->dev_addr,
					BMI160_USER_FOC_ACC_X__REG,
					&focx, 1);
				}

				/* foc y axis*/
				comres +=
				p_bmi160->BMI160_BUS_READ_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_FOC_ACC_Y__REG,
				&focy, 1);
				if (comres == SUCCESS) {
					focy = BMI160_SET_BITSLICE(focy,
					BMI160_USER_FOC_ACC_Y,
					foc_accy);
					comres +=
					p_bmi160->BMI160_BUS_WRITE_FUNC(
					p_bmi160->dev_addr,
					BMI160_USER_FOC_ACC_Y__REG,
					&focy, 1);
				}

				/* foc z axis*/
				comres +=
				p_bmi160->BMI160_BUS_READ_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_FOC_ACC_Z__REG,
				&focz, 1);
				if (comres == SUCCESS) {
					focz = BMI160_SET_BITSLICE(focz,
					BMI160_USER_FOC_ACC_Z,
					foc_accz);
					comres +=
					p_bmi160->BMI160_BUS_WRITE_FUNC(
					p_bmi160->dev_addr,
					BMI160_USER_FOC_ACC_Z__REG,
					&focz, 1);
				}

				/* trigger the FOC need to
				write 0x03 in the register 0x7e*/
				comres += bmi160_set_command_register(
				START_FOC_ACCEL_GYRO);

				comres += bmi160_get_foc_rdy(
				&focstatus);
				if ((comres != SUCCESS) ||
				(focstatus != C_BMI160_ONE_U8X)) {
					while ((comres != SUCCESS) ||
					(focstatus != C_BMI160_ONE_U8X
					&& timeout < BMI160_MAXIMUM_TIMEOUT)) {
						p_bmi160->delay_msec(
						BMI160_DELAY_SETTLING_TIME);
						comres = bmi160_get_foc_rdy(
						&focstatus);
						timeout++;
					}
				}
				if ((comres == SUCCESS) &&
				(focstatus == C_BMI160_ONE_U8X)) {
					comres +=
					bmi160_get_acc_off_comp_xaxis(
					&foc_accel_offset_x);
					*acc_off_x = foc_accel_offset_x;
					comres +=
					bmi160_get_acc_off_comp_yaxis(
					&foc_accel_offset_y);
					*acc_off_y = foc_accel_offset_y;
					comres +=
					bmi160_get_acc_off_comp_zaxis(
					&foc_accel_offset_z);
					*acc_off_z = foc_accel_offset_z;
				}
			} else {
			return ERROR;
			}
		}
	return comres;
}
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
u8 *foc_gyr_en)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_FOC_GYR_EN__REG,
			&v_data_u8r, 1);
			*foc_gyr_en = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_FOC_GYR_EN);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 foc_gyr_en, s16 *gyr_off_x, s16 *gyr_off_y, s16 *gyr_off_z)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	u8 status = SUCCESS;
	u8 timeout = C_BMI160_ZERO_U8X;
	s16 offsetx = C_BMI160_ZERO_U8X;
	s16 offsety = C_BMI160_ZERO_U8X;
	s16 offsetz = C_BMI160_ZERO_U8X;
	u8 focstatus = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			status = bmi160_set_gyro_offset_enable(
			GYRO_OFFSET_ENABLE);
			if (status == SUCCESS) {
				comres +=
				p_bmi160->BMI160_BUS_READ_FUNC
				(p_bmi160->dev_addr,
				BMI160_USER_FOC_GYR_EN__REG,
				&v_data_u8r, 1);
				if (comres == SUCCESS) {
					v_data_u8r =
					BMI160_SET_BITSLICE(v_data_u8r,
					BMI160_USER_FOC_GYR_EN,
					foc_gyr_en);
					comres +=
					p_bmi160->BMI160_BUS_WRITE_FUNC
					(p_bmi160->dev_addr,
					BMI160_USER_FOC_GYR_EN__REG,
					&v_data_u8r, 1);
				}

				/* trigger the FOC need to write 0x03
				in the register 0x7e*/
				comres += bmi160_set_command_register
				(START_FOC_ACCEL_GYRO);

				comres += bmi160_get_foc_rdy(&focstatus);
				if ((comres != SUCCESS) ||
				(focstatus != C_BMI160_ONE_U8X)) {
					while ((comres != SUCCESS) ||
					(focstatus != C_BMI160_ONE_U8X
					&& timeout < BMI160_MAXIMUM_TIMEOUT)) {
						p_bmi160->delay_msec(
						BMI160_DELAY_SETTLING_TIME);
						comres = bmi160_get_foc_rdy(
						&focstatus);
						timeout++;
					}
				}
				if ((comres == SUCCESS) &&
				(focstatus == C_BMI160_ONE_U8X)) {
					comres +=
					bmi160_get_gyro_off_comp_xaxis
					(&offsetx);
					*gyr_off_x = offsetx;

					comres +=
					bmi160_get_gyro_off_comp_yaxis
					(&offsety);
					*gyr_off_y = offsety;

					comres +=
					bmi160_get_gyro_off_comp_zaxis(
					&offsetz);
					*gyr_off_z = offsetz;
				}
			} else {
			return ERROR;
			}
		}
	return comres;
}
/*******************************************************************************
 * Description: *//**brief This API Reads Enable
 * NVM programming the register 0x6A bit 1
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
u8 *nvm_prog_en)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_CONF_NVM_PROG_EN__REG,
			&v_data_u8r, 1);
			*nvm_prog_en = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_CONF_NVM_PROG_EN);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 nvm_prog_en)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (nvm_prog_en < C_BMI160_TWO_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_CONF_NVM_PROG_EN__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_CONF_NVM_PROG_EN,
				nvm_prog_en);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_CONF_NVM_PROG_EN__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 *spi3)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_IF_CONF_SPI3__REG,
			&v_data_u8r, 1);
			*spi3 = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_IF_CONF_SPI3);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 spi3)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (spi3 < C_BMI160_TWO_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_IF_CONF_SPI3__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_IF_CONF_SPI3,
				spi3);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_IF_CONF_SPI3__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 *i2c_wdt_sel)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_IF_CONF_I2C_WDT_SEL__REG,
			&v_data_u8r, 1);
			*i2c_wdt_sel = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_IF_CONF_I2C_WDT_SEL);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
BMI160_RETURN_FUNCTION_TYPE bmi160_set_i2c_wdt_sel(
u8 i2c_wdt_sel)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (i2c_wdt_sel < C_BMI160_TWO_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_IF_CONF_I2C_WDT_SEL__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_IF_CONF_I2C_WDT_SEL,
				i2c_wdt_sel);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_IF_CONF_I2C_WDT_SEL__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 *i2c_wdt_en)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_IF_CONF_I2C_WDT_EN__REG,
			&v_data_u8r, 1);
			*i2c_wdt_en = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_IF_CONF_I2C_WDT_EN);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 i2c_wdt_en)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (i2c_wdt_en < C_BMI160_TWO_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_IF_CONF_I2C_WDT_EN__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_IF_CONF_I2C_WDT_EN,
				i2c_wdt_en);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_IF_CONF_I2C_WDT_EN__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}


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
u8 *if_mode)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_IF_CONF_IF_MODE__REG,
			&v_data_u8r, 1);
			*if_mode = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_IF_CONF_IF_MODE);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 if_mode)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (if_mode <= C_BMI160_FOUR_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_IF_CONF_IF_MODE__REG,
			&v_data_u8r, 1);
			p_bmi160->delay_msec(10);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_IF_CONF_IF_MODE,
				if_mode);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_IF_CONF_IF_MODE__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
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
u8 *gyro_sleep_trigger)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_GYRO_SLEEP_TRIGGER__REG,
			&v_data_u8r, 1);
			*gyro_sleep_trigger = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_GYRO_SLEEP_TRIGGER);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 gyro_sleep_trigger)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (gyro_sleep_trigger <= C_BMI160_SEVEN_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_GYRO_SLEEP_TRIGGER__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_GYRO_SLEEP_TRIGGER,
				gyro_sleep_trigger);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_GYRO_SLEEP_TRIGGER__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 *gyro_wakeup_trigger)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_GYRO_WAKEUP_TRIGGER__REG,
			&v_data_u8r, 1);
			*gyro_wakeup_trigger = BMI160_GET_BITSLICE(
			v_data_u8r,
			BMI160_USER_GYRO_WAKEUP_TRIGGER);
	  }
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 gyro_wakeup_trigger)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (gyro_wakeup_trigger <= C_BMI160_THREE_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_GYRO_WAKEUP_TRIGGER__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_GYRO_WAKEUP_TRIGGER,
				gyro_wakeup_trigger);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_GYRO_WAKEUP_TRIGGER__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 *gyro_sleep_state)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_GYRO_SLEEP_STATE__REG,
			&v_data_u8r, 1);
			*gyro_sleep_state = BMI160_GET_BITSLICE(
			v_data_u8r,
			BMI160_USER_GYRO_SLEEP_STATE);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 gyro_sleep_state)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (gyro_sleep_state < C_BMI160_TWO_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_GYRO_SLEEP_STATE__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_GYRO_SLEEP_STATE,
				gyro_sleep_state);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_GYRO_SLEEP_STATE__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 *gyro_wakeup_int)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_GYRO_WAKEUP_INT__REG,
			&v_data_u8r, 1);
			*gyro_wakeup_int = BMI160_GET_BITSLICE(
			v_data_u8r,
			BMI160_USER_GYRO_WAKEUP_INT);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 gyro_wakeup_int)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (gyro_wakeup_int < C_BMI160_TWO_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_GYRO_WAKEUP_INT__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_GYRO_WAKEUP_INT,
				gyro_wakeup_int);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_GYRO_WAKEUP_INT__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}

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
u8 *acc_selftest_axis)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_ACC_SELF_TEST_AXIS__REG,
			&v_data_u8r, 1);
			*acc_selftest_axis = BMI160_GET_BITSLICE(
			v_data_u8r,
			BMI160_USER_ACC_SELF_TEST_AXIS);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 acc_selftest_axis)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (acc_selftest_axis <= C_BMI160_THREE_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_ACC_SELF_TEST_AXIS__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_ACC_SELF_TEST_AXIS,
				acc_selftest_axis);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_ACC_SELF_TEST_AXIS__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 *acc_selftest_sign)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_ACC_SELF_TEST_SIGN__REG,
			&v_data_u8r, 1);
			*acc_selftest_sign = BMI160_GET_BITSLICE(
			v_data_u8r,
			BMI160_USER_ACC_SELF_TEST_SIGN);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 acc_selftest_sign)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (acc_selftest_sign < C_BMI160_TWO_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_ACC_SELF_TEST_SIGN__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_ACC_SELF_TEST_SIGN,
				acc_selftest_sign);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_ACC_SELF_TEST_SIGN__REG,
				&v_data_u8r, 1);
			}
		} else {
			comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 *acc_selftest_amp)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_SELF_TEST_AMP__REG,
			&v_data_u8r, 1);
			*acc_selftest_amp = BMI160_GET_BITSLICE(
			v_data_u8r,
			BMI160_USER_SELF_TEST_AMP);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 acc_selftest_amp)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (acc_selftest_amp < C_BMI160_TWO_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_SELF_TEST_AMP__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_SELF_TEST_AMP,
				acc_selftest_amp);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_SELF_TEST_AMP__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}

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
u8 *gyr_self_test_start)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_GYRO_SELF_TEST_START__REG,
			&v_data_u8r, 1);
			*gyr_self_test_start = BMI160_GET_BITSLICE(
			v_data_u8r,
			BMI160_USER_GYRO_SELF_TEST_START);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 gyr_self_test_start)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
		if (gyr_self_test_start < C_BMI160_TWO_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_GYRO_SELF_TEST_START__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_GYRO_SELF_TEST_START,
				gyr_self_test_start);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_GYRO_SELF_TEST_START__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
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
BMI160_RETURN_FUNCTION_TYPE bmi160_get_spi_enable(u8 *spi_en)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_NV_CONF_SPI_EN__REG,
			&v_data_u8r, 1);
			*spi_en = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_NV_CONF_SPI_EN);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
BMI160_RETURN_FUNCTION_TYPE bmi160_set_spi_enable(u8 spi_en)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_NV_CONF_SPI_EN__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_NV_CONF_SPI_EN,
				spi_en);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC
				(p_bmi160->dev_addr,
				BMI160_USER_NV_CONF_SPI_EN__REG,
				&v_data_u8r, 1);
			}
		}
	return comres;
}
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
BMI160_RETURN_FUNCTION_TYPE bmi160_get_spare0_trim(u8 *spare0_trim)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_NV_CONF_SPARE0__REG,
			&v_data_u8r, 1);
			*spare0_trim = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_NV_CONF_SPARE0);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
BMI160_RETURN_FUNCTION_TYPE bmi160_set_spare0_trim(u8 spare0_trim)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_NV_CONF_SPARE0__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_NV_CONF_SPARE0,
				spare0_trim);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_NV_CONF_SPARE0__REG,
				&v_data_u8r, 1);
			}
		}
	return comres;
}
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
BMI160_RETURN_FUNCTION_TYPE bmi160_get_nvm_counter(u8 *nvm_counter)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_NV_CONF_NVM_COUNTER__REG,
			&v_data_u8r, 1);
			*nvm_counter = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_NV_CONF_NVM_COUNTER);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 nvm_counter)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_NV_CONF_NVM_COUNTER__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_NV_CONF_NVM_COUNTER,
				nvm_counter);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_NV_CONF_NVM_COUNTER__REG,
				&v_data_u8r, 1);
			}
		}
	return comres;
}
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
s8 *acc_off_x)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_OFFSET_0_ACC_OFF_X__REG,
			&v_data_u8r, 1);
			*acc_off_x = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_OFFSET_0_ACC_OFF_X);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
s8 acc_off_x)
{
BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
u8 v_data_u8r = C_BMI160_ZERO_U8X;
u8 status = SUCCESS;
if (p_bmi160 == BMI160_NULL) {
	return E_BMI160_NULL_PTR;
	} else {
		status = bmi160_set_accel_offset_enable(
		ACCEL_OFFSET_ENABLE);
		if (status == SUCCESS) {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_OFFSET_0_ACC_OFF_X__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r =
				BMI160_SET_BITSLICE(
				v_data_u8r,
				BMI160_USER_OFFSET_0_ACC_OFF_X,
				acc_off_x);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_OFFSET_0_ACC_OFF_X__REG,
				&v_data_u8r, 1);
			}
		} else {
		return ERROR;
		}
	}
	return comres;
}
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
s8 *acc_off_y)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_OFFSET_1_ACC_OFF_Y__REG,
			&v_data_u8r, 1);
			*acc_off_y = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_OFFSET_1_ACC_OFF_Y);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
s8 acc_off_y)
{
BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
u8 v_data_u8r = C_BMI160_ZERO_U8X;
u8 status = SUCCESS;
if (p_bmi160 == BMI160_NULL) {
	return E_BMI160_NULL_PTR;
	} else {
		status = bmi160_set_accel_offset_enable(
		ACCEL_OFFSET_ENABLE);
		if (status == SUCCESS) {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_OFFSET_1_ACC_OFF_Y__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r =
				BMI160_SET_BITSLICE(
				v_data_u8r,
				BMI160_USER_OFFSET_1_ACC_OFF_Y,
				acc_off_y);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_OFFSET_1_ACC_OFF_Y__REG,
				&v_data_u8r, 1);
			}
		} else {
		return ERROR;
		}
	}
	return comres;
}
/******************************************************************************
 *	Description: *//**brief This API Reads
 *	acc_off_z from the register 0x72 bit 0 to 7
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
s8 *acc_off_z)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else{
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_OFFSET_2_ACC_OFF_Z__REG,
			&v_data_u8r, 1);
			*acc_off_z = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_OFFSET_2_ACC_OFF_Z);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
/*******************************************************************************
 *	Description: *//**brief This API Writes
 *	acc_off_z from the register 0x72 bit 0 to 7
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
s8 acc_off_z)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	u8 status = SUCCESS;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			status = bmi160_set_accel_offset_enable(
			ACCEL_OFFSET_ENABLE);
			if (status == SUCCESS) {
				comres +=
				p_bmi160->BMI160_BUS_READ_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_OFFSET_2_ACC_OFF_Z__REG,
				&v_data_u8r, 1);
				if (comres == SUCCESS) {
					v_data_u8r =
					BMI160_SET_BITSLICE(v_data_u8r,
					BMI160_USER_OFFSET_2_ACC_OFF_Z,
					acc_off_z);
					comres +=
					p_bmi160->BMI160_BUS_WRITE_FUNC(
					p_bmi160->dev_addr,
					BMI160_USER_OFFSET_2_ACC_OFF_Z__REG,
					&v_data_u8r, 1);
				}
			} else {
			return ERROR;
			}
		}
	return comres;
}
/******************************************************************************
 *	Description: *//**brief This API Reads
 *	gyr_off_x from the register 0x74 bit 0 to 7
 *
 *
 *
 *
 *  \param u8 * gyr_off_x:
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
s16 *gyr_off_x)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data1_u8r = C_BMI160_ZERO_U8X;
	u8 v_data2_u8r = C_BMI160_ZERO_U8X;
	s16 v_data3_u8r, v_data4_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_OFFSET_3_GYR_OFF_X__REG,
			&v_data1_u8r, 1);
			v_data1_u8r = BMI160_GET_BITSLICE(v_data1_u8r,
			BMI160_USER_OFFSET_3_GYR_OFF_X);
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_OFFSET_6_GYR_OFF_X__REG,
			&v_data2_u8r, 1);
			v_data2_u8r = BMI160_GET_BITSLICE(v_data2_u8r,
			BMI160_USER_OFFSET_6_GYR_OFF_X);
			v_data3_u8r = v_data2_u8r << C_BMI160_FOURTEEN_U8X;
			v_data4_u8r =  v_data1_u8r << C_BMI160_SIX_U8X;
			v_data3_u8r = v_data3_u8r | v_data4_u8r;
			*gyr_off_x = v_data3_u8r >> C_BMI160_SIX_U8X;
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
/*******************************************************************************
 *	Description: *//**brief This API Writes
 *	gyr_off_x from the register 0x74 bit 0 to 7
 *
 *  \param u8 gyr_off_x :
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
s16 gyr_off_x)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data1_u8r, v_data2_u8r = C_BMI160_ZERO_U8X;
	u16 v_data3_u8r = C_BMI160_ZERO_U8X;
	u8 status = SUCCESS;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			status = bmi160_set_gyro_offset_enable(
			GYRO_OFFSET_ENABLE);
			if (status == SUCCESS) {
				comres += p_bmi160->BMI160_BUS_READ_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_OFFSET_3_GYR_OFF_X__REG,
				&v_data2_u8r, 1);
				if (comres == SUCCESS) {
					v_data1_u8r =
					((s8) (gyr_off_x & 0x00FF));
					v_data2_u8r = BMI160_SET_BITSLICE(
					v_data2_u8r,
					BMI160_USER_OFFSET_3_GYR_OFF_X,
					v_data1_u8r);
					comres +=
					p_bmi160->BMI160_BUS_WRITE_FUNC(
					p_bmi160->dev_addr,
					BMI160_USER_OFFSET_3_GYR_OFF_X__REG,
					&v_data2_u8r, 1);
				}

				comres += p_bmi160->BMI160_BUS_READ_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_OFFSET_6_GYR_OFF_X__REG,
				&v_data2_u8r, 1);
				if (comres == SUCCESS) {
					v_data3_u8r =
					(u16) (gyr_off_x & 0x0300);
					v_data1_u8r = (u8)(v_data3_u8r
					>> BMI160_SHIFT_8_POSITION);
					v_data2_u8r = BMI160_SET_BITSLICE(
					v_data2_u8r,
					BMI160_USER_OFFSET_6_GYR_OFF_X,
					v_data1_u8r);
					comres +=
					p_bmi160->BMI160_BUS_WRITE_FUNC(
					p_bmi160->dev_addr,
					BMI160_USER_OFFSET_6_GYR_OFF_X__REG,
					&v_data2_u8r, 1);
				}
			} else {
			return ERROR;
			}
		}
	return comres;
}
/******************************************************************************
 *	Description: *//**brief This API Reads
 *	gyr_off_y from the register 0x75 bit 0 to 7
 *
 *
 *
 *  \param u8 * gyr_off_y:
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
s16 *gyr_off_y)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data1_u8r = C_BMI160_ZERO_U8X;
	u8 v_data2_u8r = C_BMI160_ZERO_U8X;
	s16 v_data3_u8r, v_data4_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_OFFSET_4_GYR_OFF_Y__REG,
			&v_data1_u8r, 1);
			v_data1_u8r = BMI160_GET_BITSLICE(v_data1_u8r,
			BMI160_USER_OFFSET_4_GYR_OFF_Y);
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_OFFSET_6_GYR_OFF_Y__REG,
			&v_data2_u8r, 1);
			v_data2_u8r = BMI160_GET_BITSLICE(v_data2_u8r,
			BMI160_USER_OFFSET_6_GYR_OFF_Y);
			v_data3_u8r = v_data2_u8r << C_BMI160_FOURTEEN_U8X;
			v_data4_u8r =  v_data1_u8r << C_BMI160_SIX_U8X;
			v_data3_u8r = v_data3_u8r | v_data4_u8r;
			*gyr_off_y = v_data3_u8r >> C_BMI160_SIX_U8X;
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
/*******************************************************************************
 *	Description: *//**brief This API Writes
 *	gyr_off_y from the register 0x75 bit 0 to 7
 *
 *  \param u8 gyr_off_y :
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
s16 gyr_off_y)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data1_u8r, v_data2_u8r = C_BMI160_ZERO_U8X;
	u16 v_data3_u8r = C_BMI160_ZERO_U8X;
	u8 status = SUCCESS;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			status = bmi160_set_gyro_offset_enable(
			GYRO_OFFSET_ENABLE);
			if (status == SUCCESS) {
				comres += p_bmi160->BMI160_BUS_READ_FUNC
				(p_bmi160->dev_addr,
				BMI160_USER_OFFSET_4_GYR_OFF_Y__REG,
				&v_data2_u8r, 1);
				if (comres == SUCCESS) {
					v_data1_u8r =
					((s8) (gyr_off_y & 0x00FF));
					v_data2_u8r = BMI160_SET_BITSLICE(
					v_data2_u8r,
					BMI160_USER_OFFSET_4_GYR_OFF_Y,
					v_data1_u8r);
					comres +=
					p_bmi160->BMI160_BUS_WRITE_FUNC
					(p_bmi160->dev_addr,
					BMI160_USER_OFFSET_4_GYR_OFF_Y__REG,
					&v_data2_u8r, 1);
				}

				comres += p_bmi160->BMI160_BUS_READ_FUNC
				(p_bmi160->dev_addr,
				BMI160_USER_OFFSET_6_GYR_OFF_Y__REG,
				&v_data2_u8r, 1);
				if (comres == SUCCESS) {
					v_data3_u8r =
					(u16) (gyr_off_y & 0x0300);
					v_data1_u8r = (u8)(v_data3_u8r
					>> BMI160_SHIFT_8_POSITION);
					v_data2_u8r = BMI160_SET_BITSLICE(
					v_data2_u8r,
					BMI160_USER_OFFSET_6_GYR_OFF_Y,
					v_data1_u8r);
					comres +=
					p_bmi160->BMI160_BUS_WRITE_FUNC
					(p_bmi160->dev_addr,
					BMI160_USER_OFFSET_6_GYR_OFF_Y__REG,
					&v_data2_u8r, 1);
				}
			} else {
			return ERROR;
			}
		}
	return comres;
}
/******************************************************************************
 *	Description: *//**brief This API Reads
 *	gyr_off_z from the register 0x76 bit 0 to 7
 *
 *
 *
 *  \param u8 * gyr_off_z:
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
s16 *gyr_off_z)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data1_u8r = C_BMI160_ZERO_U8X;
	u8 v_data2_u8r = C_BMI160_ZERO_U8X;
	s16 v_data3_u8r, v_data4_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_OFFSET_5_GYR_OFF_Z__REG,
			&v_data1_u8r, 1);
			v_data1_u8r = BMI160_GET_BITSLICE
			(v_data1_u8r,
			BMI160_USER_OFFSET_5_GYR_OFF_Z);
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_OFFSET_6_GYR_OFF_Z__REG,
			&v_data2_u8r, 1);
			v_data2_u8r = BMI160_GET_BITSLICE(
			v_data2_u8r,
			BMI160_USER_OFFSET_6_GYR_OFF_Z);
			v_data3_u8r = v_data2_u8r << C_BMI160_FOURTEEN_U8X;
			v_data4_u8r =  v_data1_u8r << C_BMI160_SIX_U8X;
			v_data3_u8r = v_data3_u8r | v_data4_u8r;
			*gyr_off_z = v_data3_u8r >> C_BMI160_SIX_U8X;
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
/*******************************************************************************
 *	Description: *//**brief This API Writes
 *	gyr_off_z from the register 0x76 bit 0 to 7
 *
 *  \param u8 gyr_off_z :
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
s16 gyr_off_z)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data1_u8r, v_data2_u8r = C_BMI160_ZERO_U8X;
	u16 v_data3_u8r = C_BMI160_ZERO_U8X;
	u8 status = SUCCESS;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			status = bmi160_set_gyro_offset_enable(
			GYRO_OFFSET_ENABLE);
			if (status == SUCCESS) {
				comres += p_bmi160->BMI160_BUS_READ_FUNC
				(p_bmi160->dev_addr,
				BMI160_USER_OFFSET_5_GYR_OFF_Z__REG,
				&v_data2_u8r, 1);
				if (comres == SUCCESS) {
					v_data1_u8r =
					((u8) (gyr_off_z & 0x00FF));
					v_data2_u8r = BMI160_SET_BITSLICE(
					v_data2_u8r,
					BMI160_USER_OFFSET_5_GYR_OFF_Z,
					v_data1_u8r);
					comres +=
					p_bmi160->BMI160_BUS_WRITE_FUNC
					(p_bmi160->dev_addr,
					BMI160_USER_OFFSET_5_GYR_OFF_Z__REG,
					&v_data2_u8r, 1);
				}

				comres += p_bmi160->BMI160_BUS_READ_FUNC
				(p_bmi160->dev_addr,
				BMI160_USER_OFFSET_6_GYR_OFF_Z__REG,
				&v_data2_u8r, 1);
				if (comres == SUCCESS) {
					v_data3_u8r =
					(u16) (gyr_off_z & 0x0300);
					v_data1_u8r = (u8)(v_data3_u8r
					>> BMI160_SHIFT_8_POSITION);
					v_data2_u8r = BMI160_SET_BITSLICE(
					v_data2_u8r,
					BMI160_USER_OFFSET_6_GYR_OFF_Z,
					v_data1_u8r);
					comres +=
					p_bmi160->BMI160_BUS_WRITE_FUNC
					(p_bmi160->dev_addr,
					BMI160_USER_OFFSET_6_GYR_OFF_Z__REG,
					&v_data2_u8r, 1);
				}
			} else {
			return ERROR;
			}
		}
	return comres;
}
/******************************************************************************
 *	Description: *//**brief This API Reads
 *	acc_off_en from the register 0x77 bit 6
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
u8 *acc_off_en)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_OFFSET_6_ACC_OFF_EN__REG,
			&v_data_u8r, 1);
			*acc_off_en = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_OFFSET_6_ACC_OFF_EN);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
/*******************************************************************************
 * Description: *//**brief This API Writes
 *	acc_off_en from the register 0x77 bit 6
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
u8 acc_off_en)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
			} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_OFFSET_6_ACC_OFF_EN__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_OFFSET_6_ACC_OFF_EN,
				acc_off_en);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_OFFSET_6_ACC_OFF_EN__REG,
				&v_data_u8r, 1);
			}
		}
	return comres;
}
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
u8 *gyr_off_en)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_OFFSET_6_GYR_OFF_EN__REG,
			&v_data_u8r, 1);
			*gyr_off_en = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_OFFSET_6_GYR_OFF_EN);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 gyr_off_en)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_OFFSET_6_GYR_OFF_EN__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r = BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_OFFSET_6_GYR_OFF_EN,
				gyr_off_en);
				comres += p_bmi160->BMI160_BUS_WRITE_FUNC(
				p_bmi160->dev_addr,
				BMI160_USER_OFFSET_6_GYR_OFF_EN__REG,
				&v_data_u8r, 1);
			}
		}
	return comres;
}
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
BMI160_RETURN_FUNCTION_TYPE bmi160_read_step_count(s16 *step_cnt)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 a_data_u8r[2] = {0, 0};
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres +=
			p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
			BMI160_USER_STEP_COUNT_LSB__REG,
			a_data_u8r, 2);

			*step_cnt = (s16)
			((((s32)((s8)a_data_u8r[1]))
			<< BMI160_SHIFT_8_POSITION) | (a_data_u8r[0]));
		}
	return comres;
}
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
u16 *step_conf)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data1_u8r = C_BMI160_ZERO_U8X;
	u8 v_data2_u8r = C_BMI160_ZERO_U8X;
	u16 v_data3_u8r = C_BMI160_ZERO_U8X;
	/* Read the 0 to 7 bit*/
	comres +=
	p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
	BMI160_USER_STEP_CONF_ZERO__REG,
	&v_data1_u8r, 1);
	/* Read the 8 to 10 bit*/
	comres +=
	p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
	BMI160_USER_STEP_CONF_ONE_CNF1__REG,
	&v_data2_u8r, 1);
	v_data2_u8r = BMI160_GET_BITSLICE(v_data2_u8r,
	BMI160_USER_STEP_CONF_ONE_CNF1);
	v_data3_u8r = ((u16)((((u32)
	((u8)v_data2_u8r))
	<< BMI160_SHIFT_8_POSITION) | (v_data1_u8r)));
	/* Read the 11 to 14 bit*/
	comres +=
	p_bmi160->BMI160_BUS_READ_FUNC(p_bmi160->dev_addr,
	BMI160_USER_STEP_CONF_ONE_CNF2__REG,
	&v_data1_u8r, 1);
	v_data1_u8r = BMI160_GET_BITSLICE(v_data1_u8r,
	BMI160_USER_STEP_CONF_ONE_CNF2);
	*step_conf = ((u16)((((u32)
	((u8)v_data1_u8r))
	<< BMI160_SHIFT_8_POSITION) | (v_data3_u8r)));

	return comres;
}
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
u16 step_conf)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 v_data1_u8r = C_BMI160_ZERO_U8X;
	u8 v_data2_u8r = C_BMI160_ZERO_U8X;
	u16 v_data3_u8r = C_BMI160_ZERO_U8X;

	/* write the 0 to 7 bit*/
	v_data1_u8r = (u8)(step_conf & 0x00FF);
	p_bmi160->BMI160_BUS_WRITE_FUNC
	(p_bmi160->dev_addr,
	BMI160_USER_STEP_CONF_ZERO__REG,
	&v_data1_u8r, 1);
	/* write the 8 to 10 bit*/
	comres += p_bmi160->BMI160_BUS_READ_FUNC
	(p_bmi160->dev_addr,
	BMI160_USER_STEP_CONF_ONE_CNF1__REG,
	&v_data2_u8r, 1);
	if (comres == SUCCESS) {
		v_data3_u8r = (u16) (step_conf & 0x0700);
		v_data1_u8r = (u8)(v_data3_u8r >> BMI160_SHIFT_8_POSITION);
		v_data2_u8r = BMI160_SET_BITSLICE(v_data2_u8r,
		BMI160_USER_STEP_CONF_ONE_CNF1, v_data1_u8r);
		p_bmi160->BMI160_BUS_WRITE_FUNC
		(p_bmi160->dev_addr,
		BMI160_USER_STEP_CONF_ONE_CNF1__REG,
		&v_data2_u8r, 1);
	}
	/* write the 11 to 14 bit*/
	comres += p_bmi160->BMI160_BUS_READ_FUNC
	(p_bmi160->dev_addr,
	BMI160_USER_STEP_CONF_ONE_CNF2__REG,
	&v_data2_u8r, 1);
	if (comres == SUCCESS) {
		v_data3_u8r = (u16) (step_conf & 0xF000);
		v_data1_u8r = (u8)(v_data3_u8r >> BMI160_SHIFT_12_POSITION);
		v_data2_u8r = BMI160_SET_BITSLICE(v_data2_u8r,
		BMI160_USER_STEP_CONF_ONE_CNF2, v_data1_u8r);
		p_bmi160->BMI160_BUS_WRITE_FUNC
		(p_bmi160->dev_addr,
		BMI160_USER_STEP_CONF_ONE_CNF2__REG,
		&v_data2_u8r, 1);
	}

	return comres;
}
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
BMI160_RETURN_FUNCTION_TYPE bmi160_get_step_counter_enable(u8 *step_cnt_en)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_USER_STEP_CONF_1_STEP_CNT_EN__REG,
			&v_data_u8r, 1);
			*step_cnt_en = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_USER_STEP_CONF_1_STEP_CNT_EN);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
BMI160_RETURN_FUNCTION_TYPE bmi160_set_step_counter_enable(u8 step_cnt_en)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
	} else {
		if (step_cnt_en < C_BMI160_THREE_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_USER_STEP_CONF_1_STEP_CNT_EN__REG,
			&v_data_u8r, 1);
			if (comres == SUCCESS) {
				v_data_u8r =
				BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_USER_STEP_CONF_1_STEP_CNT_EN,
				step_cnt_en);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC
				(p_bmi160->dev_addr,
				BMI160_USER_STEP_CONF_1_STEP_CNT_EN__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
/******************************************************************************
 *	Description: *//**brief This API set
 *	Step counter modes
 *
 *
 *  \param u8 step_mode   :
 *      The value of step counter mode
 *	BMI160_STEP_NORMAL_MODE		-	0
 *	BMI160_STEP_SENSITIVE_MODE	-	1
 *	BMI160_STEP_ROBUST_MODE		-	2
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
BMI160_RETURN_FUNCTION_TYPE bmi160_set_step_mode(u8 step_mode)
{
	BMI160_RETURN_FUNCTION_TYPE comres = SUCCESS;
	switch (step_mode) {
	case BMI160_STEP_NORMAL_MODE:
		bmi160_set_step_configuration(STEP_CONF_NORMAL);
		p_bmi160->delay_msec(5);
	break;
	case BMI160_STEP_SENSITIVE_MODE:
		bmi160_set_step_configuration(STEP_CONF_SENSITIVE);
		p_bmi160->delay_msec(5);
	break;
	case BMI160_STEP_ROBUST_MODE:
		bmi160_set_step_configuration(STEP_CONF_ROBUST);
		p_bmi160->delay_msec(5);
	break;
	default:
		comres = E_BMI160_OUT_OF_RANGE;
	break;
	}

	return comres;
}
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
u8 sig_map_interrupt)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 sig_motion = C_BMI160_ZERO_U8X;
	u8 any_mo_int1_en = 0x04;
	u8 any_mot_int2_en = 0x04;
	u8 any_mot_axis_en = 0x07;

	comres += bmi160_get_int_significant_motion_select(&sig_motion);
	if (sig_motion != C_BMI160_ONE_U8X)
		comres += bmi160_set_int_significant_motion_select(0x01);
	switch (sig_map_interrupt) {
	case BMI160_MAP_INT1:
		/* map the signification interrupt to any-motion interrupt1*/
		comres += bmi160_write_reg(
		BMI160_USER_INT_MAP_0_INT1_ANYMOTION__REG,
		&any_mo_int1_en, 1);
		p_bmi160->delay_msec(5);
		comres += bmi160_write_reg(
		BMI160_USER_INT_EN_0_ADDR,
		&any_mot_axis_en, 1);
		p_bmi160->delay_msec(5);
	break;

	case BMI160_MAP_INT2:
		/* map the signification interrupt to any-motion interrupt2*/
		comres += bmi160_write_reg(
		BMI160_USER_INT_MAP_2_INT2_ANYMOTION__REG,
		&any_mot_int2_en, 1);
		p_bmi160->delay_msec(5);
		comres += bmi160_write_reg(
		BMI160_USER_INT_EN_0_ADDR,
		&any_mot_axis_en, 1);
		p_bmi160->delay_msec(5);
	break;

	default:
		comres = E_BMI160_OUT_OF_RANGE;
	break;

	}
	return comres;
}
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
u8 step_det_map)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 step_det = C_BMI160_ZERO_U8X;
	u8 lowg_int1_en = 0x01;
	u8 lowg_int2_en = 0x01;
	u8 lowg_en = 0x08;
	/* read the status of step detector interrupt*/
	comres += bmi160_get_stepdetector_enable(&step_det);
	if (step_det != C_BMI160_ONE_U8X)
		comres += bmi160_set_stepdetector_enable(C_BMI160_ONE_U8X);
	switch (step_det_map) {
	case BMI160_MAP_INT1:
		/* map the step detector interrupt
		to Low-g interrupt 1*/
		comres += bmi160_write_reg(
		BMI160_USER_INT_MAP_0_INT1_LOWG__REG,
		&lowg_int1_en, 1);
		p_bmi160->delay_msec(5);
		/* Enable the Low-g interrupt*/
		comres += bmi160_write_reg(
		BMI160_USER_INT_EN_1_LOW_EN__REG,
		&lowg_en, 1);

		p_bmi160->delay_msec(5);
	break;
	case BMI160_MAP_INT2:
		/* map the step detector interrupt
		to Low-g interrupt 1*/
		comres += bmi160_write_reg(
		BMI160_USER_INT_MAP_2_INT2_LOWG__REG,
		&lowg_int2_en, 1);
		p_bmi160->delay_msec(5);
		/* Enable the Low-g interrupt*/
		comres += bmi160_write_reg(
		BMI160_USER_INT_EN_1_LOW_EN__REG,
		&lowg_en, 1);
		p_bmi160->delay_msec(5);
	break;
	default:
		comres = E_BMI160_OUT_OF_RANGE;
	break;
	}
	return comres;
}
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
BMI160_RETURN_FUNCTION_TYPE bmi160_clear_step_counter(void)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	/* clear the step counter*/
	comres += bmi160_set_command_register(0xB2);
	p_bmi160->delay_msec(5);

	return comres;

}
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
 *	0x12	-	Sets the PMU mode for the Accelerometer Lowpower
 *  0x14	-	Sets the PMU mode for the Gyroscope to suspend
 *	0x15	-	Sets the PMU mode for the Gyroscope to normal
 *	0x16	-	Reserved
 *	0x17	-	Sets the PMU mode for the Gyroscope to fast start-up
 *  0x18	-	Sets the PMU mode for the Magnetometer to suspend
 *	0x19	-	Sets the PMU mode for the Magnetometer to normal
 *	0x1A	-	Sets the PMU mode for the Magnetometer to Lowpower
 *	0xB0	-	Clears all data in the FIFO
 *  0xB1	-	Resets the interrupt engine
 *	0xB2	-	step_cnt_clr Clears the step counter
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
BMI160_RETURN_FUNCTION_TYPE bmi160_set_command_register(u8 cmd_reg)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
	} else {
			comres += p_bmi160->BMI160_BUS_WRITE_FUNC(
			p_bmi160->dev_addr,
			BMI160_CMD_COMMANDS__REG,
			&cmd_reg, 1);
		}
	return comres;
}
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
BMI160_RETURN_FUNCTION_TYPE bmi160_get_target_page(u8 *tar_pg)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
		} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_CMD_TARGET_PAGE__REG,
			&v_data_u8r, 1);
			*tar_pg = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_CMD_TARGET_PAGE);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
BMI160_RETURN_FUNCTION_TYPE bmi160_set_target_page(u8 tar_pg)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
	} else {
		if (tar_pg < C_BMI160_FOUR_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_CMD_TARGET_PAGE__REG,
			&v_data_u8r, 1);
			p_bmi160->delay_msec(2);
			if (comres == SUCCESS) {
				v_data_u8r =
				BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_CMD_TARGET_PAGE,
				tar_pg);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC
				(p_bmi160->dev_addr,
				BMI160_CMD_TARGET_PAGE__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
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
BMI160_RETURN_FUNCTION_TYPE bmi160_get_paging_enable(u8 *pg_en)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
	} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_CMD_PAGING_EN__REG,
			&v_data_u8r, 1);
			*pg_en = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_CMD_PAGING_EN);
		}
	return comres;
}
/* Compiler Switch if applicable
#ifdef

#endif
*/
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
u8 pg_en)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
	} else {
		if (pg_en < C_BMI160_TWO_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_CMD_PAGING_EN__REG,
			&v_data_u8r, 1);
			p_bmi160->delay_msec(2);
			if (comres == SUCCESS) {
				v_data_u8r =
				BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_CMD_PAGING_EN,
				pg_en);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC
				(p_bmi160->dev_addr,
				BMI160_CMD_PAGING_EN__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
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
u8 *control_pullup)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = C_BMI160_ZERO_U8X;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
	} else {
			comres += p_bmi160->BMI160_BUS_READ_FUNC(
			p_bmi160->dev_addr,
			BMI160_COM_C_TRIM_FIVE__REG,
			&v_data_u8r, 1);
			*control_pullup = BMI160_GET_BITSLICE(v_data_u8r,
			BMI160_COM_C_TRIM_FIVE);
		}
	return comres;

}
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
u8 control_pullup)
{
	BMI160_RETURN_FUNCTION_TYPE comres  = SUCCESS;
	u8 v_data_u8r = C_BMI160_ZERO_U8X;
	if (p_bmi160 == BMI160_NULL) {
		return E_BMI160_NULL_PTR;
	} else {
		if (control_pullup < C_BMI160_FOUR_U8X) {
			comres += p_bmi160->BMI160_BUS_READ_FUNC
			(p_bmi160->dev_addr,
			BMI160_COM_C_TRIM_FIVE__REG,
			&v_data_u8r, 1);
			p_bmi160->delay_msec(2);
			if (comres == SUCCESS) {
				v_data_u8r =
				BMI160_SET_BITSLICE(v_data_u8r,
				BMI160_COM_C_TRIM_FIVE,
				control_pullup);
				comres +=
				p_bmi160->BMI160_BUS_WRITE_FUNC
				(p_bmi160->dev_addr,
				BMI160_COM_C_TRIM_FIVE__REG,
				&v_data_u8r, 1);
			}
		} else {
		comres = E_BMI160_OUT_OF_RANGE;
		}
	}
	return comres;
}
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
struct bmi160_mag_xyz *mag_comp_xyz)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	struct bmi160mag_t mag_xyzr;
	comres = bmi160_read_mag_xyzr(&mag_xyzr);
	if (comres)
		return comres;
	/* Compensation for X axis */
	mag_comp_xyz->x = bmi160_mag_compensate_X(mag_xyzr.x, mag_xyzr.r);

	/* Compensation for Y axis */
	mag_comp_xyz->y = bmi160_mag_compensate_Y(mag_xyzr.y, mag_xyzr.r);

	/* Compensation for Z axis */
	mag_comp_xyz->z = bmi160_mag_compensate_Z(mag_xyzr.z, mag_xyzr.r);

	return comres;
}

BMI160_RETURN_FUNCTION_TYPE bmi160_mag_compensate_xyz_raw(
struct bmi160_mag_xyz *mag_comp_xyz, struct bmi160mag_t mag_xyzr)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	/* Compensation for X axis */
	mag_comp_xyz->x = bmi160_mag_compensate_X(mag_xyzr.x, mag_xyzr.r);

	/* Compensation for Y axis */
	mag_comp_xyz->y = bmi160_mag_compensate_Y(mag_xyzr.y, mag_xyzr.r);

	/* Compensation for Z axis */
	mag_comp_xyz->z = bmi160_mag_compensate_Z(mag_xyzr.z, mag_xyzr.r);

	return comres;
}

/*****************************************************************************
 *	Description: *//**\brief This API used to get the compensated X data
 *	the out put of X as s16
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
 *
 *  \param s16 mdata_x : The value of X data
 *			u16 data_r : The value of R data
 *
 *	\return results of compensated X data value output as s16
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
s16 bmi160_mag_compensate_X(s16 mdata_x, u16 data_r)
{
	s16 inter_retval = C_BMI160_ZERO_U8X;
	if (mdata_x != BMI160_MAG_FLIP_OVERFLOW_ADCVAL  /* no overflow */
	   ) {
		inter_retval = ((s16)(((u16)
		((((s32)mag_trim.dig_xyz1) << 14)/
		 (data_r != 0 ? data_r : mag_trim.dig_xyz1))) -
		((u16)0x4000)));
		inter_retval = ((s16)((((s32)mdata_x) *
				((((((((s32)mag_trim.dig_xy2) *
				((((s32)inter_retval) *
				((s32)inter_retval)) >> 7)) +
			     (((s32)inter_retval) *
			      ((s32)(((s16)mag_trim.dig_xy1)
			      << 7)))) >> 9) +
			   ((s32)0x100000)) *
			  ((s32)(((s16)mag_trim.dig_x2) +
			  ((s16)0xA0)))) >> 12)) >> 13)) +
			(((s16)mag_trim.dig_x1) << 3);
	} else {
		/* overflow */
		inter_retval = BMI160_MAG_OVERFLOW_OUTPUT;
	}
	return inter_retval;
}
/*****************************************************************************
 *	Description: *//**\brief This API used to get the compensated Y data
 *	the out put of Y as s16
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
 *  \param s16 mdata_y : The value of Y data
 *			u16 data_r : The value of R data
 *
 *	\return results of compensated Y data value output as s16
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
s16 bmi160_mag_compensate_Y(s16 mdata_y, u16 data_r)
{
	s16 inter_retval = C_BMI160_ZERO_U8X;
	if (mdata_y != BMI160_MAG_FLIP_OVERFLOW_ADCVAL  /* no overflow */
	   ) {
		inter_retval = ((s16)(((u16)(((
			(s32)mag_trim.dig_xyz1) << 14)/
			(data_r != 0 ?
			 data_r : mag_trim.dig_xyz1))) -
			((u16)0x4000)));
		inter_retval = ((s16)((((s32)mdata_y) * ((((((((s32)
			mag_trim.dig_xy2) * ((((s32) inter_retval) *
			((s32)inter_retval)) >> 7)) + (((s32)inter_retval) *
			((s32)(((s16)mag_trim.dig_xy1) << 7)))) >> 9) +
			((s32)0x100000)) * ((s32)(((s16)mag_trim.dig_y2)
			+ ((s16)0xA0)))) >> 12)) >> 13)) +
			(((s16)mag_trim.dig_y1) << 3);
	} else {
		/* overflow */
		inter_retval = BMI160_MAG_OVERFLOW_OUTPUT;
	}
	return inter_retval;
}
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
s16 bmi160_mag_compensate_Z(s16 mdata_z, u16 data_r)
{
	s32 retval = C_BMI160_ZERO_U8X;

	/* no overflow */
	if ((mdata_z != BMI160_MAG_HALL_OVERFLOW_ADCVAL)) {
		retval = (((((s32)(mdata_z - mag_trim.dig_z4)) << 15) -
			((((s32)mag_trim.dig_z3) * ((s32)(((s16)data_r) -
			((s16) mag_trim.dig_xyz1))))>>2))/
			(mag_trim.dig_z2 + ((s16)(((((s32)
			mag_trim.dig_z1) * ((((s16)data_r) << 1)))+
			(1<<15))>>16))));
		/* saturate result to +/- 2 mT */
		if (retval > BMI160_MAG_POSITIVE_SATURATION_Z) {
			retval =  BMI160_MAG_POSITIVE_SATURATION_Z;
		} else {
			if (retval < BMI160_MAG_NEGATIVE_SATURATION_Z)
				retval = BMI160_MAG_NEGATIVE_SATURATION_Z;
		}
	} else {
		/* overflow */
		retval = BMI160_MAG_OVERFLOW_OUTPUT;
	}
	return (s16)retval;
}

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
BMI160_RETURN_FUNCTION_TYPE bmi160_magnetometer_interface_init(void)
{
	/* structure used for read the mag trim values*/
	struct bmi160_mag_xyz mag_xyz;

	/* This variable used for provide the communication
	results*/
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 pull_value = C_BMI160_ZERO_U8X;
	u8 data = C_BMI160_ZERO_U8X;
	u8 mag_chipid;

	comres += bmi160_set_command_register(0x19);
	p_bmi160->delay_msec(2);
	bmi160_get_mag_pmu_status(&data);
	/* register 0x7E write the 0x37, 0x9A and 0x30*/
	comres += bmi160_set_command_register(0x37);
	p_bmi160->delay_msec(2);
	comres += bmi160_set_command_register(0x9A);
	p_bmi160->delay_msec(2);
	comres += bmi160_set_command_register(0xC0);
	p_bmi160->delay_msec(2);
	/*switch the page1*/
	comres += bmi160_set_target_page(0x01);
	p_bmi160->delay_msec(2);
	comres += bmi160_set_paging_enable(0x01);
	p_bmi160->delay_msec(2);
	/* enable the pullup configuration from
	the register 0x85 bit 4 and 5 */
	bmi160_get_pullup_configuration(&pull_value);
	p_bmi160->delay_msec(2);
	pull_value = pull_value | 0x03;
	comres += bmi160_set_pullup_configuration(pull_value);
	p_bmi160->delay_msec(2);
	/*switch the page0*/
	comres += bmi160_set_target_page(0x00);
	p_bmi160->delay_msec(2);
	bmi160_get_target_page(&data);
	p_bmi160->delay_msec(2);
	/* enable the mag interface to manual mode*/
	comres += bmi160_set_mag_manual_en(0x01);
	p_bmi160->delay_msec(2);
	/*Enable the MAG interface */
	comres += bmi160_set_if_mode(0x02);
	p_bmi160->delay_msec(2);
	bmi160_get_if_mode(&data);
	p_bmi160->delay_msec(2);

	/* Mag normal mode*/
	comres += bmi160_set_mag_write_data(0x01);
	p_bmi160->delay_msec(2);

	comres += bmi160_set_mag_write_addr(0x4B);
	p_bmi160->delay_msec(2);

	comres += bmi160_set_mag_write_data(0x06);
	p_bmi160->delay_msec(2);

	comres += bmi160_set_mag_write_addr(0x4C);
	p_bmi160->delay_msec(5);

	/* write the XY and Z repetitions*/
	comres += bmi160_set_mag_presetmode(BMI160_MAG_PRESETMODE_REGULAR);

	/* read the mag trim values*/
	comres += bmi160_read_mag_trim();

	comres = bmi160_set_mag_read_addr(BMM050_CHIP_ID);
	/* 0x04 is mag_x lsb register */
	comres += bmi160_read_reg(0x04, &mag_chipid, 1);
	printk(KERN_INFO "bmi160,bmm_chip_id:0x%x", mag_chipid);

	/* Set the power mode of mag as force mode*/
	/* The data have to write for the register
	It write the value in the register 0x4F */
	comres += bmi160_set_mag_write_data(0x02);
	p_bmi160->delay_msec(2);

	comres += bmi160_set_mag_write_addr(0x4C);
	p_bmi160->delay_msec(2);
	/* write the mag bandwidth as 25Hz*/
	comres += bmi160_set_mag_outputdatarate(BMI160_MAG_ODR_25HZ);
	p_bmi160->delay_msec(2);

	/* When mag interface is auto mode - The mag read address
	starts the register 0x42*/
	comres += bmi160_set_mag_read_addr(0x42);
	p_bmi160->delay_msec(5);
	/* enable mag interface to auto mode*/
	comres += bmi160_set_mag_manual_en(0x00);
	p_bmi160->delay_msec(2);
	bmi160_get_mag_manual_en(&data);
	p_bmi160->delay_msec(2);

	/* raw data with compensation */
	bmi160_mag_compensate_xyz(&mag_xyz);

	printk(KERN_ERR "mag read:%d, %d, %d\n",
		mag_xyz.x, mag_xyz.y, mag_xyz.z);
	return comres;
}
/***************************************************************************
 *	Description: This function used for set the magnetometer
 *	power mode.
 *	Before set the mag power mode
 *	make sure the following two point is addressed
 *		Make sure the mag interface is enabled or not,
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
u8 mag_sec_if_pow_mode)
{
	/* This variable used for provide the communication
	results*/
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	/*TODO*/
	comres += bmi160_set_command_register(0x11);/*acc op_mode*/
	switch (mag_sec_if_pow_mode) {
	case BMI160_MAG_FORCE_MODE:
		comres += bmi160_set_mag_manual_en(0x01);
		p_bmi160->delay_msec(2);
		comres += bmi160_set_command_register(0x19);
		p_bmi160->delay_msec(5);
		/* set the mag power mode as FORCE mode*/
		comres += bmi160_mag_set_powermode(FORCE_MODE);
		p_bmi160->delay_msec(1);
		/* set mag interface auto mode*/
		comres += bmi160_set_mag_manual_en(0x00);
		p_bmi160->delay_msec(1);
	break;
	case BMI160_MAG_SUSPEND_MODE:
		/* set mag interface manual mode*/
		comres += bmi160_set_mag_manual_en(0x01);
		p_bmi160->delay_msec(2);
		/* set the mag power mode as SUSPEND mode*/
		comres += bmi160_mag_set_powermode(SUSPEND_MODE);
		p_bmi160->delay_msec(2);
			/* set mag interface auto mode*/
		comres += bmi160_set_mag_manual_en(0x00);
		p_bmi160->delay_msec(2);
		/* set the secondary mag power mode as SUSPEND*/
		comres += bmi160_set_command_register(0x18);
		p_bmi160->delay_msec(2);
	break;
	default:
		comres = E_BMI160_OUT_OF_RANGE;
	break;
	}
	return comres;
}
/***************************************************************************
 *	Description: This function used for set the magnetometer
 *	power mode.
 *	Before set the mag power mode
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
BMI160_RETURN_FUNCTION_TYPE bmi160_mag_set_powermode(u8 mag_pow_mode)
{
	/* This variable used for provide the communication
	results*/
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	switch (mag_pow_mode) {
	case FORCE_MODE:
		/* Set the power mode of mag as force mode*/
		comres += bmi160_set_mag_write_data(0x01);
		p_bmi160->delay_msec(2);
		comres += bmi160_set_mag_write_addr(0x4B);
		p_bmi160->delay_msec(5);
		comres += bmi160_set_mag_write_data(0x02);
		p_bmi160->delay_msec(1);
		comres += bmi160_set_mag_write_addr(0x4C);
		p_bmi160->delay_msec(5);
		/* write the XY and Z repetitions*/
		comres +=
		bmi160_set_mag_presetmode(BMI160_MAG_PRESETMODE_REGULAR);
		comres += bmi160_set_mag_read_addr(0x42);
		p_bmi160->delay_msec(1);
	break;
	case SUSPEND_MODE:
		/* Set the power mode of mag as suspend mode*/
		comres += bmi160_set_mag_write_data(0x00);
		p_bmi160->delay_msec(2);
		comres += bmi160_set_mag_write_addr(0x4B);
		p_bmi160->delay_msec(5);
	break;
	default:
		comres = E_BMI160_OUT_OF_RANGE;
	break;
	}
	return comres;
}
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
BMI160_RETURN_FUNCTION_TYPE bmi160_set_mag_presetmode(u8 mode)
{
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	switch (mode) {
	case BMI160_MAG_PRESETMODE_LOWPOWER:
		/* write the XY and Z repetitions*/
		/* The data have to write for the register
		It write the value in the register 0x4F*/
		comres += bmi160_set_mag_write_data(
		BMI160_MAG_LOWPOWER_REPXY);
		p_bmi160->delay_msec(1);
		comres += bmi160_set_mag_write_addr(0x51);
		p_bmi160->delay_msec(1);
		/* write the Z repetitions*/
		/* The data have to write for the register
		It write the value in the register 0x4F*/
		comres += bmi160_set_mag_write_data(
		BMI160_MAG_LOWPOWER_REPZ);
		p_bmi160->delay_msec(1);
		comres += bmi160_set_mag_write_addr(0x52);
		p_bmi160->delay_msec(1);
		/* set the mag data rate as 10 to the register 0x4C*/
		comres += bmi160_set_mag_write_data(
		BMI160_MAG_LOWPOWER_DR);
		p_bmi160->delay_msec(1);
		comres += bmi160_set_mag_write_addr(0x4C);
		p_bmi160->delay_msec(1);
	break;
	case BMI160_MAG_PRESETMODE_REGULAR:
		/* write the XY and Z repetitions*/
		/* The data have to write for the register
		It write the value in the register 0x4F*/
		comres += bmi160_set_mag_write_data(
		BMI160_MAG_REGULAR_REPXY);
		p_bmi160->delay_msec(1);
		comres += bmi160_set_mag_write_addr(0x51);
		p_bmi160->delay_msec(1);
		/* write the Z repetitions*/
		/* The data have to write for the register
		It write the value in the register 0x4F*/
		comres += bmi160_set_mag_write_data(
		BMI160_MAG_REGULAR_REPZ);
		p_bmi160->delay_msec(1);
		comres += bmi160_set_mag_write_addr(0x52);
		p_bmi160->delay_msec(1);
		/* set the mag data rate as 10 to the register 0x4C*/
		comres += bmi160_set_mag_write_data(
		BMI160_MAG_REGULAR_DR);
		p_bmi160->delay_msec(1);
		comres += bmi160_set_mag_write_addr(0x4C);
		p_bmi160->delay_msec(1);
	break;
	case BMI160_MAG_PRESETMODE_HIGHACCURACY:
		/* write the XY and Z repetitions*/
		/* The data have to write for the register
		It write the value in the register 0x4F*/
		comres += bmi160_set_mag_write_data(
		BMI160_MAG_HIGHACCURACY_REPXY);
		p_bmi160->delay_msec(1);
		comres += bmi160_set_mag_write_addr(0x51);
		p_bmi160->delay_msec(1);
		/* write the Z repetitions*/
		/* The data have to write for the register
		It write the value in the register 0x4F*/
		comres += bmi160_set_mag_write_data(
		BMI160_MAG_HIGHACCURACY_REPZ);
		p_bmi160->delay_msec(1);
		comres += bmi160_set_mag_write_addr(0x52);
		p_bmi160->delay_msec(1);
		/* set the mag data rate as 20 to the register 0x4C*/
		comres += bmi160_set_mag_write_data(
		BMI160_MAG_HIGHACCURACY_DR);
		p_bmi160->delay_msec(1);
		comres += bmi160_set_mag_write_addr(0x4C);
		p_bmi160->delay_msec(1);
	break;
	case BMI160_MAG_PRESETMODE_ENHANCED:
		/* write the XY and Z repetitions*/
		/* The data have to write for the register
		It write the value in the register 0x4F*/
		comres += bmi160_set_mag_write_data(
		BMI160_MAG_ENHANCED_REPXY);
		p_bmi160->delay_msec(1);
		comres += bmi160_set_mag_write_addr(0x51);
		p_bmi160->delay_msec(1);
		/* write the Z repetitions*/
		/* The data have to write for the register
		It write the value in the register 0x4F*/
		comres += bmi160_set_mag_write_data(
		BMI160_MAG_ENHANCED_REPZ);
		p_bmi160->delay_msec(1);
		comres += bmi160_set_mag_write_addr(0x52);
		p_bmi160->delay_msec(1);
		/* set the mag data rate as 10 to the register 0x4C*/
		comres += bmi160_set_mag_write_data(
		BMI160_MAG_ENHANCED_DR);
		p_bmi160->delay_msec(1);
		comres += bmi160_set_mag_write_addr(0x4C);
		p_bmi160->delay_msec(1);
	break;
	default:
		comres = E_BMI160_OUT_OF_RANGE;
	break;
	}
	return comres;
}
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
void)
{
	/* This variable used for provide the communication
	results*/
	BMI160_RETURN_FUNCTION_TYPE comres = C_BMI160_ZERO_U8X;
	u8 data[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	/* read dig_x1 value */
	comres = bmi160_set_mag_read_addr(BMI160_MAG_DIG_X1);
	p_bmi160->delay_msec(5);
	/* 0x04 is mag_x lsb register */
	comres += bmi160_read_reg(0x04, &data[0], 1);
	mag_trim.dig_x1 = data[0];
	p_bmi160->delay_msec(5);

	/* read dig_y1 value */
	comres += bmi160_set_mag_read_addr(BMI160_MAG_DIG_Y1);
	p_bmi160->delay_msec(2);
	/* 0x04 is mag_x lsb register */
	comres += bmi160_read_reg(0x04, &data[1], 1);
	mag_trim.dig_y1 = data[1];
	p_bmi160->delay_msec(5);

	/* read dig_x2 value */
	comres += bmi160_set_mag_read_addr(BMI160_MAG_DIG_X2);
	p_bmi160->delay_msec(5);
	/* 0x04 is mag_x lsb register */
	comres += bmi160_read_reg(0x04, &data[2], 1);
	mag_trim.dig_x2 = data[2];
	p_bmi160->delay_msec(5);

	/* read dig_y2 value */
	comres += bmi160_set_mag_read_addr(BMI160_MAG_DIG_Y2);
	p_bmi160->delay_msec(5);
	/* 0x04 is mag_x lsb register */
	comres += bmi160_read_reg(0x04, &data[3], 1);
	mag_trim.dig_y2 = data[3];
	p_bmi160->delay_msec(5);

	/* read dig_xy1 value */
	comres += bmi160_set_mag_read_addr(BMI160_MAG_DIG_XY1);
	p_bmi160->delay_msec(5);
	/* 0x04 is mag_x lsb register */
	comres += bmi160_read_reg(0x04, &data[4], 1);
	mag_trim.dig_xy1 = data[4];
	p_bmi160->delay_msec(5);

	/* read dig_xy2 value */
	comres += bmi160_set_mag_read_addr(BMI160_MAG_DIG_XY2);
	p_bmi160->delay_msec(5);
	/* 0x04 is mag_x ls register */
	comres += bmi160_read_reg(0x04, &data[5], 1);
	mag_trim.dig_xy2 = data[5];
	p_bmi160->delay_msec(5);

	/* read dig_z1 lsb value */
	comres += bmi160_set_mag_read_addr(BMI160_MAG_DIG_Z1_LSB);
	p_bmi160->delay_msec(2);
	/* 0x04 is mag_x lsb register */
	comres += bmi160_read_reg(0x04, &data[6], 1);
	p_bmi160->delay_msec(5);

	/* read dig_z1 msb value */
	comres += bmi160_set_mag_read_addr(BMI160_MAG_DIG_Z1_MSB);
	p_bmi160->delay_msec(5);
	/* 0x04 is mag_x msb register */
	comres += bmi160_read_reg(0x04, &data[7], 1);
	p_bmi160->delay_msec(5);

	mag_trim.dig_z1 = (u16)((((u32)((u8)data[7]))
			<< BMI160_SHIFT_8_POSITION) | (data[6]));

	/* read dig_z2 lsb value */
	comres += bmi160_set_mag_read_addr(BMI160_MAG_DIG_Z2_LSB);
	p_bmi160->delay_msec(5);
	/* 0x04 is mag_x lsb register */
	comres += bmi160_read_reg(0x04, &data[8], 1);
	p_bmi160->delay_msec(5);
	/* read dig_z2 msb value */
	comres += bmi160_set_mag_read_addr(BMI160_MAG_DIG_Z2_MSB);
	p_bmi160->delay_msec(5);
	/* 0x04 is mag_x msb register */
	comres += bmi160_read_reg(0x04, &data[9], 1);
	p_bmi160->delay_msec(5);

	mag_trim.dig_z2 = (s16)((((s32)((s8)data[9]))
			<< BMI160_SHIFT_8_POSITION) | (data[8]));

	/* read dig_z3 lsb value */
	comres += bmi160_set_mag_read_addr(BMI160_MAG_DIG_Z3_LSB);
	p_bmi160->delay_msec(5);
	/* 0x04 is mag_x lsb register */
	comres += bmi160_read_reg(0x04, &data[10], 1);
	p_bmi160->delay_msec(5);

	/* read dig_z3 msb value */
	comres += bmi160_set_mag_read_addr(BMI160_MAG_DIG_Z3_MSB);
	p_bmi160->delay_msec(5);
	/* 0x04 is mag_x msb register */
	comres += bmi160_read_reg(0x04, &data[11], 1);
	p_bmi160->delay_msec(5);

	mag_trim.dig_z3 = (s16)((((s32)((s8)data[11]))
			<< BMI160_SHIFT_8_POSITION) | (data[10]));

	/* read dig_z4 lsb value */
	comres += bmi160_set_mag_read_addr(BMI160_MAG_DIG_Z4_LSB);
	p_bmi160->delay_msec(5);
	/* 0x04 is mag_x lsb register */
	comres += bmi160_read_reg(0x04, &data[12], 1);
	p_bmi160->delay_msec(5);
	/* read dig_z4 msb value */
	comres += bmi160_set_mag_read_addr(BMI160_MAG_DIG_Z4_MSB);
	p_bmi160->delay_msec(5);
	/* 0x04 is mag_x msb register */
	comres += bmi160_read_reg(0x04, &data[13], 1);
	p_bmi160->delay_msec(5);

	mag_trim.dig_z4 = (s16)((((s32)((s8)data[13]))
			<< BMI160_SHIFT_8_POSITION) | (data[12]));

	/* read dig_xyz1 lsb value */
	comres += bmi160_set_mag_read_addr(BMI160_MAG_DIG_XYZ1_LSB);
	p_bmi160->delay_msec(5);
	/* 0x04 is mag_x lsb register */
	comres += bmi160_read_reg(0x04, &data[14], 1);
	p_bmi160->delay_msec(5);
	/* read dig_xyz1 msb value */
	comres += bmi160_set_mag_read_addr(BMI160_MAG_DIG_XYZ1_MSB);
	p_bmi160->delay_msec(5);
	/* 0x04 is mag_x msb register */
	comres += bmi160_read_reg(0x04, &data[15], 1);
	p_bmi160->delay_msec(5);

	mag_trim.dig_xyz1 = (u16)((((u32)((u8)data[15]))
			<< BMI160_SHIFT_8_POSITION) | (data[14]));

	return comres;
}
