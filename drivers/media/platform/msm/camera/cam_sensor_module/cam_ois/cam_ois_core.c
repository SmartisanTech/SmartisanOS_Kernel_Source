/* Copyright (c) 2017, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/module.h>
#include <linux/firmware.h>
#include <cam_sensor_cmn_header.h>
#include "cam_ois_core.h"
#include "cam_ois_soc.h"
#include "cam_sensor_util.h"
#include "cam_debug_util.h"
#include "cam_res_mgr_api.h"
#include <linux/fs.h>
#include <linux/uaccess.h>

#include "OIS_head.h"
#include "OIS_prog.h"
#include "OIS_coef.h"
#define  KERNELINIT 1
#define  CALIBRATE_FILE "/persist/gyro_calib.bin"
// /////////////////////////////////////////////////////////
// VCOSET function
// ---------------------------------------------------------
// <Function>
//		To use external clock at CLK/PS, it need to set PLL.
//		After enabling PLL, more than 30ms wait time is required to change clock source.
//		So the below sequence has to be used:
// 		Input CLK/PS --> Call VCOSET0 --> Download Program/Coed --> Call VCOSET1
//
// <Input>
//		none
//
// <Output>
//		none
//
// =========================================================
void	VCOSET0(struct camera_io_master* ois_io_master_info)
{

	OIS_UWORD 	CLK_PS = 24000;            						// Input Frequency [kHz] of CLK/PS terminal (Depend on your system)
	OIS_UWORD 	FVCO_1 = 36000;                					// Target Frequency [kHz]
	OIS_UWORD 	FREF   = 25;             						// Reference Clock Frequency [kHz]

	OIS_UWORD	DIV_N  = CLK_PS / FREF - 1;         			// calc DIV_N
	OIS_UWORD	DIV_M  = FVCO_1 / FREF - 1;         			// calc DIV_M

	I2C_OIS_per_write(ois_io_master_info, 0x62, DIV_N  ); 							// Divider for internal reference clock
	I2C_OIS_per_write(ois_io_master_info, 0x63, DIV_M  ); 							// Divider for internal PLL clock
	I2C_OIS_per_write(ois_io_master_info, 0x64, 0x4060 ); 							// Loop Filter

	I2C_OIS_per_write(ois_io_master_info, 0x60, 0x3011 ); 							// PLL
	I2C_OIS_per_write(ois_io_master_info, 0x65, 0x0080 ); 							// 
	I2C_OIS_per_write(ois_io_master_info, 0x61, 0x8002 ); 							// VCOON 
	I2C_OIS_per_write(ois_io_master_info, 0x61, 0x8003 ); 							// Circuit ON 
	I2C_OIS_per_write(ois_io_master_info, 0x61, 0x8809 ); 							// PLL ON
}


void	VCOSET1(struct camera_io_master* ois_io_master_info)
{
	I2C_OIS_per_write(ois_io_master_info, 0x05, 0x000C ); 							// Prepare for PLL clock as master clock
	I2C_OIS_per_write(ois_io_master_info, 0x05, 0x000D ); 							// Change to PLL clock
}


// /////////////////////////////////////////////////////////
// Write Data to Slave device via I2C master device
// ---------------------------------------------------------
// <Function>
//		I2C master send these data to the I2C slave device.
//		This function relate to your own circuit.
//
// <Input>
//		OIS_UBYTE	slvadr	I2C slave adr
//		OIS_UBYTE	size	Transfer Size
//		OIS_UBYTE	*dat	data matrix
//
// <Output>
//		none
//
// <Description>
//		[S][SlaveAdr][W]+[dat[0]]+...+[dat[size-1]][P]
//	
// =========================================================

void	WR_I2C(struct camera_io_master* ois_io_master_info, OIS_UBYTE slvadr, OIS_UBYTE size, OIS_UBYTE *dat )
{
	int32_t rc = 0, i = 0;

	/* Please write your source code here. */
	struct cam_sensor_i2c_reg_setting  i2c_reg_settings;
	struct cam_sensor_i2c_reg_array    *i2c_reg_array = 
		(struct cam_sensor_i2c_reg_array *) 
		kzalloc(sizeof(struct cam_sensor_i2c_reg_array)*size, 
				GFP_KERNEL);

	memset(&i2c_reg_settings, 0, sizeof(i2c_reg_settings));
	memset(i2c_reg_array, 0, sizeof(*i2c_reg_array)*size);
	i2c_reg_settings.addr_type = CAMERA_SENSOR_I2C_TYPE_BYTE;
	i2c_reg_settings.data_type = CAMERA_SENSOR_I2C_TYPE_BYTE;
	i2c_reg_settings.size = size-1;
	for (i = 0; i < size-1;i++){
		i2c_reg_array[i].reg_addr = dat[0];
		i2c_reg_array[i].reg_data = dat[i+1];
		i2c_reg_array[i].delay = 0x0;
	}
	i2c_reg_settings.reg_setting = i2c_reg_array;
	i2c_reg_settings.delay = 0;
	rc = camera_io_dev_write_continuous(ois_io_master_info,&i2c_reg_settings,1);
	if (rc < 0){
		CAM_ERR(CAM_ACTUATOR,"WR_I2C write error#######");
	}
#if 0    
	CAM_ERR(CAM_ACTUATOR, "call  WR_I2C reg_data size = %d (0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X,0x%02X)",i2c_reg_settings.size,i2c_reg_array[0].reg_data,i2c_reg_array[1].reg_data,
			i2c_reg_array[2].reg_data,i2c_reg_array[3].reg_data,i2c_reg_array[4].reg_data,i2c_reg_array[5].reg_data,i2c_reg_array[6].reg_data,i2c_reg_array[7].reg_data,i2c_reg_array[8].reg_data,i2c_reg_array[9].reg_data,i2c_reg_array[10].reg_data,
			i2c_reg_array[11].reg_data,i2c_reg_array[12].reg_data,i2c_reg_array[13].reg_data,i2c_reg_array[14].reg_data,i2c_reg_array[15].reg_data,i2c_reg_array[16].reg_data,i2c_reg_array[17].reg_data,i2c_reg_array[18].reg_data,i2c_reg_array[19].reg_data,i2c_reg_array[20].reg_data,
			i2c_reg_array[21].reg_data,i2c_reg_array[22].reg_data,i2c_reg_array[23].reg_data,i2c_reg_array[24].reg_data,i2c_reg_array[25].reg_data,i2c_reg_array[26].reg_data,i2c_reg_array[27].reg_data,i2c_reg_array[28].reg_data,
			i2c_reg_array[29].reg_data,i2c_reg_array[30].reg_data,i2c_reg_array[31].reg_data,i2c_reg_array[32].reg_data);  
#endif
	kfree(i2c_reg_array);
}


// *********************************************************
// Read Data from Slave device via I2C master device
// ---------------------------------------------------------
// <Function>
//		I2C master read data from the I2C slave device.
//		This function relate to your own circuit.
//
// <Input>
//		OIS_UBYTE	slvadr	I2C slave adr
//		OIS_UBYTE	size	Transfer Size
//		OIS_UBYTE	*dat	data matrix
//
// <Output>
//		OIS_UWORD	16bit data read from I2C Slave device
//
// <Description>
//	if size == 1
//		[S][SlaveAdr][W]+[dat[0]]+         [RS][SlaveAdr][R]+[RD_DAT0]+[RD_DAT1][P]
//	if size == 2
//		[S][SlaveAdr][W]+[dat[0]]+[dat[1]]+[RS][SlaveAdr][R]+[RD_DAT0]+[RD_DAT1][P]
//
// *********************************************************
OIS_UWORD	RD_I2C(struct camera_io_master* ois_io_master_info, OIS_UBYTE slvadr, OIS_UBYTE size, OIS_UBYTE *dat )
{
	int32_t rc = 0;
	uint32_t   ret_data = 0;
	uint32_t   read_addr = 0;
	read_addr = dat[0]<<8|dat[1];
	//	ois_io_master_info->cci_client->sid = 0x0e;
	//  ois_io_master_info->cci_client->i2c_freq_mode = I2C_CUSTOM_MODE;
	rc = camera_io_dev_read(ois_io_master_info,read_addr,&ret_data,CAMERA_SENSOR_I2C_TYPE_WORD,CAMERA_SENSOR_I2C_TYPE_WORD);
	if (rc < 0){
		CAM_ERR(CAM_ACTUATOR,"RD_I2C read error#######");
	} 
	return ret_data;
}


// *********************************************************
// Read Factory Adjusted data from the non-volatile memory
// ---------------------------------------------------------
// <Function>
//		Factory adjusted data are sotred somewhere
//		non-volatile memory.  I2C master has to read these
//		data and store the data to the OIS controller.
//
// <Input>
//		none
//
// <Output>
//		_FACT_ADJ	Factory Adjusted data
//
// <Description>
//		You have to port your own system.
//
// *********************************************************
_FACT_ADJ	get_FADJ_MEM_from_non_volatile_memory( struct camera_io_master* ois_io_master_info )
{        
	_FACT_ADJ MY_ADJ;
	uint8_t eeprom_data[40] = {0};
	int32_t rc = 0,i = 0;
	ois_io_master_info->cci_client->sid = 0x50;
	ois_io_master_info->cci_client->i2c_freq_mode = I2C_FAST_MODE;

	rc = camera_io_dev_read_seq(ois_io_master_info,6913, eeprom_data,CAMERA_SENSOR_I2C_TYPE_WORD, 40);
	if (rc < 0){
		CAM_ERR(CAM_ACTUATOR,"Read eeprom ois data error#######");
	}
	ois_io_master_info->cci_client->sid = 0x0e;
	ois_io_master_info->cci_client->i2c_freq_mode = I2C_CUSTOM_MODE;
//	CAM_ERR(CAM_ACTUATOR,"wangyue eeprom_data 0x%x  0x%x 0x%x  0x%x 0x%x  0x%x",eeprom_data[0],eeprom_data[1],eeprom_data[36],eeprom_data[37],eeprom_data[38],eeprom_data[39]);
	MY_ADJ.gl_CURDAT = eeprom_data[i] | (eeprom_data[i+1] << 8);
	i = i + 2;
	MY_ADJ.gl_HALOFS_X = eeprom_data[i] | (eeprom_data[i+1] << 8);
	i = i + 2;
	MY_ADJ.gl_HALOFS_Y = eeprom_data[i] | (eeprom_data[i+1] << 8);
	i = i + 2;
	MY_ADJ.gl_HX_OFS = eeprom_data[i] | (eeprom_data[i+1] << 8);
	i = i + 2;
	MY_ADJ.gl_HY_OFS = eeprom_data[i] | (eeprom_data[i+1] << 8);
	i = i + 2;
	MY_ADJ.gl_PSTXOF = eeprom_data[i] | (eeprom_data[i+1] << 8);
	i = i + 2;
	MY_ADJ.gl_PSTYOF = eeprom_data[i] | (eeprom_data[i+1] << 8);
	i = i + 2;
	MY_ADJ.gl_GX_OFS = eeprom_data[i] | (eeprom_data[i+1] << 8);
	i = i + 2;
	MY_ADJ.gl_GY_OFS = eeprom_data[i] | (eeprom_data[i+1] << 8);
	i = i + 2;
	MY_ADJ.gl_KgxHG = eeprom_data[i] | (eeprom_data[i+1] << 8);
	i = i + 2;
	MY_ADJ.gl_KgyHG = eeprom_data[i] | (eeprom_data[i+1] << 8);
	i = i + 2;
	MY_ADJ.gl_KGXG = eeprom_data[i] | (eeprom_data[i+1] << 8);
	i = i + 2;
	MY_ADJ.gl_KGYG = eeprom_data[i] | (eeprom_data[i+1] << 8);
	i = i + 2;
	MY_ADJ.gl_SFTHAL_X = eeprom_data[i] | (eeprom_data[i+1] << 8);
	i = i + 2;
	MY_ADJ.gl_SFTHAL_Y = eeprom_data[i] | (eeprom_data[i+1] << 8);
	i = i + 2;
	MY_ADJ.gl_TMP_X_ = eeprom_data[i] | (eeprom_data[i+1] << 8);
	i = i + 2;
	MY_ADJ.gl_TMP_Y_ = eeprom_data[i] | (eeprom_data[i+1] << 8);
	i = i + 2;
	MY_ADJ.gl_KgxH0 = eeprom_data[i] | (eeprom_data[i+1] << 8);
	i = i + 2;
	MY_ADJ.gl_KgyH0 = eeprom_data[i] | (eeprom_data[i+1] << 8);
	i = i + 2;
//	CAM_ERR(CAM_ACTUATOR,"wangyue MY_ADJ.gl_CURDAT=0x%x,MY_ADJ.gl_HALOFS_X=0x%x,MY_ADJ.gl_HALOFS_Y=0x%x,MY_ADJ.gl_KgxH0=0x%x,MY_ADJ.gl_KgyH0=0x%x",MY_ADJ.gl_CURDAT,MY_ADJ.gl_HALOFS_X,MY_ADJ.gl_HALOFS_Y,MY_ADJ.gl_KgxH0,MY_ADJ.gl_KgyH0);
	return(MY_ADJ);

}

OIS_UWORD	INTG__INPUT;
OIS_UWORD	KGNTG_VALUE;
OIS_UWORD	GYRSNS;


//  *****************************************************
//  **** Program Download Function
//  *****************************************************
ADJ_STS		func_PROGRAM_DOWNLOAD(struct camera_io_master* ois_io_master_info)
{
	OIS_UWORD	sts;

	download(ois_io_master_info, 0, 0 );														// Program Download
	sts = I2C_OIS_mem__read(ois_io_master_info, _M_OIS_STS );									// Check Status

	if ( ( sts & 0x0004 ) == 0x0004 ){
	//	OIS_UWORD u16_dat;
	//	u16_dat = I2C_OIS_mem__read(ois_io_master_info, _M_FIRMVER );
		return ADJ_OK;														// Success
	}
	else{
		return PROG_DL_ERR;													// FAIL
	}
}


//  *****************************************************
//  **** COEF Download function
//  *****************************************************
void	func_COEF_DOWNLOAD(struct camera_io_master* ois_io_master_info, OIS_UWORD u16_coef_type )
{
	download(ois_io_master_info, 1, u16_coef_type );											// COEF Download

	// Get default Integ_input, KgnTG value and GYRSNS
	//INTG__INPUT = I2C_OIS_mem__read(ois_io_master_info, 0x38 );
	//KGNTG_VALUE = I2C_OIS_mem__read(ois_io_master_info, _M_KgxTG );
	//GYRSNS = I2C_OIS_mem__read(ois_io_master_info,_M_GYRSNS);
}


//  *****************************************************
//  **** Download the data
//  *****************************************************
void	download(struct camera_io_master* ois_io_master_info, OIS_UWORD u16_type, OIS_UWORD u16_coef_type ){

	// Data Transfer Size per one I2C access
	#define		DWNLD_TRNS_SIZE		(128)

	OIS_UBYTE	temp[DWNLD_TRNS_SIZE+1];
	OIS_UWORD	block_cnt;
	OIS_UWORD	total_cnt;
	OIS_UWORD	lp;
	OIS_UWORD	n;
	OIS_UWORD	u16_i;

	if	( u16_type == 0 ){
		n = DOWNLOAD_BIN_LEN;
	}
	else{
		n = DOWNLOAD_COEF_LEN;
	}
	block_cnt	= n / DWNLD_TRNS_SIZE + 1;
	total_cnt	= block_cnt;

	while( 1 ){
		// Residual Number Check
		if( block_cnt == 1 ){
			lp = n % DWNLD_TRNS_SIZE;
		}
		else{
			lp = DWNLD_TRNS_SIZE;
		}

		// Transfer Data set
		if( lp != 0 ){
			if(	u16_type == 0 ){
				temp[0] = _OP_FIRM_DWNLD;
				for( u16_i = 1; u16_i <= lp; u16_i += 1 ){
					temp[ u16_i ] = DOWNLOAD_BIN[ ( total_cnt - block_cnt ) * DWNLD_TRNS_SIZE + u16_i - 1 ];
				}
			}
			else{
				temp[0] = _OP_COEF_DWNLD;
				for( u16_i = 1; u16_i <= lp; u16_i += 1 ){
					temp[u16_i] = DOWNLOAD_COEF[(total_cnt - block_cnt) * DWNLD_TRNS_SIZE + u16_i -1];
				}
			}
			// Data Transfer
			WR_I2C(ois_io_master_info, _SLV_OIS_, lp+1, temp );
		}

		// Block Counter Decrement
		block_cnt = block_cnt - 1;
		if( block_cnt == 0 ){
			break;
		}
	}
}

void SET_FADJ_PARAM(struct camera_io_master* ois_io_master_info, const _FACT_ADJ *param )
{
	//*********************
	// HALL ADJUST
	//*********************
	// Set Hall Current DAC   value that is FACTORY ADJUSTED
	I2C_OIS_per_write(ois_io_master_info, _P_30_ADC_CH0, param->gl_CURDAT );
	// Set Hall     PreAmp Offset   that is FACTORY ADJUSTED
	I2C_OIS_per_write(ois_io_master_info, _P_31_ADC_CH1, param->gl_HALOFS_X );
	I2C_OIS_per_write(ois_io_master_info, _P_32_ADC_CH2, param->gl_HALOFS_Y );
	// Set Hall-X/Y PostAmp Offset  that is FACTORY ADJUSTED
	I2C_OIS_mem_write(ois_io_master_info, _M_X_H_ofs, param->gl_HX_OFS );
	I2C_OIS_mem_write(ois_io_master_info, _M_Y_H_ofs, param->gl_HY_OFS );
	// Set Residual Offset          that is FACTORY ADJUSTED
	I2C_OIS_per_write(ois_io_master_info, _P_39_Ch3_VAL_1, param->gl_PSTXOF );
	I2C_OIS_per_write(ois_io_master_info, _P_3B_Ch3_VAL_3, param->gl_PSTYOF );

	//*********************
	// DIGITAL GYRO OFFSET
	//*********************
//	I2C_OIS_mem_write(ois_io_master_info, _M_Kgx00, param->gl_GX_OFS );
//	I2C_OIS_mem_write(ois_io_master_info, _M_Kgy00, param->gl_GY_OFS );
	I2C_OIS_mem_write(ois_io_master_info, _M_TMP_X_, param->gl_TMP_X_ );
	I2C_OIS_mem_write(ois_io_master_info, _M_TMP_Y_, param->gl_TMP_Y_ );

	//*********************
	// HALL SENSE
	//*********************
	// Set Hall Gain   value that is FACTORY ADJUSTED
	I2C_OIS_mem_write(ois_io_master_info, _M_KgxHG, param->gl_KgxHG );
	I2C_OIS_mem_write(ois_io_master_info, _M_KgyHG, param->gl_KgyHG );
	// Set Cross Talk Canceller
	I2C_OIS_mem_write(ois_io_master_info, _M_KgxH0, param->gl_KgxH0 );
	I2C_OIS_mem_write(ois_io_master_info, _M_KgyH0, param->gl_KgyH0 );

	//*********************
	// LOOPGAIN
	//*********************
	I2C_OIS_mem_write(ois_io_master_info, _M_KgxG, param->gl_KGXG );
	I2C_OIS_mem_write(ois_io_master_info, _M_KgyG, param->gl_KGYG );

	// Position Servo ON ( OIS OFF )
	I2C_OIS_mem_write(ois_io_master_info, _M_EQCTL, 0x0C0C );
}

void SET_FADJ_PARAM_CLAF(struct camera_io_master* ois_io_master_info, const _FACT_ADJ_AF *param )
{
	I2C_OIS_per_write(ois_io_master_info, _P_37_ADC_CH7,	param->gl_CURDAZ    );				// Hall Bias
	I2C_OIS_per_write(ois_io_master_info, _P_36_ADC_CH6,	param->gl_HALOFS_Z  );				// Pre-amp offset
	I2C_OIS_per_write(ois_io_master_info, _P_38_Ch3_VAL_0,	param->gl_PSTZOF    );				// Post-amp offset
	I2C_OIS_per_write(ois_io_master_info, _P_M_HZOFS, 		param->gl_P_M_HZOFS );				// Digital offst
	I2C_OIS_per_write(ois_io_master_info, _P_M_KzHG,  		param->gl_P_M_KzHG  );				// Hall Normalized gain
}


//  *****************************************************
//  **** Write to the Peripheral register < 82h >
//  **** ------------------------------------------------
//  **** OIS_UBYTE	adr	Peripheral Address
//  **** OIS_UWORD	dat	Write data
//  *****************************************************
void	I2C_OIS_per_write(struct camera_io_master* ois_io_master_info, OIS_UBYTE u08_adr, OIS_UWORD u16_dat ){

	OIS_UBYTE	out[4];

	out[0] = _OP_Periphe_RW;
	out[1] = u08_adr;
	out[2] = ( u16_dat      ) & 0xFF;
	out[3] = ( u16_dat >> 8 ) & 0xFF;

	WR_I2C(ois_io_master_info, _SLV_OIS_, 4, out );
}

//  *****************************************************
//  **** Write to the Memory register < 84h >
//  **** ------------------------------------------------
//  **** OIS_UBYTE	adr	Memory Address
//  **** OIS_UWORD	dat	Write data
//  *****************************************************
void	I2C_OIS_mem_write(struct camera_io_master* ois_io_master_info, OIS_UBYTE u08_adr, OIS_UWORD u16_dat){

	OIS_UBYTE	out[4];

	out[0] = _OP_Memory__RW;
	out[1] = u08_adr;
	out[2] = ( u16_dat      ) & 0xFF;
	out[3] = ( u16_dat >> 8 ) & 0xFF;

	WR_I2C(ois_io_master_info, _SLV_OIS_, 4, out );
}

//  *****************************************************
//  **** Read from the Peripheral register < 82h >
//  **** ------------------------------------------------
//  **** OIS_UBYTE	adr	Peripheral Address
//  **** OIS_UWORD	dat	Read data
//  *****************************************************
OIS_UWORD	I2C_OIS_per__read(struct camera_io_master* ois_io_master_info, OIS_UBYTE u08_adr ){

	OIS_UBYTE	u08_dat[2];

	u08_dat[0] = _OP_Periphe_RW;											// Op-code
	u08_dat[1] = u08_adr;													// target address

	return RD_I2C(ois_io_master_info, _SLV_OIS_, 2, u08_dat );
}


//  *****************************************************
//  **** Read from the Memory register < 84h >
//  **** ------------------------------------------------
//  **** OIS_UBYTE	adr	Memory Address
//  **** OIS_UWORD	dat	Read data
//  *****************************************************
OIS_UWORD	I2C_OIS_mem__read(struct camera_io_master* ois_io_master_info, OIS_UBYTE u08_adr)
{
	OIS_UBYTE	u08_dat[2];

	u08_dat[0] = _OP_Memory__RW;											// Op-code
	u08_dat[1] = u08_adr;													// target address

	return RD_I2C(ois_io_master_info, _SLV_OIS_, 2, u08_dat );
}


//  *****************************************************
//  **** Special Command 8Ah
// 		_cmd_8C_EI			0	// 0x0001
// 		_cmd_8C_DI			1	// 0x0002
//  *****************************************************
void	I2C_OIS_spcl_cmnd(struct camera_io_master* ois_io_master_info, OIS_UBYTE u08_on, OIS_UBYTE u08_dat )
{
	if( ( u08_dat == _cmd_8C_EI ) ||
			( u08_dat == _cmd_8C_DI )    ){

		OIS_UBYTE out[2];

		out[0] = _OP_SpecialCMD;
		out[1] = u08_dat;

		WR_I2C(ois_io_master_info, _SLV_OIS_, 2, out );
	}
}
void set_mode_parameter( struct camera_io_master* ois_io_master_info )
{
#if 0
    //*********************
	// test mode
	I2C_OIS_mem_write(ois_io_master_info, 0x7F, 0x0C0C);
	I2C_OIS_mem_write(ois_io_master_info, 0x36, 0x7FFF);
	I2C_OIS_mem_write(ois_io_master_info, 0x40, 0x7FFF);
	I2C_OIS_mem_write(ois_io_master_info, 0x43, 0x7FFF);
	I2C_OIS_mem_write(ois_io_master_info, 0x1B, 0x0080);
	I2C_OIS_mem_write(ois_io_master_info, 0xB6, 0x7FFF);
	I2C_OIS_mem_write(ois_io_master_info, 0xC0, 0x7FFF);
	I2C_OIS_mem_write(ois_io_master_info, 0xC3, 0x7FFF);
	I2C_OIS_mem_write(ois_io_master_info, 0x9B, 0x0080);
	I2C_OIS_mem_write(ois_io_master_info, 0x38, 0x0952);
	I2C_OIS_mem_write(ois_io_master_info, 0xB8, 0x0952);
	I2C_OIS_mem_write(ois_io_master_info, 0x47, 0x3bf5);
	I2C_OIS_mem_write(ois_io_master_info, 0xC7, 0x3bf5);

    I2C_OIS_mem_write(ois_io_master_info, 0x40, 0x3FFF);
    I2C_OIS_mem_write(ois_io_master_info, 0xC0, 0x3FFF);
    I2C_OIS_mem_write(ois_io_master_info, 0x36, 0x7FF0);
    I2C_OIS_mem_write(ois_io_master_info, 0xB6, 0x7FF0);

    I2C_OIS_per_write(ois_io_master_info, 0x90, 0x7FF0);
    I2C_OIS_per_write(ois_io_master_info, 0x96, 0x0180);
    I2C_OIS_per_write(ois_io_master_info, 0x91, 0x0005);
    I2C_OIS_per_write(ois_io_master_info, 0x92, 0x0002);
    I2C_OIS_per_write(ois_io_master_info, 0x99, 0x0480);

	I2C_OIS_mem_write(ois_io_master_info, 0x7F, 0x0D0D);
#endif
  // still mode
  I2C_OIS_mem_write(ois_io_master_info, 0x7F, 0x0C0C);
  I2C_OIS_mem_write(ois_io_master_info, 0x36, 0x7ffd);
  I2C_OIS_mem_write(ois_io_master_info, 0x40, 0x3fff);
  I2C_OIS_mem_write(ois_io_master_info, 0x43, 0x28f0);
  I2C_OIS_mem_write(ois_io_master_info, 0x1B, 0x0080);
  I2C_OIS_mem_write(ois_io_master_info, 0xB6, 0x7ffd);
  I2C_OIS_mem_write(ois_io_master_info, 0xC0, 0x3fff);
  I2C_OIS_mem_write(ois_io_master_info, 0xC3, 0x28f0);
  I2C_OIS_mem_write(ois_io_master_info, 0x9B, 0x0080);
  I2C_OIS_mem_write(ois_io_master_info, 0x38, 0x1234);
  I2C_OIS_mem_write(ois_io_master_info, 0xB8, 0x1234);
  I2C_OIS_mem_write(ois_io_master_info, 0x47, 0x1e2b);
  I2C_OIS_mem_write(ois_io_master_info, 0xC7, 0x1e2b);

  I2C_OIS_mem_write(ois_io_master_info, 0x40, 0x3FFF);
  I2C_OIS_mem_write(ois_io_master_info, 0xC0, 0x3FFF);
  I2C_OIS_mem_write(ois_io_master_info, 0x36, 0x7FF0);
  I2C_OIS_mem_write(ois_io_master_info, 0xB6, 0x7FF0);

  I2C_OIS_per_write(ois_io_master_info, 0x90, 0x7FF0);
  I2C_OIS_per_write(ois_io_master_info, 0x96, 0x0180);
  I2C_OIS_per_write(ois_io_master_info, 0x91, 0x0005);
  I2C_OIS_per_write(ois_io_master_info, 0x92, 0x0002);
  I2C_OIS_per_write(ois_io_master_info, 0x99, 0x0480);

  I2C_OIS_mem_write(ois_io_master_info, 0x7F, 0x0D0D);

}

/**
 * read /persist/gyro_calib.bin if exist and lens is 0 else write gyro_calib.bin
 * need create gyro_calib.bin
 * Returns success or failure
 */
void set_gyro_offset( struct camera_io_master* ois_io_master_info )
{
	struct file *pfile = NULL;
	mm_segment_t old_fs;
	int ret = 0;
	loff_t pos = 0;
	const char * filename = CALIBRATE_FILE;
	unsigned char buf1[4] = {0};

	OIS_WORD u16_dat_x[10] = {0},u16_dat_y[10] = {0},avg_data_x = 0,avg_data_y = 0;
	int i = 0,sum_x  = 0,sum_y  = 0;

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	pfile = filp_open(filename, O_RDWR | O_CREAT, 0660);
	if (!IS_ERR(pfile)) {
		pos = vfs_llseek(pfile, 0, SEEK_END);
		if (pos <= 0) {
			CAM_ERR(CAM_OIS,"gyro_offset %s: %s open failed! pos %lld", __func__, filename,pos);
			pos = 0;
			for (i = 0 ; i < 10; i++){
				u16_dat_x[i] = I2C_OIS_mem__read(ois_io_master_info, 0x55 );
				sum_x += u16_dat_x[i];
				u16_dat_y[i] = I2C_OIS_mem__read(ois_io_master_info, 0x56 );
				sum_y += u16_dat_y[i];
			}
			avg_data_x = sum_x/10;
			avg_data_y = sum_y/10;
			buf1[0] = (avg_data_x & 0xff);
			buf1[1] = (avg_data_x & 0xff00)>>8;
			buf1[2] = (avg_data_y & 0xff);
			buf1[3] = (avg_data_y & 0xff00)>>8;
            
			ret = vfs_write(pfile, (char *)&buf1, sizeof(buf1), &pos);
			if (ret < 0) {
				CAM_ERR(CAM_OIS,"gyro_offset %s: %s vfs_write failed!", __func__, filename);
			}
			CAM_ERR(CAM_OIS,"gyro_offset %s: %s vfs_write ok! pos %lld buf1[0]0x%x,buf1[1]0x%x,buf1[2]0x%x,buf1[3]0x%x,avg_data_x=%x,avg_data_y=%x", __func__, filename,pos,buf1[0],buf1[1],buf1[2],buf1[3],avg_data_x,avg_data_y);
		} else {
			pos = 0;  
			ret =  vfs_read(pfile, (char *)&buf1, sizeof(buf1), &pos);
			if (ret < 0) {
				CAM_ERR(CAM_OIS,"gyro_offset %s: %s vfs_read failed!", __func__, filename);
			}
			avg_data_x = (buf1[1] << 8) | buf1[0];
			avg_data_y = (buf1[3] << 8) | buf1[2];
			CAM_ERR(CAM_OIS,"gyro_offset %s: %s vfs_read ok! pos %lld buf1[0]0x%x,buf1[1]0x%x,buf1[2]0x%x,buf1[3]0x%x,avg_data_x=%x,avg_data_y=%x", __func__, filename,pos,buf1[0],buf1[1],buf1[2],buf1[3],avg_data_x,avg_data_y);
			I2C_OIS_mem_write(ois_io_master_info, 0x06, avg_data_x);
			I2C_OIS_mem_write(ois_io_master_info, 0x86, avg_data_y);
		}

		filp_close(pfile, NULL);
	} else {
		CAM_ERR(CAM_OIS,"gyro_offset %s: %s filp_open failed!", __func__, filename);
		ret = -1;
	}
	set_fs(old_fs);
	return;
}

int32_t cam_ois_fw_init(struct camera_io_master *ois_io_master_info) {
	_FACT_ADJ  fadj; 
	int32_t rc = 0;

	fadj  = get_FADJ_MEM_from_non_volatile_memory(ois_io_master_info); 
    
	VCOSET0(ois_io_master_info);
	rc  = func_PROGRAM_DOWNLOAD(ois_io_master_info);                // Program Download
	if (rc < 0) {
		CAM_ERR(CAM_ACTUATOR,
				"Failed to apply func_PROGRAM_DOWNLOAD: %d",rc);
		return rc;
	}
	func_COEF_DOWNLOAD(ois_io_master_info, 0 );
	VCOSET1(ois_io_master_info);
	SET_FADJ_PARAM(ois_io_master_info, &fadj );
	I2C_OIS_spcl_cmnd(ois_io_master_info, 1, _cmd_8C_EI );   // DSP calculation START
	I2C_OIS_mem_write(ois_io_master_info, _M_EQCTL, 0x0C0C );
	I2C_OIS_mem_write(ois_io_master_info, _M_EQCTL, 0x0D0D );
	set_mode_parameter(ois_io_master_info);
    set_gyro_offset(ois_io_master_info);

	return 0;
}

int32_t cam_ois_construct_default_power_setting(
	struct cam_sensor_power_ctrl_t *power_info)
{
	int rc = 0;

	power_info->power_setting_size = 1;
	power_info->power_setting =
		(struct cam_sensor_power_setting *)
		kzalloc(sizeof(struct cam_sensor_power_setting),
			GFP_KERNEL);
	if (!power_info->power_setting)
		return -ENOMEM;

	power_info->power_setting[0].seq_type = SENSOR_VAF;
	power_info->power_setting[0].seq_val = CAM_VAF;
	power_info->power_setting[0].config_val = 1;
	power_info->power_setting[0].delay = 2;

	power_info->power_down_setting_size = 1;
	power_info->power_down_setting =
		(struct cam_sensor_power_setting *)
		kzalloc(sizeof(struct cam_sensor_power_setting),
			GFP_KERNEL);
	if (!power_info->power_down_setting) {
		rc = -ENOMEM;
		goto free_power_settings;
	}

	power_info->power_down_setting[0].seq_type = SENSOR_VAF;
	power_info->power_down_setting[0].seq_val = CAM_VAF;
	power_info->power_down_setting[0].config_val = 0;

	return rc;

free_power_settings:
	kfree(power_info->power_setting);
	return rc;
}


/**
 * cam_ois_get_dev_handle - get device handle
 * @o_ctrl:     ctrl structure
 * @arg:        Camera control command argument
 *
 * Returns success or failure
 */
static int cam_ois_get_dev_handle(struct cam_ois_ctrl_t *o_ctrl,
	void *arg)
{
	struct cam_sensor_acquire_dev    ois_acq_dev;
	struct cam_create_dev_hdl        bridge_params;
	struct cam_control              *cmd = (struct cam_control *)arg;

	if (o_ctrl->bridge_intf.device_hdl != -1) {
		CAM_ERR(CAM_OIS, "Device is already acquired");
		return -EFAULT;
	}
	if (copy_from_user(&ois_acq_dev, (void __user *) cmd->handle,
		sizeof(ois_acq_dev)))
		return -EFAULT;

	bridge_params.session_hdl = ois_acq_dev.session_handle;
	bridge_params.ops = &o_ctrl->bridge_intf.ops;
	bridge_params.v4l2_sub_dev_flag = 0;
	bridge_params.media_entity_flag = 0;
	bridge_params.priv = o_ctrl;

	ois_acq_dev.device_handle =
		cam_create_device_hdl(&bridge_params);
	o_ctrl->bridge_intf.device_hdl = ois_acq_dev.device_handle;
	o_ctrl->bridge_intf.session_hdl = ois_acq_dev.session_handle;

	CAM_DBG(CAM_OIS, "Device Handle: %d", ois_acq_dev.device_handle);
	if (copy_to_user((void __user *) cmd->handle, &ois_acq_dev,
		sizeof(struct cam_sensor_acquire_dev))) {
		CAM_ERR(CAM_OIS, "ACQUIRE_DEV: copy to user failed");
		return -EFAULT;
	}
	return 0;
}

static int cam_ois_power_up(struct cam_ois_ctrl_t *o_ctrl)
{
	int                             rc = 0;
	struct cam_hw_soc_info          *soc_info =
		&o_ctrl->soc_info;
	struct cam_ois_soc_private *soc_private;
	struct cam_sensor_power_ctrl_t  *power_info;

	soc_private =
		(struct cam_ois_soc_private *)o_ctrl->soc_info.soc_private;
	power_info = &soc_private->power_info;

	if ((power_info->power_setting == NULL) &&
		(power_info->power_down_setting == NULL)) {
		CAM_INFO(CAM_OIS,
			"Using default power settings");
		rc = cam_ois_construct_default_power_setting(power_info);
		if (rc < 0) {
			CAM_ERR(CAM_OIS,
				"Construct default ois power setting failed.");
			return rc;
		}
	}

	/* Parse and fill vreg params for power up settings */
	rc = msm_camera_fill_vreg_params(
		soc_info,
		power_info->power_setting,
		power_info->power_setting_size);
	if (rc) {
		CAM_ERR(CAM_OIS,
			"failed to fill vreg params for power up rc:%d", rc);
		return rc;
	}

	/* Parse and fill vreg params for power down settings*/
	rc = msm_camera_fill_vreg_params(
		soc_info,
		power_info->power_down_setting,
		power_info->power_down_setting_size);
	if (rc) {
		CAM_ERR(CAM_OIS,
			"failed to fill vreg params for power down rc:%d", rc);
		return rc;
	}

	power_info->dev = soc_info->dev;

	rc = cam_sensor_core_power_up(power_info, soc_info);
	if (rc) {
		CAM_ERR(CAM_OIS, "failed in ois power up rc %d", rc);
		return rc;
	}

	rc = camera_io_init(&o_ctrl->io_master_info);
	if (rc)
		CAM_ERR(CAM_OIS, "cci_init failed: rc: %d", rc);

	return rc;
}

/**
 * cam_ois_power_down - power down OIS device
 * @o_ctrl:     ctrl structure
 *
 * Returns success or failure
 */
static int cam_ois_power_down(struct cam_ois_ctrl_t *o_ctrl)
{
	int32_t                         rc = 0;
	struct cam_sensor_power_ctrl_t  *power_info;
	struct cam_hw_soc_info          *soc_info =
		&o_ctrl->soc_info;
	struct cam_ois_soc_private *soc_private;

	if (!o_ctrl) {
		CAM_ERR(CAM_OIS, "failed: o_ctrl %pK", o_ctrl);
		return -EINVAL;
	}

	soc_private =
		(struct cam_ois_soc_private *)o_ctrl->soc_info.soc_private;
	power_info = &soc_private->power_info;
	soc_info = &o_ctrl->soc_info;

	if (!power_info) {
		CAM_ERR(CAM_OIS, "failed: power_info %pK", power_info);
		return -EINVAL;
	}

	rc = msm_camera_power_down(power_info, soc_info);
	if (rc) {
		CAM_ERR(CAM_OIS, "power down the core is failed:%d", rc);
		return rc;
	}

	camera_io_release(&o_ctrl->io_master_info);

	return rc;
}

static int cam_ois_apply_settings(struct cam_ois_ctrl_t *o_ctrl,
	struct i2c_settings_array *i2c_set)
{
	struct i2c_settings_list *i2c_list;
	int32_t rc = 0;
	uint32_t i, size;

	if (o_ctrl == NULL || i2c_set == NULL) {
		CAM_ERR(CAM_OIS, "Invalid Args");
		return -EINVAL;
	}

	if (i2c_set->is_settings_valid != 1) {
		CAM_ERR(CAM_OIS, " Invalid settings");
		return -EINVAL;
	}
	list_for_each_entry(i2c_list,
		&(i2c_set->list_head), list) {
		if (i2c_list->op_code ==  CAM_SENSOR_I2C_WRITE_RANDOM) {
			rc = camera_io_dev_write(&(o_ctrl->io_master_info),
				&(i2c_list->i2c_settings));
			if (rc < 0) {
				CAM_ERR(CAM_OIS,
					"Failed in Applying i2c wrt settings");
				return rc;
			}
		} else if (i2c_list->op_code == CAM_SENSOR_I2C_POLL) {
			size = i2c_list->i2c_settings.size;
			for (i = 0; i < size; i++) {
				rc = camera_io_dev_poll(
					&(o_ctrl->io_master_info),
					i2c_list->i2c_settings.
						reg_setting[i].reg_addr,
					i2c_list->i2c_settings.
						reg_setting[i].reg_data,
					i2c_list->i2c_settings.
						reg_setting[i].data_mask,
					i2c_list->i2c_settings.addr_type,
					i2c_list->i2c_settings.data_type,
					i2c_list->i2c_settings.
						reg_setting[i].delay);
				if (rc < 0) {
					CAM_ERR(CAM_OIS,
						"i2c poll apply setting Fail");
					return rc;
				}
			}
		}
	}

	return rc;
}

static int cam_ois_slaveInfo_pkt_parser(struct cam_ois_ctrl_t *o_ctrl,
	uint32_t *cmd_buf)
{
	int32_t rc = 0;
	struct cam_cmd_ois_info *ois_info;

	if (!o_ctrl || !cmd_buf) {
		CAM_ERR(CAM_OIS, "Invalid Args");
		return -EINVAL;
	}

	ois_info = (struct cam_cmd_ois_info *)cmd_buf;
	if (o_ctrl->io_master_info.master_type == CCI_MASTER) {
		o_ctrl->io_master_info.cci_client->i2c_freq_mode =
			ois_info->i2c_freq_mode;
		o_ctrl->io_master_info.cci_client->sid =
			ois_info->slave_addr >> 1;
		o_ctrl->ois_fw_flag = ois_info->ois_fw_flag;
		o_ctrl->is_ois_calib = ois_info->is_ois_calib;
		memcpy(o_ctrl->ois_name, ois_info->ois_name, 32);
		o_ctrl->io_master_info.cci_client->retries = 3;
		o_ctrl->io_master_info.cci_client->id_map = 0;
		memcpy(&(o_ctrl->opcode), &(ois_info->opcode),
			sizeof(struct cam_ois_opcode));
		CAM_DBG(CAM_OIS, "Slave addr: 0x%x Freq Mode: %d",
			ois_info->slave_addr, ois_info->i2c_freq_mode);
	} else if (o_ctrl->io_master_info.master_type == I2C_MASTER) {
		o_ctrl->io_master_info.client->addr = ois_info->slave_addr;
		CAM_DBG(CAM_OIS, "Slave addr: 0x%x", ois_info->slave_addr);
	} else {
		CAM_ERR(CAM_OIS, "Invalid Master type : %d",
			o_ctrl->io_master_info.master_type);
		rc = -EINVAL;
	}

	return rc;
}

static int cam_ois_fw_download(struct cam_ois_ctrl_t *o_ctrl)
{
    return cam_ois_fw_init(&(o_ctrl->io_master_info));
#if 0
	uint16_t                           total_bytes = 0;
	uint8_t                           *ptr = NULL;
	int32_t                            rc = 0, cnt;
	uint32_t                           fw_size;
	const struct firmware             *fw = NULL;
	const char                        *fw_name_prog = NULL;
	const char                        *fw_name_coeff = NULL;
	char                               name_prog[32] = {0};
	char                               name_coeff[32] = {0};
	struct device                     *dev = &(o_ctrl->pdev->dev);
	struct cam_sensor_i2c_reg_setting  i2c_reg_setting;
	struct page                       *page = NULL;

	if (!o_ctrl) {
		CAM_ERR(CAM_OIS, "Invalid Args");
		return -EINVAL;
	}

	snprintf(name_coeff, 32, "%s.coeff", o_ctrl->ois_name);

	snprintf(name_prog, 32, "%s.prog", o_ctrl->ois_name);

	/* cast pointer as const pointer*/
	fw_name_prog = name_prog;
	fw_name_coeff = name_coeff;

	/* Load FW */
	rc = request_firmware(&fw, fw_name_prog, dev);
	if (rc) {
		CAM_ERR(CAM_OIS, "Failed to locate %s", fw_name_prog);
		return rc;
	}

	total_bytes = fw->size;
	i2c_reg_setting.addr_type = CAMERA_SENSOR_I2C_TYPE_BYTE;
	i2c_reg_setting.data_type = CAMERA_SENSOR_I2C_TYPE_BYTE;
	i2c_reg_setting.size = total_bytes;
	fw_size = PAGE_ALIGN(sizeof(struct cam_sensor_i2c_reg_array) *
		total_bytes) >> PAGE_SHIFT;
	page = cma_alloc(dev_get_cma_area((o_ctrl->soc_info.dev)),
		fw_size, 0);
	if (!page) {
		CAM_ERR(CAM_OIS, "Failed in allocating i2c_array");
		release_firmware(fw);
		return -ENOMEM;
	}

	i2c_reg_setting.reg_setting = (struct cam_sensor_i2c_reg_array *)(
		page_address(page));

	for (cnt = 0, ptr = (uint8_t *)fw->data; cnt < total_bytes;
		cnt++, ptr++) {
		i2c_reg_setting.reg_setting[cnt].reg_addr =
			o_ctrl->opcode.prog;
		i2c_reg_setting.reg_setting[cnt].reg_data = *ptr;
		i2c_reg_setting.reg_setting[cnt].delay = 0;
		i2c_reg_setting.reg_setting[cnt].data_mask = 0;
	}

	rc = camera_io_dev_write_continuous(&(o_ctrl->io_master_info),
		&i2c_reg_setting, 1);
	if (rc < 0) {
		CAM_ERR(CAM_OIS, "OIS FW download failed %d", rc);
		goto release_firmware;
	}
	cma_release(dev_get_cma_area((o_ctrl->soc_info.dev)),
		page, fw_size);
	page = NULL;
	fw_size = 0;
	release_firmware(fw);

	rc = request_firmware(&fw, fw_name_coeff, dev);
	if (rc) {
		CAM_ERR(CAM_OIS, "Failed to locate %s", fw_name_coeff);
		return rc;
	}

	total_bytes = fw->size;
	i2c_reg_setting.addr_type = CAMERA_SENSOR_I2C_TYPE_BYTE;
	i2c_reg_setting.data_type = CAMERA_SENSOR_I2C_TYPE_BYTE;
	i2c_reg_setting.size = total_bytes;
	fw_size = PAGE_ALIGN(sizeof(struct cam_sensor_i2c_reg_array) *
		total_bytes) >> PAGE_SHIFT;
	page = cma_alloc(dev_get_cma_area((o_ctrl->soc_info.dev)),
		fw_size, 0);
	if (!page) {
		CAM_ERR(CAM_OIS, "Failed in allocating i2c_array");
		release_firmware(fw);
		return -ENOMEM;
	}

	i2c_reg_setting.reg_setting = (struct cam_sensor_i2c_reg_array *)(
		page_address(page));

	for (cnt = 0, ptr = (uint8_t *)fw->data; cnt < total_bytes;
		cnt++, ptr++) {
		i2c_reg_setting.reg_setting[cnt].reg_addr =
			o_ctrl->opcode.coeff;
		i2c_reg_setting.reg_setting[cnt].reg_data = *ptr;
		i2c_reg_setting.reg_setting[cnt].delay = 0;
		i2c_reg_setting.reg_setting[cnt].data_mask = 0;
	}

	rc = camera_io_dev_write_continuous(&(o_ctrl->io_master_info),
		&i2c_reg_setting, 1);
	if (rc < 0)
		CAM_ERR(CAM_OIS, "OIS FW download failed %d", rc);

release_firmware:
	cma_release(dev_get_cma_area((o_ctrl->soc_info.dev)),
		page, fw_size);
	release_firmware(fw);

	return rc;
#endif   
}

/**
 * cam_ois_pkt_parse - Parse csl packet
 * @o_ctrl:     ctrl structure
 * @arg:        Camera control command argument
 *
 * Returns success or failure
 */
static int cam_ois_pkt_parse(struct cam_ois_ctrl_t *o_ctrl, void *arg)
{
	int32_t                         rc = 0;
	int32_t                         i = 0;
	uint32_t                        total_cmd_buf_in_bytes = 0;
	struct common_header           *cmm_hdr = NULL;
	uint64_t                        generic_ptr;
	struct cam_control             *ioctl_ctrl = NULL;
	struct cam_config_dev_cmd       dev_config;
	struct i2c_settings_array      *i2c_reg_settings = NULL;
	struct cam_cmd_buf_desc        *cmd_desc = NULL;
	uint64_t                        generic_pkt_addr;
	size_t                          pkt_len;
	struct cam_packet              *csl_packet = NULL;
	size_t                          len_of_buff = 0;
	uint32_t                       *offset = NULL, *cmd_buf;
	struct cam_ois_soc_private     *soc_private =
		(struct cam_ois_soc_private *)o_ctrl->soc_info.soc_private;
	struct cam_sensor_power_ctrl_t  *power_info = &soc_private->power_info;

	ioctl_ctrl = (struct cam_control *)arg;
	if (copy_from_user(&dev_config, (void __user *) ioctl_ctrl->handle,
		sizeof(dev_config)))
		return -EFAULT;
	rc = cam_mem_get_cpu_buf(dev_config.packet_handle,
		(uint64_t *)&generic_pkt_addr, &pkt_len);
	if (rc) {
		CAM_ERR(CAM_OIS,
			"error in converting command Handle Error: %d", rc);
		return rc;
	}

	if (dev_config.offset > pkt_len) {
		CAM_ERR(CAM_OIS,
			"offset is out of bound: off: %lld len: %zu",
			dev_config.offset, pkt_len);
		return -EINVAL;
	}

	csl_packet = (struct cam_packet *)
		(generic_pkt_addr + dev_config.offset);
	switch (csl_packet->header.op_code & 0xFFFFFF) {
	case CAM_OIS_PACKET_OPCODE_INIT:
		offset = (uint32_t *)&csl_packet->payload;
		offset += (csl_packet->cmd_buf_offset / sizeof(uint32_t));
		cmd_desc = (struct cam_cmd_buf_desc *)(offset);

		/* Loop through multiple command buffers */
		for (i = 0; i < csl_packet->num_cmd_buf; i++) {
			total_cmd_buf_in_bytes = cmd_desc[i].length;
			if (!total_cmd_buf_in_bytes)
				continue;

			rc = cam_mem_get_cpu_buf(cmd_desc[i].mem_handle,
				(uint64_t *)&generic_ptr, &len_of_buff);
			if (rc < 0) {
				CAM_ERR(CAM_OIS, "Failed to get cpu buf");
				return rc;
			}
			cmd_buf = (uint32_t *)generic_ptr;
			if (!cmd_buf) {
				CAM_ERR(CAM_OIS, "invalid cmd buf");
				return -EINVAL;
			}
			cmd_buf += cmd_desc[i].offset / sizeof(uint32_t);
			cmm_hdr = (struct common_header *)cmd_buf;

			switch (cmm_hdr->cmd_type) {
			case CAMERA_SENSOR_CMD_TYPE_I2C_INFO:
				rc = cam_ois_slaveInfo_pkt_parser(
					o_ctrl, cmd_buf);
				if (rc < 0) {
					CAM_ERR(CAM_OIS,
					"Failed in parsing slave info");
					return rc;
				}
				break;
			case CAMERA_SENSOR_CMD_TYPE_PWR_UP:
			case CAMERA_SENSOR_CMD_TYPE_PWR_DOWN:
				CAM_DBG(CAM_OIS,
					"Received power settings buffer");
				rc = cam_sensor_update_power_settings(
					cmd_buf,
					total_cmd_buf_in_bytes,
					power_info);
				if (rc) {
					CAM_ERR(CAM_OIS,
					"Failed: parse power settings");
					return rc;
				}
				break;
			default:
			if (o_ctrl->i2c_init_data.is_settings_valid == 0) {
				CAM_DBG(CAM_OIS,
				"Received init settings");
				i2c_reg_settings =
					&(o_ctrl->i2c_init_data);
				i2c_reg_settings->is_settings_valid = 1;
				i2c_reg_settings->request_id = 0;
				rc = cam_sensor_i2c_command_parser(
					i2c_reg_settings,
					&cmd_desc[i], 1);
				if (rc < 0) {
					CAM_ERR(CAM_OIS,
					"init parsing failed: %d", rc);
					return rc;
				}
			} else if ((o_ctrl->is_ois_calib != 0) &&
				(o_ctrl->i2c_calib_data.
					is_settings_valid == 0)) {
				CAM_DBG(CAM_OIS,
					"Received calib settings");
				i2c_reg_settings = &(o_ctrl->i2c_calib_data);
				i2c_reg_settings->is_settings_valid = 1;
				i2c_reg_settings->request_id = 0;
				rc = cam_sensor_i2c_command_parser(
					i2c_reg_settings,
					&cmd_desc[i], 1);
				if (rc < 0) {
					CAM_ERR(CAM_OIS,
						"Calib parsing failed: %d", rc);
					return rc;
				}
			}
			break;
			}
		}

		if (o_ctrl->cam_ois_state != CAM_OIS_CONFIG) {
			rc = cam_ois_power_up(o_ctrl);
			if (rc) {
				CAM_ERR(CAM_OIS, " OIS Power up failed");
				return rc;
			}
			o_ctrl->cam_ois_state = CAM_OIS_CONFIG;
		}
		CAM_ERR(CAM_OIS, "wangyue o_ctrl->ois_fw_flag=%d,o_ctrl->is_ois_calib=%d",o_ctrl->ois_fw_flag,o_ctrl->is_ois_calib);
       	o_ctrl->ois_fw_flag = 1; //only kernel init ois
		if (o_ctrl->ois_fw_flag) {
			rc = cam_ois_fw_download(o_ctrl);
			if (rc) {
				CAM_ERR(CAM_OIS, "Failed OIS FW Download");
				goto pwr_dwn;
			}
		} else {
			rc = cam_ois_apply_settings(o_ctrl, &o_ctrl->i2c_init_data);
			if (rc < 0) {
				CAM_ERR(CAM_OIS, "Cannot apply Init settings");
				goto pwr_dwn;
			}
		//	set_gyro_offset(&(o_ctrl->io_master_info));
		}

//		rc = cam_ois_apply_settings(o_ctrl, &o_ctrl->i2c_init_data);
//		if (rc < 0) {
//			CAM_ERR(CAM_OIS, "Cannot apply Init settings");
//			goto pwr_dwn;
//		}

		if (o_ctrl->is_ois_calib) {
			rc = cam_ois_apply_settings(o_ctrl,
				&o_ctrl->i2c_calib_data);
			if (rc) {
				CAM_ERR(CAM_OIS, "Cannot apply calib data");
				goto pwr_dwn;
			}
		}

		rc = delete_request(&o_ctrl->i2c_init_data);
		if (rc < 0) {
			CAM_WARN(CAM_OIS,
				"Fail deleting Init data: rc: %d", rc);
			rc = 0;
		}
		rc = delete_request(&o_ctrl->i2c_calib_data);
		if (rc < 0) {
			CAM_WARN(CAM_OIS,
				"Fail deleting Calibration data: rc: %d", rc);
			rc = 0;
		}
		break;
	case CAM_OIS_PACKET_OPCODE_OIS_CONTROL:
		if (o_ctrl->cam_ois_state < CAM_OIS_CONFIG) {
			rc = -EINVAL;
			CAM_WARN(CAM_OIS,
				"Not in right state to control OIS: %d",
				o_ctrl->cam_ois_state);
			return rc;
		}
		offset = (uint32_t *)&csl_packet->payload;
		offset += (csl_packet->cmd_buf_offset / sizeof(uint32_t));
		cmd_desc = (struct cam_cmd_buf_desc *)(offset);
		i2c_reg_settings = &(o_ctrl->i2c_mode_data);
		i2c_reg_settings->is_settings_valid = 1;
		i2c_reg_settings->request_id = 0;
		rc = cam_sensor_i2c_command_parser(i2c_reg_settings,
			cmd_desc, 1);
		if (rc < 0) {
			CAM_ERR(CAM_OIS, "OIS pkt parsing failed: %d", rc);
			return rc;
		}

		rc = cam_ois_apply_settings(o_ctrl, i2c_reg_settings);
		if (rc < 0) {
			CAM_ERR(CAM_OIS, "Cannot apply mode settings");
			return rc;
		}

		rc = delete_request(i2c_reg_settings);
		if (rc < 0)
			CAM_ERR(CAM_OIS,
				"Fail deleting Mode data: rc: %d", rc);
		break;
	default:
		break;
	}
	return rc;
pwr_dwn:
	cam_ois_power_down(o_ctrl);
	return rc;
}

void cam_ois_shutdown(struct cam_ois_ctrl_t *o_ctrl)
{
	int rc;

	if (o_ctrl->cam_ois_state == CAM_OIS_INIT)
		return;

	if (o_ctrl->cam_ois_state >= CAM_OIS_CONFIG) {
		rc = cam_ois_power_down(o_ctrl);
		if (rc < 0)
			CAM_ERR(CAM_OIS, "OIS Power down failed");
	}

	if (o_ctrl->cam_ois_state >= CAM_OIS_ACQUIRE) {
		rc = cam_destroy_device_hdl(o_ctrl->bridge_intf.device_hdl);
		if (rc < 0)
			CAM_ERR(CAM_OIS, "destroying the device hdl");
		o_ctrl->bridge_intf.device_hdl = -1;
		o_ctrl->bridge_intf.link_hdl = -1;
		o_ctrl->bridge_intf.session_hdl = -1;
	}

	o_ctrl->cam_ois_state = CAM_OIS_INIT;
}

/**
 * cam_ois_driver_cmd - Handle ois cmds
 * @e_ctrl:     ctrl structure
 * @arg:        Camera control command argument
 *
 * Returns success or failure
 */
int cam_ois_driver_cmd(struct cam_ois_ctrl_t *o_ctrl, void *arg)
{
	int                            rc = 0;
	struct cam_ois_query_cap_t     ois_cap = {0};
	struct cam_control            *cmd = (struct cam_control *)arg;

	if (!o_ctrl) {
		CAM_ERR(CAM_OIS, "e_ctrl is NULL");
		return -EINVAL;
	}

	mutex_lock(&(o_ctrl->ois_mutex));
	switch (cmd->op_code) {
	case CAM_QUERY_CAP:
		ois_cap.slot_info = o_ctrl->soc_info.index;

		if (copy_to_user((void __user *) cmd->handle,
			&ois_cap,
			sizeof(struct cam_ois_query_cap_t))) {
			CAM_ERR(CAM_OIS, "Failed Copy to User");
			rc = -EFAULT;
			goto release_mutex;
		}
		CAM_DBG(CAM_OIS, "ois_cap: ID: %d", ois_cap.slot_info);
		break;
	case CAM_ACQUIRE_DEV:
		rc = cam_ois_get_dev_handle(o_ctrl, arg);
		if (rc) {
			CAM_ERR(CAM_OIS, "Failed to acquire dev");
			goto release_mutex;
		}

		o_ctrl->cam_ois_state = CAM_OIS_ACQUIRE;
		break;
	case CAM_START_DEV:
		if (o_ctrl->cam_ois_state != CAM_OIS_CONFIG) {
			rc = -EINVAL;
			CAM_WARN(CAM_OIS,
			"Not in right state for start : %d",
			o_ctrl->cam_ois_state);
			goto release_mutex;
		}
		o_ctrl->cam_ois_state = CAM_OIS_START;
		break;
	case CAM_CONFIG_DEV:
		rc = cam_ois_pkt_parse(o_ctrl, arg);
		if (rc) {
			CAM_ERR(CAM_OIS, "Failed in ois pkt Parsing");
			goto release_mutex;
		}
		break;
	case CAM_RELEASE_DEV:
		if (o_ctrl->cam_ois_state == CAM_OIS_START) {
			rc = -EINVAL;
			CAM_WARN(CAM_OIS,
				"Cant release ois: in start state");
			goto release_mutex;
		}

		if (o_ctrl->cam_ois_state == CAM_OIS_CONFIG) {
			rc = cam_ois_power_down(o_ctrl);
			if (rc < 0) {
				CAM_ERR(CAM_OIS, "OIS Power down failed");
				goto release_mutex;
			}
		}

		if (o_ctrl->bridge_intf.device_hdl == -1) {
			CAM_ERR(CAM_OIS, "link hdl: %d device hdl: %d",
				o_ctrl->bridge_intf.device_hdl,
				o_ctrl->bridge_intf.link_hdl);
			rc = -EINVAL;
			goto release_mutex;
		}
		rc = cam_destroy_device_hdl(o_ctrl->bridge_intf.device_hdl);
		if (rc < 0)
			CAM_ERR(CAM_OIS, "destroying the device hdl");
		o_ctrl->bridge_intf.device_hdl = -1;
		o_ctrl->bridge_intf.link_hdl = -1;
		o_ctrl->bridge_intf.session_hdl = -1;
		o_ctrl->cam_ois_state = CAM_OIS_INIT;
		break;
	case CAM_STOP_DEV:
		if (o_ctrl->cam_ois_state != CAM_OIS_START) {
			rc = -EINVAL;
			CAM_WARN(CAM_OIS,
			"Not in right state for stop : %d",
			o_ctrl->cam_ois_state);
		}
		o_ctrl->cam_ois_state = CAM_OIS_CONFIG;
		break;
	default:
		CAM_ERR(CAM_OIS, "invalid opcode");
		goto release_mutex;
	}
release_mutex:
	mutex_unlock(&(o_ctrl->ois_mutex));
	return rc;
}
