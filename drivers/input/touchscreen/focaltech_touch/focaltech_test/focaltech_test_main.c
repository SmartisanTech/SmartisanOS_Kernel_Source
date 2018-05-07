/************************************************************************
* Copyright (C) 2012-2016, Focaltech Systems (R)，All Rights Reserved.
*
* File Name: focaltech_test_main.c
*
* Author: Software Development Team, AE
*
* Created: 2015-07-14
*
* Abstract: test entry for all IC
*
************************************************************************/
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/slab.h>

#include "../focaltech_core.h"
//#include "../focaltech_common.h"

#include "focaltech_test_main.h"
#include "focaltech_test_global.h"

#if 0

#include "focaltech_test_config_ft5x46.h"
#include "focaltech_test_ft5x46.h"

#include "focaltech_test_config_ft8606.h"
#include "focaltech_test_ft8606.h"

#include "focaltech_test_config_ft5822.h"
#include "focaltech_test_ft5822.h"

#include "focaltech_test_config_ft6x36.h"
#include "focaltech_test_ft6x36.h"

#include "focaltech_test_config_ft3c47.h"
#include "focaltech_test_ft3c47.h"

#include "focaltech_test_config_ft8716.h"
#include "focaltech_test_ft8716.h"

#include "focaltech_test_config_ft8736.h"
#include "focaltech_test_ft8736.h"

#include "focaltech_test_config_ft8607.h"
#include "focaltech_test_ft8607.h"

#include "focaltech_test_config_ftE716.h"
#include "focaltech_test_ftE716.h"

#include "focaltech_test_config_ftE736.h"
#include "focaltech_test_ftE736.h"

#endif

#include "focaltech_test_config_ft8716.h"
#include "focaltech_test_ft8716.h"



#include "focaltech_test_ini.h"
#include "../focaltech_common.h"

#define FTS_DRIVER_LIB_INFO  "Test_Lib_Version   V1.6.1 2016-05-19"

#define FTS_TEST_STORE_DATA_SIZE		80*1024

FTS_I2C_READ_FUNCTION fts_i2c_read_test;
FTS_I2C_WRITE_FUNCTION fts_i2c_write_test;

char *g_testparamstring = NULL;

/////////////////////IIC communication
int init_i2c_read_func(FTS_I2C_READ_FUNCTION fpI2C_Read)
{
	unsigned char value = 0;
	unsigned char recode = 0;

	FTS_TEST_DBG("");
	
	fts_i2c_read_test = fpI2C_Read;
	if(NULL == fts_i2c_read_test)
	{
		FTS_TEST_DBG("[focal] %s fts_i2c_read_test == NULL ",  __func__);
	}
	
	//debug start
	recode = ReadReg(0xa6, &value);
	if(recode != ERROR_CODE_OK)
	{
		FTS_TEST_DBG("[focal] ReadReg Error, code: %d ",  recode);	
	}
	else
	{
		FTS_TEST_DBG("[focal] ReadReg successed, Addr: 0xa6, value: 0x%02x ",  value);	
	}		
	//debug end
	
	return 0;
}

int init_i2c_write_func(FTS_I2C_WRITE_FUNCTION fpI2C_Write)
{
	FTS_TEST_DBG("");
	
	fts_i2c_write_test = fpI2C_Write;
	if(NULL == fts_i2c_write_test)
	{
		FTS_TEST_DBG("[focal] fts_i2c_read_test == NULL ");
	}	
	return 0;
}

/************************************************************************
* Name: set_param_data
* Brief:  load Config. Set IC series, init test items, init basic threshold, int detailThreshold, and set order of test items
* Input: TestParamData, from ini file.
* Output: none
* Return: 0. No sense, just according to the old format.
***********************************************************************/
int set_param_data(char * TestParamData)
{
	int ret = 0;
	
	FTS_TEST_DBG("Enter  set_param_data.");
	g_testparamstring = TestParamData;//get param of ini file
	ret = ini_get_key_data(g_testparamstring);//get param to struct
	if(ret < 0)
	{
		FTS_TEST_DBG("ini_get_key_data error.");
		return ret;
	}
	
	//从配置读取所选芯片类?
	//Set g_ScreenSetParam.iSelectedIC
	OnInit_InterfaceCfg(g_testparamstring);

	/*Get IC Name*/
	fts_ic_table_get_ic_name_from_ic_code(g_ScreenSetParam.iSelectedIC, g_strIcName);

	//测试项配置
	#if 0
	if(IC_FT5X46>>4 == g_ScreenSetParam.iSelectedIC>>4)
	{
		OnInit_FT5X22_TestItem(g_testparamstring);
		OnInit_FT5X22_BasicThreshold(g_testparamstring);
		OnInit_MCap_DetailThreshold(g_testparamstring);//测试项详细配置 
		SetTestItem_FT5X22();
	}
	else if(IC_FT8606>>4 == g_ScreenSetParam.iSelectedIC>>4)
	{
		OnInit_FT8606_TestItem(g_testparamstring);
		OnInit_FT8606_BasicThreshold(g_testparamstring);
		OnInit_MCap_DetailThreshold(g_testparamstring);
		SetTestItem_FT8606();
	}
	else if(IC_FT5822>>4 == g_ScreenSetParam.iSelectedIC>>4)
	{
		OnInit_FT5822_TestItem(g_testparamstring);
		OnInit_FT5822_BasicThreshold(g_testparamstring);
		OnInit_MCap_DetailThreshold(g_testparamstring);
		SetTestItem_FT5822();
	}
	else if(IC_FT6X36>>4 == g_ScreenSetParam.iSelectedIC>>4)
	{
		OnInit_FT6X36_TestItem(g_testparamstring);
		OnInit_FT6X36_BasicThreshold(g_testparamstring);
		OnInit_SCap_DetailThreshold(g_testparamstring);
		SetTestItem_FT6X36();
	}
	else if(IC_FT3C47U>>4 == g_ScreenSetParam.iSelectedIC>>4)
	{
		OnInit_FT3C47_TestItem(g_testparamstring);
		OnInit_FT3C47_BasicThreshold(g_testparamstring);
		OnInit_MCap_DetailThreshold(g_testparamstring);//测试项详细配置 
		SetTestItem_FT3C47();
	}
	else if(IC_FT8716>>4 == g_ScreenSetParam.iSelectedIC>>4)
	{
		OnInit_FT8716_TestItem(g_testparamstring);
		OnInit_FT8716_BasicThreshold(g_testparamstring);
		OnInit_MCap_DetailThreshold(g_testparamstring);
		SetTestItem_FT8716();
	}
	else if(IC_FT8736>>4 == g_ScreenSetParam.iSelectedIC>>4)
	{
		OnInit_FT8736_TestItem(g_testparamstring);
		OnInit_FT8736_BasicThreshold(g_testparamstring);
		OnInit_MCap_DetailThreshold(g_testparamstring);
		SetTestItem_FT8736();
	}	
	else if(IC_FT8607>>4 == g_ScreenSetParam.iSelectedIC>>4)
	{
		OnInit_FT8607_TestItem(g_testparamstring);
		OnInit_FT8607_BasicThreshold(g_testparamstring);
		OnInit_MCap_DetailThreshold(g_testparamstring);
		SetTestItem_FT8607();
	}
	else if(IC_FTE716>>4 == g_ScreenSetParam.iSelectedIC>>4)
	{
		OnInit_FTE716_TestItem(g_testparamstring);
		OnInit_FTE716_BasicThreshold(g_testparamstring);
		OnInit_MCap_DetailThreshold(g_testparamstring);
		SetTestItem_FTE716();
	}
	else if(IC_FTE736>>4 == g_ScreenSetParam.iSelectedIC>>4)
	{
		OnInit_FTE736_TestItem(g_testparamstring);
		OnInit_FTE736_BasicThreshold(g_testparamstring);
		OnInit_MCap_DetailThreshold(g_testparamstring);
		SetTestItem_FTE736();
	}	
	#endif

	if(IC_FT8716>>4 == g_ScreenSetParam.iSelectedIC>>4)
	{
		OnInit_FT8716_TestItem(g_testparamstring);
		OnInit_FT8716_BasicThreshold(g_testparamstring);
		OnInit_MCap_DetailThreshold(g_testparamstring);
		SetTestItem_FT8716();
	}
	
	
	/*gettimeofday(&time_end, NULL);//End time
	time_use = (time_end.tv_sec - time_start.tv_sec)*1000 + (time_end.tv_usec - time_start.tv_usec)/1000;
	FTS_TEST_DBG("Load Config, use time = %d ms ",  time_use);
	*/
	
	FTS_TEST_DBG("end of set_param_data.");
	return 0;
}

/************************************************************************
* Name: start_test_tp
* Brief:  Test entry. Select test items based on IC series
* Input: none
* Output: none
* Return: Test Result, PASS or FAIL
***********************************************************************/

int start_test_tp(void) 
{
	int bTestResult = 0x0;
	
	FTS_TEST_DBG("[focal] %s start ",  __func__);
	FTS_TEST_DBG("IC_%s Test",  g_strIcName);

	#if 0
	switch(g_ScreenSetParam.iSelectedIC>>4)
		{
		case IC_FT5X46>>4:
		//	#if FTS_AUTO_RESET_EN
			fts_auto_reset_suspend();
			fts_auto_reset_record_time();
		//	#endif
			
			bTestResult = FT5X46_StartTest();

		//	#if FTS_AUTO_RESET_EN
			fts_auto_reset_resume();
		//	#endif
			break;			
		case IC_FT8606>>4:
			bTestResult = FT8606_StartTest();
			break;	
		case IC_FT5822>>4:
			bTestResult = FT5822_StartTest();
			break;	
		case IC_FT6X36>>4:
			bTestResult = FT6X36_StartTest();
			break;
		case IC_FT3C47U>>4:
			bTestResult = FT3C47_StartTest();
			break;
		case IC_FT8716>>4:
		//	#if FTS_AUTO_RESET_EN
			fts_auto_reset_suspend();
			fts_auto_reset_record_time();
		//	#endif

			bTestResult = FT8716_StartTest();

		//	#if FTS_AUTO_RESET_EN
			fts_auto_reset_resume();
		//	#endif
			break;
		case IC_FT8736>>4:
			bTestResult = FT8736_StartTest();
			break;	
		case IC_FT8607>>4:
			bTestResult = FT8607_StartTest();
			break;
		case IC_FTE716>>4:
			bTestResult = FTE716_StartTest();
			break;
		case IC_FTE736>>4:
			bTestResult = FTE736_StartTest();
			break;
		default:
			FTS_TEST_DBG("[focal]  Error IC, IC Name: %s, IC Code:  %d",  g_strIcName, g_ScreenSetParam.iSelectedIC);
			break;
		}
	#endif
	switch(g_ScreenSetParam.iSelectedIC>>4)
	{
		case IC_FT8716>>4:
			
			bTestResult = FT8716_StartTest();
			break;
		
	}
	EnterWork();

	return bTestResult;
}
/************************************************************************
* Name: get_test_data
* Brief:  Get test data based on IC series
* Input: none
* Output: pTestData, External application for memory, buff size >= 1024*8
* Return: the length of test data. if length > 0, got data;else ERR.
***********************************************************************/
int get_test_data(char *pTestData)
{
	int iLen = 0;
	FTS_TEST_DBG("[focal] %s start ",  __func__);
	#if 0
	switch(g_ScreenSetParam.iSelectedIC>>4)
		{
		case IC_FT5X46>>4:
			iLen = FT5X46_get_test_data(pTestData);
			break;	
		
		case IC_FT8606>>4:
			iLen = FT8606_get_test_data(pTestData);
			break;	
		case IC_FT5822>>4:
			iLen = FT5822_get_test_data(pTestData);
			break;
		case IC_FT6X36>>4:
			iLen = FT6X36_get_test_data(pTestData);
			break;
		case IC_FT3C47U>>4:
			iLen = FT3C47_get_test_data(pTestData);
			break;
		case IC_FT8716>>4:
			iLen = FT8716_get_test_data(pTestData);
			break;	
		case IC_FT8736>>4:
			iLen = FT8736_get_test_data(pTestData);
			break;
		case IC_FT8607>>4:
			iLen = FT8607_get_test_data(pTestData);
			break;
		case IC_FTE716>>4:
			iLen = FTE716_get_test_data(pTestData);
			break;	
		case IC_FTE736>>4:
			iLen = FTE736_get_test_data(pTestData);
			break;
		default:
			FTS_TEST_DBG("[focal]  Error IC, IC Name: %s, IC Code:  %d",  g_strIcName, g_ScreenSetParam.iSelectedIC);
			break;
		}
	#endif
	switch(g_ScreenSetParam.iSelectedIC>>4)
	{
		case IC_FT8716>>4:
			iLen = FT8716_get_test_data(pTestData);
			break;

	}
	
	return iLen;	
}

int focaltech_test_main_init(void)
{
	int ret = 0;
	
	FTS_TEST_DBG("[focal] %s ",  FTS_DRIVER_LIB_INFO);	//show lib version
	
	/*申请内存，存储测试结果*/
	g_pStoreAllData = NULL;	
	if(NULL == g_pStoreAllData)
		g_pStoreAllData = fts_malloc(FTS_TEST_STORE_DATA_SIZE);
	if(NULL == g_pStoreAllData)
		return -1;
	
	/*申请内存，分配给详细阈值的结构体*/
	ret = malloc_struct_DetailThreshold();
	if(ret < 0)
		return ret;

	return 0;
}
/************************************************************************
* Name: free_test_param_data
* Brief:  release printer memory
* Input: none
* Output: none
* Return: none. 
***********************************************************************/
int focaltech_test_main_exit(void)
{

	FTS_TEST_DBG("[focal] release memory -start.");
	
	// it has been freed in fts_test_get_testparam_from_ini(). lifengshi.
	/*释放配置参数文件内容*/
/*	if(NULL != g_testparamstring)
	{
		FTS_TEST_DBG("[FTS] release memory g_testparamstring.");
		fts_free(g_testparamstring);
		g_testparamstring = NULL;
	}
*/
	/*释放存储测试结果的内存*/
	if(NULL != g_pStoreAllData)
	{
		FTS_TEST_DBG("[FTS] release memory g_pStoreAllData.");
		fts_free(g_pStoreAllData);
		g_pStoreAllData = NULL;
	}
	
	/*释放详细阈值结构体的内存*/
	FTS_TEST_DBG("[FTS] release memory  free_struct_DetailThreshold.");
	free_struct_DetailThreshold();	

	/*释放详细阈值结构体的内存*/
	release_key_data();//release memory of key data for ini file
	FTS_TEST_DBG("[focal] release memory -end.");
	return 0;
}

