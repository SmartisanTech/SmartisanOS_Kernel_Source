/************************************************************************
* Copyright (C) 2012-2015, Focaltech Systems (R)，All Rights Reserved.
*
* File Name: Global.c
*
* Author: Software Development Team, AE
*
* Created: 2015-07-14
*
* Abstract: global function for test
*
************************************************************************/
#ifndef _GLOBAL_H
#define _GLOBAL_H

#include <linux/kernel.h>
#include "focaltech_test_detail_threshold.h"
#include "../focaltech_global/focaltech_global.h"

#define MIN_HOLE_LEVEL   (-1)
#define MAX_HOLE_LEVEL   0x7F
/*-----------------------------------------------------------
Error Code for Comm
-----------------------------------------------------------*/
#define ERROR_CODE_OK								0x00
#define ERROR_CODE_CHECKSUM_ERROR				0x01
#define ERROR_CODE_INVALID_COMMAND				0x02
#define ERROR_CODE_INVALID_PARAM					0x03
#define ERROR_CODE_IIC_WRITE_ERROR				0x04
#define ERROR_CODE_IIC_READ_ERROR					0x05
#define ERROR_CODE_WRITE_USB_ERROR				0x06
#define ERROR_CODE_WAIT_RESPONSE_TIMEOUT		0x07
#define ERROR_CODE_PACKET_RE_ERROR				0x08
#define ERROR_CODE_NO_DEVICE						0x09
#define ERROR_CODE_WAIT_WRITE_TIMEOUT			0x0a
#define ERROR_CODE_READ_USB_ERROR				0x0b
#define ERROR_CODE_COMM_ERROR					0x0c
#define ERROR_CODE_ALLOCATE_BUFFER_ERROR		0x0d
#define ERROR_CODE_DEVICE_OPENED					0x0e
#define ERROR_CODE_DEVICE_CLOSED					0x0f

/*-----------------------------------------------------------
Test Status
-----------------------------------------------------------*/
#define		RESULT_NULL			0
#define		RESULT_PASS			1
#define		RESULT_NG		    		2
#define		RESULT_TESTING		3
#define		RESULT_TBD				4
#define		RESULT_REPLACE		5
#define		RESULT_CONNECTING		6

/*-----------------------------------------------------------
read write max bytes per time
-----------------------------------------------------------*/
#define BYTES_PER_TIME		128

struct StruScreenSeting 
{
	int iSelectedIC;//当前选择的IC
	int iTxNum;
	int iRxNum;
	int isNormalize;
	int iUsedMaxTxNum;//iTxNum <= iUsedMaxTxNum
	int iUsedMaxRxNum;//iRxNum <= iUsedMaxRxNum

	unsigned char iChannelsNum;//add for ft6x36
	unsigned char iKeyNum;

};

struct stTestItem
{
	unsigned char ItemType;//对测试项进行分类	CfgItem, DataTestItem, GraphTestItem,
	unsigned char TestNum;//测试时的序号
	unsigned char TestResult;//测试结果,NG\PASS\TESTING
	unsigned char ItemCode;//测试项目名代号
	//CString strItemName;//测试项名
	//CString strRemark;//注释
};

struct structSCapConfEx 
{
	unsigned char ChannelXNum;
	unsigned char ChannelYNum;
	unsigned char KeyNum;
	unsigned char KeyNumTotal;
	bool bLeftKey1;
	bool bLeftKey2;
	bool bLeftKey3;
	bool bRightKey1;
	bool bRightKey2;
	bool bRightKey3;	
};


enum NORMALIZE_Type
{
	Overall_Normalize = 0,
	Auto_Normalize = 1,
};

enum PROOF_TYPE
{
	Proof_Normal,            //模式0
	Proof_Level0,            //模式1
	Proof_NoWaterProof,      //模式2
};

extern struct stCfg_MCap_DetailThreshold g_stCfg_MCap_DetailThreshold;
extern struct stCfg_SCap_DetailThreshold g_stCfg_SCap_DetailThreshold;
//extern struct structSCapConf g_stSCapConf;
extern struct StruScreenSeting g_ScreenSetParam; //屏幕设置参数
extern struct stTestItem g_stTestItem[1][MAX_TEST_ITEM];
extern struct structSCapConfEx g_stSCapConfEx;

extern int g_TestItemNum;/*test item num*/
extern char g_strIcName[20];/*IC Name*/
extern char *g_pStoreAllData;

int GetPrivateProfileString(char *section, char *ItemName, char *defaultvalue, char *returnValue, char *IniFile);
void focal_msleep(int ms);
void SysDelay(int ms);
int focal_abs(int value);


void OnInit_InterfaceCfg(char * strIniFile);

int ReadReg(unsigned char RegAddr, unsigned char *RegData);
int WriteReg(unsigned char RegAddr, unsigned char RegData);
unsigned char Comm_Base_IIC_IO(unsigned char *pWriteBuffer, int  iBytesToWrite, unsigned char *pReadBuffer, int iBytesToRead);

unsigned char EnterWork(void);
unsigned char EnterFactory(void);

void fts_SetTestItemCodeName(unsigned char ucitemcode);

extern void *fts_malloc(size_t size);
extern void fts_free(void *p);

#define FOCAL_TEST_DEBUG_EN 	1

#if (FOCAL_TEST_DEBUG_EN)
#define FTS_TEST_DBG(fmt, args...) do {printk("[FTS] %s. line: %d.  "fmt"\n",  __FUNCTION__, __LINE__, ##args);} while (0)
#define FTS_TEST_PRINT(fmt, args...) printk("" fmt, ## args)
#else
#define FTS_TEST_DBG(fmt, args...) do{}while(0)
#define FTS_TEST_PRINT(fmt, args...) do{}while(0)
#endif


#endif
