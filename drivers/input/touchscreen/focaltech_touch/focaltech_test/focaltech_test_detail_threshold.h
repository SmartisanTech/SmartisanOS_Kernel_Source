/************************************************************************
* Copyright (C) 2012-2015, Focaltech Systems (R)，All Rights Reserved.
*
* File Name: focaltech_test_detail_threshold.h
*
* Author: Software Development Team, AE
*
* Created: 2015-07-14
*
* Abstract: Set Detail Threshold for all IC
*
************************************************************************/

#ifndef _DETAIL_THRESHOLD_H
#define _DETAIL_THRESHOLD_H

#define TX_NUM_MAX			60
#define RX_NUM_MAX			60
#define MAX_PATH			256
//#define BUFFER_LENGTH		80*80*8
#define BUFFER_LENGTH		512
#define MAX_TEST_ITEM		20//100
#define MAX_GRAPH_ITEM       20
#define MAX_CHANNEL_NUM	144

#define FORCETOUCH_ROW 1

struct stCfg_MCap_DetailThreshold
{
#if 1
	unsigned char (*InvalidNode)[RX_NUM_MAX];//无效节点，即不用测试的节点
	unsigned char (*InvalidNode_SC)[RX_NUM_MAX];//无效节点，即不用测试的节点SCAP

	int (*RawDataTest_Min)[RX_NUM_MAX];
	int (*RawDataTest_Max)[RX_NUM_MAX];
	int (*RawDataTest_Low_Min)[RX_NUM_MAX];
	int (*RawDataTest_Low_Max)[RX_NUM_MAX];
	int (*RawDataTest_High_Min)[RX_NUM_MAX];
	int (*RawDataTest_High_Max)[RX_NUM_MAX];
	int (*RxLinearityTest_Max)[RX_NUM_MAX];
	int (*TxLinearityTest_Max)[RX_NUM_MAX];
	int (*SCapRawDataTest_ON_Max)[RX_NUM_MAX];//从这开始都是自容的测试项，互容测试项必须全部放在上面
	int (*SCapRawDataTest_ON_Min)[RX_NUM_MAX];
	int (*SCapRawDataTest_OFF_Max)[RX_NUM_MAX];
	int (*SCapRawDataTest_OFF_Min)[RX_NUM_MAX];
	short (*SCapCbTest_ON_Max)[RX_NUM_MAX];
	short (*SCapCbTest_ON_Min)[RX_NUM_MAX];
	short (*SCapCbTest_OFF_Max)[RX_NUM_MAX];
	short (*SCapCbTest_OFF_Min)[RX_NUM_MAX];
	int (*NoistTest_Coefficient)[RX_NUM_MAX];
	
	int ForceTouch_SCapRawDataTest_ON_Max[FORCETOUCH_ROW][RX_NUM_MAX];//从这开始都是force touch的测试项，互容测试项必须全部放在上面
	int ForceTouch_SCapRawDataTest_ON_Min[FORCETOUCH_ROW][RX_NUM_MAX];
	int ForceTouch_SCapRawDataTest_OFF_Max[FORCETOUCH_ROW][RX_NUM_MAX];
	int ForceTouch_SCapRawDataTest_OFF_Min[FORCETOUCH_ROW][RX_NUM_MAX];
	int ForceTouch_SCapCbTest_ON_Max[FORCETOUCH_ROW][RX_NUM_MAX];
	int ForceTouch_SCapCbTest_ON_Min[FORCETOUCH_ROW][RX_NUM_MAX];
	int ForceTouch_SCapCbTest_OFF_Max[FORCETOUCH_ROW][RX_NUM_MAX];
	int ForceTouch_SCapCbTest_OFF_Min[FORCETOUCH_ROW][RX_NUM_MAX];
#else
	unsigned char InvalidNode[TX_NUM_MAX][RX_NUM_MAX];//无效节点，即不用测试的节点
	unsigned char InvalidNode_SC[TX_NUM_MAX][RX_NUM_MAX];//无效节点，即不用测试的节点SCAP

	int RawDataTest_Min[TX_NUM_MAX][RX_NUM_MAX];
	int RawDataTest_Max[TX_NUM_MAX][RX_NUM_MAX];
	int RawDataTest_Low_Min[TX_NUM_MAX][RX_NUM_MAX];
	int RawDataTest_Low_Max[TX_NUM_MAX][RX_NUM_MAX];
	int RawDataTest_High_Min[TX_NUM_MAX][RX_NUM_MAX];
	int RawDataTest_High_Max[TX_NUM_MAX][RX_NUM_MAX];
	//int RxCrosstalkTest_Max[TX_NUM_MAX][RX_NUM_MAX];
	//int RxCrosstalkTest_Min[TX_NUM_MAX][RX_NUM_MAX];
	//int PanelDifferTest_Max[TX_NUM_MAX][RX_NUM_MAX];
	//int PanelDifferTest_Min[TX_NUM_MAX][RX_NUM_MAX];
	int RxLinearityTest_Max[TX_NUM_MAX][RX_NUM_MAX];
	int TxLinearityTest_Max[TX_NUM_MAX][RX_NUM_MAX];
	//int TxShortTest_Max[TX_NUM_MAX][RX_NUM_MAX];
	//int TxShortTest_Min[TX_NUM_MAX][RX_NUM_MAX];
	//int TxShortAdvance[TX_NUM_MAX][RX_NUM_MAX];

	int SCapRawDataTest_ON_Max[TX_NUM_MAX][RX_NUM_MAX];//从这开始都是自容的测试项，互容测试项必须全部放在上面
	int SCapRawDataTest_ON_Min[TX_NUM_MAX][RX_NUM_MAX];
	int SCapRawDataTest_OFF_Max[TX_NUM_MAX][RX_NUM_MAX];
	int SCapRawDataTest_OFF_Min[TX_NUM_MAX][RX_NUM_MAX];
	short SCapCbTest_ON_Max[TX_NUM_MAX][RX_NUM_MAX];
	short SCapCbTest_ON_Min[TX_NUM_MAX][RX_NUM_MAX];
	short SCapCbTest_OFF_Max[TX_NUM_MAX][RX_NUM_MAX];
	short SCapCbTest_OFF_Min[TX_NUM_MAX][RX_NUM_MAX];
#endif

};

struct stCfg_SCap_DetailThreshold
{
	int TempData[MAX_CHANNEL_NUM];
	int RawDataTest_Max[MAX_CHANNEL_NUM];
	int RawDataTest_Min[MAX_CHANNEL_NUM];
	int CiTest_Max[MAX_CHANNEL_NUM];
	int CiTest_Min[MAX_CHANNEL_NUM];
	int DeltaCiTest_Base[MAX_CHANNEL_NUM];
	int DeltaCiTest_AnotherBase1[MAX_CHANNEL_NUM];
	int DeltaCiTest_AnotherBase2[MAX_CHANNEL_NUM];
	int CiDeviationTest_Base[MAX_CHANNEL_NUM];
	
	int NoiseTest_Max[MAX_CHANNEL_NUM];
	int DeltaCxTest_Sort[MAX_CHANNEL_NUM];         //Sort 对6x06与6x36通用
	int DeltaCxTest_Area[MAX_CHANNEL_NUM];         //Sort 对6x06与6x36通用

	int CbTest_Max[MAX_CHANNEL_NUM];
	int CbTest_Min[MAX_CHANNEL_NUM];
	int DeltaCbTest_Base[MAX_CHANNEL_NUM];
	int DifferTest_Base[MAX_CHANNEL_NUM];
	int CBDeviationTest_Base[MAX_CHANNEL_NUM];
	int K1DifferTest_Base[MAX_CHANNEL_NUM];
};

//struct stCfg_MCap_DetailThreshold g_stCfg_MCap_DetailThreshold;
//struct stCfg_SCap_DetailThreshold g_stCfg_SCap_DetailThreshold;

void OnInit_MCap_DetailThreshold(char *strIniFile);
void OnInit_SCap_DetailThreshold(char *strIniFile);

void OnInit_InvalidNode(char *strIniFile);
void OnGetTestItemParam(char *strItemName, char *strIniFile, int iDefautValue);
void OnInit_DThreshold_RawDataTest(char *strIniFile);
void OnInit_DThreshold_SCapRawDataTest(char *strIniFile);
void OnInit_DThreshold_SCapCbTest(char *strIniFile);

void OnInit_DThreshold_ForceTouch_SCapRawDataTest(char *strIniFile);
void OnInit_DThreshold_ForceTouch_SCapCbTest(char *strIniFile);

void OnInit_DThreshold_RxLinearityTest(char *strIniFile);//For FT5822
void OnInit_DThreshold_TxLinearityTest(char *strIniFile);//For FT5822

void set_max_channel_num(void);
int malloc_struct_DetailThreshold(void);
void free_struct_DetailThreshold(void);
#endif
