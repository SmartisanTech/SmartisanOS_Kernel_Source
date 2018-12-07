/************************************************************************
* Copyright (C) 2012-2015, Focaltech Systems (R)£¬All Rights Reserved.
*
* File Name: Test_FT8716.c
*
* Author: Software Development Team, AE
*
* Created: 2015-07-14
*
* Abstract: test item for FT8716
*
************************************************************************/
#ifndef _TEST_FT8716_H
#define _TEST_FT8716_H

#include "focaltech_test_main.h"

int FT8716_StartTest(void);
int FT8716_get_test_data(char *pTestData);//pTestData, External application for memory, buff size >= 1024*80

unsigned char FT8716_TestItem_RawDataTest(bool * bTestResult);
unsigned char FT8716_TestItem_ChannelsTest(bool * bTestResult);
unsigned char FT8716_TestItem_NoiseTest(bool* bTestResult);
unsigned char FT8716_TestItem_CbTest(bool* bTestResult);
unsigned char FT8716_TestItem_EnterFactoryMode(void);

unsigned char FT8716_TestItem_OpenTest(bool* bTestResult);
unsigned char FT8716_TestItem_ShortCircuitTest(bool* bTestResult);



#endif
