/*
 *
 * FocalTech TouchScreen driver.
 * 
 * Copyright (c) 2010-2016, FocalTech Systems, Ltd., all rights reserved.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

 /************************************************************************
*
* File Name: focaltech_test.c
*
* Author:	  Software Department, FocalTech
*
* Created: 2016-03-24
*   
* Modify:
*
* Abstract: create char device and proc node for  the comm between APK and TP
*
************************************************************************/

/*******************************************************************************
* Included header files
*******************************************************************************/
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/debugfs.h>
#include <asm/uaccess.h>

#include <linux/i2c.h>//iic
#include <linux/delay.h>//msleep

#include "../focaltech_common.h"
#include "focaltech_test_main.h"
#include "focaltech_test_ini.h"
#include "focaltech_test_global.h"
#include "../focaltech_core.h"

/*******************************************************************************
* Private constant and macro definitions using #define
*******************************************************************************/
#define FOCALTECH_TEST_INFO  "File Version of  focaltech_test.c:  V1.1.0 2016-05-19"

//配置文件存放目录定义
#define FTS_INI_FILE_PATH "/system/etc/"  

#define FTS_TEST_BUFFER_SIZE		80*1024
#define FTS_TEST_PRINT_SIZE		128
/*******************************************************************************
* Private enumerations, structures and unions using typedef
*******************************************************************************/


/*******************************************************************************
* Static variables
*******************************************************************************/

/*******************************************************************************
* Global variable or extern global variabls/functions
*******************************************************************************/


/*******************************************************************************
* Static function prototypes
*******************************************************************************/
static int fts_test_get_ini_size(char *config_name);
static int fts_test_read_ini_data(char *config_name, char *config_buf);
static int fts_test_save_test_data(char *file_name, char *data_buf, int iLen);
static int fts_test_get_testparam_from_ini(char *config_name);
static int fts_test_entry(char *ini_file_name);

static int fts_test_i2c_read(unsigned char *writebuf, int writelen, unsigned char *readbuf, int readlen);
static int fts_test_i2c_write(unsigned char *writebuf, int writelen);

/*******************************************************************************
* functions body
*******************************************************************************/
#if 1
//	old fts_i2c_read/write function. need to set fts_i2c_client.
extern struct i2c_client* fts_i2c_client;
extern int fts_i2c_read(struct i2c_client *client, char *writebuf,int writelen, char *readbuf, int readlen);
extern int fts_i2c_write(struct i2c_client *client, char *writebuf, int writelen);
#endif
static int fts_test_i2c_read(unsigned char *writebuf, int writelen, unsigned char *readbuf, int readlen)
{
	int iret = -1;
	#if 1
	//	old fts_i2c_read function. need to set fts_i2c_client.
	//修改成此项目用到的i2c_read函数	
	iret = fts_i2c_read(fts_i2c_client, writebuf, writelen, readbuf, readlen);
	#else
	iret = fts_i2c_read(writebuf, writelen, readbuf, readlen);
	#endif

	return iret;

}

static int fts_test_i2c_write(unsigned char *writebuf, int writelen)
{
	int iret = -1;
	#if 1
	//	old fts_i2c_write function.  need to set fts_i2c_client.
	//修改成此项目用到的i2c_write函数	
	iret = fts_i2c_write(fts_i2c_client, writebuf, writelen);
	#else
	iret = fts_i2c_write(writebuf, writelen);
	#endif	
	
	return iret;
}

//获取配置文件大小, 用于分配内存读取配置
static int fts_test_get_ini_size(char *config_name)
{
	struct file *pfile = NULL;
	struct inode *inode = NULL;
	//unsigned long magic;
	off_t fsize = 0;
	char filepath[128];
	memset(filepath, 0, sizeof(filepath));

	sprintf(filepath, "%s%s", FTS_INI_FILE_PATH, config_name);

	if (NULL == pfile)
		pfile = filp_open(filepath, O_RDONLY, 0);

	if (IS_ERR(pfile)) {
		FTS_TEST_DBG("error occured while opening file %s.",  filepath);
		return -EIO;
	}

	inode = pfile->f_path.dentry->d_inode;
	//magic = inode->i_sb->s_magic;
	fsize = inode->i_size;
	filp_close(pfile, NULL);

	return fsize;
}
//读取配置到内存
static int fts_test_read_ini_data(char *config_name, char *config_buf)
{
	struct file *pfile = NULL;
	struct inode *inode = NULL;
	//unsigned long magic;
	off_t fsize = 0;
	char filepath[128];
	loff_t pos = 0;
	mm_segment_t old_fs;

	memset(filepath, 0, sizeof(filepath));
	sprintf(filepath, "%s%s", FTS_INI_FILE_PATH, config_name);
	if (NULL == pfile)
		pfile = filp_open(filepath, O_RDONLY, 0);
	if (IS_ERR(pfile)) {
		FTS_TEST_DBG("error occured while opening file %s.",  filepath);
		return -EIO;
	}

	inode = pfile->f_path.dentry->d_inode;
	//magic = inode->i_sb->s_magic;
	fsize = inode->i_size;
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	pos = 0;
	vfs_read(pfile, config_buf, fsize, &pos);
	filp_close(pfile, NULL);
	set_fs(old_fs);

	return 0;
}
//保存测试数据到SD卡 etc.
static int fts_test_save_test_data(char *file_name, char *data_buf, int iLen)
{
	struct file *pfile = NULL;
	
	char filepath[128];
	loff_t pos;
	mm_segment_t old_fs;

	memset(filepath, 0, sizeof(filepath));
	sprintf(filepath, "%s%s", FTS_INI_FILE_PATH, file_name);
	if (NULL == pfile)
		pfile = filp_open(filepath, O_CREAT|O_RDWR, 0);
	if (IS_ERR(pfile)) {
		FTS_TEST_DBG("error occured while opening file %s.",  filepath);
		return -EIO;
	}

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	pos = 0;
	vfs_write(pfile, data_buf, iLen, &pos);
	filp_close(pfile, NULL);
	set_fs(old_fs);

	return 0;
}

//读取,解析配置文件,初始化测试变量
static int fts_test_get_testparam_from_ini(char *config_name)
{
	char *pcfiledata = NULL;
	int ret = 0;

	int inisize = fts_test_get_ini_size(config_name);

	FTS_TEST_DBG("ini_size = %d ", inisize);
	if (inisize <= 0) {
		FTS_TEST_DBG("%s ERROR:Get firmware size failed",  __func__);
		return -EIO;
	}

	pcfiledata = fts_malloc(inisize + 1);
	if(NULL == pcfiledata)
	{	
		FTS_TEST_DBG("fts_malloc failed in function:%s",  __func__);
		return -1;
	}

	memset(pcfiledata, 0, inisize + 1);
		
	if (fts_test_read_ini_data(config_name, pcfiledata)) {
		FTS_TEST_DBG(" - ERROR: fts_test_read_ini_data failed" );
		fts_free(pcfiledata);
		pcfiledata = NULL;

		return -EIO;
	} else {
		FTS_TEST_DBG("fts_test_read_ini_data successful");
	}

	ret = set_param_data(pcfiledata);

	fts_free(pcfiledata);	// lifengshi add. 20160608
	pcfiledata = NULL;
	
	if(ret < 0)
		return ret;
	
	return 0;
}

/////////////////////////////////
//测试库调用总入口
///////////////////////////////////
static int fts_test_entry(char *ini_file_name)
{
	/* place holder for future use */
    	char cfgname[128];
	char *testdata = NULL;
	char *printdata = NULL;
	int iTestDataLen=0;//库中测试数据实际长度,用于保存到文件
	int ret = 0;
	int icycle = 0, i =0;
	int print_index = 0;
	int testResult = 0x0;
	

	FTS_TEST_DBG("");
	FTS_TEST_DBG("ini_file_name:%s.", ini_file_name);
	/*用于获取存放在库中的测试数据,注意分配空间大小.*/
	FTS_TEST_DBG("Allocate memory, size: %d", FTS_TEST_BUFFER_SIZE);
	testdata = fts_malloc(FTS_TEST_BUFFER_SIZE);
	if(NULL == testdata)
	{
		FTS_TEST_DBG("fts_malloc failed in function:%s",  __func__);
		return -1;
	}
	printdata = fts_malloc(FTS_TEST_PRINT_SIZE);
	if(NULL == printdata)
	{
		FTS_TEST_DBG("fts_malloc failed in function:%s",  __func__);
		return -1;
	}
	/*初始化平台相关的I2C读写函数*/

	#if 0
	init_i2c_write_func(fts_i2c_write);
	init_i2c_read_func(fts_i2c_read);
	#else
	init_i2c_write_func(fts_test_i2c_write);
	init_i2c_read_func(fts_test_i2c_read);
	#endif

	/*初始化指针内存*/
	ret = focaltech_test_main_init();
	if(ret < 0)
	{
		FTS_TEST_DBG("focaltech_test_main_init() error.");
		goto TEST_ERR;
	}		

	/*读取解析配置文件*/
	memset(cfgname, 0, sizeof(cfgname));
	sprintf(cfgname, "%s", ini_file_name);
	FTS_TEST_DBG("ini_file_name = %s", cfgname);
	if(fts_test_get_testparam_from_ini(cfgname) <0)
	{
		FTS_TEST_DBG("get testparam from ini failure");
		goto TEST_ERR;
	}

	/*根据测试配置开始测试*/
	testResult = start_test_tp();
	if(testResult == 0x111111)
		FTS_TEST_DBG("tp test pass");
	else
		FTS_TEST_DBG("tp test failure");
		
	/*获取测试库中的测试数，并保存*/
	iTestDataLen = get_test_data(testdata);
	//FTS_TEST_DBG("\n%s", testdata);

	icycle = 0;
	/*打印触摸数据包 */
	FTS_TEST_DBG("print test data: \n");
	for(i = 0; i < iTestDataLen; i++)
	{
		if(('\0' == testdata[i])//遇到结束符
			||(icycle == FTS_TEST_PRINT_SIZE -2)//满足打印字符串长度要求
			||(i == iTestDataLen-1)//已是最后一个字符
		)
		{
			if(icycle == 0)
			{
				print_index++;
			}	
			else
			{
				memcpy(printdata, testdata + print_index, icycle);
				printdata[FTS_TEST_PRINT_SIZE-1] = '\0';
				printk("%s", printdata);
				print_index += icycle;
				icycle = 0;
			}
		}
		else
		{
			icycle++;
		}
	}
	printk("\n");		

	fts_test_save_test_data("testdata.csv", testdata, iTestDataLen);


	/*释放内存等... */
	focaltech_test_main_exit();
	
		
	//mutex_unlock(&g_device_mutex);
	if(NULL != testdata) fts_free(testdata);
	if(NULL != printdata) fts_free(printdata);	
	return testResult;
	
TEST_ERR:
	if(NULL != testdata) fts_free(testdata);
	if(NULL != printdata) fts_free(printdata);	
	return -1;
}

/////////////////////////////////
//测试库调用总入口
/************************************************************************
* Name: fts_test_entry_show
* Brief:  no
* Input: 
* Output: 
* Return: 
***********************************************************************/
///////////////////////////////////
static int fts_test_entry_show(char *ini_file_name, char *bufdest, ssize_t* pinumread)
{
	/* place holder for future use */
    	char cfgname[128] = {0};
	char *testdata = NULL;
	char *printdata = NULL;
	int iTestDataLen=0;//库中测试数据实际长度,用于保存到文件
	int ret = 0;
	int icycle = 0, i =0;
	int print_index = 0;
	int testResult = 0x0;
	
	FTS_TEST_DBG("");
	FTS_TEST_DBG("ini_file_name:%s.", ini_file_name);

	/*用于获取存放在库中的测试数据,注意分配空间大小.*/
	FTS_TEST_DBG("Allocate memory, size: %d", FTS_TEST_BUFFER_SIZE);
	testdata = fts_malloc(FTS_TEST_BUFFER_SIZE);
	if(NULL == testdata)
	{
		FTS_TEST_DBG("fts_malloc failed in function:%s",  __func__);
		return -1;
	}
	printdata = fts_malloc(FTS_TEST_PRINT_SIZE);
	if(NULL == printdata)
	{
		FTS_TEST_DBG("fts_malloc failed in function:%s",  __func__);
		return -1;
	}
	/*初始化平台相关的I2C读写函数*/
/*
	init_i2c_write_func(fts_i2c_write);
	init_i2c_read_func(fts_i2c_read);
*/
	init_i2c_write_func(fts_test_i2c_write);
	init_i2c_read_func(fts_test_i2c_read);

	/*初始化指针内存*/
	ret = focaltech_test_main_init();
	if(ret < 0)
	{
		FTS_TEST_DBG("focaltech_test_main_init() error.");
		goto TEST_ERR;
	}		

	/*读取解析配置文件*/
	memset(cfgname, 0, sizeof(cfgname));
	sprintf(cfgname, "%s", ini_file_name);
	FTS_TEST_DBG("ini_file_name = %s", cfgname);
	if(fts_test_get_testparam_from_ini(cfgname) <0)
	{
		FTS_TEST_DBG("get testparam from ini failure");
		goto TEST_ERR;
	}

	/*根据测试配置开始测试*/
	testResult = start_test_tp();
	if(testResult == 0x111111)
		FTS_TEST_DBG("tp test pass");
	else
		FTS_TEST_DBG("tp test failure");
		
	/*获取测试库中的测试数，并保存*/
	iTestDataLen = get_test_data(testdata);
	//FTS_TEST_DBG("\n%s", testdata);
	FTS_TEST_DBG(" iTestDataLen:%d", iTestDataLen);

	if(iTestDataLen < PAGE_SIZE)
		*pinumread = (ssize_t)iTestDataLen;
	else
		*pinumread = PAGE_SIZE-1;	//	if = PAGE_SIZE. then  will report "ill_read_buffer: dev_attr_show+0x0/0x4c returned bad count"

	memcpy(bufdest, testdata, (int)(*pinumread));	

	icycle = 0;
	/*打印触摸数据包 */
	FTS_TEST_DBG("print test data: \n");
	for(i = 0; i < iTestDataLen; i++)
	{
		if(('\0' == testdata[i])//遇到结束符
			||(icycle == FTS_TEST_PRINT_SIZE -2)//满足打印字符串长度要求
			||(i == iTestDataLen-1)//已是最后一个字符
		)
		{
			if(icycle == 0)
			{
				print_index++;
			}	
			else
			{
				memcpy(printdata, testdata + print_index, icycle);
				printdata[FTS_TEST_PRINT_SIZE-1] = '\0';
				printk("%s", printdata);
				print_index += icycle;
				icycle = 0;
			}
		}
		else
		{
			icycle++;
		}
	}
	printk("\n");		

	fts_test_save_test_data("testdata.csv", testdata, iTestDataLen);

	/*释放内存等... */
	focaltech_test_main_exit();
		
	//mutex_unlock(&g_device_mutex);
	if(NULL != testdata) fts_free(testdata);testdata = NULL;
	if(NULL != printdata) fts_free(printdata);
	return testResult;
	
TEST_ERR:
	if(NULL != testdata) fts_free(testdata);
	if(NULL != printdata) fts_free(printdata);	
	return -1;
}

/************************************************************************
* Name: fts_test_show
* Brief:  no
* Input: device, device attribute, char buf
* Output: no
* Return: EPERM
***********************************************************************/
static ssize_t fts_test_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	ssize_t num_read_chars = 0;

	int nret = -1;
	struct i2c_client *client = fts_i2c_client;

	mutex_lock(&fts_input_dev->mutex);
	disable_irq(client->irq);

	nret = fts_test_entry_show( "test.ini", buf, &num_read_chars);
	if(-1 != nret)
	{
		num_read_chars = scnprintf(buf, PAGE_SIZE, "%d\n", nret);
	}
	
	enable_irq(client->irq);
	mutex_unlock(&fts_input_dev->mutex);

	return num_read_chars;
}

/************************************************************************
* Name: fts_test_store
* Brief:  upgrade from app.bin
* Input: device, device attribute, char buf, char count
* Output: no
* Return: char count
***********************************************************************/
static ssize_t fts_test_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	char fwname[128] = {0};
	struct i2c_client *client = fts_i2c_client;
	memset(fwname, 0, sizeof(fwname));
	sprintf(fwname, "%s", buf);
	fwname[count-1] = '\0';
	FTS_TEST_DBG("fwname:%s.", fwname);

	mutex_lock(&fts_wq_data->wlock);
	
	disable_irq(client->irq);
	fts_test_entry( fwname);
	enable_irq(client->irq);
	
	mutex_unlock(&fts_wq_data->wlock);

	return count;
}
/*  upgrade from app.bin
*    example:echo "***.ini" > fts_test
*/
static DEVICE_ATTR(fts_test, S_IRUGO|S_IWUSR, fts_test_show, fts_test_store);

/* add your attr in here*/
static struct attribute *fts_test_attributes[] = {
	&dev_attr_fts_test.attr,
	NULL
};

static struct attribute_group fts_test_attribute_group = {
	.attrs = fts_test_attributes
};


int fts_test_init(struct i2c_client *client)
{
	int err=0;
	
	FTS_TEST_DBG("[focal] %s ",  FOCALTECH_TEST_INFO);	//show version
	FTS_TEST_DBG("");//default print: current function name and line number
	
	err = sysfs_create_group(&client->dev.kobj, &fts_test_attribute_group);
	if (0 != err) 
	{
		FTS_TEST_DBG( "[focal] %s() - ERROR: sysfs_create_group() failed.",  __func__);
		sysfs_remove_group(&client->dev.kobj, &fts_test_attribute_group);
		return -EIO;
	} 
	else 
	{
		FTS_TEST_DBG("[focal] %s() - sysfs_create_group() succeeded.", __func__);
	}
	//fts_protocol_windows_to_android(client);
	return err;
}
EXPORT_SYMBOL(fts_test_init);
int fts_test_exit(struct i2c_client *client)
{	
	FTS_TEST_DBG("");//default print: current function name and line number
	sysfs_remove_group(&client->dev.kobj, &fts_test_attribute_group);
	
	return 0;
}
EXPORT_SYMBOL(fts_test_exit);

