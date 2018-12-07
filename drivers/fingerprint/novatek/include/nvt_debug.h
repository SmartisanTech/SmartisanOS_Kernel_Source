/**
    Novatek's debug macro.

    Novatek's debug macro for fingerprint solution.

    @file       nvt_debug.h
    @ingroup
    @note       Nothing.

    Copyright   Novatek Microelectronics Corp. 2015.  All rights reserved.
*/

#include "nvt_debugdef.h"

#ifndef _NVT_DEBUG_H
#define _NVT_DEBUG_H

#ifndef __NVT_DBG_LVL__     // Select one of the following (in "nvt_debugdef.h")
//#define __NVT_DBG_LVL__         __NVT_DBG_LVL_DIS__         // Disable all output
#define __NVT_DBG_LVL__         __NVT_DBG_LVL_DBG__         // Output "ERROR" and "DEBUG" message
//#define __NVT_DBG_LVL__         __NVT_DBG_LVL_ERR__         // Only output "ERROR" message
#endif

/******************** Usage *********************

#include "nvt_debugdef.h"
#define __NVT_DBG_LVL__     __NVT_DBG_LVL_XXX__
#include "nvt_debug.h"

#include <xxx.h>
#include "yyy.h"

...

NVT_DBG_ERR()       -> Output error message.
NVT_DBG_DBG()       -> Output debug message.
NVT_DBG_MSG()       -> Output message (what you see is what you type), can't be disabled.
NVT_DBG_MARK()      -> Output function name and line number
NVT_DBG_PRINTD(v)   -> Output "VariableName = VariableValue (Decimal)"
NVT_DBG_PRINTX(v)   -> Output "VariableName = VariableValue (Hex)"
NVT_DBG_PRINTS(v)   -> Output "VariableNmae = VariableValue (String)"

*************************************************/

#include "nvt_type.h"

// Platform dependent header file
#if defined(_WIN32)

    #include <stdio.h>

#elif defined(__KERNEL__)
// Linux

    #include <linux/kernel.h>

#elif defined(__FPR_ENG_USERSPACE__)

    #include <cutils/log.h>

#else

/*
// TEE ... (TBD)
#else

    #include <?.h>

*/

#endif

/**
    @addtogroup
*/
//@{

// The following marco can't be disabled
// 1. NVT_DBG_MSG()

#if defined(_WIN32)
// Windows

    #define NVT_DBG_MSG(...)                    printf(__VA_ARGS__)

  #if defined(__CODEGEARC__)
    // CodeGear C++ Builder 2009
    #define NVT_DBG_DUMMY                       do{}while(0)
  #else
    // Microsoft Visual Studio
    #define NVT_DBG_DUMMY                                                       \
                                                __pragma(warning(push))         \
                                                __pragma(warning(disable:4127)) \
                                                do{}while(0)                    \
                                                __pragma(warning(pop))
  #endif

#elif defined(__KERNEL__)
// Linux kernel space

    #define NVT_DBG_MSG(...)                    printk(KERN_ERR __VA_ARGS__)
    #define NVT_DBG_DUMMY                       do{}while(0)

#elif defined(__FPR_ENG_USERSPACE__)
// Linux user space

    #define NVT_DBG_MSG(...)                    ALOGE(__VA_ARGS__)
    #define NVT_DBG_DUMMY                       do{}while(0)

#else

/*
// TEE ... (TBD)
#else

    #define NVT_DBG_MSG(...)

*/

#endif // Platform

#if (__NVT_DBG_LVL__ == __NVT_DBG_LVL_DIS__)

    #define NVT_DBG_ERR(fmt, ...)               NVT_DBG_DUMMY
    #define NVT_DBG_DBG(fmt, ...)               NVT_DBG_DUMMY
    #define NVT_DBG_MARK()                      NVT_DBG_DUMMY
    #define NVT_DBG_PRINTD(v)                   NVT_DBG_DUMMY
    #define NVT_DBG_PRINTX(v)                   NVT_DBG_DUMMY
    #define NVT_DBG_PRINTS(v)                   NVT_DBG_DUMMY

#else

    #if defined(_WIN32)
    // Windows

        #if defined(__CODEGEARC__)
        // CodeGear C++ Builder 2009
            #ifndef __FUNCTION__
                #define __FUNCTION__            __FUNC__
            #endif
        #endif

        #define NVT_DBG_ERR(fmt, ...)           printf("*N* [%d], %s() ERR: " fmt, __LINE__, __FUNCTION__, ##__VA_ARGS__)

        #if (__NVT_DBG_LVL__ == __NVT_DBG_LVL_ERR__)
            #define NVT_DBG_DBG(fmt, ...)       NVT_DBG_DUMMY
        #else
            #define NVT_DBG_DBG(fmt, ...)       printf("*N* [%d], %s() DBG: " fmt, __LINE__, __FUNCTION__, ##__VA_ARGS__)
        #endif

        #define NVT_DBG_MARK()                  printf("*N* [%d], %s() MARK!\n",        __LINE__, __FUNCTION__)
        #define NVT_DBG_PRINTD(v)               printf("*N* [%d], %s() %s = %d\n",      __LINE__, __FUNCTION__, #v, (NVT_INTP  )v);
        #define NVT_DBG_PRINTX(v)               printf("*N* [%d], %s() %s = 0x%X\n",    __LINE__, __FUNCTION__, #v, (NVT_UINTP )v);
        #define NVT_DBG_PRINTS(v)               printf("*N* [%d], %s() %s = %s\n",      __LINE__, __FUNCTION__, #v, (NVT_CHAR *)v);

    #elif defined(__KERNEL__)
    // Linux kernel space

        #define NVT_DBG_ERR(fmt, ...)           printk(KERN_ERR "*N* [%d], %s() ERR: " fmt, __LINE__, __FUNCTION__, ##__VA_ARGS__)

        #if (__NVT_DBG_LVL__ == __NVT_DBG_LVL_ERR__)
            #define NVT_DBG_DBG(fmt, ...)       NVT_DBG_DUMMY
        #else
            #define NVT_DBG_DBG(fmt, ...)       printk(KERN_ERR "*N* [%d], %s() DBG: " fmt, __LINE__, __FUNCTION__, ##__VA_ARGS__)
        #endif

        #define NVT_DBG_MARK()                  printk(KERN_ERR "*N* [%d], %s() MARK!\n",       __LINE__, __FUNCTION__)
        #define NVT_DBG_PRINTD(v)               printk(KERN_ERR "*N* [%d], %s() %s = %d\n",     __LINE__, __FUNCTION__, #v, (NVT_INTP  )v);
        #define NVT_DBG_PRINTX(v)               printk(KERN_ERR "*N* [%d], %s() %s = 0x%X\n",   __LINE__, __FUNCTION__, #v, (NVT_UINTP )v);
        #define NVT_DBG_PRINTS(v)               printk(KERN_ERR "*N* [%d], %s() %s = %s\n",     __LINE__, __FUNCTION__, #v, (NVT_CHAR *)v);

    #elif defined(__FPR_ENG_USERSPACE__)
    // Linux user space

        #define NVT_DBG_ERR(fmt, ...)           ALOGE("*N* [%d], %s() ERR: " fmt, __LINE__, __func__, ##__VA_ARGS__)


        #if (__NVT_DBG_LVL__ == __NVT_DBG_LVL_ERR__)
            #define NVT_DBG_DBG(fmt, ...)       NVT_DBG_DUMMY
        #else
            #define NVT_DBG_DBG(fmt, ...)       ALOGD("*N* [%d], %s() DBG: " fmt, __LINE__, __func__, ##__VA_ARGS__)
        #endif

        #define NVT_DBG_MARK()                  ALOGE("*N* [%d], %s() MARK!\n",     __LINE__, __func__)
        #define NVT_DBG_PRINTD(v)               ALOGE("*N* [%d], %s() %s = %d\n",   __LINE__, __func__, #v, (NVT_INTP  )v);
        #define NVT_DBG_PRINTX(v)               ALOGE("*N* [%d], %s() %s = 0x%X\n", __LINE__, __func__, #v, (NVT_UINTP )v);
        #define NVT_DBG_PRINTS(v)               ALOGE("*N* [%d], %s() %s = %s\n",   __LINE__, __func__, #v, (NVT_CHAR *)v);

    #else

    /*
    // TEE ... (TBD)
    #else

        #define NVT_DBG_ERR(fmt, ...)
        #define NVT_DBG_DBG(fmt, ...)
    */

    #endif // Platform

#endif // Disable output message


#define NVT_DBG_BMP_COLORTBL_SIZE   256

typedef NVT_UINT32  BMP_COLORTBL;

__PACKED__(typedef struct
{
    NVT_UINT16      uiSignature;        // Signature
    NVT_UINT32      uiFileSize;         // File Size
    NVT_UINT32      uiReserved0;        // Reserved
    NVT_UINT32      uiPAOffset;         // Pixel Array Offset
}) BMPFILE_HEADER;

typedef struct
{
    NVT_UINT32      uiDIBHeaderSize;    // DIB Header Size
    NVT_UINT32      uiImageWidth;       // Image Width
    NVT_UINT32      uiImageHeight;      // Image Height
    NVT_UINT16      uiPlanes;           // # Of Planes
    NVT_UINT16      uiBitsPerPixel;     // Bits Per Pixel
    NVT_UINT32      uiCompression;      // Compression
    NVT_UINT32      uiImageSize;        // Image Size
    NVT_UINT32      uiXPixelsPerMeter;  // X Pixels Per Meter
    NVT_UINT32      uiYPixelsPerMeter;  // Y Pixels Per Meter
    NVT_UINT32      uiColorsInTable;    // Colors # in Color Table
    NVT_UINT32      uiImportantColor;   // Important Color Count
} DIB_HEADER;

__PACKED__(typedef struct
{
    BMPFILE_HEADER      BmpFileHeader;
    DIB_HEADER          DibHeader;
    BMP_COLORTBL        ColorTable[NVT_DBG_BMP_COLORTBL_SIZE];    // Mandatory for bits per pixel <= 8
}) BMP_HEADER;

#ifdef __cplusplus
extern "C" {
#endif

/**
    Dump memory to file (RAW).

    This macro (function) will dump memory data to the file in RAW type.
    "fpr_" will be prefixed and ".raw" will be postfixed to the filename.

    @note                   For Windows System, the raw file will be located in the same folder of execution file.
                            For Linux System, the raw file will be located in /data folder.
    @param[in] Filename     The filename to store the dumped data.
    @param[in] pSrc         The address of data you want to dump.
    @param[in] uiWidth      The data width.
    @param[in] uiHeight     The data height.
    @param[in] uiStride     The data stride.
    @return     There is no return value.
*/
void NVT_DBG_DUMPRAW(const NVT_CHAR *Filename, const void *pSrc, NVT_UINT32 uiWidth, NVT_UINT32 uiHeight, NVT_UINT32 uiStride);

/**
    Dump memory to file (BMP, one channel).

    This macro (function) will dump memory data to the file in BMP 8-bits/pixel and one channel format.
    "fpr_" will be prefixed and ".bmp" will be postfixed to the filename.

    @note                   For Windows System, the BMP file will be located in the same folder of execution file.
                            For Linux System, the BMP file will be located in /data folder.
    @param[in] Filename     The filename to store the dumped data.
    @param[in] pSrc         The address of data you want to dump.
    @param[in] uiWidth      The data width.
    @param[in] uiHeight     The data height.
    @param[in] uiStride     The data stride.
    @return     There is no return value.
*/
void NVT_DBG_DUMPBMP(const NVT_CHAR *Filename, const void *pSrc, NVT_UINT32 uiWidth, NVT_UINT32 uiHeight, NVT_UINT32 uiStride);

/**
    Convert RAW type to BMP one channel.

    This macro (function) will convert RAW data to BMP 8-bits/pixel and one channel format.

    @param[in] pDst         The address of converted BMP data.
                            The size of pDst must be (uiWidth * uiHeight) + sizeof(BMP_HEADER) + padding.
    @param[in] pSrc         The address of RAW data you want to convert.
    @param[in] uiWidth      The data width.
    @param[in] uiHeight     The data height.
    @param[in] uiStride     The data stride.
    @return     There is no return value.
*/
void NVT_DBG_RAW_TO_BMP(void *pDst, const void *pSrc, NVT_UINT32 uiWidth, NVT_UINT32 uiHeight, NVT_UINT32 uiStride);

/**
    Mark current time.

    Mark current time, call NVT_DBG_PERFD() to calculate duration from last mark.

    @return     There is no return value.
*/
void NVT_DBG_PERFM(void);

/**
    Caclulate duration.

    Calculate duration from last mark.

    @return     Duration (unit: us).
*/
NVT_UINT32 NVT_DBG_PERFD(void);

#ifdef __cplusplus
}
#endif

//@}

#endif // _NVT_DEBUG_H
