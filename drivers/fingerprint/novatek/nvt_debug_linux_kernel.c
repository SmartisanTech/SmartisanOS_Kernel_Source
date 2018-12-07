/*
    Novatek's debug library.

    Novatek's debug library for fingerprint solution.

    @file       nvt_debug.c
    @ingroup
    @note       Nothing.

    Copyright   Novatek Microelectronics Corp. 2015.  All rights reserved.
*/

#include "nvt_debug.h"
#include "nvt_basic.h"

/**
    @addtogroup
*/
//@{

static BMP_HEADER BmpHeader =
{
    // BMP file header
    {
        0x4D42,                     // Signature
        0x00000000,                 // File Size
        0x00000000,                 // Reserved
        // Pixel Array Offset
        sizeof(BMPFILE_HEADER) + sizeof(DIB_HEADER) + NVT_DBG_BMP_COLORTBL_SIZE * sizeof(BMP_COLORTBL)
    },

    // DIB header
    {
        sizeof(DIB_HEADER),
        0x00000000,                 // Image Width
        0x00000000,                 // Image Height
        0x0001,                     // # Of Planes
        0x0008,                     // Bits Per Pixel
        0x00000000,                 // Compression, 0 = BI_RGB = uncompressed format
        0x00000000,                 // Image Size, for BI_RGB format, this could be zero
        0x00000B13,                 // X Pixels Per Meter, 72 DPI
        0x00000B13,                 // Y Pixels Per Meter, 72 DPI
        0x00000000,                 // Colors # in Color Table, 0 means 2^n (n = bits per pixel)
        0x00000000,                 // Important Color Count, 0 means all colors are important
    },

    // Color table for 8-bits/pixel and one channel format
    {
        0x00000000, 0x00010101, 0x00020202, 0x00030303, 0x00040404, 0x00050505, 0x00060606, 0x00070707,
        0x00080808, 0x00090909, 0x000A0A0A, 0x000B0B0B, 0x000C0C0C, 0x000D0D0D, 0x000E0E0E, 0x000F0F0F,
        0x00101010, 0x00111111, 0x00121212, 0x00131313, 0x00141414, 0x00151515, 0x00161616, 0x00171717,
        0x00181818, 0x00191919, 0x001A1A1A, 0x001B1B1B, 0x001C1C1C, 0x001D1D1D, 0x001E1E1E, 0x001F1F1F,
        0x00202020, 0x00212121, 0x00222222, 0x00232323, 0x00242424, 0x00252525, 0x00262626, 0x00272727,
        0x00282828, 0x00292929, 0x002A2A2A, 0x002B2B2B, 0x002C2C2C, 0x002D2D2D, 0x002E2E2E, 0x002F2F2F,
        0x00303030, 0x00313131, 0x00323232, 0x00333333, 0x00343434, 0x00353535, 0x00363636, 0x00373737,
        0x00383838, 0x00393939, 0x003A3A3A, 0x003B3B3B, 0x003C3C3C, 0x003D3D3D, 0x003E3E3E, 0x003F3F3F,
        0x00404040, 0x00414141, 0x00424242, 0x00434343, 0x00444444, 0x00454545, 0x00464646, 0x00474747,
        0x00484848, 0x00494949, 0x004A4A4A, 0x004B4B4B, 0x004C4C4C, 0x004D4D4D, 0x004E4E4E, 0x004F4F4F,
        0x00505050, 0x00515151, 0x00525252, 0x00535353, 0x00545454, 0x00555555, 0x00565656, 0x00575757,
        0x00585858, 0x00595959, 0x005A5A5A, 0x005B5B5B, 0x005C5C5C, 0x005D5D5D, 0x005E5E5E, 0x005F5F5F,
        0x00606060, 0x00616161, 0x00626262, 0x00636363, 0x00646464, 0x00656565, 0x00666666, 0x00676767,
        0x00686868, 0x00696969, 0x006A6A6A, 0x006B6B6B, 0x006C6C6C, 0x006D6D6D, 0x006E6E6E, 0x006F6F6F,
        0x00707070, 0x00717171, 0x00727272, 0x00737373, 0x00747474, 0x00757575, 0x00767676, 0x00777777,
        0x00787878, 0x00797979, 0x007A7A7A, 0x007B7B7B, 0x007C7C7C, 0x007D7D7D, 0x007E7E7E, 0x007F7F7F,
        0x00808080, 0x00818181, 0x00828282, 0x00838383, 0x00848484, 0x00858585, 0x00868686, 0x00878787,
        0x00888888, 0x00898989, 0x008A8A8A, 0x008B8B8B, 0x008C8C8C, 0x008D8D8D, 0x008E8E8E, 0x008F8F8F,
        0x00909090, 0x00919191, 0x00929292, 0x00939393, 0x00949494, 0x00959595, 0x00969696, 0x00979797,
        0x00989898, 0x00999999, 0x009A9A9A, 0x009B9B9B, 0x009C9C9C, 0x009D9D9D, 0x009E9E9E, 0x009F9F9F,
        0x00A0A0A0, 0x00A1A1A1, 0x00A2A2A2, 0x00A3A3A3, 0x00A4A4A4, 0x00A5A5A5, 0x00A6A6A6, 0x00A7A7A7,
        0x00A8A8A8, 0x00A9A9A9, 0x00AAAAAA, 0x00ABABAB, 0x00ACACAC, 0x00ADADAD, 0x00AEAEAE, 0x00AFAFAF,
        0x00B0B0B0, 0x00B1B1B1, 0x00B2B2B2, 0x00B3B3B3, 0x00B4B4B4, 0x00B5B5B5, 0x00B6B6B6, 0x00B7B7B7,
        0x00B8B8B8, 0x00B9B9B9, 0x00BABABA, 0x00BBBBBB, 0x00BCBCBC, 0x00BDBDBD, 0x00BEBEBE, 0x00BFBFBF,
        0x00C0C0C0, 0x00C1C1C1, 0x00C2C2C2, 0x00C3C3C3, 0x00C4C4C4, 0x00C5C5C5, 0x00C6C6C6, 0x00C7C7C7,
        0x00C8C8C8, 0x00C9C9C9, 0x00CACACA, 0x00CBCBCB, 0x00CCCCCC, 0x00CDCDCD, 0x00CECECE, 0x00CFCFCF,
        0x00D0D0D0, 0x00D1D1D1, 0x00D2D2D2, 0x00D3D3D3, 0x00D4D4D4, 0x00D5D5D5, 0x00D6D6D6, 0x00D7D7D7,
        0x00D8D8D8, 0x00D9D9D9, 0x00DADADA, 0x00DBDBDB, 0x00DCDCDC, 0x00DDDDDD, 0x00DEDEDE, 0x00DFDFDF,
        0x00E0E0E0, 0x00E1E1E1, 0x00E2E2E2, 0x00E3E3E3, 0x00E4E4E4, 0x00E5E5E5, 0x00E6E6E6, 0x00E7E7E7,
        0x00E8E8E8, 0x00E9E9E9, 0x00EAEAEA, 0x00EBEBEB, 0x00ECECEC, 0x00EDEDED, 0x00EEEEEE, 0x00EFEFEF,
        0x00F0F0F0, 0x00F1F1F1, 0x00F2F2F2, 0x00F3F3F3, 0x00F4F4F4, 0x00F5F5F5, 0x00F6F6F6, 0x00F7F7F7,
        0x00F8F8F8, 0x00F9F9F9, 0x00FAFAFA, 0x00FBFBFB, 0x00FCFCFC, 0x00FDFDFD, 0x00FEFEFE, 0x00FFFFFF
    }
};

static NVT_UINT8    uiPadData[4] = { 0, 0, 0, 0 };

static NVT_UINT32   uiDumpCnt = 0;

static NVT_UINT32   uiPerfCnt = 0;

#define nvt_dbg_generateBMPHeader(uiWidth, uiHeight)                                                \
{                                                                                                   \
    BmpHeader.BmpFileHeader.uiFileSize = sizeof(BMP_HEADER) + ALIGN_CEIL_4(uiWidth) * uiHeight;     \
    BmpHeader.DibHeader.uiImageWidth    = uiWidth;                                                  \
    BmpHeader.DibHeader.uiImageHeight   = uiHeight;                                                 \
}

#if defined(__KERNEL__)
// Linux Kernel

#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/time.h>

/*
    Dump memory to file (RAW).

    This macro (function) will dump memory data to the file in RAW type.
    "_fpr_" will be prefixed and ".raw" will be postfixed to the filename.

    @param[in] Filename     The filename to store the dumped data.
    @param[in] pSrc         The address of data you want to dump.
    @param[in] uiWidth      The data width.
    @param[in] uiHeight     The data height.
    @param[in] uiStride     The data stride.
    @return     There is no return value.
*/
void NVT_DBG_DUMPRAW(const NVT_CHAR *Filename, const void *pSrc, NVT_UINT32 uiWidth, NVT_UINT32 uiHeight, NVT_UINT32 uiStride)
{
    NVT_CHAR        FullFilename[64];
    char           *pData;
    struct file    *pFile;
    mm_segment_t    fs;

    // Check parameter
    if ((uiWidth == 0) || (uiHeight == 0) || (uiStride == 0) || (pSrc == NULL) || (strlen(Filename) > 32))
    {
        NVT_DBG_MSG("Parameter error!\n");
        return;
    }

    sprintf(FullFilename, "/data/_fpr_%s_%.4d.raw", Filename, (int)uiDumpCnt++);

    pFile = filp_open(FullFilename, O_RDWR | O_TRUNC | O_CREAT | O_SYNC, 0660);
    pData = (char *)pSrc;

    if (pFile != NULL)
    {
        fs = get_fs();
        set_fs(KERNEL_DS);
        pFile->f_op->llseek(pFile, 0, 0);

        for (; uiHeight!=0; uiHeight--)
        {
            pFile->f_op->write(pFile, pData, uiWidth, &pFile->f_pos);
            pData += uiStride;
        }
        filp_close(pFile, NULL);
        set_fs(fs);
    }
    else
    {
        NVT_DBG_MSG("Can't open file %s to dump RAW!\n", FullFilename);
    }
}

/*
    Dump memory to file (BMP, one channel).

    This macro (function) will dump memory data to the file in BMP 8-bits/pixel and one channel format.
    "_fpr_" will be prefixed and ".bmp" will be postfixed to the filename.

    @param[in] Filename     The filename to store the dumped data.
    @param[in] pSrc         The address of data you want to dump.
    @param[in] uiWidth      The data width.
    @param[in] uiHeight     The data height.
    @param[in] uiStride     The data stride.
    @return     There is no return value.
*/
void NVT_DBG_DUMPBMP(const NVT_CHAR *Filename, const void *pSrc, NVT_UINT32 uiWidth, NVT_UINT32 uiHeight, NVT_UINT32 uiStride)
{
    NVT_CHAR        FullFilename[64];
    char           *pData;
    struct file    *pFile;
    mm_segment_t    fs;

    // Check parameter
    if ((uiWidth == 0) || (uiHeight == 0) || (uiStride == 0) || (pSrc == NULL) || (strlen(Filename) > 32))
    {
        NVT_DBG_MSG("Parameter error!\n");
        return;
    }

    sprintf(FullFilename, "/data/_fpr_%s_%.4d.bmp", Filename, (int)uiDumpCnt++);

    pFile = filp_open(FullFilename, O_RDWR | O_TRUNC | O_CREAT | O_SYNC, 0660);
    pData = (char *)pSrc;

    if (pFile != NULL)
    {
        NVT_UINT32 uiRemaining;

        nvt_dbg_generateBMPHeader(uiWidth, uiHeight);

        fs = get_fs();
        set_fs(KERNEL_DS);
        pFile->f_op->llseek(pFile, 0, 0);

        // Write header
        pFile->f_op->write(pFile, (char *)&BmpHeader, sizeof(BMP_HEADER), &pFile->f_pos);

        // Write data
        uiRemaining = uiWidth & 0x03;

        pData += (uiHeight - 1) * uiStride;

        // BMP file format: row data must be 4 bytes alignment
        if (uiRemaining == 0)
        {
            // BMP file format: Write from last row to first row
            for (; uiHeight!=0; uiHeight--)
            {
                pFile->f_op->write(pFile, pData, uiWidth, &pFile->f_pos);
                pData -= uiStride;
            }
        }
        else
        {
            // BMP file format: Write from last row to first row
            for (; uiHeight!=0; uiHeight--)
            {
                pFile->f_op->write(pFile, pData, uiWidth, &pFile->f_pos);
                pData -= uiStride;

                // Padding raw data to 4 bytes
                pFile->f_op->write(pFile, (char *)uiPadData, 4 - uiRemaining, &pFile->f_pos);
            }
        }

        filp_close(pFile, NULL);
        set_fs(fs);
    }
    else
    {
        NVT_DBG_MSG("Can't open file %s to dump BMP!\n", FullFilename);
    }
}

/*
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
void NVT_DBG_RAW_TO_BMP(void *pDst, const void *pSrc, NVT_UINT32 uiWidth, NVT_UINT32 uiHeight, NVT_UINT32 uiStride)
{
    NVT_UINT32  uiRemaining;
    char       *pOffset = (char *)pDst;
    char       *pData;

    // Check parameter
    if ((uiWidth == 0) || (uiHeight == 0) || (uiStride == 0) || (pSrc == NULL) || (pDst == NULL))
    {
        NVT_DBG_MSG("Parameter error!\n");
        return;
    }

    nvt_dbg_generateBMPHeader(uiWidth, uiHeight);

    // Write header
    memcpy((void *)pDst, (const void *)&BmpHeader, sizeof(BMP_HEADER));

    pOffset += sizeof(BMP_HEADER);
    pData    = (char *)pSrc + ((uiHeight - 1) * uiStride);

    // Write data
    uiRemaining = uiWidth & 0x03;

    // BMP file format: row data must be 4 bytes alignment
    if (uiRemaining == 0)
    {
        // BMP file format: Write from last row to first row
        for (; uiHeight!=0; uiHeight--)
        {
            memcpy(pOffset, pData, uiWidth);
            pOffset += uiWidth;
            pData -= uiStride;
        }
    }
    else
    {
        // BMP file format: Write from last row to first row
        for (; uiHeight!=0; uiHeight--)
        {
            memcpy(pOffset, pData, uiWidth);
            pOffset += uiWidth;
            pData -= uiStride;

            // Padding raw data to 4 bytes
            memcpy((void *)pOffset, (const void *)uiPadData, 4 - uiRemaining);
            pOffset += (4 - uiRemaining);
        }
    }
}

/*
    Mark current time.

    Mark current time, call NVT_DBG_PERFD() to calculate duration from last mark.

    @return     There is no return value.
*/
void NVT_DBG_PERFM(void)
{
    struct timeval tv;

    do_gettimeofday(&tv);

    uiPerfCnt = (tv.tv_sec * 1000000 + tv.tv_usec);
}

/*
    Caclulate duration.

    Calculate duration from last mark.

    @return     Duration (unit: us).
*/
NVT_UINT32 NVT_DBG_PERFD(void)
{
    struct timeval tv;

    do_gettimeofday(&tv);

    return ((tv.tv_sec * 1000000 + tv.tv_usec) - uiPerfCnt);
}

#else

#error Not Linux Kernel System!

#endif

__EXPORT_SYMBOL__(NVT_DBG_DUMPRAW);
__EXPORT_SYMBOL__(NVT_DBG_DUMPBMP);
__EXPORT_SYMBOL__(NVT_DBG_RAW_TO_BMP);
__EXPORT_SYMBOL__(NVT_DBG_PERFM);
__EXPORT_SYMBOL__(NVT_DBG_PERFD);

//@}
