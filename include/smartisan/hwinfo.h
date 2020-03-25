#ifndef __HWINFO_H_
#define __HWINFO_H_

#define USE_EMMC                0
#define USE_UFS                 1
#define USE_UFS2                0
#define USE_FP                  0
#define USE_PRODUCT_VERSION     1
#define USE_NFC                 1
#define USE_LCD                 0
#define USE_TP                  0
#define USE_TP_VERSION          1
#define USE_MEMINFO             1
#define USE_CPUTYPE             1

#if USE_UFS2
int get_ufs2_support(void);
#endif
#if USE_NFC
int get_nfc_support(void);
#endif
#if USE_PRODUCT_VERSION
int get_hw_version_id(void);
int get_flash_version(void);
#endif
#endif

#ifndef KEYWORD

#define KEYWORD_ENUM
#define KEYWORD(symbol) symbol,

enum HWINFO_E{
#endif

KEYWORD(CPU_TYPE)
KEYWORD(emmc_sn)
#if USE_EMMC
KEYWORD(emmc_manufacturer)
KEYWORD(emmc_capacity)
#endif
#if USE_UFS
KEYWORD(ufs_manufacturer)
KEYWORD(ufs_capacity)
KEYWORD(ufs_version)
#endif
#if USE_UFS2
KEYWORD(ufs1_manufacturer)
KEYWORD(ufs1_capacity)
KEYWORD(ufs1_version)
#endif
KEYWORD(lpddr_manufacturer)
#if USE_LCD
KEYWORD(LCD_MFR)        //LCD manufacturer
#endif
#if USE_TP
KEYWORD(TP_MFR)          //Touch manufacturer
#endif
#if USE_TP_VERSION
KEYWORD(tp_version)
#endif
#if USE_FP
KEYWORD(FP_MFR)         //Fingerprint manufacturer
#endif
KEYWORD(BATTARY_MFR)    //battary  manufacturer
#if USE_NFC
KEYWORD(nfc_support)
#endif
#if USE_PRODUCT_VERSION
KEYWORD(version_id)
#endif
KEYWORD(secboot_version)
KEYWORD(pon_reason)
//KEYWORD(wipower)
KEYWORD(qchip_id)
KEYWORD(housing_color)
KEYWORD(flash_light)
#ifdef KEYWORD_ENUM
KEYWORD(HWINFO_MAX)
};
int smartisan_hwinfo_register(enum HWINFO_E e_hwinfo,char *hwinfo_name);
#undef KEYWORD_ENUM
#undef KEYWORD

#endif
