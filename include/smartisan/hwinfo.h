#ifndef __HWINFO_H_
#define __HWINFO_H_

#define USE_EMMC 0

int get_ufs2_support(void);
int get_nfc_support(void);
int get_hw_version_id(void);
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
KEYWORD(ufs_manufacturer)
KEYWORD(ufs_capacity)
KEYWORD(ufs_version)
KEYWORD(ufs1_manufacturer)
KEYWORD(ufs1_capacity)
KEYWORD(ufs1_version)
KEYWORD(lpddr_manufacturer)
KEYWORD(LCD_MFR)        //LCD manufacturer
KEYWORD(TP_MFR)          //Touch manufacturer
KEYWORD(FP_MFR)         //Fingerprint manufacturer
KEYWORD(BATTARY_MFR)    //battary  manufacturer
KEYWORD(nfc_support)
KEYWORD(version_id)
KEYWORD(secboot_version)
KEYWORD(pon_reason)
KEYWORD(wipower)
#ifdef KEYWORD_ENUM
KEYWORD(HWINFO_MAX)
};
int smartisan_hwinfo_register(enum HWINFO_E e_hwinfo,char *hwinfo_name);
#undef KEYWORD_ENUM
#undef KEYWORD

#endif
