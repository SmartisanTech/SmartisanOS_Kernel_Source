#ifndef KEYWORD

#define KEYWORD_ENUM
#define KEYWORD(symbol) symbol,

enum HWINFO_E{
#endif

KEYWORD(CPU_TYPE)
KEYWORD(emmc_sn)
KEYWORD(emmc_manufacturer)
KEYWORD(emmc_capacity)
KEYWORD(ufs_manufacturer)
KEYWORD(ufs_capacity)
KEYWORD(ufs_version)
KEYWORD(lpddr_manufacturer)
KEYWORD(LCD_MFR)        //LCD manufacturer
KEYWORD(TP_MFR)          //Touch manufacturer
KEYWORD(FP_MFR)         //Fingerprint manufacturer
KEYWORD(BATTARY_MFR)    //battary  manufacturer
#if 0
KEYWORD(SPEAKER_MFR)    //Speaker box manufacturer
KEYWORD(TYPEC_MFR)      //Typec  manufacturer
KEYWORD(pon_reason)
KEYWORD(secboot_version)
KEYWORD(qcn_type)
#endif
KEYWORD(nfc_support)
KEYWORD(version_id)
KEYWORD(secboot_version)
KEYWORD(pon_reason)
#ifdef KEYWORD_ENUM
KEYWORD(HWINFO_MAX)
};
int smartisan_hwinfo_register(enum HWINFO_E e_hwinfo,char *hwinfo_name);
int get_nfc_support(void);
#undef KEYWORD_ENUM
#undef KEYWORD

#endif
