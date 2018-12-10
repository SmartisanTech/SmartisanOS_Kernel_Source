#ifndef KEYWORD

#define KEYWORD_ENUM
#define KEYWORD(symbol) symbol,

enum HWINFO_E{
#endif

KEYWORD(CPU_TYPE)
KEYWORD(pon_reason)
KEYWORD(secboot_version)
KEYWORD(version_id)
KEYWORD(qcn_type)
KEYWORD(emmc_sn)
KEYWORD(emmc_manufacturer)
KEYWORD(emmc_capacity)
KEYWORD(lpddr_manufacturer)
KEYWORD(SPEAKER_MFR)    //Speaker box manufacturer
KEYWORD(FP_MFR)         //Fingerprint manufacturer
KEYWORD(LCD_MFR)        //LCD manufacturer
KEYWORD(TP_MFR)         //Touch manufacturer
KEYWORD(BATTARY_MFR)    //battary  manufacturer
KEYWORD(TYPEC_MFR)      //Typec  manufacturer
KEYWORD(BACK_CAM_MFR)         //camera  manufacturer
KEYWORD(BACKAUX_CAM_MFR)      //camera  manufacturer
KEYWORD(FRONT_CAM_MFR)        //camera  manufacturer

#ifdef KEYWORD_ENUM
KEYWORD(HWINFO_MAX)
};
int smartisan_hwinfo_register(enum HWINFO_E e_hwinfo,char *hwinfo_name);
#undef KEYWORD_ENUM
#undef KEYWORD

#endif
