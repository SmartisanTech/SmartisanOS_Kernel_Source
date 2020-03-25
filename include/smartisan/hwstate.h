#ifndef KEYWORD

#define KEYWORD_ENUM
#define KEYWORD(symbol) symbol,

enum HWSTATE_E{
#endif

KEYWORD(touchscreen)
KEYWORD(smb1355)
KEYWORD(fsa4480)
KEYWORD(goodixfp)

#ifdef KEYWORD_ENUM
KEYWORD(HWSTATE_MAX)
};
int smartisan_hwstate_set(char *hwstate_name, char *module_state);
#undef KEYWORD_ENUM
#undef KEYWORD
#endif
