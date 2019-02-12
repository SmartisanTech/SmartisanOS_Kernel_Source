#ifndef KEYWORD

#define USE_EMMC 0
#define KEYWORD_ENUM
#define KEYWORD(symbol) symbol,

enum HWSTATE_E{
#endif

KEYWORD(i2cspi_state)
KEYWORD(fingerprint)
KEYWORD(audio_receiver_l)
KEYWORD(audio_speaker_r)
KEYWORD(audio_intelligo)
KEYWORD(audio_cs35l41)
KEYWORD(touch)
KEYWORD(nfc)
KEYWORD(usb_redriver)
KEYWORD(vibrator)
KEYWORD(camera_main)
KEYWORD(camera_aux)
KEYWORD(camera_front)
#ifdef KEYWORD_ENUM
KEYWORD(HWSTATE_MAX)
};
int smartisan_hwstate_set(char *hwstate_name, char *module_state);
#undef KEYWORD_ENUM
#undef KEYWORD

extern int debussy_get_presence(void);
extern int max98927_get_i2c_states(void);

#endif
