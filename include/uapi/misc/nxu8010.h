#ifndef _TT_NXU8010_H
#define _TT_NXU8010_H
#include <linux/i2c.h>
#include <linux/fs.h>
#include <linux/ioctl.h>

#define NXU8010_IOCTL_INIT              _IO('n', 0x01)
#define NXU8010_IOCTL_G_DATA            _IOR('n', 0x02, unsigned char)
#define NXU8010_IOCTL_G_CHIPID          _IOR('n', 0x03,GET_NEXU8010_DATA)

typedef struct {
	int16_t r_data;
	int16_t g_data;
	int16_t b_data;
	int16_t w_data;
} GET_NEXU8010_DATA ;

#endif
