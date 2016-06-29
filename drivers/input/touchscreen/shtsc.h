#ifndef _SHTSC_H
#define _SHTSC_H

#define SHTSC_DRIVER_NAME      "shtsc"

// hiroshi@sharp
#define OMAP4PANDA_GPIO_SHTSC_IRQ 59 // pin#28 of J6
#define OMAP4PANDA_GPIO_SHTSC_RESET 37 // pin#10 of J6
// pin#28 of J3 is GND

#if defined(CONFIG_TOUCHSCREEN_SHTSC_I2C)
// I2C4_SDA pin#23 of J3 (GPIO133)
// I2C4_SCL pin#24 of J3 (GPIO132)
// DGND pin#27,28 of J3 
#elif defined (CONFIG_TOUCHSCREEN_SHTSC_SPI)
// #define OMAP4PANDA_GPIO_SHTSC_GPIO 56 -- not used any more?
// panda MCSPI1
// other pins of J3 for SPI are #12(MOSI,GPIO#136), #16(CS0=SS,#137), #18(MISO,#135), #20(SCK,#134)
#define SHTSC_MAX_SPI_SPEED_IN_HZ (6*1000*1000)
#else // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)
error
#endif // (CONFIG_TOUCHSCREEN_SHTSC_UNKNOWNIF??)

#if 1//2014.11.12 changed
struct shtsc_i2c_pdata
{
	/* touch panel's minimum and maximum coordinates */
	u32 panel_minx;
	u32 panel_maxx;
	u32 panel_miny;
	u32 panel_maxy;

	/* display's minimum and maximum coordinates */
	u32 disp_minx;
	u32 disp_maxx;
	u32 disp_miny;
	u32 disp_maxy;

	unsigned long irqflags;
	bool	i2c_pull_up;
	bool	digital_pwr_regulator;
	bool    disable_gpios;
	int reset_gpio;
	u32 reset_gpio_flags;
	int id_gpio;
	u32 id_gpio_flags;
	int irq_gpio;
	u32 irq_gpio_flags;
	int *key_codes;

	int		ts_touch_num_max;
	int		ts_pressure_max;
	int		ts_flip_x;
	int		ts_flip_y;
	int		ts_swap_xy;

	int (*init_hw) (bool);
	int (*power_on) (bool);
};
#else
struct shtsc_i2c_pdata
{
	int reset_pin;		/* Reset pin is wired to this GPIO (optional) */
	int irq_pin;		/* IRQ pin is wired to this GPIO */
};
#endif

#endif /* _SHTSC_H */
