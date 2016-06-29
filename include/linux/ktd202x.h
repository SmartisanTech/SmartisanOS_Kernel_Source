#ifndef _LINUX_AW2013_H
#define _LINUX_AW2013_H

#include <linux/types.h>
#include <linux/i2c.h>
#include <linux/regulator/consumer.h>
#include <linux/reboot.h>
struct ktd202x_platform_data {
    struct regulator *vcc_i2c;
};

enum leds_color {
    RED = 0,
    GREEN,
    BLUE,
    MAX,
};

struct ktd202x_chip {
    struct i2c_client *client;
    struct mutex i2c_lock;
    struct notifier_block reboot_nb;
    u8 color;
    u32 ramp_period;
    u32 period;
    u8 brightness;
    u8 current_red;
    u8 current_green;
    u8 current_blue;
    u8 brightness_red;
    u8 brightness_green;
    u8 brightness_blue;
    int max_brightness;
    int blink_red;
    int blink_green;
    int blink_blue;
    int power_status;
    u8 scaling;
    u32 ontime;
};

void ktd202x_breath_leds(struct ktd202x_chip *chip, u8 color);
void ktd202x_led_on(struct ktd202x_chip *chip, u8 color);
#endif
