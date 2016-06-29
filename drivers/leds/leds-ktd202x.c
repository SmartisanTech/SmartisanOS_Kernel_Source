#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/i2c.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/ktd202x.h>
#include <linux/platform_device.h>
#include <linux/delay.h>
#include <soc/qcom/socinfo.h>

#define MODULE_NAME "ktd202x"

#define EN_RESET_CONTROL 0x00
#define FLASH_PERIOD 0x01
#define LED_ON_TIMER_1 0x02
#define LED_ON_TIMER_2 0x03
#define LED_ENABLE_CONTROL 0x04
#define RAMP_TIMES 0x05
#define CURRENT_1  0x06
#define CURRENT_2  0x07
#define CURRENT_3  0x08
#define CURRENT_4  0x09
struct ktd202x_chip *the_ktd202x_chip;
void ktd202x_breath_leds(struct ktd202x_chip *chip, u8 color);

void ktd202x_set_scaling(struct ktd202x_chip *chip)
{
    u8 value;

    if ((chip->scaling > 3) || (chip->scaling < 0)) {
        chip->scaling = 1;
    }
    value = (u8)(chip->scaling << 5);
    i2c_smbus_write_byte_data(chip->client, EN_RESET_CONTROL, value);// mode set---IC work when both SCL and SDA goes high
}

void ktd202x_set_period(struct ktd202x_chip *chip)
{
    u8 period = 0;
    if (chip->period < 128) {
        chip->period = 128; //ms
    } else if ((128 < chip->period) && (chip->period <= 384)) {
        chip->period = 384; //ms
    } else if (chip->period > 16380) {
        chip->period = 16380;
    }

    if (chip->period > 128) {
        period = (u8)((chip->period - 384) / 128 + 1); //the value write in Reg1[6-0]
    } else {
        period = 0;
    }

    i2c_smbus_write_byte_data(chip->client, FLASH_PERIOD, period);//dry flash period
}

void ktd202x_set_ramp_time(struct ktd202x_chip *chip)
{
    u8 ramp_time = 0;//ms
    u32 ramp_time1 = 0;//ms

    if (chip->ramp_period < 2) {
        ramp_time1 = 0;
    }

    switch (chip->scaling) {
    case 0:
        if (chip->ramp_period > 1440)
            chip->ramp_period = 1440;
        ramp_time1 = chip->ramp_period;
        break;
    case 1:
        if (chip->ramp_period > 2880)
            chip->ramp_period = 2880;
        ramp_time1 = chip->ramp_period / 2;
        break;
    case 2:
        if (chip->ramp_period > 5760)
            chip->ramp_period = 5760;
        ramp_time1 = chip->ramp_period / 4;
        break;
    case 3:
        if (chip->ramp_period > 180)
            chip->ramp_period = 180;
        ramp_time1 = chip->ramp_period * 8;
        break;
    default:
        break;
    }
    ramp_time1 = ramp_time1 / 96; //the value write in Reg
    ramp_time1 = ((ramp_time1 << 4) | ramp_time1); //the value write in Reg
    ramp_time = (u8)ramp_time1; //the value write in Reg
    i2c_smbus_write_byte_data(chip->client, RAMP_TIMES, ramp_time);//rase time
}

void ktd202x_set_ontime(struct ktd202x_chip *chip)
{
    u8 ontime = 0;
    ontime = (u8)((chip->ontime * 100 * 100) / (chip->period * 39));
    i2c_smbus_write_byte_data(chip->client, LED_ON_TIMER_1, ontime);//led flashing(curerent ramp-up and down countinuously)
}

void ktd202x_set_current(struct ktd202x_chip *chip, int color)
{
    switch (color) {
        case GREEN:
            chip->current_green = (u8)(chip->brightness_green); //need to deal with the translate from brightness to current
            i2c_smbus_write_byte_data(chip->client, CURRENT_1, chip->current_green);//set current is 15mA
            break;
        case RED:
            chip->current_red = (u8)(chip->brightness_red);
            i2c_smbus_write_byte_data(chip->client, CURRENT_2, chip->current_red);//set current is 15mA
            break;
        case BLUE:
            chip->current_blue = (u8)(chip->brightness_blue);
            i2c_smbus_write_byte_data(chip->client, CURRENT_3, chip->current_blue);//set current is 15mA
            break;
    }
}

static ssize_t scaling_store(struct device *dev,
        struct device_attribute *attr,
        const char *buf, size_t count)
{
    ssize_t ret;
    unsigned long scaling;
    struct ktd202x_chip *chip;

    chip = the_ktd202x_chip;

    ret = kstrtoul(buf, 10, &scaling);
    if (ret)
        return ret;

    chip->scaling = scaling;

    if (!chip->brightness_red)
        chip->brightness_red = 255;
    ktd202x_breath_leds(chip, RED);

    return count;
}

static ssize_t period_store(struct device *dev,
        struct device_attribute *attr,
        const char *buf, size_t count)
{
    ssize_t ret;
    unsigned long period;
    struct ktd202x_chip *chip;

    chip = the_ktd202x_chip;

    ret = kstrtoul(buf, 10, &period);
    if (ret)
        return ret;

    chip->period = period; //ms

    if (!chip->brightness_red)
        chip->brightness_red = 255;
    ktd202x_breath_leds(chip, RED);

    return count;
}

static ssize_t ramp_time_store(struct device *dev,
        struct device_attribute *attr,
        const char *buf, size_t count)
{
    ssize_t ret;
    unsigned long ramp_period;
    struct ktd202x_chip *chip;

    chip = the_ktd202x_chip;

    ret = kstrtoul(buf, 10, &ramp_period);
    if (ret)
        return ret;

    chip->ramp_period = ramp_period;

    if (!chip->brightness_red)
        chip->brightness_red = 255;
    ktd202x_breath_leds(chip, RED);

    return count;
}

static ssize_t ontime_store(struct device *dev,
        struct device_attribute *attr,
        const char *buf, size_t count)
{
    ssize_t ret;
    unsigned long ontime;
    struct ktd202x_chip *chip;

    chip = the_ktd202x_chip;

    ret = kstrtoul(buf, 10, &ontime);
    if (ret)
        return ret;

    chip->ontime = ontime;

    if (!chip->brightness_red)
        chip->brightness_red = 255;
    ktd202x_breath_leds(chip, RED);

    return count;
}

static DEVICE_ATTR(scaling, 0664, NULL, scaling_store);
static DEVICE_ATTR(period, 0664, NULL, period_store);
static DEVICE_ATTR(ramp_time, 0664, NULL, ramp_time_store);
static DEVICE_ATTR(ontime, 0664, NULL, ontime_store);

static struct attribute *ktd202x_attrs[] = {
    &dev_attr_scaling.attr,
    &dev_attr_period.attr,
    &dev_attr_ramp_time.attr,
    &dev_attr_ontime.attr,
    NULL
};

static const struct attribute_group ktd202x_attrs_group = {
    .attrs = ktd202x_attrs,
};

void ktd202x_set_color(struct ktd202x_chip *chip, u8 color)
{
#if 0
    switch (color) {
        case GREEN:
            if (chip->brightness_green) {
                if (chip->blink_green) {
                    chip->color |= 0x02;
                } else {
                    chip->color |= 0x01;
                }
            } else {
                chip->color &= 0xfc;
            }
            break;
        case RED:
            if (chip->brightness_red) {
                if (chip->blink_red) {
                    chip->color |= 0x08;
                } else {
                    chip->color |= 0x04;
                }
            } else {
                chip->color &= 0xf3;
            }
            break;
        case BLUE:
            if (chip->brightness_blue) {
                if (chip->blink_blue) {
                    chip->color |= 0x20;
                } else {
                    chip->color |= 0x10;
                }
            } else {
                chip->color &= 0xcf;
            }
            break;
        default:
            break;
    }
#endif

    if (chip->brightness_blue || chip->brightness_green || chip->brightness_red) {
            if (chip->blink_green || chip->blink_blue || chip->blink_red) {
                    //if one led blink, let all the led blink
                    chip->color = 0x2a;
            } else {
                    //if no led blink, let all led bright
                    chip->color = 0x15;
            }
    } else {
            //turn off all led
            chip->color = 0xc0;
    }
    i2c_smbus_write_byte_data(chip->client, LED_ENABLE_CONTROL, chip->color);//allocate led1 to timer1
    ktd202x_set_current(chip, color);
}

void ktd202x_breath_leds(struct ktd202x_chip *chip, u8 color)
{
    if (chip->brightness_red || chip->brightness_green || chip->brightness_blue) {
        ktd202x_set_scaling(chip);
        ktd202x_set_ramp_time(chip);
        ktd202x_set_period(chip);
        i2c_smbus_write_byte_data(chip->client, LED_ON_TIMER_1, 0x00);//reset internal counter
        ktd202x_set_color(chip, color);
        ktd202x_set_ontime(chip);
    } else {
        i2c_smbus_write_byte_data(chip->client, EN_RESET_CONTROL, 0x08);//Device OFF-Either SCL goes low or SDA stops toggling
        chip->color = 0;
    }
}
EXPORT_SYMBOL_GPL(ktd202x_breath_leds);

void ktd202x_led_on(struct ktd202x_chip *chip, u8 color)
{
    if (chip->brightness_red || chip->brightness_green || chip->brightness_blue) {
        ktd202x_set_scaling(chip);
        ktd202x_set_color(chip, color);
    } else {
        i2c_smbus_write_byte_data(chip->client, EN_RESET_CONTROL, 0x08);//Device OFF-Either SCL goes low or SDA stops toggling
        chip->color = 0;
    }
}
EXPORT_SYMBOL_GPL(ktd202x_led_on);

static int ktd202x_power_init(struct i2c_client *client, struct ktd202x_platform_data *data, int on)
{
    int rc;

    if (!on)
        goto pwr_deinit;

    data->vcc_i2c = regulator_get(&client->dev, "vcc_i2c");
    if (IS_ERR(data->vcc_i2c)) {
        rc = PTR_ERR(data->vcc_i2c);
        dev_err(&client->dev, "Regulator get failed vcc_i2c rc=%d\n", rc);
        return rc;
    }

    rc = regulator_enable(data->vcc_i2c);
    if (rc) {
        dev_err(&client->dev, "regulator vcc i2c enable failed, rc=%d\n", rc);
        regulator_put(data->vcc_i2c);
        return rc;
    }

    the_ktd202x_chip->power_status = 1;
    return 0;

pwr_deinit:
    if (the_ktd202x_chip->power_status) {
        regulator_disable(data->vcc_i2c);
    }
    regulator_put(data->vcc_i2c);
    the_ktd202x_chip->power_status = 0;

    return 0;
}

static int msm_ktd202x_reboot_notifity(struct notifier_block *self, unsigned long action, void *priv)
{
    the_ktd202x_chip->brightness_red = 0;
    the_ktd202x_chip->brightness_green = 0;
    the_ktd202x_chip->brightness_blue = 0;
    ktd202x_led_on(the_ktd202x_chip, RED);

    return 0;
}

static int ktd202x_suspend(struct device *dev)
{
    struct ktd202x_chip *chip;
    struct ktd202x_platform_data *pdata;

    chip = the_ktd202x_chip;
    pdata = chip->client->dev.platform_data;
    if (!(chip->brightness_red || chip->brightness_green || chip->brightness_blue)) {
        if (the_ktd202x_chip->power_status) {
            ktd202x_power_init(chip->client, pdata, 0);
        }
    }
    return 0;
}

static int ktd202x_resume(struct device *dev)
{
    struct ktd202x_chip *chip;
    struct ktd202x_platform_data *pdata;

    chip = the_ktd202x_chip;
    pdata = chip->client->dev.platform_data;
    if (!(chip->brightness_red || chip->brightness_green || chip->brightness_blue)) {
        if (!the_ktd202x_chip->power_status) {
            ktd202x_power_init(chip->client, pdata, 1);
        }
    }
    return 0;
}

static SIMPLE_DEV_PM_OPS(ktd202x_pm_ops, ktd202x_suspend, ktd202x_resume);

static int ktd202x_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
    struct ktd202x_chip *chip;
    struct ktd202x_platform_data *pdata;
    int ret;
    uint32_t hw_ver;
    uint8_t hw_ver_major;

    hw_ver = socinfo_get_platform_version();
    hw_ver_major = (uint8_t)(hw_ver >> 8 & 0xff) - 1;
    the_ktd202x_chip = NULL;

    if (!hw_ver_major) {
        pr_err("%s:hw_ver=%d, hw_ver_major=%d\n", __func__, hw_ver, hw_ver_major);
        return -1;
    }
    chip = kzalloc(sizeof(struct ktd202x_chip), GFP_KERNEL);
    if (chip == NULL)
        return -ENOMEM;

    the_ktd202x_chip = chip;

    if (client->dev.of_node) {
        pdata = devm_kzalloc(&client->dev, sizeof(struct ktd202x_platform_data), GFP_KERNEL);
        if (!pdata) {
            dev_err(&client->dev, "Failed to allocate memory\n");
            goto out_alloc_failed;
        }

        client->dev.platform_data = pdata;
    } else {
        pdata = client->dev.platform_data;
    }

    ret = i2c_check_functionality(client->adapter, I2C_FUNC_I2C);
    if (!ret) {
        dev_err(&client->dev, "I2C not supported\n");
        goto out_parse_failed;
    }


    chip->client = client;

    chip->power_status = 0;
    ktd202x_power_init(client, pdata, 1);

    chip->reboot_nb.notifier_call = msm_ktd202x_reboot_notifity;
    register_reboot_notifier(&(chip->reboot_nb));

    mutex_init(&chip->i2c_lock);
    i2c_set_clientdata(client, chip);

    ret = i2c_smbus_write_byte_data(chip->client, LED_ENABLE_CONTROL, 0x00);// initialization LED off
    if (ret) {
        msleep(100);
        ret = i2c_smbus_write_byte_data(chip->client, LED_ENABLE_CONTROL, 0x00);// initialization LED off
        if (ret) {
            pr_err("%s:i2c write error, failed to register the ktd202x driver\n", __func__);
            goto remove_the_driver;
        }
    }
    chip->color = 0;

    ret = sysfs_create_group(&(chip->client->dev.kobj), &ktd202x_attrs_group);
    if (ret) {
        pr_err("%s:failed to create sysfs\n", __func__);
    }
    return 0;
remove_the_driver:
    unregister_reboot_notifier(&(chip->reboot_nb));
    ktd202x_power_init(client, pdata, 0);
out_parse_failed:
    if (client->dev.of_node)
        devm_kfree(&client->dev, pdata);
out_alloc_failed:
    kfree(chip);
    the_ktd202x_chip = NULL;

    return ret;
}

static int ktd202x_remove(struct i2c_client *client)
{
    struct ktd202x_chip *chip = i2c_get_clientdata(client);

    sysfs_remove_group(&(chip->client->dev.kobj), &ktd202x_attrs_group);
    unregister_reboot_notifier(&(chip->reboot_nb));
    kfree(chip);
    return 0;
}

static const struct i2c_device_id ktd202x_id[] = {
    { MODULE_NAME, 0},
    { }
};

static struct of_device_id ktd202x_match_table[] = {
    { .compatible = "ktd202x",},
    { },
};

static struct i2c_driver ktd202x_driver = {
    .driver = {
        .name = MODULE_NAME,
        .owner = THIS_MODULE,
        .of_match_table = ktd202x_match_table,
        .pm = &ktd202x_pm_ops,
    },
    .probe = ktd202x_probe,
    .remove = ktd202x_remove,
    .id_table = ktd202x_id,
};

static int __init ktd202x_init(void)
{
    return i2c_add_driver(&ktd202x_driver);
}

static void __exit ktd202x_exit(void)
{
    i2c_del_driver(&ktd202x_driver);
}

subsys_initcall(ktd202x_init);
module_exit(ktd202x_exit);

MODULE_AUTHOR("Xinzhu Gu <xinzhu.gu@sim.com>");
MODULE_DESCRIPTION("led expander for KTD202X");
MODULE_LICENSE("GPL");
