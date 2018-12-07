#include <linux/delay.h>
#include <linux/i2c.h>
#include <linux/module.h>
#include <linux/of_gpio.h>
#include <linux/gpio.h>
#include <linux/debugfs.h>

static struct {
	struct device *dev;
	int reset_gpio;
	struct dentry *dbg_dir;
	struct i2c_client *client;

}ig1600_priv;

#ifdef CONFIG_DEBUG_FS
static ssize_t ig1600_dbgfs_chipid_read(struct file *file,
                     char __user *user_buf, size_t count,
                     loff_t *ppos)
{
	char kbuf[20] = {0};
	struct device *dev = ig1600_priv.dev;
	struct i2c_client *client = ig1600_priv.client;
	u8 writebuf[4] = {0x2A, 0x00, 0x0F, 0xF0};
	u8 readbuf[4] = {0};
	int i, ret;

	struct i2c_msg msgs[] =
	{
		{
			.addr = client->addr,
			.flags = 0,
			.len = 4,
			.buf = writebuf,
		},
		{
			.addr = client->addr,
			.flags = I2C_M_RD,
			.len = 4,
			.buf = readbuf,
		},
	};

	ret = i2c_transfer(client->adapter, msgs, 2);
	if (ret < 0) {
		dev_err(dev, "i2c_transfer failed: %d\n", ret);
		return -EIO;
	}

	for (i = 0; i < 4; i++)
		ret += snprintf(kbuf+ret, sizeof(kbuf)-ret, "%02x", readbuf[3-i]);

	ret += snprintf(kbuf+ret, sizeof(kbuf)-ret, "\n");

	return simple_read_from_buffer(user_buf, count, ppos, kbuf, ret);
}

static ssize_t ig1600_dbgfs_reset_read(struct file *file,
                     char __user *user_buf, size_t count,
                     loff_t *ppos)
{
	char kbuf[20];
	int reset_gpio = ig1600_priv.reset_gpio;
	int ret;

	gpio_direction_output(reset_gpio, 0);
	msleep(10);
	gpio_direction_output(reset_gpio, 1);
	msleep(5);

	ret = snprintf(kbuf, sizeof(kbuf), "reset chip\n");
	return simple_read_from_buffer(user_buf, count, ppos, kbuf, ret);
}

static const struct file_operations ig1600_dbgfs_chipid_fops = {
    .read = ig1600_dbgfs_chipid_read,
};

static const struct file_operations ig1600_dbgfs_reset_fops = {
    .read = ig1600_dbgfs_reset_read,
};

static void ig1600_debug_init(void)
{

	ig1600_priv.dbg_dir = debugfs_create_dir("ig1600", NULL);
	debugfs_create_file("chip_id", S_IRUGO|S_IWUGO, ig1600_priv.dbg_dir,
		NULL, &ig1600_dbgfs_chipid_fops);
	debugfs_create_file("reset", S_IRUGO|S_IWUGO, ig1600_priv.dbg_dir,
		NULL, &ig1600_dbgfs_reset_fops);
}

static void ig1600_debug_remove(void)
{
	if (ig1600_priv.dbg_dir)
		debugfs_remove_recursive(ig1600_priv.dbg_dir);
}
#endif

static int ig1600_i2c_probe(struct i2c_client *i2c,
		const struct i2c_device_id *id)
{
	struct device *dev = &i2c->dev;
	struct device_node *fnode = dev->of_node;
	int reset_gpio, ret = 0;

	dev_info(dev, "%s enter.\n", __func__);

	if (!fnode) {
		dev_err(dev, "%s: ofnode is null.\n", __func__);
		return -EINVAL;
	}

	ig1600_priv.dev = dev;
	ig1600_priv.client = i2c;
	reset_gpio = of_get_named_gpio(fnode, "ig1600,reset-gpio", 0);
	if (gpio_is_valid(reset_gpio)) {
		dev_info(dev, "Get reset gpio: %d\n", reset_gpio);
		ig1600_priv.reset_gpio = reset_gpio;
	} else {
		dev_err(dev, "get reset gpio failed: %d\n", reset_gpio);
		return -EINVAL;
	}

	ret = gpio_request(ig1600_priv.reset_gpio, "ig1600_reset_gpio");
	if (ret) {
		dev_err(dev, "%s request gpio %d failed: %d\n", __func__,
			ig1600_priv.reset_gpio, ret);
		return ret;
	}

	gpio_direction_output(ig1600_priv.reset_gpio, 0);
	msleep(10);
	gpio_direction_output(ig1600_priv.reset_gpio, 1);
	msleep(5);

#ifdef CONFIG_DEBUG_FS
	ig1600_debug_init();
#endif
	return ret;
}

static int ig1600_i2c_remove(struct i2c_client *client)
{
	if (gpio_is_valid(ig1600_priv.reset_gpio))
		gpio_free(ig1600_priv.reset_gpio);

#ifdef CONFIG_DEBUG_FS
	ig1600_debug_remove();
#endif

	return 0;
}

static const struct i2c_device_id ig1600_i2c_id[] = {
	{ "ig1600", 0 },
	{ },
};

static const struct of_device_id ig1600_of_match[] = {
	{ .compatible = "ig1600", },
	{ }
};
MODULE_DEVICE_TABLE(of, ig1600_of_match);

static struct i2c_driver ig1600_i2c_driver = {
	.driver = {
		.name = "ig1600",
		.of_match_table = of_match_ptr(ig1600_of_match),
	},
	.probe	= ig1600_i2c_probe,
	.remove = ig1600_i2c_remove,
	.id_table = ig1600_i2c_id,
};

module_i2c_driver(ig1600_i2c_driver)

MODULE_LICENSE("GPL");
