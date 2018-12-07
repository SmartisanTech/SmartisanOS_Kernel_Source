/**
 * Company: Smartisan.com
 * @author HeZehua
 * @date 2017-11-19
 * @version 1.0
 * 
 * .....................我佛慈悲........................
 *                       _oo0oo_
 *                      o8888888o
 *                      88" . "88
 *                      (| -_- |)
 *                      0\  =  /0
 *                    ___/`---'\___
 *                  .' \\|     |// '.
 *                 / \\|||  :  |||// \
 *                / _||||| -卍-|||||- \
 *               |   | \\\  -  /// |   |
 *               | \_|  ''\---/''  |_/ |
 *               \  .-\__  '-'  ___/-. /
 *             ___'. .'  /--.--\  `. .'___
 *          ."" '<  `.___\_<|>_/___.' >' "".
 *         | | :  `- \`.;`\ _ /`;.`/ - ` : | |
 *         \  \ `_.   \_ __\ /__ _/   .-` /  /
 *     =====`-.____`.___ \_____/___.-`___.-'=====
 *                       `=---='
 * -卍-卍-卍-卍-卍-卍-卍-卍-卍-卍-卍-卍-卍-卍-卍-卍-卍-
 *
 *..................佛祖开光 ,永无BUG................... 
 */

#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/err.h>
#include <linux/i2c.h>
#include <linux/slab.h>
#include <linux/debugfs.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/regulator/consumer.h>
#include <linux/of_gpio.h>
#include <linux/of_device.h>
#include <linux/usb/usbpd.h>
#include "../usb/pd/usbpd.h"
#include <smartisan/hwstate.h>

#define TUSB544_DEVICE "tusb544"

/**************************************
			 gpio129  gpio122  gpio43
DVT1			0		0		0
DVT2			0		0		1
***************************************/
#define HW_VERSION_0       129    //gpio 129
#define HW_VERSION_1       122    //gpio 122
#define HW_VERSION_2       43     //gpio 43
#define GPIO_VALUE_GET(v) gpiod_get_value_cansleep(gpio_to_desc(v))
#define HW_VERSION_ID  ((GPIO_VALUE_GET(HW_VERSION_0) << 2) | (GPIO_VALUE_GET(HW_VERSION_1) << 1) | (GPIO_VALUE_GET(HW_VERSION_2)))

static int uart_state;
static int usb_orientation;
static int usb_role_mode = -1;
static int usb_typec_mode = 0;
static int redriver_power_state = 1;

typedef enum {
	TUSB544_I2C_GENERAL_REG_4 = 0x0A,
	TUSB544_I2C_GENERAL_REG_6 = 0x0C,
	TUSB544_I2C_DISPLAYPORT_REG_4 = 0x13,
} TUSB544_I2C_REG;

enum tusb544_i2c_config_dir_sel {
	TUSB544_DIR_SEL_NO_CONFIG	= -1,
	TUSB544_USB_DP_SOURCE		= 0x00,
	TUSB544_USB_DP_SINK			= 0x01,
	TUSB544_USB_CUSTOM_SOURCE	= 0x02,
	TUSB544_USB_CUSTOM_SINK		= 0x03
};

enum tusb544_i2c_config_ctl_sel {
	TUSB544_CTL_SEL_NO_CONFIG		= -1,
	TUSB544_POWER_DOWN				= 0x00,
	TUSB544_USB31					= 0x01,
	TUSB544_DP_4LANE_MODE			= 0x02,
	TUSB544_USB31_ALTERNATE_MODE	= 0x03
};

enum tusb544_i2c_aux_sbu_ovr {
	TUSB544_AUX_SBU_OVR_DISABLE  = 0x00,
	TUSB544_AUX_SBU_OVR_P1		 = 0x01,
	TUSB544_AUX_SBU_OVR_P2		 = 0x02
};

struct usb_rdv {
	struct i2c_client		*client;
	struct device		*dev;
	int			peek_poke_address;
	struct dentry		*debug_root;
	struct regulator *vddio;
	struct regulator *vccio;
	struct mutex		write_lock;
	unsigned int sw_uart_sel;
	unsigned int dp_dvdd_en;
	unsigned int aux_sel;
	unsigned int aux_oe;
	int 	probe_completed;
};

static const int reg_offset[] = {0x0A, 0x0B, 0x0C, 0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x23};
static int reg_value[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static struct usb_rdv *chip;

static int hw_version;

static int write_reg(struct i2c_client *client,
		int reg, int value)
{
	int ret;

	mutex_lock(&chip->write_lock);
	ret = i2c_smbus_write_byte_data(client, reg, value);

	if (ret < 0)
		dev_err(&client->dev, "%s: err %d\n", __func__, ret);

	mutex_unlock(&chip->write_lock);
	return ret;
}

static int read_reg(struct i2c_client *client, int reg)
{
	int ret;

	ret = i2c_smbus_read_byte_data(client, reg);

	if (ret < 0)
		dev_err(&client->dev, "%s: err %d\n", __func__, ret);

	return ret;
}

int rdv_usb3_dp_alt_mode(bool enable)
{
	u8 gen_4;

	if (!chip->probe_completed)
	{
		printk("%s: no redriver\n", __func__);
		return 0;
	}

	gen_4 = read_reg(chip->client, TUSB544_I2C_GENERAL_REG_4);
	gen_4 &= 0xfc;
	if (enable)
		gen_4 |= TUSB544_USB31_ALTERNATE_MODE;
	else
		gen_4 |= TUSB544_DP_4LANE_MODE;
	write_reg(chip->client, TUSB544_I2C_GENERAL_REG_4, gen_4);
	printk("%s: %d\n" , __func__, enable);

	return 0;
}
EXPORT_SYMBOL(rdv_usb3_dp_alt_mode);


int rdv_aux_sbu_mapping(struct usbpd_attr *attrs)
{
	u8 gen_4, gen_6, dp_4;
	u8 flip = 0, dirsel = 0, ctlsel = 0, a2s = 0;

	if (!attrs)
	{
		return 0;
	}

	/* pwr_role: 
	 * (1)PR_NONE=-1, usb disconnect
	 * (2)PR_SINK= 0, sink mode
	 * (3)PR_SRC = 1, dp/cable etc detect
	 *
	 * typec_mode: Indicates USB Type-C CC connection status
	 * atl_mode: unusefull, can be deleted
	 * */
	printk("+++++++++4, role=%d, typec_mode= %d, atl_mode=%d\n", attrs->pwr_role, attrs->typec_mode, attrs->alt_mode);
	usb_role_mode = attrs->pwr_role;
	usb_typec_mode = attrs->typec_mode;
	usb_orientation = attrs->cc_orientation;

	/*debug*/
	if (chip->peek_poke_address == 0xff) {
		printk("Warning: for debug, disable orientation switch\n");
		return 0;
	}

	if (!chip->probe_completed && (attrs->alt_mode == TUSB544_ALTERNATE_MODE_DP) && hw_version) {    //version > dvt0
		uart_state = gpio_get_value(chip->sw_uart_sel);
		if (!uart_state)  //gpio == 0, uart enabled
		{
			printk("%s: disable uart before switch SBU\n", __func__);
			gpio_set_value(chip->sw_uart_sel, 0); //disable uart before switch SBU, or sysrq signal occur
			msleep(1);
		}
		if (attrs->cc_orientation == ORIENTATION_CC1) {
			printk("%s: positive : D+,D-=HSD1+,HSD1-\n", __func__);
			gpio_set_value(chip->aux_sel, 0);
			gpio_set_value(chip->aux_oe, 0);
		}
		else if (attrs->cc_orientation == ORIENTATION_CC2) {
			printk("%s: negative : D+,D-=HSD2-,HSD2+\n", __func__);
			gpio_set_value(chip->aux_sel, 1);
			gpio_set_value(chip->aux_oe, 0);
		}

		if (!uart_state)
		{
			msleep(1);
			gpio_set_value(chip->sw_uart_sel, 1);
		}

		return 0;
	}
    else if (!chip->probe_completed)
    {
        return 0;
    }

	if (attrs->cc_orientation == ORIENTATION_CC1) {
		flip = 0; //Flipped
		a2s = TUSB544_AUX_SBU_OVR_P1;
	}
	else if (attrs->cc_orientation == ORIENTATION_CC2) {
		flip = 1; //Unflipped
		a2s = TUSB544_AUX_SBU_OVR_P2;
	}

	gen_4 = read_reg(chip->client, TUSB544_I2C_GENERAL_REG_4);
	gen_6 = read_reg(chip->client, TUSB544_I2C_GENERAL_REG_6);
	dp_4 = read_reg(chip->client, TUSB544_I2C_DISPLAYPORT_REG_4);

	switch (attrs->pwr_role) {
		case PR_SRC:
			dirsel = TUSB544_USB_DP_SOURCE;

			if (attrs->alt_mode == TUSB544_ALTERNATE_MODE_DP) {
				ctlsel = TUSB544_USB31_ALTERNATE_MODE;	
			} else if (attrs->alt_mode == TUSB544_ALTERNATE_MODE_CUSTOM) {
				ctlsel = TUSB544_USB31_ALTERNATE_MODE;	
			} else { 
				ctlsel = TUSB544_USB31;
			}

			break;
	case PR_SINK:
			dirsel = TUSB544_USB_DP_SOURCE; //Default

			if (attrs->alt_mode == TUSB544_ALTERNATE_MODE_DP) {
				ctlsel = TUSB544_USB31_ALTERNATE_MODE; //init state: 2 lane for dp, and 2 lane for usb3.0
			} else if (attrs->alt_mode == TUSB544_ALTERNATE_MODE_CUSTOM) {
				ctlsel = TUSB544_USB31_ALTERNATE_MODE; 
			} else {
				ctlsel = TUSB544_USB31;
			}

			break;
		case PR_NONE:
			dirsel = TUSB544_USB_DP_SOURCE; //Default
			ctlsel = TUSB544_POWER_DOWN;
			break;

		default: break;
	}

	gen_4 &= 0xf8;
	gen_4 |= (flip << 2) | ctlsel | 0x18;
	gen_6 &= 0xfc;
	gen_6 |= dirsel | 0x60;
	dp_4 &= 0xcf;
	dp_4 |= (a2s << 4);

	write_reg(chip->client, TUSB544_I2C_GENERAL_REG_4, gen_4);
	write_reg(chip->client, TUSB544_I2C_GENERAL_REG_6, gen_6);
	write_reg(chip->client, TUSB544_I2C_DISPLAYPORT_REG_4, dp_4);
	write_reg(chip->client, 0x10 , 0x99);
	write_reg(chip->client, 0x11 , 0x99);
	write_reg(chip->client, 0x20 , 0x22);
	write_reg(chip->client, 0x21 , 0xff);
	write_reg(chip->client, 0x22 , 0x84);
	write_reg(chip->client, 0x23 , 0x03);

	printk ("Typec orientation = %d, gen4=%#x, gen6=%#x, dp4=%#x\n", attrs->cc_orientation, gen_4, gen_6, dp_4);

	return 0;
}
EXPORT_SYMBOL(rdv_aux_sbu_mapping);

static int get_reg(void *data, u64 *val)
{
	struct usb_rdv *chip = data;
	u8 temp;

	temp = read_reg(chip->client, chip->peek_poke_address);
	if (temp < 0) {
		pr_err("Couldn't read reg %x\n",
			chip->peek_poke_address);
		return -EAGAIN;
	}
	*val = temp;
	return 0;
}

static int set_reg(void *data, u64 val)
{
	struct usb_rdv *chip = data;
	int rc;
	u8 temp;

	temp = (u8) val;
	rc = write_reg(chip->client, chip->peek_poke_address, temp);
	if (rc) {
		pr_err("Couldn't write 0x%02x to 0x%02x rc= %d\n",
			temp, chip->peek_poke_address, rc);
		return -EAGAIN;
	}
	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(poke_poke_debug_ops, get_reg, set_reg, "0x%02llx\n");

static ssize_t registers_read_file(struct file *file, char __user *user_buf,
				    size_t count, loff_t *ppos)
{
	struct usb_rdv *chip = file->private_data;
	struct i2c_client *client = chip->client;
	const int reg_offset[] = {0x0A, 0x0B, 0x0C, 0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x23};
	u8 value;
	char *buf;
	int written = 0;
	int i, ret;

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	for (i = 0; i < sizeof(reg_offset) / sizeof(reg_offset[0]); i++) {
		value = read_reg(client, reg_offset[i]);
		if (value >= 0)
			written += sprintf(buf + written, "0x%02x = 0x%02x\n", reg_offset[i], value);
	}

	ret = simple_read_from_buffer(user_buf, count, ppos,
		buf, written);

	kfree(buf);
	return ret;
}

static int registers_backup(void)
{
	int i;
	struct i2c_client *client;

	if (!chip->probe_completed)
		return 0;
	client = chip->client;

	for (i = 0; i < sizeof(reg_offset) / sizeof(reg_offset[0]); i++) {
		reg_value[i] = read_reg(client, reg_offset[i]);
		if (reg_value[i] < 0)
			pr_err("%s: reg[%d] read fail\n", __func__, i);
	}

	return 0;
}

static int registers_restore(void)
{
	int i, ret;
	struct i2c_client *client;

	if (!chip->probe_completed)
		return 0;
	client = chip->client;

	msleep(2);
	for (i = 0; i < sizeof(reg_offset) / sizeof(reg_offset[0]); i++) {
		ret = write_reg(client, reg_offset[i] , reg_value[i]);
		if (ret)
		{
			pr_err("%s: reg[%d] restore fail, try again\n", __func__, i);
			msleep(2);
			if (write_reg(client, reg_offset[i] , reg_value[i]))
				pr_err("%s: reg[%d] restore fail\n", __func__, i);
		}
	}

	return 0;
}

static const struct file_operations registers_debug_ops = {
	.open = simple_open,
	.read = registers_read_file,
	.llseek = default_llseek,
};

static int create_debugfs_entries(struct usb_rdv *chip)
{
	struct dentry *ent;

	chip->debug_root = debugfs_create_dir("tusb544", NULL);
	if (!chip->debug_root) {
		pr_err("Couldn't create debug dir\n");
	} else {
		ent = debugfs_create_x32("address", S_IFREG | 0644,
					  chip->debug_root,
					  &(chip->peek_poke_address));
		if (!ent)
			pr_err("Couldn't create address debug file\n");

		ent = debugfs_create_file("data", S_IFREG | 0644,
					  chip->debug_root, chip,
					  &poke_poke_debug_ops);
		if (!ent)
			pr_err("Couldn't create data debug file\n");

		ent = debugfs_create_file("registers", S_IFREG | 0644,
					  chip->debug_root, chip, &registers_debug_ops);
		if (!ent)
			pr_err("Couldn't create registers debug file\n");
	}

	return 0;
}
#if 0
static int rdv_regulator_init(struct usb_rdv *chip)
{
	struct regulator *reg;
	struct i2c_client *client = chip->client;
	int  ret = 0;

		printk("----------2\n");
	reg = devm_regulator_get(&client->dev, "vddio");
	if (IS_ERR(reg)) {
		printk("----------1\n");
		ret = PTR_ERR(reg);
		pr_err("failed to get rdv regulator: (%d)\n",
			ret);
		return ret;
	}

	chip->regs[0] = reg;
#if 0
	reg = devm_regulator_get(&client->dev, "vddio19");
	if (IS_ERR(reg)) {
		ret = PTR_ERR(reg);
		pr_err("failed to get rdv regulator: (%d)\n",
			ret);
		return ret;
	}

	chip->regs[1] = reg;

	for (i = 0; i < 2; i++) {
		ret = regulator_enable(chip->regs[i]);
		if (ret)
			pr_err("failed to enable regulator: supply-%d (%d)\n",
				i, ret);
	}
	
#endif
	return 0;
}
#endif

static int rdv_parse_dt(struct device *dev, struct usb_rdv *chip)
{
	int r = 0;
	struct device_node *np = dev->of_node;

if (hw_version > 0)
{
	chip->aux_sel = of_get_named_gpio(np, "ti,aux-sel", 0);
	r = gpio_request(chip->aux_sel, "sw_aux_sel");
	if (r) {
		printk("sbu switch sel request fail \n");
	}
	gpio_direction_output(chip->aux_sel, 1);

	chip->aux_oe = of_get_named_gpio(np, "ti,aux-oe", 0);
	r = gpio_request(chip->aux_oe, "sw_aux_oe");
	if (r) {
		printk("sbu switch oe request fail \n");
	}
	gpio_direction_output(chip->aux_oe, 1);
}

	chip->sw_uart_sel = of_get_named_gpio(np, "ti,uart-sel", 0);

	chip->dp_dvdd_en = of_get_named_gpio(np, "ti,dvdd-en", 0);
	if (gpio_is_valid(chip->dp_dvdd_en)) {
		r = gpio_request(chip->dp_dvdd_en, "dp_dvdd_en");
		if (r) {
			dev_err(dev,
			"%s: unable to request tusb544 enable gpio [%d]\n",
				__func__,
				chip->dp_dvdd_en);
			goto err_mem;
		}
		r = gpio_direction_output(chip->dp_dvdd_en, 1);
		if (r) {
			dev_err(dev,
				"%s: unable to set direction for tusb544 enable gpio [%d]\n",
					__func__,
					chip->dp_dvdd_en);
			goto err_free_dvdd;
		}
	}

	return 0;
err_free_dvdd:
	gpio_free(chip->dp_dvdd_en);

err_mem:
	dev_err(dev,
	"%s: failed to get uart_sel_gpio, check hardware\n",
		 __func__);
	return r;
}

static int rdv_probe(struct i2c_client *client,
			const struct i2c_device_id *id)
{
	int ret;
	struct i2c_adapter *adapter = to_i2c_adapter(client->dev.parent);
	pr_info("tusb544 probe ++\n");

	hw_version = HW_VERSION_ID;
	if (!i2c_check_functionality(adapter, I2C_FUNC_SMBUS_BYTE_DATA))
		return -EIO;

	chip = kzalloc(sizeof(struct usb_rdv), GFP_KERNEL);	
	if (!chip) {
		dev_err(&client->dev, "failed to allocate driver data\n");
		return -ENOMEM;
	}

	chip->client = client;
	i2c_set_clientdata(client, chip);

	ret = rdv_parse_dt(&client->dev, chip);
	if (ret){
		dev_err(&client->dev,
			"failed to enable uart sel gpio: %d\n", ret);
		goto error_ret;
	}

	if (gpio_is_valid(chip->dp_dvdd_en)) {
		gpio_set_value(chip->dp_dvdd_en, 1);
		msleep(5);
	}

	chip->vccio = devm_regulator_get(&client->dev, "vccio");
	if (IS_ERR(chip->vccio)) {
		ret = PTR_ERR(chip->vccio);
		if (ret != -EPROBE_DEFER)
			dev_err(&client->dev,
				"Failed to get 'avdd' regulator: %d\n", ret);
	}
	else
	{
		ret = regulator_enable(chip->vccio);
		if (ret) {
			dev_err(&client->dev,
					"failed to enable avdd regulator: %d\n", ret);
		}
		msleep(10);
	}

	chip->vddio = devm_regulator_get(&client->dev, "vddio");
	if (IS_ERR(chip->vddio)) {
		ret = PTR_ERR(chip->vddio);
		if (ret != -EPROBE_DEFER)
			dev_err(&client->dev,
				"Failed to get 'avdd' regulator: %d\n", ret);
	}
	else
	{
		ret = regulator_enable(chip->vddio);
		if (ret) {
			dev_err(&client->dev,
					"failed to enable avdd regulator: %d\n", ret);
			goto ret_enb_vdd;
		}
		msleep(10); 
	}

	ret = read_reg(client, 0x0);
	if (ret < 0)
	{
		smartisan_hwstate_set("usb_redriver", "fail");
		goto ret_enb_vdd;
	}
	else
		smartisan_hwstate_set("usb_redriver", "ok");

	mutex_init(&chip->write_lock);
	write_reg(client, 0x0a , 0x18); //Default to disable.
	write_reg(client, 0x0c , 0x60);
	write_reg(client, 0x10 , 0x99);
	write_reg(client, 0x11 , 0x99);
	write_reg(client, 0x13 , 0x00);
	write_reg(client, 0x20 , 0x22);
	write_reg(client, 0x21 , 0xff);
	write_reg(client, 0x22 , 0x84);
	write_reg(client, 0x23 , 0x03);

	create_debugfs_entries(chip);

	chip->probe_completed = 1;
	
	pr_info("tusb544 successfully probed.\n");
	return 0;

ret_enb_vdd:
	if (!IS_ERR(chip->vccio))
	       regulator_disable(chip->vccio);
	if (!IS_ERR(chip->vddio))
	       regulator_disable(chip->vddio);
	/*
	if (gpio_is_valid(chip->dp_dvdd_en)) {
		gpio_set_value(chip->dp_dvdd_en, 0);
		gpio_free(chip->dp_dvdd_en);
	} dvt2 supply power to sbu switch*/
error_ret:
	//kfree(chip);
	//chip = NULL;
	chip->probe_completed = 0;
	
	return 0;
}

static int rdv_remove(struct i2c_client *client)
{
	struct usb_rdv *chip = i2c_get_clientdata(client);

	debugfs_remove_recursive(chip->debug_root);
	kfree(chip);

	return 0;
}

static const struct of_device_id msm_match_table[] = {
	{.compatible = "ti,re-driver"},
	{}
};

MODULE_DEVICE_TABLE(of, msm_match_table);

static const struct i2c_device_id rdv_id[] = {
	{TUSB544_DEVICE, 0},
	{}
};

static int rdv_suspend(struct device *dev) {
	pr_info("suspend re,driver!\n");
	if ((usb_role_mode != PR_NONE) || (usb_typec_mode > 0))   //if usb/dp/cable/audio_adepter etc connected, do not power off
	{
		pr_info("suspend re,driver: alt_mode, do not power down!\n");
		return 0;
	}
	redriver_power_state = 0;
	if (!chip->probe_completed)
	{
		if (gpio_is_valid(chip->dp_dvdd_en)) {
			gpio_set_value(chip->dp_dvdd_en, 0);
		}
		if (gpio_is_valid(chip->aux_sel)) {
			gpio_set_value(chip->aux_sel, 0);
			gpio_direction_input(chip->aux_sel);
		}
		if (gpio_is_valid(chip->aux_oe)) {
			gpio_set_value(chip->aux_oe, 0);
			gpio_direction_input(chip->aux_oe);
		}
		pr_info("suspend re,driver: no redriver hardware, power off sbu switch!\n");
		return 0;
	}
	registers_backup();
	if (!IS_ERR(chip->vccio))
	       regulator_disable(chip->vccio);
	if (!IS_ERR(chip->vddio))
	       regulator_disable(chip->vddio);
	if (gpio_is_valid(chip->dp_dvdd_en)) {
		gpio_set_value(chip->dp_dvdd_en, 0);
	}
	pr_info("suspend re,driver done!\n");
	return 0;
}

static int rdv_resume(struct device *dev) {
	int ret = 0;
	pr_info("resume re,driver!\n");
	if (redriver_power_state == 1)
	{
		pr_info("resume re,driver: alredy power on!\n");
		return 0;
	}
	else
		redriver_power_state = 1;

	if (!chip->probe_completed)
	{
		if (gpio_is_valid(chip->dp_dvdd_en)) {
			gpio_set_value(chip->dp_dvdd_en, 1);
		}
		if (usb_orientation == ORIENTATION_CC1)
		{
			if (gpio_is_valid(chip->aux_sel)) {
				gpio_direction_output(chip->aux_sel, 0);
				gpio_set_value(chip->aux_sel, 0);
			}
			if (gpio_is_valid(chip->aux_oe)) {
				gpio_direction_output(chip->aux_oe, 0);
				gpio_set_value(chip->aux_oe, 0);
			}
		}
		else
		{
			if (gpio_is_valid(chip->aux_sel)) {
				gpio_direction_output(chip->aux_sel, 1);
				gpio_set_value(chip->aux_sel, 1);
			}
			if (gpio_is_valid(chip->aux_oe)) {
				gpio_direction_output(chip->aux_oe, 0);
				gpio_set_value(chip->aux_oe, 0);
			}
		}
		return 0;
	}

	if (gpio_is_valid(chip->dp_dvdd_en)) {
		gpio_set_value(chip->dp_dvdd_en, 1);
	}
	if (!IS_ERR(chip->vddio))
	{
		ret = regulator_enable(chip->vddio);
		if (ret) {
			pr_err("failed to enable avdd regulator: %d\n", ret);
		}
	}
	if (!IS_ERR(chip->vccio))
	{
		ret = regulator_enable(chip->vccio);
		if (ret) {
			pr_err("failed to enable avdd regulator: %d\n", ret);
		}
	}
	registers_restore();  //todo: here need to refine, to reduce resume time
	pr_info("resume re,driver done!\n");
	return 0;
}

static const struct dev_pm_ops rdv_pm_ops = {
	.suspend = rdv_suspend,
	.resume = rdv_resume,
};

static struct i2c_driver rdv = {
	.id_table = rdv_id,
	.probe = rdv_probe,
	.remove = rdv_remove,
	.driver = {
		.owner = THIS_MODULE,
		.name = TUSB544_DEVICE,
		.of_match_table = msm_match_table,
		.pm = &rdv_pm_ops,
	},
};

/*
 * module load/unload record keeping
 */
static int __init rdv_dev_init(void)
{
	pr_info("tusb544 init ++\n");
	return i2c_add_driver(&rdv);
}
module_init(rdv_dev_init);

static void __exit rdv_dev_exit(void)
{
	i2c_del_driver(&rdv);
}
module_exit(rdv_dev_exit);
