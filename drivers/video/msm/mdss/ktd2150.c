#include <linux/module.h>
#include <linux/init.h>
#include <linux/i2c.h>
#include <linux/input.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/irq.h>
#include <linux/regulator/consumer.h>
#include <linux/of_gpio.h>
#include <linux/gpio.h>

#ifdef CONFIG_HAS_EARLYSUSPEND
#include <linux/earlysuspend.h>
#endif

#ifdef __KERNEL__
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/unistd.h>
#include <linux/types.h>
#include <linux/string.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#endif

#ifdef KTD_DEBUG
#define ktd_printk(fmt,args...)  printk(fmt,##args)
#else
#define ktd_printk(fmt,args...)  do{}while(0)
#endif

struct ktd215x{
	struct i2c_client *client;
	int enp_gpio;
	int enn_gpio;
};

#define KTD_I2C_READ 0
#define KTD_DEBUG 0

#define KTD_SLAVE_ID 0x3E
#define KTD_REG_VPOS 0x00 //Positive voltage output register.Default value 0x0A.
#define KTD_REG_VNEG 0x01 //Negative voltage output register.Default value 0x0A.
#define KTD_REG_CONTROL 0x03 //Control register 1

#define KTD_ENABLE    0

/*************ktd2150*****************/
#define OUT_P_VALUE_0    0xD0  //5.8v  
#define OUT_N_VALUE_0    0xC0  //-5.6v

/*************ktd2151*****************/
#define OUT_P_VALUE_1    0x12  //5.8v
#define OUT_N_VALUE_1    0x10  //-5.6v

static u8 OUT_P_VALUE = 0x0;
static u8 OUT_N_VALUE = 0x0;

static struct ktd215x *ktd_data;

extern u32 socinfo_get_platform_version(void);
static u32 PLATFORM_VER = 0x0;

static int ktd_i2c_write(struct i2c_client *client, u8 *wbuf, int wlen)
{
	int ret;
	
	struct i2c_msg msgs[] = {
		{
			.addr = client->addr,
			.flags = 0,
			.len = wlen,
			.buf = wbuf,
		},
	};
	ret = i2c_transfer(client->adapter, msgs, 1);

	return ret;
}

static int ktd_reg_write(struct i2c_client *client, u8 addr, u8 val)
{
	char buf[2] = {0};
	buf[0] = addr;
	buf[1] = val;
	
	return ktd_i2c_write(client,buf,sizeof(buf));
}
#if KTD_I2C_READ
static int ktd_i2c_read(struct i2c_client *client, char *writebuf, 
				int writelen, char *readbuf, int readlen)
{
	int ret;
	struct i2c_msg msgs[] = {
		{
			 .addr = client->addr,
			 .flags = 0,
			 .len = writelen,
			 .buf = writebuf,
		 },
		{
			 .addr = client->addr,
			 .flags = I2C_M_RD,
			 .len = readlen,
			 .buf = readbuf,
		 },
	};
	ret = i2c_transfer(client->adapter, msgs, 2);
	if (ret < 0)
		dev_err(&client->dev, "%s: i2c read error.\n",
			__func__);
	return ret;		
}
#endif
void ktd2150_enp_enable(int enp)
{    
	gpio_direction_output(ktd_data->enp_gpio, 1);
	if (enp){
		gpio_set_value(ktd_data->enp_gpio,1);
	
	}else{
		gpio_set_value(ktd_data->enp_gpio,0);
	}
}

void ktd2150_enn_enable(int enn)
{    
	gpio_direction_output(ktd_data->enn_gpio, 1);
	if (enn){
		gpio_set_value(ktd_data->enn_gpio,1);
	}else{
		gpio_set_value(ktd_data->enn_gpio,0);
	}
}


static void ktd2150_P_output(u8 value)
{
#if KTD_I2C_READ	
	u8 readdata[1];
#endif
	ktd2150_enp_enable(1);
	ktd_reg_write(ktd_data->client, KTD_REG_VPOS,value);
	//printk("@@ ktd slave addr: 0x%x",ktd_data->client->addr);
#if KTD_I2C_READ	
	ktd_i2c_read(ktd_data->client, KTD_REG_VPOS,value,readdata,1);
	ktd_printk("@@ read VPOS:%x\n",readdata[0]);
#endif
}

static void ktd2150_N_output(u8 value)
{
	ktd2150_enn_enable(1);
	ktd_reg_write(ktd_data->client,KTD_REG_VNEG,value);
}

void ktd2150_powerfor_lcd(int enable)
{
	if (ktd_data == NULL)
		return;

	if (enable){
		ktd2150_P_output(OUT_P_VALUE);
		mdelay(5);
		ktd2150_N_output(OUT_N_VALUE);
	}
	else{
		ktd2150_enn_enable(0);
		mdelay(5);
		ktd2150_enp_enable(0);
	}
}
EXPORT_SYMBOL_GPL(ktd2150_powerfor_lcd);

static int ktd251x_parse_dt(struct device *dev, struct ktd215x *pdata){

	int ret = 0;
	struct device_node *np = dev->of_node;
	//printk("%s \n",__func__);
	pdata->enp_gpio= of_get_named_gpio(np,"ktd,enp-gpio", 0);
	//printk("enp-gpio:%d\n",pdata->enp_gpio);
	if (!gpio_is_valid(pdata->enp_gpio)){
		pr_err("%s:%d, enp gpio not specified\n",__func__,__LINE__);
		ret = -1;
	}
	ret = gpio_request(pdata->enp_gpio, "enp_gpio");
	if (ret) {
		pr_err("request enp_gpio failed, rc=%d\n",
			ret);
	}

	pdata->enn_gpio= of_get_named_gpio(np,"ktd,enn-gpio", 0);
	if (!gpio_is_valid(pdata->enn_gpio)){
		pr_err("%s:%d, enn gpio not specified\n",__func__,__LINE__);
		ret = -2;
	}
	printk("enn-gpio:%d\n",pdata->enn_gpio);

	ret= gpio_request(pdata->enn_gpio, "enn_gpio");
	if (ret) {
		pr_err("request enn_gpio failed, rc=%d\n",
			ret);
	}

	return ret;
}

static int ktd215x_probe(struct i2c_client *client,
		const struct i2c_device_id *id)
{
	int err = 0;
	
	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		dev_err(&client->dev, "i2c_check_functionality error\n");
		err = -EPERM;
		goto exit;
	}
	if (client->dev.of_node) {
		ktd_data = devm_kzalloc(&client->dev,
			sizeof(*ktd_data), GFP_KERNEL);
		if (!ktd_data) {
			dev_err(&client->dev, "Failed to allcated memory\n");
			err = -ENOMEM;
			goto exit;
		}
		err = ktd251x_parse_dt(&client->dev, ktd_data);
		if (err) {
			dev_err(&client->dev, "Failed to parse device tree\n");
			err = -EINVAL;
			goto pdata_free_exit;
		}
	} else {
		ktd_data = client->dev.platform_data;
		dev_err(&client->dev, "use  platform data\n");
	}

	if (!ktd_data) {
		dev_err(&client->dev, "Cannot get device platform data\n");
		err = -EINVAL;
		goto kfree_exit;
	}

	ktd_data->client = client;
	
	PLATFORM_VER = socinfo_get_platform_version();
	PLATFORM_VER = (PLATFORM_VER >> 8) & 0xFF;
	
	if (PLATFORM_VER == 0x1){
		OUT_P_VALUE = OUT_P_VALUE_0;
		OUT_N_VALUE = OUT_N_VALUE_0;
	}
	else{
		OUT_P_VALUE = OUT_P_VALUE_1;
		OUT_N_VALUE = OUT_N_VALUE_1;
	}
	//printk("@@ ktd215x_probe sucess plat_version =%x\n",PLATFORM_VER);
	return 0;
pdata_free_exit:
	if (ktd_data && (client->dev.of_node))
		devm_kfree(&client->dev, ktd_data);
	ktd_data = NULL;
kfree_exit:
	kfree(ktd_data);	
exit:
	return err;	
}

static int ktd215x_remove(struct i2c_client *client){
	return 0;
}

static const struct i2c_device_id ktd2150_id[] = {
	{ "ktd2150", 0 },
	{ }
};

MODULE_DEVICE_TABLE(i2c, ktd2150_id);

static struct of_device_id ktd2150_of_match[] = {
	{ .compatible = "kinetic,ktd2150",},
	{ },
};

static struct i2c_driver ktd215x_driver = {
	.driver = {
		.name = "ktd2150",
		.owner = THIS_MODULE,
		.of_match_table = ktd2150_of_match,
	},
	.probe = ktd215x_probe,
	.remove = ktd215x_remove,
	.id_table = ktd2150_id,
};

static int __init ktd215x_init(void)
{
	return i2c_add_driver(&ktd215x_driver);
}
static void __exit ktd215x_exit(void)
{
	//ktd_printk(KERN_INFO "@@ ktd215x_exit");
	return i2c_del_driver(&ktd215x_driver);
}

module_init(ktd215x_init);
module_exit(ktd215x_exit);

MODULE_AUTHOR("kevin@sim");
MODULE_DESCRIPTION("ktd215x driver");
MODULE_LICENSE("GPL");
