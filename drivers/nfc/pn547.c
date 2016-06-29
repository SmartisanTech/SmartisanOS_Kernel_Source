/*
 * Copyright (C) 2010 Trusted Logic S.A.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/i2c.h>
#include <linux/jiffies.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/platform_device.h>
#include <linux/gpio.h>
#include <linux/miscdevice.h>
#include <linux/spinlock.h>
#include <linux/nfc/pn547.h>
//#include <mach/gpio.h>
//#include <mach/irqs.h>
//#include <mach/board.h>
#include <linux/of_device.h>
#include <linux/of_gpio.h>

#define MAX_BUFFER_SIZE	512

struct pn547_dev	{
	wait_queue_head_t	read_wq;
	struct mutex		read_mutex;
	struct i2c_client	*client;
	struct miscdevice	pn547_device;
	unsigned int 		ven_gpio;
	unsigned int 		firm_gpio;
	unsigned int		irq_gpio;
	bool			irq_enabled;
	spinlock_t		irq_enabled_lock;
};


static void pn547_disable_irq(struct pn547_dev *pn547_dev)
{
	unsigned long flags;

	spin_lock_irqsave(&pn547_dev->irq_enabled_lock, flags);
	if (pn547_dev->irq_enabled) {
		disable_irq_nosync(pn547_dev->client->irq);
		pn547_dev->irq_enabled = false;
	}
	spin_unlock_irqrestore(&pn547_dev->irq_enabled_lock, flags);
}

static irqreturn_t pn547_dev_irq_handler(int irq, void *dev_id)
{
	struct pn547_dev *pn547_dev = dev_id;


	
	if (!gpio_get_value(pn547_dev->irq_gpio)) {
		return IRQ_HANDLED;
	}

	pn547_disable_irq(pn547_dev);

	/* Wake up waiting readers */
	wake_up(&pn547_dev->read_wq);

	return IRQ_HANDLED;
}

static ssize_t pn547_dev_read(struct file *filp, char __user *buf,
		size_t count, loff_t *offset)
{
	struct pn547_dev *pn547_dev = filp->private_data;
	char tmp[MAX_BUFFER_SIZE];
	int ret,i;

	if (count > MAX_BUFFER_SIZE)
		count = MAX_BUFFER_SIZE;

	pr_debug("%s : reading %zu bytes.\n", __func__, count);

	mutex_lock(&pn547_dev->read_mutex);

	if (!gpio_get_value(pn547_dev->irq_gpio)) {
		if (filp->f_flags & O_NONBLOCK) {
			ret = -EAGAIN;
			goto fail;
		}

		pn547_dev->irq_enabled = true;
		enable_irq(pn547_dev->client->irq);
		ret = wait_event_interruptible(pn547_dev->read_wq,
				gpio_get_value(pn547_dev->irq_gpio));

		pn547_disable_irq(pn547_dev);

		if (ret)
			goto fail;
	}

	/* Read data */
	ret = i2c_master_recv(pn547_dev->client, tmp, count);
	mutex_unlock(&pn547_dev->read_mutex);

	if (ret < 0) {
		pr_err("%s: i2c_master_recv returned %d\n", __func__, ret);
		return ret;
	}
	if (ret > count) {
		pr_err("%s: received too many bytes from i2c (%d)\n",
			__func__, ret);
		return -EIO;
	}
	if (copy_to_user(buf, tmp, ret)) {
		pr_err("%s : failed to copy to user space\n", __func__);
		return -EFAULT;
	}

	pr_debug("IFD->PC:");
	for(i = 0; i < ret; i++){
		pr_debug(" %02X", tmp[i]);
	}
	pr_debug("\n");

	return ret;

fail:
	mutex_unlock(&pn547_dev->read_mutex);
	return ret;
}

static ssize_t pn547_dev_write(struct file *filp, const char __user *buf,
		size_t count, loff_t *offset)
{
	struct pn547_dev  *pn547_dev;
	char tmp[MAX_BUFFER_SIZE];
	int ret,i;

	pn547_dev = filp->private_data;

	if (count > MAX_BUFFER_SIZE)
		count = MAX_BUFFER_SIZE;

	if (copy_from_user(tmp, buf, count)) {
		pr_err("%s : failed to copy from user space\n", __func__);
		return -EFAULT;
	}

	pr_debug("%s : writing %zu bytes.\n", __func__, count);
	/* Write data */
	ret = i2c_master_send(pn547_dev->client, tmp, count);
	if (ret != count) {
		pr_err("%s : i2c_master_send returned %d\n", __func__, ret);
		ret = -EIO;
		goto exit;
	}
	pr_debug("PC->IFD:");
	for(i = 0; i < count; i++){
		pr_debug(" %02X", tmp[i]);
	}
	pr_debug("\n");

exit:
	return ret;
}

static int pn547_dev_open(struct inode *inode, struct file *filp)
{
	struct pn547_dev *pn547_dev = container_of(filp->private_data,
						struct pn547_dev,
						pn547_device);

	filp->private_data = pn547_dev;

	pr_debug("%s : %d,%d\n", __func__, imajor(inode), iminor(inode));

	return 0;
}

static long pn547_dev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct pn547_dev *pn547_dev = filp->private_data;

	switch (cmd) {
	case PN547_SET_PWR:
		if (arg == 2) {
			/* power on with firmware download (requires hw reset)
			 */
			printk("%s power on with firmware\n", __func__);
			gpio_set_value(pn547_dev->ven_gpio, 0);
			gpio_set_value(pn547_dev->firm_gpio, 1);
			msleep(10);
			gpio_set_value(pn547_dev->ven_gpio, 1);
			msleep(50);
			gpio_set_value(pn547_dev->ven_gpio, 0);
			msleep(10);
		} else if (arg == 1) {
			/* power on */
			printk("%s power on\n", __func__);
			gpio_set_value(pn547_dev->firm_gpio, 0);
			gpio_set_value(pn547_dev->ven_gpio, 0);
                        enable_irq_wake (pn547_dev->client->irq);
                        
			msleep(10);
		} else  if (arg == 0) {
			/* power off */
			printk("%s power off\n", __func__);
			gpio_set_value(pn547_dev->firm_gpio, 0);
			gpio_set_value(pn547_dev->ven_gpio, 1);
                        disable_irq_wake (pn547_dev->client->irq);
			msleep(10);
		} else {
			printk("%s bad arg %lu\n", __func__, arg);
			return -EINVAL;
		}
		break;
	default:
		printk("%s bad ioctl %u\n", __func__, cmd);
		return -EINVAL;
	}

	return 0;
}

static const struct file_operations pn547_dev_fops = {
	.owner	= THIS_MODULE,
	.llseek	= no_llseek,
	.read	= pn547_dev_read,
	.write	= pn547_dev_write,
	.open	= pn547_dev_open,
	.unlocked_ioctl  = pn547_dev_ioctl,
};

static long nfc_parse_dt(struct device *dev, struct pn547_i2c_platform_data *pdata)
{
	int r = 0;
	struct device_node *np = dev->of_node;
	printk("%s 1\n", __func__);
/*
	r = of_property_read_u32(np, "reg", &pdata->reg);
	if (r)
		{
			printk("%s fail to copy reg\n", __func__);
			return -EINVAL;
		}
*/		
	/*
	r = of_property_read_u32(np, "qcom,clk-gpio", &pdata->ven_gpio);
	if (r)
		return -EINVAL;
	*/
	//printk("nfc_parse_dt firm:%d,irq:%d,ven:%d\n",pdata->firm_gpio,pdata->irq_gpio,pdata->ven_gpio);
	pdata->firm_gpio = of_get_named_gpio(np, "qcom,firm-gpio", 0);
	if (!gpio_is_valid(pdata->firm_gpio))
		{
			printk("%s fail to copy firm_gpio\n", __func__);
			return -EINVAL;
		}

	pdata->irq_gpio = of_get_named_gpio(np, "qcom,irq-gpio", 0);
	if (!gpio_is_valid(pdata->irq_gpio))
		{
			printk("%s fail to copy irq_gpio\n", __func__);
			return -EINVAL;
		}
	
	pdata->ven_gpio = of_get_named_gpio(np, "qcom,ven-gpio", 0);
	if (!gpio_is_valid(pdata->ven_gpio))
		{
			printk("%s fail to copy ven_gpio\n", __func__);
			return -EINVAL;
		}

	//printk("nfc_parse_dt firm:%d,irq:%d,ven:%d\n",pdata->firm_gpio,pdata->irq_gpio,pdata->ven_gpio);
	return r;
}

static int pn547_probe(struct i2c_client *client,
		const struct i2c_device_id *id)
{
	
	int ret;
	struct pn547_i2c_platform_data *platform_data_from_board;
	struct pn547_dev *pn547_dev;

        pr_err("pn547 enter probe\n");
	if (client->dev.of_node) {
		
		platform_data_from_board = devm_kzalloc(&client->dev,
			sizeof(struct pn547_i2c_platform_data), GFP_KERNEL);
		
		if (!platform_data_from_board) {
			dev_err(&client->dev,
			"pn547 probe: Failed to allocate memory\n");
			return -ENOMEM;
		}
		
		ret = nfc_parse_dt(&client->dev, platform_data_from_board);
		if (ret)
			return ret;
	} else {
		
		platform_data_from_board = client->dev.platform_data;
	}
		//platform_data_from_board = client->dev.platform_data;

	if (platform_data_from_board == NULL) {
		pr_err("%s : nfc probe fail\n", __func__);
		return  -ENODEV;
	}

	pr_err("nfc probe step01 is ok\n");
 
	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		pr_err("%s : need I2C_FUNC_I2C\n", __func__);
		return  -ENODEV;
	}

	printk("nfc probe step02 is ok\n");


	printk("nfc probe step03 is ok\n");

	pn547_dev = kzalloc(sizeof(*pn547_dev), GFP_KERNEL);
	if (pn547_dev == NULL) {
		dev_err(&client->dev,
				"failed to allocate memory for module data\n");
		ret = -ENOMEM;
		goto err_exit;
	}

	printk("nfc probe step04 is ok\n");

	pn547_dev->irq_gpio = platform_data_from_board->irq_gpio;
	pn547_dev->ven_gpio  = platform_data_from_board->ven_gpio;
	pn547_dev->firm_gpio  = platform_data_from_board->firm_gpio;
	pn547_dev->client   = client;

	/* init mutex and queues */
	init_waitqueue_head(&pn547_dev->read_wq);
	mutex_init(&pn547_dev->read_mutex);
	spin_lock_init(&pn547_dev->irq_enabled_lock);

	pn547_dev->pn547_device.minor = MISC_DYNAMIC_MINOR;
	//pn547_dev->pn547_device.name = PN547_NAME;
	pn547_dev->pn547_device.name = "pn544";
	pn547_dev->pn547_device.fops = &pn547_dev_fops;

	ret = misc_register(&pn547_dev->pn547_device);
	if (ret) {
		pr_err("%s : misc_register failed\n", __FILE__);
		goto err_misc_register;
	}
	printk("nfc probe step05 is ok\n");



    if(gpio_request(platform_data_from_board->irq_gpio,"nfc_int") != 0)
	{
	  printk("PN547: gpio_IRQ_request error\n");
	  goto err_irq;
	}

    if(gpio_request(platform_data_from_board->ven_gpio,"nfc_ven") != 0)
	{
	  printk("PN547: gpio_VEN_request error\n");
	  goto err_ven;
	}

    if(gpio_request(platform_data_from_board->firm_gpio,"nfc_firm") != 0)
	{
	  printk("PN547: gpio_firm_request error\n");
	  goto err_firm;
	}



 
	gpio_direction_output(platform_data_from_board->firm_gpio, 0);
	gpio_direction_output(platform_data_from_board->ven_gpio, 1);
    	//printk("nfc probe GPIO is ok\n");
	
	gpio_direction_input(platform_data_from_board->irq_gpio);
	client->irq = gpio_to_irq(platform_data_from_board->irq_gpio);
	pr_info("%s : requesting IRQ %d\n", __func__, client->irq);
	pn547_dev->irq_enabled = true;

	ret = request_irq(client->irq, pn547_dev_irq_handler,
			  IRQF_TRIGGER_HIGH, client->name, pn547_dev);
	if (ret) {
		//printk("request_irq failed\n");
		dev_err(&client->dev, "request_irq failed\n");
		goto err_request_irq_failed;
	}
	printk("nfc probe step06 is ok\n");

	pn547_disable_irq(pn547_dev);
	i2c_set_clientdata(client, pn547_dev);

	printk("nfc probe successful\n");

	return 0;

err_request_irq_failed:
	misc_deregister(&pn547_dev->pn547_device);
err_misc_register:
	mutex_destroy(&pn547_dev->read_mutex);
	kfree(pn547_dev);
err_exit:
	gpio_free(platform_data_from_board->firm_gpio);
err_ven:
	gpio_free(platform_data_from_board->ven_gpio);
err_irq:
	gpio_free(platform_data_from_board->irq_gpio);
err_firm:
    gpio_free(platform_data_from_board->firm_gpio);
	return ret;
}

static int pn547_remove(struct i2c_client *client)
{
	struct pn547_dev *pn547_dev;

	pn547_dev = i2c_get_clientdata(client);
	free_irq(client->irq, pn547_dev);
	misc_deregister(&pn547_dev->pn547_device);
	mutex_destroy(&pn547_dev->read_mutex);
	gpio_free(pn547_dev->irq_gpio);
	gpio_free(pn547_dev->ven_gpio);
	gpio_free(pn547_dev->firm_gpio);
	kfree(pn547_dev);

	return 0;
}

static const struct i2c_device_id pn547_id[] = {
	{ PN547_NAME, 0 },
	{ }
};
static struct of_device_id pn547_match_table[] = {
        { .compatible = "NXP,pn547",},
        { },
};

static struct i2c_driver pn547_driver = {
	.id_table	= pn547_id,
	.probe		= pn547_probe,
	.remove		= pn547_remove,
	.driver		= {
		.owner	= THIS_MODULE,
		.name	= PN547_NAME,
		.of_match_table = pn547_match_table,
	},
};

/*
 * module load/unload record keeping
 */

static int __init pn547_dev_init(void)
{
	pr_info("Loading pn547 driver\n");
	return i2c_add_driver(&pn547_driver);
}
module_init(pn547_dev_init);

static void __exit pn547_dev_exit(void)
{
	pr_info("Unloading pn547 driver\n");
	i2c_del_driver(&pn547_driver);
}
module_exit(pn547_dev_exit);

MODULE_AUTHOR("Ernest Li");
MODULE_DESCRIPTION("NFC PN547 driver");
MODULE_LICENSE("GPL");
