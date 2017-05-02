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
//#include <linux/nfc/pn547.h>
//arm64 has no these header files
//#include <mach/gpio.h>
//#include <mach/irqs.h>
//#include <mach/board.h>
#include <linux/of_device.h>
#include <linux/of_gpio.h>


/*
 * PN547 power control via ioctl
 * PN547_SET_PWR(0): power off
 * PN547_SET_PWR(1): power on
 * PN547_SET_PWR(2): reset and power on with firmware download enabled
 */

#define PN547_MAGIC     0xE9
//#define PN547_SET_PWR   _IOW(PN547_MAGIC, 0x01, unsigned int)
#define PN544_SET_PWR   _IOW(PN547_MAGIC, 0x01, unsigned int)

//#define PN547_NAME "pn547"
#define PN547_NAME "nq-nci"
#define MAX_BUFFER_SIZE	512

static int debug_mask_enable = 0;
module_param_named(debug_mask_enable, debug_mask_enable, int, S_IRUGO | S_IWUSR | S_IWGRP);

struct pn547_i2c_platform_data
{
        unsigned int irq_gpio;
        unsigned int ven_gpio;
        unsigned int firm_gpio;
        unsigned int clkreq_gpio;
        const char *clk_src_name;
};

struct pn547_dev
{
	wait_queue_head_t	read_wq;
	struct mutex		read_mutex;
	struct i2c_client	*client;
	struct miscdevice	pn547_device;

	unsigned int 		ven_gpio;
	unsigned int 		firm_gpio;
	unsigned int		irq_gpio;
	unsigned int		clkreq_gpio;

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

static void pn547_enable_irq(struct pn547_dev *pn547_dev)
{
	unsigned long flags;
        spin_lock_irqsave(&pn547_dev->irq_enabled_lock, flags);
        if (!pn547_dev->irq_enabled) {
		pn547_dev->irq_enabled = true;
                enable_irq(pn547_dev->client->irq);
        }
        spin_unlock_irqrestore(&pn547_dev->irq_enabled_lock, flags);
}

static irqreturn_t pn547_dev_irq_handler(int irq, void *dev_id)
{
	struct pn547_dev *pn547_dev = dev_id;

    if(debug_mask_enable ==1)
        printk("---nxp pn547_dev_irq_handler\n");
	if (!gpio_get_value(pn547_dev->irq_gpio)) {
		pr_err("%s : wrong irq\n", __func__);
		return IRQ_HANDLED;
	}

	pn547_disable_irq(pn547_dev);

	/* Wake up waiting readers */
	wake_up(&pn547_dev->read_wq);

	return IRQ_HANDLED;
}

static ssize_t pn547_dev_read(struct file *filp, char __user *buf, size_t count, loff_t *offset)
{
	struct pn547_dev *pn547_dev = filp->private_data;
	char tmp[MAX_BUFFER_SIZE];
	int ret,i;
    if(debug_mask_enable == 1)
        printk("---nxp pn547_dev_read\n");
	if (count > MAX_BUFFER_SIZE)
		count = MAX_BUFFER_SIZE;

    /*
	pr_info("%s : reading %zu bytes,gpio 0x%x.\n", __func__, count,gpio_get_value(pn547_dev->irq_gpio);
    */
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

		if (ret){
			pr_err("%s:wait_event_interruptible error ret = %d\n", __func__, ret);
			goto fail;
		}
	}

	/* Read data */
	ret = i2c_master_recv(pn547_dev->client, tmp, count);
	mutex_unlock(&pn547_dev->read_mutex);

	if (ret < 0) {
		pr_err("%s: i2c_master_recv returned %d\n", __func__, ret);
		goto fail;
	}
	if (ret > count) {
		pr_err("%s: received too many bytes from i2c (%d)\n",
			__func__, ret);
		goto fail;
	}
	if (copy_to_user(buf, tmp, ret)) {
		pr_err("%s : failed to copy to user space\n", __func__);
		goto fail;
	}

    if(debug_mask_enable == 1) {
    	pr_err("IFD->PC:");
    	for(i = 0; i < ret; i++){
    		pr_err(" %02X", tmp[i]);
    	}
    	pr_err("\n");
    }
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

	pr_err("%s : writing %zu bytes.\n", __func__, count);
	/* Write data */
	ret = i2c_master_send(pn547_dev->client, tmp, count);
	if (ret != count) {
		pr_err("%s : i2c_master_send returned %d\n", __func__, ret);
		//ret = -EIO;
		goto exit;
	}
    if(debug_mask_enable == 1) {
	    pr_err("PC->IFD:");
	    for(i = 0; i < count; i++){
		    pr_err(" %02X", tmp[i]);
	    }
	    pr_err("\n");
    }
exit:
	return ret;
}

static int pn547_dev_open(struct inode *inode, struct file *filp)
{
	struct pn547_dev *pn547_dev = container_of(filp->private_data, struct pn547_dev, pn547_device);

	filp->private_data = pn547_dev;

        /*add*/
        pn547_enable_irq(pn547_dev);

	dev_dbg (&pn547_dev->client->dev, "%s: %d,%d\n", __func__, imajor(inode), iminor(inode));

	return 0;
}

static long pn547_dev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct pn547_dev *pn547_dev = filp->private_data;

    if(debug_mask_enable == 1)
        printk("---nxp pn547_dev_ioctl\n");
	switch (cmd) {
	case PN544_SET_PWR:
//	case PN547_SET_PWR:
		if (arg == 0) {
			/* power off */
			//printk("%s power off\n", __func__);
			pr_err("%s power off\n", __func__);

                        /*ADD: reset, disable interrupt*/
                        pn547_disable_irq(pn547_dev);

                        dev_dbg(&pn547_dev->client->dev, "%s: gpio_set_value disable\n", __func__);
                        if(gpio_is_valid(pn547_dev->firm_gpio))
                               gpio_set_value(pn547_dev->firm_gpio, 0);

			gpio_set_value(pn547_dev->ven_gpio, 0);

			msleep(40);

		} else if (arg == 1) {
			/* power on */
			//printk("%s power on\n", __func__);
			pr_err("%s power on\n", __func__);
                        if(gpio_is_valid(pn547_dev->firm_gpio))
      gpio_set_value(pn547_dev->firm_gpio, 0);
			gpio_set_value(pn547_dev->ven_gpio, 1);
			/*ADD ???*/
                        pn547_disable_irq(pn547_dev);

			msleep(40);

		} else  if (arg == 2) {

			/* power on with firmware download (requires hw reset)
			 */
			//printk("%s power on with firmware\n", __func__);
			pr_err("%s power on with firmware\n", __func__);
			gpio_set_value(pn547_dev->ven_gpio, 1);
			//msleep(10);
			msleep(40);
                        if(gpio_is_valid(pn547_dev->firm_gpio))
                              gpio_set_value(pn547_dev->firm_gpio, 1);
			//msleep(10);
			msleep(40);
			gpio_set_value(pn547_dev->ven_gpio, 0);
			msleep(50);
			gpio_set_value(pn547_dev->ven_gpio, 1);
			//msleep(10);
			msleep(40);

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
        .compat_ioctl = pn547_dev_ioctl,

};

static long nfc_parse_dt(struct device *dev, struct pn547_i2c_platform_data *pdata)
{
	int r = 0;
	struct device_node *np = dev->of_node;
    if(debug_mask_enable == 1)
        printk("---nxp nfc_parse_dt\n");
        pdata->ven_gpio = of_get_named_gpio(np, "qcom,nq-ven", 0);
        if (!gpio_is_valid(pdata->ven_gpio))
	{
              dev_err(dev, "%s ven_gpio is not valid\n", __func__);
              return -EINVAL;
	}
    if(debug_mask_enable == 1)
        printk("---nxp nfc_parse_dt qcom,nq-ven=%d\n",pdata->ven_gpio);

	pdata->irq_gpio = of_get_named_gpio(np, "qcom,nq-irq", 0);
	if (!gpio_is_valid(pdata->irq_gpio))
	{
              dev_err(dev, "%s irq_gpio is not valid\n", __func__);
              return -EINVAL;
	}
    if(debug_mask_enable == 1)
        printk("---nxp nfc_parse_dt qcom,nq-irq=%d\n",pdata->irq_gpio);

	pdata->firm_gpio = of_get_named_gpio(np, "qcom,nq-firm", 0);
	if (!gpio_is_valid(pdata->firm_gpio))
	{
              dev_err(dev, "%s firm_gpio is not valid\n", __func__);
              return -EINVAL;
    }
    if(debug_mask_enable == 1)
        printk("---nxp nfc_parse_dt qcom,nq-firm=%d\n",pdata->firm_gpio);

        pdata->clkreq_gpio = of_get_named_gpio(np, "qcom,nq-clkreq", 0);
/*
	if (!gpio_is_valid(pdata->clkreq_gpio))
	{
              dev_err(dev, "%s clkreq_gpio is not valid\n", __func__);
              return -EINVAL;
        }
*/

        r = of_property_read_string(np, "clock-names", &pdata->clk_src_name);
        if (r)
               return -EINVAL;

        return r;
}

static int pn547_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
	
	int ret;
        int irqn = 0;
	struct pn547_i2c_platform_data *platform_data;
	struct pn547_dev *pn547_dev;
   // struct clk *nfc_clk;
    
    if(debug_mask_enable == 1)
        printk("---nxp pn547_probe\n");
        dev_dbg(&client->dev, "%s: enter\n", __func__);
	if (client->dev.of_node) {
		
		platform_data = devm_kzalloc(&client->dev, sizeof(struct pn547_i2c_platform_data), GFP_KERNEL);
		
		if (!platform_data) {
			dev_err(&client->dev, "pn547 probe: Failed to allocate memory\n");
			return -ENOMEM;
		}
		
		ret = nfc_parse_dt(&client->dev, platform_data);
		if (ret)
			return ret;
	} else {
		
		platform_data = client->dev.platform_data;
	}

        dev_dbg(&client->dev, "%s, inside nfc-nci flags = %x\n", __func__, client->flags);

	if (platform_data == NULL) {
		dev_err(&client->dev, "%s: platform_data failed\n", __func__);
		return  -ENODEV;
	}
 
	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		dev_err(&client->dev, "%s : need I2C_FUNC_I2C\n", __func__);
		return  -ENODEV;
	}

	pn547_dev = kzalloc(sizeof(*pn547_dev), GFP_KERNEL);
	if (pn547_dev == NULL) {
		dev_err(&client->dev, "%s: failed to allocate memory for pn548_dev\n", __func__);
		return -ENOMEM;
	}

	pn547_dev->client = client;


        /*en_gpio*/
        if (gpio_is_valid(platform_data->ven_gpio))
        {
             ret = gpio_request(platform_data->ven_gpio, "nfc_ven");
             if (ret)
             {
                   dev_err(&client->dev, "%s: unable to request gpio [%d]\n", __func__, platform_data->ven_gpio);

             	   goto err_free_dev;
             }
             /*why not 1 ???*/
             ret = gpio_direction_output(platform_data->ven_gpio, 0);
             if (ret)
             {
                  dev_err(&client->dev, "%s: unable to set direction for gpio [%d]\n", __func__, platform_data->ven_gpio);
                  goto err_en_gpio;
             }

        }else{
             dev_err(&client->dev, "%s: ven_gpio not provided\n", __func__);
             goto err_free_dev;
        }

        /*irq_gpio*/
        if (gpio_is_valid(platform_data->irq_gpio))
        {
             ret = gpio_request(platform_data->irq_gpio, "nfc_int");
             if (ret)
             {
                   dev_err(&client->dev, "%s: unable to request gpio [%d]\n", __func__, platform_data->ven_gpio);
                   goto err_en_gpio;
             }
             ret = gpio_direction_input(platform_data->irq_gpio);
             if (ret) {
                   dev_err(&client->dev, "%s: unable to set direction for gpio [%d]\n", __func__, platform_data->irq_gpio);
                   goto err_irq;
             }
             
             irqn = gpio_to_irq(platform_data->irq_gpio);
             if (irqn < 0){
                   ret = irqn;
                   goto err_irq;
             }
             
             client->irq = irqn;

        }else{
             dev_err(&client->dev, "%s: ven_gpio not provided\n", __func__);
             goto err_en_gpio;
        }

        /*firm_gpio*/
        if(gpio_is_valid(platform_data->firm_gpio))
	{
              ret = gpio_request(platform_data->firm_gpio,"nfc_firm");
              if (ret)
              {
                    dev_err(&client->dev, "%s: unable to request gpio [%d]\n", __func__, platform_data->firm_gpio);
                    goto err_irq;
              }
              ret = gpio_direction_output(platform_data->firm_gpio, 0);
              if (ret)
              {
                    dev_err(&client->dev, "%s: cannot set direction for gpio [%d]\n", __func__, platform_data->firm_gpio);
                    goto err_firm_gpio;
              }
	}else{
              dev_err(&client->dev, "%s: firm gpio not provided\n", __func__);
              goto err_irq;
        }
 
        /*clkreq_gpio*/
        if (gpio_is_valid(platform_data->clkreq_gpio))
        {
            ret = gpio_request(platform_data->clkreq_gpio, "nfc_clkreq_gpio");
            if (ret)
            {
                  dev_err(&client->dev, "%s: unable to request gpio [%d]\n", __func__, platform_data->clkreq_gpio);
                  goto err_firm_gpio;
            }
            ret = gpio_direction_input(platform_data->clkreq_gpio);
            if (ret)
            {
                dev_err(&client->dev, "%s: cannot set direction for gpio [%d]\n", __func__, platform_data->clkreq_gpio);
                goto err_clkreq_gpio;
            }
            pn547_dev->clkreq_gpio = platform_data->clkreq_gpio;

        }/*else{
              dev_err(&client->dev, "%s: clkreq gpio not provided\n", __func__);
              goto err_firm_gpio;
        }*/

        pn547_dev->irq_gpio = platform_data->irq_gpio;
        pn547_dev->ven_gpio = platform_data->ven_gpio;
        pn547_dev->firm_gpio = platform_data->firm_gpio;

        /* init mutex and queues */
        init_waitqueue_head(&pn547_dev->read_wq);
        mutex_init(&pn547_dev->read_mutex);
        spin_lock_init(&pn547_dev->irq_enabled_lock);

        pn547_dev->pn547_device.minor = MISC_DYNAMIC_MINOR;
        pn547_dev->pn547_device.name = PN547_NAME;
        pn547_dev->pn547_device.fops = &pn547_dev_fops;

	ret = misc_register(&pn547_dev->pn547_device);
	if (ret) {
		dev_err(&client->dev, "%s : misc_register failed\n", __func__);
		goto err_misc_register;
	}

        /* NFC_INT IRQ */
        pr_info("%s : requesting IRQ %d\n", __func__, client->irq);
        pn547_dev->irq_enabled = true;
	ret = request_irq(client->irq, pn547_dev_irq_handler, IRQF_TRIGGER_HIGH, client->name, pn547_dev);
	//ret = request_irq(client->irq, pn547_dev_irq_handler, IRQF_TRIGGER_RISING, client->name, pn547_dev);
	if (ret) {
              dev_err(&client->dev, "%s: request_irq failed\n", __func__);
              goto err_request_irq_failed;
	}

	pn547_disable_irq(pn547_dev);

        device_init_wakeup(&client->dev, true);
        device_set_wakeup_capable(&client->dev, true);

	i2c_set_clientdata(client, pn547_dev);
        gpio_set_value(platform_data->ven_gpio, 1);

        dev_dbg(&client->dev, "%s: probing pn547 exited successfully\n", __func__);

	return 0;

err_request_irq_failed:
	misc_deregister(&pn547_dev->pn547_device);

err_misc_register:
	mutex_destroy(&pn547_dev->read_mutex);
err_clkreq_gpio:
        gpio_free(platform_data->clkreq_gpio);
err_firm_gpio:
	gpio_free(platform_data->firm_gpio);
err_irq:
	gpio_free(platform_data->irq_gpio);
err_en_gpio:
	gpio_free(platform_data->ven_gpio);
err_free_dev:
        kfree(pn547_dev);

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
	gpio_free(pn547_dev->clkreq_gpio);

	kfree(pn547_dev);

	return 0;
}

static const struct i2c_device_id pn547_id[] = {
	{ PN547_NAME, 0 },
	{ }
};
static struct of_device_id pn547_match_table[] = {
  //      { .compatible = "NXP,pn547"},
        { .compatible = "NXP,pn544"},
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
