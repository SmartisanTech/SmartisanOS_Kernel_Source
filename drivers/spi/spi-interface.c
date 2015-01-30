#include <linux/module.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/spi/spi.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/gpio.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/regulator/consumer.h>
#include <linux/string.h>
#include <linux/of_gpio.h>

#ifdef CONFIG_OF
static struct of_device_id qcom_spi_interface_table[] = {
	{ .compatible = "qcom,spi-interface",},
	{ },
};
#else
#define qcom_spi_test_table NULL
#endif

struct spi_message spi_msg;
struct spi_transfer spi_xfer;
u8 *tx_buf;
struct spi_device *spi_current = NULL;

int spi_send_data_interface(unsigned char * spi_tx_buf, unsigned int size)
{
	tx_buf = spi_tx_buf;
	spi_message_init(&spi_msg);

	spi_xfer.tx_buf = tx_buf;
	spi_xfer.len = size ;
	spi_xfer.bits_per_word = 8;
	spi_xfer.speed_hz = spi_current->max_speed_hz ;

	spi_message_add_tail(&spi_xfer, &spi_msg);

	return spi_sync(spi_current, &spi_msg);
}

EXPORT_SYMBOL_GPL(spi_send_data_interface);

static int __devinit spi_interface_probe(struct spi_device *spi)
{
	int cs;
	int cpha,cpol,cs_high;

	dev_err(&spi->dev, "%s\n", __func__);

	spi_current = spi ;
	spi->bits_per_word = 8;
	cs = spi->chip_select;
	cpha = ( spi->mode & SPI_CPHA ) ? 1:0;
	cpol = ( spi->mode & SPI_CPOL ) ? 1:0;
	cs_high = ( spi->mode & SPI_CS_HIGH ) ? 1:0;

	printk(KERN_ERR " smartisan: cs=%d, cpha = %d, cpol =%d \n", cs, cpha, cpol);

	return 0;
}

static struct spi_driver spi_interface_driver = {
	.driver = {
		.name = "qcom_spi_interface",
		.owner = THIS_MODULE,
		.of_match_table = qcom_spi_interface_table,
	},
	.probe = spi_interface_probe,
};

static int __init spi_interface_init(void)
{
	return spi_register_driver(&spi_interface_driver);
}

static void __exit spi_interface_exit(void)
{
	spi_unregister_driver(&spi_interface_driver);
}

module_init(spi_interface_init);
module_exit(spi_interface_exit);
MODULE_DESCRIPTION("SPI INTERFACE");
MODULE_LICENSE("GPL v2");
