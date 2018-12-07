#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/kref.h>
#include <linux/uaccess.h>
#include <linux/usb.h>
#include <linux/io.h>
#include <linux/mutex.h>
#include <linux/firmware.h>
#include "dfu.h"

#define USB_BULK_TIMEOUT		5000

/* DFU GET_STATUS Response Values */
struct dfu_status {
	u8 status;
	u8 state;
};

enum {
	DFU_STATE_IDLE = 0,
	DFU_STATE_DNLOAD_IDLE,
	DFU_STATE_DNLOAD_BUSY,
	DFU_STATE_DNLOAD_SYNC,
	DFU_STATE_DNLOAD_COMPLETE,
	DFU_STATE_DNLOAD_ERROR,
};

enum {
	DFU_STATUS_OK = 0,
	DFU_STATUS_ERR_TARGET,
	DFU_STATUS_ERR_FILE,
	DFU_STATUS_ERR_WRITE,
	DFU_STATUS_NOT_DONE,
	DFU_STATUS_ERR_FIRMWARE,
};

/* FW Version Information */
struct fw_version {
	u16 idVendor;
	u16 idProduct;
	u16 deviceId;
	u16 iVersion;
};

/* FW Header Information */
struct fw_header_info {
	struct fw_version version;
	unsigned int length;
	u16 chksum;
	u16 reserved;
};

struct dfu_fw_entry {
	u16 deviceId;
	char name[48];
};

static struct dfu_fw_entry dfu_fw_entry_array[] = {
	{ DEVICE_MCU_0,		MCU_DOWN_STREAM_FW },
	{ DEVICE_SMARTPA_1,	SMART_PA_1_FW },
	{ DEVICE_SMARTPA_2,	SMART_PA_2_FW },
	{ DEVICE_SMARTPA_3,	SMART_PA_3_FW },
	{ DEVICE_CX20921,	CX20921_FW },
	{ DEVICE_MCU_1,		MCU_UP_STREAM_FW },
	{ DEVICE_SCALER,	SCALER_FW },
};

#define MAX_FW_NUMS	\
	(sizeof(dfu_fw_entry_array) / sizeof (struct dfu_fw_entry))
struct usb_dfu {
	struct usb_device		*udev;
	struct usb_interface		*interface;
	struct semaphore		limit_sem;
	struct usb_anchor		submitted;
	unsigned char           	*bulk_in_buffer;
	unsigned char           	*bulk_out_buffer;
	size_t				bulk_in_size;
	size_t				bulk_in_filled;
	size_t				bulk_in_copied;
	size_t				bulk_out_size;
	__u8				bulk_in_endpointAddr;
	__u8				bulk_out_endpointAddr;
	int				errors;
	struct kref			kref;
	struct mutex			io_mutex;
	wait_queue_head_t		bulk_in_wait;
	wait_queue_head_t		bulk_out_wait;
	struct delayed_work		upgrade_dwork;
	struct workqueue_struct		*upgrade_workqueue;
	spinlock_t              	err_lock;
	u8				fw_loaded;
	u8				idx;
	u16				blockno;
	struct fw_header_info		dfu_fw_info[MAX_FW_NUMS];
	struct dfu_status		stat;
	const struct firmware		*fw_entry;
};

static struct dentry			*dfu_fw_root;
static struct dentry			*dfu_fw_file;

static int dfu_get_usb_fw_version(struct usb_dfu *udp, struct fw_version *fv);
static int dfu_get_usb_state(struct usb_dfu *udp, u8 *state);
static int dfu_clear_usb_status(struct usb_dfu *udp);
static int dfu_fw_upgrade(struct usb_dfu *udp, u8 idx);
static int start_fw_upload(struct usb_dfu *udp, u8 idx);

static ssize_t dfu_fw_read(struct file* file, char __user* user_buf, size_t len, loff_t* offset)
{
	int i;
	struct file *pfile;
	char filepath[128];
	loff_t pos;
	mm_segment_t old_fs;
	struct fw_version fv;
	off_t fsize = sizeof(struct fw_version);
	pfile = NULL;

	for (i = 0; i < MAX_FW_NUMS; i++) {
		memset(filepath, 0, sizeof(filepath));
		memset(&fv, 0, sizeof(fv));
		sprintf(filepath, "%s%s", DFU_LOCAL_FW_SYS_PATH, dfu_fw_entry_array[i].name);
		pfile = filp_open(filepath, O_RDONLY, 0);
		if (IS_ERR(pfile)) {
			pr_err("dfu open local file %s failed\n", filepath);
			return -EIO;
		}

		old_fs = get_fs();
		set_fs(KERNEL_DS);
		pos = 0;
		vfs_read(pfile, (char __user*)&fv, fsize, &pos);
		pr_info("file:%s vid:0x%02x-pid:0x%02x-deviceId:0x%02x-iVersion:0x%02x\n",
				filepath, fv.idVendor, fv.idProduct, fv.deviceId, fv.iVersion);
		filp_close(pfile, NULL);
		set_fs(old_fs);
		if (copy_to_user(user_buf + i*fsize, &fv,  fsize))
			pr_info("%s copy data to user space failed!\n", __func__);
	} 

	*offset = fsize * MAX_FW_NUMS;

	/* return 0 to terminal the cat request*/
	return 0;
	//return fsize * MAX_FW_NUMS;
}

static int dfu_fw_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int dfu_fw_close(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations dfu_fw_file_fops = {
	.owner = THIS_MODULE,
        .open = dfu_fw_open,
        .read = dfu_fw_read,
        .llseek = generic_file_llseek,
        .release =dfu_fw_close,
};

static void dump_fw_version(struct fw_version *fv, struct device *dev)
{
	dev_dbg(dev, "dump fw versions:\n");
	dev_dbg(dev, "vid:0x%02x-pid:0x%02x-deviceId:0x%02x-iVersion:0x%02x\n",
			fv->idVendor, fv->idProduct, fv->deviceId, fv->iVersion);
}

static ssize_t version_show(struct device *dev, struct device_attribute *attr,
		                char *buf)
{
	int retval;
	struct fw_version fv;
	struct usb_dfu *udp = dev_get_drvdata(dev);
	struct usb_interface *interface = udp->interface;

	dev_dbg(&interface->dev, "%s idx:%d\n", __func__, udp->idx);
	retval = dfu_get_usb_fw_version(udp, &fv);
	if (retval)
		return snprintf(buf, PAGE_SIZE, "%s:None\n", dfu_fw_entry_array[udp->idx].name);
	else
		return snprintf(buf, PAGE_SIZE, "%s:0x%02x-0x%02x-0x%02x-0x%02x\n",
				dfu_fw_entry_array[udp->idx].name,
				fv.idVendor, fv.idProduct, fv.deviceId, fv.iVersion);
}

static ssize_t version_store(struct device *dev, struct device_attribute *attr,
		                const char *buf, size_t count)
{
	u8 idx;
	int retval;
	struct usb_dfu *udp = dev_get_drvdata(dev);
	struct usb_interface *interface = udp->interface;

	retval = kstrtou8(buf, 0, &idx);
	if (retval) 
		return retval;

	if (idx < MAX_FW_NUMS)
		udp->idx = idx;
	else {
		udp->idx = 0;
		dev_err(&interface->dev, "%s invalid idx:%d is beyond '(0~5)' set to default'(0)'\n",
				__func__, idx);
	}

	dev_dbg(&interface->dev, "%s udp->idx:%d\n", __func__, udp->idx);

        return count;
}
static DEVICE_ATTR_RW(version);

static ssize_t state_show(struct device *dev, struct device_attribute *attr,
		                char *buf)
{
	char buffer[32];
	struct usb_dfu *udp = dev_get_drvdata(dev);
	struct usb_interface *interface = udp->interface;
	int retval;
	u8 state;

	retval = dfu_get_usb_state(udp, &state);
	dev_dbg(&interface->dev, "%s state:%d\n", __func__, state);
	if (retval < 0)
		return snprintf(buf, sizeof(buffer), "%s\n", "Got DFU status failed!");

	memset(buffer, 0, sizeof(buffer));
	switch (state) {
		case DFU_STATE_IDLE:
			memcpy(buffer, "DFU_STATE_IDLE", 14);
			break;
		case DFU_STATE_DNLOAD_IDLE:
			memcpy(buffer, "DFU_STATE_DNLOAD_IDLE", 21);
			break;
		case DFU_STATE_DNLOAD_BUSY:
			memcpy(buffer, "DFU_STATE_DNLOAD_BUSY", 21);
			break;
		case DFU_STATE_DNLOAD_SYNC:
			memcpy(buffer, "DFU_STATE_DNLOAD_SYNC", 21);
			break;
		case DFU_STATE_DNLOAD_COMPLETE:
			memcpy(buffer, "DFU_STATE_DNLOAD_COMPLETE", 25);
			break;
		case DFU_STATE_DNLOAD_ERROR:
			memcpy(buffer, "DFU_STATE_DNLOAD_ERROR", 22);
			break;
		default:
			memcpy(buffer, "DFU_UNKNOWN", 11);
			break;
	}

        return snprintf(buf, sizeof(buffer), "%s\n", buffer);
}

static ssize_t state_store(struct device *dev, struct device_attribute *attr,
		                const char *buf, size_t count)
{
	struct usb_dfu *udp = dev_get_drvdata(dev);
	struct usb_interface *interface = udp->interface;
	int retval = dfu_clear_usb_status(udp);

	if (retval < 0)
		dev_err(&interface->dev, "%s clear usb status failed!\n", __func__);

        return count;
}
static DEVICE_ATTR_RW(state);

static ssize_t download_store(struct device *dev, struct device_attribute *attr,
		                const char *buf, size_t count)
{
	u8 idx;
	int retval;
	struct usb_dfu *udp = dev_get_drvdata(dev);
	struct usb_interface *interface = udp->interface;

	retval = kstrtou8(buf, 0, &idx);
	if (retval)
		return retval;

	if (idx < MAX_FW_NUMS) {
		retval = dfu_fw_upgrade(udp, idx);
		if (retval)
			dev_err(&interface->dev, "%s dfu fw upgrade failed!\n", __func__);
	} else
		dev_err(&interface->dev, "%s invalid idx:%d is beyond '(0-5')\n",
				__func__, idx);

        return count;
}
static DEVICE_ATTR_WO(download);

static ssize_t upload_show(struct device *dev, struct device_attribute *attr,
		                char *buf)
{
	struct usb_dfu *udp = dev_get_drvdata(dev);
	u8 idx = udp->idx;

	start_fw_upload(udp, idx);
        return snprintf(buf, PAGE_SIZE, "%s\n", "upload");
}

static ssize_t upload_store(struct device *dev, struct device_attribute *attr,
		                const char *buf, size_t count)
{
	u8 idx;
	int retval;
	struct usb_dfu *udp = dev_get_drvdata(dev);
	struct usb_interface *interface = udp->interface;

	retval = kstrtou8(buf, 0, &idx);
	if (retval)
		return retval;

	if (idx < MAX_FW_NUMS) {
		udp->idx = idx;
	} else {
		udp->idx = 0;
		dev_err(&interface->dev, "%s invalid idx:%d is beyond '(0~5)' set to default'(0)'\n",
				__func__, idx);
	}

        return count;
}
static DEVICE_ATTR_RW(upload);

static void dfu_delete(struct kref *kref)
{
	struct usb_dfu *dev = container_of(kref, struct usb_dfu, kref);

	cancel_delayed_work_sync(&dev->upgrade_dwork);
	flush_workqueue(dev->upgrade_workqueue);
	destroy_workqueue(dev->upgrade_workqueue);

	usb_put_dev(dev->udev);
	dev->udev = NULL;

	if (dev->bulk_in_buffer)
		kfree(dev->bulk_in_buffer);
	if (dev->bulk_out_buffer)
		kfree(dev->bulk_out_buffer);
	kfree(dev);
}

static int fw_check_valid_version(struct fw_version *fv, int idx)
{
	return  (fv->idVendor != USB_DFU_VENDOR_ID ||
			(fv->idProduct != USB_DFU_DOWN_STREAM_PRODUCT_ID &&
			fv->idProduct != USB_DFU_UP_STREAM_PRODUCT_ID)  ||
			fv->deviceId != dfu_fw_entry_array[idx].deviceId);

}

static u16 cal_chksum(const u8 *data, int size)
{
	unsigned long chksum = 0;
	const u16 *buf = (u16 *)data;

	while( size > 1) {
		chksum += *buf++;
		size -= sizeof(u16);
	}

	if (size)
		chksum += *(u8 *)buf;

	chksum = (chksum >> 16) + (chksum & 0xffff);
	chksum += chksum >> 16;

	return (u16)chksum;
}

static int fw_checksum_verify(struct usb_dfu *udp)
{
	u16 chksum;
	struct device *dev = &udp->interface->dev;
	const struct firmware *fwp = udp->fw_entry;
	struct fw_header_info *fwh = (struct fw_header_info *)fwp->data;
	const u8 *fw_data = fwp->data + sizeof(*fwh);
	int fw_length = fwp->size - sizeof(*fwh);

	chksum = cal_chksum(fw_data, fw_length);

	dev_dbg(dev, "calculate chksum = 0x%04x fw->chksum = 0x%04x fw_length:%d\n",
			chksum, fwh->chksum, fw_length);

	return (chksum == fwh->chksum);
}


static int dfu_get_local_fw_version(struct usb_dfu *udp,  struct fw_version *fv)
{
	char filename[64];
	const struct firmware *fwp;
	struct fw_header_info *fwh;
	unsigned int fw_length;
	unsigned int cal_fw_length;
	struct device *dev = &udp->interface->dev;
	u8 idx = udp->idx;
	int retval = 0;

	dev_dbg(dev, "%s enter\n", __func__);
	memset(filename, 0, sizeof(filename));
	sprintf(filename, "%s", dfu_fw_entry_array[idx].name);
	retval = request_firmware(&udp->fw_entry, filename, dev);
	if (retval) {
		dev_err(dev, "request %s firmware failed! retval = %d\n", filename, retval);
		return -EINVAL;
	}


	fwp = udp->fw_entry;
	fwh = (struct fw_header_info *)fwp->data;
	dev_dbg(dev, "%s request firmware length:%ld", __func__, fwp->size);
	if (fwp->size < sizeof(*fwh)) {
		dev_err(dev, "invalid %s fw length(%ld)\n", filename, fwp->size);
		return -EINVAL;
	}
	*fv = fwh->version;
	retval = fw_check_valid_version(fv, idx);
	if (retval) {
		dev_err(dev, "local fw version self check failed!\n");
		dump_fw_version(fv, dev);
		return -EINVAL;
	}

	fw_length = fwh->length; //the length is not inclue the header information
	cal_fw_length = fwp->size - sizeof(*fwh);
	if (fw_length != cal_fw_length) {
		dev_err(dev, "local fw length(%d!=%d) check failed!\n", fw_length, cal_fw_length);
		return -EINVAL;
	}

	if (!fw_checksum_verify(udp)) {
		retval = -EINVAL;
		dev_err(dev, "local fw checksum verify failed!\n");
	}

	return retval;
}

static int dfu_get_usb_state(struct usb_dfu *udp, u8 *state)
{
        int retval;
	struct usb_device *udev = udp->udev;
	u16 wIndex = dfu_fw_entry_array[udp->idx].deviceId;

        retval = usb_control_msg(udev, usb_rcvctrlpipe(udev, 0), DFU_GETSTATE,
				USB_TYPE_CLASS | USB_DIR_IN | USB_RECIP_INTERFACE,
				0, wIndex, state, 1, USB_CTRL_GET_TIMEOUT);
        return retval;
}

static int dfu_get_usb_status(struct usb_dfu *udp, struct dfu_status *stat)
{
	int retval;
	struct usb_interface *interface = udp->interface;
	struct device *dev = &interface->dev;
	struct usb_device *udev = udp->udev;
	u16 wIndex = dfu_fw_entry_array[udp->idx].deviceId;

	dev_dbg(dev, "%s enter\n", __func__);
	retval = usb_control_msg(udev, usb_rcvctrlpipe(udev, 0), DFU_GETSTATUS,
			      USB_TYPE_CLASS | USB_DIR_IN | USB_RECIP_INTERFACE,
			      0, wIndex, stat, sizeof(struct dfu_status),
			      USB_CTRL_GET_TIMEOUT);
	if (retval >= 0)
		dev_dbg(dev, "%s got status:%d state:%d return retval:%d", __func__,
				stat->status, stat->state, retval);
	else
		dev_err(dev, "dfu get status failed!\n");

	return retval;
}

static int dfu_clear_usb_status(struct usb_dfu *udp)
{
	struct usb_device *udev = udp->udev;
	struct device *dev = &udp->interface->dev;
	u16 wIndex = dfu_fw_entry_array[udp->idx].deviceId;

	dev_dbg(dev, "%s enter\n", __func__);
	return usb_control_msg(udev, usb_sndctrlpipe(udev, 0), DFU_CLRSTATUS,
			       USB_TYPE_CLASS | USB_DIR_OUT | USB_RECIP_INTERFACE,
			       0, wIndex, NULL, 0,
			       USB_CTRL_SET_TIMEOUT);
}

static int dfu_get_usb_fw_version(struct usb_dfu *udp, struct fw_version *fv)
{
	struct usb_interface *interface = udp->interface;
	struct device *dev = &interface->dev;
	struct usb_device *udev = udp->udev;
	void *data = fv;
	u8 idx = udp->idx;
	u16 wIndex = dfu_fw_entry_array[idx].deviceId;
	u16 size = sizeof(struct fw_version);
	int retval;

	dev_dbg(dev, "%s enter\n", __func__);
	retval =usb_control_msg(udev, usb_sndctrlpipe(udev, 0), DFU_GETVERSION,
	                     USB_TYPE_CLASS | USB_DIR_IN | USB_RECIP_INTERFACE,
			     0, wIndex, data, size,
                             USB_CTRL_GET_TIMEOUT);
	if (retval >= 0) {
		retval = fw_check_valid_version(fv, idx);
		if (retval) {
			dev_err(dev, "usb fw version self check failed!\n");
			dump_fw_version(fv, &interface->dev);
		}
	} else {
		dev_err(dev, "dfu get %s version failed!\n", dfu_fw_entry_array[idx].name);
	}

	return retval;
}

static int compare_local_and_usb_fw_version(struct fw_version fv_local, struct fw_version fv_usb)
{
	return (fv_local.deviceId == fv_usb.deviceId &&
			fv_local.iVersion > fv_usb.iVersion);
}

static int dfu_dnload(struct usb_dfu *udp, void *data, int blockno, int size)
{
	struct usb_device *udev = udp->udev;
	u16 wIndex = dfu_fw_entry_array[udp->idx].deviceId;

	dev_dbg(&udp->interface->dev, "%s enter blockno:%d size:%d\n",
		       __func__, blockno, size);
	return usb_control_msg(udev, usb_sndctrlpipe(udev, 0), DFU_DNLOAD,
			       USB_TYPE_CLASS | USB_DIR_OUT | USB_RECIP_INTERFACE,
			       blockno, wIndex, data, size,
			       USB_CTRL_SET_TIMEOUT);
}

static int start_fw_upload(struct usb_dfu *udp, u8 idx)
{
	return 0;
}

static int start_fw_upgrade(struct usb_dfu *udp, u8 idx)
{
	int retval;
	int actual_length;
	struct dfu_status stat;
	u8 state = 0;
	u8 status = 0;
	int need_dfu_state = 1;
	int is_done = 0;
	int timeout_array[] = {5, 10, 10, 10, 10, 5, 50};
	struct usb_device *udev = udp->udev;
	unsigned int bulk_out_size = udp->bulk_out_size;
	unsigned char *buf = udp->bulk_out_buffer;
	struct usb_interface *interface = udp->interface;
	struct device *dev = &interface->dev;
	unsigned int pipe = usb_sndbulkpipe(udev, udp->bulk_out_endpointAddr);
	const struct firmware *fwp = udp->fw_entry;
	struct fw_header_info *fwh = (struct fw_header_info *)fwp->data;

#if 1
	unsigned int fw_raw_length = fwh->length; //the length is not inclue the header information
#else
	unsigned int fw_raw_length = fwp->size - sizeof(*fwh); //the length is not inclue the header information
#endif
	char *fw_raw_data = (char *)fwp->data + sizeof(struct fw_header_info);
	int trans_times = fw_raw_length / bulk_out_size + 1;
	unsigned int writesize = min(fw_raw_length, bulk_out_size);


	dev_dbg(dev, "%s enter idx:%d fw_raw_length:%d\n", __func__, idx, fw_raw_length);
	if(fw_raw_length <= 0) {
		retval = -EINVAL;
		goto exit;
	}

	retval = dfu_get_usb_status(udp, &stat);
	if (retval >= 0) {
		if (stat.status != DFU_STATUS_OK && stat.state != DFU_STATE_IDLE)
			dfu_clear_usb_status(udp);
	} else {
		dev_err(dev, "cannot get DFU status before starting transfer: %d\n", retval);
		goto exit;
	}

	udp->blockno = 0;
	do {
		if (need_dfu_state) {
			retval = dfu_get_usb_state(udp, &state);
			if (retval < 0) {
				dev_err(dev, "cannot get DFU state: %d\n", retval);
				goto exit;
			}
			need_dfu_state = 0;
		}

		switch (state) {
		case DFU_STATE_IDLE:
			dev_dbg(dev, "DFU_STATE_IDLE\n");
			memcpy(buf, fwh, sizeof(*fwh));
			retval = dfu_dnload(udp, buf, udp->blockno, sizeof(*fwh));
			if (retval < 0) {
				dev_err(dev, "dfu_dnload blockno:%d failed!\n", udp->blockno);
				goto exit;
			}
			need_dfu_state = 1;
			break;
		case DFU_STATE_DNLOAD_IDLE:
			//FIX ME(need send blockno by dfu_dnload or not)
			dev_dbg(dev, "DFU DNLOAD....\n");
			dev_dbg(dev, "%s transfer times(%d/%d) length = %d\n",
					__func__, udp->blockno, trans_times, writesize);
			memcpy(buf, fw_raw_data, writesize);
			/* send the data out the bulk port */
			retval = usb_bulk_msg(udev, pipe,
					buf, writesize, &actual_length, USB_BULK_TIMEOUT);
			if (retval < 0) {
				dev_err(dev, "%s - usb bulk msg error %d\n", __func__, retval);
				goto exit;
			}
			fw_raw_data += actual_length;
			fw_raw_length -= actual_length;
			writesize = min(fw_raw_length, bulk_out_size);
			need_dfu_state = 1;

#if 0
			if (udp->blockno == trans_times)
				is_done = 1;
			/* all fw transfer have completed and then send a zero packet */
			if (udp->blockno == trans_times) {
				retval = dfu_dnload(udp, (void *)fwh, udp->blockno, 0);
				if (retval < 0) {
					dev_err(dev, "dfu_dnload blockno:%d failed!\n", udp->blockno);
						goto exit;
				}
			}
#endif
			break;
		case DFU_STATE_DNLOAD_BUSY:
			dev_dbg(dev, "DFU DNLOAD BUSY\n");
			need_dfu_state = 1;
			schedule_timeout_interruptible(msecs_to_jiffies(timeout_array[idx]));
			break;
		case DFU_STATE_DNLOAD_SYNC:
			dev_dbg(dev, "DFU DNLOAD SYNC\n");
			retval = dfu_get_usb_status(udp, &stat);
			if (retval >= 0) {
				state = stat.state;
				status = stat.status;
				if (status == DFU_STATUS_OK)
					udp->blockno++;
				else {
					retval = -EINVAL;
					dev_err(dev, "dfu get error status:%d\n", status);
					goto exit;
				}
				need_dfu_state = 0;
			} else
				dev_err(dev, "dfu get usb status return %d\n", retval);
			break;
		case DFU_STATE_DNLOAD_ERROR:
			dev_dbg(dev, "DFU_STATE_DNLOAD_ERROR\n");
			break;
		case DFU_STATE_DNLOAD_COMPLETE:
			dev_dbg(dev, "DFU_STATE_DNLOAD_COMPLETE\n");
			is_done = 1;
			break;
		default:
			dev_dbg(dev, "DFU UNKNOWN STATE!\n");
			retval = -EINVAL;
			break;

		}
	} while (!is_done && (retval >= 0));

exit:
	return retval;
}

static int dfu_fw_upgrade(struct usb_dfu *udp, u8 idx)
{
	struct fw_version fv_local;
	struct fw_version fv_usb;
	struct device *dev = &udp->interface->dev;
	int retry_count = 0;
	int retval = 0;

	dev_dbg(dev, "%s enter idx:%d\n", __func__, idx);
	udp->idx = idx;
	/* the current deviceId fw already loaded */
	if (udp->fw_loaded & (idx << 1))
		return 0;

	/* get local fw information */
	retval = dfu_get_local_fw_version(udp, &fv_local);
	if (retval) {
		goto upgrade_local_err;
	}

	/* get dfu usb fw information */
	retval = dfu_get_usb_fw_version(udp, &fv_usb);
	if (retval)
		goto upgrade_usb_err;

	/* check the local and usb fw version to decide wether need the really upgrade or not */
	if(!compare_local_and_usb_fw_version(fv_local, fv_usb)) {
		dev_err(dev, "compare fw versions failed!\n");
		dev_err(dev, "local version deviceId:0x%02x iVersion:0x%02x\n", fv_local.deviceId, fv_local.iVersion);
		dev_err(dev, "usb version deviceId:0x%02x iVersion:0x%02x\n", fv_usb.deviceId, fv_usb.iVersion);
		goto upgrade_usb_err;
	}

	do {
		retval = start_fw_upgrade(udp, idx);
	} while (retval && (retry_count++ < 3));
	dev_info(dev, "dfu fw upgrade return retval:%d retry_count:%d\n",
			retval, retry_count);

	if (!retval && retry_count < 3) {
		dev_info(dev, "dfu fw upgrade done!\n");
	} else {
		dev_err(dev, "dfu fw upgrade failed!\n");
		goto upgrade_usb_err;
	}

	dfu_clear_usb_status(udp);

	if (udp->fw_entry) {
		release_firmware(udp->fw_entry);
		udp->fw_entry = NULL;
	}

	return 0;

upgrade_usb_err:
upgrade_local_err:
	if (udp->fw_entry)
		release_firmware(udp->fw_entry);
	retval = -EINVAL;

	return retval;
}

static u16 dfu_fw_upgrade_entry(struct usb_dfu *udp)
{
	int i;
	int retval = 0;

	for (i = 0; i < MAX_FW_NUMS; i++) {
		retval = dfu_fw_upgrade(udp, i);
		if (!retval)
			udp->fw_loaded |= 1 << i;
	}

	return udp->fw_loaded;
}

static void show_upgrade_result(struct usb_dfu *udp)
{
	int i;
	struct device *dev = &udp->interface->dev;
	u8 fw_loaded = udp->fw_loaded;

	dev_dbg(dev, "%s fw loaded value:0x%02x\n", __func__, fw_loaded);

	for (i = 0; i < MAX_FW_NUMS; i++) {
		if (fw_loaded & (1 << i))
			dev_info(dev, "FW %s is upgraded!\n", dfu_fw_entry_array[i].name);
		else
			dev_info(dev, "FW %s is not upgraded!\n", dfu_fw_entry_array[i].name);
	}

	return;
}

static void dfu_upgrade_delayed_work(struct work_struct *work)
{
	struct delayed_work *delayed_work = container_of(work, struct delayed_work, work);
	struct usb_dfu *udp = container_of(delayed_work, struct usb_dfu, upgrade_dwork);
	struct device *dev = &udp->interface->dev;
	u16 fw_loaded;
	static int try_upgrade_again = 0;


	/* this lock makes sure we don't submit URBs to gone devices */
	mutex_lock(&udp->io_mutex);
	if (!udp->interface) {          /* disconnect() was called */
		dev_info(dev, "usb has disconnected stop upgrade!\n");
		mutex_unlock(&udp->io_mutex);
		return;
	}
	fw_loaded = dfu_fw_upgrade_entry(udp);
	show_upgrade_result(udp);
	if (fw_loaded == DEVICE_ALL_BIT_MASK) {
		dev_info(dev, "dfu all fw upgrade successfully!!!\n");
		mutex_unlock(&udp->io_mutex);
		return;
	} else if (!try_upgrade_again){
		try_upgrade_again = 1;
		dev_info(dev, "dfu upgrade fw_loaded:0x%02x do one more upgrade again\n",
				fw_loaded);
		queue_delayed_work(udp->upgrade_workqueue, &udp->upgrade_dwork, HZ);
	}
	mutex_unlock(&udp->io_mutex);

	return;
}

int dfu_open(struct inode *inode, struct file *file)
{
        return 0;
}

static long dfu_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
        return 0;
}

static long dfu_compat_ioctl(struct file *file, unsigned int cmd,
		                             unsigned long arg)
{
        return dfu_ioctl(file, cmd, arg);
}


static const struct file_operations dfu_fops = {
	.owner =		THIS_MODULE,
	.open =			dfu_open,
	.unlocked_ioctl =	dfu_ioctl,
	.compat_ioctl =		dfu_compat_ioctl,
#if 0
	.read =		dfu_read,
	.write =	dfu_write,
	.release =	dfu_release,
	.flush =	dfu_flush,
	.llseek =	noop_llseek,
#endif
};

/*
 * usb class driver info in order to get a minor number from the usb core,
 * and to have the device registered with the driver core
 */
#define USB_DFU_MINOR_BASE	193
static struct usb_class_driver dfu_class = {
	.name =		"dfu%d",
	.fops =		&dfu_fops,
	.minor_base =	USB_DFU_MINOR_BASE,
};

static int dfu_probe(struct usb_interface *interface,
		      const struct usb_device_id *id)
{
	struct usb_dfu *dev;
	struct usb_endpoint_descriptor *endpoint;
	struct usb_host_interface *iface_desc;
	size_t buffer_size;
	int i;
	int retval = -ENOMEM;

	dev_dbg(&interface->dev, "dfu probe started\n");

	/* allocate memory for our device state and initialize it */
	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		goto error;

	kref_init(&dev->kref);
	mutex_init(&dev->io_mutex);
	init_usb_anchor(&dev->submitted);
	init_waitqueue_head(&dev->bulk_in_wait);
	init_waitqueue_head(&dev->bulk_out_wait);
	spin_lock_init(&dev->err_lock);
	dev->fw_loaded = 0;
	dev->idx = 0;

	dev->udev = usb_get_dev(interface_to_usbdev(interface));
	dev->interface = interface;
	/* set up the endpoint information */
	/* use only the first bulk-in and bulk-out endpoints */
	iface_desc = interface->cur_altsetting;
	for (i = 0; i < iface_desc->desc.bNumEndpoints; ++i) {
		endpoint = &iface_desc->endpoint[i].desc;

		if (!dev->bulk_in_endpointAddr &&
		    usb_endpoint_is_bulk_in(endpoint)) {
			/* we found a bulk in endpoint */
#if 1
			buffer_size = usb_endpoint_maxp(endpoint);
#else
			buffer_size = USB_BLOCK_SIZE;
#endif
			dev->bulk_in_size = buffer_size;
			dev->bulk_in_endpointAddr = endpoint->bEndpointAddress;
			dev->bulk_in_buffer = kmalloc(buffer_size, GFP_KERNEL);
			if (!dev->bulk_in_buffer)
				goto error;
		}

		if (!dev->bulk_out_endpointAddr &&
		    usb_endpoint_is_bulk_out(endpoint)) {
			/* we found a bulk out endpoint */
#if 1
			buffer_size = usb_endpoint_maxp(endpoint);
#else
			buffer_size = USB_BLOCK_SIZE;
#endif
			dev->bulk_out_size = buffer_size;
			dev->bulk_out_endpointAddr = endpoint->bEndpointAddress;
			dev->bulk_out_buffer = kmalloc(buffer_size, GFP_KERNEL);
			if (!dev->bulk_out_buffer)
				goto error;
		}
	}
	if (!(dev->bulk_in_endpointAddr && dev->bulk_out_endpointAddr)) {
		dev_err(&interface->dev,
			"Could not find both bulk-in and bulk-out endpoints\n");
		goto error;
	}

	/* save our data pointer in this interface device */
	usb_set_intfdata(interface, dev);

	/* we can register the device now, as it is ready */
	retval = usb_register_dev(interface, &dfu_class);
	if (retval) {
		/* something prevented us from registering this driver */
		dev_err(&interface->dev,
			"Not able to get a minor for this device.\n");
		usb_set_intfdata(interface, NULL);
		goto error;
	}


	/* let the user know what node this device is now attached to */
	dev_info(&interface->dev,
		 "USB DFU device now attached to USBDFU-%d",
		 interface->minor);

	dev->upgrade_workqueue = create_singlethread_workqueue("dfu_upgrade");
	if (!dev->upgrade_workqueue)
		goto error;
	INIT_DELAYED_WORK(&dev->upgrade_dwork, dfu_upgrade_delayed_work);
	queue_delayed_work(dev->upgrade_workqueue, &dev->upgrade_dwork, HZ);

	device_create_file(&interface->dev, &dev_attr_version);
	device_create_file(&interface->dev, &dev_attr_state);
	device_create_file(&interface->dev, &dev_attr_download);
	device_create_file(&interface->dev, &dev_attr_upload);

	return 0;

error:
	if (dev)
		/* this frees allocated memory */
		kref_put(&dev->kref, dfu_delete);
	return retval;
}

static void dfu_disconnect(struct usb_interface *interface)
{
	struct usb_dfu *dev;
	int minor = interface->minor;

	dev = usb_get_intfdata(interface);
	usb_set_intfdata(interface, NULL);

	device_remove_file(&interface->dev, &dev_attr_version);
	device_remove_file(&interface->dev, &dev_attr_state);
	device_remove_file(&interface->dev, &dev_attr_download);
	device_remove_file(&interface->dev, &dev_attr_upload);

	/* give back our minor */
	usb_deregister_dev(interface, &dfu_class);

	/* prevent more I/O from starting */
	mutex_lock(&dev->io_mutex);
	dev->interface = NULL;
	mutex_unlock(&dev->io_mutex);

	/* decrement our usage count */
	kref_put(&dev->kref, dfu_delete);

	dev_info(&interface->dev, "USB DFU #%d now disconnected", minor);
}

static void dfu_draw_down(struct usb_dfu *dev)
{
}

static int dfu_suspend(struct usb_interface *intf, pm_message_t message)
{
	struct usb_dfu *dev = usb_get_intfdata(intf);

	if (!dev)
		return 0;
	dfu_draw_down(dev);

	return 0;
}

static int dfu_resume(struct usb_interface *intf)
{
	return 0;
}

static int dfu_pre_reset(struct usb_interface *intf)
{
	struct usb_dfu *dev = usb_get_intfdata(intf);

	dev_dbg(&intf->dev, "usb dfu_pre_reset start\n");
	mutex_lock(&dev->io_mutex);
	dfu_draw_down(dev);

	return 0;
}

static int dfu_post_reset(struct usb_interface *intf)
{
	struct usb_dfu *dev = usb_get_intfdata(intf);

	dev_dbg(&intf->dev, "usb dfu_post_reset start\n");
	/* we are sure no URBs are active - no locking needed */
	dev->errors = -EPIPE;
	mutex_unlock(&dev->io_mutex);

	return 0;
}

/* table of devices that work with this driver */
static const struct usb_device_id dfu_table[] = {
	{ USB_DEVICE(USB_DFU_VENDOR_ID, USB_DFU_DOWN_STREAM_PRODUCT_ID),
	  USB_INTERFACE_INFO(0xFE, 0x1, 0x1)
	},
	{ USB_DEVICE(USB_DFU_VENDOR_ID, USB_DFU_UP_STREAM_PRODUCT_ID),
	  USB_INTERFACE_INFO(0xFE, 0x1, 0x1)
	},
	{ }					/* Terminating entry */
};
MODULE_DEVICE_TABLE(usb, dfu_table);

static struct usb_driver dfu_driver = {
	.name =			"dfu",
	.probe =		dfu_probe,
	.disconnect =		dfu_disconnect,
	.suspend =		dfu_suspend,
	.resume =		dfu_resume,
	.pre_reset =		dfu_pre_reset,
	.post_reset =		dfu_post_reset,
	.id_table =		dfu_table,
	.supports_autosuspend = 0,
};

static int __init dfu_init(void)
{
	int retval = -ENOMEM;

	dfu_fw_root = debugfs_create_dir("dfu_fw_root", NULL);
	if (IS_ERR(dfu_fw_root) || !dfu_fw_root)
		goto fail;

	dfu_fw_file = debugfs_create_file("dfu_fw_file", S_IRUGO,
			dfu_fw_root, NULL, &dfu_fw_file_fops);
	if (!dfu_fw_file)
		goto debugfs_create_file_fail;

	retval = usb_register(&dfu_driver);
	if (retval)
		goto usb_register_fail;

	return 0;

usb_register_fail:
	debugfs_remove(dfu_fw_file);
debugfs_create_file_fail:
	debugfs_remove(dfu_fw_root);
fail:
	return retval;
}

static void __exit dfu_exit(void)
{
	debugfs_remove(dfu_fw_file);
	debugfs_remove(dfu_fw_root);
	usb_deregister(&dfu_driver);
}

late_initcall(dfu_init);
module_exit(dfu_exit);
MODULE_DESCRIPTION("DFU driver");
MODULE_LICENSE("GPL");
