#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/debugfs.h>
#include <linux/slab.h>

#define DEBUG_DIR_NAME        "audev_pst"
#define MAX98927_LEFT_NAME    "max98927_left"
#define MAX98927_RIGHT_NAME   "max98927_right"
#define IGO_NAME              "intelligo"

#define MAX98927_LEFT    ((void *)1)
#define MAX98927_RIGHT   ((void *)2)

typedef struct
{
	struct dentry *dbg_dir;
	struct dentry *max98927_left;
	struct dentry *max98927_right;
	struct dentry *intelligo;
} audev_pst_t;

static audev_pst_t *audev_pst = NULL;

extern int debussy_get_presence(void);
extern int max98927_get_i2c_states(void);

static ssize_t igo_pst_read(struct file *file,
				 char __user *user_buf, size_t count,
				 loff_t *ppos)
{
	int status = false;
	int len = 0;
	char kbuf[4] = {0};

	if (*ppos != 0)
		return 0;

	pr_info("%s enter\n", __func__);

	status = debussy_get_presence();
	len = snprintf(kbuf, sizeof(kbuf), "%d\n", !!status);

	return simple_read_from_buffer(user_buf, count, ppos, kbuf, len);
}

static const struct file_operations igo_pst_ops = {
	.open = simple_open,
	.read = igo_pst_read,
	.llseek = default_llseek,
};

static ssize_t max98927_pst_read(struct file *file,
				 char __user *user_buf, size_t count,
				 loff_t *ppos)
{
	void *channel;
	unsigned int status;
	int len = 0;
	bool exist = false;
	char kbuf[4] = {0};

	if (*ppos != 0)
		return 0;

	pr_info("%s enter\n", __func__);

	channel = file->private_data;
	status = max98927_get_i2c_states();

	if (channel == MAX98927_LEFT)
		exist = status & 0x1;
	else if (channel == MAX98927_RIGHT)
		exist = status & (1<<1);

	len = snprintf(kbuf, sizeof(kbuf),  "%d\n", !!exist);
	return simple_read_from_buffer(user_buf, count, ppos, kbuf, len);
}

static const struct file_operations max98927_pst_ops = {
	.open = simple_open,
	.read = max98927_pst_read,
	.llseek = default_llseek,
};

static int __init audev_pst_init(void)
{
	int ret;

	audev_pst = kzalloc(sizeof(audev_pst_t), GFP_KERNEL);
	if (IS_ERR_OR_NULL(audev_pst)) {
		ret = -ENOMEM;
		pr_err("%s: kzalloc failed\n", __func__);
		goto err1;
	}

	audev_pst->dbg_dir = debugfs_create_dir(DEBUG_DIR_NAME, NULL);
	if (IS_ERR_OR_NULL(audev_pst->dbg_dir)) {
		pr_err("%s: create %s failed\n", __func__, DEBUG_DIR_NAME);
		ret = -EINVAL;
		goto err2;
	}

	audev_pst->max98927_left = debugfs_create_file(MAX98927_LEFT_NAME, S_IRUGO,
		audev_pst->dbg_dir, MAX98927_LEFT, &max98927_pst_ops);
	if (IS_ERR_OR_NULL(audev_pst->max98927_left))
		pr_err("%s: create %s failed\n", __func__, MAX98927_LEFT_NAME);

	audev_pst->max98927_right = debugfs_create_file(MAX98927_RIGHT_NAME, S_IRUGO,
		audev_pst->dbg_dir, MAX98927_RIGHT, &max98927_pst_ops);
	if (IS_ERR_OR_NULL(audev_pst->max98927_left))
		pr_err("%s: create %s failed\n", __func__, MAX98927_LEFT_NAME);

	audev_pst->intelligo = debugfs_create_file(IGO_NAME, S_IRUGO,
		audev_pst->dbg_dir, NULL, &igo_pst_ops);
	if (IS_ERR_OR_NULL(audev_pst->intelligo))
		pr_err("%s: create %s failed\n", __func__, IGO_NAME);

	return 0;

err2:
	kfree(audev_pst);
	audev_pst = NULL;
err1:
	return ret;
}

static void __exit audev_pst_exit(void)
{
	if (audev_pst) {
		debugfs_remove_recursive(audev_pst->dbg_dir);
		kfree(audev_pst);
		audev_pst = NULL;
	}

	return;
}

module_init(audev_pst_init);
module_exit(audev_pst_exit);
MODULE_LICENSE("GPL");
