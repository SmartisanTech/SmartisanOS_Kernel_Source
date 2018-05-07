#include <linux/file.h>
#include <linux/fs.h>
#include <linux/xattr.h>
#include <linux/dcache.h>
#include "sdcardfs.h"

static struct dentry *
sdcardfs_dentry_to_lower(struct dentry *dentry)
{
    struct dentry* ret;

    ret = ((struct sdcardfs_dentry_info *)dentry->d_fsdata)->lower_path.dentry;
    return ret;
}

int
sdcardfs_setxattr(struct dentry *dentry, const char *name, const void *value, size_t size, int flags)
{
	int rc = 0;
	struct dentry *lower_dentry;

	lower_dentry = sdcardfs_dentry_to_lower(dentry);
	if (!d_inode(lower_dentry)->i_op->setxattr) {
		rc = -EOPNOTSUPP;
		goto out;
	}

	rc = vfs_setxattr(lower_dentry, name, value, size, flags);
out:
	return rc;
}

static ssize_t
sdcardfs_getxattr_lower(struct dentry *lower_dentry, const char *name, void *value, size_t size)
{
	int rc = 0;

	if (!d_inode(lower_dentry)->i_op->getxattr) {
		rc = -EOPNOTSUPP;
		goto out;
	}
	rc = d_inode(lower_dentry)->i_op->getxattr(lower_dentry, name, value,
						   size);
out:
	return rc;
}

ssize_t
sdcardfs_getxattr(struct dentry *dentry, const char *name, void *value, size_t size)
{
    ssize_t ret;
	ret = sdcardfs_getxattr_lower(sdcardfs_dentry_to_lower(dentry), name,
				       value, size);
    return ret;
}

ssize_t
sdcardfs_listxattr(struct dentry *dentry, char *list, size_t size)
{
	int rc = 0;
	struct dentry *lower_dentry;

	lower_dentry = sdcardfs_dentry_to_lower(dentry);
	if (!d_inode(lower_dentry)->i_op->listxattr) {
		rc = -EOPNOTSUPP;
		goto out;
	}
	rc = d_inode(lower_dentry)->i_op->listxattr(lower_dentry, list, size);
out:
	return rc;
}

int
sdcardfs_removexattr(struct dentry *dentry, const char *name)
{
	int rc = 0;
	struct dentry *lower_dentry;

	lower_dentry = sdcardfs_dentry_to_lower(dentry);
	if (!d_inode(lower_dentry)->i_op->removexattr) {
		rc = -EOPNOTSUPP;
		goto out;
	}
	mutex_lock(&d_inode(lower_dentry)->i_mutex);
	rc = d_inode(lower_dentry)->i_op->removexattr(lower_dentry, name);
	mutex_unlock(&d_inode(lower_dentry)->i_mutex);
out:
	return rc;
}
