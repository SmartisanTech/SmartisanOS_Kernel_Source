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
ssize_t
sdcardfs_listxattr(struct dentry *dentry, char *list, size_t size)
{
	int rc = 0;
	struct dentry *lower_dentry;
	struct inode *inode;
	const struct cred *saved_cred = NULL;
	struct sdcardfs_sb_info *sbi = SDCARDFS_SB(dentry->d_sb);

	inode = d_inode(dentry);
	lower_dentry = sdcardfs_dentry_to_lower(dentry);
	if (!d_inode(lower_dentry)->i_op->listxattr) {
		rc = -EOPNOTSUPP;
		goto out;
	}

	/* save current_cred and override it */
	OVERRIDE_CRED(sbi, saved_cred, SDCARDFS_I(inode));
	rc = vfs_listxattr(lower_dentry, list, size);
	REVERT_CRED(saved_cred);

out:
	return rc;
}

int __sdcardfs_xattr_get(struct dentry *dentry, const char *name,
		  void *value, size_t size)
{
	ssize_t res;
	struct dentry *lower_dentry;
	struct inode *inode;
	const struct cred *saved_cred = NULL;
	struct sdcardfs_sb_info *sbi = SDCARDFS_SB(dentry->d_sb);

	inode = d_inode(dentry);
	lower_dentry = sdcardfs_dentry_to_lower(dentry);

	/* save current_cred and override it */
	OVERRIDE_CRED(sbi, saved_cred, SDCARDFS_I(inode));
	res = vfs_getxattr(lower_dentry, name, value, size);
	REVERT_CRED(saved_cred);

	return res;
}
int __sdcardfs_xattr_set(struct dentry *dentry, const char *name, const void *value,
		  size_t size, int flags)
{
	ssize_t res;
	struct dentry *lower_dentry;
	const struct cred *saved_cred = NULL;
	struct sdcardfs_sb_info *sbi = SDCARDFS_SB(dentry->d_sb);
	struct inode *inode;

	inode = d_inode(dentry);
	lower_dentry = sdcardfs_dentry_to_lower(dentry);
	//ftrace_print("%s, %d, magic=0x%X, ino=%lu, name=%s, value=%p, size=%zd, flags=%d\n", __func__, __LINE__, inode->i_sb->s_magic, inode->i_ino, name, value, size, flags);

	/* save current_cred and override it */
	OVERRIDE_CRED(sbi, saved_cred, SDCARDFS_I(inode));
	if (value)
		res = vfs_setxattr(lower_dentry, name, value, size, flags);
	else {
		WARN_ON(flags != XATTR_REPLACE);
		res = vfs_removexattr(lower_dentry, name);
	}
	REVERT_CRED(saved_cred);

	return res;
}


static int sdcardfs_xattr_get(const struct xattr_handler *handler,
			       struct dentry *dentry, struct inode *inode,
			       const char *name, void *buffer, size_t size)
{
	return __sdcardfs_xattr_get(dentry, name, buffer, size);
}

static int sdcardfs_xattr_set(const struct xattr_handler *handler,
			       struct dentry *dentry, struct inode *inode,
			       const char *name, const void *value,
			       size_t size, int flags)
{
	return __sdcardfs_xattr_set(dentry, name, value, size, flags);
}

static const struct xattr_handler sdcardfs_xattr_handler = {
	.prefix	= "", /* catch all */
	.get = sdcardfs_xattr_get,
	.set = sdcardfs_xattr_set,
};

const struct xattr_handler *sdcardfs_xattr_handlers[] = {
	&sdcardfs_xattr_handler,
	NULL
};

