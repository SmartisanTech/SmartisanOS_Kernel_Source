/*
 * fs/sdcardfs/sdcardfs.h
 *
 * The sdcardfs v2.0
 *   This file system replaces the sdcard daemon on Android
 *   On version 2.0, some of the daemon functions have been ported
 *   to support the multi-user concepts of Android 4.4
 *
 * Copyright (c) 2013 Samsung Electronics Co. Ltd
 *   Authors: Daeho Jeong, Woojoong Lee, Seunghwan Hyun,
 *               Sunghwan Yun, Sungjong Seo
 *
 * This program has been developed as a stackable file system based on
 * the WrapFS which written by
 *
 * Copyright (c) 1998-2011 Erez Zadok
 * Copyright (c) 2009     Shrikar Archak
 * Copyright (c) 2003-2011 Stony Brook University
 * Copyright (c) 2003-2011 The Research Foundation of SUNY
 *
 * This file is dual licensed.  It may be redistributed and/or modified
 * under the terms of the Apache 2.0 License OR version 2 of the GNU
 * General Public License.
 */

#ifndef _SDCARDFS_H_
#define _SDCARDFS_H_

#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/seq_file.h>
#include <linux/statfs.h>
#include <linux/fs_stack.h>
#include <linux/magic.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/security.h>
#include <linux/string.h>
#include <linux/ratelimit.h>
#include "multiuser.h"

/* the file system magic number */
#define SDCARDFS_SUPER_MAGIC	0xb550ca10

/* the file system name */
#define SDCARDFS_NAME "sdcardfs"

/* sdcardfs root inode number */
#define SDCARDFS_ROOT_INO     1

/* useful for tracking code reachability */
#define UDBG printk(KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)

#define SDCARDFS_DIRENT_SIZE 256

/* temporary static uid settings for development */
#define AID_ROOT             0	/* uid for accessing /mnt/sdcard & extSdcard */
#define AID_MEDIA_RW      1023	/* internal media storage write access */

#define AID_SDCARD_RW     1015	/* external storage write access */
#define AID_SDCARD_R      1028	/* external storage read access */
#define AID_SDCARD_PICS   1033	/* external storage photos access */
#define AID_SDCARD_AV     1034	/* external storage audio/video access */
#define AID_SDCARD_ALL    1035	/* access all users external storage */

#define AID_PACKAGE_INFO  1027
#define AID_EVERYBODY     9997

/* OVERRIDE_CRED() and REVERT_CRED()
 * 	OVERRID_CRED()
 * 		backup original task->cred
 * 		and modifies task->cred->fsuid/fsgid to specified value.
 *	REVERT_CRED()
 * 		restore original task->cred->fsuid/fsgid.
 * These two macro should be used in pair, and OVERRIDE_CRED() should be
 * placed at the beginning of a function, right after variable declaration.
 */
#define OVERRIDE_CRED(sdcardfs_sbi, saved_cred)	\
	saved_cred = override_fsids(sdcardfs_sbi->options.fs_low_uid, \
								sdcardfs_sbi->options.fs_low_gid); \
	if (!saved_cred) { return -ENOMEM; }

#define OVERRIDE_CRED_PTR(sdcardfs_sbi, saved_cred)	\
	saved_cred = override_fsids(sdcardfs_sbi->options.fs_low_uid, \
								sdcardfs_sbi->options.fs_low_gid); \
	if (!saved_cred) { return ERR_PTR(-ENOMEM); }

#define OVERRIDE_ROOT_CRED(saved_cred) \
	saved_cred = override_fsids(0, 0); \
	if (!saved_cred) { return -ENOMEM; }

#define REVERT_CRED(saved_cred)	revert_fsids(saved_cred)

#define DEBUG_CRED()		\
	printk("KAKJAGI: %s:%d fsuid %d fsgid %d\n", 	\
		__FUNCTION__, __LINE__, 		\
		(int)current->cred->fsuid, 		\
		(int)current->cred->fsgid);

/* Permission mode for a specific node. Controls how file permissions
 * are derived for children nodes. */
typedef enum {
	/* Nothing special; this node should just inherit from its parent. */
	PERM_INHERIT,
	/* This node is one level above a normal root; used for legacy layouts
	 * which use the first level to represent user_id. */
	PERM_PRE_ROOT,
	/* This node is "/" */
	PERM_ROOT,
	/* This node is "/Android" */
	PERM_ANDROID,
	/* This node is "/Android/data" */
	PERM_ANDROID_DATA,
	/* This node is "/Android/obb" */
	PERM_ANDROID_OBB,
	/* This node is "/Android/media" */
	PERM_ANDROID_MEDIA,
	/* knox folder */
	PERM_ANDROID_KNOX,
	/* knox user folder*/
	PERM_ANDROID_KNOX_USER,
	/* knox Android folder*/
	PERM_ANDROID_KNOX_ANDROID,
	/* knox shared folder */
	PERM_ANDROID_KNOX_SHARED,
	/* knox data folder */
	PERM_ANDROID_KNOX_DATA,
	/* knox package data folder */
	PERM_ANDROID_KNOX_PACKAGE_DATA
} perm_t;

typedef enum {
	LOWER_FS_EXT4,
	LOWER_FS_FAT,
} lower_fs_t;

typedef enum {
	TYPE_NONE,
	TYPE_DEFAULT,
	TYPE_READ,
	TYPE_WRITE,
} type_t;

struct sdcardfs_sb_info;
struct sdcardfs_mount_options;

/* Do not directly use this function. Use OVERRIDE_CRED() instead. */
const struct cred * override_fsids(uid_t fsuid, gid_t fsgid);
/* Do not directly use this function, use REVERT_CRED() instead. */
void revert_fsids(const struct cred * old_cred);

/* operations vectors defined in specific files */
extern const struct file_operations sdcardfs_main_fops;
extern const struct file_operations sdcardfs_dir_fops;
extern const struct inode_operations sdcardfs_main_iops;
extern const struct inode_operations sdcardfs_dir_iops;
extern const struct inode_operations sdcardfs_symlink_iops;
extern const struct super_operations sdcardfs_sops;
extern const struct super_operations sdcardfs_multimount_sops;
extern const struct dentry_operations sdcardfs_ci_dops;
extern const struct address_space_operations sdcardfs_aops, sdcardfs_dummy_aops;
extern const struct vm_operations_struct sdcardfs_vm_ops;

extern int sdcardfs_init_inode_cache(void);
extern void sdcardfs_destroy_inode_cache(void);
extern int sdcardfs_init_dentry_cache(void);
extern void sdcardfs_destroy_dentry_cache(void);
extern int new_dentry_private_data(struct dentry *dentry);
extern void free_dentry_private_data(struct dentry *dentry);
extern struct dentry *sdcardfs_lookup(struct inode *dir, struct dentry *dentry,
				    unsigned int flags);
extern int sdcardfs_interpose(struct dentry *dentry, struct super_block *sb,
			    struct path *lower_path);

#ifdef SDCARD_FS_XATTR
extern int sdcardfs_setxattr(struct dentry *dentry, const char *name, const void *value, size_t size, int flags);
extern ssize_t sdcardfs_getxattr(struct dentry *dentry, const char *name, void *value, size_t size);
extern ssize_t sdcardfs_listxattr(struct dentry *dentry, char *list, size_t size);
extern int sdcardfs_removexattr(struct dentry *dentry, const char *name);
#endif // SDCARD_FS_XATTR
/* file private data */
struct sdcardfs_file_info {
	struct file *lower_file;
	const struct vm_operations_struct *lower_vm_ops;
};

/* sdcardfs inode data in memory */
struct sdcardfs_inode_info {
	struct inode *lower_inode;
	/* state derived based on current position in hierachy
	 */
	perm_t perm;
	userid_t userid;
	uid_t d_uid;
	gid_t d_gid;
	bool under_android;

	struct inode vfs_inode;
};

/* sdcardfs dentry data in memory */
struct sdcardfs_dentry_info {
	spinlock_t lock;	/* protects lower_path */
	struct path lower_path;
	struct path orig_path;
#ifdef CONFIG_SDP
	int under_knox;
	int userid;
#define PERMISSION_PRE_ROOT 		0
#define PERMISSION_ROOT 		1
#define PERMISSION_ANDROID 		2
#define PERMISSION_UNDER_ANDROID 	3
	int permission;
	appid_t appid;
#endif
};

struct sdcardfs_mount_options {
	uid_t fs_low_uid;
	gid_t fs_low_gid;
	gid_t gid;
	userid_t userid;
	lower_fs_t lower_fs;
	unsigned int reserved_mb;
	mode_t mask;
	bool multi_user;
	char *label;
	type_t type;
};

/* sdcardfs super-block data in memory */
struct sdcardfs_sb_info {
	struct super_block *lower_sb;
	/* derived perm policy : some of options have been added
	 * to sdcardfs_mount_options (Android 4.4 support) */
	struct sdcardfs_mount_options options;
	spinlock_t lock;	/* protects obbpath */
	char *obbpath_s;
	struct path obbpath;
	void *pkgl_id;
	char *devpath;
};

/*
 * inode to private data
 *
 * Since we use containers and the struct inode is _inside_ the
 * sdcardfs_inode_info structure, SDCARDFS_I will always (given a non-NULL
 * inode pointer), return a valid non-NULL pointer.
 */
static inline struct sdcardfs_inode_info *SDCARDFS_I(const struct inode *inode)
{
	return container_of(inode, struct sdcardfs_inode_info, vfs_inode);
}

/* dentry to private data */
#define SDCARDFS_D(dent) ((struct sdcardfs_dentry_info *)(dent)->d_fsdata)

/* superblock to private data */
#define SDCARDFS_SB(super) ((struct sdcardfs_sb_info *)(super)->s_fs_info)

/* file to private Data */
#define SDCARDFS_F(file) ((struct sdcardfs_file_info *)((file)->private_data))

/* file to lower file */
static inline struct file *sdcardfs_lower_file(const struct file *f)
{
	return SDCARDFS_F(f)->lower_file;
}

static inline void sdcardfs_set_lower_file(struct file *f, struct file *val)
{
	SDCARDFS_F(f)->lower_file = val;
}

/* inode to lower inode. */
static inline struct inode *sdcardfs_lower_inode(const struct inode *i)
{
	return SDCARDFS_I(i)->lower_inode;
}

static inline void sdcardfs_set_lower_inode(struct inode *i, struct inode *val)
{
	SDCARDFS_I(i)->lower_inode = val;
}

/* copy the inode attrs from src to dest except uid and gid */
static inline void sdcardfs_copy_inode_attr(struct inode *dest, const struct inode *src)
{
	dest->i_mode = src->i_mode;
	dest->i_rdev = src->i_rdev;
	dest->i_atime = src->i_atime;
	dest->i_mtime = src->i_mtime;
	dest->i_ctime = src->i_ctime;
	dest->i_blkbits = src->i_blkbits;
	dest->i_flags = src->i_flags;
	set_nlink(dest, src->i_nlink);
}

/* superblock to lower superblock */
static inline struct super_block *sdcardfs_lower_super(
	const struct super_block *sb)
{
	return SDCARDFS_SB(sb)->lower_sb;
}

static inline void sdcardfs_set_lower_super(struct super_block *sb,
					  struct super_block *val)
{
	SDCARDFS_SB(sb)->lower_sb = val;
}

/* path based (dentry/mnt) macros */
static inline void pathcpy(struct path *dst, const struct path *src)
{
	dst->dentry = src->dentry;
	dst->mnt = src->mnt;
}

/* sdcardfs_get_pname functions calls path_get()
 * therefore, the caller must call "proper" path_put functions
 */
#define SDCARDFS_DENT_FUNC(pname) \
static inline void sdcardfs_get_##pname(const struct dentry *dent, \
					struct path *pname) \
{ \
	spin_lock(&SDCARDFS_D(dent)->lock); \
	pathcpy(pname, &SDCARDFS_D(dent)->pname); \
	path_get(pname); \
	spin_unlock(&SDCARDFS_D(dent)->lock); \
	return; \
} \
static inline void sdcardfs_put_##pname(const struct dentry *dent, \
					struct path *pname) \
{ \
	path_put(pname); \
	return; \
} \
static inline void sdcardfs_set_##pname(const struct dentry *dent, \
					struct path *pname) \
{ \
	spin_lock(&SDCARDFS_D(dent)->lock); \
	pathcpy(&SDCARDFS_D(dent)->pname, pname); \
	spin_unlock(&SDCARDFS_D(dent)->lock); \
	return; \
} \
static inline void sdcardfs_reset_##pname(const struct dentry *dent) \
{ \
	spin_lock(&SDCARDFS_D(dent)->lock); \
	SDCARDFS_D(dent)->pname.dentry = NULL; \
	SDCARDFS_D(dent)->pname.mnt = NULL; \
	spin_unlock(&SDCARDFS_D(dent)->lock); \
	return; \
} \
static inline void sdcardfs_put_reset_##pname(const struct dentry *dent) \
{ \
	struct path pname; \
	spin_lock(&SDCARDFS_D(dent)->lock); \
	if(SDCARDFS_D(dent)->pname.dentry) { \
		pathcpy(&pname, &SDCARDFS_D(dent)->pname); \
		SDCARDFS_D(dent)->pname.dentry = NULL; \
		SDCARDFS_D(dent)->pname.mnt = NULL; \
		spin_unlock(&SDCARDFS_D(dent)->lock); \
		path_put(&pname); \
	} else \
		spin_unlock(&SDCARDFS_D(dent)->lock); \
	return; \
}

SDCARDFS_DENT_FUNC(lower_path)
SDCARDFS_DENT_FUNC(orig_path)

static inline void sdcardfs_copy_lower_path(const struct dentry *dent,
					struct path *lower_path)
{
	spin_lock(&SDCARDFS_D(dent)->lock);
	pathcpy(lower_path, &SDCARDFS_D(dent)->lower_path);
	spin_unlock(&SDCARDFS_D(dent)->lock);
	return;
}

static inline int has_graft_path(const struct dentry *dent)
{
	int ret = 0;

	spin_lock(&SDCARDFS_D(dent)->lock);
	if (SDCARDFS_D(dent)->orig_path.dentry != NULL)
		ret = 1;
	spin_unlock(&SDCARDFS_D(dent)->lock);

	return ret;
}

static inline void sdcardfs_get_real_lower(const struct dentry *dent,
						struct path *real_lower)
{
	/* in case of a local obb dentry
	 * the orig_path should be returned
	 */
	if(has_graft_path(dent))
		sdcardfs_get_orig_path(dent, real_lower);
	else
		sdcardfs_get_lower_path(dent, real_lower);
}

static inline void sdcardfs_put_real_lower(const struct dentry *dent,
						struct path *real_lower)
{
	if(has_graft_path(dent))
		sdcardfs_put_orig_path(dent, real_lower);
	else
		sdcardfs_put_lower_path(dent, real_lower);
}

/* for packagelist.c */
extern appid_t get_appid(void *pkgl_id, const char *app_name);
extern int check_caller_access_to_name(struct inode *parent_node, const char* name);
extern int open_flags_to_access_mode(int open_flags);
extern void *packagelist_create(void);
extern void packagelist_destroy(void *pkgl_id);
extern int packagelist_init(void);
extern void packagelist_exit(void);

/* for derived_perm.c */
extern void setup_derived_state(struct inode *inode, perm_t perm,
			userid_t userid, uid_t uid, gid_t gid, bool under_android);
extern void get_derived_permission(struct dentry *parent, struct dentry *dentry);
extern void fix_derived_permission(struct inode *inode);
extern void update_derived_permission(struct dentry *dentry);
extern int need_graft_path(struct dentry *dentry);
extern int is_base_obbpath(struct dentry *dentry);
extern int is_obbpath_invalid(struct dentry *dentry);
extern int setup_obb_dentry(struct dentry *dentry, struct path *lower_path);

/* locking helpers */
static inline struct dentry *lock_parent(struct dentry *dentry)
{
	struct dentry *dir = dget_parent(dentry);
	mutex_lock_nested(&d_inode(dir)->i_mutex, I_MUTEX_PARENT);
	return dir;
}

static inline void unlock_dir(struct dentry *dir)
{
	mutex_unlock(&d_inode(dir)->i_mutex);
	dput(dir);
}

static inline int prepare_dir(const char *path_s, uid_t uid, gid_t gid, mode_t mode)
{
	int err;
	struct dentry *dent;
	struct path path;
	struct iattr attrs;

	dent = kern_path_create(AT_FDCWD, path_s, &path, LOOKUP_DIRECTORY);

	if (IS_ERR(dent)) {
		err = PTR_ERR(dent);
		if (err == -EEXIST)
			err = 0;
		return err;
	}

	err = mnt_want_write(path.mnt);
	if (err)
		goto out;

	err = vfs_mkdir(d_inode(path.dentry), dent, mode);
	if (err) {
		if (err == -EEXIST)
			err = 0;
		goto out_drop;
	}

	attrs.ia_uid = make_kuid(current_user_ns(), uid);
	attrs.ia_gid = make_kgid(current_user_ns(), gid);
	attrs.ia_valid = ATTR_UID | ATTR_GID;
	mutex_lock(&d_inode(dent)->i_mutex);
	notify_change(dent, &attrs, NULL);
	mutex_unlock(&d_inode(dent)->i_mutex);

out_drop:
	mnt_drop_write(path.mnt);

out:
	dput(dent);
	/* parent dentry locked by kern_path_create */
	mutex_unlock(&d_inode(path.dentry)->i_mutex);
	path_put(&path);
	return err;
}

/*
 * Return 1, if a disk has enough free space, otherwise 0.
 * We assume that any files can not be overwritten.
 */
static inline int check_min_free_space(struct dentry *dentry, size_t size, int dir)
{
	int err;
	struct path lower_path;
	struct kstatfs statfs;
	u64 avail;
	struct sdcardfs_sb_info *sbi = SDCARDFS_SB(dentry->d_sb);

	if (sbi->options.reserved_mb) {
		/* Get fs stat of lower filesystem. */
		sdcardfs_get_lower_path(dentry, &lower_path);
		err = vfs_statfs(&lower_path, &statfs);
		sdcardfs_put_lower_path(dentry, &lower_path);

		if (unlikely(err))
			goto out_invalid;

		/* Invalid statfs informations. */
		if (unlikely(statfs.f_bsize == 0))
			goto out_invalid;

		/* if you are checking directory, set size to f_bsize. */
		if (unlikely(dir))
			size = statfs.f_bsize;

		/* available size */
		avail = statfs.f_bavail * statfs.f_bsize;

		/* not enough space */
		if ((u64)size > avail)
			goto out_nospc;

		/* enough space */
		if ((avail - size) > (sbi->options.reserved_mb * 1024 * 1024))
			return 1;
		goto out_nospc;
	} else
		return 1;

out_invalid:
	printk(KERN_INFO "statfs               : invalid return\n");
	printk(KERN_INFO "vfs_statfs error#    : %d\n", err);
	printk(KERN_INFO "statfs.f_type        : 0x%X\n", (u32)statfs.f_type);
	printk(KERN_INFO "statfs.f_blocks      : %llu blocks\n", statfs.f_blocks);
	printk(KERN_INFO "statfs.f_bfree       : %llu blocks\n", statfs.f_bfree);
	printk(KERN_INFO "statfs.f_files       : %llu\n", statfs.f_files);
	printk(KERN_INFO "statfs.f_ffree       : %llu\n", statfs.f_ffree);
	printk(KERN_INFO "statfs.f_fsid.val[1] : 0x%X\n", (u32)statfs.f_fsid.val[1]);
	printk(KERN_INFO "statfs.f_fsid.val[0] : 0x%X\n", (u32)statfs.f_fsid.val[0]);
	printk(KERN_INFO "statfs.f_namelen     : %ld\n", statfs.f_namelen);
	printk(KERN_INFO "statfs.f_frsize      : %ld\n", statfs.f_frsize);
	printk(KERN_INFO "statfs.f_flags       : %ld\n", statfs.f_flags);
	printk(KERN_INFO "sdcardfs reserved_mb : %u\n", sbi->options.reserved_mb);
	if (sbi->devpath)
		printk(KERN_INFO "sdcardfs source path : %s\n", sbi->devpath);

out_nospc:
	printk_ratelimited(KERN_INFO "statfs.f_bavail : %llu blocks / "
				     "statfs.f_bsize : %ld bytes / "
				     "required size : %llu byte\n"
				,statfs.f_bavail, statfs.f_bsize, (u64)size);
	return 0;
}
#endif	/* not _SDCARDFS_H_ */
