/*
 * fs/sdcardfs/derived_perm.c
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

#include "sdcardfs.h"

/* copy derived state from parent inode */
static void inherit_derived_state(struct inode *parent, struct inode *child)
{
	struct sdcardfs_inode_info *pi = SDCARDFS_I(parent);
	struct sdcardfs_inode_info *ci = SDCARDFS_I(child);

	ci->perm = PERM_INHERIT;
	ci->userid = pi->userid;
	ci->d_uid = pi->d_uid;
	ci->d_gid = pi->d_gid;
	ci->under_android = pi->under_android;
}

/* helper function for derived state */
void setup_derived_state(struct inode *inode, perm_t perm,
                        userid_t userid, uid_t uid, gid_t gid, bool under_android)
{
	struct sdcardfs_inode_info *info = SDCARDFS_I(inode);

	info->perm = perm;
	info->userid = userid;
	info->d_uid = uid;
	info->d_gid = gid;
	info->under_android = under_android;
}

void get_derived_permission(struct dentry *parent, struct dentry *dentry)
{
	struct sdcardfs_sb_info *sbi = SDCARDFS_SB(dentry->d_sb);
	struct sdcardfs_inode_info *info = SDCARDFS_I(d_inode(dentry));
	struct sdcardfs_inode_info *parent_info= SDCARDFS_I(d_inode(parent));
#ifdef CONFIG_SDP
	struct sdcardfs_dentry_info *parent_dinfo = SDCARDFS_D(parent);
#endif
	appid_t appid;

	/* By default, each inode inherits from its parent.
	 * the properties are maintained on its private fields
	 * because the inode attributes will be modified with that of
	 * its lower inode.
	 * The derived state will be updated on the last
	 * stage of each system call by fix_derived_permission(inode).
	 */

	inherit_derived_state(d_inode(parent), d_inode(dentry));

	/* Derive custom permissions based on parent and current node */
	switch (parent_info->perm) {
		case PERM_INHERIT:
			/* Already inherited above */
			break;
		case PERM_PRE_ROOT:
			/* Legacy internal layout places users at top level */
			info->perm = PERM_ROOT;
			info->userid = simple_strtoul(dentry->d_name.name, NULL, 10);
			break;
		case PERM_ROOT:
			/* Assume masked off by default. */
			if (!strcasecmp(dentry->d_name.name, "Android")) {
				/* App-specific directories inside; let anyone traverse */
				info->perm = PERM_ANDROID;
				info->under_android = true;
			} else if (!strcasecmp(dentry->d_name.name, "knox")) {
				info->perm = PERM_ANDROID_KNOX;
				info->d_gid = AID_SDCARD_R;
				info->under_android = false;
			}
			break;
		case PERM_ANDROID:
			if (!strcasecmp(dentry->d_name.name, "data")) {
				/* App-specific directories inside; let anyone traverse */
				info->perm = PERM_ANDROID_DATA;
			} else if (!strcasecmp(dentry->d_name.name, "obb")) {
				/* App-specific directories inside; let anyone traverse */
				info->perm = PERM_ANDROID_OBB;
				// FIXME : this feature will be implemented later.
				/* Single OBB directory is always shared */
			} else if (!strcasecmp(dentry->d_name.name, "media")) {
				/* App-specific directories inside; let anyone traverse */
				info->perm = PERM_ANDROID_MEDIA;
			}
			break;
		/* same policy will be applied on PERM_ANDROID_DATA
		 * and PERM_ANDROID_OBB */
		case PERM_ANDROID_DATA:
		case PERM_ANDROID_OBB:
		case PERM_ANDROID_MEDIA:
			appid = get_appid(sbi->pkgl_id, dentry->d_name.name);
			if (appid != 0) {
				info->d_uid = multiuser_get_uid(parent_info->userid, appid);
			}
			break;
		/** KNOX permission */
		case PERM_ANDROID_KNOX:
			info->perm = PERM_ANDROID_KNOX_USER;
			info->userid = simple_strtoul(dentry->d_name.name, NULL, 10);
			info->d_gid = AID_SDCARD_R;
			info->under_android = false;
			break;
		case PERM_ANDROID_KNOX_USER:
			if (!strcasecmp(dentry->d_name.name, "Android")) {
				info->perm = PERM_ANDROID_KNOX_ANDROID;
				info->under_android = false;
			}
			break;
		case PERM_ANDROID_KNOX_ANDROID:
			if (!strcasecmp(dentry->d_name.name, "data")) {
				info->perm = PERM_ANDROID_KNOX_DATA;
				info->under_android = false;
			} else if (!strcasecmp(dentry->d_name.name, "shared")) {
				info->perm = PERM_ANDROID_KNOX_SHARED;
				info->d_gid = AID_SDCARD_RW;
				info->d_uid = multiuser_get_uid(parent_info->userid, 0);
				info->under_android = false;
			}
			break;
		case PERM_ANDROID_KNOX_SHARED:
			break;
		case PERM_ANDROID_KNOX_DATA:
			appid = get_appid(sbi->pkgl_id, dentry->d_name.name);
			info->perm = PERM_ANDROID_KNOX_PACKAGE_DATA;
			if (appid != 0) {
				info->d_uid = multiuser_get_uid(parent_info->userid, appid);
			} else {
				info->d_uid = multiuser_get_uid(parent_info->userid, 0);
			}
			info->under_android = false;
			break;
		case PERM_ANDROID_KNOX_PACKAGE_DATA:
			break;
	}
#ifdef CONFIG_SDP
	if((parent_info->perm == PERM_PRE_ROOT) && (parent_dinfo->under_knox) && (parent_dinfo->userid >= 0)) {
		info->userid = parent_dinfo->userid;
	}

	if(parent_dinfo->under_knox) {
		if(parent_dinfo->permission == PERMISSION_UNDER_ANDROID) {
			if (parent_dinfo->appid != 0){
				info->d_uid = multiuser_get_uid(parent_info->userid, parent_dinfo->appid);
			}
		}
	}
#endif
}

/* set vfs_inode from sdcardfs_inode */
void fix_derived_permission(struct inode *inode) {
	struct sdcardfs_inode_info *info = SDCARDFS_I(inode);
	struct sdcardfs_sb_info *sbi = SDCARDFS_SB(inode->i_sb);
	struct sdcardfs_mount_options *opts = &sbi->options;
	mode_t visible_mode;
	mode_t owner_mode;
	mode_t filtered_mode;

	inode->i_uid = make_kuid(current_user_ns(), info->d_uid);

	if (info->d_gid == AID_SDCARD_RW) {
        /* As an optimization, certain trusted system components only run
         * as owner but operate across all users. Since we're now handing
         * out the sdcard_rw GID only to trusted apps, we're okay relaxing
         * the user boundary enforcement for the default view. The UIDs
         * assigned to app directories are still multiuser aware. */
		inode->i_gid = make_kgid(current_user_ns(), AID_SDCARD_RW);
	} else {
		inode->i_gid = make_kgid(current_user_ns(), multiuser_get_uid(info->userid, info->d_gid));
	}

	visible_mode = 00775 & ~opts->mask;
	if (info->perm == PERM_PRE_ROOT) {
        /* Top of multi-user view should always be visible to ensure
         * secondary users can traverse inside. */
		visible_mode = 00711;
	} else if (info->perm == PERM_ANDROID_KNOX_PACKAGE_DATA
			&& !info->under_android) {
		visible_mode = visible_mode & ~00006;
	} else if (info->under_android) {
		if (info->d_gid == AID_SDCARD_RW) {
			visible_mode = visible_mode & ~00006;
		} else {
			visible_mode = visible_mode & ~00007;
		}
	}

	owner_mode = inode->i_mode & 0700;
	filtered_mode = visible_mode & (owner_mode | (owner_mode >> 3) | (owner_mode >> 6));
	inode->i_mode = ((inode->i_mode & S_IFMT) | filtered_mode);
}

/* main function for updating derived permission */
inline void update_derived_permission(struct dentry *dentry)
{
	struct dentry *parent;

	if(!dentry || !d_inode(dentry)) {
		printk(KERN_ERR "sdcardfs: %s: invalid dentry\n", __func__);
		return;
	}
	/* FIXME:
	 * 1. need to check whether the dentry is updated or not
	 * 2. remove the root dentry update
	 */
	if(IS_ROOT(dentry)) {
		//setup_default_pre_root_state(d_inode(dentry));
	} else {
		parent = dget_parent(dentry);
		if(parent) {
			get_derived_permission(parent, dentry);
			dput(parent);
		}
	}
	fix_derived_permission(d_inode(dentry));
}

int need_graft_path(struct dentry *dentry)
{
	int ret = 0;
	struct dentry *parent = dget_parent(dentry);
	struct sdcardfs_inode_info *parent_info= SDCARDFS_I(d_inode(parent));
	struct sdcardfs_sb_info *sbi = SDCARDFS_SB(dentry->d_sb);

	if(parent_info->perm == PERM_ANDROID &&
			!strcasecmp(dentry->d_name.name, "obb") &&
			sbi->options.multi_user) {
		ret = 1;
	}
	dput(parent);
	return ret;
}

int is_obbpath_invalid(struct dentry *dent)
{
	int ret = 0;
	struct sdcardfs_dentry_info *di = SDCARDFS_D(dent);
	struct sdcardfs_sb_info *sbi = SDCARDFS_SB(dent->d_sb);
	char *path_buf, *obbpath_s;

	/* check the base obbpath has been changed.
	 * this routine can check an uninitialized obb dentry as well.
	 * regarding the uninitialized obb, refer to the sdcardfs_mkdir() */
	spin_lock(&di->lock);
	if(di->orig_path.dentry) {
 		if(!di->lower_path.dentry) {
			ret = 1;
		} else {
			path_get(&di->lower_path);
			//lower_parent = lock_parent(lower_path->dentry);

			path_buf = kmalloc(PATH_MAX, GFP_ATOMIC);
			if(!path_buf) {
				ret = 1;
				printk(KERN_ERR "sdcardfs: fail to allocate path_buf in %s.\n", __func__);
			} else {
				obbpath_s = d_path(&di->lower_path, path_buf, PATH_MAX);
				if (d_unhashed(di->lower_path.dentry) ||
					strcasecmp(sbi->obbpath_s, obbpath_s)) {
					ret = 1;
				}
				kfree(path_buf);
			}

			//unlock_dir(lower_parent);
			path_put(&di->lower_path);
		}
	}
	spin_unlock(&di->lock);
	return ret;
}

int is_base_obbpath(struct dentry *dentry)
{
	int ret = 0;
	struct dentry *parent = dget_parent(dentry);
	struct sdcardfs_inode_info *parent_info= SDCARDFS_I(d_inode(parent));
	struct sdcardfs_sb_info *sbi = SDCARDFS_SB(dentry->d_sb);

	spin_lock(&SDCARDFS_D(dentry)->lock);
	/* if multi_user is true */
	if(sbi->options.multi_user && parent_info->perm == PERM_PRE_ROOT &&
			!strcasecmp(dentry->d_name.name, "obb")) {
		ret = 1;
	}
	/* if multi_user is false, /Android/obb is the base obbpath */
	else if (!sbi->options.multi_user && parent_info->perm == PERM_ANDROID &&
			!strcasecmp(dentry->d_name.name, "obb")) {
		ret = 1;
	}
	spin_unlock(&SDCARDFS_D(dentry)->lock);
	dput(parent);
	return ret;
}

/* The lower_path will be stored to the dentry's orig_path
 * and the base obbpath will be copyed to the lower_path variable.
 * if an error returned, there's no change in the lower_path
 * returns: -ERRNO if error (0: no error) */
int setup_obb_dentry(struct dentry *dentry, struct path *lower_path)
{
	int err = 0;
	struct sdcardfs_sb_info *sbi = SDCARDFS_SB(dentry->d_sb);
	struct path obbpath;

	/* A local obb dentry must have its own orig_path to support rmdir
	 * and mkdir of itself. Usually, we expect that the sbi->obbpath
	 * is avaiable on this stage. */
	sdcardfs_set_orig_path(dentry, lower_path);

	err = kern_path(sbi->obbpath_s,
			LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &obbpath);

	if(!err) {
		/* the obbpath base has been found */
		printk(KERN_INFO "sdcardfs: the sbi->obbpath is found\n");
		pathcpy(lower_path, &obbpath);
	} else {
		/* if the sbi->obbpath is not available, we can optionally
		 * setup the lower_path with its orig_path.
		 * but, the current implementation just returns an error
		 * because the sdcard daemon also regards this case as
		 * a lookup fail. */
		printk(KERN_INFO "sdcardfs: the sbi->obbpath is not available\n");
	}
	return err;
}
