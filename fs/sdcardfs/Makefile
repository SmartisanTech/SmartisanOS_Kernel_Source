ifeq ($(CONFIG_SDCARD_FS_XATTR),y)
EXTRA_CFLAGS += -DSDCARD_FS_XATTR
endif

obj-$(CONFIG_SDCARD_FS) += sdcardfs.o

sdcardfs-y := dentry.o file.o inode.o main.o super.o lookup.o mmap.o packagelist.o derived_perm.o
sdcardfs-$(CONFIG_SDCARD_FS_XATTR) += xattr.o
