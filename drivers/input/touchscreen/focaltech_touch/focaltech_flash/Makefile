#
# Makefile for the focaltech touchscreen drivers.
#

# Each configuration option enables a list of files.
ccflags-y += -I$(srctree)/drivers/input/touchscreen/
ccflags-y += -I$(srctree)/drivers/input/touchscreen/$(CONFIG_TOUCHSCREEN_FTS_DIRECTORY)
ccflags-y += -I$(srctree)/drivers/base

obj-$(CONFIG_TOUCHSCREEN_FTS) += focaltech_ft8716_upgrade.o
obj-$(CONFIG_TOUCHSCREEN_FTS) += focaltech_upgrade_idc.o
obj-$(CONFIG_TOUCHSCREEN_FTS) += focaltech_upgrade_test.o


