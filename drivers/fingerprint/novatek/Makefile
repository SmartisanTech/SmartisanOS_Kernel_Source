PWD			:= $(shell pwd)
KERNEL_DIR	:= ../..

#obj-y += nvt_spidev.o nvt_fpr_msm8994.o nt16101_utils.o nvt_debug_linux_kernel.o
#obj-y += nvt_spidev_16301.o nvt_fpr_msm8994.o nt16301_utils.o nvt_debug_linux_kernel.o
#obj-y += nvt_fpr_msm8994.o nvt_debug_linux_kernel.o
obj-y += nvt_fpr_sdm670.o nvt_debug_linux_kernel.o
#obj-y += nvt_fpr_sdm845_pt.o nvt_debug_linux_kernel.o
#obj-y += nvt_spidev_16301.o nvt_fpr_msm8994.o nt16201_utils.o nvt_debug_linux_kernel.o

ccflags-y += -Idrivers/fingerprint/novatek/include

all modules:
	ARCH=arm make -C $(KERNEL_DIR) M=$(PWD) modules

clean:
	$(RM) *.ko *.o module* .fpr* Module* *mod.c *.o.cmd
