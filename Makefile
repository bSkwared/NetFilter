ifneq ($(KERNELRELEASE),)
# call from kernel build system

nf_mod-objs := netfilter_main.o

obj-m	:= nf_mod.o

else

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)

modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

endif

clean:
	rm -rf *.o *.ko *.mod.c *.order *.symvers

