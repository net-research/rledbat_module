ifeq ($(KERNELRELEASE),)

KERNELDIR ?= /lib/modules/$(shell uname -r)/build

module:
	$(MAKE) -C $(KERNELDIR) M=$(shell pwd) C=1 modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(shell pwd) C=1 clean

.PHONY: module clean

else

MODULE = rledbat_receive.o
CFLAGS_$(MODULE) := -DDEBUG -Wall -Wextra -Wno-unused-parameter
obj-m := $(MODULE)

endif
