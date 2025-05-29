# See https://docs.kernel.org/kbuild/makefiles.html

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

EXTRA_CFLAGS = -I$(PWD)/include
obj-m += sch_theaterq.o
#sch_theaterq-y := sch_theaterq.o
ccflags-y += -include $(PWD)/include/uapi/linux/pkt_sch_theaterq.h

.PHONY: clean

all: sch_theaterq.c include/uapi/linux/pkt_sch_theaterq.h
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
