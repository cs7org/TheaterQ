PACKAGE_BASE := package/
KERNEL_TARGET = $(shell uname -r)
PATH_MODULE := $(PACKAGE_BASE)/lib/modules/$(KERNEL_TARGET)/extra/
PATH_IPROUTE := $(PACKAGE_BASE)/usr/lib/$(shell uname -m)-linux-gnu/tc/
PATH_UDEV := $(PACKAGE_BASE)/etc/udev/rules.d/

.PHONY: clean

all: DEBIAN/control 42-theaterq.rules
	make -C ../theaterq_lkm all
	make -C ../theaterq_tc all
	mkdir -p $(PATH_MODULE)
	cp ../theaterq_lkm/sch_theaterq.ko $(PATH_MODULE)/.
	mkdir -p $(PATH_IPROUTE)
	cp ../theaterq_tc/tclib/q_theaterq.so $(PATH_IPROUTE)/.
	mkdir -p $(PATH_UDEV)
	cp 42-theaterq.rules $(PATH_UDEV)/.
	cp -r DEBIAN $(PACKAGE_BASE)/.
	dpkg-deb --build $(PACKAGE_BASE) theaterq.deb

clean:
	rm -rf $(PACKAGE_BASE) theaterq.deb
