IPR2 := ./iproute2
IPR2_TC := $(IPR2)/tc
IPR2_UAPI := $(IPR2)/include/uapi/linux
TC_LIB := ./tclib

.PHONY: clean

all: q_theaterq.c
	cp -v q_theaterq.c $(IPR2_TC)/.
	cp -v ../theaterq_lkm/include/uapi/linux/pkt_sch_theaterq.h $(IPR2_UAPI)/.
	make -C $(IPR2) -j$(nproc --ignore 1) TCSO=q_theaterq.so all
	mkdir -p $(TC_LIB)
	cp $(IPR2_TC)/q_theaterq.so $(TC_LIB)/.
clean:
	make -C $(IPR2) clean
	rm -vf $(IPR2_TC)/q_theaterq.c
	rm -vf $(IPR2_UAPI)/pkt_sch_theaterq.h
	rm -vrf $(TC_LIB)
