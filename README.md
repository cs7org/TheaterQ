# NetworkTheater: Kernel Module for Trace File based Link Emulation

## Kernel Module
Build & Install:
```bash
# Install the required dependencies, e.g. on Debian:
# sudo apt install linux-headers-generic build-essentials make

cd theaterq_lkm
make all
sudo insmod sch_theaterq.ko
```

# TC Command for iproute2
Build & Use:
```bash
git submodule update --init
cd theaterq_tc
make all

TC_LIB_DIR=tclib tc qdisc [...]
```
