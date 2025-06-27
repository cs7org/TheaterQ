# TheaterQ: Kernel Module for Trace File based Link Emulation

## Kernel Module
Build & Install:
```bash
# Install the required dependencies, e.g. on Debian:
# sudo apt install linux-headers-generic build-essentials make

cd theaterq_lkm
make all
sudo insmod sch_theaterq.ko
```

## TC Command for iproute2
Build & Use:
```bash
git submodule update --init
cd theaterq_tc
make all

TC_LIB_DIR=tclib tc qdisc [...]
```

## Trace File Format
TheaterQ expects the following Trace File line format:
```
<DELAY>,<LATENCY>,<JITTER>,<RATE>,<LOSS>,<LIMIT>\n
```
- **`DELAY`**: Delay after which this line is activated in ns. The first entry must have a delay of 0.
- **`LATENCY`** and **`JITTER`**: Packet delay latency in ns.
- **`RATE`**: Adds a packet size based delay to each packet to emulate fixed link speeds, rate is given in bits per second.
- **`LOSS`**: Probability for a packet loss as a scaled 32bit integer value (0% = 0, 100% = `U32_MAX`).
- **`LIMIT`**: Currently available queue size as number of packets (or in bytes, depending on configuration). Packets that cannot be enqueued will be dropped. Once enqueued packets are always dequeued, changing the limit will not delete packets from the queue.

On parsing errors, the chardev will return *EINVAL* and an error message will be visible in `dmesg`.

## Usage
Install the kernel module and set `TC_LIB_DIR`:
```bash
export TC_LIB_DIR=/absolute/path/to/tclib
```

TheaterQ is used in the following way:

1. Install the TheaterQ qdisc to an outgoing interface, e.g.:
   ```bash
   tc qdisc add dev <oif> root handle <major> theaterq
   ```
   Since the TheaterQ is classfull, it is possible to install other qdiscs as its child. After installing TheaterQ it will first run transparently (no delays, no packet loss).
2. The TheaterQ instance is now in the `LOAD` stage. A character device at `/dev/theaterq:<oif>:<major>:0` is available to ingest the Trace Files.
   ```bash
   cat tracefile > /dev/theaterq:<oif>:<major>:0
   ```
3. Start the Trace File Playback. Once started, the character device no longer accepts new inputs.
   ```bash
   tc qdisc change dev <oif> root handle <major> theaterq stage {ARM|RUN} cont {LOOP|CLEAR|HOLD}
   ```
   - `stage ARM` will start the playback when the first packet is transmitted. `stage RUN` will start the playback immediately.
   - `cont LOOP` will restart at the beginning of the Trace File after the end was reached, `cont HOLD` will hold the last values of the Trace File, and `cont CLEAR` will reset the qdisc to transparent operation.
   - Additionally, a seed for the jitter/loss random generator and a packet overhead for the rate calculation can be specified, see `tc qdisc add theaterq help` for further details. The `byteqlen` option switches the queue length limit (*`<LIMIT>`*) from packets counts to packet byte length.  The `allow_gso` flag disables automatic GSO packet segmentation.
4. By using 
   ```bash
   tc qdisc change dev <oif> root handle <major> theaterq stage LOAD
   ```
   it is possible to reset TheaterQ back to its transparent mode and to add additional Trace File entries via the character device. All Trace File entries can be cleared using
   ```bash
   tc qdisc change dev <oif> root handle <major> theaterq stage CLEAR
   ```
   In both cases the Trace File Replay is stopped.

## Debugging and Statistics

The current configuration, applied link emulation settings, the position inside the replayed Trace File as well as the ingestion character device path can be obtained using the following command. Use `-j` for a JSON representation.
```bash
tc [-j] qdisc show dev <oif> handle <major>
```
Important values:
- `entries`: Loaded Trace File entries
- `position`: Currently applied Trace File entry (starting with 0, only valid when stage is `RUN` or `FINISHED`)
- `delay`, `jitter`, `rate`, `loss`, `limit`: Currently active link emulation setting from the Trace File. 

The xstats subsystem can be used to obtain additional statistics, use `-j` for a JSON representation.
```bash
tc [-j] -s qdisc show dev <oif> handle <major>
```
Important values:
- `looped`: Number of Trace File repetitions (when cont is `LOOP`)
- `duration`: Accumulated runtime of all Trace File entries
- `entries`: Number of entries that were applied
