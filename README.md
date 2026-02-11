# TheaterQ: Kernel Module for Dynamic Link Emulation

TheaterQ provides a Linux queuing discipline for network emulation.
It can introduce different link impairments, e.g., bandwidth bottlenecks, delays, packet drops or packet reordering.
In difference to *NetEm*, these impairments can be configured with changes over time using Trace Files in a CSV format.
Therefore, it can be used to emulate network links or paths with dynamic characteristics.

## Kernel Module
Build & Install:
```bash
# Install the required dependencies, e.g. on Debian:
# sudo apt install linux-headers-generic build-essential make

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

# Make sure iproute2 is installed on the target system, e.g. on Debian:
# sudo apt install iproute2
# tc qdisc commands need to be executed with root privileges.

TC_LIB_DIR=tclib tc qdisc [...]
```

## Trace File Format
TheaterQ expects two Trace File line formats:
```
# Simple:
<KEEP>,<LATENCY>,<RATE>,<LOSS>,<LIMIT>\n
  u64     u64      u64    a)     u32

# Extended:
<KEEP>,<LATENCY>,<JITTER>,<RATE>,<LOSS>,<LIMIT>,<DUP_PROB>,<DUP_DELAY>,<ROUTE_ID>\n
  u64     u64      u64      u64     a)    u32       a)         u64         b)

# Type hints:
# a) Scaled u32: 0% = 0, 100% = U32_MAX
# b) u32 limited by reorder_routes kernel module options (default max is 244), 0 is reserved
```
Types are identical in both formats. 
Default format is `SIMPLE`, during creation of a TheaterQ qdisc instance the format can be set to `EXTENDED` by using the `ingest EXTENDED` option.
Lines starting with a non-numeric character are ignored.

- **`KEEP`**: The time in µs how long this entry is kept active before continuing with the next Trace File entry. Entries with 0 time or large values (>= U64_MAX / 1000) are not allowed.
- **`LATENCY`** and **`JITTER`**: Packet delay latency in ns with standard deviation.
- **`RATE`**: Adds a packet size based delay to each packet to emulate fixed link speeds, rate is given in bits per second.
- **`LOSS`**: Probability for a packet loss as a scaled 32bit integer value (0% = 0, 100% = `U32_MAX`, 0 in simple format).
- **`LIMIT`**: Currently available FIFO queue size as number of packets (or in bytes, depending on configuration). Packets that cannot be enqueued will be dropped. Once enqueued packets are always dequeued, changing the limit will not delete packets from the queue. Should not contain the bandwidth-delay product of the link, as this is handled by a second queue.
- **`DUP_PROB`** and **`DUP_DELAY`**: Probability for a packet to be duplicated, as a scaled 32bit integer value (0% = 0, 100% = `U32_MAX`, 0 in simple format). The duplicate will be statically delayed **`DUP_DELAY`** ns. A duplicated packet processed like any other, thus it is additionally affected by the `DELAY` and `JITTER`.
- **`ROUTE_ID`**: Allow implicit packet reordering only when the route through the network changes. Packets transmitted with the same route ID will not implicitly reorder (e.g. due to delay changes or when jitter is high). Packets transmitted without route ID changes will be transmitted strictly in arrival order, only during changes of the route ID implicit packet reordering is possible. Use 0 (default in simple format) to always allow implicit packet reordering.
Duplicated packets with `DUP_DELAY` are not affected by the route ID.
By default, 255 different routes are enabled, see [Module Parameters](#module-parameters) on how to increase this value during module load.

On parsing errors, the chardev will return *EINVAL* and an error message will be visible in `dmesg`.
Please note that rapid changes of the `LATENCY` values or high `JITTER` values will lead to implicit packet reordering, as long as `ROUTE_ID` is not used.

## Usage
Install the kernel module and set `TC_LIB_DIR`:
```bash
export TC_LIB_DIR=/absolute/path/to/tclib
```
> For a permanent installation of the *iproute2* plugin, the binary `theaterq_tc/tclib/q_theaterq.so` can be copied to `/usr/lib/<OS ARCH>-linux-gnu/tc/`.

TheaterQ is used in the following way:

1. Install the TheaterQ qdisc to an outgoing interface, e.g.:
   ```bash
   tc qdisc add dev <oif> root handle <major> theaterq <options>
   ```
   Since the TheaterQ is classful, it is possible to install other qdiscs as its child (Please note: Packets are dropped before they are enqueued in the child qdisc, therefore, AQM qdiscs might not work as expected). After installing TheaterQ it will first run transparently (no delays, no packet loss).
   When required, the extended Trace File format can be enabled using the `ingest EXTENDED` option.
2. The TheaterQ instance is now in the `LOAD` stage. A character device at `/dev/theaterq:<oif>:<major>:0` is available to ingest the Trace Files.
   ```bash
   cat tracefile > /dev/theaterq:<oif>:<major>:0
   ```
3. Start the Trace File playback. Once started, the character device no longer accepts new inputs.
   ```bash
   tc qdisc change dev <oif> root handle <major> theaterq stage {ARM|RUN} cont {LOOP|CLEAR|HOLD}
   ```
   - `stage ARM` will start the playback when the first packet is transmitted. `stage RUN` will start the playback immediately.
   - `cont LOOP` will restart at the beginning of the Trace File after the end was reached, `cont HOLD` will hold the last values of the Trace File, and `cont CLEAR` will reset the qdisc to transparent operation.
   - Additionally, a seed for the jitter/loss random generator and a packet overhead for the rate calculation can be specified, see `tc qdisc add theaterq help` for further details. 
   The `byteqlen` option switches the queue length limit (*`<LIMIT>`*) from packets counts to packet byte length, `pktqlen` will switch it back to packets (default: packets).
   The `allow_gso`/`prevent_gso` flag disables/enables automatic GSO packet segmentation (default: disabled). 
   Use `ecn_enable`/`ecn_disbale` to configure whether RFC 3168 ECNs should be sent when queue length limit (*`<LIMIT>`*) is reached (default: disabled).
   Use `apply_before_q`/`apply_after_q` to select whether link characteristics (delay, jitter, bandwidth limitations) should be applied before packets are enqueued into the FFO or after dequeuing. In the latter case, effects of link characteristics are delayed the amount of time a packet spends in the queue (in case of a single packet transmission, both settings will behave identical).
   Use ``
4. By using 
   ```bash
   tc qdisc change dev <oif> root handle <major> theaterq stage LOAD
   ```
   it is possible to reset TheaterQ back to its transparent mode and to add additional Trace File entries via the character device. All Trace File entries can be cleared using
   ```bash
   tc qdisc change dev <oif> root handle <major> theaterq stage CLEAR
   ```
   In both cases the Trace File replay is stopped.

### Syncgroups
Multiple TheaterQ qdisc instances can be added to syncgroups, e.g. to sync the Trace File replay between a forward and return link interface. Use the following workflow:
1. Create both qdiscs on different interfaces but add the `syncgroup <group>` option. All qdiscs with the same syncgroup number will be started synchronously. With default settings, 8 syncgroups are available (0-7), while each group can have up to 8 members. To add a syncgroup, they have to be in stage `LOAD`, `ARM` or `FINISH`.
2. Load the Trace Files. Note: Trace files can have different entries and lengths, just the start point is synchronized between the groups.
3. Setting one qdisc to the `RUN` stage will set all the other to `RUN`, whenever possible (e.g. a Trace File was ingested, and they are in a suitable stage).
It is also possible to set one or more qdiscs to the `ARM` stage; in this case, the first received packet on any qdisc in this stage and group will set all members and itself to `RUN`.
4. Setting one qdisc of a group to stage `LOAD` or `CLEAR` will set all other members to `LOAD` and stop the Trace File replay.
5. Pass to `syncgroup -1` to a qdisc to leave the current syncgroup.

By default, 8 syncgroups with 8 members each are available by default. See [Module Parameters](#module-parameters) to change these values during loading of the module.

## Debugging and Statistics

The current configuration, applied link emulation settings, the position inside the replayed Trace File as well as the ingestion character device path can be obtained using the following command. Use `-j` for a JSON representation.
```bash
tc [-j] qdisc show dev <oif> handle <major>
```
Important values:
- `entries`: Loaded Trace File entries
- `position`: Currently applied Trace File entry (starting with 0, only valid when stage is `RUN` or `FINISHED`)
- `delay`, `jitter`, `rate`, `loss`, `limit`, `duplicate_probability`, `duplicate_delay`: Currently active link emulation setting from the Trace File. 

The xstats subsystem can be used to obtain additional statistics, use `-j` for a JSON representation.
```bash
tc [-j] -s qdisc show dev <oif> handle <major>
```
Important values:
- `looped`: Number of Trace File repetitions (when cont is `LOOP`)
- `duration`: Accumulated runtime of all Trace File entries
- `entries`: Number of entries that were applied

## Module Parameters
The kernel module can be configured during loading with the following parameters:
- `syncgrps`: Maximum number of syncgroups (u8, default = 8)
- `syncgrps_members`: Maximum number of members in each syncgroup (u8, default = 8)
- `reorder_routes`: Number of different reorder routes (each reorder routes internally tracks an u64 timestamp, static memory allocation for each theaterq instance: *reorder_routes * 8 bytes*). The *ROUTE_ID* in the extended format cannot be larger than this value (u16, default = 255)

Example:
```bash
sudo insmod sch_theaterq.ko syncgrps=16 syncgrps_members=16 reorder_routes=1024
```
Check the current configuration using `cat /sys/module/sch_theaterq/parameters/{syncgrps,syncgrps_members,reorder_routes}`. Parameter settings cannot be changed while the module is loaded.

## License
This project is licensed under the [GNU General Public License v2.0](LICENSE). For more details, see the `LICENSE` file or see https://www.gnu.org/licenses/.
