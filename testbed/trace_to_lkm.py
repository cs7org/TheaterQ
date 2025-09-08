#!/usr/bin/python3

import argparse
import subprocess

def load_theaterq(interface: str, trace: str) -> None:
    command = f"TC_LIB_DIR=/var/local/tclib tc qdisc add dev {interface} root handle 5 theaterq stage LOAD ingest EXTENDED"
    proc = subprocess.run(command, shell=True)
    if proc.returncode != 0:
        raise Exception("Unable to add qdisc")
    
    with open(trace, "r") as handle:
        traces = handle.readlines()
    
    traces = traces[1:]

    with open(f"/dev/theaterq:{interface}:5:0", "w") as handle:
        prev = 0
        for trace in traces:
            # Trace Format: at,delay,stddev,link_cap,queue_capacity,hops,ratio
            # LKM Format: <DELAY>,<LATENCY>,<JITTER>,<RATE>,<LOSS>,<LIMIT>,<DUP_PROB>,<DUP_DELAY>\n

            at, delay, stddev, min_link_cap, queue_cap, drops = trace.replace("\n", "").split(",")
            at_lkm = int(at)
            delay_lkm = max(0, int(delay) * 1000 - (1000 * 1000))
            jitter_lkm = int(float(stddev) * 1000)
            rate_lkm = int(float(min_link_cap))
            queue_cap_lkm = int((((float(min_link_cap) / 8) * (int(delay) / (1000 * 1000))) / 1024) * 0.5) + int(int(queue_cap) * 0.5)
            drops_lkm = int(round(float(drops) * 4294967295))

            handle.write(f"{at_lkm - prev},{delay_lkm},{jitter_lkm},{rate_lkm},{drops_lkm},{queue_cap_lkm},0,0\n")
            prev = at_lkm


def run_theaterq(interface: str) -> None:
    command = f"TC_LIB_DIR=/var/local/tclib tc qdisc change dev {interface} root handle 5 theaterq stage RUN cont HOLD"
    proc = subprocess.run(command, shell=True)
    if proc.returncode != 0:
        raise Exception("Unable to change qdisc")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("--interface", "-i", type=str, required=True, 
                        help="Interface")
    parser.add_argument("--trace", "-t", type=str, required=True,
                        help="Trace File")
    parser.add_argument("MODE", type=str, choices=["load", "run"])

    args = parser.parse_args()

    if args.MODE == "load":
        load_theaterq(args.interface, args.trace)
    else:
        run_theaterq(args.interface)
