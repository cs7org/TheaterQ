#!/bin/bash

if [[ "$EUID" -ne 0 ]]; then
    echo "Error: Script must be run as root user (e.g. via sudo)" >&2
    exit 1
fi

make -C ../theaterq_lkm all
cp ../theaterq_lkm/sch_theaterq.ko .
make -C ../theaterq_lkm clean

make -C ../theaterq_tc all
cp ../theaterq_tc/tclib/q_theaterq.so .
make -C ../theaterq_tc clean

export FORWARD_TRACE="traces/delay.csv"
export RETURN_TRACE="traces/null.csv"

p2t run -e pingtest_script -i INIT .
p2t export csv -o out/ -e pingtest_script .
p2t clean -e pingtest_script
