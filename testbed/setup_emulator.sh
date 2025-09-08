#!/bin/bash

# Bash strict mode.
set -euo pipefail
IFS=$'\n\t'

ethtool -K eth1 tso off gso off gro off
ethtool -K eth2 tso off gso off gro off

ip a a 10.0.0.2/24 dev eth1
ip a a 10.0.1.2/24 dev eth2
ip l s up dev eth1
ip l s up dev eth2

sysctl -w net.ipv4.ip_forward=1 > /dev/null

insmod $TESTBED_PACKAGE/sch_theaterq.ko
install -m 0655 -d /var/local/tclib
cp $TESTBED_PACKAGE/q_theaterq.so /var/local/tclib/.

#python3 trace_to_lkm.py -i $FORWARD_LINK -t $TESTBED_PACKAGE/$FORWARD_TRACE load
#python3 trace_to_lkm.py -i $RETURN_LINK -t $TESTBED_PACKAGE/$RETURN_TRACE load
