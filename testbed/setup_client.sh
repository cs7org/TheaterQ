#!/bin/bash

ethtool -K eth1 tso off gso off gro off

ip a a $IP_ADDRESS dev eth1
ip l s up dev eth1
ip r a $ROUTE dev eth1

/usr/sbin/tc qdisc add root handle 1: dev eth1 netem limit 10
