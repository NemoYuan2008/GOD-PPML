#!/usr/bin/bash

case "$1" in
    "wan")
    sudo tc qdisc del dev eth0 root >/dev/null 2>&1
	sudo tc qdisc add dev eth0 root netem delay 40ms rate 100Mbps
	;;
    "lan")
    sudo tc qdisc del dev eth0 root >/dev/null 2>&1
	sudo tc qdisc add dev eth0 root netem delay 0.1ms rate 15Gbps
	;;
    "reset")
	sudo tc qdisc del dev eth0 root
	;;    
    "custom")
	sudo tc qdisc add dev eth0 root netem delay ${2}ms rate ${3}Mbit
	;;
    *)
	echo "OPTIONS: use 'wan', 'lan', 'reset' or 'custom [delay] [rate]'."
	exit 1
	;;
esac