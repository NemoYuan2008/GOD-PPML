#!/usr/bin/env bash

if (( EUID == 0 )); then
    tc_command=(tc)
else
    tc_command=(sudo tc)
fi

case "$1" in
    "wan")
	"${tc_command[@]}" qdisc del dev lo root >/dev/null 2>&1
	"${tc_command[@]}" qdisc add dev lo root netem delay 40ms rate 100Mbps
	;;
    "lan")
	"${tc_command[@]}" qdisc del dev lo root >/dev/null 2>&1
	"${tc_command[@]}" qdisc add dev lo root netem delay 0.1ms rate 15Gbps
	;;
    "reset")
	"${tc_command[@]}" qdisc del dev lo root
	;;    
    "custom")
	"${tc_command[@]}" qdisc add dev lo root netem delay "${2}ms" rate "${3}Mbit"
	;;
    *)
	echo "OPTIONS: use 'wan', 'lan', 'reset' or 'custom [delay] [rate]'."
	exit 1
	;;
esac
