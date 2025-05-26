#!/usr/bin/env bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <protocol> <progname>"
    exit 1
fi

protocol=$1
progname=$2

./dev-scripts/run-$protocol.sh $progname 3 2 2
sleep 3
./dev-scripts/run-$protocol.sh $progname 5 3 4
sleep 3
./dev-scripts/run-$protocol.sh $progname 7 4 6
sleep 3
./dev-scripts/run-$protocol.sh $progname 9 5 8
sleep 3
./dev-scripts/run-$protocol.sh $progname 11 6 10
sleep 3
./dev-scripts/run-$protocol.sh $progname 13 7 12
sleep 3
./dev-scripts/run-$protocol.sh $progname 15 8 14
