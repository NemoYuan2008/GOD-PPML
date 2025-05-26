#!/usr/bin/env bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <protocol> <progname>"
    exit 1
fi

protocol=$1
progname=$2

./dev-scripts/run-$protocol.sh $progname 3 0 1
sleep 3
./dev-scripts/run-$protocol.sh $progname 5 0 2
sleep 3
./dev-scripts/run-$protocol.sh $progname 7 0 3
sleep 3
./dev-scripts/run-$protocol.sh $progname 9 0 4
sleep 3
./dev-scripts/run-$protocol.sh $progname 11 0 5
sleep 3
./dev-scripts/run-$protocol.sh $progname 13 0 6
sleep 3
./dev-scripts/run-$protocol.sh $progname 15 0 7
