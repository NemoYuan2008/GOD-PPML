#!/usr/bin/env bash

HERE=$(cd `dirname $0`; pwd)
SPDZROOT=$HERE/..

if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <progname> <number_of_parties> <start_party> <end_party>"
    exit 1
fi

progname=$1
nparties=$2
start=$3
end=$4
port=12345

server1=192.168.0.11
server2=192.168.0.104

for i in $(seq $start $end); do
    echo "Running $SPDZROOT/atlas-bgin-party.x -pn $port -N $nparties -h $server1 $i $progname"

    if [ $i -eq $end ]; then
        $SPDZROOT/atlas-bgin-party.x -pn $port -N $nparties -h $server1 $i $progname
    else
        $SPDZROOT/atlas-bgin-party.x -pn $port -N $nparties -h $server1 $i $progname >/dev/null 2>&1 &
    fi
done