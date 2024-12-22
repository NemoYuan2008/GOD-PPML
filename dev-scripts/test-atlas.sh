#!/usr/bin/env bash

# A helper script only for development purposes

port=12345

# Runs all but the last party
for i in $(seq 0 $(($1 - 2))); do
    echo ./atlas-party.x -pn $port -N $1 $i "${@:2}"
    if [ $i -eq $(($1 - 2)) ]; then
        ./atlas-party.x -pn $port -N $1 $i "${@:2}"
    else
        ./atlas-party.x -pn $port -N $1 $i "${@:2}" > /dev/null 2>&1 &
    fi
done