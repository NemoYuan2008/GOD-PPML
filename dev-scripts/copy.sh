#!/usr/bin/env bash

# A helper script only for development purposes
# Use with caution

HERE=$(cd `dirname $0`; pwd)
Root=$HERE/..
CompilerRoot=$HERE/../../MP-SPDZ-Compiler
cp -rf "$CompilerRoot/Compiler" "$Root"

# test if the first argument is -a
if [ "$1" == "-a" ]; then
    echo "Copying all files"
    cp -rf "$CompilerRoot/Programs" "$Root"
fi