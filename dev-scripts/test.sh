#!/usr/bin/env bash

set -u
set -o pipefail

usage() {
    echo "Usage: ./dev-scripts/test.sh {1-net-a|1-net-b|1-net-c} [output-file]" >&2
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
    usage
    exit 2
fi

program=$1
case "$program" in
    1-net-a|1-net-b|1-net-c)
        ;;
    *)
        echo "Unsupported program: $program" >&2
        usage
        exit 2
        ;;
esac

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
cd "$repo_root" || exit 1

if [[ ! -x ./compile.py ]]; then
    echo "Error: ./compile.py is missing or not executable." >&2
    exit 1
fi

if [[ ! -x ./Scripts/atlas-gsz.sh ]]; then
    echo "Error: ./Scripts/atlas-gsz.sh is missing or not executable." >&2
    exit 1
fi

if [[ $# -eq 2 ]]; then
    output_file=$2
else
    log_dir="$repo_root/dev-scripts/test-results"
    mkdir -p "$log_dir"
    output_file="$log_dir/${program}-$(date -u +%Y%m%dT%H%M%SZ).txt"
fi

mkdir -p "$(dirname -- "$output_file")"
output_file=$(cd -- "$(dirname -- "$output_file")" && pwd)/$(basename -- "$output_file")

exec > >(tee -a "$output_file") 2>&1

echo "ATLAS_GSZ_TEST_SUITE_BEGIN program=$program ftag_chunk_width=372 utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "ATLAS_GSZ_OUTPUT_FILE path=$output_file"
echo "ATLAS_GSZ_COMPILE_BEGIN program=$program budget=1000000 utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

./compile.py "$program" --budget 1000000
compile_status=$?

echo "ATLAS_GSZ_COMPILE_END program=$program status=$compile_status utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
if (( compile_status != 0 )); then
    echo "ATLAS_GSZ_TEST_SUITE_END program=$program status=$compile_status utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    exit "$compile_status"
fi

overall_status=0
for parties in 3 5 7 9 11 13 15; do
    echo "ATLAS_GSZ_RUN_BEGIN program=$program parties=$parties ftag_chunk_width=372 utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    ATLAS_GSZ_FTAG_CHUNK_WIDTH=372 \
        ./Scripts/atlas-gsz.sh -N "$parties" "$program"
    run_status=$?

    echo "ATLAS_GSZ_RUN_END program=$program parties=$parties status=$run_status utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    if (( run_status != 0 )); then
        overall_status=1
    fi
done

echo "ATLAS_GSZ_TEST_SUITE_END program=$program status=$overall_status utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
exit "$overall_status"
