#!/usr/bin/env bash

set -u
set -o pipefail

usage() {
    echo "Usage: ./dev-scripts/run-accuracy.sh [output-file]" >&2
}

if [[ $# -gt 1 ]]; then
    usage
    exit 2
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
cd "$repo_root" || exit 1

for required_file in ./compile.py ./Scripts/atlas-gsz.sh; do
    if [[ ! -x "$required_file" ]]; then
        echo "Error: $required_file is missing or not executable." >&2
        exit 1
    fi
done

programs=(3-acc-a 3-acc-b 3-acc-c)
for program in "${programs[@]}"; do
    if [[ ! -f "Programs/Source/${program}.py" ]]; then
        echo "Error: Programs/Source/${program}.py is missing." >&2
        exit 1
    fi
done

if [[ $# -eq 1 ]]; then
    output_file=$1
else
    log_dir="$repo_root/dev-scripts/test-results"
    mkdir -p "$log_dir"
    output_file="$log_dir/run-accuracy-$(date -u +%Y%m%dT%H%M%SZ).txt"
fi

mkdir -p "$(dirname -- "$output_file")"
output_file=$(cd -- "$(dirname -- "$output_file")" && pwd)/$(basename -- "$output_file")

exec > >(tee -a "$output_file") 2>&1

overall_status=0

echo "ATLAS_GSZ_ACCURACY_ALL_BEGIN protocol=god programs=3-acc-a,3-acc-b,3-acc-c parties=3 utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "ATLAS_GSZ_ACCURACY_OUTPUT_FILE protocol=god path=$output_file"

for program in "${programs[@]}"; do
    echo "ATLAS_GSZ_ACCURACY_COMPILE_BEGIN protocol=god program=$program parties=3 budget=1000000 utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    ./compile.py "$program" --budget 1000000
    compile_status=$?

    echo "ATLAS_GSZ_ACCURACY_COMPILE_END protocol=god program=$program parties=3 status=$compile_status utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    if (( compile_status != 0 )); then
        overall_status=1
        continue
    fi

    echo "ATLAS_GSZ_ACCURACY_RUN_BEGIN protocol=god program=$program parties=3 utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    env \
        -u ATLAS_GSZ_COMM_AUDIT \
        -u ATLAS_GSZ_RUNTIME_AUDIT \
        -u ATLAS_GSZ_MEMORY_AUDIT \
        -u ATLAS_GSZ_AUTH_TEST \
        ./Scripts/atlas-gsz.sh -N 3 "$program"
    run_status=$?

    echo "ATLAS_GSZ_ACCURACY_RUN_END protocol=god program=$program parties=3 status=$run_status utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    if (( run_status != 0 )); then
        overall_status=1
    fi
done

echo "ATLAS_GSZ_ACCURACY_ALL_END protocol=god status=$overall_status utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
exit "$overall_status"
