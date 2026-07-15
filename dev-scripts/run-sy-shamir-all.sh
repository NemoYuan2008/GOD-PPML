#!/usr/bin/env bash

set -u
set -o pipefail

usage() {
    echo "Usage: ./dev-scripts/run-sy-shamir-all.sh [output-file]" >&2
}

if [[ $# -gt 1 ]]; then
    usage
    exit 2
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
cd "$repo_root" || exit 1

for required_file in ./compile.py ./Scripts/sy-shamir.sh ./dev-scripts/throttle.sh; do
    if [[ ! -x "$required_file" ]]; then
        echo "Error: $required_file is missing or not executable." >&2
        exit 1
    fi
done

if [[ $# -eq 1 ]]; then
    output_file=$1
else
    log_dir="$repo_root/dev-scripts/test-results"
    mkdir -p "$log_dir"
    output_file="$log_dir/run-sy-shamir-all-$(date -u +%Y%m%dT%H%M%SZ).txt"
fi

mkdir -p "$(dirname -- "$output_file")"
output_file=$(cd -- "$(dirname -- "$output_file")" && pwd)/$(basename -- "$output_file")

exec > >(tee -a "$output_file") 2>&1

throttle_touched=0
cleanup() {
    local original_status=$?
    local reset_status=0

    trap - EXIT

    if (( throttle_touched )); then
        echo "SY_SHAMIR_THROTTLE_RESET_BEGIN protocol=sy-shamir utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        ./dev-scripts/throttle.sh reset
        reset_status=$?
        echo "SY_SHAMIR_THROTTLE_RESET_END protocol=sy-shamir status=$reset_status utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    fi

    if (( original_status == 0 && reset_status != 0 )); then
        original_status=$reset_status
    fi
    exit "$original_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

programs=(1-net-a 1-net-b 1-net-c)
networks=(lan wan)
parties_list=(3 5 7 9 11 13 15)
overall_status=0

echo "SY_SHAMIR_ALL_BEGIN protocol=sy-shamir programs=1-net-a,1-net-b,1-net-c networks=lan,wan parties=3,5,7,9,11,13,15 utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "SY_SHAMIR_OUTPUT_FILE protocol=sy-shamir path=$output_file"

for program in "${programs[@]}"; do
    echo "SY_SHAMIR_COMPILE_BEGIN protocol=sy-shamir program=$program budget=1000000 utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    ./compile.py "$program" --budget 1000000
    compile_status=$?

    echo "SY_SHAMIR_COMPILE_END protocol=sy-shamir program=$program status=$compile_status utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    if (( compile_status != 0 )); then
        overall_status=1
        continue
    fi

    for network in "${networks[@]}"; do
        echo "SY_SHAMIR_THROTTLE_BEGIN protocol=sy-shamir program=$program network=$network utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

        throttle_touched=1
        ./dev-scripts/throttle.sh "$network"
        throttle_status=$?

        echo "SY_SHAMIR_THROTTLE_END protocol=sy-shamir program=$program network=$network status=$throttle_status utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        if (( throttle_status != 0 )); then
            overall_status=1
            continue
        fi

        for parties in "${parties_list[@]}"; do
            echo "SY_SHAMIR_RUN_BEGIN protocol=sy-shamir program=$program network=$network parties=$parties utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

            env \
                -u ATLAS_GSZ_COMM_AUDIT \
                -u ATLAS_GSZ_RUNTIME_AUDIT \
                -u ATLAS_GSZ_MEMORY_AUDIT \
                -u ATLAS_GSZ_AUTH_TEST \
                ./Scripts/sy-shamir.sh -N "$parties" "$program"
            run_status=$?

            echo "SY_SHAMIR_RUN_END protocol=sy-shamir program=$program network=$network parties=$parties status=$run_status utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
            if (( run_status != 0 )); then
                overall_status=1
            fi
        done
    done
done

echo "SY_SHAMIR_ALL_END protocol=sy-shamir status=$overall_status utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
exit "$overall_status"
