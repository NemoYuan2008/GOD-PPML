#!/usr/bin/env bash

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

success_modes=(
    ordinary-public ordinary-private unsupported-only empty
    two-consecutive work-between-outputs dot-residual
    mul-trunc-boundary retained-opening-only called-tape
    no-output-finalization
)
failure_modes=(
    gs20-failure authentication-rejection retained-opening-failure
    direct-secret-print share-file secret-socket mixed-gc
    mixed-gc-reveal mixed-gf2n run-function
)

for mode in "${success_modes[@]}" "${failure_modes[@]}"; do
    conda run -n pytorch ./compile.py 0-output-gate "$mode"
done
conda run -n pytorch ./compile.py 0-output-gate-multi-worker

require_field()
{
    local report=$1 field=$2 expected=$3
    if ! rg -q "(^| )${field}=${expected}( |$)" <<<"$report"; then
        echo "expected ${field}=${expected} in output-gate report" >&2
        echo "$report" >&2
        return 1
    fi
}

require_nonzero_field()
{
    local report=$1 field=$2
    if ! rg -q "(^| )${field}=[1-9][0-9]*( |$)" <<<"$report"; then
        echo "expected nonzero ${field} in output-gate report" >&2
        echo "$report" >&2
        return 1
    fi
}

require_clean_post_state()
{
    local report=$1 field
    for field in x_verify y_verify z_verify partial_transcripts \
            virtual_transcript virtual_evidence capture_active \
            capture_finalized capture_records capture_consumptions \
            capture_producer_indices capture_output_indices frozen_batch \
            dealer_batches nu_material holder_tags global_invocations \
            retained_opening_values retained_opening_secrets; do
        require_field "$report" "$field" 0
    done
    require_field "$report" receipt 0/0/0/0/0
}

run_success()
{
    local players=$1 mode=$2 log reports first last report
    log=$(mktemp)
    ATLAS_GSZ_AUTH_TEST="output-gate-$mode" PLAYERS="$players" \
        ./Scripts/atlas-gsz.sh "0-output-gate-$mode" >"$log" 2>&1
    rg 'ATLAS_GSZ_OUTPUT_GATE|OUTPUT_GATE_VALUE|OUTPUT_GATE_NO_SECRET' "$log"
    rg -q 'ATLAS_GSZ_OUTPUT_GATE .* status=PASS' "$log"
    reports=$(rg '^ATLAS_GSZ_OUTPUT_GATE' "$log")
    first=$(head -n 1 <<<"$reports")
    last=$(tail -n 1 <<<"$reports")

    while IFS= read -r report; do
        require_field "$report" recursion_guard_rejections 0
        require_field "$report" recursion_rejected 0
        require_field "$report" failed_output_gates 0
        require_clean_post_state "$report"
    done <<<"$reports"

    case "$mode" in
        ordinary-public|ordinary-private|called-tape)
            require_field "$last" output_gate_invocations 1
            require_field "$last" output_triggered_residual_batches 1
            require_field "$last" gs20_checks 1
            require_field "$last" authentication_started 1
            require_field "$last" authentication_completed 1
            require_field "$last" authentication_accepted 1
            require_field "$last" check_tag_challenges 1
            require_nonzero_field "$last" total_gate_comm
            ;;
        unsupported-only|mul-trunc-boundary)
            require_field "$last" output_triggered_residual_batches 1
            require_field "$last" gs20_checks 1
            require_field "$last" authentication_started 0
            require_field "$last" check_tag_challenges 0
            require_nonzero_field "$last" total_gate_comm
            ;;
        empty)
            require_field "$last" empty_output_gates 1
            require_field "$last" output_triggered_residual_batches 0
            require_field "$last" gs20_checks 0
            require_field "$last" authentication_started 0
            require_field "$last" total_gate_comm 0
            ;;
        two-consecutive)
            require_field "$first" output_gate_invocations 1
            require_field "$first" output_triggered_residual_batches 1
            require_field "$first" gs20_checks 1
            require_field "$first" authentication_started 1
            require_field "$last" output_gate_invocations 2
            require_field "$last" empty_output_gates 1
            require_field "$last" gs20_checks 0
            require_field "$last" authentication_started 0
            require_field "$last" total_gate_comm 0
            ;;
        work-between-outputs)
            require_field "$last" output_gate_invocations 2
            require_field "$last" empty_output_gates 0
            require_field "$last" output_triggered_residual_batches 2
            require_field "$last" gs20_checks 1
            require_field "$last" authentication_started 1
            require_field "$last" check_key_setup 0
            require_nonzero_field "$last" total_gate_comm
            ;;
        dot-residual)
            require_field "$last" output_triggered_residual_batches 1
            require_field "$last" gs20_checks 1
            require_field "$last" gs20_dimension_reduction_challenges 2
            require_field "$last" authentication_started 1
            require_field "$last" check_tag_challenges 1
            require_nonzero_field "$last" total_gate_comm
            ;;
        retained-opening-only)
            require_field "$last" output_triggered_residual_batches 0
            require_field "$last" output_triggered_retained_opening_checks 1
            require_field "$last" gs20_checks 0
            require_field "$last" authentication_started 0
            require_nonzero_field "$last" retained_opening_comm
            ;;
        no-output-finalization)
            require_field "$last" output_gate_invocations 0
            require_field "$last" gs20_checks 1
            require_field "$last" authentication_started 1
            require_field "$last" actual_revealed_outputs 0
            require_field "$last" total_gate_comm 0
            require_nonzero_field "$last" normal_finalization_comm
            ;;
    esac

    if [[ "$mode" != no-output-finalization ]]; then
        require_field "$last" actual_revealed_outputs 1
    fi
    require_field "$last" destructor_comm 0
    require_field "$last" duplicate_finalization 0
    rm -f "$log"
}

run_failure()
{
    local players=$1 mode=$2 log report
    log=$(mktemp)
    if ATLAS_GSZ_AUTH_TEST="output-gate-$mode" PLAYERS="$players" \
            ./Scripts/atlas-gsz.sh "0-output-gate-$mode" >"$log" 2>&1; then
        echo "expected failure for $mode with $players parties" >&2
        rm -f "$log"
        return 1
    fi
    rg 'ATLAS_GSZ_OUTPUT_GATE' "$log"
    rg -q 'ATLAS_GSZ_OUTPUT_GATE .* status=REJECTED' "$log"
    rg -q 'actual_revealed_outputs=0' "$log"
    report=$(rg '^ATLAS_GSZ_OUTPUT_GATE' "$log" | tail -n 1)
    require_field "$report" actual_revealed_outputs 0
    require_field "$report" recursion_guard_rejections 0
    require_field "$report" destructor_comm 0
    if rg -q 'OUTPUT_GATE_VALUE' "$log"; then
        echo "failed gate revealed an application value for $mode" >&2
        rm -f "$log"
        return 1
    fi
    if [[ "$mode" == gs20-failure \
            || "$mode" == authentication-rejection \
            || "$mode" == retained-opening-failure ]]; then
        rg -q 'second_attempt_comm=0 second_attempt_challenges=0 second_attempt_authentication=0' "$log"
        require_field "$report" output_gate_invocations 2
        require_field "$report" failed_output_gates 2
    else
        require_field "$report" total_gate_comm 0
    fi
    case "$mode" in
        gs20-failure)
            require_field "$report" gs20_checks 1
            require_field "$report" authentication_started 0
            require_nonzero_field "$report" gs20_comm
            ;;
        authentication-rejection)
            require_field "$report" gs20_checks 1
            require_field "$report" authentication_started 1
            require_field "$report" authentication_completed 1
            require_field "$report" authentication_accepted 0
            ;;
        retained-opening-failure)
            require_field "$report" output_triggered_retained_opening_checks 1
            require_field "$report" gs20_checks 0
            require_nonzero_field "$report" retained_opening_comm
            ;;
        mixed-gc)
            require_field "$report" kind \
                    unsupported_arithmetic_to_gc_conversion
            require_field "$report" output_gate_invocations 1
            require_field "$report" failed_output_gates 1
            require_field "$report" gs20_checks 0
            require_field "$report" authentication_started 0
            ;;
        mixed-gc-reveal)
            require_field "$report" kind gc_secret_reveal
            require_field "$report" output_gate_invocations 1
            require_field "$report" failed_output_gates 1
            require_field "$report" gs20_checks 0
            require_field "$report" authentication_started 0
            ;;
        run-function)
            require_field "$report" output_gate_invocations 0
            rg -q 'ATLAS_GSZ_RUN_FUNCTION_REJECTION .*rejected_before_prepare=1 .*rejected_before_argument_copy=1 .*rejected_before_tape=1 .*rejected_before_result_copy=1' "$log"
            ;;
        *)
            require_field "$report" output_gate_invocations 1
            require_field "$report" failed_output_gates 1
            require_field "$report" gs20_checks 0
            require_field "$report" authentication_started 0
            ;;
    esac
    rm -f "$log"
}

for players in 3 5; do
    for mode in "${success_modes[@]}"; do
        run_success "$players" "$mode"
    done
    for mode in "${failure_modes[@]}"; do
        run_failure "$players" "$mode"
    done

    log=$(mktemp)
    if ATLAS_GSZ_AUTH_TEST=output-gate-multi-worker PLAYERS="$players" \
            ./Scripts/atlas-gsz.sh 0-output-gate-multi-worker \
            >"$log" 2>&1; then
        echo "expected multi-worker rejection with $players parties" >&2
        rm -f "$log"
        exit 1
    fi
    rg 'ATLAS_GSZ_OUTPUT_GATE' "$log"
    rg -q 'multi_worker_rejected=1' "$log"
    rg -q 'output_gate_invocations=0 .*gs20_checks=0 .*authentication_started=0' "$log"
    rg -q 'total_gate_comm=0 .*actual_revealed_outputs=0' "$log"
    rm -f "$log"
done
