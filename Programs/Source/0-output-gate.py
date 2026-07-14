"""Focused production residual-flush and pre-output-gating workloads."""

from Compiler.library import (break_point, function_call_tape, print_ln,
                              print_ln_to, runtime_error_if)
from Compiler.types import Array, regint, sgf2n, sint


mode = program.args[1] if len(program.args) > 1 else 'ordinary-public'


def scalar(left, right):
    return sint(left) * sint(right)


def reveal_and_check(value, expected, label):
    opened = value.reveal()
    runtime_error_if(opened != expected, '%s: %s != %s',
                     label, opened, expected)
    print_ln('OUTPUT_GATE_VALUE mode=%s value=%s', mode, opened)


if mode == 'ordinary-public':
    reveal_and_check(scalar(7, 9), 63, mode)
elif mode == 'ordinary-private':
    private = scalar(7, 9).reveal_to(0)
    print_ln_to(0, 'OUTPUT_GATE_VALUE mode=%s value=%s', mode, private)
elif mode == 'unsupported-only':
    unsupported = (sint(3) << 16).mul_trunc(sint(4 << 16), 64, 16)
    reveal_and_check(unsupported, 12 << 16, mode)
elif mode == 'empty':
    reveal_and_check(sint(17), 17, mode)
elif mode == 'two-consecutive':
    value = scalar(5, 6)
    reveal_and_check(value, 30, mode + '-first')
    break_point('output-gate-two-consecutive')
    reveal_and_check(value + 1, 31, mode + '-second')
elif mode == 'work-between-outputs':
    first = scalar(2, 3).reveal()
    runtime_error_if(first != 6, '%s-first: %s != 6', mode, first)
    print_ln('OUTPUT_GATE_VALUE mode=%s value=%s', mode, first)
    break_point('output-gate-work-between-outputs')
    reveal_and_check((sint(first) + 1) * sint(5), 35,
                     mode + '-second')
elif mode == 'dot-residual':
    left = Array.create_from([sint(1), sint(2), sint(3)])
    right = Array.create_from([sint(4), sint(5), sint(6)])
    reveal_and_check(left.dot(right), 32, mode)
elif mode == 'mul-trunc-boundary':
    ordinary = scalar(2, 3)
    unsupported_left = (ordinary - 6 + 3) << 16
    unsupported = unsupported_left.mul_trunc(
            sint(4 << 16), 64, 16)
    reveal_and_check(unsupported, 12 << 16, mode)
elif mode in ('retained-opening-only',
              'retained-opening-failure'):
    reveal_and_check(sint(23), 23, mode)
elif mode in ('gs20-failure', 'authentication-rejection'):
    # The focused C++ hook corrupts verification/authentication only after
    # this real ordinary residual reaches the semantic output boundary.
    reveal_and_check(scalar(8, 9), 72, mode)
elif mode == 'direct-secret-print':
    sint(31).output()
elif mode == 'share-file':
    sint.write_to_file([sint(32)])
elif mode == 'secret-socket':
    # Rejection precedes stream reset/packing and therefore precedes use of
    # this deliberately invalid client handle.
    sint(33).write_share_to_socket(regint(999))
elif mode == 'mixed-gc':
    # AtlasGsz has no usable arithmetic-to-GC SPLIT implementation. Reject
    # before reading the prime secret or reaching the generic unsupported
    # fallback. No binary secret is constructed or revealed.
    sint(5).split_to_n_summands(8, 3)
elif mode == 'mixed-gc-reveal':
    # This direct binary constant deliberately bypasses the unavailable
    # arithmetic-to-GC producer path and genuinely reaches GC REVEAL. The
    # runtime must reject before reveal-time masking, opening, or output.
    from Compiler.GC.types import sbit
    sbit(1).reveal().output()
elif mode == 'mixed-gf2n':
    # Stage 1 rejects the mixed-machine GF2N secret reveal by default.
    sgf2n(1).reveal()
elif mode == 'called-tape':
    @function_call_tape
    def called_multiply(left, right):
        return left * right

    reveal_and_check(called_multiply(sint(6), sint(7)), 42, mode)
elif mode == 'no-output-finalization':
    # Keep the ordinary result live in internal secret memory. Proc.check()
    # must verify/authenticate it before Machine::run serializes that memory.
    scalar(8, 9).store_in_mem(0)
    print_ln('OUTPUT_GATE_NO_SECRET_OUTPUT mode=%s', mode)
elif mode in ('run-function', 'multi-worker'):
    # The runtime rejects these modes before online tape execution.
    print_ln('OUTPUT_GATE_UNREACHABLE mode=%s', mode)
else:
    raise CompilerError('unknown 0-output-gate mode: %s' % mode)
