"""Focused schedule that AtlasGsz Stage 1 must reject before execution."""

from Compiler.library import multithread, print_ln
from Compiler.types import sint


@multithread(2, 2)
def worker(_, __):
    value = sint(2) * sint(3)
    print_ln('OUTPUT_GATE_MULTI_WORKER_THREAD_UNREACHABLE %s', value.reveal())


print_ln('OUTPUT_GATE_MULTI_WORKER_UNREACHABLE')
