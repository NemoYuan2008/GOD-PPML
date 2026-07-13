'''
Focused ordinary-batch integration workload.

With ATLAS_GSZ_AUTH_TEST=honest-batch-integration, AtlasGsz uses the
test-only effective coordinate threshold four. The dependent operation order
creates seven accepted batches: a below-threshold residual batch, four
naturally threshold-triggered batches (including a length-five overshoot),
one real truncation eligibility-boundary batch, and one final residual batch.
The truncation itself is checked once in an unsupported-only GS20 batch and
its real AtlasPrep bit generation exercises the independently owned
preprocessing mul-public protocol branch.
'''

from Compiler.library import print_ln, runtime_error_if
from Compiler.types import Array, sint


def dot(left, right):
    return Array.create_from(left).dot(Array.create_from(right))


op1 = sint(2) * sint(3)
op2 = (sint(4) + op1) * sint(5)

op3 = (sint(6) + op2) * sint(7)
op4 = dot([sint(1) + op3, sint(2), sint(3)],
          [sint(2), sint(3), sint(4)])

op5 = (sint(8) + op4) * sint(9)
op6 = dot([sint(1) + op5, sint(2), sint(3)],
          [sint(4), sint(5), sint(6)])

# One high-level dot operation crosses the effective threshold and still
# creates exactly one captured operation and one concrete king e_t source.
op7 = dot([sint(1) + op6, sint(2), sint(3), sint(4), sint(5)],
          [sint(2), sint(3), sint(4), sint(5), sint(6)])

op8 = (sint(10) + op7) * sint(11)

# A genuine unsupported mul-trunc operation follows the ordinary batch. Its
# dependency on op8 fixes the real eligibility boundary in the online trace;
# op9 consumes the zero difference so ordinary arithmetic remains unchanged.
unsupported_left = (op8 - sint(644688) + sint(3)) * (1 << 16)
unsupported = unsupported_left.mul_trunc(
    sint(4 << 16), 64, 16)

op9 = (sint(12) + op8 + unsupported - unsupported) * sint(13)
op10 = dot([sint(1) + op9, sint(2), sint(3)],
           [sint(2), sint(3), sint(4)])

op11 = (sint(14) + op10) * sint(15)
op12 = dot([sint(1) + op11, sint(2)], [sint(2), sint(3)])

results = [op1, op2, op3, op4, op5, op6,
           op7, op8, op9, op10, op11, op12]
expected = [6, 50, 392, 804, 7308, 29264,
            58598, 644688, 8381100, 16762220,
            251433510, 502867028]

for ordinal, (actual, wanted) in enumerate(zip(results, expected), 1):
    opened = actual.reveal()
    runtime_error_if(opened != wanted,
                     'honest batch operation %s: %s != %s',
                     ordinal, opened, wanted)
    print_ln('%s', opened)

unsupported_opened = unsupported.reveal()
print_ln('%s', unsupported_opened)
