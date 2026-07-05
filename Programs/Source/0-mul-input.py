'''
Regression test for ordinary AtlasGsz multiplication.

This test exercises multiple ordinary sint multiplications in one
batch. It is intended to cover the PartialMult transcript path with
record length equal to one.
'''

from Compiler.types import sint
from Compiler.library import print_ln


values = sint.input_tensor_via(0, [7, 9, 11, 13])

a = values[0] * values[1]
b = values[2] * values[3]
c = (values[0] + values[2]) * (values[1] + values[3])

print_ln('%s', a.reveal())  # 63
print_ln('%s', b.reveal())  # 143
print_ln('%s', c.reveal())  # 396
