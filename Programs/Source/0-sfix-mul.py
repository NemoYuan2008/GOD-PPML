from Compiler.types import sfix, Array
from Compiler.library import print_ln


sfix.set_precision(16, 61)


a = Array.create_from([sfix(1), sfix(2), sfix(3), sfix(4)])
b = Array.create_from([sfix(5), sfix(6), sfix(7), sfix(8)])
c = Array.create_from([sfix(9), sfix(10), sfix(11)])
d = sfix(12)

# Check in asm output that the operations are merged and cisc'ed
aa = a * a
bb = b * b
ab = a * b
cc = c * c
dd = d * d

print_ln('%s', aa.reveal())
print_ln('%s', bb.reveal())
print_ln('%s', ab.reveal())
print_ln('%s', cc.reveal())
print_ln('%s', dd.reveal())
