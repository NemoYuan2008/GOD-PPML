from Compiler.types import sfix, sint
from Compiler.library import print_ln

sfix.set_precision(16, 61)

a = [2]
b = [3]

x = sfix.input_tensor_via(0, a)
y = sfix.input_tensor_via(1, b)

print_ln('%s', (x * y).reveal())