from Compiler.types import sfix, sint
from Compiler.library import print_ln

sfix.set_precision(16, 61)

x = sint.input_tensor_via(0, [1, 2, 3, 4, 5])
y = sfix.input_tensor_via(0, [1, 2, 3, 4, 5])

for i in range (10000):
    x.dot(x)
    x * x
    y.dot(y)
    y * y
