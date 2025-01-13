from Compiler.types import sfix, sint
from Compiler.library import print_ln

sfix.set_precision(16, 61)

x = sint.input_tensor_via(0, [i for i in range(9)])
y = sfix.input_tensor_via(0, [i for i in range(9)])

a = x.dot(x)
b = x * x
a.reveal()
b.reveal()

c = x * x
d = x.dot(x)

y * y
y.dot(y)