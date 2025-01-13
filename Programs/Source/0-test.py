from Compiler.types import sfix, sint
from Compiler.library import print_ln

sfix.set_precision(16, 61)

# x = sint.input_tensor_via(0, [1, 2, 3, 4, 5, 6, 7, 8, 8, 10, 11])
x = sint.input_tensor_via(0, [1, 2, 3, 4])
# y = sfix.input_tensor_via(0, [1, 2, 3, 4])

# a = x.dot(x)
b = x * x
# a.reveal()
# b.reveal()

# c = x * x
# d = x.dot(x)