from Compiler.types import sfix, sint
from Compiler.library import print_ln

sfix.set_precision(16, 61)

sfix_1_4 = sfix.input_tensor_via(0, [1, 2, 3, 4])
sint_1_4 = sint.input_tensor_via(0, [1, 2, 3, 4])

sint_1_4 * sint_1_4
sfix_1_4 * sfix_1_4