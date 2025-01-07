'''
This file is used for our internal testing purposes.

Check that:
1. The program produces the expected output.
2. In the assembly code, the ltz operations is vectorized and CISC'ed.
'''

from Compiler.types import sint
from Compiler.library import print_ln

nTimes = 10

a = [i for i in range(nTimes)] + [-i for i in range(nTimes)]
a_secret = sint(a)
res = a_secret < 0
print_ln('%s', res.reveal())
