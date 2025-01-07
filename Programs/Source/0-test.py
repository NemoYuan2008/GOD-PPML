from Compiler.types import sfix, sint
from Compiler.library import print_ln

sfix.set_precision(16, 61)

print_ln('%s', (sfix(1) * sfix(-1)).reveal())