from Compiler.types import sint
from Compiler.library import print_ln

a = sint(1) < 0
print_ln('%s', a.reveal())
