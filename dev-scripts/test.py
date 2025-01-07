import sys
sys.path.append('./') # To be run from project root

from Compiler.types import sfix, sint, cfix, Array, Matrix
from Compiler.library import print_ln
from Compiler.compilerLib import Compiler

compiler = Compiler(
    custom_args=[
        '-a', 'debug',
    ]
)


@compiler.register_function('0-direct')
def run():
    program = compiler.prog
    program.use_trunc_pr = False
    sfix.set_precision(16, 61)

    a = sint(1) < 0
    print_ln('%s', a.reveal())


if __name__ == '__main__':
    compiler.compile_func()
