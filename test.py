from Compiler.types import sfix, sint, cfix, Array, Matrix
from Compiler.library import print_ln
from Compiler.compilerLib import Compiler

compiler = Compiler(
    custom_args=[
        # "-P 2305843009213693951", 
        "-a",
        "debug",
    ]
)


@compiler.register_function('0-direct')
def run():
    program = compiler.prog
    # program.use_trunc_pr = True

    a = Array.create_from([sfix(1), sfix(2), sfix(3), sfix(4)])
    b = Array.create_from([sfix(5), sfix(6), sfix(7), sfix(8)])
    c = Array.create_from([sfix(9), sfix(10), sfix(11)])

    aa = a * a
    bb = b * b
    ab = a * b
    cc = c * c

    d = sfix(9) * sfix(10)

    print_ln('%s', aa.reveal())
    print_ln('%s', bb.reveal())
    print_ln('%s', ab.reveal())
    print_ln('%s', cc.reveal())
    print_ln('%s', d.reveal())


if __name__ == "__main__":
    compiler.compile_func()
