from Compiler.types import sfix, sint, cfix, Array, Matrix
from Compiler.library import print_ln
from Compiler.compilerLib import Compiler

compiler = Compiler(
    custom_args=[
        # "-P 2305843009213693951", 
        "-a debug",
    ]
)


@compiler.register_function('0-sfix-direct')
def fix_mult():
    program = compiler.prog
    program.use_trunc_pr = True

    a = sfix(10)
    b = sfix(1.5)
    c = a * b



# @compiler.register_function('0-sfix-dot-direct')
# def fix_dot():
#     program = compiler.prog

#     a = Array.create_from([sfix(1), sfix(2), sfix(3), sfix(4)])
#     c = Matrix.create_from([
#         [sfix(1), sfix(2), sfix(3)],
#         [sfix(4), sfix(5), sfix(6)],
#         [sfix(7), sfix(8), sfix(9)],
#         [sfix(10), sfix(11), sfix(12)]
#     ])
#     a = a.to_row_matrix()
#     res = a.dot(c)
#     res = res.to_array()


if __name__ == "__main__":
    compiler.compile_func()
