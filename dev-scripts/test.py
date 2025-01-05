import sys
sys.path.append('./') # To be run from project root

from Compiler.types import sfix, sint, cfix, Array, Matrix
from Compiler.library import print_ln
from Compiler.compilerLib import Compiler

compiler = Compiler(
    custom_args=[
        # '--prime',
        # '2147483647', # 2^31 - 1
        # '2305843009213693951', # 2^61 - 1
        '-a',
        'debug',
    ]
)


@compiler.register_function('0-direct')
def run():
    program = compiler.prog
    program.use_trunc_pr = False
    sfix.set_precision(13, 61)

    # sint * sint, size: 1x4 * 4x1, no truncation, matmuls
    a_sint = Array.create_from([sint(1), sint(2), sint(3), sint(4)])
    res = a_sint.dot(a_sint)
    print_ln('%s', res.reveal()) # [30]

    # sfix * sfix, size: 1x4 * 4x1, with truncation, matmuls_trunc
    a = Array.create_from([sfix(1), sfix(2), sfix(3), sfix(4)])
    res = a.dot(a)
    print_ln('%s', res.reveal()) # [30]

    # sfix * sint, size: 1x4 * 4x1, no truncation, matmulsm
    res = a.dot(a_sint)
    print_ln('%s', res.reveal()) # [30]

    # sint * sfix, size: 1x4 * 4x1, no truncation, matmulsm
    res = a_sint.dot(a)
    print_ln('%s', res.reveal()) # [30]

    # sfix * sfix, size: 1x4 * 4x3, with truncation, matmuls_trunc
    b = Matrix.create_from([
        [sfix(1), sfix(2), sfix(3)],
        [sfix(4), sfix(5), sfix(6)],
        [sfix(7), sfix(8), sfix(9)],
        [sfix(10), sfix(11), sfix(12)]
    ])
    res = a.to_row_matrix().dot(b).to_array()
    print_ln('%s', res.reveal()) # [70, 80, 90]

    # sfix * sfix, size: 1x3 * 3x3, with truncation, matmuls_trunc
    a = Array.create_from([sfix(1), sfix(2), sfix(3)])
    b = Matrix.create_from([
        [sfix(1), sfix(2), sfix(3)],
        [sfix(4), sfix(5), sfix(6)],
        [sfix(7), sfix(8), sfix(9)],
    ])
    res = a.to_row_matrix().dot(b).to_array()
    print_ln('%s', res.reveal()) # [30, 36, 42]

    print_ln('%s', (a * a).reveal())


if __name__ == '__main__':
    compiler.compile_func()
