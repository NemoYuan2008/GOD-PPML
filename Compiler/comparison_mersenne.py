from . import instructions_base
from . import util
from . import program
from . import floatingpoint


@instructions_base.ret_cisc
def LTZ(a):
    '''
    Return (a ?< 0)
    '''
    from .types import sintbit, sint
    from .instructions import bit
    from .comparison import BitLTL, BitLTC1
    from .comparison import const_rounds

    # print(const_rounds)
    
    bit_length = program.Program.prog.options.mersenne

    r_bits = [sintbit() for _ in range(bit_length)]
    for i in range(bit_length):
        bit(r_bits[i])
    r = sint.bit_compose(r_bits)
    y = (r + 2 * a).reveal(check=False)
    y_lsb = y & 1
    b = y_lsb + r_bits[0] - 2 * r_bits[0] * y_lsb # b = y_lsb ^ r[0]
    
    c = sintbit()

    if const_rounds:
        c = BitLTC(y, r_bits)
        # BitLTC1(c, y, r_bits)
    else:
        BitLTL(c, y, r_bits)

    return b + c - 2 * b * c


def BitLTC(a, b):
    '''
    Return (a ?< b)

    a: cint
    b: array of sintbit
    '''
    from .types import sintbit
    from .comparison import PreMulC

    k = len(b)
    a_bits = floatingpoint.bits(a, k)

    a_bits_not = [x.bit_not() for x in a_bits]
    b_bits_not = [x.bit_not() for x in b]

    # c_i = a_not_i ^ b_not_i
    c_bits = [x + y - 2 * x * y for x, y in zip(a_bits_not, b_bits_not)]
    c_bits_not = [x.bit_not() for x in c_bits]
    d_bits = PreMulC(c_bits_not)
    d_bits_not = [x.bit_not() for x in d_bits]

    e = [d_bits_not[i] - d_bits_not[i + 1] for i in range(k - 1)]
    e.append(d_bits_not[k - 1])

    res = sum(lhs * rhs for lhs, rhs in zip(a_bits, e))

    return res