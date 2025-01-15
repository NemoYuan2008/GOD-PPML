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
    from .library import print_ln, print_str


    bit_length = program.Program.prog.options.mersenne

    r_bits = [sintbit() for _ in range(bit_length)]
    for i in range(bit_length):
        bit(r_bits[i])
    r = sint.bit_compose(r_bits)

    y = (r + 2 * a).reveal(check=False) # y = 2a + r
    y_lsb = y & 1
    b = y_lsb + r_bits[0] - 2 * r_bits[0] * y_lsb # b = y_lsb ^ r[0]
    
    c = sintbit()

    if const_rounds:
        c = BitLTC(y, r_bits)
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
    from .library import print_ln, print_str

    k = len(b)
    a_bits = floatingpoint.bits(a, k)

    a_bits_not = [x.bit_not() for x in a_bits]
    b_bits_not = [x.bit_not() for x in b]

    # c_i = a_not_i ^ b_not_i
    c_bits = [lhs + rhs - 2 * lhs * rhs for lhs, rhs in zip(a_bits_not, b_bits_not)]
    c_bits_not = [x.bit_not() for x in c_bits]

    d_bits = PreMulC(list(reversed(c_bits_not)))
    d_bits.reverse()
    d_bits_not = [x.bit_not() for x in d_bits]

    e = [d_bits_not[i] - d_bits_not[i + 1] for i in range(k - 1)]
    e.append(d_bits_not[k - 1])

    return sum(lhs * rhs for lhs, rhs in zip(a_bits_not, e))


def PreMulC(a):
    '''
    a: array of sint
    '''
    from .types import sint
    from .instructions import inverse

    k = len(a)

    r = [sint() for _ in range(k)]
    s = [sint() for _ in range(k)]
    for i in range(k):
        inverse(r[i], s[i])
    t = [s[0]] + [r[i - 1] * s[i] for i in range(1, k)]
    c = [a[i] * t[i] for i in range(k)]
    for c_i in c:
        c_i = c_i.reveal(check=False)
    c_mult = 1
    res = []
    for i in range(k):
        c_mult *= c[i]
        res.append(c_mult * r[i])
    return res
