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

    BitLTL(c, y, r_bits)

    return b + c - 2 * b * c
