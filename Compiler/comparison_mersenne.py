from . import instructions_base
from . import util
from . import program


@instructions_base.ret_cisc
def LTZ(a):
    '''
    Return (a ?< 0)
    '''
    from .types import sintbit, sint
    from .instructions import bit
    from .comparison import BitLTL
    
    bit_length = program.Program.prog.options.mersenne

    r_bits = [sintbit() for _ in range(bit_length)]
    for i in range(bit_length):
        bit(r_bits[i])
    r = sint.bit_compose(r_bits)
    y = (r + 2 * a).reveal(check=False)
    y_lsb = y & 1
    b = y_lsb + r_bits[0] - 2 * r_bits[0] * y_lsb # b = y_lsb ^ r[0]
    c = sintbit()
    BitLTL(c, y, r_bits)

    return c
