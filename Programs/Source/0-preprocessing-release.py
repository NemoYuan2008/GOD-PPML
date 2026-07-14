"""Focused genuine preprocessing consumers for AtlasGsz release tests."""

mode = program.args[1] if len(program.args) > 1 else 'persistent'

if mode in ('persistent', 'new-batch', 'gs20-failure'):
    count = 3
    bits = [sint.get_random_bit() for _ in range(count)]
    opened = [bit.reveal() for bit in bits]
    valid = sum(value * (value - 1) for value in opened)
    print_ln('PREPROCESSING_RELEASE_APPLICATION_SUCCESS mode=%s valid=%s',
             mode, valid)
elif mode == 'empty':
    mask, _ = sint.get_random_input_mask_for(0)
    print_ln('PREPROCESSING_RELEASE_APPLICATION_SUCCESS mode=%s value=%s',
             mode, mask.reveal())
elif mode in ('temporary', 'temporary-empty'):
    a, b, c = sint.get_random_triple()
    print_ln('PREPROCESSING_RELEASE_APPLICATION_SUCCESS mode=%s valid=%s',
             mode, (c - a * b).reveal())
elif mode == 'square':
    a, a2 = sint.get_random_square()
    print_ln('PREPROCESSING_RELEASE_APPLICATION_SUCCESS mode=%s valid=%s',
             mode, (a2 - a * a).reveal())
elif mode == 'retained-opening':
    mask, _ = sint.get_random_input_mask_for(0)
    print_ln('PREPROCESSING_RELEASE_APPLICATION_SUCCESS mode=%s value=%s',
             mode, mask.reveal())
elif mode == 'dabit':
    arithmetic_bit, _ = sint.get_dabit()
    valid = arithmetic_bit * (arithmetic_bit - 1)
    print_ln('PREPROCESSING_RELEASE_APPLICATION_SUCCESS mode=%s valid=%s',
             mode, valid.reveal())
elif mode == 'edabit':
    program.use_edabit(True)
    whole, _ = sint.get_edabit(1, strict=False)
    print_ln('PREPROCESSING_RELEASE_APPLICATION_SUCCESS mode=%s value=%s',
             mode, whole.reveal())
else:
    raise CompilerError('unknown 0-preprocessing-release mode: %s' % mode)
