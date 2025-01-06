from Compiler.types import sfix, sint, Array, Matrix
from Compiler.library import print_ln


sfix.set_precision(16, 61)


# sint * sint, size: 1x4 * 4x1, no truncation, matmuls
a_sint = sint.input_tensor_via(0, [1, 2, 3, 4])
res = a_sint.dot(a_sint)
print_ln('%s', res.reveal()) # [30]

# sfix * sfix, size: 1x4 * 4x1, with truncation, matmuls_trunc
a = sfix.input_tensor_via(0, [1, 2, 3, 4])
res = a.dot(a)
print_ln('%s', res.reveal()) # [30]

# sfix * sint, size: 1x4 * 4x1, no truncation, matmulsm
res = a.dot(a_sint)
print_ln('%s', res.reveal()) # [30]

# sint * sfix, size: 1x4 * 4x1, no truncation, matmulsm
res = a_sint.dot(a)
print_ln('%s', res.reveal()) # [30]

# sfix * sfix, size: 1x4 * 4x3, with truncation, matmuls_trunc
b = sint.input_tensor_via(0,
                          [[1, 2, 3],
                           [4, 5, 6],
                           [7, 8, 9],
                           [10, 11, 12]])
res = a.to_row_matrix().dot(b).to_array()
print_ln('%s', res.reveal()) # [70, 80, 90]

# sfix * sfix, size: 1x3 * 3x3, with truncation, matmuls_trunc
a = sfix.input_tensor_via(0, [1, 2, 3])
b = sfix.input_tensor_via(0,
                          [[1, 2, 3],
                           [4, 5, 6],
                           [7, 8, 9]])
res = a.to_row_matrix().dot(b).to_array()
print_ln('%s', res.reveal()) # [30, 36, 42]

print_ln('%s', (a * a).reveal())
