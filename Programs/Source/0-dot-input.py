''' 
This file is used for our internal testing purposes.

Check that:
1. The program produces the expected output.
2. In the assembly code, the matmuls_trunc instruction is merged.
3. In the assembly code, the mul_trunc instruction is vectorized, merged, and CISC'ed.
4. The sint multiplication is not affected by the truncation.
'''

from Compiler.types import sfix, sint, Array, Matrix
from Compiler.library import print_ln


sfix.set_precision(16, 61)


sint_1_4 = sint.input_tensor_via(0, [1, 2, 3, 4])
sfix_1_4 = sfix.input_tensor_via(0, [1, 2, 3, 4])
sfix_4_3 = sfix.input_tensor_via(0, 
                                 [[1, 2, 3],
                                  [4, 5, 6],
                                  [7, 8, 9],
                                  [10, 11, 12]])
sfix_1_3 = sfix.input_tensor_via(0, [1, 2, 3])
sfix_3_3 = sfix.input_tensor_via(0,
                                 [[1, 2, 3],
                                  [4, 5, 6],
                                  [7, 8, 9]])


# sint * sint, size: 1x4 * 4x1, no truncation, matmuls
res1 = sint_1_4.dot(sint_1_4)

# sfix * sint, size: 1x4 * 4x1, no truncation, matmulsm
res2 = sfix_1_4.dot(sint_1_4)

# sint * sfix, size: 1x4 * 4x1, no truncation, matmulsm
res3 = sint_1_4.dot(sfix_1_4)

# sfix * sfix, size: 1x4 * 4x1, with truncation, matmuls_trunc
res4 = sfix_1_4.dot(sfix_1_4)

# sfix * sfix, size: 1x4 * 4x3, with truncation, matmuls_trunc
res5 = sfix_1_4.to_row_matrix().dot(sfix_4_3).to_array()

# sfix * sfix, size: 1x3 * 3x3, with truncation, matmuls_trunc
res6 = sfix_1_3.to_row_matrix().dot(sfix_3_3).to_array()

# sfix * sfix, element-wise, with truncation, mul_trunc
res7 = sfix_1_4 * sfix_1_4

# sfix * sfix, element-wise, with truncation, mul_trunc
res8 = sfix_1_3 * sfix_1_3

print_ln('%s', res1.reveal()) # [30]
print_ln('%s', res2.reveal()) # [30]
print_ln('%s', res3.reveal()) # [30]
print_ln('%s', res4.reveal()) # [30]
print_ln('%s', res5.reveal()) # [70, 80, 90]
print_ln('%s', res6.reveal()) # [30, 36, 42]
print_ln('%s', res7.reveal()) # [1, 4, 9, 16]
print_ln('%s', res8.reveal()) # [1, 4, 9]
