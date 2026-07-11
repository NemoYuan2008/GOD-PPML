'''
Focused workload for tentative DoubleRand source capture.

The six operations alternate between the ordinary scalar-multiplication and
ordinary dot-product wrappers. All operands are distinct private inputs, and
there are no truncation or public-output multiplications.
'''

from Compiler.library import print_ln, runtime_error_if
from Compiler.types import Array, sint


scalar_1 = sint.input_tensor_via(0, [2, 3])
dot_1_left = sint.input_tensor_via(0, [4, 6])
dot_1_right = sint.input_tensor_via(0, [5, 7])
scalar_2 = sint.input_tensor_via(0, [8, 9])
dot_2_left = sint.input_tensor_via(0, [10, 12])
dot_2_right = sint.input_tensor_via(0, [11, 13])
scalar_3 = sint.input_tensor_via(0, [14, 15])
dot_3_left = sint.input_tensor_via(0, [16, 18])
dot_3_right = sint.input_tensor_via(0, [17, 19])


def check_print(opened, expected, ordinal):
    runtime_error_if(opened != expected,
                     'tentative capture result %s: %s != %s',
                     ordinal, opened, expected)
    print_ln('%s', opened)


result_1 = scalar_1[0] * scalar_1[1]
result_2 = Array.create_from(
        [dot_1_left[0] + result_1, dot_1_left[1]]).dot(dot_1_right)
result_3 = (scalar_2[0] + result_2) * scalar_2[1]
result_4 = Array.create_from(
        [dot_2_left[0] + result_3, dot_2_left[1]]).dot(dot_2_right)
result_5 = (scalar_3[0] + result_4) * scalar_3[1]
result_6 = Array.create_from(
        [dot_3_left[0] + result_5, dot_3_left[1]]).dot(dot_3_right)

opened_results = [value.reveal() for value in
                  [result_1, result_2, result_3,
                   result_4, result_5, result_6]]
expected_results = [6, 92, 900, 10166, 152700, 2596514]
for ordinal, (opened, expected) in enumerate(
        zip(opened_results, expected_results), 1):
    check_print(opened, expected, ordinal)
