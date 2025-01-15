'''
This file is used for our internal testing purposes.
'''


from Compiler.types import sfix
from Compiler.library import print_ln
from Compiler import ml

import torch
sfix.set_precision(16, 61)

input_channels = 1
input_size = 2  # 2x2 input
conv_filters = 1  # single filter
kernel_size = 1  # 1x1 kernel
conv_output = input_size - kernel_size + 1  # will be 2x2
flattened_size = input_size * input_size  # 4 for 2x2 input

kernel_weights = torch.tensor([1.5], dtype=torch.float32).reshape(conv_filters, input_channels, kernel_size, kernel_size)
dense_weights = torch.eye(flattened_size, dtype=torch.float32)
dense_biases = torch.zeros(flattened_size, dtype=torch.float32)
test_input = torch.tensor([1,2,3,4], dtype=torch.float32).reshape(1, input_channels, input_size, input_size)

layers = [
    ml.easyConv2d([input_channels, input_size, input_size, 1], 1, conv_filters, kernel_size, 1, 0),
    ml.Dense(1, flattened_size, flattened_size)
]

layers[0].weights = sfix.input_tensor_via(0, kernel_weights)
layers[1].W = sfix.input_tensor_via(0, dense_weights)
layers[1].b = sfix.input_tensor_via(0, dense_biases)

# The input
layers[0].X = sfix.input_tensor_via(0, test_input)

optimizer = ml.Optimizer(layers)
optimizer.forward(1)

res = layers[1].Y.reveal()

'''
Expected output:
[[[1.5, 3, 4.5, 6]]]
'''
print_ln('res: %s', res)