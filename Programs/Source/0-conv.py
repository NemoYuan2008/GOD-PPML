'''
This file is used for our internal testing purposes.
'''


from Compiler.types import sfix
from Compiler.library import print_ln
from Compiler import ml

import torch
import torch.nn as nn

sfix.set_precision(16, 61)

input_channels = 1
input_size = 5  # 5x5 input
conv_filters = 4
kernel_size = 3
pool_size = 2
output_size = 5

conv_output = input_size - kernel_size + 1
flattened_size = conv_output * conv_output * conv_filters

# Create deterministic kernels (4 filters of 3x3x1)
kernel_weights = torch.tensor([i for i in range(36)], dtype=torch.float32).reshape(conv_filters, input_channels, kernel_size, kernel_size)

layers = [
    ml.easyConv2d([input_channels, input_size, input_size, 1], 1, conv_filters, kernel_size, 1, 0),
    ml.Dense(1, flattened_size, output_size)
]

# Set the conv weights
layers[0].weights = sfix.input_tensor_via(0, kernel_weights)

# Create and set dense layer weights (36 x 5 matrix) and biases (5)
dense_weights = torch.tensor([1 for i in range(180)], dtype=torch.float32).reshape(flattened_size, output_size)
dense_biases = torch.tensor([i for i in range(5)], dtype=torch.float32)

layers[1].W = sfix.input_tensor_via(0, dense_weights)
layers[1].b = sfix.input_tensor_via(0, dense_biases)

test_input = torch.tensor([i for i in range(25)], dtype=torch.float32).reshape(1, input_channels, input_size, input_size)

secure_input = sfix.input_tensor_via(0, test_input)
optimizer = ml.Optimizer(layers)

layers[0].X = secure_input
optimizer.forward(1)

res = layers[-1].Y.reveal()

'''
Expected output:
[[[71496, 71497, 71498, 71499, 71500]]]
'''
print_ln('%s', res)