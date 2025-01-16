'''
Network-B (Sarda) as in the paper LXY24

The NN is defined as follows: (pseudo code)
batch_size = 1
Conv2D(height=28, width=28, channels=1, filters=5, kernel_size=2, stride=2, padding=0)
ReLU()
Flatten()
Dense(in=980, out=100)
ReLU()
Dense(in=100, out=10)
'''

from Compiler.types import sfix
from Compiler import ml
from Compiler.library import print_ln
import numpy as np

# ml.set_n_threads(4)
sfix.set_precision(16, 61)

input_channels = 1
input_size = 28
conv_filters = 5
kernel_size = 2
stride = 2
padding = 0
conv_output = (input_size - kernel_size + 2 * padding) // stride + 1
flattened_size = conv_output * conv_output * conv_filters
fc_layer_1_out = 100
output_size = 10

layers = [
    ml.easyConv2d([1, 28, 28, 1], 1, conv_filters, kernel_size, stride, padding),
    ml.Relu(shape=(1, conv_output, conv_output, conv_filters)),
    ml.Dense(N=1, d_in=flattened_size, d_out=fc_layer_1_out),
    ml.Relu(shape=(1, fc_layer_1_out)),
    ml.Dense(N=1, d_in=fc_layer_1_out, d_out=output_size),
]

# layers[0].X = sfix.Tensor([1, input_channels, input_size, input_size])

layers[0].X = sfix.input_tensor_via(0, np.random.rand(1, input_channels, input_size, input_size), binary=True)
layers[0].weights = sfix.input_tensor_via(0, np.random.rand(conv_filters, input_channels, kernel_size, kernel_size), binary=True)
layers[2].W = sfix.input_tensor_via(0, np.random.rand(flattened_size, fc_layer_1_out), binary=True)
layers[2].b = sfix.input_tensor_via(0, np.random.rand(fc_layer_1_out), binary=True)
layers[4].W = sfix.input_tensor_via(0, np.random.rand(fc_layer_1_out, output_size), binary=True)
layers[4].b = sfix.input_tensor_via(0, np.random.rand(output_size), binary=True)

optimizer = ml.Optimizer(layers)
optimizer.forward(1)
