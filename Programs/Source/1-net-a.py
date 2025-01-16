'''
SecureML
(Network-A as in the paper)

The NN is defined as follows: (pseudo code)
batch_size = 1
Dense(784, 128)
ReLU()
Dense(128, 128)
ReLU()
Dense(128, 10)
'''

from Compiler.types import sfix
from Compiler import ml
from Compiler.library import print_ln
import numpy as np

sfix.set_precision(16, 61)

input_size = 28 * 28
layer_1_out = 128
layer_2_out = 128
output_size = 10
batch_size = 1


layers = [
    ml.Dense(N=1, d_in=input_size, d_out=layer_1_out),
    ml.Relu(shape=(batch_size, layer_1_out)),
    ml.Dense(N=1, d_in=layer_1_out, d_out=layer_2_out),
    ml.Relu(shape=(batch_size, layer_2_out)),
    ml.Dense(N=1, d_in=layer_2_out, d_out=output_size),
]

layers[0].X = sfix.input_tensor_via(0, np.random.rand(batch_size, input_size), binary=True)
layers[0].W = sfix.input_tensor_via(0, np.random.rand(input_size, layer_1_out), binary=True)
layers[0].b = sfix.input_tensor_via(0, np.random.rand(layer_1_out), binary=True)
layers[2].W = sfix.input_tensor_via(0, np.random.rand(layer_1_out, layer_2_out), binary=True)
layers[2].b = sfix.input_tensor_via(0, np.random.rand(layer_2_out), binary=True)
layers[4].W = sfix.input_tensor_via(0, np.random.rand(layer_2_out, output_size), binary=True)
layers[4].b = sfix.input_tensor_via(0, np.random.rand(output_size), binary=True)
# layers[0].X = sfix.Array(batch_size * input_size)

optimizer = ml.Optimizer(layers)
optimizer.forward(1)