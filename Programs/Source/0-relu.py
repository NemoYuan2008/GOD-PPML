'''
This file is used for our internal testing purposes.
'''


from Compiler.types import sfix
from Compiler import ml
from Compiler.library import print_ln
import numpy as np

sfix.set_precision(16, 61)

input_size = 5
output_size = 5
batch_size = 1

input_data = np.array( # batch_size x input_size
    [[1, 0, 1, 0, 1]]
) 
biases = np.array( # output_size
    [1, 2, 3, 4, 5]
) 
weights = np.array([ # input_size x output_size
    [  1,   2,   3,   4,   5],
    [  6,   7,   8,   9,  10],
    [ 11,  12,  13,  14,  15],
    [ 16,  17,  18,  19,  20],
    [-21,  22, -23,  24, -25],
])

input_data_secret = sfix.input_tensor_via(0, input_data, binary=True)
weights_secret = sfix.input_tensor_via(0, weights, binary=True)
biases_secret = sfix.input_tensor_via(0, biases, binary=True)

dense_layer = ml.Dense(N=1, d_in=input_size, d_out=output_size, debug=True)
dense_layer.X = input_data_secret
dense_layer.W = weights_secret
dense_layer.b = biases_secret

relu_layer = ml.Relu(shape=(1, 5))

layers = [dense_layer, relu_layer]
optimizer = ml.Optimizer(layers)

optimizer.forward(1)
dense_output = dense_layer.Y.reveal()
relu_output = relu_layer.Y.reveal()

'''
Expected output: 
[[[-8, 38, -4, 46, 0]]]
[[[0, 38, 0, 46, 0]]]
'''
print_ln('dense_output = %s', dense_output)
print_ln('relu_output = %s', relu_output)
