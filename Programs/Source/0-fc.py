from Compiler.types import sfix
from Compiler import ml
from Compiler.library import print_ln

sfix.set_precision(16, 61)

input_size = 5
output_size = 5
batch_size = 1

# input_data = torch.ones(batch_size, input_size)

input_data = [[1, 0, 1, 0, 1]] # batch_size x input_size
weights = [ # input_size x output_size
    [1,  2,  3,  4,  5],
    [6,  7,  8,  9,  10],
    [11, 12, 13, 14, 15],
    [16, 17, 18, 19, 20],
    [21, 22, 23, 24, 25]
] 
biases = [1, 2, 3, 4, 5] # output_size

input_data_secret = sfix.input_tensor_via(0, input_data, binary=True)
weights_secret = sfix.input_tensor_via(0, weights, binary=True)
biases_secret = sfix.input_tensor_via(0, biases, binary=True)

dense_layer = ml.Dense(N=1, d_in=input_size, d_out=output_size, debug=True)
dense_layer.X = input_data_secret
dense_layer.W = weights_secret
dense_layer.b = biases_secret

layers = [dense_layer]
optimizer = ml.Optimizer(layers)

optimizer.forward(1)
res = dense_layer.Y.reveal()

# Expected output: [[34, 38, 42, 46, 50]]
print_ln('res = %s', res)
