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

sfix.set_precision(16, 61)

input_size = 28 * 28
layer_1_out = 128
layer_2_out = 128
output_size = 10

batch_size = 1
n_iterations = 1
N = batch_size * n_iterations

ml.Layer.back_batch_size = batch_size
ml.set_n_threads(None)

layers = [
    ml.Dense(N=1, d_in=input_size, d_out=layer_1_out),
    ml.Relu(shape=(batch_size, layer_1_out)),
    ml.Dense(N=1, d_in=layer_1_out, d_out=layer_2_out),
    ml.Relu(shape=(batch_size, layer_2_out)),
    ml.Dense(N=1, d_in=layer_2_out, d_out=output_size),
    ml.MultiOutput(N=1, d_out=output_size, approx=True),
]

for x in layers[0].X, layers[-1].Y:
    x.assign_all(0)

sgd = ml.SGD(layers, n_epochs=1, debug=False, report_loss=False)
sgd.reset()
sgd.run(batch_size=batch_size)
