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

ml.Layer.back_batch_size = 1
ml.set_n_threads(None)

layers = [
    ml.easyConv2d([1, 28, 28, 1], 1, conv_filters, kernel_size, stride, padding),
    ml.Relu(shape=(1, conv_output, conv_output, conv_filters)),
    ml.Dense(N=1, d_in=flattened_size, d_out=fc_layer_1_out),
    ml.Relu(shape=(1, fc_layer_1_out)),
    ml.Dense(N=1, d_in=fc_layer_1_out, d_out=output_size),
    ml.MultiOutput(N=1, d_out=output_size, approx=True),
]

for x in layers[0].X, layers[-1].Y:
    x.assign_all(0)

sgd = ml.SGD(layers, n_epochs=1, debug=False, report_loss=False)
sgd.reset()
sgd.run(batch_size=1)
