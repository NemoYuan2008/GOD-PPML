'''
MiniONN
(Network-C as in the paper)

The NN is defined as follows: (pseudo code)
batch_size = 1
Conv2D(height=28, width=28, channels=1, filters=16, kernel_size=5, stride=1, padding=0)
MaxPooling2D(height=24, width=24, channels=16, pool_size=2, stride=2, padding=0)
ReLU()
Conv2D(height=12, width=12, channels=16, filters=16, kernel_size=5, stride=1, padding=0)
MaxPooling2D(height=8, width=8, channels=16, pool_size=2, stride=2, padding=0)
ReLU()
Flatten()
Dense(in=256, out=100)
ReLU()
Dense(in=100, out=10)
'''

from Compiler.types import sfix
from Compiler import ml

sfix.set_precision(16, 61)

input_channels = 1
input_size = 28
conv1_filters = 16
kernel_size = 5
stride = 1
padding = 0
pool_size = 2
pool_stride = 2

conv1_output = (input_size - kernel_size + 2 * padding) // stride + 1
pool1_output = (conv1_output - pool_size) // pool_stride + 1
conv2_output = (pool1_output - kernel_size + 2 * padding) // stride + 1
pool2_output = (conv2_output - pool_size) // pool_stride + 1

flattened_size = pool2_output * pool2_output * conv1_filters
fc_layer_1_out = 100
output_size = 10

ml.Layer.back_batch_size = 1
ml.set_n_threads(None)

layers = [
    ml.easyConv2d([1, input_size, input_size, input_channels], input_channels, conv1_filters, kernel_size, stride, padding), # 0
    ml.easyMaxPool([1, conv1_output, conv1_output, conv1_filters], pool_size, pool_stride), # 1
    ml.Relu(shape=(1, pool1_output, pool1_output, conv1_filters)), # 2
    ml.easyConv2d([1, pool1_output, pool1_output, conv1_filters], conv1_filters, conv1_filters, kernel_size, stride, padding), # 3
    ml.easyMaxPool([1, conv2_output, conv2_output, conv1_filters], pool_size, pool_stride), # 4
    ml.Relu(shape=(1, pool2_output, pool2_output, conv1_filters)), # 5
    ml.Dense(N=1, d_in=flattened_size, d_out=fc_layer_1_out), # 6
    ml.Relu(shape=(1, fc_layer_1_out)), # 7
    ml.Dense(N=1, d_in=fc_layer_1_out, d_out=output_size), # 8
    ml.MultiOutput(N=1, d_out=output_size, approx=True), # 9
]

for x in layers[0].X, layers[-1].Y:
    x.assign_all(0)

sgd = ml.SGD(layers, n_epochs=1, debug=False, report_loss=False)
sgd.reset()
sgd.run(batch_size=1)
