# this trains an AlexNet network on ImageNet in cleartext
# before testing it in secure computation

# program.options_from_args()

from Compiler.types import sfix
from Compiler import ml
from Compiler.library import print_ln
import numpy as np

# ml.set_n_threads(4)
sfix.set_precision(16, 61)

# try:
#     ml.set_n_threads(int(program.args[1]))
# except:
#     pass

# Original AlexNet for ImageNet (224x224 input)
input_size = 224

# Layer 1: Conv1 + ReLU + MaxPool1
conv_1_in_channels = 3
conv_1_out_channels = 96
conv_1_kernel = 11
conv_1_stride = 4
conv_1_padding = 0
conv_1_out_shape = (input_size - conv_1_kernel + 2 * conv_1_padding) // conv_1_stride + 1
print(f"Conv1 output shape: {conv_1_out_shape}")  # Should be 54

pool_1_in_shape = conv_1_out_shape
pool_1_kernel = 3
pool_1_stride = 2
pool_1_out_shape = (pool_1_in_shape - pool_1_kernel) // pool_1_stride + 1
print(f"Pool1 output shape: {pool_1_out_shape}")  # Should be 26

# Layer 2: Conv2 + ReLU + MaxPool2
conv_2_in_channels = conv_1_out_channels
conv_2_in_shape = pool_1_out_shape
conv_2_out_channels = 256
conv_2_kernel = 5
conv_2_stride = 1
conv_2_padding = 2
conv_2_out_shape = (conv_2_in_shape - conv_2_kernel + 2 * conv_2_padding) // conv_2_stride + 1
print(f"Conv2 output shape: {conv_2_out_shape}")  # Should be 26

pool_2_in_shape = conv_2_out_shape
pool_2_kernel = 3
pool_2_stride = 2
pool_2_out_shape = (pool_2_in_shape - pool_2_kernel) // pool_2_stride + 1
print(f"Pool2 output shape: {pool_2_out_shape}")  # Should be 12

# Layer 3: Conv3 + ReLU (no pooling)
conv_3_in_channels = conv_2_out_channels
conv_3_in_shape = pool_2_out_shape
conv_3_out_channels = 384
conv_3_kernel = 3
conv_3_stride = 1
conv_3_padding = 1
conv_3_out_shape = (conv_3_in_shape - conv_3_kernel + 2 * conv_3_padding) // conv_3_stride + 1
print(f"Conv3 output shape: {conv_3_out_shape}")  # Should be 12

# Layer 4: Conv4 + ReLU (no pooling)
conv_4_in_channels = conv_3_out_channels
conv_4_in_shape = conv_3_out_shape
conv_4_out_channels = 384
conv_4_kernel = 3
conv_4_stride = 1
conv_4_padding = 1
conv_4_out_shape = (conv_4_in_shape - conv_4_kernel + 2 * conv_4_padding) // conv_4_stride + 1
print(f"Conv4 output shape: {conv_4_out_shape}")  # Should be 12

# Layer 5: Conv5 + ReLU + MaxPool5
conv_5_in_channels = conv_4_out_channels
conv_5_in_shape = conv_4_out_shape
conv_5_out_channels = 256
conv_5_kernel = 3
conv_5_stride = 1
conv_5_padding = 1
conv_5_out_shape = (conv_5_in_shape - conv_5_kernel + 2 * conv_5_padding) // conv_5_stride + 1
print(f"Conv5 output shape: {conv_5_out_shape}")  # Should be 12

pool_5_in_shape = conv_5_out_shape
pool_5_kernel = 3
pool_5_stride = 2
pool_5_out_shape = (pool_5_in_shape - pool_5_kernel) // pool_5_stride + 1
print(f"Pool5 output shape: {pool_5_out_shape}")  # Should be 5

# Calculate flattened size for fully connected layers
flattened_size = pool_5_out_shape * pool_5_out_shape * conv_5_out_channels
print(f"Flattened size: {flattened_size}")  # Should be 6400

# Fully connected layer sizes (original AlexNet)
fc1_in_size = flattened_size
fc1_out_size = 4096

fc2_in_size = fc1_out_size
fc2_out_size = 4096

fc3_in_size = fc2_out_size
fc3_out_size = 1000  # ImageNet has 1000 classes

print(f"FC1: {fc1_in_size} -> {fc1_out_size}")
print(f"FC2: {fc2_in_size} -> {fc2_out_size}")
print(f"FC3: {fc3_in_size} -> {fc3_out_size}")

# Build the network layers
layers = [
    # Layer 1: Conv1 + ReLU + MaxPool1
    ml.easyConv2d([1, input_size, input_size, conv_1_in_channels], conv_1_in_channels, conv_1_out_channels, conv_1_kernel, conv_1_stride, conv_1_padding), # 0
    ml.Relu([1, conv_1_out_shape, conv_1_out_shape, conv_1_out_channels]), # 1
    ml.easyMaxPool([1, conv_1_out_shape, conv_1_out_shape, conv_1_out_channels], pool_1_kernel, pool_1_stride), # 2
    
    # Layer 2: Conv2 + ReLU + MaxPool2
    ml.easyConv2d([1, pool_1_out_shape, pool_1_out_shape, conv_2_in_channels], conv_2_in_channels, conv_2_out_channels, conv_2_kernel, conv_2_stride, conv_2_padding), # 3
    ml.Relu([1, conv_2_out_shape, conv_2_out_shape, conv_2_out_channels]), # 4
    ml.easyMaxPool([1, conv_2_out_shape, conv_2_out_shape, conv_2_out_channels], pool_2_kernel, pool_2_stride), # 5
    
    # Layer 3: Conv3 + ReLU
    ml.easyConv2d([1, pool_2_out_shape, pool_2_out_shape, conv_3_in_channels], conv_3_in_channels, conv_3_out_channels, conv_3_kernel, conv_3_stride, conv_3_padding), # 6
    ml.Relu([1, conv_3_out_shape, conv_3_out_shape, conv_3_out_channels]), # 7
    
    # Layer 4: Conv4 + ReLU
    ml.easyConv2d([1, conv_3_out_shape, conv_3_out_shape, conv_4_in_channels], conv_4_in_channels, conv_4_out_channels, conv_4_kernel, conv_4_stride, conv_4_padding), # 8
    ml.Relu([1, conv_4_out_shape, conv_4_out_shape, conv_4_out_channels]), # 9
    
    # Layer 5: Conv5 + ReLU + MaxPool5
    ml.easyConv2d([1, conv_4_out_shape, conv_4_out_shape, conv_5_in_channels], conv_5_in_channels, conv_5_out_channels, conv_5_kernel, conv_5_stride, conv_5_padding), # 10
    ml.Relu([1, conv_5_out_shape, conv_5_out_shape, conv_5_out_channels]), # 11
    ml.easyMaxPool([1, conv_5_out_shape, conv_5_out_shape, conv_5_out_channels], pool_5_kernel, pool_5_stride), # 12
    
    # Fully connected layers
    ml.Dense(N=1, d_in=flattened_size, d_out=fc1_out_size), # 13
    ml.Relu([1, fc1_out_size]), # 14
    
    ml.Dense(N=1, d_in=fc1_out_size, d_out=fc2_out_size), # 15
    ml.Relu([1, fc2_out_size]), # 16
    
    ml.Dense(N=1, d_in=fc2_out_size, d_out=fc3_out_size), # 17
]


# Assign random weights to all layers and input to first layer
# Input tensor for the first layer (ImageNet input: 224x224x3)
layers[0].X = sfix.input_tensor_via(0, np.random.rand(1, conv_1_in_channels, input_size, input_size), binary=True)

# Conv layer weights (format: [out_channels, in_channels, kernel_height, kernel_width])
layers[0].weights = sfix.input_tensor_via(0, np.random.rand(conv_1_out_channels, conv_1_in_channels, conv_1_kernel, conv_1_kernel), binary=True)
layers[3].weights = sfix.input_tensor_via(0, np.random.rand(conv_2_out_channels, conv_2_in_channels, conv_2_kernel, conv_2_kernel), binary=True)
layers[6].weights = sfix.input_tensor_via(0, np.random.rand(conv_3_out_channels, conv_3_in_channels, conv_3_kernel, conv_3_kernel), binary=True)
layers[8].weights = sfix.input_tensor_via(0, np.random.rand(conv_4_out_channels, conv_4_in_channels, conv_4_kernel, conv_4_kernel), binary=True)
layers[10].weights = sfix.input_tensor_via(0, np.random.rand(conv_5_out_channels, conv_5_in_channels, conv_5_kernel, conv_5_kernel), binary=True)

# Dense layer weights and biases
# FC1: 6400 -> 4096
layers[13].W = sfix.input_tensor_via(0, np.random.rand(flattened_size, fc1_out_size), binary=True)
layers[13].b = sfix.input_tensor_via(0, np.random.rand(fc1_out_size), binary=True)

# FC2: 4096 -> 4096
layers[15].W = sfix.input_tensor_via(0, np.random.rand(fc1_out_size, fc2_out_size), binary=True)
layers[15].b = sfix.input_tensor_via(0, np.random.rand(fc2_out_size), binary=True)

# FC3: 4096 -> 1000 (ImageNet classes)
layers[17].W = sfix.input_tensor_via(0, np.random.rand(fc2_out_size, fc3_out_size), binary=True)
layers[17].b = sfix.input_tensor_via(0, np.random.rand(fc3_out_size), binary=True)

print(f"\nAlexNet Architecture Summary:")
print(f"Input: {input_size}x{input_size}x{conv_1_in_channels}")
print(f"Conv1: {conv_1_out_shape}x{conv_1_out_shape}x{conv_1_out_channels}")
print(f"Pool1: {pool_1_out_shape}x{pool_1_out_shape}x{conv_1_out_channels}")
print(f"Conv2: {conv_2_out_shape}x{conv_2_out_shape}x{conv_2_out_channels}")
print(f"Pool2: {pool_2_out_shape}x{pool_2_out_shape}x{conv_2_out_channels}")
print(f"Conv3: {conv_3_out_shape}x{conv_3_out_shape}x{conv_3_out_channels}")
print(f"Conv4: {conv_4_out_shape}x{conv_4_out_shape}x{conv_4_out_channels}")
print(f"Conv5: {conv_5_out_shape}x{conv_5_out_shape}x{conv_5_out_channels}")
print(f"Pool5: {pool_5_out_shape}x{pool_5_out_shape}x{conv_5_out_channels}")
print(f"Flatten: {flattened_size}")
print(f"FC1: {fc1_out_size}")
print(f"FC2: {fc2_out_size}")
print(f"FC3: {fc3_out_size} (ImageNet classes)")

optimizer = ml.Optimizer(layers)
optimizer.forward(1)
