import torch
import torch.nn as nn
import numpy as np

print("=== Simple PyTorch Conv2d Example ===")

# Set random seed for reproducibility
torch.manual_seed(42)
np.random.seed(42)

# Define simple convolution parameters
batch_size = 1
in_channels = 1
out_channels = 2
input_height = 4
input_width = 4
kernel_size = 3
stride = 1
padding = 1

print(f"Parameters:")
print(f"  Input shape: ({batch_size}, {in_channels}, {input_height}, {input_width})")
print(f"  Kernel size: {kernel_size}")
print(f"  Stride: {stride}")
print(f"  Padding: {padding}")
print(f"  Output channels: {out_channels}")

# Create simple input tensor 
input_tensor = torch.arange(1, batch_size * in_channels * input_height * input_width + 1, dtype=torch.float32)
input_tensor = input_tensor.reshape(batch_size, in_channels, input_height, input_width)

print(f"\nInput tensor shape: {input_tensor.shape}")
print(f"Input tensor:")
# print(input_tensor)
print(f"Channel 0:")
print(f"{input_tensor[0, 0].numpy()}")

# Create single Conv2d layer (no Sequential)
conv = nn.Conv2d(in_channels=in_channels, 
                 out_channels=out_channels,
                 kernel_size=kernel_size,
                 stride=stride,
                 padding=padding,
                 bias=True
                 )

# Initialize weights with simple values for debugging
with torch.no_grad():
    # Initialize conv weights to simple sequential values
    weight_data = torch.arange(1, conv.weight.numel() + 1, dtype=torch.float32) * 0.1
    conv.weight.data = weight_data.reshape(conv.weight.shape)
    
    # Initialize bias to simple values
    conv.bias.data = torch.tensor([0.1, 0.2], dtype=torch.float32)

print(f"\nConvolution weights shape: {conv.weight.shape}")
print(f"Convolution weights:")
for out_ch in range(out_channels):
    print(f"Output channel {out_ch}:")
    print(f"{conv.weight[out_ch, 0].detach().numpy()}")

print(f"\nBias:")
print(f"{conv.bias.detach().numpy()}")

# Perform convolution
output = conv(input_tensor)

print(f"\nOutput shape: {output.shape}")
conv_output_h = (input_height + 2*padding - kernel_size)//stride + 1
conv_output_w = (input_width + 2*padding - kernel_size)//stride + 1
print(f"Expected output shape: ({batch_size}, {out_channels}, {conv_output_h}, {conv_output_w})")

print(f"\nConv2d output:")
for c in range(out_channels):
    print(f"Output channel {c}:")
    print(f"{output[0, c].detach().numpy()}")



# Print summary
print(f"\n=== Summary ===")
print(f"Input: {input_tensor.shape} with values 1-16")
print(f"Conv2d: {in_channels} -> {out_channels} channels, {kernel_size}x{kernel_size} kernel")
print(f"Output: {output.shape}")
print(f"Weights: sequential values 0.1, 0.2, 0.3, ...")
print(f"Bias: [0.1, 0.2]")
print("Ready for MP-SPDZ integration!")


from Compiler.types import sfix
import Compiler.ml as ml
from Compiler.library import print_ln


input_tensor_secret = sfix.input_tensor_via(0, input_tensor, binary=True)
weights = sfix.input_tensor_via(0, conv.weight.data, binary=True)
bias = sfix.input_tensor_via(0, conv.bias.data, binary=True)

conv_secret = ml.easyConv2d([in_channels, input_height, input_width, 1], batch_size, out_channels, kernel_size, stride, padding)

conv_secret.X = input_tensor_secret
conv_secret.weights = weights
conv_secret.bias = bias

print_ln("bias in secret: %s", conv_secret.bias.reveal())

layers = [conv_secret]
optimizer = ml.Optimizer(layers)
optimizer.forward(1)

print(conv_secret.Y.shape)

print_ln("Secure Conv2d output: %s", conv_secret.Y.reveal())