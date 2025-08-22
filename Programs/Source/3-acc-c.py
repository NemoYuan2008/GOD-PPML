import torch
import torch.nn as nn
import torchvision


net = nn.Sequential(
    nn.Conv2d(1, 16, kernel_size=5, stride=1, padding=0),
    nn.MaxPool2d(kernel_size=2, stride=2, padding=0),
    nn.ReLU(),
    nn.Conv2d(16, 16, kernel_size=5, stride=1, padding=0),
    nn.MaxPool2d(kernel_size=2, stride=2, padding=0),
    nn.ReLU(),
    nn.Flatten(),
    nn.Linear(256, 100),
    nn.ReLU(),
    nn.Linear(100, 10)
)

print('Downloading the dataset to ./Player-Data (if needed), please wait...')

# train for a bit
transform = torchvision.transforms.Compose([torchvision.transforms.ToTensor(),])
dataset_train_torch = torchvision.datasets.MNIST(root='./Player-Data', train=True, download=True, transform=transform)
optimizer = torch.optim.Adam(net.parameters(), amsgrad=True)
criterion = nn.CrossEntropyLoss()

num_epochs = 10
print(f'Training for {num_epochs} epochs')

for epoch in range(num_epochs):
    for i, data in enumerate(torch.utils.data.DataLoader(dataset_train_torch, batch_size=128)):
        inputs, labels = data
        
        optimizer.zero_grad()
        outputs = net(inputs)
        loss = criterion(outputs, labels)
        loss.backward()
        optimizer.step()

with torch.no_grad():
    dataset_test_torch = torchvision.datasets.MNIST(root='./Player-Data', train=False, download=True, transform=transform)
    
    total = correct_classified = 0

    for data in torch.utils.data.DataLoader(dataset_test_torch, batch_size=128):
        inputs, labels = data

        outputs = net(inputs)
        _, predicted = torch.max(outputs.data, 1)
        total += labels.size(0)
        correct_classified += (predicted == labels).sum().item()

    print(f'Test Accuracy: {correct_classified / total * 100:.2f}%')


############ Begin MP-SPDZ code ############


from Compiler.types import sint, sfix
import Compiler.ml as ml
from Compiler.library import print_ln

# ml.set_n_threads(4)

dataset_train = torchvision.datasets.MNIST(root='./Player-Data', train=True, download=True)
# normalize to [0,1] before input
training_samples = sfix.input_tensor_via(0, dataset_train.data / 255., binary=True)
training_labels = sint.input_tensor_via(0, dataset_train.targets, binary=True, one_hot=True)

dataset_test = torchvision.datasets.MNIST(root='./Player-Data', train=False, download=True)
test_samples = sfix.input_tensor_via(0, dataset_test.data / 255., binary=True)
test_labels = sint.input_tensor_via(0, dataset_test.targets, binary=True, one_hot=True)

print(f"dataset_train shape: {dataset_train.data.shape}")
print(f"Training samples shape: {training_samples.shape}")

layers = ml.layers_from_torch(net, training_samples.shape, 128, input_via=0)
optimizer = ml.Optimizer(layers)

n_correct, loss = optimizer.reveal_correctness(test_samples, test_labels, 128, running=True)
print_ln('Secure accuracy: %s/%s', n_correct, len(test_samples))

