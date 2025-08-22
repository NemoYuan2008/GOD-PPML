import torch
import torch.nn as nn
import torchvision


net = nn.Sequential(
    nn.Linear(28 * 28, 128),
    nn.ReLU(),
    nn.Linear(128, 128),
    nn.ReLU(),
    nn.Linear(128, 10),
)

print('Downloading the dataset to ./Player-Data if needed, please wait...')

transform = torchvision.transforms.Compose([torchvision.transforms.ToTensor(),])
dataset_train_torch = torchvision.datasets.MNIST(root='./Player-Data', train=True, download=True, transform=transform)
dataset_test_torch = torchvision.datasets.MNIST(root='./Player-Data', train=False, download=True, transform=transform)

# train for a bit

optimizer = torch.optim.Adam(net.parameters(), amsgrad=True)
criterion = nn.CrossEntropyLoss()

num_epochs = 5
print(f'Training for {num_epochs} epochs')

for epoch in range(num_epochs):
    for i, data in enumerate(torch.utils.data.DataLoader(dataset_train_torch, batch_size=128)):
        inputs, labels = data
        
        # MNIST images come as (batch_size, 1, 28, 28), need to flatten to (batch_size, 784)
        inputs = inputs.view(inputs.size(0), -1)
        
        optimizer.zero_grad()
        outputs = net(inputs)
        loss = criterion(outputs, labels)
        loss.backward()
        optimizer.step()

with torch.no_grad():
    total = correct_classified = 0

    for data in torch.utils.data.DataLoader(dataset_test_torch, batch_size=128):
        inputs, labels = data

        # MNIST images come as (batch_size, 1, 28, 28), need to flatten to (batch_size, 784)
        inputs = inputs.view(inputs.size(0), -1)

        outputs = net(inputs)
        _, predicted = torch.max(outputs.data, 1)
        total += labels.size(0)
        correct_classified += (predicted == labels).sum().item()

    print(f'Plaintext Test Accuracy: {correct_classified / total * 100:.2f}%')


############ Begin MP-SPDZ code ############


from Compiler.types import sint, sfix
import Compiler.ml as ml
from Compiler.library import print_ln


dataset_train = torchvision.datasets.MNIST(root='./Player-Data', train=True, download=True)
dataset_test = torchvision.datasets.MNIST(root='./Player-Data', train=False, download=True)

# normalize to [0,1] before input
training_samples = sfix.input_tensor_via(0, dataset_train.data / 255., binary=True)
training_labels = sint.input_tensor_via(0, dataset_train.targets, binary=True, one_hot=True)

test_samples = sfix.input_tensor_via(0, dataset_test.data / 255., binary=True)
test_labels = sint.input_tensor_via(0, dataset_test.targets, binary=True, one_hot=True)

layers = ml.layers_from_torch(net, training_samples.shape, 128, input_via=0)
optimizer = ml.Optimizer(layers)


n_correct, loss = optimizer.reveal_correctness(test_samples, test_labels, 128, running=True)
print_ln('Secure accuracy: %s/%s', n_correct, len(test_samples))
