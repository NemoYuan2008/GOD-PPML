# Maliciously Scalable PPML

This is the repository for the paper "Maliciously Secure and Scalable Privacy-Preserving Machine Learning with an Honest Majority". It is a heavy modification of the [MP-SPDZ](https://github.com/data61/MP-SPDZ) framework. This README contains the steps for building the source code and reproducing the results.

This repository contains the implementation of the following protocols:

- The maliciously secure protocols in the paper
- The [BGIN20](https://ia.cr/2020/1451) verification protocol (secure-with-abort, Fiat-Shamir version), which is based on distributed zero-knowledge proofs
- The [GSZ20](https://ia.cr/2020/134) verification protocol (secure-with-abort version)
- The semi-honest protocol mentioned in the paper

## Setup

A Mac or Linux machine is required for running the code.
We have tested the code on both macOS 15 and Ubuntu 22.04.

### Installing C++ Library Dependencies

On Ubuntu, run the following command:

```sh
sudo apt-get install automake build-essential clang cmake git libboost-dev libboost-filesystem-dev libboost-iostreams-dev libboost-thread-dev libgmp-dev libntl-dev libsodium-dev libssl-dev libtool python3
```

On macOS, you would need to install [Homebrew](https://brew.sh), then run the following command:

```sh
brew install openssl boost libsodium gmp
```

### Installing Python Dependencies

The only required Python package is `numpy`, which can be installed using `pip` or `conda`, e.g.,

```sh
pip3 install numpy
```

### Building the Code

To build the source code, run the following from the root of the project directory.

```sh
make atlas
```

You may wish to add `-j8` option to speed up the building: `make atlas -j8`.

### Generating SSL Certificates

All the communications between the parties are encrypted, so a one-time SSL certificate setup is required. To do so, run the following command from the root of the project directory:

```sh
./Scripts/setup-ssl.sh <number-of-parties>
```

where `<number-of-parties>` is the maximum number of parties that you want to test. For example, `./Scripts/setup-ssl.sh 15` suffices for testing up to 15 parties.

## Reproducing the Results

This section provides steps to reproducing the results.
All of the commands in this section should be run from the root of the project directory.

**Note:**
The commands will run all the parties on the local machine, but in the original paper they were run on two machines.
Also, there are some parameters that can influence the running time, in particular WAN running time.
Please refer to [Notes for Reproducing the results](#notes-for-reproducing-the-results) for details.

### Example Command

To benchmark Network-A in the paper, first run:

```sh
./compile.py 1-net-a --budget 1000000
```

Then, run the following script for benchmarking our protocols with BGIN instantiation for 5 parties:

```sh
./Scripts/atlas-bgin.sh -N 5 1-net-a
```

The program will print all the statistics at the end of execution. All of the parties are run on the local machine.

### General Command

In general, to benchmark MPC of neural network, first run:

```sh
./compile.py <prog-name> --budget 1000000
```

with `<prog-name>` being one of `1-net-a`, `1-net-b`, `1-net-c`, which correspond to Networks-A, B, C in the paper.

Then run the following command to execute the program

```sh
./Scripts/<protocol>.sh -N <number-of-parties> <prog-name>
```

with `<number-of-parties>` being the number of parties that run the computation, `<prog-name>` being the same as the previous command, and  `<protocol>` being one of the following:

- `atlas`: which runs the semi-honest program
- `atlas-bgin`: which runs our protocol with BGIN instantiation of the verification
- `atlas-gsz`: which runs our protocol with GSZ instantiation of the verification

### Notes for Reproducing the results

All of the notes in this section mainly affect execution time (in particular WAN time), and has minimal impact on total communication.

- When collecting the original data of the paper, we chose the `--budget 1000000` argument for the `./compile.py` command. When running this command for `1-net-c`, it make take some time (~1min). Reducing this argument reduces the memory needed for the compilation, but increases the round count and running time for the MPC execution. See [the original MP-SPDZ document](https://mp-spdz.readthedocs.io/en/latest/troubleshooting.html#high-number-of-rounds-or-slow-wan-execution) for details.
- When collecting the original data of the paper, the parameters `max_before_check` and `max_before_shrink` in the file `Protocols/AtlasConfig.h` was set to 400,000. Larger values result in smaller communication rounds and running time, but more memory usage.
- When collecting the original data of the paper, the parties were run on two different machines, while the above commands are for local execution. Please refer to the [Network](https://mp-spdz.readthedocs.io/en/latest/networking.html) section of the original MP-SPDZ document for remote execution commands.
- The "sy-shamir" protocol mentioned in the paper was benchmarked using the [original (unmodified) version of MP-SPDZ](https://github.com/data61/MP-SPDZ). Please use the script `Scripts/sy-shamir.sh` in the original framework.

## Training and accuracy

For training, run

```sh
./compile.py 2-train-c
./Scripts/atlas-bgin.sh -N 3 2-train-c
```

For accuracy, run (need pytorch installed)

```sh
./compile.py 3-acc-a
./Scripts/atlas-bgin.sh -N 3 3-acc-a
```

Since this evaluates the whole MNIST test set, it may take some time.

The code for the networks are located at `Programs/Source`, where you can see the network structure.
