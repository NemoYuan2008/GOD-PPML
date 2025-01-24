# Maliciously Scalable PPML

This is the repository for the paper "Maliciously Secure and Scalable Privacy-Preserving Machine Learning with an Honest Majority". It is a heavy modification of the [MP-SPDZ](https://github.com/data61/MP-SPDZ) framework. This README contains the steps for building the source code and reproducing the results.

This repository contains the implementation of the following protocols:

- The maliciously secure protocols in the paper
- The [BGIN20](https://ia.cr/2020/1451) verification protocol (secure-with-abort, Fiat-Shamir version), which is based on distributed zero-knowledge proofs
- The [GSZ20](https://ia.cr/2020/134) verification protocol (secure-with-abort version)
- The semi-honest protocol mentioned in the paper

## Setup

The code has been test on both macOS and Linux.

### Installing Dependencies

To build the source code, first install the dependencies. On Ubuntu, the following might suffice:

```sh
sudo apt-get install automake build-essential clang cmake git libboost-dev libboost-filesystem-dev libboost-iostreams-dev libboost-thread-dev libgmp-dev libntl-dev libsodium-dev libssl-dev libtool python3
```

On macOS, you need to install [Homebrew](https://brew.sh), then run the following command:

```sh
brew install openssl boost libsodium gmp yasm ntl cmake
```

### Building the Code

To build the Code, run the following from the root of the project directory.

```sh
make atlas
```

You may wish to and `-j8` option to speed up the building: `make atlas -j8`.

### Generating SSL Certificates

All the communications between the parties are encrypted, so a one-time SSL certificate setup is required. Run the following command:

```sh
./Scripts/setup-ssl.sh <number-of-parties>
```

where `<number-of-parties>` is the maximum number of parties that you want to test. For example, `./Scripts/setup-ssl.sh 15` suffices for testing up to 15 parties.

## Reproducing the Results

All of the commands should be run from the root of the project directory.

### Example Command

To benchmark Network-A in the paper, first run (you may need to install `numpy`)

```sh
./compile.py 1-net-a --budget 1000000
```

Then, run the following script for benchmarking our protocols with BGIN instantiation for 5 parties

```sh
./Scripts/atlas-bgin.sh -N 5 1-net-a
```

The program will print all the statistics at the end of execution. All of the parties are run on the local machine.

### General Command

In general, to benchmark MPC of neural network, first run:

```sh
./compile.py <prog-name> --budget 1000000
```

with `<prog-name>` being one of `1-net-a`, `1-net-b-`, `1-net-c`, which correspond to Networks-A, B, C in the paper.

Then run the following command to execute the program

```sh
./Scripts/<protocol>.sh -N <number-of-parties> <prog-name>
```

with `<number-of-parties>` being the number of parties that run the computation, `<prog-name>` being the same as the previous command, and  `<protocol>` being one of the following:

- `atlas`: which runs the semi-honest program
- `atlas-bgin`: which runs our protocol with BGIN instantiation of the verification
- `atlas-gsz`: which runs our protocol with GSZ instantiation of the verification

## Notes

- When collecting the original data of the paper, we chose the `--budget 1000000` argument for the `./compile.py` command. When running this command for `1-net-c`, it make take a lot of time and memory. Reducing this argument reduces the memory needed for the compilation, but increases the round count and running time for the MPC execution. See [the original MP-SPDZ document](https://mp-spdz.readthedocs.io/en/latest/troubleshooting.html#high-number-of-rounds-or-slow-wan-execution) for details.
- This repo is a heavy modification of the MP-SPDZ framework. Please only use it to test the protocols in the paper, and do not use this repo to run the protocols that are implemented in MP-SPDZ.
