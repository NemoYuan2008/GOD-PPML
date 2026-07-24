# GOD-PPML

This is the artifact repository for the GOD-PPML paper. It is a substantial
modification of the [MP-SPDZ](https://github.com/data61/MP-SPDZ) framework.
This README explains how to build the artifact and reproduce the paper's
inference experiments.

The artifact implements inference for the three neural networks evaluated in
the paper: Networks A, B, and C.

## Setup

A macOS or Linux machine is required. The code has been tested on macOS 15 and
Ubuntu 22.04.

### Installing C++ library dependencies

On Ubuntu, run:

```sh
sudo apt-get install automake build-essential clang cmake git libboost-dev libboost-filesystem-dev libboost-iostreams-dev libboost-thread-dev libgmp-dev libntl-dev libsodium-dev libssl-dev libtool python3
```

On macOS, first install [Homebrew](https://brew.sh), then run:

```sh
brew install openssl boost libsodium gmp
```

### Installing Python dependencies

Inference requires `numpy`. Install it with `pip` or `conda`, for example:

```sh
pip3 install numpy torch
```

Obtaining the accuracy result additionally requires PyTorch. For example:

```sh
pip3 install torch torchvision
```

### Building the code

From the root of the project directory, run:

```sh
make atlas-gsz-party.x
```

Parallel compilation can reduce the build time, for example:

```sh
make -j8 atlas-gsz-party.x
```

### Generating SSL certificates

Communication between the parties is encrypted, so a one-time SSL certificate
setup is required. From the root of the project directory, run:

```sh
./Scripts/setup-ssl.sh <number-of-parties>
```

`<number-of-parties>` is the maximum number of parties that you plan to use.
For example, the following command generates certificates sufficient for
experiments with up to 15 parties:

```sh
./Scripts/setup-ssl.sh 15
```

## Reproducing the inference results

Run all commands in this section from the root of the project directory.

The commands below launch all parties on one local machine. The paper's
experiments used two machines. See
[Notes for reproducing the results](#notes-for-reproducing-the-results) for
details that primarily affect running time.

### Example: Network A with five parties

First compile Network A:

```sh
./compile.py 1-net-a --budget 1000000
```

Then run the GOD-PPML protocol with five parties:

```sh
ATLAS_GSZ_FTAG_CHUNK_WIDTH=372 \
    ./Scripts/atlas-gsz.sh -N 5 1-net-a
```

The program prints execution and communication statistics when it finishes.

### General command

Compile the desired inference program:

```sh
./compile.py <program> --budget 1000000
```

`<program>` must be one of:

- `1-net-a` for Network A;
- `1-net-b` for Network B;
- `1-net-c` for Network C.

Then run it with the desired number of parties:

```sh
ATLAS_GSZ_FTAG_CHUNK_WIDTH=372 \
    ./Scripts/atlas-gsz.sh -N <number-of-parties> <program>
```

For example, to run Network C with 15 parties:

```sh
./compile.py 1-net-c --budget 1000000
ATLAS_GSZ_FTAG_CHUNK_WIDTH=372 \
    ./Scripts/atlas-gsz.sh -N 15 1-net-c
```

The network definitions are in `Programs/Source/1-net-a.py`,
`Programs/Source/1-net-b.py`, and `Programs/Source/1-net-c.py`.

### Notes for reproducing the results

- The paper's experiments used `--budget 1000000` when compiling each
  network. Compiling `1-net-c` can take about one minute. A smaller budget
  reduces compilation memory usage but can increase the MPC round count and
  execution time. See the MP-SPDZ documentation on
  [high round counts and slow WAN execution](https://mp-spdz.readthedocs.io/en/latest/troubleshooting.html#high-number-of-rounds-or-slow-wan-execution).
- Keep `ATLAS_GSZ_FTAG_CHUNK_WIDTH=372` set for every invocation of
  `./Scripts/atlas-gsz.sh` so that the authentication batching matches the
  paper's experiment configuration.
- Runtime depends on the network environment, machine specifications, and the
  batching parameters in `Protocols/AtlasConfig.h`. Use the repository's
  committed configuration when reproducing the reported results.
- Compiling a network replaces the previous program. Rerun `compile.py` when
  switching networks.

## Reproducing the accuracy result

The accuracy experiment evaluates the complete MNIST test set and may take
some time. PyTorch must be installed.

```sh
./compile.py 3-acc-a
./Scripts/atlas-gsz.sh -N 3 3-acc-a
```
