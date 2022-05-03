# DynO: Dynamic Oblivious Primitives

Using this guide you should be able to reproduce our results.

## 1. Preparation

You need [Conan](https://conan.io), [CMake](https://cmake.org), [Ninja](https://ninja-build.org), and a C++ compiler (we
use [CLang](https://clang.llvm.org)).

These configurations have been tested:

* macOS Monterey (12.3.1) on ArmV8 (Apple Silicon); Apple clang version 13.1.6 (clang-1316.0.21.2)
* Ubuntu 20.04 on x86\_64; clang version 13.0.1 (Ubuntu clang version 13.0.1-++20220120110924+75e33f71c2da-1~exp1~20220120231001.58)

### 1.1 (a) macOS

It is assumed that you have Brew and Apple clang installed. If not, run:

```bash
xcode-select --install
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

You can install the requirements via:

```bash
brew install cmake conan make ninja
```

### 1.1 (b) Ubuntu 20.04

```bash
sudo apt update
#sudo apt upgrade # It's generally good to do this; especially on a fresh VM.
sudo apt install -y cmake lsb-release ninja-build python3-pip software-properties-common wget
pip install conan # Installs to ~/.local/bin
echo 'PATH="$HOME/.local/bin:$PATH"' >> ~/.profile
. ~/.profile
wget https://apt.llvm.org/llvm.sh \
 && chmod +x llvm.sh \
 && sudo ./llvm.sh 13 \
 && rm llvm.sh
```

## 2. Build

Get this repository, `cd` into the project directory, and do the following:

```bash
make build
```

If all goes well, the executable(s) will be in the `bin` directory (`cmake-build-release/bin`).

## 3. Run

Go back to the project root and run [`run_timeits.sh`](./run_timeits.sh).

```bash
./run_timeits.sh
```
