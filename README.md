# CWire
A lightweight asynchronous networking library for C

# Dependencies

## External Dependencies
- OpenSSL
- LibUV

## Included Dependencies (submodules)
- llhttp

## Toolchain
- node & npm (for llhttp)
- gcc
- cmake

# Setup

## OS Support
The library is currently only tested on Linux based distributions using GCC.

## Getting the sources
Create a local clone of the repo
```
git clone --recursive https://github.com/Wykerd/cwire.git
```

## Building
```
mkdir build
cd build
cmake ..
make
```
Alternatively you can use some IDE with CMake support. I personally use VSCode with C/C++ and CMake Tools extensions from Microsoft to develop this project.


## Running the demo
Run `./cwire-demo` from the build output directory 