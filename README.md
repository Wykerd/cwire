# CWire
A lightweight asynchronous networking library for C.

Includes:
- TCP socket wrapper
- TLS wrapper
- Full RFC 6455 compliant WebSocket implementation

# Dependencies

## External Dependencies
- OpenSSL
- LibUV

## Included Dependencies (submodules)
- llhttp

## Toolchain
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