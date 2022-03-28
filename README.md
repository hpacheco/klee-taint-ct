KLEE-TAINT Symbolic Virtual Machine
===================================

This is the fork of KLEE-taint used for our CS-550 project. 
To reproduce our results correctly perform the following steps:
- Clone the repository with submodules. 
- Build klee using the instructions [here](https://klee.github.io/build-llvm9/).
- Switch to the examples/taint folder and build the submodule OpenSSL using the instructions [here](https://github.com/rishabh246/openssl/blob/3.0.0-cmake/NOTES-CMAKE.md).
- Switch to any of the examples and run `make verify`
