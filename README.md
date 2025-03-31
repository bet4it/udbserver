# udbserver - Unicorn Emulator Debug Server

`udbserver` is a debugging plugin for [Unicorn Engine](https://www.unicorn-engine.org/) that implements the [GDB Remote Serial Protocol](https://sourceware.org/gdb/onlinedocs/gdb/Remote-Protocol.html).

It enables GDB-compatible debugging capabilities for Unicorn-based emulation projects, allowing you to inspect and control the emulation state through a GDB client.

## Features

* [x] Registers
* [x] Memory
* [x] Single Step
* [x] Breakpoint
* [x] Watchpoint
* [ ] Ctrl-C interrupt

## Architectures Support

* i386
* x86\_64
* ARM
* AArch64
* M68K
* MIPS
* PowerPC
* RISC-V

## Installation & Usage

### Python

The easiest way to get started is via pip:

``
pip install udbserver
``

Check out the [Python binding](bindings/python) for examples and documentation.

### Rust

As a native Rust project, you can use `udbserver` directly as a crate. Check out the [example](examples/server.rs):

``
cargo run --example server
``

### Other Languages

`udbserver` provides bindings for several languages:

* [C-compatible API](bindings/c)
* [Go](bindings/go)
* [Java](bindings/java)

Please check the corresponding directories for language-specific installation and usage instructions.
