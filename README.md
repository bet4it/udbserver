# udbserver - Unicorn Emulator Debug Server

When you do emulation with [Unicorn Engine](https://www.unicorn-engine.org/), do you want to inspect the inner state during every step?

`udbserver` is a plugin for Unicorn, provides a debug server which implements [GDB Remote Serial Protocol](https://sourceware.org/gdb/onlinedocs/gdb/Remote-Protocol.html). You can connect it by a `GDB` client and do debugging as what you do on real program.

`udbserver` can be used as a crate by Rust program, but it also provides a C library and bindings for other languages. You can use it inside most Unicorn based projects!

## Features

* [x] Registers
* [x] Memory
* [x] Single Step
* [x] Breakpoint
* [x] Watchpoint
* [ ] Ctrl-C interrupt

## Architectures support

* i386
* x86\_64
* ARM
* AArch64
* MIPS
* PowerPC

# Usage

## API

`udbserver` only provides one API:

```c
void udbserver(void* handle, uint16_t port, uint64_t start_addr);
```

The `handle` should be the raw handle of a Unicorn instance, `port` is the port to be listened, `start_addr` is the address which when Unicorn runs at the debug server will start and wait to be connected. if `start_addr` is provided with `0`, the debug server will start instantly.

You can call this API inside a Unicorn hook, so you can integrate `udbserver` inside other Unicorn based project easily.

## Used in Rust

You can use `udbserver` as a crate in `Rust`.

You can check the [example](examples/server.rs) on how to use it.

And you can try it by:

```sh
$ cargo run --example server
```

Then you can connect it with `gdb-multiarch`.

## Installation

`udbserver` provides a C-compatible set of library, header and pkg-config files, which help you to use it with other languages.

To build and install it you need to use [cargo-c](https://crates.io/crates/cargo-c):

```sh
$ cargo install cargo-c
$ mkdir build
$ cargo cinstall --release --prefix=/usr --destdir build
$ sudo cp -a build/* /
```

## Language bindings

After install the `udbserver` library, you can use `udbserver` in other languages.

You could check the examples on how to use `udbserver` by different languages:

* [C](bindings/c)
* [Go](bindings/go)
* [Java](bindings/java)
* [Python](bindings/python)
