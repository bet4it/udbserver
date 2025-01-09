# C bindings for udbserver

## API

`udbserver` provides a simple API:

```c
void udbserver(void* handle, uint16_t port, uint64_t start_addr);
```

Parameters:
- `handle`: The raw handle of a Unicorn instance
- `port`: The port number to listen on
- `start_addr`: The address at which the debug server will start and wait for connection. If set to `0`, the debug server starts immediately

You can call this API inside a Unicorn hook to integrate `udbserver` within other Unicorn-based projects.

## Installation

`udbserver` provides a C-compatible set of library, header and pkg-config files. To build and install it you need to use [cargo-c](https://crates.io/crates/cargo-c):

```sh
cargo install cargo-c
mkdir build
cargo cinstall --release --prefix=/usr --destdir build
sudo cp -dr build/* /
```

## Usage

Check the [example](example.c) on how to use it:

```sh
$ gcc example.c -lunicorn -ludbserver -o example
$ ./example
```
