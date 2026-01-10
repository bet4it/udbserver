{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    git
    cmake
    clang
    cargo
    cargo-c
    clippy
    rustc
    rustfmt
    pkg-config
    unicorn

    python3
    python3Packages.build
    python3Packages.wheel
    python3Packages.setuptools
    python3Packages.setuptools-rust
    python3Packages.setuptools-scm
  ];

  LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
}
