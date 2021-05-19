#!/usr/bin/env python3
# encoding: utf-8

from distutils.core import setup, Extension


rust_module = Extension('udbserver',
                           sources=['udbserver.c'],
                           libraries=['udbserver'],
                           include_dirs=['../../include'],
                           library_dirs=['../../target/release'],
                           )

setup (name = 'udbserver',
       version = '0.1',
       author      = "Bet4",
       description = """Udbserver""",
       ext_modules = [rust_module],
       py_modules = [],
       )
