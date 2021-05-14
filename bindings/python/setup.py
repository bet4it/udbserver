#!/usr/bin/env python3

"""
setup.py file for SWIG example
"""

from distutils.core import setup, Extension


rust_module = Extension('_udbserver',
                           sources=['udbserver_wrap.c'],
                           libraries=['udbserver'],
                           )

setup (name = 'rust',
       version = '0.1',
       author      = "Bet4",
       description = """Udbserver""",
       ext_modules = [rust_module],
       py_modules = [],
       )
