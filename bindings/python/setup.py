#!/usr/bin/env python3
# encoding: utf-8

from setuptools import setup, Extension


rust_module = Extension('udbserver',
                           sources=['udbserver.c'],
                           libraries=['udbserver'],
                           )

setup (name = 'udbserver',
       version = '0.1',
       author = 'Bet4',
       author_email = '0xbet4@gmail.com',
       description = 'Python bindings of udbserver',
       url = 'https://github.com/bet4it/udbserver',
       license='MIT License',
       classifiers=[
           'Intended Audience :: Developers',
           'License :: OSI Approved :: MIT License',
           'Programming Language :: Python :: 3',
           'Topic :: Software Development :: Debuggers',
       ],
       ext_modules = [rust_module],
       py_modules = [],
       )
