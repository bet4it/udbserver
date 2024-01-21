#!/usr/bin/env python3
# encoding: utf-8

import sys

from setuptools import setup, Extension

EXTENSION_LIBRARIES = ['udbserver']
LIBRARY_DIRS = []
INCLUDE_DIRS = []

if sys.platform in ('win32', 'cygwin'):
    EXTENSION_LIBRARIES += ['unicorn', 'ws2_32', 'advapi32', 'userenv',
                            'bcrypt']
    LIBRARY_DIRS = ['../../build/usr/lib/']
    INCLUDE_DIRS = ['../../build/usr/include/']

rust_module = Extension('udbserver', sources=['udbserver.c'],
                        libraries=EXTENSION_LIBRARIES,
                        library_dirs=LIBRARY_DIRS,
                        include_dirs=INCLUDE_DIRS)

setup(
    name='udbserver',
    version='0.1',
    author='Bet4',
    author_email='0xbet4@gmail.com',
    description='Python bindings of udbserver',
    url='https://github.com/bet4it/udbserver',
    license='MIT License',
    classifiers=['Intended Audience :: Developers',
                 'License :: OSI Approved :: MIT License',
                 'Programming Language :: Python :: 3',
                 'Topic :: Software Development :: Debuggers'],
    ext_modules=[rust_module],
    py_modules=[],
    )
