#!/usr/bin/env python3
# encoding: utf-8

from setuptools import setup, Extension
from pathlib import Path
import os
import shutil
import subprocess

ROOT_DIR = Path(os.path.realpath(__file__)).parent

VERSION = "0.1"

def cargo_cinstall():
    args = ["cargo", "cinstall"]
    if not os.getenv("DEBUG", ""):
        args += ["--release"]
    args += ["--prefix", "/usr", "--destdir", "python_build"]
    subprocess.check_output(args, cwd=ROOT_DIR)

    return Path(ROOT_DIR) / "python_build" / "usr" 

BUILD_DIR = cargo_cinstall()

rust_module = Extension('udbserver_rust',
                        include_dirs=[str(BUILD_DIR / "include")],
                        sources=['udbserver.c'],
                        library_dirs=["/usr/local/lib"], # Assume unicorn is install globally as cargo.toml suggests
                        extra_link_args=["-Wl,--no-as-needed", "-l:libunicorn.so"],
                        extra_objects=[str(BUILD_DIR / "lib" / "libudbserver.a")],
                        )

setup (name = 'udbserver',
       version = VERSION,
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
       packages=["udbserver"],
       install_requires=[
        "unicorn>=2.0.0rc7"
       ],
       py_modules = [],
       is_pure=False,
       package_data={
           "udbserver" : ["udbserver.c"]
       }
)
