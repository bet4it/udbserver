Python bindings for udbserver
=========================

This package provides Python bindings for udbserver, allowing you to debug your Unicorn-based projects with GDB.
For more details about udbserver, please check the `project homepage <https://github.com/bet4it/udbserver>`_.

Installation
-----------

From PyPI
~~~~~~~~~

It's highly recommended to install the Python package via pip::

    pip install udbserver

From source
~~~~~~~~~~

To build and install this package manually::

    python3 -m build --wheel
    pip install dist/*.whl
