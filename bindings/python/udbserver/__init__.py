import os
import ctypes
import sys
from unicorn import Uc
from ctypes import c_void_p, c_uint16, c_uint64

_current_dir = os.path.dirname(os.path.abspath(__file__))

if sys.platform.startswith('win'):
    _library_file = "libudbserver.pyd"
else:
    _library_file = "libudbserver.so"

_udbserver_lib = ctypes.cdll.LoadLibrary(os.path.join(_current_dir, _library_file))

_udbserver_lib.udbserver.argtypes = [c_void_p, c_uint16, c_uint64]
_udbserver_lib.udbserver.restype = None

def udbserver(uc: Uc, port: int = 1234, start_addr: int = 0):
    """Start udbserver.
    """
    _udbserver_lib.udbserver(int(uc._uch.value), port, start_addr)
