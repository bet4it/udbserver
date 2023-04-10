import os
import ctypes
from unicorn import Uc
from ctypes import c_void_p, c_uint16, c_uint64

_current_dir = os.path.dirname(os.path.abspath(__file__))
_udbserver_lib = ctypes.cdll.LoadLibrary(os.path.join(_current_dir, "libudbserver.so"))

_udbserver_lib.udbserver.argtypes = [c_void_p, c_uint16, c_uint64]
_udbserver_lib.udbserver.restype = None

def udbserver(uc: Uc, port: int = 1234, start_addr: int = 0):
    """Start udbserver.
    """
    _udbserver_lib.udbserver(int(uc._uch.value), port, start_addr)
