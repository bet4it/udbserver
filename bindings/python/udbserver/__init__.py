from unicorn import *
from udbserver_rust import udbserver as udb

def udbserver(uc: Uc, port: int = 1234, start_addr: int = 0):
    """Start udbserver.
    """
    return udb(int(uc._uch.value), port, start_addr)