import os
import socket
import struct
import tempfile
from binascii import unhexlify
from collections import defaultdict

from unicorn import *
from .reg_map import *

class UnicornGdbserver():
    def __init__(self, uc):
        self.uc = uc
        self.ip = '127.0.0.1'
        self.port = 9999
        self.last_pkt = None
        self.step_state = False
        self.stop_state = True
        self.watch_address = None
        self.step_hook = None
        self.bp_hooks = [defaultdict(dict) for i in range(6)]

        arch = uc.query(UC_QUERY_ARCH)
        if arch == UC_ARCH_X86:
            mode = uc.query(UC_QUERY_MODE)
            if mode == UC_MODE_32:
                self.reg_map = reg_map_x86
                self.architecture = 'i386'
            elif mode == UC_MODE_64:
                self.reg_map = reg_map_x64
                self.architecture = 'i386:x86-64'
        elif arch == UC_ARCH_ARM:
            self.reg_map = reg_map_arm
            self.architecture = 'arm'
        elif arch == UC_ARCH_ARM64:
            self.reg_map = reg_map_arm64
            self.architecture = 'aarch64'

        fd, self.maps_file = tempfile.mkstemp()
        os.close(fd)

    def addr_to_str(self, addr, size):
        return addr.to_bytes(size, byteorder='little').hex()

    def bin_to_escstr(self, rawbin):
        return rawbin.replace(b'}', b'}]').replace(b'*', b'}\n').replace(b'$', b'}\x03').replace(b'#', b'}\x04')

    def setup_server(self):
        print("udb> Listening on %s:%u" % (self.ip, self.port))
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.ip, self.port))
        sock.listen(1)
        clientsocket, addr = sock.accept()
        self.sock           = sock
        self.clientsocket   = clientsocket
        self.netin          = clientsocket.makefile('r')
        self.netout         = clientsocket.makefile('w')

    def close(self):
        os.remove(self.maps_file)
        self.netin.close()
        self.netout.close()
        self.clientsocket.close()
        self.sock.close()

    def bp_hook_func(self, uc, address, size, data):
        if self.step_state:
            self.step_state = False
            return

        if self.step_hook:
            self.uc.hook_del(self.step_hook)
            self.step_hook = None
        if self.watch_address:
            self.send("T05watch:%x;" % self.watch_address)
            self.watch_address = None
        else:
            self.send("S05")
        self.stop_state = True
        self.main_loop()

    def mem_hook_func(self, uc, access, address, size, value, data):
        self.watch_address = address
        self.step_hook = self.uc.hook_add(UC_HOOK_CODE, self.bp_hook_func)

    def main_loop(self):
        while self.stop_state and self.receive() == 'Good':
            pkt = self.last_pkt
            self.send_raw('+')

            def handle_qmark(subcmd):
                self.send("S05")

            def handle_c(subcmd):
                self.stop_state = False

            def handle_D(subcmd):
                self.send('OK')
                self.stop_state = False
                self.close()

            def handle_g(subcmd):
                s = ''
                for reg in self.reg_map:
                    val = self.uc.reg_read(reg[0])
                    tmp = self.addr_to_str(val, reg[1])
                    s += tmp
                self.send(s)

            def handle_H(subcmd):
                if subcmd.startswith('g'):
                    self.send('OK')
                if subcmd.startswith('c'):
                    self.send('OK')

            def handle_m(subcmd):
                addr, size = map(lambda x:int(x, 16), subcmd.split(','))
                try:
                    mem = self.uc.mem_read(addr, size).hex()
                    self.send(mem)
                except:
                    self.send('E14')

            def handle_M(subcmd):
                addr, data = subcmd.split(',')
                size, data = data.split(':')
                addr = int(addr, 16)
                data = bytes.fromhex(data)
                try:
                    self.uc.mem_write(addr, data)
                    self.send('OK')
                except:
                    self.send('E01')

            def handle_p(subcmd):
                try:
                    reg_index = int(subcmd, 16)
                    if self.architecture == 'arm' and reg_index == 25:
                        reg_value = self.addr_to_str(self.uc.reg_read(UC_ARM_REG_CPSR), 4)
                    elif self.architecture =='aarch64' and reg_index in [33, 66, 67]:
                        reg_value = '00000000'
                    else:
                        reg = self.reg_map[reg_index]
                        reg_value = self.uc.reg_read(reg[0])
                        reg_value = self.addr_to_str(reg_value, reg[1])
                    self.send(reg_value)
                except:
                    self.send('E01')

            def handle_P(subcmd):
                try:
                    reg_index, reg_data = subcmd.split('=')
                    reg_index = int(reg_index, 16)
                    reg_data = int.from_bytes(bytes.fromhex(reg_data), byteorder='little')
                    if self.architecture == 'arm' and reg_index == 25:
                        reg = [UC_ARM_REG_CPSR, 4]
                    else:
                        reg = self.reg_map[reg_index]
                    self.uc.reg_write(reg[0], reg_data)
                    self.send('OK')
                except:
                    self.send('E01')

            def handle_q(subcmd):
                if subcmd.startswith('Supported:'):
                    self.send("PacketSize=8000;qXfer:features:read+;multiprocess+")
                elif subcmd.startswith('Xfer:features:read'):
                    self.send(f"l<target version=\"1.0\"><architecture>{self.architecture}</architecture></target>")
                elif subcmd == "Attached":
                    self.send("")
                elif subcmd.startswith("C"):
                    self.send("QCp7d0.7d0")
                elif subcmd == "fThreadInfo":
                    self.send("mp7d0.7d0")
                elif subcmd == "sThreadInfo":
                    self.send("l")
                elif subcmd == "TStatus":
                    self.send("")
                elif subcmd.startswith("Symbol"):
                    self.send("")
                elif subcmd.startswith("Attached"):
                    self.send("")
                elif subcmd == "Offsets":
                    self.send("Text=0;Data=0;Bss=0")

            def handle_Q(subcmd):
                self.send('')

            def handle_s(subcmd):
                self.stop_state = False
                self.step_state = True
                self.step_hook = self.uc.hook_add(UC_HOOK_CODE, self.bp_hook_func)

            def handle_v(subcmd):
                if subcmd == 'MustReplyEmpty':
                    self.send("")

                elif subcmd.startswith('File:open'):
                    (file_path, flags, mode) = subcmd.split(':')[-1].split(',')
                    file_path = unhexlify(file_path).decode(encoding='UTF-8')
                    flags = int(flags, 16)
                    mode = int(mode, 16)
                    if file_path.startswith("/proc") and file_path.endswith("/maps"):
                        def _perms_mapping(ps):
                            perms_d = {1: "r", 2: "w", 4: "x"}
                            perms_sym = []
                            for idx, val in perms_d.items():
                                if idx & ps != 0:
                                    perms_sym.append(val)
                                else:
                                    perms_sym.append("-")
                            return "".join(perms_sym)
                        with open(self.maps_file, 'w') as f:
                            for r in self.uc.mem_regions():
                                f.write("%s-%s %s 0 0 0\n" % (hex(r[0]), hex(r[1]+1), _perms_mapping(r[2])))
                        fd = os.open(self.maps_file, os.O_RDONLY)
                        self.send("F%x" % fd)
                    else:
                        self.send("F-1")

                elif subcmd.startswith('File:pread:'):
                    fd, count, offset = map(lambda x:int(x, 16), subcmd.split(':')[-1].split(','))
                    data = os.pread(fd, count, offset)
                    size = len(data)
                    data = self.bin_to_escstr(data)
                    if data:
                        self.send(("F%x;" % size).encode() + (data))
                    else:
                        self.send("F0;")

                elif subcmd.startswith('File:close'):
                    fd = subcmd.split(':')[-1]
                    fd = int(fd, 16)
                    os.close(fd)
                    self.send("F0")

                elif subcmd.startswith('Kill'):
                    self.send("OK")
                    self.stop_state = False
                    self.close()

                else:
                    self.send("")

            def handle_X(subcmd):
                self.send('')

            def handle_Z(subcmd):
                ztype, addr, size = map(lambda x:int(x, 16), subcmd.split(','))
                try:
                    def add_write_hook(ztype, addr, size):
                        h = self.uc.hook_add(UC_HOOK_MEM_WRITE, self.mem_hook_func, None, addr, addr+size)
                        self.bp_hooks[ztype][size][addr] = h

                    def add_read_hook(ztype, addr, size):
                        h = self.uc.hook_add(UC_HOOK_MEM_READ, self.mem_hook_func, None, addr, addr+size)
                        self.bp_hooks[ztype][size][addr] = h

                    if ztype == 0 or ztype == 1:
                        h = self.uc.hook_add(UC_HOOK_CODE, self.bp_hook_func, None, addr, addr)
                        self.bp_hooks[ztype][size][addr] = h
                        self.send('OK')
                    elif ztype == 2:
                        add_write_hook(ztype, addr, size)
                        self.send('OK')
                    elif ztype == 3:
                        add_read_hook(ztype, addr, size)
                        self.send('OK')
                    elif ztype == 4:
                        add_read_hook(ztype, addr, size)
                        add_write_hook(ztype+1, addr, size)
                        self.send('OK')
                    else:
                        self.send('E22')
                except:
                    self.send('E22')

            def handle_z(subcmd):
                ztype, addr, size = map(lambda x:int(x, 16), subcmd.split(','))
                try:
                    self.uc.hook_del(self.bp_hooks[ztype][size][addr])
                    del(self.bp_hooks[ztype][size][addr])
                    if ztype == 4:
                        self.uc.hook_del(self.bp_hooks[ztype+1][size][addr])
                        del(self.bp_hooks[ztype+1][size][addr])
                    self.send('OK')
                except:
                    self.send('E22')

            def handle_exclaim(subcmd):
                self.send('OK')

            commands = {
                '!': handle_exclaim,
                '?': handle_qmark,
                'c': handle_c,
                'D': handle_D,
                'g': handle_g,
                'H': handle_H,
                'm': handle_m,
                'M': handle_M,
                'p': handle_p,
                'P': handle_P,
                'q': handle_q,
                'Q': handle_Q,
                's': handle_s,
                'v': handle_v,
                'X': handle_X,
                'Z': handle_Z,
                'z': handle_z
            }
            cmd, subcmd = pkt[0], pkt[1:]
            if cmd == 'k':
                break
            if cmd not in commands:
                self.send('')
                print("udb> Command not supported: %s\n" %(cmd))
                continue
            commands[cmd](subcmd)

    def receive(self):
        '''Receive a packet from a GDB client'''
        csum = 0
        state = 'Finding SOP'
        packet = ''
        try:
            while True:
                c = self.netin.read(1)
                if len(c) != 1:
                    return 'Error: EOF'
                if state == 'Finding SOP':
                    if c == '$':
                        state = 'Finding EOP'
                elif state == 'Finding EOP':
                    if c == '#':
                        if csum != int(self.netin.read(2), 16):
                            raise Exception('invalid checksum')
                        self.last_pkt = packet
                        return 'Good'
                    else:
                        packet += c
                        csum = (csum + ord(c)) & 0xff
                else:
                    raise Exception('should not be here')
        except:
            self.close()
            raise

    def checksum(self, data):
        if isinstance(data, str):
            data = data.encode('latin-1')
        return sum(data) & 0xff

    def send(self, msg):
        """Send a packet to the GDB client"""
        if type(msg) == str:
            self.send_raw('$%s#%.2x' % (msg, self.checksum(msg)))
        else:
            self.clientsocket.send(b'$%s#%.2x' % (msg, self.checksum(msg)))
            self.netout.flush()

    def send_raw(self, r):
        self.netout.write(r)
        self.netout.flush()

def udbserver(ql):
    u = UnicornGdbserver(ql.uc)
    u.setup_server()
    u.main_loop()

