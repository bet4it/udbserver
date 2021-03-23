import socket
import struct
from unicorn import *
from .reg_map import reg_map_x64

class UnicornGdbserver():
    def __init__(self, uc):
        self.uc = uc
        self.ip = '127.0.0.1'
        self.port = 9999
        self.last_pkt = None
        self.step_state = False
        self.stop_state = True
        self.step_hook = None
        self.bp_hooks = {}
        self.reg_map = reg_map_x64

    def addr_to_str(self, addr, size, endian="big"):
        if size == 8:
            addr = (hex(int.from_bytes(struct.pack("Q", addr), byteorder=endian)))
            addr = '{:0>16}'.format(addr[2:])
        elif size == 4:
            addr = (hex(int.from_bytes(struct.pack("I", addr), byteorder=endian)))
            addr = ('{:0>8}'.format(addr[2:]))
        addr = str(addr)    
        return addr

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
        self.netin.close()
        self.netout.close()
        self.clientsocket.close()
        self.sock.close()

    def hook_func(self, uc, address, size, data):
        if self.step_state:
            self.step_state = False
        else:
            if self.step_hook:
                self.uc.hook_del(self.step_hook)
                self.step_hook = None
            self.stop_state = True
            self.send("S05")
            self.main_loop()

    def main_loop(self):
        while self.stop_state and self.receive() == 'Good':
            pkt = self.last_pkt
            self.send_raw('+')

            def handle_qmark(subcmd):
                self.send("S05")

            def handle_c(subcmd):
                self.stop_state = False

            def handle_D(subcmd):
                self.stop_state = False
                self.send('OK')

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
                addr, size = subcmd.split(',')
                addr = int(addr, 16)
                size = int(size, 16)
                try:
                    tmp = ''
                    for s in range(size):
                        mem = self.uc.mem_read(addr + s, 1)
                        mem = "".join(
                            [str("{:02x}".format(ord(c))) for c in mem.decode('latin1')])
                        tmp += mem
                    self.send(tmp)
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
                    reg = self.reg_map[reg_index]
                    reg_value = self.uc.reg_read(reg[0])
                    reg_value = self.addr_to_str(reg_value, reg[1])
                    self.send(reg_value)
                except:
                    self.close()
                    raise

            def handle_P(subcmd):
                reg_index, reg_data = subcmd.split('=')
                reg_index = int(reg_index, 16)
                reg_data = int(reg_data, 16)
                reg = self.reg_map[reg_index]
                if reg[1] == 8:
                    reg_data = int.from_bytes(struct.pack('<Q', reg_data), byteorder='big')
                elif reg[1] == 4:
                    reg_data = int.from_bytes(struct.pack('<I', reg_data), byteorder='big')
                self.uc.reg_write(reg[0], reg_data)
                self.send('OK')

            def handle_q(subcmd):
                if subcmd.startswith('Supported:'):
                    self.send("PacketSize=8000;qXfer:features:read+")
                elif subcmd.startswith('Xfer:features:read'):
                    self.send("l<target version=\"1.0\"><architecture>i386:x86-64</architecture></target>")
                elif subcmd == "Attached":
                    self.send("")
                elif subcmd.startswith("C"):
                    self.send("")
                elif subcmd == "fThreadInfo":
                    self.send("m0")
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
                self.step_hook = self.uc.hook_add(UC_HOOK_CODE, self.hook_func, None)

            def handle_v(subcmd):
                if subcmd == 'MustReplyEmpty':
                    self.send("")
                else:
                    self.send("")

            def handle_X(subcmd):
                self.send('')

            def handle_Z(subcmd):
                data = subcmd
                ztype = data[data.find('Z') + 1:data.find(',')]
                if ztype == '0':
                    ztype, address, value = data.split(',')
                    address = int(address, 16)
                    try:
                        h = self.uc.hook_add(UC_HOOK_CODE, self.hook_func, None, address, address)
                        self.bp_hooks[address] = h
                        self.send('OK')
                    except:
                        self.send('E22')
                else:
                    self.send('E22')

            def handle_z(subcmd):
                data = subcmd.split(',')
                if len(data) != 3:
                    self.send('E22')
                try:
                    type = data[0]
                    addr = int(data[1], 16)
                    length = data[2]
                    if addr in self.bp_hooks:
                        self.uc.hook_del(self.bp_hooks[addr])
                        del(self.bp_hooks[addr])
                        self.send('OK')
                    else:
                        self.send('E22')
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
        checksum = 0
        for c in data:
            if type(c) == str:
                checksum += (ord(c))
            else:
                checksum += c
        return checksum & 0xff

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

