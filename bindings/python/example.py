from unicorn import *
from unicorn.arm_const import *
from udbserver import udbserver_hook

ADDRESS = 0x1000
ARM_CODE = b"\x0f\x00\xa0\xe1\x14\x00\x80\xe2\x00\x10\x90\xe5\x14\x10\x81\xe2\x00\x10\x80\xe5\xfb\xff\xff\xea"

mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
mu.mem_map(ADDRESS, 0x400)
mu.mem_write(ADDRESS, ARM_CODE)
mu.reg_write(UC_ARM_REG_PC, ADDRESS)

mu.hook_add(UC_HOOK_CODE, lambda *x:{})
mu.hook_add(UC_HOOK_MEM_READ, lambda *x:{})
mu.hook_add(UC_HOOK_CODE, udbserver_hook, begin=0x1000, end=0x1000)

mu.emu_start(0x1000, 0x2000, count=1000)
