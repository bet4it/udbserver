use crate::DynResult;

use crate::uc_hook;
use gdbstub::target;
use gdbstub::target::ext::base::singlethread::GdbInterrupt;
use gdbstub::target::ext::base::singlethread::{ResumeAction, SingleThreadOps, StopReason};
use gdbstub::target::{Target, TargetError, TargetResult};
use std::ptr::null_mut;
use unicorn::unicorn_const::uc_error;
use unicorn::RegisterARM;
use unicorn::UnicornHandle;

pub static REG_MAP_ARM: [RegisterARM; 13] = [
    RegisterARM::R0,
    RegisterARM::R1,
    RegisterARM::R2,
    RegisterARM::R3,
    RegisterARM::R4,
    RegisterARM::R5,
    RegisterARM::R6,
    RegisterARM::R7,
    RegisterARM::R8,
    RegisterARM::R9,
    RegisterARM::R10,
    RegisterARM::R11,
    RegisterARM::R12,
];

pub struct Global {
    step_state: bool,
    step_hook: uc_hook,
}

static mut G: Global = Global {
    step_state: false,
    step_hook: null_mut(),
};

pub fn step_hook(mut uc: UnicornHandle, _address: u64, _size: u32) {
    unsafe {
        if G.step_state {
            G.step_state = false;
            return;
        }
        if G.step_hook != null_mut() {
            uc.remove_hook(G.step_hook).expect("Failed to remove hook");
            G.step_hook = null_mut();
        }
    }
    crate::udbserver(uc).expect("Failed to start udbserver");
}

pub struct Emu<'a> {
    uc: UnicornHandle<'a>,
}

impl Emu<'_> {
    pub fn new(uc: UnicornHandle) -> DynResult<Emu> {
        Ok(Emu { uc: uc })
    }
}

impl Target for Emu<'_> {
    type Arch = gdbstub_arch::arm::Armv4t;
    type Error = &'static str;

    #[inline(always)]
    fn base_ops(&mut self) -> target::ext::base::BaseOps<Self::Arch, Self::Error> {
        target::ext::base::BaseOps::SingleThread(self)
    }
}

impl SingleThreadOps for Emu<'_> {
    fn resume(&mut self, action: ResumeAction, _gdb_interrupt: GdbInterrupt<'_>) -> Result<StopReason<u32>, Self::Error> {
        match action {
            ResumeAction::Step => {
                unsafe {
                    G.step_state = true;
                    G.step_hook = self.uc.add_code_hook(1, 0, step_hook).expect("failed to add code hook");
                }
                Err("udbserver")
            }
            _ => Err("cannot resume with signal"),
        }
    }

    fn read_registers(&mut self, regs: &mut gdbstub_arch::arm::reg::ArmCoreRegs) -> TargetResult<(), Self> {
        for (idx, reg) in REG_MAP_ARM.iter().enumerate() {
            regs.r[idx] = self.uc.reg_read(*reg as i32).expect("Failed to read register") as u32;
        }
        regs.sp = self.uc.reg_read(RegisterARM::SP as i32).expect("Failed to read register") as u32;
        regs.lr = self.uc.reg_read(RegisterARM::LR as i32).expect("Failed to read register") as u32;
        regs.pc = self.uc.reg_read(RegisterARM::PC as i32).expect("Failed to read register") as u32;
        Ok(())
    }

    fn write_registers(&mut self, regs: &gdbstub_arch::arm::reg::ArmCoreRegs) -> TargetResult<(), Self> {
        for (idx, reg) in REG_MAP_ARM.iter().enumerate() {
            self.uc.reg_write(*reg as i32, regs.r[idx] as u64).expect("Failed to write register");
        }
        self.uc.reg_write(RegisterARM::SP as i32, regs.sp as u64).expect("Failed to write register");
        self.uc.reg_write(RegisterARM::LR as i32, regs.lr as u64).expect("Failed to write register");
        self.uc.reg_write(RegisterARM::PC as i32, regs.pc as u64).expect("Failed to write register");
        Ok(())
    }

    fn read_addrs(&mut self, start_addr: u32, data: &mut [u8]) -> TargetResult<(), Self> {
        match self.uc.mem_read(start_addr as u64, data) {
            Ok(_) => Ok(()),
            Err(uc_error::READ_UNMAPPED) => Err(TargetError::Errno(1)),
            Err(_) => Err(TargetError::Fatal("Failed to read addr")),
        }
    }

    fn write_addrs(&mut self, start_addr: u32, data: &[u8]) -> TargetResult<(), Self> {
        match self.uc.mem_write(start_addr as u64, data) {
            Ok(_) => Ok(()),
            Err(uc_error::WRITE_UNMAPPED) => Err(TargetError::Errno(1)),
            Err(_) => Err(TargetError::Fatal("Failed to write addr")),
        }
    }
}
