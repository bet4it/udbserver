use crate::DynResult;

use gdbstub::target;
use gdbstub::target::ext::base::singlethread::GdbInterrupt;
use gdbstub::target::ext::base::singlethread::{ResumeAction, SingleThreadOps, StopReason};
use gdbstub::target::{Target, TargetError, TargetResult};
use unicorn::unicorn_const::{uc_error, SECOND_SCALE};
use unicorn::RegisterARM;

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

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Event {
    Break,
}

impl Target for Emu<'_> {
    type Arch = gdbstub_arch::arm::Armv4t;
    type Error = &'static str;

    #[inline(always)]
    fn base_ops(&mut self) -> target::ext::base::BaseOps<Self::Arch, Self::Error> {
        target::ext::base::BaseOps::SingleThread(self)
    }
}

pub struct Emu<'a> {
    uc: unicorn::UnicornHandle<'a>,
}

impl Emu<'_> {
    pub fn new(uc: unicorn::UnicornHandle) -> DynResult<Emu> {
        Ok(Emu { uc: uc })
    }

    pub fn step(&mut self) -> Option<Event> {
        let pc = self.uc.reg_read(RegisterARM::PC as i32).expect("Failed to read PC when step");
        self.uc.emu_start(pc, 0x2000, 10 * SECOND_SCALE, 1).expect("Failed in emu_start");
        return Some(Event::Break);
    }
}

impl SingleThreadOps for Emu<'_> {
    fn resume(&mut self, action: ResumeAction, _gdb_interrupt: GdbInterrupt<'_>) -> Result<StopReason<u32>, Self::Error> {
        match action {
            ResumeAction::Step => match self.step() {
                Some(e) => e,
                None => return Ok(StopReason::DoneStep),
            },
            ResumeAction::Continue => match self.step() {
                Some(e) => e,
                None => return Ok(StopReason::DoneStep),
            },
            _ => return Err("cannot resume with signal"),
        };
        Ok(StopReason::DoneStep)
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
