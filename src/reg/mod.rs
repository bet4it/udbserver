use core::convert::TryInto;
use unicorn_engine::unicorn_const::{Arch, Mode};

mod arm;
mod arm64;
mod mips;
mod x64;
mod x86;

pub struct RegMap {
    regs: &'static [(Option<i32>, usize)],
    len: usize,
    desc: &'static str,
}

impl RegMap {
    pub fn new(arch: Arch, mode: Mode) -> &'static Self {
        match arch {
            Arch::ARM => &arm::REGMAP,
            Arch::ARM64 => &arm64::REGMAP,
            Arch::MIPS => &mips::REGMAP,
            Arch::X86 => {
                if mode.contains(Mode::MODE_32) {
                    &x86::REGMAP
                } else {
                    &x64::REGMAP
                }
            }
            _ => panic!("Unknown arch"),
        }
    }

    pub fn reg_list(&self) -> impl Iterator<Item = (Option<i32>, usize)> + '_ {
        self.regs.iter().take(self.len).copied()
    }

    pub fn get_reg(&self, id: usize) -> Result<(Option<i32>, usize), ()> {
        match self.regs.get(id) {
            Some(reg) => Ok(*reg),
            None => Err(()),
        }
    }

    pub fn from_bytes(&self, bytes: &[u8]) -> u64 {
        match bytes.len() {
            2 => u16::from_le_bytes(bytes.try_into().unwrap()) as u64,
            4 => u32::from_le_bytes(bytes.try_into().unwrap()) as u64,
            8 => u64::from_le_bytes(bytes.try_into().unwrap()),
            _ => panic!("Unknown length"),
        }
    }

    pub fn to_bytes(&self, val: u64, len: usize) -> Vec<u8> {
        val.to_le_bytes()[..len].to_vec()
    }

    pub fn description_xml(&self) -> &'static str {
        self.desc
    }
}
