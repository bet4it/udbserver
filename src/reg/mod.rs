use core::convert::TryInto;
use unicorn_engine::unicorn_const::{Arch, Mode};

mod arm;
mod arm64;
mod m68k;
mod mips;
mod ppc;
mod riscv32;
mod riscv64;
mod x64;
mod x86;

enum Endian {
    Big,
    Little,
}

pub struct RegMap {
    regs: &'static [(Option<i32>, usize)],
    len: usize,
    desc: &'static str,
}

pub struct Register {
    map: &'static RegMap,
    endian: Endian,
}

impl Register {
    pub fn new(arch: Arch, mode: Mode) -> Self {
        let map = match arch {
            Arch::ARM => &arm::REGMAP,
            Arch::ARM64 => &arm64::REGMAP,
            Arch::M68K => &m68k::REGMAP,
            Arch::MIPS => &mips::REGMAP,
            Arch::PPC => &ppc::REGMAP,
            Arch::RISCV => {
                if mode.contains(Mode::RISCV32) {
                    &riscv32::REGMAP
                } else {
                    &riscv64::REGMAP
                }
            }
            Arch::X86 => {
                if mode.contains(Mode::MODE_32) {
                    &x86::REGMAP
                } else {
                    &x64::REGMAP
                }
            }
            _ => panic!("Unknown arch"),
        };
        let endian = {
            if mode.contains(Mode::BIG_ENDIAN) {
                Endian::Big
            } else {
                Endian::Little
            }
        };
        Register { map, endian }
    }

    pub fn list(&self) -> impl Iterator<Item = (Option<i32>, usize)> + '_ {
        self.map.regs.iter().take(self.map.len).copied()
    }

    pub fn get(&self, id: usize) -> Result<(Option<i32>, usize), ()> {
        match self.map.regs.get(id) {
            Some(reg) => Ok(*reg),
            None => Err(()),
        }
    }

    pub fn read_u64(&self, bytes: &[u8]) -> u64 {
        match self.endian {
            Endian::Little => match bytes.len() {
                2 => u16::from_le_bytes(bytes.try_into().unwrap()) as u64,
                4 => u32::from_le_bytes(bytes.try_into().unwrap()) as u64,
                8 => u64::from_le_bytes(bytes.try_into().unwrap()),
                _ => panic!("Unknown length"),
            },
            Endian::Big => match bytes.len() {
                2 => u16::from_be_bytes(bytes.try_into().unwrap()) as u64,
                4 => u32::from_be_bytes(bytes.try_into().unwrap()) as u64,
                8 => u64::from_be_bytes(bytes.try_into().unwrap()),
                _ => panic!("Unknown length"),
            },
        }
    }

    pub fn write_u64(&self, val: u64, len: usize) -> Vec<u8> {
        match self.endian {
            Endian::Little => val.to_le_bytes()[..len].to_vec(),
            Endian::Big => val.to_be_bytes()[8 - len..].to_vec(),
        }
    }

    pub fn description_xml(&self) -> &'static str {
        self.map.desc
    }
}
