use core::num::NonZeroUsize;
use gdbstub::arch::{Arch, RegId, Registers};

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct GenericRegId(pub u64);

impl RegId for GenericRegId {
    fn from_raw_id(id: usize) -> Option<(Self, Option<NonZeroUsize>)> {
        Some((GenericRegId(id as u64), None))
    }
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct GenericRegs {
    pub buf: Vec<u8>,
}

impl Registers for GenericRegs {
    type ProgramCounter = u64;

    fn pc(&self) -> Self::ProgramCounter {
        0
    }

    fn gdb_serialize(&self, mut write_byte: impl FnMut(Option<u8>)) {
        for byte in self.buf.iter() {
            write_byte(Some(*byte))
        }
    }

    fn gdb_deserialize(&mut self, bytes: &[u8]) -> Result<(), ()> {
        self.buf = bytes.to_vec();
        Ok(())
    }
}

pub struct GenericArch {}

impl Arch for GenericArch {
    type Usize = u64;
    type Registers = GenericRegs;
    type RegId = GenericRegId;
    type BreakpointKind = usize;
}
