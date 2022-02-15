use crate::reg::RegMap;
use unicorn_engine::RegisterX86;

pub static REGMAP: RegMap = RegMap {
    regs: &[
        (Some(RegisterX86::RAX as i32), 8),
        (Some(RegisterX86::RBX as i32), 8),
        (Some(RegisterX86::RCX as i32), 8),
        (Some(RegisterX86::RDX as i32), 8),
        (Some(RegisterX86::RSI as i32), 8),
        (Some(RegisterX86::RDI as i32), 8),
        (Some(RegisterX86::RBP as i32), 8),
        (Some(RegisterX86::RSP as i32), 8),
        (Some(RegisterX86::R8 as i32), 8),
        (Some(RegisterX86::R9 as i32), 8),
        (Some(RegisterX86::R10 as i32), 8),
        (Some(RegisterX86::R11 as i32), 8),
        (Some(RegisterX86::R12 as i32), 8),
        (Some(RegisterX86::R13 as i32), 8),
        (Some(RegisterX86::R14 as i32), 8),
        (Some(RegisterX86::R15 as i32), 8),
        (Some(RegisterX86::RIP as i32), 8),
        (Some(RegisterX86::EFLAGS as i32), 4),
        (Some(RegisterX86::CS as i32), 4),
        (Some(RegisterX86::SS as i32), 4),
        (Some(RegisterX86::DS as i32), 4),
        (Some(RegisterX86::ES as i32), 4),
        (Some(RegisterX86::FS as i32), 4),
        (Some(RegisterX86::GS as i32), 4),
        (Some(RegisterX86::ST0 as i32), 10),
        (Some(RegisterX86::ST1 as i32), 10),
        (Some(RegisterX86::ST2 as i32), 10),
        (Some(RegisterX86::ST3 as i32), 10),
        (Some(RegisterX86::ST4 as i32), 10),
        (Some(RegisterX86::ST5 as i32), 10),
        (Some(RegisterX86::ST6 as i32), 10),
        (Some(RegisterX86::ST7 as i32), 10),
        (None, 4), // fctrl
        (None, 4), // fstat
        (None, 4), // ftag
        (None, 4), // fiseg
        (None, 4), // fioff
        (None, 4), // foseg
        (None, 4), // fooff
        (None, 4), // fop
        (Some(RegisterX86::XMM0 as i32), 16),
        (Some(RegisterX86::XMM1 as i32), 16),
        (Some(RegisterX86::XMM2 as i32), 16),
        (Some(RegisterX86::XMM3 as i32), 16),
        (Some(RegisterX86::XMM4 as i32), 16),
        (Some(RegisterX86::XMM5 as i32), 16),
        (Some(RegisterX86::XMM6 as i32), 16),
        (Some(RegisterX86::XMM7 as i32), 16),
        (Some(RegisterX86::XMM8 as i32), 16),
        (Some(RegisterX86::XMM9 as i32), 16),
        (Some(RegisterX86::XMM10 as i32), 16),
        (Some(RegisterX86::XMM11 as i32), 16),
        (Some(RegisterX86::XMM12 as i32), 16),
        (Some(RegisterX86::XMM13 as i32), 16),
        (Some(RegisterX86::XMM14 as i32), 16),
        (Some(RegisterX86::XMM15 as i32), 16),
        (Some(RegisterX86::MXCSR as i32), 4),
    ],
    len: 24,
    desc: r#"<target version="1.0"><architecture>i386:x86-64</architecture></target>"#,
};
