use crate::reg::RegMap;
use phf::phf_ordered_map;
use unicorn::RegisterX86;

pub static REGMAP: RegMap = RegMap {
    regs: phf_ordered_map! {
        0u64 => (Some(RegisterX86::RAX as i32), 8),
        1u64 => (Some(RegisterX86::RBX as i32), 8),
        2u64 => (Some(RegisterX86::RCX as i32), 8),
        3u64 => (Some(RegisterX86::RDX as i32), 8),
        4u64 => (Some(RegisterX86::RSI as i32), 8),
        5u64 => (Some(RegisterX86::RDI as i32), 8),
        6u64 => (Some(RegisterX86::RBP as i32), 8),
        7u64 => (Some(RegisterX86::RSP as i32), 8),
        8u64 => (Some(RegisterX86::R8 as i32), 8),
        9u64 => (Some(RegisterX86::R9 as i32), 8),
        10u64 => (Some(RegisterX86::R10 as i32), 8),
        11u64 => (Some(RegisterX86::R11 as i32), 8),
        12u64 => (Some(RegisterX86::R12 as i32), 8),
        13u64 => (Some(RegisterX86::R13 as i32), 8),
        14u64 => (Some(RegisterX86::R14 as i32), 8),
        15u64 => (Some(RegisterX86::R15 as i32), 8),
        16u64 => (Some(RegisterX86::RIP as i32), 8),
        17u64 => (Some(RegisterX86::EFLAGS as i32), 4),
        18u64 => (Some(RegisterX86::CS as i32), 4),
        19u64 => (Some(RegisterX86::SS as i32), 4),
        20u64 => (Some(RegisterX86::DS as i32), 4),
        21u64 => (Some(RegisterX86::ES as i32), 4),
        22u64 => (Some(RegisterX86::FS as i32), 4),
        23u64 => (Some(RegisterX86::GS as i32), 4),
    },
    len: 24,
    desc: r#"<target version="1.0"><architecture>i386:x86-64</architecture></target>"#,
};
