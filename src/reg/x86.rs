use crate::reg::RegMap;
use phf::phf_ordered_map;
use unicorn::RegisterX86;

pub static REGMAP: RegMap = RegMap {
    regs: phf_ordered_map! {
        0u64 => (Some(RegisterX86::EAX as i32), 4),
        1u64 => (Some(RegisterX86::ECX as i32), 4),
        2u64 => (Some(RegisterX86::EDX as i32), 4),
        3u64 => (Some(RegisterX86::EBX as i32), 4),
        4u64 => (Some(RegisterX86::ESP as i32), 4),
        5u64 => (Some(RegisterX86::EBP as i32), 4),
        6u64 => (Some(RegisterX86::ESI as i32), 4),
        7u64 => (Some(RegisterX86::EDI as i32), 4),
        8u64 => (Some(RegisterX86::EIP as i32), 4),
        9u64 => (Some(RegisterX86::EFLAGS as i32), 4),
        10u64 => (Some(RegisterX86::CS as i32), 4),
        11u64 => (Some(RegisterX86::SS as i32), 4),
        12u64 => (Some(RegisterX86::DS as i32), 4),
        13u64 => (Some(RegisterX86::ES as i32), 4),
        14u64 => (Some(RegisterX86::FS as i32), 4),
        15u64 => (Some(RegisterX86::GS as i32), 4),
    },
    len: 16,
    desc: r#"<target version="1.0"><architecture>i386</architecture></target>"#,
};
