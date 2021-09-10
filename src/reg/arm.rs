use crate::reg::RegMap;
use phf::phf_ordered_map;
use unicorn::RegisterARM;

pub static REGMAP: RegMap = RegMap {
    regs: phf_ordered_map! {
        0u64 => (Some(RegisterARM::R0 as i32), 4),
        1u64 => (Some(RegisterARM::R1 as i32), 4),
        2u64 => (Some(RegisterARM::R2 as i32), 4),
        3u64 => (Some(RegisterARM::R3 as i32), 4),
        4u64 => (Some(RegisterARM::R4 as i32), 4),
        5u64 => (Some(RegisterARM::R5 as i32), 4),
        6u64 => (Some(RegisterARM::R6 as i32), 4),
        7u64 => (Some(RegisterARM::R7 as i32), 4),
        8u64 => (Some(RegisterARM::R8 as i32), 4),
        9u64 => (Some(RegisterARM::R9 as i32), 4),
        10u64 => (Some(RegisterARM::R10 as i32), 4),
        11u64 => (Some(RegisterARM::R11 as i32), 4),
        12u64 => (Some(RegisterARM::R12 as i32), 4),
        13u64 => (Some(RegisterARM::SP as i32), 4),
        14u64 => (Some(RegisterARM::LR as i32), 4),
        15u64 => (Some(RegisterARM::PC as i32), 4),
        25u64 => (Some(RegisterARM::CPSR as i32), 4),
    },
    len: 16,
    desc: r#"<target version="1.0"><architecture>arm</architecture></target>"#,
};
