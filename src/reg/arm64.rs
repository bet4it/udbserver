use crate::reg::RegMap;
use phf::phf_ordered_map;
use unicorn::RegisterARM64;

pub static REGMAP: RegMap = RegMap {
    regs: phf_ordered_map! {
        0u64 => (Some(RegisterARM64::X0 as i32), 8),
        1u64 => (Some(RegisterARM64::X1 as i32), 8),
        2u64 => (Some(RegisterARM64::X2 as i32), 8),
        3u64 => (Some(RegisterARM64::X3 as i32), 8),
        4u64 => (Some(RegisterARM64::X4 as i32), 8),
        5u64 => (Some(RegisterARM64::X5 as i32), 8),
        6u64 => (Some(RegisterARM64::X6 as i32), 8),
        7u64 => (Some(RegisterARM64::X7 as i32), 8),
        8u64 => (Some(RegisterARM64::X8 as i32), 8),
        9u64 => (Some(RegisterARM64::X9 as i32), 8),
        10u64 => (Some(RegisterARM64::X10 as i32), 8),
        11u64 => (Some(RegisterARM64::X11 as i32), 8),
        12u64 => (Some(RegisterARM64::X12 as i32), 8),
        13u64 => (Some(RegisterARM64::X13 as i32), 8),
        14u64 => (Some(RegisterARM64::X14 as i32), 8),
        15u64 => (Some(RegisterARM64::X15 as i32), 8),
        16u64 => (Some(RegisterARM64::X16 as i32), 8),
        17u64 => (Some(RegisterARM64::X17 as i32), 8),
        18u64 => (Some(RegisterARM64::X18 as i32), 8),
        19u64 => (Some(RegisterARM64::X19 as i32), 8),
        20u64 => (Some(RegisterARM64::X20 as i32), 8),
        21u64 => (Some(RegisterARM64::X21 as i32), 8),
        22u64 => (Some(RegisterARM64::X22 as i32), 8),
        23u64 => (Some(RegisterARM64::X23 as i32), 8),
        24u64 => (Some(RegisterARM64::X24 as i32), 8),
        25u64 => (Some(RegisterARM64::X25 as i32), 8),
        26u64 => (Some(RegisterARM64::X26 as i32), 8),
        27u64 => (Some(RegisterARM64::X27 as i32), 8),
        28u64 => (Some(RegisterARM64::X28 as i32), 8),
        29u64 => (Some(RegisterARM64::X29 as i32), 8),
        30u64 => (Some(RegisterARM64::X30 as i32), 8),
        31u64 => (Some(RegisterARM64::SP as i32), 8),
        32u64 => (Some(RegisterARM64::PC as i32), 8),
        33u64 => (None, 8), // CPSR
        66u64 => (None, 8), // FPSR
        67u64 => (None, 8), // FPCR
    },
    len: 33,
    desc: r#"<target version="1.0"><architecture>aarch64</architecture></target>"#,
};
