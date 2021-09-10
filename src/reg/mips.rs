use crate::reg::RegMap;
use phf::phf_ordered_map;
use unicorn::RegisterMIPS;

pub static REGMAP: RegMap = RegMap {
    regs: phf_ordered_map! {
        0u64 => (Some(RegisterMIPS::ZERO as i32), 4),
        1u64 => (Some(RegisterMIPS::AT as i32), 4),
        2u64 => (Some(RegisterMIPS::V0 as i32), 4),
        3u64 => (Some(RegisterMIPS::V1 as i32), 4),
        4u64 => (Some(RegisterMIPS::A0 as i32), 4),
        5u64 => (Some(RegisterMIPS::A1 as i32), 4),
        6u64 => (Some(RegisterMIPS::A2 as i32), 4),
        7u64 => (Some(RegisterMIPS::A3 as i32), 4),
        8u64 => (Some(RegisterMIPS::T0 as i32), 4),
        9u64 => (Some(RegisterMIPS::T1 as i32), 4),
        10u64 => (Some(RegisterMIPS::T2 as i32), 4),
        11u64 => (Some(RegisterMIPS::T3 as i32), 4),
        12u64 => (Some(RegisterMIPS::T4 as i32), 4),
        13u64 => (Some(RegisterMIPS::T5 as i32), 4),
        14u64 => (Some(RegisterMIPS::T6 as i32), 4),
        15u64 => (Some(RegisterMIPS::T7 as i32), 4),
        16u64 => (Some(RegisterMIPS::S0 as i32), 4),
        17u64 => (Some(RegisterMIPS::S1 as i32), 4),
        18u64 => (Some(RegisterMIPS::S2 as i32), 4),
        19u64 => (Some(RegisterMIPS::S3 as i32), 4),
        20u64 => (Some(RegisterMIPS::S4 as i32), 4),
        21u64 => (Some(RegisterMIPS::S5 as i32), 4),
        22u64 => (Some(RegisterMIPS::S6 as i32), 4),
        23u64 => (Some(RegisterMIPS::S7 as i32), 4),
        24u64 => (Some(RegisterMIPS::T8 as i32), 4),
        25u64 => (Some(RegisterMIPS::T9 as i32), 4),
        26u64 => (Some(RegisterMIPS::K0 as i32), 4),
        27u64 => (Some(RegisterMIPS::K1 as i32), 4),
        28u64 => (Some(RegisterMIPS::GP as i32), 4),
        29u64 => (Some(RegisterMIPS::SP as i32), 4),
        30u64 => (Some(RegisterMIPS::S8 as i32), 4),
        31u64 => (Some(RegisterMIPS::RA as i32), 4),
        32u64 => (None, 4), // SR
        33u64 => (Some(RegisterMIPS::LO as i32), 4),
        34u64 => (Some(RegisterMIPS::HI as i32), 4),
        35u64 => (None, 4), // BAD
        36u64 => (None, 4), // CAUSE
        37u64 => (Some(RegisterMIPS::PC as i32), 4),
        70u64 => (None, 4), // FSR
        71u64 => (None, 4), // FIR
    },
    len: 32,
    desc: r#"<target version="1.0"><architecture>mips</architecture></target>"#,
};
