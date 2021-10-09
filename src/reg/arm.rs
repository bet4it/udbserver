use crate::reg::RegMap;
use unicorn::RegisterARM;

pub static REGMAP: RegMap = RegMap {
    regs: &[
        (Some(RegisterARM::R0 as i32), 4),
        (Some(RegisterARM::R1 as i32), 4),
        (Some(RegisterARM::R2 as i32), 4),
        (Some(RegisterARM::R3 as i32), 4),
        (Some(RegisterARM::R4 as i32), 4),
        (Some(RegisterARM::R5 as i32), 4),
        (Some(RegisterARM::R6 as i32), 4),
        (Some(RegisterARM::R7 as i32), 4),
        (Some(RegisterARM::R8 as i32), 4),
        (Some(RegisterARM::R9 as i32), 4),
        (Some(RegisterARM::R10 as i32), 4),
        (Some(RegisterARM::R11 as i32), 4),
        (Some(RegisterARM::R12 as i32), 4),
        (Some(RegisterARM::SP as i32), 4),
        (Some(RegisterARM::LR as i32), 4),
        (Some(RegisterARM::PC as i32), 4),
        (Some(RegisterARM::CPSR as i32), 4),
    ],
    len: 17,
    desc: r#"
        <target version="1.0">
            <architecture>arm</architecture>
            <feature name="org.gnu.gdb.arm.core">
              <reg name="r0" bitsize="32" type="uint32"/>
              <reg name="r1" bitsize="32" type="uint32"/>
              <reg name="r2" bitsize="32" type="uint32"/>
              <reg name="r3" bitsize="32" type="uint32"/>
              <reg name="r4" bitsize="32" type="uint32"/>
              <reg name="r5" bitsize="32" type="uint32"/>
              <reg name="r6" bitsize="32" type="uint32"/>
              <reg name="r7" bitsize="32" type="uint32"/>
              <reg name="r8" bitsize="32" type="uint32"/>
              <reg name="r9" bitsize="32" type="uint32"/>
              <reg name="r10" bitsize="32" type="uint32"/>
              <reg name="r11" bitsize="32" type="uint32"/>
              <reg name="r12" bitsize="32" type="uint32"/>
              <reg name="sp" bitsize="32" type="data_ptr"/>
              <reg name="lr" bitsize="32"/>
              <reg name="pc" bitsize="32" type="code_ptr"/>
              <reg name="cpsr" bitsize="32"/>
            </feature>
        </target>
    "#,
};
