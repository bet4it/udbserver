use crate::reg::RegMap;
use unicorn_engine::RegisterPPC;

pub static REGMAP: RegMap = RegMap {
    regs: &[
        (Some(RegisterPPC::R0 as i32), 4),
        (Some(RegisterPPC::R1 as i32), 4),
        (Some(RegisterPPC::R2 as i32), 4),
        (Some(RegisterPPC::R3 as i32), 4),
        (Some(RegisterPPC::R4 as i32), 4),
        (Some(RegisterPPC::R5 as i32), 4),
        (Some(RegisterPPC::R6 as i32), 4),
        (Some(RegisterPPC::R7 as i32), 4),
        (Some(RegisterPPC::R8 as i32), 4),
        (Some(RegisterPPC::R9 as i32), 4),
        (Some(RegisterPPC::R10 as i32), 4),
        (Some(RegisterPPC::R11 as i32), 4),
        (Some(RegisterPPC::R12 as i32), 4),
        (Some(RegisterPPC::R13 as i32), 4),
        (Some(RegisterPPC::R14 as i32), 4),
        (Some(RegisterPPC::R15 as i32), 4),
        (Some(RegisterPPC::R16 as i32), 4),
        (Some(RegisterPPC::R17 as i32), 4),
        (Some(RegisterPPC::R18 as i32), 4),
        (Some(RegisterPPC::R19 as i32), 4),
        (Some(RegisterPPC::R20 as i32), 4),
        (Some(RegisterPPC::R21 as i32), 4),
        (Some(RegisterPPC::R22 as i32), 4),
        (Some(RegisterPPC::R23 as i32), 4),
        (Some(RegisterPPC::R24 as i32), 4),
        (Some(RegisterPPC::R25 as i32), 4),
        (Some(RegisterPPC::R26 as i32), 4),
        (Some(RegisterPPC::R27 as i32), 4),
        (Some(RegisterPPC::R28 as i32), 4),
        (Some(RegisterPPC::R29 as i32), 4),
        (Some(RegisterPPC::R30 as i32), 4),
        (Some(RegisterPPC::R31 as i32), 4),
        (Some(RegisterPPC::PC as i32), 4),
        (Some(RegisterPPC::MSR as i32), 4),
        (Some(RegisterPPC::CR as i32), 4),
        (Some(RegisterPPC::LR as i32), 4),
        (Some(RegisterPPC::CTR as i32), 4),
        (Some(RegisterPPC::XER as i32), 4),
    ],
    len: 37,
    desc: r#"
        <target version="1.0">
            <architecture>powerpc:common</architecture>
            <feature name="org.gnu.gdb.power.core">
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
                <reg name="r13" bitsize="32" type="uint32"/>
                <reg name="r14" bitsize="32" type="uint32"/>
                <reg name="r15" bitsize="32" type="uint32"/>
                <reg name="r16" bitsize="32" type="uint32"/>
                <reg name="r17" bitsize="32" type="uint32"/>
                <reg name="r18" bitsize="32" type="uint32"/>
                <reg name="r19" bitsize="32" type="uint32"/>
                <reg name="r20" bitsize="32" type="uint32"/>
                <reg name="r21" bitsize="32" type="uint32"/>
                <reg name="r22" bitsize="32" type="uint32"/>
                <reg name="r23" bitsize="32" type="uint32"/>
                <reg name="r24" bitsize="32" type="uint32"/>
                <reg name="r25" bitsize="32" type="uint32"/>
                <reg name="r26" bitsize="32" type="uint32"/>
                <reg name="r27" bitsize="32" type="uint32"/>
                <reg name="r28" bitsize="32" type="uint32"/>
                <reg name="r29" bitsize="32" type="uint32"/>
                <reg name="r30" bitsize="32" type="uint32"/>
                <reg name="r31" bitsize="32" type="uint32"/>
                <reg name="pc" bitsize="32" type="code_ptr"/>
                <reg name="msr" bitsize="32" type="uint32"/>
                <reg name="cr" bitsize="32" type="uint32"/>
                <reg name="lr" bitsize="32" type="code_ptr"/>
                <reg name="ctr" bitsize="32" type="uint32"/>
                <reg name="xer" bitsize="32" type="uint32"/>
            </feature>
        </target>
    "#,
};
