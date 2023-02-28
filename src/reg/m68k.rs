use crate::reg::RegMap;
use unicorn_engine::RegisterM68K;

pub static REGMAP: RegMap = RegMap {
    regs: &[
        (Some(RegisterM68K::D0 as i32), 4),
        (Some(RegisterM68K::D1 as i32), 4),
        (Some(RegisterM68K::D2 as i32), 4),
        (Some(RegisterM68K::D3 as i32), 4),
        (Some(RegisterM68K::D4 as i32), 4),
        (Some(RegisterM68K::D5 as i32), 4),
        (Some(RegisterM68K::D6 as i32), 4),
        (Some(RegisterM68K::D7 as i32), 4),
        (Some(RegisterM68K::A0 as i32), 4),
        (Some(RegisterM68K::A1 as i32), 4),
        (Some(RegisterM68K::A2 as i32), 4),
        (Some(RegisterM68K::A3 as i32), 4),
        (Some(RegisterM68K::A4 as i32), 4),
        (Some(RegisterM68K::A5 as i32), 4),
        (Some(RegisterM68K::A6 as i32), 4),
        (Some(RegisterM68K::A7 as i32), 4),
        (Some(RegisterM68K::SR as i32), 4),
        (Some(RegisterM68K::PC as i32), 4),
    ],
    len: 18,
    desc: r#"
        <target version="1.0">
            <architecture>m68k</architecture>
            <feature name="org.gnu.gdb.m68k.core">
                <reg name="d0" bitsize="32"/>
                <reg name="d1" bitsize="32"/>
                <reg name="d2" bitsize="32"/>
                <reg name="d3" bitsize="32"/>
                <reg name="d4" bitsize="32"/>
                <reg name="d5" bitsize="32"/>
                <reg name="d6" bitsize="32"/>
                <reg name="d7" bitsize="32"/>
                <reg name="a0" bitsize="32" type="data_ptr"/>
                <reg name="a1" bitsize="32" type="data_ptr"/>
                <reg name="a2" bitsize="32" type="data_ptr"/>
                <reg name="a3" bitsize="32" type="data_ptr"/>
                <reg name="a4" bitsize="32" type="data_ptr"/>
                <reg name="a5" bitsize="32" type="data_ptr"/>
                <reg name="fp" bitsize="32" type="data_ptr"/>
                <reg name="sp" bitsize="32" type="data_ptr"/>
                <reg name="ps" bitsize="32"/>
                <reg name="pc" bitsize="32" type="code_ptr"/>
            </feature>
        </target>
    "#,
};
