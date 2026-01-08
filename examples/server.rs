use unicorn_engine::unicorn_const::{Arch, Mode, Prot};
use unicorn_engine::{RegisterARM, Unicorn};

struct CustomData {
    pub _val: u32,
}

fn main() {
    let arm_code32: Vec<u8> = vec![
        0x0f, 0x00, 0xa0, 0xe1, 0x14, 0x00, 0x80, 0xe2, 0x00, 0x10, 0x90, 0xe5, 0x14, 0x10, 0x81, 0xe2, 0x00, 0x10, 0x80, 0xe5, 0xfb, 0xff, 0xff, 0xea,
    ];
    let mut uc = Unicorn::new(Arch::ARM, Mode::LITTLE_ENDIAN).expect("Failed to initialize Unicorn instance");
    uc.mem_map(0x1000, 0x400, Prot::ALL).expect("Failed to map code page");
    uc.mem_write(0x1000, &arm_code32).expect("Failed to write instructions");
    uc.reg_write(RegisterARM::PC as i32, 0x1000).expect("Failed write PC");

    udbserver::udbserver(&mut uc, 1234, 0x1000).expect("Failed to start udbserver");

    uc.emu_start(0x1000, 0x2000, 0, 1000).expect("Failed to start emu");
}
