use unicorn_engine::unicorn_const::{Arch, Mode, Prot};
use unicorn_engine::{RegisterARM, Unicorn};

const ARM_CODE32: &[u8] = &[
    0x0f, 0x00, 0xa0, 0xe1, 0x14, 0x00, 0x80, 0xe2, 0x00, 0x10, 0x90, 0xe5, 0x14, 0x10, 0x81, 0xe2, 0x00, 0x10, 0x80, 0xe5, 0xfb, 0xff, 0xff, 0xea,
];

#[allow(dead_code)]
struct BlaFoo {
    test: [u8; 256],
    test2: String,
}
fn main() {
    let mut uc = Unicorn::new(Arch::ARM, Mode::LITTLE_ENDIAN).expect("Failed to initialize Unicorn instance");
    uc.mem_map(0x1000, 0x400, Prot::ALL).expect("Failed to map code page");
    uc.mem_write(0x1000, &ARM_CODE32).expect("Failed to write instructions");
    uc.reg_write(RegisterARM::PC as i32, 0x1000).expect("Failed write PC");

    udbserver::udbserver(&mut uc, 1234, 0x1000).expect("Failed to start udbserver");

    uc.emu_start(0x1000, 0x2000, 0, 1000).expect("Failed to start emu");
}

#[test]
fn main_user_data() {
    let data = BlaFoo {
        test: [0; 256],
        test2: String::from("ffffffffffffff"),
    };
    let mut uc = Unicorn::new_with_data(Arch::ARM, Mode::LITTLE_ENDIAN, data).expect("Failed to initialize Unicorn instance");
    uc.mem_map(0x1000, 0x400, Prot::ALL).expect("Failed to map code page");
    uc.mem_write(0x1000, &ARM_CODE32).expect("Failed to write instructions");
    uc.reg_write(RegisterARM::PC as i32, 0x1000).expect("Failed write PC");

    udbserver::udbserver(&mut uc, 1234, 0x1000).expect("Failed to start udbserver");

    uc.emu_start(0x1000, 0x2000, 0, 1000).expect("Failed to start emu");
}
