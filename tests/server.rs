use unicorn::Unicorn;
use unicorn::unicorn_const::{Arch, Mode, Permission};
use unicorn::RegisterARM;

#[test]
fn run_server() {
    let arm_code32: Vec<u8> = vec![0x17, 0x00, 0x40, 0xe2]; // sub r0, #23
    let mut unicorn = Unicorn::new(Arch::ARM, Mode::LITTLE_ENDIAN).expect("Failed to initialize Unicorn instance");
    let mut uc = unicorn.borrow();
    uc.mem_map(0x1000, 0x4000, Permission::ALL).expect("Failed to map code page");
    uc.mem_write(0x1000, &arm_code32).expect("Failed to write instructions");
    uc.reg_write(RegisterARM::PC as i32, 0x1000).expect("Failed write PC");
    uc.add_code_hook(0x1000, 0x1000, udbserver::udbserver_hook).expect("Failed to add hook");
    uc.emu_start(0x1000, 0x2000, 0, 1000).expect("Failed to start emu");
}
