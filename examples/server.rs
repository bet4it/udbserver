use unicorn::unicorn_const::{Arch, Mode, Permission};
use unicorn::unicorn_const::{HookType, MemType};
use unicorn::RegisterARM;
use unicorn::{Unicorn, UnicornHandle};

fn main() {
    let arm_code32: Vec<u8> = vec![
        0x0f, 0x00, 0xa0, 0xe1, 0x14, 0x00, 0x80, 0xe2, 0x00, 0x10, 0x90, 0xe5, 0x14, 0x10, 0x81, 0xe2, 0x00, 0x10, 0x80, 0xe5, 0xfb, 0xff, 0xff, 0xea,
    ];
    let mut unicorn = Unicorn::new(Arch::ARM, Mode::LITTLE_ENDIAN).expect("Failed to initialize Unicorn instance");
    let mut uc = unicorn.borrow();
    uc.mem_map(0x1000, 0x4000, Permission::ALL).expect("Failed to map code page");
    uc.mem_write(0x1000, &arm_code32).expect("Failed to write instructions");
    uc.reg_write(RegisterARM::PC as i32, 0x1000).expect("Failed write PC");
    uc.add_code_hook(1, 0, |_uc: UnicornHandle, _addr: u64, _size: u32| {})
        .expect("Failed to add hook");
    uc.add_mem_hook(
        HookType::MEM_READ,
        1,
        0,
        |_uc: UnicornHandle, _mem_type: MemType, _addr: u64, _size: usize, _value: i64| {},
    )
    .expect("Failed to add hook");
    uc.add_code_hook(0x1000, 0x1000, udbserver::udbserver_hook).expect("Failed to add hook");
    uc.emu_start(0x1000, 0x2000, 0, 1000).expect("Failed to start emu");
}
