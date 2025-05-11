#![allow(non_camel_case_types)]

use singlyton::SingletonOption;
use std::borrow::BorrowMut;
use unicorn_engine::{uc_engine, Unicorn};

static UNICORN: SingletonOption<Unicorn<()>> = SingletonOption::new();

#[no_mangle]
pub extern "C" fn udbserver(handle: *mut uc_engine, port: u16, start_addr: u64) {
    if UNICORN.is_some() {
        return;
    }
    if let Ok(unicorn) = unsafe { Unicorn::from_handle(handle) } {
        UNICORN.replace(unicorn);
    } else {
        panic!("Failed to convert handle to Unicorn");
    }
    crate::udbserver(UNICORN.get_mut().borrow_mut(), port, start_addr).expect("Failed to start udbserver");
}

pub fn clean() {
    UNICORN.take();
}
