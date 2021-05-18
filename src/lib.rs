#![allow(non_camel_case_types)]

mod udbserver;
mod emu;

use unicorn::Unicorn;
use std::ffi::c_void;
pub type uc_handle = *mut c_void;

#[no_mangle]
pub extern "C" fn udbserver(handle : uc_handle) -> i32 {
    let unicorn = Unicorn::from(handle);
    match udbserver::udbserver(unicorn) {
        Ok(_) => 0,
        Err(_) => -1
    }
}

