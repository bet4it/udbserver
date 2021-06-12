#![allow(non_camel_case_types)]

use std::ffi::c_void;
use unicorn::Unicorn;

pub type uc_handle = *mut c_void;
pub type uc_hook = *mut c_void;

#[no_mangle]
pub extern "C" fn udbserver(handle: uc_handle) {
    static mut INIT: bool = false;
    unsafe {
        if INIT == false {
            INIT = true;
            let uc = Box::leak(Box::new(Unicorn::from(handle))).borrow();
            crate::udbserver(uc).expect("Failed to start udbserver");
        }
    }
}

#[no_mangle]
pub extern "C" fn udbserver_hook(handle: uc_handle, _address: u64, _size: u32) {
    udbserver(handle);
}
