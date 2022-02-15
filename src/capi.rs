#![allow(non_camel_case_types)]

use std::convert::TryFrom;
use std::ffi::c_void;
use std::ptr::null_mut;
use unicorn_engine::Unicorn;

pub type uc_handle = *mut c_void;
pub type uc_hook = *mut c_void;

static mut HANDLE: uc_handle = null_mut();
static mut UNICORN: Option<&mut Unicorn<()>> = None;

#[no_mangle]
pub extern "C" fn udbserver(handle: uc_handle, port: u16, start_addr: u64) {
    let uc;
    unsafe {
        if handle != HANDLE {
            if let Ok(unicorn) = Unicorn::try_from(handle) {
                UNICORN = Some(Box::leak(Box::new(unicorn)));
            } else {
                panic!("Failed convert handle to Unicorn")
            }
        }
        uc = UNICORN.as_mut().unwrap();
    }
    crate::udbserver(uc, port, start_addr).expect("Failed to start udbserver");
}
