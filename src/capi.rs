#![allow(non_camel_case_types)]

use singlyton::{Singleton, SingletonOption};
use std::borrow::BorrowMut;
use std::convert::TryFrom;
use std::ffi::c_void;
use std::ptr::null_mut;
use unicorn_engine::Unicorn;

type uc_handle = *mut c_void;

static HANDLE: Singleton<uc_handle> = Singleton::new(null_mut());
static UNICORN: SingletonOption<&mut Unicorn<()>> = SingletonOption::new();

#[no_mangle]
pub extern "C" fn udbserver(handle: uc_handle, port: u16, start_addr: u64) {
    if handle != *HANDLE.get() {
        if let Ok(unicorn) = Unicorn::try_from(handle) {
            HANDLE.replace(handle);
            UNICORN.replace(Box::leak(Box::new(unicorn)));
        } else {
            panic!("Failed convert handle to Unicorn")
        }
    }
    crate::udbserver(UNICORN.get_mut().borrow_mut(), port, start_addr).expect("Failed to start udbserver");
}
