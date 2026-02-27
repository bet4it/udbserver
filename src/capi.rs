#![allow(non_camel_case_types)]

use singlyton::SingletonOption;
use std::borrow::BorrowMut;
use std::ffi::c_void;
use std::panic::AssertUnwindSafe;
use unicorn_engine::{uc_engine, Unicorn};

type uc_handle = *mut c_void;

static UNICORN: SingletonOption<Unicorn<()>> = SingletonOption::new();

fn start_udbserver(handle: uc_handle, port: u16, start_addr: u64) -> Result<(), String> {
    if UNICORN.is_some() {
        return Ok(());
    }
    let unicorn = unsafe { Unicorn::from_handle(handle as *mut uc_engine) }.map_err(|error| format!("Failed to convert handle to Unicorn: {error}"))?;
    UNICORN.replace(unicorn);
    crate::udbserver(UNICORN.get_mut().borrow_mut(), port, start_addr).map_err(|error| format!("Failed to start udbserver: {error}"))
}

#[no_mangle]
pub extern "C" fn udbserver(handle: uc_handle, port: u16, start_addr: u64) -> i32 {
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| start_udbserver(handle, port, start_addr)));
    match result {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => {
            eprintln!("{error}");
            clean();
            -1
        }
        Err(_) => {
            eprintln!("udbserver panicked");
            clean();
            -2
        }
    }
}

pub fn clean() {
    UNICORN.take();
}
