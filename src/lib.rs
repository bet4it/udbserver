mod udbserver;
mod emu;

#[no_mangle]
pub extern "C" fn udbserver() -> i32 {
    match udbserver::udbserver() {
        Ok(_) => 0,
        Err(_) => -1
    }
}

