mod capi;
mod emu;

use capi::uc_hook;
use gdbstub::{DisconnectReason, GdbStub, GdbStubError};
use once_cell::sync::OnceCell;
use std::net::{TcpListener, TcpStream};
use unicorn::UnicornHandle;

pub type DynResult<T> = Result<T, Box<dyn std::error::Error>>;

fn wait_for_tcp(port: u16) -> DynResult<TcpStream> {
    let sockaddr = format!("127.0.0.1:{}", port);
    eprintln!("Waiting for a GDB connection on {:?}...", sockaddr);

    let sock = TcpListener::bind(sockaddr)?;
    let (stream, addr) = sock.accept()?;
    eprintln!("Debugger connected from {}", addr);

    Ok(stream)
}

pub fn udbserver(uc: UnicornHandle) -> DynResult<()> {
    let mut emu = crate::emu::Emu::new(uc)?;
    static CONNECTION: OnceCell<TcpStream> = OnceCell::new();
    let conn = CONNECTION.get_or_init(|| match wait_for_tcp(9001) {
        Ok(n) => n,
        Err(_) => panic!("tcp listen failed"),
    });

    let mut debugger = GdbStub::new(conn.try_clone().expect("try_clone failed"));

    match debugger.run(&mut emu) {
        Ok(DisconnectReason::Disconnect) => {
            println!("Disconnect!");
            return Ok(());
        }
        Ok(DisconnectReason::TargetExited(code)) => println!("Target exited with code {}!", code),
        Ok(DisconnectReason::TargetTerminated(sig)) => {
            println!("Target terminated with signal {}!", sig)
        }
        Ok(DisconnectReason::Kill) => {
            println!("GDB sent a kill command!");
            return Ok(());
        }
        Err(GdbStubError::TargetError("udbserver")) => {
            return Ok(());
        }
        Err(_) => {
            return Ok(());
        }
    }

    Ok(())
}

pub fn udbserver_hook(uc: UnicornHandle<'_>, _address: u64, _size: u32) {
    udbserver(uc).expect("Failed to run udbserver");
}
