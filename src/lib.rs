mod emu;
mod capi;

use std::net::{TcpListener, TcpStream};

use gdbstub::{Connection, DisconnectReason, GdbStub};

pub type DynResult<T> = Result<T, Box<dyn std::error::Error>>;

fn wait_for_tcp(port: u16) -> DynResult<TcpStream> {
    let sockaddr = format!("127.0.0.1:{}", port);
    eprintln!("Waiting for a GDB connection on {:?}...", sockaddr);

    let sock = TcpListener::bind(sockaddr)?;
    let (stream, addr) = sock.accept()?;
    eprintln!("Debugger connected from {}", addr);

    Ok(stream)
}

pub fn udbserver(mut unicorn: unicorn::Unicorn) -> DynResult<()> {
    let uc = unicorn.borrow();

    let mut emu = crate::emu::Emu::new(uc)?;

    let connection: Box<dyn Connection<Error = std::io::Error>> = { Box::new(wait_for_tcp(9001)?) };

    let mut debugger = GdbStub::new(connection);

    match debugger.run(&mut emu)? {
        DisconnectReason::Disconnect => {
            println!("Disconnect!");
            return Ok(());
        }
        DisconnectReason::TargetExited(code) => println!("Target exited with code {}!", code),
        DisconnectReason::TargetTerminated(sig) => {
            println!("Target terminated with signal {}!", sig)
        }
        DisconnectReason::Kill => {
            println!("GDB sent a kill command!");
            return Ok(());
        }
    }

    Ok(())
}
