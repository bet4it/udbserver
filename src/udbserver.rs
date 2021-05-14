use std::net::{TcpListener, TcpStream};

use gdbstub::{Connection, DisconnectReason, GdbStub};
use unicorn::unicorn_const::{Arch, Mode, Permission};
use unicorn::RegisterARM;

pub type DynResult<T> = Result<T, Box<dyn std::error::Error>>;

fn wait_for_tcp(port: u16) -> DynResult<TcpStream> {
    let sockaddr = format!("127.0.0.1:{}", port);
    eprintln!("Waiting for a GDB connection on {:?}...", sockaddr);

    let sock = TcpListener::bind(sockaddr)?;
    let (stream, addr) = sock.accept()?;
    eprintln!("Debugger connected from {}", addr);

    Ok(stream)
}

pub fn udbserver() -> DynResult<()> {
    let arm_code32: Vec<u8> = vec![0x17, 0x00, 0x40, 0xe2]; // sub r0, #23
    let mut unicorn = unicorn::Unicorn::new(Arch::ARM, Mode::LITTLE_ENDIAN, 0).expect("Failed to initialize Unicorn instance");
    let mut uc = unicorn.borrow();
    uc.mem_map(0x1000, 0x4000, Permission::ALL).expect("Failed to map code page");
    uc.mem_write(0x1000, &arm_code32).expect("Failed to write instructions");
    uc.reg_write(RegisterARM::PC as i32, 0x1000).expect("Failed write PC");

    let mut emu = crate::emu::Emu::new(uc)?;

    let connection: Box<dyn Connection<Error = std::io::Error>> = { Box::new(wait_for_tcp(9001)?) };

    let mut debugger = GdbStub::new(connection);

    match debugger.run(&mut emu)? {
        DisconnectReason::Disconnect => {
            println!("Disconnect!");
            return Ok(());
        }
        DisconnectReason::TargetHalted => println!("Target halted!"),
        DisconnectReason::Kill => {
            println!("GDB sent a kill command!");
            return Ok(());
        }
    }

    Ok(())
}
