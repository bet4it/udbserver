mod capi;
mod emu;

use gdbstub::state_machine::GdbStubStateMachine;
use gdbstub::target::ext::base::singlethread::StopReason;
use gdbstub::target::ext::breakpoints::WatchKind;
use gdbstub::{ConnectionExt, DisconnectReason, GdbStub};
use std::net::{TcpListener, TcpStream};
use unicorn::unicorn_const::{HookType, MemType};
use unicorn::UnicornHandle;

pub type DynResult<T> = Result<T, Box<dyn std::error::Error>>;

static mut GDBSTUB: Option<GdbStubStateMachine<emu::Emu, TcpStream>> = None;
static mut EMU: Option<emu::Emu> = None;

fn wait_for_tcp(port: u16) -> DynResult<TcpStream> {
    let sockaddr = format!("127.0.0.1:{}", port);
    eprintln!("Waiting for a GDB connection on {:?}...", sockaddr);

    let sock = TcpListener::bind(sockaddr)?;
    let (stream, addr) = sock.accept()?;
    eprintln!("Debugger connected from {}", addr);

    Ok(stream)
}

pub fn udbserver(mut uc: UnicornHandle, port: u16, start_addr: u64) -> DynResult<()> {
    uc.add_code_hook(1, 0, |_uc: UnicornHandle, _addr: u64, _size: u32| {})
        .expect("Failed to add empty code hook");
    uc.add_mem_hook(
        HookType::MEM_READ,
        1,
        0,
        |_uc: UnicornHandle, _mem_type: MemType, _addr: u64, _size: usize, _value: i64| {},
    )
    .expect("Failed to add empty mem hook");
    if start_addr != 0 {
        uc.add_code_hook(start_addr, start_addr, move |uc: UnicornHandle, _addr: u64, _size: u32| {
            udbserver_entry(uc, port).expect("Failed to start udbserver")
        })
        .expect("Failed to add udbserver hook");
        Ok(())
    } else {
        udbserver_entry(uc, port)
    }
}

fn udbserver_entry(uc: UnicornHandle, port: u16) -> DynResult<()> {
    unsafe {
        if !GDBSTUB.is_none() {
            return Ok(());
        }
        GDBSTUB = Some(GdbStub::new(wait_for_tcp(port)?).run_state_machine()?);
        EMU = Some(emu::Emu::new(std::mem::transmute::<UnicornHandle<'_>, UnicornHandle<'static>>(uc))?)
    }
    udbserver_loop()
}

fn udbserver_resume(addr: Option<u64>) -> DynResult<()> {
    let emu = unsafe { EMU.as_mut().unwrap() };
    let mut gdb = unsafe { GDBSTUB.take().unwrap() };
    let reason = if let Some(watch_addr) = addr {
        StopReason::Watch {
            kind: WatchKind::Write,
            addr: watch_addr as u32,
        }
    } else {
        StopReason::DoneStep
    };
    if let GdbStubStateMachine::DeferredStopReason(gdb_inner) = gdb {
        match gdb_inner.deferred_stop_reason(emu, reason.into())? {
            (_, Some(disconnect_reason)) => return handle_disconnect(disconnect_reason),
            (gdb_state, None) => gdb = gdb_state,
        }
    }
    unsafe { GDBSTUB = Some(gdb) }
    udbserver_loop()
}

fn udbserver_loop() -> DynResult<()> {
    let emu = unsafe { EMU.as_mut().unwrap() };
    let mut gdb = unsafe { GDBSTUB.take().unwrap() };
    loop {
        gdb = match gdb {
            GdbStubStateMachine::Pump(mut gdb) => {
                let byte = gdb.borrow_conn().read()?;
                let (gdb, disconnect_reason) = gdb.pump(emu, byte)?;
                match disconnect_reason {
                    Some(reason) => return handle_disconnect(reason),
                    None => gdb,
                }
            }
            GdbStubStateMachine::DeferredStopReason(_) => {
                unsafe { GDBSTUB = Some(gdb) }
                return Ok(());
            }
        }
    }
}

fn handle_disconnect(reason: DisconnectReason) -> DynResult<()> {
    unsafe {
        GDBSTUB.take();
        EMU.take();
    }
    match reason {
        DisconnectReason::Disconnect => {
            println!("Disconnect!");
            Ok(())
        }
        DisconnectReason::TargetExited(code) => {
            println!("Target exited with code {}!", code);
            Ok(())
        }
        DisconnectReason::TargetTerminated(sig) => {
            println!("Target terminated with signal {}!", sig);
            Ok(())
        }
        DisconnectReason::Kill => {
            println!("GDB sent a kill command!");
            Ok(())
        }
    }
}
