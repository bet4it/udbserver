#[cfg(feature = "capi")]
mod capi;

mod arch;
mod emu;
mod reg;

use gdbstub::conn::ConnectionExt;
use gdbstub::stub::state_machine::GdbStubStateMachine;
use gdbstub::stub::{DisconnectReason, GdbStubBuilder, SingleThreadStopReason};
use gdbstub::target::ext::breakpoints::WatchKind;
use std::net::{TcpListener, TcpStream};
use unicorn_engine::unicorn_const::{HookType, MemType};
use unicorn_engine::Unicorn;

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

pub fn udbserver(uc: &mut Unicorn<()>, port: u16, start_addr: u64) -> DynResult<()> {
    uc.add_code_hook(1, 0, |_uc: &mut Unicorn<'_, ()>, _addr: u64, _size: u32| {})
        .expect("Failed to add empty code hook");
    uc.add_mem_hook(
        HookType::MEM_READ,
        1,
        0,
        |_uc: &mut Unicorn<'_, ()>, _mem_type: MemType, _addr: u64, _size: usize, _value: i64| true,
    )
    .expect("Failed to add empty mem hook");
    if start_addr != 0 {
        uc.add_code_hook(start_addr, start_addr, move |uc: &mut Unicorn<'_, ()>, _addr: u64, _size: u32| {
            udbserver_entry(uc, port).expect("Failed to start udbserver")
        })
        .expect("Failed to add udbserver hook");
        Ok(())
    } else {
        udbserver_entry(uc, port)
    }
}

fn udbserver_entry(uc: &mut Unicorn<()>, port: u16) -> DynResult<()> {
    unsafe {
        if GDBSTUB.is_some() {
            return Ok(());
        }
        let mut emu = emu::Emu::new(std::mem::transmute::<&mut Unicorn<()>, &mut Unicorn<'static, ()>>(uc))?;
        GDBSTUB = Some(GdbStubBuilder::new(wait_for_tcp(port)?).build()?.run_state_machine(&mut emu)?);
        EMU = Some(emu)
    }
    udbserver_loop()
}

fn udbserver_resume(addr: Option<u64>) -> DynResult<()> {
    let emu = unsafe { EMU.as_mut().unwrap() };
    let mut gdb = unsafe { GDBSTUB.take().unwrap() };
    let reason = if let Some(watch_addr) = addr {
        SingleThreadStopReason::Watch {
            tid: (),
            kind: WatchKind::Write,
            addr: watch_addr,
        }
    } else {
        SingleThreadStopReason::DoneStep
    };
    if let GdbStubStateMachine::Running(gdb_inner) = gdb {
        match gdb_inner.report_stop(emu, reason) {
            Ok(gdb_state) => gdb = gdb_state,
            Err(_) => return Ok(()),
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
            GdbStubStateMachine::Idle(mut gdb) => {
                let byte = gdb.borrow_conn().read()?;
                gdb.incoming_data(emu, byte)?
            }
            GdbStubStateMachine::Running(_) => break,
            GdbStubStateMachine::CtrlCInterrupt(_) => break,
            GdbStubStateMachine::Disconnected(gdb) => return handle_disconnect(gdb.get_reason()),
        }
    }
    unsafe { GDBSTUB = Some(gdb) };
    Ok(())
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
