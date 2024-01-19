#[cfg(feature = "capi")]
mod capi;

mod arch;
mod emu;
mod reg;

use gdbstub::conn::ConnectionExt;
use gdbstub::stub::state_machine::GdbStubStateMachine;
use gdbstub::stub::{DisconnectReason, GdbStubBuilder, SingleThreadStopReason};
use gdbstub::target::ext::breakpoints::WatchKind;
use singlyton::SingletonOption;
use std::borrow::BorrowMut;
use std::ffi::c_void;
use std::net::{TcpListener, TcpStream};
use unicorn_engine::unicorn_const::{HookType, MemType};
use unicorn_engine::Unicorn;

type DynResult<T> = Result<T, Box<dyn std::error::Error>>;
type Hook = *mut c_void;

static GDBSTUB: SingletonOption<GdbStubStateMachine<emu::Emu, TcpStream>> = SingletonOption::new();
static EMU: SingletonOption<emu::Emu> = SingletonOption::new();

fn wait_for_tcp(port: u16) -> DynResult<TcpStream> {
    let sockaddr = format!("0.0.0.0:{}", port);
    eprintln!("Waiting for a GDB connection on {:?}...", sockaddr);

    let sock = TcpListener::bind(sockaddr)?;
    let (stream, addr) = sock.accept()?;
    eprintln!("Debugger connected from {}", addr);

    Ok(stream)
}

pub fn udbserver(uc: &mut Unicorn<()>, port: u16, start_addr: u64) -> DynResult<()> {
    let code_hook = uc
        .add_code_hook(1, 0, |_: &mut Unicorn<'_, ()>, _: u64, _: u32| {})
        .expect("Failed to add empty code hook");
    let mem_hook = uc
        .add_mem_hook(HookType::MEM_READ, 1, 0, |_: &mut Unicorn<'_, ()>, _: MemType, _: u64, _: usize, _: i64| true)
        .expect("Failed to add empty mem hook");
    if start_addr != 0 {
        let uc_ptr = uc as *mut Unicorn<()>;
        uc.add_code_hook(start_addr, start_addr, move |_, _, _| {
            udbserver_entry(unsafe { &mut *uc_ptr }, port, code_hook, mem_hook).expect("Failed to start udbserver")
        })
        .expect("Failed to add udbserver hook");
        Ok(())
    } else {
        udbserver_entry(uc, port, code_hook, mem_hook)
    }
}

fn udbserver_entry(uc: &mut Unicorn<()>, port: u16, code_hook: Hook, mem_hook: Hook) -> DynResult<()> {
    if GDBSTUB.is_some() {
        return Ok(());
    }
    let uc_static = unsafe { std::mem::transmute::<&mut Unicorn<()>, &mut Unicorn<'static, ()>>(uc) };
    let mut emu = emu::Emu::new(uc_static, code_hook, mem_hook)?;
    GDBSTUB.replace(GdbStubBuilder::new(wait_for_tcp(port)?).build()?.run_state_machine(&mut emu)?);
    EMU.replace(emu);
    udbserver_loop()
}

fn udbserver_resume(addr: Option<u64>) -> DynResult<()> {
    let mut gdb = GDBSTUB.take().unwrap();
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
        match gdb_inner.report_stop(EMU.get_mut().borrow_mut(), reason) {
            Ok(gdb_state) => gdb = gdb_state,
            Err(_) => return Ok(()),
        }
    }
    GDBSTUB.replace(gdb);
    udbserver_loop()
}

fn udbserver_loop() -> DynResult<()> {
    let mut gdb = GDBSTUB.take().unwrap();
    loop {
        gdb = match gdb {
            GdbStubStateMachine::Idle(mut gdb_inner) => {
                let byte = gdb_inner.borrow_conn().read()?;
                gdb_inner.incoming_data(EMU.get_mut().borrow_mut(), byte)?
            }
            GdbStubStateMachine::Running(_) => break,
            GdbStubStateMachine::CtrlCInterrupt(_) => break,
            GdbStubStateMachine::Disconnected(gdb_inner) => return handle_disconnect(gdb_inner.get_reason()),
        }
    }
    GDBSTUB.replace(gdb);
    Ok(())
}

fn handle_disconnect(reason: DisconnectReason) -> DynResult<()> {
    EMU.take();
    #[cfg(feature = "capi")]
    capi::clean();
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
