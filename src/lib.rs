#[cfg(feature = "capi")]
mod capi;

mod arch;
mod emu;
mod reg;

use gdbstub::common::Signal;
use gdbstub::conn::ConnectionExt;
use gdbstub::stub::run_blocking::WaitForStopReasonError;
use gdbstub::stub::{run_blocking, DisconnectReason, GdbStub, SingleThreadStopReason};
use gdbstub::target::ext::breakpoints::WatchKind;
use gdbstub::target::Target;
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use unicorn_engine::{uc_engine, Unicorn};

type DynResult<T> = Result<T, Box<dyn std::error::Error>>;

fn wait_for_tcp(port: u16) -> DynResult<TcpStream> {
    let sockaddr = format!("0.0.0.0:{}", port);
    eprintln!("Waiting for a GDB connection on {:?}...", sockaddr);

    let sock = TcpListener::bind(sockaddr)?;
    let (stream, addr) = sock.accept()?;
    eprintln!("Debugger connected from {}", addr);

    Ok(stream)
}

enum GdbEventLoop<'a> {
    _Phantom(std::marker::PhantomData<&'a u64>),
}

impl<'a> run_blocking::BlockingEventLoop for GdbEventLoop<'a> {
    type Target = emu::Emu<'a>;
    type Connection = Box<dyn ConnectionExt<Error = std::io::Error>>;
    type StopReason = SingleThreadStopReason<u64>;

    fn wait_for_stop_reason(
        target: &mut Self::Target,
        conn: &mut Self::Connection,
    ) -> Result<
        run_blocking::Event<Self::StopReason>,
        run_blocking::WaitForStopReasonError<<Self::Target as Target>::Error, <Self::Connection as gdbstub::conn::Connection>::Error>,
    > {
        loop {
            match target.rx_handle.try_recv() {
                Ok(addr) => {
                    let stop_reason = if let Some(watch_addr) = addr {
                        SingleThreadStopReason::Watch {
                            tid: (),
                            kind: WatchKind::Write,
                            addr: watch_addr,
                        }
                    } else {
                        SingleThreadStopReason::DoneStep
                    };
                    return Ok(run_blocking::Event::TargetStopped(stop_reason));
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => (),
                Err(_) => {
                    return Err(WaitForStopReasonError::Target("Failed to read addr"));
                }
            }

            if conn.peek().map(|b| b.is_some()).unwrap_or(false) {
                let byte = conn.read().map_err(run_blocking::WaitForStopReasonError::Connection)?;
                return Ok(run_blocking::Event::IncomingData(byte));
            }
        }
    }

    fn on_interrupt(_target: &mut Self::Target) -> Result<Option<Self::StopReason>, <Self::Target as Target>::Error> {
        Ok(Some(SingleThreadStopReason::Signal(Signal::SIGINT)))
    }
}

pub fn gdb_thread(mut emu: emu::Emu, port: u16, rx_once: Receiver<()>) {
    rx_once.recv().unwrap();
    let connection: Box<dyn ConnectionExt<Error = std::io::Error>> = Box::new(wait_for_tcp(port).unwrap());
    let gdb = GdbStub::new(connection);
    match gdb.run_blocking::<GdbEventLoop>(&mut emu) {
        Ok(disconnect_reason) => {
            let _ = handle_disconnect(disconnect_reason);
        }
        Err(e) => {
            eprintln!("error occurred in GDB session: {}", e);
        }
    }
}

pub fn udbserver<T>(uc: &mut Unicorn<T>, port: u16, start_addr: u64) -> DynResult<()> {
    let uc_handle = uc.get_handle() as usize;
    let (tx_first, rx_first): (Sender<()>, Receiver<()>) = channel();
    let (tx_once, rx_once): (Sender<()>, Receiver<()>) = channel();
    thread::Builder::new()
        .name("udbserver".to_string())
        .spawn(move || {
            let emu = emu::Emu::new(uc_handle as *mut uc_engine, start_addr, tx_once).unwrap();
            tx_first.send(()).unwrap();
            gdb_thread(emu, port, rx_once);
        })
        .unwrap();
    rx_first.recv().unwrap();
    Ok(())
}

fn handle_disconnect(reason: DisconnectReason) -> DynResult<()> {
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
