use crate::arch;
use crate::reg::Register;
use crate::DynResult;

use gdbstub::common::Signal;
use gdbstub::target;
use gdbstub::target::ext::breakpoints::WatchKind;
use gdbstub::target::{TargetError, TargetResult};
use std::collections::HashSet;
use std::convert::TryFrom;
use std::ops::Range;
use std::sync::mpsc::{channel, Receiver, Sender};
use unicorn_engine::unicorn_const::{uc_error, HookType, MemType, Mode, Query};
use unicorn_engine::{uc_engine, UcHookId, Unicorn};

fn copy_to_buf(data: &[u8], buf: &mut [u8]) -> usize {
    let len = data.len();
    let buf = &mut buf[..len];
    buf.copy_from_slice(data);
    len
}

fn copy_range_to_buf(data: &[u8], offset: u64, length: usize, buf: &mut [u8]) -> usize {
    let offset = match usize::try_from(offset) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let len = data.len();
    let data = &data[len.min(offset)..len.min(offset + length)];
    copy_to_buf(data, buf)
}

fn code_cb(uc: &mut Unicorn<EmuState>, addr: u64, _size: u32) {
    let state = uc.get_data_mut();
    if state.in_step {
        if let Some(tx_once) = state.tx_once.take() {
            tx_once.send(()).unwrap();
        } else {
            state.tx_handle.send(None).unwrap();
        }
        state.in_step = false;
        state.rx_done.recv().unwrap();
    } else {
        if state.sw_breakpoints.contains(&addr) || state.hw_breakpoints.contains(&addr) {
            state.tx_handle.send(None).unwrap();
            state.rx_done.recv().unwrap();
        }
    }
}

fn mem_cb(uc: &mut Unicorn<EmuState>, mem_type: MemType, addr: u64, size: usize, _value: i64) -> bool {
    let state = uc.get_data();
    if mem_type == MemType::READ {
        for r in state.r_watchpoints.iter() {
            if r.start < addr + size as u64 && addr < r.end {
                state.tx_handle.send(Some(r.start)).unwrap();
                state.rx_done.recv().unwrap();
                return true;
            }
        }
        for r in state.rw_watchpoints.iter() {
            if r.start < addr + size as u64 && addr < r.end {
                state.tx_handle.send(Some(r.start)).unwrap();
                state.rx_done.recv().unwrap();
                return true;
            }
        }
    }
    if mem_type == MemType::WRITE {
        for r in state.w_watchpoints.iter() {
            if r.start < addr + size as u64 && addr < r.end {
                state.tx_handle.send(Some(r.start)).unwrap();
                state.rx_done.recv().unwrap();
                return true;
            }
        }
        for r in state.rw_watchpoints.iter() {
            if r.start < addr + size as u64 && addr < r.end {
                state.tx_handle.send(Some(r.start)).unwrap();
                state.rx_done.recv().unwrap();
                return true;
            }
        }
    }
    true
}

pub struct EmuState {
    pub tx_handle: Sender<Option<u64>>,
    pub rx_done: Receiver<()>,
    pub tx_once: Option<Sender<()>>,
    pub in_step: bool,
    pub sw_breakpoints: HashSet<u64>,
    pub hw_breakpoints: HashSet<u64>,
    pub r_watchpoints: Vec<Range<u64>>,
    pub w_watchpoints: Vec<Range<u64>>,
    pub rw_watchpoints: Vec<Range<u64>>,
}

pub struct Emu<'a> {
    uc: Unicorn<'a, EmuState>,
    reg: Register,
    code_hook: UcHookId,
    mem_hook: UcHookId,
    pub rx_handle: Receiver<Option<u64>>,
    tx_done: Sender<()>,
}

impl<'a> Emu<'a> {
    pub fn new(uc_handle: *mut uc_engine, _start_addr: u64, tx_once: Sender<()>) -> DynResult<Emu<'a>> {
        let (tx_handle, rx_handle): (Sender<Option<u64>>, Receiver<Option<u64>>) = channel();
        let (tx_done, rx_done): (Sender<()>, Receiver<()>) = channel();
        let state = EmuState {
            tx_handle,
            rx_done,
            tx_once: Some(tx_once),
            in_step: true,
            sw_breakpoints: HashSet::new(),
            hw_breakpoints: HashSet::new(),
            r_watchpoints: Vec::new(),
            w_watchpoints: Vec::new(),
            rw_watchpoints: Vec::new(),
        };
        if let Ok(mut uc) = unsafe { Unicorn::from_handle_with_data(uc_handle, state) } {
            let arch = uc.get_arch();
            let query_mode = uc.query(Query::MODE).expect("Failed to query mode");
            let mode = Mode::try_from(query_mode as i32).unwrap();
            let reg: Register = Register::new(arch, mode);
            let code_hook = uc.add_code_hook(1, 0, code_cb).expect("Failed to add code hook");
            let mem_hook = uc
                .add_mem_hook(HookType::MEM_READ | HookType::MEM_WRITE, 1, 0, mem_cb)
                .expect("Failed to add mem hook");
            Ok(Emu {
                uc,
                reg,
                code_hook,
                mem_hook,
                rx_handle,
                tx_done,
            })
        } else {
            panic!("Failed to convert handle to Unicorn");
        }
    }
}

impl<'a> Drop for Emu<'a> {
    fn drop(&mut self) {
        self.uc.remove_hook(self.code_hook).expect("Failed to remove code hook");
        self.uc.remove_hook(self.mem_hook).expect("Failed to remove mem hook");
        self.tx_done.send(()).unwrap();
    }
}

impl<'a> target::Target for Emu<'a> {
    type Arch = arch::GenericArch;
    type Error = &'static str;

    #[inline(always)]
    fn base_ops(&mut self) -> target::ext::base::BaseOps<Self::Arch, Self::Error> {
        target::ext::base::BaseOps::SingleThread(self)
    }

    #[inline(always)]
    fn support_breakpoints(&mut self) -> Option<target::ext::breakpoints::BreakpointsOps<Self>> {
        Some(self)
    }

    #[inline(always)]
    fn support_target_description_xml_override(&mut self) -> Option<target::ext::target_description_xml_override::TargetDescriptionXmlOverrideOps<Self>> {
        Some(self)
    }
}

impl<'a> target::ext::base::singlethread::SingleThreadBase for Emu<'a> {
    fn read_registers(&mut self, regs: &mut arch::GenericRegs) -> TargetResult<(), Self> {
        regs.buf = Vec::new();
        for reg in self.reg.list() {
            let val = match reg.0 {
                Some(regid) => self.uc.reg_read(regid).map_err(|_| ())?,
                None => 0,
            };
            regs.buf.extend(self.reg.write_u64(val, reg.1));
        }
        Ok(())
    }

    fn write_registers(&mut self, regs: &arch::GenericRegs) -> TargetResult<(), Self> {
        let mut i = 0;
        for reg in self.reg.list() {
            let part = &regs.buf[i..i + reg.1];
            let val = self.reg.read_u64(part);
            i += reg.1;
            if let Some(regid) = reg.0 {
                self.uc.reg_write(regid, val).map_err(|_| ())?
            }
        }
        Ok(())
    }

    #[inline(always)]
    fn support_single_register_access(&mut self) -> Option<target::ext::base::single_register_access::SingleRegisterAccessOps<(), Self>> {
        Some(self)
    }

    fn read_addrs(&mut self, start_addr: u64, data: &mut [u8]) -> TargetResult<usize, Self> {
        match self.uc.mem_read(start_addr, data) {
            Ok(_) => Ok(data.len()),
            Err(uc_error::READ_UNMAPPED) => Err(TargetError::Errno(1)),
            Err(_) => Err(TargetError::Fatal("Failed to read addr")),
        }
    }

    fn write_addrs(&mut self, start_addr: u64, data: &[u8]) -> TargetResult<(), Self> {
        match self.uc.mem_write(start_addr, data) {
            Ok(_) => Ok(()),
            Err(uc_error::WRITE_UNMAPPED) => Err(TargetError::Errno(1)),
            Err(_) => Err(TargetError::Fatal("Failed to write addr")),
        }
    }

    #[inline(always)]
    fn support_resume(&mut self) -> Option<target::ext::base::singlethread::SingleThreadResumeOps<Self>> {
        Some(self)
    }
}

impl<'a> target::ext::base::singlethread::SingleThreadResume for Emu<'a> {
    fn resume(&mut self, _signal: Option<Signal>) -> Result<(), Self::Error> {
        self.tx_done.send(()).unwrap();
        Ok(())
    }

    #[inline(always)]
    fn support_single_step(&mut self) -> Option<target::ext::base::singlethread::SingleThreadSingleStepOps<Self>> {
        Some(self)
    }
}

impl<'a> target::ext::base::singlethread::SingleThreadSingleStep for Emu<'a> {
    fn step(&mut self, signal: Option<Signal>) -> Result<(), Self::Error> {
        if signal.is_some() {
            return Err("no support for stepping with signal");
        }
        let state = self.uc.get_data_mut();
        state.in_step = true;
        self.tx_done.send(()).unwrap();
        Ok(())
    }
}

impl<'a> target::ext::breakpoints::Breakpoints for Emu<'a> {
    #[inline(always)]
    fn support_sw_breakpoint(&mut self) -> Option<target::ext::breakpoints::SwBreakpointOps<Self>> {
        Some(self)
    }

    #[inline(always)]
    fn support_hw_breakpoint(&mut self) -> Option<target::ext::breakpoints::HwBreakpointOps<Self>> {
        Some(self)
    }

    #[inline(always)]
    fn support_hw_watchpoint(&mut self) -> Option<target::ext::breakpoints::HwWatchpointOps<Self>> {
        Some(self)
    }
}

impl<'a> target::ext::breakpoints::SwBreakpoint for Emu<'a> {
    fn add_sw_breakpoint(&mut self, addr: u64, _kind: usize) -> TargetResult<bool, Self> {
        let state = self.uc.get_data_mut();
        Ok(state.sw_breakpoints.insert(addr))
    }

    fn remove_sw_breakpoint(&mut self, addr: u64, _kind: usize) -> TargetResult<bool, Self> {
        let state = self.uc.get_data_mut();
        Ok(state.sw_breakpoints.remove(&addr))
    }
}

impl<'a> target::ext::breakpoints::HwBreakpoint for Emu<'a> {
    fn add_hw_breakpoint(&mut self, addr: u64, _kind: usize) -> TargetResult<bool, Self> {
        let state = self.uc.get_data_mut();
        Ok(state.hw_breakpoints.insert(addr))
    }

    fn remove_hw_breakpoint(&mut self, addr: u64, _kind: usize) -> TargetResult<bool, Self> {
        let state = self.uc.get_data_mut();
        Ok(state.hw_breakpoints.remove(&addr))
    }
}

impl<'a> target::ext::breakpoints::HwWatchpoint for Emu<'a> {
    fn add_hw_watchpoint(&mut self, addr: u64, len: u64, kind: WatchKind) -> TargetResult<bool, Self> {
        let state = self.uc.get_data_mut();
        match kind {
            WatchKind::Read => state.r_watchpoints.push(addr..addr + len - 1),
            WatchKind::Write => state.w_watchpoints.push(addr..addr + len - 1),
            WatchKind::ReadWrite => state.rw_watchpoints.push(addr..addr + len - 1),
        }
        Ok(true)
    }

    fn remove_hw_watchpoint(&mut self, addr: u64, len: u64, kind: WatchKind) -> TargetResult<bool, Self> {
        let state = self.uc.get_data_mut();
        match kind {
            WatchKind::Read => state.r_watchpoints.retain(|r: &Range<u64>| *r != (addr..addr + len - 1)),
            WatchKind::Write => state.w_watchpoints.retain(|r: &Range<u64>| *r != (addr..addr + len - 1)),
            WatchKind::ReadWrite => state.rw_watchpoints.retain(|r: &Range<u64>| *r != (addr..addr + len - 1)),
        }
        Ok(true)
    }
}

impl<'a> target::ext::base::single_register_access::SingleRegisterAccess<()> for Emu<'a> {
    fn read_register(&mut self, _tid: (), reg_id: arch::GenericRegId, buf: &mut [u8]) -> TargetResult<usize, Self> {
        let reg = self.reg.get(reg_id.0)?;
        if reg.1 <= 8 {
            let val = match reg.0 {
                Some(regid) => self.uc.reg_read(regid).map_err(|_| ())?,
                None => 0,
            };
            Ok(copy_to_buf(&self.reg.write_u64(val, reg.1), buf))
        } else if let Some(regid) = reg.0 {
            let data = &self.uc.reg_read_long(regid).map_err(|_| ())?;
            Ok(copy_to_buf(data, buf))
        } else {
            Ok(0)
        }
    }

    fn write_register(&mut self, _tid: (), reg_id: arch::GenericRegId, val: &[u8]) -> TargetResult<(), Self> {
        let reg = self.reg.get(reg_id.0)?;
        assert!(reg.1 == val.len(), "Length mismatch when write register {}", reg.0.unwrap());
        if let Some(regid) = reg.0 {
            if reg.1 <= 8 {
                let v = self.reg.read_u64(val);
                self.uc.reg_write(regid, v).map_err(|_| ())?;
            } else {
                self.uc.reg_write_long(regid, val).map_err(|_| ())?;
            }
        }
        Ok(())
    }
}

impl<'a> target::ext::target_description_xml_override::TargetDescriptionXmlOverride for Emu<'a> {
    fn target_description_xml(&self, _annex: &[u8], offset: u64, length: usize, buf: &mut [u8]) -> TargetResult<usize, Self> {
        let xml = self.reg.description_xml().as_bytes();
        Ok(copy_range_to_buf(xml, offset, length, buf))
    }
}
