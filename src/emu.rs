use crate::arch;
use crate::reg::Register;
use crate::DynResult;

use gdbstub::common::Signal;
use gdbstub::target;
use gdbstub::target::ext::breakpoints::WatchKind;
use gdbstub::target::{TargetError, TargetResult};
use singlyton::{Singleton, SingletonOption};
use std::collections::HashMap;
use std::convert::TryFrom;
use unicorn_engine::unicorn_const::{uc_error, HookType, MemType, Mode, Query};
use unicorn_engine::{UcHookId, Unicorn};

static STEP_STATE: Singleton<bool> = Singleton::new(false);
static STEP_HOOK: SingletonOption<UcHookId> = SingletonOption::new();
static WATCH_ADDR: SingletonOption<u64> = SingletonOption::new();

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

fn step_cb(uc: &mut Unicorn<()>, _addr: u64, _size: u32) {
    if *STEP_STATE.get() {
        STEP_STATE.replace(false);
        return;
    }
    if let Some(step_hook) = STEP_HOOK.take() {
        uc.remove_hook(step_hook).expect("Failed to remove step hook");
    }
    crate::udbserver_resume(WATCH_ADDR.take()).expect("Failed to resume udbserver");
}

fn watch_cb(uc: &mut Unicorn<()>, _mem_type: MemType, addr: u64, _size: usize, _value: i64) -> bool {
    if WATCH_ADDR.is_none() {
        WATCH_ADDR.replace(addr);
        if STEP_HOOK.is_none() {
            STEP_HOOK.replace(uc.add_code_hook(1, 0, step_cb).expect("Failed to add code hook"));
        }
    }
    true
}

pub struct Emu {
    uc: &'static mut Unicorn<'static, ()>,
    reg: Register,
    code_hook: UcHookId,
    mem_hook: UcHookId,
    bp_sw_hooks: HashMap<u64, UcHookId>,
    bp_hw_hooks: HashMap<u64, UcHookId>,
    wp_r_hooks: HashMap<u64, HashMap<u64, UcHookId>>,
    wp_w_hooks: HashMap<u64, HashMap<u64, UcHookId>>,
    wp_rw_hooks: HashMap<u64, HashMap<u64, UcHookId>>,
}

impl Emu {
    pub fn new(uc: &'static mut Unicorn<'static, ()>, code_hook: UcHookId, mem_hook: UcHookId) -> DynResult<Emu> {
        let arch = uc.get_arch();
        let query_mode = uc.query(Query::MODE).expect("Failed to query mode");
        let mode = Mode::from_bits(query_mode as i32).unwrap();
        let reg = Register::new(arch, mode);
        Ok(Emu {
            uc,
            reg,
            code_hook,
            mem_hook,
            bp_sw_hooks: HashMap::new(),
            bp_hw_hooks: HashMap::new(),
            wp_r_hooks: HashMap::new(),
            wp_w_hooks: HashMap::new(),
            wp_rw_hooks: HashMap::new(),
        })
    }
}

impl Drop for Emu {
    fn drop(&mut self) {
        self.uc.remove_hook(self.code_hook).expect("Failed to remove empty code hook");
        self.uc.remove_hook(self.mem_hook).expect("Failed to remove empty mem hook");
    }
}

impl target::Target for Emu {
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

impl target::ext::base::singlethread::SingleThreadBase for Emu {
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

impl target::ext::base::singlethread::SingleThreadResume for Emu {
    fn resume(&mut self, _signal: Option<Signal>) -> Result<(), Self::Error> {
        Ok(())
    }

    #[inline(always)]
    fn support_single_step(&mut self) -> Option<target::ext::base::singlethread::SingleThreadSingleStepOps<Self>> {
        Some(self)
    }
}

impl target::ext::base::singlethread::SingleThreadSingleStep for Emu {
    fn step(&mut self, signal: Option<Signal>) -> Result<(), Self::Error> {
        if signal.is_some() {
            return Err("no support for stepping with signal");
        }

        STEP_STATE.replace(true);
        STEP_HOOK.replace(self.uc.add_code_hook(1, 0, step_cb).map_err(|_| "Failed to add code hook")?);

        Ok(())
    }
}

impl target::ext::breakpoints::Breakpoints for Emu {
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

macro_rules! add_breakpoint {
    ( $self:ident, $addr:ident, $hook_map:ident ) => {{
        let hook = match $self.uc.add_code_hook($addr.into(), $addr.into(), step_cb) {
            Ok(h) => h,
            Err(_) => return Ok(false),
        };
        $self.$hook_map.insert($addr.into(), hook);
        Ok(true)
    }};
    ( $self:ident, $mem_type:ident, $addr:ident, $len:ident, $hook_map:ident ) => {{
        let hook = match $self.uc.add_mem_hook(HookType::$mem_type, $addr.into(), ($addr + $len - 1).into(), watch_cb) {
            Ok(h) => h,
            Err(_) => return Ok(false),
        };
        $self.$hook_map.entry($len).or_insert(HashMap::new()).insert($addr.into(), hook);
        Ok(true)
    }};
}

macro_rules! remove_breakpoint {
    ( $self:ident, $addr:ident, $hook_map:ident ) => {{
        let hook = match $self.$hook_map.remove(&$addr.into()) {
            Some(h) => h,
            None => return Ok(false),
        };
        match $self.uc.remove_hook(hook) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }};
    ( $self:ident, $addr:ident, $len:ident, $hook_map:ident ) => {{
        let map = match $self.$hook_map.get_mut(&$len) {
            Some(h) => h,
            None => return Ok(false),
        };
        let hook = match map.remove(&$addr.into()) {
            Some(h) => h,
            None => return Ok(false),
        };
        match $self.uc.remove_hook(hook) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }};
}

impl target::ext::breakpoints::SwBreakpoint for Emu {
    fn add_sw_breakpoint(&mut self, addr: u64, _kind: usize) -> TargetResult<bool, Self> {
        add_breakpoint!(self, addr, bp_sw_hooks)
    }

    fn remove_sw_breakpoint(&mut self, addr: u64, _kind: usize) -> TargetResult<bool, Self> {
        remove_breakpoint!(self, addr, bp_sw_hooks)
    }
}

impl target::ext::breakpoints::HwBreakpoint for Emu {
    fn add_hw_breakpoint(&mut self, addr: u64, _kind: usize) -> TargetResult<bool, Self> {
        add_breakpoint!(self, addr, bp_hw_hooks)
    }

    fn remove_hw_breakpoint(&mut self, addr: u64, _kind: usize) -> TargetResult<bool, Self> {
        remove_breakpoint!(self, addr, bp_hw_hooks)
    }
}

impl target::ext::breakpoints::HwWatchpoint for Emu {
    fn add_hw_watchpoint(&mut self, addr: u64, len: u64, kind: WatchKind) -> TargetResult<bool, Self> {
        match kind {
            WatchKind::Read => add_breakpoint!(self, MEM_READ, addr, len, wp_r_hooks),
            WatchKind::Write => add_breakpoint!(self, MEM_WRITE, addr, len, wp_w_hooks),
            WatchKind::ReadWrite => add_breakpoint!(self, MEM_VALID, addr, len, wp_rw_hooks),
        }
    }

    fn remove_hw_watchpoint(&mut self, addr: u64, len: u64, kind: WatchKind) -> TargetResult<bool, Self> {
        match kind {
            WatchKind::Read => remove_breakpoint!(self, addr, len, wp_r_hooks),
            WatchKind::Write => remove_breakpoint!(self, addr, len, wp_w_hooks),
            WatchKind::ReadWrite => remove_breakpoint!(self, addr, len, wp_rw_hooks),
        }
    }
}

impl target::ext::base::single_register_access::SingleRegisterAccess<()> for Emu {
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

impl target::ext::target_description_xml_override::TargetDescriptionXmlOverride for Emu {
    fn target_description_xml(&self, _annex: &[u8], offset: u64, length: usize, buf: &mut [u8]) -> TargetResult<usize, Self> {
        let xml = self.reg.description_xml().as_bytes();
        Ok(copy_range_to_buf(xml, offset, length, buf))
    }
}
