use crate::DynResult;

use crate::uc_hook;
use gdbstub::target;
use gdbstub::target::ext::base::singlethread::{GdbInterrupt, ResumeAction, SingleThreadOps, StopReason};
use gdbstub::target::ext::breakpoints::WatchKind;
use gdbstub::target::{Target, TargetError, TargetResult};
use std::collections::HashMap;
use std::ptr::null_mut;
use unicorn::unicorn_const::uc_error;
use unicorn::unicorn_const::{HookType, MemType};
use unicorn::RegisterARM;
use unicorn::UnicornHandle;

pub static REG_MAP_ARM: [RegisterARM; 13] = [
    RegisterARM::R0,
    RegisterARM::R1,
    RegisterARM::R2,
    RegisterARM::R3,
    RegisterARM::R4,
    RegisterARM::R5,
    RegisterARM::R6,
    RegisterARM::R7,
    RegisterARM::R8,
    RegisterARM::R9,
    RegisterARM::R10,
    RegisterARM::R11,
    RegisterARM::R12,
];

pub struct Global {
    step_state: bool,
    step_hook: uc_hook,
    watch_addr: Option<u64>,
    bp_sw_hooks: HashMap<u64, uc_hook>,
    bp_hw_hooks: HashMap<u64, uc_hook>,
    wp_r_hooks: HashMap<u32, HashMap<u64, uc_hook>>,
    wp_w_hooks: HashMap<u32, HashMap<u64, uc_hook>>,
    wp_rw_hooks: HashMap<u32, HashMap<u64, uc_hook>>,
}

static mut G: Option<Global> = None;

pub fn step_hook(mut uc: UnicornHandle, _addr: u64, _size: u32) {
    let global;
    let msg: String;
    unsafe {
        global = G.as_mut().unwrap();
    }
    if global.step_state {
        global.step_state = false;
        return;
    }
    if global.step_hook != null_mut() {
        uc.remove_hook(global.step_hook).expect("Failed to remove hook");
        global.step_hook = null_mut();
    }
    if let Some(watch_addr) = global.watch_addr {
        msg = format!("T05watch:{:x};", watch_addr);
        global.watch_addr = None
    } else {
        msg = "S05".to_string();
    }
    crate::udbserver_conn(uc, Some(msg)).expect("Failed to start udbserver");
}

pub fn mem_hook(mut uc: UnicornHandle, _mem_type: MemType, addr: u64, _size: usize, _value: i64) {
    let global;
    unsafe {
        global = G.as_mut().unwrap();
    }
    if global.watch_addr == None {
        global.watch_addr = Some(addr);
        global.step_hook = uc.add_code_hook(1, 0, step_hook).expect("failed to add code hook");
    }
}

pub struct Emu<'a> {
    uc: UnicornHandle<'a>,
    v: &'static mut Global,
}

impl Emu<'_> {
    pub fn new(uc: UnicornHandle) -> DynResult<Emu> {
        unsafe {
            if G.is_none() {
                G = Some(Global {
                    step_state: false,
                    step_hook: null_mut(),
                    watch_addr: None,
                    bp_sw_hooks: HashMap::new(),
                    bp_hw_hooks: HashMap::new(),
                    wp_r_hooks: HashMap::new(),
                    wp_w_hooks: HashMap::new(),
                    wp_rw_hooks: HashMap::new(),
                });
            }
            Ok(Emu {
                uc: uc,
                v: G.as_mut().unwrap(),
            })
        }
    }
}

impl Target for Emu<'_> {
    type Arch = gdbstub_arch::arm::Armv4t;
    type Error = &'static str;

    #[inline(always)]
    fn base_ops(&mut self) -> target::ext::base::BaseOps<Self::Arch, Self::Error> {
        target::ext::base::BaseOps::SingleThread(self)
    }

    #[inline(always)]
    fn breakpoints(&mut self) -> Option<target::ext::breakpoints::BreakpointsOps<Self>> {
        Some(self)
    }
}

impl SingleThreadOps for Emu<'_> {
    fn resume(&mut self, action: ResumeAction, _gdb_interrupt: GdbInterrupt<'_>) -> Result<StopReason<u32>, Self::Error> {
        match action {
            ResumeAction::Step => {
                self.v.step_state = true;
                self.v.step_hook = self.uc.add_code_hook(1, 0, step_hook).expect("failed to add code hook");
                Ok(StopReason::Custom)
            }
            ResumeAction::Continue => Ok(StopReason::Custom),
            _ => Err("cannot resume with signal"),
        }
    }

    fn read_registers(&mut self, regs: &mut gdbstub_arch::arm::reg::ArmCoreRegs) -> TargetResult<(), Self> {
        for (idx, reg) in REG_MAP_ARM.iter().enumerate() {
            regs.r[idx] = self.uc.reg_read(*reg as i32).expect("Failed to read register") as u32;
        }
        regs.sp = self.uc.reg_read(RegisterARM::SP as i32).expect("Failed to read register") as u32;
        regs.lr = self.uc.reg_read(RegisterARM::LR as i32).expect("Failed to read register") as u32;
        regs.pc = self.uc.reg_read(RegisterARM::PC as i32).expect("Failed to read register") as u32;
        Ok(())
    }

    fn write_registers(&mut self, regs: &gdbstub_arch::arm::reg::ArmCoreRegs) -> TargetResult<(), Self> {
        for (idx, reg) in REG_MAP_ARM.iter().enumerate() {
            self.uc.reg_write(*reg as i32, regs.r[idx] as u64).expect("Failed to write register");
        }
        self.uc.reg_write(RegisterARM::SP as i32, regs.sp as u64).expect("Failed to write register");
        self.uc.reg_write(RegisterARM::LR as i32, regs.lr as u64).expect("Failed to write register");
        self.uc.reg_write(RegisterARM::PC as i32, regs.pc as u64).expect("Failed to write register");
        Ok(())
    }

    fn read_addrs(&mut self, start_addr: u32, data: &mut [u8]) -> TargetResult<(), Self> {
        match self.uc.mem_read(start_addr as u64, data) {
            Ok(_) => Ok(()),
            Err(uc_error::READ_UNMAPPED) => Err(TargetError::Errno(1)),
            Err(_) => Err(TargetError::Fatal("Failed to read addr")),
        }
    }

    fn write_addrs(&mut self, start_addr: u32, data: &[u8]) -> TargetResult<(), Self> {
        match self.uc.mem_write(start_addr as u64, data) {
            Ok(_) => Ok(()),
            Err(uc_error::WRITE_UNMAPPED) => Err(TargetError::Errno(1)),
            Err(_) => Err(TargetError::Fatal("Failed to write addr")),
        }
    }
}

impl target::ext::breakpoints::Breakpoints for Emu<'_> {
    #[inline(always)]
    fn sw_breakpoint(&mut self) -> Option<target::ext::breakpoints::SwBreakpointOps<Self>> {
        Some(self)
    }

    #[inline(always)]
    fn hw_breakpoint(&mut self) -> Option<target::ext::breakpoints::HwBreakpointOps<Self>> {
        Some(self)
    }

    #[inline(always)]
    fn hw_watchpoint(&mut self) -> Option<target::ext::breakpoints::HwWatchpointOps<Self>> {
        Some(self)
    }
}

macro_rules! add_breakpoint {
    ( $self:ident, $addr:ident, $hook_map:ident ) => {{
        let hook = match $self.uc.add_code_hook($addr.into(), $addr.into(), step_hook) {
            Ok(h) => h,
            Err(_) => return Ok(false),
        };
        $self.v.$hook_map.insert($addr.into(), hook);
        Ok(true)
    }};
    ( $self:ident, $mem_type:ident, $addr:ident, $len:ident, $hook_map:ident ) => {{
        let hook = match $self.uc.add_mem_hook(HookType::$mem_type, $addr.into(), ($addr + $len - 1).into(), mem_hook) {
            Ok(h) => h,
            Err(_) => return Ok(false),
        };
        $self.v.$hook_map.entry($len).or_insert(HashMap::new()).insert($addr.into(), hook);
        Ok(true)
    }};
}

macro_rules! remove_breakpoint {
    ( $self:ident, $addr:ident, $hook_map:ident ) => {{
        let hook = match $self.v.$hook_map.remove(&$addr.into()) {
            Some(h) => h,
            None => return Ok(false),
        };
        match $self.uc.remove_hook(hook) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }};
    ( $self:ident, $addr:ident, $len:ident, $hook_map:ident ) => {{
        let map = match $self.v.$hook_map.get_mut(&$len) {
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

impl target::ext::breakpoints::SwBreakpoint for Emu<'_> {
    fn add_sw_breakpoint(&mut self, addr: u32, _kind: gdbstub_arch::arm::ArmBreakpointKind) -> TargetResult<bool, Self> {
        add_breakpoint!(self, addr, bp_sw_hooks)
    }

    fn remove_sw_breakpoint(&mut self, addr: u32, _kind: gdbstub_arch::arm::ArmBreakpointKind) -> TargetResult<bool, Self> {
        remove_breakpoint!(self, addr, bp_sw_hooks)
    }
}

impl target::ext::breakpoints::HwBreakpoint for Emu<'_> {
    fn add_hw_breakpoint(&mut self, addr: u32, _kind: gdbstub_arch::arm::ArmBreakpointKind) -> TargetResult<bool, Self> {
        add_breakpoint!(self, addr, bp_hw_hooks)
    }

    fn remove_hw_breakpoint(&mut self, addr: u32, _kind: gdbstub_arch::arm::ArmBreakpointKind) -> TargetResult<bool, Self> {
        remove_breakpoint!(self, addr, bp_hw_hooks)
    }
}

impl target::ext::breakpoints::HwWatchpoint for Emu<'_> {
    fn add_hw_watchpoint(&mut self, addr: u32, len: u32, kind: WatchKind) -> TargetResult<bool, Self> {
        match kind {
            WatchKind::Read => add_breakpoint!(self, MEM_READ, addr, len, wp_r_hooks),
            WatchKind::Write => add_breakpoint!(self, MEM_WRITE, addr, len, wp_w_hooks),
            WatchKind::ReadWrite => add_breakpoint!(self, MEM_VALID, addr, len, wp_rw_hooks),
        }
    }

    fn remove_hw_watchpoint(&mut self, addr: u32, len: u32, kind: WatchKind) -> TargetResult<bool, Self> {
        match kind {
            WatchKind::Read => remove_breakpoint!(self, addr, len, wp_r_hooks),
            WatchKind::Write => remove_breakpoint!(self, addr, len, wp_w_hooks),
            WatchKind::ReadWrite => remove_breakpoint!(self, addr, len, wp_rw_hooks),
        }
    }
}
