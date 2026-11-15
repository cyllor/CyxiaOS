//! Complete baseline x86-64 process state with an explicit syscall personality.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserAbi {
    CyxiaNative,
    NativeOs,
    Linux64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Address,
    Argument,
    Active,
    NotReady,
    Unsupported,
    Clock,
    Mapping,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Syscall {
    pub abi: UserAbi,
    pub number: u64,
    pub operation: u64,
    pub args: [u64; 6],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreemptReason {
    Timer,
    Wake,
    Stop,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
    Execute,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultReason {
    NotPresent,
    Permission,
    InvalidInstruction,
    Arithmetic,
    GeneralProtection,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserFault {
    /// Actual exception vector, or 256 for the synthetic SYSCALL entry frame.
    pub vector: u16,
    pub error: u64,
    pub address: u64,
    pub access: Access,
    pub reason: FaultReason,
    pub instruction: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserExit {
    Syscall(Syscall),
    Preempted(PreemptReason),
    Fault(UserFault),
}
/// ISA-specific signal state. Register order: r15,r14,r13,r12,r11,r10,r9,r8,
/// rdi,rsi,rbp,rdx,rcx,rbx,rax. Shared scheduling policy does not interpret it.
#[derive(Clone)]
pub struct X86SignalState {
    pub registers: [u64; 15],
    pub pc: u64,
    pub sp: u64,
    pub status: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    pub fxsave: [u8; 512],
}
#[repr(C, align(16))]
#[derive(Clone)]
pub(crate) struct FxState(pub [u8; 512]);
impl FxState {
    pub const fn empty() -> Self {
        let mut bytes = [0; 512];
        bytes[0] = 0x7f;
        bytes[1] = 3;
        bytes[24] = 0x80;
        bytes[25] = 0x1f;
        Self(bytes)
    }
}
// Same register order as TrapFrame; keep actual CPU state out of shared policy.
#[repr(C, align(16))]
#[derive(Clone)]
pub struct Context {
    pub(crate) registers: [u64; 15], // r15,r14,r13,r12,r11,r10,r9,r8,rdi,rsi,rbp,rdx,rcx,rbx,rax
    pub(crate) instruction: u64,
    pub(crate) stack: u64,
    pub(crate) flags: u64,
    pub(crate) fs_base: u64,
    pub(crate) gs_base: u64,
    pub(crate) fx: FxState,
    pub(crate) personality: UserAbi,
    pub(crate) exit: Option<UserExit>,
    pub(crate) syscall_pc: u64,
}
impl Context {
    pub const fn empty() -> Self {
        Self {
            registers: [0; 15],
            instruction: 0,
            stack: 0,
            flags: 0x202,
            fs_base: 0,
            gs_base: 0,
            fx: FxState::empty(),
            personality: UserAbi::CyxiaNative,
            exit: None,
            syscall_pc: 0,
        }
    }
    pub fn initialize(&mut self, entry: u64, stack: u64, abi: UserAbi) -> Result<(), Error> {
        user_address(entry)?;
        user_address(stack)?;
        if stack % 16 != 0 {
            return Err(Error::Address);
        }
        *self = Self::empty();
        self.instruction = entry;
        self.stack = stack;
        self.personality = abi;
        Ok(())
    }
    pub fn abi(&self) -> UserAbi {
        self.personality
    }
    pub fn pc(&self) -> u64 {
        self.instruction
    }
    pub fn set_pc(&mut self, value: u64) -> Result<(), Error> {
        user_address(value)?;
        self.instruction = value;
        Ok(())
    }
    pub fn sp(&self) -> u64 {
        self.stack
    }
    pub fn set_sp(&mut self, value: u64) -> Result<(), Error> {
        user_address(value)?;
        self.stack = value;
        Ok(())
    }
    pub fn tls(&self) -> u64 {
        self.fs_base
    }
    pub fn set_tls(&mut self, value: u64) -> Result<(), Error> {
        if value >= 0x0000_8000_0000_0000 {
            return Err(Error::Address);
        }
        self.fs_base = value;
        Ok(())
    }
    pub fn argument(&self, index: usize) -> Option<u64> {
        [8, 9, 11, 5, 7, 6]
            .get(index)
            .map(|&register| self.registers[register])
    }
    pub fn set_argument(&mut self, index: usize, value: u64) -> Result<(), Error> {
        let register = *[8, 9, 11, 5, 7, 6].get(index).ok_or(Error::Argument)?;
        self.registers[register] = value;
        Ok(())
    }
    pub fn set_native_operation(&mut self, value: u64) {
        self.registers[6] = value;
    }
    pub fn result(&self) -> u64 {
        self.registers[if self.personality != UserAbi::CyxiaNative {
            14
        } else {
            8
        }]
    }
    pub fn set_result(&mut self, value: u64) {
        let i = if self.personality != UserAbi::CyxiaNative {
            14
        } else {
            8
        };
        self.registers[i] = value;
    }
    pub fn set_results(&mut self, values: [u64; 4]) {
        if self.personality != UserAbi::CyxiaNative {
            self.registers[14] = values[0];
        } else {
            for (i, value) in values.into_iter().enumerate() {
                let _ = self.set_argument(i, value);
            }
        }
    }
    pub fn syscall(&self) -> Option<Syscall> {
        if let Some(UserExit::Syscall(call)) = self.exit {
            Some(call)
        } else {
            None
        }
    }
    pub fn last_exit(&self) -> Option<UserExit> {
        self.exit
    }
    pub fn restart_syscall(&mut self) -> Result<(), Error> {
        let call = self.syscall().ok_or(Error::NotReady)?;
        if self.syscall_pc < 4096 {
            return Err(Error::NotReady);
        }
        self.registers[14] = call.number;
        for (index, value) in call.args.into_iter().enumerate() {
            self.set_argument(index, value)?;
        }
        self.instruction = self.syscall_pc;
        Ok(())
    }
    pub fn clone_for_thread(&self, stack: u64, tls: u64) -> Result<Self, Error> {
        let mut child = self.clone();
        child.set_sp(stack)?;
        child.set_tls(tls)?;
        child.set_result(0);
        child.exit = None;
        Ok(child)
    }
    pub fn signal_state(&self) -> X86SignalState {
        X86SignalState {
            registers: self.registers,
            pc: self.instruction,
            sp: self.stack,
            status: self.flags,
            fs_base: self.fs_base,
            gs_base: self.gs_base,
            fxsave: self.fx.0,
        }
    }
    pub fn restore_signal_state(&mut self, state: X86SignalState) -> Result<(), Error> {
        user_address(state.pc)?;
        user_address(state.sp)?;
        if state.fs_base >= 0x0000_8000_0000_0000
            || state.gs_base >= 0x0000_8000_0000_0000
            || state.status & ((3 << 12) | (1 << 14) | (1 << 17)) != 0
        {
            return Err(Error::Address);
        }
        let saved_mask = u32::from_le_bytes(self.fx.0[28..32].try_into().unwrap());
        let mask = if saved_mask == 0 { 0xffbf } else { saved_mask };
        let mxcsr = u32::from_le_bytes(state.fxsave[24..28].try_into().unwrap());
        if mxcsr & !mask != 0 {
            return Err(Error::Argument);
        }
        self.registers = state.registers;
        self.instruction = state.pc;
        self.stack = state.sp;
        self.flags = (state.status & 0x240cd5) | 0x202;
        self.fs_base = state.fs_base;
        self.gs_base = state.gs_base;
        self.fx = FxState(state.fxsave);
        // MXCSR_MASK is processor authority, not restorable user state. Keep
        // its original hardware value (including the architectural zero-mask
        // fallback) so another restore or a clone cannot expand permission.
        self.fx.0[28..32].copy_from_slice(&saved_mask.to_le_bytes());
        self.exit = None;
        self.syscall_pc = 0;
        Ok(())
    }
}
fn user_address(value: u64) -> Result<(), Error> {
    if !(4096..0x0000_8000_0000_0000).contains(&value) {
        Err(Error::Address)
    } else {
        Ok(())
    }
}
