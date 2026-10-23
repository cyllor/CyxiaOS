//! Bounded signal dispositions, masks, pending delivery and AArch64 signal frames.
//!
//! Linux arm64 UAPI layouts (not copied implementation):
//! <https://github.com/torvalds/linux/blob/v6.12/arch/arm64/include/uapi/asm/sigcontext.h>
//! <https://github.com/torvalds/linux/blob/v6.12/arch/arm64/include/uapi/asm/ucontext.h>
//! The shipped musl 1.2.6 aarch64 bits/signal.h agrees with these offsets.
//! Bounded per-thread alternate stacks; no handler syscall restart, job control,
//! SVE/SME, or siglongjmp. Sigreturn restores a validated uc_stack descriptor.
//! Each realtime signal has one pending slot; overflow returns Again, never
//! silently coalesces. Standard signals coalesce as required by their ABI.
use crate::Errno;

pub const COUNT: usize = 64;
pub const MAX_FRAMES: usize = 4;
pub const SA_SIGINFO: u64 = 4;
pub const SA_NOCLDSTOP: u64 = 1;
pub const SA_ONSTACK: u64 = 0x08000000;
pub const SA_RESTART: u64 = 0x10000000;
pub const SA_RESTORER: u64 = 0x04000000;
pub const SA_NODEFER: u64 = 0x40000000;
pub const SA_RESETHAND: u64 = 0x80000000;
// No job-control stop notifications exist yet; this flag suppresses such
// notifications and is retained in the action for later child-process support.
pub const SUPPORTED_FLAGS: u64 =
    SA_NOCLDSTOP | SA_SIGINFO | SA_RESTORER | SA_NODEFER | SA_RESETHAND | SA_ONSTACK;
pub const MINSIGSTKSZ: u64 = 6144;
const UNBLOCKABLE: u64 = (1 << 8) | (1 << 18);
pub const SIGINFO_BYTES: usize = 128;
pub const UCONTEXT_OFFSET: usize = 128;
pub const MCONTEXT_OFFSET: usize = 304;
pub const FPSIMD_OFFSET: usize = 592;
pub const RT_FRAME_BYTES: usize = 4688;
/// Includes the AArch64 frame-pointer record immediately above rt_sigframe.
pub const FRAME_BYTES: usize = RT_FRAME_BYTES + 16;
const FPSIMD_MAGIC: u32 = 0x46508001;
const FPSIMD_BYTES: usize = 528;
const NZCV: u64 = 0xf0000000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Action {
    pub handler: u64,
    pub flags: u64,
    pub restorer: u64,
    pub mask: u64,
}
impl Action {
    pub const DEFAULT: Self = Self {
        handler: 0,
        flags: 0,
        restorer: 0,
        mask: 0,
    };
    pub fn decode(bytes: &[u8; 32]) -> Result<Self, Errno> {
        // musl's public sa_flags is signed int, while its k_sigaction.flags is
        // unsigned long. SA_RESETHAND therefore arrives sign-extended on LP64.
        // Accept only canonical zero/int32 extensions; unrelated high bits
        // remain invalid instead of being silently truncated.
        let raw_flags = get64(bytes, 8);
        let narrow_flags = raw_flags as u32;
        if raw_flags != u64::from(narrow_flags) && raw_flags != (narrow_flags as i32 as i64) as u64
        {
            return Err(Errno::Inval);
        }
        let action = Self {
            handler: get64(bytes, 0),
            flags: u64::from(narrow_flags),
            restorer: get64(bytes, 16),
            mask: get64(bytes, 24) & !UNBLOCKABLE,
        };
        action.validate()?;
        Ok(action)
    }
    pub fn encode(self) -> [u8; 32] {
        let mut bytes = [0; 32];
        for (i, value) in [self.handler, self.flags, self.restorer, self.mask]
            .iter()
            .enumerate()
        {
            put64(&mut bytes, i * 8, *value);
        }
        bytes
    }
    pub fn validate(self) -> Result<(), Errno> {
        // SIG_DFL/SIG_IGN never invoke a returning handler, so retaining
        // SA_RESTART creates no syscall-restart obligation. Real handlers
        // still reject it until interrupted syscall restarts are implemented.
        let supported = SUPPORTED_FLAGS | if self.handler <= 1 { SA_RESTART } else { 0 };
        if self.flags & !supported != 0
            || (self.handler > 1
                && (!user_pc(self.handler)
                    || self.flags & SA_RESTORER == 0
                    || !user_pc(self.restorer)))
        {
            return Err(Errno::Inval);
        }
        Ok(())
    }
}

/// Already-owned user memory, not a new allocation or an AI resource grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AltStack {
    pub base: u64,
    pub size: u64,
}
impl AltStack {
    pub const DISABLED: Self = Self { base: 0, size: 0 };
    pub fn contains(self, sp: u64) -> bool {
        self.size != 0 && sp > self.base && sp <= self.base.saturating_add(self.size)
    }
    pub fn decode(bytes: &[u8; 24], setting: bool) -> Result<Self, Errno> {
        let flags = get32(bytes, 8);
        if flags == 2 {
            if !setting && (get64(bytes, 0) != 0 || get64(bytes, 16) != 0) {
                return Err(Errno::Inval);
            }
            return Ok(Self::DISABLED);
        }
        if flags != 0 && (setting || flags != 1) {
            return Err(Errno::Inval);
        }
        let stack = Self {
            base: get64(bytes, 0),
            size: get64(bytes, 16),
        };
        if stack.size < MINSIGSTKSZ {
            return Err(Errno::Nomem);
        }
        if stack.base == 0 || stack.base.checked_add(stack.size).is_none() {
            return Err(Errno::Inval);
        }
        Ok(stack)
    }
    pub fn encode(self, sp: u64) -> [u8; 24] {
        let mut bytes = [0; 24];
        put64(&mut bytes, 0, self.base);
        put32(
            &mut bytes,
            8,
            if self.size == 0 {
                2
            } else {
                u32::from(self.contains(sp))
            },
        );
        put64(&mut bytes, 16, self.size);
        bytes
    }
    pub fn frame_address(self, sp: u64, on_stack: bool) -> Result<u64, Errno> {
        let switch = on_stack && self.size != 0 && !self.contains(sp);
        let top = if switch {
            self.base.checked_add(self.size).ok_or(Errno::Fault)?
        } else {
            sp
        };
        let address = frame_address(top)?;
        if (switch || self.contains(sp)) && address < self.base {
            return Err(Errno::Fault);
        }
        Ok(address)
    }
}

pub fn set_frame_stack(bytes: &mut [u8; FRAME_BYTES], stack: AltStack, sp: u64) {
    bytes[UCONTEXT_OFFSET + 16..UCONTEXT_OFFSET + 40].copy_from_slice(&stack.encode(sp));
}
pub fn frame_stack(bytes: &[u8; FRAME_BYTES]) -> Result<AltStack, Errno> {
    AltStack::decode(
        bytes[UCONTEXT_OFFSET + 16..UCONTEXT_OFFSET + 40]
            .try_into()
            .unwrap(),
        false,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    pub code: i32,
    pub sender_pid: u32,
    pub address: u64,
}
impl Info {
    pub const EMPTY: Self = Self {
        code: 0,
        sender_pid: 0,
        address: 0,
    };
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    Ignore(u32),
    Terminate(u32),
    Handler {
        signal: u32,
        action: Action,
        info: Info,
    },
}
#[derive(Clone, Copy)]
struct ActiveFrame {
    address: u64,
    tls: u64,
}
const EMPTY_FRAME: ActiveFrame = ActiveFrame { address: 0, tls: 0 };

/// One disposition table shared by all threads in a process.
pub struct Actions {
    actions: [Action; COUNT],
}
impl Default for Actions {
    fn default() -> Self {
        Self::new()
    }
}
impl Actions {
    pub const fn new() -> Self {
        Self {
            actions: [Action::DEFAULT; COUNT],
        }
    }
    pub fn action(&self, signal: u32) -> Result<Action, Errno> {
        Ok(self.actions[index(signal)?])
    }
    pub fn validate_action(signal: u32, action: Action) -> Result<(), Errno> {
        index(signal)?;
        if signal == 9 || signal == 19 {
            return Err(Errno::Inval);
        }
        action.validate()
    }
    pub fn set_action(&mut self, signal: u32, mut action: Action) -> Result<(), Errno> {
        Self::validate_action(signal, action)?;
        action.mask &= !UNBLOCKABLE;
        self.actions[index(signal)?] = action;
        Ok(())
    }
    /// exec discards installed handlers and preserves explicit SIG_IGN.
    pub fn for_exec(&self) -> Self {
        Self {
            actions: core::array::from_fn(|i| {
                if self.actions[i].handler == 1 {
                    self.actions[i]
                } else {
                    Action::DEFAULT
                }
            }),
        }
    }
    pub fn ignored(&self, signal: u32) -> Result<bool, Errno> {
        let action = self.action(signal)?;
        Ok(action.handler == 1 || (action.handler == 0 && default_ignored(signal)))
    }
}

pub struct Signals {
    mask: u64,
    pending: u64,
    forced: u64,
    infos: [Info; COUNT],
    frames: [ActiveFrame; MAX_FRAMES],
    depth: usize,
}
impl Default for Signals {
    fn default() -> Self {
        Self::new()
    }
}
impl Signals {
    pub const fn new() -> Self {
        Self {
            mask: 0,
            pending: 0,
            forced: 0,
            infos: [Info::EMPTY; COUNT],
            frames: [EMPTY_FRAME; MAX_FRAMES],
            depth: 0,
        }
    }
    pub fn mask(&self) -> u64 {
        self.mask
    }
    pub fn changed_mask(&self, how: u64, set: u64) -> Result<u64, Errno> {
        Ok(match how {
            0 => self.mask | set,
            1 => self.mask & !set,
            2 => set,
            _ => return Err(Errno::Inval),
        } & !UNBLOCKABLE)
    }
    pub fn set_mask(&mut self, mask: u64) {
        self.mask = mask & !UNBLOCKABLE;
    }
    pub fn pending(&self) -> u64 {
        self.pending
    }
    pub fn ready(&self) -> bool {
        self.pending & (!self.mask | self.forced) != 0
    }
    /// Forced synchronous faults cannot remain ignored or blocked indefinitely.
    pub fn raise(
        &mut self,
        actions: &Actions,
        signal: u32,
        info: Info,
        forced: bool,
    ) -> Result<(), Errno> {
        let i = index(signal)?;
        if (18..=22).contains(&signal) {
            return Err(Errno::Nosys);
        }
        let bit = 1u64 << i;
        if !forced
            && (actions.actions[i].handler == 1
                || (actions.actions[i].handler == 0 && default_ignored(signal)))
        {
            return Ok(());
        }
        if signal >= 32 && self.pending & bit != 0 && !forced {
            return Err(Errno::Again);
        }
        if self.pending & bit == 0 || forced {
            self.infos[i] = info;
        }
        self.pending |= bit;
        if forced {
            self.forced |= bit;
        }
        Ok(())
    }
    pub fn next(&self, actions: &Actions) -> Option<Delivery> {
        let ready = self.pending & (!self.mask | self.forced);
        if ready == 0 {
            return None;
        }
        // SIGKILL takes priority over every catchable signal.
        let i = if ready & (1 << 8) != 0 {
            8
        } else {
            ready.trailing_zeros() as usize
        };
        let signal = i as u32 + 1;
        let action = actions.actions[i];
        if self.forced & (1 << i) != 0 && (self.mask & (1 << i) != 0 || action.handler == 1) {
            return Some(Delivery::Terminate(signal));
        }
        Some(match action.handler {
            1 => Delivery::Ignore(signal),
            0 if default_ignored(signal) => Delivery::Ignore(signal),
            0 => Delivery::Terminate(signal),
            _ => Delivery::Handler {
                signal,
                action,
                info: self.infos[i],
            },
        })
    }
    pub fn transfer_ready(&mut self, target: &mut Signals, actions: &Actions) {
        let available = self.pending & !target.mask;
        for i in 0..COUNT {
            if available & (1u64 << i) != 0 {
                let signal = i as u32 + 1;
                if target.raise(actions, signal, self.infos[i], false).is_ok() {
                    // Valid number, and successful enqueue precedes removal.
                    let _ = self.consume(signal);
                }
            }
        }
    }
    pub fn consume(&mut self, signal: u32) -> Result<(), Errno> {
        let i = index(signal)?;
        self.pending &= !(1 << i);
        self.forced &= !(1 << i);
        self.infos[i] = Info::EMPTY;
        Ok(())
    }
    pub fn can_enter(&self) -> Result<(), Errno> {
        if self.depth == MAX_FRAMES {
            Err(Errno::Overflow)
        } else {
            Ok(())
        }
    }
    /// Call only after the entire user frame has been written successfully.
    pub fn enter(
        &mut self,
        actions: &mut Actions,
        signal: u32,
        address: u64,
        tls: u64,
    ) -> Result<(), Errno> {
        self.can_enter()?;
        let action = actions.action(signal)?;
        if !matches!(self.next(actions), Some(Delivery::Handler { signal: s, .. }) if s == signal)
            || !address.is_multiple_of(16)
        {
            return Err(Errno::Inval);
        }
        self.consume(signal)?;
        self.frames[self.depth] = ActiveFrame { address, tls };
        self.depth += 1;
        self.mask |= action.mask;
        if action.flags & SA_NODEFER == 0 {
            self.mask |= 1 << (signal - 1);
        }
        self.mask &= !UNBLOCKABLE;
        if action.flags & SA_RESETHAND != 0 {
            actions.actions[signal as usize - 1] = Action::DEFAULT;
        }
        Ok(())
    }
    pub fn frame_tls(&self, address: u64) -> Result<u64, Errno> {
        if self.depth == 0 || self.frames[self.depth - 1].address != address {
            return Err(Errno::Fault);
        }
        Ok(self.frames[self.depth - 1].tls)
    }
    /// Commit a fully validated frame return, including a handler-edited mask.
    pub fn leave(&mut self, address: u64, mask: u64) -> Result<(), Errno> {
        self.frame_tls(address)?;
        self.depth -= 1;
        self.frames[self.depth] = EMPTY_FRAME;
        self.set_mask(mask);
        Ok(())
    }
}
fn index(signal: u32) -> Result<usize, Errno> {
    if !(1..=64).contains(&signal) {
        Err(Errno::Inval)
    } else {
        Ok(signal as usize - 1)
    }
}
fn default_ignored(signal: u32) -> bool {
    matches!(signal, 17 | 23 | 28)
}
fn user_pc(pc: u64) -> bool {
    pc != 0 && pc < (1u64 << 48) && pc.is_multiple_of(4)
}

/// Architecture-neutral bytes of the AArch64 user state; no hardware FP access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameState {
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
    pub fault_address: u64,
    pub simd: [[u64; 2]; 32],
    pub fpsr: u32,
    pub fpcr: u32,
}
impl FrameState {
    pub const EMPTY: Self = Self {
        regs: [0; 31],
        sp: 0,
        pc: 0,
        pstate: 0,
        fault_address: 0,
        simd: [[0; 2]; 32],
        fpsr: 0,
        fpcr: 0,
    };
    fn validate(&self) -> Result<(), Errno> {
        if !user_pc(self.pc)
            || self.sp == 0
            || self.sp >= (1u64 << 48)
            || !self.sp.is_multiple_of(16)
            || self.pstate & !NZCV != 0
        {
            return Err(Errno::Inval);
        }
        Ok(())
    }
}
pub fn frame_address(sp: u64) -> Result<u64, Errno> {
    let address = sp.checked_sub(FRAME_BYTES as u64).ok_or(Errno::Fault)? & !15;
    if address == 0 || sp >= (1u64 << 48) {
        return Err(Errno::Fault);
    }
    Ok(address)
}

pub fn encode_frame(
    out: &mut [u8; FRAME_BYTES],
    state: &FrameState,
    mask: u64,
    signal: u32,
    info: Info,
) -> Result<(), Errno> {
    index(signal)?;
    // Interrupted PC/SP may themselves be invalid (for example an attempted
    // branch to an unmapped address). The handler must be able to inspect and
    // repair them; validation belongs to sigreturn, before restoring execution.
    if state.pstate & !NZCV != 0 {
        return Err(Errno::Inval);
    }
    out.fill(0);
    put32(out, 0, signal);
    put32(out, 8, info.code as u32);
    if signal == 17 && info.code > 0 {
        // SIGCHLD's union is pid/uid/status, not the fault-address union.
        put32(out, 16, info.sender_pid);
        put32(out, 24, info.address as u32);
    } else if info.code <= 0 {
        put32(out, 16, info.sender_pid);
    } else {
        put64(out, 16, info.address);
    }
    put32(out, UCONTEXT_OFFSET + 24, 2); // SS_DISABLE: no alternate stack.
    put64(out, UCONTEXT_OFFSET + 40, mask & !UNBLOCKABLE);
    put64(out, MCONTEXT_OFFSET, state.fault_address);
    for (i, reg) in state.regs.iter().enumerate() {
        put64(out, MCONTEXT_OFFSET + 8 + i * 8, *reg);
    }
    put64(out, MCONTEXT_OFFSET + 256, state.sp);
    put64(out, MCONTEXT_OFFSET + 264, state.pc);
    put64(out, MCONTEXT_OFFSET + 272, state.pstate);
    put32(out, FPSIMD_OFFSET, FPSIMD_MAGIC);
    put32(out, FPSIMD_OFFSET + 4, FPSIMD_BYTES as u32);
    put32(out, FPSIMD_OFFSET + 8, state.fpsr);
    put32(out, FPSIMD_OFFSET + 12, state.fpcr);
    for (i, reg) in state.simd.iter().enumerate() {
        put64(out, FPSIMD_OFFSET + 16 + i * 16, reg[0]);
        put64(out, FPSIMD_OFFSET + 24 + i * 16, reg[1]);
    }
    put64(out, RT_FRAME_BYTES, state.regs[29]);
    put64(out, RT_FRAME_BYTES + 8, state.regs[30]);
    Ok(())
}

/// Exact bounded FPSIMD layout only. The kernel additionally verifies that the
/// alternate-stack descriptor describes writable user memory before restoring it.
pub fn decode_frame(bytes: &[u8; FRAME_BYTES]) -> Result<(FrameState, u64), Errno> {
    frame_stack(bytes)?;
    if get64(bytes, UCONTEXT_OFFSET) != 0
        || get64(bytes, UCONTEXT_OFFSET + 8) != 0
        || get32(bytes, FPSIMD_OFFSET) != FPSIMD_MAGIC
        || get32(bytes, FPSIMD_OFFSET + 4) != FPSIMD_BYTES as u32
        || bytes[FPSIMD_OFFSET + FPSIMD_BYTES..RT_FRAME_BYTES]
            .iter()
            .any(|b| *b != 0)
    {
        return Err(Errno::Inval);
    }
    let mut state = FrameState::EMPTY;
    state.fault_address = get64(bytes, MCONTEXT_OFFSET);
    for (i, reg) in state.regs.iter_mut().enumerate() {
        *reg = get64(bytes, MCONTEXT_OFFSET + 8 + i * 8);
    }
    state.sp = get64(bytes, MCONTEXT_OFFSET + 256);
    state.pc = get64(bytes, MCONTEXT_OFFSET + 264);
    state.pstate = get64(bytes, MCONTEXT_OFFSET + 272);
    state.fpsr = get32(bytes, FPSIMD_OFFSET + 8);
    state.fpcr = get32(bytes, FPSIMD_OFFSET + 12);
    for (i, reg) in state.simd.iter_mut().enumerate() {
        *reg = [
            get64(bytes, FPSIMD_OFFSET + 16 + i * 16),
            get64(bytes, FPSIMD_OFFSET + 24 + i * 16),
        ];
    }
    state.validate()?;
    Ok((state, get64(bytes, UCONTEXT_OFFSET + 40) & !UNBLOCKABLE))
}
fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn get32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn get64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

const _: () = {
    assert!(MCONTEXT_OFFSET == UCONTEXT_OFFSET + 176);
    assert!(FPSIMD_OFFSET == MCONTEXT_OFFSET + 288);
    assert!(RT_FRAME_BYTES == FPSIMD_OFFSET + 4096);
    assert!(FRAME_BYTES.is_multiple_of(16));
};

#[cfg(test)]
mod tests {
    use super::*;

    fn handler(flags: u64) -> Action {
        Action {
            handler: 0x01001000,
            restorer: 0x01002000,
            flags: flags | SA_RESTORER,
            mask: 0,
        }
    }
    fn state() -> FrameState {
        let mut state = FrameState {
            pc: 0x01003000,
            sp: 0x03008000,
            pstate: 0xa0000000,
            fpcr: 0x400000,
            fpsr: 0x8000001,
            fault_address: 0x12345,
            ..FrameState::EMPTY
        };
        for (i, reg) in state.regs.iter_mut().enumerate() {
            *reg = 0x100 + i as u64;
        }
        for (i, reg) in state.simd.iter_mut().enumerate() {
            *reg = [i as u64, !(i as u64)];
        }
        state
    }

    struct TestSignals {
        actions: Actions,
        signals: Signals,
    }
    impl core::ops::Deref for TestSignals {
        type Target = Signals;
        fn deref(&self) -> &Signals {
            &self.signals
        }
    }
    impl core::ops::DerefMut for TestSignals {
        fn deref_mut(&mut self) -> &mut Signals {
            &mut self.signals
        }
    }
    impl TestSignals {
        fn new() -> Self {
            Self {
                actions: Actions::new(),
                signals: Signals::new(),
            }
        }
        fn action(&self, n: u32) -> Result<Action, Errno> {
            self.actions.action(n)
        }
        fn set_action(&mut self, n: u32, a: Action) -> Result<(), Errno> {
            self.actions.set_action(n, a)?;
            if self.actions.ignored(n)? {
                self.signals.consume(n)?;
            }
            Ok(())
        }
        fn raise(&mut self, n: u32, i: Info, f: bool) -> Result<(), Errno> {
            self.signals.raise(&self.actions, n, i, f)
        }
        fn next(&self) -> Option<Delivery> {
            self.signals.next(&self.actions)
        }
        fn enter(&mut self, n: u32, a: u64, t: u64) -> Result<(), Errno> {
            self.signals.enter(&mut self.actions, n, a, t)
        }
    }
    #[test]
    fn threads_share_dispositions_but_keep_masks_pending_and_frames_separate() {
        let mut actions = Actions::new();
        let mut a = Signals::new();
        let mut b = Signals::new();
        let mut process = Signals::new();
        actions.set_action(13, handler(SA_RESETHAND)).unwrap();
        a.set_mask(1 << 12);
        process.raise(&actions, 13, Info::EMPTY, false).unwrap();
        process.transfer_ready(&mut a, &actions);
        assert_eq!(a.pending(), 0);
        assert_eq!(process.pending(), 1 << 12);
        process.transfer_ready(&mut b, &actions);
        assert_eq!(process.pending(), 0);
        b.enter(&mut actions, 13, 0x03006000, 0x01005000).unwrap();
        assert_eq!(actions.action(13), Ok(Action::DEFAULT));
        assert_eq!(a.frame_tls(0x03006000), Err(Errno::Fault));
        assert_eq!(b.frame_tls(0x03006000), Ok(0x01005000));
        a.raise(&actions, 13, Info::EMPTY, false).unwrap();
        assert_eq!(a.next(&actions), None);
        a.set_mask(0);
        assert_eq!(a.next(&actions), Some(Delivery::Terminate(13)));
    }

    #[test]
    fn action_roundtrip_and_unsupported_flags_are_explicit() {
        let action = handler(SA_SIGINFO | SA_NODEFER | SA_RESETHAND);
        assert_eq!(Action::decode(&action.encode()), Ok(action));
        let mut signals = TestSignals::new();
        assert_eq!(
            Action::decode(&handler(SA_NOCLDSTOP).encode()),
            Ok(handler(SA_NOCLDSTOP))
        );
        assert_eq!(handler(SA_ONSTACK).validate(), Ok(()));
        for disposition in [0, 1] {
            let action = Action {
                handler: disposition,
                flags: SA_RESTART,
                ..Action::DEFAULT
            };
            assert_eq!(Action::decode(&action.encode()), Ok(action));
        }
        for flags in [SA_RESTART, 2, 1u64 << 63] {
            assert_eq!(signals.set_action(11, handler(flags)), Err(Errno::Inval));
        }
        for action in [
            Action {
                flags: 0,
                ..handler(0)
            },
            Action {
                handler: 3,
                ..handler(0)
            },
            Action {
                restorer: 0,
                ..handler(0)
            },
            Action {
                handler: 0xffff000000000000,
                ..handler(0)
            },
        ] {
            assert_eq!(signals.set_action(11, action), Err(Errno::Inval));
        }
        for number in [0, 9, 19, 65, u32::MAX] {
            assert_eq!(signals.set_action(number, handler(0)), Err(Errno::Inval));
        }
        assert_eq!(signals.action(11), Ok(Action::DEFAULT));
    }

    #[test]
    fn alternate_stack_status_bounds_and_nested_frame_placement() {
        let stack = AltStack {
            base: 0x0400_0000,
            size: 32768,
        };
        let normal_sp = 0x0300_8000;
        assert_eq!(AltStack::decode(&stack.encode(normal_sp), true), Ok(stack));
        let first = stack.frame_address(normal_sp, true).unwrap();
        assert_eq!(first, stack.base + stack.size - FRAME_BYTES as u64);
        assert_eq!(get32(&stack.encode(first), 8), 1);
        assert_eq!(
            AltStack::decode(&stack.encode(first), true),
            Err(Errno::Inval)
        );
        assert_eq!(AltStack::decode(&stack.encode(first), false), Ok(stack));
        let nested = stack.frame_address(first, true).unwrap();
        assert_eq!(nested, first - FRAME_BYTES as u64);
        assert_eq!(
            stack.frame_address(normal_sp, false),
            frame_address(normal_sp)
        );
        assert_eq!(
            stack.frame_address(stack.base + 16, false),
            Err(Errno::Fault)
        );
        assert_eq!(
            AltStack::DISABLED.frame_address(normal_sp, true),
            frame_address(normal_sp)
        );
        let mut frame = [0; FRAME_BYTES];
        encode_frame(&mut frame, &state(), 0, 11, Info::EMPTY).unwrap();
        set_frame_stack(&mut frame, stack, normal_sp);
        assert_eq!(frame_stack(&frame), Ok(stack));
        assert_eq!(decode_frame(&frame).unwrap().0, state());
    }

    #[test]
    fn alternate_stack_rejects_small_unknown_and_overflowing_ranges() {
        let stack = AltStack {
            base: 0x0400_0000,
            size: MINSIGSTKSZ,
        };
        let encoded = stack.encode(0);
        for flags in [1, 3, 0x8000_0000] {
            let mut bytes = encoded;
            put32(&mut bytes, 8, flags);
            assert_eq!(AltStack::decode(&bytes, true), Err(Errno::Inval));
        }
        let mut bytes = encoded;
        put64(&mut bytes, 16, MINSIGSTKSZ - 1);
        assert_eq!(AltStack::decode(&bytes, true), Err(Errno::Nomem));
        put64(&mut bytes, 16, MINSIGSTKSZ);
        put64(&mut bytes, 0, u64::MAX - MINSIGSTKSZ + 1);
        assert_eq!(AltStack::decode(&bytes, true), Err(Errno::Inval));
        put32(&mut bytes, 8, 2);
        assert_eq!(AltStack::decode(&bytes, true), Ok(AltStack::DISABLED));
        assert_eq!(AltStack::decode(&bytes, false), Err(Errno::Inval));
        assert_eq!(
            AltStack::decode(&AltStack::DISABLED.encode(0), false),
            Ok(AltStack::DISABLED)
        );
    }

    #[test]
    fn musl_sign_extended_sa_resethand_is_normalized_without_accepting_unknown_bits() {
        let action = handler(SA_SIGINFO | SA_RESETHAND);
        let mut encoded = action.encode();
        put64(&mut encoded, 8, 0xffff_ffff_8400_0004);
        assert_eq!(Action::decode(&encoded), Ok(action));
        for flags in [
            0xffff_ffff_0400_0004,
            0x0000_0001_8400_0004,
            0xffff_fffe_8400_0004,
            0xffff_ffff_9400_0004,
        ] {
            put64(&mut encoded, 8, flags);
            assert_eq!(Action::decode(&encoded), Err(Errno::Inval));
        }
    }

    #[test]
    fn masks_cannot_block_kill_or_stop_and_changes_are_explicit() {
        let mut signals = TestSignals::new();
        signals.set_mask(u64::MAX);
        assert_eq!(signals.mask(), !UNBLOCKABLE);
        assert_eq!(signals.changed_mask(1, u64::MAX), Ok(0));
        assert_eq!(signals.changed_mask(2, 1 << 10), Ok(1 << 10));
        assert_eq!(signals.changed_mask(3, 0), Err(Errno::Inval));
        signals.raise(9, Info::EMPTY, false).unwrap();
        assert!(signals.ready());
        assert_eq!(signals.next(), Some(Delivery::Terminate(9)));
    }

    #[test]
    fn standard_signals_coalesce_first_info_and_defaults_are_real() {
        let mut signals = TestSignals::new();
        signals.set_action(13, handler(0)).unwrap();
        let first = Info {
            code: 0,
            sender_pid: 7,
            address: 0,
        };
        signals.raise(13, first, false).unwrap();
        signals.raise(13, Info::EMPTY, false).unwrap();
        assert_eq!(
            signals.next(),
            Some(Delivery::Handler {
                signal: 13,
                action: handler(0),
                info: first
            })
        );
        signals.raise(9, Info::EMPTY, false).unwrap();
        assert_eq!(signals.next(), Some(Delivery::Terminate(9)));
        for number in [4, 11, 13, 15] {
            let mut fresh = TestSignals::new();
            fresh.raise(number, Info::EMPTY, false).unwrap();
            assert_eq!(fresh.next(), Some(Delivery::Terminate(number)));
        }
    }

    #[test]
    fn realtime_second_instance_is_rejected_instead_of_lost() {
        let mut signals = TestSignals::new();
        for number in 32..=64 {
            signals.raise(number, Info::EMPTY, false).unwrap();
            assert_eq!(signals.raise(number, Info::EMPTY, false), Err(Errno::Again));
        }
        assert_eq!(signals.pending().count_ones(), 33);
        for number in 18..=22 {
            assert_eq!(signals.raise(number, Info::EMPTY, false), Err(Errno::Nosys));
        }
    }

    #[test]
    fn ignored_pending_is_removed_and_forced_faults_cannot_hide() {
        let mut signals = TestSignals::new();
        signals.set_action(11, handler(0)).unwrap();
        signals.set_mask(1 << 10);
        signals.raise(11, Info::EMPTY, false).unwrap();
        assert!(!signals.ready());
        signals.raise(11, Info::EMPTY, true).unwrap();
        assert_eq!(signals.next(), Some(Delivery::Terminate(11)));
        signals
            .set_action(
                11,
                Action {
                    handler: 1,
                    ..Action::DEFAULT
                },
            )
            .unwrap();
        assert_eq!(signals.pending(), 0);
        signals.raise(11, Info::EMPTY, false).unwrap();
        assert_eq!(signals.pending(), 0);
        signals.raise(11, Info::EMPTY, true).unwrap();
        assert_eq!(signals.next(), Some(Delivery::Terminate(11)));
        for number in [17, 23, 28] {
            signals.raise(number, Info::EMPTY, false).unwrap();
            assert_eq!(signals.pending() & (1 << (number - 1)), 0);
        }
    }

    #[test]
    fn reset_hand_and_masks_commit_only_after_frame_publication() {
        let mut signals = TestSignals::new();
        let action = Action {
            mask: (1 << 14) | UNBLOCKABLE,
            ..handler(SA_RESETHAND)
        };
        signals.set_action(11, action).unwrap();
        signals.raise(11, Info::EMPTY, false).unwrap();
        assert_ne!(signals.action(11).unwrap().handler, 0);
        signals.enter(11, 0x03006000, 0x01005000).unwrap();
        assert_eq!(signals.mask(), (1 << 10) | (1 << 14));
        assert_eq!(signals.action(11), Ok(Action::DEFAULT));
        assert_eq!(signals.frame_tls(0x03006000), Ok(0x01005000));
        assert_eq!(signals.leave(0x03006010, 0), Err(Errno::Fault));
        signals.leave(0x03006000, u64::MAX).unwrap();
        assert_eq!(signals.mask(), !UNBLOCKABLE);
        assert_eq!(signals.frame_tls(0x03006000), Err(Errno::Fault));
    }

    #[test]
    fn nodefer_nested_frames_preserve_each_tls_and_enforce_bound() {
        let mut signals = TestSignals::new();
        signals.set_action(13, handler(SA_NODEFER)).unwrap();
        for depth in 0..MAX_FRAMES {
            signals.raise(13, Info::EMPTY, false).unwrap();
            signals
                .enter(13, 0x03007000 - depth as u64 * 0x1000, depth as u64 + 1)
                .unwrap();
            assert_eq!(signals.mask(), 0);
        }
        signals.raise(13, Info::EMPTY, false).unwrap();
        assert_eq!(signals.enter(13, 0x03001000, 99), Err(Errno::Overflow));
        for depth in (0..MAX_FRAMES).rev() {
            let address = 0x03007000 - depth as u64 * 0x1000;
            assert_eq!(signals.frame_tls(address), Ok(depth as u64 + 1));
            signals.leave(address, 0).unwrap();
        }
    }

    #[test]
    fn linux_layout_roundtrip_preserves_all_registers_and_frame_chain() {
        let state = state();
        let mut bytes = [0xff; FRAME_BYTES];
        let info = Info {
            code: 1,
            sender_pid: 0,
            address: 0x200000,
        };
        encode_frame(&mut bytes, &state, 0x4000, 11, info).unwrap();
        assert_eq!(decode_frame(&bytes), Ok((state, 0x4000)));
        assert_eq!(get32(&bytes, 0), 11);
        assert_eq!(get32(&bytes, 8), 1);
        assert_eq!(get64(&bytes, 16), 0x200000);
        assert_eq!(get64(&bytes, 568), state.pc);
        assert_eq!(get32(&bytes, 592), FPSIMD_MAGIC);
        assert_eq!(get64(&bytes, RT_FRAME_BYTES), state.regs[29]);
        assert_eq!(get64(&bytes, RT_FRAME_BYTES + 8), state.regs[30]);
        encode_frame(
            &mut bytes,
            &state,
            0,
            13,
            Info {
                sender_pid: 99,
                ..Info::EMPTY
            },
        )
        .unwrap();
        assert_eq!(get32(&bytes, 16), 99);
        assert_eq!(get32(&bytes, 20), 0);
    }

    #[test]
    fn legitimate_ucontext_edits_are_used_instead_of_hidden_saved_copy() {
        let mut bytes = [0; FRAME_BYTES];
        encode_frame(&mut bytes, &state(), 0, 11, Info::EMPTY).unwrap();
        put64(&mut bytes, 312, 0xfeed);
        put64(&mut bytes, 560, 0x03007000);
        put64(&mut bytes, 568, 0x01004000);
        put64(&mut bytes, 576, 0x60000000);
        put64(&mut bytes, 168, u64::MAX);
        put32(&mut bytes, 600, 0x08000000);
        put32(&mut bytes, 604, 0x800000);
        put64(&mut bytes, 608 + 31 * 16, 0x11223344);
        let (restored, mask) = decode_frame(&bytes).unwrap();
        assert_eq!(restored.regs[0], 0xfeed);
        assert_eq!(
            (restored.sp, restored.pc, restored.pstate),
            (0x03007000, 0x01004000, 0x60000000)
        );
        assert_eq!((restored.fpsr, restored.fpcr), (0x08000000, 0x800000));
        assert_eq!(restored.simd[31][0], 0x11223344);
        assert_eq!(mask, !UNBLOCKABLE);
    }

    #[test]
    fn privileged_state_unknown_extensions_and_invalid_alt_stack_are_rejected() {
        let mut original = [0; FRAME_BYTES];
        encode_frame(&mut original, &state(), 0, 11, Info::EMPTY).unwrap();
        for (offset, value) in [
            (576, 0x5),
            (576, 0x80),
            (568, 0xffff000000000000),
            (568, 3),
            (560, 1),
            (128, 1),
            (136, 1),
            (144, 1),
            (160, 1),
            (592, 0),
            (1120, 1),
        ] {
            let mut bytes = original;
            put64(&mut bytes, offset, value);
            assert_eq!(decode_frame(&bytes), Err(Errno::Inval), "offset={offset}");
        }
        let mut bytes = original;
        put32(&mut bytes, 152, 0);
        assert_eq!(decode_frame(&bytes), Err(Errno::Nomem));
    }

    #[test]
    fn faulting_pc_can_be_reported_but_must_be_repaired_before_return() {
        let interrupted = FrameState { pc: 3, ..state() };
        let mut bytes = [0; FRAME_BYTES];
        encode_frame(&mut bytes, &interrupted, 0, 11, Info::EMPTY).unwrap();
        assert_eq!(get64(&bytes, 568), 3);
        assert_eq!(decode_frame(&bytes), Err(Errno::Inval));
        put64(&mut bytes, 568, 0x01003000);
        assert!(decode_frame(&bytes).is_ok());
    }

    #[test]
    fn frame_bounds_and_invalid_encode_do_not_modify_output() {
        for sp in [0, FRAME_BYTES as u64 - 1, u64::MAX] {
            assert_eq!(frame_address(sp), Err(Errno::Fault));
        }
        assert_eq!(frame_address(0x03008000).unwrap() % 16, 0);
        let mut bytes = [0xa5; FRAME_BYTES];
        assert_eq!(
            encode_frame(&mut bytes, &state(), 0, 0, Info::EMPTY),
            Err(Errno::Inval)
        );
        assert!(bytes.iter().all(|b| *b == 0xa5));
    }
}
