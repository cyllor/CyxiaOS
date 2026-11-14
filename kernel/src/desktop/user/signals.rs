//! Foreground-only Linux AArch64 signal delivery for explicitly selected ELF.
//! The parent wakes interrupted waits and owns process termination. All frame
//! I/O goes through Runner usercopy; no pointer supplied by EL0 is dereferenced.
use super::{Context, Errno, Runner};
use cyxia_posix::signal::{
    self, Action, Actions, AltStack, Delivery, FRAME_BYTES, FrameState, Info, RT_FRAME_BYTES,
    SA_ONSTACK, SA_SIGINFO, UCONTEXT_OFFSET,
};

impl Runner {
    pub(super) fn signal_stack(&mut self, new: u64, old: u64) -> Result<u64, Errno> {
        let previous = self.thread.alt_stack;
        let next = if new == 0 {
            None
        } else {
            if previous.contains(self.thread.context.sp) {
                return Err(Errno::Perm);
            }
            let mut bytes = [0; 24];
            self.copy_from(new, &mut bytes)?;
            let stack = AltStack::decode(&bytes, true)?;
            if stack.size != 0 {
                self.validate(stack.base, super::count(stack.size)?, true)?;
            }
            Some(stack)
        };
        if old != 0 {
            self.copy_to(old, &previous.encode(self.thread.context.sp))?;
        }
        if let Some(stack) = next {
            self.thread.alt_stack = stack;
        }
        Ok(0)
    }
    pub(super) fn signal_action(
        &mut self,
        signal: u64,
        action: u64,
        old: u64,
        set_size: u64,
    ) -> Result<u64, Errno> {
        if set_size != 8 {
            return Err(Errno::Inval);
        }
        let signal = u32::try_from(signal).map_err(|_| Errno::Inval)?;
        let previous = self.threads.shared.actions.action(signal)?;
        let new = if action != 0 {
            let mut bytes = [0; 32];
            self.copy_from(action, &mut bytes)?;
            let new = Action::decode(&bytes)?;
            Actions::validate_action(signal, new)?;
            Some(new)
        } else {
            None
        };
        // Read the proposed action before writing oldact (the two may alias).
        // No disposition changes if either user buffer is invalid.
        if old != 0 {
            self.copy_to(old, &previous.encode())?;
        }
        if let Some(new) = new {
            self.threads.shared.actions.set_action(signal, new)?;
            if self.threads.shared.actions.ignored(signal)? {
                self.thread.signals.consume(signal)?;
                self.threads.shared.pending.consume(signal)?;
                for thread in &mut self.threads.parked {
                    thread.signals.consume(signal)?;
                }
            }
        }
        Ok(0)
    }

    pub(super) fn signal_mask(
        &mut self,
        how: u64,
        set: u64,
        old: u64,
        set_size: u64,
    ) -> Result<u64, Errno> {
        if set_size != 8 {
            return Err(Errno::Inval);
        }
        let previous = self.thread.signals.mask();
        let next = if set != 0 {
            let mut bytes = [0; 8];
            self.copy_from(set, &mut bytes)?;
            Some(
                self.thread
                    .signals
                    .changed_mask(how, u64::from_le_bytes(bytes))?,
            )
        } else {
            None
        };
        if old != 0 {
            self.copy_to(old, &previous.to_le_bytes())?;
        }
        if let Some(next) = next {
            self.thread.signals.set_mask(next);
        }
        Ok(0)
    }

    /// Queue real pending delivery. Parent must wake an interrupted waiting
    /// process if signals.ready(), then apply that syscall's EINTR semantics.
    pub(super) fn queue_signal(
        &mut self,
        signal: u32,
        info: Info,
        forced: bool,
    ) -> Result<(), Errno> {
        self.thread
            .signals
            .raise(&self.threads.shared.actions, signal, info, forced)
    }

    /// Run before each EL0 entry. Some(code) requests default termination;
    /// any error building a handler frame must terminate with SIGSEGV/139.
    /// No context or mask changes occur before complete frame copy succeeds.
    pub(super) fn deliver_signal(&mut self) -> Result<Option<u32>, Errno> {
        if !self.linux {
            return Ok(None);
        }
        self.threads
            .shared
            .pending
            .transfer_ready(&mut self.thread.signals, &self.threads.shared.actions);
        // At most 64 pending signal numbers; no unbounded ignore-draining loop.
        for _ in 0..signal::COUNT {
            match self.thread.signals.next(&self.threads.shared.actions) {
                None => return Ok(None),
                Some(Delivery::Ignore(signal)) => self.thread.signals.consume(signal)?,
                Some(Delivery::Terminate(signal)) => {
                    self.thread.signals.consume(signal)?;
                    return Ok(Some(128 + signal));
                }
                Some(Delivery::Handler {
                    signal,
                    action,
                    info,
                }) => {
                    self.thread.signals.can_enter()?;
                    self.validate(action.handler, 4, false)?;
                    self.validate(action.restorer, 4, false)?;
                    let address = self
                        .thread
                        .alt_stack
                        .frame_address(self.thread.context.sp, action.flags & SA_ONSTACK != 0)?;
                    self.validate(address, FRAME_BYTES, true)?;
                    let mut state = FrameState {
                        regs: self.thread.context.regs,
                        sp: self.thread.context.sp,
                        pc: self.thread.context.pc,
                        pstate: self.thread.context.status,
                        fault_address: self.thread.context.far,
                        simd: self.thread.context.simd,
                        fpcr: self.thread.context.fpcr as u32,
                        fpsr: self.thread.context.fpsr as u32,
                    };
                    // Readiness may have made this thread runnable before a
                    // process-directed signal arrived. The old SVC remains a
                    // blocked syscall until it actually retries; a handler
                    // must return EINTR rather than silently retrying it.
                    if self.thread.retry_syscall {
                        state.pc = state.pc.checked_add(4).ok_or(Errno::Fault)?;
                        state.regs[0] = (-(Errno::Intr as i64)) as u64;
                    }
                    let mut bytes = [0; FRAME_BYTES];
                    signal::encode_frame(
                        &mut bytes,
                        &state,
                        self.thread.signals.mask(),
                        signal,
                        info,
                    )?;
                    signal::set_frame_stack(
                        &mut bytes,
                        self.thread.alt_stack,
                        self.thread.context.sp,
                    );
                    self.copy_to(address, &bytes)?;
                    self.thread.signals.enter(
                        &mut self.threads.shared.actions,
                        signal,
                        address,
                        self.thread.context.tpidr_el0,
                    )?;
                    self.thread.retry_syscall = false;
                    self.thread.retry_descriptor = None;
                    self.thread.context.regs[0] = u64::from(signal);
                    self.thread.context.regs[1] = if action.flags & SA_SIGINFO != 0 {
                        address
                    } else {
                        0
                    };
                    self.thread.context.regs[2] = if action.flags & SA_SIGINFO != 0 {
                        address + UCONTEXT_OFFSET as u64
                    } else {
                        0
                    };
                    self.thread.context.regs[29] = address + RT_FRAME_BYTES as u64;
                    self.thread.context.regs[30] = action.restorer;
                    self.thread.context.pc = action.handler;
                    self.thread.context.sp = address;
                    self.thread.context.status &= 0xf0000000;
                    self.thread.context.kind = 0;
                    self.thread.context.esr = 0;
                    return Ok(None);
                }
            }
        }
        Ok(None)
    }

    /// A successful rt_sigreturn restores user-edited registers, mask and
    /// FPSIMD contents. Return the restored x0 so ordinary syscall completion
    /// does not overwrite it. An error is a bad frame: parent must terminate
    /// SIGSEGV, not resume the restorer with a fabricated syscall error value.
    pub(super) fn signal_return(&mut self) -> Result<u64, Errno> {
        let address = self.thread.context.sp;
        let tls = self.thread.signals.frame_tls(address)?;
        let mut bytes = [0; FRAME_BYTES];
        self.copy_from(address, &mut bytes)?;
        let stack = signal::frame_stack(&bytes)?;
        if stack.size != 0 {
            self.validate(stack.base, super::count(stack.size)?, true)?;
        }
        let (state, mask) = signal::decode_frame(&bytes)?;
        self.validate(state.pc, 4, false)?;
        self.validate(state.sp.checked_sub(1).ok_or(Errno::Fault)?, 1, true)?;
        // The TLS register is not part of Linux's ordinary signal ucontext.
        // Keep a private per-level copy so a handler cannot lose the thread's
        // original TLS accidentally; no user bytes select another process.
        self.thread.signals.leave(address, mask)?;
        // Linux restores uc_stack on return, including after a handler on the
        // ordinary stack successfully changes its registered alternate stack.
        // Validate all user edits before committing any restored state.
        self.thread.alt_stack = stack;
        self.thread.context = Context {
            regs: state.regs,
            pc: state.pc,
            status: state.pstate,
            sp: state.sp,
            far: state.fault_address,
            tpidr_el0: tls,
            simd: state.simd,
            fpcr: u64::from(state.fpcr),
            fpsr: u64::from(state.fpsr),
            ..Context::empty()
        };
        Ok(self.thread.context.regs[0])
    }
}
