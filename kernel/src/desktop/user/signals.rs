//! Foreground Linux signal policy with architecture-owned frame serialization.
//! The parent wakes interrupted waits and owns process termination. All frame
//! I/O goes through Runner usercopy; no pointer supplied by user code is dereferenced.
use super::{Errno, Runner, Supervisor, Wait};
use crate::process_arch::{self, SIGNAL_FRAME_BYTES as FRAME_BYTES};
use cyxia_posix::signal::{self, Action, Actions, AltStack, Delivery, Info, SA_ONSTACK};

#[derive(Clone, Copy)]
pub(super) struct Request {
    tid: u32,
    target: u32,
    signal: u32,
}

impl Runner {
    /// Cross-process lookup belongs to the supervisor after all AP contexts
    /// have returned. This request owns no target references or user pointers.
    pub(super) fn request_process_signal(
        &mut self,
        target: u64,
        signal: u32,
    ) -> Result<u64, Errno> {
        let target = u32::try_from(target)
            .ok()
            .filter(|pid| *pid != 0 && *pid <= i32::MAX as u32)
            .ok_or(Errno::Srch)?;
        if self.pending_signal.is_some() {
            return Err(Errno::Again);
        }
        self.pending_signal = Some(Request {
            tid: self.thread.tid,
            target,
            signal,
        });
        self.block(Wait::Signal);
        Ok(0)
    }

    pub(super) fn signal_stack(&mut self, new: u64, old: u64) -> Result<u64, Errno> {
        let previous = self.thread.alt_stack;
        let next = if new == 0 {
            None
        } else {
            if previous.contains(self.thread.context.sp()) {
                return Err(Errno::Perm);
            }
            let mut bytes = [0; 24];
            self.copy_from(new, &mut bytes)?;
            let stack = AltStack::decode_for(&bytes, true, process_arch::IMAGE_ABI)?;
            if stack.size != 0 {
                self.validate(stack.base, super::count(stack.size)?, true)?;
            }
            Some(stack)
        };
        if old != 0 {
            self.copy_to(old, &previous.encode(self.thread.context.sp()))?;
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
            let new = Action::decode_for(&bytes, process_arch::IMAGE_ABI)?;
            Actions::validate_action_for(signal, new, process_arch::IMAGE_ABI)?;
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
            self.threads
                .shared
                .actions
                .set_action_for(signal, new, process_arch::IMAGE_ABI)?;
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

    /// Run before each user entry. Some(code) requests default termination;
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
                    self.validate(action.handler, process_arch::INSTRUCTION_ALIGNMENT, false)?;
                    self.validate(action.restorer, process_arch::INSTRUCTION_ALIGNMENT, false)?;
                    let address = process_arch::signal_frame_address(
                        self.thread.alt_stack,
                        self.thread.context.sp(),
                        action.flags & SA_ONSTACK != 0,
                    )?;
                    self.validate(address, FRAME_BYTES, true)?;
                    let mut bytes = [0; FRAME_BYTES];
                    self.thread.context.encode_signal_frame(
                        &mut bytes,
                        address,
                        self.thread.signals.mask(),
                        signal,
                        info,
                        self.thread.alt_stack,
                        action.restorer,
                    )?;
                    self.copy_to(address, &bytes)?;
                    self.thread.signals.enter_for(
                        &mut self.threads.shared.actions,
                        signal,
                        address,
                        self.thread.context.tls(),
                        process_arch::IMAGE_ABI,
                    )?;
                    self.thread.retry_syscall = false;
                    self.thread.retry_descriptor = None;
                    self.thread
                        .context
                        .signal_handler(action, address, signal)?;
                    return Ok(None);
                }
            }
        }
        Ok(None)
    }

    /// A successful rt_sigreturn restores user-edited registers, mask and
    /// floating-point state. Return the restored result so syscall completion
    /// does not overwrite it. An error is a bad frame: parent must terminate
    /// SIGSEGV, not resume the restorer with a fabricated syscall error value.
    pub(super) fn signal_return(&mut self) -> Result<u64, Errno> {
        let address = self.thread.context.signal_return_address()?;
        let tls = self.thread.signals.frame_tls(address)?;
        let mut bytes = [0; FRAME_BYTES];
        self.copy_from(address, &mut bytes)?;
        let (context, mask, stack) = self
            .thread
            .context
            .restore_signal_frame(&bytes, address, tls)?;
        if stack.size != 0 {
            self.validate(stack.base, super::count(stack.size)?, true)?;
        }
        self.validate(context.pc(), process_arch::INSTRUCTION_ALIGNMENT, false)?;
        self.validate(context.sp().checked_sub(1).ok_or(Errno::Fault)?, 1, true)?;
        self.thread.signals.leave(address, mask)?;
        self.thread.alt_stack = stack;
        self.thread.context = context;
        Ok(self.thread.context.result())
    }
}

impl Supervisor {
    /// Called only by CPU0 after the parallel phase has drained every root and
    /// restored every Runner. No user process runs between validation, enqueue,
    /// and completion; a cancelled origin must not send a deferred signal.
    pub(super) fn service_signals(&mut self, origin: usize) {
        let Some(request) = self.runners[origin].pending_signal.take() else {
            return;
        };
        let sender = &self.runners[origin];
        if !sender.status.state.active()
            || !sender.linux
            || !core::iter::once(&sender.thread)
                .chain(sender.threads.parked.iter())
                .any(|thread| {
                    thread.active
                        && thread.tid == request.tid
                        && matches!(thread.waiting, Some(Wait::Signal))
                })
        {
            return;
        }
        let sender_pid = sender.status.pid;
        let result = self
            .runners
            .iter_mut()
            .find(|runner| runner.status.pid == request.target && runner.status.state.active())
            .ok_or(Errno::Srch)
            .and_then(|target| {
                // Every supported POSIX process has real/effective/saved UID 0.
                // Same-UID peers may signal; parenthood authorizes wait only.
                // Native runners can be queried, but have no Linux delivery
                // contract: never report successful undeliverable signals.
                if request.signal == 0 {
                    return Ok(0);
                }
                if !target.linux {
                    return Err(Errno::Opnotsupp);
                }
                target.threads.shared.pending.raise(
                    &target.threads.shared.actions,
                    request.signal,
                    Info {
                        code: 0, // SI_USER
                        sender_pid,
                        address: 0,
                    },
                    false,
                )?;
                Ok(0)
            });
        self.runners[origin].supervisor_result(request.tid, result);
    }
}
