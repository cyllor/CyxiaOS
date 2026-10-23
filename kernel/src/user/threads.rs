//! Bounded CPU0 thread mechanism. One Runner owns the address space and FDs.
//! Eight 4KiB context slots plus a shared signal page and a spare page occupy
//! ten actual boot-reserved pages. Model 8193 admits one context credit while
//! preserving its two-credit floor; neither stack nor heap bytes are fabricated.
#[cfg(any(feature = "ported", feature = "graphics"))]
use super::Errno;
use super::{Context, LocalIpc, Runner, UserState, Wait};

#[cfg(feature = "ported")]
pub(super) const MAX_THREADS: usize = 8;
#[repr(C, align(4096))]
pub(super) struct Thread {
    pub context: Context,
    #[cfg(feature = "ported")]
    pub signals: cyxia_posix::signal::Signals,
    #[cfg(feature = "ported")]
    pub alt_stack: cyxia_posix::signal::AltStack,
    #[cfg(feature = "ported")]
    pub futex_mask: u32,
    #[cfg(feature = "ported")]
    pub clear_tid: u64,
    // A readiness wake can precede the next dispatch. Keep the interrupted
    // syscall identity until its rewound SVC actually executes again.
    #[cfg(feature = "ported")]
    pub retry_syscall: bool,
    #[cfg(feature = "ported")]
    pub retry_descriptor: Option<(i32, u64)>, // FD + global OFD generation, weak binding
    pub tid: u32,
    pub active: bool,
    pub waiting: Option<Wait>,
    pub ready_since: u64,
    pub cpu_bound: bool,
}
impl Thread {
    pub const fn new() -> Self {
        Self {
            context: Context::empty(),
            #[cfg(feature = "ported")]
            signals: cyxia_posix::signal::Signals::new(),
            #[cfg(feature = "ported")]
            alt_stack: cyxia_posix::signal::AltStack::DISABLED,
            #[cfg(feature = "ported")]
            futex_mask: u32::MAX,
            #[cfg(feature = "ported")]
            clear_tid: 0,
            #[cfg(feature = "ported")]
            retry_syscall: false,
            #[cfg(feature = "ported")]
            retry_descriptor: None,
            tid: 0,
            active: false,
            waiting: None,
            ready_since: 0,
            cpu_bound: false,
        }
    }
    #[inline(never)]
    pub fn reset(&mut self) {
        self.context = Context::empty();
        #[cfg(feature = "ported")]
        {
            self.signals = cyxia_posix::signal::Signals::new();
            self.alt_stack = cyxia_posix::signal::AltStack::DISABLED;
            self.futex_mask = u32::MAX;
            self.clear_tid = 0;
            self.retry_syscall = false;
            self.retry_descriptor = None;
        }
        self.tid = 0;
        self.active = false;
        self.waiting = None;
        self.ready_since = 0;
        self.cpu_bound = false;
    }
    fn runnable(&self) -> bool {
        self.active && self.waiting.is_none()
    }
}
const _: () = assert!(core::mem::size_of::<Thread>() == 4096);

#[cfg(feature = "ported")]
#[repr(C, align(4096))]
pub(super) struct Shared {
    pub actions: cyxia_posix::signal::Actions,
    pub pending: cyxia_posix::signal::Signals,
    pub dispatch: Option<(u64, cyxia_contracts::DecisionSource)>,
}
#[cfg(feature = "ported")]
#[repr(C, align(4096))]
pub(super) struct Group {
    pub parked: [Thread; MAX_THREADS - 1],
    pub shared: Shared,
    // This real reserved page is part of the conservative admission envelope.
    // It is not available to another subsystem while any Runner exists.
    spare: [u8; 4096],
}
#[cfg(feature = "ported")]
impl Group {
    // Reset each bounded record in place; constructing the whole 36KiB Group
    // as a temporary would exhaust the 64KiB kernel stack during ELF launch.
    #[inline(never)]
    pub fn reset(&mut self) {
        for thread in &mut self.parked {
            thread.reset();
        }
        self.shared.actions = cyxia_posix::signal::Actions::new();
        self.shared.pending = cyxia_posix::signal::Signals::new();
        self.shared.dispatch = None;
    }
    pub const fn new() -> Self {
        Self {
            parked: [const { Thread::new() }; MAX_THREADS - 1],
            shared: Shared {
                actions: cyxia_posix::signal::Actions::new(),
                pending: cyxia_posix::signal::Signals::new(),
                dispatch: None,
            },
            spare: [0; 4096],
        }
    }
}
#[cfg(feature = "ported")]
const _: () = {
    assert!(core::mem::size_of::<Shared>() == 4096);
    assert!(core::mem::size_of::<Thread>() + core::mem::size_of::<Group>() == 10 * 4096);
};

impl Runner {
    pub(super) fn prepare_threads(&mut self, time: u64, ipc: &mut LocalIpc) {
        if !self.status.state.active() {
            return;
        }
        #[cfg(feature = "ported")]
        {
            if self.thread.active {
                self.threads
                    .shared
                    .pending
                    .transfer_ready(&mut self.thread.signals, &self.threads.shared.actions);
            }
            self.wake(time, ipc);
            for index in 0..MAX_THREADS - 1 {
                core::mem::swap(&mut self.thread, &mut self.threads.parked[index]);
                if self.thread.active {
                    self.threads
                        .shared
                        .pending
                        .transfer_ready(&mut self.thread.signals, &self.threads.shared.actions);
                }
                self.wake(time, ipc);
                core::mem::swap(&mut self.thread, &mut self.threads.parked[index]);
            }
            let candidates = core::array::from_fn::<_, MAX_THREADS, _>(|index| {
                let thread = self.thread_at(index);
                thread
                    .runnable()
                    .then_some(cyxia_ai_runtime::UserCandidate {
                        waiting_ms: time.saturating_sub(thread.ready_since),
                        cpu_bound: thread.cpu_bound,
                    })
            });
            // Same bounded local model as process selection. Ages advance until
            // the chosen thread actually executes; parked threads never consume
            // a CPU slice merely because their process was considered.
            if self.threads.shared.dispatch.take().is_some() {
                super::ai::record(super::ai::Domain::CpuThread, |c| c.cancelled());
            }
            if let Some(choice) = cyxia_ai_runtime::user_dispatch_policy(&candidates).unwrap() {
                super::ai::record(super::ai::Domain::CpuThread, |c| c.proposal(choice.model));
                self.threads.shared.dispatch = Some((choice.model, choice.source));
                if choice.index > 0 {
                    core::mem::swap(&mut self.thread, &mut self.threads.parked[choice.index - 1]);
                }
            }
        }
        #[cfg(not(feature = "ported"))]
        self.wake(time, ipc);
        self.refresh_thread_state();
    }
    pub(super) fn refresh_thread_state(&mut self) {
        if !self.status.state.active() {
            return;
        }
        let runnable = self.thread.runnable();
        #[cfg(feature = "ported")]
        let runnable = runnable || self.threads.parked.iter().any(Thread::runnable);
        self.status.state = if runnable {
            UserState::Running
        } else {
            UserState::Waiting
        };
    }
    #[cfg(feature = "graphics")]
    pub(super) fn complete_display(&mut self, tid: u32, success: bool, time: u64) {
        let complete = |thread: &mut Thread| {
            if thread.active && thread.tid == tid && matches!(thread.waiting, Some(Wait::Display)) {
                thread.context.regs[0] = if success {
                    0
                } else {
                    (-(Errno::Io as i64)) as u64
                };
                thread.waiting = None;
                thread.ready_since = time;
                true
            } else {
                false
            }
        };
        let mut completed = complete(&mut self.thread);
        #[cfg(feature = "ported")]
        for thread in &mut self.threads.parked {
            completed |= complete(thread);
        }
        if completed {
            self.status.wakeups = self.status.wakeups.saturating_add(1);
        }
        self.refresh_thread_state();
    }
}

#[cfg(feature = "ported")]
mod linux_threads {
    use super::super::ai::{self, Domain};
    use super::super::{FileSystem, GrantLedger, now};
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};
    use cyxia_ai_runtime::accounting::Attempt;
    use cyxia_posix::signal::Info;
    // Leader IDs remain process IDs; extra TIDs never collide or wrap/reuse.
    // Linux futex owner values reserve bits 30/31; musl recursive/errorcheck
    // mutexes mask IDs to 30 bits. Never allocate an ID in either flag bit.
    static NEXT_TID: AtomicU32 = AtomicU32::new(0x1000_0000);
    const REQUIRED_CLONE_FLAGS: u64 = 0x003d_0f00;
    const CLONE_DETACHED: u64 = 0x0040_0000;
    impl Runner {
        pub(super) fn thread_at(&self, index: usize) -> &Thread {
            if index == 0 {
                &self.thread
            } else {
                &self.threads.parked[index - 1]
            }
        }
        fn thread_at_mut(&mut self, index: usize) -> &mut Thread {
            if index == 0 {
                &mut self.thread
            } else {
                &mut self.threads.parked[index - 1]
            }
        }
        fn live_threads(&self) -> usize {
            usize::from(self.thread.active)
                + self.threads.parked.iter().filter(|t| t.active).count()
        }
        pub(in super::super) fn clone_thread(
            &mut self,
            flags: u64,
            stack: u64,
            parent_tid: u64,
            tls: u64,
            child_tid: u64,
        ) -> Result<u64, Errno> {
            let mut attempt = Attempt::default();
            let result =
                self.clone_thread_accounted(flags, stack, parent_tid, tls, child_tid, &mut attempt);
            ai::admission(Domain::Thread, attempt, &result);
            result
        }
        fn clone_thread_accounted(
            &mut self,
            flags: u64,
            stack: u64,
            parent_tid: u64,
            tls: u64,
            child_tid: u64,
            attempt: &mut Attempt,
        ) -> Result<u64, Errno> {
            // Linux ignores obsolete CLONE_DETACHED, which musl 1.2.6 still sets.
            // Process creation, alternate sharing, namespaces, and child-settid
            // are deliberately unsupported rather than silently approximated.
            if flags & !CLONE_DETACHED != REQUIRED_CLONE_FLAGS {
                return Err(Errno::Nosys);
            }
            if stack == 0 || !stack.is_multiple_of(16) {
                return Err(Errno::Inval);
            }
            self.validate(stack, 16, true)?;
            self.validate(parent_tid, 4, true)?;
            self.validate(child_tid, 4, true)?;
            // TPIDR is an opaque userspace value. Its use is checked by the MMU,
            // exactly like any other user register; it grants no kernel access.
            let Some(slot) = self.threads.parked.iter().position(|thread| !thread.active) else {
                self.status.thread_denials = self.status.thread_denials.saturating_add(1);
                return Err(Errno::Again);
            };
            attempt.proposed(8193);
            let (allow, model) =
                cyxia_ai_runtime::user_memory_policy((10 - self.live_threads()) as u32, 1)
                    .map_err(|_| Errno::Io)?;
            attempt.decided(allow, model);
            self.status.thread_memory_model = model;
            if !allow {
                self.status.thread_denials = self.status.thread_denials.saturating_add(1);
                return Err(Errno::Again);
            }
            let tid = NEXT_TID
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |tid| {
                    tid.checked_add(1).filter(|next| *next < 0x3fff_ffff)
                })
                .map_err(|_| Errno::Again)?;
            let mut child = Thread::new();
            let context = &self.thread.context;
            child.context = Context {
                regs: context.regs,
                pc: context.pc,
                status: context.status,
                sp: stack,
                esr: 0,
                far: 0,
                kind: 0,
                tpidr_el0: tls,
                simd: context.simd,
                fpcr: context.fpcr,
                fpsr: context.fpsr,
            };
            child.context.regs[0] = 0;
            child.signals.set_mask(self.thread.signals.mask());
            child.clear_tid = child_tid;
            child.tid = tid;
            child.active = true;
            child.ready_since = now();
            // All validation and admission precedes publication. CPU0 cannot
            // execute either context midway through these two writes.
            self.copy_to(parent_tid, &tid.to_le_bytes())?;
            self.threads.parked[slot] = child;
            ai::record(Domain::Thread, |c| c.grant(1));
            self.status.thread_admissions = self.status.thread_admissions.saturating_add(1);
            self.status.thread_count = self.live_threads() as u32;
            self.status.thread_peak = self.status.thread_peak.max(self.status.thread_count);
            Ok(u64::from(tid))
        }
        pub(in super::super) fn thread_exit(
            &mut self,
            fs: &mut FileSystem,
            ledger: &mut GrantLedger,
            ipc: &mut LocalIpc,
            code: u32,
        ) {
            let address = self.thread.clear_tid;
            self.thread.clear_tid = 0;
            if address != 0 && self.copy_to(address, &0u32.to_le_bytes()).is_ok() {
                self.wake_futex(address, 1);
            }
            if self.thread.active && self.thread.tid >= 0x1000_0000 {
                ai::record(Domain::Thread, |c| c.release(1));
            }
            self.thread.active = false;
            self.thread.waiting = None;
            self.thread.retry_syscall = false;
            self.thread.retry_descriptor = None;
            self.status.thread_count = self.live_threads() as u32;
            if self.status.thread_count == 0 {
                self.finish(fs, ledger, ipc, UserState::Exited, code);
            } else {
                self.refresh_thread_state();
            }
        }
        pub(in super::super) fn clear_all_threads(&mut self) {
            self.status.thread_count = 0;
            if self.threads.shared.dispatch.take().is_some() {
                ai::record(Domain::CpuThread, |c| c.cancelled());
            }
            for index in 0..MAX_THREADS {
                let address = self.thread_at(index).clear_tid;
                if self.thread_at(index).active && address != 0 {
                    let _ = self.copy_to(address, &0u32.to_le_bytes());
                }
                let thread = self.thread_at_mut(index);
                if thread.active && thread.tid >= 0x1000_0000 {
                    ai::record(Domain::Thread, |c| c.release(1));
                }
                thread.clear_tid = 0;
                thread.active = false;
                thread.waiting = None;
                thread.retry_syscall = false;
                thread.retry_descriptor = None;
            }
        }
        fn read_futex(&self, address: u64) -> Result<u32, Errno> {
            if !address.is_multiple_of(4) {
                return Err(Errno::Inval);
            }
            let mut value = [0; 4];
            self.copy_from(address, &mut value)?;
            Ok(u32::from_le_bytes(value))
        }
        fn wake_futex(&mut self, address: u64, count: usize) -> usize {
            self.wake_futex_mask(address, count, u32::MAX)
        }
        fn wake_futex_mask(&mut self, address: u64, count: usize, mask: u32) -> usize {
            let mut woke = 0;
            let time = now();
            for index in 0..MAX_THREADS {
                let thread = self.thread_at_mut(index);
                if woke < count
                    && thread.active
                    && thread.futex_mask & mask != 0
                    && matches!(thread.waiting, Some(Wait::Futex { address: a, .. }) if a == address)
                {
                    thread.waiting = None;
                    thread.context.regs[0] = 0;
                    thread.ready_since = time;
                    woke += 1;
                }
            }
            self.status.wakeups = self.status.wakeups.saturating_add(woke as u64);
            self.refresh_thread_state();
            woke
        }
        pub(in super::super) fn futex(
            &mut self,
            address: u64,
            op: u64,
            value: u64,
            timeout: u64,
            address2: u64,
            compare: u64,
        ) -> Result<u64, Errno> {
            let command = op & !128; // PRIVATE is equivalent within this address space.
            // CLOCK_REALTIME remains explicitly unsupported. Rust's ordinary
            // parking uses absolute CLOCK_MONOTONIC WAIT_BITSET deadlines.
            if !matches!(command, 0 | 1 | 3 | 4 | 9 | 10) {
                return Err(Errno::Nosys);
            }
            let mask = if matches!(command, 9 | 10) {
                let mask = compare as u32;
                if mask == 0 {
                    return Err(Errno::Inval);
                }
                mask
            } else {
                u32::MAX
            };
            let observed = self.read_futex(address)?;
            if matches!(command, 0 | 9) {
                // User value test + waiter registration are indivisible on CPU0.
                if observed != value as u32 {
                    return Err(Errno::Again);
                }
                let until = if timeout == 0 {
                    u64::MAX
                } else {
                    let mut bytes = [0; 16];
                    self.copy_from(timeout, &mut bytes)?;
                    let seconds = i64::from_le_bytes(bytes[..8].try_into().unwrap());
                    let nanos = i64::from_le_bytes(bytes[8..].try_into().unwrap());
                    if seconds < 0 || !(0..1_000_000_000).contains(&nanos) {
                        return Err(Errno::Inval);
                    }
                    let millis = (seconds as u64)
                        .checked_mul(1000)
                        .and_then(|ms| ms.checked_add((nanos as u64).div_ceil(1_000_000)))
                        .ok_or(Errno::Overflow)?;
                    let until = if command == 9 {
                        millis
                    } else {
                        // now() is rounded down to whole ticks. Round the
                        // relative start up so a nonzero wait cannot expire
                        // before the requested real elapsed duration.
                        now()
                            .checked_add(millis)
                            .and_then(|end| end.checked_add(u64::from(millis != 0)))
                            .ok_or(Errno::Overflow)?
                    };
                    if until <= now() {
                        return Err(Errno::Timedout);
                    }
                    until
                };
                self.thread.futex_mask = mask;
                self.block(Wait::Futex { address, until });
                Ok(0)
            } else {
                let count = value as i32;
                if count < 0 {
                    return Err(Errno::Inval);
                }
                if matches!(command, 1 | 10) {
                    return Ok(self.wake_futex_mask(address, count as usize, mask) as u64);
                }
                let requeue = timeout as i32;
                if requeue < 0 || address2 == address {
                    return Err(Errno::Inval);
                }
                self.read_futex(address2)?;
                if command == 4 && observed != compare as u32 {
                    return Err(Errno::Again);
                }
                let woke = self.wake_futex(address, count as usize);
                let mut moved = 0;
                for index in 0..MAX_THREADS {
                    let thread = self.thread_at_mut(index);
                    if moved < requeue as usize
                        && thread.active
                        && let Some(Wait::Futex {
                            address: source, ..
                        }) = &mut thread.waiting
                        && *source == address
                    {
                        *source = address2;
                        moved += 1;
                    }
                }
                Ok((woke + moved) as u64)
            }
        }
        pub(in super::super) fn send_signal(
            &mut self,
            number: u64,
            target: u64,
            thread_target: u64,
            signal: u64,
        ) -> Result<u64, Errno> {
            let (tid, signal) = if number == 131 {
                if target != self.status.pid as u64 {
                    return Err(Errno::Srch);
                }
                (thread_target, signal)
            } else {
                (target, thread_target)
            };
            let info = Info {
                code: if number == 129 { 0 } else { -6 },
                sender_pid: self.status.pid,
                address: 0,
            };
            let signal = u32::try_from(signal).map_err(|_| Errno::Inval)?;
            if signal > 64 {
                return Err(Errno::Inval);
            }
            if number == 129 {
                if tid != 0 && tid != self.status.pid as u64 {
                    return Err(Errno::Srch);
                }
                if signal != 0 {
                    self.threads.shared.pending.raise(
                        &self.threads.shared.actions,
                        signal,
                        info,
                        false,
                    )?;
                }
            } else {
                let index = (0..MAX_THREADS)
                    .find(|&index| {
                        let thread = self.thread_at(index);
                        thread.active && thread.tid as u64 == tid
                    })
                    .ok_or(Errno::Srch)?;
                if signal != 0 {
                    if index == 0 {
                        self.thread.signals.raise(
                            &self.threads.shared.actions,
                            signal,
                            info,
                            false,
                        )?;
                    } else {
                        self.threads.parked[index - 1].signals.raise(
                            &self.threads.shared.actions,
                            signal,
                            info,
                            false,
                        )?;
                    }
                }
            }
            Ok(0)
        }
    }
}
