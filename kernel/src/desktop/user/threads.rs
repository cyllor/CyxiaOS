//! Bounded CPU0 thread mechanism. One Runner owns the address space and FDs.
//! Eight legacy or sixteen full-OS 4KiB context slots, a shared signal page and
//! a spare page occupy ten or eighteen actual boot-reserved pages. Model 8193
//! admits one context credit while preserving its two-credit floor; user stacks
//! and heap bytes are separately backed and admitted.
#[cfg(any(feature = "ported", feature = "graphics"))]
use super::Errno;
use super::{Context, LocalIpc, Runner, UserState, Wait};

#[cfg(feature = "ported")]
pub(super) const MAX_THREADS: usize = if cfg!(feature = "full-os") { 16 } else { 8 };
#[cfg(feature = "ported")]
fn thread_slots(mut occupied: u16) -> impl Iterator<Item = usize> {
    core::iter::from_fn(move || {
        if occupied == 0 {
            return None;
        }
        let slot = occupied.trailing_zeros() as usize;
        occupied &= occupied - 1;
        Some(slot)
    })
}
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
    // syscall identity until its rewound syscall actually executes again.
    #[cfg(feature = "ported")]
    pub retry_syscall: bool,
    #[cfg(feature = "ported")]
    pub retry_descriptor: Option<(i32, u64)>, // FD + global OFD generation, weak binding
    #[cfg(feature = "ported")]
    pub poll_snapshot: super::linux::PollSnapshot,
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
            #[cfg(feature = "ported")]
            poll_snapshot: super::linux::PollSnapshot::new(),
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
            self.poll_snapshot.invalidate();
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

/// Registration for an entirely blocked process, built after an authoritative
/// scan. A direct completion publishes Running through refresh_thread_state.
#[cfg(feature = "ported")]
#[derive(Clone, Copy)]
pub(super) struct IdleWait {
    until: u64,
    ipc_epoch: Option<u64>,
    checkpoint: Option<u64>,
    pub(super) has_child: bool,
}
#[cfg(feature = "ported")]
impl IdleWait {
    fn register(runner: &Runner, ipc: &LocalIpc) -> Option<Self> {
        let mut idle = Self {
            until: u64::MAX,
            ipc_epoch: None,
            checkpoint: None,
            has_child: false,
        };
        for slot in runner.active_thread_slots() {
            match runner.thread_at(slot).waiting? {
                Wait::Sleep(until)
                | Wait::Retry(until)
                | Wait::Nanosleep { until, .. }
                | Wait::Futex { until, .. } => idle.until = idle.until.min(until),
                Wait::Ipc(..) => idle.ipc_epoch = Some(ipc.readiness_epoch()),
                // Only the single in-flight storage generation can return Again.
                Wait::Checkpoint(generation) => idle.checkpoint = Some(generation),
                Wait::Child { .. } => idle.has_child = true,
                Wait::Spawn | Wait::Signal => {}
                #[cfg(feature = "graphics")]
                Wait::Display => {}
                // Descriptor bindings, user poll arrays and timers have their
                // own readiness rules. Leave these runners on the sampling path.
                Wait::Poll { .. }
                | Wait::Epoll { .. }
                | Wait::Unix { .. }
                | Wait::TimerRead { .. } => return None,
            }
        }
        Some(idle)
    }

    fn unchanged(self, time: u64, ipc: &LocalIpc) -> bool {
        time < self.until
            && self
                .ipc_epoch
                .is_none_or(|epoch| epoch != u64::MAX && epoch == ipc.readiness_epoch())
            && self.checkpoint.is_none_or(|generation| {
                super::super::storage::checkpoint_complete(generation) == Err(Errno::Again)
            })
    }
}

#[cfg(feature = "ported")]
#[repr(C, align(4096))]
pub(super) struct Shared {
    pub actions: cyxia_posix::signal::Actions,
    pub pending: cyxia_posix::signal::Signals,
    pub dispatch: Option<(u64, cyxia_contracts::DecisionSource)>,
    parked_active: u16,
    pub(super) idle_wait: Option<IdleWait>,
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
    // Reset each bounded record in place; constructing the whole Group (36KiB
    // legacy, 68KiB full OS) would exhaust the 64KiB kernel stack at ELF launch.
    #[inline(never)]
    pub fn reset(&mut self) {
        for thread in &mut self.parked {
            thread.reset();
        }
        self.shared.actions = cyxia_posix::signal::Actions::new();
        self.shared.pending = cyxia_posix::signal::Signals::new();
        self.shared.dispatch = None;
        self.shared.parked_active = 0;
        self.shared.idle_wait = None;
    }
    pub const fn new() -> Self {
        Self {
            parked: [const { Thread::new() }; MAX_THREADS - 1],
            shared: Shared {
                actions: cyxia_posix::signal::Actions::new(),
                pending: cyxia_posix::signal::Signals::new(),
                dispatch: None,
                parked_active: 0,
                idle_wait: None,
            },
            spare: [0; 4096],
        }
    }
    fn parked_slots(&self) -> impl Iterator<Item = usize> + use<> {
        thread_slots(self.shared.parked_active)
    }
    fn first_free_parked(&self) -> Option<usize> {
        let slot = self.shared.parked_active.trailing_ones() as usize;
        (slot < MAX_THREADS - 1).then_some(slot)
    }
    fn sync_parked_slot(&mut self, slot: usize) {
        let bit = 1u16 << slot;
        self.shared.parked_active =
            (self.shared.parked_active & !bit) | (u16::from(self.parked[slot].active) << slot);
    }
}
#[cfg(feature = "ported")]
const RESERVED_CONTEXT_PAGES: usize =
    (core::mem::size_of::<Thread>() + core::mem::size_of::<Group>()) / 4096;
#[cfg(feature = "ported")]
const _: () = {
    assert!(core::mem::size_of::<Shared>() == 4096);
    assert!(
        core::mem::size_of::<Thread>() + core::mem::size_of::<Group>() == (MAX_THREADS + 2) * 4096
    );
    assert!(RESERVED_CONTEXT_PAGES <= 64); // Model 8193's existing input domain.
    assert!(MAX_THREADS <= u16::BITS as usize);
};

impl Runner {
    // Slot zero owns the selected context. Non-ported profiles have only it.
    pub(super) fn thread_at(&self, slot: usize) -> &Thread {
        #[cfg(feature = "ported")]
        if slot != 0 {
            return &self.threads.parked[slot - 1];
        }
        debug_assert_eq!(slot, 0);
        &self.thread
    }

    pub(super) fn thread_at_mut(&mut self, slot: usize) -> &mut Thread {
        #[cfg(feature = "ported")]
        if slot != 0 {
            return &mut self.threads.parked[slot - 1];
        }
        debug_assert_eq!(slot, 0);
        &mut self.thread
    }

    #[cfg(feature = "ported")]
    fn active_thread_slots(&self) -> impl Iterator<Item = usize> + use<> {
        thread_slots((self.threads.shared.parked_active << 1) | u16::from(self.thread.active))
    }

    pub(super) fn prepare_threads(&mut self, time: u64, ipc: &mut LocalIpc) {
        if !self.status.state.active() {
            return;
        }
        #[cfg(feature = "ported")]
        {
            if self.status.state == UserState::Waiting
                && self
                    .threads
                    .shared
                    .idle_wait
                    .is_some_and(|idle| idle.unchanged(time, ipc))
                && self.threads.shared.pending.pending() == 0
            {
                return;
            }
            self.threads.shared.idle_wait = None;
            if self.thread.active {
                self.threads
                    .shared
                    .pending
                    .transfer_ready(&mut self.thread.signals, &self.threads.shared.actions);
            }
            self.wake(0, time, ipc);
            for index in self.threads.parked_slots() {
                let thread = &mut self.threads.parked[index];
                self.threads
                    .shared
                    .pending
                    .transfer_ready(&mut thread.signals, &self.threads.shared.actions);
                if thread.waiting.is_some() {
                    self.wake(index + 1, time, ipc);
                }
            }
            let mut candidates = [None; MAX_THREADS];
            for index in self.active_thread_slots() {
                let thread = self.thread_at(index);
                candidates[index] = thread
                    .runnable()
                    .then_some(cyxia_ai_runtime::UserCandidate {
                        waiting_ms: time.saturating_sub(thread.ready_since),
                        cpu_bound: thread.cpu_bound,
                    });
            }
            // Same bounded local model as process selection. Ages advance until
            // the chosen thread actually executes; parked threads never consume
            // a CPU slice merely because their process was considered.
            if self.threads.shared.dispatch.take().is_some() {
                super::ai::record(super::ai::Domain::CpuThread, |c| c.cancelled());
            }
            let choice = if cfg!(feature = "full-os") {
                cyxia_ai_runtime::full_os_thread_dispatch_policy(&candidates)
            } else {
                cyxia_ai_runtime::user_dispatch_policy(&candidates)
            }
            .unwrap();
            if let Some(choice) = choice {
                super::ai::record(super::ai::Domain::CpuThread, |c| c.proposal(choice.model));
                self.threads.shared.dispatch = Some((choice.model, choice.source));
                if choice.index > 0 {
                    let slot = choice.index - 1;
                    core::mem::swap(&mut self.thread, &mut self.threads.parked[slot]);
                    self.threads.sync_parked_slot(slot);
                }
            } else {
                self.threads.shared.idle_wait = IdleWait::register(self, ipc);
            }
        }
        #[cfg(not(feature = "ported"))]
        self.wake(0, time, ipc);
        self.refresh_thread_state();
    }
    pub(super) fn refresh_thread_state(&mut self) {
        if !self.status.state.active() {
            return;
        }
        self.status.state = if self.has_runnable_thread() {
            UserState::Running
        } else {
            UserState::Waiting
        };
    }
    pub(super) fn has_runnable_thread(&self) -> bool {
        let runnable = self.thread.runnable();
        #[cfg(feature = "ported")]
        let runnable = runnable
            || self
                .threads
                .parked_slots()
                .any(|slot| self.threads.parked[slot].runnable());
        runnable
    }
    #[cfg(feature = "graphics")]
    pub(super) fn complete_display(&mut self, tid: u32, success: bool, time: u64) {
        let complete = |thread: &mut Thread| {
            if thread.active && thread.tid == tid && matches!(thread.waiting, Some(Wait::Display)) {
                thread.context.set_result(if success {
                    0
                } else {
                    (-(Errno::Io as i64)) as u64
                });
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
        fn live_threads(&self) -> usize {
            usize::from(self.thread.active)
                + self.threads.shared.parked_active.count_ones() as usize
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
            let stack_bytes = cyxia_posix::linux_abi::validate_clone_stack(
                crate::process_arch::IMAGE_ABI,
                stack,
            )?;
            self.validate(stack, stack_bytes, true)?;
            self.validate(parent_tid, 4, true)?;
            self.validate(child_tid, 4, true)?;
            #[cfg(target_arch = "x86_64")]
            if !super::super::capacity::thread_available()
                || self.live_threads() >= super::super::capacity::per_process_thread_limit()
            {
                self.status.thread_denials = self.status.thread_denials.saturating_add(1);
                return Err(Errno::Again);
            }
            // TLS is an opaque user value. The CPU backend validates its range;
            // later user accesses are checked by the private address space.
            let Some(slot) = self.threads.first_free_parked() else {
                self.status.thread_denials = self.status.thread_denials.saturating_add(1);
                return Err(Errno::Again);
            };
            attempt.proposed(8193);
            let (allow, model) = cyxia_ai_runtime::user_memory_policy(
                (RESERVED_CONTEXT_PAGES - self.live_threads()) as u32,
                1,
            )
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
            child.context = self.thread.context.clone_for_thread(stack, tls)?;
            child.signals.set_mask(self.thread.signals.mask());
            child.clear_tid = child_tid;
            child.tid = tid;
            child.active = true;
            child.ready_since = now();
            // All validation and admission precedes publication. CPU0 cannot
            // execute either context midway through these two writes.
            self.copy_to(parent_tid, &tid.to_le_bytes())?;
            self.threads.parked[slot] = child;
            self.threads.sync_parked_slot(slot);
            #[cfg(target_arch = "x86_64")]
            super::super::capacity::thread_started();
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
            #[cfg(target_arch = "x86_64")]
            if self.thread.active {
                super::super::capacity::threads_released(1);
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
            self.threads.shared.parked_active = 0;
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
            for index in self.active_thread_slots() {
                if woke == count {
                    break;
                }
                let thread = self.thread_at_mut(index);
                if thread.futex_mask & mask != 0
                    && matches!(thread.waiting, Some(Wait::Futex { address: a, .. }) if a == address)
                {
                    thread.waiting = None;
                    thread.context.set_result(0);
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
                for index in self.active_thread_slots() {
                    if moved == requeue as usize {
                        break;
                    }
                    let thread = self.thread_at_mut(index);
                    if let Some(Wait::Futex {
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
            number: cyxia_posix::linux_abi::Call,
            target: u64,
            thread_target: u64,
            signal: u64,
        ) -> Result<u64, Errno> {
            let (tid, signal) = if number == cyxia_posix::linux_abi::Call::Tgkill {
                (thread_target, signal)
            } else {
                (target, thread_target)
            };
            let signal = u32::try_from(signal).map_err(|_| Errno::Inval)?;
            if signal as usize > cyxia_posix::signal::COUNT {
                return Err(Errno::Inval);
            }
            if number == cyxia_posix::linux_abi::Call::Tgkill && target != self.status.pid as u64 {
                return Err(Errno::Srch);
            }
            let info = Info {
                code: if number == cyxia_posix::linux_abi::Call::Kill {
                    0
                } else {
                    -6
                },
                sender_pid: self.status.pid,
                address: 0,
            };
            if number == cyxia_posix::linux_abi::Call::Kill {
                // Process groups and broadcast delivery have no implementation.
                // Do not reinterpret kill(0, sig) as a successful self signal.
                if tid == 0 || (tid as i64) < 0 {
                    return Err(Errno::Opnotsupp);
                }
                if tid != self.status.pid as u64 {
                    return self.request_process_signal(tid, signal);
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
                    self.threads.shared.idle_wait = None;
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
