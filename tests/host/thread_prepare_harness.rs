#![allow(dead_code)]
extern crate self as cyxia_ai_runtime;
use std::sync::atomic::{AtomicUsize, Ordering};
// PRODUCTION_CAPACITY
static SWAPS: AtomicUsize = AtomicUsize::new(0);
static CHOICE: AtomicUsize = AtomicUsize::new(0);
static IPC_EPOCH: AtomicUsize = AtomicUsize::new(0);
static FLUSHED: AtomicUsize = AtomicUsize::new(0);
static RUNNABLE_CHECKS: AtomicUsize = AtomicUsize::new(0);
static EPOLL_SAMPLES: AtomicUsize = AtomicUsize::new(0);
#[derive(Clone, Copy)]
pub enum DecisionSource { Model }
#[derive(Clone, Copy, Debug)]
pub struct UserCandidate { waiting_ms: u64, cpu_bound: bool }
pub struct Choice { index: usize, model: u64, source: DecisionSource }
fn choose(candidates: &[Option<UserCandidate>]) -> Result<Option<Choice>, ()> {
    let index = CHOICE.load(Ordering::SeqCst);
    Ok(candidates[index].as_ref().map(|_| Choice { index, model: 8193, source: DecisionSource::Model }))
}
pub fn full_os_thread_dispatch_policy(candidates: &[Option<UserCandidate>]) -> Result<Option<Choice>, ()> { choose(candidates) }
pub fn user_dispatch_policy(candidates: &[Option<UserCandidate>]) -> Result<Option<Choice>, ()> { choose(candidates) }
fn now_ns() -> u64 { 50 }
mod storage {
    pub fn checkpoint_complete(generation: u64) -> Result<u64, super::user::Errno> {
        if generation == 5 || generation == super::FLUSHED.load(super::Ordering::SeqCst) as u64 {
            Ok(generation)
        } else {
            Err(super::user::Errno::Again)
        }
    }
}
mod user {
    use super::*;
    mod ai {
        pub enum Domain { CpuThread }
        pub struct Counter;
        impl Counter { pub fn cancelled(&mut self) {} pub fn proposal(&mut self, _: u64) {} }
        pub fn record(_: Domain, update: impl FnOnce(&mut Counter)) { update(&mut Counter); }
    }
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum UserState { Running, Waiting, Exited }
    impl UserState { fn active(self) -> bool { self != Self::Exited } }
    struct Status { state: UserState, waits: u64, wakeups: u64, pid: u32 }
    #[derive(Clone, PartialEq, Eq, Debug)]
    struct Signals { tid: u32, deliveries: u32, signalled: bool }
    #[derive(Clone, PartialEq, Eq, Debug)]
    struct PollSnapshot;
    impl PollSnapshot { fn invalidate(&mut self) {} }
    #[derive(Clone, PartialEq, Eq, Debug)]
    #[repr(C, align(4096))]
    struct Thread {
        context: Context, tid: u32, active: bool, waiting: Option<Wait>,
        retry_syscall: bool, retry_descriptor: Option<(i32, u64)>,
        poll_snapshot: PollSnapshot,
        signals: Signals, ready_since: u64, cpu_bound: bool,
    }
    impl Thread {
        // PRODUCTION_RUNNABLE
    }
    struct Pending { order: Vec<u32>, signal: bool }
    impl Pending {
        fn pending(&self) -> u64 { u64::from(self.signal) }
        fn transfer_ready(&mut self, signals: &mut Signals, _: &()) {
            if self.signal {
                signals.signalled = true;
                self.signal = false;
            }
            self.order.push(signals.tid);
            signals.deliveries += 1;
        }
    }
    // PRODUCTION_IDLE_TYPE
    struct Shared { idle_wait: Option<IdleWait>, pending: Pending, actions: (), dispatch: Option<(u64, DecisionSource)>, parked_active: u16 }
    // PRODUCTION_THREAD_SLOTS
    struct Group { parked: [Thread; MAX_THREADS - 1], shared: Shared }
    impl Group {
        // PRODUCTION_GROUP
    }
    struct LocalIpc { wakes: Vec<u32> }
    struct Runner { status: Status, thread: Thread, threads: Group, linux: bool, process: Process, memory: [u8; 64] }
    // WAKE_FIXTURE
    mod preparation {
        use super::*;
        // PRODUCTION_IDLE_IMPL
        fn observed_swap(left: &mut Thread, right: &mut Thread) {
            SWAPS.fetch_add(1, Ordering::SeqCst);
            core::mem::swap(left, right);
        }
        impl Runner {
            // PRODUCTION_PREPARE
        }
        fn thread(index: usize, active: bool, waiting: bool) -> Thread {
            Thread { context: Context { bytes: [index as u8; 3800], result: 123, syscall: 0, pc: 100 }, tid: index as u32, active,
            retry_syscall: false, retry_descriptor: None, poll_snapshot: PollSnapshot,
                waiting: waiting.then_some(Wait::Ipc(index as u32, ())), signals: Signals { tid: index as u32, deliveries: 0, signalled: false },
                ready_since: 0, cpu_bound: false }
        }
        fn runner(parked_active: bool, waiting: bool) -> Runner {
            assert_eq!(core::mem::size_of::<Thread>(), 4096);
            SWAPS.store(0, Ordering::SeqCst); CHOICE.store(0, Ordering::SeqCst);
            IPC_EPOCH.store(0, Ordering::SeqCst); FLUSHED.store(0, Ordering::SeqCst);
            let mut runner = Runner { status: Status { state: UserState::Running, pid: 41, waits: 0, wakeups: 0 },
                linux: true, process: Process, memory: [0; 64], thread: thread(0, true, waiting),
                threads: Group { parked: core::array::from_fn(|i| thread(i + 1, parked_active, waiting)),
                    shared: Shared { idle_wait: None, pending: Pending { order: vec![], signal: false }, actions: (), dispatch: None, parked_active: 0 } } };
            for slot in 0..MAX_THREADS - 1 {
                runner.threads.sync_parked_slot(slot);
            }
            runner
        }
        #[test]
        fn inactive_slots_do_not_copy_contexts_or_receive_signals() {
            let mut runner = runner(false, false); let before = runner.threads.parked.clone();
            let mut ipc = LocalIpc { wakes: vec![] };
            runner.prepare_threads(50, &mut ipc);
            assert_eq!(SWAPS.load(Ordering::SeqCst), 0);
            assert_eq!(runner.threads.parked, before);
            assert_eq!(runner.threads.shared.pending.order, vec![0]);
            assert!(ipc.wakes.is_empty());
        }
        #[test]
        fn ready_slots_receive_pending_signals_in_order_without_context_copies() {
            let mut runner = runner(true, false); let before = runner.threads.parked.clone();
            let mut ipc = LocalIpc { wakes: vec![] };
            runner.prepare_threads(50, &mut ipc);
            assert_eq!(SWAPS.load(Ordering::SeqCst), 0);
            assert_eq!(runner.threads.shared.pending.order, (0..MAX_THREADS as u32).collect::<Vec<_>>());
            for (after, before) in runner.threads.parked.iter().zip(before) {
                assert_eq!(after.context, before.context);
                assert_eq!(after.signals.deliveries, 1);
                assert_eq!(after.ready_since, before.ready_since);
            }
            assert!(ipc.wakes.is_empty());
        }
        #[test]
        fn blocked_contexts_still_wake_in_order_and_restore_their_owner() {
            let mut runner = runner(true, true); let mut ipc = LocalIpc { wakes: vec![] };
            runner.prepare_threads(50, &mut ipc);
            assert_eq!(SWAPS.load(Ordering::SeqCst), 0);
            assert_eq!(ipc.wakes, (0..MAX_THREADS as u32).collect::<Vec<_>>());
            for i in 0..MAX_THREADS {
                let thread = runner.thread_at(i);
                assert_eq!(thread.signals.tid, i as u32);
                assert_eq!(thread.context.result, (-(Errno::Badf as i64)) as u64);
                assert_eq!(thread.context.bytes[1], i as u8);
                assert_eq!(thread.ready_since, 50); assert!(thread.waiting.is_none());
            }
        }
        #[test]
        fn selecting_last_parked_thread_performs_only_the_actual_selection_swap() {
            let mut runner = runner(false, false); let last = MAX_THREADS - 2;
            runner.threads.parked[last].active = true;
            runner.threads.sync_parked_slot(last);
            CHOICE.store(MAX_THREADS - 1, Ordering::SeqCst);
            let mut ipc = LocalIpc { wakes: vec![] }; runner.prepare_threads(50, &mut ipc);
            assert_eq!(SWAPS.load(Ordering::SeqCst), 1);
            assert_eq!(runner.thread.signals.tid, (MAX_THREADS - 1) as u32);
            assert_eq!(runner.thread.context.bytes[10], (MAX_THREADS - 1) as u8);
            assert_eq!(runner.threads.parked[last].signals.tid, 0);
            assert_eq!(runner.threads.shared.pending.order, vec![0, (MAX_THREADS - 1) as u32]);
        }
        #[test]
        fn parked_waits_use_their_own_descriptors_buffers_results_and_deadlines() {
            let mut r = runner(true, false);
            let selected = r.thread.clone();
            let waits = [
                Wait::Futex { address: 0x4000, until: 49 },
                Wait::Poll { address: 1, count: 3, until: 100 },
                Wait::Epoll { descriptor: 7, identity: 99, epoch: 1, address: 2, count: 4, until: 100 },
                Wait::Epoll { descriptor: 7, identity: 55, epoch: 1, address: 3, count: 5, until: 100 },
                Wait::TimerRead { descriptor: 7, identity: 99 },
                Wait::Display,
                Wait::Checkpoint(5),
            ];
            for (thread, wait) in r.threads.parked.iter_mut().zip(waits) { thread.waiting = Some(wait); }
            r.prepare_threads(50, &mut LocalIpc { wakes: vec![] });
            assert_eq!(r.thread.context, selected.context);
            assert_eq!(&r.memory[..4], &[0, 3, 4, 0]);
            let parked = &r.threads.parked;
            assert_eq!(parked[0].context.result, (-110i64) as u64);
            assert_eq!(parked[1].context.result, 1);
            assert_eq!(parked[2].context.result, 2);
            assert_eq!(parked[3].context.result, (-9i64) as u64);
            assert_eq!(parked[4].waiting, Some(waits[4]));
            assert_eq!(parked[5].waiting, Some(Wait::Display));
            assert_eq!(parked[6].context.result, 0);
            assert_eq!(r.status.wakeups, 5);
            r.complete_display(6, false, 75);
            assert!(r.threads.parked[5].waiting.is_none());
            assert_eq!(r.threads.parked[5].context.result, (-5i64) as u64);
            assert_eq!(r.threads.parked[5].ready_since, 75);
            assert_eq!(r.status.wakeups, 6);
            assert_eq!(r.thread.context, selected.context);
            assert_eq!(SWAPS.load(Ordering::SeqCst), 0);
        }
        #[test]
        fn unchanged_parked_epoll_skips_scans_until_timeout() {
            EPOLL_SAMPLES.store(0, Ordering::SeqCst);
            let mut r = runner(true, false);
            let mut ipc = LocalIpc { wakes: vec![] };
            r.threads.parked[0].waiting = Some(Wait::Epoll {
                descriptor: 7, identity: 99, epoch: 0, address: 0, count: 1, until: 100,
            });
            for time in 40..80 {
                r.prepare_threads(time, &mut ipc);
            }
            assert!(r.threads.parked[0].waiting.is_some());
            assert_eq!(EPOLL_SAMPLES.load(Ordering::SeqCst), 0);
            r.prepare_threads(100, &mut ipc);
            assert!(r.threads.parked[0].waiting.is_none());
            assert_eq!(EPOLL_SAMPLES.load(Ordering::SeqCst), 1);
            assert_eq!(r.threads.parked[0].context.result, 0);
        }
        #[test]
        fn parked_signals_restart_only_the_interrupted_thread_and_copy_its_sleep_remainder() {
            let mut r = runner(true, false);
            r.thread.context.syscall = 999;
            let selected = r.thread.clone();
            let a = &mut r.threads.parked[0];
            a.waiting = Some(Wait::Futex { address: 4, until: u64::MAX });
            a.signals.signalled = true;
            let b = &mut r.threads.parked[1];
            b.waiting = Some(Wait::Nanosleep { until: 15_000, deadline_ns: 2_000_000_080, remaining: 16 });
            b.signals.signalled = true;
            b.retry_syscall = true;
            b.retry_descriptor = Some((7, 99));
            b.context.pc = 202;
            r.prepare_threads(50, &mut LocalIpc { wakes: vec![] });
            assert_eq!(r.thread.context, selected.context);
            let [a, b, ..] = &r.threads.parked;
            assert!(a.retry_syscall);
            assert_eq!(a.context.pc, 98);
            assert_eq!(a.context.result, 123);
            assert_eq!(b.context.pc, 204);
            assert_eq!(b.context.result, (-4i64) as u64);
            assert!(!b.retry_syscall);
            assert_eq!(b.retry_descriptor, None);
            assert_eq!(u64::from_le_bytes(r.memory[16..24].try_into().unwrap()), 2);
            assert_eq!(u64::from_le_bytes(r.memory[24..32].try_into().unwrap()), 30);
            assert_eq!(r.status.wakeups, 2);
        }
        #[test]
        fn parked_socket_and_timer_retries_validate_the_waiting_threads_weak_binding() {
            let mut r = runner(true, false);
            r.thread.retry_descriptor = Some((3, 10));
            let a = &mut r.threads.parked[0];
            a.waiting = Some(Wait::Unix { handle: 10, descriptor: 7, write: false });
            a.retry_descriptor = Some((7, 99));
            let wait = a.waiting;
            let b = &mut r.threads.parked[1];
            b.waiting = wait;
            b.retry_descriptor = Some((7, 101));
            let c = &mut r.threads.parked[2];
            c.waiting = Some(Wait::TimerRead { descriptor: 7, identity: 50 });
            r.prepare_threads(50, &mut LocalIpc { wakes: vec![] });
            assert!(r.threads.parked[0].waiting.is_some());
            assert!(r.threads.parked[1].waiting.is_none());
            assert!(r.threads.parked[2].waiting.is_none());
            assert_eq!(r.status.wakeups, 2);
        }
        #[test]
        fn idle_prepare_skips_all_contexts_until_the_first_deadline_or_direct_completion() {
            let mut r = runner(true, false);
            let mut ipc = LocalIpc { wakes: vec![] };
            r.thread.waiting = Some(Wait::Sleep(10_000));
            for thread in &mut r.threads.parked {
                thread.waiting = Some(Wait::Futex { address: 96, until: 1000 });
            }
            r.threads.parked[0].waiting = Some(Wait::Display);
            r.prepare_threads(0, &mut ipc);
            assert_eq!(r.status.state, UserState::Waiting);
            r.threads.shared.pending.order.clear();
            RUNNABLE_CHECKS.store(0, Ordering::SeqCst);
            for t in 1..1000 { r.prepare_threads(t, &mut ipc); }
            assert_eq!(r.threads.shared.pending.order.len(), 0, "idle thread scans");
            assert_eq!(RUNNABLE_CHECKS.load(Ordering::SeqCst), 0, "idle candidate scans");
            r.prepare_threads(1000, &mut ipc);
            assert_eq!(r.status.state, UserState::Running);
            assert_eq!(r.threads.parked[1].context.result, (-110i64) as u64);
            assert_eq!(r.threads.parked[1].ready_since, 1000);
            assert_eq!(r.threads.parked[0].waiting, Some(Wait::Display));
        }
        #[test]
        fn cached_indefinite_wait_observes_the_first_signal_or_display_completion() {
            for signal in [true, false] {
                let mut r = runner(true, false);
                r.thread.waiting = Some(Wait::Child { pid: -1, status: 0, nonblock: false });
                for thread in &mut r.threads.parked { thread.waiting = Some(Wait::Display); }
                let mut ipc = LocalIpc { wakes: vec![] };
                r.prepare_threads(1, &mut ipc);
                r.prepare_threads(2, &mut ipc);
                if signal {
                    r.threads.shared.pending.signal = true;
                } else {
                    r.complete_display(1, true, 3);
                }
                r.prepare_threads(3, &mut ipc);
                assert_eq!(r.status.state, UserState::Running);
                assert_eq!(r.thread.retry_syscall, signal);
                assert_eq!(r.status.wakeups, 1);
            }
            // A new syscall may replace a completed registration before an
            // intervening prepare. Its earlier deadline must take precedence.
            let mut r = runner(false, false);
            let mut ipc = LocalIpc { wakes: vec![] };
            r.block(Wait::Display);
            r.prepare_threads(1, &mut ipc);
            r.complete_display(0, true, 2);
            r.block(Wait::Sleep(5));
            r.prepare_threads(5, &mut ipc);
            assert!(r.thread.waiting.is_none());
            assert_eq!(r.thread.ready_since, 5);
        }
        #[test]
        fn ipc_and_checkpoint_generations_rescan_on_their_own_producer_events() {
            let mut r = runner(false, false);
            r.thread.waiting = Some(Wait::Ipc(100, ()));
            let mut ipc = LocalIpc { wakes: vec![] };
            r.prepare_threads(1, &mut ipc);
            for t in 2..20 { r.prepare_threads(t, &mut ipc); }
            assert_eq!(ipc.wakes, vec![100], "repeated unchanged IPC sample");
            IPC_EPOCH.store(1, Ordering::SeqCst);
            r.prepare_threads(20, &mut ipc);
            assert_eq!(r.thread.ready_since, 20);
            assert_eq!(ipc.wakes, vec![100, 100]);
            r.thread.waiting = Some(Wait::Checkpoint(6));
            r.prepare_threads(21, &mut ipc);
            r.threads.shared.pending.order.clear();
            r.prepare_threads(22, &mut ipc);
            assert!(r.threads.shared.pending.order.is_empty());
            FLUSHED.store(6, Ordering::SeqCst);
            r.prepare_threads(23, &mut ipc);
            assert!(r.thread.waiting.is_none());
            assert_eq!(r.thread.ready_since, 23);
        }
        #[test]
        fn runnable_query_skips_empty_context_slots() {
            let mut runner = runner(false, true);
            let last = MAX_THREADS - 2;
            runner.threads.parked[last] = thread(MAX_THREADS - 1, true, false);
            runner.threads.sync_parked_slot(last);
            RUNNABLE_CHECKS.store(0, Ordering::SeqCst);
            assert!(runner.has_runnable_thread());
            assert_eq!(RUNNABLE_CHECKS.load(Ordering::SeqCst), 2);
            // Promoting a parked thread after exit of the previous foreground
            // leaves the selected park slot available again.
            runner.thread.active = false;
            CHOICE.store(MAX_THREADS - 1, Ordering::SeqCst);
            runner.prepare_threads(50, &mut LocalIpc { wakes: vec![] });
            assert_eq!(runner.thread.signals.tid, (MAX_THREADS - 1) as u32);
            assert_eq!(runner.threads.parked_slots().count(), 0);
        }
    }
}
