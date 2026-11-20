#![allow(dead_code)]
extern crate self as cyxia_ai_runtime;
use std::sync::atomic::{AtomicUsize, Ordering};
// PRODUCTION_CAPACITY
static SWAPS: AtomicUsize = AtomicUsize::new(0);
static CHOICE: AtomicUsize = AtomicUsize::new(0);
#[derive(Clone, Copy)]
pub enum DecisionSource { Model }
pub struct UserCandidate { waiting_ms: u64, cpu_bound: bool }
pub struct Choice { index: usize, model: u64, source: DecisionSource }
fn choose(candidates: &[Option<UserCandidate>]) -> Result<Option<Choice>, ()> {
    let index = CHOICE.load(Ordering::SeqCst);
    Ok(candidates[index].as_ref().map(|_| Choice { index, model: 8193, source: DecisionSource::Model }))
}
pub fn full_os_thread_dispatch_policy(candidates: &[Option<UserCandidate>]) -> Result<Option<Choice>, ()> { choose(candidates) }
pub fn user_dispatch_policy(candidates: &[Option<UserCandidate>]) -> Result<Option<Choice>, ()> { choose(candidates) }
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
    struct Status { state: UserState }
    #[derive(Clone, PartialEq, Eq, Debug)]
    struct Signals { tid: u32, deliveries: u32 }
    #[derive(Clone, PartialEq, Eq, Debug)]
    #[repr(C, align(4096))]
    struct Thread {
        context: [u8; 3900], active: bool, waiting: Option<()>,
        signals: Signals, ready_since: u64, cpu_bound: bool,
    }
    impl Thread {
        // PRODUCTION_RUNNABLE
    }
    struct Pending { order: Vec<u32> }
    impl Pending {
        fn transfer_ready(&mut self, signals: &mut Signals, _: &()) {
            self.order.push(signals.tid);
            signals.deliveries += 1;
        }
    }
    struct Shared { pending: Pending, actions: (), dispatch: Option<(u64, DecisionSource)> }
    struct Group { parked: [Thread; MAX_THREADS - 1], shared: Shared }
    struct LocalIpc { wakes: Vec<u32> }
    struct Runner { status: Status, thread: Thread, threads: Group }
    impl Runner {
        fn thread_at(&self, index: usize) -> &Thread {
            if index == 0 { &self.thread } else { &self.threads.parked[index - 1] }
        }
        // Explicit wake fixture. Linux wait/restart semantics are covered by
        // their own cases and real guests; this observes preparation order.
        fn wake(&mut self, time: u64, ipc: &mut LocalIpc) {
            if !self.thread.active || self.thread.waiting.is_none() { return; }
            ipc.wakes.push(self.thread.signals.tid);
            self.thread.context[0] = 0xee;
            self.thread.waiting = None;
            self.thread.ready_since = time;
        }
    }
    mod preparation {
        use super::*;
        fn observed_swap(left: &mut Thread, right: &mut Thread) {
            SWAPS.fetch_add(1, Ordering::SeqCst);
            core::mem::swap(left, right);
        }
        impl Runner {
            // PRODUCTION_PREPARE
        }
        fn thread(index: usize, active: bool, waiting: bool) -> Thread {
            Thread { context: [index as u8; 3900], active,
                waiting: waiting.then_some(()), signals: Signals { tid: index as u32, deliveries: 0 },
                ready_since: 0, cpu_bound: false }
        }
        fn runner(parked_active: bool, waiting: bool) -> Runner {
            assert_eq!(core::mem::size_of::<Thread>(), 4096);
            SWAPS.store(0, Ordering::SeqCst); CHOICE.store(0, Ordering::SeqCst);
            Runner { status: Status { state: UserState::Running }, thread: thread(0, true, waiting),
                threads: Group { parked: core::array::from_fn(|i| thread(i + 1, parked_active, waiting)),
                    shared: Shared { pending: Pending { order: vec![] }, actions: (), dispatch: None } } }
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
            assert_eq!(SWAPS.load(Ordering::SeqCst), 2 * (MAX_THREADS - 1));
            assert_eq!(ipc.wakes, (0..MAX_THREADS as u32).collect::<Vec<_>>());
            for i in 0..MAX_THREADS {
                let thread = runner.thread_at(i);
                assert_eq!(thread.signals.tid, i as u32);
                assert_eq!(thread.context[0], 0xee); assert_eq!(thread.context[1], i as u8);
                assert_eq!(thread.ready_since, 50); assert!(thread.waiting.is_none());
            }
        }
        #[test]
        fn selecting_last_parked_thread_performs_only_the_actual_selection_swap() {
            let mut runner = runner(false, false); let last = MAX_THREADS - 2;
            runner.threads.parked[last].active = true;
            CHOICE.store(MAX_THREADS - 1, Ordering::SeqCst);
            let mut ipc = LocalIpc { wakes: vec![] }; runner.prepare_threads(50, &mut ipc);
            assert_eq!(SWAPS.load(Ordering::SeqCst), 1);
            assert_eq!(runner.thread.signals.tid, (MAX_THREADS - 1) as u32);
            assert_eq!(runner.thread.context[10], (MAX_THREADS - 1) as u8);
            assert_eq!(runner.threads.parked[last].signals.tid, 0);
            assert_eq!(runner.threads.shared.pending.order, vec![0, (MAX_THREADS - 1) as u32]);
        }
    }
}
