#![allow(dead_code)]
use std::sync::atomic::{AtomicUsize, Ordering};
// PROCESS_CAPACITY
static SWAPS: AtomicUsize = AtomicUsize::new(0);
static RELEASES: AtomicUsize = AtomicUsize::new(0);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
// ERRNO
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
// USER_STATE
mod user {
    use super::*;
    mod threads { // THREAD_CAPACITY
    }
    mod ai {
        pub enum Domain {
            SpawnReceipt,
        }
        pub struct Counter;
        impl Counter {
            pub fn release(&mut self, units: u64) {
                super::super::RELEASES.fetch_add(units as usize, super::super::Ordering::SeqCst);
            }
        }
        pub fn record(_: Domain, update: impl FnOnce(&mut Counter)) {
            update(&mut Counter);
        }
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Wait {
        Child {
            pid: i32,
            status: u64,
            nonblock: bool,
        },
        Sleep,
        Spawn,
    }
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Context {
        result: Option<u64>,
    }
    impl Context {
        fn set_result(&mut self, value: u64) {
            self.result = Some(value);
        }
    }
    #[derive(Clone, Debug, PartialEq, Eq)]
    #[repr(C, align(4096))]
    struct Thread {
        bytes: [u8; 3800],
        tid: u32,
        active: bool,
        waiting: Option<Wait>,
        ready_since: u64,
        context: Context,
    }
    impl Thread {
        // RUNNABLE
    }
    struct Group {
        parked: [Thread; threads::MAX_THREADS - 1],
    }
    struct Status {
        pid: u32,
        state: UserState,
        wakeups: u64,
    }
    struct Runner {
        status: Status,
        thread: Thread,
        threads: Group,
        copy_fault: bool,
        writes: Vec<(u32, u64, Vec<u8>)>,
    }
    fn now() -> u64 {
        77
    }
    impl Runner {
        // Explicit usercopy boundary: validate selected TID and preserve failure.
        fn copy_to(&mut self, address: u64, bytes: &[u8]) -> Result<(), Errno> {
            if self.copy_fault {
                return Err(Errno::Fault);
            }
            self.writes.push((self.thread.tid, address, bytes.to_vec()));
            Ok(())
        }
        // RUNNER_METHODS
    }
    mod collection {
        use super::*;
        // RECEIPT_CAPACITY
        // RECEIPT_TYPES
        struct Supervisor {
            runners: Vec<Runner>,
            children: Children,
            publication: Vec<Receipt>,
            publications: usize,
        }
        fn observed_swap(a: &mut Thread, b: &mut Thread) {
            SWAPS.fetch_add(1, Ordering::SeqCst);
            core::mem::swap(a, b);
        }
        impl Supervisor {
            // Exit publication itself is covered by the real custody harness.
            // Queue one pre-frozen receipt to witness publication-before-wait.
            fn publish_child_exits(&mut self) {
                self.publications += 1;
                for receipt in self.publication.drain(..) {
                    *self
                        .children
                        .receipts
                        .iter_mut()
                        .find(|slot| slot.is_none())
                        .unwrap() = Some(receipt);
                }
            }
            // COLLECT
        }
        fn thread(tid: u32, active: bool) -> Thread {
            Thread {
                bytes: [tid as u8; 3800],
                tid,
                active,
                waiting: None,
                ready_since: 0,
                context: Context { result: None },
            }
        }
        fn setup(active: usize) -> Supervisor {
            assert!(active <= MAX_PROCESSES);
            assert_eq!(core::mem::size_of::<Thread>(), 4096);
            SWAPS.store(0, Ordering::SeqCst);
            RELEASES.store(0, Ordering::SeqCst);
            Supervisor {
                runners: (0..MAX_PROCESSES)
                    .map(|i| Runner {
                        status: Status {
                            pid: 100 + i as u32,
                            state: if i < active {
                                UserState::Running
                            } else {
                                UserState::Idle
                            },
                            wakeups: 0,
                        },
                        thread: thread(10, i < active),
                        threads: Group {
                            parked: core::array::from_fn(|i| thread(11 + i as u32, false)),
                        },
                        copy_fault: false,
                        writes: vec![],
                    })
                    .collect(),
                children: Children::new(),
                publication: vec![],
                publications: 0,
            }
        }
        fn receipt(parent: u32, child: u32, status: Option<u32>) -> Receipt {
            Receipt {
                parent,
                child,
                status,
                auto_reap: false,
            }
        }
        fn wait(thread: &mut Thread, child: i32, nonblock: bool) {
            thread.active = true;
            thread.waiting = Some(Wait::Child {
                pid: child,
                status: 0x1000,
                nonblock,
            });
        }
        #[test]
        fn no_child_waits_exchange_zero_contexts_at_actual_process_and_thread_limits() {
            let mut s = setup(MAX_PROCESSES);
            s.collect_children();
            s.collect_children();
            assert_eq!(
                SWAPS.load(Ordering::SeqCst),
                0,
                "unneeded 4KiB child-collection context exchanges"
            );
            assert_eq!(s.publications, 2);
            assert_eq!(RELEASES.load(Ordering::SeqCst), 0);
        }
        #[test]
        fn other_waits_keep_context_bytes_owner_and_wait_state_without_exchanges() {
            let mut s = setup(1);
            let r = &mut s.runners[0];
            r.thread.waiting = Some(Wait::Spawn);
            for thread in &mut r.threads.parked {
                thread.active = true;
                thread.waiting = Some(Wait::Sleep);
            }
            let selected = r.thread.clone();
            let parked = r.threads.parked.clone();
            s.collect_children();
            assert_eq!(s.runners[0].thread, selected);
            assert_eq!(s.runners[0].threads.parked, parked);
            assert_eq!(s.runners[0].status.state, UserState::Waiting);
            assert_eq!(SWAPS.load(Ordering::SeqCst), 0);
        }
        #[test]
        fn selected_wait_consumes_published_receipt_without_parked_exchanges() {
            let mut s = setup(1);
            wait(&mut s.runners[0].thread, 200, false);
            s.publication.push(receipt(100, 200, Some(23 << 8)));
            s.collect_children();
            assert_eq!(s.runners[0].thread.context.result, Some(200));
            assert_eq!(
                s.runners[0].writes,
                vec![(10, 0x1000, (23u32 << 8).to_le_bytes().to_vec())]
            );
            assert!(s.children.receipts.iter().all(Option::is_none));
            assert_eq!(RELEASES.load(Ordering::SeqCst), 1);
            assert_eq!(s.publications, 1);
            assert_eq!(SWAPS.load(Ordering::SeqCst), 0);
        }
        #[test]
        fn last_legal_parked_wait_restores_selected_owner_and_result() {
            let mut s = setup(1);
            let selected = s.runners[0].thread.clone();
            let last = threads::MAX_THREADS - 2;
            wait(&mut s.runners[0].threads.parked[last], 200, false);
            let tid = s.runners[0].threads.parked[last].tid;
            s.children.receipts[0] = Some(receipt(100, 200, Some(0)));
            s.collect_children();
            assert_eq!(s.runners[0].thread, selected);
            let restored = &s.runners[0].threads.parked[last];
            assert_eq!(restored.context.result, Some(200));
            assert_eq!(restored.ready_since, 77);
            assert_eq!(restored.bytes[0], tid as u8);
            assert_eq!(s.runners[0].writes[0].0, tid);
            assert_eq!(SWAPS.load(Ordering::SeqCst), 2);
        }
        #[test]
        fn copy_fault_retains_receipt_until_successful_retry_and_releases_once() {
            let mut s = setup(1);
            let last = threads::MAX_THREADS - 2;
            wait(&mut s.runners[0].threads.parked[last], 200, false);
            s.runners[0].copy_fault = true;
            s.children.receipts[0] = Some(receipt(100, 200, Some(7 << 8)));
            s.collect_children();
            assert_eq!(
                s.runners[0].threads.parked[last].context.result,
                Some((-(Errno::Fault as i64)) as u64)
            );
            assert!(s.children.receipts[0].is_some());
            assert_eq!(RELEASES.load(Ordering::SeqCst), 0);
            wait(&mut s.runners[0].threads.parked[last], 200, false);
            s.runners[0].copy_fault = false;
            s.collect_children();
            assert_eq!(s.runners[0].threads.parked[last].context.result, Some(200));
            assert!(s.children.receipts[0].is_none());
            assert_eq!(RELEASES.load(Ordering::SeqCst), 1);
            assert_eq!(SWAPS.load(Ordering::SeqCst), 4);
        }
        #[test]
        fn two_waiters_consume_one_receipt_in_existing_thread_order() {
            let mut s = setup(1);
            for i in 0..2 {
                wait(&mut s.runners[0].threads.parked[i], 200, false);
            }
            s.children.receipts[0] = Some(receipt(100, 200, Some(0)));
            s.collect_children();
            assert_eq!(s.runners[0].threads.parked[0].context.result, Some(200));
            assert_eq!(
                s.runners[0].threads.parked[1].context.result,
                Some((-(Errno::Child as i64)) as u64)
            );
            assert_eq!(s.runners[0].writes.len(), 1);
            assert_eq!(RELEASES.load(Ordering::SeqCst), 1);
            assert_eq!(SWAPS.load(Ordering::SeqCst), 4);
        }
        #[test]
        fn nonblocking_wait_returns_zero_and_blocking_wait_remains_parked() {
            let mut s = setup(1);
            wait(&mut s.runners[0].thread, -1, true);
            let last = threads::MAX_THREADS - 2;
            wait(&mut s.runners[0].threads.parked[last], 200, false);
            s.children.receipts[0] = Some(receipt(100, 200, None));
            s.collect_children();
            assert_eq!(s.runners[0].thread.context.result, Some(0));
            assert!(s.runners[0].threads.parked[last].waiting.is_some());
            assert_eq!(s.runners[0].threads.parked[last].context.result, None);
            assert!(s.runners[0].writes.is_empty());
            assert_eq!(RELEASES.load(Ordering::SeqCst), 0);
        }
        #[test]
        fn unrelated_parent_and_auto_reap_receipts_are_not_consumed() {
            let mut s = setup(1);
            wait(&mut s.runners[0].thread, -1, true);
            s.children.receipts[0] = Some(receipt(999, 200, Some(0)));
            s.children.receipts[1] = Some(Receipt {
                auto_reap: true,
                ..receipt(100, 201, Some(0))
            });
            s.collect_children();
            assert_eq!(
                s.runners[0].thread.context.result,
                Some((-(Errno::Child as i64)) as u64)
            );
            assert!(s.children.receipts[0].is_some() && s.children.receipts[1].is_some());
            assert_eq!(RELEASES.load(Ordering::SeqCst), 0);
        }
    }
}
