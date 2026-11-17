//! Production launch/publication/wait bodies over explicit host mechanism facades.
//! Real POSIX status/signal types and kernel AI counters remain in use. This is
//! not native execution, MMU/resource-release validation, or a timing claim.
#![allow(dead_code)]

use cyxia_posix::Errno;
use std::sync::atomic::{AtomicBool, Ordering};

static FAIL_IMAGE_LOAD: AtomicBool = AtomicBool::new(false);
pub fn log(_: &[u8]) {}
pub fn hex(_: u64) {}
mod entropy {
    pub fn fill(bytes: &mut [u8]) -> Result<(), cyxia_posix::Errno> {
        bytes.fill(7);
        Ok(())
    }
}
mod process_arch {
    pub const IMAGE_ABI: cyxia_posix::ImageAbi = cyxia_posix::ImageAbi::X86_64;
    pub fn make_writable(_: u64, _: usize) -> Result<(), cyxia_posix::Errno> { Ok(()) }
}
mod exec_memory {
    pub const PROFILE: () = ();
    pub struct StackInput<'a> {
        pub random: [u8; 16],
        pub argv: &'a [&'a [u8]],
        pub envp: &'a [&'a [u8]],
        pub execfn: &'a [u8],
    }
}
mod kernel {
    // AI_SOURCE
    mod threads { pub const MAX_THREADS: usize = 3; }
    mod objects {
        pub fn release<T>(_: &mut T, _: ()) -> Result<(), cyxia_posix::Errno> { Ok(()) }
    }
    mod custody {
        use super::ai::{self, Domain as AiDomain};
        use super::objects;
        use crate::{Errno, FAIL_IMAGE_LOAD, Ordering, process_arch};
        use cyxia_ai_runtime::accounting::{Attempt, Counters};
        use cyxia_posix::{UserState, UserStatus, OPEN_MAX, signal, spawn::Mapping};

        const SLOTS: usize = 8;
        const MAPPED_PAGES: u32 = 8;
        const CODE_BYTES: usize = cyxia_posix::usermem::CODE_BYTES;
        const IMAGE: &[u8] = b"host loader boundary";
        const SERVICES: &[u8] = b"host native loader boundary";
        const PORTED: &[(&str, &str, &[u8])] = &[("probe", "/probe", b"host ELF boundary")];
        const STRING_BYTES: usize = 4096;
        const RECEIPTS: usize = 10;
        fn now() -> u64 { 123 }

        #[derive(Default)]
        struct FileSystem;
        struct PageCount(u32);
        struct ReleaseReceipt(u32);
        impl ReleaseReceipt {
            unsafe fn after_revoke(_: u64, _: u32, pages: PageCount) -> Self { Self(pages.0) }
        }
        struct Snapshot { free: u32 }
        struct GrantLedger { free: u32, starts: usize, fail_start: Option<usize> }
        impl GrantLedger {
            fn snapshot(&self) -> Snapshot { Snapshot { free: self.free } }
            fn release_completed(&mut self, receipt: ReleaseReceipt) -> Result<(), Errno> {
                self.free += receipt.0;
                Ok(())
            }
        }
        #[derive(Default)]
        struct LocalIpc;
        impl LocalIpc {
            fn close_owner(&mut self, _: u32) {}
            fn pair(&mut self, _: u32, _: u32) -> Result<[u32; 2], Errno> { Ok([10, 11]) }
        }
        #[derive(Default)]
        struct Context { result: Option<u64> }
        impl Context {
            fn initialize(_: u64, _: u64, _: bool) -> Result<Self, Errno> { Ok(Self::default()) }
            fn set_argument(&mut self, _: usize, _: u64) {}
            fn set_result(&mut self, result: u64) { self.result = Some(result); }
        }
        #[derive(Clone, Copy)]
        enum Wait { Spawn, Child { pid: i32, status: u64, nonblock: bool } }
        struct Thread {
            tid: u32,
            active: bool,
            waiting: Option<Wait>,
            ready_since: u64,
            context: Context,
            signals: signal::Signals,
        }
        impl Thread {
            fn new(tid: u32) -> Self {
                Self { tid, active: tid != 0, waiting: None, ready_since: 0,
                       context: Context::default(), signals: signal::Signals::new() }
            }
            fn runnable(&self) -> bool { self.active && self.waiting.is_none() }
        }
        struct Pending {
            inner: signal::Signals,
            calls: Vec<(u32, signal::Info)>,
        }
        impl Pending {
            fn raise(&mut self, actions: &signal::Actions, number: u32,
                     info: signal::Info, forced: bool) -> Result<(), Errno> {
                self.calls.push((number, info));
                self.inner.raise(actions, number, info, forced)
            }
        }
        struct Shared { pending: Pending, actions: signal::Actions }
        struct Threads { parked: [Thread; 2], shared: Shared }
        impl Threads {
            fn new() -> Self {
                let mut actions = signal::Actions::new();
                actions.set_action_for(17, signal::Action {
                    handler: 0x0100_0000, restorer: 0x0100_0020,
                    flags: signal::SA_RESTORER, mask: 0,
                }, process_arch::IMAGE_ABI).unwrap();
                Self { parked: core::array::from_fn(|_| Thread::new(0)),
                       shared: Shared { actions, pending: Pending {
                           inner: signal::Signals::new(), calls: Vec::new() } } }
            }
        }
        struct Table([u64; 512]);
        #[derive(Default)]
        struct Storage;
        impl Storage {
            fn clear(&mut self) {}
            fn base_ptr(&self) -> *const u8 { core::ptr::null() }
            fn roots(&self) -> [u64; 0] { [] }
            fn bind(&mut self, _: usize, _: u32) {}
            fn retire(&mut self) {}
        }
        struct SharedMemory;
        impl SharedMemory {
            fn clear(&mut self) {}
            fn roots(&self) -> [(usize, u64); 0] { [] }
        }
        struct Executable;
        impl Executable {
            fn clear(&mut self) {}
            fn roots(&self) -> [(usize, u64); 0] { [] }
            fn load(&mut self, _: usize, _: u32, _: &executable::Plan,
                    _: crate::exec_memory::StackInput<'_>) -> Result<u64, Errno> {
                if FAIL_IMAGE_LOAD.load(Ordering::SeqCst) { Err(Errno::Nomem) }
                else { Ok(0x2000) }
            }
        }
        mod executable {
            pub struct Plan { pub entry: u64 }
            pub fn parse_for_profile(_: &[u8], _: cyxia_posix::ImageAbi, _: ())
                -> Result<Plan, ()> { Ok(Plan { entry: 0x0100_0000 }) }
        }
        struct Path(String);
        impl Path { fn as_str(&self) -> &str { &self.0 } }
        struct Process;
        impl Process {
            fn resolved_path(&self, _: &FileSystem, path: &str) -> Result<Path, Errno> {
                Ok(Path(path.into()))
            }
            fn validate_spawn_descriptors(&self, _: &FileSystem, _: Option<&str>,
                                          _: &[Mapping]) -> Result<(), Errno> { Ok(()) }
            fn spawn_descriptors(&self, _: &mut FileSystem, _: Option<&str>,
                                 _: &[Mapping], _: u32) -> Result<Self, Errno> { Ok(Self) }
            fn close_all(&mut self, _: &mut FileSystem) -> Result<Vec<()>, Errno> { Ok(Vec::new()) }
        }
        mod pty { pub fn release_actor(_: u32) {} }

        // RECEIPT_TYPES

        struct Runner {
            status: UserStatus,
            thread: Thread,
            threads: Threads,
            pending_spawn: Option<Request>,
            pending_signal: Option<()>,
            linux: bool,
            process: Process,
            lease: Option<(u32, u64)>,
            heap: Storage,
            arena: Storage,
            space: Storage,
            executable: Executable,
            shared: SharedMemory,
            l1: Table,
            l2: Table,
            l3: Table,
            write_error: bool,
            written: Vec<(u64, u32)>,
        }
        impl Runner {
            fn new(pid: u32, parent: u32) -> Self {
                Self { status: UserStatus { pid, parent_pid: parent,
                           state: if pid == 0 { UserState::Idle } else { UserState::Running },
                           thread_count: u32::from(pid != 0), ..UserStatus::EMPTY },
                       thread: Thread::new(pid), threads: Threads::new(),
                       pending_spawn: None, pending_signal: None, linux: true,
                       process: Process, lease: (pid != 0).then_some((pid, pid as u64)),
                       heap: Storage, arena: Storage, space: Storage,
                       executable: Executable, shared: SharedMemory,
                       l1: Table([0; 512]), l2: Table([0; 512]), l3: Table([0; 512]),
                       write_error: false, written: Vec::new() }
            }
            // ELF/MMU/resource acquisition is the explicit facade. The actual
            // supervisor launch body must publish before reaching this overwrite.
            fn start(&mut self, _: &str, _: &[u8], pid: u32, _: Option<u64>, _: bool,
                     ledger: &mut GrantLedger, attempt: &mut Attempt) -> Result<(), Errno> {
                ledger.starts += 1;
                if ledger.fail_start == Some(ledger.starts) { return Err(Errno::Io); }
                let (allowed, model) = cyxia_ai_runtime::user_memory_policy(ledger.free, MAPPED_PAGES)
                    .map_err(|_| Errno::Io)?;
                attempt.decided(allowed, model);
                if !allowed { return Err(Errno::Nomem); }
                *self = Self::new(pid, 0);
                ledger.free -= MAPPED_PAGES;
                ai::record(AiDomain::Process, |c| c.grant(u64::from(MAPPED_PAGES)));
                Ok(())
            }
            fn validate(&self, _: u64, _: usize, _: bool) -> Result<(), Errno> { Ok(()) }
            fn copy_to(&mut self, address: u64, bytes: &[u8]) -> Result<(), Errno> {
                if self.write_error { return Err(Errno::Fault); }
                self.written.push((address, u32::from_le_bytes(bytes.try_into().unwrap())));
                Ok(())
            }
            fn clear_all_threads(&mut self) {
                for thread in core::iter::once(&mut self.thread).chain(&mut self.threads.parked) {
                    thread.active = false;
                    thread.waiting = None;
                }
            }
            // RUNNER_METHODS
        }
        struct Supervisor {
            runners: [Runner; SLOTS],
            children: Children,
            ledger: GrantLedger,
            ipc: LocalIpc,
            next_pid: u32,
            focus_pid: u32,
        }
        impl Supervisor {
            // SUPERVISOR_METHODS
        }

        fn counters(domain: AiDomain) -> Counters {
            let mut result = Counters::ZERO;
            ai::record(domain, |value| result = *value);
            result
        }
        fn fixture(auto_reap: bool) -> Supervisor {
            for domain in [AiDomain::Process, AiDomain::SpawnReceipt] {
                ai::record(domain, |c| *c = Counters::ZERO);
            }
            FAIL_IMAGE_LOAD.store(false, Ordering::SeqCst);
            let mut s = Supervisor { runners: core::array::from_fn(|_| Runner::new(0, 0)),
                children: Children::new(), ledger: GrantLedger { free: 48, starts: 0, fail_start: None },
                ipc: LocalIpc, next_pid: 3, focus_pid: 1 };
            s.runners[0] = Runner::new(1, 0);
            s.runners[1] = Runner::new(2, 1);
            s.children.receipts[0] = Some(Receipt { parent: 1, child: 2, status: None, auto_reap });
            ai::record(AiDomain::Process, |c| { c.grant(8); c.grant(8); });
            ai::record(AiDomain::SpawnReceipt, |c| c.grant(1));
            s
        }
        fn terminate(s: &mut Supervisor, slot: usize, state: UserState, code: u32) {
            s.runners[slot].finish(&mut FileSystem, &mut s.ledger, &mut s.ipc, state, code);
        }
        fn wait(s: &mut Supervisor, pid: i32, address: u64, nonblock: bool) {
            s.runners[0].request_wait(pid as i64 as u64, address, u64::from(nonblock), 0).unwrap();
            s.collect_children();
        }
        fn request() -> Request {
            let mut request = Request { tid: 1, flags: 0, path: [0; 96], path_len: 6,
                cwd: [0; 96], cwd_len: None, bytes: [0; STRING_BYTES], args: [[0; 2]; 32],
                argc: 1, env: [[0; 2]; 32], envc: 0,
                mappings: [Mapping { source: -1, target: 0 }; OPEN_MAX], map_count: 0 };
            request.path[..6].copy_from_slice(b"/probe");
            request.bytes[..6].copy_from_slice(b"/probe");
            request.args[0] = [0, 6];
            request
        }
        fn errno(error: Errno) -> u64 { (-(error as i64)) as u64 }
        fn receipt(s: &Supervisor, pid: u32) -> Option<&Receipt> {
            s.children.receipts.iter().flatten().find(|r| r.child == pid)
        }

        #[test]
        fn launch_modes_publish_before_overwrite_and_wait_once() {
            for (mode, native) in [("hello", false), ("idle", true), ("spin", true)] {
                let mut s = fixture(false);
                terminate(&mut s, 1, UserState::Exited, 42);
                let slot = s.launch(mode, native).unwrap();
                assert_eq!(slot, 1);
                assert_eq!(receipt(&s, 2).unwrap().status, Some(42 << 8),
                           "terminal receipt was overwritten at the shared launch boundary");
                assert_eq!(s.runners[0].threads.shared.pending.calls.len(), 1);
                let pending = &mut s.runners[0].threads.shared;
                assert!(matches!(pending.pending.inner.next(&pending.actions),
                    Some(signal::Delivery::Handler { signal: 17, info, .. }) if info.sender_pid == 2));
                pending.pending.inner.consume(17).unwrap();
                wait(&mut s, 2, 0x1000, false);
                assert_eq!(s.runners[0].thread.context.result, Some(2));
                assert_eq!(s.runners[0].written, vec![(0x1000, 42 << 8)]);
                assert!(receipt(&s, 2).is_none());
                for _ in 0..3 { s.collect_children(); }
                assert_eq!(s.runners[0].threads.shared.pending.calls.len(), 1);
                assert_eq!(counters(AiDomain::SpawnReceipt).release_units, 1);
                assert_eq!(counters(AiDomain::Process).release_units, 8);
                wait(&mut s, 2, 0, false);
                assert_eq!(s.runners[0].thread.context.result, Some(errno(Errno::Child)));
            }
        }

        #[test]
        fn actual_spawn_reuses_runner_without_erasing_prior_waitable_child() {
            let mut s = fixture(false);
            terminate(&mut s, 1, UserState::Exited, 23);
            s.runners[0].pending_spawn = Some(request());
            s.runners[0].block(Wait::Spawn);
            s.service_spawn(0, &mut FileSystem);
            assert_eq!(s.runners[0].thread.context.result, Some(3));
            assert_eq!(s.runners[1].status.pid, 3);
            assert_eq!(receipt(&s, 2).unwrap().status, Some(23 << 8));
            assert_eq!(receipt(&s, 3).unwrap().status, None);
            wait(&mut s, 2, 0, false);
            assert_eq!(s.runners[0].thread.context.result, Some(2));
            let c = counters(AiDomain::SpawnReceipt);
            assert_eq!((c.requests, c.approved, c.committed, c.grant_units, c.release_units),
                       (1, 1, 1, 2, 1));
        }

        #[test]
        fn ipc_pair_reuses_terminal_slot_through_the_same_publication_gate() {
            let mut s = fixture(false);
            terminate(&mut s, 1, UserState::Exited, 7);
            assert_eq!(s.pair(&mut FileSystem), Ok([3, 4]));
            assert_eq!(receipt(&s, 2).unwrap().status, Some(7 << 8));
            wait(&mut s, 2, 0, false);
            assert_eq!(s.runners[0].thread.context.result, Some(2));
            assert_eq!(counters(AiDomain::SpawnReceipt).release_units, 1);
        }

        #[test]
        fn failed_launch_and_pair_rollback_keep_the_previous_receipt() {
            for fail_start in [1, 2] {
                let mut s = fixture(false);
                terminate(&mut s, 1, UserState::Exited, 5);
                s.ledger.fail_start = Some(fail_start);
                assert_eq!(s.pair(&mut FileSystem), Err(Errno::Io));
                assert_eq!(receipt(&s, 2).unwrap().status, Some(5 << 8));
                assert_eq!(s.runners[0].threads.shared.pending.calls.len(), 1);
                wait(&mut s, 2, 0, false);
                assert_eq!(s.runners[0].thread.context.result, Some(2));
                for _ in 0..3 { s.collect_children(); }
                assert_eq!(counters(AiDomain::SpawnReceipt).release_units, 1);
            }
        }

        #[test]
        fn exits_signals_faults_kills_and_timeouts_keep_their_wait_encoding() {
            for (state, code, signal, expected) in [
                (UserState::Exited, 300, 0, 44 << 8),
                (UserState::Exited, 143, 15, 15),
                (UserState::Killed, 137, 0, 9),
                (UserState::Fault, 139, 0, 11),
                (UserState::Timeout, 124, 0, 124 << 8),
            ] {
                let mut s = fixture(false);
                s.runners[1].status.exit_signal = signal;
                terminate(&mut s, 1, state, code);
                s.launch("idle", true).unwrap();
                assert_eq!(receipt(&s, 2).unwrap().status, Some(expected));
                let (_, info) = s.runners[0].threads.shared.pending.calls[0];
                assert_eq!(info.code, if expected & 127 == 0 { 1 } else { 2 });
                assert_eq!(info.address, if expected & 127 == 0 { expected as u64 >> 8 }
                                       else { expected as u64 });
                wait(&mut s, 2, 0x1000, false);
                assert_eq!(s.runners[0].written[0].1, expected);
                assert_eq!(counters(AiDomain::SpawnReceipt).release_units, 1);
            }
        }

        #[test]
        fn parent_death_detaches_live_or_finished_child_before_parent_slot_reuse() {
            for child_finished in [false, true] {
                let mut s = fixture(false);
                if child_finished { terminate(&mut s, 1, UserState::Exited, 42); }
                terminate(&mut s, 0, UserState::Killed, 137);
                assert_eq!(s.launch("idle", true), Ok(0));
                assert_eq!(s.runners[1].status.parent_pid, 0);
                assert!(s.children.receipts.iter().all(Option::is_none));
                if !child_finished { terminate(&mut s, 1, UserState::Exited, 42); }
                for _ in 0..3 { s.collect_children(); }
                assert!(s.runners[0].threads.shared.pending.calls.is_empty());
                assert_eq!(counters(AiDomain::SpawnReceipt).release_units, 1);
            }
        }

        #[test]
        fn automatic_reap_notifies_and_releases_exactly_once() {
            let mut s = fixture(true);
            terminate(&mut s, 1, UserState::Exited, 42);
            s.launch("idle", true).unwrap();
            assert!(receipt(&s, 2).is_none());
            assert_eq!(s.runners[0].threads.shared.pending.calls.len(), 1);
            for _ in 0..3 { s.collect_children(); }
            assert_eq!(counters(AiDomain::SpawnReceipt).release_units, 1);
            wait(&mut s, 2, 0, false);
            assert_eq!(s.runners[0].thread.context.result, Some(errno(Errno::Child)));
        }

        #[test]
        fn spawn_admission_reclaims_auto_receipts_before_evaluating_capacity() {
            let mut s = fixture(true);
            for i in 1..8 {
                s.children.receipts[i] = Some(Receipt { parent: 1, child: 100 + i as u32,
                    status: Some(0), auto_reap: false });
                ai::record(AiDomain::SpawnReceipt, |c| c.grant(1));
            }
            terminate(&mut s, 1, UserState::Exited, 42);
            let result = s.spawn_image(0, &request(), &mut FileSystem);
            assert_eq!(result, Ok(3), "auto-reaped receipts did not reach admission");
            assert!(receipt(&s, 2).is_none());
            assert!(receipt(&s, 3).is_some());
            let c = counters(AiDomain::SpawnReceipt);
            assert_eq!((c.approved, c.denied, c.grant_units, c.release_units), (1, 0, 9, 1));
        }

        #[test]
        fn failed_usercopy_preserves_status_for_retry_after_runner_reuse() {
            let mut s = fixture(false);
            terminate(&mut s, 1, UserState::Exited, 17);
            s.launch("idle", true).unwrap();
            s.runners[0].write_error = true;
            wait(&mut s, 2, 0x1000, false);
            assert_eq!(s.runners[0].thread.context.result, Some(errno(Errno::Fault)));
            assert_eq!(receipt(&s, 2).unwrap().status, Some(17 << 8));
            assert_eq!(counters(AiDomain::SpawnReceipt).released, 0);
            s.runners[0].write_error = false;
            wait(&mut s, 2, 0x2000, false);
            assert_eq!(s.runners[0].thread.context.result, Some(2));
            assert_eq!(s.runners[0].written, vec![(0x2000, 17 << 8)]);
            assert_eq!(counters(AiDomain::SpawnReceipt).released, 1);
        }

        #[test]
        fn nonblocking_and_parked_waiters_never_double_consume_a_receipt() {
            let mut s = fixture(false);
            wait(&mut s, 2, 0, true);
            assert_eq!(s.runners[0].thread.context.result, Some(0));
            assert_eq!(counters(AiDomain::SpawnReceipt).released, 0);
            terminate(&mut s, 1, UserState::Exited, 11);
            s.launch("idle", true).unwrap();
            s.runners[0].threads.parked[0] = Thread::new(0x1000_0001);
            s.runners[0].threads.parked[0].waiting =
                Some(Wait::Child { pid: 2, status: 0, nonblock: false });
            wait(&mut s, -1, 0, false);
            assert_eq!(s.runners[0].thread.context.result, Some(2));
            assert_eq!(s.runners[0].threads.parked[0].context.result, Some(errno(Errno::Child)));
            assert!(s.runners[0].threads.parked[0].waiting.is_none());
            assert_eq!(counters(AiDomain::SpawnReceipt).released, 1);
        }

        #[test]
        fn default_ignored_sigchld_does_not_discard_a_waitable_exit() {
            let mut s = fixture(false);
            s.runners[0].threads.shared.actions.set_action_for(17,
                signal::Action::DEFAULT,
                process_arch::IMAGE_ABI).unwrap();
            terminate(&mut s, 1, UserState::Exited, 3);
            s.launch("idle", true).unwrap();
            assert_eq!(s.runners[0].threads.shared.pending.inner.pending(), 0);
            wait(&mut s, 2, 0, false);
            assert_eq!(s.runners[0].thread.context.result, Some(2));
            assert_eq!(s.runners[0].threads.shared.pending.calls.len(), 1);
            assert_eq!(counters(AiDomain::SpawnReceipt).released, 1);
        }

        #[test]
        fn failed_image_load_reclaims_only_its_unpublished_child() {
            let mut s = fixture(false);
            terminate(&mut s, 1, UserState::Exited, 19);
            FAIL_IMAGE_LOAD.store(true, Ordering::SeqCst);
            assert_eq!(s.spawn_image(0, &request(), &mut FileSystem), Err(Errno::Nomem));
            assert_eq!(s.runners[1].status.pid, 3);
            assert!(!s.runners[1].status.state.active());
            assert!(receipt(&s, 3).is_none());
            assert_eq!(receipt(&s, 2).unwrap().status, Some(19 << 8));
            assert_eq!(counters(AiDomain::Process).release_units, 16);
            let c = counters(AiDomain::SpawnReceipt);
            assert_eq!((c.approved, c.failed, c.committed, c.grant_units, c.release_units),
                       (1, 1, 0, 1, 0));
            wait(&mut s, 2, 0, false);
            assert_eq!(s.runners[0].thread.context.result, Some(2));
            assert_eq!(s.runners[0].threads.shared.pending.calls.len(), 1);
            assert_eq!(counters(AiDomain::SpawnReceipt).release_units, 1);
        }
    }
}
