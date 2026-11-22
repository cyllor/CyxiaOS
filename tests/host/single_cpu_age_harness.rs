//! Single-CPU dispatch must restart the winner's age after a granted slice.
//! The real `dispatch_parallel` and `process_dispatch_policy` are injected; only
//! the AP publication machinery, accounting and the clock are fixtures. The AP
//! branch never executes because `online_cpus()` reports CPU0 alone.
#![allow(dead_code)]
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

static CLOCK_NS: AtomicU64 = AtomicU64::new(0);
static SELECTED: [AtomicUsize; 2] = [AtomicUsize::new(0), AtomicUsize::new(0)];

pub const SLOTS: usize = 2;
pub use cyxia_ai_runtime::{UserCandidate, UserDispatch};
pub use cyxia_contracts::DecisionSource;
pub use std::fmt::Write;

pub mod cyxia_shell {
    pub use crate::Shell;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Errno {
    Again,
}
pub type Exit = Result<(), Errno>;

pub mod ai {
    #[derive(Clone, Copy)]
    pub enum AiDomain {
        CpuProcess,
    }
    pub struct Counter;
    impl Counter {
        pub fn proposal(&mut self, _: u64) {}
        pub fn cancelled(&mut self) {}
        pub fn dispatch(&mut self, _: crate::DecisionSource) {}
    }
    pub fn record(_: AiDomain, update: impl FnOnce(&mut Counter)) {
        update(&mut Counter);
    }
}
pub use ai::AiDomain;

pub mod runtime {
    pub fn online_cpus() -> u32 {
        1
    }
    pub fn idle_until_while(_: u64, _: impl FnMut() -> bool) -> Result<(), ()> {
        Ok(())
    }
}

pub mod dispatch {
    use super::{Exit, Space};
    #[derive(Clone, Copy)]
    pub struct Context;
    #[derive(Clone, Copy)]
    pub struct Job {
        pub context: Context,
        pub space: Space,
        pub deadline_ns: u64,
    }
    pub struct Completion {
        pub job: Job,
        pub exit: Exit,
        pub entered: bool,
        pub entered_ns: u64,
        pub returned_ns: u64,
        pub local_syscalls: u64,
    }
    pub struct Submission {
        pub ticket: usize,
        pub wake: bool,
    }
    pub struct Drained {
        pub completions: [Option<Completion>; 3],
    }
    pub fn begin_phase() {}
    pub fn submit(_: usize, job: Job) -> Result<Submission, ((), Job)> {
        Err(((), job))
    }
    pub fn try_collect(_: usize) -> Result<Option<Completion>, ()> {
        Ok(None)
    }
    pub fn is_complete(_: usize) -> Result<bool, ()> {
        Ok(false)
    }
    pub fn drain(_: &[usize], _: u64) -> Result<Drained, ()> {
        Ok(Drained { completions: [None, None, None] })
    }
}

#[derive(Clone, Copy)]
pub struct Space;
impl Space {
    pub fn quiescent(&self) -> Result<(), ()> {
        Ok(())
    }
}
#[derive(Clone, Copy)]
pub struct Slice {
    pub budget_ms: u64,
}
pub struct FileSystem;
pub struct Task {
    pub state: cyxia_ai_runtime::TaskState,
    pub paused: bool,
}
pub struct Runtime;
impl Runtime {
    pub fn tasks(&self) -> core::slice::Iter<'_, Task> {
        [].iter()
    }
}
pub struct Shell {
    fs: FileSystem,
    runtime: Runtime,
}
impl Shell {
    pub fn fs_mut(&mut self) -> &mut FileSystem {
        &mut self.fs
    }
    pub fn runtime_mut(&mut self) -> &mut Runtime {
        &mut self.runtime
    }
}
pub struct Ledger;
impl Ledger {
    pub fn snapshot(&self) -> Free {
        Free { free: 0 }
    }
}
pub struct Free {
    pub free: u64,
}
pub struct Ipc;
pub struct Out;
impl std::fmt::Write for Out {
    fn write_str(&mut self, _: &str) -> std::fmt::Result {
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UserState {
    Running,
    Waiting,
    Exited,
}
impl UserState {
    pub fn active(self) -> bool {
        self != Self::Exited
    }
}
#[derive(Clone, Copy)]
pub struct Status {
    pub state: UserState,
    pub pid: u32,
    pub rank_model: u64,
    pub ai_selections: u64,
    pub guard_selections: u64,
    pub syscalls: u64,
    pub esr: u64,
    pub far: u64,
    pub code: u64,
}
#[derive(Clone, Copy)]
pub struct Thread {
    pub tid: u32,
    pub ready_since: u64,
    pub cpu_bound: bool,
    pub context: dispatch::Context,
}

pub struct Runner {
    pub status: Status,
    pub thread: Thread,
    pub space: Space,
    index: usize,
}
impl Runner {
    /// A CPU-bound slice that stays runnable: it never blocks, so only the
    /// dispatcher can restart its age.
    pub fn tick(&mut self, _: &mut FileSystem, _: &mut Ledger, _: &mut Ipc, _: usize) -> bool {
        SELECTED[self.index].fetch_add(1, Ordering::SeqCst);
        self.thread.cpu_bound = true;
        true
    }
    pub fn record_selection(&mut self, _: UserDispatch, _: bool) {}
    pub fn prepare_job(
        &mut self,
        _: &mut FileSystem,
        _: &mut Ledger,
        _: &mut Ipc,
        _: usize,
    ) -> Option<(dispatch::Job, Slice)> {
        None
    }
    pub fn complete_job(
        &mut self,
        _: Slice,
        _: Exit,
        _: bool,
        _: u64,
        _: &mut FileSystem,
        _: &mut Ledger,
        _: &mut Ipc,
    ) {
    }
}
pub struct Supervisor {
    pub runners: [Runner; SLOTS],
    pub ledger: Ledger,
    pub ipc: Ipc,
}
impl Supervisor {
    pub fn report_dispatch(&mut self, _: usize, _: &mut impl std::fmt::Write) {}
}
pub fn receipt(_: usize, _: u32, _: u32, _: &dispatch::Completion) {}
pub fn now_ns() -> u64 {
    CLOCK_NS.load(Ordering::SeqCst)
}
pub fn now() -> u64 {
    now_ns() / 1_000_000
}
// PRODUCTION_POLICY

mod parallel {
    use super::*;
    use super::{dispatch, runtime};
    // PRODUCTION_DISPATCH
}

fn supervisor() -> Supervisor {
    let runner = |index: usize, pid: u32, cpu_bound: bool| Runner {
        status: Status {
            state: UserState::Running,
            pid,
            rank_model: 0,
            ai_selections: 0,
            guard_selections: 0,
            syscalls: 0,
            esr: 0,
            far: 0,
            code: 0,
        },
        thread: Thread { tid: pid, ready_since: 0, cpu_bound, context: dispatch::Context },
        space: Space,
        index,
    };
    Supervisor {
        runners: [runner(0, 1, true), runner(1, 2, false)],
        ledger: Ledger,
        ipc: Ipc,
    }
}

/// Both runnable processes must receive CPU0. Without an age restart the
/// starvation guard freezes on one permanently oldest candidate.
#[test]
fn single_cpu_dispatch_shares_cpu0_between_runnable_processes() {
    CLOCK_NS.store(0, Ordering::SeqCst);
    for counter in &SELECTED {
        counter.store(0, Ordering::SeqCst);
    }
    let mut supervisor = supervisor();
    let mut shell = Shell { fs: FileSystem, runtime: Runtime };
    let mut out = Out;
    const ROUNDS: u64 = 200;
    // Count only rounds past the 100 ms starvation guard: an early courtesy
    // slice must not mask a dispatcher that later freezes on one candidate.
    let mut guarded = [0usize; 2];
    for round in 1..=ROUNDS {
        CLOCK_NS.store(round * 4_000_000, Ordering::SeqCst);
        let before = [
            SELECTED[0].load(Ordering::SeqCst),
            SELECTED[1].load(Ordering::SeqCst),
        ];
        let candidates = core::array::from_fn::<_, SLOTS, _>(|i| {
            let runner = &supervisor.runners[i];
            (runner.status.state == UserState::Running).then_some(UserCandidate {
                waiting_ms: now().saturating_sub(runner.thread.ready_since),
                cpu_bound: runner.thread.cpu_bound,
            })
        });
        supervisor.dispatch_parallel(candidates, &mut shell, &mut out);
        if round * 4 >= 120 {
            for index in 0..2 {
                guarded[index] += SELECTED[index].load(Ordering::SeqCst) - before[index];
            }
        }
    }
    let first = SELECTED[0].load(Ordering::SeqCst);
    let second = SELECTED[1].load(Ordering::SeqCst);
    std::println!(
        "SINGLE_CPU_AGE rounds={ROUNDS} pid1={first} pid2={second} guarded_pid1={} guarded_pid2={}",
        guarded[0],
        guarded[1]
    );
    assert_eq!(first + second, ROUNDS as usize, "every round dispatched once");
    assert!(guarded[0] > 0, "CPU-bound process starved once the guard engaged");
    assert!(guarded[1] > 0, "peer starved once the guard engaged on a single aging winner");
}

/// The winner's age must restart at the slice boundary, matching the AP and
/// aarch64 paths, so the next round ranks the waiting peer as older.
#[test]
fn granted_slice_restarts_the_winner_age() {
    CLOCK_NS.store(0, Ordering::SeqCst);
    for counter in &SELECTED {
        counter.store(0, Ordering::SeqCst);
    }
    let mut supervisor = supervisor();
    let mut shell = Shell { fs: FileSystem, runtime: Runtime };
    let mut out = Out;
    CLOCK_NS.store(40_000_000, Ordering::SeqCst);
    let candidates = core::array::from_fn::<_, SLOTS, _>(|i| {
        let runner = &supervisor.runners[i];
        Some(UserCandidate {
            waiting_ms: now().saturating_sub(runner.thread.ready_since),
            cpu_bound: runner.thread.cpu_bound,
        })
    });
    supervisor.dispatch_parallel(candidates, &mut shell, &mut out);
    let winner = SELECTED
        .iter()
        .enumerate()
        .find(|(_, count)| count.load(Ordering::SeqCst) > 0)
        .map(|(index, _)| index)
        .expect("one process was dispatched");
    assert_eq!(
        supervisor.runners[winner].thread.ready_since,
        now(),
        "granted slice left the winner aging"
    );
}
