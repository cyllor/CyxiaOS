//! Native task ownership. Every shared mutation uses one nonblocking gate.
//! EL0 and blocking file/device work execute outside that gate.
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use cyxia_arch_aarch64::{cpu, mmu, timer, user};
use cyxia_contracts::PhysAddr;
use cyxia_prototype::domains::maintenance::{BackgroundBudgets, CpuDebit};
use cyxia_prototype::domains::tasks::*;
use cyxia_prototype::domains::{Action, ApplyId, Error, ObjectKey, PolicyStamp, WINDOW_NS};
use sha2::{Digest, Sha256};
#[path = "domain_tasks/abi.rs"]
mod abi;
#[path = "domain_tasks/deadline.rs"]
mod deadline;
#[path = "domain_tasks/execution.rs"]
mod execution;
#[path = "domain_tasks/memory.rs"]
mod memory;
#[path = "domain_tasks/owner_gate.rs"]
mod owner_gate;
#[path = "domain_tasks/publication.rs"]
mod publication;
#[path = "domain_tasks/service_authority.rs"]
mod service_authority;
pub(crate) use publication::{BaselinePublication, reserve_baseline_publication};
#[path = "domain_tasks/local_evidence.rs"]
mod local_evidence;
#[path = "domain_tasks/replay.rs"]
pub mod replay;
pub use abi::{
    close_network, fault, grant_endpoint, grant_file_cap, network_drain, network_key,
    network_pending, network_write, open_network, syscall,
};
pub use execution::{
    acknowledge_local_result, cancel_spawn, close_admission, dispatch, heartbeat_ns,
    init_recoverable, local_result, probe_status, query_local, query_spawn, readonly_drained,
    recoverable_key, recoverable_result, recoverable_submit, remote_activate, remote_capacity,
    remote_fault, remote_release, remote_selected, remote_start, remote_stopped, remote_word,
    request_stop, running, service, service_io_piece, start_generation, start_probe_client,
    start_storage_client, stopped, submit_local, submit_spawn,
};
pub use local_evidence::bind_local_failure_request;
pub(crate) use memory::with_user_memory;
pub use memory::{
    cache_read, copyin, copyout, invalidate_file, set_cache_loader, set_file_service,
};

const TASKS: usize = 60;
const ORDINARY_TASKS: usize = TASKS - 4;
const LAUNCHES: usize = 72;
const PAGES: usize = 1024;
const TABLE_PAGES: usize = TASKS * 3;
const CODE_FRAME: usize = TABLE_PAGES;
const CLIENT_CODE_FRAME: usize = CODE_FRAME + 1;
const CODE_PAGES: usize = 5;
const USER_LIMIT: u64 = 0x20_0000;
const IPC_BYTES: usize = 256;
const ZERO: ObjectKey = ObjectKey {
    id: 0,
    generation: 0,
};
const NO_POLICY: PolicyStamp = PolicyStamp {
    version: 0,
    snapshot_ns: 0,
    installed_until_ns: 0,
};
pub const KERNEL_CALLER: ObjectKey = ObjectKey {
    id: u64::MAX,
    generation: 1,
};
const TASK_SERVICE: ObjectKey = ObjectKey {
    id: u64::MAX - 1,
    generation: 1,
};
const FILE_SERVICE: ObjectKey = ObjectKey {
    id: u64::MAX - 2,
    generation: 1,
};
const CLUSTER_CALLER: ObjectKey = ObjectKey {
    id: u64::MAX - 3,
    generation: 1,
};
const NETWORK_SERVICE_ID: u64 = u64::MAX - 4;
const NETWORK_CALLER_ID: u64 = u64::MAX - 5;
const PACKAGE: ObjectKey = ObjectKey {
    id: 1,
    generation: 1,
};
pub const CLIENT_PACKAGE: ObjectKey = ObjectKey {
    id: 2,
    generation: 1,
};
const REMOTE_ID: u64 = 0x100;
const MEMORY_KEY: ObjectKey = ObjectKey {
    id: 0x4d454d,
    generation: 1,
};
const SERVICE_KEY: ObjectKey = ObjectKey {
    id: 0x535643,
    generation: 1,
};
// Preserve the full 70 ms control capacity while keeping a measured host
// scheduling pause out of the aligned-window tail. This is admission-only;
// every turn is still charged its exact requested and actual CPU time.
const CONTROL_WINDOW_HEADROOM_NS: u64 = 20_000_000;
const ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/prototype-task.elf"));
const CLIENT_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/prototype-client.elf"));
const SELFTEST_ENABLED: bool = include!(concat!(env!("OUT_DIR"), "/domain-selftest.rs"));
#[repr(C, align(4096))]
struct Page([u8; 4096]);
static mut POOL: [Page; PAGES] = [const { Page([0; 4096]) }; PAGES];
static mut CONTEXTS: [user::Context; TASKS] = [const { user::Context::empty() }; TASKS];
static LOCK: owner_gate::Gate = owner_gate::Gate::new();
static READY: AtomicBool = AtomicBool::new(false);
static CACHE_EPOCH: AtomicU64 = AtomicU64::new(1);
static CREDIT_KIND: [AtomicU64; 64] = [const { AtomicU64::new(0) }; 64];
static CREDIT_NS: [AtomicU64; 64] = [const { AtomicU64::new(0) }; 64];
static COMPLETE_READY: [AtomicBool; 64] = [const { AtomicBool::new(false) }; 64];
static COMPLETE_ACTUAL: [AtomicU64; 64] = [const { AtomicU64::new(0) }; 64];
static COMPLETE_AT: [AtomicU64; 64] = [const { AtomicU64::new(0) }; 64];
static RETURN_PENDING: [AtomicBool; TASKS] = [const { AtomicBool::new(false) }; TASKS];
static FILE_PENDING: [AtomicBool; TASKS] = [const { AtomicBool::new(false) }; TASKS];
static FILE_BUSY: [AtomicBool; TASKS] = [const { AtomicBool::new(false) }; TASKS];
static FILE_DONE: [AtomicBool; TASKS] = [const { AtomicBool::new(false) }; TASKS];
#[repr(C, align(64))]
pub struct TaskEvidence {
    pub words: [AtomicU64; 32],
}
#[used]
#[unsafe(no_mangle)]
pub static DOMAIN_TASK_EVIDENCE: TaskEvidence = TaskEvidence {
    words: [const { AtomicU64::new(0) }; 32],
};
#[used]
#[unsafe(no_mangle)]
pub static TASK_OVERRUN_EVIDENCE: TaskEvidence = TaskEvidence {
    words: [const { AtomicU64::new(0) }; 32],
};
#[derive(Clone, Copy, PartialEq, Eq)]
enum Life {
    Free,
    Ready,
    Running,
    Waiting,
    Exiting,
}
#[derive(Clone, Copy)]
struct Task {
    key: ObjectKey,
    group: ObjectKey,
    parent: ObjectKey,
    package: ObjectKey,
    spawn_id: u64,
    failure: Option<Error>,
    cpu: u16,
    life: Life,
    deadline: u64,
    endpoint: ObjectKey,
    caps: [ObjectKey; 8],
    own_query_cap: u64,
    regions: [u64; 8],
    region_count: usize,
    exit_code: u64,
    terminal_seen: bool,
    optional: bool,
    recipe: u16,
    closed: bool,
    stop_apply: Option<ApplyId>,
    start_apply: Option<ApplyId>,
    entered: bool,
    pending: bool,
    pending_sequence: u64,
    completed_sequence: u64,
    response: u64,
    vector_output: u64,
    blocked: bool,
    heartbeat_ns: u64,
    capture_ready: bool,
    capture_index: Option<usize>,
}
impl Task {
    const EMPTY: Self = Self {
        key: ZERO,
        group: ZERO,
        parent: ZERO,
        package: ZERO,
        spawn_id: 0,
        failure: None,
        cpu: 0,
        life: Life::Free,
        deadline: 0,
        endpoint: ZERO,
        caps: [ZERO; 8],
        own_query_cap: 0,
        regions: [0; 8],
        region_count: 0,
        exit_code: 0,
        terminal_seen: false,
        optional: false,
        recipe: 0,
        closed: false,
        stop_apply: None,
        start_apply: None,
        entered: false,
        pending: false,
        pending_sequence: 0,
        completed_sequence: 0,
        response: 0,
        vector_output: 0,
        blocked: false,
        heartbeat_ns: 0,
        capture_ready: false,
        capture_index: None,
    };
}
struct Launch {
    request: Option<SpawnRequest>,
    cpu: u16,
    deadline: u64,
    len: usize,
    input: [u8; 4096],
    recipe: u16,
}
impl Launch {
    const EMPTY: Self = Self {
        request: None,
        cpu: 0,
        deadline: 0,
        len: 0,
        input: [0; 4096],
        recipe: 0,
    };
}
#[derive(Clone, Copy)]
struct Remote {
    key: ObjectKey,
    leaf: u64,
    ended: bool,
}
#[derive(Clone, Copy)]
struct Network {
    epoch: u64,
    endpoint: ObjectKey,
}
#[derive(Clone, Copy)]
struct NetworkSend {
    grant: SendGrant,
    request: u64,
    bytes: [u8; IPC_BYTES],
    len: usize,
}
#[derive(Clone, Copy)]
struct VectorLease {
    grants: [Option<SendGrant>; 2],
    requests: [u64; 2],
    needed: u8,
    ready: bool,
    deadline: u64,
}
impl VectorLease {
    const EMPTY: Self = Self {
        grants: [None; 2],
        requests: [0; 2],
        needed: 0,
        ready: false,
        deadline: 0,
    };
}
impl Network {
    fn owner(self) -> ObjectKey {
        ObjectKey {
            id: NETWORK_SERVICE_ID,
            generation: self.epoch,
        }
    }
    fn caller(self) -> ObjectKey {
        ObjectKey {
            id: NETWORK_CALLER_ID,
            generation: self.epoch,
        }
    }
}
#[derive(Clone, Copy)]
struct Active {
    dispatch: Dispatch,
    state: RunState,
    optional: Option<CpuDebit>,
}
#[derive(Clone, Copy)]
struct ExitRecord {
    key: ObjectKey,
    parent: ObjectKey,
    code: u64,
    value: u64,
    finished_ns: u64,
}
#[derive(Clone, Copy)]
struct Rate {
    window: [u64; 10],
    value: [u64; 10],
}
impl Rate {
    const EMPTY: Self = Self {
        window: [u64::MAX; 10],
        value: [0; 10],
    };
    fn add(&mut self, now: u64, n: u64) {
        let window = now / 100_000_000;
        let i = window as usize % 10;
        if self.window[i] != window {
            self.window[i] = window;
            self.value[i] = 0;
        }
        self.value[i] = self.value[i].saturating_add(n);
    }
    fn get(&self, now: u64) -> u64 {
        let window = now / 100_000_000;
        self.window
            .iter()
            .zip(&self.value)
            .filter(|(at, _)| **at <= window && window - **at < 10)
            .fold(0u64, |sum, (_, n)| sum.saturating_add(*n))
    }
}
#[path = "domain_tasks/samples.rs"]
mod samples;
use samples::Samples;

struct Facts {
    cpu: [Rate; 16],
    wakes: [Rate; 16],
    spawn: [Rate; 16],
    wait: [Samples; 16],
    node_wait: Samples,
    attempts: u64,
    rejected: u64,
    faults: Rate,
    last_faults: u64,
    reclaim_ns: Rate,
    vectors: Rate,
    vector_latency: Samples,
    vector_started: [u64; TASKS],
    vector_measured: [bool; TASKS],
    last_vector_len: u64,
    ipc_messages: [Rate; 34],
    ipc_admitted: [u64; 34],
    ipc_generation: [u64; 34],
}
impl Facts {
    const EMPTY: Self = Self {
        cpu: [Rate::EMPTY; 16],
        wakes: [Rate::EMPTY; 16],
        spawn: [Rate::EMPTY; 16],
        wait: [Samples::EMPTY; 16],
        node_wait: Samples::EMPTY,
        attempts: 0,
        rejected: 0,
        faults: Rate::EMPTY,
        last_faults: 0,
        reclaim_ns: Rate::EMPTY,
        vectors: Rate::EMPTY,
        vector_latency: Samples::EMPTY,
        vector_started: [0; TASKS],
        vector_measured: [false; TASKS],
        last_vector_len: 0,
        ipc_messages: [Rate::EMPTY; 34],
        ipc_admitted: [0; 34],
        ipc_generation: [0; 34],
    };
}
type ValidateFile = fn(ObjectKey) -> Result<(), Error>;
type StatFile = fn(ObjectKey) -> Result<u64, Error>;
type LoadCache = fn(ObjectKey, u64, &mut [u8; 4096]) -> Result<(), Error>;
struct State {
    scheduler: Scheduler,
    admission: SpawnAdmission,
    memory: Memory<PAGES, 512>,
    ipc: Ipc<IPC_BYTES>,
    services: ServiceBatch,
    background: BackgroundBudgets,
    tasks: [Task; TASKS],
    launches: [Launch; LAUNCHES],
    vectors: [Option<SubmitVector>; TASKS],
    vector_leases: [VectorLease; TASKS],
    vector_ids: [u64; TASKS],
    exits: [Option<ExitRecord>; 256],
    layout: CpuLayout,
    draining: u64,
    active: [Option<Active>; 64],
    remote: Option<Remote>,
    network: Option<Network>,
    network_send: Option<NetworkSend>,
    network_epoch: u64,
    generation: u64,
    service_admitted: bool,
    wake: u64,
    cursor: usize,
    service_phase: u8,
    lifecycle_cursor: usize,
    vector_cursor: usize,
    launch_cursor: usize,
    metrics_cursor: usize,
    task_endpoint: ObjectKey,
    file_endpoint: ObjectKey,
    service_sequence: u64,
    validate_file: Option<ValidateFile>,
    stat_file: Option<StatFile>,
    load_cache: Option<LoadCache>,
    diagnostic_window: u64,
    recovery_window: u64,
    recovery_started: u16,
    cache_epoch: u64,
    cache_stamp: PolicyStamp,
    cache_action: Option<Action>,
    cache_receipt: Option<(PolicyStamp, Action)>,
    spawn_receipts: [u64; 16],
    background_receipts: [u64; 16],
    probe_key: Option<ObjectKey>,
    probe_exit: Option<u64>,
    throttled: [Option<(ObjectKey, u64)>; 64],
    facts: Facts,
}
impl State {
    const fn new() -> Self {
        Self {
            scheduler: Scheduler::new(),
            admission: SpawnAdmission::new(),
            memory: Memory::new(),
            ipc: Ipc::new(),
            services: ServiceBatch::new(),
            background: BackgroundBudgets::new(),
            tasks: [Task::EMPTY; TASKS],
            launches: [const { Launch::EMPTY }; LAUNCHES],
            vectors: [const { None }; TASKS],
            vector_leases: [VectorLease::EMPTY; TASKS],
            vector_ids: [0; TASKS],
            exits: [None; 256],
            layout: CpuLayout {
                business_mask: 13,
                healthy_mask: 15,
                generation: 1,
            },
            draining: 0,
            active: [None; 64],
            remote: None,
            network: None,
            network_send: None,
            network_epoch: 0,
            generation: 1,
            service_admitted: false,
            wake: 0,
            cursor: 0,
            service_phase: 0,
            lifecycle_cursor: 0,
            vector_cursor: 0,
            launch_cursor: 0,
            metrics_cursor: 0,
            task_endpoint: ZERO,
            file_endpoint: ZERO,
            service_sequence: 0,
            validate_file: None,
            stat_file: None,
            load_cache: None,
            diagnostic_window: u64::MAX,
            recovery_window: u64::MAX,
            recovery_started: 0,
            cache_epoch: 1,
            cache_stamp: NO_POLICY,
            cache_action: None,
            cache_receipt: None,
            spawn_receipts: [0; 16],
            background_receipts: [0; 16],
            probe_key: None,
            probe_exit: None,
            throttled: [None; 64],
            facts: Facts::EMPTY,
        }
    }
}
static mut STATE: State = State::new();
// These immutable target identities are published by READY. Ordinary policy
// discovery must not borrow the large mutable task owner merely to read values
// that never change after initialization.
static IPC_TARGETS: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
// A native builtin turn reserves at most 10 ms, but the shared monotonic clock
// can advance while an MTTCG vCPU is descheduled. Requiring 20 ms at entry
// still admits the ninth 10 ms turn at t=80 ms (the complete 90 ms business
// capacity) while keeping the measured host pause out of the window tail.
const BUILTIN_WINDOW_HEADROOM_NS: u64 = 20_000_000;
// The native PMU charges translated execution rather than the architectural
// timer interval. A tail grant smaller than one complete builtin turn can be
// exhausted before QEMU delivers the timer PPI, so leave it undispatched for
// the next budget window instead of creating an unavoidable overrun.
const BUILTIN_MIN_GRANT_NS: u64 = 10_000_000;
// One EL0 entry must fit even the admitted 1 ms ordinary-task profile. A
// thread's 10 ms window entitlement/guarantee is not an indivisible entry:
// short syscall returns may resume against its remaining exact credit.
// Smaller tails still defer, and actual overruns retain strict quarantine.
const DYNAMIC_EL0_MIN_GRANT_NS: u64 = 1_000_000;
struct Guard {
    permit: Option<owner_gate::Permit<'static>>,
}
impl Drop for Guard {
    fn drop(&mut self) {
        // Four fixed 250 us heartbeat opportunities, not a runtime budget. An
        // offline/descheduled waiter cannot reserve shared ownership forever.
        self.permit.take().unwrap().release(timer::ticks());
    }
}
fn acquire_guard() -> Result<Guard, Error> {
    let permit = LOCK
        .try_acquire(
            cpu::slot(),
            timer::ticks(),
            (timer::frequency() / 1000).max(1),
        )
        .ok_or(Error::Busy)?;
    Ok(Guard {
        permit: Some(permit),
    })
}
fn locked<R>(f: impl FnOnce(&mut State) -> Result<R, Error>) -> Result<R, Error> {
    let _guard = acquire_guard()?;
    unsafe { f(&mut *core::ptr::addr_of_mut!(STATE)) }
}
pub fn now_ns() -> u64 {
    ((u128::from(timer::ticks()) * 1_000_000_000) / u128::from(timer::frequency()))
        .min(u128::from(u64::MAX)) as u64
}

/// Close an actual per-vCPU interval at the current shared-monotonic point.
/// The projected start keeps evidence on the common time axis without charging
/// time spent descheduled or running another vCPU.
pub(crate) fn finish_cpu_interval(started: u64) -> (u64, u64, u64) {
    let finished_ns = now_ns();
    let actual_ns = timer::cpu_elapsed_ns(started);
    (
        finished_ns.saturating_sub(actual_ns),
        finished_ns,
        actual_ns,
    )
}
fn group(id: u64) -> ObjectKey {
    ObjectKey { id, generation: 1 }
}
fn builtin(slot: usize) -> ObjectKey {
    group(slot as u64)
}
fn task_index(tasks: &[Task; TASKS], key: ObjectKey) -> Result<usize, Error> {
    tasks
        .iter()
        .position(|t| t.life != Life::Free && t.key == key)
        .ok_or(Error::Stale)
}
fn group_index(s: &State, key: ObjectKey) -> Result<usize, Error> {
    let i = key
        .id
        .checked_sub(1)
        .filter(|i| *i < 16)
        .ok_or(Error::Stale)? as usize;
    s.scheduler.weight(key, now_ns())?;
    Ok(i)
}
fn ratio(n: u64, d: u64) -> u64 {
    if d == 0 {
        if n == 0 { 0 } else { 1000 }
    } else {
        ((u128::from(n) * 1000) / u128::from(d)).min(1000) as u64
    }
}
fn error_word(error: Error) -> u64 {
    let errno = match error {
        Error::Auth => 13,
        Error::Again | Error::Busy | Error::NotReady => 11,
        Error::Capacity | Error::Budget => 12,
        Error::NotFound => 2,
        Error::Stale => 116,
        Error::Expired => 110,
        Error::Unsupported => 38,
        Error::Io => 5,
        _ => 22,
    };
    (-(errno as i64)) as u64
}

pub fn init() -> Result<(), Error> {
    if READY.load(Ordering::Acquire) {
        return Ok(());
    }
    if cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    locked(|s| {
        s.memory.reserve_frames(0, TABLE_PAGES + CODE_PAGES)?;
        s.memory.reserve_progress_frames(PAGES - 32, 32)?;
        s.memory.configure_cache_baseline(64)?;
        for i in 1..=16 {
            s.scheduler.register_group(group(i))?;
            s.admission.register_group(group(i))?;
        }
        let now = now_ns();
        for slot in 2..=3 {
            s.scheduler.admit(
                ThreadSpec {
                    key: builtin(slot),
                    group: group(slot as u64 - 1),
                    cpu: slot as u16,
                    allowed_mask: 12,
                    minimum_ns: 0,
                    budget_ns: 30_000_000,
                },
                s.layout,
                now,
            )?;
        }
        match admit_service(s, now_ns()) {
            Ok(()) | Err(Error::Budget) => {}
            Err(error) => return Err(error),
        }
        s.background.register(group(15), 100, 0, now)?;
        s.background.register(group(16), 100, 0, now)?;
        s.task_endpoint = s.ipc.open(TASK_SERVICE, false)?;
        s.file_endpoint = s.ipc.open(FILE_SERVICE, false)?;
        for (word, value) in IPC_TARGETS.iter().zip([
            s.task_endpoint.id,
            s.task_endpoint.generation,
            s.file_endpoint.id,
            s.file_endpoint.generation,
        ]) {
            word.store(value, Ordering::Relaxed);
        }
        memory::load_code(ELF, CODE_FRAME, 1)?;
        memory::load_code(CLIENT_ELF, CLIENT_CODE_FRAME, 4)?;
        Ok(())
    })?;
    READY.store(true, Ordering::Release);
    Ok(())
}
fn admit_service(s: &mut State, now: u64) -> Result<(), Error> {
    if s.service_admitted {
        return Ok(());
    }
    s.scheduler.admit(
        ThreadSpec {
            key: group(0x101),
            group: group(14),
            cpu: 0,
            allowed_mask: 1,
            minimum_ns: 20_000_000,
            budget_ns: 60_000_000,
        },
        s.layout,
        now,
    )?;
    s.service_admitted = true;
    replay::service_admitted();
    Ok(())
}
pub fn publish_layout(
    business_mask: u64,
    healthy_mask: u64,
    core_generation: u64,
    draining_mask: u64,
) -> Result<(), Error> {
    locked(|s| {
        if core_generation == 0 || core_generation < s.layout.generation {
            return Err(Error::Stale);
        }
        if core_generation == s.layout.generation
            && (business_mask != s.layout.business_mask || healthy_mask != s.layout.healthy_mask)
        {
            return Err(Error::Conflict);
        }
        s.layout = CpuLayout {
            business_mask,
            healthy_mask,
            generation: core_generation,
        };
        s.draining = draining_mask;
        let recover =
            s.scheduler.stats().quarantine_mask & business_mask & healthy_mask & !draining_mask;
        for cpu in 0..64 {
            if recover & (1u64 << cpu) != 0 {
                let _ = s.scheduler.recover_cpu(cpu, s.layout, now_ns());
            }
        }
        Ok(())
    })
}
pub fn can_control_move(slot: usize) -> Result<(), Error> {
    locked(|s| can_control_move_locked(s, slot))
}
fn can_control_move_locked(s: &State, slot: usize) -> Result<(), Error> {
    if slot >= 64 {
        return Err(Error::Range);
    }
    if slot == 0 && s.service_admitted {
        return Err(Error::Budget);
    }
    if s.tasks
        .iter()
        .any(|t| t.life != Life::Free && usize::from(t.cpu) == slot)
        || s.launches
            .iter()
            .any(|l| l.request.is_some() && usize::from(l.cpu) == slot)
        || (slot == 3 && s.remote.is_some())
    {
        return Err(Error::Budget);
    }
    Ok(())
}
/// Atomically exclude new business admission after validating that no task,
/// launch, or remote commitment would be stranded on the moving CPU.
pub fn prepare_control_move(slot: usize) -> Result<(), Error> {
    locked(|s| {
        can_control_move_locked(s, slot)?;
        s.draining |= 1u64 << slot;
        Ok(())
    })
}
pub fn close_cpu(slot: usize) -> Result<(), Error> {
    locked(|s| {
        if slot >= 64 {
            return Err(Error::Range);
        }
        if COMPLETE_READY[slot].load(Ordering::Acquire) {
            let _ = complete_locked(s, slot);
        }
        s.draining |= 1u64 << slot;
        if s.active[slot].is_some()
            || s.scheduler.control_active(slot).is_some()
            || COMPLETE_READY[slot].load(Ordering::Acquire)
            || s.tasks
                .iter()
                .any(|t| t.life != Life::Free && usize::from(t.cpu) == slot)
            || (slot == 3 && s.remote.is_some())
        {
            return Err(Error::Busy);
        }
        Ok(())
    })
}
pub fn quiescent(slot: usize) -> bool {
    locked(|s| {
        Ok(slot < 64
            && s.active[slot].is_none()
            && s.scheduler.control_active(slot).is_none()
            && !s
                .tasks
                .iter()
                .any(|t| t.life != Life::Free && usize::from(t.cpu) == slot)
            && !(slot == 3 && s.remote.is_some()))
    })
    .unwrap_or(false)
}
#[derive(Clone, Copy, Debug)]
pub struct Credit {
    pub sequence: u64,
    pub thread: ObjectKey,
    pub reserved_ns: u64,
    optional: bool,
}
struct Captures(core::cell::UnsafeCell<[Option<crate::learning_evidence::OwnerAttempt>; 64]>);
// Include the complete existing per-CPU bank after its token gains retained
// exit metadata; the learning workspace bound must not hide that growth.
pub const CAPTURE_CREDIT_BYTES: usize = core::mem::size_of::<Captures>();
// Slot i is accessed only by CPU i, and never by an interrupt handler.
unsafe impl Sync for Captures {}
static CAPTURES: Captures = Captures(core::cell::UnsafeCell::new([const { None }; 64]));
struct WarmCaptures(core::cell::UnsafeCell<[Option<crate::learning_prewarm::Attempt>; 64]>);
// The same per-CPU ownership as CAPTURES; IRQs never access these cells.
unsafe impl Sync for WarmCaptures {}
static WARM_CAPTURES: WarmCaptures =
    WarmCaptures(core::cell::UnsafeCell::new([const { None }; 64]));
fn track_credit(
    slot: usize,
    result: Result<Option<Credit>, Error>,
) -> Result<Option<Credit>, Error> {
    if let Ok(Some(credit)) = &result {
        debug_assert_eq!(cpu::slot(), slot);
        let attempt = crate::learning_evidence::attempt_work(credit.thread, credit.optional)
            .ok()
            .flatten();
        unsafe {
            let cell = CAPTURES
                .0
                .get()
                .cast::<Option<crate::learning_evidence::OwnerAttempt>>()
                .add(slot);
            let old = cell.replace(attempt);
            drop(old);
            let warm = WARM_CAPTURES
                .0
                .get()
                .cast::<Option<crate::learning_prewarm::Attempt>>()
                .add(slot);
            drop(warm.replace(crate::learning_prewarm::attempt_task(credit.thread)));
        }
    }
    result
}
fn finish_capture(slot: usize, first: u64, last: u64) {
    let warm = unsafe {
        WARM_CAPTURES
            .0
            .get()
            .cast::<Option<crate::learning_prewarm::Attempt>>()
            .add(slot)
            .replace(None)
    };
    if let Some(mut warm) = warm {
        let _ = crate::learning_prewarm::finish(&mut warm, first, last);
    }
    let attempt = unsafe {
        CAPTURES
            .0
            .get()
            .cast::<Option<crate::learning_evidence::OwnerAttempt>>()
            .add(slot)
            .replace(None)
    };
    if let Some(mut attempt) = attempt {
        // A busy exit is explicitly excluded by OwnerAttempt::drop, including
        // the exact measured duration; it can never become missing-free data.
        let _ = crate::learning_evidence::finish_attempt(&mut attempt, first, last);
    }
}
fn discard_capture(slot: usize) {
    unsafe {
        let capture = CAPTURES
            .0
            .get()
            .cast::<Option<crate::learning_evidence::OwnerAttempt>>()
            .add(slot);
        drop(capture.replace(None));
        let warm = WARM_CAPTURES
            .0
            .get()
            .cast::<Option<crate::learning_prewarm::Attempt>>()
            .add(slot);
        drop(warm.replace(None));
    }
}
fn throttle(s: &mut State, key: ObjectKey, now: u64) {
    if let Some(slot) = s
        .throttled
        .iter_mut()
        .find(|slot| slot.is_none_or(|(k, _)| k == key))
    {
        *slot = Some((key, now / 100_000_000 + 1));
    }
    if let Ok(i) = task_index(&s.tasks, key) {
        s.tasks[i].blocked = true;
    }
}
fn refresh_throttled(s: &mut State, now: u64) {
    for i in 0..64 {
        if let Some((key, window)) = s.throttled[i]
            && now / 100_000_000 >= window
        {
            let ready = task_index(&s.tasks, key).map_or(true, |i| {
                s.tasks[i].life == Life::Ready && (!s.tasks[i].optional || s.tasks[i].pending)
            });
            if ready && s.scheduler.set_runnable(key, true, now).is_err() {
                continue;
            }
            s.throttled[i] = None;
            if ready && let Ok(t) = task_index(&s.tasks, key) {
                s.tasks[t].blocked = false;
            }
        }
    }
}
pub fn begin_builtin(slot: usize, _now: u64) -> Option<Credit> {
    if !READY.load(Ordering::Acquire) || slot >= 64 || cpu::slot() != slot {
        return None;
    }
    track_credit(
        slot,
        locked(|s| {
            if COMPLETE_READY[slot].load(Ordering::Acquire) {
                let _ = complete_locked(s, slot);
            }
            if s.draining & (1u64 << slot) != 0 || s.active[slot].is_some() {
                return Ok(None);
            }
            let now = now_ns();
            if slot == 0 {
                match admit_service(s, now) {
                    Ok(()) => {}
                    Err(Error::Budget | Error::Busy) => return Ok(None),
                    Err(e) => return Err(e),
                }
            }
            refresh_throttled(s, now);
            let Some(mut d) = s.scheduler.dispatch_with_window_headroom(
                slot,
                s.layout,
                now,
                10_000_000,
                BUILTIN_WINDOW_HEADROOM_NS,
            )?
            else {
                return Ok(None);
            };
            let safety = if d.thread == builtin(slot) {
                BUILTIN_MIN_GRANT_NS
            } else if d.thread.id >= 0x1000 {
                DYNAMIC_EL0_MIN_GRANT_NS
            } else {
                match task_index(&s.tasks, d.thread) {
                    Ok(i)
                        if !s.tasks[i].optional
                            && s.probe_key != Some(d.thread)
                            && s.tasks[i].parent != CLUSTER_CALLER =>
                    {
                        1_000_000
                    }
                    _ => 2_000_000,
                }
            };
            if d.reserved_ns < safety {
                match s.scheduler.resize_dispatch(d, safety) {
                    Ok(next) => d = next,
                    Err(_) => {
                        s.scheduler.complete(d, 0, RunState::Blocked, now)?;
                        throttle(s, d.thread, now);
                        return Ok(None);
                    }
                }
            }
            let optional = task_index(&s.tasks, d.thread).is_ok_and(|i| s.tasks[i].optional);
            let debit = if optional {
                if let Err(error) = crate::domain_control::admit_dependency(
                    crate::domain_control::Prerequisite {
                        domain: 13,
                        target: d.group,
                    },
                    1,
                    now,
                ) {
                    s.scheduler.complete(d, 0, RunState::Blocked, now)?;
                    throttle(s, d.thread, now);
                    return Err(error);
                }
                let status = match s.background.current_status(d.group, now) {
                    Ok(status) => status,
                    Err(error) => {
                        s.scheduler.complete(d, 0, RunState::Blocked, now)?;
                        throttle(s, d.thread, now);
                        return Err(error);
                    }
                };
                let remaining = (u64::from(status.budget_milli) * 100_000)
                    .saturating_sub(status.spent_ns)
                    .saturating_sub(status.reserved_ns);
                if remaining < safety {
                    s.scheduler.complete(d, 0, RunState::Blocked, now)?;
                    throttle(s, d.thread, now);
                    return Ok(None);
                }
                if d.reserved_ns > remaining {
                    match s.scheduler.resize_dispatch(d, remaining) {
                        Ok(next) => d = next,
                        Err(error) => {
                            s.scheduler.complete(d, 0, RunState::Blocked, now)?;
                            throttle(s, d.thread, now);
                            return Err(error);
                        }
                    }
                }
                match s.background.reserve(d.group, d.reserved_ns, now) {
                    Ok(debit) => Some(debit),
                    Err(_) => {
                        s.scheduler.complete(d, 0, RunState::Blocked, now)?;
                        throttle(s, d.thread, now);
                        return Ok(None);
                    }
                }
            } else {
                None
            };
            s.active[slot] = Some(Active {
                dispatch: d,
                state: RunState::Runnable,
                optional: debit,
            });
            if let Ok(i) = group_index(s, d.group) {
                s.facts.wait[i].add(d.waited_ns);
                s.facts.node_wait.add(d.waited_ns);
            }
            CREDIT_NS[slot].store(d.reserved_ns, Ordering::Relaxed);
            CREDIT_KIND[slot].store(
                if d.thread.id == REMOTE_ID {
                    2
                } else if d.thread.id >= 0x1000 {
                    3
                } else {
                    1
                },
                Ordering::Release,
            );
            Ok(Some(Credit {
                sequence: d.sequence,
                thread: d.thread,
                reserved_ns: d.reserved_ns,
                optional,
            }))
        }),
    )
    .ok()
    .flatten()
}
pub fn begin_service(now: u64) -> Option<Credit> {
    begin_builtin(0, now)
}
pub fn builtin_selected(slot: usize) -> bool {
    slot < 64 && CREDIT_KIND[slot].load(Ordering::Acquire) == 1
}
/// Recheck an unstarted builtin credit immediately before entering its task
/// body. MTTCG may deschedule this vCPU after selection; if that consumed the
/// protected wall envelope, refund the untouched CPU and optional-budget
/// reservations so the task can be selected in a fresh window.
fn revalidate_unstarted(slot: usize, kind: u64) -> bool {
    if slot >= 64
        || cpu::slot() != slot
        || CREDIT_KIND[slot].load(Ordering::Acquire) != kind
        || COMPLETE_READY[slot].load(Ordering::Acquire)
    {
        return false;
    }
    let result = locked(|s| {
        let active = s.active[slot].ok_or(Error::Stale)?;
        let now = now_ns();
        if active.dispatch.window == now / WINDOW_NS
            && WINDOW_NS - now % WINDOW_NS >= BUILTIN_WINDOW_HEADROOM_NS
        {
            return Ok(true);
        }
        s.scheduler.cancel_unstarted(active.dispatch, now)?;
        if let Some(debit) = active.optional {
            s.background.complete(debit, 0, now)?;
        }
        s.active[slot] = None;
        CREDIT_NS[slot].store(0, Ordering::Relaxed);
        CREDIT_KIND[slot].store(0, Ordering::Release);
        Ok(false)
    });
    match result {
        Ok(true) => true,
        Ok(false) => {
            discard_capture(slot);
            false
        }
        // The task gate is deliberately nonblocking. Contention leaves the
        // exact existing credit untouched, so preserve the prior execution
        // path rather than stranding an active reservation.
        Err(_) => true,
    }
}
pub fn revalidate_builtin(slot: usize) -> bool {
    revalidate_unstarted(slot, 1)
}
pub fn revalidate_service_segment() -> bool {
    revalidate_unstarted(0, 5)
}
/// A non-preemptible mechanism piece needs the whole bounded envelope. A
/// short remainder is returned without running the body or blocking its thread.
pub fn begin_service_segment() -> Option<Credit> {
    if cpu::slot() != 0 || !READY.load(Ordering::Acquire) {
        return None;
    }
    track_credit(
        0,
        locked(|s| {
            if COMPLETE_READY[0].load(Ordering::Acquire) {
                let _ = complete_locked(s, 0);
            }
            if s.active[0].is_some() || s.draining & 1 != 0 {
                return Ok(None);
            }
            let now = now_ns();
            admit_service(s, now)?;
            let Some(mut d) = s.scheduler.dispatch_with_window_headroom(
                0,
                s.layout,
                now,
                2_500_000,
                BUILTIN_WINDOW_HEADROOM_NS,
            )?
            else {
                return Ok(None);
            };
            if d.thread == group(0x101) && d.reserved_ns < 2_500_000 {
                if let Ok(full) = s.scheduler.resize_dispatch(d, 2_500_000) {
                    d = full;
                }
            }
            if d.thread != group(0x101) || d.reserved_ns != 2_500_000 {
                s.scheduler.complete(d, 0, RunState::Runnable, now)?;
                return Ok(None);
            }
            s.active[0] = Some(Active {
                dispatch: d,
                state: RunState::Runnable,
                optional: None,
            });
            CREDIT_NS[0].store(d.reserved_ns, Ordering::Relaxed);
            CREDIT_KIND[0].store(5, Ordering::Release);
            Ok(Some(Credit {
                sequence: d.sequence,
                thread: d.thread,
                reserved_ns: d.reserved_ns,
                optional: false,
            }))
        }),
    )
    .ok()
    .flatten()
}
/// Authority for a bounded CPU0 mechanism piece, including exact baseline
/// restoration after an optional numerical worker has failed. Merely running
/// on CPU0, an EL0 TLS slice or an already submitted bill is insufficient.
pub(crate) struct PaidServiceWitness {
    _private: (),
}
fn service_witness_locked(s: &State) -> Result<PaidServiceWitness, Error> {
    if cpu::slot() != 0 || !READY.load(Ordering::Acquire) {
        return Err(Error::Auth);
    }
    let active = s.active[0].as_ref().ok_or(Error::NotReady)?;
    service_authority::authorize(
        service_authority::View {
            cpu: cpu::slot(),
            held: active.dispatch,
            actual: s.scheduler.active(0),
            layout: s.layout,
            draining: s.draining,
            quarantine: s.scheduler.stats().quarantine_mask,
            kind: CREDIT_KIND[0].load(Ordering::Acquire),
            published_credit_ns: CREDIT_NS[0].load(Ordering::Acquire),
            settlement_pending: COMPLETE_READY[0].load(Ordering::Acquire),
        },
        now_ns(),
    )?;
    Ok(PaidServiceWitness { _private: () })
}
pub fn authorize_service_turn() -> Result<(), Error> {
    if cpu::slot() != 0 || !READY.load(Ordering::Acquire) {
        return Err(Error::Auth);
    }
    locked(|s| service_witness_locked(s).map(|_| ()))
}
/// Actual stopped file syscalls awaiting the CPU0 owner. This is demand, not
/// permission to replay a request: completion custody and in-flight requests
/// are excluded, and the file service still validates the complete user frame.
pub fn pending_file_requests() -> Result<[Option<(ObjectKey, u64)>; TASKS], Error> {
    if cpu::slot() != 0 || !READY.load(Ordering::Acquire) {
        return Err(Error::Auth);
    }
    locked(|s| {
        let mut requests = [None; TASKS];
        for (i, out) in requests.iter_mut().enumerate() {
            let task = &s.tasks[i];
            if task.life != Life::Waiting
                || !FILE_PENDING[i].load(Ordering::Acquire)
                || FILE_DONE[i].load(Ordering::Acquire)
                || FILE_BUSY[i].load(Ordering::Acquire)
                || s.active
                    .iter()
                    .flatten()
                    .any(|a| a.dispatch.thread == task.key)
            {
                continue;
            }
            // A Waiting file caller has stopped EL0 and cannot be dispatched
            // while FILE_PENDING is held. Copy only the saved frame address.
            let context = unsafe { &*core::ptr::addr_of!(CONTEXTS).cast::<user::Context>().add(i) };
            if context.kind == 8
                && context.esr >> 26 == 0x15
                && context.esr & 0xffff == 0x45
                && context.regs[8] == 0x40
            {
                *out = Some((task.key, context.regs[1]));
            }
        }
        Ok(requests)
    })
}
/// Executes one bounded, nonblocking owner piece against real CPU0 capacity.
/// Blocking I/O must split at its progress callback and use a retained request.
pub fn service_segment<R>(body: impl FnOnce() -> R) -> Option<R> {
    begin_service_segment()?;
    if !revalidate_service_segment() {
        return None;
    }
    let started = timer::cpu_ticks();
    let result = body();
    let (_, finished_ns, actual_ns) = finish_cpu_interval(started);
    let _ = complete_service(actual_ns, finished_ns);
    Some(result)
}
fn begin_file_credit(owner: ObjectKey) -> Result<Option<Credit>, Error> {
    if cpu::slot() != 0 || !READY.load(Ordering::Acquire) {
        return Err(Error::Auth);
    }
    track_credit(
        0,
        locked(|s| {
            if COMPLETE_READY[0].load(Ordering::Acquire) {
                let _ = complete_locked(s, 0);
            }
            if s.active[0].is_some() || s.draining & 1 != 0 {
                return Ok(None);
            }
            let i = task_index(&s.tasks, owner)?;
            if s.tasks[i].life != Life::Waiting || !FILE_BUSY[i].load(Ordering::Acquire) {
                return Err(Error::Conflict);
            }
            let now = now_ns();
            let layout = CpuLayout {
                business_mask: s.layout.business_mask & !s.draining,
                ..s.layout
            };
            let Some(d) = s
                .scheduler
                .dispatch_service_exact(owner, 0, layout, now, 2_500_000)?
            else {
                return Ok(None);
            };
            s.active[0] = Some(Active {
                dispatch: d,
                state: RunState::Blocked,
                optional: None,
            });
            CREDIT_NS[0].store(d.reserved_ns, Ordering::Relaxed);
            CREDIT_KIND[0].store(4, Ordering::Release);
            Ok(Some(Credit {
                sequence: d.sequence,
                thread: owner,
                reserved_ns: d.reserved_ns,
                optional: false,
            }))
        }),
    )
}
fn complete_locked(s: &mut State, slot: usize) -> Result<(), Error> {
    if !COMPLETE_READY[slot].load(Ordering::Acquire) {
        return Err(Error::NotReady);
    }
    let active = s.active[slot].ok_or(Error::Stale)?;
    let actual = COMPLETE_ACTUAL[slot].load(Ordering::Relaxed);
    let finished = COMPLETE_AT[slot].load(Ordering::Relaxed);
    let result = s
        .scheduler
        .complete(active.dispatch, actual, active.state, finished);
    if s.scheduler.active(slot).is_some() {
        if slot == 0
            && crate::storage_fault_capture::PROFILE
            && let Err(error) = result
        {
            DOMAIN_TASK_EVIDENCE.words[13].store(actual, Ordering::Relaxed);
            DOMAIN_TASK_EVIDENCE.words[14].store(active.dispatch.started_ns, Ordering::Relaxed);
            DOMAIN_TASK_EVIDENCE.words[15].store(finished, Ordering::Relaxed);
            DOMAIN_TASK_EVIDENCE.words[12].store(error as u64 + 1, Ordering::Release);
        }
        return result;
    }
    if result == Err(Error::Budget) {
        if let Some(row) = match slot {
            0 => Some(2),
            2 => Some(12),
            3 => Some(22),
            _ => None,
        } {
            let words = &TASK_OVERRUN_EVIDENCE.words;
            words[0].store(0, Ordering::Relaxed);
            for (i, v) in [
                active.dispatch.sequence,
                active.dispatch.thread.id,
                active.dispatch.thread.generation,
                active.dispatch.reserved_ns,
                actual,
                active.dispatch.started_ns,
                finished,
                active.dispatch.window,
                active.dispatch.core_generation,
                u64::from(active.optional.is_some()),
            ]
            .into_iter()
            .enumerate()
            {
                words[row + i].store(v, Ordering::Relaxed);
            }
            words[1].fetch_add(1, Ordering::Relaxed);
            words[0].store(0x4359_4f56_4552_0001, Ordering::Release);
        }
    }
    s.active[slot] = None;
    let optional = active
        .optional
        .map(|debit| s.background.complete(debit, actual, finished));
    if let Ok(i) = group_index(s, active.dispatch.group) {
        s.facts.cpu[i].add(finished, actual);
    }
    COMPLETE_READY[slot].store(false, Ordering::Release);
    CREDIT_KIND[slot].store(0, Ordering::Release);
    if result == Err(Error::Budget) {
        publish_evidence(s);
    }
    result.and(optional.unwrap_or(Ok(())))
}
pub fn complete_builtin(slot: usize, actual_ns: u64, finished_ns: u64) -> Result<(), Error> {
    if slot >= 64 || cpu::slot() != slot || CREDIT_KIND[slot].load(Ordering::Acquire) == 0 {
        return Err(Error::Stale);
    }
    if COMPLETE_READY[slot].load(Ordering::Acquire) {
        return Err(Error::Busy);
    }
    finish_capture(slot, finished_ns.saturating_sub(actual_ns), finished_ns);
    COMPLETE_ACTUAL[slot].store(actual_ns, Ordering::Relaxed);
    COMPLETE_AT[slot].store(finished_ns, Ordering::Relaxed);
    COMPLETE_READY[slot].store(true, Ordering::Release);
    match locked(|s| complete_locked(s, slot)) {
        Err(Error::Busy | Error::NotReady) => Ok(()),
        result => result,
    }
}
pub fn complete_service(actual_ns: u64, finished_ns: u64) -> Result<(), Error> {
    complete_builtin(0, actual_ns, finished_ns)
}
pub fn cpu_window_usage(slot: usize, now: u64) -> Result<(u64, u64), Error> {
    locked(|s| s.scheduler.cpu_window_usage(slot, now))
}
/// Actual healthy, non-draining C ownership for a protected role registration.
pub fn control_owner_context(slot: usize) -> Result<(u64, u64), Error> {
    if !matches!(slot, 1 | 2) {
        return Err(Error::Range);
    }
    locked(|s| {
        let bit = 1u64 << slot;
        if s.layout.business_mask & bit != 0
            || s.layout.healthy_mask & bit == 0
            || s.draining & bit != 0
            || s.scheduler.stats().quarantine_mask & bit != 0
        {
            return Err(Error::NotReady);
        }
        Ok((s.layout.generation, s.generation))
    })
}
/// Only the real C worker on this CPU may spend this credit. During a drain,
/// cleanup may settle/abort its existing job before the stop acknowledgement.
pub fn begin_control(required_ns: u64, cleanup: bool) -> Result<Option<ControlCredit>, Error> {
    let slot = cpu::slot();
    if !matches!(slot, 1 | 2) {
        return Err(Error::Auth);
    }
    locked(|s| {
        if s.draining & (1u64 << slot) != 0 && !cleanup {
            return Err(Error::Busy);
        }
        s.scheduler.reserve_control_with_window_headroom(
            slot,
            s.layout,
            now_ns(),
            required_ns,
            CONTROL_WINDOW_HEADROOM_NS,
        )
    })
}
/// Authenticate the exact still-live reservation on its original control CPU.
/// Reconstructed or already-settled credits cannot authorize replay CPU work.
pub(crate) fn verify_control_credit(credit: &ControlCredit) -> Result<(), Error> {
    let slot = cpu::slot();
    if !matches!(slot, 1 | 2) || usize::from(credit.cpu) != slot {
        return Err(Error::Auth);
    }
    locked(|s| {
        if s.scheduler.control_active(slot) == Some(*credit) {
            Ok(())
        } else {
            Err(Error::Stale)
        }
    })
}
pub fn complete_control(
    credit: ControlCredit,
    actual_ns: u64,
    finished_ns: u64,
) -> Result<(), Error> {
    if usize::from(credit.cpu) != cpu::slot() {
        return Err(Error::Auth);
    }
    locked(|s| {
        let result = s.scheduler.complete_control(credit, actual_ns, finished_ns);
        if result == Err(Error::Budget) {
            publish_evidence(s);
        }
        result
    })
}
pub fn record_control_cost(slot: usize, actual_ns: u64, finished_ns: u64) -> Result<(), Error> {
    locked(|s| {
        if slot >= 64 {
            return Err(Error::Range);
        }
        if s.layout.business_mask & (1u64 << slot) != 0 || s.active[slot].is_some() {
            return Err(Error::Busy);
        }
        s.scheduler
            .record_control_cost(slot, actual_ns, finished_ns, s.layout.generation)
    })
}
pub fn active_slice_ticks(slot: usize) -> Option<u64> {
    if slot >= 64 || CREDIT_KIND[slot].load(Ordering::Acquire) == 0 {
        return None;
    }
    Some(
        ((u128::from((CREDIT_NS[slot].load(Ordering::Relaxed) / 8).min(250_000))
            * u128::from(timer::frequency()))
            / 1_000_000_000)
            .max(1) as u64,
    )
}
pub fn slice_ticks(slot: usize) -> u64 {
    active_slice_ticks(slot).unwrap_or_else(|| (timer::frequency() / 1000).max(1))
}

fn validate_locked(s: &State, action: Action, target: ObjectKey, now: u64) -> Result<(), Error> {
    action.validate()?;
    match action {
        Action::CpuWeight(_) | Action::SpawnTokens(_) => {
            group_index(s, target)?;
            Ok(())
        }
        Action::Cache { pages, .. } if target == MEMORY_KEY => {
            let grant = (pages / 4).min(256);
            let usage = crate::domain_storage::cache_usage();
            let (task_base, task_pages) = memory_backing()?;
            let (file_base, file_pages) = crate::domain_storage::cache_backing()?;
            let task_end = task_base
                .checked_add(u64::from(task_pages) * 4096)
                .ok_or(Error::Overflow)?;
            let file_end = file_base
                .checked_add(u64::from(file_pages) * 4096)
                .ok_or(Error::Overflow)?;
            if !file_base.is_multiple_of(4096)
                || file_pages == 0
                || u64::from(file_pages) != usage[3]
                || (task_base < file_end && file_base < task_end)
            {
                return Err(Error::Conflict);
            }
            if grant as usize > PAGES - TABLE_PAGES - CODE_PAGES - 32
                || u64::from(pages - grant) > usage[3]
            {
                Err(Error::Budget)
            } else {
                Ok(())
            }
        }
        Action::Ipc { .. } => {
            s.ipc.policy(target, now)?;
            Ok(())
        }
        Action::ServiceBatch(_) if target == SERVICE_KEY => Ok(()),
        Action::BackgroundBudget(budget) => {
            let status = s.background.status(target)?;
            if budget < status.committed_milli {
                Err(Error::Budget)
            } else {
                Ok(())
            }
        }
        _ => Err(Error::Stale),
    }
}
pub fn validate_action(action: Action, target: ObjectKey, _now: u64) -> Result<(), Error> {
    locked(|s| validate_locked(s, action, target, now_ns()))
}
fn legal_options(
    options: &[Option<Action>],
    target: ObjectKey,
    _at: u64,
    output: &mut [Option<Action>],
) -> Result<usize, Error> {
    // Candidate tiers share one immutable owner view. Reacquiring the task
    // gate for every value adds cross-vCPU exclusive traffic without observing
    // a newer state that could validly belong to the same candidate set.
    locked(|s| {
        let now = now_ns();
        let first = options.iter().flatten().next().copied();
        if matches!(first, Some(Action::Cache { .. })) {
            // The partition identity and physical spans are common to every
            // Cache tier. Read and validate them once, then vary only the
            // candidate's page grant. A shared hard error still rejects each
            // option exactly as the scalar callback did.
            let cache = (|| {
                if target != MEMORY_KEY {
                    return Err(Error::Stale);
                }
                let usage = crate::domain_storage::cache_usage();
                let (task_base, task_pages) = memory_backing()?;
                let (file_base, file_pages) = crate::domain_storage::cache_backing()?;
                let task_end = task_base
                    .checked_add(u64::from(task_pages) * 4096)
                    .ok_or(Error::Overflow)?;
                let file_end = file_base
                    .checked_add(u64::from(file_pages) * 4096)
                    .ok_or(Error::Overflow)?;
                if !file_base.is_multiple_of(4096)
                    || file_pages == 0
                    || u64::from(file_pages) != usage[3]
                    || (task_base < file_end && file_base < task_end)
                {
                    return Err(Error::Conflict);
                }
                Ok(usage[3])
            })();
            return cyxia_prototype::policy::collect_legal_actions(options, output, |action| {
                action.validate()?;
                let available = cache?;
                let Action::Cache { pages, .. } = action else {
                    return Err(Error::Stale);
                };
                let grant = (pages / 4).min(256);
                if grant as usize > PAGES - TABLE_PAGES - CODE_PAGES - 32
                    || u64::from(pages - grant) > available
                {
                    Err(Error::Budget)
                } else {
                    Ok(())
                }
            });
        }
        cyxia_prototype::policy::collect_legal_actions(options, output, |action| {
            validate_locked(s, action, target, now)
        })
    })
}
pub fn install(
    action: Action,
    target: ObjectKey,
    stamp: PolicyStamp,
    _now: u64,
) -> Result<(), Error> {
    locked(|s| {
        let now = now_ns();
        validate_locked(s, action, target, now)?;
        match action {
            Action::CpuWeight(weight) => s.scheduler.install_weight(target, weight, stamp, now),
            Action::SpawnTokens(tokens) => {
                let i = group_index(s, target)?;
                s.admission.install_tokens(target, tokens, stamp, now)?;
                s.spawn_receipts[i] = stamp.version;
                Ok(())
            }
            Action::Cache { pages, batch } => {
                s.cache_stamp.accepts(stamp, now)?;
                let grant = (pages / 4).min(256);
                s.memory
                    .validate_cache_partition(pages, batch, grant, 64, stamp, now)?;
                crate::domain_storage::set_cache_partition_expiring(pages - grant, batch, stamp)?;
                s.memory
                    .install_cache_partition(pages, batch, grant, 64, stamp, now)?;
                s.cache_stamp = stamp;
                s.cache_action = Some(action);
                record_cache_receipt(s, now);
                Ok(())
            }
            Action::Ipc { budget, batch } => s.ipc.install(target, budget, batch, stamp, now),
            Action::ServiceBatch(batch) => s.services.install(batch, stamp, now),
            Action::BackgroundBudget(budget) => {
                let i = group_index(s, target)?;
                s.background.install(target, budget, stamp, now)?;
                s.background_receipts[i] = stamp.version;
                Ok(())
            }
            _ => Err(Error::Unsupported),
        }
    })
}
pub fn enumerate_target(domain: u16, ordinal: usize) -> Option<ObjectKey> {
    locked(|s| Ok(target_locked(s, domain, ordinal)))
        .ok()
        .flatten()
}
fn target_locked(s: &State, domain: u16, ordinal: usize) -> Option<ObjectKey> {
    match domain {
        1 | 2 => s.scheduler.group_at(ordinal),
        3 => (ordinal == 0).then_some(MEMORY_KEY),
        5 => s.ipc.endpoint_at(ordinal),
        8 => (ordinal == 0).then_some(SERVICE_KEY),
        13 => [group(15), group(16)].get(ordinal).copied(),
        _ => None,
    }
}
fn projected_target(domain: u16, ordinal: usize) -> Option<ObjectKey> {
    match domain {
        1 | 2 => (ordinal < 16).then(|| group(ordinal as u64 + 1)),
        3 => (ordinal == 0).then_some(MEMORY_KEY),
        5 => {
            let base = ordinal
                .checked_mul(2)
                .filter(|base| *base + 1 < IPC_TARGETS.len())?;
            let target = ObjectKey {
                id: IPC_TARGETS[base].load(Ordering::Relaxed),
                generation: IPC_TARGETS[base + 1].load(Ordering::Relaxed),
            };
            (target.id != 0 && target.generation != 0).then_some(target)
        }
        8 => (ordinal == 0).then_some(SERVICE_KEY),
        13 => [group(15), group(16)].get(ordinal).copied(),
        _ => None,
    }
}
pub(crate) fn queued_targets(
    queries: &[crate::domain_control::target_batch::Query],
    output: &mut [Option<ObjectKey>],
) -> Result<(), Error> {
    if !READY.load(Ordering::Acquire) {
        return Err(Error::NotReady);
    }
    crate::domain_control::target_batch::resolve(queries, output, |q| {
        projected_target(q.domain, q.ordinal)
    })
}
pub fn current_action(domain: u16, target: ObjectKey) -> Result<Action, Error> {
    locked(|s| current_locked(s, domain, target, now_ns()))
}
fn current_locked(s: &State, domain: u16, target: ObjectKey, now: u64) -> Result<Action, Error> {
    match domain {
        1 => Ok(Action::CpuWeight(s.scheduler.weight(target, now)?)),
        2 => Ok(Action::SpawnTokens(s.admission.tokens(target, now)?)),
        3 if target == MEMORY_KEY => {
            let (pages, batch) = s.memory.cache_policy(now);
            Ok(Action::Cache { pages, batch })
        }
        5 => {
            let (budget, batch) = s.ipc.policy(target, now)?;
            Ok(Action::Ipc { budget, batch })
        }
        8 if target == SERVICE_KEY => Ok(Action::ServiceBatch(s.services.policy(now))),
        13 => Ok(Action::BackgroundBudget(
            s.background.peek_status(target, now)?.budget_milli,
        )),
        _ => Err(Error::Stale),
    }
}
pub fn observation(domain: u16, target: ObjectKey) -> Result<[u64; 4], Error> {
    locked(|s| {
        let now = now_ns();
        match domain {
            1 => {
                let i = group_index(s, target)?;
                let (_, ready) = s.scheduler.group_threads(target)?;
                Ok([
                    ready as u64,
                    s.facts.wait[i].p99()? / 1000,
                    s.facts.cpu[i].get(now) / 1_000_000,
                    s.facts.wakes[i].get(now),
                ])
            }
            2 => {
                let i = group_index(s, target)?;
                let (total, ready) = s.scheduler.group_threads(target)?;
                Ok([
                    s.facts.spawn[i].get(now),
                    total as u64,
                    ratio((total - ready) as u64, total as u64),
                    s.admission.queued(target)? as u64,
                ])
            }
            3 if target == MEMORY_KEY => {
                let m = s.memory.stats();
                let fs = crate::domain_storage::cache_usage();
                let fm = crate::domain_storage::metrics();
                Ok([
                    m.free_pages as u64 + u64::from(fs[3].saturating_sub(fs[0])),
                    s.facts.faults.get(now),
                    ratio(
                        m.cache_hits.saturating_add(fm.cache_hits),
                        m.cache_hits
                            .saturating_add(m.cache_misses)
                            .saturating_add(fm.cache_hits)
                            .saturating_add(fm.cache_misses),
                    ),
                    s.facts.reclaim_ns.get(now) / 1000,
                ])
            }
            5 => {
                let v = s.ipc.stats(target)?;
                let i = target
                    .id
                    .checked_sub(1)
                    .filter(|i| *i < 34)
                    .ok_or(Error::Stale)? as usize;
                Ok([
                    v.depth as u64,
                    if s.facts.ipc_generation[i] == target.generation {
                        s.facts.ipc_messages[i].get(now)
                    } else {
                        0
                    },
                    v.receive_wait_ns / v.delivered.max(1) / 1000,
                    ratio(v.depth as u64, 128),
                ])
            }
            8 if target == SERVICE_KEY => {
                let v = s.services.stats();
                Ok([
                    s.facts.vectors.get(now),
                    s.facts.vector_latency.p99()? / 1000,
                    s.facts.last_vector_len,
                    ratio(v.errors, v.completed),
                ])
            }
            13 => {
                group_index(s, target)?;
                let status = s.background.peek_status(target, now)?;
                let cores = (s.layout.business_mask
                    & s.layout.healthy_mask
                    & !s.draining
                    & !s.scheduler.stats().quarantine_mask)
                    .count_ones() as u64;
                let total = s
                    .facts
                    .cpu
                    .iter()
                    .map(|r| r.get(now))
                    .fold(0u64, u64::saturating_add);
                Ok([
                    1000 - ratio(total, cores.saturating_mul(1_000_000_000)),
                    status.spent_ns / 1000,
                    s.facts.node_wait.p99()? / 1000,
                    cores,
                ])
            }
            _ => Err(Error::Stale),
        }
    })
}
pub fn node_scheduler_observation() -> Result<[u64; 4], Error> {
    locked(|s| {
        let now = now_ns();
        let cores = (s.layout.business_mask
            & s.layout.healthy_mask
            & !s.draining
            & !s.scheduler.stats().quarantine_mask)
            .count_ones() as u64;
        let actual = s
            .facts
            .cpu
            .iter()
            .map(|r| r.get(now))
            .fold(0u64, u64::saturating_add);
        let wakes = s
            .facts
            .wakes
            .iter()
            .map(|r| r.get(now))
            .fold(0u64, u64::saturating_add);
        Ok([
            u64::from(s.scheduler.stats().runnable),
            s.facts.node_wait.p99()? / 1000,
            ratio(actual, cores.saturating_mul(1_000_000_000)),
            wakes,
        ])
    })
}
pub fn memory_scope() -> Result<[u64; 2], Error> {
    locked(|s| {
        let fs = crate::domain_storage::cache_usage();
        Ok([
            s.memory.stats().free_pages as u64 + u64::from(fs[3].saturating_sub(fs[0])),
            (PAGES - TABLE_PAGES - CODE_PAGES - 32) as u64 + u64::from(fs[3]),
        ])
    })
}
pub fn business_cpu_ns() -> Result<u64, Error> {
    locked(|s| Ok(s.scheduler.stats().actual_ns))
}
/// Monotonic task/remote resource ownership generation. Queueing a request does
/// not allocate a CPU/page owner; creation, release and restart do advance it.
pub fn resource_generation() -> Result<u64, Error> {
    locked(|s| Ok(s.generation))
}
/// Physical owner span, including this owner's reserved PTE/code/progress pages.
/// Ordinary allocation capacity is separately reported by `memory_scope`.
pub fn memory_backing() -> Result<(u64, u32), Error> {
    if !READY.load(Ordering::Acquire) {
        return Err(Error::NotReady);
    }
    Ok((memory::frame_phys(0)?, PAGES as u32))
}
/// Identity of the initialized physical cache partition owner, including its
/// baseline policy before the controller publishes any desired version.
/// Validate the current D03 owner and its file-cache partition from one task
/// gate acquisition and one coherent file-owner projection. This is used only
/// while binding a control proposal; executor admission still calls the normal
/// dependency resolver and revalidates the actual owners.
pub(crate) fn control_cache_dependency(
    at: u64,
) -> Result<crate::domain_control::Prerequisite, Error> {
    if !READY.load(Ordering::Acquire) {
        return Err(Error::NotReady);
    }
    locked(|s| {
        let (pages, batch) = s.memory.cache_policy(at);
        let action = Action::Cache { pages, batch };
        action.validate()?;
        let authorized = s.memory.cache_authorized_pages(at);
        let grant = (pages / 4).min(256);
        let (cache, (file_base, file_pages)) = crate::domain_storage::cache_dependency_view(at)?;
        let (task_base, task_pages) = memory_backing()?;
        let task_end = task_base
            .checked_add(u64::from(task_pages) * 4096)
            .ok_or(Error::Overflow)?;
        let file_end = file_base
            .checked_add(u64::from(file_pages) * 4096)
            .ok_or(Error::Overflow)?;
        if authorized > pages as usize
            || cache[2] != u64::from(pages).saturating_sub(authorized as u64)
            || cache[0] > cache[3]
            || cache[2] > cache[3]
            || authorized > PAGES - TABLE_PAGES - CODE_PAGES - 32
            || !file_base.is_multiple_of(4096)
            || file_pages == 0
            || u64::from(file_pages) != cache[3]
            || (task_base < file_end && file_base < task_end)
        {
            return Err(Error::NotReady);
        }
        if grant as usize > PAGES - TABLE_PAGES - CODE_PAGES - 32
            || u64::from(pages - grant) > cache[3]
        {
            return Err(Error::Budget);
        }
        Ok(crate::domain_control::Prerequisite {
            domain: 3,
            target: MEMORY_KEY,
        })
    })
}

pub fn memory_key() -> Result<ObjectKey, Error> {
    let (base, pages) = memory_backing()?;
    if base & 4095 != 0 || pages == 0 {
        return Err(Error::NotReady);
    }
    locked(|s| {
        // This takes the actual FS owner gate, whose entry applies TTL fallback
        // before reporting its admission target. Busy is not a zero-page grant.
        let fs = crate::domain_storage::cache_partition_status()?;
        let (total, _) = s.memory.cache_policy(now_ns());
        let grant = s.memory.cache_authorized_pages(now_ns());
        if grant > total as usize
            || fs[2] != u64::from(total).saturating_sub(grant as u64)
            || fs[0] > fs[3]
            || fs[2] > fs[3]
            || grant > PAGES - TABLE_PAGES - CODE_PAGES - 32
        {
            return Err(Error::NotReady);
        }
        Ok(MEMORY_KEY)
    })
}
/// Both transports are real, independently bounded FIFO endpoints. A service
/// batch can contain operations for either owner, so both are prerequisites.
pub fn service_endpoints(target: ObjectKey) -> Result<[ObjectKey; 2], Error> {
    if target != SERVICE_KEY || !READY.load(Ordering::Acquire) {
        return Err(Error::Stale);
    }
    locked(|s| service_endpoints_locked(s, target))
}
fn service_endpoints_locked(s: &State, target: ObjectKey) -> Result<[ObjectKey; 2], Error> {
    if target != SERVICE_KEY || !READY.load(Ordering::Acquire) {
        return Err(Error::Stale);
    }
    s.ipc.stats(s.task_endpoint)?;
    s.ipc.stats(s.file_endpoint)?;
    Ok([s.task_endpoint, s.file_endpoint])
}
pub fn common_metrics() -> Result<[u64; 3], Error> {
    locked(|s| {
        let fs = crate::domain_storage::cache_usage();
        let mask = s.layout.business_mask
            & s.layout.healthy_mask
            & !s.draining
            & !s.scheduler.stats().quarantine_mask;
        let free = s.memory.stats().free_pages as u64 + u64::from(fs[3].saturating_sub(fs[0]));
        let pages = (PAGES - TABLE_PAGES - CODE_PAGES - 32) as u64 + u64::from(fs[3]);
        let committed = (0..64)
            .filter(|cpu| s.layout.business_mask & (1u64 << cpu) != 0)
            .map(|cpu| s.scheduler.committed_ns(cpu))
            .sum();
        Ok([
            ratio(free, pages),
            ratio(committed, u64::from(mask.count_ones()) * 90_000_000),
            ratio(s.facts.rejected, s.facts.attempts),
        ])
    })
}

#[path = "domain_tasks/receipts.rs"]
mod receipts;
fn record_cache_receipt(s: &mut State, now: u64) {
    let Some(action @ Action::Cache { pages, .. }) = s.cache_action else {
        return;
    };
    if !s.cache_stamp.live(now) {
        return;
    }
    let grant = (pages / 4).min(256) as usize;
    let fs = crate::domain_storage::cache_usage();
    if s.memory.cache_authorized_pages(now) == grant
        && fs[2] == u64::from(pages) - grant as u64
        && s.memory.stats().cache_pages <= grant
        && fs[0] <= fs[2]
    {
        s.cache_receipt = Some((s.cache_stamp, action));
    }
}
fn completion(
    action: Action,
    target: ObjectKey,
    stamp: PolicyStamp,
) -> Result<cyxia_prototype::policy::ExecutionState, Error> {
    locked(|s| {
        use cyxia_prototype::policy::ExecutionState;
        let now = now_ns();
        if let Action::Cache { .. } = action {
            if s.cache_receipt == Some((stamp, action)) {
                return Ok(ExecutionState::Applied);
            }
            if s.cache_stamp != stamp {
                return Err(Error::Stale);
            }
            record_cache_receipt(s, now);
            if s.cache_receipt == Some((stamp, action)) {
                return Ok(ExecutionState::Applied);
            }
            let fs = crate::domain_storage::cache_usage();
            // An expired shrink still owns old resident/dirty references until
            // both actual owners have restored and reached their baseline.
            let debt = s.memory.stats().cache_pages > 64
                || s.memory.cache_authorized_pages(now) != 64
                || fs[2] != 192
                || fs[0] > 192;
            return Ok(receipts::reconcile(0, stamp, now, debt));
        }
        let version = match action {
            Action::CpuWeight(_) => s.scheduler.policy_receipt(target)?,
            Action::SpawnTokens(_) => s.spawn_receipts[group_index(s, target)?],
            Action::Ipc { .. } => s.ipc.policy_receipt(target)?,
            Action::ServiceBatch(_) if target == SERVICE_KEY => s.services.policy_receipt(),
            Action::BackgroundBudget(_) => s.background_receipts[group_index(s, target)?],
            _ => return Err(Error::Unsupported),
        };
        let in_flight = matches!(action, Action::CpuWeight(_))
            && s.active
                .iter()
                .flatten()
                .any(|a| a.dispatch.group == target && a.dispatch.policy_version == stamp.version);
        Ok(receipts::reconcile(version, stamp, now, in_flight))
    })
}
fn control_target(domain: u16, _kind: u16, ordinal: usize) -> Option<ObjectKey> {
    enumerate_target(domain, ordinal)
}
fn control_current(domain: u16, _kind: u16, target: ObjectKey) -> Result<Action, Error> {
    current_action(domain, target)
}
fn control_features(
    action: Action,
    target: ObjectKey,
) -> Result<cyxia_prototype::features::TargetFeatures, Error> {
    validate_action(action, target, now_ns())?;
    Ok(cyxia_prototype::features::TargetFeatures::default())
}
fn control_apply(
    action: Action,
    id: ApplyId,
    stamp: PolicyStamp,
    now: u64,
) -> Result<cyxia_prototype::policy::ExecutionState, Error> {
    install(action, id.target, stamp, now)?;
    match completion(action, id.target, stamp) {
        Err(Error::Busy) => Ok(cyxia_prototype::policy::ExecutionState::Pending),
        v => v,
    }
}
fn control_reconcile(
    action: Action,
    id: ApplyId,
    stamp: PolicyStamp,
    _now: u64,
) -> Result<cyxia_prototype::policy::ExecutionState, Error> {
    completion(action, id.target, stamp)
}
pub fn register_control() -> Result<(), Error> {
    for domain in [1, 2, 3, 5, 8, 13] {
        crate::domain_control::register(crate::domain_control::Family {
            domain,
            kind: 1,
            target_source: crate::domain_control::TargetSource::Tasks,
            target: control_target,
            observe: |domain, target| {
                observation(domain, target)
                    .map(cyxia_prototype::features::DomainObservation::complete)
            },
            current: control_current,
            legal: validate_action,
            legal_options,
            target_features: control_features,
            apply: control_apply,
            reconcile: control_reconcile,
        })?;
    }
    crate::domain_control::register_dependencies(1, scheduling_dependencies)?;
    crate::domain_control::register_dependencies(8, vector_dependencies)?;
    crate::domain_control::register_execution_observer(5, confirm_ipc_execution)?;
    Ok(())
}
pub fn confirm_ipc_execution(target: ObjectKey, version: u64) -> Result<(), Error> {
    locked(|s| s.ipc.confirm_policy_version(target, version))
}
fn scheduling_dependencies(
    target: ObjectKey,
) -> Result<[Option<crate::domain_control::Prerequisite>; 2], Error> {
    if !matches!(target.id, 15 | 16) {
        return Ok([None; 2]);
    }
    locked(|s| scheduling_dependencies_locked(s, target))
}
fn scheduling_dependencies_locked(
    s: &State,
    target: ObjectKey,
) -> Result<[Option<crate::domain_control::Prerequisite>; 2], Error> {
    if !matches!(target.id, 15 | 16) {
        return Ok([None; 2]);
    }
    group_index(s, target)?;
    s.background.status(target)?;
    Ok([
        Some(crate::domain_control::Prerequisite { domain: 13, target }),
        None,
    ])
}
fn vector_dependencies(
    target: ObjectKey,
) -> Result<[Option<crate::domain_control::Prerequisite>; 2], Error> {
    Ok(service_endpoints(target)?
        .map(|target| Some(crate::domain_control::Prerequisite { domain: 5, target })))
}

fn publish_evidence(s: &State) {
    let words = &DOMAIN_TASK_EVIDENCE.words;
    let put = |i: usize, v: u64| words[i].store(v, Ordering::Relaxed);
    put(0, 0);
    put(1, now_ns());
    let stats = s.scheduler.stats();
    put(2, stats.quarantine_mask);
    put(3, stats.overruns);
    put(4, s.scheduler.cpu_spent_ns(0).unwrap_or(u64::MAX));
    put(5, s.scheduler.cpu_spent_ns(2).unwrap_or(u64::MAX));
    put(6, s.scheduler.cpu_spent_ns(3).unwrap_or(u64::MAX));
    put(7, s.scheduler.thread_count() as u64);
    put(8, u64::from(s.service_admitted));
    if let Some(key) = s.probe_key {
        put(9, key.id);
        put(10, key.generation);
        put(13, s.probe_exit.unwrap_or(u64::MAX));
        if let Ok(i) = task_index(&s.tasks, key) {
            let t = &s.tasks[i];
            put(11, t.life as u64);
            put(12, u64::from(t.entered));
            put(14, s.scheduler.thread_cpu_ns(key).unwrap_or(u64::MAX));
            put(19, u64::from(t.blocked));
            put(20, u64::from(RETURN_PENDING[i].load(Ordering::Acquire)));
            put(21, u64::from(FILE_PENDING[i].load(Ordering::Acquire)));
            put(22, u64::from(FILE_BUSY[i].load(Ordering::Acquire)));
            put(23, u64::from(FILE_DONE[i].load(Ordering::Acquire)));
            if !s.active.iter().flatten().any(|a| a.dispatch.thread == key)
                && !FILE_BUSY[i].load(Ordering::Acquire)
            {
                let c = unsafe { &*core::ptr::addr_of!(CONTEXTS).cast::<user::Context>().add(i) };
                put(15, c.pc);
                put(16, c.kind);
                put(17, c.esr);
                put(18, c.far);
                put(29, c.regs[0]);
                put(30, c.regs[8]);
            }
        }
    }
    put(24, CREDIT_KIND[3].load(Ordering::Acquire));
    put(25, u64::from(COMPLETE_READY[3].load(Ordering::Acquire)));
    put(26, s.active[3].map_or(0, |a| a.dispatch.thread.id));
    put(27, s.active[3].map_or(0, |a| a.dispatch.reserved_ns));
    put(28, s.active[3].map_or(0, |a| a.dispatch.sequence));
    put(31, u64::from(stats.runnable));
    words[0].store(0x4359_5441_534b_0001, Ordering::Release);
}
