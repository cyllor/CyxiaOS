//! Native task ownership. Every shared mutation uses one nonblocking gate.
//! EL0 and blocking file/device work execute outside that gate.
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use cyxia_arch_aarch64::{cpu, mmu, timer, user};
use cyxia_contracts::PhysAddr;
use cyxia_prototype::domains::maintenance::{BackgroundBudgets, CpuDebit};
use cyxia_prototype::domains::tasks::*;
use cyxia_prototype::domains::{Action, ApplyId, Error, ObjectKey, PolicyStamp};
use sha2::{Digest, Sha256};
#[path = "domain_tasks/abi.rs"]
mod abi;
#[path = "domain_tasks/execution.rs"]
mod execution;
#[path = "domain_tasks/memory.rs"]
mod memory;
pub use abi::{
    close_network, fault, grant_endpoint, grant_file_cap, network_drain, network_key,
    network_pending, network_write, open_network, syscall,
};
pub use execution::{
    cancel_spawn, close_admission, dispatch, heartbeat_ns, init_recoverable, probe_status,
    query_local, query_spawn, readonly_drained, recoverable_key, recoverable_result,
    recoverable_submit, remote_activate, remote_capacity, remote_fault, remote_release,
    remote_selected, remote_start, remote_stopped, remote_word, request_stop, running, service,
    start_generation, start_probe_client, stopped, submit_local, submit_spawn,
};
pub use memory::{
    cache_read, copyin, copyout, invalidate_file, probe_user, set_cache_loader, set_file_service,
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
const ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/prototype-task.elf"));
const CLIENT_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/prototype-client.elf"));
const SELFTEST_ENABLED: bool = include!(concat!(env!("OUT_DIR"), "/domain-selftest.rs"));
#[repr(C, align(4096))]
struct Page([u8; 4096]);
static mut POOL: [Page; PAGES] = [const { Page([0; 4096]) }; PAGES];
static mut CONTEXTS: [user::Context; TASKS] = [const { user::Context::empty() }; TASKS];
static LOCK: AtomicBool = AtomicBool::new(false);
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
#[derive(Clone, Copy)]
struct Samples {
    values: [u64; 64],
    count: usize,
    next: usize,
}
impl Samples {
    const EMPTY: Self = Self {
        values: [0; 64],
        count: 0,
        next: 0,
    };
    fn add(&mut self, value: u64) {
        self.values[self.next] = value;
        self.next = (self.next + 1) % 64;
        self.count = (self.count + 1).min(64);
    }
    fn p99(&self) -> Result<u64, Error> {
        if self.count == 0 {
            return Err(Error::NotReady);
        }
        let mut values = self.values;
        values[..self.count].sort_unstable();
        Ok(values[(self.count * 99).div_ceil(100) - 1])
    }
}
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
struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        LOCK.store(false, Ordering::Release);
    }
}
fn locked<R>(f: impl FnOnce(&mut State) -> Result<R, Error>) -> Result<R, Error> {
    LOCK.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| Error::Busy)?;
    let _guard = Guard;
    unsafe { f(&mut *core::ptr::addr_of_mut!(STATE)) }
}
pub fn now_ns() -> u64 {
    ((u128::from(timer::ticks()) * 1_000_000_000) / u128::from(timer::frequency()))
        .min(u128::from(u64::MAX)) as u64
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
    if !READY.load(Ordering::Acquire) || slot >= 64 {
        return None;
    }
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
        let Some(mut d) = s.scheduler.dispatch(slot, s.layout, now, 10_000_000)? else {
            return Ok(None);
        };
        let safety = match task_index(&s.tasks, d.thread) {
            Ok(i)
                if !s.tasks[i].optional
                    && s.probe_key != Some(d.thread)
                    && s.tasks[i].parent != CLUSTER_CALLER =>
            {
                1_000_000
            }
            _ => 2_000_000,
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
        }))
    })
    .ok()
    .flatten()
}
pub fn begin_service(now: u64) -> Option<Credit> {
    begin_builtin(0, now)
}
fn begin_file_credit(owner: ObjectKey) -> Result<Option<Credit>, Error> {
    if cpu::slot() != 0 || !READY.load(Ordering::Acquire) {
        return Err(Error::Auth);
    }
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
        }))
    })
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
    locked(|s| {
        Ok(match domain {
            1 | 2 => s.scheduler.group_at(ordinal),
            3 => (ordinal == 0).then_some(MEMORY_KEY),
            5 => s.ipc.endpoint_at(ordinal),
            8 => (ordinal == 0).then_some(SERVICE_KEY),
            13 => [group(15), group(16)].get(ordinal).copied(),
            _ => None,
        })
    })
    .ok()
    .flatten()
}
pub fn current_action(domain: u16, target: ObjectKey) -> Result<Action, Error> {
    locked(|s| {
        let now = now_ns();
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
                s.background.current_status(target, now)?.budget_milli,
            )),
            _ => Err(Error::Stale),
        }
    })
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
                let status = s.background.current_status(target, now)?;
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
    locked(|s| {
        s.ipc.stats(s.task_endpoint)?;
        s.ipc.stats(s.file_endpoint)?;
        Ok([s.task_endpoint, s.file_endpoint])
    })
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

fn completion(
    action: Action,
    target: ObjectKey,
    stamp: PolicyStamp,
) -> Result<cyxia_prototype::policy::ExecutionState, Error> {
    locked(|s| {
        use cyxia_prototype::policy::ExecutionState;
        if !stamp.live(now_ns()) {
            return Ok(ExecutionState::Failed(Error::Expired));
        }
        if let Action::Cache { .. } = action {
            if s.cache_stamp != stamp {
                return Err(Error::Stale);
            }
            let fs = crate::domain_storage::cache_usage();
            return Ok(
                if s.memory.stats().cache_pages <= s.memory.cache_authorized_pages(now_ns())
                    && fs[0] <= fs[2]
                {
                    ExecutionState::Applied
                } else {
                    ExecutionState::Pending
                },
            );
        }
        let version = match action {
            Action::CpuWeight(_) => s.scheduler.policy_receipt(target)?,
            Action::SpawnTokens(_) => s.spawn_receipts[group_index(s, target)?],
            Action::Ipc { .. } => s.ipc.policy_receipt(target)?,
            Action::ServiceBatch(_) if target == SERVICE_KEY => s.services.policy_receipt(),
            Action::BackgroundBudget(_) => s.background_receipts[group_index(s, target)?],
            _ => return Err(Error::Unsupported),
        };
        Ok(if version == stamp.version {
            ExecutionState::Applied
        } else {
            ExecutionState::Pending
        })
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
            target: control_target,
            observe: observation,
            current: control_current,
            legal: validate_action,
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
    locked(|s| {
        group_index(s, target)?;
        s.background.status(target)?;
        Ok([
            Some(crate::domain_control::Prerequisite { domain: 13, target }),
            None,
        ])
    })
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
