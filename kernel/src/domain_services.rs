//! CPU0 service owners. Every receipt is tied to an actual owner transition,
//! process generation or UART write; synchronous disk work runs outside this gate.
use core::sync::atomic::{AtomicBool, Ordering};
use cyxia_contracts::{ConsoleOps, PlatformError};
use cyxia_prototype::{
    domains::{
        Action, ApplyId, Error, ObjectKey, PolicyStamp,
        maintenance::{ConsoleHardware, ConsolePump, RecoveryBackend, RecoverySupervisor},
        platform::TimerClass,
    },
    features::{DomainObservation, TargetFeatures},
    policy::ExecutionState,
};

#[path = "domain_services/console_baseline.rs"]
mod console_baseline;
#[path = "domain_services/replay_sources.rs"]
mod replay_sources;
pub const SOURCE_IDENTITY_BYTES: usize = replay_sources::IDENTITY_BYTES;
#[path = "domain_services/replay_serial.rs"]
pub mod replay_serial;

const CORE_ID: u64 = 0x434f5245;
const BACKGROUND_TIMER_ID: u64 = 2;
const BACKGROUND_PERIOD: u64 = 10_000_000;
const HEARTBEAT_PERIOD: u64 = 500_000_000;
const RECORDS: usize = 272;
const ZERO: ObjectKey = ObjectKey {
    id: 0,
    generation: 0,
};
static LOCK: AtomicBool = AtomicBool::new(false);
static READY: AtomicBool = AtomicBool::new(false);
static CONSOLE_READY: AtomicBool = AtomicBool::new(false);
static BACKGROUND_DUE: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Default)]
struct CoreFacts {
    control: u64,
    business: u64,
    healthy: u64,
    draining: u64,
    core_generation: u64,
    ledger_generation: u64,
    at: u64,
}
#[derive(Clone, Copy)]
struct CoreRecord {
    apply: ApplyId,
    stamp: PolicyStamp,
    desired: u64,
    state: ExecutionState,
    started: u64,
    order: u64,
}
#[derive(Clone, Copy)]
struct ConsoleRecord {
    apply: ApplyId,
    stamp: PolicyStamp,
    chars: u16,
    state: ExecutionState,
}
#[derive(Clone, Copy)]
struct Recoverable {
    key: ObjectKey,
    recipe: u16,
    since: u64,
    last_restart: Option<u64>,
    active: Option<ApplyId>,
    pending_probe: Option<(ObjectKey, u64)>,
    next_probe: u64,
    request: u64,
    errors: u64,
    error_window: u64,
}
struct State {
    boot: u64,
    console_key: ObjectKey,
    console: ConsolePump,
    console_record: Option<ConsoleRecord>,
    console_version: u64,
    console_window: u64,
    console_calls: u64,
    console_full: u64,
    console_cpu: u64,
    console_wait: u64,
    timer_registered: bool,
    timer_armed: bool,
    cores: CoreFacts,
    core_records: [Option<CoreRecord>; RECORDS],
    core_sequence: u64,
    core_seen: (u64, u64),
    recovery: RecoverySupervisor,
    services: [Option<Recoverable>; 2],
}
#[derive(Clone, Copy)]
struct ServiceView {
    key: ObjectKey,
    recipe: u16,
    since: u64,
    last_restart: Option<u64>,
    active: bool,
    errors: u64,
    error_window: u64,
    isolated: Result<bool, Error>,
    restarts: Result<u64, Error>,
}
#[derive(Clone, Copy)]
struct ReadView {
    at: u64,
    boot: u64,
    cores: CoreFacts,
    core_pending: bool,
    services: [Option<ServiceView>; 2],
    console_key: ObjectKey,
    console_window: u64,
    console_metrics: [u64; 4],
    console_action: u16,
    console_until: u64,
    console_poisoned: bool,
}
static READ_VIEW: crate::domain_platform::read_snapshot::ReadSnapshot<ReadView> =
    crate::domain_platform::read_snapshot::ReadSnapshot::new();
static mut STATE: State = State {
    boot: 0,
    console_key: ZERO,
    console: ConsolePump::new(),
    console_record: None,
    console_version: 0,
    console_window: 0,
    console_calls: 0,
    console_full: 0,
    console_cpu: 0,
    console_wait: 0,
    timer_registered: false,
    timer_armed: false,
    cores: CoreFacts {
        control: 0,
        business: 0,
        healthy: 0,
        draining: 0,
        core_generation: 0,
        ledger_generation: 0,
        at: 0,
    },
    core_records: [None; RECORDS],
    core_sequence: 0,
    core_seen: (0, 0),
    recovery: RecoverySupervisor::new(),
    services: [None; 2],
};
struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        LOCK.store(false, Ordering::Release);
    }
}
fn with<R>(f: impl FnOnce(&mut State) -> Result<R, Error>) -> Result<R, Error> {
    if cyxia_arch_aarch64::cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    LOCK.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| Error::Busy)?;
    let _guard = Guard;
    unsafe {
        let state = &mut *core::ptr::addr_of_mut!(STATE);
        let result = f(state);
        publish_view(state);
        result
    }
}
fn publish_view(state: &State) {
    replay_sources::publish(
        state.console_key,
        state
            .services
            .map(|item| item.map(|service| (service.key, service.recipe))),
    );
    let now = now_ns();
    let calls = state.console.calls.saturating_sub(state.console_calls);
    let full = state.console.full.saturating_sub(state.console_full);
    let view = ReadView {
        at: now,
        boot: state.boot,
        cores: state.cores,
        core_pending: state
            .core_records
            .iter()
            .flatten()
            .any(|r| !r.state.terminal()),
        services: state.services.map(|slot| {
            slot.map(|s| ServiceView {
                key: s.key,
                recipe: s.recipe,
                since: s.since,
                last_restart: s.last_restart,
                active: s.active.is_some(),
                errors: s.errors,
                error_window: s.error_window,
                isolated: state.recovery.isolated(s.key),
                restarts: state.recovery.restarts(s.key),
            })
        }),
        console_key: state.console_key,
        console_window: state.console_window,
        console_metrics: [
            state.console.queued() as u64,
            if calls == 0 {
                0
            } else {
                ((u128::from(full) * 1000) / u128::from(calls)).min(u128::from(u64::MAX)) as u64
            },
            state.console.cpu_ns.saturating_sub(state.console_cpu) / 1000,
            state.console_wait / 1000,
        ],
        console_action: state.console.current(now),
        console_until: state
            .console_record
            .map_or(0, |r| r.stamp.installed_until_ns),
        console_poisoned: state.console.poisoned(),
    };
    let _ = READ_VIEW.publish(view);
}
/// C projects a small result under the separate snapshot gate. It never copies
/// the complete view or holds the live service/UART/recovery owner gate.
fn read<R>(f: impl FnOnce(&ReadView) -> Result<R, Error>) -> Result<R, Error> {
    if !READY.load(Ordering::Acquire) {
        return Err(Error::NotReady);
    }
    READ_VIEW
        .inspect(|view| {
            let now = now_ns();
            if now < view.at || now - view.at >= 50_000_000 {
                return Err(Error::Busy);
            }
            f(view)
        })
        .map_err(|_| Error::Busy)?
        .ok_or(Error::NotReady)?
}
fn now_ns() -> u64 {
    crate::domain_platform::now_ns()
}
fn core_key(s: &State) -> ObjectKey {
    ObjectKey {
        id: CORE_ID,
        generation: s.boot,
    }
}
fn timer_key(s: &State) -> ObjectKey {
    ObjectKey {
        id: BACKGROUND_TIMER_ID,
        generation: s.boot,
    }
}
fn due(_: ObjectKey, _: u64) {
    BACKGROUND_DUE.store(true, Ordering::Release);
}

/// Each stage is idempotent. Recovery targets are registered only after the
/// task owner has created their actual address space, endpoint and generation.
pub fn init() -> Result<(), Error> {
    if READY.load(Ordering::Acquire) {
        return Ok(());
    }
    let identity = crate::prototype_storage::identity().ok_or(Error::NotReady)?;
    with(|s| {
        if s.boot != 0 && s.boot != identity.epoch {
            return Err(Error::Conflict);
        }
        s.boot = identity.epoch;
        let base = crate::UART.load(Ordering::Acquire);
        if base == 0 {
            return Err(Error::NotReady);
        }
        s.console_key = ObjectKey {
            id: base.checked_sub(crate::HIGH).ok_or(Error::Range)?,
            generation: s.boot,
        };
        CONSOLE_READY.store(true, Ordering::Release);
        crate::domain_tasks::init_recoverable()?;
        let now = now_ns();
        for i in 0..2 {
            if s.services[i].is_some() {
                continue;
            }
            let recipe = i as u16 + 1;
            let key = crate::domain_tasks::recoverable_key(recipe).ok_or(Error::Again)?;
            s.recovery.register(key, recipe)?;
            s.services[i] = Some(Recoverable {
                key,
                recipe,
                since: now,
                last_restart: None,
                active: None,
                pending_probe: None,
                next_probe: now,
                request: 1,
                errors: 0,
                error_window: now / 1_000_000_000,
            });
        }
        if !s.timer_registered {
            crate::domain_platform::register_timer(timer_key(s), TimerClass::Soft, 1_000_000, due)?;
            s.timer_registered = true;
        }
        if !s.timer_armed {
            crate::domain_platform::arm_timer(
                timer_key(s),
                now.checked_add(BACKGROUND_PERIOD).ok_or(Error::Overflow)?,
                now,
            )?;
            s.timer_armed = true;
        }
        READY.store(true, Ordering::Release);
        Ok(())
    })
}

pub fn console_ready() -> bool {
    CONSOLE_READY.load(Ordering::Acquire)
}
/// Only the ordinary framed console pump is a Canary target. Critical boot
/// and panic UART paths do not use this queued batch policy.
pub fn canary_target() -> Result<cyxia_prototype::learning::governance::TargetRegistration, Error> {
    if !console_ready() {
        return Err(Error::NotReady);
    }
    read(|view| console_baseline::registration(view.console_key, view.console_poisoned))
}
struct Frame {
    bytes: [u8; 128],
    used: usize,
}
impl ConsoleOps for Frame {
    fn try_write(&mut self, bytes: &[u8]) -> Result<usize, PlatformError> {
        let end = self
            .used
            .checked_add(bytes.len())
            .ok_or(PlatformError::Invalid)?;
        let target = self
            .bytes
            .get_mut(self.used..end)
            .ok_or(PlatformError::Invalid)?;
        target.copy_from_slice(bytes);
        self.used = end;
        Ok(bytes.len())
    }
}
pub fn enqueue_frame(session: u64, sequence: u64, payload: &[u8]) -> Result<(), Error> {
    if !console_ready() {
        return Err(Error::NotReady);
    }
    if crate::learning_canary::owns_output() || replay_serial::reserved() {
        // Optional frames receive ordinary backpressure while the registered
        // measurement owner holds a fixed workload. Emergency audit output
        // has its own path and is not admitted through this queue.
        return Err(Error::Again);
    }
    let mut frame = Frame {
        bytes: [0; 128],
        used: 0,
    };
    cyxia_kernel_core::console::write_frame(&mut frame, session, sequence, payload)
        .map_err(|_| Error::Format)?;
    // A frame is admitted in one bounded copy, so backpressure never publishes
    // a partial transport frame or reorders a retried frame.
    with(|s| s.console.enqueue(&frame.bytes[..frame.used], now_ns()))
}

/// Typed CPU0-only access for the protected ordinary serial replay owner.
/// The returned watermark is a byte already accepted into the actual queue.
pub(crate) fn replay_console_enqueue(bytes: &[u8]) -> Result<u64, Error> {
    crate::domain_tasks::authorize_service_turn()?;
    with(|s| {
        s.console.enqueue(bytes, now_ns())?;
        s.console
            .written
            .checked_add(s.console.queued() as u64)
            .ok_or(Error::Overflow)
    })
}
pub(crate) fn replay_console_state() -> Result<(ObjectKey, u64, usize, bool), Error> {
    crate::domain_tasks::authorize_service_turn()?;
    with(|s| {
        Ok((
            s.console_key,
            s.console.written,
            s.console.queued(),
            s.console.poisoned(),
        ))
    })
}
/// The executor's actual accepted installation, before any UART receipt.
pub(crate) fn replay_console_installation() -> Result<Option<(PolicyStamp, ExecutionState)>, Error>
{
    crate::domain_tasks::authorize_service_turn()?;
    with(|s| Ok(s.console_record.map(|r| (r.stamp, r.state))))
}
struct Uart {
    base: u64,
}
impl ConsoleHardware for Uart {
    fn try_write(&mut self, byte: u8) -> Result<bool, Error> {
        if self.base == 0 {
            return Err(Error::NotReady);
        }
        unsafe {
            if core::ptr::read_volatile((self.base + 0x18) as *const u32) & 0x20 != 0 {
                return Ok(false);
            }
            core::ptr::write_volatile(self.base as *mut u32, u32::from(byte));
            core::arch::asm!("dsb oshst", options(nostack, preserves_flags));
        }
        Ok(true)
    }
    fn now_ns(&mut self) -> u64 {
        now_ns()
    }
}
fn console_state(s: &mut State, now: u64) {
    if let Some(record) = &mut s.console_record {
        if record.state.terminal() {
            return;
        }
        record.state = if s.console_version == record.stamp.version {
            ExecutionState::Applied
        } else if s.console.poisoned() {
            ExecutionState::Unknown
        } else if !record.stamp.live(now) {
            ExecutionState::Failed(Error::Expired)
        } else {
            ExecutionState::Pending
        };
    }
}
fn pump_console(s: &mut State, now: u64) -> Result<(), Error> {
    let unresolved = s.console_record.is_some_and(|r| !r.state.terminal());
    let _ = crate::learning_canary::before_console(&mut s.console, s.console_key, now, unresolved);
    if s.console_window != now / 100_000_000 {
        s.console_window = now / 100_000_000;
        s.console_calls = s.console.calls;
        s.console_full = s.console.full;
        s.console_cpu = s.console.cpu_ns;
        s.console_wait = 0;
    }
    let before = s.console.written;
    let receipt = crate::learning_evidence::measure(
        s.console_key,
        cyxia_prototype::learning::reward::CpuClass::ExecutorWork,
        || {
            s.console.pump(
                now,
                &mut Uart {
                    base: crate::UART.load(Ordering::Acquire),
                },
            )
        },
    );
    crate::interrupts::TEST_PROGRESS
        .bytes
        .fetch_add(s.console.written.saturating_sub(before), Ordering::Relaxed);
    if let Ok(receipt) = receipt {
        if receipt.chars != 0 {
            s.console_wait = receipt.wait_ns;
            s.console_version = s.console_version.max(receipt.policy_version);
        }
    }
    console_state(s, now);
    let unresolved = s.console_record.is_some_and(|r| !r.state.terminal());
    let _ = crate::learning_canary::after_console(&s.console, s.console_key, now_ns(), unresolved);
    receipt.map(|_| ())
}

/// The runtime publishes actual owner and ledger generations at its existing
/// serialized topology point. This does not request or claim a migration.
pub fn core_observe(
    control: u64,
    business: u64,
    healthy: u64,
    draining: u64,
    core_generation: u64,
    ledger_generation: u64,
    now: u64,
) -> Result<(), Error> {
    with(|s| {
        if control & business != 0
            || (control | business | healthy | draining) & !15 != 0
            || control == 0
            || core_generation == 0
            || ledger_generation == 0
            || core_generation < s.cores.core_generation
            || ledger_generation < s.cores.ledger_generation
            || now < s.cores.at
        {
            return Err(Error::Conflict);
        }
        s.cores = CoreFacts {
            control,
            business,
            healthy,
            draining,
            core_generation,
            ledger_generation,
            at: now,
        };
        Ok(())
    })
}
pub fn core_request() -> Option<(ApplyId, PolicyStamp, u64)> {
    with(|s| {
        Ok(s.core_records
            .iter()
            .flatten()
            .find(|r| !r.state.terminal())
            .map(|r| (r.apply, r.stamp, r.desired)))
    })
    .ok()
    .flatten()
}
pub fn core_complete(apply: ApplyId, result: Result<u64, Error>, now: u64) -> Result<(), Error> {
    with(|s| {
        let i = s
            .core_records
            .iter()
            .position(|r| r.is_some_and(|r| r.apply == apply))
            .ok_or(Error::Stale)?;
        let record = s.core_records[i].as_mut().ok_or(Error::Stale)?;
        if now < record.started {
            return Err(Error::Range);
        }
        let state = match result {
            Ok(actual) if actual == record.desired && actual == s.cores.control => {
                ExecutionState::Applied
            }
            Ok(_) => return Err(Error::Conflict),
            Err(Error::Busy | Error::Again) => ExecutionState::Pending,
            Err(Error::Io | Error::NotReady) => ExecutionState::Unknown,
            Err(error) => ExecutionState::Failed(error),
        };
        if record.state.terminal() {
            return if record.state == state {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        // A delayed retry cannot erase an already ambiguous transition.
        record.state =
            if record.state == ExecutionState::Unknown && state == ExecutionState::Pending {
                ExecutionState::Unknown
            } else {
                state
            };
        Ok(())
    })
}

struct Recovery {
    apply: ApplyId,
}
impl RecoveryBackend for Recovery {
    fn close_admission(&mut self, target: ObjectKey) -> Result<(), Error> {
        crate::domain_tasks::close_admission(target, self.apply)
    }
    fn readonly_drained(&mut self, target: ObjectKey) -> Result<bool, Error> {
        crate::domain_tasks::readonly_drained(target)
    }
    fn request_stop(&mut self, target: ObjectKey) -> Result<(), Error> {
        crate::domain_tasks::request_stop(target, self.apply)
    }
    fn stopped(&mut self, target: ObjectKey) -> Result<bool, Error> {
        crate::domain_tasks::stopped(target)
    }
    fn start_generation(&mut self, target: ObjectKey, next: u64) -> Result<(), Error> {
        crate::domain_tasks::start_generation(target, next, self.apply)
    }
    fn running(&mut self, target: ObjectKey, generation: u64) -> Result<bool, Error> {
        crate::domain_tasks::running(ObjectKey {
            id: target.id,
            generation,
        })
    }
}
fn count_error(service: &mut Recoverable, now: u64) {
    if service.error_window != now / 1_000_000_000 {
        service.error_window = now / 1_000_000_000;
        service.errors = 0;
    }
    service.errors = service.errors.saturating_add(1);
}
fn poll_services(s: &mut State, now: u64) -> Result<(), Error> {
    for entry in &mut s.services {
        let Some(service) = entry.as_mut() else {
            continue;
        };
        if let Some(apply) = service.active {
            crate::learning_evidence::measure(
                apply.target,
                cyxia_prototype::learning::reward::CpuClass::ExecutorAction,
                || {
                    let old = s.recovery.query(apply)?;
                    let receipt = s.recovery.poll(apply, now, &mut Recovery { apply })?;
                    if receipt.state.terminal() {
                        service.active = None;
                        if receipt.state == ExecutionState::Applied {
                            service.key.generation = receipt.generation;
                            service.pending_probe = None;
                            service.next_probe = now;
                            service.since = now;
                        } else if old.state != receipt.state {
                            count_error(service, now);
                        }
                    }
                    Ok::<(), Error>(())
                },
            )?;
        }
        // Real readonly IPC requests and EL0 replies supply liveness. No timer
        // callback or generation assignment manufactures a heartbeat.
        if let Some((key, sequence)) = service.pending_probe {
            match crate::domain_tasks::recoverable_result(key, sequence) {
                Ok(value) => {
                    if service.recipe == 2 && value != service.request - 1 {
                        count_error(service, now);
                    }
                    service.pending_probe = None;
                    service.next_probe = now.saturating_add(HEARTBEAT_PERIOD);
                }
                Err(Error::Busy | Error::Again) => {}
                Err(_) => {
                    // A response might still exist. Keep its exact owner and
                    // sequence until a verified restart retires that generation.
                    if now >= service.next_probe {
                        count_error(service, now);
                        service.next_probe = now.saturating_add(HEARTBEAT_PERIOD);
                    }
                }
            }
        } else if service.active.is_none()
            && now >= service.next_probe
            && !replay::owns(service.recipe)
        {
            let id = service.request;
            let next = id.checked_add(1).ok_or(Error::Overflow)?;
            match crate::domain_tasks::recoverable_submit(service.recipe, id, id) {
                Ok(sequence) => {
                    service.pending_probe = Some((service.key, sequence));
                    service.request = next;
                    service.next_probe = now.saturating_add(HEARTBEAT_PERIOD);
                }
                Err(Error::Busy | Error::Again | Error::NotReady) => {}
                Err(_) => {
                    count_error(service, now);
                    service.next_probe = now.saturating_add(HEARTBEAT_PERIOD);
                }
            }
        }
    }
    Ok(())
}
#[path = "domain_services/replay.rs"]
pub mod replay;

/// Called from the outer CPU0 loop, never recursively from a disk progress
/// callback. The callback may progress the coordinator and TCP owner only.
pub fn service(now: u64, progress: &mut dyn FnMut()) -> Result<(), Error> {
    if !READY.load(Ordering::Acquire) {
        return Err(Error::NotReady);
    }
    crate::domain_platform::poll(now)?;
    with(|s| {
        for r in s.core_records.iter_mut().flatten() {
            if !r.state.terminal() && now.saturating_sub(r.started) >= 200_000_000 {
                r.state = ExecutionState::Unknown;
            }
        }
        poll_services(s, now)?;
        pump_console(s, now)
    })?;
    if BACKGROUND_DUE.swap(false, Ordering::AcqRel) {
        with(|s| {
            crate::domain_platform::arm_timer(
                timer_key(s),
                now.checked_add(BACKGROUND_PERIOD).ok_or(Error::Overflow)?,
                now,
            )?;
            Ok(())
        })?;
        let result = crate::domain_storage::background_flush(now, progress);
        match result {
            Ok(_) => {}
            Err(Error::Busy | Error::Again | Error::Budget | Error::NotReady | Error::Conflict) => {
                BACKGROUND_DUE.store(true, Ordering::Release);
            }
            Err(error) => return Err(error),
        }
    }
    // Reclaim remains bounded even when dependencies block new writeback.
    match crate::domain_storage::cache_reclaim_turn() {
        Ok(_) | Err(Error::Busy | Error::Again) => Ok(()),
        Err(error) => Err(error),
    }
}

#[path = "domain_services/target_projection.rs"]
mod target_projection;
fn target(domain: u16, kind: u16, ordinal: usize) -> Option<ObjectKey> {
    if !READY.load(Ordering::Acquire) {
        return None;
    }
    target_projection::target(
        &READ_VIEW,
        target_projection::Query {
            domain,
            kind,
            ordinal,
        },
        now_ns,
        project_targets,
    )
}
fn project_targets(s: &ReadView) -> target_projection::Targets {
    target_projection::Targets {
        published_ns: s.at,
        core: (s.cores.core_generation != 0).then(|| core_view_key(s)),
        services: core::array::from_fn(|i| s.services[i].as_ref().map(|service| service.key)),
        console: s.console_key,
    }
}
pub(crate) fn queued_targets(
    queries: &[crate::domain_control::target_batch::Query],
    output: &mut [Option<ObjectKey>],
) -> Result<(), Error> {
    if !READY.load(Ordering::Acquire) {
        return Err(Error::NotReady);
    }
    let targets = target_projection::targets(&READ_VIEW, now_ns, project_targets)?;
    crate::domain_control::target_batch::resolve(queries, output, |q| {
        targets.get(target_projection::Query {
            domain: q.domain,
            kind: q.kind,
            ordinal: q.ordinal,
        })
    })
}
fn core_view_key(s: &ReadView) -> ObjectKey {
    ObjectKey {
        id: CORE_ID,
        generation: s.boot,
    }
}
fn service_view_index(s: &ReadView, target: ObjectKey) -> Result<usize, Error> {
    s.services
        .iter()
        .position(|v| v.is_some_and(|v| v.key == target))
        .ok_or(Error::Stale)
}
fn service_index(s: &State, target: ObjectKey) -> Result<usize, Error> {
    s.services
        .iter()
        .position(|v| v.is_some_and(|v| v.key == target))
        .ok_or(Error::Stale)
}
fn observation(domain: u16, target: ObjectKey) -> Result<[u64; 4], Error> {
    read(|s| match domain {
        1 if target == core_view_key(s) => crate::domain_tasks::node_scheduler_observation(),
        14 => {
            let service = s.services[service_view_index(s, target)?].ok_or(Error::Stale)?;
            let now = now_ns();
            let heartbeat = crate::domain_tasks::heartbeat_ns(target)?;
            Ok([
                now.saturating_sub(if heartbeat == 0 {
                    service.since
                } else {
                    heartbeat
                }) / 1_000_000,
                if service.error_window == now / 1_000_000_000 {
                    service.errors
                } else {
                    0
                },
                service.restarts?,
                s.services.iter().flatten().filter(|v| v.active).count() as u64,
            ])
        }
        15 if target == s.console_key => {
            let live = now_ns() / 100_000_000 == s.console_window;
            Ok([
                s.console_metrics[0],
                if live { s.console_metrics[1] } else { 0 },
                if live { s.console_metrics[2] } else { 0 },
                if live { s.console_metrics[3] } else { 0 },
            ])
        }
        _ => Err(Error::Stale),
    })
}
/// Project the CoreSet current action and its task-owner observation from one
/// immutable service snapshot. The task metrics keep their own owner check;
/// this merely avoids reacquiring the identical service publication twice.
pub(crate) fn core_preparation(target: ObjectKey) -> Result<(Action, DomainObservation), Error> {
    read(|s| {
        if target != core_view_key(s) || s.cores.core_generation == 0 {
            return Err(Error::Stale);
        }
        Ok((
            Action::ControlSet(s.cores.control),
            DomainObservation::complete(crate::domain_tasks::node_scheduler_observation()?),
        ))
    })
}
fn current(domain: u16, kind: u16, target: ObjectKey) -> Result<Action, Error> {
    read(|s| match (domain, kind) {
        (1, 2) if target == core_view_key(s) && s.cores.core_generation != 0 => {
            Ok(Action::ControlSet(s.cores.control))
        }
        (14, 1) => {
            service_view_index(s, target)?;
            Ok(Action::RecoveryRecipe(0))
        }
        (15, 1) if target == s.console_key => {
            Ok(Action::ConsoleBatch(if now_ns() < s.console_until {
                s.console_action
            } else {
                8
            }))
        }
        _ => Err(Error::Stale),
    })
}
fn legal_locked(s: &State, action: Action, target: ObjectKey, now: u64) -> Result<(), Error> {
    if !READY.load(Ordering::Acquire) {
        return Err(Error::NotReady);
    }
    action.validate()?;
    match action {
        Action::ControlSet(mask) => {
            if target != core_key(s) || s.cores.core_generation == 0 {
                return Err(Error::Stale);
            }
            if ![2, 6].contains(&mask)
                || mask & s.cores.healthy != mask
                || mask & s.cores.draining != 0
                || s.cores.business & s.cores.healthy & !s.cores.draining & !mask == 0
            {
                return Err(Error::Budget);
            }
            if mask != s.cores.control {
                if (mask ^ s.cores.control) != 4 {
                    return Err(Error::Range);
                }
                if s.core_records.iter().flatten().any(|r| !r.state.terminal()) {
                    return Err(Error::Busy);
                }
                crate::domain_tasks::can_control_move(2)?;
            }
            Ok(())
        }
        Action::RecoveryRecipe(recipe) => {
            let service = s.services[service_index(s, target)?].ok_or(Error::Stale)?;
            if recipe == 0 {
                return Ok(());
            }
            if recipe != service.recipe {
                return Err(Error::Auth);
            }
            if replay::preparing(service.recipe) {
                return Err(Error::Busy);
            }
            if service.active.is_some() || s.recovery.isolated(target)? {
                return Err(Error::Busy);
            }
            if service
                .last_restart
                .is_some_and(|at| now < at || now - at < 1_000_000_000)
            {
                return Err(Error::Again);
            }
            Ok(())
        }
        Action::ConsoleBatch(_) if target == s.console_key => {
            if s.console.poisoned() {
                Err(Error::Io)
            } else {
                Ok(())
            }
        }
        _ => Err(Error::Unsupported),
    }
}
fn legal(action: Action, target: ObjectKey, now: u64) -> Result<(), Error> {
    read(|s| legal_view(s, action, target, now))
}
fn legal_options(
    options: &[Option<Action>],
    target: ObjectKey,
    now: u64,
    output: &mut [Option<Action>],
) -> Result<usize, Error> {
    read(|view| {
        cyxia_prototype::policy::collect_legal_actions(options, output, |action| {
            legal_view(view, action, target, now)
        })
    })
}
fn legal_view(s: &ReadView, action: Action, target: ObjectKey, now: u64) -> Result<(), Error> {
    action.validate()?;
    match action {
        Action::ControlSet(mask) => {
            if target != core_view_key(s) || s.cores.core_generation == 0 {
                return Err(Error::Stale);
            }
            if ![2, 6].contains(&mask)
                || mask & s.cores.healthy != mask
                || mask & s.cores.draining != 0
                || s.cores.business & s.cores.healthy & !s.cores.draining & !mask == 0
            {
                return Err(Error::Budget);
            }
            if mask != s.cores.control {
                if (mask ^ s.cores.control) != 4 {
                    return Err(Error::Range);
                }
                if s.core_pending {
                    return Err(Error::Busy);
                }
                crate::domain_tasks::can_control_move(2)?;
            }
            Ok(())
        }
        Action::RecoveryRecipe(recipe) => {
            let service = s.services[service_view_index(s, target)?].ok_or(Error::Stale)?;
            if recipe == 0 {
                return Ok(());
            }
            if recipe != service.recipe {
                return Err(Error::Auth);
            }
            if replay::preparing(service.recipe) {
                return Err(Error::Busy);
            }
            if service.active || service.isolated? {
                return Err(Error::Busy);
            }
            if service
                .last_restart
                .is_some_and(|at| now < at || now - at < 1_000_000_000)
            {
                return Err(Error::Again);
            }
            Ok(())
        }
        Action::ConsoleBatch(_) if target == s.console_key => {
            if s.console_poisoned {
                Err(Error::Io)
            } else {
                Ok(())
            }
        }
        _ => Err(Error::Unsupported),
    }
}
fn target_features(action: Action, target: ObjectKey) -> Result<TargetFeatures, Error> {
    read(|s| {
        legal_view(s, action, target, now_ns())?;
        Ok(if let Action::ControlSet(mask) = action {
            TargetFeatures {
                // The controller adds P199's queued mandatory WCET estimate
                // while it owns that queue; there is no nested policy borrow.
                values: [
                    Some(u64::from((mask & s.cores.healthy).count_ones()) * 1000),
                    None,
                    None,
                    Some(1),
                ],
            }
        } else {
            TargetFeatures::default()
        })
    })
}
fn core_apply(
    s: &mut State,
    mask: u64,
    apply: ApplyId,
    stamp: PolicyStamp,
    now: u64,
) -> Result<ExecutionState, Error> {
    if let Some(old) = s.core_records.iter().flatten().find(|r| r.apply == apply) {
        return if old.desired == mask && old.stamp == stamp {
            Ok(old.state)
        } else {
            Err(Error::Conflict)
        };
    }
    if (apply.controller_epoch, apply.plan_seq) <= s.core_seen {
        return Err(Error::Stale);
    }
    PolicyStamp::default().accepts_action(Action::ControlSet(mask), stamp, now)?;
    legal_locked(s, Action::ControlSet(mask), apply.target, now)?;
    if s.core_records.iter().flatten().any(|r| !r.state.terminal()) {
        return Err(Error::Busy);
    }
    let i = s
        .core_records
        .iter()
        .position(Option::is_none)
        .or_else(|| {
            s.core_records
                .iter()
                .enumerate()
                .filter_map(|(i, r)| r.filter(|r| r.state.terminal()).map(|r| (i, r.order)))
                .min_by_key(|(_, order)| *order)
                .map(|(i, _)| i)
        })
        .ok_or(Error::Capacity)?;
    let order = s.core_sequence.checked_add(1).ok_or(Error::Overflow)?;
    let state = if mask == s.cores.control {
        ExecutionState::Applied
    } else {
        ExecutionState::Pending
    };
    s.core_records[i] = Some(CoreRecord {
        apply,
        stamp,
        desired: mask,
        state,
        started: now,
        order,
    });
    s.core_sequence = order;
    s.core_seen = (apply.controller_epoch, apply.plan_seq);
    Ok(state)
}
fn apply(
    action: Action,
    id: ApplyId,
    stamp: PolicyStamp,
    now: u64,
) -> Result<ExecutionState, Error> {
    with(|s| {
        if id.boot_epoch != s.boot
            || id.controller_epoch == 0
            || id.plan_seq == 0
            || id.action_index >= 16
        {
            return Err(Error::Auth);
        }
        match action {
            Action::ControlSet(mask) => core_apply(s, mask, id, stamp, now),
            Action::RecoveryRecipe(recipe) => {
                if s.recovery.query(id).is_ok() {
                    return s
                        .recovery
                        .begin_policy(id, recipe, stamp, now)
                        .map(|r| r.state);
                }
                legal_locked(s, action, id.target, now)?;
                let i = service_index(s, id.target)?;
                let receipt = s.recovery.begin_policy(id, recipe, stamp, now)?;
                if recipe != 0 {
                    let service = s.services[i].as_mut().ok_or(Error::Stale)?;
                    service.last_restart = Some(now);
                    service.active = Some(id);
                }
                Ok(receipt.state)
            }
            Action::ConsoleBatch(chars) => {
                if let Some(old) = s.console_record {
                    if old.apply == id {
                        if old.chars != chars || old.stamp != stamp {
                            return Err(Error::Conflict);
                        }
                        console_state(s, now);
                        return Ok(s.console_record.unwrap().state);
                    }
                    console_state(s, now);
                    if !s.console_record.unwrap().state.terminal() {
                        return Err(Error::Busy);
                    }
                    old.stamp.accepts(stamp, now)?;
                }
                legal_locked(s, action, id.target, now)?;
                s.console.install(stamp, chars, now)?;
                s.console_record = Some(ConsoleRecord {
                    apply: id,
                    stamp,
                    chars,
                    state: ExecutionState::Pending,
                });
                Ok(ExecutionState::Pending)
            }
            _ => Err(Error::Unsupported),
        }
    })
}
fn reconcile(
    action: Action,
    id: ApplyId,
    stamp: PolicyStamp,
    now: u64,
) -> Result<ExecutionState, Error> {
    with(|s| match action {
        Action::ControlSet(mask) => {
            let Some(record) = s.core_records.iter_mut().flatten().find(|r| r.apply == id) else {
                return Ok(ExecutionState::Failed(Error::Again));
            };
            if record.desired != mask || record.stamp != stamp {
                return Err(Error::Conflict);
            }
            if !record.state.terminal() && now.saturating_sub(record.started) >= 200_000_000 {
                record.state = ExecutionState::Unknown;
            }
            Ok(record.state)
        }
        Action::RecoveryRecipe(recipe) => match s.recovery.query(id) {
            Ok(receipt) if receipt.recipe == recipe => Ok(receipt.state),
            Ok(_) => Err(Error::Conflict),
            Err(Error::Stale) => Ok(ExecutionState::Failed(Error::Again)),
            Err(error) => Err(error),
        },
        Action::ConsoleBatch(chars) => {
            let Some(old) = s.console_record else {
                return Ok(ExecutionState::Failed(Error::Again));
            };
            if old.apply != id {
                return if old.stamp.version < stamp.version {
                    Ok(ExecutionState::Failed(Error::Again))
                } else {
                    Err(Error::Stale)
                };
            }
            if old.stamp != stamp || old.chars != chars {
                return Err(Error::Conflict);
            }
            console_state(s, now);
            Ok(s.console_record.unwrap().state)
        }
        _ => Err(Error::Unsupported),
    })
}
pub fn register_control() -> Result<(), Error> {
    if !READY.load(Ordering::Acquire) {
        return Err(Error::NotReady);
    }
    for (domain, kind) in [(1, 2), (14, 1), (15, 1)] {
        crate::domain_control::register(crate::domain_control::Family {
            domain,
            kind,
            target_source: crate::domain_control::TargetSource::Services,
            target,
            observe: |domain, target| {
                observation(domain, target)
                    .map(cyxia_prototype::features::DomainObservation::complete)
            },
            current,
            legal,
            legal_options,
            target_features,
            apply,
            reconcile,
        })?;
    }
    Ok(())
}
