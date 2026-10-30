//! CPU0 owns the mutable executors. Hard IRQs touch only fixed atomics and GIC
//! registers; polling/ACK/DMA ownership stays with each original device driver.
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use cyxia_arch_aarch64::{cpu, timer};
use cyxia_contracts::BootInfo;
use cyxia_driver_gicv2::Gic;
use cyxia_prototype::{
    domains::{Action, ApplyId, Error, ObjectKey, PolicyStamp, platform::*},
    features::{DomainObservation, TargetFeatures},
    policy::ExecutionState,
};
#[path = "domain_platform/ipi.rs"]
mod ipi;
#[path = "domain_platform/irq_metrics.rs"]
mod irq_metrics;
#[path = "domain_platform/irq_replay.rs"]
pub mod irq_replay;
#[path = "domain_platform/read_snapshot.rs"]
pub(crate) mod read_snapshot;
#[path = "domain_platform/replay.rs"]
pub mod replay;
pub use ipi::{consume_ipi, ipi_enter, ipi_result, register_ipi_cpu, request_ipi};
use irq_metrics::{Histogram, Snapshot};
const IRQ_SLOTS: usize = 32;
const TIMER_SLOTS: usize = 256;
const IRQ_ALLOWED: u64 = 9; // CPU0/CPU3 anchors; CPU2 control handoff has no SPI.
static READY: AtomicBool = AtomicBool::new(false);
static COUNT: AtomicUsize = AtomicUsize::new(0);
static IDS: [AtomicU64; IRQ_SLOTS] = [const { AtomicU64::new(0) }; IRQ_SLOTS];
static BASES: [AtomicU64; IRQ_SLOTS] = [const { AtomicU64::new(0) }; IRQ_SLOTS];
static DEVICES: [AtomicU64; IRQ_SLOTS] = [const { AtomicU64::new(0) }; IRQ_SLOTS];
static LIVE: [AtomicBool; IRQ_SLOTS] = [const { AtomicBool::new(false) }; IRQ_SLOTS];
static INFLIGHT: [AtomicU64; IRQ_SLOTS] = [const { AtomicU64::new(0) }; IRQ_SLOTS];
static MASKED: [AtomicBool; IRQ_SLOTS] = [const { AtomicBool::new(true) }; IRQ_SLOTS];
static ROUTE_BLOCKED: [AtomicBool; IRQ_SLOTS] = [const { AtomicBool::new(false) }; IRQ_SLOTS];
static TARGET: [AtomicU64; IRQ_SLOTS] = [const { AtomicU64::new(0) }; IRQ_SLOTS];
static ROUTE_GENERATION: [AtomicU64; IRQ_SLOTS] = [const { AtomicU64::new(1) }; IRQ_SLOTS];
static DESIRED: [AtomicU64; IRQ_SLOTS] = [const { AtomicU64::new(0) }; IRQ_SLOTS];
static HANDLED: [AtomicU64; IRQ_SLOTS] = [const { AtomicU64::new(0) }; IRQ_SLOTS];
static LAST_CPU: [AtomicU64; IRQ_SLOTS] = [const { AtomicU64::new(u64::MAX) }; IRQ_SLOTS];
static IRQ_STARTED: [AtomicU64; IRQ_SLOTS] = [const { AtomicU64::new(0) }; IRQ_SLOTS];
static HANDLER_TICKS: [AtomicU64; IRQ_SLOTS] = [const { AtomicU64::new(0) }; IRQ_SLOTS];
static UNKNOWN: AtomicU64 = AtomicU64::new(0);
static HISTOGRAMS: [Histogram; IRQ_SLOTS] = [const { Histogram::new() }; IRQ_SLOTS];
static mut WINDOW_AT: u64 = 0;
static mut WINDOW_CORE: u64 = 0;
static mut PREVIOUS_SAMPLES: [Snapshot; IRQ_SLOTS] = [const { Snapshot::new() }; IRQ_SLOTS];
static mut SAMPLE_WORKSPACE: Snapshot = Snapshot::new();
static mut PREVIOUS_VALID: [bool; IRQ_SLOTS] = [true; IRQ_SLOTS];
static mut IRQ_MEASUREMENTS: [Option<[u64; 4]>; IRQ_SLOTS] = [None; IRQ_SLOTS];
static mut TIMER_MEASUREMENTS: Option<[u64; 4]> = None;
static mut PREVIOUS_TIMERS: (u64, u64) = (0, 0);
static CONTEXT_LOCK: AtomicBool = AtomicBool::new(false);
static CORE_GENERATION: AtomicU64 = AtomicU64::new(0);
static LEDGER_GENERATION: AtomicU64 = AtomicU64::new(0);
static HEALTHY_BUSINESS: AtomicU64 = AtomicU64::new(0);
static DRAINING: AtomicU64 = AtomicU64::new(0);
static CONTEXT_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static mut ROUTERS: [Option<IrqRouter>; IRQ_SLOTS] = [const { None }; IRQ_SLOTS];
static mut ROUTE_RESULT: [Option<IrqProgress>; IRQ_SLOTS] = [None; IRQ_SLOTS];
static mut NEXT_RETRY: [u64; IRQ_SLOTS] = [0; IRQ_SLOTS];
type TimerCallback = fn(ObjectKey, u64);
static mut TIMERS: Timers = Timers::new();
static mut TIMER_KEYS: [Option<ObjectKey>; TIMER_SLOTS] = [None; TIMER_SLOTS];
static mut CALLBACKS: [Option<TimerCallback>; TIMER_SLOTS] = [None; TIMER_SLOTS];
static mut EVENTS: [Option<ObjectKey>; TIMER_SLOTS] = [None; TIMER_SLOTS];
static ARMED_TICKS: [AtomicU64; TIMER_SLOTS] = [const { AtomicU64::new(u64::MAX) }; TIMER_SLOTS];
static NEXT_TIMER: AtomicU64 = AtomicU64::new(u64::MAX);
static POLLING: AtomicBool = AtomicBool::new(false);
const TIMER_SERVICE: ObjectKey = ObjectKey {
    id: 7,
    generation: 1,
};
static mut TIMER_POLICY: Option<(ApplyId, PolicyStamp, u16)> = None;
static TIMER_USED_VERSION: AtomicU64 = AtomicU64::new(0);
#[derive(Clone, Copy)]
struct ControlView {
    published_ns: u64,
    measurement_core: u64,
    irq: [Option<[u64; 4]>; IRQ_SLOTS],
    timer: Option<[u64; 4]>,
    soft_timers: usize,
    timer_policy: Option<(ApplyId, PolicyStamp, u16)>,
}
static CONTROL_VIEW: read_snapshot::ReadSnapshot<ControlView> = read_snapshot::ReadSnapshot::new();
fn owner_view() -> ControlView {
    owner();
    ControlView {
        published_ns: now_ns(),
        measurement_core: unsafe { *core::ptr::addr_of!(WINDOW_CORE) },
        irq: unsafe { *core::ptr::addr_of!(IRQ_MEASUREMENTS) },
        timer: unsafe { *core::ptr::addr_of!(TIMER_MEASUREMENTS) },
        soft_timers: unsafe { (&*core::ptr::addr_of!(TIMERS)).soft_observation().0 },
        timer_policy: unsafe { *core::ptr::addr_of!(TIMER_POLICY) },
    }
}
fn publish_view() {
    let _ = CONTROL_VIEW.publish(owner_view());
}
// Keep the IRQ measurement array in its protected snapshot. Timer candidate
// revalidation needs just one scalar or policy stamp, and must not copy all
// IRQ observations on every legality/current-parameter check.
#[inline(never)]
fn inspect_owner<R>(inspect: impl FnOnce(&ControlView) -> Result<R, Error>) -> Result<R, Error> {
    inspect(&owner_view())
}
fn inspect_view<R>(inspect: impl FnOnce(&ControlView) -> Result<R, Error>) -> Result<R, Error> {
    if cpu::slot() == 0 {
        return inspect_owner(inspect);
    }
    CONTROL_VIEW
        .inspect(|view| {
            let now = now_ns();
            if now < view.published_ns || now - view.published_ns > 50_000_000 {
                return Err(Error::NotReady);
            }
            inspect(view)
        })
        .map_err(|_| Error::Busy)?
        .ok_or(Error::NotReady)?
}
fn owner() {
    assert_eq!(cpu::slot(), 0);
}
fn slot(irq: u32) -> Result<usize, Error> {
    (0..COUNT.load(Ordering::Acquire))
        .find(|&i| IDS[i].load(Ordering::Relaxed) == u64::from(irq))
        .ok_or(Error::NotFound)
}
fn platform_error(_: cyxia_contracts::PlatformError) -> Error {
    Error::Io
}
fn increment(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        Some(v.saturating_add(1))
    });
}
pub fn now_ns() -> u64 {
    ((u128::from(timer::ticks()) * 1_000_000_000) / u128::from(timer::frequency()))
        .min(u128::from(u64::MAX)) as u64
}
fn ticks_from_ns(ns: u64) -> Result<u64, Error> {
    u64::try_from((u128::from(ns) * u128::from(timer::frequency())).div_ceil(1_000_000_000))
        .map_err(|_| Error::Overflow)
}
pub fn init(info: &BootInfo) -> Result<(), Error> {
    owner();
    if READY.load(Ordering::Acquire) {
        return Err(Error::Exists);
    }
    if info.virtio_count > info.virtio.len() {
        return Err(Error::Format);
    }
    let mut count = 0;
    for resource in &info.virtio[..info.virtio_count] {
        if resource.len < 0x200 || !(32..1020).contains(&resource.irq) {
            continue;
        }
        let base = resource
            .base
            .0
            .checked_add(crate::HIGH)
            .ok_or(Error::Overflow)?;
        let (magic, version, device) = unsafe {
            (
                core::ptr::read_volatile(base as *const u32),
                core::ptr::read_volatile((base + 4) as *const u32),
                core::ptr::read_volatile((base + 8) as *const u32),
            )
        };
        if magic != 0x7472_6976 || version != 2 || ![1, 2, 4].contains(&device) {
            continue;
        }
        if count == IRQ_SLOTS
            || (0..count).any(|i| IDS[i].load(Ordering::Relaxed) == u64::from(resource.irq))
        {
            return Err(Error::Capacity);
        }
        let router = IrqRouter::new(
            ObjectKey {
                id: resource.irq as u64,
                generation: 1,
            },
            resource.irq,
            IRQ_ALLOWED,
        )?;
        crate::smp::gic()
            .enable(resource.irq)
            .map_err(platform_error)?;
        crate::smp::gic()
            .mask(resource.irq)
            .map_err(platform_error)?;
        IDS[count].store(resource.irq as u64, Ordering::Relaxed);
        BASES[count].store(base, Ordering::Relaxed);
        DEVICES[count].store(device as u64, Ordering::Relaxed);
        unsafe {
            (*core::ptr::addr_of_mut!(ROUTERS))[count] = Some(router);
        }
        count += 1;
    }
    COUNT.store(count, Ordering::Release);
    unsafe {
        *core::ptr::addr_of_mut!(WINDOW_AT) = now_ns();
    }
    READY.store(true, Ordering::Release);
    publish_view();
    Ok(())
}
pub fn publish_context(core: u64, ledger: u64, business: u64, draining: u64) -> Result<(), Error> {
    owner();
    if core == 0 || ledger == 0 {
        return Err(Error::Format);
    }
    if CONTEXT_LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(Error::Busy);
    }
    let result = (|| {
        let old_core = CORE_GENERATION.load(Ordering::Relaxed);
        let old_ledger = LEDGER_GENERATION.load(Ordering::Relaxed);
        if core < old_core || ledger < old_ledger {
            return Err(Error::Stale);
        }
        let ownership_changed = HEALTHY_BUSINESS.load(Ordering::Relaxed) != business;
        // DRAIN can begin before ownership is republished. Its independent
        // mask is part of every commit guard and must be visible immediately.
        if ownership_changed && core == old_core && ledger == old_ledger {
            return Err(Error::Stale);
        }
        let sequence = CONTEXT_SEQUENCE.load(Ordering::Relaxed);
        let next = sequence.checked_add(2).ok_or(Error::Overflow)?;
        for i in 0..COUNT.load(Ordering::Acquire) {
            if IRQ_ALLOWED & business & !draining & (1 << TARGET[i].load(Ordering::Relaxed)) == 0 {
                crate::smp::gic()
                    .mask(IDS[i].load(Ordering::Relaxed) as u32)
                    .map_err(platform_error)?;
                MASKED[i].store(true, Ordering::Release);
                ROUTE_BLOCKED[i].store(true, Ordering::Release);
            }
        }
        CONTEXT_SEQUENCE.store(sequence + 1, Ordering::SeqCst);
        CORE_GENERATION.store(core, Ordering::Relaxed);
        LEDGER_GENERATION.store(ledger, Ordering::Relaxed);
        HEALTHY_BUSINESS.store(business, Ordering::Relaxed);
        DRAINING.store(draining, Ordering::Relaxed);
        CONTEXT_SEQUENCE.store(next, Ordering::Release);
        ipi::publish_generation(core)?;
        Ok(())
    })();
    CONTEXT_LOCK.store(false, Ordering::Release);
    result
}
fn topology(i: usize) -> Result<IrqTopology, Error> {
    for _ in 0..3 {
        let seq = CONTEXT_SEQUENCE.load(Ordering::Acquire);
        if seq & 1 != 0 {
            continue;
        }
        let value = IrqTopology {
            core_generation: CORE_GENERATION.load(Ordering::Relaxed),
            ledger_generation: LEDGER_GENERATION.load(Ordering::Relaxed),
            route_generation: ROUTE_GENERATION[i].load(Ordering::Acquire),
            healthy_business: HEALTHY_BUSINESS.load(Ordering::Relaxed),
            draining: DRAINING.load(Ordering::Relaxed),
        };
        core::sync::atomic::fence(Ordering::Acquire);
        if CONTEXT_SEQUENCE.load(Ordering::Relaxed) == seq {
            return Ok(value);
        }
    }
    Err(Error::Busy)
}
struct Hardware;
impl IrqHardware for Hardware {
    fn topology(&self, irq: u32) -> Result<IrqTopology, Error> {
        topology(slot(irq)?)
    }
    fn mask(&mut self, irq: u32) -> Result<(), Error> {
        let i = slot(irq)?;
        ROUTE_BLOCKED[i].store(true, Ordering::Release);
        crate::smp::gic().mask(irq).map_err(platform_error)?;
        MASKED[i].store(true, Ordering::Release);
        Ok(())
    }
    fn synchronized(&mut self, irq: u32) -> Result<bool, Error> {
        let i = slot(irq)?;
        Ok(INFLIGHT[i].load(Ordering::Acquire) == 0 && !crate::smp::gic().active(irq))
    }
    fn commit_route(&mut self, irq: u32, guard: IrqCommitGuard) -> Result<u64, Error> {
        let i = slot(irq)?;
        if CONTEXT_LOCK
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return Err(Error::Busy);
        }
        let result = (|| {
            let current = topology(i)?;
            if !LIVE[i].load(Ordering::Acquire) {
                return Err(Error::NotReady);
            }
            if current != guard.topology
                || guard.object
                    != (ObjectKey {
                        id: irq as u64,
                        generation: 1,
                    })
                || guard.allowed != IRQ_ALLOWED
                || guard.target_cpu >= 4
                || DESIRED[i].load(Ordering::Acquire) != guard.desired_version
                || IRQ_ALLOWED
                    & current.healthy_business
                    & !current.draining
                    & (1 << guard.target_cpu)
                    == 0
            {
                return Err(Error::Stale);
            }
            if INFLIGHT[i].load(Ordering::Acquire) != 0 || crate::smp::gic().active(irq) {
                return Err(Error::Busy);
            }
            let generation = current
                .route_generation
                .checked_add(1)
                .ok_or(Error::Overflow)?;
            crate::smp::gic()
                .route_masked_spi(irq, guard.target_cpu)
                .map_err(platform_error)?;
            TARGET[i].store(guard.target_cpu as u64, Ordering::Relaxed);
            ROUTE_GENERATION[i].store(generation, Ordering::Release);
            MASKED[i].store(false, Ordering::Release);
            ROUTE_BLOCKED[i].store(false, Ordering::Release);
            if let Err(error) = crate::smp::gic().unmask(irq) {
                MASKED[i].store(true, Ordering::Release);
                ROUTE_BLOCKED[i].store(true, Ordering::Release);
                return Err(platform_error(error));
            }
            Ok(generation)
        })();
        CONTEXT_LOCK.store(false, Ordering::Release);
        result
    }
}
pub fn registered_irq(index: usize) -> Option<(ObjectKey, u32, u64)> {
    if index >= COUNT.load(Ordering::Acquire) {
        return None;
    }
    Some((
        ObjectKey {
            id: IDS[index].load(Ordering::Relaxed),
            generation: 1,
        },
        DEVICES[index].load(Ordering::Relaxed) as u32,
        BASES[index].load(Ordering::Relaxed) - crate::HIGH,
    ))
}
pub fn enable_device_irq(irq: u32) -> Result<(), Error> {
    owner();
    LIVE[slot(irq)?].store(true, Ordering::Release);
    device_polled(irq).map(|_| ())
}
pub fn device_polled(irq: u32) -> Result<bool, Error> {
    owner();
    let i = slot(irq)?;
    if !LIVE[i].load(Ordering::Acquire)
        || ROUTE_BLOCKED[i].load(Ordering::Acquire)
        || INFLIGHT[i].load(Ordering::Acquire) != 0
        || crate::smp::gic().active(irq)
    {
        return Ok(false);
    }
    let current = topology(i)?;
    if IRQ_ALLOWED
        & current.healthy_business
        & !current.draining
        & (1 << TARGET[i].load(Ordering::Acquire))
        == 0
    {
        return Ok(false);
    }
    if unsafe { core::ptr::read_volatile((BASES[i].load(Ordering::Relaxed) + 0x60) as *const u32) }
        != 0
    {
        return Ok(false);
    }
    MASKED[i].store(false, Ordering::Release);
    if let Err(error) = crate::smp::gic().unmask(irq) {
        MASKED[i].store(true, Ordering::Release);
        return Err(platform_error(error));
    }
    Ok(true)
}
pub fn irq_enter(gic: &Gic, irq: u32, cpu: usize, started: u64) -> bool {
    let Ok(i) = slot(irq) else {
        return false;
    };
    INFLIGHT[i].fetch_add(1, Ordering::AcqRel);
    IRQ_STARTED[i].store(started, Ordering::Relaxed);
    irq_replay::entered(irq, cpu, started);
    let _ = gic.mask(irq);
    MASKED[i].store(true, Ordering::Release);
    LAST_CPU[i].store(cpu as u64, Ordering::Relaxed);
    increment(&HANDLED[i]);
    true
}
pub fn irq_complete(irq: u32) {
    if let Ok(i) = slot(irq) {
        let ticks = timer::ticks().saturating_sub(IRQ_STARTED[i].load(Ordering::Relaxed));
        let _ = HANDLER_TICKS[i].fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            Some(v.saturating_add(ticks))
        });
        HISTOGRAMS[i].record(ticks, timer::frequency());
        irq_replay::completed(irq, timer::ticks());
        INFLIGHT[i].fetch_sub(1, Ordering::Release);
    }
}
pub fn unknown_irq() {
    increment(&UNKNOWN);
}
pub fn irq_key(irq: u32) -> Option<ObjectKey> {
    slot(irq).ok().map(|_| ObjectKey {
        id: u64::from(irq),
        generation: 1,
    })
}
#[derive(Clone, Copy)]
pub struct IrqObservation {
    pub handled: u64,
    pub last_cpu: Option<u16>,
    pub handler_ticks: u64,
    pub target_cpu: u16,
    pub route_generation: u64,
    pub masked: bool,
}
pub fn irq_observation(irq: u32) -> Result<IrqObservation, Error> {
    let i = slot(irq)?;
    let cpu = LAST_CPU[i].load(Ordering::Acquire);
    Ok(IrqObservation {
        handled: HANDLED[i].load(Ordering::Acquire),
        last_cpu: (cpu != u64::MAX).then_some(cpu as u16),
        handler_ticks: HANDLER_TICKS[i].load(Ordering::Acquire),
        target_cpu: TARGET[i].load(Ordering::Acquire) as u16,
        route_generation: ROUTE_GENERATION[i].load(Ordering::Acquire),
        masked: MASKED[i].load(Ordering::Acquire),
    })
}
pub fn install_irq(
    apply: ApplyId,
    stamp: PolicyStamp,
    target: u16,
    now: u64,
) -> Result<IrqProgress, Error> {
    owner();
    let i = slot(u32::try_from(apply.target.id).map_err(|_| Error::Range)?)?;
    if !LIVE[i].load(Ordering::Acquire) {
        return Err(Error::NotReady);
    }
    let previous = DESIRED[i].swap(stamp.version, Ordering::AcqRel);
    let result = unsafe {
        (*core::ptr::addr_of_mut!(ROUTERS))[i]
            .as_mut()
            .unwrap()
            .request(apply, stamp, target, now, &mut Hardware)
    };
    if result.is_err() {
        DESIRED[i].store(previous, Ordering::Release);
    }
    if let Ok(progress) = result {
        unsafe {
            (*core::ptr::addr_of_mut!(ROUTE_RESULT))[i] = Some(progress);
        }
    }
    result
}
pub fn irq_result(irq: u32) -> Result<Option<IrqProgress>, Error> {
    owner();
    Ok(unsafe { (*core::ptr::addr_of!(ROUTE_RESULT))[slot(irq)?] })
}
fn timer_slot(key: ObjectKey) -> Result<usize, Error> {
    unsafe {
        (&*core::ptr::addr_of!(TIMER_KEYS))
            .iter()
            .position(|stored| *stored == Some(key))
    }
    .ok_or(Error::Stale)
}
fn refresh_deadline() {
    let next = ARMED_TICKS
        .iter()
        .map(|n| n.load(Ordering::Acquire))
        .min()
        .unwrap_or(u64::MAX);
    NEXT_TIMER.store(next, Ordering::Release);
    let (enabled, current): (u64, u64);
    unsafe {
        core::arch::asm!("mrs {}, cntp_ctl_el0", out(reg) enabled, options(nostack, preserves_flags));
        core::arch::asm!("mrs {}, cntp_cval_el0", out(reg) current, options(nostack, preserves_flags));
    }
    if enabled & 1 != 0 && next < current {
        unsafe {
            timer::arm(next);
        }
    }
}
struct TimerEvents;
impl TimerBackend for TimerEvents {
    fn arm(&mut self, arm: TimerArm) -> Result<(), Error> {
        ARMED_TICKS[timer_slot(arm.key)?]
            .store(ticks_from_ns(arm.programmed_ns)?, Ordering::Release);
        refresh_deadline();
        if arm.policy_version != 0 {
            TIMER_USED_VERSION.store(arm.policy_version, Ordering::Release);
        }
        Ok(())
    }
    fn cancel(&mut self, key: ObjectKey) -> Result<(), Error> {
        ARMED_TICKS[timer_slot(key)?].store(u64::MAX, Ordering::Release);
        refresh_deadline();
        Ok(())
    }
    fn fire(&mut self, key: ObjectKey) -> Result<(), Error> {
        let i = timer_slot(key)?;
        unsafe {
            let event = &mut (*core::ptr::addr_of_mut!(EVENTS))[i];
            if event.is_some() {
                return Err(Error::Busy);
            }
            *event = Some(key);
        }
        ARMED_TICKS[i].store(u64::MAX, Ordering::Release);
        refresh_deadline();
        Ok(())
    }
}
pub fn register_timer(
    key: ObjectKey,
    class: TimerClass,
    slack: u64,
    callback: TimerCallback,
) -> Result<(), Error> {
    owner();
    let i = unsafe {
        (&*core::ptr::addr_of!(TIMER_KEYS))
            .iter()
            .position(Option::is_none)
    }
    .ok_or(Error::Capacity)?;
    unsafe {
        (&mut *core::ptr::addr_of_mut!(TIMERS)).register(key, class, slack)?;
        (*core::ptr::addr_of_mut!(TIMER_KEYS))[i] = Some(key);
        (*core::ptr::addr_of_mut!(CALLBACKS))[i] = Some(callback);
    }
    publish_view();
    Ok(())
}
pub fn arm_timer(key: ObjectKey, deadline: u64, now: u64) -> Result<TimerArm, Error> {
    owner();
    unsafe { (&mut *core::ptr::addr_of_mut!(TIMERS)).arm(key, deadline, now, &mut TimerEvents) }
}
pub fn cancel_timer(key: ObjectKey) -> Result<(), Error> {
    owner();
    unsafe { (&mut *core::ptr::addr_of_mut!(TIMERS)).cancel(key, &mut TimerEvents) }
}
pub fn install_timer_policy(stamp: PolicyStamp, us: u16, now: u64) -> Result<(), Error> {
    owner();
    unsafe { (&mut *core::ptr::addr_of_mut!(TIMERS)).install(stamp, us, now) }
}
pub fn next_deadline_ticks(hard: u64) -> u64 {
    hard.min(NEXT_TIMER.load(Ordering::Acquire))
}
pub fn timer_observation() -> (usize, u64, u64) {
    owner();
    let t = unsafe { &*core::ptr::addr_of!(TIMERS) };
    (t.registered(), t.wakeups, t.late_ns)
}
pub fn poll(now: u64) -> Result<(), Error> {
    owner();
    if !READY.load(Ordering::Acquire) {
        return Err(Error::NotReady);
    }
    if POLLING.swap(true, Ordering::AcqRel) {
        return Err(Error::Busy);
    }
    let result = (|| {
        ipi::probe_turn(now);
        for i in 0..COUNT.load(Ordering::Acquire) {
            if !LIVE[i].load(Ordering::Acquire) {
                continue;
            }
            let key = ObjectKey {
                id: IDS[i].load(Ordering::Acquire),
                generation: 1,
            };
            crate::learning_evidence::measure(
                key,
                cyxia_prototype::learning::reward::CpuClass::ExecutorAction,
                || poll_route(i, now),
            )?;
        }
        crate::learning_evidence::measure(
            TIMER_SERVICE,
            cyxia_prototype::learning::reward::CpuClass::ExecutorWork,
            || unsafe {
                (&mut *core::ptr::addr_of_mut!(TIMERS)).poll(now, TIMER_SLOTS, &mut TimerEvents)
            },
        )?;
        for i in 0..TIMER_SLOTS {
            let event = unsafe { (*core::ptr::addr_of_mut!(EVENTS))[i].take() };
            if let Some(key) = event
                && let Some(callback) = unsafe { (*core::ptr::addr_of!(CALLBACKS))[i] }
            {
                callback(key, now);
            }
        }
        sample_observations(now);
        Ok(())
    })();
    publish_view();
    POLLING.store(false, Ordering::Release);
    result
}
fn poll_route(i: usize, now: u64) -> Result<(), Error> {
    let router = unsafe { (*core::ptr::addr_of_mut!(ROUTERS))[i].as_mut().unwrap() };
    let progress = router.poll(now, &mut Hardware);
    if let Ok(progress) = progress {
        unsafe {
            (*core::ptr::addr_of_mut!(ROUTE_RESULT))[i] = Some(progress);
        }
        if progress == IrqProgress::Pending {
            return Ok(());
        }
    }
    let current = topology(i)?;
    let legal = IRQ_ALLOWED & current.healthy_business & !current.draining;
    let needed = ROUTE_BLOCKED[i].load(Ordering::Acquire)
        || legal == 0
        || legal.trailing_zeros() as u64 != TARGET[i].load(Ordering::Acquire);
    if needed
        && (router.policy_expired(now) || matches!(progress, Ok(IrqProgress::Degraded(_))))
        && now >= unsafe { (*core::ptr::addr_of!(NEXT_RETRY))[i] }
    {
        let progress = router.force_baseline(now, &mut Hardware)?;
        unsafe {
            (*core::ptr::addr_of_mut!(ROUTE_RESULT))[i] = Some(progress);
            (*core::ptr::addr_of_mut!(NEXT_RETRY))[i] = now.saturating_add(IRQ_ROUTE_TIMEOUT_NS);
        }
    }
    Ok(())
}
fn sample_observations(now: u64) {
    let elapsed = now.saturating_sub(unsafe { *core::ptr::addr_of!(WINDOW_AT) });
    if elapsed < 1_000_000_000 {
        return;
    }
    let core = CORE_GENERATION.load(Ordering::Acquire);
    let stable = unsafe { *core::ptr::addr_of!(WINDOW_CORE) } == core;
    let mut total_ticks = 0u128;
    let mut complete = true;
    let mut windows = [None; IRQ_SLOTS];
    for i in 0..COUNT.load(Ordering::Acquire) {
        let sample = unsafe { &mut *core::ptr::addr_of_mut!(SAMPLE_WORKSPACE) };
        if !HISTOGRAMS[i].snapshot(sample) {
            unsafe {
                (*core::ptr::addr_of_mut!(PREVIOUS_VALID))[i] = false;
            }
            complete = false;
            continue;
        }
        let previous = unsafe { &mut (*core::ptr::addr_of_mut!(PREVIOUS_SAMPLES))[i] };
        let was_valid = unsafe { (*core::ptr::addr_of!(PREVIOUS_VALID))[i] };
        let delta = sample.since(previous);
        previous.copy_from(sample);
        unsafe {
            (*core::ptr::addr_of_mut!(PREVIOUS_VALID))[i] = true;
        }
        let Some(delta) = delta.filter(|_| was_valid) else {
            complete = false;
            continue;
        };
        total_ticks += u128::from(delta.ticks);
        if let Some(p99) = delta.p99_us {
            windows[i] = Some([
                (u128::from(delta.count) * 1_000_000_000 / u128::from(elapsed)) as u64,
                p99,
                0,
                1,
            ]);
        }
    }
    let business = HEALTHY_BUSINESS.load(Ordering::Acquire).count_ones();
    let occupancy = if business == 0 {
        0
    } else {
        (total_ticks * 1_000_000_000 * 1000
            / u128::from(timer::frequency())
            / u128::from(elapsed)
            / u128::from(business))
        .min(1000) as u64
    };
    for window in &mut windows {
        if !stable || !complete || business == 0 {
            *window = None;
        } else if let Some(fields) = window {
            fields[2] = occupancy;
        }
    }
    let (count, slack, wakeups, overruns) =
        unsafe { (&*core::ptr::addr_of!(TIMERS)).soft_observation() };
    let (last_wakeups, last_overruns) = unsafe { *core::ptr::addr_of!(PREVIOUS_TIMERS) };
    unsafe {
        *core::ptr::addr_of_mut!(IRQ_MEASUREMENTS) = windows;
        *core::ptr::addr_of_mut!(TIMER_MEASUREMENTS) = (count != 0).then_some([
            count as u64,
            (u128::from(wakeups.saturating_sub(last_wakeups)) * 1_000_000_000 / u128::from(elapsed))
                as u64,
            slack / 1000,
            overruns.saturating_sub(last_overruns),
        ]);
        *core::ptr::addr_of_mut!(PREVIOUS_TIMERS) = (wakeups, overruns);
        *core::ptr::addr_of_mut!(WINDOW_AT) = now;
        *core::ptr::addr_of_mut!(WINDOW_CORE) = core;
    }
}
fn control_target(domain: u16, _: u16, ordinal: usize) -> Option<ObjectKey> {
    if !READY.load(Ordering::Acquire) {
        return None;
    }
    if domain == 7 {
        return (ordinal == 0 && inspect_view(|view| Ok(view.soft_timers != 0)).ok()?)
            .then_some(TIMER_SERVICE);
    }
    (0..COUNT.load(Ordering::Acquire))
        .filter(|&i| LIVE[i].load(Ordering::Acquire))
        .nth(ordinal)
        .and_then(|i| registered_irq(i).map(|v| v.0))
}
pub(crate) fn queued_targets(
    queries: &[crate::domain_control::target_batch::Query],
    output: &mut [Option<ObjectKey>],
) -> Result<(), Error> {
    if !READY.load(Ordering::Acquire) {
        return Err(Error::NotReady);
    }
    let timers = if queries.iter().any(|q| q.domain == 7) {
        inspect_view(|view| Ok(view.soft_timers != 0))?
    } else {
        false
    };
    let mut irqs = [None; IRQ_SLOTS];
    let count = COUNT.load(Ordering::Acquire).min(IRQ_SLOTS);
    for (index, key) in irqs.iter_mut().enumerate().take(count) {
        if LIVE[index].load(Ordering::Acquire) {
            *key = Some(ObjectKey {
                id: IDS[index].load(Ordering::Relaxed),
                generation: 1,
            });
        }
    }
    crate::domain_control::target_batch::resolve(queries, output, |q| match (q.domain, q.kind) {
        (6, 1) => irqs.iter().flatten().nth(q.ordinal).copied(),
        (7, 1) if q.ordinal == 0 && timers => Some(TIMER_SERVICE),
        _ => None,
    })
}
fn control_observe(domain: u16, key: ObjectKey) -> Result<[u64; 4], Error> {
    if domain == 7 {
        if key != TIMER_SERVICE {
            return Err(Error::Stale);
        }
        return inspect_view(|view| {
            if view.measurement_core != CORE_GENERATION.load(Ordering::Acquire) {
                return Err(Error::NotReady);
            }
            view.timer.ok_or(Error::NotReady)
        });
    }
    if key.generation != 1 {
        return Err(Error::Stale);
    }
    let i = slot(u32::try_from(key.id).map_err(|_| Error::Range)?)?;
    inspect_view(|view| {
        if view.measurement_core != CORE_GENERATION.load(Ordering::Acquire) {
            return Err(Error::NotReady);
        }
        view.irq[i].ok_or(Error::NotReady)
    })
}
#[derive(Clone, Copy)]
pub(crate) struct TimerPreparation {
    current: Action,
    observation: DomainObservation,
}
impl TimerPreparation {
    pub(crate) const fn current(&self) -> Action {
        self.current
    }
    pub(crate) const fn observation(&self) -> DomainObservation {
        self.observation
    }
    pub(crate) fn legal_options(
        &self,
        options: &[Option<Action>],
        output: &mut [Option<Action>],
    ) -> Result<usize, Error> {
        let current = self.current;
        cyxia_prototype::policy::collect_legal_actions(options, output, |action| {
            action.validate()?;
            match (current, action) {
                (Action::SoftCoalesce(_), Action::SoftCoalesce(_)) => Ok(()),
                _ => Err(Error::Unsupported),
            }
        })
    }
    pub(crate) fn target_features(&self, action: Action) -> Result<TargetFeatures, Error> {
        action.validate()?;
        match (self.current, action) {
            (Action::SoftCoalesce(_), Action::SoftCoalesce(_)) => Ok(TargetFeatures::default()),
            _ => Err(Error::Unsupported),
        }
    }
}
/// Project D07's current action, observation and candidate-readiness from one
/// immutable platform owner view. The token authorizes only candidate
/// construction; CHECK and REVALIDATE still call the live family legality
/// path before PUBLISH can expose a policy root or executor state.
pub(crate) fn timer_preparation(key: ObjectKey, at: u64) -> Result<TimerPreparation, Error> {
    if key != TIMER_SERVICE {
        return Err(Error::Stale);
    }
    inspect_view(|view| {
        if view.soft_timers == 0 || view.measurement_core != CORE_GENERATION.load(Ordering::Acquire)
        {
            return Err(Error::NotReady);
        }
        let observation = DomainObservation::complete(view.timer.ok_or(Error::NotReady)?);
        let current = Action::SoftCoalesce(
            view.timer_policy
                .filter(|(_, stamp, _)| stamp.live(at))
                .map_or(0, |(_, _, value)| value),
        );
        Ok(TimerPreparation {
            current,
            observation,
        })
    })
}

fn control_current(domain: u16, _: u16, key: ObjectKey) -> Result<Action, Error> {
    if domain == 7 {
        if key != TIMER_SERVICE {
            return Err(Error::Stale);
        }
        return inspect_view(|view| {
            Ok(Action::SoftCoalesce(
                view.timer_policy
                    .filter(|(_, s, _)| s.live(now_ns()))
                    .map_or(0, |(_, _, v)| v),
            ))
        });
    }
    if key.generation != 1 {
        return Err(Error::Stale);
    }
    Ok(Action::IrqTarget(
        irq_observation(u32::try_from(key.id).map_err(|_| Error::Range)?)?.target_cpu,
    ))
}
fn control_legal(action: Action, key: ObjectKey, _: u64) -> Result<(), Error> {
    action.validate()?;
    match action {
        Action::SoftCoalesce(_)
            if key == TIMER_SERVICE && inspect_view(|view| Ok(view.soft_timers != 0))? =>
        {
            Ok(())
        }
        Action::IrqTarget(cpu) if key.generation == 1 => {
            let i = slot(u32::try_from(key.id).map_err(|_| Error::Range)?)?;
            let t = topology(i)?;
            if !LIVE[i].load(Ordering::Acquire) {
                return Err(Error::NotReady);
            }
            if IRQ_ALLOWED & t.healthy_business & !t.draining & (1 << cpu) == 0 {
                return Err(Error::Auth);
            }
            Ok(())
        }
        _ => Err(Error::Unsupported),
    }
}
fn legal_options(
    options: &[Option<Action>],
    key: ObjectKey,
    now: u64,
    output: &mut [Option<Action>],
) -> Result<usize, Error> {
    cyxia_prototype::policy::collect_legal_actions(options, output, |action| {
        control_legal(action, key, now)
    })
}
fn irq_execution(
    progress: IrqProgress,
    apply: ApplyId,
    target: u16,
) -> Result<ExecutionState, Error> {
    Ok(match progress {
        IrqProgress::Pending => ExecutionState::Pending,
        IrqProgress::Applied(r) if r.apply == Some(apply) && r.target_cpu == target => {
            ExecutionState::Applied
        }
        IrqProgress::Applied(_) => ExecutionState::Unknown,
        IrqProgress::Degraded(e) => ExecutionState::Failed(e),
    })
}
fn control_apply(
    action: Action,
    apply: ApplyId,
    stamp: PolicyStamp,
    now: u64,
) -> Result<ExecutionState, Error> {
    owner();
    control_legal(action, apply.target, now)?;
    match action {
        Action::IrqTarget(target) => {
            irq_execution(install_irq(apply, stamp, target, now)?, apply, target)
        }
        Action::SoftCoalesce(value) => {
            if let Some((old, s, v)) = unsafe { *core::ptr::addr_of!(TIMER_POLICY) }
                && old == apply
            {
                if (s, v) != (stamp, value) {
                    return Err(Error::Conflict);
                }
                return control_reconcile(action, apply, stamp, now);
            }
            install_timer_policy(stamp, value, now)?;
            unsafe {
                *core::ptr::addr_of_mut!(TIMER_POLICY) = Some((apply, stamp, value));
            }
            publish_view();
            Ok(ExecutionState::Pending)
        }
        _ => Err(Error::Unsupported),
    }
}
fn control_reconcile(
    action: Action,
    apply: ApplyId,
    stamp: PolicyStamp,
    now: u64,
) -> Result<ExecutionState, Error> {
    owner();
    match action {
        Action::IrqTarget(target) => {
            let i = slot(u32::try_from(apply.target.id).map_err(|_| Error::Range)?)?;
            let result = unsafe {
                (*core::ptr::addr_of!(ROUTERS))[i]
                    .as_ref()
                    .unwrap()
                    .query(apply, stamp, target)?
            };
            irq_execution(result, apply, target)
        }
        Action::SoftCoalesce(value) => {
            if unsafe { *core::ptr::addr_of!(TIMER_POLICY) } != Some((apply, stamp, value)) {
                return Err(Error::Stale);
            }
            if TIMER_USED_VERSION.load(Ordering::Acquire) == stamp.version {
                return Ok(ExecutionState::Applied);
            }
            Ok(if stamp.live(now) {
                ExecutionState::Pending
            } else {
                ExecutionState::Failed(Error::Expired)
            })
        }
        _ => Err(Error::Unsupported),
    }
}
pub fn register_control() -> Result<(), Error> {
    for domain in [6, 7] {
        crate::domain_control::register(crate::domain_control::Family {
            domain,
            kind: 1,
            target_source: crate::domain_control::TargetSource::Platform,
            target: control_target,
            observe: |domain, target| {
                control_observe(domain, target)
                    .map(cyxia_prototype::features::DomainObservation::complete)
            },
            current: control_current,
            legal: control_legal,
            legal_options,
            target_features: |action, key| {
                control_legal(action, key, now_ns())?;
                Ok(TargetFeatures::default())
            },
            apply: control_apply,
            reconcile: control_reconcile,
        })?;
    }
    Ok(())
}
