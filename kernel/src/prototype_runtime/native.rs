//! ABI3 native controller. One immutable job owns one isolated worker; physical
//! costs survive C/B changes and are settled before the stop acknowledgement.
use super::*;
use cyxia_prototype::domains::{ApplyId, Error as DomainError, PolicyStamp, WINDOW_NS};

const PREPAY_NS: u64 = 2_500_000;
const CONTROL_NS: u64 = 70_000_000;
const PHYSICAL_NS: u64 = 90_000_000;
const WALL_NS: u64 = 50_000_000;
static READY: AtomicBool = AtomicBool::new(false);
static TARGET: AtomicU64 = AtomicU64::new(1);
static JOB_CPU: AtomicU64 = AtomicU64::new(0);
static FAILED_CPUS: AtomicU64 = AtomicU64::new(0);
pub(super) fn ready() -> bool {
    READY.load(Ordering::Acquire)
}

pub(super) fn ns(ticks: u64) -> u64 {
    ((u128::from(ticks) * 1_000_000_000) / u128::from(timer::frequency())).min(u128::from(u64::MAX))
        as u64
}
fn ticks(ns: u64) -> u64 {
    ((u128::from(ns) * u128::from(timer::frequency())) / 1_000_000_000).min(u128::from(u64::MAX))
        as u64
}
#[derive(Clone, Copy)]
struct Bill {
    actual: u64,
    finished: u64,
}
pub(super) struct WorkerState {
    bill: Option<Bill>,
    probe: u8,
    probe_started: u64,
    probing: bool,
    in_job: bool,
    cpu_ns: u64,
    failed: bool,
}
impl WorkerState {
    pub(super) const fn new() -> Self {
        Self {
            bill: None,
            probe: 0,
            probe_started: 0,
            probing: false,
            in_job: false,
            cpu_ns: 0,
            failed: false,
        }
    }
    pub(super) fn discard(&mut self) {
        self.in_job = false;
        self.probing = false;
    }
}
/// `Busy` is unconsumed; `Budget` has already charged and isolated the CPU.
/// A failed/stale bill stays owned and cannot be hidden by closing a gate.
pub(super) fn settle(worker: &mut Worker) -> bool {
    let Some(bill) = worker.native.bill else {
        return true;
    };
    match crate::domain_tasks::record_control_cost(cpu::slot(), bill.actual, bill.finished) {
        Ok(()) => worker.native.bill = None,
        Err(DomainError::Budget) => {
            worker.native.bill = None;
            fail_worker(worker);
        }
        Err(DomainError::Busy | DomainError::NotReady) => return false,
        Err(_) => {
            fail_worker(worker);
            return false;
        }
    }
    true
}
fn fail_worker(worker: &mut Worker) {
    if !worker.native.failed {
        worker.native.failed = true;
        FAILED_CPUS.fetch_or(1 << cpu::slot(), Ordering::Release);
        CONTROL_OVERRUNS.fetch_add(1, Ordering::Relaxed);
    }
}
fn finish(worker: &mut Worker, valid: bool) {
    if let Some(context) = worker.context.as_ref() {
        RESULT_KIND.store(context.kind, Ordering::Relaxed);
        RESULT_ESR.store(context.esr, Ordering::Relaxed);
    }
    RESULT_PREEMPTIONS.store(worker.preemptions, Ordering::Relaxed);
    REQUEST_END.store(timer::ticks(), Ordering::Relaxed);
    JOB_CPU.store(worker.native.cpu_ns, Ordering::Relaxed);
    worker.context = None;
    worker.native.in_job = false;
    REQUEST.store(if valid { 3 } else { 4 }, Ordering::Release);
}
fn clear_private(slot: usize) {
    unsafe {
        let output = if slot == 1 {
            core::ptr::addr_of_mut!(OUTPUT)
        } else {
            core::ptr::addr_of_mut!(SECOND_OUTPUT)
        };
        (*output).0.fill(0);
        let stack = if slot == 1 {
            core::ptr::addr_of_mut!(STACK_PAGES)
        } else {
            core::ptr::addr_of_mut!(SECOND_STACK)
        };
        for n in 0..8 {
            (*stack.cast::<Page>().add(n)).0.fill(0);
        }
        core::arch::asm!("dsb ish", options(nostack));
    }
}
pub(super) fn step(worker: &mut Worker) {
    let slot = cpu::slot();
    if !matches!(slot, 1 | 2) || !READY.load(Ordering::Acquire) || !settle(worker) {
        return;
    }
    if worker.native.failed {
        if worker.native.in_job {
            finish(worker, false);
        }
        return;
    }
    let now = crate::domain_tasks::now_ns();
    // Process a captured return only after its actual CPU bill was accepted.
    if let Some(context) = worker.context.as_ref() {
        if context.kind != 0 {
            if worker.native.probing {
                if context.kind != 9 {
                    let (address, fsc) = [
                        (abi::INPUT_VA, 0x4f),
                        (abi::MODEL_VA, 0x4f),
                        (0xb0000, 0x47),
                        (0x30000, 0x07),
                    ][worker.native.probe as usize];
                    if context.kind != 8
                        || context.esr >> 26 != 0x24
                        || context.esr & 0x7f != fsc
                        || context.far != address
                    {
                        fail_worker(worker);
                        return;
                    }
                    PROTECTED.fetch_add(1, Ordering::Release);
                    worker.native.probe += 1;
                    worker.context = None;
                    worker.native.probing = false;
                    worker.probed = worker.native.probe == 4;
                } else if now.saturating_sub(worker.native.probe_started) >= WALL_NS {
                    fail_worker(worker);
                    return;
                }
            } else if worker.native.in_job {
                let expired =
                    now.saturating_sub(ns(REQUEST_START.load(Ordering::Relaxed))) >= WALL_NS;
                if context.kind != 9 || expired {
                    let valid = !expired
                        && context.kind == 8
                        && context.esr >> 26 == 0x15
                        && context.esr & 0xffff == abi::SUBMIT
                        && context.regs[0] == abi::OUTPUT_VA
                        && context.regs[1] == 4096;
                    finish(worker, valid);
                    return;
                }
            }
        }
    }
    if !worker.probed && worker.context.is_none() {
        clear_private(slot);
        worker.context = Some(fresh(u64::from(worker.native.probe) + 1));
        worker.native.probing = true;
        worker.native.probe_started = now;
    }
    if worker.probed && worker.context.is_none() {
        if TARGET.load(Ordering::Acquire) != slot as u64
            || REQUEST
                .compare_exchange(1, 2, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
        {
            return;
        }
        clear_private(slot);
        let sequence = unsafe {
            if slot == 1 {
                (*core::ptr::addr_of!(INPUT)).0[2]
            } else {
                (*core::ptr::addr_of!(SECOND_INPUT)).0[2]
            }
        };
        worker.context = Some(fresh(if FAULT_MODE == 1 && sequence == 5 {
            5
        } else {
            0
        }));
        worker.native.in_job = true;
        worker.native.cpu_ns = 0;
        worker.preemptions = 0;
    }
    if worker.native.in_job
        && now.saturating_sub(ns(REQUEST_START.load(Ordering::Relaxed))) >= WALL_NS
    {
        finish(worker, false);
        return;
    }
    let window = now / WINDOW_NS;
    if worker.window != window {
        worker.window = window;
        worker.charged = 0;
    }
    let end_window = match (window + 1).checked_mul(WINDOW_NS) {
        Some(v) => v,
        None => return,
    };
    if worker.charged.saturating_add(PREPAY_NS) > CONTROL_NS
        || now.saturating_add(PREPAY_NS) > end_window
    {
        return;
    }
    let Ok((spent, reserved)) = crate::domain_tasks::cpu_window_usage(slot, now) else {
        return;
    };
    if spent.saturating_add(reserved).saturating_add(PREPAY_NS) > PHYSICAL_NS {
        return;
    }
    let begin = timer::ticks();
    if ns(begin).saturating_add(PREPAY_NS) > end_window {
        return;
    }
    worker.charged += PREPAY_NS;
    CONTROL_MAX_DEBIT.fetch_max(worker.charged / 100_000, Ordering::Relaxed);
    CONTROL_TOTAL_DEBIT.fetch_add(PREPAY_NS / 100_000, Ordering::Relaxed);
    let context = worker.context.as_mut().unwrap();
    // Clear only the captured exception classification; all saved registers,
    // SIMD state and PC are preserved across timer returns.
    context.kind = 0;
    let root = unsafe { core::ptr::addr_of!(ROOTS).cast::<Page>().add(slot * 2 + 1) as u64 };
    unsafe {
        enter_service(
            context,
            phys(root),
            begin.saturating_add(ticks(250_000).max(1)),
        );
    }
    let end = timer::ticks();
    let actual = ns(end - begin);
    let finished = ns(end);
    worker.charged = worker
        .charged
        .saturating_sub(PREPAY_NS)
        .saturating_add(actual);
    CONTROL_TICKS.fetch_add(end - begin, Ordering::Relaxed);
    MAX_SLICE[slot].fetch_max(end - begin, Ordering::Relaxed);
    if worker.native.in_job {
        worker.native.cpu_ns = worker.native.cpu_ns.saturating_add(actual);
    }
    if context.kind == 9 {
        worker.preemptions = worker.preemptions.saturating_add(1);
    }
    worker.native.bill = Some(Bill { actual, finished });
    if actual > PREPAY_NS || finished > end_window || worker.charged > CONTROL_NS {
        fail_worker(worker);
    }
    let _ = settle(worker);
}

#[derive(Clone, Copy)]
struct CoreAction {
    apply: ApplyId,
    stamp: PolicyStamp,
    target: u64,
    started: bool,
    result: Option<Result<u64, DomainError>>,
}
pub(super) struct CoordinatorState {
    next_cpu: usize,
    core: Option<CoreAction>,
    context_at: u64,
    sample_at: u64,
    last_at: u64,
    control_capacity: u64,
    business_capacity: u64,
    control_ticks: u64,
    business_ns: u64,
    control_ratio: u64,
    business_ratio: u64,
}
impl CoordinatorState {
    pub(super) fn new(now: u64) -> Self {
        Self {
            next_cpu: 1,
            core: None,
            context_at: 0,
            sample_at: ns(now),
            last_at: ns(now),
            control_capacity: 0,
            business_capacity: 0,
            control_ticks: 0,
            business_ns: 0,
            control_ratio: 0,
            business_ratio: 0,
        }
    }
}
fn ratio(n: u64, d: u64) -> u64 {
    if d == 0 {
        if n == 0 { 0 } else { 1000 }
    } else {
        ((u128::from(n) * 1000) / u128::from(d)).min(u128::from(u64::MAX)) as u64
    }
}
fn publish(c: &mut Coordinator, now: u64) -> Result<(), DomainError> {
    put(61, 1);
    // Readiness is independent of an FS transaction borrowing its broker. A
    // D03 dependency separately validates the live partition under that gate.
    crate::domain_tasks::memory_backing()?;
    put(61, 2);
    let failed = FAILED_CPUS.load(Ordering::Acquire);
    for slot in 1..=2 {
        if failed & (1 << slot) != 0 && !c.owner.snapshot().suspect.contains(slot) {
            let _ = c.owner.suspect(slot);
        }
    }
    let s = c.owner.snapshot();
    let ledger_generation = s
        .ledger_generation
        .checked_add(crate::domain_tasks::resource_generation()?)
        .ok_or(DomainError::Overflow)?;
    put(61, 3);
    let healthy = s.online.bits()
        & !s.suspect.bits()
        & !s.quarantined.bits()
        & !FAILED_CPUS.load(Ordering::Acquire);
    let draining = s.draining.bits() | s.transition.bits();
    crate::domain_tasks::publish_layout(s.business.bits(), healthy, s.core_generation, draining)?;
    put(61, 4);
    crate::domain_platform::publish_context(
        s.core_generation,
        ledger_generation,
        s.business.bits() & healthy,
        draining,
    )?;
    put(61, 5);
    crate::domain_services::core_observe(
        s.control.bits(),
        s.business.bits(),
        healthy,
        draining,
        s.core_generation,
        ledger_generation,
        now,
    )?;
    put(61, 6);
    let metrics = crate::domain_tasks::common_metrics()?;
    let actual = crate::domain_tasks::business_cpu_ns()?;
    put(61, 7);
    let interval = now.saturating_sub(c.native.last_at);
    c.native.control_capacity = c
        .native
        .control_capacity
        .saturating_add(interval.saturating_mul(u64::from(
            (s.control.bits() & healthy & !draining).count_ones(),
        )));
    c.native.business_capacity =
        c.native
            .business_capacity
            .saturating_add(interval.saturating_mul(u64::from(
                (s.business.bits() & healthy & !draining).count_ones(),
            )));
    c.native.last_at = now;
    if now.saturating_sub(c.native.sample_at) >= WINDOW_NS {
        let control = CONTROL_TICKS.load(Ordering::Acquire);
        c.native.control_ratio = ratio(
            ns(control.saturating_sub(c.native.control_ticks)),
            c.native.control_capacity,
        );
        c.native.business_ratio = ratio(
            actual.saturating_sub(c.native.business_ns),
            c.native.business_capacity,
        );
        c.native.control_ticks = control;
        c.native.business_ns = actual;
        c.native.control_capacity = 0;
        c.native.business_capacity = 0;
        c.native.sample_at = now;
    }
    crate::domain_control::publish_context(crate::domain_control::Context {
        core_generation: s.core_generation,
        ledger_generation,
        control_mask: s.control.bits(),
        business_mask: s.business.bits(),
        healthy_mask: healthy,
        draining_mask: draining,
        common: [
            c.native.control_ratio,
            c.native.business_ratio,
            u64::from(REQUEST.load(Ordering::Acquire) != 0),
            metrics[0],
            metrics[1],
            metrics[2],
            0,
            u64::from(draining != 0),
        ],
    })?;
    c.native.context_at = now;
    put(61, 8);
    READY.store(true, Ordering::Release);
    Ok(())
}
fn core_turn(c: &mut Coordinator, tick: u64, now: u64) {
    if c.native.core.is_none() && REQUEST.load(Ordering::Acquire) == 0 && c.handoff.is_none() {
        if let Some((apply, stamp, target)) = crate::domain_services::core_request() {
            c.native.core = Some(CoreAction {
                apply,
                stamp,
                target,
                started: false,
                result: None,
            });
        }
    }
    let Some(mut action) = c.native.core else {
        return;
    };
    if action.result.is_none() && !action.started {
        let state = c.owner.snapshot();
        if action.target == state.control.bits()
            && state.suspect.is_empty()
            && state.draining.is_empty()
        {
            action.result = Some(Ok(action.target));
        } else if now.saturating_sub(action.stamp.snapshot_ns) >= 200_000_000 {
            action.result = Some(Err(DomainError::Expired));
        } else if ![2, 6].contains(&action.target) {
            action.result = Some(Err(DomainError::Range));
        } else {
            if action.target == 6 && crate::domain_tasks::can_control_move(2).is_err() {
                return;
            }
            if crate::domain_tasks::prepare_control_move(2).is_err() {
                return;
            }
            c.propose(action.target, tick);
            if c.handoff.is_some() {
                action.started = true;
            } else {
                // Re-open task admission only if the physical gate never closed.
                if GATES[2].view().enabled {
                    let _ = crate::domain_tasks::publish_layout(
                        state.business.bits(),
                        state.online.bits() & !state.suspect.bits() & !state.quarantined.bits(),
                        state.core_generation,
                        state.draining.bits(),
                    );
                }
                return;
            }
        }
    }
    if action.started && action.result.is_none() {
        c.poll_handoff(tick);
        if c.handoff.is_none() {
            let state = c.owner.snapshot();
            action.result = Some(
                if state.control.bits() == action.target
                    && state.suspect.is_empty()
                    && state.draining.is_empty()
                {
                    Ok(action.target)
                } else {
                    Err(DomainError::NotReady)
                },
            );
        }
    }
    c.native.core = Some(action);
    if let Some(result) = action.result {
        if publish(c, now).is_ok()
            && crate::domain_services::core_complete(action.apply, result, now).is_ok()
        {
            c.native.core = None;
        }
    }
}
fn evidence(c: &mut Coordinator, tick: u64) {
    if tick.saturating_sub(c.sample_at) < c.frequency / 100 {
        return;
    }
    let s = c.owner.snapshot();
    c.publication = c.publication.saturating_add(2);
    put(2, c.publication - 1);
    for (i, v) in [
        MAGIC,
        3,
        c.publication - 1,
        tick,
        c.frequency,
        c.window,
        s.control.bits(),
        s.business.bits(),
        s.transition.bits(),
        s.quarantined.bits(),
        s.core_generation,
        s.ledger_generation,
        c.service_generation,
        c.requests,
        c.successes,
        c.faults,
        c.preemptions,
        c.stale,
        OVERRUNS.load(Ordering::Acquire),
        progress()[0],
        progress()[1],
        TOTAL_TICKS[2].load(Ordering::Acquire),
        TOTAL_TICKS[3].load(Ordering::Acquire),
    ]
    .into_iter()
    .enumerate()
    {
        put(i, v);
    }
    put(28, PROTECTED.load(Ordering::Acquire));
    put(29, FAULT_MODE);
    put(30, c.origin);
    put(31, c.successes + c.faults + c.stale);
    put(32, c.boot.epoch);
    put(35, CONTROL_MAX_DEBIT.load(Ordering::Acquire));
    put(36, CONTROL_TICKS.load(Ordering::Acquire));
    put(37, CONTROL_TOTAL_DEBIT.load(Ordering::Acquire));
    put(38, CONTROL_OVERRUNS.load(Ordering::Acquire));
    put(39, MAX_SLICE[1].load(Ordering::Acquire));
    put(40, MAX_SLICE[2].load(Ordering::Acquire));
    put(41, MAX_SLICE[3].load(Ordering::Acquire));
    put(43, c.transitions);
    for (i, v) in [
        STOP_OPERATION.load(Ordering::Acquire),
        STOP_ACK.load(Ordering::Acquire),
        STOP_TASK_ACK.load(Ordering::Acquire),
        STOP_IRQ_ACK.load(Ordering::Acquire),
        STOP_TLB_ACK.load(Ordering::Acquire),
        STOP_REF_ACK.load(Ordering::Acquire),
        DMA_OWNERS.load(Ordering::Acquire),
        DEVICE_IRQ_OWNERS.load(Ordering::Acquire),
    ]
    .into_iter()
    .enumerate()
    {
        put(46 + i, v);
    }
    put(56, FAILED_CPUS.load(Ordering::Acquire));
    put(57, TARGET.load(Ordering::Acquire));
    put(58, JOB_CPU.load(Ordering::Acquire));
    put(59, c.native.control_ratio);
    put(60, c.native.business_ratio);
    RUNTIME_V13_EVIDENCE.0[2].store(c.publication, Ordering::Release);
    c.sample_at = tick;
}
pub(super) fn poll(c: &mut Coordinator) {
    check_failures();
    let tick = timer::ticks();
    let now = ns(tick);
    if c.wake_pulse.due(tick) {
        wake_workers();
    }
    let window = now / WINDOW_NS;
    if window > c.window {
        if c.owner.advance_window(window).is_ok() {
            c.window = window;
        }
    }
    core_turn(c, tick, now);
    let publication = publish(c, now);
    let published = publication.is_ok();
    put(62, publication.err().map_or(0, |e| e as u64 + 1));
    put(63, now);
    // Current ownership/ledger reaches the root before any new action APPLY.
    // Already-started reconciliation retains its obligation across changes.
    if published {
        let _ = crate::domain_control::poll(now);
    }
    match REQUEST.load(Ordering::Acquire) {
        state @ (3 | 4) => {
            let cpu_ns = JOB_CPU.load(Ordering::Relaxed);
            let result = if state == 3 {
                let output: [u64; 512] = core::array::from_fn(|i| unsafe {
                    let page = if TARGET.load(Ordering::Relaxed) == 1 {
                        core::ptr::addr_of!(OUTPUT)
                    } else {
                        core::ptr::addr_of!(SECOND_OUTPUT)
                    };
                    (*page).0.as_ptr().add(i).read_volatile()
                });
                crate::domain_control::accept(&output, cpu_ns)
            } else {
                crate::domain_control::abort(cpu_ns).map(|_| 0)
            };
            let consumed = match result {
                Err(DomainError::Busy) => {
                    crate::domain_control::pending_job().is_ok_and(|pending| !pending)
                }
                _ => true,
            };
            if consumed {
                c.preemptions = c
                    .preemptions
                    .saturating_add(RESULT_PREEMPTIONS.load(Ordering::Relaxed));
                match result {
                    Ok(version) if version != 0 => c.successes += 1,
                    _ if state == 4 => {
                        c.faults += 1;
                        c.service_generation = c.service_generation.saturating_add(1);
                    }
                    _ => c.stale += 1,
                }
                REQUEST.store(0, Ordering::Release);
            }
        }
        _ => {}
    }
    if published
        && REQUEST.load(Ordering::Acquire) == 0
        && c.handoff.is_none()
        && c.native.core.is_none()
    {
        let state = c.owner.snapshot();
        let available = state.control.bits()
            & !state.suspect.bits()
            & !state.draining.bits()
            & !FAILED_CPUS.load(Ordering::Acquire);
        let slot = if available & (1 << c.native.next_cpu) != 0 {
            c.native.next_cpu
        } else if available & 2 != 0 {
            1
        } else if available & 4 != 0 {
            2
        } else {
            0
        };
        if slot != 0 {
            if let Ok(Some(input)) = crate::domain_control::next(c.service_generation) {
                unsafe {
                    let page = if slot == 1 {
                        core::ptr::addr_of_mut!(INPUT)
                    } else {
                        core::ptr::addr_of_mut!(SECOND_INPUT)
                    };
                    (*page).0.copy_from_slice(&input);
                    core::arch::asm!("dsb ish", options(nostack));
                }
                c.requests = c.requests.saturating_add(1);
                c.request_at = timer::ticks();
                REQUEST_START.store(c.request_at, Ordering::Relaxed);
                JOB_CPU.store(0, Ordering::Relaxed);
                TARGET.store(slot as u64, Ordering::Relaxed);
                REQUEST.store(1, Ordering::Release);
                c.native.next_cpu = if slot == 1 { 2 } else { 1 };
                wake_workers();
            }
        }
    }
    evidence(c, tick);
}
