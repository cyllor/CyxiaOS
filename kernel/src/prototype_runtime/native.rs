//! ABI3 native controller. One immutable job owns one isolated worker; physical
//! costs survive C/B changes and are settled before the stop acknowledgement.
use super::*;
use cyxia_prototype::domains::{ApplyId, Error as DomainError, PolicyStamp, WINDOW_NS};

const PREPAY_NS: u64 = 2_500_000;
// The boot mapping self-test is recovery/setup work, not one model proposal.
// It keeps exact actual accounting but reserves the design's 8 ms recovery slice.
const PROBE_PREPAY_NS: u64 = 8_000_000;
const WALL_NS: u64 = 50_000_000;
// The mapping probe is a boot self-test that spans separately prepaid turns;
// it is not a proposal whose single-turn wall deadline may be extended.
const PROBE_WALL_NS: u64 = 1_000_000_000;
const PRIVATE_CLEAR_PAGES: usize = 9;
const PRIVATE_CLEAR_BYTES: usize = PRIVATE_CLEAR_PAGES * 4096;
const PRIVATE_CLEAR_SLICE_NS: u64 = 500_000;
const FALLBACK_ZERO_BLOCK_BYTES: usize = 64;
const SERVICE_SLICE_NS: u64 = 100_000;
const RETURN_ENVELOPE_NS: u64 = 2_000_000;
static READY: AtomicBool = AtomicBool::new(false);
static TARGET: AtomicU64 = AtomicU64::new(1);
static JOB_CPU: AtomicU64 = AtomicU64::new(0);
static FAILED_CPUS: AtomicU64 = AtomicU64::new(0);
static CONTROLLER_EPOCH: AtomicU64 = AtomicU64::new(1);
static OWNER_CONTEXT: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
// The exact target accompanies the real stop operation, published before its
// CPU2 notification. It is not a duration or a fabricated stop receipt.
static STOP_MEASURE: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
pub(super) fn learning_context() -> Result<(u64, u64), DomainError> {
    let first = OWNER_CONTEXT[0].load(Ordering::Acquire);
    if first == 0 || first & 1 != 0 {
        return Err(DomainError::NotReady);
    }
    let core = OWNER_CONTEXT[1].load(Ordering::Acquire);
    let task = OWNER_CONTEXT[2].load(Ordering::Acquire);
    let ledger = OWNER_CONTEXT[3].load(Ordering::Acquire);
    let actual = crate::domain_tasks::control_owner_context(1)?;
    if first != OWNER_CONTEXT[0].load(Ordering::Acquire) || actual != (core, task) {
        return Err(DomainError::NotReady);
    }
    Ok((core, ledger))
}

static STARTED_JOBS: AtomicU64 = AtomicU64::new(0);
static RESULT_VERSION: AtomicU64 = AtomicU64::new(0);
#[repr(C, align(64))]
struct ControlCreditEvidence([AtomicU64; 64]);
#[used]
#[unsafe(no_mangle)]
static CONTROL_CREDIT_EVIDENCE: ControlCreditEvidence =
    ControlCreditEvidence([const { AtomicU64::new(0) }; 64]);
pub(super) fn ready() -> bool {
    READY.load(Ordering::Acquire)
}

pub(super) fn capture_owner(slot: usize) -> cyxia_prototype::domains::ObjectKey {
    cyxia_prototype::domains::ObjectKey {
        id: 0x4354_524c_0000 + slot as u64,
        generation: CONTROLLER_EPOCH.load(Ordering::Acquire),
    }
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
    credit: cyxia_prototype::domains::tasks::ControlCredit,
    body_started: u64,
    actual: u64,
    finished: u64,
    phase: u64,
    phase_mask: u64,
}
#[derive(Clone, Copy)]
enum Completion {
    Empty,
    Reply(u64),
    ReadOnly,
    Fault,
}
pub(super) struct WorkerState {
    bill: Option<Bill>,
    completion: Option<Completion>,
    returned: Option<Completion>,
    model: Option<crate::domain_control::NativeModelPin>,
    model_mapped: bool,
    source: Option<crate::domain_control::JobSource>,
    measurement: Option<crate::domain_control::core_replay::Measurement>,
    probe: u8,
    probe_started: u64,
    clear_next: u32,
    probing: bool,
    in_job: bool,
    publish_pending: bool,
    abort_pending: bool,
    job_started: u64,
    cpu_ns: u64,
    failed: bool,
    phase: u64,
    phase_mask: u64,
}
impl WorkerState {
    pub(super) const fn new() -> Self {
        Self {
            bill: None,
            completion: None,
            returned: None,
            model: None,
            model_mapped: false,
            source: None,
            measurement: None,
            probe: 0,
            probe_started: 0,
            clear_next: 0,
            probing: false,
            in_job: false,
            publish_pending: false,
            abort_pending: false,
            job_started: 0,
            cpu_ns: 0,
            failed: false,
            phase: 0,
            phase_mask: 0,
        }
    }
    pub(super) fn discard(&mut self) {
        // The stop path proves there is no bill or root-owned job first.
        self.clear_next = 0;
        self.probing = false;
    }
    fn phase(&mut self, phase: u64) {
        self.phase = phase;
        self.phase_mask |= 1u64 << phase;
    }
}
fn credit_failure(worker: &Worker, bill: Bill, error: DomainError) {
    let slot = usize::from(bill.credit.cpu);
    if !matches!(slot, 1 | 2) {
        return;
    }
    let base = if slot == 1 { 2 } else { 24 };
    let words = &CONTROL_CREDIT_EVIDENCE.0;
    if words[base]
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return;
    }
    let c = bill.credit;
    let control = c
        .control_total_ns
        .saturating_sub(c.reserved_ns)
        .saturating_add(bill.actual);
    let physical = c
        .physical_total_ns
        .saturating_sub(c.reserved_ns)
        .saturating_add(bill.actual);
    let end = c.window.saturating_add(1).saturating_mul(WINDOW_NS);
    let flags = u64::from(bill.actual > c.reserved_ns)
        | (u64::from(bill.finished > end) << 1)
        | (u64::from(control > 70_000_000) << 2)
        | (u64::from(physical > 90_000_000) << 3);
    for (i, value) in [
        slot as u64,
        c.sequence,
        c.core_generation,
        c.window,
        c.started_ns,
        bill.body_started,
        bill.finished,
        c.reserved_ns,
        bill.actual,
        c.control_total_ns,
        control,
        c.physical_total_ns,
        physical,
        bill.phase,
        bill.phase_mask,
        worker.native.cpu_ns,
        worker.native.job_started,
        REQUEST.load(Ordering::Acquire),
        worker.preemptions,
        flags,
        error as u64 + 1,
    ]
    .into_iter()
    .enumerate()
    {
        words[base + 1 + i].store(value, Ordering::Relaxed);
    }
    words[base].store(2, Ordering::Release);
    words[1].store(1, Ordering::Relaxed);
    words[0].store(0x4359_4343_5245_4401, Ordering::Release);
}
/// Busy has not consumed the exact physical reservation. Budget has consumed
/// the bill, retained its actual cost and quarantined this physical CPU.
pub(super) fn settle(worker: &mut Worker) -> bool {
    let Some(bill) = worker.native.bill else {
        return true;
    };
    match crate::domain_tasks::complete_control(bill.credit, bill.actual, bill.finished) {
        Ok(()) => worker.native.bill = None,
        Err(DomainError::Budget) => {
            credit_failure(worker, bill, DomainError::Budget);
            worker.native.bill = None;
            fail_worker(worker);
        }
        Err(DomainError::Busy | DomainError::NotReady) => return false,
        Err(error) => {
            credit_failure(worker, bill, error);
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
fn conclude(worker: &mut Worker, completion: Completion) {
    if let Some(context) = worker.context.as_ref() {
        RESULT_KIND.store(context.kind, Ordering::Relaxed);
        RESULT_ESR.store(context.esr, Ordering::Relaxed);
    }
    worker.context = None;
    if worker.native.model_mapped {
        model_mapping(cpu::slot(), None);
        worker.native.model_mapped = false;
    }
    worker.native.in_job = false;
    worker.native.clear_next = 0;
    worker.native.returned = None;
    worker.native.publish_pending = false;
    worker.native.abort_pending = false;
    worker.native.completion = Some(completion);
}
fn publish_completion(worker: &mut Worker) {
    if worker.native.bill.is_some()
        || worker.native.model.is_some()
        || worker.native.model_mapped
        || worker.native.measurement.is_some()
    {
        return;
    }
    let Some(completion) = worker.native.completion else {
        return;
    };
    if let Some(work) = worker.native.source.and_then(|source| source.work) {
        if crate::domain_control::core_replay::retired(work).is_err() {
            return;
        }
    }
    worker.native.completion = None;
    worker.native.source = None;
    let (state, version) = match completion {
        Completion::Empty => (5, 0),
        Completion::Reply(version) => (3, version),
        Completion::ReadOnly => (6, 0),
        Completion::Fault => (4, 0),
    };
    RESULT_VERSION.store(version, Ordering::Relaxed);
    RESULT_PREEMPTIONS.store(worker.preemptions, Ordering::Relaxed);
    REQUEST_END.store(timer::ticks(), Ordering::Relaxed);
    JOB_CPU.store(worker.native.cpu_ns, Ordering::Relaxed);
    // No consumer or ownership handoff observes completion before settlement.
    REQUEST.store(state, Ordering::Release);
}
fn model_mapping(slot: usize, physical: Option<u64>) {
    // This leaf's sole C owner has stopped its EL0 context. Revocation reaches
    // the local TLB before the immutable bank pin can be released.
    unsafe {
        let leaf = &mut *core::ptr::addr_of_mut!(LEAVES)
            .cast::<Page>()
            .add(slot * 2 + 1);
        leaf.0[abi::MODEL_VA as usize / 4096] = physical.map_or(0, |address| {
            mmu::encode_user_leaf(PhysAddr(address), false, false).expect("pinned model page")
        });
        core::arch::asm!(
            "dsb ishst",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            options(nostack)
        );
    }
}
fn release_model(worker: &mut Worker) -> bool {
    if worker.context.is_some() || worker.native.in_job || worker.native.model_mapped {
        return false;
    }
    let Some(pin) = worker.native.model.as_ref() else {
        return true;
    };
    match crate::domain_control::release_job_model(pin) {
        Ok(()) => {
            worker.native.model = None;
            true
        }
        Err(DomainError::Busy | DomainError::Again | DomainError::NotReady) => false,
        Err(_) => {
            fail_worker(worker);
            false
        }
    }
}
fn private_zero_block_bytes() -> Option<usize> {
    let dczid: u64;
    unsafe {
        core::arch::asm!(
            "mrs {dczid}, dczid_el0",
            dczid = out(reg) dczid,
            options(nomem, nostack, preserves_flags)
        );
    }
    if dczid & (1 << 4) != 0 {
        return None;
    }
    let bytes = 4usize.checked_shl((dczid & 0xf) as u32)?;
    (bytes != 0 && bytes <= 4096 && bytes.is_power_of_two() && 4096usize.is_multiple_of(bytes))
        .then_some(bytes)
}
fn clear_private_block(slot: usize, offset: usize, block_bytes: usize, use_zero_block: bool) {
    debug_assert!(offset < PRIVATE_CLEAR_BYTES);
    debug_assert!(block_bytes != 0 && block_bytes <= 4096);
    let page = offset / 4096;
    let within = offset % 4096;
    debug_assert!(page < PRIVATE_CLEAR_PAGES);
    debug_assert!(within + block_bytes <= 4096);
    unsafe {
        let page = if page == 0 {
            output_ptr(slot)
        } else {
            stack_ptr(slot).cast::<Page>().add(page - 1)
        };
        let address = page.cast::<u8>().add(within);
        if use_zero_block && (address as usize).is_multiple_of(block_bytes) {
            core::arch::asm!("dc zva, {address}", address = in(reg) address, options(nostack));
        } else {
            core::ptr::write_bytes(address, 0, block_bytes);
        }
    }
}
fn continue_private_clear(worker: &mut Worker, slot: usize) -> bool {
    let next = worker.native.clear_next;
    if next == 0 {
        return true;
    }
    worker
        .native
        .phase(if worker.native.probing { 1 } else { 4 });
    let started = timer::ticks();
    let slice_ticks = ticks(PRIVATE_CLEAR_SLICE_NS).max(1);
    let zero_block_bytes = private_zero_block_bytes();
    let block_bytes = zero_block_bytes.unwrap_or(FALLBACK_ZERO_BLOCK_BYTES);
    let mut offset = usize::try_from(next - 1).unwrap_or(PRIVATE_CLEAR_BYTES);
    while offset < PRIVATE_CLEAR_BYTES {
        let within = offset % 4096;
        let bytes = block_bytes
            .min(4096 - within)
            .min(PRIVATE_CLEAR_BYTES - offset);
        clear_private_block(slot, offset, bytes, zero_block_bytes == Some(bytes));
        offset += bytes;
        if timer::ticks().saturating_sub(started) >= slice_ticks {
            break;
        }
    }
    unsafe {
        core::arch::asm!("dsb ish", options(nostack));
    }
    if worker.native.in_job {
        worker.native.cpu_ns = worker
            .native
            .cpu_ns
            .saturating_add(ns(timer::ticks() - started));
    }
    worker.native.clear_next = if offset == PRIVATE_CLEAR_BYTES {
        0
    } else {
        u32::try_from(offset + 1).unwrap_or(0)
    };
    // Never combine the just-cleared range with EL0 entry. The following paid
    // turn receives the full envelope for mapping/preparation and its slice.
    false
}
fn finish_root_return(
    worker: &mut Worker,
    witness: &crate::domain_control::core_replay::PaidWorkWitness,
) {
    let Some(completion) = worker.native.returned else {
        return;
    };
    if let Some(work) = worker.native.source.and_then(|source| source.work) {
        // Successful warm work is acknowledged only while this actual credit
        // remains live; a busy owner keeps the stopped job and exact token.
        if crate::domain_control::core_replay::report_completed(work, witness).is_err() {
            return;
        }
    }
    conclude(worker, completion);
}
fn root_return(
    worker: &mut Worker,
    slot: usize,
    witness: &crate::domain_control::core_replay::PaidWorkWitness,
) {
    if worker.native.returned.is_some() {
        finish_root_return(worker, witness);
        return;
    }
    if worker.native.abort_pending {
        worker.native.phase(7);
        if crate::domain_control::abort(worker.native.cpu_ns).is_ok() {
            worker.native.returned = Some(Completion::Fault);
            finish_root_return(worker, witness);
        }
        return;
    }
    worker.native.phase(6);
    // This CPU's EL0 context is stopped. The other C worker has a disjoint
    // private output page, and CPU0 never writes either page after startup.
    let output: &[u64; 512] = unsafe {
        let page = if slot == 1 {
            output_ptr(1)
        } else {
            output_ptr(2)
        };
        &(*page).0
    };
    let result = crate::domain_control::accept(output, worker.native.cpu_ns);
    if let Err(error) = result {
        match crate::domain_control::pending_job() {
            Ok(false) => {}
            Ok(true) => {
                if error != DomainError::Busy {
                    worker.native.publish_pending = false;
                    worker.native.abort_pending = true;
                }
                return;
            }
            Err(_) => return,
        }
    }
    // An accepted root version remains a success even if cost settlement
    // later detects an overrun. Read-only work never claims a policy version.
    worker.native.returned = Some(
        if worker.native.source.is_some_and(|source| {
            source.class == cyxia_prototype::learning::reward::CpuClass::ExecutorWork
        }) {
            Completion::ReadOnly
        } else {
            Completion::Reply(result.unwrap_or(0))
        },
    );
    finish_root_return(worker, witness);
}
/// Candidate encoding has sizeable bounded scratch. Its lifetime must not
/// become the permanent frame of the sibling learning/validation dispatch.
#[inline(never)]
fn next_input(
    controller: u64,
    witness: &crate::domain_control::core_replay::PaidWorkWitness,
    started: u64,
    input: &mut [u64; 512],
) -> Result<Option<crate::domain_control::JobSource>, DomainError> {
    crate::domain_control::next_paid(controller, witness, started, input)
}
#[inline(never)]
fn run_turn(
    worker: &mut Worker,
    credit: cyxia_prototype::domains::tasks::ControlCredit,
    begin: u64,
    witness: &crate::domain_control::core_replay::PaidWorkWitness,
) {
    let slot = cpu::slot();
    let now = ns(timer::ticks());
    if worker.native.completion.is_some() && !worker.native.in_job {
        // step() settled the preceding context bill. This separate prepaid
        // owner piece releases only the already revoked immutable bank pin.
        worker.native.phase(8);
        let _ = release_model(worker);
        return;
    }
    if worker.native.in_job
        && !worker.native.publish_pending
        && worker.native.returned.is_none()
        && now.saturating_sub(worker.native.job_started) >= WALL_NS
    {
        worker.native.abort_pending = true;
    }
    if worker.native.in_job && (worker.native.publish_pending || worker.native.abort_pending) {
        root_return(worker, slot, witness);
        return;
    }
    if let Some(context) = worker.context.as_ref() {
        if context.kind != 0 {
            if worker.native.probing {
                worker.native.phase(8);
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
                    // The final probe completion is its own prepaid recovery turn.
                    // A fresh 2.5 ms model turn must acquire and encode the first job.
                    return;
                } else if now.saturating_sub(worker.native.probe_started) >= PROBE_WALL_NS {
                    fail_worker(worker);
                    return;
                } else {
                    // Retire this timer return in its own paid turn. Re-entering
                    // EL0 below would charge two context-switch envelopes to one
                    // 2.5 ms evaluation credit.
                    worker.context.as_mut().expect("probe context").kind = 0;
                    return;
                }
            } else if worker.native.in_job {
                if context.kind == 9 {
                    // The previous slice has already preserved all registers.
                    // A later paid turn may arm the next slice, but this turn
                    // performs only the deterministic return bookkeeping.
                    worker.context.as_mut().expect("job context").kind = 0;
                    return;
                }
                worker.native.publish_pending = context.kind == 8
                    && context.esr >> 26 == 0x15
                    && context.esr & 0xffff == abi::SUBMIT
                    && context.regs[0] == abi::OUTPUT_VA
                    && context.regs[1] == 4096;
                worker.native.abort_pending = !worker.native.publish_pending;
                root_return(worker, slot, witness);
                return;
            }
        }
    }
    if !worker.probed && worker.context.is_none() && !worker.native.probing {
        worker.native.phase(1);
        worker.native.clear_next = 1;
        worker.native.probing = true;
        worker.native.probe_started = now;
        // Do not combine the ownership/state transition with the first private
        // memory touch. The next independently prepaid turn performs the clear.
        return;
    }
    if worker.native.probing
        && worker.context.is_none()
        && now.saturating_sub(worker.native.probe_started) >= PROBE_WALL_NS
    {
        fail_worker(worker);
        return;
    }
    if worker.probed && worker.context.is_none() && !worker.native.in_job {
        if TARGET.load(Ordering::Acquire) != slot as u64
            || REQUEST
                .compare_exchange(1, 2, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
        {
            return;
        }
        worker.preemptions = 0;
        worker.native.cpu_ns = 0;
        REQUEST_START.store(timer::ticks(), Ordering::Relaxed);
        worker.native.phase(3);
        // Charge initialization too; no large value-return scratch is retained
        // while either preparation sibling constructs its candidate set.
        let preparation_started = ns(timer::ticks());
        let mut input = [0; 512];
        let source = match next_input(
            CONTROLLER_EPOCH.load(Ordering::Acquire),
            witness,
            preparation_started,
            &mut input,
        ) {
            Ok(Some(source)) => source,
            _ => {
                conclude(worker, Completion::Empty);
                return;
            }
        };
        worker.native.source = Some(source);
        worker.native.in_job = true;
        worker.native.job_started = input[4];
        STARTED_JOBS.fetch_add(1, Ordering::Release);
        // Encoding above opened its own exact source before constructing the
        // immutable job. Subsequent private copy, inference and cleanup share
        // this protected job source across all real paid turns.
        worker.native.measurement =
            crate::domain_control::core_replay::Measurement::new(source, witness).ok();
        if worker.native.measurement.is_none() {
            worker.native.abort_pending = true;
            return;
        }
        worker.native.phase(4);
        let copy_start = timer::ticks();
        unsafe {
            let page = if slot == 1 {
                input_ptr(1)
            } else {
                input_ptr(2)
            };
            (*page).0.copy_from_slice(&input);
            core::arch::asm!("dsb ish", options(nostack));
        }
        worker.native.clear_next = 1;
        worker.native.cpu_ns = worker
            .native
            .cpu_ns
            .saturating_add(ns(timer::ticks() - copy_start));
        return;
    }
    if !continue_private_clear(worker, slot) {
        return;
    }
    if worker.native.probing && worker.context.is_none() {
        worker.context = Some(fresh(u64::from(worker.native.probe) + 1));
    }
    if worker.native.in_job && worker.context.is_none() && !worker.native.abort_pending {
        let preparation = timer::ticks();
        let input = unsafe { &(*input_ptr(slot)).0 };
        if worker.native.model.is_none() {
            let result = crate::domain_control::pin_job_model(input[2], input[3]);
            if result.is_err() {
                // A retry is real protected preparation CPU, even when no
                // model capability has been acquired yet. Keep it in the
                // same encode/infer/decode bill as the eventual success.
                worker.native.cpu_ns = worker
                    .native
                    .cpu_ns
                    .saturating_add(ns(timer::ticks() - preparation));
            }
            match result {
                Ok(pin) => worker.native.model = Some(pin),
                Err(DomainError::Busy | DomainError::Again | DomainError::NotReady) => return,
                Err(_) => {
                    worker.native.abort_pending = true;
                    return;
                }
            }
        }
        let pin = worker.native.model.as_ref().expect("owned job model");
        model_mapping(slot, Some(pin.physical_address()));
        worker.native.model_mapped = true;
        worker.context = Some(fresh(if FAULT_MODE == 1 && input[2] == 5 {
            5
        } else {
            0
        }));
        worker.native.cpu_ns = worker
            .native
            .cpu_ns
            .saturating_add(ns(timer::ticks() - preparation));
    }
    // Account encoding and private-page preparation before choosing a slice.
    // A turn with less than the full return envelope yields without entering EL0.
    let entered = timer::ticks();
    if ns(entered.saturating_sub(begin)).saturating_add(RETURN_ENVELOPE_NS) > credit.reserved_ns {
        return;
    }
    let Some(context) = worker.context.as_mut() else {
        return;
    };
    context.kind = 0;
    worker
        .native
        .phase(if worker.native.probing { 2 } else { 5 });
    let root = unsafe { core::ptr::addr_of!(ROOTS).cast::<Page>().add(slot * 2 + 1) as u64 };
    unsafe {
        enter_service(
            context,
            phys(root),
            entered.saturating_add(ticks(SERVICE_SLICE_NS).max(1)),
            crate::a02_capture::Task {
                id: capture_owner(slot).id,
                generation: capture_owner(slot).generation,
                role: 2,
                affinity: 1 << slot,
            },
        );
    }
    let end = timer::ticks();
    let actual = ns(end - entered);
    MAX_SLICE[slot].fetch_max(end - entered, Ordering::Relaxed);
    if worker.native.in_job {
        worker.native.cpu_ns = worker.native.cpu_ns.saturating_add(actual);
    }
    if context.kind == 9 {
        worker.preemptions = worker.preemptions.saturating_add(1);
    }
}
fn charge_turn(
    worker: &mut Worker,
    credit: cyxia_prototype::domains::tasks::ControlCredit,
    begin: u64,
) {
    finish_measurement(worker);
    let end = timer::ticks();
    let actual = ns(end - begin);
    worker.window = credit.window;
    worker.charged = credit
        .control_total_ns
        .saturating_sub(credit.reserved_ns)
        .saturating_add(actual);
    CONTROL_TICKS.fetch_add(end - begin, Ordering::Relaxed);
    learning::mandatory(&mut worker.extra, credit.started_ns, actual);
    worker.native.bill = Some(Bill {
        credit,
        body_started: ns(begin),
        actual,
        finished: ns(end),
        phase: worker.native.phase,
        phase_mask: worker.native.phase_mask,
    });
    let _ = settle(worker);
    publish_completion(worker);
}
fn finish_measurement(worker: &mut Worker) -> bool {
    if let Some(measurement) = worker.native.measurement.as_mut() {
        if measurement.finish() == Err(DomainError::Busy) {
            return false;
        }
        worker.native.measurement = None;
    }
    true
}
fn begin_measurement(
    worker: &mut Worker,
    witness: &crate::domain_control::core_replay::PaidWorkWitness,
) -> bool {
    if let Some(source) = worker.native.source {
        match crate::domain_control::core_replay::Measurement::new(source, witness) {
            Ok(measurement) => worker.native.measurement = Some(measurement),
            Err(_) => return false,
        }
    }
    true
}
pub(super) fn step(worker: &mut Worker) {
    let slot = cpu::slot();
    if !matches!(slot, 1 | 2)
        || !READY.load(Ordering::Acquire)
        || !finish_measurement(worker)
        || !settle(worker)
        || !learning::settle(&mut worker.extra)
    {
        return;
    }
    publish_completion(worker);
    if worker.native.failed {
        return;
    }
    if worker.probed
        && worker.context.is_none()
        && !worker.native.in_job
        && worker.native.completion.is_none()
        && worker.native.model.is_none()
        && (REQUEST.load(Ordering::Acquire) != 1 || TARGET.load(Ordering::Acquire) != slot as u64)
    {
        learning::step(&mut worker.extra);
        return;
    }
    let reservation_ns = if worker.probed && !worker.native.probing {
        PREPAY_NS
    } else {
        PROBE_PREPAY_NS
    };
    if !learning::allow_mandatory(&worker.extra, reservation_ns, ns(timer::ticks())) {
        return;
    }
    let Ok(Some(credit)) = crate::domain_tasks::begin_control(reservation_ns, false) else {
        return;
    };
    let begin = timer::ticks();
    worker.native.phase = 0;
    worker.native.phase_mask = 0;
    CONTROL_MAX_DEBIT.fetch_max(credit.control_total_ns / 100_000, Ordering::Relaxed);
    CONTROL_TOTAL_DEBIT.fetch_add(credit.reserved_ns / 100_000, Ordering::Relaxed);
    if let Ok(witness) = crate::domain_control::core_replay::PaidWorkWitness::new(credit) {
        if begin_measurement(worker, &witness) {
            run_turn(worker, credit, begin, &witness);
        }
    }
    // A failed witness lookup still returns its real physical reservation.
    charge_turn(worker, credit, begin);
}
/// A closed gate never substitutes for settlement or cancellation of the
/// original root job. Only its actual C owner can issue this abort.
pub(super) fn stop_ready(worker: &mut Worker) -> bool {
    if !finish_measurement(worker) || !settle(worker) || !learning::quiescent(&mut worker.extra) {
        return false;
    }
    publish_completion(worker);
    if worker.native.in_job {
        let Ok(Some(credit)) = crate::domain_tasks::begin_control(PREPAY_NS, true) else {
            return false;
        };
        let begin = timer::ticks();
        worker.native.phase = 0;
        worker.native.phase_mask = 0;
        if let Ok(witness) = crate::domain_control::core_replay::PaidWorkWitness::new(credit) {
            if begin_measurement(worker, &witness) {
                worker.native.abort_pending = true;
                root_return(worker, cpu::slot(), &witness);
            }
        }
        charge_turn(worker, credit, begin);
        if worker.native.in_job
            || worker.native.bill.is_some()
            || worker.native.measurement.is_some()
        {
            return false;
        }
    }
    if worker.native.model.is_some() {
        let Ok(Some(credit)) = crate::domain_tasks::begin_control(PREPAY_NS, true) else {
            return false;
        };
        let begin = timer::ticks();
        worker.native.phase(8);
        if let Ok(witness) = crate::domain_control::core_replay::PaidWorkWitness::new(credit) {
            if begin_measurement(worker, &witness) {
                let _ = release_model(worker);
            }
        }
        charge_turn(worker, credit, begin);
    }
    publish_completion(worker);
    worker.native.model.is_none()
        && worker.native.bill.is_none()
        && worker.native.measurement.is_none()
        && worker.native.completion.is_none()
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
pub(super) fn publish_stop_measure(operation: u64, state: &CoordinatorState) {
    STOP_MEASURE[0].store(0, Ordering::Release);
    if let Some(action) = state.core {
        STOP_MEASURE[1].store(action.apply.target.id, Ordering::Relaxed);
        STOP_MEASURE[2].store(action.apply.target.generation, Ordering::Relaxed);
        STOP_MEASURE[0].store(operation, Ordering::Release);
    }
}
pub(super) fn measure_stop_tail<R>(operation: u64, body: impl FnOnce() -> R) -> R {
    let first = STOP_MEASURE[0].load(Ordering::Acquire);
    let owner = cyxia_prototype::domains::ObjectKey {
        id: STOP_MEASURE[1].load(Ordering::Relaxed),
        generation: STOP_MEASURE[2].load(Ordering::Relaxed),
    };
    // A missing/mixed tag remains missing evidence during a real replay; it
    // cannot silently borrow a different operation's owner registration.
    let owner =
        if first == operation && first != 0 && STOP_MEASURE[0].load(Ordering::Acquire) == first {
            owner
        } else {
            cyxia_prototype::domains::ObjectKey {
                id: 0,
                generation: 0,
            }
        };
    crate::learning_evidence::measure(
        owner,
        cyxia_prototype::learning::reward::CpuClass::ExecutorAction,
        body,
    )
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
    crate::a02_capture::publish(
        s.core_generation,
        [
            s.control.bits(),
            s.business.bits(),
            s.transition.bits(),
            s.quarantined.bits(),
            s.draining.bits(),
            s.suspect.bits(),
        ],
    );
    let task_generation = crate::domain_tasks::resource_generation()?;
    let ledger_generation = s
        .ledger_generation
        .checked_add(task_generation)
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
    let sequence = OWNER_CONTEXT[0]
        .load(Ordering::Relaxed)
        .checked_add(2)
        .ok_or(DomainError::Overflow)?;
    OWNER_CONTEXT[0].store(sequence - 1, Ordering::Release);
    OWNER_CONTEXT[1].store(s.core_generation, Ordering::Relaxed);
    OWNER_CONTEXT[2].store(task_generation, Ordering::Relaxed);
    OWNER_CONTEXT[3].store(ledger_generation, Ordering::Relaxed);
    OWNER_CONTEXT[0].store(sequence, Ordering::Release);
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
    let Some(action) = c.native.core else {
        return;
    };
    crate::learning_evidence::measure(
        action.apply.target,
        cyxia_prototype::learning::reward::CpuClass::ExecutorAction,
        || core_action_turn(c, tick, now, action),
    );
}
fn core_action_turn(c: &mut Coordinator, tick: u64, now: u64, mut action: CoreAction) {
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
    c.requests = STARTED_JOBS.load(Ordering::Acquire);
    match REQUEST.load(Ordering::Acquire) {
        state @ (3 | 4 | 5 | 6) => {
            c.preemptions = c
                .preemptions
                .saturating_add(RESULT_PREEMPTIONS.load(Ordering::Relaxed));
            match state {
                3 if RESULT_VERSION.load(Ordering::Relaxed) != 0 => c.successes += 1,
                3 => c.stale += 1,
                4 => {
                    c.faults += 1;
                    c.service_generation = c.service_generation.saturating_add(1);
                }
                _ => {}
            }
            REQUEST.store(0, Ordering::Release);
            // Expose an actual idle boundary to core_turn on the next poll.
            // Reissuing an empty opportunity here would starve an accepted
            // CoreSet forever even though every old job had completed.
            evidence(c, tick);
            return;
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
            // Only an opportunity is published here. The actual C owner must
            // prepay its full turn before creating/encoding a protected job.
            c.request_at = timer::ticks();
            CONTROLLER_EPOCH.store(c.service_generation, Ordering::Relaxed);
            TARGET.store(slot as u64, Ordering::Relaxed);
            REQUEST.store(1, Ordering::Release);
            c.native.next_cpu = if slot == 1 { 2 } else { 1 };
            wake_workers();
        }
    }
    evidence(c, tick);
}
