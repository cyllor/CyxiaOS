//! Immutable image identity and bounded address-space installation for the
//! independent EL0 learning-governance coordinator.
//!
//! The boot self-test enters that image on the actual CPU1 C owner, verifies
//! mapping faults and timer preemption, then revalidates a canonical `Wait`
//! command in EL1. It grants no publication authority and shares the existing
//! mandatory 61 ms / total 70 ms control budget rather than allocating another
//! surplus.
use super::*;
use crate::control_pool::{self as pool, Allocation, Lease};
use core::cell::UnsafeCell;
use cyxia_prototype::{
    domains::{Error, ObjectKey, tasks::ControlCredit},
    learning::{
        coordinator_wire::{
            COMMAND_BYTES, Command, CommandAction, CoordinatorSnapshot, LastCommandStatus,
            SNAPSHOT_BYTES,
        },
        governance::Stage,
        worker_wire::JobBinding,
    },
};
use sha2::{Digest, Sha256};
#[path = "governance/outcome.rs"]
mod outcome;

const CODE_BASE: u64 = 0x80000;
const CODE_LIMIT: u64 = 0x100000;
const CODE_PAGES: usize = ((CODE_LIMIT - CODE_BASE) / 4096) as usize;
const INPUT_BASE: u64 = 0x100000;
const OUTPUT_BASE: u64 = 0x101000;
const STACK_BASE: u64 = 0x102000;
const STACK_PAGES: usize = 4;
const STACK_TOP: u64 = STACK_BASE + STACK_PAGES as u64 * 4096;
const TABLE_PAGES: usize = 3;
const OWNER: ObjectKey = ObjectKey {
    id: 0x474f_5645_524e_0001,
    generation: 1,
};
const ROLE_CONTEXT: ObjectKey = ObjectKey {
    id: 0x474f_5643_4f4f_0001,
    generation: 1,
};
const MAGIC: u64 = 0x4359_474f_5645_5201;

#[used]
#[unsafe(no_mangle)]
static GOVERNANCE_SERVICE_ELF: [u8; include_bytes!(concat!(
    env!("OUT_DIR"),
    "/prototype-governance.elf"
))
.len()] = *include_bytes!(concat!(env!("OUT_DIR"), "/prototype-governance.elf"));

#[repr(C, align(64))]
pub struct Evidence([AtomicU64; 16]);
#[used]
#[unsafe(no_mangle)]
pub static GOVERNANCE_V13_EVIDENCE: Evidence = Evidence([const { AtomicU64::new(0) }; 16]);

#[derive(Clone, Copy)]
struct ImagePlan {
    entry: u64,
    segments: [cyxia_kernel_core::control_plane::image::Segment; 8],
    count: usize,
    pages: usize,
}

struct Resources {
    code: Allocation,
    input: Allocation,
    output: Allocation,
    stack: Allocation,
    tables: Allocation,
    _code_pin: Lease,
    _table_pin: Lease,
    plan: ImagePlan,
    root: u64,
    image_hash: [u8; 32],
}
struct ResourceCell(UnsafeCell<Option<Resources>>);
unsafe impl Sync for ResourceCell {}
static RESOURCES: ResourceCell = ResourceCell(UnsafeCell::new(None));
static CLAIMED: AtomicBool = AtomicBool::new(false);
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// This identity is necessary but not sufficient authority. A future dispatch
/// ticket must additionally bind the actual C owner, credit and trap context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registration {
    pub role_context: ObjectKey,
    pub image_hash: [u8; 32],
    pub entry: u64,
    pub root: u64,
    pub input: ObjectKey,
    pub output: ObjectKey,
    pub stack: ObjectKey,
    pub stack_top: u64,
}

fn u16_at(bytes: &[u8], at: usize) -> Result<u16, Error> {
    Ok(u16::from_le_bytes(
        bytes
            .get(at..at.checked_add(2).ok_or(Error::Range)?)
            .ok_or(Error::Format)?
            .try_into()
            .map_err(|_| Error::Format)?,
    ))
}
fn u32_at(bytes: &[u8], at: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(
        bytes
            .get(at..at.checked_add(4).ok_or(Error::Range)?)
            .ok_or(Error::Format)?
            .try_into()
            .map_err(|_| Error::Format)?,
    ))
}
fn u64_at(bytes: &[u8], at: usize) -> Result<u64, Error> {
    Ok(u64::from_le_bytes(
        bytes
            .get(at..at.checked_add(8).ok_or(Error::Range)?)
            .ok_or(Error::Format)?
            .try_into()
            .map_err(|_| Error::Format)?,
    ))
}

fn parse_image(bytes: &[u8]) -> Result<ImagePlan, Error> {
    if bytes.len() > CODE_PAGES * 4096
        || bytes.get(..7) != Some(b"\x7fELF\x02\x01\x01")
        || u16_at(bytes, 16)? != 2
        || u16_at(bytes, 18)? != 183
        || u32_at(bytes, 20)? != 1
        || u16_at(bytes, 52)? != 64
        || u16_at(bytes, 54)? != 56
    {
        return Err(Error::Format);
    }
    let entry = u64_at(bytes, 24)?;
    let headers = usize::try_from(u64_at(bytes, 32)?).map_err(|_| Error::Range)?;
    let headers_count = usize::from(u16_at(bytes, 56)?);
    if headers_count == 0 || headers_count > 8 {
        return Err(Error::Format);
    }
    let mut plan = ImagePlan {
        entry,
        segments: [cyxia_kernel_core::control_plane::image::Segment::default(); 8],
        count: 0,
        pages: 0,
    };
    let mut seen = 0u128;
    let mut entry_found = false;
    for index in 0..headers_count {
        let at = headers
            .checked_add(index.checked_mul(56).ok_or(Error::Range)?)
            .ok_or(Error::Range)?;
        bytes
            .get(at..at.checked_add(56).ok_or(Error::Range)?)
            .ok_or(Error::Format)?;
        match u32_at(bytes, at)? {
            0 | 4 | 6 | 0x6474_e551 => continue,
            1 => {}
            _ => return Err(Error::Auth),
        }
        let flags = u32_at(bytes, at + 4)?;
        let offset = usize::try_from(u64_at(bytes, at + 8)?).map_err(|_| Error::Range)?;
        let address = u64_at(bytes, at + 16)?;
        let file_size = usize::try_from(u64_at(bytes, at + 32)?).map_err(|_| Error::Range)?;
        let memory_size = usize::try_from(u64_at(bytes, at + 40)?).map_err(|_| Error::Range)?;
        let end = address
            .checked_add(memory_size as u64)
            .ok_or(Error::Range)?;
        if !matches!(flags, 4 | 5)
            || memory_size == 0
            || file_size > memory_size
            || address < CODE_BASE
            || end > CODE_LIMIT
            || !address.is_multiple_of(4096)
            || !offset.is_multiple_of(4096)
            || u64_at(bytes, at + 48)? != 4096
            || bytes
                .get(offset..offset.checked_add(file_size).ok_or(Error::Range)?)
                .is_none()
        {
            return Err(Error::Format);
        }
        let first = usize::try_from((address - CODE_BASE) / 4096).map_err(|_| Error::Range)?;
        let last = usize::try_from((end - CODE_BASE).div_ceil(4096)).map_err(|_| Error::Range)?;
        for page in first..last {
            let bit = 1u128.checked_shl(page as u32).ok_or(Error::Range)?;
            if seen & bit != 0 {
                return Err(Error::Conflict);
            }
            seen |= bit;
        }
        entry_found |= flags == 5
            && entry >= address
            && entry < address + file_size as u64
            && entry.is_multiple_of(4);
        plan.segments[plan.count] = cyxia_kernel_core::control_plane::image::Segment {
            offset,
            address,
            file_size,
            memory_size,
            executable: flags == 5,
        };
        plan.count += 1;
        plan.pages = plan.pages.max(last);
    }
    if !entry_found || plan.count == 0 || plan.pages == 0 || plan.pages > CODE_PAGES {
        return Err(Error::Format);
    }
    Ok(plan)
}

fn copy_image(plan: ImagePlan, code: Allocation) -> Result<Lease, Error> {
    for page in 0..plan.pages {
        pool::zero_chunk(code, page * 4096, 4096)?;
        let page_start = CODE_BASE as usize + page * 4096;
        for segment in &plan.segments[..plan.count] {
            let start = page_start.max(segment.address as usize);
            let end = (page_start + 4096).min(segment.address as usize + segment.file_size);
            if start < end {
                let source = segment.offset + start - segment.address as usize;
                pool::write(
                    code,
                    start - CODE_BASE as usize,
                    &GOVERNANCE_SERVICE_ELF[source..source + end - start],
                )?;
            }
        }
    }
    let (base, _, _) = pool::span(code)?;
    unsafe {
        for offset in (0..plan.pages * 4096).step_by(64) {
            core::arch::asm!("dc cvau, {}", in(reg) base + offset, options(nostack));
        }
        core::arch::asm!("dsb ish", "ic iallu", "dsb ish", "isb", options(nostack));
    }
    pool::seal(code)?;
    pool::pin_readonly(code)
}

fn build_tables(
    plan: ImagePlan,
    code: Allocation,
    input: Allocation,
    output: Allocation,
    stack: Allocation,
    tables: Allocation,
) -> Result<(u64, Lease), Error> {
    for page in 0..TABLE_PAGES {
        pool::zero_chunk(tables, page * 4096, 4096)?;
    }
    let (table_va, table_pa, _) = pool::span(tables)?;
    let (_, code_pa, _) = pool::span(code)?;
    let (_, input_pa, _) = pool::span(input)?;
    let (_, output_pa, _) = pool::span(output)?;
    let (_, stack_pa, _) = pool::span(stack)?;
    unsafe {
        let root = table_va as *mut Page;
        let middle = root.add(1);
        let leaf = root.add(2);
        (*root).0[0] = (table_pa + 4096) | 3;
        (*middle).0[0] = (table_pa + 8192) | 3;
        for segment in &plan.segments[..plan.count] {
            let first =
                usize::try_from((segment.address - CODE_BASE) / 4096).map_err(|_| Error::Range)?;
            let last = (first * 4096 + segment.memory_size).div_ceil(4096);
            for page in first..last {
                (*leaf).0[CODE_BASE as usize / 4096 + page] = mmu::encode_user_leaf(
                    PhysAddr(code_pa + page as u64 * 4096),
                    false,
                    segment.executable,
                )
                .map_err(|_| Error::Range)?;
            }
        }
        (*leaf).0[INPUT_BASE as usize / 4096] =
            mmu::encode_user_leaf(PhysAddr(input_pa), false, false).map_err(|_| Error::Range)?;
        (*leaf).0[OUTPUT_BASE as usize / 4096] =
            mmu::encode_user_leaf(PhysAddr(output_pa), true, false).map_err(|_| Error::Range)?;
        for page in 0..STACK_PAGES {
            (*leaf).0[STACK_BASE as usize / 4096 + page] =
                mmu::encode_user_leaf(PhysAddr(stack_pa + page as u64 * 4096), true, false)
                    .map_err(|_| Error::Range)?;
        }
        core::arch::asm!("dsb ishst", "isb", options(nostack));
    }
    pool::seal(tables)?;
    let pin = pool::pin_readonly(tables)?;
    Ok((table_pa, pin))
}

fn publish_evidence(resources: &Resources) {
    let values = [
        MAGIC,
        1,
        resources.plan.entry,
        resources.root,
        resources.plan.pages as u64,
        1,
        1,
        STACK_PAGES as u64,
        TABLE_PAGES as u64,
        ROLE_CONTEXT.id,
        ROLE_CONTEXT.generation,
    ];
    for (index, value) in values.into_iter().enumerate() {
        GOVERNANCE_V13_EVIDENCE.0[index].store(value, Ordering::Relaxed);
    }
    for (index, word) in resources.image_hash.chunks_exact(8).enumerate() {
        GOVERNANCE_V13_EVIDENCE.0[11 + index].store(
            u64::from_le_bytes(word.try_into().unwrap()),
            Ordering::Relaxed,
        );
    }
    GOVERNANCE_V13_EVIDENCE.0[15].store(1, Ordering::Release);
}

pub(super) fn init() -> Result<(), Error> {
    if cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    CLAIMED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| Error::Exists)?;
    let plan = parse_image(&GOVERNANCE_SERVICE_ELF)?;
    let code = pool::allocate(OWNER, plan.pages)?;
    let input = pool::allocate(OWNER, 1)?;
    let output = pool::allocate(OWNER, 1)?;
    let stack = pool::allocate(OWNER, STACK_PAGES)?;
    let tables = pool::allocate(OWNER, TABLE_PAGES)?;
    pool::zero_chunk(input, 0, 4096)?;
    pool::zero_chunk(output, 0, 4096)?;
    for page in 0..STACK_PAGES {
        pool::zero_chunk(stack, page * 4096, 4096)?;
    }
    let code_pin = copy_image(plan, code)?;
    let (root, table_pin) = build_tables(plan, code, input, output, stack, tables)?;
    let image_hash: [u8; 32] = Sha256::digest(&GOVERNANCE_SERVICE_ELF).into();
    let resources = Resources {
        code,
        input,
        output,
        stack,
        tables,
        _code_pin: code_pin,
        _table_pin: table_pin,
        plan,
        root,
        image_hash,
    };
    unsafe {
        *RESOURCES.0.get() = Some(resources);
    }
    let resources = unsafe { (&*RESOURCES.0.get()).as_ref().ok_or(Error::NotReady)? };
    publish_evidence(resources);
    INITIALIZED.store(true, Ordering::Release);
    Ok(())
}

pub fn registration() -> Result<Registration, Error> {
    if !INITIALIZED.load(Ordering::Acquire) {
        return Err(Error::NotReady);
    }
    let resources = unsafe { (&*RESOURCES.0.get()).as_ref().ok_or(Error::NotReady)? };
    Ok(Registration {
        role_context: ROLE_CONTEXT,
        image_hash: resources.image_hash,
        entry: resources.plan.entry,
        root: resources.root,
        input: resources.input.key(),
        output: resources.output.key(),
        stack: resources.stack.key(),
        stack_top: STACK_TOP,
    })
}

// The mapping identity above is only a prerequisite. This state machine proves
// that the separately linked image can actually enter EL0 on the current C
// owner, fault on its protected mappings, return through the timer, and submit
// a canonical command which EL1 revalidates against the real owner/credit
// context. It deliberately authorizes no policy mutation.
const RUNTIME_MAGIC: u64 = 0x4359_4752_554e_0001;
const RUNTIME_VERSION: u64 = 1;
const RUNTIME_PREPAY_NS: u64 = 2_500_000;
const COMMAND_DEADLINE_NS: u64 = 50_000_000;
const PHASE_INPUT_PROBE: u64 = 1;
const PHASE_CODE_PROBE: u64 = 2;
const PHASE_UNMAPPED_PROBE: u64 = 3;
const PHASE_TIMER_PROBE: u64 = 4;
const PHASE_PREPARE: u64 = 5;
const PHASE_RUN: u64 = 6;
const PHASE_VALIDATE: u64 = 7;
const PHASE_COMPLETE: u64 = 8;
const SESSION: ObjectKey = ObjectKey {
    id: 0x474f_5653_4553_0001,
    generation: 1,
};
const SELFTEST_JOB: u64 = 0x474f_5652_554e_0001;

#[repr(C, align(64))]
pub struct RuntimeEvidence([AtomicU64; 64]);
#[used]
#[unsafe(no_mangle)]
pub static GOVERNANCE_RUNTIME_V13_EVIDENCE: RuntimeEvidence =
    RuntimeEvidence([const { AtomicU64::new(0) }; 64]);

#[derive(Clone, Copy)]
struct RuntimeBill {
    credit: ControlCredit,
    actual_ns: u64,
    finished_ns: u64,
}

struct Runtime {
    phase: u64,
    context: Option<user::Context>,
    pins: [Option<Lease>; 3],
    snapshot: Option<CoordinatorSnapshot>,
    command: Option<Command>,
    bill: Option<RuntimeBill>,
    turns: u64,
    probe_turns: u64,
    command_turns: u64,
    total_actual_ns: u64,
    max_actual_ns: u64,
    preemptions: u64,
    core_generation: u64,
    ledger_generation: u64,
    last_credit_sequence: u64,
    last_credit_core: u64,
    last_exit_kind: u64,
    last_exit_esr: u64,
    svc_x0: u64,
    svc_x1: u64,
    command_kind: u64,
    command_sequence: u64,
    snapshot_revision: u64,
    validation_ns: u64,
    probe_esr: [u64; 3],
    probe_far: [u64; 3],
    spin_kind: u64,
    command_digest: [u8; 32],
    snapshot_digest: [u8; 32],
    snapshot_now_ns: u64,
    snapshot_deadline_ns: u64,
    validated_core_generation: u64,
    validated_ledger_generation: u64,
    last_bill: [u64; 8],
    failed: u64,
    completed: bool,
}
impl Runtime {
    const fn new() -> Self {
        Self {
            phase: PHASE_INPUT_PROBE,
            context: None,
            pins: [const { None }; 3],
            snapshot: None,
            command: None,
            bill: None,
            turns: 0,
            probe_turns: 0,
            command_turns: 0,
            total_actual_ns: 0,
            max_actual_ns: 0,
            preemptions: 0,
            core_generation: 0,
            ledger_generation: 0,
            last_credit_sequence: 0,
            last_credit_core: 0,
            last_exit_kind: 0,
            last_exit_esr: 0,
            svc_x0: 0,
            svc_x1: 0,
            command_kind: 0,
            command_sequence: 0,
            snapshot_revision: 0,
            validation_ns: 0,
            probe_esr: [0; 3],
            probe_far: [0; 3],
            spin_kind: 0,
            command_digest: [0; 32],
            snapshot_digest: [0; 32],
            snapshot_now_ns: 0,
            snapshot_deadline_ns: 0,
            validated_core_generation: 0,
            validated_ledger_generation: 0,
            last_bill: [0; 8],
            failed: 0,
            completed: false,
        }
    }
}
struct RuntimeCell(UnsafeCell<Runtime>);
unsafe impl Sync for RuntimeCell {}
static RUNTIME: RuntimeCell = RuntimeCell(UnsafeCell::new(Runtime::new()));

fn runtime_ns(ticks: u64) -> u64 {
    ((u128::from(ticks) * 1_000_000_000) / u128::from(timer::frequency())).min(u128::from(u64::MAX))
        as u64
}
fn runtime_ticks(ns: u64) -> u64 {
    ((u128::from(ns) * u128::from(timer::frequency())) / 1_000_000_000).min(u128::from(u64::MAX))
        as u64
}
fn runtime_resources() -> Result<&'static Resources, Error> {
    if !INITIALIZED.load(Ordering::Acquire) {
        return Err(Error::NotReady);
    }
    unsafe { (&*RESOURCES.0.get()).as_ref().ok_or(Error::NotReady) }
}
fn runtime_state() -> &'static mut Runtime {
    debug_assert_eq!(cpu::slot(), 1);
    unsafe { &mut *RUNTIME.0.get() }
}
fn hash_label(label: &[u8], image_hash: [u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(label);
    hash.update(image_hash);
    hash.update(ROLE_CONTEXT.id.to_le_bytes());
    hash.update(ROLE_CONTEXT.generation.to_le_bytes());
    hash.finalize().into()
}
fn hash_words(hash: [u8; 32]) -> [u64; 4] {
    let mut out = [0; 4];
    for (destination, word) in out.iter_mut().zip(hash.chunks_exact(8)) {
        *destination = u64::from_le_bytes(word.try_into().unwrap());
    }
    out
}
fn publish_runtime(runtime: &Runtime) {
    let sequence = &GOVERNANCE_RUNTIME_V13_EVIDENCE.0[63];
    sequence.fetch_add(1, Ordering::AcqRel);
    let resources = unsafe { (&*RESOURCES.0.get()).as_ref() };
    let image_hash = resources.map_or([0; 32], |resources| resources.image_hash);
    let command_hash = hash_words(runtime.command_digest);
    let snapshot_hash = hash_words(runtime.snapshot_digest);
    let image_hash = hash_words(image_hash);
    let values = [
        RUNTIME_MAGIC,
        RUNTIME_VERSION,
        runtime.phase,
        runtime.core_generation,
        runtime.ledger_generation,
        runtime.last_credit_sequence,
        u64::from(cpu::slot() as u16),
        runtime.turns,
        runtime.total_actual_ns,
        runtime.max_actual_ns,
        runtime.preemptions,
        runtime.last_exit_esr,
        runtime.svc_x0,
        runtime.svc_x1,
        runtime.command_kind,
        runtime.command_sequence,
        runtime.snapshot_revision,
        runtime.validation_ns,
        ROLE_CONTEXT.id,
        ROLE_CONTEXT.generation,
        runtime.probe_esr[0],
        runtime.probe_far[0],
        runtime.probe_esr[1],
        runtime.probe_far[1],
        runtime.probe_esr[2],
        runtime.probe_far[2],
        runtime.spin_kind,
        u64::from(runtime.completed),
        command_hash[0],
        command_hash[1],
        command_hash[2],
        command_hash[3],
        snapshot_hash[0],
        snapshot_hash[1],
        snapshot_hash[2],
        snapshot_hash[3],
        image_hash[0],
        image_hash[1],
        image_hash[2],
        image_hash[3],
        runtime.last_bill[0],
        runtime.last_bill[1],
        runtime.last_bill[2],
        runtime.last_bill[3],
        runtime.last_bill[4],
        runtime.last_bill[5],
        runtime.last_bill[6],
        runtime.last_bill[7],
        runtime.failed,
        resources.map_or(0, |resources| resources.root),
        resources.map_or(0, |resources| resources.plan.entry),
        resources.map_or(0, |resources| resources.input.key().id),
        resources.map_or(0, |resources| resources.output.key().id),
        resources.map_or(0, |resources| resources.stack.key().id),
        runtime.snapshot_deadline_ns,
        runtime.snapshot_now_ns,
        runtime.validated_core_generation,
        runtime.validated_ledger_generation,
        runtime.last_credit_core,
        runtime.last_exit_kind,
        runtime.probe_turns,
        runtime.command_turns,
        0,
    ];
    for (destination, value) in GOVERNANCE_RUNTIME_V13_EVIDENCE.0[..63].iter().zip(values) {
        destination.store(value, Ordering::Relaxed);
    }
    sequence.fetch_add(1, Ordering::Release);
}
fn fail_runtime(runtime: &mut Runtime, code: u64) {
    if runtime.failed == 0 {
        runtime.failed = code.max(1);
    }
    publish_runtime(runtime);
}
fn runtime_task() -> crate::a02_capture::Task {
    crate::a02_capture::Task {
        id: ROLE_CONTEXT.id,
        generation: ROLE_CONTEXT.generation,
        role: 2,
        affinity: 1 << 1,
    }
}
fn fresh_runtime(mode: u64, resources: &Resources) -> user::Context {
    let mut context = user::Context::empty();
    context.pc = resources.plan.entry;
    context.sp = STACK_TOP;
    context.regs[0] = mode;
    context.regs[1] = SNAPSHOT_BYTES as u64;
    context.regs[2] = COMMAND_BYTES as u64;
    context
}
fn release_runtime_pins(runtime: &mut Runtime) -> Result<bool, Error> {
    for index in 0..runtime.pins.len() {
        let Some(lease) = runtime.pins[index].take() else {
            continue;
        };
        match pool::unpin(&lease) {
            Ok(()) => {}
            Err(Error::Busy | Error::NotReady) => {
                runtime.pins[index] = Some(lease);
                return Ok(false);
            }
            Err(error) => {
                runtime.pins[index] = Some(lease);
                return Err(error);
            }
        }
    }
    Ok(true)
}
fn acquire_runtime_pins(runtime: &mut Runtime, resources: &Resources) -> Result<bool, Error> {
    let allocations = [resources.input, resources.output, resources.stack];
    for (index, allocation) in allocations.into_iter().enumerate() {
        if runtime.pins[index].is_some() {
            continue;
        }
        match pool::pin(allocation) {
            Ok(lease) => runtime.pins[index] = Some(lease),
            Err(Error::Busy | Error::NotReady) => return Ok(false),
            Err(error) => return Err(error),
        }
    }
    Ok(true)
}
fn prepare_runtime_context(
    runtime: &mut Runtime,
    resources: &Resources,
    mode: u64,
) -> Result<(), Error> {
    if runtime.pins.iter().any(Option::is_some) {
        return Err(Error::Busy);
    }
    if mode == 0 {
        pool::zero_chunk(resources.output, 0, 4096)?;
        for page in 0..STACK_PAGES {
            pool::zero_chunk(resources.stack, page * 4096, 4096)?;
        }
        unsafe {
            core::arch::asm!("dsb ishst", options(nostack));
        }
    }
    runtime.context = Some(fresh_runtime(mode, resources));
    Ok(())
}
fn process_runtime_exit(runtime: &mut Runtime) -> Result<(), Error> {
    let context = runtime.context.as_mut().ok_or(Error::Conflict)?;
    let kind = context.kind;
    runtime.last_exit_kind = kind;
    runtime.last_exit_esr = context.esr;
    match runtime.phase {
        PHASE_INPUT_PROBE | PHASE_CODE_PROBE | PHASE_UNMAPPED_PROBE => {
            if kind == 9 {
                runtime.preemptions = runtime.preemptions.saturating_add(1);
                context.kind = 0;
                return Ok(());
            }
            let index =
                usize::try_from(runtime.phase - PHASE_INPUT_PROBE).map_err(|_| Error::Range)?;
            let (address, fsc) = [(INPUT_BASE, 0x4f), (CODE_BASE, 0x4f), (0x30000, 0x07)][index];
            if kind != 8
                || context.esr >> 26 != 0x24
                || context.esr & 0x7f != fsc
                || context.far != address
            {
                return Err(Error::Auth);
            }
            runtime.probe_esr[index] = context.esr;
            runtime.probe_far[index] = context.far;
            runtime.context = None;
            runtime.phase = runtime.phase.checked_add(1).ok_or(Error::Overflow)?;
        }
        PHASE_TIMER_PROBE => {
            if kind != 9 {
                return Err(Error::Auth);
            }
            runtime.preemptions = runtime.preemptions.saturating_add(1);
            runtime.spin_kind = kind;
            runtime.context = None;
            runtime.phase = PHASE_PREPARE;
        }
        PHASE_RUN => {
            if kind == 9 {
                runtime.preemptions = runtime.preemptions.saturating_add(1);
                context.kind = 0;
                return Ok(());
            }
            if kind != 8
                || context.esr >> 26 != 0x15
                || context.esr & 0xffff != 0x562
                || context.regs[0] != OUTPUT_BASE
                || context.regs[1] != COMMAND_BYTES as u64
            {
                return Err(Error::Auth);
            }
            runtime.svc_x0 = context.regs[0];
            runtime.svc_x1 = context.regs[1];
            runtime.context = None;
            runtime.phase = PHASE_VALIDATE;
        }
        _ => return Err(Error::Conflict),
    }
    Ok(())
}
fn run_runtime_context(runtime: &mut Runtime, resources: &Resources) -> Result<(), Error> {
    if runtime
        .context
        .as_ref()
        .is_some_and(|context| context.kind != 0)
    {
        if !release_runtime_pins(runtime)? {
            return Ok(());
        }
        return process_runtime_exit(runtime);
    }
    let mode = match runtime.phase {
        PHASE_INPUT_PROBE => 1,
        PHASE_CODE_PROBE => 2,
        PHASE_UNMAPPED_PROBE => 3,
        PHASE_TIMER_PROBE => 4,
        PHASE_RUN => 0,
        _ => return Err(Error::Conflict),
    };
    if runtime.context.is_none() {
        prepare_runtime_context(runtime, resources, mode)?;
    }
    if !acquire_runtime_pins(runtime, resources)? {
        return Ok(());
    }
    let slice = outcome::entry_slice_ns(mode)?;
    let context = runtime.context.as_mut().ok_or(Error::Conflict)?;
    context.kind = 0;
    unsafe {
        crate::smp::enter_service(
            context,
            resources.root,
            timer::ticks().saturating_add(runtime_ticks(slice).max(1)),
            runtime_task(),
            None,
            true,
            true,
        );
    }
    if runtime.phase <= PHASE_TIMER_PROBE {
        runtime.probe_turns = runtime.probe_turns.saturating_add(1);
    } else {
        runtime.command_turns = runtime.command_turns.saturating_add(1);
    }
    if !release_runtime_pins(runtime)? {
        return Ok(());
    }
    process_runtime_exit(runtime)
}
fn prepare_runtime_snapshot(
    runtime: &mut Runtime,
    resources: &Resources,
    credit: ControlCredit,
) -> Result<(), Error> {
    if runtime.context.is_some() || runtime.pins.iter().any(Option::is_some) {
        return Err(Error::Busy);
    }
    let (core_generation, ledger_generation) = crate::domain_tasks::control_owner_context(1)?;
    if credit.cpu != 1 || credit.core_generation != core_generation {
        return Err(Error::Stale);
    }
    let now_ns = runtime_ns(timer::ticks());
    let deadline_ns = now_ns
        .checked_add(COMMAND_DEADLINE_NS)
        .ok_or(Error::Overflow)?;
    let original_hash = hash_label(
        b"CYXIA_GOVERNANCE_SELFTEST_ORIGINAL_1.3\0",
        resources.image_hash,
    );
    let registration_hash = hash_label(
        b"CYXIA_GOVERNANCE_SELFTEST_REGISTRATION_1.3\0",
        resources.image_hash,
    );
    let snapshot = CoordinatorSnapshot {
        binding: JobBinding {
            boot_epoch: 1,
            job_id: SELFTEST_JOB,
            controller_epoch: 1,
            core_generation,
            model_generation: 1,
            data_generation: 1,
            role_context: ROLE_CONTEXT,
            image_hash: resources.image_hash,
            ledger_generation,
        },
        session: SESSION,
        revision: 1,
        now_ns,
        deadline_ns,
        stage: Stage::Active,
        original_hash,
        candidate_hash: resources.image_hash,
        registration_hash,
        shadow_coverage: 0,
        closed_windows: 0,
        permit: None,
        pending: None,
        baseline_ready: false,
        last_command_sequence: 0,
        last_command_status: LastCommandStatus::None,
        verified_score: None,
    };
    let mut bytes = [0; SNAPSHOT_BYTES];
    snapshot.encode(&mut bytes).map_err(|_| Error::Schema)?;
    pool::write(resources.input, 0, &bytes)?;
    pool::zero_chunk(resources.output, 0, 4096)?;
    unsafe {
        core::arch::asm!("dsb ishst", options(nostack));
    }
    runtime.snapshot_digest = snapshot.digest().map_err(|_| Error::Schema)?;
    runtime.snapshot_now_ns = now_ns;
    runtime.snapshot_deadline_ns = deadline_ns;
    runtime.snapshot_revision = snapshot.revision;
    runtime.core_generation = core_generation;
    runtime.ledger_generation = ledger_generation;
    runtime.snapshot = Some(snapshot);
    runtime.phase = PHASE_RUN;
    Ok(())
}
fn validate_runtime_command(runtime: &mut Runtime, resources: &Resources) -> Result<(), Error> {
    if runtime.context.is_some() || runtime.pins.iter().any(Option::is_some) {
        return Err(Error::Busy);
    }
    let snapshot = runtime.snapshot.ok_or(Error::NotReady)?;
    let (core_generation, ledger_generation) = crate::domain_tasks::control_owner_context(1)?;
    if core_generation != runtime.core_generation
        || ledger_generation != runtime.ledger_generation
        || snapshot.binding.core_generation != core_generation
        || snapshot.binding.ledger_generation != ledger_generation
        || snapshot.binding.role_context != ROLE_CONTEXT
        || snapshot.binding.image_hash != resources.image_hash
    {
        return Err(Error::Stale);
    }
    let mut bytes = [0; COMMAND_BYTES];
    unsafe {
        core::arch::asm!("dsb ish", options(nostack));
    }
    pool::read(resources.output, 0, &mut bytes)?;
    let command = Command::decode(&bytes).map_err(|_| Error::Schema)?;
    let now_ns = runtime_ns(timer::ticks());
    command
        .validate_for_snapshot(snapshot, now_ns)
        .map_err(|_| Error::Auth)?;
    if command.action != CommandAction::Wait
        || command.sequence != 1
        || command.binding.core_generation != core_generation
        || command.binding.ledger_generation != ledger_generation
    {
        return Err(Error::Auth);
    }
    runtime.command_kind = 1;
    runtime.command_sequence = command.sequence;
    runtime.command_digest = command.digest().map_err(|_| Error::Schema)?;
    runtime.command = Some(command);
    runtime.validation_ns = now_ns;
    runtime.validated_core_generation = core_generation;
    runtime.validated_ledger_generation = ledger_generation;
    runtime.completed = true;
    runtime.phase = PHASE_COMPLETE;
    Ok(())
}
fn settle_runtime_bill(runtime: &mut Runtime) -> bool {
    let Some(bill) = runtime.bill else {
        return true;
    };
    match crate::domain_tasks::complete_control(bill.credit, bill.actual_ns, bill.finished_ns) {
        Ok(()) => {
            runtime.bill = None;
            runtime.last_bill[7] = 1;
            publish_runtime(runtime);
            true
        }
        Err(Error::Busy | Error::NotReady) => false,
        Err(Error::Budget) => {
            runtime.bill = None;
            fail_runtime(runtime, 0x601);
            true
        }
        Err(error) => {
            runtime.bill = None;
            fail_runtime(runtime, 0x610 + error as u64);
            true
        }
    }
}

/// A completed coordinator turn still owns its physical credit until exact
/// settlement succeeds. Mandatory input becoming ready must not bypass that
/// old bill: it would otherwise keep the same control CPU permanently busy.
pub(super) fn settle() -> bool {
    if cpu::slot() != 1 || !INITIALIZED.load(Ordering::Acquire) {
        return true;
    }
    settle_runtime_bill(runtime_state())
}

fn perform_runtime_turn(
    runtime: &mut Runtime,
    resources: &Resources,
    credit: ControlCredit,
) -> Result<(), Error> {
    let current = crate::domain_tasks::control_owner_context(1)?;
    if credit.cpu != 1 || credit.core_generation != current.0 {
        return Err(Error::Stale);
    }
    runtime.last_credit_core = credit.core_generation;
    match runtime.phase {
        PHASE_INPUT_PROBE | PHASE_CODE_PROBE | PHASE_UNMAPPED_PROBE | PHASE_TIMER_PROBE
        | PHASE_RUN => run_runtime_context(runtime, resources),
        PHASE_PREPARE => prepare_runtime_snapshot(runtime, resources, credit),
        PHASE_VALIDATE => validate_runtime_command(runtime, resources),
        PHASE_COMPLETE => Ok(()),
        _ => Err(Error::Conflict),
    }
}

/// Run at most one physically prepaid coordinator turn. Returning true means
/// this role still owns the current idle scheduling opportunity; no Shadow,
/// Canary or training work may borrow the same turn.
pub(super) fn step(extra: &mut super::learning::Worker) -> bool {
    if cpu::slot() != 1 || !INITIALIZED.load(Ordering::Acquire) {
        return false;
    }
    let runtime = runtime_state();
    if !settle_runtime_bill(runtime) {
        publish_runtime(runtime);
        return true;
    }
    if runtime.completed {
        publish_runtime(runtime);
        return false;
    }
    if runtime.failed != 0 {
        if release_runtime_pins(runtime).ok() == Some(true) {
            runtime.context = None;
        }
        publish_runtime(runtime);
        return runtime.pins.iter().any(Option::is_some);
    }
    let now_ns = runtime_ns(timer::ticks());
    if !super::learning::allow_mandatory(extra, RUNTIME_PREPAY_NS, now_ns) {
        publish_runtime(runtime);
        return true;
    }
    let Ok(Some(credit)) = crate::domain_tasks::begin_control(RUNTIME_PREPAY_NS, false) else {
        publish_runtime(runtime);
        return true;
    };
    let cpu_started = timer::cpu_ticks();
    let result =
        runtime_resources().and_then(|resources| perform_runtime_turn(runtime, resources, credit));
    let actual_ns = timer::cpu_elapsed_ns(cpu_started);
    let finished_ns = runtime_ns(timer::ticks());
    runtime.turns = runtime.turns.saturating_add(1);
    runtime.total_actual_ns = runtime.total_actual_ns.saturating_add(actual_ns);
    runtime.max_actual_ns = runtime.max_actual_ns.max(actual_ns);
    runtime.last_credit_sequence = credit.sequence;
    runtime.last_bill = [
        credit.started_ns,
        finished_ns,
        credit.reserved_ns,
        actual_ns,
        credit.control_total_ns,
        credit.physical_total_ns,
        credit.window,
        0,
    ];
    super::learning::mandatory(extra, credit.started_ns, actual_ns);
    runtime.bill = Some(RuntimeBill {
        credit,
        actual_ns,
        finished_ns,
    });
    if let Some(code) = outcome::failure_code(result) {
        fail_runtime(runtime, code);
    }
    let _ = settle_runtime_bill(runtime);
    publish_runtime(runtime);
    true
}

/// The role has no external side effect or retained policy obligation. A stop
/// may discard only a returned, unpinned self-test context; its physical bill
/// must still settle first.
pub(super) fn quiescent() -> bool {
    if cpu::slot() != 1 || !INITIALIZED.load(Ordering::Acquire) {
        return true;
    }
    let runtime = runtime_state();
    if !settle_runtime_bill(runtime) {
        return false;
    }
    match release_runtime_pins(runtime) {
        Ok(true) => {
            if runtime.context.is_some() && !runtime.completed {
                runtime.context = None;
                fail_runtime(runtime, 0x7f0);
            }
        }
        Ok(false) => return false,
        Err(error) => {
            fail_runtime(runtime, 0x7f8 + error as u64);
            return false;
        }
    }
    publish_runtime(runtime);
    runtime.bill.is_none() && runtime.context.is_none() && runtime.pins.iter().all(Option::is_none)
}
