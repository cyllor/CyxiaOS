//! Continuous experimental CACP runtime and bounded native ownership handoff.
//!
//! CPU1 owns the restartable EL0 model. CPU0 owns scheduling accounting; neither
//! business CPU waits for inference. This profile has no native DMA/reference
//! adapters in the standalone profile; unified mode registers actual stop producers.
//! Business programs are explicitly bounded CPU workloads, not desktop services.
use super::*;
#[path = "../../user/prototype-runtime/abi.rs"]
mod abi;
#[path = "../../user/prototype-runtime/dynamic.rs"]
mod dynamic;
#[path = "../../user/prototype-runtime/idle.rs"]
mod idle;
#[cfg(feature = "unified-runtime")]
#[path = "prototype_runtime/learning.rs"]
mod learning;
#[cfg(feature = "unified-runtime")]
#[path = "prototype_runtime/native.rs"]
mod native;
use cyxia_kernel_core::control_plane::image::{BASE, Image, PAGES};
use cyxia_prototype::cores::{CoreSet, Cores, Plane as OwnerPlane, ThreadSpec};
use dynamic::{Handoff, NativeStop};
#[used]
#[unsafe(no_mangle)]
static RUNTIME_SERVICE_ELF: [u8; include_bytes!(concat!(
    env!("OUT_DIR"),
    "/prototype-runtime.elf"
))
.len()] = *include_bytes!(concat!(env!("OUT_DIR"), "/prototype-runtime.elf"));
const FAULT_MODE: u64 = include!(concat!(env!("OUT_DIR"), "/runtime-fault.rs"));
const MAGIC: u64 = 0x43595852554e3133;
const RECORDS: usize = 32;
const RECORD_WORDS: usize = 24;
// Reserve 10 ms before each 1 ms timer slice, including observed TCG/return
// latency. A longer actual dispatch fails shut instead of hiding the overrun.
const SLICE_MILLI: u16 = 100;
#[repr(C, align(4096))]
struct RuntimeEvidence([AtomicU64; 1024]);
#[used]
#[unsafe(no_mangle)]
static RUNTIME_V13_EVIDENCE: RuntimeEvidence = RuntimeEvidence([const { AtomicU64::new(0) }; 1024]);
#[cfg(not(feature = "unified-runtime"))]
static mut IMAGE: [Page; PAGES] = [const { Page::ZERO }; PAGES];
#[cfg(not(feature = "unified-runtime"))]
static mut INPUT: Page = Page::ZERO;
#[cfg(not(feature = "unified-runtime"))]
static mut SECOND_INPUT: Page = Page::ZERO;
#[cfg(not(feature = "unified-runtime"))]
static mut SECOND_OUTPUT: Page = Page::ZERO;
#[cfg(not(feature = "unified-runtime"))]
static mut SECOND_STACK: [Page; 8] = [const { Page::ZERO }; 8];
#[cfg(feature = "unified-runtime")]
static POOL_IMAGE: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "unified-runtime")]
static POOL_PRIVATE: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
#[cfg(feature = "unified-runtime")]
static mut POOL_ALLOCATIONS: [Option<crate::control_pool::Allocation>; 3] = [None; 3];
#[cfg(feature = "unified-runtime")]
static mut POOL_PINS: [Option<crate::control_pool::Lease>; 3] = [const { None }; 3];
static SECOND_REQUEST: AtomicU64 = AtomicU64::new(0);
static SECOND_START: AtomicU64 = AtomicU64::new(0);
static STOP_OPERATION: AtomicU64 = AtomicU64::new(0);
static STOP_ACK: AtomicU64 = AtomicU64::new(0);
static STOP_TASK_ACK: AtomicU64 = AtomicU64::new(0);
static STOP_IRQ_ACK: AtomicU64 = AtomicU64::new(0);
static STOP_TLB_ACK: AtomicU64 = AtomicU64::new(0);
static STOP_REF_ACK: AtomicU64 = AtomicU64::new(0);
static IRQ_INFLIGHT: [AtomicU64; C] = [const { AtomicU64::new(0) }; C];
// Unified devices and their pinned DMA pools/ordinary IRQ routes belong solely
// to the CPU0 broker. This registry is their actual admission rule, not a stop
// event. A future device route to CPU2 must first extend these registries.
static DMA_OWNERS: AtomicU64 = AtomicU64::new(0);
static DEVICE_IRQ_OWNERS: AtomicU64 = AtomicU64::new(0);
static DEVICE_REGISTRY_READY: AtomicBool = AtomicBool::new(false);
static COORDINATOR_CLAIMED: AtomicBool = AtomicBool::new(false);
#[cfg(not(feature = "unified-runtime"))]
static mut OUTPUT: Page = Page::ZERO;
#[cfg(not(feature = "unified-runtime"))]
static mut STACK_PAGES: [Page; 8] = [const { Page::ZERO }; 8];
static ENTRY: AtomicU64 = AtomicU64::new(0);
// 0 idle; 1 request published; 2 owned by CPU1; 3 reply; 4 failure.
static REQUEST: AtomicU64 = AtomicU64::new(0);
static REQUEST_START: AtomicU64 = AtomicU64::new(0);
static REQUEST_END: AtomicU64 = AtomicU64::new(0);
static RESULT_KIND: AtomicU64 = AtomicU64::new(0);
static RESULT_ESR: AtomicU64 = AtomicU64::new(0);
static RESULT_PREEMPTIONS: AtomicU64 = AtomicU64::new(0);
// Each worker is the sole writer of its slot. Avoid a cross-core exclusive RMW
// at the synchronous probe-return boundary; readers sum the four exact counts.
static PROTECTED: [AtomicU64; C] = [const { AtomicU64::new(0) }; C];
// Per-CPU one-credit mailboxes: idle / grant / executing / completion / expired.
static DISPATCH: [AtomicU64; C] = [const { AtomicU64::new(0) }; C];
static EXPIRES: [AtomicU64; C] = [const { AtomicU64::new(0) }; C];
static ELAPSED: [AtomicU64; C] = [const { AtomicU64::new(0) }; C];
static TOTAL_TICKS: [AtomicU64; C] = [const { AtomicU64::new(0) }; C];
static OVERRUNS: AtomicU64 = AtomicU64::new(0);
static CLOCK_ORIGIN: AtomicU64 = AtomicU64::new(0);
static CONTROL_MAX_DEBIT: AtomicU64 = AtomicU64::new(0);
static CONTROL_TICKS: AtomicU64 = AtomicU64::new(0);
static CONTROL_TOTAL_DEBIT: AtomicU64 = AtomicU64::new(0);
static CONTROL_OVERRUNS: AtomicU64 = AtomicU64::new(0);
static MAX_SLICE: [AtomicU64; C] = [const { AtomicU64::new(0) }; C];
fn record_protected() {
    let counter = &PROTECTED[cpu::slot()];
    counter.store(
        counter.load(Ordering::Relaxed).saturating_add(1),
        Ordering::Release,
    );
}
fn protected_count() -> u64 {
    PROTECTED.iter().fold(0u64, |total, counter| {
        total.saturating_add(counter.load(Ordering::Acquire))
    })
}

fn image_ptr() -> *mut Page {
    #[cfg(feature = "unified-runtime")]
    {
        POOL_IMAGE.load(Ordering::Acquire) as *mut Page
    }
    #[cfg(not(feature = "unified-runtime"))]
    {
        core::ptr::addr_of_mut!(IMAGE).cast::<Page>()
    }
}
fn input_ptr(slot: usize) -> *mut Page {
    #[cfg(feature = "unified-runtime")]
    {
        POOL_PRIVATE[slot - 1].load(Ordering::Acquire) as *mut Page
    }
    #[cfg(not(feature = "unified-runtime"))]
    {
        if slot == 1 {
            core::ptr::addr_of_mut!(INPUT)
        } else {
            core::ptr::addr_of_mut!(SECOND_INPUT)
        }
    }
}
fn output_ptr(slot: usize) -> *mut Page {
    #[cfg(feature = "unified-runtime")]
    {
        input_ptr(slot).wrapping_add(1)
    }
    #[cfg(not(feature = "unified-runtime"))]
    {
        if slot == 1 {
            core::ptr::addr_of_mut!(OUTPUT)
        } else {
            core::ptr::addr_of_mut!(SECOND_OUTPUT)
        }
    }
}
fn stack_ptr(slot: usize) -> *mut Page {
    #[cfg(feature = "unified-runtime")]
    {
        input_ptr(slot).wrapping_add(2)
    }
    #[cfg(not(feature = "unified-runtime"))]
    {
        if slot == 1 {
            core::ptr::addr_of_mut!(STACK_PAGES).cast::<Page>()
        } else {
            core::ptr::addr_of_mut!(SECOND_STACK).cast::<Page>()
        }
    }
}
#[cfg(feature = "unified-runtime")]
fn reserve_pool() {
    use crate::control_pool as pool;
    use cyxia_prototype::domains::ObjectKey;
    assert_eq!(cpu::slot(), 0);
    for (index, pages) in [PAGES, 10, 10].into_iter().enumerate() {
        let allocation = pool::allocate(
            ObjectKey {
                id: 0x4352_5400 + index as u64,
                generation: 1,
            },
            pages,
        )
        .expect("runtime control backing");
        let (address, _, _) = pool::span(allocation).expect("runtime control span");
        unsafe {
            (*core::ptr::addr_of_mut!(POOL_ALLOCATIONS))[index] = Some(allocation);
        }
        if index == 0 {
            POOL_IMAGE.store(address as u64, Ordering::Release)
        } else {
            POOL_PRIVATE[index - 1].store(address as u64, Ordering::Release)
        }
    }
}

pub(super) unsafe fn init() {
    #[cfg(feature = "unified-runtime")]
    reserve_pool();
    let image = Image::parse(&RUNTIME_SERVICE_ELF).expect("runtime EL0 image");
    unsafe {
        let leaf = &mut *core::ptr::addr_of_mut!(LEAVES).cast::<Page>().add(3);
        leaf.0.fill(0);
        let arena = image_ptr().cast::<u8>();
        for segment in image.segments.iter().take(image.count) {
            let offset = (segment.address - BASE) as usize;
            core::ptr::copy_nonoverlapping(
                image.bytes.as_ptr().add(segment.offset),
                arena.add(offset),
                segment.file_size,
            );
            for page in offset / 4096..(offset + segment.memory_size).div_ceil(4096) {
                leaf.0[BASE as usize / 4096 + page] = mmu::encode_user_leaf(
                    PhysAddr(phys(arena.add(page * 4096) as u64)),
                    false,
                    segment.executable,
                )
                .unwrap();
            }
        }
        for offset in (0..PAGES * 4096).step_by(64) {
            core::arch::asm!("dc cvau, {}", in(reg) arena.add(offset), options(nostack));
        }
        core::arch::asm!("dsb ish", options(nostack));
        leaf.0[abi::INPUT_VA as usize / 4096] =
            mmu::encode_user_leaf(PhysAddr(phys(input_ptr(1) as u64)), false, false).unwrap();
        leaf.0[abi::OUTPUT_VA as usize / 4096] =
            mmu::encode_user_leaf(PhysAddr(phys(output_ptr(1) as u64)), true, false).unwrap();
        for n in 0..8 {
            let address = stack_ptr(1).cast::<Page>().add(n);
            leaf.0[0xb1 + n] =
                mmu::encode_user_leaf(PhysAddr(phys(address as u64)), true, false).unwrap();
        }
    }
    if cfg!(feature = "unified-runtime") {
        unsafe {
            let source = core::ptr::addr_of!(LEAVES).cast::<Page>().add(3);
            let leaf = &mut *core::ptr::addr_of_mut!(LEAVES).cast::<Page>().add(5);
            leaf.0.copy_from_slice(&(*source).0);
            leaf.0[abi::INPUT_VA as usize / 4096] =
                mmu::encode_user_leaf(PhysAddr(phys(input_ptr(2) as u64)), false, false).unwrap();
            leaf.0[abi::OUTPUT_VA as usize / 4096] =
                mmu::encode_user_leaf(PhysAddr(phys(output_ptr(2) as u64)), true, false).unwrap();
            for n in 0..8 {
                let page = stack_ptr(2).cast::<Page>().add(n);
                leaf.0[0xb1 + n] =
                    mmu::encode_user_leaf(PhysAddr(phys(page as u64)), true, false).unwrap();
            }
        }
    }
    ENTRY.store(image.entry, Ordering::Release);
    #[cfg(feature = "unified-runtime")]
    {
        for index in 0..3 {
            let allocation = unsafe {
                (*core::ptr::addr_of!(POOL_ALLOCATIONS))[index].expect("runtime pool allocation")
            };
            if index == 0 {
                crate::control_pool::seal(allocation).expect("seal control image");
            }
            let pin = crate::control_pool::pin(allocation).expect("pin control image");
            unsafe {
                (*core::ptr::addr_of_mut!(POOL_PINS))[index] = Some(pin);
            }
        }
        learning::init().expect("learning control pool");
    }
}
fn fresh(mode: u64) -> user::Context {
    let mut context = user::Context::empty();
    context.pc = ENTRY.load(Ordering::Acquire);
    context.sp = abi::STACK_TOP;
    context.regs[0] = mode;
    context
}
pub(super) struct Worker {
    context: Option<user::Context>,
    preemptions: u64,
    probed: bool,
    window: u64,
    charged: u64,
    #[cfg(feature = "unified-runtime")]
    native: native::WorkerState,
    #[cfg(feature = "unified-runtime")]
    extra: learning::Worker,
}
impl Worker {
    pub(super) const fn new() -> Self {
        Self {
            context: None,
            preemptions: 0,
            probed: false,
            window: 0,
            charged: 0,
            #[cfg(feature = "unified-runtime")]
            native: native::WorkerState::new(),
            #[cfg(feature = "unified-runtime")]
            extra: learning::Worker::new(),
        }
    }
}
#[cfg(feature = "unified-runtime")]
pub use learning::InputLoan as LearningInputLoan;
#[cfg(feature = "unified-runtime")]
pub use learning::Registration as LearningRegistration;
#[cfg(feature = "unified-runtime")]
pub use learning::{Request as LearningRequest, Status as LearningStatus};
#[cfg(feature = "unified-runtime")]
pub fn learning_driver_workspace()
-> Result<crate::control_pool::Allocation, cyxia_prototype::domains::Error> {
    learning::driver_workspace()
}
#[cfg(feature = "unified-runtime")]
pub fn learning_session_workspace()
-> Result<crate::control_pool::Allocation, cyxia_prototype::domains::Error> {
    learning::session_workspace()
}
#[cfg(feature = "unified-runtime")]
pub fn borrow_learning_input() -> Result<LearningInputLoan, cyxia_prototype::domains::Error> {
    learning::borrow_input()
}
#[cfg(feature = "unified-runtime")]
pub fn learning_input_span(
    loan: &LearningInputLoan,
) -> Result<(usize, usize), cyxia_prototype::domains::Error> {
    learning::input_span(loan)
}
#[cfg(feature = "unified-runtime")]
pub fn seal_learning_input(
    loan: &mut LearningInputLoan,
) -> Result<crate::control_pool::Allocation, cyxia_prototype::domains::Error> {
    learning::seal_input(loan)
}
#[cfg(feature = "unified-runtime")]
pub fn abandon_learning_input(
    loan: &mut LearningInputLoan,
) -> Result<(), cyxia_prototype::domains::Error> {
    learning::abandon_input(loan)
}
#[cfg(feature = "unified-runtime")]
pub fn authorize_learning_turn() -> Result<(), cyxia_prototype::domains::Error> {
    learning::require_extra_caller()
}
#[cfg(feature = "unified-runtime")]
pub fn register_learning_driver(
    turn: fn() -> Result<bool, cyxia_prototype::domains::Error>,
) -> Result<(), cyxia_prototype::domains::Error> {
    learning::register_driver(turn)
}
#[cfg(feature = "unified-runtime")]
pub fn learning_registration(
    role: cyxia_prototype::learning::worker_wire::Role,
) -> Result<LearningRegistration, cyxia_prototype::domains::Error> {
    learning::registration(role)
}
#[cfg(feature = "unified-runtime")]
pub fn install_learning_capture(
    node: [u8; 32],
    boot: u64,
) -> Result<(), cyxia_prototype::domains::Error> {
    learning::install_capture(node, boot)
}
#[cfg(feature = "unified-runtime")]
pub fn install_learning_capture_storage(
    node: [u8; 32],
    boot: u64,
) -> Result<(), cyxia_prototype::domains::Error> {
    learning::install_capture_storage(node, boot)
}
#[cfg(feature = "unified-runtime")]
pub fn install_learning_history_storage(
    node: [u8; 32],
    boot: u64,
) -> Result<(), cyxia_prototype::domains::Error> {
    learning::install_history_storage(node, boot)
}
#[cfg(feature = "unified-runtime")]
pub fn verify_learning_completion(
    claim: &cyxia_prototype::learning::worker::CompletionClaim,
) -> Result<(), cyxia_prototype::learning::Error> {
    learning::verify_completion(claim)
}
#[cfg(feature = "unified-runtime")]
pub fn verify_learning_score_completion(
    claim: &cyxia_prototype::learning::worker::CompletionClaim,
    receipt: &cyxia_prototype::learning::governance::WorkReceipt,
) -> Result<(), cyxia_prototype::learning::Error> {
    learning::verify_score_completion(claim, receipt)
}
#[cfg(feature = "unified-runtime")]
pub fn take_learning_score_receipt(
    key: cyxia_prototype::domains::ObjectKey,
) -> Result<cyxia_prototype::learning::governance::WorkReceipt, cyxia_prototype::domains::Error> {
    learning::take_score_receipt(key)
}
#[cfg(feature = "unified-runtime")]
pub fn submit_learning(
    request: LearningRequest,
) -> Result<cyxia_prototype::domains::ObjectKey, cyxia_prototype::domains::Error> {
    learning::submit(request)
}
#[cfg(feature = "unified-runtime")]
pub fn query_learning(
    key: cyxia_prototype::domains::ObjectKey,
) -> Result<LearningStatus, cyxia_prototype::domains::Error> {
    learning::query(key)
}
#[cfg(feature = "unified-runtime")]
pub fn read_learning_result(
    key: cyxia_prototype::domains::ObjectKey,
    offset: usize,
    out: &mut [u8],
) -> Result<(), cyxia_prototype::domains::Error> {
    learning::read_result(key, offset, out)
}
#[cfg(feature = "unified-runtime")]
pub fn acknowledge_learning(
    key: cyxia_prototype::domains::ObjectKey,
) -> Result<(), cyxia_prototype::domains::Error> {
    learning::acknowledge(key)
}
#[cfg(feature = "unified-runtime")]
pub fn cancel_learning(
    key: cyxia_prototype::domains::ObjectKey,
) -> Result<(), cyxia_prototype::domains::Error> {
    learning::cancel(key)
}
/// One bounded scheduling turn on the control CPU. A stalled model returns on
/// every timer tick; its old context is discarded only after user::enter returns.
pub(super) fn step(worker: &mut Worker) {
    #[cfg(feature = "unified-runtime")]
    {
        native::step(worker);
        return;
    }
    if cpu::slot() == 2 {
        secondary_control_step(worker);
        return;
    }
    assert_eq!(cpu::slot(), 1);
    if !worker.probed {
        unsafe {
            core::arch::asm!("ic iallu", "dsb ish", "isb", options(nostack));
        }
        for (n, (address, fsc)) in [
            (abi::INPUT_VA, 0x4f),
            (abi::MODEL_VA, 0x4f),
            (0xb0000, 0x47),
            (0x30000, 0x07),
        ]
        .into_iter()
        .enumerate()
        {
            let mut context = fresh(n as u64 + 1);
            let end = deadline();
            loop {
                execute(&mut context, 3);
                if context.kind != 9 {
                    break;
                }
                if timer::ticks() >= end {
                    fatal(181);
                }
            }
            if context.kind != 8
                || context.esr >> 26 != 0x24
                || context.esr & 0x7f != fsc
                || context.far != address
            {
                fatal(182);
            }
            record_protected();
        }
        worker.probed = true;
    }
    if CONTROL_OVERRUNS.load(Ordering::Acquire) != 0 {
        return;
    }
    if worker.context.is_none() {
        if REQUEST
            .compare_exchange(1, 2, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let sequence = unsafe { (*input_ptr(1)).0[2] };
        unsafe {
            (*output_ptr(1)).0.fill(0);
            for n in 0..8 {
                (*stack_ptr(1).cast::<Page>().add(n)).0.fill(0);
            }
            core::arch::asm!("dsb ish", options(nostack));
        }
        worker.context = Some(fresh(if FAULT_MODE == 1 && sequence == 5 {
            5
        } else {
            0
        }));
        worker.preemptions = 0;
        REQUEST_START.store(timer::ticks(), Ordering::Relaxed);
    }
    if CONTROL_OVERRUNS.load(Ordering::Acquire) != 0 {
        return;
    }
    let frequency = timer::frequency();
    let now = timer::ticks();
    let origin = CLOCK_ORIGIN.load(Ordering::Acquire);
    let window = (now - origin) / (frequency / 10);
    if window > worker.window {
        worker.window = window;
        worker.charged = 0;
    }
    let timed_out = now - REQUEST_START.load(Ordering::Relaxed) >= frequency / 10;
    let context = worker.context.as_mut().unwrap();
    if !timed_out {
        let end_window = origin + (window + 1) * (frequency / 10);
        if worker.charged + u64::from(SLICE_MILLI) > 700 || now + frequency / 100 > end_window {
            return;
        }
        worker.charged += u64::from(SLICE_MILLI);
        CONTROL_MAX_DEBIT.fetch_max(worker.charged, Ordering::Relaxed);
        CONTROL_TOTAL_DEBIT.fetch_add(u64::from(SLICE_MILLI), Ordering::Relaxed);
        let begin = timer::ticks();
        execute(context, 3);
        let end = timer::ticks();
        CONTROL_TICKS.fetch_add(end - begin, Ordering::Relaxed);
        MAX_SLICE[1].fetch_max(end - begin, Ordering::Relaxed);
        if end - begin > frequency / 100 || end > end_window {
            CONTROL_OVERRUNS.fetch_add(1, Ordering::Release);
        }
        if context.kind == 9 {
            worker.preemptions += 1;
            if end - REQUEST_START.load(Ordering::Relaxed) < frequency / 10
                && CONTROL_OVERRUNS.load(Ordering::Acquire) == 0
            {
                return;
            }
        }
    }
    let end = timer::ticks();
    let valid = !timed_out
        && CONTROL_OVERRUNS.load(Ordering::Acquire) == 0
        && context.kind == 8
        && context.esr >> 26 == 0x15
        && context.esr & 0xffff == abi::SUBMIT
        && context.regs[0] == abi::OUTPUT_VA
        && context.regs[1] == (abi::OUTPUT_WORDS * 8) as u64;
    RESULT_KIND.store(context.kind, Ordering::Relaxed);
    RESULT_ESR.store(context.esr, Ordering::Relaxed);
    RESULT_PREEMPTIONS.store(worker.preemptions, Ordering::Relaxed);
    REQUEST_END.store(end, Ordering::Relaxed);
    worker.context = None;
    REQUEST.store(if valid { 3 } else { 4 }, Ordering::Release);
}
pub(super) fn business_enter(slot: usize) -> bool {
    assert!((2..4).contains(&slot));
    #[cfg(feature = "unified-runtime")]
    {
        if !native::ready() {
            return false;
        }
        return crate::domain_tasks::begin_builtin(slot, crate::domain_tasks::now_ns()).is_some();
    }
    if DISPATCH[slot]
        .compare_exchange(1, 2, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return false;
    }
    // Reject a delayed grant instead of carrying it into a fresh budget window.
    if timer::ticks().saturating_add(timer::frequency() / 100)
        > EXPIRES[slot].load(Ordering::Relaxed)
    {
        DISPATCH[slot].store(4, Ordering::Release);
        return false;
    }
    true
}
pub(super) fn business_complete(slot: usize, start: u64) {
    #[cfg(feature = "unified-runtime")]
    {
        let actual_ns = timer::cpu_elapsed_ns(start);
        let finished_ticks = timer::ticks();
        let evidence_ticks = ((u128::from(actual_ns) * u128::from(timer::frequency()))
            / 1_000_000_000)
            .min(u128::from(u64::MAX)) as u64;
        MAX_SLICE[slot].fetch_max(evidence_ticks, Ordering::Relaxed);
        TOTAL_TICKS[slot].fetch_add(evidence_ticks, Ordering::Relaxed);
        // The selected credit belongs to exactly one dynamic, remote, or
        // builtin thread. Its deferred completion cannot grant a second slice.
        let _ = crate::domain_tasks::complete_builtin(slot, actual_ns, native::ns(finished_ticks));
        return;
    }
    #[cfg(not(feature = "unified-runtime"))]
    {
        let end = timer::ticks();
        let elapsed = end - start;
        ELAPSED[slot].store(elapsed, Ordering::Relaxed);
        MAX_SLICE[slot].fetch_max(elapsed, Ordering::Relaxed);
        TOTAL_TICKS[slot].fetch_add(elapsed, Ordering::Relaxed);
        if elapsed > timer::frequency() / 100 || end > EXPIRES[slot].load(Ordering::Relaxed) {
            OVERRUNS.fetch_add(1, Ordering::Release);
            // Returning a permit is not enough to authorize another slice. CPU0
            // observes this terminal fault and stops granting further execution.
        }
        DISPATCH[slot].store(3, Ordering::Release);
    }
}
fn progress() -> [u64; 2] {
    [
        PROGRESS[4].load(Ordering::Acquire),
        PROGRESS[6].load(Ordering::Acquire),
    ]
}
fn put(index: usize, value: u64) {
    RUNTIME_V13_EVIDENCE.0[index].store(value, Ordering::Relaxed);
}
fn write_record(records: &mut [[u64; RECORD_WORDS]; RECORDS], record: [u64; RECORD_WORDS]) {
    records[(record[0] as usize - 1) % RECORDS] = record;
}
/// Never terminates after a target number of inferences. The verifier samples
/// this running service, resumes it and proves forward progress in another sample.
pub(super) fn run(info: &BootInfo) -> ! {
    let boot = super::super::prototype_storage::boot(info);
    let mut coordinator = Coordinator::new(boot);
    super::super::log(b"RUNTIME_V13_STARTED mode=continuous ownership=fixed model=untrained\n");
    loop {
        coordinator.poll();
    }
}
pub(crate) struct Coordinator {
    #[cfg(feature = "unified-runtime")]
    native: native::CoordinatorState,
    boot: cyxia_prototype::boot::BootIdentity,
    frequency: u64,
    origin: u64,
    owner: Cores,
    threads: [Option<cyxia_prototype::cores::ThreadHandle>; 2],
    window: u64,
    spent: [u64; 2],
    prepaid: [u64; 2],
    max_spent: [u64; 2],
    weights: [u64; 2],
    active_weights: [u64; 2],
    active_policy_sequence: u64,
    window_ticks: [u64; 2],
    completions: [u64; 2],
    expired: [u64; 2],
    windows: [[u64; 16]; 12],
    window_receipts: usize,
    service_generation: u64,
    requests: u64,
    successes: u64,
    faults: u64,
    stale: u64,
    preemptions: u64,
    policy_sequence: u64,
    policy_at: u64,
    request_at: u64,
    sample_at: u64,
    last_progress: [u64; 2],
    input: [u64; abi::INPUT_WORDS],
    records: [[u64; RECORD_WORDS]; RECORDS],
    publication: u64,
    wake_pulse: idle::WakePulse,
    handoff: Option<Handoff>,
    handoff_sequence: u64,
    handoff_target: u64,
    handoff_model_sequence: u64,
    last_handoff_ms: Option<u64>,
    transitions: u64,
    control_work: u64,
    secondary_sequence: u64,
    secondary_jobs: u64,
    secondary_input: [u64; abi::INPUT_WORDS],
}
impl Coordinator {
    pub(crate) fn new(boot: cyxia_prototype::boot::BootIdentity) -> Self {
        assert!(
            COORDINATOR_CLAIMED
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        );
        let frequency = timer::frequency();
        assert!(frequency >= 1000);
        let origin = timer::ticks();
        CLOCK_ORIGIN.store(origin, Ordering::Release);
        let mut owner = Cores::new(CoreSet::from_bits(15), CoreSet::from_bits(2)).unwrap();
        let threads = [2, 3].map(|slot| {
            Some(
                owner
                    .admit(ThreadSpec {
                        thread_id: slot as u64,
                        budget_milli: 900,
                        allowed_mask: CoreSet::from_bits(1 << slot),
                        assigned_cpu: slot,
                    })
                    .unwrap(),
            )
        });
        let window = 0;
        let spent = [0u64; 2];
        let max_spent = [0u64; 2];
        let weights = [1u64; 2];
        let active_weights = weights;
        let active_policy_sequence = 0u64;
        let window_ticks = [0u64; 2];
        let completions = [0u64; 2];
        let expired = [0u64; 2];
        let windows = [[0u64; 16]; 12];
        let window_receipts = 0usize;
        let service_generation = 1u64;
        let requests = 0u64;
        let successes = 0u64;
        let faults = 0u64;
        let stale = 0u64;
        let preemptions = 0u64;
        let policy_sequence = 0u64;
        let policy_at = origin;
        let request_at = origin.saturating_sub(frequency / 10);
        let sample_at = origin;
        let last_progress = [0u64; 2];
        let input = [0u64; abi::INPUT_WORDS];
        let records = [[0u64; RECORD_WORDS]; RECORDS];
        let publication = 0u64;
        Self {
            #[cfg(feature = "unified-runtime")]
            native: native::CoordinatorState::new(origin),
            boot,
            frequency,
            origin,
            owner,
            threads,
            window,
            spent,
            prepaid: [0; 2],
            max_spent,
            weights,
            active_weights,
            active_policy_sequence,
            window_ticks,
            completions,
            expired,
            windows,
            window_receipts,
            service_generation,
            requests,
            successes,
            faults,
            stale,
            preemptions,
            policy_sequence,
            policy_at,
            request_at,
            sample_at,
            last_progress,
            input,
            records,
            publication,
            wake_pulse: idle::WakePulse::new(frequency / 1000),
            handoff: None,
            handoff_sequence: 0,
            handoff_target: 2,
            handoff_model_sequence: 0,
            last_handoff_ms: None,
            transitions: 0,
            control_work: 0,
            secondary_sequence: 0,
            secondary_jobs: 0,
            secondary_input: [0; abi::INPUT_WORDS],
        }
    }
    /// One bounded CPU0 mechanism turn. Device/network work belongs between turns.
    pub(crate) fn poll(&mut self) {
        #[cfg(feature = "unified-runtime")]
        {
            native::poll(self);
            return;
        }
        check_failures();
        let now = timer::ticks();
        let elapsed = now - self.origin;
        let now_window = elapsed / (self.frequency / 10);
        if cfg!(feature = "unified-runtime") {
            // Budget/deadline waiters may have a saved context but no new
            // mailbox publication. A bounded heartbeat guarantees another turn
            // whenever the CPU0 mechanism broker is making progress.
            if self.wake_pulse.due(now) {
                wake_workers();
            }
            self.poll_handoff(now);
            self.poll_secondary(now);
        }
        // Reap credits before advancing the ledger. A slice from the old window
        // cannot be hidden by reset or by controller restart.
        for slot in 2..4 {
            match DISPATCH[slot].load(Ordering::Acquire) {
                state @ (3 | 4) => {
                    if state == 3 {
                        self.window_ticks[slot - 2] += ELAPSED[slot].load(Ordering::Relaxed);
                        self.completions[slot - 2] += 1;
                        if cfg!(feature = "unified-runtime") {
                            self.control_work = (self.control_work + 1).min(32);
                        }
                    } else {
                        self.expired[slot - 2] += 1;
                    }
                    DISPATCH[slot].store(0, Ordering::Release);
                }
                1 if now_window > self.window => {
                    if DISPATCH[slot]
                        .compare_exchange(1, 0, Ordering::AcqRel, Ordering::Relaxed)
                        .is_ok()
                    {
                        self.expired[slot - 2] += 1;
                    }
                }
                _ => (),
            }
        }
        if now_window > self.window
            && (2..4).all(|slot| DISPATCH[slot].load(Ordering::Acquire) == 0)
        {
            self.windows[self.window_receipts % 12] = [
                self.window + 1,
                self.origin + self.window * (self.frequency / 10),
                self.origin + (self.window + 1) * (self.frequency / 10),
                self.active_policy_sequence,
                self.active_weights[0],
                self.active_weights[1],
                self.spent[0],
                self.spent[1],
                self.window_ticks[0],
                self.window_ticks[1],
                self.completions[0],
                self.completions[1],
                self.expired[0],
                self.expired[1],
                0,
                0,
            ];
            self.window_receipts += 1;
            self.owner.advance_window(now_window).unwrap();
            self.window = now_window;
            self.spent = [0; 2];
            self.prepaid = [0; 2];
            self.window_ticks = [0; 2];
            self.completions = [0; 2];
            self.expired = [0; 2];
            if now - self.policy_at > self.frequency * 10 {
                self.active_weights = [1, 1];
                self.active_policy_sequence = 0;
            } else {
                self.active_weights = self.weights;
                self.active_policy_sequence = self.policy_sequence;
            }
        }
        // Unified requests observe a stable reservation/debit snapshot while
        // business spends predebited credits independently of model progress.
        // A stalled model therefore never closes the business dispatch path.
        if cfg!(feature = "unified-runtime") && now_window == self.window {
            for n in 0..2 {
                if self.prepaid[n] == 0 && self.owner.permits(n + 2, OwnerPlane::Business) {
                    if let Some(thread) = self.threads[n] {
                        let debit = (self.active_weights[n] * 400).min(800) as u16;
                        if self.owner.charge(thread, debit).is_ok() {
                            self.prepaid[n] = u64::from(debit);
                        }
                    }
                }
            }
        }
        match REQUEST.load(Ordering::Acquire) {
            3 | 4 => {
                let state = REQUEST.load(Ordering::Relaxed);
                let accepted_at = timer::ticks();
                let output: [u64; abi::OUTPUT_WORDS] = core::array::from_fn(|n| unsafe {
                    (*output_ptr(1)).0.as_ptr().add(n).read_volatile()
                });
                let end = REQUEST_END.load(Ordering::Relaxed);
                let start = REQUEST_START.load(Ordering::Relaxed);
                let count = RESULT_PREEMPTIONS.load(Ordering::Relaxed);
                self.preemptions += count;
                let current_progress = progress();
                let mut outcome = 0;
                let selected = if cfg!(feature = "unified-runtime") {
                    output[4] & 0xff
                } else {
                    output[4]
                };
                let target = output[4] >> 8;
                let version = if cfg!(feature = "unified-runtime") {
                    2
                } else {
                    1
                };
                if state == 3
                    && output[..4]
                        == [
                            abi::OUTPUT_MAGIC,
                            version,
                            self.requests,
                            self.service_generation,
                        ]
                    && selected < 2
                    && output[7] == self.boot.epoch
                    && accepted_at - self.request_at <= self.frequency / 10
                    && self.owner.snapshot().core_generation == self.input[6]
                    && (!cfg!(feature = "unified-runtime")
                        || (self.owner.snapshot().ledger_generation == self.input[7]
                            && [2, 6].contains(&target)))
                {
                    self.weights = if selected == 0 { [2, 1] } else { [1, 2] };
                    self.policy_sequence = self.requests;
                    self.policy_at = accepted_at;
                    self.successes += 1;
                    outcome = 1;
                    if cfg!(feature = "unified-runtime") {
                        self.control_work = self.control_work.saturating_sub(1);
                        self.propose(target, accepted_at);
                    }
                } else if state == 4 {
                    self.faults += 1;
                    outcome = 2;
                } else {
                    self.stale += 1;
                }
                write_record(
                    &mut self.records,
                    [
                        self.requests,
                        self.service_generation,
                        start,
                        end,
                        self.input[8],
                        self.input[9],
                        self.input[10],
                        self.input[11],
                        selected,
                        output[5],
                        output[6],
                        self.weights[0],
                        self.weights[1],
                        RESULT_KIND.load(Ordering::Relaxed),
                        RESULT_ESR.load(Ordering::Relaxed),
                        count,
                        outcome,
                        self.input[6],
                        self.input[7],
                        (accepted_at - self.request_at) * 1000 / self.frequency,
                        current_progress[0] - self.input[8],
                        current_progress[1] - self.input[9],
                        target,
                        self.input[15],
                    ],
                );
                if state == 4 {
                    self.service_generation = self.service_generation.checked_add(1).unwrap();
                }
                REQUEST.store(0, Ordering::Release);
            }
            _ => (),
        }
        if now - self.request_at >= self.frequency / 10
            && REQUEST.load(Ordering::Acquire) == 0
            && self.handoff.is_none()
        {
            self.requests = self.requests.checked_add(1).unwrap();
            let current_progress = progress();
            let snapshot = self.owner.snapshot();
            self.input = [
                abi::INPUT_MAGIC,
                if cfg!(feature = "unified-runtime") {
                    2
                } else {
                    1
                },
                self.requests,
                self.service_generation,
                now,
                self.frequency,
                snapshot.core_generation,
                snapshot.ledger_generation,
                current_progress[0],
                current_progress[1],
                current_progress[0] - self.last_progress[0],
                current_progress[1] - self.last_progress[1],
                self.window,
                2,
                self.boot.epoch,
                if cfg!(feature = "unified-runtime") {
                    self.control_work
                } else {
                    0
                },
            ];
            self.last_progress = current_progress;
            unsafe {
                (&mut (*input_ptr(1)).0)[..abi::INPUT_WORDS].copy_from_slice(&self.input);
                core::arch::asm!("dsb ish", options(nostack));
            }
            self.request_at = now;
            REQUEST.store(1, Ordering::Release);
            wake_workers();
        }
        let end_window = self.origin + (self.window + 1) * (self.frequency / 10);
        if OVERRUNS.load(Ordering::Acquire) == 0
            && now_window == self.window
            && now.saturating_add(self.frequency / 100) <= end_window
        {
            for slot in 2..4 {
                let n = slot - 2;
                // AI weight chooses at most 4/8 ten-ms credits. Both choices
                // remain below the fixed 90-ms hard admission cap per CPU.
                let limit = if cfg!(feature = "unified-runtime") {
                    self.prepaid[n]
                } else {
                    self.active_weights[n] * 400
                };
                if self.spent[n] < limit
                    && DISPATCH[slot].load(Ordering::Acquire) == 0
                    && self.owner.permits(slot, OwnerPlane::Business)
                    && (slot != 2 || self.handoff.is_none())
                    && self.threads[n].is_some()
                {
                    if !cfg!(feature = "unified-runtime") {
                        self.owner
                            .charge(self.threads[n].unwrap(), SLICE_MILLI)
                            .unwrap();
                    }
                    self.spent[n] += u64::from(SLICE_MILLI);
                    self.max_spent[n] = self.max_spent[n].max(self.spent[n]);
                    EXPIRES[slot].store(end_window, Ordering::Relaxed);
                    DISPATCH[slot].store(1, Ordering::Release);
                    wake_workers();
                }
            }
        }
        if now - self.sample_at >= self.frequency / 100 {
            self.publication = self.publication.checked_add(2).unwrap();
            RUNTIME_V13_EVIDENCE.0[2].store(self.publication - 1, Ordering::SeqCst);
            let snapshot = self.owner.snapshot();
            let p = progress();
            for (index, value) in [
                MAGIC,
                1,
                self.publication - 1,
                now,
                self.frequency,
                self.window,
                snapshot.control.bits(),
                snapshot.business.bits(),
                snapshot.transition.bits(),
                snapshot.quarantined.bits(),
                snapshot.core_generation,
                snapshot.ledger_generation,
                self.service_generation,
                self.requests,
                self.successes,
                self.faults,
                self.preemptions,
                self.stale,
                OVERRUNS.load(Ordering::Acquire),
                p[0],
                p[1],
                TOTAL_TICKS[2].load(Ordering::Acquire),
                TOTAL_TICKS[3].load(Ordering::Acquire),
                self.max_spent[0],
                self.max_spent[1],
                self.active_weights[0],
                self.active_weights[1],
                self.active_policy_sequence,
                protected_count(),
                FAULT_MODE,
                self.origin,
                self.successes + self.faults + self.stale,
            ]
            .into_iter()
            .enumerate()
            {
                put(index, value);
            }
            put(32, self.boot.epoch);
            put(
                33,
                u64::from_le_bytes(self.boot.filesystem[..8].try_into().unwrap()),
            );
            put(
                34,
                u64::from_le_bytes(self.boot.filesystem[8..].try_into().unwrap()),
            );
            put(35, CONTROL_MAX_DEBIT.load(Ordering::Acquire));
            put(36, CONTROL_TICKS.load(Ordering::Acquire));
            put(37, CONTROL_TOTAL_DEBIT.load(Ordering::Acquire));
            put(38, CONTROL_OVERRUNS.load(Ordering::Acquire));
            put(39, MAX_SLICE[1].load(Ordering::Acquire));
            put(40, MAX_SLICE[2].load(Ordering::Acquire));
            put(41, MAX_SLICE[3].load(Ordering::Acquire));
            for (slot, record) in self.records.iter().enumerate() {
                for (index, value) in record.iter().enumerate() {
                    put(64 + slot * RECORD_WORDS + index, *value);
                }
            }
            put(42, self.window_receipts as u64);
            put(43, self.transitions);
            put(44, self.control_work);
            put(45, self.secondary_jobs);
            put(46, STOP_OPERATION.load(Ordering::Acquire));
            put(47, STOP_ACK.load(Ordering::Acquire));
            put(48, STOP_TASK_ACK.load(Ordering::Acquire));
            put(49, STOP_IRQ_ACK.load(Ordering::Acquire));
            put(50, STOP_TLB_ACK.load(Ordering::Acquire));
            put(51, STOP_REF_ACK.load(Ordering::Acquire));
            put(52, DMA_OWNERS.load(Ordering::Acquire));
            put(53, DEVICE_IRQ_OWNERS.load(Ordering::Acquire));
            put(54, PROGRESS[5].load(Ordering::Acquire));
            put(55, self.handoff_model_sequence);
            for (slot, record) in self.windows.iter().enumerate() {
                for (index, value) in record.iter().enumerate() {
                    put(832 + slot * 16 + index, *value);
                }
            }
            // This timestamp follows every acquired receipt included above.
            put(3, timer::ticks());
            RUNTIME_V13_EVIDENCE.0[2].store(self.publication, Ordering::Release);
            self.sample_at = now;
        }
        core::hint::spin_loop();
    }
}

#[used]
#[unsafe(no_mangle)]
static DYNAMIC_V13_EVIDENCE: Evidence = Evidence {
    words: [const { AtomicU64::new(0) }; 512],
};
static STOP_MASKED: AtomicBool = AtomicBool::new(false);

pub(super) fn irq_enter(slot: usize) {
    IRQ_INFLIGHT[slot].fetch_add(1, Ordering::AcqRel);
}
pub(super) fn irq_exit(slot: usize) {
    IRQ_INFLIGHT[slot].fetch_sub(1, Ordering::Release);
}

/// CPU2 alone executes this after leaving EL0 and dropping its dispatch permit.
/// Its dispatcher has already retired the old context before calling here.
pub(super) fn stop_turn(worker: &mut Worker) {
    if cpu::slot() != 2 || FAULT_MODE == 2 {
        return;
    }
    let operation = STOP_OPERATION.load(Ordering::Acquire);
    if operation == 0 || STOP_ACK.load(Ordering::Acquire) == operation || !GATES[2].quiescent() {
        return;
    }
    #[cfg(feature = "unified-runtime")]
    {
        // A returned EL0 context is not yet a stop proof while its CPU bill or
        // a task/PTE owner remains in custody. Each operation is retried later.
        if !native::stop_ready(worker) {
            return;
        }
        // Control-job cleanup already owns its P credit/capture. The local
        // task/IRQ/PTE stop and its acknowledgement are separate E_action CPU.
        native::measure_stop_tail(operation, || stop_action_tail(worker, operation));
        return;
    }
    #[cfg(not(feature = "unified-runtime"))]
    stop_action_tail(worker, operation);
}
fn stop_action_tail(worker: &mut Worker, operation: u64) {
    #[cfg(feature = "unified-runtime")]
    {
        if crate::domain_tasks::close_cpu(2).is_err() || !crate::domain_tasks::quiescent(2) {
            return;
        }
        worker.native.discard();
    }
    worker.context = None;
    if matches!(SECOND_REQUEST.load(Ordering::Acquire), 1 | 2) {
        SECOND_REQUEST.store(4, Ordering::Release);
    }
    let _ = DISPATCH[2].compare_exchange(1, 4, Ordering::AcqRel, Ordering::Relaxed);
    if DISPATCH[2].load(Ordering::Acquire) == 2 {
        return;
    }
    STOP_TASK_ACK.store(operation, Ordering::Release);
    #[cfg(feature = "unified-runtime")]
    heartbeat(false);
    unsafe {
        cpu::disable_timer();
    }
    gic()
        .mask(TIMER_IRQ.load(Ordering::Acquire) as u32)
        .unwrap();
    unsafe {
        core::arch::asm!("dsb sy", "isb", options(nostack));
    }
    if gic().enabled(TIMER_IRQ.load(Ordering::Acquire) as u32)
        || IRQ_INFLIGHT[2].load(Ordering::Acquire) != 0
    {
        return;
    }
    STOP_MASKED.store(true, Ordering::Release);
    STOP_IRQ_ACK.store(operation, Ordering::Release);
    // Real low-walk revocation and architectural completion. No page is reused
    // on a remote CPU's silence; each acknowledged operation is local to CPU2.
    unsafe {
        core::arch::asm!(
        "mrs x9, tcr_el1", "orr x9, x9, #0x80", "msr tcr_el1, x9", "isb",
        "tlbi vmalle1is", "dsb ish", "isb", out("x9") _, options(nostack));
    }
    STOP_TLB_ACK.store(operation, Ordering::Release);
    // Context and user::ACTIVE borrows were retired on the actual return path;
    // CPU2 has no device queue or external service reference admission rights.
    STOP_REF_ACK.store(operation, Ordering::Release);
    STOP_ACK.store(operation, Ordering::Release);
}
pub(super) fn resume_turn(slot: usize) {
    if slot == 2 && STOP_MASKED.swap(false, Ordering::AcqRel) {
        #[cfg(feature = "unified-runtime")]
        native::measure_stop_tail(STOP_OPERATION.load(Ordering::Acquire), resume_action_tail);
        #[cfg(not(feature = "unified-runtime"))]
        resume_action_tail();
    }
}
fn resume_action_tail() {
    #[cfg(feature = "unified-runtime")]
    heartbeat(true);
    gic()
        .enable(TIMER_IRQ.load(Ordering::Acquire) as u32)
        .unwrap();
}

fn secondary_control_step(worker: &mut Worker) {
    assert_eq!(cpu::slot(), 2);
    if CONTROL_OVERRUNS.load(Ordering::Acquire) != 0 {
        return;
    }
    let frequency = timer::frequency();
    let now = timer::ticks();
    let origin = CLOCK_ORIGIN.load(Ordering::Acquire);
    let window = now.saturating_sub(origin) / (frequency / 10);
    if window > worker.window {
        worker.window = window;
        worker.charged = 0;
    }
    if worker.charged + u64::from(SLICE_MILLI) > 700
        || now + frequency / 100 > origin + (window + 1) * (frequency / 10)
    {
        return;
    }
    if worker.context.is_none() {
        if SECOND_REQUEST
            .compare_exchange(1, 2, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        unsafe {
            (*output_ptr(2)).0.fill(0);
            for n in 0..8 {
                (*stack_ptr(2).cast::<Page>().add(n)).0.fill(0);
            }
        }
        worker.context = Some(fresh(0));
        SECOND_START.store(now, Ordering::Relaxed);
    }
    worker.charged += u64::from(SLICE_MILLI);
    let ctx = worker.context.as_mut().unwrap();
    execute(ctx, 5);
    let end = timer::ticks();
    MAX_SLICE[2].fetch_max(end - now, Ordering::Relaxed);
    if end - now > frequency / 100 {
        CONTROL_OVERRUNS.fetch_add(1, Ordering::Release);
    }
    if ctx.kind == 9 && end - SECOND_START.load(Ordering::Relaxed) < frequency / 10 {
        return;
    }
    let valid = ctx.kind == 8
        && ctx.esr >> 26 == 0x15
        && ctx.esr & 0xffff == abi::SUBMIT
        && ctx.regs[0] == abi::OUTPUT_VA
        && ctx.regs[1] == (abi::OUTPUT_WORDS * 8) as u64;
    worker.context = None;
    PROGRESS[5].fetch_add(1, Ordering::Release);
    SECOND_REQUEST.store(if valid { 3 } else { 4 }, Ordering::Release);
}

impl Coordinator {
    fn propose(&mut self, target: u64, now: u64) {
        let state = self.owner.snapshot();
        let ms = now.saturating_sub(self.origin) * 1000 / self.frequency;
        if target == state.control.bits()
            || self.handoff.is_some()
            || self
                .last_handoff_ms
                .is_some_and(|last| ms.saturating_sub(last) < 1000)
        {
            return;
        }
        let Ok(mut handoff) = Handoff::new(&state, target, ms) else {
            return;
        };
        // Close dispatch at its linearization point before publishing draining
        // in the serialized owner. An already-entered permit remains old work.
        let gate = &GATES[2];
        let view = gate.view();
        if !view.enabled || gate.close(view.token.unwrap()).is_err() {
            return;
        }
        let handoff_result = handoff.poll_with_thread(
            &mut self.owner,
            NativeStop::default(),
            ms,
            &mut self.threads[0],
        );
        #[cfg(feature = "unified-runtime")]
        self.capture_ownership();
        if handoff_result.is_err() {
            // An unexpected admission failure leaves the physical fence closed
            // and preserves source obligations, rather than reviving work.
            let _ = self.owner.suspect(2);
            #[cfg(feature = "unified-runtime")]
            self.capture_ownership();
            return;
        }
        self.handoff_sequence += 1;
        self.handoff_target = target;
        self.handoff_model_sequence = self.requests;
        self.handoff = Some(handoff);
        // Revocation is one bounded CAS per turn; no busy wait or cross-module lock.
        #[cfg(feature = "unified-runtime")]
        native::publish_stop_measure(self.handoff_sequence, &self.native);
        STOP_OPERATION.store(self.handoff_sequence, Ordering::Release);
        wake_workers();
        self.last_handoff_ms = Some(ms);
        report(
            "DYNAMIC_V13_DRAIN",
            self.requests,
            target,
            self.handoff_sequence,
        );
    }
    #[cfg(feature = "unified-runtime")]
    fn capture_ownership(&self) {
        let s = self.owner.snapshot();
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
    }
    fn poll_handoff(&mut self, now: u64) {
        if self.handoff.is_none() {
            return;
        }
        let gate = &GATES[2];
        let view = gate.view();
        if view.enabled {
            match gate.close(view.token.unwrap()) {
                Ok(()) | Err(Error::Busy) => (),
                Err(_) => fatal(191),
            }
        }
        let operation = self.handoff_sequence;
        let stop = NativeStop {
            dispatch: gate.quiescent(),
            tasks: STOP_TASK_ACK.load(Ordering::Acquire) == operation,
            irq: STOP_IRQ_ACK.load(Ordering::Acquire) == operation
                && DEVICE_IRQ_OWNERS.load(Ordering::Acquire) & 4 == 0,
            dma: DEVICE_REGISTRY_READY.load(Ordering::Acquire)
                && DMA_OWNERS.load(Ordering::Acquire) & 4 == 0,
            tlb: STOP_TLB_ACK.load(Ordering::Acquire) == operation,
            references: STOP_REF_ACK.load(Ordering::Acquire) == operation,
        };
        let ms = now.saturating_sub(self.origin) * 1000 / self.frequency;
        let result = self.handoff.as_mut().unwrap().poll_with_thread(
            &mut self.owner,
            stop,
            ms,
            &mut self.threads[0],
        );
        #[cfg(feature = "unified-runtime")]
        self.capture_ownership();
        match result {
            Ok(false) => (),
            Ok(true) => {
                self.transitions += 1;
                let state = self.owner.snapshot();
                if self.handoff_target == 2 {
                    // Cores retains source spending through release/re-admission.
                    // If that window lacks capacity, defer business admission to
                    // the next aligned window; ownership publication stays valid.
                    self.admit_movable();
                }
                let generation = gate.view().token.unwrap().generation + 1;
                gate.open(Token {
                    generation,
                    plane: plane(self.handoff_target, 2),
                })
                .unwrap();
                wake_workers();
                let offset = 16 + ((self.transitions - 1) as usize % 16) * 16;
                for (n, value) in [
                    operation,
                    self.handoff_model_sequence,
                    self.last_handoff_ms.unwrap(),
                    ms,
                    self.handoff_target,
                    state.control.bits(),
                    state.business.bits(),
                    state.core_generation,
                    generation,
                    63,
                    PROGRESS[4].load(Ordering::Acquire),
                    PROGRESS[5].load(Ordering::Acquire),
                    PROGRESS[6].load(Ordering::Acquire),
                    self.secondary_jobs,
                    self.control_work,
                    self.boot.epoch,
                ]
                .into_iter()
                .enumerate()
                {
                    DYNAMIC_V13_EVIDENCE.words[offset + n].store(value, Ordering::Relaxed);
                }
                DYNAMIC_V13_EVIDENCE.words[0].store(0x43595844594e3133, Ordering::Relaxed);
                DYNAMIC_V13_EVIDENCE.words[1].store(self.transitions, Ordering::Release);
                report(
                    "DYNAMIC_V13_PUBLISH",
                    self.handoff_model_sequence,
                    self.handoff_target,
                    self.transitions,
                );
                self.handoff = None;
            }
            Err(error) => {
                // Gate remains closed. Missing native completion never resumes
                // old execution or gives CPU2 to another plane.
                report(
                    "DYNAMIC_V13_RECONCILE",
                    operation,
                    self.owner.snapshot().suspect.bits(),
                    error as u64,
                );
                self.handoff = None;
            }
        }
    }
    fn admit_movable(&mut self) {
        if self.threads[0].is_none() && self.owner.permits(2, OwnerPlane::Business) {
            self.threads[0] = self
                .owner
                .admit(ThreadSpec {
                    thread_id: 2,
                    budget_milli: 900,
                    allowed_mask: CoreSet::from_bits(4),
                    assigned_cpu: 2,
                })
                .ok();
        }
    }
    fn poll_secondary(&mut self, _now: u64) {
        match SECOND_REQUEST.load(Ordering::Acquire) {
            3 => {
                let output: [u64; abi::OUTPUT_WORDS] = core::array::from_fn(|n| unsafe {
                    (*output_ptr(2)).0.as_ptr().add(n).read_volatile()
                });
                if output[..4]
                    == [
                        abi::OUTPUT_MAGIC,
                        2,
                        self.secondary_sequence,
                        self.service_generation,
                    ]
                    && output[7] == self.boot.epoch
                    && output[4] & 0xff < 2
                {
                    self.secondary_jobs += 1;
                    self.control_work = self.control_work.saturating_sub(1);
                }
                SECOND_REQUEST.store(0, Ordering::Release);
            }
            4 => {
                SECOND_REQUEST.store(0, Ordering::Release);
            }
            _ => (),
        }
        self.admit_movable();
        if self.control_work == 0
            || self.handoff.is_some()
            || !self.owner.permits(2, OwnerPlane::Control)
            || SECOND_REQUEST.load(Ordering::Acquire) != 0
        {
            return;
        }
        self.secondary_sequence += 1;
        self.secondary_input = self.input;
        self.secondary_input[0] = abi::INPUT_MAGIC;
        self.secondary_input[1] = 2;
        self.secondary_input[2] = self.secondary_sequence;
        self.secondary_input[3] = self.service_generation;
        self.secondary_input[6] = self.owner.snapshot().core_generation;
        self.secondary_input[7] = self.owner.snapshot().ledger_generation;
        self.secondary_input[14] = self.boot.epoch;
        self.secondary_input[15] = self.control_work;
        unsafe {
            (&mut (*input_ptr(2)).0)[..abi::INPUT_WORDS].copy_from_slice(&self.secondary_input);
            core::arch::asm!("dsb ish", options(nostack));
        }
        SECOND_REQUEST.store(1, Ordering::Release);
        wake_workers();
    }
}

/// CPU0's unified boot adapter calls this after attaching every native device.
/// The unified profile admits all driver/DMA/ordinary-IRQ work to CPU0 alone;
/// no EL0 service has MMIO or a route-admission capability for another CPU.
pub(crate) fn register_broker_devices() {
    assert_eq!(cpu::slot(), 0);
    assert!(!DEVICE_REGISTRY_READY.load(Ordering::Acquire));
    DMA_OWNERS.store(1, Ordering::Relaxed);
    DEVICE_IRQ_OWNERS.store(1, Ordering::Relaxed);
    DEVICE_REGISTRY_READY.store(true, Ordering::Release);
}

/// Shared boot-fixed origin for subordinate business ledgers. A service restart
/// cannot create a fresh accounting window or refund execution already spent.
#[cfg(feature = "unified-runtime")]
pub(crate) fn budget_origin() -> u64 {
    CLOCK_ORIGIN.load(Ordering::Acquire)
}

/// Publish memory before signalling the architectural event register. A worker
/// executes a single WFE without first clearing its pending event, so a SEV
/// between its no-work observation and WFE remains observable and cannot be
/// lost. Spurious wakeups simply recheck the actual gate/mailbox state.
pub(crate) fn wake_workers() {
    #[cfg(feature = "unified-runtime")]
    unsafe {
        core::arch::asm!("dsb ishst", "sev", options(nostack));
    }
}
/// Caller owns no Gate permit and no borrowed EL0 context while parked.
/// Standalone selftest profiles retain their existing execution behavior.
pub(super) fn idle_worker() {
    #[cfg(feature = "unified-runtime")]
    unsafe {
        core::arch::asm!("wfe", options(nostack));
    }
    #[cfg(not(feature = "unified-runtime"))]
    core::hint::spin_loop();
}
