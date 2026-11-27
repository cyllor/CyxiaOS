//! Opt-in native multicore execution gate, deliberately separate from the
//! existing CPU0 desktop/shell. Only this bounded workload is certified here.
//! The base control-role program is a deterministic fixture. The retired
//! ai-control-selftest / model-v13-selftest fixtures replay pre-cutover
//! CPU1-control history and build only under the explicit legacy-coreset
//! feature; design §2 fixes control EL0 to CPU0 (cpu0_v0199::CONTROL_MASK).
//! The independent net-selftest branch adds CPU0-owned DMA for EL1 Ethernet
//! bring-up and does not run the core-transition proof fixture. No remote
//! resources, RCU readers or production workers exist in this profile. The
//! resulting proof provider MUST NOT be used by production.
#[cfg(feature = "unified-runtime")]
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use cyxia_arch_aarch64::{cpu, mmu, timer, user};
use cyxia_contracts::{BootInfo, GicResource, PhysAddr};
use cyxia_driver_gicv2::{Gic, IrqAck};
#[cfg(feature = "legacy-coreset")]
use cyxia_kernel_core::control_plane::cores::{Proof, ScaleProposal};
use cyxia_kernel_core::control_plane::{
    Error, Plane,
    cores::{Limits, Ownership},
    dispatch::{Gate, Token},
};
#[cfg(feature = "ai-control-selftest")]
#[path = "../../runtime/control/control_service.rs"]
mod controller;
#[cfg(feature = "model-v13-selftest")]
#[path = "../../runtime/control/prototype_model.rs"]
mod prototype_model;
// RETIREMENT MARKER (design §2: control EL0 runs only on CPU0). Both fixtures
// above are pre-cutover history, not live control topologies: controller::run
// drives Ownership with control=CPU1 and dynamic CPU1<->CPU2 migration, and
// prototype_model installs its EL0 image into CPU1's control root (space 3)
// and asserts cpu::slot()==1. Re-hosting them on CPU0 would falsify the
// retired mechanism they exercise, so they are gated behind the explicit
// legacy-coreset retirement umbrella instead of silently building a CPU1
// control gate. The default smp-selftest profile never compiles them.
#[cfg(all(feature = "ai-control-selftest", not(feature = "legacy-coreset")))]
compile_error!(
    "ai-control-selftest is retired pre-cutover CPU1-control history; enable legacy-coreset explicitly to replay it"
);
#[cfg(all(feature = "model-v13-selftest", not(feature = "legacy-coreset")))]
compile_error!(
    "model-v13-selftest is retired pre-cutover CPU1-control history; enable legacy-coreset explicitly to replay it"
);
#[cfg(feature = "prototype-runtime")]
#[path = "../../runtime/control/prototype_runtime.rs"]
pub(crate) mod prototype_runtime;
#[cfg(feature = "v0199-advice-e2e-selftest")]
#[path = "v0199_advice_e2e.rs"]
mod v0199_advice_e2e;
// V0.20 shares fixed-core PSCI and GIC setup. The explicit diagnostic
// build adds the EL0 fixture, test network identity and scratch media.
#[cfg(feature = "v020-production-diagnostic")]
#[path = "production.rs"]
pub(crate) mod production;
#[cfg(cyxia_startup_catalog)]
#[path = "production/authorized.rs"]
pub(crate) mod production;
#[cfg(all(
    feature = "v020-production",
    not(feature = "v020-production-diagnostic"),
    not(cyxia_startup_catalog)
))]
#[path = "production/resident.rs"]
pub(crate) mod production;
#[cfg(all(
    feature = "v020-production",
    any(
        feature = "v0199-cpu0-role-selftest",
        feature = "v0199-advice-e2e-selftest",
        feature = "v0199-control-bringup",
        feature = "v0199-epoch-disk-selftest",
        feature = "v0199-format-selftest",
        feature = "v0199-sec-n-selftest",
        feature = "ai-control-selftest",
        feature = "legacy-coreset",
        feature = "prototype-runtime",
        feature = "unified-runtime",
        feature = "net-selftest",
        feature = "model-v13-selftest",
        feature = "storage-v13-selftest",
        feature = "tcp-v13-selftest",
    )
))]
compile_error!("v020-production requires the plain smp-selftest profile");
#[cfg(feature = "v0199-cpu0-role-selftest")]
#[path = "v0199_role_selftest.rs"]
mod v0199_role_selftest;
// The advice-chain E2E fixture owns the CPU0 EL0 turn loop and the shared
// execute()/context() mechanism; it must not be combined with another profile
// that also hijacks CPU0 or rewrites the dispatch/execute path.
#[cfg(all(
    feature = "v0199-advice-e2e-selftest",
    any(
        feature = "v0199-cpu0-role-selftest",
        feature = "ai-control-selftest",
        feature = "legacy-coreset",
        feature = "prototype-runtime",
        feature = "unified-runtime",
        feature = "net-selftest",
        feature = "model-v13-selftest",
        feature = "storage-v13-selftest",
        feature = "tcp-v13-selftest",
    )
))]
compile_error!("v0199-advice-e2e-selftest requires the plain smp-selftest profile");
#[cfg(any(
    feature = "v0199-control-bringup",
    feature = "v0199-epoch-disk-selftest"
))]
#[path = "v0199_control_bringup.rs"]
mod v0199_control_bringup;
#[cfg(feature = "v0199-control-bringup")]
pub(super) use v0199_control_bringup::BudgetMeter;
#[cfg(feature = "v0199-d01-scheduler-selftest")]
#[path = "v0199_d01_fixture.rs"]
mod v0199_d01_fixture;
#[cfg(feature = "v0199-epoch-disk-selftest")]
#[path = "v0199_d02_fixture.rs"]
mod v0199_d02_fixture;
#[cfg(feature = "v0199-epoch-disk-selftest")]
#[path = "v0199_d05_fixture.rs"]
mod v0199_d05_fixture;
#[cfg(feature = "v0199-epoch-disk-selftest")]
#[path = "v0199_d07_fixture.rs"]
mod v0199_d07_fixture;
#[cfg(feature = "v0199-d11-rng-selftest")]
#[path = "v0199_d11_fixture.rs"]
mod v0199_d11_fixture;
#[cfg(feature = "v0199-epoch-disk-selftest")]
#[path = "v0199_d15_fixture.rs"]
mod v0199_d15_fixture;
#[cfg(feature = "v0199-epoch-disk-selftest")]
#[path = "v0199_effect_fixture.rs"]
mod v0199_effect_fixture;
#[cfg(feature = "v0199-epoch-disk-selftest")]
#[path = "v0199_epoch_disk.rs"]
mod v0199_epoch_disk;
#[cfg(feature = "v0199-format-selftest")]
#[path = "v0199_format_fixture.rs"]
mod v0199_format_fixture;
// Dedicated scratch VirtIO-blk plumbing, shared by the format fixture and the
// v020 opt-in media-staging lane (production/media_staging.rs).
#[cfg(any(
    feature = "v0199-format-selftest",
    feature = "v020-production-media-staging",
    cyxia_startup_catalog
))]
#[path = "scratch_blk.rs"]
mod scratch_blk;
// SEC-N local-echo guest loader + SVC 0x43 broker, shared by the SEC-N fixture
// and the V0.20 diagnostic boot (production/net.rs).
#[cfg(any(
    feature = "v0199-sec-n-selftest",
    feature = "v020-production-diagnostic"
))]
#[path = "sec_n_broker.rs"]
mod sec_n_broker;
#[cfg(feature = "v0199-sec-n-selftest")]
#[path = "v0199_sec_n_fixture.rs"]
mod v0199_sec_n_fixture;
// The SEC-N deployment fixture owns the CPU0 EL0 turn loop (its own private guest
// TTBR0); it must not be combined with another profile that also hijacks CPU0 or
// rewrites the dispatch/execute path.
#[cfg(all(
    feature = "v0199-sec-n-selftest",
    any(
        feature = "v0199-cpu0-role-selftest",
        feature = "v0199-advice-e2e-selftest",
        feature = "v0199-control-bringup",
        feature = "v0199-epoch-disk-selftest",
        feature = "v0199-format-selftest",
        feature = "ai-control-selftest",
        feature = "legacy-coreset",
        feature = "prototype-runtime",
        feature = "unified-runtime",
        feature = "net-selftest",
        feature = "model-v13-selftest",
        feature = "storage-v13-selftest",
        feature = "tcp-v13-selftest",
    )
))]
compile_error!("v0199-sec-n-selftest requires the plain smp-selftest profile");
#[cfg(feature = "v0199-epoch-disk-selftest")]
#[path = "v0199_ram_inventory.rs"]
mod v0199_ram_inventory;
#[cfg(all(
    feature = "v0199-control-bringup",
    feature = "v0199-epoch-disk-selftest"
))]
compile_error!("epoch scratch disk and role bringup require separate evidence profiles");
#[cfg(all(
    feature = "v0199-format-selftest",
    any(
        feature = "v0199-control-bringup",
        feature = "v0199-epoch-disk-selftest"
    )
))]
compile_error!(
    "format scratch disk requires a separate evidence profile from role bringup and epoch scratch"
);
#[cfg(feature = "register-v15-selftest")]
#[path = "../../diagnostics/register_evidence.rs"]
mod register_evidence;
const C: usize = cyxia_contracts::BOOT_CPUS;
const PRIVATE_SPACES: usize = C * 2
    + if cfg!(feature = "v0199-cpu0-role-selftest") {
        8
    } else {
        0
    }
    + if cfg!(feature = "v0199-advice-e2e-selftest") {
        8
    } else {
        0
    }
    + if cfg!(feature = "v020-production-diagnostic") {
        8
    } else {
        0
    }
    + if cfg!(feature = "v0199-d01-scheduler-selftest") {
        2
    } else {
        0
    };
const EXEC_STACK_BYTES: usize = crate::machine::SMP_EXEC_STACK_BYTES;
const STACK_BYTES: usize = 4096 + EXEC_STACK_BYTES;
const CODE: u64 = 0x10000;
const DATA: u64 = 0x20000;
const STACK: u64 = 0x30000;
#[used]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".cyxia.boot")]
static CYXIA_SMP_PROFILE: [u64; 6] = [1, 4, 8, 1, 0, 0];
const REQUIRED: usize = 4; // Test configuration only; never an AI core-count rule.

core::arch::global_asm!(
    include_str!("../../../../crates/arch-aarch64/src/secondary.S"),
    max_cpus = const C,
    exec_stack_pages = const EXEC_STACK_BYTES / 4096,
);
core::arch::global_asm!(
    include_str!("smp_user.S"),
    d02_enabled = const cfg!(feature = "v0199-epoch-disk-selftest") as u8,
    d01_enabled = const cfg!(feature = "v0199-d01-scheduler-selftest") as u8,
);
#[cfg(feature = "v0199-advice-e2e-selftest")]
core::arch::global_asm!(include_str!("v0199_advice_user.S"));
#[repr(C, align(4096))]
struct Page([u64; 512]);
impl Page {
    const ZERO: Self = Self([0; 512]);
}
#[repr(C, align(4096))]
struct Stacks([u8; C * STACK_BYTES]);
static mut STACKS: Stacks = Stacks([0; C * STACK_BYTES]);
#[unsafe(no_mangle)]
static mut SMP_STACK_TOPS: [u64; C] = [0; C];
// CPU0 writes these before releasing BOOT_READY. Thereafter only CPU i writes
// the two data/stack pages belonging to its slot; tables are never modified.
static mut ROOTS: [Page; PRIVATE_SPACES] = [const { Page::ZERO }; PRIVATE_SPACES];
static mut MIDDLES: [Page; PRIVATE_SPACES] = [const { Page::ZERO }; PRIVATE_SPACES];
static mut LEAVES: [Page; PRIVATE_SPACES] = [const { Page::ZERO }; PRIVATE_SPACES];
static mut DATA_PAGES: [Page; PRIVATE_SPACES] = [const { Page::ZERO }; PRIVATE_SPACES];
static mut USER_STACKS: [Page; PRIVATE_SPACES] = [const { Page::ZERO }; PRIVATE_SPACES];
static mut GICS: [Option<Gic>; C] = [const { None }; C];
static mut RESOURCE: Option<GicResource> = None;
static AFFINITIES: [AtomicU64; C] = [const { AtomicU64::new(u64::MAX) }; C];
static BOOT_READY: AtomicBool = AtomicBool::new(false);
static ONLINE: AtomicU64 = AtomicU64::new(1);
static QUIT: AtomicBool = AtomicBool::new(false);
static STOPPED: AtomicU64 = AtomicU64::new(0);
static TIMER_IRQ: AtomicU64 = AtomicU64::new(0);
static GATES: [Gate; C] = [const { Gate::new() }; C];
static PROGRESS: [AtomicU64; C * 2] = [const { AtomicU64::new(0) }; C * 2];
static IRQS: [AtomicU64; C] = [const { AtomicU64::new(0) }; C];
static FAULT_PROBES: [AtomicU64; C] = [const { AtomicU64::new(0) }; C];
static FAILURES: [AtomicU64; C] = [const { AtomicU64::new(0) }; C];
static LAST_ESR: [AtomicU64; C] = [const { AtomicU64::new(0) }; C];
#[repr(C, align(4096))]
pub struct Evidence {
    pub words: [AtomicU64; 512],
}
#[used]
#[unsafe(no_mangle)]
pub static SMP_EVIDENCE: Evidence = Evidence {
    words: [const { AtomicU64::new(0) }; 512],
};
static LAST_FAR: [AtomicU64; C] = [const { AtomicU64::new(0) }; C];
/// Sticky original fatal context. CPU0's later secondary-failure panic does
/// not carry the faulting CPU's ELR/FAR, and its UART frame may still be queued.
#[cfg(feature = "unified-runtime")]
#[repr(C, align(64))]
struct FaultEvidence([AtomicU64; 8 + C * 8]);
#[cfg(feature = "unified-runtime")]
#[used]
#[unsafe(no_mangle)]
static SMP_FAULT_EVIDENCE: FaultEvidence = FaultEvidence([const { AtomicU64::new(0) }; 8 + C * 8]);
#[cfg(feature = "unified-runtime")]
static HEARTBEAT: [AtomicBool; C] = [const { AtomicBool::new(false) }; C];
#[cfg(feature = "unified-runtime")]
#[repr(C, align(64))]
struct SliceTiming {
    words: [AtomicU64; 128],
}
#[cfg(feature = "unified-runtime")]
impl SliceTiming {
    const fn new() -> Self {
        let mut words = [const { AtomicU64::new(0) }; 128];
        words[0] = AtomicU64::new(0x4359_534c_4943_4501);
        words[1] = AtomicU64::new(1);
        Self { words }
    }
}
#[cfg(feature = "unified-runtime")]
#[used]
#[unsafe(no_mangle)]
static TASK_SLICE_EVIDENCE: SliceTiming = SliceTiming::new();
#[cfg(feature = "unified-runtime")]
static RECORD_SLICE_EXCEPTION: [AtomicBool; C] = [const { AtomicBool::new(false) }; C];
#[cfg(feature = "unified-runtime")]
static BUILTIN_CAPTURE_READY: [AtomicBool; C] = [const { AtomicBool::new(false) }; C];
#[cfg(feature = "unified-runtime")]
static BUILTIN_CAPTURE_INDEX: [AtomicU64; C] = [const { AtomicU64::new(u64::MAX) }; C];
#[cfg(feature = "unified-runtime")]
#[repr(C, align(64))]
struct BuiltinDetail([UnsafeCell<[u64; 8]>; 4]);
#[cfg(feature = "unified-runtime")]
unsafe impl Sync for BuiltinDetail {}
#[cfg(feature = "unified-runtime")]
#[used]
#[unsafe(no_mangle)]
static BUILTIN_TASK_DETAIL: BuiltinDetail = BuiltinDetail([const { UnsafeCell::new([0; 8]) }; 4]);
#[cfg(feature = "unified-runtime")]
fn builtin_detail(slot: usize, phase: usize) {
    if slot >= 4 || phase >= 8 {
        return;
    }
    let row = BUILTIN_TASK_DETAIL.0[slot].get().cast::<u64>();
    unsafe {
        if phase + 1 < 8 {
            row.add(phase + 1).write_volatile(0);
        }
        row.add(phase).write_volatile(timer::cpu_ticks());
    }
}
#[cfg(feature = "unified-runtime")]
const _: () = assert!(core::mem::size_of::<BuiltinDetail>() == 256);
unsafe extern "C" {
    static cyxia_secondary_start: u8;
    static smp_user_start: u8;
    static smp_user_end: u8;
    static ram_l3: u8;
    #[cfg(feature = "v0199-advice-e2e-selftest")]
    static v0199_advice_user_start: u8;
    #[cfg(feature = "v0199-advice-e2e-selftest")]
    static v0199_advice_user_end: u8;
}
#[cfg(not(cyxia_signed_resident))]
fn index(slot: usize, plane: Plane) -> usize {
    slot * 2 + usize::from(plane == Plane::Control)
}
fn phys(address: u64) -> u64 {
    address
        .checked_sub(super::HIGH)
        .expect("high kernel pointer")
}
#[cfg(feature = "unified-runtime")]
fn builtin_asid(root: u64) -> u8 {
    let first = phys(core::ptr::addr_of!(ROOTS) as u64);
    let stride = core::mem::size_of::<Page>() as u64;
    let offset = root.checked_sub(first).expect("builtin root below fixture");
    assert!(offset % stride == 0);
    let index = offset / stride;
    assert!(index < (C * 2) as u64);
    0x90 + u8::try_from(index).expect("builtin root index")
}
fn cookie(i: usize) -> u64 {
    0x43595800 + i as u64
}
fn deadline() -> u64 {
    timer::ticks()
        .checked_add(timer::frequency() * 5)
        .expect("deadline")
}
pub(crate) fn gic() -> &'static Gic {
    // Each slot is initialized on its own CPU before it enables interrupts.
    unsafe {
        (&*core::ptr::addr_of!(GICS)
            .cast::<Option<Gic>>()
            .add(cpu::slot()))
            .as_ref()
            .unwrap()
    }
}
fn report_payload<'a>(data: &'a mut [u8], label: &str, a: u64, b: u64, c: u64) -> &'a [u8] {
    // All resident reports use this fixed decimal format. Direct writes
    // keep the EL1 telemetry call graph independent of formatter vtables.
    let mut used = label.len();
    data[..used].copy_from_slice(label.as_bytes());
    for (prefix, mut value) in [(b" a=", a), (b" b=", b), (b" c=", c)] {
        let mut decimal = [0; 20];
        let mut start = decimal.len();
        loop {
            start -= 1;
            decimal[start] = b'0' + (value % 10) as u8;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        let after_prefix = used + prefix.len();
        data[used..after_prefix].copy_from_slice(prefix);
        used = after_prefix + decimal.len() - start;
        data[after_prefix..used].copy_from_slice(&decimal[start..]);
    }
    data[used] = b'\n';
    &data[..=used]
}
fn report(label: &str, a: u64, b: u64, c: u64) {
    // CPU0 alone owns the framed UART writer; secondary CPUs publish atomics.
    let mut data = [0; 192];
    super::log(report_payload(&mut data, label, a, b, c));
}
pub(super) fn check_failures() {
    for i in 1..REQUIRED {
        let error = FAILURES[i].load(Ordering::Acquire);
        if error != 0 {
            report(
                "SMP_ERROR",
                i as u64,
                error,
                LAST_ESR[i].load(Ordering::Acquire),
            );
            report(
                "SMP_ERROR_FAR",
                i as u64,
                LAST_FAR[i].load(Ordering::Acquire),
                0,
            );
            panic!("secondary failure");
        }
    }
}
fn wait(mut condition: impl FnMut() -> bool) {
    let end = deadline();
    while !condition() {
        check_failures();
        if timer::ticks() >= end {
            panic!("SMP deadline");
        }
        core::hint::spin_loop();
    }
}
pub fn fatal(code: u64) -> ! {
    #[cfg(feature = "unified-runtime")]
    record_fault(code, 0, None);
    stop_failed(code)
}
#[cfg(feature = "unified-runtime")]
fn record_fault(code: u64, kind: u64, frame: Option<&super::ExceptionFrame>) {
    let slot = cpu::slot();
    if slot >= C {
        return;
    }
    let bank = &SMP_FAULT_EVIDENCE.0;
    let base = 8 + slot * 8;
    if bank[base]
        .compare_exchange(0, u64::MAX, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    // Independent rows have a single writer. Code is the row's release seal;
    // u64::MAX means an incomplete fatal capture, never a healthy snapshot.
    let context = frame.map_or([0; 5], |f| {
        [f.esr, f.far, f.elr, f.spsr, f as *const _ as u64]
    });
    bank[base + 1].store(timer::ticks(), Ordering::Relaxed);
    bank[base + 2].store(kind, Ordering::Relaxed);
    for (index, value) in context.into_iter().enumerate() {
        bank[base + 3 + index].store(value, Ordering::Relaxed);
    }
    bank[1].store(1, Ordering::Relaxed);
    bank[2].store(C as u64, Ordering::Relaxed);
    bank[3].store(8, Ordering::Relaxed);
    bank[base].store(code, Ordering::Release);
    bank[0].store(0x4359_534d_5046_4131, Ordering::Release);
}
#[cfg(feature = "v020-production")]
fn stop_failed(code: u64) -> ! {
    crate::machine::panic_stop::stop(code)
}

#[cfg(not(feature = "v020-production"))]
fn stop_failed(code: u64) -> ! {
    if let Some(failure) = cpu::registered_slot().and_then(|slot| FAILURES.get(slot)) {
        failure.store(code, Ordering::Release);
    }
    super::halt()
}
/// Handle only this profile's private timer and EL0 traps. No production global
/// IRQ singleton or CPU0 user scheduler is touched by a secondary CPU.
pub fn exception(frame: &mut super::ExceptionFrame, kind: u64) {
    let slot = cpu::slot();
    #[cfg(feature = "unified-runtime")]
    if slot < 4 && RECORD_SLICE_EXCEPTION[slot].load(Ordering::Acquire) && matches!(kind, 8 | 9) {
        let row = 2 + slot * 30;
        TASK_SLICE_EVIDENCE.words[row + 7].store(timer::ticks(), Ordering::Relaxed);
        TASK_SLICE_EVIDENCE.words[row + 8].store(kind, Ordering::Relaxed);
        TASK_SLICE_EVIDENCE.words[row + 9].store(frame.esr, Ordering::Relaxed);
        TASK_SLICE_EVIDENCE.words[row + 10].store(frame.far, Ordering::Relaxed);
        TASK_SLICE_EVIDENCE.words[row + 11].store(frame.elr, Ordering::Relaxed);
    }
    LAST_ESR[slot].store(frame.esr, Ordering::Relaxed);
    LAST_FAR[slot].store(frame.far, Ordering::Relaxed);
    if kind == 9 || kind == 5 {
        #[cfg(feature = "unified-runtime")]
        let irq_started = timer::ticks();
        #[cfg(feature = "prototype-runtime")]
        prototype_runtime::irq_enter(slot);
        let ack = gic().acknowledge();
        match ack {
            IrqAck::Active { id, .. } if id as u64 == TIMER_IRQ.load(Ordering::Relaxed) => {
                #[cfg(feature = "v020-production-authenticated-net")]
                let active_poll;
                unsafe {
                    #[cfg(feature = "unified-runtime")]
                    if HEARTBEAT[slot].load(Ordering::Acquire) {
                        timer::arm(timer::ticks().saturating_add(heartbeat_ticks()));
                    } else {
                        cpu::disable_timer();
                    }
                    #[cfg(not(feature = "unified-runtime"))]
                    cpu::disable_timer();
                    #[cfg(feature = "v020-production-authenticated-net")]
                    {
                        active_poll = slot == 0 && kind == 5 && sec_n_broker::rearm_active_poll_timer();
                    }
                    #[cfg(any(
                        feature = "v020-production-signed-resident",
                        all(
                            feature = "v020-production",
                            not(feature = "v020-production-diagnostic")
                        )
                    ))]
                    if slot == 0 && kind == 5 {
                        timer::arm(production::timer_deadline());
                    }
                }
                #[cfg(feature = "unified-runtime")]
                if slot < 4 {
                    TASK_SLICE_EVIDENCE.words[2 + slot * 30 + 20]
                        .store(irq_started, Ordering::Relaxed);
                    TASK_SLICE_EVIDENCE.words[2 + slot * 30 + 21].fetch_add(1, Ordering::Relaxed);
                }
                IRQS[slot].fetch_add(1, Ordering::Relaxed);
                gic().end(ack);
                #[cfg(feature = "prototype-runtime")]
                prototype_runtime::irq_exit(slot);
                #[cfg(feature = "v020-production-authenticated-net")]
                if active_poll {
                    return;
                }
            }
            #[cfg(feature = "unified-runtime")]
            IrqAck::Active { id: 0, .. } => {
                gic().end(ack);
                crate::domain_platform::ipi_enter(slot);
                prototype_runtime::irq_exit(slot);
            }
            #[cfg(feature = "unified-runtime")]
            IrqAck::Active { id, .. } => {
                let owner = crate::domain_platform::irq_key(id).unwrap_or(
                    cyxia_prototype::domains::ObjectKey {
                        id: u64::from(id),
                        generation: 1,
                    },
                );
                crate::learning_evidence::measure(
                    owner,
                    cyxia_prototype::learning::reward::CpuClass::ExecutorWork,
                    || {
                        let registered =
                            crate::domain_platform::irq_enter(gic(), id, slot, irq_started);
                        if !registered {
                            let _ = gic().mask(id);
                            crate::domain_platform::unknown_irq();
                        }
                        gic().end(ack);
                        if registered {
                            crate::domain_platform::irq_complete(id);
                        }
                    },
                );
                prototype_runtime::irq_exit(slot);
            }
            #[cfg(feature = "unified-runtime")]
            IrqAck::Spurious => {
                prototype_runtime::irq_exit(slot);
            }
            #[cfg(any(
                feature = "v020-production-signed-resident",
                all(
                    feature = "v020-production",
                    not(feature = "v020-production-diagnostic")
                )
            ))]
            IrqAck::Spurious if kind == 5 => {}
            #[cfg(all(
                feature = "v020-production-authenticated-net",
                not(feature = "unified-runtime")
            ))]
            IrqAck::Spurious
                if slot == 0 && kind == 5 && sec_n_broker::rearm_active_poll_timer() => return,
            #[cfg(not(feature = "unified-runtime"))]
            _ => fatal(10 + kind),
        }
        #[cfg(any(
            feature = "unified-runtime",
            feature = "v020-production-signed-resident",
            all(
                feature = "v020-production",
                not(feature = "v020-production-diagnostic")
            )
        ))]
        if kind == 5 {
            return;
        }
    }
    if (kind == 8 || kind == 9)
        && let Some(pc) = unsafe {
            user::capture(
                &frame.regs,
                frame.elr,
                frame.spsr,
                frame.esr,
                frame.far,
                kind,
            )
        }
    {
        frame.elr = pc;
        frame.spsr = 0x3c5;
        return;
    }
    #[cfg(feature = "unified-runtime")]
    record_fault(40 + kind, kind, Some(frame));
    stop_failed(40 + kind)
}
unsafe fn init_memory() {
    unsafe {
        let code = core::ptr::addr_of!(smp_user_start) as u64;
        let end = core::ptr::addr_of!(smp_user_end) as u64;
        assert!(code.is_multiple_of(4096) && end - code <= 4096);
        for i in 0..PRIVATE_SPACES {
            let root = core::ptr::addr_of_mut!(ROOTS).cast::<Page>().add(i);
            let mid = core::ptr::addr_of_mut!(MIDDLES).cast::<Page>().add(i);
            let leaf = core::ptr::addr_of_mut!(LEAVES).cast::<Page>().add(i);
            let data = core::ptr::addr_of_mut!(DATA_PAGES).cast::<Page>().add(i);
            let stack = core::ptr::addr_of_mut!(USER_STACKS).cast::<Page>().add(i);
            (*root).0[0] = phys(mid as u64) | 3;
            (*mid).0[0] = phys(leaf as u64) | 3;
            (*leaf).0[(CODE / 4096) as usize] =
                mmu::encode_user_leaf(PhysAddr(phys(code)), false, true).unwrap();
            (*leaf).0[(DATA / 4096) as usize] =
                mmu::encode_user_leaf(PhysAddr(phys(data as u64)), true, false).unwrap();
            (*leaf).0[(STACK / 4096) as usize] =
                mmu::encode_user_leaf(PhysAddr(phys(stack as u64)), true, false).unwrap();
            (*data).0[0] = cookie(i);
        }
        init_secondary_stacks();
    }
}

/// Install guard pages and stack tops before permitting any PSCI CPU_ON.
unsafe fn init_secondary_stacks() {
    unsafe {
        let base = core::ptr::addr_of_mut!(STACKS) as u64;
        let boot_leaves = (core::ptr::addr_of!(ram_l3) as u64 + super::HIGH) as *mut u64;
        for slot in 0..C {
            let guard = base + slot as u64 * STACK_BYTES as u64;
            let page = (phys(guard) - cyxia_platform_virt::RAM_BASE) / 4096;
            boot_leaves.add(page as usize).write_volatile(0);
            (*core::ptr::addr_of_mut!(SMP_STACK_TOPS))[slot] = guard + STACK_BYTES as u64;
        }
        core::arch::asm!(
            "dsb ishst",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            options(nostack)
        );
    }
}

#[cfg(feature = "v020-production")]
fn bring_up_production(info: &BootInfo) {
    assert_eq!(cpu::slot(), 0);
    if info.cpu_count != REQUIRED {
        report(
            "SMP_REJECT_CPU_COUNT",
            info.cpu_count as u64,
            REQUIRED as u64,
            0,
        );
        panic!("unsupported CPU count for V0.20");
    }
    let topo = cyxia_platform_virt::cpu_topology(info, cpu::affinity()).expect("PSCI topology");
    assert_eq!(topo.count, REQUIRED);
    let mut resource = info.gic.unwrap();
    resource.distributor.0 += super::HIGH;
    resource.cpu.0 += super::HIGH;
    let irq = info.timer_irq.unwrap();
    assert!((16..32).contains(&irq));
    TIMER_IRQ.store(irq as u64, Ordering::Relaxed);
    // SAFETY: CPU0 owns these pre-SMP writes. The DTB-validated resources use
    // the mapped high Device alias. BOOT_READY releases all state to workers.
    unsafe {
        *core::ptr::addr_of_mut!(RESOURCE) = Some(resource);
        *core::ptr::addr_of_mut!(GICS).cast::<Option<Gic>>() = Some(Gic::new(resource).unwrap());
        #[cfg(feature = "v020-production-diagnostic")]
        init_memory();
        #[cfg(not(feature = "v020-production-diagnostic"))]
        init_secondary_stacks();
    }
    for (slot, affinity) in AFFINITIES.iter().enumerate().take(topo.count) {
        affinity.store(topo.affinity[slot], Ordering::Release);
    }
    crate::machine::panic_stop::register_cpu(gic(), 0);
    BOOT_READY.store(true, Ordering::Release);
    unsafe {
        core::arch::asm!("dsb sy", options(nostack));
    }
    let entry = core::ptr::addr_of!(cyxia_secondary_start) as u64;
    assert!((cyxia_platform_virt::ENTRY..cyxia_platform_virt::ENTRY + 4096).contains(&entry));
    for slot in 1..topo.count {
        // SAFETY: affinity and conduit came from DTB topology. The assembly
        // entry verifies the slot and enters with its prepared stack.
        let result = unsafe { cpu::start(topo.conduit, topo.affinity[slot], entry, slot as u64) };
        report(
            "SMP_CPU_ON",
            slot as u64,
            topo.affinity[slot],
            result as u64,
        );
        assert_eq!(result, 0, "CPU_ON must report success");
    }
    let online = (1 << REQUIRED) - 1;
    wait(|| ONLINE.load(Ordering::Acquire) == online);
    crate::machine::panic_stop::publish_ready(online);
    report("SMP_BOOT_OK", topo.count as u64, online, 0);
    #[cfg(feature = "v020-panic-stop-selftest")]
    crate::machine::panic_stop::exercise();
}

// SAFETY: called only after the stop coordinator acquires its registered
// four-CPU ready state. Each CPU published its own GIC interface before that.
#[cfg(feature = "v020-production")]
pub(super) unsafe fn gic_for_terminal_stop(slot: usize) -> Option<&'static Gic> {
    if slot >= REQUIRED {
        return None;
    }
    unsafe { (&*core::ptr::addr_of!(GICS).cast::<Option<Gic>>().add(slot)).as_ref() }
}
#[cfg(not(cyxia_startup_catalog))]
fn context(i: usize) -> user::Context {
    let mut ctx = user::Context::empty();
    ctx.pc = CODE;
    ctx.sp = STACK + 4096;
    ctx.regs[0] = cookie(i);
    ctx.regs[1] = DATA;
    #[cfg(feature = "unified-runtime")]
    {
        // Only the production-style unified fixture may return voluntarily.
        // The SMP self-test keeps mode zero so every completed turn still
        // proves private-timer preemption; probe contexts overwrite this mode.
        ctx.regs[2] = 4;
    }
    ctx.tpidr_el0 = cookie(i);
    for r in 0..32 {
        ctx.simd[r] = [cookie(i), r as u64];
    }
    ctx
}
#[cfg(feature = "unified-runtime")]
fn builtin_capture_task(slot: usize, i: usize) -> crate::a02_capture::Task {
    crate::a02_capture::Task {
        id: 0x534d_5000 + i as u64,
        generation: 1,
        role: 1,
        affinity: 1 << slot,
    }
}
#[cfg(feature = "unified-runtime")]
fn prepare_builtin_capture(slot: usize, i: usize) -> bool {
    if BUILTIN_CAPTURE_READY[slot].load(Ordering::Acquire) {
        return true;
    }
    let encoded = crate::a02_capture::prepare(builtin_capture_task(slot, i))
        .and_then(|index| u64::try_from(index).ok())
        .unwrap_or(u64::MAX);
    BUILTIN_CAPTURE_INDEX[slot].store(encoded, Ordering::Relaxed);
    BUILTIN_CAPTURE_READY[slot].store(true, Ordering::Release);
    false
}
#[cfg(feature = "unified-runtime")]
fn builtin_capture_index(slot: usize) -> Option<usize> {
    if !BUILTIN_CAPTURE_READY[slot].load(Ordering::Acquire) {
        return None;
    }
    let encoded = BUILTIN_CAPTURE_INDEX[slot].load(Ordering::Relaxed);
    if encoded == u64::MAX {
        None
    } else {
        usize::try_from(encoded).ok()
    }
}
#[cfg(not(cyxia_startup_catalog))]
fn execute(ctx: &mut user::Context, i: usize) {
    let root = unsafe { core::ptr::addr_of!(ROOTS).cast::<Page>().add(i) as u64 };
    let quantum = (timer::frequency() / 1000).max(1);
    #[cfg(feature = "unified-runtime")]
    let quantum = if matches!(cpu::slot(), 2 | 3) && !matches!(i, 3 | 5) {
        crate::domain_tasks::active_slice_ticks(cpu::slot())
            .map_or(quantum, |slice| quantum.min(slice.max(1)))
    } else {
        quantum
    };
    // IRQs stay masked in EL1; only user::enter enables EL0 interrupt delivery.
    // A non-yielding user program must be forcibly returned by the private PPI.
    unsafe {
        #[cfg(feature = "unified-runtime")]
        enter_builtin_service(
            ctx,
            phys(root),
            timer::ticks().saturating_add(quantum),
            crate::a02_capture::Task {
                role: if i % 2 == 1 { 2 } else { 1 },
                ..builtin_capture_task(cpu::slot(), i)
            },
            builtin_capture_index(cpu::slot()),
            true,
            false,
        );
        #[cfg(not(feature = "unified-runtime"))]
        {
            timer::arm(timer::ticks().saturating_add(quantum));
            user::enter(ctx, phys(root));
            cpu::disable_timer();
        }
    }
}
#[cfg(feature = "unified-runtime")]
fn fixture_yielded(ctx: &user::Context) -> bool {
    ctx.kind == 9 || ctx.kind == 8 && ctx.esr >> 26 == 0x15 && ctx.esr & 0xffff == 4
}
#[cfg(feature = "unified-runtime")]
fn fixture_context_valid(ctx: &user::Context, i: usize) -> bool {
    if !fixture_yielded(ctx) || ctx.regs[0] != cookie(i) || ctx.tpidr_el0 != cookie(i) {
        return false;
    }
    let expected = cookie(i);
    let mut simd = ctx.simd.as_ptr();
    let valid: u64;
    // Validate every saved 128-bit Q register with a fixed AArch64 loop. The
    // generic iterator path adds sizeable translated control flow after the
    // architectural return even though the evidence shape is fixed at 32.
    unsafe {
        core::arch::asm!(
            "mov x9, #0",
            "2:",
            "ldp x10, x11, [{simd}], #16",
            "cmp x10, {expected}",
            "b.ne 3f",
            "cmp x11, x9",
            "b.ne 3f",
            "add x9, x9, #1",
            "cmp x9, #32",
            "b.ne 2b",
            "mov {valid}, #1",
            "b 4f",
            "3:",
            "mov {valid}, #0",
            "4:",
            simd = inout(reg) simd => _,
            expected = in(reg) expected,
            valid = out(reg) valid,
            out("x9") _,
            out("x10") _,
            out("x11") _,
            options(nostack, readonly),
        );
    }
    valid != 0
}
#[cfg(all(
    not(feature = "unified-runtime"),
    not(cyxia_signed_resident)
))]
fn fixture_yielded(ctx: &user::Context) -> bool {
    ctx.kind == 9
}
#[cfg(not(cyxia_signed_resident))]
fn probes(slot: usize, i: usize) {
    // Probe an EL1-only address, an unmapped private address, code write, NX data,
    // and the user stack guard. A successful access/SVC is failure, not evidence.
    let kernel_address = (core::ptr::addr_of!(BOOT_READY) as u64) & !7;
    for (mode, address, ec, fsc) in [
        (1, kernel_address, 0x24, 0x0f),
        (1, 0x40000, 0x24, 0x07),
        (2, CODE, 0x24, 0x4f),
        (3, DATA, 0x20, 0x0f),
        (2, STACK - 4096, 0x24, 0x47),
    ] {
        let mut ctx = context(i);
        ctx.regs[1] = address;
        ctx.regs[2] = mode;
        // A timer may preempt a probe before the access. Resume, don't confuse
        // an IRQ with a permission fault. No new authority is created here.
        let end = deadline();
        loop {
            execute(&mut ctx, i);
            if ctx.kind != 9 {
                break;
            }
            if timer::ticks() >= end {
                fatal(70);
            }
        }
        if ctx.kind != 8 || ctx.esr >> 26 != ec || ctx.far != address || ctx.esr & 0x7f != fsc {
            fatal(71 + mode);
        }
        FAULT_PROBES[slot].fetch_add(1, Ordering::Release);
    }
}
#[unsafe(no_mangle)]
extern "C" fn secondary_entry(slot: usize) -> ! {
    if slot != cpu::slot() || slot >= C {
        fatal(1);
    }
    while !BOOT_READY.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }
    if cpu::affinity() != AFFINITIES[slot].load(Ordering::Acquire) {
        fatal(2);
    }
    #[cfg(any(feature = "unified-runtime", feature = "v0199-epoch-disk-selftest"))]
    unsafe {
        timer::init_cpu_accounting();
    }
    let resource = unsafe { (*core::ptr::addr_of!(RESOURCE)).unwrap() };
    let controller = unsafe { Gic::attach_cpu(resource) }.unwrap();
    controller
        .enable(TIMER_IRQ.load(Ordering::Acquire) as u32)
        .unwrap();
    unsafe {
        *core::ptr::addr_of_mut!(GICS)
            .cast::<Option<Gic>>()
            .add(slot) = Some(controller);
    }
    #[cfg(feature = "v020-production")]
    crate::machine::panic_stop::register_cpu(gic(), slot);
    #[cfg(feature = "unified-runtime")]
    {
        crate::domain_platform::register_ipi_cpu(gic(), slot).expect("IPI CPU registration");
        // A real fixed hard tick remains armed while EL1 does bounded setup or
        // waits for work. Timer/IRQ progress cannot depend on an EL0 admission.
        heartbeat(true);
        unsafe {
            timer::enable_irqs();
        }
    }
    #[cfg(feature = "unified-runtime")]
    crate::boot_recovery::formal::el1();
    ONLINE.fetch_or(1 << slot, Ordering::Release);
    #[cfg(feature = "v020-panic-stop-late-selftest")]
    crate::machine::panic_stop::hold_healthy_peer_until_result(slot);
    #[cfg(feature = "register-v15-selftest")]
    register_evidence::worker(slot);
    #[cfg(any(
        feature = "v020-production-signed-resident",
        all(
            feature = "v020-production",
            not(feature = "v020-production-diagnostic")
        )
    ))]
    {
        // Startup has yet to authorize any business EL0. The parked CPUs stay
        // online with their exception vectors and interrupt interfaces active.
        unsafe { timer::enable_irqs() };
        loop {
            timer::idle();
        }
    }
    #[cfg(all(
        not(feature = "v020-production-signed-resident"),
        any(
            not(feature = "v020-production"),
            feature = "v020-production-diagnostic"
        )
    ))]
    secondary_work(slot)
}

#[cfg(all(
    not(feature = "v020-production-signed-resident"),
    any(
        not(feature = "v020-production"),
        feature = "v020-production-diagnostic"
    )
))]
fn secondary_work(slot: usize) -> ! {
    let mut contexts = [context(slot * 2), context(slot * 2 + 1)];
    let mut tested = [false; 2];
    #[cfg(feature = "prototype-runtime")]
    let mut runtime_worker = prototype_runtime::Worker::new();
    #[cfg(feature = "ai-control-selftest")]
    let mut service_context = controller::context();
    while !QUIT.load(Ordering::Acquire) {
        let view = GATES[slot].view();
        if !view.enabled {
            #[cfg(feature = "prototype-runtime")]
            if slot == 2 {
                // Retire contexts before publishing task/reference stop events.
                contexts = [context(slot * 2), context(slot * 2 + 1)];
                prototype_runtime::stop_turn(&mut runtime_worker);
            }
            #[cfg(feature = "prototype-runtime")]
            prototype_runtime::idle_worker();
            #[cfg(not(feature = "prototype-runtime"))]
            core::hint::spin_loop();
            continue;
        }
        #[cfg(feature = "prototype-runtime")]
        prototype_runtime::resume_turn(slot);
        let Some(token) = view.token else {
            fatal(3);
        };
        let Ok(permit) = GATES[slot].try_enter(token) else {
            continue;
        };
        // The native D02 diagnostic worker is admitted only under the
        // ordinary fixed business gate. It exclusively reuses the dormant
        // private slot 3 after actual architectural stop/TLBI/scrub.
        #[cfg(feature = "v0199-epoch-disk-selftest")]
        if slot == 1
            && token.plane == Plane::Business
            && (v0199_d02_fixture::worker_step() || v0199_d05_fixture::worker_step())
        {
            drop(permit);
            continue;
        }
        #[cfg(feature = "v0199-d01-scheduler-selftest")]
        if slot == 1
            && token.plane == Plane::Business
            && v0199_d01_fixture::worker_step(token.generation)
        {
            drop(permit);
            continue;
        }
        let role = usize::from(token.plane == Plane::Control);
        let i = index(slot, token.plane);
        // Retired pre-cutover replay: a control token here is the old CPU1
        // control gate, reachable only under the explicit legacy-coreset
        // umbrella (see the retirement compile_error at the module head).
        #[cfg(feature = "model-v13-selftest")]
        if role == 1 {
            prototype_model::step();
            drop(permit);
            continue;
        }
        #[cfg(feature = "prototype-runtime")]
        if role == 1 {
            prototype_runtime::step(&mut runtime_worker);
            drop(permit);
            prototype_runtime::idle_worker();
            continue;
        }
        if !tested[role] {
            probes(slot, i);
            tested[role] = true;
        }
        #[cfg(feature = "ai-control-selftest")]
        if role == 1 {
            controller::step(&mut service_context);
            drop(permit);
            continue;
        }
        #[cfg(feature = "unified-runtime")]
        super::unified_task::expire_idle(slot);
        #[cfg(feature = "prototype-runtime")]
        if !prototype_runtime::business_enter(slot) {
            drop(permit);
            prototype_runtime::idle_worker();
            continue;
        }
        #[cfg(feature = "unified-runtime")]
        {
            let runtime_start = timer::cpu_ticks();
            let builtin_selected = super::domain_tasks::builtin_selected(slot);
            if builtin_selected {
                builtin_detail(slot, 0);
                let capture_ready = prepare_builtin_capture(slot, i);
                builtin_detail(slot, 1);
                if !capture_ready {
                    prototype_runtime::business_complete(slot, runtime_start);
                    drop(permit);
                    prototype_runtime::idle_worker();
                    continue;
                }
            }
            if super::unified_task::step(slot) {
                prototype_runtime::business_complete(slot, runtime_start);
                drop(permit);
                prototype_runtime::idle_worker();
                continue;
            }
            if builtin_selected {
                builtin_detail(slot, 2);
            }
            // A builtin credit may have waited while this vCPU was
            // descheduled after selection. It has executed no task body yet;
            // refund an expired credit instead of carrying it across a window.
            if !super::domain_tasks::revalidate_builtin(slot) {
                drop(permit);
                prototype_runtime::idle_worker();
                continue;
            }
            if builtin_selected {
                builtin_detail(slot, 3);
            }
        }
        let ctx = &mut contexts[role];
        #[cfg(all(feature = "prototype-runtime", feature = "unified-runtime"))]
        let runtime_start = timer::cpu_ticks();
        #[cfg(all(feature = "prototype-runtime", not(feature = "unified-runtime")))]
        let runtime_start = timer::ticks();
        #[cfg(feature = "unified-runtime")]
        builtin_detail(slot, 4);
        execute(ctx, i);
        #[cfg(feature = "unified-runtime")]
        let valid = fixture_context_valid(ctx, i);
        #[cfg(not(feature = "unified-runtime"))]
        let valid = fixture_yielded(ctx)
            && ctx.regs[0] == cookie(i)
            && ctx.tpidr_el0 == cookie(i)
            && !ctx
                .simd
                .iter()
                .enumerate()
                .any(|(r, v)| *v != [cookie(i), r as u64]);
        if !valid {
            fatal(4);
        }
        // All user writes completed before user::enter returned its TLB barrier.
        PROGRESS[i].fetch_add(1, Ordering::Release);
        #[cfg(feature = "prototype-runtime")]
        prototype_runtime::business_complete(slot, runtime_start);
        drop(permit);
    }
    unsafe {
        cpu::disable_timer();
    }
    STOPPED.fetch_or(1 << slot, Ordering::Release);
    super::halt()
}
/// Legacy dynamic-transition resource limits (CPU1 control). Only the legacy
/// ai-control-selftest / legacy-coreset profiles use these; the default fixed
/// CPU0 fixture builds its own cpu0_v0199 limits.
#[cfg(any(feature = "ai-control-selftest", feature = "legacy-coreset"))]
fn limits() -> Limits {
    Limits {
        resource_epoch: 1,
        min_control_cores: 1,
        min_control_capacity: 1,
        min_business_capacity: 1,
        committed_business_capacity: 1,
        protected_control: 2,
        protected_business: 1,
        cooldown_ticks: 0,
    }
}
#[cfg_attr(feature = "v020-production", allow(dead_code))]
fn plane(mask: u64, slot: usize) -> Plane {
    if mask & (1 << slot) != 0 {
        Plane::Control
    } else {
        Plane::Business
    }
}
fn close_gate(gate: &Gate) {
    let token = gate.view().token.expect("configured gate");
    wait(|| match gate.close(token) {
        Ok(()) => true,
        Err(Error::Busy) => false,
        Err(_) => panic!("stale dispatch configuration"),
    });
}
/// Retired legacy dynamic CoreSet transition exercise. It is kept for history
/// behind the non-default legacy-coreset feature and NEVER runs in the default
/// fixed-CPU0 smp-selftest fixture.
#[cfg(feature = "legacy-coreset")]
fn transition(ownership: &mut Ownership<C>, target: u64, sequence: u64) {
    transition_request(
        ownership,
        ScaleProposal {
            generation: ownership.snapshot().generation,
            resource_epoch: 1,
            sequence,
            desired_control: target,
            deadline: deadline(),
        },
    );
}
#[cfg(feature = "legacy-coreset")]
fn transition_request(ownership: &mut Ownership<C>, proposal: ScaleProposal) {
    let target = proposal.desired_control;
    let old = ownership.snapshot();
    let changed = old.control ^ target;
    // Revoke the real dispatch gates BEFORE entering the abstract transition.
    // Until close's RMW, an entered dispatch is old in-flight work, not new work.
    for (slot, gate) in GATES.iter().enumerate().take(REQUIRED).skip(1) {
        if changed & (1 << slot) != 0 {
            close_gate(gate);
        }
    }
    let now = timer::ticks();
    let ticket = ownership.begin(proposal, now, limits()).unwrap();
    wait(|| (1..REQUIRED).all(|slot| changed & (1 << slot) == 0 || GATES[slot].quiescent()));
    for slot in 1..REQUIRED {
        if changed & (1 << slot) == 0 {
            continue;
        }
        // In this closed test profile the only work is the tracked EL0 dispatch.
        // Its return disabled low walks and completed TLBI; IRQ was EOI'd and
        // timer disabled. No DMA, RCU, IPI workers or production references exist.
        ownership
            .acknowledge_drain(ticket, slot, Proof::DRAIN, timer::ticks())
            .unwrap();
        ownership
            .acknowledge_handoff(ticket, slot, Proof::HANDOFF, timer::ticks())
            .unwrap();
    }
    let snapshot = ownership.publish(ticket, timer::ticks(), limits()).unwrap();
    for (slot, gate) in GATES.iter().enumerate().take(REQUIRED).skip(1) {
        if changed & (1 << slot) != 0 {
            let generation = gate
                .view()
                .token
                .unwrap()
                .generation
                .checked_add(1)
                .unwrap();
            gate.open(Token {
                generation,
                plane: plane(snapshot.control, slot),
            })
            .unwrap();
        }
    }
    assert_eq!(snapshot.control & snapshot.business, 0);
    report(
        if cfg!(feature = "ai-control-selftest") {
            "SMP_SCALE_MODEL"
        } else {
            "SMP_SCALE_FIXTURE"
        },
        snapshot.control,
        snapshot.business,
        snapshot.generation,
    );
}
#[cfg(feature = "unified-runtime")]
pub(crate) fn boot_progress() -> [u64; 5] {
    [
        ONLINE.load(Ordering::Acquire),
        PROGRESS[4].load(Ordering::Acquire),
        PROGRESS[6].load(Ordering::Acquire),
        IRQS[2].load(Ordering::Acquire),
        IRQS[3].load(Ordering::Acquire),
    ]
}
// Under v020-production boot.rs routes directly to production::run(info), so the
// fixture dispatch below is intentionally bypassed (still live for every other
// smp-selftest profile).
#[cfg_attr(feature = "v020-production", allow(dead_code))]
pub fn run(
    info: &BootInfo,
    #[cfg(feature = "v0199-control-bringup")] mut budget: BudgetMeter,
) -> ! {
    #[cfg(feature = "unified-runtime")]
    crate::boot_recovery::formal::el1();
    if info.cpu_count != REQUIRED {
        report(
            "SMP_REJECT_CPU_COUNT",
            info.cpu_count as u64,
            REQUIRED as u64,
            0,
        );
        panic!("unsupported CPU count for this acceptance profile");
    }
    let topo = cyxia_platform_virt::cpu_topology(info, cpu::affinity()).expect("PSCI topology");
    assert_eq!(
        topo.count, REQUIRED,
        "this acceptance profile requires exactly four vCPUs"
    );
    let mut resource = info.gic.unwrap();
    resource.distributor.0 += super::HIGH;
    resource.cpu.0 += super::HIGH;
    let irq = info.timer_irq.unwrap();
    assert!((16..32).contains(&irq));
    TIMER_IRQ.store(irq as u64, Ordering::Relaxed);
    unsafe {
        *core::ptr::addr_of_mut!(RESOURCE) = Some(resource);
        *core::ptr::addr_of_mut!(GICS).cast::<Option<Gic>>() = Some(Gic::new(resource).unwrap());
        #[cfg(feature = "unified-runtime")]
        crate::domain_platform::register_ipi_cpu(gic(), 0).expect("IPI bootstrap registration");
        #[cfg(feature = "unified-runtime")]
        enable_service_timer();
        init_memory();
        #[cfg(feature = "register-v15-selftest")]
        register_evidence::init();
        #[cfg(feature = "ai-control-selftest")]
        controller::init();
        #[cfg(feature = "model-v13-selftest")]
        prototype_model::init();
        #[cfg(feature = "prototype-runtime")]
        prototype_runtime::init();
    }
    for (slot, affinity) in AFFINITIES.iter().enumerate().take(topo.count) {
        affinity.store(topo.affinity[slot], Ordering::Release);
    }
    #[cfg(feature = "unified-runtime")]
    crate::a02_capture::init();
    BOOT_READY.store(true, Ordering::Release);
    unsafe {
        core::arch::asm!("dsb sy", options(nostack));
    }
    // This symbol is deliberately linked at a physical low entry address.
    let entry = core::ptr::addr_of!(cyxia_secondary_start) as u64;
    assert!((cyxia_platform_virt::ENTRY..cyxia_platform_virt::ENTRY + 4096).contains(&entry));
    for slot in 1..topo.count {
        let result = unsafe { cpu::start(topo.conduit, topo.affinity[slot], entry, slot as u64) };
        report(
            "SMP_CPU_ON",
            slot as u64,
            topo.affinity[slot],
            result as u64,
        );
        assert_eq!(result, 0, "CPU_ON must report success");
    }
    #[cfg(feature = "v0199-control-bringup")]
    {
        gic().enable(irq).unwrap();
        budget.wait_for(|| ONLINE.load(Ordering::Acquire) == 15);
    }
    #[cfg(not(feature = "v0199-control-bringup"))]
    wait(|| ONLINE.load(Ordering::Acquire) == 15);
    report(
        "SMP_BOOT_OK",
        topo.count as u64,
        ONLINE.load(Ordering::Acquire),
        0,
    );
    #[cfg(feature = "register-v15-selftest")]
    register_evidence::finish();
    for (slot, gate) in GATES.iter().enumerate().take(REQUIRED).skip(1) {
        gate.open(Token {
            generation: 1,
            // Fixed CPU0 topology (design §2): CPU1-3 are all business. Only
            // the explicit legacy-coreset retirement umbrella opens the old
            // CPU1 control gate; ai-control-selftest / model-v13-selftest
            // require that feature (retirement compile_error at module head)
            // and never run in the default profile.
            plane: if cfg!(feature = "legacy-coreset") {
                plane(2, slot)
            } else {
                Plane::Business
            },
        })
        .unwrap();
    }
    #[cfg(feature = "prototype-runtime")]
    prototype_runtime::wake_workers();
    #[cfg(feature = "tcp-v13-selftest")]
    super::cluster_transport::run(info);
    #[cfg(feature = "storage-v13-selftest")]
    super::prototype_storage::run(info);
    #[cfg(feature = "unified-runtime")]
    super::unified::run(info);
    #[cfg(all(feature = "prototype-runtime", not(feature = "unified-runtime")))]
    prototype_runtime::run(info);
    #[cfg(feature = "net-selftest")]
    super::net_selftest::run(info);
    #[cfg(feature = "model-v13-selftest")]
    prototype_model::run();
    #[cfg(feature = "v0199-epoch-disk-selftest")]
    v0199_epoch_disk::run(info);
    #[cfg(feature = "v0199-format-selftest")]
    v0199_format_fixture::run(info);
    #[cfg(feature = "v0199-sec-n-selftest")]
    v0199_sec_n_fixture::run(info);
    #[cfg(feature = "v0199-control-bringup")]
    v0199_control_bringup::run(budget);
    #[cfg(all(
        feature = "v0199-cpu0-role-selftest",
        not(any(
            feature = "v0199-control-bringup",
            feature = "v0199-epoch-disk-selftest",
            feature = "v0199-format-selftest"
        ))
    ))]
    v0199_role_selftest::run();
    #[cfg(feature = "v0199-advice-e2e-selftest")]
    v0199_advice_e2e::run();
    #[cfg(feature = "ai-control-selftest")]
    {
        let ownership =
            Ownership::<C>::new(15, 2, [1; C], core::array::from_fn(|i| 1 << i), limits()).unwrap();
        controller::run(ownership)
    }
    // Retired legacy dynamic CoreSet transition exercise; never the default.
    #[cfg(feature = "legacy-coreset")]
    {
        let ownership =
            Ownership::<C>::new(15, 2, [1; C], core::array::from_fn(|i| 1 << i), limits()).unwrap();
        fixture(ownership)
    }
    // Default V0.20 acceptance: validate the fixed CPU0 control topology.
    #[cfg(not(any(
        feature = "v0199-cpu0-role-selftest",
        feature = "v0199-advice-e2e-selftest",
        feature = "ai-control-selftest",
        feature = "net-selftest",
        feature = "model-v13-selftest",
        feature = "prototype-runtime",
        feature = "storage-v13-selftest",
        feature = "tcp-v13-selftest",
        feature = "v0199-sec-n-selftest",
        feature = "legacy-coreset"
    )))]
    fixed_cpu0_fixture()
}
/// Default V0.20 smp-selftest fixture: validate the FIXED CPU0 control
/// topology (C={CPU0}, B={CPU1,CPU2,CPU3}) while CPU1-3 run only business EL0
/// fixtures. Positive: control on CPU0, business on CPU1-3. Negative: business
/// on CPU0 denied, control on CPU1-3 denied, no second control core. On a CPU0
/// fault the ledger fails closed (control quarantined, no business promotion)
/// while in-flight business obligations keep running until deterministic
/// cleanup. The retired dynamic CoreSet transition exercise never runs here.
#[cfg(not(any(
    feature = "v0199-cpu0-role-selftest",
    feature = "v0199-advice-e2e-selftest",
    feature = "ai-control-selftest",
    feature = "net-selftest",
    feature = "model-v13-selftest",
    feature = "prototype-runtime",
    feature = "storage-v13-selftest",
    feature = "tcp-v13-selftest",
    feature = "v0199-sec-n-selftest",
    feature = "legacy-coreset"
)))]
fn fixed_cpu0_fixture() -> ! {
    use cyxia_kernel_core::control_plane::cpu0_v0199 as profile;
    let fixed_limits = Limits {
        resource_epoch: 1,
        min_control_cores: 1,
        min_control_capacity: 1,
        min_business_capacity: 3,
        committed_business_capacity: 3,
        protected_control: profile::CONTROL_MASK,
        protected_business: profile::BUSINESS_MASK,
        cooldown_ticks: 0,
    };
    let mut ownership = Ownership::<REQUIRED>::new_v0199_cpu0(
        profile::ONLINE,
        [1; REQUIRED],
        core::array::from_fn(|i| 1 << i),
        fixed_limits,
    )
    .expect("fixed CPU0 control ownership");
    let snapshot = ownership.snapshot();
    // Positive: exactly one CPU0 control core and three business cores.
    profile::validate_snapshot(snapshot).expect("single CPU0 + three business cores");
    assert_eq!(snapshot.control, 0b0001);
    assert_eq!(snapshot.business, 0b1110);
    assert!(snapshot.permits(0, Plane::Control));
    // Negative: CPU0 can never run ordinary business, and no business core
    // (CPU1-3) may run control.
    assert!(!snapshot.permits(0, Plane::Business));
    for slot in 1..REQUIRED {
        assert!(snapshot.permits(slot, Plane::Business));
        assert!(!snapshot.permits(slot, Plane::Control));
    }
    // Negative: a second control core or business-on-CPU0 snapshot is denied.
    let mut second_control = snapshot;
    second_control.control = 0b0011;
    assert!(profile::validate_snapshot(second_control).is_err());
    let mut business_on_cpu0 = snapshot;
    business_on_cpu0.business = 0b1111;
    assert!(profile::validate_snapshot(business_on_cpu0).is_err());
    report(
        "SMP_FIXED_CPU0",
        snapshot.control,
        snapshot.business,
        snapshot.generation,
    );
    // CPU1-3 run only business fixtures; wait for bounded business progress.
    wait(|| (1..REQUIRED).all(|slot| PROGRESS[slot * 2].load(Ordering::Acquire) >= 4));
    // Fail closed on a CPU0 fault: quarantine the control core, never promote
    // a business core to control. In-flight business obligations keep running.
    let _ticket = ownership.fault(0, timer::ticks()).unwrap();
    let quarantined = ownership.snapshot();
    assert_ne!(quarantined.quarantined & 1, 0);
    assert!(!quarantined.permits(0, Plane::Control));
    for slot in 1..REQUIRED {
        assert!(!quarantined.permits(slot, Plane::Control));
        assert!(quarantined.permits(slot, Plane::Business));
    }
    report(
        "SMP_CONTROL_STALL",
        quarantined.quarantined,
        quarantined.control,
        quarantined.business,
    );
    // Deterministic cleanup: close every business gate and stop the workers.
    for gate in GATES.iter().take(REQUIRED).skip(1) {
        close_gate(gate);
    }
    wait(|| (1..REQUIRED).all(|i| GATES[i].quiescent()));
    QUIT.store(true, Ordering::Release);
    wait(|| STOPPED.load(Ordering::Acquire) == 14);
    check_failures();
    for slot in 1..REQUIRED {
        assert!(IRQS[slot].load(Ordering::Acquire) > 0);
        report(
            "SMP_CPU_EVIDENCE",
            slot as u64,
            IRQS[slot].load(Ordering::Acquire),
            PROGRESS[slot * 2].load(Ordering::Acquire),
        );
    }
    // QMP-readable evidence page for the fixed CPU0 topology.
    let final_snapshot = ownership.snapshot();
    for (i, value) in [
        0x4359_5853_4d50_3031,
        1,
        0,
        15,
        14,
        0b0001,
        0b1110,
        0,
        final_snapshot.quarantined,
        final_snapshot.control,
        final_snapshot.business,
        0,
        0,
        0,
        0,
        0,
    ]
    .into_iter()
    .enumerate()
    {
        SMP_EVIDENCE.words[i].store(value, Ordering::Relaxed);
    }
    for slot in 0..REQUIRED {
        let start = 16 + slot * 8;
        let values = [
            AFFINITIES[slot].load(Ordering::Acquire),
            PROGRESS[slot * 2].load(Ordering::Acquire),
            PROGRESS[slot * 2 + 1].load(Ordering::Acquire),
            IRQS[slot].load(Ordering::Acquire),
            FAULT_PROBES[slot].load(Ordering::Acquire),
            FAILURES[slot].load(Ordering::Acquire),
            unsafe { (*core::ptr::addr_of!(DATA_PAGES).cast::<Page>().add(slot * 2)).0[1] },
            unsafe {
                (*core::ptr::addr_of!(DATA_PAGES)
                    .cast::<Page>()
                    .add(slot * 2 + 1))
                .0[1]
            },
        ];
        for (offset, value) in values.into_iter().enumerate() {
            SMP_EVIDENCE.words[start + offset].store(value, Ordering::Relaxed);
        }
    }
    SMP_EVIDENCE.words[2].store(1, Ordering::Release);
    super::log(b"SMP_SCOPE model=fixed_cpu0 production_isolation=false physical_isolation=false\n");
    super::log(b"SMP_SELFTEST_PASS cpus=4\n");
    super::halt()
}

/// Retired legacy dynamic C/B/T/Q transition fixture (CPU1 control). Kept for
/// history behind the non-default legacy-coreset feature; the default
/// smp-selftest profile runs fixed_cpu0_fixture instead.
#[cfg(feature = "legacy-coreset")]
fn fixture(mut ownership: Ownership<C>) -> ! {
    wait(|| {
        PROGRESS[3].load(Ordering::Acquire) >= 4
            && PROGRESS[4].load(Ordering::Acquire) >= 4
            && PROGRESS[6].load(Ordering::Acquire) >= 4
    });
    transition(&mut ownership, 6, 1);
    wait(|| PROGRESS[5].load(Ordering::Acquire) >= 4);
    let control_at_close = PROGRESS[5].load(Ordering::Acquire);
    transition(&mut ownership, 2, 2);
    let business_before = PROGRESS[4].load(Ordering::Acquire);
    wait(|| PROGRESS[4].load(Ordering::Acquire) >= business_before + 4);
    // The old role must have stopped; one dispatch could finish while closing.
    assert!(PROGRESS[5].load(Ordering::Acquire) <= control_at_close + 1);
    // Model/controller stall: no more control work, but business is not blocked.
    close_gate(&GATES[1]);
    wait(|| GATES[1].quiescent());
    ownership.fault(1, timer::ticks()).unwrap();
    let stopped = PROGRESS[3].load(Ordering::Acquire);
    let before = PROGRESS[6].load(Ordering::Acquire);
    wait(|| PROGRESS[6].load(Ordering::Acquire) >= before + 8);
    assert_eq!(PROGRESS[3].load(Ordering::Acquire), stopped);
    report(
        "SMP_CONTROL_STALL",
        stopped,
        before,
        PROGRESS[6].load(Ordering::Acquire),
    );
    for gate in GATES.iter().take(REQUIRED).skip(1) {
        close_gate(gate);
    }
    wait(|| (1..REQUIRED).all(|i| GATES[i].quiescent()));
    QUIT.store(true, Ordering::Release);
    wait(|| STOPPED.load(Ordering::Acquire) == 14);
    check_failures();
    for slot in 1..REQUIRED {
        assert!(IRQS[slot].load(Ordering::Acquire) > 0);
        assert_eq!(
            FAULT_PROBES[slot].load(Ordering::Acquire),
            if slot == 2 { 10 } else { 5 }
        );
        report(
            "SMP_CPU_EVIDENCE",
            slot as u64,
            IRQS[slot].load(Ordering::Acquire),
            FAULT_PROBES[slot].load(Ordering::Acquire),
        );
        report(
            "SMP_ROLE_PROGRESS",
            slot as u64,
            PROGRESS[slot * 2].load(Ordering::Acquire),
            PROGRESS[slot * 2 + 1].load(Ordering::Acquire),
        );
    }
    let final_snapshot = ownership.snapshot();
    // Publish a separate QMP-readable page, not just a string "PASS". The runner
    // stops the VM and hashes this exact page after reading the final frame.
    for (i, value) in [
        0x4359_5853_4d50_3031,
        1,
        0,
        15,
        14,
        2,
        6,
        2,
        final_snapshot.quarantined,
        final_snapshot.control,
        final_snapshot.business,
        0,
        0,
        0,
        0,
        0,
    ]
    .into_iter()
    .enumerate()
    {
        SMP_EVIDENCE.words[i].store(value, Ordering::Relaxed);
    }
    for slot in 0..REQUIRED {
        let start = 16 + slot * 8;
        let values = [
            AFFINITIES[slot].load(Ordering::Acquire),
            PROGRESS[slot * 2].load(Ordering::Acquire),
            PROGRESS[slot * 2 + 1].load(Ordering::Acquire),
            IRQS[slot].load(Ordering::Acquire),
            FAULT_PROBES[slot].load(Ordering::Acquire),
            FAILURES[slot].load(Ordering::Acquire),
            unsafe { (*core::ptr::addr_of!(DATA_PAGES).cast::<Page>().add(slot * 2)).0[1] },
            unsafe {
                (*core::ptr::addr_of!(DATA_PAGES)
                    .cast::<Page>()
                    .add(slot * 2 + 1))
                .0[1]
            },
        ];
        for (offset, value) in values.into_iter().enumerate() {
            SMP_EVIDENCE.words[start + offset].store(value, Ordering::Relaxed);
        }
    }
    SMP_EVIDENCE.words[2].store(1, Ordering::Release);
    super::log(b"SMP_SCOPE model=fixture production_isolation=false physical_isolation=false\n");
    super::log(b"SMP_SELFTEST_PASS cpus=4\n");
    super::halt()
}

#[cfg(feature = "unified-runtime")]
pub(crate) fn enable_service_timer() {
    assert_eq!(cpu::slot(), 0);
    gic()
        .enable(TIMER_IRQ.load(Ordering::Acquire) as u32)
        .unwrap();
    // Registered device sources self-mask in the deterministic IRQ handler.
    // Their original owner alone polls/ACKs and unmasks; no driver is reentered.
    unsafe {
        heartbeat(true);
        timer::enable_irqs();
    }
}

#[cfg(feature = "unified-runtime")]
fn heartbeat_ticks() -> u64 {
    (timer::frequency() / 4000).max(1)
}
#[cfg(feature = "unified-runtime")]
fn heartbeat(enabled: bool) {
    let slot = cpu::slot();
    HEARTBEAT[slot].store(enabled, Ordering::Release);
    unsafe {
        if enabled {
            timer::arm(timer::ticks().saturating_add(heartbeat_ticks()));
        } else {
            cpu::disable_timer();
        }
    }
}

#[cfg(feature = "unified-runtime")]
pub(crate) fn restore_service_heartbeat() {
    let slot = cpu::slot();
    if HEARTBEAT[slot].load(Ordering::Acquire) {
        heartbeat(true);
    } else {
        unsafe { cpu::disable_timer() };
    }
}

#[cfg(feature = "unified-runtime")]
/// # Safety
/// The context and address-space root must satisfy user::enter's contract.
/// `record_slice_evidence` controls only the auxiliary timing bank; A02 always
/// records the authoritative task boundary around the architectural entry.
pub(crate) unsafe fn enter_service(
    context: &mut user::Context,
    root: u64,
    deadline: u64,
    task: crate::a02_capture::Task,
    capture_index: Option<usize>,
    capture_boundary: bool,
    record_slice_evidence: bool,
) {
    unsafe {
        enter_service_inner(
            context,
            root,
            deadline,
            task,
            capture_index,
            capture_boundary,
            record_slice_evidence,
            false,
        )
    }
}
#[cfg(feature = "unified-runtime")]
unsafe fn enter_builtin_service(
    context: &mut user::Context,
    root: u64,
    deadline: u64,
    task: crate::a02_capture::Task,
    capture_index: Option<usize>,
    capture_boundary: bool,
    record_slice_evidence: bool,
) {
    unsafe {
        enter_service_inner(
            context,
            root,
            deadline,
            task,
            capture_index,
            capture_boundary,
            record_slice_evidence,
            true,
        )
    }
}
#[cfg(feature = "unified-runtime")]
unsafe fn enter_service_inner(
    context: &mut user::Context,
    root: u64,
    deadline: u64,
    task: crate::a02_capture::Task,
    capture_index: Option<usize>,
    capture_boundary: bool,
    record_slice_evidence: bool,
    immutable_root: bool,
) {
    let slot = cpu::slot();
    if !capture_boundary {
        // The only uncaptured caller is the audited mapping probe. Its
        // integer-only transition already masks/restores DAIF around ACTIVE
        // and TTBR0 installation, so wrapping it in a second DAIF transition
        // adds no exclusion. Keep the independent timer backstop armed after
        // the synchronous return; its caller restores the fixed heartbeat in
        // a separate paid recovery turn.
        debug_assert!(!record_slice_evidence && !immutable_root);
        unsafe {
            timer::arm(deadline);
            user::enter_integer_probe(context, root);
        }
        return;
    }
    let saved_daif: u64;
    let row = 2 + slot * 30;
    if record_slice_evidence && slot < 4 {
        // Header words are immutable static initialization. Each row has one
        // CPU writer, so its entry count needs no cross-core exclusive RMW.
        let entries = TASK_SLICE_EVIDENCE.words[row].load(Ordering::Relaxed);
        TASK_SLICE_EVIDENCE.words[row].store(entries.saturating_add(1), Ordering::Relaxed);
        TASK_SLICE_EVIDENCE.words[row + 1].store(timer::ticks(), Ordering::Relaxed);
        TASK_SLICE_EVIDENCE.words[row + 14].store(0, Ordering::Relaxed);
        TASK_SLICE_EVIDENCE.words[row + 4].store(deadline, Ordering::Relaxed);
    }
    unsafe {
        core::arch::asm!("mrs {}, daif", "msr daifset, #2", "isb", out(reg) saved_daif, options(nostack, preserves_flags));
        if record_slice_evidence && slot < 4 {
            TASK_SLICE_EVIDENCE.words[row + 2].store(saved_daif, Ordering::Relaxed);
            TASK_SLICE_EVIDENCE.words[row + 3].store(timer::ticks(), Ordering::Relaxed);
        }
        timer::arm(deadline);
        if record_slice_evidence && slot < 4 {
            let ctl: u64;
            let cval: u64;
            core::arch::asm!("mrs {}, cntp_ctl_el0", "mrs {}, cntp_cval_el0",out(reg)ctl,out(reg)cval,options(nostack));
            TASK_SLICE_EVIDENCE.words[row + 15].store(ctl, Ordering::Relaxed);
            TASK_SLICE_EVIDENCE.words[row + 16].store(cval, Ordering::Relaxed);
            let armed_at = timer::ticks();
            TASK_SLICE_EVIDENCE.words[row + 5].store(armed_at, Ordering::Relaxed);
            TASK_SLICE_EVIDENCE.words[row + 6].store(armed_at, Ordering::Relaxed);
        }
        if capture_boundary {
            if let Some(index) = capture_index {
                crate::a02_capture::enter_prepared(task, index);
            } else {
                crate::a02_capture::enter(task);
            }
        }
        if immutable_root {
            builtin_detail(slot, 5);
        }
        if record_slice_evidence {
            RECORD_SLICE_EXCEPTION[slot].store(true, Ordering::Release);
        }
        if immutable_root {
            user::enter_immutable(context, root, builtin_asid(root));
        } else {
            user::enter(context, root);
        }
        #[cfg(target_os = "none")]
        crate::boot_recovery::formal::el0_return(context, root, task.role);
        if immutable_root {
            builtin_detail(slot, 6);
        }
        if record_slice_evidence {
            RECORD_SLICE_EXCEPTION[slot].store(false, Ordering::Release);
        }
        if capture_boundary {
            if let Some(index) = capture_index {
                crate::a02_capture::returned_prepared(index);
            } else {
                crate::a02_capture::returned();
            }
        }
        if immutable_root {
            builtin_detail(slot, 7);
        }
        if record_slice_evidence && slot < 4 {
            TASK_SLICE_EVIDENCE.words[row + 12].store(timer::ticks(), Ordering::Relaxed);
        }
        if HEARTBEAT[slot].load(Ordering::Acquire) {
            heartbeat(true);
        } else {
            cpu::disable_timer();
        }
        if record_slice_evidence && slot < 4 {
            TASK_SLICE_EVIDENCE.words[row + 13].store(timer::ticks(), Ordering::Relaxed);
        }
        core::arch::asm!("msr daif, {}", "isb", in(reg) saved_daif, options(nostack, preserves_flags));
    }
    if record_slice_evidence && slot < 4 {
        TASK_SLICE_EVIDENCE.words[row + 14].store(timer::ticks(), Ordering::Release);
    }
}
