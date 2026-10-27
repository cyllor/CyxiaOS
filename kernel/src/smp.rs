//! Opt-in native multicore execution gate, deliberately separate from the
//! existing CPU0 desktop/shell. Only this bounded workload is certified here.
//! The base control-role program is a deterministic fixture. The explicit
//! ai-control-selftest feature substitutes the independent EL0 model service.
//! The independent net-selftest branch adds CPU0-owned DMA for EL1 Ethernet
//! bring-up and does not run the core-transition proof fixture. No remote
//! resources, RCU readers or production workers exist in this profile. The
//! resulting proof provider MUST NOT be used by production.
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use cyxia_arch_aarch64::{cpu, mmu, timer, user};
use cyxia_contracts::{BootInfo, GicResource, PhysAddr};
use cyxia_driver_gicv2::{Gic, IrqAck};
use cyxia_kernel_core::control_plane::{
    Error, Plane,
    cores::{Limits, Ownership, Proof, ScaleProposal},
    dispatch::{Gate, Token},
};
#[cfg(feature = "ai-control-selftest")]
#[path = "control_service.rs"]
mod controller;
#[cfg(feature = "model-v13-selftest")]
#[path = "prototype_model.rs"]
mod prototype_model;
#[cfg(feature = "prototype-runtime")]
#[path = "prototype_runtime.rs"]
pub(crate) mod prototype_runtime;
const C: usize = cyxia_contracts::BOOT_CPUS;
const STACK_BYTES: usize = 4096 + 65536;
const CODE: u64 = 0x10000;
const DATA: u64 = 0x20000;
const STACK: u64 = 0x30000;
#[used]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".cyxia.boot")]
static CYXIA_SMP_PROFILE: [u64; 6] = [1, 4, 8, 1, 0, 0];
const REQUIRED: usize = 4; // Test configuration only; never an AI core-count rule.

core::arch::global_asm!(include_str!("../../crates/arch-aarch64/src/secondary.S"), max_cpus=const C);
core::arch::global_asm!(include_str!("smp_user.S"));
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
static mut ROOTS: [Page; C * 2] = [const { Page::ZERO }; C * 2];
static mut MIDDLES: [Page; C * 2] = [const { Page::ZERO }; C * 2];
static mut LEAVES: [Page; C * 2] = [const { Page::ZERO }; C * 2];
static mut DATA_PAGES: [Page; C * 2] = [const { Page::ZERO }; C * 2];
static mut USER_STACKS: [Page; C * 2] = [const { Page::ZERO }; C * 2];
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
unsafe extern "C" {
    static cyxia_secondary_start: u8;
    static smp_user_start: u8;
    static smp_user_end: u8;
    static ram_l3: u8;
}
fn index(slot: usize, plane: Plane) -> usize {
    slot * 2 + usize::from(plane == Plane::Control)
}
fn phys(address: u64) -> u64 {
    address
        .checked_sub(super::HIGH)
        .expect("high kernel pointer")
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
fn report(label: &str, a: u64, b: u64, c: u64) {
    use core::fmt::Write;
    struct Text {
        data: [u8; 192],
        n: usize,
    }
    impl Write for Text {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let end = self.n + s.len();
            let out = self.data.get_mut(self.n..end).ok_or(core::fmt::Error)?;
            out.copy_from_slice(s.as_bytes());
            self.n = end;
            Ok(())
        }
    }
    // CPU0 alone owns the framed UART writer; secondary CPUs publish atomics.
    let mut text = Text {
        data: [0; 192],
        n: 0,
    };
    writeln!(&mut text, "{label} a={a} b={b} c={c}").unwrap();
    super::log(&text.data[..text.n]);
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
fn stop_failed(code: u64) -> ! {
    let slot = cpu::slot();
    FAILURES[slot].store(code, Ordering::Release);
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
                unsafe {
                    #[cfg(feature = "unified-runtime")]
                    if HEARTBEAT[slot].load(Ordering::Acquire) {
                        timer::arm(timer::ticks().saturating_add(heartbeat_ticks()));
                    } else {
                        cpu::disable_timer();
                    }
                    #[cfg(not(feature = "unified-runtime"))]
                    cpu::disable_timer();
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
            #[cfg(not(feature = "unified-runtime"))]
            _ => fatal(10 + kind),
        }
        #[cfg(feature = "unified-runtime")]
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
        for i in 0..C * 2 {
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
        enter_service(
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
#[cfg(not(feature = "unified-runtime"))]
fn fixture_yielded(ctx: &user::Context) -> bool {
    ctx.kind == 9
}
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
    #[cfg(feature = "unified-runtime")]
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
    ONLINE.fetch_or(1 << slot, Ordering::Release);
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
        let role = usize::from(token.plane == Plane::Control);
        let i = index(slot, token.plane);
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
            if super::domain_tasks::builtin_selected(slot) && !prepare_builtin_capture(slot, i) {
                prototype_runtime::business_complete(slot, runtime_start);
                drop(permit);
                prototype_runtime::idle_worker();
                continue;
            }
            if super::unified_task::step(slot) {
                prototype_runtime::business_complete(slot, runtime_start);
                drop(permit);
                prototype_runtime::idle_worker();
                continue;
            }
            // A builtin credit may have waited while this vCPU was
            // descheduled after selection. It has executed no task body yet;
            // refund an expired credit instead of carrying it across a window.
            if !super::domain_tasks::revalidate_builtin(slot) {
                drop(permit);
                prototype_runtime::idle_worker();
                continue;
            }
        }
        let ctx = &mut contexts[role];
        #[cfg(all(feature = "prototype-runtime", feature = "unified-runtime"))]
        let runtime_start = timer::cpu_ticks();
        #[cfg(all(feature = "prototype-runtime", not(feature = "unified-runtime")))]
        let runtime_start = timer::ticks();
        execute(ctx, i);
        if !fixture_yielded(ctx)
            || ctx.regs[0] != cookie(i)
            || ctx.tpidr_el0 != cookie(i)
            || ctx
                .simd
                .iter()
                .enumerate()
                .any(|(r, v)| *v != [cookie(i), r as u64])
        {
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
#[cfg(not(feature = "ai-control-selftest"))]
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
pub fn run(info: &BootInfo) -> ! {
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
    wait(|| ONLINE.load(Ordering::Acquire) == 15);
    report(
        "SMP_BOOT_OK",
        topo.count as u64,
        ONLINE.load(Ordering::Acquire),
        0,
    );
    for (slot, gate) in GATES.iter().enumerate().take(REQUIRED).skip(1) {
        gate.open(Token {
            generation: 1,
            plane: plane(2, slot),
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
    #[cfg(not(any(
        feature = "net-selftest",
        feature = "model-v13-selftest",
        feature = "prototype-runtime",
        feature = "storage-v13-selftest",
        feature = "tcp-v13-selftest"
    )))]
    let ownership =
        Ownership::<C>::new(15, 2, [1; C], core::array::from_fn(|i| 1 << i), limits()).unwrap();
    #[cfg(feature = "ai-control-selftest")]
    controller::run(ownership);
    #[cfg(not(any(
        feature = "ai-control-selftest",
        feature = "net-selftest",
        feature = "model-v13-selftest",
        feature = "prototype-runtime",
        feature = "storage-v13-selftest",
        feature = "tcp-v13-selftest"
    )))]
    fixture(ownership)
}
#[cfg(not(any(
    feature = "ai-control-selftest",
    feature = "net-selftest",
    feature = "model-v13-selftest",
    feature = "prototype-runtime",
    feature = "storage-v13-selftest",
    feature = "tcp-v13-selftest"
)))]
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
    let saved_daif: u64;
    let slot = cpu::slot();
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
        RECORD_SLICE_EXCEPTION[slot].store(record_slice_evidence, Ordering::Release);
        if capture_boundary {
            user::enter(context, root);
        } else {
            // The only non-captured entries are audited mapping probes. Their
            // immutable executable range has no FP/SIMD opcode and faults on
            // its first memory access, so no vector state is touched.
            user::enter_integer_probe(context, root);
        }
        RECORD_SLICE_EXCEPTION[slot].store(false, Ordering::Release);
        if capture_boundary {
            if let Some(index) = capture_index {
                crate::a02_capture::returned_prepared(index);
            } else {
                crate::a02_capture::returned();
            }
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
