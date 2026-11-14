//! Fixed first-observation bank. Facts come only from actual native boundaries.
//! Per-CPU architecture rows have one writer; AI rows share the control-owner
//! gate. A stopped verifier rejects any incomplete release-published row.
use super::*;
use cyxia_arch_aarch64::user;
use cyxia_prototype::{
    domains::ObjectKey,
    policy::{ModelBinding, PlanView},
};

#[repr(C, align(64))]
struct Formal([AtomicU64; 256]);
#[used]
#[unsafe(no_mangle)]
static A01_FORMAL_EVIDENCE: Formal = Formal([const { AtomicU64::new(0) }; 256]);

fn put(i: usize, value: u64) {
    A01_FORMAL_EVIDENCE.0[i].store(value, Ordering::Relaxed);
}
fn get(i: usize) -> u64 {
    A01_FORMAL_EVIDENCE.0[i].load(Ordering::Acquire)
}
pub(super) fn init(config: &[u64; 64]) {
    crate::memory_fault_capture::init(config);
    crate::ownership_evidence::initialize(
        config,
        include!(concat!(env!("OUT_DIR"), "/runtime-fault.rs")),
    );
    put(1, 1);
    put(2, 256);
    put(3, MODE.load(Ordering::Acquire));
    for (i, value) in config[4..18].iter().copied().enumerate() {
        put(16 + i, value);
    }
    A01_FORMAL_EVIDENCE.0[0].store(0x4359_4130_3146_3031, Ordering::Release);
}
pub(super) fn durable(epoch: u64, ticks: u64) {
    put(4, epoch);
    put(5, ticks);
}
pub(super) fn model_passed(ticks: u64) {
    put(6, ticks);
}
pub(super) fn active(ticks: u64) {
    put(7, ticks);
}
fn registers() -> [u64; 6] {
    let el: u64;
    let sctlr: u64;
    let tcr: u64;
    let root: u64;
    let vbar: u64;
    let mpidr: u64;
    unsafe {
        core::arch::asm!("mrs {}, CurrentEL", "mrs {}, sctlr_el1", "mrs {}, tcr_el1",
            "mrs {}, ttbr1_el1", "mrs {}, vbar_el1", "mrs {}, mpidr_el1",
            out(reg) el, out(reg) sctlr, out(reg) tcr, out(reg) root,
            out(reg) vbar, out(reg) mpidr, options(nostack, preserves_flags));
    }
    [el, sctlr, tcr, root, vbar, mpidr]
}
pub(crate) fn el1() {
    let slot = cpu::slot();
    if slot >= 4 {
        return;
    }
    let row = 32 + slot * 24;
    if get(row) != 0 {
        return;
    }
    put(row, 1);
    put(row + 1, slot as u64);
    put(row + 2, timer::ticks());
    for (i, value) in registers().into_iter().enumerate() {
        put(row + 3 + i, value);
    }
    A01_FORMAL_EVIDENCE.0[row].store(2, Ordering::Release);
}
pub(crate) fn el0_return(context: &user::Context, root: u64, role: u64) {
    let slot = cpu::slot();
    // Initial business mapping probes deliberately return a lower-EL abort.
    // They are not ordinary completion witnesses and must not consume this
    // first-return latch. Their existing caller still validates/faults them;
    // this read-only recorder cannot turn an exception into a normal return.
    if slot >= 4 || !matches!(context.kind, 8 | 9) || context.kind == 8 && context.esr >> 26 != 0x15
    {
        return;
    }
    let row = 32 + slot * 24 + 12;
    if get(row) != 0 {
        return;
    }
    let el: u64;
    let actual_root: u64;
    let tcr: u64;
    unsafe {
        core::arch::asm!("mrs {}, CurrentEL", "mrs {}, ttbr0_el1", "mrs {}, tcr_el1",
            out(reg) el, out(reg) actual_root, out(reg) tcr,
            options(nostack, preserves_flags));
    }
    put(row, 1);
    for (i, value) in [
        timer::ticks(),
        context.status,
        context.esr,
        context.kind,
        context.pc,
        root,
        actual_root,
        tcr,
        el,
        role,
    ]
    .into_iter()
    .enumerate()
    {
        put(row + 1 + i, value);
    }
    A01_FORMAL_EVIDENCE.0[row].store(2, Ordering::Release);
}
fn authority_observed(boot: u64) {
    let ticks = timer::ticks();
    if boot == 0 || boot != get(4) || get(5) == 0 || ticks < get(5) || get(6) == 0 || get(7) == 0 {
        put(10, get(10) | 1);
    }
}
pub(crate) struct Key {
    pub boot: u64,
    pub controller: u64,
    pub sequence: u64,
    pub target: ObjectKey,
    pub model: ModelBinding,
    pub domain: u16,
    pub kind: u16,
    pub candidate_hash: [u8; 32],
    pub root_version: u64,
    pub core_generation: u64,
    pub ledger_generation: u64,
    pub control_mask: u64,
}
fn hashes(at: usize, candidate: [u8; 32], model: [u8; 32]) {
    for (i, bytes) in candidate
        .chunks_exact(8)
        .chain(model.chunks_exact(8))
        .enumerate()
    {
        put(at + i, u64::from_le_bytes(bytes.try_into().unwrap()));
    }
}
pub(crate) fn new_key(key: Key) {
    authority_observed(key.boot);
    let count = get(8);
    put(8, count.saturating_add(1));
    if count != 0 {
        return;
    }
    put(128, 1);
    for (i, value) in [
        timer::ticks(),
        key.boot,
        key.controller,
        key.sequence,
        key.target.id,
        key.target.generation,
        cpu::slot() as u64,
        key.model.generation,
        u64::from(key.domain),
        u64::from(key.kind),
        0,
    ]
    .into_iter()
    .enumerate()
    {
        put(129 + i, value);
    }
    hashes(140, key.candidate_hash, key.model.model_hash);
    for (i, value) in [
        key.root_version,
        key.core_generation,
        key.ledger_generation,
        key.control_mask,
    ]
    .into_iter()
    .enumerate()
    {
        put(148 + i, value);
    }
    A01_FORMAL_EVIDENCE.0[128].store(2, Ordering::Release);
}
pub(crate) fn published<P: PlanView>(boot: u64, plan: &P, version: u64, control_mask: u64) {
    authority_observed(boot);
    let count = get(9);
    put(9, count.saturating_add(1));
    if count != 0 {
        return;
    }
    let Some(first) = plan.iter().next() else {
        put(10, get(10) | 2);
        return;
    };
    let e = first.envelope;
    put(160, 1);
    for (i, value) in [
        timer::ticks(),
        boot,
        e.controller_epoch,
        e.decision_seq,
        e.target.id,
        e.target.generation,
        cpu::slot() as u64,
        plan.header().plan_seq,
        version,
        plan.header().active_model_generation,
        u64::from(first.action.domain()),
        u64::from(first.action.kind()),
    ]
    .into_iter()
    .enumerate()
    {
        put(161 + i, value);
    }
    hashes(173, e.candidate_set_hash, e.model_hash);
    for (i, value) in [
        e.snapshot_seq,
        e.core_generation,
        e.ledger_generation,
        control_mask,
    ]
    .into_iter()
    .enumerate()
    {
        put(181 + i, value);
    }
    A01_FORMAL_EVIDENCE.0[160].store(2, Ordering::Release);
}
