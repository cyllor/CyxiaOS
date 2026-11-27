//! Recovery gate and per-CPU exception summaries.
//!
//! Each authorized 0x41 checks the EL1-owned checkpoint pair facts. This boot
//! starts with staged facts for the identical initial pair. After the successful
//! publication and replay, a probe withdraws one validation witness. The next
//! actual EL0 publish therefore takes the single-valid-copy RECOVERY_REQUIRED
//! path. EL0 exception observations never supply checkpoint facts.
//!
//! UNSAFE BOUNDARY REGISTRATION:
//! * CPU0 initializes SLOTS once before entering EL0. The diagnostic boot
//!   also initializes GATE before the secondaries start and uses staged
//!   facts. The signed resident boot has no staged gate. READY publishes
//!   initialization. Only synchronous CPU0 code accesses GATE.
//! * Each CPU exclusively owns its accumulator in SLOTS while running EL0.
//!   The diagnostic handoff requires QUIT, a quiescent business gate and
//!   STOPPED. A signed business worker instead publishes its writer stop
//!   after dropping the last dispatch permit and retiring its private root.
//!   The network worker may still run on that core with independent state.
//! * EVENTS and REJECTED publish each producer's own count. TAKEN records
//!   completed transfers. CPU0 consumes the retained summaries for the seal.
//!   The live-control service derives three volatile RECONCILE audit slots
//!   from these transferred proofs. Role 11 acknowledges the audit slots.
//!   The underlying RecoveryProof accumulators remain owned by CPU0.
//! * CPU0 increments GATE_REJECTS on an in-vector RECOVERY_REQUIRED refusal,
//!   and samples the parent advice gate via gate_ptr() between EL0 turns.
//! * BLOCK_HOLD is the CPU0 foreground's immutable terminal custody. The
//!   scratch owner transfers the sealed record once, then the mount gate
//!   remains closed. The driver still owns all queue/DMA storage.
//! * Signed resident staging can transfer an independently authorized
//!   carrier and the exclusive block device into durable custody. Only
//!   metered CPU0 foreground work performs its I/O. The in-vector audit
//!   service reads the confirmed state and reserves acknowledged writes.

#[cfg(any(feature = "v020-production-media-staging", cyxia_startup_catalog))]
use super::super::scratch_blk::{self, ScratchTerminalCustody};
#[cfg(feature = "v020-production-diagnostic")]
use super::super::{FAULT_PROBES, GATES, QUIT, STOPPED, fatal, report};
#[cfg(feature = "v020-production-diagnostic")]
use super::{
    ACCEPT_COUNT, BOOT, E_AUTH, PUB, ROLE_COUNT, SUPER, SVC_OUT, advice_carrier, evidence, gate_ptr,
};
use core::mem::MaybeUninit;
use core::ptr::addr_of_mut;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use cyxia_kernel_core::control_plane::Identity;
#[cfg(cyxia_business_package)]
use cyxia_kernel_core::control_plane::cpu0_v0199::{BUSINESS_MASK, BUSINESS_THREAD_ID_BASE};
use cyxia_kernel_core::security::Error;
#[cfg(cyxia_signed_resident)]
use cyxia_kernel_core::security::durable_role_epoch_v0199::ConfirmedBootPolicy;
use cyxia_kernel_core::security::recovery_proof_v2::{
    ACCUMULATOR_COUNT, DegradedEvent, DegradedEventKind, RecoveryAccumulator,
};
#[cfg(feature = "v020-production-diagnostic")]
use cyxia_kernel_core::security::recovery_proof_v2::{
    CheckpointPairFacts, RecoveryGate, RecoveryState,
};
use sha2::{Digest, Sha256};

#[cfg(cyxia_startup_catalog)]
#[path = "recovery/durable.rs"]
mod durable;
#[cfg(cyxia_startup_catalog)]
pub(super) use durable::{
    ack_durable, check_durable_ack, confirm_delivery, durable_available, has_pending_persistence,
    install_durable, open_durable, persist_pending, read_durable,
};

/// Protection generation of the staged boot (first generation).
#[cfg(feature = "v020-production-diagnostic")]
const PROTECTION_GENERATION: u64 = 1;
const INITIAL_WRITER_GENERATION: u64 = 1;
#[cfg(feature = "v020-production-diagnostic")]
const SECONDARIES: u64 = ((1 << ACCUMULATOR_COUNT) - 1) & !1;
#[cfg(feature = "v020-production-diagnostic")]
const FATAL_RECORD_REJECTED: u64 = 0x5731_1320;
#[cfg(feature = "v020-production-diagnostic")]
const FATAL_INIT: u64 = 0x5731_1321;
#[cfg(feature = "v020-production-diagnostic")]
const FATAL_GATE: u64 = 0x5731_1322;
#[cfg(all(feature = "v020-production-diagnostic", not(cyxia_signed_resident)))]
const FATAL_NO_SLOT: u64 = 0x5731_1323;
#[cfg(feature = "v020-production-diagnostic")]
const FATAL_PROBE: u64 = 0x5731_1324;
#[cfg(feature = "v020-production-diagnostic")]
const FATAL_TAKEOVER: u64 = 0x5731_1325;

#[repr(C, align(64))]
struct Slot(MaybeUninit<RecoveryAccumulator>);

#[cfg(feature = "v020-production-diagnostic")]
struct StagedGate {
    gate: RecoveryGate,
    pair: CheckpointPairFacts,
}

#[cfg(feature = "v020-production-diagnostic")]
static mut GATE: Option<StagedGate> = None;
static mut SLOTS: [Slot; ACCUMULATOR_COUNT] =
    [const { Slot(MaybeUninit::uninit()) }; ACCUMULATOR_COUNT];
static READY: AtomicBool = AtomicBool::new(false);
static INIT_CLAIMED: AtomicBool = AtomicBool::new(false);
static EVENTS: [AtomicU64; ACCUMULATOR_COUNT] = [const { AtomicU64::new(0) }; ACCUMULATOR_COUNT];
#[cfg(cyxia_startup_catalog)]
static STOPPED_WRITERS: AtomicU64 = AtomicU64::new(0);
#[cfg(any(feature = "v020-production-media-staging", cyxia_startup_catalog))]
static mut BLOCK_HOLD: Option<&'static ScratchTerminalCustody> = None;
#[cfg(feature = "v020-production-diagnostic")]
static REJECTED: [AtomicU64; ACCUMULATOR_COUNT] = [const { AtomicU64::new(0) }; ACCUMULATOR_COUNT];
static TAKEN: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "v020-production-diagnostic")]
static GATE_REJECTS: AtomicU64 = AtomicU64::new(0);

/// Accept the sealed transport outcome and retain the same record throughout
/// this boot. A terminal stop is not proof of an operation's result.
#[cfg(any(feature = "v020-production-media-staging", cyxia_startup_catalog))]
pub(super) fn contain_terminal_block(confirmed_epoch: u64) -> bool {
    assert_eq!(cyxia_arch_aarch64::cpu::slot(), 0);
    if let Some(custody) = scratch_blk::take_terminal_custody() {
        // SAFETY: CPU0 owns this foreground handoff alone. The driver's
        // one-shot transfer admits just one initialized, immutable record.
        unsafe { addr_of_mut!(BLOCK_HOLD).write(Some(custody)) };
        custody.report_handoff(confirmed_epoch);
    }
    // SAFETY: same CPU0 owner. Copy only the reference, never the record.
    unsafe { core::ptr::addr_of!(BLOCK_HOLD).read() }.is_some()
}

/// The staged initial pair: both copies valid, same FS UUID, the fresh-image
/// identical initial pair, relation provable. Every adverse fact is false.
#[cfg(feature = "v020-production-diagnostic")]
const fn staged_pair() -> CheckpointPairFacts {
    CheckpointPairFacts {
        first_valid: true,
        second_valid: true,
        same_fs_uuid: true,
        identical_initial_pair: true,
        same_generation_different_content: false,
        relation_provable: true,
        higher_generation_log: false,
    }
}

/// Build the four accumulators. CPU0, once, before running any EL0.
fn init(
    boot_epoch: u64,
    #[cfg(feature = "v020-production-diagnostic")] gate: Option<StagedGate>,
) -> Result<(), Error> {
    if cyxia_arch_aarch64::cpu::slot() != 0 {
        return Err(Error::Unauthorized);
    }
    if INIT_CLAIMED.swap(true, Ordering::AcqRel) {
        return Err(Error::Busy);
    }
    let mut accs = [const { MaybeUninit::<RecoveryAccumulator>::uninit() }; ACCUMULATOR_COUNT];
    for (cpu, acc) in accs.iter_mut().enumerate() {
        acc.write(RecoveryAccumulator::new(
            boot_epoch,
            cpu as u32,
            INITIAL_WRITER_GENERATION,
        )?);
    }
    // SAFETY: INIT_CLAIMED makes this the only initialization; it runs on CPU0
    // before any EL0 role runs. Secondaries in the signed profile are parked;
    // no reference to GATE or SLOTS exists. Use only raw addr_of_mut! places.
    unsafe {
        #[cfg(feature = "v020-production-diagnostic")]
        addr_of_mut!(GATE).write(gate);
        for (cpu, acc) in accs.into_iter().enumerate() {
            addr_of_mut!(SLOTS[cpu]).write(Slot(acc));
        }
    }
    READY.store(true, Ordering::Release);
    Ok(())
}

/// run()'s entry hook: a failed init stops the boot fail-closed.
#[cfg(feature = "v020-production-diagnostic")]
pub(super) fn init_or_fatal() {
    let pair = staged_pair();
    let gate = RecoveryGate::new(BOOT, PROTECTION_GENERATION, SUPER, &pair)
        .unwrap_or_else(|_| fatal(FATAL_INIT));
    if gate.state() != RecoveryState::Verified
        || init(BOOT, Some(StagedGate { gate, pair })).is_err()
    {
        fatal(FATAL_INIT);
    }
}

/// Initialize audit ownership after the real signed pair allocates this boot.
/// The proof summarizes retained faults and carries no permission to reopen.
#[cfg(cyxia_signed_resident)]
pub(super) fn init_signed(policy: &ConfirmedBootPolicy<'_>) -> Result<(), Error> {
    init(
        policy.boot_epoch(),
        #[cfg(feature = "v020-production-diagnostic")]
        None,
    )?;
    #[cfg(cyxia_startup_catalog)]
    durable::bind(policy)?;
    Ok(())
}

fn event_digest(cpu: u32, actor: Option<Identity>, esr: u64, far: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(esr.to_le_bytes());
    h.update(far.to_le_bytes());
    h.update(cpu.to_le_bytes());
    if let Some(actor) = actor {
        h.update(actor.id.to_le_bytes());
        h.update(actor.generation.to_le_bytes());
    }
    h.finalize().into()
}

/// Record one EL0 fault into the faulting CPU's own accumulator. Runs in that
/// CPU's exception context; `cpu` must be the current CPU slot.
#[cfg(all(feature = "v020-production-diagnostic", not(cyxia_signed_resident)))]
pub(crate) fn record_fault(cpu: u32, esr: u64, far: u64) {
    let i = cyxia_arch_aarch64::cpu::slot();
    if i >= ACCUMULATOR_COUNT {
        // No accumulator exists for this CPU; never drop the event silently.
        fatal(FATAL_NO_SLOT);
    }
    // REJECTED/EVENTS are indexed by the CURRENT CPU only, never by `cpu`.
    if cpu as usize != i || record_event(i, None, esr, far).is_err() {
        REJECTED[i].fetch_add(1, Ordering::Release);
    }
}

/// The signed resident turn has authenticated the live EL0 root and stopped
/// the task. Retain its identity from the private scheduler, not user bytes.
#[cfg(cyxia_signed_resident)]
pub(super) fn record_role_failure(actor: Identity, esr: u64, far: u64) -> Result<(), Error> {
    if cyxia_arch_aarch64::cpu::slot() != 0 || !actor.valid() {
        return Err(Error::Unauthorized);
    }
    record_event(0, Some(actor), esr, attributed_far(esr, far))
}

#[cfg(cyxia_signed_resident)]
fn attributed_far(esr: u64, far: u64) -> u64 {
    // FAR is defined for the relevant abort classes only, when FnV is clear.
    if matches!((esr >> 26) & 0x3f, 0x20 | 0x24) && esr & (1 << 10) == 0 {
        far
    } else {
        0
    }
}

/// Only a classified abort from the current pinned business context supplies
/// this actor. The caller retires the writer before CPU0 may read its slot.
#[cfg(cyxia_business_package)]
pub(super) fn record_business_failure(actor: Identity, esr: u64, far: u64) -> Result<(), Error> {
    let i = cyxia_arch_aarch64::cpu::slot();
    if i == 0
        || i >= ACCUMULATOR_COUNT
        || !actor.valid()
        || actor.id != BUSINESS_THREAD_ID_BASE + i as u64
    {
        return Err(Error::Unauthorized);
    }
    record_event(i, Some(actor), esr, attributed_far(esr, far))
}

/// This worker has returned from its last EL0 turn and retired its root.
/// Its release hands off all writes to the CPU0 foreground recovery owner.
#[cfg(cyxia_business_package)]
pub(super) fn stop_business_writer() {
    let i = cyxia_arch_aarch64::cpu::slot();
    assert!((1..ACCUMULATOR_COUNT).contains(&i) && READY.load(Ordering::Acquire));
    STOPPED_WRITERS.fetch_or(1 << i, Ordering::Release);
}

#[cfg(cyxia_business_package)]
pub(super) fn business_writers_stopped() -> bool {
    STOPPED_WRITERS.load(Ordering::Acquire) & BUSINESS_MASK == BUSINESS_MASK
}

/// Preserve the unclassified CPU0 syndrome before the terminal stop. It
/// carries no task attribution and cannot authorize a replacement.
#[cfg(cyxia_signed_resident)]
pub(super) fn record_unattributed_sync(esr: u64, far: u64) {
    if cyxia_arch_aarch64::cpu::slot() == 0 {
        let _ = record_event(0, None, esr, far);
    }
}

fn record_event(i: usize, actor: Option<Identity>, esr: u64, far: u64) -> Result<(), Error> {
    if !READY.load(Ordering::Acquire) || TAKEN.load(Ordering::Acquire) & (1 << i) != 0 {
        return Err(Error::Unauthorized);
    }
    #[cfg(cyxia_startup_catalog)]
    if STOPPED_WRITERS.load(Ordering::Acquire) & (1 << i) != 0 {
        return Err(Error::Unauthorized);
    }
    // SAFETY: slot i was initialized before READY (Acquire above) and is only
    // referenced by CPU i until its final STOPPED release; an
    // exception handler does not re-enter itself on the same CPU here.
    let acc = unsafe { (*addr_of_mut!(SLOTS[i])).0.assume_init_mut() };
    let ev = DegradedEvent {
        kind: DegradedEventKind::OtherCritical,
        event_id: acc.proof().last_event_id.saturating_add(1),
        event_digest: event_digest(i as u32, actor, esr, far),
        object_id: actor.map_or(0, |id| id.id),
        object_generation: actor.map_or(1, |id| id.generation),
        failure_code: ((esr >> 26) & 0x3f) as u32,
    };
    acc.record(&ev)?;
    EVENTS[i].store(acc.proof().total_count, Ordering::Release);
    Ok(())
}

/// Scoped access to the recovery gate: `None` before init or off CPU0. The
/// `&mut` never escapes `f`, so no caller can hold an aliasing reference.
#[cfg(feature = "v020-production-diagnostic")]
fn with_gate<R>(f: impl FnOnce(&mut StagedGate) -> R) -> Option<R> {
    if !READY.load(Ordering::Acquire) || cyxia_arch_aarch64::cpu::slot() != 0 {
        return None;
    }
    // SAFETY: GATE was initialized before READY (Acquire above). Only CPU0
    // (checked) reaches here, CPU0 code is synchronous, and `with_gate` is
    // never called re-entrantly from inside `f`, so this is the only live
    // reference for the duration of `f`.
    unsafe { (*addr_of_mut!(GATE)).as_mut().map(f) }
}

/// Re-evaluate the EL1 facts at the side-effect boundary, including on retries.
#[cfg(feature = "v020-production-diagnostic")]
pub(super) fn publish_allowed() -> bool {
    let state = with_gate(|staged| staged.gate.raise(&staged.pair));
    if state == Some(RecoveryState::RecoveryRequired) {
        GATE_REJECTS.fetch_add(1, Ordering::Relaxed);
    }
    state == Some(RecoveryState::Verified)
}

/// Withdraw the second staged validation witness, then issue the real 0x41.
/// The probe changes the input only. The vector must latch the state itself.
#[cfg(feature = "v020-production-diagnostic")]
pub(super) fn publish_probe(pub_space: usize, pub_args: [u64; 6]) {
    // SAFETY: CPU0 control plane; the gate reference is consumed immediately
    // and no in-vector dispatch is running between these synchronous calls.
    let published = unsafe { (&*gate_ptr()).published_count() };
    assert_eq!(published, 1, "probe must run while the plan is published");
    let rejects_before = GATE_REJECTS.load(Ordering::Relaxed);
    assert_eq!(rejects_before, 0, "gate refused a publish before the probe");
    with_gate(|staged| {
        assert_eq!(staged.gate.state(), RecoveryState::Verified);
        assert!(staged.pair.first_valid && staged.pair.second_valid);
        staged.pair.second_valid = false;
        staged.pair.identical_initial_pair = false;
        staged.pair.relation_provable = false;
    })
    .unwrap_or_else(|| fatal(FATAL_GATE));
    advice_carrier(pub_space, 0x41, pub_args);
    let out = SVC_OUT[ROLE_COUNT + 3].load(Ordering::Relaxed);
    assert_eq!(
        out, E_AUTH as u64,
        "0x41 must refuse the staged single-copy pair"
    );
    let rejects_after = GATE_REJECTS.load(Ordering::Relaxed);
    assert_eq!(
        rejects_after, 1,
        "the refusal must come from the recovery gate"
    );
    // SAFETY: as above; the refused SVC already returned to this CPU0 loop.
    let after = unsafe { (&*gate_ptr()).published_count() };
    assert_eq!(after, 1, "refused publish must leave published_count at 1");
    assert_eq!(
        ACCEPT_COUNT.load(Ordering::Relaxed),
        1,
        "no new native accept"
    );
    let state = with_gate(|staged| staged.gate.state()).unwrap_or_else(|| fatal(FATAL_GATE));
    if state != RecoveryState::RecoveryRequired {
        fatal(FATAL_PROBE);
    }
    report("V020_PROD_RECOVERY_REJECT", PUB.id, out, after as u64);
    report(
        "V020_W11_RECOVERY_GATE_REJECTS",
        rejects_before,
        rejects_after,
        state as u64,
    );
}

/// EL1 consumes each stopped producer's retained proof on CPU0. The published
/// event counts provide independent watermarks for the generation transition.
#[cfg(feature = "v020-production-diagnostic")]
pub(super) fn takeover_stopped() {
    if cyxia_arch_aarch64::cpu::slot() != 0
        || !READY.load(Ordering::Acquire)
        || !QUIT.load(Ordering::Acquire)
        || STOPPED.load(Ordering::Acquire) != SECONDARIES
        || TAKEN.load(Ordering::Relaxed) != 0
    {
        fatal(FATAL_TAKEOVER);
    }
    let mut retained = 0u64;
    let mut fixture_faults = 0u64;
    for i in 1..ACCUMULATOR_COUNT {
        if !GATES[i].quiescent() {
            fatal(FATAL_TAKEOVER);
        }
        // SAFETY: init published SLOTS before READY. STOPPED above acquires
        // the writer's final release after it permanently left EL0. This is
        // the only CPU0 caller and its references end before the next turn.
        let acc = unsafe { (*addr_of_mut!(SLOTS[i])).0.assume_init_mut() };
        let watermark = EVENTS[i].load(Ordering::Acquire);
        acc.takeover_stopped_writer(BOOT, i as u32, INITIAL_WRITER_GENERATION, watermark)
            .unwrap_or_else(|_| fatal(FATAL_TAKEOVER));
        retained = retained.saturating_add(acc.proof().total_count);
        // smp::probes increments this only after checking the actual FAR/EC/FSC.
        let checked = FAULT_PROBES[i].load(Ordering::Acquire);
        if checked > acc.proof().total_count {
            fatal(FATAL_TAKEOVER);
        }
        fixture_faults = fixture_faults.saturating_add(checked);
        TAKEN.fetch_or(1 << i, Ordering::Release);
    }
    report(
        "V020_W11_RECOVERY_HANDOFF",
        TAKEN.load(Ordering::Acquire),
        retained,
        fixture_faults,
    );
}

/// Snapshot CPU0 and all three transferred writers after their final stopped handoff.
#[cfg(feature = "v020-production-live-control")]
pub(super) fn handed_off_proofs()
-> Option<[cyxia_kernel_core::security::recovery_proof_v2::RecoveryProofV2; ACCUMULATOR_COUNT]> {
    if cyxia_arch_aarch64::cpu::slot() != 0 || TAKEN.load(Ordering::Acquire) != SECONDARIES {
        return None;
    }
    // CPU0 is the current owner of all accumulators. The release in
    // takeover_stopped follows the worker stop and its generation advance.
    Some(core::array::from_fn(|i| unsafe {
        *(*addr_of_mut!(SLOTS[i])).0.assume_init_ref().proof()
    }))
}

/// Seal the actual proof counts and the measured refusal / handoff outcomes.
#[cfg(feature = "v020-production-diagnostic")]
pub(super) fn publish() {
    if REJECTED.iter().any(|r| r.load(Ordering::Acquire) != 0) {
        fatal(FATAL_RECORD_REJECTED);
    }
    let mask = TAKEN.load(Ordering::Acquire);
    if cyxia_arch_aarch64::cpu::slot() != 0 || mask != SECONDARIES {
        fatal(FATAL_TAKEOVER);
    }
    let mut events = 0u64;
    // i indexes a static mut MaybeUninit array via addr_of_mut!; an iterator
    // would obscure the raw-pointer slot arithmetic the SAFETY note relies on.
    #[allow(clippy::needless_range_loop)]
    for i in 0..ACCUMULATOR_COUNT {
        // SAFETY: CPU0 owns slot 0 and checked that all secondary slots have
        // completed takeover. This seal cannot run concurrently with CPU0 EL0.
        let acc = unsafe { (*addr_of_mut!(SLOTS[i])).0.assume_init_ref() };
        events = events.saturating_add(acc.proof().total_count);
    }
    evidence::put(
        evidence::W11_RECOVERY_ACCUMULATORS,
        ACCUMULATOR_COUNT as u64,
    );
    evidence::put(evidence::W11_DEGRADED_EVENTS, events);
    evidence::put(
        evidence::W11_RECOVERY_REQUIRED_REJECTS,
        GATE_REJECTS.load(Ordering::Relaxed),
    );
    evidence::put(evidence::W11_RECOVERY_PAIR_FACTS_STAGED, 1);
    evidence::put(
        evidence::W11_RECOVERY_WRITER_TAKEOVERS,
        u64::from(mask.count_ones()),
    );
}
