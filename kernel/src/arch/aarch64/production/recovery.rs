//! V0.20 wave 11: RecoveryProof v2 in-memory gate + per-CPU degraded-audit
//! accumulators for the production boot, gating the 0x41 PUBLISH endpoint.
//!
//! The kernel-core contract types are used directly: one `RecoveryGate` (the
//! B-side publish gate) and four `RecoveryAccumulator`s (one per CPU). They are
//! held in separate statics, NOT inside one `RecoveryAuthority`, because the
//! accumulators have different single writers (their own CPU) than the gate
//! (CPU0). A shared `&mut RecoveryAuthority` from several CPUs would alias.
//!
//! HONEST SCOPE: the pair facts are STAGED (no superblock pair is read: G-A
//! touches no v1 on-disk layout), the boot epoch is the staged volatile BOOT,
//! and everything lives in volatile bss, not the protected pool.
//! `recovery_pair_facts_staged=true`.
//!
//! UNSAFE BOUNDARY REGISTRATION (baseline SEC-BUF: minimal trusted boundaries).
//! * GATE (static mut MaybeUninit<RecoveryGate>): `ptr::write`-initialized once
//!   by `init` on CPU0, guarded by the INIT_CLAIMED swap, before any secondary CPU is
//!   started. After that only CPU0 touches it: `publish_allowed` (in-vector
//!   0x41 dispatch, which first requires cpu == 0) and `observe_unknown`
//!   (run()). Every reference lives within one synchronous CPU0 call.
//! * SLOTS (static mut [Slot; 4], one cache line each): `ptr::write`-initialized
//!   by CPU0 in `init` before secondaries start (BOOT_READY Release in run()
//!   orders it). After that slot `i` is written ONLY by CPU `i`, from
//!   `record_fault` in that CPU's own exception context; no other CPU ever
//!   forms a reference to it. Cross-CPU readers use only the atomics below.
//! * INIT_CLAIMED / READY (atomics): INIT_CLAIMED makes `init` one-shot; READY
//!   is set with Release after both inits, and `record_fault` / the gate refuse
//!   until they observe it with Acquire.
//! * EVENTS / REJECTED ([AtomicU64; 4]): each written only by its own CPU with
//!   Release; CPU0 reads them with Acquire at the evidence seal, after the
//!   business CPUs stopped.
//! * PUBLISH_REJECTED (atomic): CPU0 only (set by `publish_probe`).
//! * `publish_probe` reads the parent's advice GATE via `gate_ptr()` on CPU0
//!   under the parent's registration (production.rs LEDGER/GATE).

use super::super::{fatal, report};
use super::{
    ACCEPT_COUNT, BOOT, E_AUTH, PUB, ROLE_COUNT, SUPER, SVC_OUT, advice_carrier, evidence, gate_ptr,
};
use core::mem::MaybeUninit;
use core::ptr::addr_of_mut;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use cyxia_kernel_core::security::Error;
use cyxia_kernel_core::security::recovery_proof_v2::{
    ACCUMULATOR_COUNT, CheckpointPairFacts, DegradedEvent, DegradedEventKind, RecoveryAccumulator,
    RecoveryGate, RecoveryState,
};
use sha2::{Digest, Sha256};

/// Protection generation of the staged boot (first generation).
const PROTECTION_GENERATION: u64 = 1;
/// Fatal codes (fail-closed): a rejected degraded event, init failure, gate
/// used before init / off CPU0, a fault on a CPU without an accumulator, and
/// the gate not reaching Unknown in the probe.
const FATAL_RECORD_REJECTED: u64 = 0x5731_1320;
const FATAL_INIT: u64 = 0x5731_1321;
const FATAL_GATE: u64 = 0x5731_1322;
const FATAL_NO_SLOT: u64 = 0x5731_1323;
const FATAL_PROBE: u64 = 0x5731_1324;

#[repr(C, align(64))]
struct Slot(MaybeUninit<RecoveryAccumulator>);

static mut GATE: MaybeUninit<RecoveryGate> = MaybeUninit::uninit();
static mut SLOTS: [Slot; ACCUMULATOR_COUNT] =
    [const { Slot(MaybeUninit::uninit()) }; ACCUMULATOR_COUNT];
static READY: AtomicBool = AtomicBool::new(false);
static INIT_CLAIMED: AtomicBool = AtomicBool::new(false);
static EVENTS: [AtomicU64; ACCUMULATOR_COUNT] = [const { AtomicU64::new(0) }; ACCUMULATOR_COUNT];
static REJECTED: [AtomicU64; ACCUMULATOR_COUNT] =
    [const { AtomicU64::new(0) }; ACCUMULATOR_COUNT];
static PUBLISH_REJECTED: AtomicBool = AtomicBool::new(false);

/// The staged initial pair: both copies valid, same FS UUID, the fresh-image
/// identical initial pair, relation provable. Every adverse fact is false.
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

/// Build the gate and the four accumulators. CPU0, once, before SMP bring-up.
pub(super) fn init(boot_epoch: u64) -> Result<(), Error> {
    if INIT_CLAIMED.swap(true, Ordering::AcqRel) {
        return Err(Error::Busy);
    }
    let gate = RecoveryGate::new(boot_epoch, PROTECTION_GENERATION, SUPER, &staged_pair())?;
    if gate.state() != RecoveryState::Verified {
        return Err(Error::Invalid);
    }
    let mut accs = [const { MaybeUninit::<RecoveryAccumulator>::uninit() }; ACCUMULATOR_COUNT];
    for (cpu, acc) in accs.iter_mut().enumerate() {
        acc.write(RecoveryAccumulator::new(boot_epoch, cpu as u32, 1)?);
    }
    // SAFETY: INIT_CLAIMED makes this the only initialization; it runs on CPU0
    // before any secondary CPU starts or any EL0 role runs, so no other
    // reference to GATE or SLOTS exists. Only raw addr_of_mut! places are used.
    unsafe {
        addr_of_mut!(GATE).write(MaybeUninit::new(gate));
        for (cpu, acc) in accs.into_iter().enumerate() {
            addr_of_mut!(SLOTS[cpu]).write(Slot(acc));
        }
    }
    READY.store(true, Ordering::Release);
    Ok(())
}

/// run()'s entry hook: a failed init stops the boot fail-closed.
pub(super) fn init_or_fatal() {
    if init(BOOT).is_err() {
        fatal(FATAL_INIT);
    }
}

fn event_digest(cpu: u32, esr: u64, far: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(esr.to_le_bytes());
    h.update(far.to_le_bytes());
    h.update(cpu.to_le_bytes());
    h.finalize().into()
}

/// Record one EL0 fault into the faulting CPU's own accumulator. Runs in that
/// CPU's exception context; `cpu` must be the current CPU slot.
pub(crate) fn record_fault(cpu: u32, esr: u64, far: u64) {
    let i = cpu as usize;
    if i >= ACCUMULATOR_COUNT {
        // No accumulator exists for this CPU; never drop the event silently.
        fatal(FATAL_NO_SLOT);
    }
    if cpu as usize != cyxia_arch_aarch64::cpu::slot() || !READY.load(Ordering::Acquire) {
        REJECTED[i].fetch_add(1, Ordering::Release);
        return;
    }
    // SAFETY: slot i was initialized before READY (Acquire above) and is only
    // ever referenced by CPU i, which is the current CPU (checked above); an
    // exception handler does not re-enter itself on the same CPU here.
    let acc = unsafe { (*addr_of_mut!(SLOTS[i])).0.assume_init_mut() };
    let ev = DegradedEvent {
        kind: DegradedEventKind::OtherCritical,
        event_id: acc.proof().last_event_id.saturating_add(1),
        event_digest: event_digest(cpu, esr, far),
        object_id: 0,
        object_generation: 1,
        failure_code: (esr >> 26) as u32,
    };
    match acc.record(&ev) {
        Ok(()) => EVENTS[i].store(acc.proof().total_count, Ordering::Release),
        Err(_) => {
            REJECTED[i].fetch_add(1, Ordering::Release);
        }
    }
}

fn gate() -> Option<&'static mut RecoveryGate> {
    if !READY.load(Ordering::Acquire) || cyxia_arch_aarch64::cpu::slot() != 0 {
        return None;
    }
    // SAFETY: initialized before READY; only CPU0 (checked) references GATE and
    // each caller consumes the reference within one synchronous call.
    Some(unsafe { (*addr_of_mut!(GATE)).assume_init_mut() })
}

/// The 0x41 publish gate: true only while the recovery state is Verified.
pub(super) fn publish_allowed() -> bool {
    gate().is_some_and(|g| g.state() == RecoveryState::Verified)
}

/// Uncertain completion: Verified -> Unknown (never back online).
fn observe_unknown() -> RecoveryState {
    match gate() {
        Some(g) => g.mark_unknown(),
        None => fatal(FATAL_GATE),
    }
}

/// After terminal settlement: an uncertain completion closes the gate, and a
/// fresh 0x41 through the existing publisher carrier is refused with E_AUTH
/// before the bridge runs. Nothing is published or natively accepted.
pub(super) fn publish_probe(pub_space: usize, pub_args: [u64; 6]) {
    // SAFETY: CPU0 control plane; the gate reference is consumed immediately
    // and no in-vector dispatch is running between these synchronous calls.
    let published = unsafe { (&*gate_ptr()).published_count() };
    if observe_unknown() != RecoveryState::Unknown {
        fatal(FATAL_PROBE);
    }
    advice_carrier(pub_space, 0x41, pub_args);
    let out = SVC_OUT[ROLE_COUNT + 3].load(Ordering::Relaxed);
    assert_eq!(out, E_AUTH as u64, "publish must be refused after UNKNOWN");
    // SAFETY: as above; the refused SVC already returned to this CPU0 loop.
    let after = unsafe { (&*gate_ptr()).published_count() };
    assert_eq!(after, published, "refused publish must not publish");
    assert_eq!(ACCEPT_COUNT.load(Ordering::Relaxed), 1, "no new native accept");
    PUBLISH_REJECTED.store(true, Ordering::Relaxed);
    report("V020_PROD_RECOVERY_REJECT", PUB.id, out, after as u64);
}

/// Evidence seal: words 131..134. Any rejected record fails the boot closed.
pub(super) fn publish() {
    if REJECTED.iter().any(|r| r.load(Ordering::Acquire) != 0) {
        fatal(FATAL_RECORD_REJECTED);
    }
    let events = EVENTS
        .iter()
        .fold(0u64, |sum, e| sum.saturating_add(e.load(Ordering::Acquire)));
    let ready = READY.load(Ordering::Acquire);
    evidence::put(
        evidence::W11_RECOVERY_ACCUMULATORS,
        if ready { ACCUMULATOR_COUNT as u64 } else { 0 },
    );
    evidence::put(evidence::W11_DEGRADED_EVENTS, events);
    evidence::put(
        evidence::W11_RECOVERY_PUBLISH_REJECTED,
        PUBLISH_REJECTED.load(Ordering::Relaxed) as u64,
    );
    evidence::put(evidence::W11_RECOVERY_PAIR_FACTS_STAGED, ready as u64);
}
