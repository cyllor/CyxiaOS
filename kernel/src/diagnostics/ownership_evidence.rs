//! Read-only actual CoreAction -> handoff -> owner -> model receipt evidence.
//! CPU0 alone appends metadata. Model rows are copied under the existing
//! control-owner gate, before their original evidence slot may be reused.
use core::sync::atomic::{AtomicU64, Ordering};
use cyxia_prototype::{
    cores::Cores,
    domains::{ApplyId, Error, PolicyStamp},
};

const SLOTS: usize = 8;
const ROW: usize = 896;
const WORDS: usize = 128 + SLOTS * ROW;
#[repr(C, align(64))]
struct Evidence([AtomicU64; WORDS]);
#[used]
#[unsafe(no_mangle)]
static OWNERSHIP_V15_EVIDENCE: Evidence = Evidence([const { AtomicU64::new(0) }; WORDS]);
fn get(at: usize) -> u64 {
    OWNERSHIP_V15_EVIDENCE.0[at].load(Ordering::Acquire)
}
fn put(at: usize, value: u64) {
    OWNERSHIP_V15_EVIDENCE.0[at].store(value, Ordering::Relaxed);
}
fn identity(apply: ApplyId) -> [u64; 6] {
    [
        apply.boot_epoch,
        apply.controller_epoch,
        apply.plan_seq,
        u64::from(apply.action_index),
        apply.target.id,
        apply.target.generation,
    ]
}
fn row(apply: ApplyId) -> Option<usize> {
    let key = identity(apply);
    (0..get(4).min(SLOTS as u64) as usize)
        .map(|i| 128 + i * ROW)
        .find(|at| key.iter().enumerate().all(|(i, v)| get(at + 2 + i) == *v))
}
fn begin(at: usize) {
    OWNERSHIP_V15_EVIDENCE.0[at].fetch_add(1, Ordering::AcqRel);
}
fn end(at: usize) {
    OWNERSHIP_V15_EVIDENCE.0[at].fetch_add(1, Ordering::Release);
}
pub(crate) fn initialize(config: &[u64; 64], fault: u64) {
    put(1, 1);
    put(2, WORDS as u64);
    put(6, fault);
    put(8, ROW as u64);
    put(9, SLOTS as u64);
    for (i, v) in config[4..18].iter().copied().enumerate() {
        put(16 + i, v);
    }
    OWNERSHIP_V15_EVIDENCE.0[0].store(0x4359_4f57_4e31_3531, Ordering::Release);
}
fn snapshot(at: usize, owner: &Cores, now: u64, operation: u64, proofs: u64, ack: u64) {
    let s = owner.snapshot();
    let values = [
        now,
        s.online.bits(),
        s.control.bits(),
        s.business.bits(),
        s.transition.bits(),
        s.quarantined.bits(),
        s.draining.bits(),
        s.suspect.bits(),
        s.core_generation,
        s.ledger_generation,
        owner.budget_window(),
        u64::from(owner.committed_milli(2).unwrap_or(u16::MAX)),
        u64::from(owner.window_spent_milli(2).unwrap_or(u16::MAX)),
        proofs,
        operation,
        ack,
    ];
    for (i, v) in values.into_iter().enumerate() {
        put(at + i, v);
    }
}
pub(crate) fn accepted(
    apply: ApplyId,
    stamp: PolicyStamp,
    desired: u64,
    context: [u64; 2],
    owner: &Cores,
    now: u64,
) {
    if desired == owner.snapshot().control.bits() || row(apply).is_some() {
        return;
    }
    let count = get(4);
    if count >= SLOTS as u64 {
        put(5, get(5).saturating_add(1));
        return;
    }
    let at = 128 + count as usize * ROW;
    begin(at);
    put(at + 1, 1);
    for (i, v) in identity(apply).into_iter().enumerate() {
        put(at + 2 + i, v);
    }
    put(at + 8, desired);
    put(at + 9, stamp.snapshot_ns);
    put(at + 10, now);
    put(at + 12, stamp.version);
    put(at + 18, context[0]);
    put(at + 19, context[1]);
    snapshot(at + 32, owner, now, 0, 0, 0);
    put(3, apply.boot_epoch);
    put(4, count + 1);
    end(at);
}
pub(crate) fn draining(apply: ApplyId, operation: u64, owner: &Cores, now: u64) {
    let Some(at) = row(apply) else { return };
    if get(at + 1) & 2 != 0 {
        return;
    }
    begin(at);
    put(at + 11, operation);
    snapshot(at + 48, owner, now, operation, 0, 0);
    put(at + 1, get(at + 1) | 2);
    end(at);
}
pub(crate) fn published(
    apply: ApplyId,
    operation: u64,
    owner: &Cores,
    now: u64,
    proofs: u64,
    ack: u64,
) {
    let Some(at) = row(apply) else { return };
    if get(at + 1) & 4 != 0 {
        return;
    }
    begin(at);
    snapshot(at + 64, owner, now, operation, proofs, ack);
    put(at + 1, get(at + 1) | 4);
    end(at);
}
pub(crate) fn completed(apply: ApplyId, owner: &Cores, now: u64) {
    let Some(at) = row(apply) else { return };
    if get(at + 1) & 16 != 0 {
        return;
    }
    begin(at);
    snapshot(at + 80, owner, now, get(at + 11), 0, 0);
    put(at + 1, get(at + 1) | 16);
    put(11, get(11).saturating_add(1));
    end(at);
}
pub(crate) fn failed(apply: ApplyId, owner: &Cores, now: u64, operation: u64, ack: u64) {
    let Some(at) = row(apply) else { return };
    if get(at + 1) & 64 != 0 {
        return;
    }
    begin(at);
    snapshot(at + 96, owner, now, operation, 0, ack);
    put(at + 1, get(at + 1) | 64);
    end(at);
}
pub(crate) fn model_witness(apply: ApplyId, slot: usize, sequence: u64) -> Result<(), Error> {
    let Some(at) = row(apply) else { return Ok(()) };
    if get(at + 1) & 8 != 0 {
        return Ok(());
    }
    begin(at);
    let result = crate::domain_evidence::ownership_snapshot(slot, sequence, |i, value| {
        put(at + if i < 32 { 128 + i } else { 192 + i - 32 }, value);
    });
    if result.is_ok() {
        put(at + 14, sequence);
        put(at + 15, 2);
        put(at + 16, 32);
        put(at + 17, slot as u64);
        put(at + 1, get(at + 1) | 8);
        put(10, get(10).saturating_add(1));
    }
    end(at);
    result
}

/// Retain the actual contraction receipt only after both owner changes finish.
/// CPU0 consumes this observer; it never changes core ownership or model choice.
pub(crate) fn visit_ordinary_roundtrip(
    window: cyxia_prototype::a03::DemandWindow,
    mut copy: impl FnMut(usize, u64),
) -> Option<cyxia_prototype::a03::Completion> {
    let completion = cyxia_prototype::a03::completed_roundtrip(get, window)?;
    for i in 0..640 {
        copy(i, get(completion.row + 192 + i));
    }
    // The model copy must still belong to the same complete, last owner row.
    (cyxia_prototype::a03::completed_roundtrip(get, window) == Some(completion))
        .then_some(completion)
}
