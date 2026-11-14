//! Passive, bounded provenance for an actually sealed baseline refusal.
//! CPU0 submission context only; no callback authority or clock reads.
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use cyxia_prototype::{
    domains::Error,
    policy::{ExecutionState, PlanReceipt, Snapshot},
};
pub const BYTES: usize = 6 * 512 + 8 * 8 + 8;
const MAGIC: u64 = 0x4359_4250_4341_3136;
#[repr(C, align(64))]
pub struct Bank([[AtomicU64; 64]; 6]);
#[used]
#[unsafe(no_mangle)]
pub static BASELINE_PUBLICATION_FIRST_CAUSE: Bank =
    Bank([const { [const { AtomicU64::new(0) }; 64] }; 6]);
static ACTIVE: AtomicBool = AtomicBool::new(false);
static READ: [AtomicU64; 8] = [const { AtomicU64::new(0) }; 8];
pub fn begin(enabled: bool) {
    if enabled {
        for w in &READ {
            w.store(0, Ordering::Relaxed);
        }
    }
    ACTIVE.store(enabled, Ordering::Release);
}
pub fn observe(
    reason: u64,
    view_at: u64,
    observed: u64,
    cpu: usize,
    requested: u64,
    current: u64,
    pending: bool,
    flags: u64,
) {
    if !ACTIVE.load(Ordering::Acquire) || cpu != 0 || READ[0].load(Ordering::Relaxed) != 0 {
        return;
    }
    let values = [
        reason,
        view_at,
        observed,
        cpu as u64,
        requested,
        current,
        u64::from(pending),
        flags,
    ];
    for (w, v) in READ.iter().zip(values) {
        w.store(v, Ordering::Relaxed);
    }
}
pub fn finish(
    trial: u64,
    token: u64,
    boot: u64,
    first: Snapshot,
    receipt: Option<PlanReceipt>,
    facts: [u64; 27],
    plan_hash: [u8; 32],
) {
    let enabled = ACTIVE.swap(false, Ordering::AcqRel);
    if !enabled || !(1..=6).contains(&trial) {
        return;
    }
    let Some(receipt) = receipt else { return };
    let ExecutionState::Failed(error) = receipt.state() else {
        return;
    };
    if receipt.version != 0
        || receipt.id.boot_epoch != boot
        || receipt.id.plan_seq != first.sequence
    {
        return;
    }
    let mut words = [0u64; 64];
    words[1] = MAGIC;
    words[2] = 1;
    words[3] = trial;
    words[4] = token;
    words[5..32].copy_from_slice(&facts);
    words[32..36].copy_from_slice(&[
        READ[0].load(Ordering::Relaxed),
        READ[1].load(Ordering::Relaxed),
        READ[2].load(Ordering::Relaxed),
        READ[3].load(Ordering::Relaxed),
    ]);
    words[36..42].copy_from_slice(&[
        boot,
        first.sequence,
        first.taken_ns,
        first.ledger_generation,
        first.core_generation,
        receipt.id.plan_seq,
    ]);
    for (i, c) in plan_hash.chunks_exact(8).enumerate() {
        words[42 + i] = u64::from_le_bytes(c.try_into().unwrap());
    }
    words[46] = error as u64 + 1;
    words[47] = receipt.version;
    words[48] = receipt.action_count as u64;
    words[49..53].copy_from_slice(&[
        READ[4].load(Ordering::Relaxed),
        READ[5].load(Ordering::Relaxed),
        READ[6].load(Ordering::Relaxed),
        READ[7].load(Ordering::Relaxed),
    ]);
    publish(
        &BASELINE_PUBLICATION_FIRST_CAUSE,
        trial as usize - 1,
        &words,
    );
}
fn publish(bank: &Bank, slot: usize, words: &[u64; 64]) {
    let row = &bank.0[slot];
    if row[0]
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    for (w, v) in row.iter().zip(words).skip(1) {
        w.store(*v, Ordering::Relaxed);
    }
    row[0].store(2, Ordering::Release);
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn first_refusal_per_trial_is_bounded_immutable_and_codes_are_domain_plus_one() {
        let bank = Bank([const { [const { AtomicU64::new(0) }; 64] }; 6]);
        let mut w = [0; 64];
        w[46] = Error::Busy as u64 + 1;
        publish(&bank, 0, &w);
        w[46] = Error::NotReady as u64 + 1;
        publish(&bank, 0, &w);
        publish(&bank, 5, &w);
        assert_eq!(bank.0[0][46].load(Ordering::Acquire), 10);
        assert_eq!(bank.0[5][46].load(Ordering::Acquire), 20);
    }
    #[test]
    fn only_actual_version_zero_failed_receipt_latches_matching_trial_and_operands() {
        use cyxia_prototype::policy::{PlanId, PlanReceipt};
        let snapshot = Snapshot {
            sequence: 7,
            taken_ns: 100,
            ledger_generation: 1,
            core_generation: 1,
        };
        let mut receipt = PlanReceipt {
            id: PlanId {
                boot_epoch: 1,
                controller_epoch: 1,
                plan_seq: 7,
            },
            version: 1,
            published_ns: 123,
            action_count: 1,
            actions: [ExecutionState::Applied; 16],
        };
        begin(true);
        finish(2, 3, 1, snapshot, Some(receipt), [0; 27], [9; 32]);
        assert_eq!(
            BASELINE_PUBLICATION_FIRST_CAUSE.0[1][0].load(Ordering::Acquire),
            0
        );
        receipt.version = 0;
        receipt.actions[0] = ExecutionState::Failed(Error::Busy);
        begin(false);
        finish(2, 3, 1, snapshot, Some(receipt), [0; 27], [9; 32]);
        assert_eq!(
            BASELINE_PUBLICATION_FIRST_CAUSE.0[1][0].load(Ordering::Acquire),
            0
        );
        begin(true);
        observe(2, 100, 60_000_100, 0, 0, 0, false, 1);
        observe(1, 0, 0, 0, 0, 0, false, 0);
        finish(2, 3, 1, snapshot, Some(receipt), [0; 27], [9; 32]);
        let row = &BASELINE_PUBLICATION_FIRST_CAUSE.0[1];
        assert_eq!(row[0].load(Ordering::Acquire), 2);
        assert_eq!(row[32].load(Ordering::Acquire), 2);
        assert_eq!(row[33].load(Ordering::Acquire), 100);
        assert_eq!(row[34].load(Ordering::Acquire), 60_000_100);
        assert_eq!(row[46].load(Ordering::Acquire), 10);
    }
}
