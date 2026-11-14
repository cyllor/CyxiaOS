//! Architecture-neutral completion gate for the ordinary A03 demand scene.
//! This checks recorded execution facts, not model arithmetic or native provenance.
pub const OWNER_WORDS: usize = 128 + 8 * 896;
pub const OWNER_ROW: usize = 896;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DemandWindow {
    pub first_ns: u64,
    pub withdrawn_ns: u64,
    pub drained_ns: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Completion {
    pub row: usize,
    pub publication: u64,
    pub job: u64,
    pub version: u64,
    pub input_ns: u64,
    pub applied_ns: u64,
}

/// Read a bounded owner bank without allocating a second 58 KiB snapshot.
/// The adapter must expose the existing owner ABI, including publication seals.
/// No proposal, same-mask action, pending receipt or partial handoff can finish.
pub fn completed_roundtrip(
    mut read: impl FnMut(usize) -> u64,
    window: DemandWindow,
) -> Option<Completion> {
    let count = read(4);
    let boot = read(3);
    if read(0) != 0x4359_4f57_4e31_3531
        || read(1) != 1
        || read(2) != OWNER_WORDS as u64
        || boot == 0
        || !(2..=8).contains(&count)
        || (5..=7).any(|i| read(i) != 0)
        || read(8) != OWNER_ROW as u64
        || read(9) != 8
        || read(10) != count
        || read(11) != count
        || window.first_ns == 0
        || window.first_ns >= window.withdrawn_ns
        || window.withdrawn_ns > window.drained_ns
    {
        return None;
    }
    let mut previous_mask = 2;
    let mut previous_operation = 0;
    let mut previous_job = 0;
    let mut previous_complete = 0;
    let mut previous_generation = 0;
    let mut seals = [0; 8];
    let mut result = None;
    for i in 0..count as usize {
        let row = 128 + i * OWNER_ROW;
        let mut r = |offset| read(row + offset);
        let publication = r(0);
        seals[i] = publication;
        let desired = r(8);
        let operation = r(11);
        let job = r(14);
        if publication == 0
            || publication & 1 != 0
            || r(1) != 31
            || r(2) != boot
            || [3, 4, 6, 7, 9, 12].into_iter().any(|j| r(j) == 0)
            || r(5) != 0
            || desired != (previous_mask ^ 4)
            || operation <= previous_operation
            || job <= previous_job
            || r(15) != 2
            || r(16) != 32
            || r(17) >= 64
        {
            return None;
        }
        let mut time = previous_complete;
        let mut generation = previous_generation;
        let mut ledger = 0;
        let mut budget_window = 0;
        let mut spent = 0;
        for at in [32, 48, 64, 80] {
            let (control, business, transition, quarantined) =
                (r(at + 2), r(at + 3), r(at + 4), r(at + 5));
            if r(at) < time
                || r(at) == 0
                || r(at + 1) != 15
                || control & business != 0
                || control | business | transition | quarantined != 15
                || (control | business) & (transition | quarantined) != 0
                || r(at + 8) < generation
                || r(at + 8) == 0
                || r(at + 9) == 0
                || r(at + 9) < ledger
                || r(at + 11) > 900
                || r(at + 12) > r(at + 11)
                || (at != 32 && r(at + 10) == budget_window && r(at + 12) < spent)
            {
                return None;
            }
            time = r(at);
            generation = r(at + 8);
            ledger = r(at + 9);
            budget_window = r(at + 10);
            spent = r(at + 12);
        }
        if r(34) != previous_mask
            || r(32) != r(10)
            || r(9) > r(10)
            || (36..40).any(|j| r(j) != 0)
            || r(50) != previous_mask
            || r(51) != r(35)
            || r(54) != 4
            || r(55) != 0
            || r(62) != operation
            || r(66) != desired
            || r(82) != desired
            || r(67) != 15 ^ desired
            || r(83) != 15 ^ desired
            || (68..72).chain(84..88).any(|j| r(j) != 0)
            || r(72) <= r(56)
            || r(77) != 63
            || r(78) != operation
            || r(79) != operation
            || r(64).checked_sub(r(48))? >= 200_000_000
        {
            return None;
        }
        if i == 0 && (r(9) < window.first_ns || r(80) > window.withdrawn_ns) {
            return None;
        }
        let model = 192;
        let input = model + 32;
        if r(model) != job
            || r(model + 1) != job
            || r(model + 13) != r(12)
            || r(model + 14) != 2
            || r(model + 15) != 0
            || r(model + 19) != 1
            || r(model + 30) != 1
            || r(model + 36) != r(9)
            || r(model + 28) < r(80)
            || r(model + 639) == 0
            || r(model + 639) & 1 != 0
            || r(model + 2) != 1
            || r(model + 3) != 2
            || [(4, 6), (5, 7), (6, 3), (7, 2)]
                .into_iter()
                .any(|(field, identity)| r(model + field) != r(identity))
            || r(input + 2) != job
            || r(input + 3) != r(3)
            || r(input + 6) != r(18)
            || r(18) != r(40)
            || r(input + 7) != r(19)
            || r(input + 8) != 1
            || r(input + 9) != 2
            || r(input + 10) != r(6)
            || r(input + 11) != r(7)
            || r(input + 14) != boot
            || r(input + 36) != job
            || r(input + 37) != r(4)
            || r(input + 38) != job
            || r(input + 400) != previous_mask
            || r(input + 401) != 15 ^ previous_mask
            || r(input + 402) != 15
            || r(input + 403) != 0
            || r(0) != publication
        {
            return None;
        }
        result = Some(Completion {
            row,
            publication,
            job,
            version: r(12),
            input_ns: r(9),
            applied_ns: r(model + 28),
        });
        previous_mask = desired;
        previous_job = job;
        previous_operation = operation;
        previous_complete = r(80);
        previous_generation = r(88);
    }
    let result = result?;
    (previous_mask == 2
        && result.input_ns > window.drained_ns
        && read(3) == boot
        && read(4) == count
        && read(10) == count
        && read(11) == count
        && (5..=7).all(|i| read(i) == 0)
        && (0..count as usize).all(|i| read(128 + i * OWNER_ROW) == seals[i])
        && read(result.row) == result.publication)
        .then_some(result)
}
