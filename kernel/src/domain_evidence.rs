//! Bounded, read-only native evidence for the ordinary domain control path.
//! A capture retains raw input, the EL0 reply, measured cost and the separate
//! executor outcome. The sequence lock makes an interrupted update detectable.
use core::sync::atomic::{AtomicU64, Ordering};
use cyxia_prototype::{
    domains::Error,
    policy::{ExecutionState, ModelBinding},
};

pub const SLOTS: usize = 64;
pub const HEADER_WORDS: usize = 512;
pub const RECORD_WORDS: usize = 640;
const INPUT: usize = 32;
const OUTPUT: usize = 544;
const SEQLOCK: usize = 639;
#[repr(C, align(4096))]
pub struct Evidence([AtomicU64; HEADER_WORDS + SLOTS * RECORD_WORDS]);
#[used]
#[unsafe(no_mangle)]
pub static DOMAIN_CONTROL_EVIDENCE: Evidence =
    Evidence([const { AtomicU64::new(0) }; HEADER_WORDS + SLOTS * RECORD_WORDS]);
fn put(index: usize, value: u64) {
    DOMAIN_CONTROL_EVIDENCE.0[index].store(value, Ordering::Relaxed);
}
fn get(index: usize) -> u64 {
    DOMAIN_CONTROL_EVIDENCE.0[index].load(Ordering::Acquire)
}
fn add(index: usize) {
    DOMAIN_CONTROL_EVIDENCE.0[index].fetch_add(1, Ordering::Relaxed);
}
fn base(slot: usize) -> usize {
    HEADER_WORDS + slot * RECORD_WORDS
}
fn begin_write(at: usize) {
    DOMAIN_CONTROL_EVIDENCE.0[at + SEQLOCK].fetch_add(1, Ordering::AcqRel);
}
fn end_write(at: usize) {
    DOMAIN_CONTROL_EVIDENCE.0[at + SEQLOCK].fetch_add(1, Ordering::Release);
}
fn family(domain: u64, kind: u64) -> usize {
    match (domain, kind) {
        (1, 1) => 0,
        (1, 2) => 1,
        (2..=15, 1) => domain as usize,
        (16, 1) => 16,
        (16, 2) => 17,
        _ => 18,
    }
}
pub fn initialize(boot: u64, model: ModelBinding) {
    put(1, 1);
    put(2, boot);
    put(12, SLOTS as u64);
    put(13, RECORD_WORDS as u64);
    put(14, model.generation);
    for (at, hash) in [(16, model.model_hash), (20, model.schema_hash)] {
        for i in 0..4 {
            put(
                at + i,
                u64::from_le_bytes(hash[i * 8..i * 8 + 8].try_into().unwrap()),
            );
        }
    }
    // The embedded bootstrap model is explicitly untrained.
    put(24, 0);
    DOMAIN_CONTROL_EVIDENCE.0[0].store(0x435958444f4d3031, Ordering::Release);
}
pub fn registered(index: usize) {
    DOMAIN_CONTROL_EVIDENCE.0[3].fetch_or(1u64 << index, Ordering::Release);
}
/// Reserved header words, all writers under the original control-owner gate.
/// 128 magic,129 schema,130 visits,131 denials,132..136 reason counts;
/// 136..158 latest exact context,159 seqlock;192..214 first denied candidate.
/// Reason: 0 open,1 no boot,2 live job,3 optimizer stopped,4 governance lease.
pub fn preparation_admission(context: [u64; 22]) {
    DOMAIN_CONTROL_EVIDENCE.0[159].fetch_add(1, Ordering::AcqRel);
    put(128, 0x4359_4144_4d49_0001);
    put(129, 1);
    add(130);
    let reason = context[2];
    if reason != 0 {
        add(131);
        if reason <= 4 {
            add(131 + reason as usize);
        }
        if get(218) == 0 {
            for (i, value) in context.iter().copied().enumerate() {
                put(192 + i, value);
            }
            put(218, 1);
        }
    }
    for (i, value) in context.into_iter().enumerate() {
        put(136 + i, value);
    }
    DOMAIN_CONTROL_EVIDENCE.0[159].fetch_add(1, Ordering::Release);
}
/// Independent header seqlock:160 magic,161 schema,162 transitions,164..184
/// immutable first transition context,191 publication. Partial CPU sum is a
/// lower bound, not a newly measured total or a fabricated rejection cause.
pub fn optimization_stop(context: [u64; 20]) {
    DOMAIN_CONTROL_EVIDENCE.0[191].fetch_add(1, Ordering::AcqRel);
    put(160, 0x4359_4f50_5354_0001);
    put(161, 1);
    add(162);
    if get(164) == 0 {
        for (i, value) in context.into_iter().enumerate() {
            put(164 + i, value);
        }
    }
    DOMAIN_CONTROL_EVIDENCE.0[191].fetch_add(1, Ordering::Release);
}
/// Original candidate pre-executor Stale, independent of the first scope trace.
/// Header220..255: magic/schema/count/first-present,31 facts,255 seqlock.
/// The Control gate owns this lane; only its first matching payload is retained.
pub fn candidate_stale(context: [u64; 31]) {
    DOMAIN_CONTROL_EVIDENCE.0[255].fetch_add(1, Ordering::AcqRel);
    put(220, 0x4359_5354_414c_0001);
    put(221, 1);
    put(222, get(222).saturating_add(1));
    if get(223) == 0 {
        for (i, value) in context.into_iter().enumerate() {
            put(224 + i, value);
        }
        put(223, 1);
    }
    DOMAIN_CONTROL_EVIDENCE.0[255].fetch_add(1, Ordering::Release);
}
/// Services-owner writer, independent of Control/Task header publications.
/// Per recipe 1/2:256/320, latest +8..+33, first Unknown +36..+61,
/// +2 total, +3 current-identity polls, +4 identity changes, +5 first present,
/// +63 seqlock. First Unknown belongs only to the latest full ApplyId.
pub fn recovery_observation(
    observation: &cyxia_prototype::domains::maintenance::RecoveryObservation,
    cpu: u64,
) {
    let r = observation.receipt;
    if !(1..=2).contains(&r.recipe) {
        return;
    }
    let at = 256 + (usize::from(r.recipe) - 1) * 64;
    let apply = r.apply;
    let identity = [
        apply.boot_epoch,
        apply.controller_epoch,
        apply.plan_seq,
        u64::from(apply.action_index),
        apply.target.id,
        apply.target.generation,
    ];
    DOMAIN_CONTROL_EVIDENCE.0[at + 63].fetch_add(1, Ordering::AcqRel);
    if identity
        .iter()
        .enumerate()
        .any(|(i, value)| get(at + 8 + i) != *value)
    {
        put(at + 3, 0);
        put(at + 5, 0);
        add(at + 4);
        for i in 36..62 {
            put(at + i, 0);
        }
    }
    let before = state(observation.state_before);
    let after = state(r.state);
    let (result, error) = match observation.result {
        Ok(true) => (1, 0),
        Ok(false) => (2, 0),
        Err(e) => (3, e as u64 + 1),
    };
    let policy = observation.policy.unwrap_or_default();
    let row = [
        identity[0],
        identity[1],
        identity[2],
        identity[3],
        identity[4],
        identity[5],
        u64::from(r.recipe),
        policy.version,
        r.generation,
        r.started_ns,
        observation.at_ns,
        u64::from(observation.phase_before),
        u64::from(observation.issued_before),
        u64::from(observation.phase_after),
        u64::from(observation.issued_after),
        u64::from(observation.method),
        result,
        error,
        before.0,
        before.1,
        after.0,
        after.1,
        r.finished_ns,
        policy.snapshot_ns,
        policy.installed_until_ns,
        cpu,
    ];
    put(at, 0x4359_5253_5643_0001);
    put(at + 1, 1);
    add(at + 2);
    add(at + 3);
    for (i, value) in row.iter().copied().enumerate() {
        put(at + 8 + i, value);
    }
    if r.state == ExecutionState::Unknown && get(at + 5) == 0 {
        for (i, value) in row.into_iter().enumerate() {
            put(at + 36 + i, value);
        }
        put(at + 5, 1);
    }
    DOMAIN_CONTROL_EVIDENCE.0[at + 63].fetch_add(1, Ordering::Release);
}
/// TaskGuard writer. Per recipe 1/2:384/448, latest +8..+55, first blocked
/// summary +56..+61, +5 presence, +63 independent seqlock. No clock/query.
pub fn recovery_predicate(recipe: u16, context: [u64; 48]) {
    if !(1..=2).contains(&recipe) {
        return;
    }
    let at = 384 + (usize::from(recipe) - 1) * 64;
    DOMAIN_CONTROL_EVIDENCE.0[at + 63].fetch_add(1, Ordering::AcqRel);
    if context[..6]
        .iter()
        .enumerate()
        .any(|(i, value)| get(at + 8 + i) != *value)
    {
        put(at + 3, 0);
        put(at + 5, 0);
        add(at + 4);
        for i in 56..62 {
            put(at + i, 0);
        }
    }
    put(at, 0x4359_5254_534b_0001);
    put(at + 1, 1);
    add(at + 2);
    add(at + 3);
    if (context[9] != 0 || context[10] == 3) && get(at + 5) == 0 {
        for (i, value) in [
            context[9],
            context[8],
            context[6],
            context[7],
            get(at + 2),
            context[10],
        ]
        .into_iter()
        .enumerate()
        {
            put(at + 56 + i, value);
        }
        put(at + 5, 1);
    }
    for (i, value) in context.into_iter().enumerate() {
        put(at + 8 + i, value);
    }
    DOMAIN_CONTROL_EVIDENCE.0[at + 63].fetch_add(1, Ordering::Release);
}
/// Called under the same control-owner gate as begin/finish/progress. An
/// accepted action owns its original input until the executor settles it;
/// UNKNOWN is a live obligation, not an eviction opportunity. A full capture
/// table applies backpressure before another candidate is registered.
pub fn available_slot(start: usize) -> Option<usize> {
    (0..SLOTS)
        .map(|offset| (start + offset) % SLOTS)
        .find(|&slot| {
            let at = base(slot);
            get(at + SEQLOCK) & 1 == 0
                && (get(at) == 0
                    || get(at + 30) != 0 && (get(at + 13) == 0 || matches!(get(at + 14), 2 | 3)))
        })
}
pub fn begin(slot: usize, input: &[u64; 512], input_hash: [u8; 32]) {
    let at = base(slot);
    begin_write(at);
    put(at, 0);
    for i in 1..SEQLOCK {
        put(at + i, 0);
    }
    put(at + 1, input[2]);
    put(at + 2, input[8]);
    put(at + 3, input[9]);
    put(at + 4, input[10]);
    put(at + 5, input[11]);
    put(at + 6, input[3]);
    put(at + 7, input[14]);
    put(at + 8, input[4]);
    put(at + 16, input[15]);
    put(at + 17, u64::MAX);
    put(at + 20, input[5]);
    for (i, word) in input.iter().enumerate() {
        put(at + INPUT + i, *word);
    }
    for i in 0..4 {
        put(
            at + 608 + i,
            u64::from_le_bytes(input_hash[i * 8..i * 8 + 8].try_into().unwrap()),
        );
    }
    put(at, input[2]);
    end_write(at);
    put(4, input[2]);
    put(11, slot as u64);
    add(32 + family(input[8], input[9]));
}
fn error(error: Error) -> u64 {
    match error {
        Error::Format => 1,
        Error::Auth => 2,
        Error::Schema => 3,
        Error::Stale => 4,
        Error::Capacity => 5,
        Error::Budget => 6,
        Error::Conflict => 7,
        Error::Expired => 8,
        Error::Unsupported => 9,
        Error::Busy => 10,
        Error::Again => 11,
        Error::NotFound => 12,
        Error::Exists => 13,
        Error::NotDirectory => 14,
        Error::IsDirectory => 15,
        Error::NotEmpty => 16,
        Error::Range => 17,
        Error::Io => 18,
        Error::Overflow => 19,
        Error::NotReady => 20,
    }
}
fn state(value: ExecutionState) -> (u64, u64) {
    match value {
        ExecutionState::Pending => (1, 0),
        ExecutionState::Applied => (2, 0),
        ExecutionState::Failed(e) => (3, error(e)),
        ExecutionState::Unknown => (4, 0),
    }
}
#[allow(clippy::too_many_arguments)]
pub fn finish(
    slot: usize,
    sequence: u64,
    cpu_ns: u64,
    encode_ns: u64,
    decode_ns: u64,
    publication_ns: u64,
    approved_version: u64,
    outcome: ExecutionState,
    selected: u64,
    output: Option<&[u64; 512]>,
) {
    let at = base(slot);
    if get(at) != sequence || get(at + 30) != 0 {
        return;
    }
    begin_write(at);
    let (status, code) = state(outcome);
    put(at + 9, crate::domain_platform::now_ns());
    put(at + 10, cpu_ns);
    put(at + 11, encode_ns);
    put(at + 12, publication_ns);
    put(at + 13, approved_version);
    put(at + 14, status);
    put(at + 15, code);
    put(at + 17, selected);
    put(at + 18, u64::from(publication_ns > 500_000));
    put(at + 19, u64::from(output.is_some()));
    put(at + 29, decode_ns);
    put(at + 30, 1);
    if let Some(output) = output {
        for (i, word) in output[..64].iter().enumerate() {
            put(at + OUTPUT + i, *word);
        }
    }
    end_write(at);
    if approved_version == 0 {
        add(6);
        add(96 + family(get(at + 2), get(at + 3)));
    } else {
        add(5);
    }
}
pub fn progress(slot: usize, sequence: u64, version: u64, outcome: ExecutionState, now: u64) {
    let at = base(slot);
    let (status, code) = state(outcome);
    if get(at) != sequence
        || get(at + 13) != version
        || get(at + 14) == status && get(at + 15) == code
    {
        return;
    }
    begin_write(at);
    put(at + 14, status);
    put(at + 15, code);
    put(at + 28, now);
    end_write(at);
    match outcome {
        ExecutionState::Applied => {
            add(7);
            add(64 + family(get(at + 2), get(at + 3)));
        }
        ExecutionState::Failed(_) => add(8),
        ExecutionState::Unknown => add(9),
        ExecutionState::Pending => (),
    }
}
pub fn aborted() {
    add(10);
}
pub fn observer_failed(domain: u16, version: u64, failure: Error) {
    if get(25) == 0 {
        put(26, u64::from(domain));
        put(27, version);
        DOMAIN_CONTROL_EVIDENCE.0[25].store(error(failure), Ordering::Release);
    }
}
pub fn stability_failed(domain: u16, version: u64, failure: Error) {
    if get(28) == 0 {
        put(29, u64::from(domain));
        put(30, version);
        DOMAIN_CONTROL_EVIDENCE.0[28].store(error(failure), Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn proposal(sequence: u64, domain: u64) -> ([u64; 512], [u8; 32]) {
        let mut input = core::array::from_fn(|i| sequence * 1024 + i as u64);
        input[2] = sequence;
        input[8] = domain;
        input[9] = 1;
        let bytes: Vec<_> = input.iter().flat_map(|w| w.to_le_bytes()).collect();
        (input, Sha256::digest(bytes).into())
    }

    #[test]
    fn delayed_executor_retains_original_input_reply_and_hash_until_real_terminal() {
        // Use the actual native record writer and allocator. D12 can wait for
        // a later TLS admission while unrelated control jobs wrap the ring.
        let (input, hash) = proposal(1, 12);
        let reply = [0x55u64; 512];
        assert_eq!(available_slot(0), Some(0));
        begin(0, &input, hash);
        finish(
            0,
            1,
            10,
            20,
            30,
            40,
            7,
            ExecutionState::Pending,
            2,
            Some(&reply),
        );
        progress(0, 1, 7, ExecutionState::Unknown, 50_000_001);
        for sequence in 2..=4 * SLOTS as u64 {
            let start = (sequence as usize - 1) % SLOTS;
            let slot = available_slot(start).unwrap();
            assert_ne!(slot, 0, "pending TLS admission lost its original input");
            let (other, digest) = proposal(sequence, 10);
            begin(slot, &other, digest);
            finish(
                slot,
                sequence,
                1,
                1,
                1,
                1,
                sequence + 7,
                ExecutionState::Pending,
                0,
                Some(&reply),
            );
            progress(
                slot,
                sequence,
                sequence + 7,
                ExecutionState::Applied,
                sequence,
            );
        }
        let at = base(0);
        assert_eq!(get(at), 1);
        assert_eq!(get(at + 13), 7);
        assert_eq!(get(at + 14), 4);
        assert_eq!(
            core::array::from_fn::<_, 512, _>(|i| get(at + INPUT + i)),
            input
        );
        assert_eq!(
            core::array::from_fn::<_, 64, _>(|i| get(at + OUTPUT + i)),
            reply[..64]
        );
        let stored_hash: Vec<_> = (0..4)
            .flat_map(|i| get(at + 608 + i).to_le_bytes())
            .collect();
        assert_eq!(stored_hash, hash);
        progress(0, 2, 7, ExecutionState::Applied, 3_000_000_000);
        progress(0, 1, 8, ExecutionState::Applied, 3_000_000_000);
        assert_eq!(
            get(at + 14),
            4,
            "another sequence/version cannot settle this action"
        );
        progress(0, 1, 7, ExecutionState::Applied, 3_000_000_000);
        assert_eq!(get(at + 14), 2);
        assert_eq!(get(at + 28), 3_000_000_000);
        assert_eq!(get(64 + 12), 1);
        assert_eq!(available_slot(0), Some(0));

        // Every live slot is retained, including unfinished inference and
        // UNKNOWN. No new job may evict one just to keep making progress.
        for slot in 0..SLOTS {
            let sequence = 1000 + slot as u64;
            let (pending, digest) = proposal(sequence, 12);
            begin(slot, &pending, digest);
            if slot != 0 {
                finish(
                    slot,
                    sequence,
                    1,
                    1,
                    1,
                    1,
                    sequence,
                    ExecutionState::Pending,
                    0,
                    Some(&reply),
                );
                progress(slot, sequence, sequence, ExecutionState::Unknown, sequence);
            }
        }
        assert_eq!(available_slot(0), None);
        finish(
            0,
            1000,
            1,
            1,
            1,
            0,
            0,
            ExecutionState::Failed(Error::Expired),
            0,
            None,
        );
        assert_eq!(available_slot(1), Some(0));
        progress(
            7,
            1007,
            1007,
            ExecutionState::Failed(Error::Again),
            4_000_000_000,
        );
        assert_eq!(available_slot(7), Some(7));
    }
}
