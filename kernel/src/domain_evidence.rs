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
