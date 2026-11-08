//! [DEBUG-v15-placement] Actual local broker entry/return and owner outcomes.
//! Eight bounded diagnostic slots never authorize or release any obligation.
use super::{Entry, SpawnState};
use core::sync::atomic::{AtomicU64, Ordering};
use cyxia_prototype::domains::Error;

const ROWS: usize = 8;
const ROW_WORDS: usize = 32;
const MAGIC: u64 = 0x4359_4c52_4551_3031;
pub(super) struct Observation {
    pub index: Option<usize>,
    phase: u64,
    started_ns: u64,
    submit: bool,
    query: bool,
    owner_op: u64,
    owner_state: Option<SpawnState>,
    owner_error: Option<Error>,
}
impl Observation {
    pub fn new(phase: u64, started_ns: u64) -> Self {
        Self {
            index: None,
            phase,
            started_ns,
            submit: false,
            query: false,
            owner_op: 0,
            owner_state: None,
            owner_error: None,
        }
    }
    pub fn owner(&mut self, operation: u64, result: &Result<SpawnState, Error>) {
        self.submit |= operation == 11;
        self.query |= operation == 12;
        self.owner_op = operation;
        self.owner_state = result.as_ref().ok().copied();
        self.owner_error = result.as_ref().err().copied();
    }
    pub fn finish(self, entry: Entry, result: (u64, usize, u64), finished_ns: u64) {
        LOCAL_REQUEST_EVIDENCE.record(self, entry, result, finished_ns);
    }
}
fn state(value: SpawnState) -> (u64, u64, u64, u64) {
    match value {
        SpawnState::Queued => (0, 0, 0, 0),
        SpawnState::Created(key) => (1, 0, key.id, key.generation),
        SpawnState::Failed(error) => (2, error as u64 + 1, 0, 0),
        SpawnState::Unknown => (3, 0, 0, 0),
        SpawnState::Cancelled => (4, 0, 0, 0),
    }
}
/// Header: seqlock, magic, schema, rows, row words, publications,
/// replacements, reserved. Row layout is mirrored by the independent decoder.
#[repr(C, align(64))]
pub struct Evidence([AtomicU64; 8 + ROWS * ROW_WORDS]);
impl Evidence {
    pub const fn new() -> Self {
        Self([const { AtomicU64::new(0) }; 8 + ROWS * ROW_WORDS])
    }
    fn record(
        &self,
        observation: Observation,
        entry: Entry,
        result: (u64, usize, u64),
        finished_ns: u64,
    ) {
        let sequence = self.0[0].load(Ordering::Relaxed);
        if sequence & 1 != 0 || sequence > u64::MAX - 2 {
            return;
        }
        if self.0[0]
            .compare_exchange(sequence, sequence + 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let at = 8 + observation.index.unwrap_or(0) % ROWS * ROW_WORDS;
        if self.0[at].load(Ordering::Relaxed) != entry.key.id
            || self.0[at + 1].load(Ordering::Relaxed) != entry.key.generation
        {
            if self.0[at].load(Ordering::Relaxed) != 0 {
                self.0[6].fetch_add(1, Ordering::Relaxed);
            }
            for slot in &self.0[at..at + ROW_WORDS] {
                slot.store(0, Ordering::Relaxed);
            }
        }
        let (status, error, target, generation) = state(entry.state);
        let (owner_state, owner_error) = observation
            .owner_state
            .map(|v| {
                let s = state(v);
                (s.0, s.1)
            })
            .unwrap_or((
                u64::MAX,
                observation.owner_error.map_or(0, |e| e as u64 + 1),
            ));
        let words = [
            entry.key.id,
            entry.key.generation,
            entry.spawn_id,
            observation.phase,
            result.0,
            result.1 as u64,
            result.2,
            observation.owner_error.map_or(0, |e| e as u64 + 1),
            status,
            error,
            target,
            generation,
            u64::from(entry.retryable),
            u64::from(entry.completion.is_some()),
            u64::from(entry.acknowledged),
            entry.deadline_ns,
            observation.started_ns,
            finished_ns,
        ];
        for (slot, value) in self.0[at..at + 18].iter().zip(words) {
            slot.store(value, Ordering::Relaxed);
        }
        let count = at
            + match observation.phase {
                11 => 18,
                12 => 19,
                _ => 20,
            };
        self.0[count].fetch_add(1, Ordering::Relaxed);
        for (offset, called) in [(21, observation.submit), (22, observation.query)] {
            if called {
                self.0[at + offset].fetch_add(1, Ordering::Relaxed);
            }
        }
        for (offset, value) in [
            (23, observation.owner_op),
            (24, owner_state),
            (25, owner_error),
            (26, entry.input_len),
            (
                27,
                entry
                    .completion
                    .map_or(0, |r| if r.is_ok() { 1 } else { 2 }),
            ),
            (
                28,
                entry
                    .completion
                    .and_then(Result::ok)
                    .map_or(0, |(_, at)| at),
            ),
            (
                29,
                entry
                    .completion
                    .and_then(Result::err)
                    .map_or(0, |e| e as u64 + 1),
            ),
        ] {
            self.0[at + offset].store(value, Ordering::Relaxed);
        }
        for (slot, value) in
            self.0[1..6]
                .iter()
                .zip([MAGIC, 1, ROWS as u64, ROW_WORDS as u64, sequence / 2 + 1])
        {
            slot.store(value, Ordering::Relaxed);
        }
        self.0[0].store(sequence + 2, Ordering::Release);
    }
    #[cfg(test)]
    pub fn snapshot(&self) -> [u64; 8 + ROWS * ROW_WORDS] {
        core::array::from_fn(|i| self.0[i].load(Ordering::Acquire))
    }
}
#[used]
#[unsafe(no_mangle)]
pub static LOCAL_REQUEST_EVIDENCE: Evidence = Evidence::new();
const _: () = assert!(core::mem::size_of::<Evidence>() == 2112);
