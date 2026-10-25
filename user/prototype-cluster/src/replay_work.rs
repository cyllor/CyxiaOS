//! Bounded copied requests from the protected replay owner. This carries
//! business identities/results only; it is never an authority for CPU time.
use cyxia_prototype::{domains::{Error, ObjectKey}, learning::capture::RunKey};
pub const BYTES: usize = 72;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Work { pub run: RunKey, pub id: u64, pub family: u16, pub kind: u16,
    pub arrived_ns: u64, pub deadline_ns: u64, pub seed: u64 }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkResult { pub id: u64, pub outcome: u64, pub target: ObjectKey,
    pub started_ns: u64, pub finished_ns: u64 }
fn words(bytes: &[u8]) -> Result<[u64; 9], Error> {
    if bytes.len() != BYTES { return Err(Error::Format); }
    Ok(core::array::from_fn(|i| u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap())))
}
fn encode(words: [u64; 9]) -> [u8; BYTES] {
    let mut out = [0; BYTES];
    for (i, v) in words.into_iter().enumerate() { out[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes()); } out
}
impl Work {
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let v = words(bytes)?;
        let w = Self { run: RunKey { boot_epoch: v[0], trial_id: v[1], generation: v[2] }, id: v[3],
            family: u16::try_from(v[4]).map_err(|_| Error::Range)?, kind: u16::try_from(v[5]).map_err(|_| Error::Range)?,
            arrived_ns: v[6], deadline_ns: v[7], seed: v[8] };
        if w.run.boot_epoch == 0 || w.run.trial_id == 0 || w.run.generation == 0 || !(1..256).contains(&w.id)
            || !matches!((w.family, w.kind), (10, 1) | (12, 1) | (16, 1) | (16, 2))
            || w.deadline_ns <= w.arrived_ns { return Err(Error::Format); }
        Ok(w)
    }
    pub fn encode(self) -> [u8; BYTES] { encode([self.run.boot_epoch, self.run.trial_id, self.run.generation,
        self.id, self.family as u64, self.kind as u64, self.arrived_ns, self.deadline_ns, self.seed]) }
}
impl WorkResult {
    pub fn encode(self, run: RunKey) -> [u8; BYTES] { encode([run.boot_epoch, run.trial_id, run.generation,
        self.id, self.outcome, self.target.id, self.target.generation, self.started_ns, self.finished_ns]) }
}
pub fn payload(seed: u64, id: u64) -> ([u8; 64], u64) {
    let mut bytes = [0; 64]; let mut sum = 0;
    for (i, b) in bytes.chunks_exact_mut(8).enumerate() {
        let value = (seed.rotate_left(i as u32) ^ id.wrapping_mul(17) ^ i as u64) & 0xffff;
        sum += value; b.copy_from_slice(&value.to_le_bytes());
    }
    (bytes, sum)
}
