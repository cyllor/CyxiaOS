//! Experimental continuous-runtime ABI. This is not the 1.3 PolicyEnvelope.
pub const INPUT_VA: u64 = 0xa0000;
pub const OUTPUT_VA: u64 = 0xa1000;
pub const MODEL_VA: u64 = 0x90000;
pub const STACK_TOP: u64 = 0xb9000;
pub const INPUT_MAGIC: u64 = 0x4359585254494e31;
pub const OUTPUT_MAGIC: u64 = 0x43595852544f5531;
pub const INPUT_WORDS: usize = 16;
pub const OUTPUT_WORDS: usize = 8;
pub const SUBMIT: u64 = 0x541;
pub const MODEL_BYTES: usize = 2772;
#[path = "../../crates/prototype/src/learning/seed.rs"]
mod domain_seed;
/// Candidate-sensitive initialization for the unified eighteen-family path.
/// This remains explicitly untrained. Standalone diagnostic ABI 1/2 keeps its
/// original known-vector fixture; normal ABI 3 jobs map the registered bank.
pub const fn domain_model_bytes() -> [u8; MODEL_BYTES] {
    domain_seed::UNTRAINED_SEED0_BYTES
}
/// Hand-authored bootstrap model: score the positive observed service deficit.
/// It is deliberately labelled untrained and cannot certify 1.3 model governance.
pub const fn model_bytes() -> [u8; MODEL_BYTES] {
    let mut bytes = [0; MODEL_BYTES];
    bytes[0] = 64;
    bytes[1] = (-64i8) as u8;
    bytes[2048] = 64;
    bytes[2560] = 64;
    bytes
}
pub fn candidates(delta: [u64; 2]) -> [[i16; 64]; 2] {
    let mut out = [[0; 64]; 2];
    out[0][0] = delta[1].min(i16::MAX as u64) as i16;
    out[0][1] = delta[0].min(i16::MAX as u64) as i16;
    out[1][0] = out[0][1];
    out[1][1] = out[0][0];
    out
}

/// Score fixed candidate identities [one control core, two control cores].
pub fn core_candidates(backlog: u64) -> [[i16; 64]; 2] {
    let mut out = [[0; 64]; 2];
    // Same local MLP and stable argmax as resource selection. These are candidate
    // features, never an EL1 load-threshold branch choosing the destination.
    out[0][0] = 4;
    out[1][0] = backlog.min(i16::MAX as u64) as i16;
    out
}
