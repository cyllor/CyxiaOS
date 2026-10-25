//! Resumable numerical jobs and protected completion admission. Preparation
//! starts from already accepted replay labels; untrusted wire rows cannot be
//! promoted back into AcceptedSample. All expensive arithmetic runs in Worker.
mod accept;
mod encode;
mod execute;
pub use accept::{CompletionAuthority, CompletionClaim, PreparedJob};
pub use encode::{Encoder, EncoderState};
pub use execute::Worker;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    pub completed: u64,
    pub done: bool,
}
