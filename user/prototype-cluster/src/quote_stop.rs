//! Actual quote-owner stop latch. A replay stop never cancels an issued quote
//! and only a genuinely newer installed positive offer can reopen publication.
use crate::abi::{QuoteStopReceiptWire, QuoteStopWire, DOMAIN_APPLIED, DOMAIN_REJECTED};

pub struct Owner {
    latest: QuoteStopReceiptWire,
    accepted: QuoteStopReceiptWire,
    high_sequence: u64,
    stopped_at_version: Option<u64>,
}
impl Owner {
    pub const fn new() -> Self {
        Self { latest: QuoteStopReceiptWire::EMPTY, accepted: QuoteStopReceiptWire::EMPTY,
            high_sequence: 0, stopped_at_version: None }
    }
    pub fn stopped(&self) -> bool { self.stopped_at_version.is_some() }
    pub fn receipt(&self) -> QuoteStopReceiptWire { self.latest }
    /// Called only after QuotePolicy accepted this exact positive version.
    pub fn installed(&mut self, version: u64) {
        if self.stopped_at_version.is_some_and(|old| version > old) {
            self.stopped_at_version = None;
        }
    }
    pub fn apply(&mut self, command: QuoteStopWire, boot: u64, offer_version: u64, now: u64) {
        if command.sequence == 0 || command == self.latest.command { return; }
        if command == self.accepted.command { self.latest = self.accepted; return; }
        let valid = command.boot_epoch == boot && command.replay_id != 0
            && command.owner_id != 0 && command.owner_generation != 0
            && command.sequence > self.high_sequence && command.issued_ns <= now;
        self.latest = QuoteStopReceiptWire { command, offer_version, started_ns: now,
            finished_ns: now, outcome: if valid { DOMAIN_APPLIED } else { DOMAIN_REJECTED } };
        if valid {
            self.accepted = self.latest;
            self.high_sequence = command.sequence;
            self.stopped_at_version = Some(offer_version);
        }
    }
}
impl Default for Owner { fn default() -> Self { Self::new() } }
