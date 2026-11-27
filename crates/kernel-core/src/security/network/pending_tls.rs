//! Frozen SecurityProfile v3 time limits for an accepted, unauthenticated TCP connection.

pub const TLS_HANDSHAKE_MS: u16 = 3000;
pub const TLS_RECORD_IDLE_MS: u16 = 1000;
const HANDSHAKE_NS: u64 = TLS_HANDSHAKE_MS as u64 * 1_000_000;
const RECORD_IDLE_NS: u64 = TLS_RECORD_IDLE_MS as u64 * 1_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingLimit {
    Handshake,
    RecordIdle,
}

#[derive(Clone, Copy)]
pub struct PendingTls {
    accepted_ns: u64,
    handshake_end_ns: u64,
    last_read_ns: u64,
}

impl PendingTls {
    pub fn new(accepted_ns: u64) -> Option<Self> {
        Some(Self {
            accepted_ns,
            handshake_end_ns: accepted_ns.checked_add(HANDSHAKE_NS)?,
            last_read_ns: accepted_ns,
        })
    }

    pub fn accepted_ns(self) -> u64 {
        self.accepted_ns
    }

    pub fn deadline(self) -> (u64, PendingLimit) {
        let idle_end = self.last_read_ns.saturating_add(RECORD_IDLE_NS);
        if idle_end < self.handshake_end_ns {
            (idle_end, PendingLimit::RecordIdle)
        } else {
            (self.handshake_end_ns, PendingLimit::Handshake)
        }
    }

    /// Called only after a positive read from the protected TCP port. Polls,
    /// sends and empty reads cannot renew the window.
    pub fn record_read(&mut self, observed_ns: u64) -> bool {
        if observed_ns < self.last_read_ns || observed_ns >= self.deadline().0 {
            return false;
        }
        self.last_read_ns = observed_ns;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_input_stops_at_one_second_and_cannot_reopen() {
        let start = 10;
        let mut pending = PendingTls::new(start).unwrap();
        let idle_end = start + RECORD_IDLE_NS;
        assert_eq!(pending.deadline(), (idle_end, PendingLimit::RecordIdle));
        assert!(!pending.record_read(idle_end));
        assert!(!pending.record_read(idle_end + 1));
        assert_eq!(pending.deadline(), (idle_end, PendingLimit::RecordIdle));
    }

    #[test]
    fn real_progress_never_extends_the_absolute_handshake() {
        let start = 10;
        let mut pending = PendingTls::new(start).unwrap();
        for t in [1, 2, 3, 4] {
            assert!(pending.record_read(start + t * 750_000_000 - 1));
        }
        let end = start + HANDSHAKE_NS;
        assert_eq!(pending.deadline(), (end, PendingLimit::Handshake));
        assert!(!pending.record_read(end));
        assert!(!pending.record_read(start));
        assert!(PendingTls::new(u64::MAX - HANDSHAKE_NS + 1).is_none());
    }
}
