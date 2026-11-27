//! Frozen SecurityProfile v3 time limits for a native TLS connection.

pub const TLS_HANDSHAKE_MS: u16 = 3000;
pub const TLS_RECORD_IDLE_MS: u16 = 1000;
pub const TLS_ACTIVE_IDLE_SECONDS: u16 = 30;
pub const TLS_SESSION_SECONDS: u16 = 300;
const HANDSHAKE_NS: u64 = TLS_HANDSHAKE_MS as u64 * 1_000_000;
const RECORD_IDLE_NS: u64 = TLS_RECORD_IDLE_MS as u64 * 1_000_000;
const ACTIVE_IDLE_NS: u64 = TLS_ACTIVE_IDLE_SECONDS as u64 * 1_000_000_000;
const SESSION_NS: u64 = TLS_SESSION_SECONDS as u64 * 1_000_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Pending,
    Active,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Limit {
    Lifetime,
    Idle,
}

#[derive(Clone, Copy)]
pub struct TlsWindow {
    phase: Phase,
    start_ns: u64,
    lifetime_end_ns: u64,
    last_read_ns: u64,
}

impl TlsWindow {
    pub fn new(phase: Phase, start_ns: u64) -> Option<Self> {
        let lifetime = match phase {
            Phase::Pending => HANDSHAKE_NS,
            Phase::Active => SESSION_NS,
        };
        Some(Self {
            phase,
            start_ns,
            lifetime_end_ns: start_ns.checked_add(lifetime)?,
            last_read_ns: start_ns,
        })
    }

    pub fn start_ns(self) -> u64 {
        self.start_ns
    }

    pub fn phase(self) -> Phase {
        self.phase
    }

    pub fn last_read_ns(self) -> u64 {
        self.last_read_ns
    }

    pub fn deadline(self) -> (u64, Limit) {
        let idle = match self.phase {
            Phase::Pending => RECORD_IDLE_NS,
            Phase::Active => ACTIVE_IDLE_NS,
        };
        let idle_end = self.last_read_ns.saturating_add(idle);
        if idle_end < self.lifetime_end_ns {
            (idle_end, Limit::Idle)
        } else {
            (self.lifetime_end_ns, Limit::Lifetime)
        }
    }

    pub fn admits_io_at(self, observed_ns: u64) -> bool {
        self.last_read_ns <= observed_ns && observed_ns < self.deadline().0
    }

    /// Called only after a positive read from the protected TCP port. Polls,
    /// sends and empty reads cannot renew the window.
    pub fn record_read(&mut self, observed_ns: u64) -> bool {
        if !self.admits_io_at(observed_ns) {
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
    fn transmit_checks_the_clock_at_admission_and_does_not_extend_the_window() {
        let start = 1_000;
        let active = TlsWindow::new(Phase::Active, start).unwrap();
        let expiry = start + ACTIVE_IDLE_NS;
        assert!(active.admits_io_at(expiry - 1));
        assert!(!active.admits_io_at(expiry));
        assert!(!active.admits_io_at(start - 1));
        assert_eq!(active.deadline(), (expiry, Limit::Idle));
    }

    #[test]
    fn pending_input_stops_at_one_second_and_cannot_reopen() {
        let start = 10;
        let mut pending = TlsWindow::new(Phase::Pending, start).unwrap();
        let idle_end = start + RECORD_IDLE_NS;
        assert_eq!(pending.deadline(), (idle_end, Limit::Idle));
        assert!(!pending.record_read(idle_end));
        assert!(!pending.record_read(idle_end + 1));
        assert_eq!(pending.deadline(), (idle_end, Limit::Idle));
    }

    #[test]
    fn real_progress_never_extends_the_absolute_handshake() {
        let start = 10;
        let mut pending = TlsWindow::new(Phase::Pending, start).unwrap();
        for t in [1, 2, 3, 4] {
            assert!(pending.record_read(start + t * 750_000_000 - 1));
        }
        let end = start + HANDSHAKE_NS;
        assert_eq!(pending.deadline(), (end, Limit::Lifetime));
        assert!(!pending.record_read(end));
        assert!(!pending.record_read(start));
        assert!(TlsWindow::new(Phase::Pending, u64::MAX - HANDSHAKE_NS + 1).is_none());
    }

    #[test]
    fn active_read_moves_the_idle_bound_only_while_the_connection_is_live() {
        let start = 10;
        let mut active = TlsWindow::new(Phase::Active, start).unwrap();
        assert_eq!(active.deadline(), (start + ACTIVE_IDLE_NS, Limit::Idle));
        let read = start + ACTIVE_IDLE_NS - 1;
        assert!(active.record_read(read));
        assert!(!active.record_read(read - 1));
        assert_eq!(active.deadline(), (read + ACTIVE_IDLE_NS, Limit::Idle));
        assert!(!active.record_read(read + ACTIVE_IDLE_NS));
    }

    #[test]
    fn regularly_active_session_keeps_its_original_lifetime_bound() {
        let start = 10;
        let mut active = TlsWindow::new(Phase::Active, start).unwrap();
        for step in 1..=12 {
            assert!(active.record_read(start + step * 25_000_000_000 - 1));
        }
        let deadline = start + SESSION_NS;
        assert_eq!(active.deadline(), (deadline, Limit::Lifetime));
        assert!(!active.record_read(deadline));
        assert!(TlsWindow::new(Phase::Active, u64::MAX - SESSION_NS + 1).is_none());
    }
}
