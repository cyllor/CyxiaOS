//! Bounded, non-authoritative TLS session-exit diagnostics. These codes explain
//! why the EL0 service left one session; they never grant identity or recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum SessionExitReason {
    ConnectionLost = 1,
    ClockUnavailable = 2,
    DomainTick = 3,
    TcpRead = 4,
    TlsReceive = 5,
    TlsPump = 6,
    HandshakeTicket = 7,
    HandshakeFinish = 8,
    EnterAuthenticated = 9,
    PlaintextIngest = 10,
    PlaintextConsume = 11,
    DriverTick = 12,
    ReplayReconnect = 13,
    TlsEgress = 14,
}

impl SessionExitReason {
    pub const EVENT_BASE: u64 = 0x230;

    pub const fn trace_event(self) -> u64 {
        Self::EVENT_BASE + self as u64
    }
}

#[cfg(test)]
mod tests {
    use super::SessionExitReason;

    #[test]
    fn exit_events_are_stable_unique_and_nonfatal() {
        let reasons = [
            SessionExitReason::ConnectionLost,
            SessionExitReason::ClockUnavailable,
            SessionExitReason::DomainTick,
            SessionExitReason::TcpRead,
            SessionExitReason::TlsReceive,
            SessionExitReason::TlsPump,
            SessionExitReason::HandshakeTicket,
            SessionExitReason::HandshakeFinish,
            SessionExitReason::EnterAuthenticated,
            SessionExitReason::PlaintextIngest,
            SessionExitReason::PlaintextConsume,
            SessionExitReason::DriverTick,
            SessionExitReason::ReplayReconnect,
            SessionExitReason::TlsEgress,
        ];
        for (index, reason) in reasons.into_iter().enumerate() {
            assert_eq!(reason.trace_event(), 0x231 + index as u64);
            assert!(!(0xfe..=0x108).contains(&reason.trace_event()));
            assert!(reason.trace_event() < 0xf000);
        }
    }
}
