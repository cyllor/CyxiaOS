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
    IngressBegin = 15,
    TlsCreate = 16,
}

/// Stable classification; rustls error internals and strings never leave EL0.
pub fn tls_result(error: &cyxia_cluster_transport::tls::Error) -> u64 {
    use cyxia_cluster_transport::tls::Error::*;
    0x1000
        + match error {
            Identity => 1,
            Entropy => 2,
            Time => 3,
            Clock => 4,
            Timeout => 5,
            Protocol(_) => 6,
            Buffer => 7,
            WouldBlock => 8,
            Handshake => 9,
            Closed => 10,
            Direction => 11,
        }
}

pub fn domain_result(error: cyxia_prototype::domains::Error) -> u64 {
    0x2001 + error as u64
}

/// Preserve the original POLL branch instead of collapsing all failures to a
/// disconnected boolean. None means this exact session remains live.
pub fn connection_result(result: Result<(bool, u64), u64>, expected: u64) -> Option<u64> {
    match result {
        Ok((true, epoch)) if epoch == expected => None,
        Ok((false, _)) => Some(0x4005),
        Ok((true, _)) => Some(0x4004),
        Err(status) => Some(0x3000 + status),
    }
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
    fn poll_exit_distinguishes_original_error_disconnect_and_replacement() {
        use super::connection_result;
        assert_eq!(connection_result(Ok((true, 7)), 7), None);
        assert_eq!(connection_result(Ok((false, 7)), 7), Some(0x4005));
        assert_eq!(connection_result(Ok((true, 8)), 7), Some(0x4004));
        assert_eq!(connection_result(Err(3), 7), Some(0x3003));
    }

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
