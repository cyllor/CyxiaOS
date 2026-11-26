//! Evidence for the authenticated Supervisor's multi-handle turn.
//! The driver retains the exact live selectors through grant retirement.

use super::{
    ACK_VOLATILE, CLOSE, E_AUTH, E_CONFLICT, E_STALE, EAGAIN, OPEN, READ, Request, evidence, report,
};

const LIVE_HANDLES: usize = 4;
const EXPECTED_DENIALS: u8 = 0x7f;
const EXPECTED_REVOKED: u8 = (1 << LIVE_HANDLES) - 1;

#[derive(Clone, Copy, Default)]
pub(super) struct SessionChecks {
    peak: u64,
    opens: u64,
    reads: u64,
    closes: u64,
    replays: u64,
    acks: u64,
    denials: u8,
    revoked: u8,
    retired: [u64; LIVE_HANDLES],
}

impl SessionChecks {
    pub(super) fn record_success(&mut self, op: u16, replay: bool, live: usize) {
        self.peak = self.peak.max(live as u64);
        if replay {
            self.replays = self.replays.saturating_add(1);
            return;
        }
        let count = match op {
            OPEN => &mut self.opens,
            READ => &mut self.reads,
            CLOSE => &mut self.closes,
            ACK_VOLATILE => &mut self.acks,
            _ => return,
        };
        *count = count.saturating_add(1);
    }

    pub(super) fn record_denial(&mut self, request: Request<'_>, errno: i64) {
        self.denials |= match (request.op, request.request_id, errno) {
            (OPEN, 24, EAGAIN) => 1 << 0,
            (READ, 24, E_CONFLICT) => 1 << 1,
            (ACK_VOLATILE, 24, EAGAIN) => 1 << 2,
            (READ, 26, E_STALE) => 1 << 3,
            (OPEN, 20, E_STALE) => 1 << 4,
            (READ, 28, EAGAIN) => 1 << 5,
            (READ, 28, E_AUTH) => 1 << 6,
            _ => 0,
        };
    }

    pub(super) fn turn_complete(&self, live: usize, retained: usize) -> bool {
        let acks = if cfg!(feature = "v020-production-file-volatile-write") {
            9
        } else {
            12
        };
        live == LIVE_HANDLES
            && retained == 0
            && (
                self.peak,
                self.opens,
                self.reads,
                self.closes,
                self.replays,
                self.acks,
            ) == (LIVE_HANDLES as u64, 5, 3, 1, 2, acks)
            && self.denials == EXPECTED_DENIALS
    }

    pub(super) fn retire(&mut self, selectors: [u64; LIVE_HANDLES]) {
        self.retired = selectors;
    }

    pub(super) fn record_revocation(&mut self, request: Request<'_>, selector: u64) {
        if request.op != READ || !(101..=104).contains(&request.request_id) || selector == 0 {
            return;
        }
        if let Some(index) = self.retired.iter().position(|&live| live == selector) {
            self.revoked |= 1 << index;
            self.retired[index] = 0;
        }
    }

    pub(super) const fn retirement_confirmed(&self) -> bool {
        self.revoked == EXPECTED_REVOKED
    }

    pub(super) fn publish(self, boot: u64) {
        let denials = u64::from(self.denials);
        let revoked = u64::from(self.revoked);
        for (i, word) in [
            boot,
            self.peak,
            self.opens,
            self.reads,
            self.closes,
            self.replays,
            self.acks,
            denials,
            revoked,
        ]
        .into_iter()
        .enumerate()
        {
            evidence::put(evidence::W20_FILE_SESSIONS + i, word);
        }
        report("V020_W20_FILE_HANDLES", boot, self.peak, self.opens);
        report("V020_W20_FILE_IO", self.reads, self.closes, self.replays);
        report("V020_W20_FILE_CHECKS", self.acks, denials, revoked);
    }
}
