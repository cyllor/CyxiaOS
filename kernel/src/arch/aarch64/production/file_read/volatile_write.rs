//! Evidence for the authenticated CPU0 file overwrite turn.

use super::{
    ACK_VOLATILE, E_AUTH, E_CONFLICT, E_FORMAT, E_STALE, READ, Request, WRITE, evidence, report,
};

#[derive(Default)]
pub(super) struct WriteChecks {
    writes: u64,
    reads: u64,
    replays: u64,
    acks: u64,
    denials: u8,
}

impl WriteChecks {
    pub(super) fn record_success(&mut self, op: u16, replay: bool) {
        let count = match (op, replay) {
            (WRITE, false) => &mut self.writes,
            (READ, false) => &mut self.reads,
            (WRITE, true) => &mut self.replays,
            (ACK_VOLATILE, false) => &mut self.acks,
            _ => return,
        };
        *count = count.saturating_add(1);
    }

    pub(super) fn record_denial(&mut self, request: Request<'_>, errno: i64) {
        self.denials |= match (request.op, request.request_id, errno) {
            (WRITE, 13, E_FORMAT) => 1 << 0,
            (WRITE, 13, E_CONFLICT) => 1 << 1,
            (WRITE, 18, E_STALE) => 1 << 2,
            (WRITE, 19, E_AUTH) => 1 << 3,
            _ => 0,
        };
    }

    pub(super) fn turn_complete(&self, service: &super::FileReadService) -> bool {
        service.live_handles() == 0
            && service.retained_count() == 0
            && service.write_sequence() == 2
            && (
                self.writes,
                self.reads,
                self.replays,
                self.acks,
                self.denials,
            ) == (2, 2, 1, 9, 15)
    }

    pub(super) fn publish(self, boot: u64, rights: u32, write_sequence: u64) {
        let rights = u64::from(rights);
        let denials = u64::from(self.denials);
        for (i, word) in [
            boot,
            rights,
            self.writes,
            write_sequence,
            self.reads,
            self.replays,
            denials,
            self.acks,
        ]
        .into_iter()
        .enumerate()
        {
            evidence::put(evidence::W21_VOLATILE_WRITE + i, word);
        }
        report("V020_W21_WRITE", boot, rights, self.writes);
        report(
            "V020_W21_WRITE_READBACK",
            self.reads,
            write_sequence,
            self.replays,
        );
        report("V020_W21_WRITE_CHECKS", self.acks, denials, 0);
    }
}
