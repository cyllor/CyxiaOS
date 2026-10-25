//! Bounded, durable handoff of ordinary application's immutable requests.
//! Transport failures query the original journal entry; they never issue a
//! second logical request or turn an uncertain START into local fallback.
use super::*;
use cyxia_prototype_cluster::{application as wire, application_journal as journal_app};

pub(super) struct Binding {
    actor: ObjectKey,
    sequence: u64,
    request: PlacementRequest,
    submitted_ns: u64,
    rejected: bool,
    sent: Option<wire::Status>,
    detached: bool,
    expected: u64,
    completion: Option<wire::Completion>,
    completed_sent: bool,
}
impl Binding {
    fn same(&self, record: &journal_app::Record, peer: ObjectKey) -> bool {
        self.actor == record.actor && self.sequence == record.sequence
            && self.submitted_ns == record.submitted_ns && self.request == record.request(peer)
    }
}
pub(super) struct Incoming {
    record: journal_app::Record,
    encoded: Vec<u8>,
    committed: bool,
    scan: u64,
}
impl NativeDomains {
    pub(crate) fn recover_application(&mut self, bytes: &[u8], peer: [u8; 32]) -> Result<(), ()> {
        let record = journal_app::Record::decode(bytes).map_err(|_| ())?;
        self.add_application(record, node_key(peer), false)
    }
    fn add_application(&mut self, record: journal_app::Record, peer: ObjectKey, rejected: bool) -> Result<(), ()> {
        if let Some(old) = self.applications.iter().find(|b|
            b.request.key == record.key || b.actor == record.actor && b.sequence == record.sequence)
        {
            return if old.same(&record, peer) && old.rejected == rejected { Ok(()) } else { Err(()) };
        }
        if self.applications.len() >= 4096 { return Err(()); }
        let request = record.request(peer);
        let expected = record.input.chunks_exact(8).fold(0u64, |sum, b| sum.wrapping_add(u64::from_le_bytes(b.try_into().unwrap())));
        if !rejected {
            if self.payloads.len() >= 32 { return Err(()); }
            self.payloads.push(Payload { request, bytes: record.input });
        }
        self.applications.push(Binding { actor: record.actor, sequence: record.sequence,
            request, submitted_ns: record.submitted_ns, rejected, sent: None, detached: false,
            expected, completion: None, completed_sent: false });
        Ok(())
    }
    pub(crate) fn finish_application_recovery(&mut self) -> Result<(), ()> {
        for b in &self.applications {
            if b.rejected { continue; }
            match self.queue.status(b.request.key) {
                // A fully scanned durable journal has no placement intent for
                // this accepted request. It acquired no execution obligation.
                Err(DomainError::NotFound) => { self.queue.submit(b.request, 0).map_err(|_| ())?; }
                Ok(_) => (),
                Err(_) => return Err(()),
            }
        }
        Ok(())
    }
    pub(super) fn publish_application_status(&mut self) -> Result<(), ()> {
        let count = self.applications.len();
        for offset in 0..count {
            let i = (self.application_cursor + offset) % count;
            let b = &self.applications[i];
            if b.detached || b.sent.is_some_and(wire::Status::terminal) { continue; }
            let (state, target) = if b.rejected {
                (wire::REJECTED, ObjectKey { id: 5, generation: 0 })
            } else {
                match self.queue.status(b.request.key).map_err(|_| ())? {
                    PlacementStatus::Pending | PlacementStatus::Deferred => (wire::PENDING, ObjectKey::default()),
                    PlacementStatus::Unknown => (wire::UNKNOWN, ObjectKey::default()),
                    PlacementStatus::Complete(PlacementOutcome::Local(key)) => (wire::LOCAL, key),
                    PlacementStatus::Complete(PlacementOutcome::Peer { contract, .. }) => (wire::REMOTE, contract),
                    PlacementStatus::Complete(PlacementOutcome::Rejected(_)) =>
                        (wire::REJECTED, ObjectKey { id: 11, generation: 0 }),
                }
            };
            let status = wire::Status { key: b.request.key, state, target };
            if b.sent == Some(status) { continue; }
            let bytes = status.encode().map_err(|_| ())?;
            self.application_cursor = (i + 1) % count;
            match broker::request(OP_TASK, &bytes, &mut [], 0, [14, 0, 0]) {
                Ok(_) => self.applications[i].sent = Some(status),
                // A reboot retired that kernel application's address space.
                // The durable placement obligation still remains in the queue.
                Err(NOT_FOUND) => self.applications[i].detached = true,
                Err(AGAIN) => (),
                Err(_) => return Err(()),
            }
            break;
        }
        Ok(())
    }
}
impl Driver {
    fn application_completions(&mut self, native: &mut NativeDomains, now: u64) -> Result<(), ()> {
        let count = native.applications.len();
        for offset in 0..count {
            let i = (native.application_cursor + offset) % count;
            let b = &mut native.applications[i];
            if b.detached || b.completed_sent { continue; }
            let Some(status) = b.sent.filter(|s| s.terminal()) else { continue; };
            if b.completion.is_none() {
                let result = match status.state {
                    wire::LOCAL => {
                        let mut input = b.request.key.id.to_le_bytes().to_vec();
                        input.extend_from_slice(&b.request.key.generation.to_le_bytes()); input.extend_from_slice(&b.request.payload_hash);
                        let mut output = [0; 16];
                        match broker::request(OP_TASK, &input, &mut output, 0, [27, 0, 0]) {
                            Ok((16, _)) => {
                                let value = u64::from_le_bytes(output[..8].try_into().unwrap());
                                if value != b.expected { return Err(()); }
                                Some((1, value, u64::from_le_bytes(output[8..].try_into().unwrap())))
                            }
                            Err(AGAIN) => None,
                            Err(NOT_FOUND) => { b.detached = true; None },
                            Err(FAILED) => Some((2, 0, now)),
                            _ => return Err(()),
                        }
                    }
                    wire::REMOTE => self.engine.results.iter().find(|r| r.received && contract_key(r.key.contract) == status.target
                        && r.state != TaskState::Started && !self.engine.contracts.iter().any(|c| c.terms.id == r.key.contract))
                        .map(|r| {
                            if r.state == TaskState::Done {
                                if r.body != b.expected.to_le_bytes() { return Err(()); }
                                Ok((1, b.expected, now))
                            } else { Ok((2, 0, now)) }
                        }).transpose()?,
                    wire::REJECTED => Some((2, 0, now)),
                    _ => None,
                };
                if let Some((outcome, value, finished_ns)) = result { b.completion = Some(wire::Completion {
                    key: b.request.key, outcome, target: status.target, value, finished_ns, closed: 1 }); }
            }
            if let Some(completion) = b.completion {
                match broker::request(OP_TASK, &completion.encode(), &mut [], 0, [28, 0, 0]) {
                    Ok((0, _)) => b.completed_sent = true,
                    Err(AGAIN) => {},
                    Err(NOT_FOUND) => b.detached = true,
                    _ => return Err(()),
                }
            }
            native.application_cursor = (i + 1) % count;
            break;
        }
        Ok(())
    }
    pub(super) fn application_tick(&mut self, now_ns: u64) -> Result<(), ()> {
        let Some(mut n) = self.native.take() else { return Ok(()); };
        let result = self.application_turn(&mut n, now_ns);
        self.native = Some(n);
        result
    }
    fn application_turn(&mut self, n: &mut NativeDomains, now_ns: u64) -> Result<(), ()> {
        n.publish_application_status()?;
        self.application_completions(n, now_ns)?;
        if n.incoming.is_none() {
            if n.queue.pending_count() >= 32 || n.payloads.len() >= 32 || n.applications.len() >= 4096 {
                return Ok(());
            }
            let mut bytes = [0; PAYLOAD];
            let size = match broker::request(OP_TASK, &[], &mut bytes, 0, [13, 0, 0]) {
                Ok((size, _)) if size <= bytes.len() => size,
                Err(AGAIN) => return Ok(()),
                _ => return Err(()),
            };
            let submission = wire::Submission::decode(&bytes[..size]).map_err(|_| ())?;
            if submission.key.generation != self.engine.boot
                || submission.submitted_ns > broker::clock_ns().max(now_ns) {
                return Err(());
            }
            let record = journal_app::Record::from_submission(submission, package_hash()?);
            let peer = node_key(self.engine.peer);
            if let Some(old) = n.applications.iter_mut().find(|b| b.request.key == record.key
                || b.actor == record.actor && b.sequence == record.sequence) {
                if !old.same(&record, peer) { return Err(()); }
                // Retry a lost handoff acknowledgement using the same state.
                old.sent = None;
                return n.publish_application_status();
            }
            let encoded = record.encode().map_err(|_| ())?;
            let committed = match write_record(0, &encoded) {
                Ok(()) => true,
                Err(REJECTED) => {
                    n.add_application(record, peer, true)?;
                    return n.publish_application_status();
                }
                Err(_) => false,
            };
            n.incoming = Some(Incoming { record, encoded, committed, scan: 2 });
        }
        let incoming = n.incoming.as_mut().unwrap();
        if !incoming.committed {
            // One bounded record query per turn; do not re-append after a lost
            // commit reply or infer non-commit from a timeout/missing record.
            match read_record(incoming.scan) {
                Ok(Some(bytes)) if bytes == incoming.encoded => incoming.committed = true,
                Ok(Some(_)) => incoming.scan = incoming.scan.checked_add(1).filter(|n| *n <= 32768).ok_or(())?,
                Ok(None) | Err(_) => (),
            }
            if !incoming.committed { return Ok(()); }
        }
        let peer = node_key(self.engine.peer);
        let request = incoming.record.request(peer);
        match n.queue.submit_at(request, incoming.record.submitted_ns, broker::clock_ns().max(now_ns)) {
            Ok(_) => (),
            Err(DomainError::Capacity) => return Ok(()),
            Err(_) => return Err(()),
        }
        let record = n.incoming.take().unwrap().record;
        n.add_application(record, peer, false)?;
        n.publish_application_status()
    }
}
