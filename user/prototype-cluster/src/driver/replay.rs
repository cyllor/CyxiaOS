//! Actual paired replay business. Requests survive disconnects. A result is
//! emitted only after its protocol response, new TLS authentication, or the
//! original task's correct terminal result and contract closure.
use super::*;
use cyxia_prototype::domains::{Error as DomainError, ObjectKey, platform::{PlacementChoice, PlacementStatus, PlacementOutcome}};
use cyxia_prototype_cluster::replay_work::{self as wire, Work, WorkResult};

#[derive(Clone, Copy)]
enum Stage { New, Status([u8; 16]), Reconnect { old: u64, requested: bool },
    Quote, Placement(ObjectKey), Done(WorkResult) }
#[derive(Clone, Copy)]
pub(super) struct Active { work: Work, started: u64, stage: Stage }
fn zero() -> ObjectKey { ObjectKey { id: 0, generation: 0 } }
fn contract_key(id: [u8; 16]) -> ObjectKey { ObjectKey {
    id: u64::from_le_bytes(id[..8].try_into().unwrap()).max(1),
    generation: u64::from_le_bytes(id[8..].try_into().unwrap()).max(1) } }
impl Active {
    fn done(&mut self, outcome: u64, target: ObjectKey, at: u64) {
        self.stage = Stage::Done(WorkResult { id: self.work.id, outcome, target, started_ns: self.started, finished_ns: at });
    }
}
impl Driver {
    pub(super) fn replay_tick(&mut self, now_ns: u64) -> Result<(), ()> {
        if self.replay.is_none() {
            let mut bytes = [0; wire::BYTES];
            match broker::request(OP_TASK, &[], &mut bytes, 0, [25, 0, 0]) {
                Ok((wire::BYTES, _)) => {
                    let work = Work::decode(&bytes).map_err(|_| ())?;
                    if work.arrived_ns > now_ns { return Err(()); }
                    self.replay = Some(Active { work, started: now_ns, stage: Stage::New });
                }
                Err(AGAIN | NOT_FOUND | FAILED) => return Ok(()),
                _ => return Err(()),
            }
        }
        let mut active = self.replay.ok_or(())?;
        match active.stage {
            Stage::New => {
                if now_ns >= active.work.deadline_ns { active.done(3, zero(), now_ns); }
                else if self.engine.ready() {
                    match active.work.family {
                        10 => {
                            self.send(48, Vec::new(), None)?;
                            let mut request = [0; 16]; request[..8].copy_from_slice(&self.engine.boot.to_le_bytes());
                            request[8..].copy_from_slice(&self.request.to_le_bytes());
                            active.stage = Stage::Status(request);
                        }
                        12 => { active.stage = Stage::Reconnect { old: self.kernel_epoch, requested: false }; }
                        16 => { active.stage = Stage::Quote; }
                        _ => return Err(()),
                    }
                }
            }
            Stage::Status(_) => {
                // A query has no task/resource side effect. Its identity stays
                // retained so a delayed response cannot complete a later one.
                if now_ns >= active.work.deadline_ns { active.done(3, zero(), now_ns); }
            }
            Stage::Reconnect { .. } => {}, // authentication callback owns completion
            Stage::Quote => {
                if now_ns >= active.work.deadline_ns { active.done(3, zero(), now_ns); }
                else if let Some(quote) = self.native.as_ref().and_then(|n| n.peer)
                    .filter(|p| p.received_ms.saturating_mul(1_000_000) >= active.started
                        && p.expires_ms > now_ns / 1_000_000 || p.wire.status != 0
                            && p.received_ms.saturating_mul(1_000_000) >= active.started)
                {
                    if quote.wire.status != 0 { active.done(2, zero(), now_ns); }
                    else if !self.engine.contracts.iter().any(|c| c.remote) {
                        let mut identity = b"CYXIA_REAL_PEER_WORK_1.3\0".to_vec();
                        for n in [active.work.run.boot_epoch, active.work.run.trial_id, active.work.run.generation, active.work.id] {
                            identity.extend_from_slice(&n.to_le_bytes());
                        }
                        identity.extend_from_slice(&self.engine.local);
                        let hash = self.engine.crypto.sha256(&identity);
                        let key = ObjectKey { id: u64::from_le_bytes(hash[..8].try_into().unwrap()).max(1), generation: self.engine.boot };
                        let (input, _) = wire::payload(active.work.seed, active.work.id);
                        match self.submit_placement(key, &input, now_ns) {
                            Ok(_) => {
                                self.native.as_mut().ok_or(())?.queue.choose(cyxia_prototype::domains::ApplyId {
                                    boot_epoch: self.engine.boot, controller_epoch: active.work.run.generation,
                                    plan_seq: active.work.run.trial_id, action_index: active.work.id as u16, target: key,
                                }, PlacementChoice::Peer, now_ns).map_err(|_| ())?;
                                active.stage = Stage::Placement(key);
                            }
                            Err(DomainError::Busy | DomainError::Again | DomainError::Capacity) => {},
                            Err(_) => { active.done(2, zero(), now_ns); },
                        }
                    }
                }
            }
            Stage::Placement(key) => {
                match self.native.as_ref().ok_or(())?.queue.status(key).map_err(|_| ())? {
                    PlacementStatus::Complete(PlacementOutcome::Peer { contract, .. }) => {
                        if let Some(result) = self.engine.results.iter().find(|r| r.received && contract_key(r.key.contract) == contract
                            && r.state != TaskState::Started && !self.engine.contracts.iter().any(|c| c.terms.id == r.key.contract))
                        {
                            if result.state == TaskState::Done {
                                let (_, sum) = wire::payload(active.work.seed, active.work.id);
                                if result.body != sum.to_le_bytes() { return Err(()); }
                                active.done(1, contract, now_ns);
                            } else { active.done(2, contract, now_ns); }
                        }
                    }
                    PlacementStatus::Complete(PlacementOutcome::Rejected(_)) => { active.done(2, zero(), now_ns); }
                    PlacementStatus::Complete(PlacementOutcome::Local(_)) => return Err(()),
                    _ => {}, // UNKNOWN must reconcile the same intent, even after deadline.
                }
            }
            Stage::Done(result) => {
                match broker::request(OP_TASK, &result.encode(active.work.run), &mut [], 0, [26, 0, 0]) {
                    Ok((0, _)) => { self.replay = None; return Ok(()); }
                    Err(AGAIN) => {},
                    _ => return Err(()),
                }
            }
        }
        self.replay = Some(active); Ok(())
    }
    pub(super) fn replay_status_complete(&mut self, request: [u8; 16], completed: bool, at: u64) {
        if let Some(active) = self.replay.as_mut() {
            if matches!(active.stage, Stage::Status(id) if id == request) {
                active.done(if completed { 1 } else { 2 }, ObjectKey { id: 1, generation: self.kernel_epoch }, at);
            }
        }
    }
    pub fn replay_wants_reconnect(&mut self, epoch: u64) -> bool {
        let Some(active) = self.replay.as_mut() else { return false; };
        if let Stage::Reconnect { old, requested } = &mut active.stage {
            if *old == epoch && !*requested { *requested = true; return true; }
        }
        false
    }
    /// Called only after TlsIngress accepted the actual authenticated session.
    pub fn replay_authenticated(&mut self, epoch: u64, at: u64) {
        let Some(active) = self.replay.as_mut() else { return; };
        if matches!(active.stage, Stage::Reconnect { old, requested: true } if old != epoch && epoch != 0) {
            active.done(1, ObjectKey { id: 1, generation: epoch }, at);
        }
    }
}
