//! Durable protocol transitions. An effect is inert until the storage broker
//! acknowledges a committed journal transaction. Unknown I/O freezes authority.
extern crate alloc;
use super::wire::{Config, Header, Proof};
use alloc::{vec, vec::Vec};
pub trait Crypto {
    fn sha256(&self, bytes: &[u8]) -> [u8; 32];
    fn sign(&self, bytes: &[u8]) -> [u8; 64];
    fn verify(&self, node: &[u8; 32], bytes: &[u8], signature: &[u8; 64]) -> bool;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Conflict,
    State,
    Isolated,
    Busy,
    UnknownIo,
    Capacity,
    Expired,
    Replay,
    Counter,
    NotFound,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Durability {
    Committed,
    Rejected,
    Unknown,
}
#[derive(Clone, Debug)]
pub struct Effect {
    pub id: u64,
    pub bytes: Vec<u8>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Member {
    Standalone,
    Confirmed,
    Bound,
    Leaving,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContractState {
    Prepared,
    GrantPending,
    Granted,
    Suspended,
    Revoking,
    Released,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskState {
    Started,
    Done,
    Failed,
    Cancelled,
    Lost,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskKey {
    pub cluster: [u8; 32],
    pub contract: [u8; 16],
    pub task: [u8; 16],
    pub attempt: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Terms {
    pub id: [u8; 16],
    pub cpu_milli: u16,
    pub memory_pages: u32,
    pub runtime_ms: u32,
    pub package_hash: [u8; 32],
    pub input_hash: [u8; 32],
}
#[derive(Clone, Debug)]
pub struct Contract {
    pub remote: bool,
    pub terms: Terms,
    pub request_hash: [u8; 32],
    pub reservation: [u8; 16],
    pub owner_boot: u64,
    pub grant_epoch: u64,
    pub deadline_ms: u64,
    pub state: ContractState,
    pub task: Option<TaskKey>,
    pub enqueued: bool,
}
#[derive(Clone, Debug)]
pub struct ResultRecord {
    pub key: TaskKey,
    pub state: TaskState,
    pub input_hash: [u8; 32],
    pub result_hash: [u8; 32],
    pub body: Vec<u8>,
    pub acknowledged: bool,
    pub received: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub contract: [u8; 16],
    pub request_hash: [u8; 32],
    pub terminal_hash: Option<[u8; 32]>,
}
#[derive(Debug)]
pub struct Execution {
    pub key: TaskKey,
    pub package_hash: [u8; 32],
    pub input_hash: [u8; 32],
}
pub const MAX_EFFECT: usize = 33_200;
pub struct Engine<C: Crypto> {
    pub crypto: C,
    pub local: [u8; 32],
    pub peer: [u8; 32],
    pub boot: u64,
    pub member: Member,
    pub config: Option<Config>,
    pub proof: Option<Proof>,
    pub contracts: Vec<Contract>,
    pub results: Vec<ResultRecord>,
    pub formation_counter: u64,
    pub peer_counter: u64,
    pub last_epoch: u64,
    lock: Option<([u8; 32], u64)>,
    signature: Option<[u8; 64]>,
    peer_boot: u64,
    session: [u8; 32],
    seq: u64,
    reconciled: bool,
    sent_ready: bool,
    received_ready: bool,
    isolated: bool,
    frozen: bool,
    pending: Option<Effect>,
    serial: u64,
    contract_tombstones: Vec<([u8; 16], [u8; 32])>,
    task_tombstones: Vec<(TaskKey, [u8; 32], TaskState, [u8; 32])>,
    last_left: Option<[u8; 32]>,
    pub last_leave_proof: Option<[u8; 312]>,
    leave_signed: Option<([u8; 184], [u8; 64])>,
    requested_tasks: Vec<(TaskKey, [u8; 32])>,
    pub leave_intent: Option<[u8; 16]>,
}
impl<C: Crypto> Engine<C> {
    pub fn new(local: [u8; 32], peer: [u8; 32], boot: u64, crypto: C) -> Result<Self, Error> {
        if local == peer || boot == 0 {
            return Err(Error::Invalid);
        }
        Ok(Self {
            crypto,
            local,
            peer,
            boot,
            member: Member::Standalone,
            config: None,
            proof: None,
            contracts: Vec::new(),
            results: Vec::new(),
            formation_counter: 0,
            peer_counter: 0,
            last_epoch: 0,
            lock: None,
            signature: None,
            peer_boot: 0,
            session: [0; 32],
            seq: 0,
            reconciled: false,
            sent_ready: false,
            received_ready: false,
            isolated: true,
            frozen: false,
            pending: None,
            serial: 0,
            contract_tombstones: Vec::new(),
            task_tombstones: Vec::new(),
            last_left: None,
            last_leave_proof: None,
            leave_signed: None,
            requested_tasks: Vec::new(),
            leave_intent: None,
        })
    }
    pub fn formation_lock(&self) -> Option<([u8; 32], u64)> {
        self.lock
    }
    pub fn frozen_leave(&self) -> Option<([u8; 184], [u8; 64])> {
        self.leave_signed
    }
    pub fn requested_task(&self, key: TaskKey, input_hash: [u8; 32]) -> bool {
        self.requested_tasks.contains(&(key, input_hash))
    }
    pub fn record_request_task(
        &mut self,
        key: TaskKey,
        input_hash: [u8; 32],
    ) -> Result<Effect, Error> {
        self.admit()?;
        if self.requested_tasks.len() >= 4096 && !self.requested_tasks.contains(&(key, input_hash))
        {
            return Err(Error::Capacity);
        }
        if key.cluster != self.cluster()
            || self
                .requested_tasks
                .iter()
                .any(|(k, h)| k.contract == key.contract && (*k != key || *h != input_hash))
            || !self.contracts.iter().any(|c| {
                c.remote
                    && c.terms.id == key.contract
                    && c.terms.input_hash == input_hash
                    && c.state == ContractState::Granted
            })
        {
            return Err(Error::Conflict);
        }
        let mut b = Vec::new();
        encode_key(&mut b, key);
        b.extend_from_slice(&input_hash);
        self.stage(14, &b)
    }
    pub fn cluster(&self) -> [u8; 32] {
        self.config.map(|c| self.cluster_for(&c)).unwrap_or([0; 32])
    }
    pub fn formation_for(&self, c: &Config) -> [u8; 32] {
        self.hash_domain(b"CX-FORM-v1", &c.encode())
    }
    pub fn cluster_for(&self, c: &Config) -> [u8; 32] {
        self.hash_domain(b"CX-CLUSTER-v1", &self.formation_for(c))
    }
    fn hash_domain(&self, d: &[u8], b: &[u8]) -> [u8; 32] {
        let mut v = Vec::with_capacity(d.len() + b.len());
        v.extend_from_slice(d);
        v.extend_from_slice(b);
        self.crypto.sha256(&v)
    }
    fn available(&self) -> Result<(), Error> {
        if self.frozen {
            Err(Error::UnknownIo)
        } else if self.pending.is_some() {
            Err(Error::Busy)
        } else {
            Ok(())
        }
    }
    fn stage(&mut self, tag: u8, b: &[u8]) -> Result<Effect, Error> {
        self.available()?;
        let id = self.serial.checked_add(1).ok_or(Error::Counter)?;
        let mut bytes = Vec::with_capacity(b.len() + 13);
        bytes.extend_from_slice(b"CXE1");
        bytes.extend_from_slice(&id.to_le_bytes());
        bytes.push(tag);
        bytes.extend_from_slice(b);
        let e = Effect { id, bytes };
        self.pending = Some(e.clone());
        Ok(e)
    }
    pub fn complete(&mut self, id: u64, d: Durability) -> Result<(), Error> {
        let e = self.pending.take().ok_or(Error::State)?;
        if e.id != id {
            self.pending = Some(e);
            return Err(Error::Conflict);
        }
        if d == Durability::Rejected {
            for c in &mut self.contracts {
                if c.state == ContractState::GrantPending {
                    c.state = ContractState::Prepared;
                }
            }
            return Err(Error::Capacity);
        }
        if d == Durability::Unknown {
            self.frozen = true;
            self.isolate();
            return Err(Error::UnknownIo);
        }
        self.recover_event(&e.bytes)
    }
    pub fn ready(&self) -> bool {
        !self.frozen
            && !self.isolated
            && self.member == Member::Bound
            && self.reconciled
            && self.sent_ready
            && self.received_ready
    }
    pub fn isolate(&mut self) {
        self.isolated = true;
        self.reconciled = false;
        self.sent_ready = false;
        self.received_ready = false;
    }
    pub fn hello(&mut self, peer_boot: u64, session: [u8; 32]) -> Result<(), Error> {
        self.available()?;
        if peer_boot == 0 || session == [0; 32] {
            return Err(Error::Invalid);
        }
        if !self.isolated && (self.peer_boot != peer_boot || self.session != session) {
            self.isolate();
            return Err(Error::Conflict);
        }
        self.peer_boot = peer_boot;
        self.session = session;
        self.seq = 0;
        self.reconciled = false;
        self.sent_ready = false;
        self.received_ready = false;
        self.isolated = false;
        Ok(())
    }
    pub fn accept_header(&mut self, h: &Header) -> Result<(), Error> {
        if self.isolated
            || h.sender_boot != self.peer_boot
            || h.receiver_boot != self.boot
            || h.sequence <= self.seq
            || (!(matches!(h.kind & 0x7fff, 3..=5) && h.cluster == [0; 32] && h.epoch == 0)
                && (h.cluster != self.cluster()
                    || h.epoch != self.config.map(|c| c.epoch).unwrap_or(0)))
        {
            return Err(Error::Replay);
        }
        self.seq = h.sequence;
        Ok(())
    }
    pub fn statuses(&self) -> Vec<Status> {
        let mut out: Vec<Status> = self
            .contracts
            .iter()
            .filter(|c| c.state != ContractState::Prepared)
            .map(|c| Status {
                contract: c.terms.id,
                request_hash: c.request_hash,
                terminal_hash: self
                    .results
                    .iter()
                    .find(|r| r.key.contract == c.terms.id && r.state != TaskState::Started)
                    .map(|r| r.result_hash)
                    .or_else(|| {
                        self.task_tombstones
                            .iter()
                            .find(|(k, _, _, _)| k.contract == c.terms.id)
                            .map(|(_, h, _, _)| *h)
                    }),
            })
            .collect();
        for (id, hash) in &self.contract_tombstones {
            if !out.iter().any(|s| s.contract == *id) {
                out.push(Status {
                    contract: *id,
                    request_hash: *hash,
                    terminal_hash: self
                        .results
                        .iter()
                        .find(|r| r.key.contract == *id && r.state != TaskState::Started)
                        .map(|r| r.result_hash)
                        .or_else(|| {
                            self.task_tombstones
                                .iter()
                                .find(|(k, _, _, _)| k.contract == *id)
                                .map(|(_, h, _, _)| *h)
                        }),
                });
            }
        }
        out
    }
    pub fn reconcile(&mut self, peer: &[Status]) -> Result<(), Error> {
        self.available()?;
        if self.isolated || self.member != Member::Bound || peer.len() > 4096 {
            return Err(Error::State);
        }
        let ours = self.statuses();
        if ours.len() != peer.len()
            || ours.iter().any(|s| !peer.contains(s))
            || self.contracts.iter().any(|c| {
                matches!(
                    c.state,
                    ContractState::Suspended | ContractState::GrantPending
                )
            })
            || self.results.iter().any(|r| r.state == TaskState::Started)
        {
            return Err(Error::Conflict);
        }
        self.reconciled = true;
        Ok(())
    }
    pub fn send_ready(&mut self) -> Result<(), Error> {
        if self.member != Member::Bound || self.isolated || !self.reconciled {
            return Err(Error::State);
        }
        self.sent_ready = true;
        Ok(())
    }
    pub fn peer_ready(
        &mut self,
        boot: u64,
        session: [u8; 32],
        cluster: [u8; 32],
    ) -> Result<(), Error> {
        if self.isolated
            || boot != self.peer_boot
            || session != self.session
            || cluster != self.cluster()
        {
            return Err(Error::Replay);
        }
        self.received_ready = true;
        Ok(())
    }
    pub fn begin_formation(&mut self, nonce: [u8; 32]) -> Result<Effect, Error> {
        if self.member != Member::Standalone || nonce == [0; 32] {
            return Err(Error::State);
        }
        let counter = self
            .formation_counter
            .checked_add(1)
            .ok_or(Error::Counter)?;
        let mut b = Vec::new();
        b.extend_from_slice(&counter.to_le_bytes());
        b.extend_from_slice(&nonce);
        b.extend_from_slice(&self.last_epoch.to_le_bytes());
        self.stage(1, &b)
    }
    pub fn confirm(&mut self, c: Config, peer_frozen_epoch: u64) -> Result<Effect, Error> {
        if self.member == Member::Confirmed && self.config == Some(c) {
            return self.stage(
                2,
                &self.confirm_bytes(c, self.signature.ok_or(Error::State)?),
            );
        }
        if self.member != Member::Standalone {
            return Err(Error::State);
        }
        Config::decode(&c.encode()).map_err(|_| Error::Invalid)?;
        let i = usize::from(c.nodes[1] == self.local);
        if c.nodes[i] != self.local || c.nodes[1 - i] != self.peer {
            return Err(Error::Invalid);
        }
        let (nonce, frozen) = self.lock.ok_or(Error::State)?;
        if c.counters[i] != self.formation_counter
            || c.nonces[i] != nonce
            || c.counters[1 - i] <= self.peer_counter
            || c.epoch
                != frozen
                    .max(peer_frozen_epoch)
                    .checked_add(1)
                    .ok_or(Error::Counter)?
            || self.last_left == Some(self.cluster_for(&c))
        {
            return Err(Error::Replay);
        }
        let mut msg = b"CX-CONFIRM-v1".to_vec();
        msg.extend_from_slice(&self.formation_for(&c));
        let sig = self.crypto.sign(&msg);
        self.stage(2, &self.confirm_bytes(c, sig))
    }
    fn confirm_bytes(&self, c: Config, sig: [u8; 64]) -> Vec<u8> {
        let mut b = c.encode().to_vec();
        b.extend_from_slice(&sig);
        b
    }
    pub fn signature(&self) -> Option<[u8; 64]> {
        self.signature
    }
    pub fn bind(&mut self, p: Proof) -> Result<Effect, Error> {
        if self.member == Member::Bound {
            if self.proof != Some(p) {
                return Err(Error::Conflict);
            }
        } else if self.member != Member::Confirmed || self.config != Some(p.config) {
            return Err(Error::State);
        }
        if p.formation != self.formation_for(&p.config) {
            return Err(Error::Invalid);
        }
        let mut msg = b"CX-CONFIRM-v1".to_vec();
        msg.extend_from_slice(&p.formation);
        for i in 0..2 {
            if !self
                .crypto
                .verify(&p.config.nodes[i], &msg, &p.signatures[i])
            {
                return Err(Error::Invalid);
            }
        }
        let i = usize::from(p.config.nodes[1] == self.local);
        if self.signature != Some(p.signatures[i]) {
            return Err(Error::Conflict);
        }
        self.stage(3, &p.encode())
    }
    fn admit(&self) -> Result<(), Error> {
        self.available()?;
        if !self.ready() {
            Err(Error::Isolated)
        } else {
            Ok(())
        }
    }
    pub fn request_hash(&self, t: &Terms) -> [u8; 32] {
        self.request_hash_for(t, self.peer, self.local)
    }
    pub fn request_hash_for(&self, t: &Terms, requester: [u8; 32], owner: [u8; 32]) -> [u8; 32] {
        let mut b = b"CX-CONTRACT-v1".to_vec();
        b.extend_from_slice(&self.cluster());
        b.extend_from_slice(&requester);
        b.extend_from_slice(&owner);
        encode_terms(&mut b, t);
        self.crypto.sha256(&b)
    }
    pub fn prepare(
        &mut self,
        t: Terms,
        hash: [u8; 32],
        reservation: [u8; 16],
        now_ms: u64,
        ttl_ms: u32,
    ) -> Result<(), Error> {
        self.admit()?;
        self.contracts
            .retain(|c| c.state != ContractState::Prepared || now_ms < c.deadline_ms);
        if t.cpu_milli == 0
            || t.cpu_milli > 900
            || t.memory_pages == 0
            || t.runtime_ms == 0
            || t.runtime_ms > 60000
            || ttl_ms == 0
            || ttl_ms > 2000
            || reservation == [0; 16]
            || hash != self.request_hash(&t)
        {
            return Err(Error::Invalid);
        }
        if self.contract_tombstones.iter().any(|(id, _)| *id == t.id) {
            return Err(Error::Conflict);
        }
        if let Some(c) = self.contracts.iter().find(|c| c.terms.id == t.id) {
            return if c.request_hash == hash
                && c.reservation == reservation
                && c.owner_boot == self.boot
                && c.state == ContractState::Prepared
                && now_ms < c.deadline_ms
            {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        let cpu: u32 = self
            .contracts
            .iter()
            .filter(|c| !c.remote && c.state != ContractState::Released)
            .map(|c| c.terms.cpu_milli as u32)
            .sum();
        let pages: u64 = self
            .contracts
            .iter()
            .filter(|c| !c.remote && c.state != ContractState::Released)
            .map(|c| c.terms.memory_pages as u64)
            .sum();
        if cpu + t.cpu_milli as u32 > 900 || pages + t.memory_pages as u64 > 65536 {
            return Err(Error::Capacity);
        }
        let reserved = self
            .contracts
            .iter()
            .filter(|c| c.state != ContractState::Released)
            .count();
        if reserved >= 32
            || self.results.iter().filter(|r| !r.acknowledged).count() + reserved >= 128
            || self.contract_tombstones.len() + reserved >= 4096
            || self.task_tombstones.len() + reserved >= 4096
        {
            return Err(Error::Capacity);
        }
        self.contracts.push(Contract {
            remote: false,
            terms: t,
            request_hash: hash,
            reservation,
            owner_boot: self.boot,
            grant_epoch: 1,
            deadline_ms: now_ms.checked_add(ttl_ms as u64).ok_or(Error::Counter)?,
            state: ContractState::Prepared,
            task: None,
            enqueued: false,
        });
        Ok(())
    }
    pub fn record_request(&mut self, terms: Terms, hash: [u8; 32]) -> Result<Effect, Error> {
        self.admit()?;
        if hash != self.request_hash_for(&terms, self.local, self.peer)
            || self.contracts.iter().any(|c| c.terms.id == terms.id)
            || self
                .contract_tombstones
                .iter()
                .any(|(id, _)| *id == terms.id)
        {
            return Err(Error::Conflict);
        }
        let c = Contract {
            remote: true,
            terms,
            request_hash: hash,
            reservation: [0; 16],
            owner_boot: self.peer_boot,
            grant_epoch: 1,
            deadline_ms: 0,
            state: ContractState::Prepared,
            task: None,
            enqueued: false,
        };
        self.stage(11, &encode_contract(&c))
    }
    pub fn cancel_request(&mut self, id: [u8; 16]) -> Result<Effect, Error> {
        let c = self
            .contracts
            .iter()
            .find(|c| c.remote && c.terms.id == id && c.state == ContractState::Prepared)
            .ok_or(Error::State)?;
        let mut b = id.to_vec();
        b.extend_from_slice(&c.request_hash);
        self.stage(12, &b)
    }
    pub fn abandon_prepared(&mut self, id: [u8; 16]) -> Result<(), Error> {
        self.available()?;
        if !self
            .contracts
            .iter()
            .any(|c| !c.remote && c.terms.id == id && c.state == ContractState::Prepared)
        {
            return Err(Error::State);
        }
        self.contracts.retain(|c| c.terms.id != id);
        Ok(())
    }
    pub fn observe_grant(
        &mut self,
        terms: Terms,
        hash: [u8; 32],
        reservation: [u8; 16],
        owner_boot: u64,
        grant_epoch: u64,
    ) -> Result<Effect, Error> {
        self.available()?;
        if hash != self.request_hash_for(&terms, self.local, self.peer)
            || owner_boot == 0
            || grant_epoch == 0
            || self.member != Member::Bound
            || self.isolated
        {
            return Err(Error::Invalid);
        }
        let c = Contract {
            remote: true,
            terms,
            request_hash: hash,
            reservation,
            owner_boot,
            grant_epoch,
            deadline_ms: 0,
            state: ContractState::Granted,
            task: None,
            enqueued: false,
        };
        self.stage(10, &encode_contract(&c))
    }
    pub fn commit(
        &mut self,
        id: [u8; 16],
        reservation: [u8; 16],
        hash: [u8; 32],
        now_ms: u64,
    ) -> Result<Effect, Error> {
        self.admit()?;
        let c = self
            .contracts
            .iter()
            .find(|c| c.terms.id == id)
            .ok_or(Error::NotFound)?;
        if c.reservation != reservation || c.request_hash != hash || c.owner_boot != self.boot {
            return Err(Error::Conflict);
        }
        if c.state == ContractState::Granted {
            return self.stage(4, &encode_contract(c));
        }
        if c.state != ContractState::Prepared || now_ms >= c.deadline_ms {
            return Err(Error::Expired);
        }
        let mut c = c.clone();
        c.state = ContractState::Granted;
        c.deadline_ms = now_ms
            .checked_add(c.terms.runtime_ms as u64)
            .ok_or(Error::Counter)?;
        let b = encode_contract(&c);
        let e = self.stage(4, &b)?;
        self.contracts
            .iter_mut()
            .find(|c| c.terms.id == id)
            .unwrap()
            .state = ContractState::GrantPending;
        Ok(e)
    }
    pub fn activate(
        &mut self,
        key: TaskKey,
        hash: [u8; 32],
        input: &[u8],
        owner_boot: u64,
        grant_epoch: u64,
        now_ms: u64,
    ) -> Result<Effect, Error> {
        self.admit()?;
        if input.len() > 32768 || key.cluster != self.cluster() {
            return Err(Error::Invalid);
        }
        let c = self
            .contracts
            .iter()
            .find(|c| c.terms.id == key.contract)
            .ok_or(Error::NotFound)?;
        if c.task.is_some() {
            return Err(Error::Conflict);
        }
        if c.state != ContractState::Granted
            || c.owner_boot != owner_boot
            || owner_boot != self.boot
            || c.grant_epoch != grant_epoch
            || c.request_hash != hash
            || c.terms.input_hash != self.crypto.sha256(input)
        {
            return Err(Error::Conflict);
        }
        if now_ms >= c.deadline_ms {
            return Err(Error::Expired);
        }
        let r = ResultRecord {
            key,
            state: TaskState::Started,
            input_hash: c.terms.input_hash,
            result_hash: [0; 32],
            body: Vec::new(),
            acknowledged: false,
            received: false,
        };
        self.stage(5, &encode_result(&r))
    }
    pub fn enqueue(
        &mut self,
        key: TaskKey,
        owner_boot: u64,
        grant_epoch: u64,
        now_ms: u64,
    ) -> Result<Execution, Error> {
        self.admit()?;
        let c = self
            .contracts
            .iter_mut()
            .find(|c| c.terms.id == key.contract)
            .ok_or(Error::NotFound)?;
        if c.task != Some(key)
            || c.enqueued
            || c.state != ContractState::Granted
            || owner_boot != self.boot
            || owner_boot != c.owner_boot
            || c.grant_epoch != grant_epoch
        {
            return Err(Error::Conflict);
        }
        if now_ms >= c.deadline_ms {
            return Err(Error::Expired);
        }
        c.enqueued = true;
        Ok(Execution {
            key,
            package_hash: c.terms.package_hash,
            input_hash: c.terms.input_hash,
        })
    }
    pub fn finish(&mut self, key: TaskKey, state: TaskState, body: &[u8]) -> Result<Effect, Error> {
        self.available()?;
        if body.len() > 32768 || state == TaskState::Started {
            return Err(Error::Invalid);
        }
        let r = self
            .results
            .iter()
            .find(|r| r.key == key)
            .ok_or(Error::NotFound)?;
        if r.state != TaskState::Started {
            return Err(Error::Conflict);
        }
        let c = self
            .contracts
            .iter()
            .find(|c| c.terms.id == key.contract)
            .ok_or(Error::NotFound)?;
        if !c.enqueued && !matches!(state, TaskState::Cancelled | TaskState::Lost) {
            return Err(Error::State);
        }
        let mut r = r.clone();
        r.state = state;
        r.body = body.to_vec();
        r.result_hash = result_digest(&self.crypto, state, body);
        self.stage(5, &encode_result(&r))
    }
    pub fn receive_result(
        &mut self,
        key: TaskKey,
        state: TaskState,
        input_hash: [u8; 32],
        body: &[u8],
        hash: [u8; 32],
    ) -> Result<Effect, Error> {
        self.available()?;
        if self.isolated
            || !self.requested_task(key, input_hash)
            || key.cluster != self.cluster()
            || body.len() > 32768
            || state == TaskState::Started
            || hash != result_digest(&self.crypto, state, body)
        {
            return Err(Error::Invalid);
        }
        if let Some(r) = self.results.iter().find(|r| r.key == key) {
            if r.result_hash != hash
                || r.state != state
                || r.input_hash != input_hash
                || r.body != body
            {
                return Err(Error::Conflict);
            }
        }
        if self.results.len() >= 128 && !self.results.iter().any(|r| r.key == key) {
            return Err(Error::Capacity);
        }
        self.stage(
            5,
            &encode_result(&ResultRecord {
                key,
                state,
                input_hash,
                result_hash: hash,
                body: body.to_vec(),
                acknowledged: false,
                received: true,
            }),
        )
    }
    pub fn ack_ready(&self, key: TaskKey) -> Result<[u8; 32], Error> {
        let r = self
            .results
            .iter()
            .find(|r| r.key == key && r.received && r.state != TaskState::Started)
            .ok_or(Error::State)?;
        Ok(r.result_hash)
    }
    pub fn ack_result(&mut self, key: TaskKey, hash: [u8; 32]) -> Result<Effect, Error> {
        self.available()?;
        if let Some((_, h, _, _)) = self.task_tombstones.iter().find(|(k, _, _, _)| *k == key) {
            if *h != hash {
                return Err(Error::Conflict);
            }
        } else {
            let r = self
                .results
                .iter()
                .find(|r| r.key == key && !r.received && r.state != TaskState::Started)
                .ok_or(Error::State)?;
            if r.result_hash != hash {
                return Err(Error::Conflict);
            }
        }
        let mut b = Vec::new();
        encode_key(&mut b, key);
        b.extend_from_slice(&hash);
        self.stage(6, &b)
    }
    pub fn close(&mut self, id: [u8; 16], quiescent: bool) -> Result<Effect, Error> {
        self.available()?;
        if let Some((_, hash)) = self.contract_tombstones.iter().find(|(old, _)| *old == id) {
            let mut b = id.to_vec();
            b.extend_from_slice(hash);
            return self.stage(9, &b);
        }
        let c = self
            .contracts
            .iter()
            .find(|c| c.terms.id == id)
            .ok_or(Error::NotFound)?;
        if !quiescent
            || c.task.is_some_and(|k| {
                self.results
                    .iter()
                    .any(|r| r.key == k && r.state == TaskState::Started)
            })
        {
            return Err(Error::Busy);
        }
        let mut c = c.clone();
        if c.state != ContractState::Released {
            c.grant_epoch = c.grant_epoch.checked_add(1).ok_or(Error::Counter)?;
        }
        c.state = ContractState::Released;
        self.stage(if c.remote { 10 } else { 4 }, &encode_contract(&c))
    }
    pub fn recovery_loss(&mut self) -> Result<Option<Effect>, Error> {
        self.available()?;
        if let Some(r) = self
            .results
            .iter()
            .find(|r| {
                r.state == TaskState::Started
                    && self.contracts.iter().any(|c| {
                        c.terms.id == r.key.contract && !c.remote && c.owner_boot != self.boot
                    })
            })
            .cloned()
        {
            let mut r = r;
            r.state = TaskState::Lost;
            r.body.clear();
            r.result_hash = result_digest(&self.crypto, TaskState::Lost, &[]);
            return self.stage(5, &encode_result(&r)).map(Some);
        }
        Ok(None)
    }
    pub fn leave_with_id(&mut self, id: [u8; 16]) -> Result<Effect, Error> {
        if !matches!(self.member, Member::Bound | Member::Leaving)
            || self.leave_intent.is_some_and(|old| old != id)
        {
            return Err(Error::State);
        }
        self.sent_ready = false;
        self.received_ready = false;
        self.reconciled = false;
        self.stage(7, &id)
    }
    pub fn leave(&mut self) -> Result<Effect, Error> {
        if !matches!(self.member, Member::Bound | Member::Leaving) {
            return Err(Error::State);
        }
        self.sent_ready = false;
        self.received_ready = false;
        self.reconciled = false;
        self.stage(7, &[])
    }
    pub fn obligation_digest(&self) -> [u8; 32] {
        let mut statuses = self.statuses();
        statuses.sort_unstable_by_key(|s| s.contract);
        let mut b = b"CX-OBLIGATIONS-v1".to_vec();
        for s in statuses {
            b.extend_from_slice(&s.contract);
            b.extend_from_slice(&s.request_hash);
            b.push(u8::from(s.terminal_hash.is_some()));
            if let Some(h) = s.terminal_hash {
                b.extend_from_slice(&h)
            }
        }
        self.crypto.sha256(&b)
    }
    pub fn leave_record(
        &self,
        leave_id: [u8; 16],
        digests: [[u8; 32]; 2],
    ) -> Result<[u8; 184], Error> {
        if self.member != Member::Leaving
            || self
                .contracts
                .iter()
                .any(|c| c.state != ContractState::Released)
            || self.results.iter().any(|r| !r.received && !r.acknowledged)
        {
            return Err(Error::Busy);
        }
        let c = self.config.ok_or(Error::State)?;
        let i = usize::from(c.nodes[1] == self.local);
        if digests[i] != self.obligation_digest() {
            return Err(Error::Conflict);
        }
        let mut b = [0; 184];
        b[..32].copy_from_slice(&self.cluster());
        b[32..40].copy_from_slice(&c.epoch.to_le_bytes());
        b[40..56].copy_from_slice(&leave_id);
        b[56..88].copy_from_slice(&c.nodes[0]);
        b[88..120].copy_from_slice(&c.nodes[1]);
        b[120..152].copy_from_slice(&digests[0]);
        b[152..184].copy_from_slice(&digests[1]);
        Ok(b)
    }
    pub fn sign_leave(&self, record: &[u8; 184]) -> Result<[u8; 64], Error> {
        let c = self.config.ok_or(Error::State)?;
        if self.member != Member::Leaving
            || record[..32] != self.cluster()
            || record[32..40] != c.epoch.to_le_bytes()
            || record[56..88] != c.nodes[0]
            || record[88..120] != c.nodes[1]
            || record[120 + 32 * usize::from(c.nodes[1] == self.local)
                ..152 + 32 * usize::from(c.nodes[1] == self.local)]
                != self.obligation_digest()
            || self
                .contracts
                .iter()
                .any(|c| c.state != ContractState::Released)
            || self.results.iter().any(|r| !r.received && !r.acknowledged)
        {
            return Err(Error::State);
        }
        let mut m = b"CX-LEAVE-v1".to_vec();
        m.extend_from_slice(record);
        Ok(self.crypto.sign(&m))
    }
    pub fn confirm_leave(&mut self, record: [u8; 184]) -> Result<Effect, Error> {
        let signature = self.sign_leave(&record)?;
        if self.leave_signed.is_some_and(|(old, _)| old != record) {
            return Err(Error::Conflict);
        }
        let mut b = record.to_vec();
        b.extend_from_slice(&signature);
        self.stage(13, &b)
    }
    pub fn leave_signature(&self) -> Option<[u8; 64]> {
        self.leave_signed.map(|(_, signature)| signature)
    }
    pub fn finish_leave(&mut self, proof: &[u8; 312]) -> Result<Effect, Error> {
        let c = self.config.ok_or(Error::State)?;
        if self
            .leave_signed
            .is_none_or(|(record, _)| record != proof[..184])
        {
            return Err(Error::State);
        }
        if self.member != Member::Leaving
            || proof[..32] != self.cluster()
            || proof[32..40] != c.epoch.to_le_bytes()
            || proof[56..88] != c.nodes[0]
            || proof[88..120] != c.nodes[1]
            || self
                .contracts
                .iter()
                .any(|c| c.state != ContractState::Released)
            || self.results.iter().any(|r| !r.received && !r.acknowledged)
        {
            return Err(Error::State);
        }
        let mut m = b"CX-LEAVE-v1".to_vec();
        m.extend_from_slice(&proof[..184]);
        for i in 0..2 {
            if !self.crypto.verify(
                &c.nodes[i],
                &m,
                proof[184 + 64 * i..248 + 64 * i].try_into().unwrap(),
            ) {
                return Err(Error::Invalid);
            }
        }
        self.stage(8, proof)
    }
    fn validate_event(&self, b: &[u8]) -> Result<(), Error> {
        if b.len() < 13
            || b.len() > MAX_EFFECT
            || &b[..4] != b"CXE1"
            || u64::from_le_bytes(b[4..12].try_into().unwrap())
                != self.serial.checked_add(1).ok_or(Error::Counter)?
        {
            return Err(Error::Replay);
        }
        let mut r = Read::new(&b[13..]);
        match b[12] {
            1 => {
                let counter = r.u64()?;
                let nonce: [u8; 32] = r.arr()?;
                let epoch = r.u64()?;
                if self.member != Member::Standalone
                    || counter <= self.formation_counter
                    || nonce == [0; 32]
                    || epoch != self.last_epoch
                {
                    return Err(Error::Replay);
                }
            }
            2 => {
                let c = Config::decode(r.take(252)?).map_err(|_| Error::Invalid)?;
                let signature = r.arr()?;
                let i = usize::from(c.nodes[1] == self.local);
                if c.nodes[i] != self.local || c.nodes[1 - i] != self.peer {
                    return Err(Error::Invalid);
                }
                if self.member == Member::Confirmed {
                    if self.config != Some(c) || self.signature != Some(signature) {
                        return Err(Error::Conflict);
                    }
                } else {
                    let (nonce, epoch) = self.lock.ok_or(Error::State)?;
                    if self.member != Member::Standalone
                        || c.counters[i] != self.formation_counter
                        || c.nonces[i] != nonce
                        || c.counters[1 - i] <= self.peer_counter
                        || c.epoch <= epoch
                        || c.epoch <= self.last_epoch
                    {
                        return Err(Error::Replay);
                    }
                }
                let mut m = b"CX-CONFIRM-v1".to_vec();
                m.extend_from_slice(&self.formation_for(&c));
                if !self.crypto.verify(&self.local, &m, &signature) {
                    return Err(Error::Invalid);
                }
            }
            3 => {
                let p = Proof::decode(r.take(412)?).map_err(|_| Error::Invalid)?;
                if !matches!(self.member, Member::Confirmed | Member::Bound)
                    || self.config != Some(p.config)
                    || p.formation != self.formation_for(&p.config)
                {
                    return Err(Error::State);
                }
                let mut m = b"CX-CONFIRM-v1".to_vec();
                m.extend_from_slice(&p.formation);
                for i in 0..2 {
                    if !self.crypto.verify(&p.config.nodes[i], &m, &p.signatures[i]) {
                        return Err(Error::Invalid);
                    }
                }
                if self.signature
                    != Some(p.signatures[usize::from(p.config.nodes[1] == self.local)])
                {
                    return Err(Error::Conflict);
                }
            }
            4 | 10 | 11 => {
                let c = decode_contract(&mut r)?;
                let expected = if b[12] == 10 || b[12] == 11 {
                    self.request_hash_for(&c.terms, self.local, self.peer)
                } else {
                    self.request_hash(&c.terms)
                };
                if self.config.is_none()
                    || c.owner_boot == 0
                    || c.grant_epoch == 0
                    || c.request_hash != expected
                    || !matches!(c.state, ContractState::Granted | ContractState::Released)
                        && !(b[12] == 11 && c.state == ContractState::Prepared)
                {
                    return Err(Error::Invalid);
                }
                if let Some(old) = self.contracts.iter().find(|x| x.terms.id == c.terms.id) {
                    if old.request_hash != c.request_hash {
                        return Err(Error::Conflict);
                    }
                } else if self.contracts.len() >= 32 {
                    return Err(Error::Capacity);
                }
            }
            5 => {
                let out = decode_result(&mut r)?;
                if out.key.cluster != self.cluster()
                    || (out.state != TaskState::Started
                        && out.result_hash != result_digest(&self.crypto, out.state, &out.body))
                {
                    return Err(Error::Invalid);
                }
                if out.received && !self.requested_task(out.key, out.input_hash) {
                    return Err(Error::Conflict);
                }
                if !out.received {
                    let c = self
                        .contracts
                        .iter()
                        .find(|c| c.terms.id == out.key.contract)
                        .ok_or(Error::State)?;
                    if c.terms.input_hash != out.input_hash || c.task.is_some_and(|k| k != out.key)
                    {
                        return Err(Error::Conflict);
                    }
                }
                if !self.results.iter().any(|x| x.key == out.key) && self.results.len() >= 128 {
                    return Err(Error::Capacity);
                }
            }
            6 => {
                let key = decode_key(&mut r)?;
                let hash = r.arr()?;
                if !self.results.iter().any(|out| {
                    out.key == key && out.result_hash == hash && out.state != TaskState::Started
                }) && !self
                    .task_tombstones
                    .iter()
                    .any(|(k, h, _, _)| *k == key && *h == hash)
                {
                    return Err(Error::Conflict);
                }
            }
            14 => {
                let key = decode_key(&mut r)?;
                let hash = r.arr()?;
                if key.cluster != self.cluster()
                    || self
                        .requested_tasks
                        .iter()
                        .any(|(k, h)| k.contract == key.contract && (*k != key || *h != hash))
                    || !self.contracts.iter().any(|c| {
                        c.remote
                            && c.terms.id == key.contract
                            && c.terms.input_hash == hash
                            && c.state == ContractState::Granted
                    })
                {
                    return Err(Error::Conflict);
                }
            }
            13 => {
                let record = r.arr()?;
                let signature = r.arr()?;
                if self.sign_leave(&record)? != signature
                    || self.leave_signed.is_some_and(|(old, _)| old != record)
                {
                    return Err(Error::Conflict);
                }
            }
            12 => {
                let id = r.arr()?;
                let hash = r.arr()?;
                if !self.contracts.iter().any(|c| {
                    c.remote
                        && c.state == ContractState::Prepared
                        && c.terms.id == id
                        && c.request_hash == hash
                }) {
                    return Err(Error::Conflict);
                }
            }
            9 => {
                let id = r.arr()?;
                let hash = r.arr()?;
                if !self.contract_tombstones.contains(&(id, hash)) {
                    return Err(Error::Conflict);
                }
            }
            7 => {
                if r.b.len() == 16 {
                    let id = r.arr()?;
                    if self.leave_intent.is_some_and(|old| old != id) {
                        return Err(Error::Conflict);
                    }
                }
                if !matches!(self.member, Member::Bound | Member::Leaving) {
                    return Err(Error::State);
                }
            }
            8 => {
                let p = r.take(312)?;
                let c = self.config.ok_or(Error::State)?;
                self.sign_leave(p[..184].try_into().unwrap())?;
                if self
                    .leave_signed
                    .is_none_or(|(record, _)| record != p[..184])
                {
                    return Err(Error::State);
                }
                let mut m = b"CX-LEAVE-v1".to_vec();
                m.extend_from_slice(&p[..184]);
                for i in 0..2 {
                    if !self.crypto.verify(
                        &c.nodes[i],
                        &m,
                        p[184 + 64 * i..248 + 64 * i].try_into().unwrap(),
                    ) {
                        return Err(Error::Invalid);
                    }
                }
            }
            _ => return Err(Error::Invalid),
        }
        if !r.done() {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    pub fn recover_event(&mut self, b: &[u8]) -> Result<(), Error> {
        self.validate_event(b)?;
        if b.len() < 13 || &b[..4] != b"CXE1" {
            return Err(Error::Invalid);
        }
        let serial = u64::from_le_bytes(b[4..12].try_into().unwrap());
        if serial != self.serial.checked_add(1).ok_or(Error::Counter)? {
            return Err(Error::Replay);
        }
        let mut r = Read::new(&b[13..]);
        match b[12] {
            1 => {
                let count = r.u64()?;
                let nonce = r.arr()?;
                let epoch = r.u64()?;
                if count <= self.formation_counter {
                    return Err(Error::Replay);
                }
                self.formation_counter = count;
                self.lock = Some((nonce, epoch));
            }
            2 => {
                let c = Config::decode(r.take(252)?).map_err(|_| Error::Invalid)?;
                let sig = r.arr()?;
                self.config = Some(c);
                self.signature = Some(sig);
                self.last_epoch = c.epoch;
                self.member = Member::Confirmed;
            }
            3 => {
                let p = Proof::decode(r.take(412)?).map_err(|_| Error::Invalid)?;
                self.config = Some(p.config);
                self.peer_counter = p.config.counters[usize::from(p.config.nodes[0] == self.local)];
                self.proof = Some(p);
                self.member = Member::Bound;
            }
            4 | 10 | 11 => {
                let mut c = decode_contract(&mut r)?;
                c.remote = b[12] == 10 || b[12] == 11;
                if !c.remote && c.state == ContractState::Granted && c.owner_boot != self.boot {
                    c.state = ContractState::Suspended
                }
                if c.state == ContractState::Released
                    && !self
                        .contract_tombstones
                        .iter()
                        .any(|(id, _)| *id == c.terms.id)
                {
                    if self.contract_tombstones.len() >= 4096 {
                        return Err(Error::Capacity);
                    }
                    self.contract_tombstones.push((c.terms.id, c.request_hash));
                }
                if let Some(old) = self.contracts.iter_mut().find(|x| x.terms.id == c.terms.id) {
                    c.task = old.task;
                    c.enqueued = old.enqueued;
                    *old = c;
                } else {
                    if self.contracts.len() >= 32 {
                        return Err(Error::Capacity);
                    }
                    self.contracts.push(c);
                }
                self.contracts
                    .retain(|c| c.state != ContractState::Released);
            }
            5 => {
                let out = decode_result(&mut r)?;
                if let Some(c) = self
                    .contracts
                    .iter_mut()
                    .find(|c| c.terms.id == out.key.contract)
                {
                    c.task = Some(out.key);
                }
                if let Some(old) = self.results.iter_mut().find(|x| x.key == out.key) {
                    *old = out
                } else {
                    if self.results.len() >= 128 {
                        return Err(Error::Capacity);
                    }
                    self.results.push(out)
                }
            }
            6 => {
                let key = decode_key(&mut r)?;
                let hash = r.arr()?;
                if let Some(out) = self.results.iter_mut().find(|r| r.key == key) {
                    if out.result_hash != hash {
                        return Err(Error::Conflict);
                    }
                    out.acknowledged = true;
                    out.body.clear();
                }
                if !self.task_tombstones.iter().any(|(k, _, _, _)| *k == key) {
                    if self.task_tombstones.len() >= 4096 {
                        return Err(Error::Capacity);
                    }
                    let out = self
                        .results
                        .iter()
                        .find(|r| r.key == key)
                        .ok_or(Error::State)?;
                    self.task_tombstones
                        .push((key, hash, out.state, out.input_hash));
                }
                self.results.retain(|r| r.key != key || r.received);
            }
            14 => {
                let key = decode_key(&mut r)?;
                let hash = r.arr()?;
                if !self.requested_tasks.contains(&(key, hash)) {
                    if self.requested_tasks.len() >= 4096 {
                        return Err(Error::Capacity);
                    }
                    self.requested_tasks.push((key, hash));
                }
                if let Some(c) = self
                    .contracts
                    .iter_mut()
                    .find(|c| c.remote && c.terms.id == key.contract)
                {
                    c.task = Some(key);
                }
            }
            13 => {
                let record = r.arr()?;
                let signature = r.arr()?;
                self.leave_signed = Some((record, signature));
            }
            12 => {
                let id: [u8; 16] = r.arr()?;
                let _hash: [u8; 32] = r.arr()?;
                self.contracts.retain(|c| c.terms.id != id);
            }
            9 => {
                let _id: [u8; 16] = r.arr()?;
                let _hash: [u8; 32] = r.arr()?;
            }
            7 => {
                if r.b.len() == 16 {
                    self.leave_intent = Some(r.arr()?);
                }
                self.member = Member::Leaving;
                self.sent_ready = false;
                self.received_ready = false;
                self.reconciled = false;
            }
            8 => {
                let p = r.take(312)?;
                self.last_left = Some(p[..32].try_into().unwrap());
                self.last_leave_proof = Some(p.try_into().unwrap());
                self.leave_signed = None;
                self.leave_intent = None;
                self.member = Member::Standalone;
                self.config = None;
                self.proof = None;
                self.lock = None;
                self.signature = None;
                self.contracts.clear();
                self.results.clear();
                self.contract_tombstones.clear();
                self.task_tombstones.clear();
                self.requested_tasks.clear();
                self.isolate();
            }
            _ => return Err(Error::Invalid),
        }
        if !r.done() {
            self.frozen = true;
            return Err(Error::Invalid);
        }
        self.serial = serial;
        Ok(())
    }
}
pub fn result_digest<C: Crypto>(crypto: &C, state: TaskState, body: &[u8]) -> [u8; 32] {
    if state == TaskState::Done {
        crypto.sha256(body)
    } else {
        let mut b = vec![state as u8];
        b.extend_from_slice(body);
        crypto.sha256(&b)
    }
}
fn encode_terms(b: &mut Vec<u8>, t: &Terms) {
    b.extend_from_slice(&t.id);
    b.extend_from_slice(&t.cpu_milli.to_le_bytes());
    b.extend_from_slice(&t.memory_pages.to_le_bytes());
    b.extend_from_slice(&t.runtime_ms.to_le_bytes());
    b.extend_from_slice(&t.package_hash);
    b.extend_from_slice(&t.input_hash)
}
fn encode_contract(c: &Contract) -> Vec<u8> {
    let mut b = Vec::new();
    encode_terms(&mut b, &c.terms);
    b.extend_from_slice(&c.request_hash);
    b.extend_from_slice(&c.reservation);
    b.extend_from_slice(&c.owner_boot.to_le_bytes());
    b.extend_from_slice(&c.grant_epoch.to_le_bytes());
    b.extend_from_slice(&c.deadline_ms.to_le_bytes());
    b.push(c.state as u8);
    b
}
fn encode_key(b: &mut Vec<u8>, k: TaskKey) {
    b.extend_from_slice(&k.cluster);
    b.extend_from_slice(&k.contract);
    b.extend_from_slice(&k.task);
    b.extend_from_slice(&k.attempt.to_le_bytes());
}
fn encode_result(r: &ResultRecord) -> Vec<u8> {
    let mut b = Vec::new();
    encode_key(&mut b, r.key);
    b.push(r.state as u8);
    b.extend_from_slice(&r.input_hash);
    b.extend_from_slice(&r.result_hash);
    b.push(u8::from(r.received));
    b.extend_from_slice(&(r.body.len() as u32).to_le_bytes());
    b.extend_from_slice(&r.body);
    b
}
struct Read<'a> {
    b: &'a [u8],
    at: usize,
}
impl<'a> Read<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, at: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(n).ok_or(Error::Invalid)?;
        let out = self.b.get(self.at..end).ok_or(Error::Invalid)?;
        self.at = end;
        Ok(out)
    }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.arr()?))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.arr()?))
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn done(&self) -> bool {
        self.at == self.b.len()
    }
}
fn decode_key(r: &mut Read<'_>) -> Result<TaskKey, Error> {
    Ok(TaskKey {
        cluster: r.arr()?,
        contract: r.arr()?,
        task: r.arr()?,
        attempt: r.u64()?,
    })
}
fn decode_contract(r: &mut Read<'_>) -> Result<Contract, Error> {
    let terms = Terms {
        id: r.arr()?,
        cpu_milli: u16::from_le_bytes(r.arr()?),
        memory_pages: r.u32()?,
        runtime_ms: r.u32()?,
        package_hash: r.arr()?,
        input_hash: r.arr()?,
    };
    let request_hash = r.arr()?;
    let reservation = r.arr()?;
    let owner_boot = r.u64()?;
    let grant_epoch = r.u64()?;
    let deadline_ms = r.u64()?;
    let state = match r.byte()? {
        0 => ContractState::Prepared,
        1 => ContractState::GrantPending,
        2 => ContractState::Granted,
        3 => ContractState::Suspended,
        4 => ContractState::Revoking,
        5 => ContractState::Released,
        _ => return Err(Error::Invalid),
    };
    Ok(Contract {
        remote: false,
        terms,
        request_hash,
        reservation,
        owner_boot,
        grant_epoch,
        deadline_ms,
        state,
        task: None,
        enqueued: false,
    })
}
fn decode_result(r: &mut Read<'_>) -> Result<ResultRecord, Error> {
    let key = decode_key(r)?;
    let state = match r.byte()? {
        0 => TaskState::Started,
        1 => TaskState::Done,
        2 => TaskState::Failed,
        3 => TaskState::Cancelled,
        4 => TaskState::Lost,
        _ => return Err(Error::Invalid),
    };
    let input_hash = r.arr()?;
    let result_hash = r.arr()?;
    let received = match r.byte()? {
        0 => false,
        1 => true,
        _ => return Err(Error::Invalid),
    };
    let len = r.u32()? as usize;
    if len > 32768 {
        return Err(Error::Capacity);
    }
    let body = r.take(len)?.to_vec();
    Ok(ResultRecord {
        key,
        state,
        input_hash,
        result_hash,
        body,
        acknowledged: false,
        received,
    })
}
