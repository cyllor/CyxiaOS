//! Bounded stream RPC driver used by the native EL0 TLS runtime.
//! Storage acknowledgements precede all externally visible durable replies.
use crate::broker;
use alloc::vec::Vec;
use cyxia_cluster_transport::tls::IdentitySigner;
use cyxia_prototype::cluster::{
    self, Crypto, Durability, Effect, Engine, Member, Status, TaskKey, TaskState, Terms,
    wire::{Config, Header, Proof},
};
use cyxia_prototype_cluster::abi::*;
struct RingCrypto {
    signer: IdentitySigner,
    own_public: [u8; 32],
    peer_public: [u8; 32],
    local: [u8; 32],
    peer: [u8; 32],
}
impl Crypto for RingCrypto {
    fn sha256(&self, b: &[u8]) -> [u8; 32] {
        ring::digest::digest(&ring::digest::SHA256, b)
            .as_ref()
            .try_into()
            .unwrap()
    }
    fn sign(&self, b: &[u8]) -> [u8; 64] {
        self.signer.sign(b)
    }
    fn verify(&self, node: &[u8; 32], b: &[u8], s: &[u8; 64]) -> bool {
        let public = if *node == self.local {
            &self.own_public
        } else if *node == self.peer {
            &self.peer_public
        } else {
            return false;
        };
        IdentitySigner::verify(public, node, b, s)
    }
}
#[derive(Clone, Copy)]
struct OwnedStatus {
    terms: Terms,
    hash: [u8; 32],
    reservation: [u8; 16],
    boot: u64,
    epoch: u64,
}
struct OutSnapshot {
    id: u64,
    items: Vec<Status>,
    cursor: usize,
    owned: Vec<OwnedStatus>,
}
struct InSnapshot {
    id: u64,
    items: Vec<Status>,
    owned: Vec<OwnedStatus>,
}
pub struct Driver {
    engine: Engine<RingCrypto>,
    input: Vec<u8>,
    output: Vec<u8>,
    sent: usize,
    sequence: u64,
    request: u64,
    session: [u8; 32],
    challenge: [u8; 32],
    local_nonce: [u8; 32],
    peer_nonce: [u8; 32],
    peer_counter: u64,
    peer_last: u64,
    peer_boot: u64,
    active: bool,
    last_rx: u64,
    last_status: u64,
    formation_sent: bool,
    ready_sent: bool,
    quoted: bool,
    prepared: bool,
    committed: bool,
    activated: bool,
    done: bool,
    terms: Option<Terms>,
    reservation: [u8; 16],
    contract_hash: [u8; 32],
    kernel_token: Option<u64>,
    kernel_contract: Option<[u8; 16]>,
    kernel_epoch: u64,
    task_key: Option<TaskKey>,
    deadline: u64,
    sent_results: Vec<TaskKey>,
    recovering: bool,
    leave_id: Option<[u8; 16]>,
    finished_leave: bool,
    snapshot_id: u64,
    out_snapshot: Option<OutSnapshot>,
    in_snapshot: Option<InSnapshot>,
}
impl Driver {
    pub fn new(
        boot: u64,
        uuid: [u8; 16],
        local: [u8; 32],
        peer: [u8; 32],
        signer: IdentitySigner,
        peer_public: [u8; 32],
    ) -> Result<Self, ()> {
        let own_public = signer.public_key();
        let crypto = RingCrypto {
            signer,
            own_public,
            peer_public,
            local,
            peer,
        };
        if crypto.sha256(&own_public) != local || crypto.sha256(&peer_public) != peer {
            return Err(());
        }
        let mut engine = Engine::new(local, peer, boot, crypto).map_err(|_| ())?;
        let mut identity = b"CXID1".to_vec();
        identity.extend_from_slice(&uuid);
        identity.extend_from_slice(&local);
        identity.extend_from_slice(&peer);
        match read_record(1)? {
            None => write_record(0, &identity).map_err(|_| ())?,
            Some(record) => {
                if record != identity {
                    return Err(());
                }
            }
        }
        let mut ordinal = 2;
        while let Some(record) = read_record(ordinal)? {
            engine.recover_event(&record).map_err(|_| ())?;
            ordinal += 1;
            if ordinal > 32768 {
                return Err(());
            }
        }
        while let Some(e) = engine.recovery_loss().map_err(|_| ())? {
            persist(&mut engine, e)?;
            broker::trace(0x218);
        }
        let done = !engine.statuses().is_empty() || !engine.contracts.is_empty();
        let leave_id = engine.leave_intent.or_else(|| {
            engine
                .frozen_leave()
                .map(|(record, _)| record[40..56].try_into().unwrap())
        });
        Ok(Self {
            engine,
            input: Vec::new(),
            output: Vec::new(),
            sent: 0,
            sequence: 0,
            request: 0,
            session: [0; 32],
            challenge: [0; 32],
            local_nonce: [0; 32],
            peer_nonce: [0; 32],
            peer_counter: 0,
            peer_last: 0,
            peer_boot: 0,
            active: false,
            last_rx: 0,
            last_status: 0,
            formation_sent: false,
            ready_sent: false,
            quoted: false,
            prepared: false,
            committed: false,
            activated: false,
            done,
            terms: None,
            reservation: [0; 16],
            contract_hash: [0; 32],
            kernel_token: None,
            kernel_contract: None,
            kernel_epoch: 0,
            task_key: None,
            deadline: 0,
            sent_results: Vec::new(),
            recovering: false,
            leave_id,
            finished_leave: false,
            snapshot_id: 0,
            out_snapshot: None,
            in_snapshot: None,
        })
    }
    pub fn connect(&mut self, challenge: [u8; 32], now: u64) -> Result<(), ()> {
        self.disconnect();
        if challenge == [0; 32] {
            return Err(());
        }
        self.recovering = !self.engine.contracts.is_empty()
            || !self.engine.statuses().is_empty()
            || !self.engine.results.is_empty();
        self.finished_leave = false;
        self.out_snapshot = None;
        self.in_snapshot = None;
        self.challenge = challenge;
        self.active = true;
        self.last_rx = now;
        self.last_status = now;
        self.kernel_epoch = broker::poll().map_err(|_| ())?.1;
        broker::request(OP_TASK, &[], &mut [], 0, [9, 1, self.kernel_epoch]).map_err(|_| ())?;
        self.sent_results.clear();
        if self.engine.member == Member::Standalone {
            if let Some((nonce, _)) = self.engine.formation_lock() {
                self.local_nonce = nonce;
            } else {
                broker::entropy(&mut self.local_nonce).map_err(|_| ())?;
                let e = self
                    .engine
                    .begin_formation(self.local_nonce)
                    .map_err(|_| ())?;
                persist(&mut self.engine, e)?;
            }
        } else if let Some(c) = self.engine.config {
            let i = usize::from(c.nodes[1] == self.engine.local);
            self.local_nonce = c.nonces[i];
        }
        let mut body = Vec::new();
        body.extend_from_slice(&self.engine.local);
        body.extend_from_slice(&self.challenge);
        body.extend_from_slice(&self.engine.formation_counter.to_le_bytes());
        body.extend_from_slice(
            &self
                .engine
                .formation_lock()
                .map(|(_, epoch)| epoch)
                .unwrap_or(self.engine.last_epoch)
                .to_le_bytes(),
        );
        body.extend_from_slice(&self.local_nonce);
        body.push(self.engine.member as u8);
        self.send(1, body, None)?;
        Ok(())
    }
    pub fn begin_leave(&mut self, id: [u8; 16]) -> Result<(), ()> {
        if !self.active || self.peer_boot == 0 {
            return Err(());
        }
        let e = self.engine.leave_with_id(id).map_err(|_| ())?;
        persist(&mut self.engine, e)?;
        broker::request(OP_TASK, &[], &mut [], 0, [9, 1, self.kernel_epoch]).map_err(|_| ())?;
        self.leave_id = Some(id);
        let mut b = id.to_vec();
        b.extend_from_slice(&self.engine.obligation_digest());
        self.send(32, b, None)
    }
    pub fn disconnect(&mut self) {
        if let Some(id) = self
            .engine
            .contracts
            .iter()
            .find(|c| !c.remote && c.state == cluster::ContractState::Prepared)
            .map(|c| c.terms.id)
        {
            if let Some(token) = self.kernel_token {
                if broker::request(OP_TASK, &[], &mut [], 0, [5, token, 0]).is_ok()
                    && broker::request(OP_TASK, &[], &mut [], 0, [8, token, 0]).is_ok()
                    && broker::request(OP_TASK, &[], &mut [], 0, [4, token, 0]).is_ok()
                {
                    let _ = self.engine.abandon_prepared(id);
                    self.kernel_token = None;
                }
            }
        }
        let _ = broker::request(OP_TASK, &[], &mut [], 0, [9, 0, self.kernel_epoch]);
        self.active = false;
        self.engine.isolate();
        self.input.clear();
        self.output.clear();
        self.sent = 0;
        self.sequence = 0;
        self.peer_boot = 0;
        self.formation_sent = false;
        self.ready_sent = false;
        self.quoted = false;
        self.prepared = false;
        self.committed = false;
    }
    pub fn outgoing(&self) -> &[u8] {
        &self.output[self.sent..]
    }
    pub fn consume_outgoing(&mut self, n: usize) {
        if n <= self.output.len() - self.sent {
            self.sent += n;
            if self.sent == self.output.len() {
                self.output.clear();
                self.sent = 0;
            }
        } else {
            self.disconnect();
        }
    }
    pub fn ingest(&mut self, bytes: &[u8], now: u64) -> Result<usize, ()> {
        if !self.active || self.input.len() + bytes.len() > 96 + 65536 {
            return Err(());
        }
        self.input.extend_from_slice(bytes);
        loop {
            if self.input.len() < 96 {
                break;
            }
            let h = Header::decode(&self.input[..96]).map_err(|_| ())?;
            let n = 96 + h.body_len as usize;
            if self.input.len() < n {
                break;
            }
            let body = self.input[96..n].to_vec();
            self.input.drain(..n);
            self.handle(h, &body, now)?;
            self.last_rx = now;
            if self.engine.ready() {
                broker::request(OP_TASK, &[], &mut [], 0, [9, 2, self.kernel_epoch])
                    .map_err(|_| ())?;
            }
        }
        Ok(bytes.len())
    }
    fn send(&mut self, kind: u16, body: Vec<u8>, reply: Option<[u8; 16]>) -> Result<(), ()> {
        if body.len() > 65536 || self.output.len() + 96 + body.len() > 131264 {
            return Err(());
        }
        self.sequence = self.sequence.checked_add(1).ok_or(())?;
        let request = if let Some(id) = reply {
            id
        } else {
            self.request = self.request.checked_add(1).ok_or(())?;
            let mut id = [0; 16];
            id[..8].copy_from_slice(&self.engine.boot.to_le_bytes());
            id[8..].copy_from_slice(&self.request.to_le_bytes());
            id
        };
        let mut h = Header {
            kind,
            body_len: body.len() as u32,
            sequence: self.sequence,
            request,
            cluster: if matches!(self.engine.member, Member::Bound | Member::Leaving) {
                self.engine.cluster()
            } else {
                [0; 32]
            },
            epoch: if matches!(self.engine.member, Member::Bound | Member::Leaving) {
                self.engine.config.map(|c| c.epoch).unwrap_or(0)
            } else {
                0
            },
            sender_boot: self.engine.boot,
            receiver_boot: self.peer_boot,
        };
        if kind & 0x7fff == 33 && body.len() == 312 {
            h.cluster = body[..32].try_into().unwrap();
            h.epoch = u64::from_le_bytes(body[32..40].try_into().unwrap());
        }
        self.output.extend_from_slice(&h.encode());
        self.output.extend_from_slice(&body);
        Ok(())
    }
    fn status(&mut self) -> Result<(), ()> {
        if self.out_snapshot.is_none() {
            let mut items = self.engine.statuses();
            if items.len() > 4096 {
                return Err(());
            }
            items.sort_unstable_by_key(|s| s.contract);
            self.snapshot_id = self.snapshot_id.checked_add(1).ok_or(())?;
            let owned = self
                .engine
                .contracts
                .iter()
                .filter(|c| !c.remote && c.state != cluster::ContractState::Prepared)
                .map(|c| OwnedStatus {
                    terms: c.terms,
                    hash: c.request_hash,
                    reservation: c.reservation,
                    boot: c.owner_boot,
                    epoch: c.grant_epoch,
                })
                .collect();
            self.out_snapshot = Some(OutSnapshot {
                id: self.snapshot_id,
                items,
                cursor: 0,
                owned,
            });
        }
        self.status_page()
    }
    fn status_page(&mut self) -> Result<(), ()> {
        let Some(snapshot) = self.out_snapshot.as_ref() else {
            return Ok(());
        };
        if self.outgoing().len() > 96 * 1024 {
            return Ok(());
        }
        let mut b = Vec::new();
        let proof = self.engine.proof.map(|p| p.encode());
        b.push(u8::from(proof.is_some()));
        if let Some(p) = proof {
            b.extend_from_slice(&p)
        }
        b.extend_from_slice(&snapshot.id.to_le_bytes());
        b.push(u8::from(snapshot.cursor > 0));
        if snapshot.cursor > 0 {
            b.extend_from_slice(&snapshot.items[snapshot.cursor - 1].contract)
        }
        let end = (snapshot.cursor + 32).min(snapshot.items.len());
        b.push(u8::from(end < snapshot.items.len()));
        b.extend_from_slice(&((end - snapshot.cursor) as u32).to_le_bytes());
        for item in &snapshot.items[snapshot.cursor..end] {
            b.extend_from_slice(&item.contract);
            b.extend_from_slice(&item.request_hash);
            b.push(u8::from(item.terminal_hash.is_some()));
            if let Some(h) = item.terminal_hash {
                b.extend_from_slice(&h)
            }
        }
        let owned = if snapshot.cursor == 0 {
            &snapshot.owned[..]
        } else {
            &[]
        };
        b.extend_from_slice(&(owned.len() as u32).to_le_bytes());
        for c in owned {
            b.extend_from_slice(&terms_bytes(c.terms));
            b.extend_from_slice(&c.hash);
            b.extend_from_slice(&c.reservation);
            b.extend_from_slice(&c.boot.to_le_bytes());
            b.extend_from_slice(&c.epoch.to_le_bytes());
        }
        self.send(2, b, None)?;
        let snapshot = self.out_snapshot.as_mut().ok_or(())?;
        snapshot.cursor = end;
        if end == snapshot.items.len() {
            self.out_snapshot = None;
        }
        Ok(())
    }
    fn handle(&mut self, h: Header, b: &[u8], now: u64) -> Result<(), ()> {
        let kind = h.kind & 0x7fff;
        #[cfg(test)]
        broker::trace(0x10000 + h.kind as u64);
        let response = h.kind & 0x8000 != 0;
        if kind == 1 {
            if self.peer_boot != 0
                || h.sequence != 1
                || b.len() != 113
                || b[..32] != self.engine.peer
                || h.sender_boot == 0
                || !(h.receiver_boot == 0 || h.receiver_boot == self.engine.boot)
            {
                return Err(());
            }
            let peer_challenge: [u8; 32] = b[32..64].try_into().unwrap();
            let mut m = b"CX-SESSION-v1".to_vec();
            if self.engine.local < self.engine.peer {
                m.extend_from_slice(&self.challenge);
                m.extend_from_slice(&peer_challenge)
            } else {
                m.extend_from_slice(&peer_challenge);
                m.extend_from_slice(&self.challenge)
            }
            self.session = self.engine.crypto.sha256(&m);
            self.peer_boot = h.sender_boot;
            self.peer_counter = u64::from_le_bytes(b[64..72].try_into().unwrap());
            self.peer_last = u64::from_le_bytes(b[72..80].try_into().unwrap());
            self.peer_nonce = b[80..112].try_into().unwrap();
            self.engine
                .hello(self.peer_boot, self.session)
                .map_err(|_| ())?;
            if self.engine.member == Member::Standalone
                && b[112] == Member::Leaving as u8
                && self
                    .engine
                    .last_leave_proof
                    .is_some_and(|proof| proof[..32] == h.cluster)
            {
                let proof = self.engine.last_leave_proof.unwrap();
                self.send(33, proof.to_vec(), None)?;
                self.finished_leave = true;
                broker::request(OP_TASK, &[], &mut [], 0, [9, 0, self.kernel_epoch])
                    .map_err(|_| ())?;
                return Ok(());
            }
            if self.engine.member == Member::Leaving {
                if let Some((record, signature)) = self.engine.frozen_leave() {
                    let mut out = record.to_vec();
                    out.extend_from_slice(&signature);
                    self.send(0x8020, out, None)?;
                } else if let Some(id) = self.engine.leave_intent {
                    let mut out = id.to_vec();
                    out.extend_from_slice(&self.engine.obligation_digest());
                    self.send(32, out, None)?;
                }
            } else if self.engine.member == Member::Bound {
                self.status()?;
            } else if self.engine.member == Member::Confirmed {
                let c = self.engine.config.ok_or(())?;
                let mut body = c.encode().to_vec();
                body.extend_from_slice(&self.engine.signature().ok_or(())?);
                self.send(4, body, None)?;
            } else if self.engine.member == Member::Standalone
                && self.engine.local < self.engine.peer
            {
                let c = Config {
                    trust_domain: self.engine.crypto.sha256(b"CyxiaOS paired native v1"),
                    nodes: [self.engine.local, self.engine.peer],
                    counters: [self.engine.formation_counter, self.peer_counter],
                    nonces: [self.local_nonce, self.peer_nonce],
                    schema: self.engine.crypto.sha256(b"CX-RPC-native-schema-1"),
                    policy: self.engine.crypto.sha256(b"pure-vector-sum-only"),
                    epoch: self
                        .engine
                        .formation_lock()
                        .map(|(_, epoch)| epoch)
                        .unwrap_or(self.engine.last_epoch)
                        .max(self.peer_last)
                        .checked_add(1)
                        .ok_or(())?,
                };
                self.formation_sent = true;
                self.send(3, c.encode().to_vec(), None)?;
            }
            self.resume_closure()?;
            return Ok(());
        }
        if self.finished_leave {
            if h.sender_boot != self.peer_boot || h.receiver_boot != self.engine.boot {
                return Err(());
            }
            return Ok(());
        }
        self.engine.accept_header(&h).map_err(|_| ())?;
        match (kind, response) {
            (3, false) => {
                let c = Config::decode(b).map_err(|_| ())?;
                if self.engine.local < self.engine.peer
                    || c.trust_domain != self.engine.crypto.sha256(b"CyxiaOS paired native v1")
                    || c.schema != self.engine.crypto.sha256(b"CX-RPC-native-schema-1")
                    || c.policy != self.engine.crypto.sha256(b"pure-vector-sum-only")
                {
                    return Err(());
                }
                let e = self.engine.confirm(c, self.peer_last).map_err(|_| ())?;
                persist(&mut self.engine, e)?;
                let mut body = c.encode().to_vec();
                body.extend_from_slice(&self.engine.signature().ok_or(())?);
                self.send(4, body, None)?;
                broker::trace(0x210);
            }
            (4, false) => {
                if b.len() != 316 {
                    return Err(());
                }
                let c = Config::decode(&b[..252]).map_err(|_| ())?;
                let signature: [u8; 64] = b[252..].try_into().unwrap();
                if self.engine.member == Member::Standalone {
                    let e = self.engine.confirm(c, self.peer_last).map_err(|_| ())?;
                    persist(&mut self.engine, e)?;
                    let mut body = c.encode().to_vec();
                    body.extend_from_slice(&self.engine.signature().ok_or(())?);
                    self.send(4, body, None)?;
                    broker::trace(0x210);
                }
                let own = self.engine.signature().ok_or(())?;
                let sigs = if self.engine.local < self.engine.peer {
                    [own, signature]
                } else {
                    [signature, own]
                };
                let p = Proof {
                    config: c,
                    formation: self.engine.formation_for(&c),
                    signatures: sigs,
                };
                let e = self.engine.bind(p).map_err(|_| ())?;
                persist(&mut self.engine, e)?;
                broker::trace(0x211);
                self.send(5, p.encode().to_vec(), None)?;
                self.status()?;
            }
            (5, false) => {
                let p = Proof::decode(b).map_err(|_| ())?;
                if self.engine.member != Member::Bound {
                    let e = self.engine.bind(p).map_err(|_| ())?;
                    persist(&mut self.engine, e)?;
                    broker::trace(0x211);
                } else if self.engine.proof != Some(p) {
                    return Err(());
                }
                self.status()?;
            }
            (2, false) | (2, true) => {
                let mut r = Reader::new(b);
                let proof = match r.byte()? {
                    0 => None,
                    1 => Some(Proof::decode(r.take(412)?).map_err(|_| ())?),
                    _ => return Err(()),
                };
                if proof != self.engine.proof || proof.is_none() {
                    return Err(());
                }
                let snapshot_id = r.u64()?;
                if snapshot_id == 0 {
                    return Err(());
                }
                let cursor = match r.byte()? {
                    0 => None,
                    1 => Some(r.arr()?),
                    _ => return Err(()),
                };
                let more = match r.byte()? {
                    0 => false,
                    1 => true,
                    _ => return Err(()),
                };
                if cursor.is_none() {
                    self.in_snapshot = Some(InSnapshot {
                        id: snapshot_id,
                        items: Vec::new(),
                        owned: Vec::new(),
                    });
                }
                let incoming = self.in_snapshot.as_ref().ok_or(())?;
                if incoming.id != snapshot_id || cursor != incoming.items.last().map(|s| s.contract)
                {
                    return Err(());
                }
                let count = r.u32()? as usize;
                if count > 32 {
                    return Err(());
                }
                let mut statuses = Vec::new();
                for _ in 0..count {
                    let contract = r.arr()?;
                    let request_hash = r.arr()?;
                    let terminal_hash = match r.byte()? {
                        0 => None,
                        1 => Some(r.arr()?),
                        _ => return Err(()),
                    };
                    statuses.push(Status {
                        contract,
                        request_hash,
                        terminal_hash,
                    })
                }
                let owners = r.u32()? as usize;
                if owners > 32 || (cursor.is_some() && owners != 0) {
                    return Err(());
                }
                let mut owned = Vec::new();
                for _ in 0..owners {
                    owned.push(OwnedStatus {
                        terms: read_terms(&mut r)?,
                        hash: r.arr()?,
                        reservation: r.arr()?,
                        boot: r.u64()?,
                        epoch: r.u64()?,
                    });
                }
                r.end()?;
                let incoming = self.in_snapshot.as_mut().ok_or(())?;
                for item in statuses {
                    if incoming
                        .items
                        .last()
                        .is_some_and(|old| old.contract >= item.contract)
                        || incoming.items.len() >= 4096
                    {
                        return Err(());
                    }
                    incoming.items.push(item);
                }
                incoming.owned.extend(owned);
                if more {
                    if count == 0 {
                        return Err(());
                    }
                    return Ok(());
                }
                let incoming = self.in_snapshot.take().ok_or(())?;
                let statuses = incoming.items;
                let mut ownerids = Vec::new();
                for c in incoming.owned {
                    ownerids.push(c.terms.id);
                    if self.recovering
                        && self.engine.contracts.iter().any(|old| {
                            old.remote
                                && old.terms.id == c.terms.id
                                && old.request_hash == c.hash
                                && old.state == cluster::ContractState::Prepared
                        })
                    {
                        let e = self
                            .engine
                            .observe_grant(c.terms, c.hash, c.reservation, c.boot, c.epoch)
                            .map_err(|_| ())?;
                        persist(&mut self.engine, e)?;
                    }
                }
                if self.recovering {
                    let pending: Vec<_> = self
                        .engine
                        .contracts
                        .iter()
                        .filter(|c| {
                            c.remote
                                && c.state == cluster::ContractState::Prepared
                                && !ownerids.contains(&c.terms.id)
                        })
                        .map(|c| c.terms.id)
                        .collect();
                    for id in pending {
                        let e = self.engine.cancel_request(id).map_err(|_| ())?;
                        persist(&mut self.engine, e)?;
                    }
                    let closes: Vec<_> = self
                        .engine
                        .contracts
                        .iter()
                        .filter(|c| c.remote && c.state != cluster::ContractState::Prepared)
                        .map(|c| c.terms.id)
                        .collect();
                    for id in closes {
                        self.send(22, id.to_vec(), None)?;
                    }
                }
                if self.engine.reconcile(&statuses).is_ok() && !self.ready_sent {
                    self.engine.send_ready().map_err(|_| ())?;
                    self.ready_sent = true;
                    self.send(6, self.session.to_vec(), None)?;
                }
            }
            (6, false) => {
                if b != self.session {
                    return Err(());
                }
                self.engine
                    .peer_ready(self.peer_boot, self.session, self.engine.cluster())
                    .map_err(|_| ())?;
                if self.engine.ready() {
                    broker::request(OP_TASK, &[], &mut [], 0, [9, 2, self.kernel_epoch])
                        .map_err(|_| ())?;
                    broker::trace(0x212);
                }
            }
            (16, false) => {
                if !b.is_empty() || !self.engine.ready() {
                    return Err(());
                }
                let hash = package_hash()?;
                let mut out = self.engine.boot.to_le_bytes().to_vec();
                out.extend_from_slice(&2000u32.to_le_bytes());
                out.extend_from_slice(&hash);
                self.send(0x8010, out, Some(h.request))?;
            }
            (16, true) => {
                if b.len() != 44 {
                    return Err(());
                }
                let owner_boot = u64::from_le_bytes(b[..8].try_into().unwrap());
                if owner_boot != self.peer_boot || b[12..44] != package_hash()? {
                    return Err(());
                }
                let mut idbytes = b"CX-DEMO-CONTRACT-v1".to_vec();
                idbytes.extend_from_slice(&self.engine.cluster());
                idbytes.extend_from_slice(&self.engine.local);
                let hash = self.engine.crypto.sha256(&idbytes);
                let t = Terms {
                    id: hash[..16].try_into().unwrap(),
                    cpu_milli: 100,
                    memory_pages: 16,
                    runtime_ms: 60000,
                    package_hash: b[12..44].try_into().unwrap(),
                    input_hash: self.engine.crypto.sha256(&task_input()),
                };
                self.contract_hash =
                    self.engine
                        .request_hash_for(&t, self.engine.local, self.engine.peer);
                self.terms = Some(t);
                let mut body = terms_bytes(t);
                body.extend_from_slice(&self.contract_hash);
                body.extend_from_slice(&owner_boot.to_le_bytes());
                let e = self
                    .engine
                    .record_request(t, self.contract_hash)
                    .map_err(|_| ())?;
                persist(&mut self.engine, e)?;
                self.done = true;
                self.send(17, body, None)?;
            }
            (17, false) => {
                let mut r = Reader::new(b);
                let t = read_terms(&mut r)?;
                let hash = r.arr()?;
                let owner_boot = r.u64()?;
                r.end()?;
                if owner_boot != self.engine.boot || t.package_hash != package_hash()? {
                    return Err(());
                }
                let mut reserve = Vec::new();
                reserve.extend_from_slice(&(t.cpu_milli as u64).to_le_bytes());
                reserve.extend_from_slice(&(t.memory_pages as u64).to_le_bytes());
                reserve.extend_from_slice(&(t.runtime_ms as u64).to_le_bytes());
                reserve.extend_from_slice(&t.id);
                reserve.extend_from_slice(&t.input_hash);
                reserve.extend_from_slice(&t.package_hash);
                broker::entropy(&mut self.reservation).map_err(|_| ())?;
                let (_, token) =
                    broker::request(OP_TASK, &reserve, &mut [], 0, [0, 0, 0]).map_err(|_| ())?;
                self.kernel_token = Some(token);
                self.kernel_contract = Some(t.id);
                if self
                    .engine
                    .prepare(t, hash, self.reservation, now, 2000)
                    .is_err()
                {
                    let _ = broker::request(OP_TASK, &[], &mut [], 0, [4, token, 0]);
                    self.kernel_token = None;
                    self.kernel_contract = None;
                    return Err(());
                }
                self.terms = Some(t);
                self.contract_hash = hash;
                let mut out = t.id.to_vec();
                out.extend_from_slice(&self.reservation);
                out.extend_from_slice(&2000u32.to_le_bytes());
                self.send(0x8011, out, Some(h.request))?;
                broker::trace(0x220);
            }
            (17, true) => {
                if b.len() != 36 || b[..16] != self.terms.ok_or(())?.id {
                    return Err(());
                }
                self.reservation = b[16..32].try_into().unwrap();
                let mut out = b[..32].to_vec();
                out.extend_from_slice(&self.contract_hash);
                self.send(18, out, None)?;
                self.prepared = true;
            }
            (18, false) => {
                if b.len() != 64 {
                    return Err(());
                }
                let id = b[..16].try_into().unwrap();
                let reservation = b[16..32].try_into().unwrap();
                let hash = b[32..64].try_into().unwrap();
                let e = self
                    .engine
                    .commit(id, reservation, hash, now)
                    .map_err(|_| ())?;
                persist(&mut self.engine, e)?;
                self.deadline = now + self.terms.ok_or(())?.runtime_ms as u64;
                let mut grant = self.deadline.to_le_bytes().to_vec();
                grant.extend_from_slice(&1u64.to_le_bytes());
                grant.extend_from_slice(&id);
                broker::request(
                    OP_TASK,
                    &grant,
                    &mut [],
                    0,
                    [7, self.kernel_token.ok_or(())?, 0],
                )
                .map_err(|_| ())?;
                broker::trace(0x213);
                let mut out = id.to_vec();
                out.extend_from_slice(&self.engine.boot.to_le_bytes());
                out.extend_from_slice(&1u64.to_le_bytes());
                self.send(0x8012, out, Some(h.request))?;
            }
            (18, true) => {
                if b.len() != 32 || b[..16] != self.terms.ok_or(())?.id {
                    return Err(());
                }
                let owner_boot = u64::from_le_bytes(b[16..24].try_into().unwrap());
                let grant_epoch = u64::from_le_bytes(b[24..32].try_into().unwrap());
                let t = self.terms.ok_or(())?;
                let e = self
                    .engine
                    .observe_grant(
                        t,
                        self.contract_hash,
                        self.reservation,
                        owner_boot,
                        grant_epoch,
                    )
                    .map_err(|_| ())?;
                persist(&mut self.engine, e)?;
                let key = TaskKey {
                    cluster: self.engine.cluster(),
                    contract: t.id,
                    task: [1; 16],
                    attempt: 1,
                };
                let e = self
                    .engine
                    .record_request_task(key, t.input_hash)
                    .map_err(|_| ())?;
                persist(&mut self.engine, e)?;
                self.task_key = Some(key);
                let mut out = key_bytes(key);
                out.extend_from_slice(&self.contract_hash);
                out.extend_from_slice(&owner_boot.to_le_bytes());
                out.extend_from_slice(&grant_epoch.to_le_bytes());
                let input = task_input();
                out.extend_from_slice(&(input.len() as u32).to_le_bytes());
                out.extend_from_slice(&input);
                self.send(19, out, None)?;
                self.committed = true;
            }
            (19, false) => {
                let mut r = Reader::new(b);
                let key = read_key(&mut r)?;
                let hash = r.arr()?;
                let owner_boot = r.u64()?;
                let grant_epoch = r.u64()?;
                let len = r.u32()? as usize;
                if len > 32768 {
                    return Err(());
                }
                let input = r.take(len)?;
                r.end()?;
                let e = self
                    .engine
                    .activate(key, hash, input, owner_boot, grant_epoch, now)
                    .map_err(|_| ())?;
                persist(&mut self.engine, e)?;
                self.task_key = Some(key);
                self.activated = true;
                let token = self.kernel_token.ok_or(())?;
                let dispatched = (|| -> Result<(), ()> {
                    for (offset, chunk) in input.chunks(PAYLOAD).enumerate() {
                        broker::request(
                            OP_TASK,
                            chunk,
                            &mut [],
                            0,
                            [1, token, (offset * PAYLOAD) as u64],
                        )
                        .map_err(|_| ())?;
                    }
                    let current = broker::time().ok_or(())?.0;
                    self.engine
                        .enqueue(key, owner_boot, grant_epoch, current)
                        .map_err(|_| ())?;
                    let mut start = (input.len() as u64).to_le_bytes().to_vec();
                    start.extend_from_slice(&self.deadline.to_le_bytes());
                    start.extend_from_slice(&self.kernel_epoch.to_le_bytes());
                    start.extend_from_slice(&grant_epoch.to_le_bytes());
                    start.extend_from_slice(&key.contract);
                    broker::request(OP_TASK, &start, &mut [], 0, [2, token, 0]).map_err(|_| ())?;
                    Ok(())
                })();
                if dispatched.is_err() {
                    // State 1 is the kernel's proof that no queue owner ever
                    // existed. Quiescent DONE/CANCELLED alone cannot prove it.
                    if matches!(
                        broker::request(OP_TASK, &[], &mut [], 0, [8, token, 0]),
                        Ok((_, 1))
                    ) && broker::request(OP_TASK, &[], &mut [], 0, [5, token, 0]).is_ok()
                        && broker::request(OP_TASK, &[], &mut [], 0, [8, token, 0]).is_ok()
                    {
                        let e = self
                            .engine
                            .finish(key, TaskState::Cancelled, &[])
                            .map_err(|_| ())?;
                        persist(&mut self.engine, e)?;
                        self.activated = false;
                        broker::trace(0x215);
                        return Ok(());
                    }
                    return Err(());
                }
                broker::trace(0x214);
            }
            (20, false) => {
                let mut r = Reader::new(b);
                let key = read_key(&mut r)?;
                let state = match r.byte()? {
                    1 => TaskState::Done,
                    2 => TaskState::Failed,
                    3 => TaskState::Cancelled,
                    4 => TaskState::Lost,
                    _ => return Err(()),
                };
                let input_hash = r.arr()?;
                let hash = r.arr()?;
                let len = r.u32()? as usize;
                if len > 32768 {
                    return Err(());
                }
                let body = r.take(len)?;
                r.end()?;
                if state == TaskState::Done && body != 10i64.to_le_bytes() {
                    return Err(());
                }
                let e = self
                    .engine
                    .receive_result(key, state, input_hash, body, hash)
                    .map_err(|_| ())?;
                persist(&mut self.engine, e)?;
                let hash = self.engine.ack_ready(key).map_err(|_| ())?;
                broker::trace(0x216);
                let mut out = key_bytes(key);
                out.extend_from_slice(&hash);
                self.send(21, out, None)?;
                self.done = true;
                self.task_key = Some(key);
            }
            (21, false) => {
                let mut r = Reader::new(b);
                let key = read_key(&mut r)?;
                let hash = r.arr()?;
                r.end()?;
                let e = self.engine.ack_result(key, hash).map_err(|_| ())?;
                persist(&mut self.engine, e)?;
                broker::trace(0x217);
                self.send(0x8015, b.to_vec(), Some(h.request))?;
            }
            (21, true) => {
                if b.len() != 104 {
                    return Err(());
                }
                let key = self.task_key.ok_or(())?;
                self.send(22, key.contract.to_vec(), None)?;
            }
            (22, false) => {
                if b.len() != 16 {
                    return Err(());
                }
                let id = b.try_into().unwrap();
                let token = if self.kernel_contract == Some(id) {
                    self.kernel_token
                } else {
                    None
                };
                if let Some(token) = token {
                    broker::request(OP_TASK, &[], &mut [], 0, [8, token, 0]).map_err(|_| ())?;
                } else if self
                    .engine
                    .contracts
                    .iter()
                    .any(|c| c.terms.id == id && !c.remote && c.owner_boot == self.engine.boot)
                {
                    return Err(());
                }
                let e = self.engine.close(id, true).map_err(|_| ())?;
                persist(&mut self.engine, e)?;
                if let Some(token) = token {
                    broker::request(OP_TASK, &[], &mut [], 0, [4, token, 0]).map_err(|_| ())?;
                }
                if token.is_some() {
                    self.kernel_token = None;
                    self.kernel_contract = None;
                }
                broker::trace(0x219);
                self.send(0x8016, b.to_vec(), Some(h.request))?;
            }
            (22, true) => {
                if b.len() != 16 {
                    return Err(());
                }
                let e = self
                    .engine
                    .close(b.try_into().unwrap(), true)
                    .map_err(|_| ())?;
                persist(&mut self.engine, e)?;
                broker::trace(0x219);
                self.recovering = false;
            }
            (32, false) => {
                if b.len() != 48 {
                    return Err(());
                }
                let id = b[..16].try_into().unwrap();
                let peer_digest = b[16..48].try_into().unwrap();
                if self.engine.member == Member::Bound {
                    let e = self.engine.leave_with_id(id).map_err(|_| ())?;
                    persist(&mut self.engine, e)?;
                }
                broker::request(OP_TASK, &[], &mut [], 0, [9, 1, self.kernel_epoch])
                    .map_err(|_| ())?;
                let own = self.engine.obligation_digest();
                let digests = if self.engine.local < self.engine.peer {
                    [own, peer_digest]
                } else {
                    [peer_digest, own]
                };
                let record = self.engine.leave_record(id, digests).map_err(|_| ())?;
                let e = self.engine.confirm_leave(record).map_err(|_| ())?;
                persist(&mut self.engine, e)?;
                let mut out = record.to_vec();
                out.extend_from_slice(&self.engine.leave_signature().ok_or(())?);
                self.send(0x8020, out, Some(h.request))?;
            }
            (32, true) => {
                if b.len() != 248 || Some(b[40..56].try_into().unwrap()) != self.leave_id {
                    return Err(());
                }
                let record: [u8; 184] = b[..184].try_into().unwrap();
                let peer_signature: [u8; 64] = b[184..248].try_into().unwrap();
                let e = self.engine.confirm_leave(record).map_err(|_| ())?;
                persist(&mut self.engine, e)?;
                let own = self.engine.leave_signature().ok_or(())?;
                let mut proof = [0; 312];
                proof[..184].copy_from_slice(&record);
                let sigs = if self.engine.local < self.engine.peer {
                    [own, peer_signature]
                } else {
                    [peer_signature, own]
                };
                proof[184..248].copy_from_slice(&sigs[0]);
                proof[248..312].copy_from_slice(&sigs[1]);
                let e = self.engine.finish_leave(&proof).map_err(|_| ())?;
                persist(&mut self.engine, e)?;
                self.send(33, proof.to_vec(), None)?;
                broker::request(OP_TASK, &[], &mut [], 0, [9, 0, self.kernel_epoch])
                    .map_err(|_| ())?;
                self.finished_leave = true;
                broker::trace(0x221);
            }
            (33, false) => {
                let proof: [u8; 312] = b.try_into().map_err(|_| ())?;
                let e = self.engine.finish_leave(&proof).map_err(|_| ())?;
                persist(&mut self.engine, e)?;
                broker::request(OP_TASK, &[], &mut [], 0, [9, 0, self.kernel_epoch])
                    .map_err(|_| ())?;
                self.finished_leave = true;
                broker::trace(0x221);
            }
            _ => return Err(()),
        }
        Ok(())
    }
    pub fn tick(&mut self, now: u64) -> Result<(), ()> {
        if self.finished_leave {
            return Ok(());
        }
        if !self.active {
            return Ok(());
        }
        self.status_page()?;
        if now.saturating_sub(self.last_rx) >= 1500 {
            self.disconnect();
            return Err(());
        }
        if self.peer_boot != 0 && now.saturating_sub(self.last_status) >= 500 {
            self.status()?;
            self.last_status = now;
        }
        if self.engine.ready()
            && self.engine.local < self.engine.peer
            && !self.quoted
            && self.engine.contracts.is_empty()
            && !self.done
        {
            self.send(16, Vec::new(), None)?;
            self.quoted = true;
        }
        if option_env!("CYXIA_CLUSTER_LEAVE") == Some("1")
            && self.engine.local < self.engine.peer
            && self.done
            && self.engine.contracts.is_empty()
            && self.engine.member == Member::Bound
            && self.leave_id.is_none()
        {
            let id = self.engine.crypto.sha256(&self.engine.cluster());
            self.begin_leave(id[..16].try_into().unwrap())?;
        }
        self.offline_tick(now)?;
        if self.peer_boot != 0 {
            self.resend_results()?;
        }

        Ok(())
    }
    fn resume_closure(&mut self) -> Result<(), ()> {
        let received: Vec<_> = self
            .engine
            .results
            .iter()
            .filter(|r| r.received && r.state != TaskState::Started)
            .map(|r| (r.key, r.result_hash))
            .collect();
        for (key, hash) in received {
            let mut b = key_bytes(key);
            b.extend_from_slice(&hash);
            self.send(21, b, None)?;
            self.send(22, key.contract.to_vec(), None)?;
        }
        self.resend_results()?;
        Ok(())
    }
    fn send_result(&mut self, key: TaskKey) -> Result<(), ()> {
        let result = self
            .engine
            .results
            .iter()
            .find(|r| r.key == key)
            .ok_or(())?;
        let mut out = key_bytes(key);
        out.push(result.state as u8);
        out.extend_from_slice(&result.input_hash);
        out.extend_from_slice(&result.result_hash);
        out.extend_from_slice(&(result.body.len() as u32).to_le_bytes());
        out.extend_from_slice(&result.body);
        self.send(20, out, None)?;
        if !self.sent_results.contains(&key) {
            self.sent_results.push(key)
        }
        Ok(())
    }
    fn resend_results(&mut self) -> Result<(), ()> {
        // Queue one complete retained result per turn. A full bounded output
        // queue is backpressure; the TLS stream must be allowed to drain it.
        let next = self
            .engine
            .results
            .iter()
            .find(|r| {
                !r.received
                    && !r.acknowledged
                    && r.state != TaskState::Started
                    && !self.sent_results.contains(&r.key)
            })
            .map(|r| (r.key, 96usize + 141 + r.body.len()));
        if let Some((key, frame_bytes)) = next {
            if self
                .output
                .len()
                .checked_add(frame_bytes)
                .is_some_and(|n| n <= 131264)
            {
                self.send_result(key)?;
            }
        }
        Ok(())
    }
    pub fn offline_tick(&mut self, _now: u64) -> Result<(), ()> {
        if self.activated {
            let token = self.kernel_token.ok_or(())?;
            let mut body = [0; 8];
            match broker::request(OP_TASK, &[], &mut body, 0, [3, token, 0]) {
                Ok((8, _)) => {
                    let key = self.task_key.ok_or(())?;
                    let e = self
                        .engine
                        .finish(key, TaskState::Done, &body)
                        .map_err(|_| ())?;
                    persist(&mut self.engine, e)?;
                    if self.active && self.peer_boot != 0 {
                        self.send_result(key)?;
                    }
                    self.activated = false;
                    broker::trace(0x215);
                }
                Err(AGAIN) => {}
                Err(FAILED) => {
                    let key = self.task_key.ok_or(())?;
                    let e = self
                        .engine
                        .finish(key, TaskState::Failed, &[])
                        .map_err(|_| ())?;
                    persist(&mut self.engine, e)?;
                    self.activated = false;
                    if self.active && self.peer_boot != 0 {
                        self.send_result(key)?;
                    }
                    broker::trace(0x215);
                }
                _ => return Err(()),
            }
        }
        Ok(())
    }
}
fn package_hash() -> Result<[u8; 32], ()> {
    let mut hash = [0; 32];
    let (n, _) = broker::request(OP_TASK, &[], &mut hash, 0, [6, 0, 0]).map_err(|_| ())?;
    if n != 32 {
        return Err(());
    }
    Ok(hash)
}
fn persist(engine: &mut Engine<RingCrypto>, effect: Effect) -> Result<(), ()> {
    match write_record(effect.id, &effect.bytes) {
        Ok(()) => engine
            .complete(effect.id, Durability::Committed)
            .map_err(|_| ()),
        Err(REJECTED) => {
            let _ = engine.complete(effect.id, Durability::Rejected);
            Err(())
        }
        Err(_) => {
            let _ = engine.complete(effect.id, Durability::Unknown);
            Err(())
        }
    }
}
fn write_record(key: u64, bytes: &[u8]) -> Result<(), u64> {
    if bytes.len() > cluster::MAX_EFFECT {
        return Err(FAILED);
    }
    for (i, chunk) in bytes.chunks(PAYLOAD).enumerate() {
        let phase = u64::from((i + 1) * PAYLOAD >= bytes.len());
        broker::request(
            OP_STORE_PUT,
            chunk,
            &mut [],
            (i * PAYLOAD) as u64,
            [key, bytes.len() as u64, phase],
        )?;
    }
    Ok(())
}
fn read_record(key: u64) -> Result<Option<Vec<u8>>, ()> {
    let mut chunk = [0; PAYLOAD];
    let (n, total) = match broker::request(OP_STORE_GET, &[], &mut chunk, 0, [key, 0, 0]) {
        Ok(v) => v,
        Err(NOT_FOUND) => return Ok(None),
        Err(_) => return Err(()),
    };
    let total = total as usize;
    if total == 0 || total > cluster::MAX_EFFECT || n > total {
        return Err(());
    }
    let mut out = chunk[..n].to_vec();
    while out.len() < total {
        let offset = out.len();
        let (n, again) = broker::request(OP_STORE_GET, &[], &mut chunk, offset as u64, [key, 0, 0])
            .map_err(|_| ())?;
        if n == 0 || again as usize != total || offset + n > total {
            return Err(());
        }
        out.extend_from_slice(&chunk[..n]);
    }
    Ok(Some(out))
}
fn task_input() -> Vec<u8> {
    let mut v = Vec::new();
    for n in [1i64, 2, 3, 4] {
        v.extend_from_slice(&n.to_le_bytes())
    }
    v
}
fn terms_bytes(t: Terms) -> Vec<u8> {
    let mut v = t.id.to_vec();
    v.extend_from_slice(&t.cpu_milli.to_le_bytes());
    v.extend_from_slice(&t.memory_pages.to_le_bytes());
    v.extend_from_slice(&t.runtime_ms.to_le_bytes());
    v.extend_from_slice(&t.package_hash);
    v.extend_from_slice(&t.input_hash);
    v
}
fn key_bytes(k: TaskKey) -> Vec<u8> {
    let mut v = k.cluster.to_vec();
    v.extend_from_slice(&k.contract);
    v.extend_from_slice(&k.task);
    v.extend_from_slice(&k.attempt.to_le_bytes());
    v
}
struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, at: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], ()> {
        let end = self.at.checked_add(n).ok_or(())?;
        let b = self.b.get(self.at..end).ok_or(())?;
        self.at = end;
        Ok(b)
    }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N], ()> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    fn byte(&mut self) -> Result<u8, ()> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, ()> {
        Ok(u32::from_le_bytes(self.arr()?))
    }
    fn u64(&mut self) -> Result<u64, ()> {
        Ok(u64::from_le_bytes(self.arr()?))
    }
    fn end(&self) -> Result<(), ()> {
        if self.at == self.b.len() {
            Ok(())
        } else {
            Err(())
        }
    }
}
fn read_terms(r: &mut Reader<'_>) -> Result<Terms, ()> {
    Ok(Terms {
        id: r.arr()?,
        cpu_milli: u16::from_le_bytes(r.arr()?),
        memory_pages: r.u32()?,
        runtime_ms: r.u32()?,
        package_hash: r.arr()?,
        input_hash: r.arr()?,
    })
}
fn read_key(r: &mut Reader<'_>) -> Result<TaskKey, ()> {
    Ok(TaskKey {
        cluster: r.arr()?,
        contract: r.arr()?,
        task: r.arr()?,
        attempt: r.u64()?,
    })
}

#[cfg(test)]
#[path = "../tests/support/recovery_checks.rs"]
mod recovery_checks;
#[cfg(test)]
#[path = "../tests/support/resend_checks.rs"]
mod resend_checks;
