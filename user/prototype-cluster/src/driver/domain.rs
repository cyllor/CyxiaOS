//! Native domain adapters. Every admission invokes the real durable contract or
//! LOCAL broker; a lost reply remains UNKNOWN and is subsequently only queried.
use super::*;
use cyxia_prototype::domains::{
    ApplyId, Error as DomainError, ObjectKey, platform::*,
};
use cyxia_prototype_cluster::{
    domain_ingress::{accept_placement_policy, policy_stamp, receipt},
    domain_placement::{self as journal, QuoteWire, Record},
};
#[path = "application.rs"]
mod application;

struct Payload {
    request: PlacementRequest,
    bytes: Vec<u8>,
}
#[derive(Clone, Copy)]
pub(super) struct PeerQuote {
    pub(super) wire: QuoteWire,
    pub(super) expires_ms: u64,
    pub(super) received_ms: u64,
    rtt_us: u64,
}
#[derive(Clone, Copy)]
struct IssuedQuote {
    seq: u64,
    quote: CpuQuote,
}
pub(super) struct NativeDomains {
    pub(super) queue: &'static mut PlacementQueue,
    payloads: Vec<Payload>,
    quote: QuotePolicy,
    quote_stop: cyxia_prototype_cluster::quote_stop::Owner,
    offer: PolicyWire,
    placement: PolicyWire,
    offer_receipt: PolicyReceiptWire,
    placement_receipt: PolicyReceiptWire,
    pub(super) peer: Option<PeerQuote>,
    quote_inflight: Option<([u8; 16], u64)>,
    last_quote_ms: u64,
    next_offer: u64,
    issued: [Option<IssuedQuote>; 64],
    applications: Vec<application::Binding>,
    incoming: Option<application::Incoming>,
    application_cursor: usize,
}
impl NativeDomains {
    pub(super) fn new(queue: &'static mut PlacementQueue) -> Self {
        Self {
            queue,
            payloads: Vec::new(),
            quote: QuotePolicy::new(),
            quote_stop: cyxia_prototype_cluster::quote_stop::Owner::new(),
            offer: PolicyWire::default(),
            placement: PolicyWire::default(),
            offer_receipt: PolicyReceiptWire::default(),
            placement_receipt: PolicyReceiptWire::default(),
            peer: None,
            quote_inflight: None,
            last_quote_ms: 0,
            next_offer: 0,
            issued: [None; 64],
            applications: Vec::new(),
            incoming: None,
            application_cursor: 0,
        }
    }
    pub(super) fn recover(&mut self, bytes: &[u8]) -> Result<(), ()> {
        match journal::decode(bytes).map_err(|_| ())? {
            Record::Intent(intent, input) => {
                self.queue.restore_intent(intent, 0).map_err(|_| ())?;
                if let Some(old) = self
                    .payloads
                    .iter()
                    .find(|p| p.request.key == intent.request.key)
                {
                    if old.request != intent.request || old.bytes != input {
                        return Err(());
                    }
                } else {
                    if self.payloads.len() >= 32 {
                        return Err(());
                    }
                    self.payloads.push(Payload {
                        request: intent.request,
                        bytes: input,
                    });
                }
            }
            Record::Receipt(intent, outcome) => {
                self.queue
                    .restore_receipt(intent, outcome, 0)
                    .map_err(|_| ())?;
                self.payloads
                    .retain(|p| p.request.key != intent.request.key);
            }
        }
        Ok(())
    }
    pub(super) fn disconnect(&mut self) {
        self.peer = None;
        self.quote_inflight = None;
        self.issued.fill(None);
    }
    fn install(&mut self, input: DomainInput, boot: u64, now: u64) {
        let p = input.offer;
        if p.version != 0 && (p.version != self.offer.version || p != self.offer) {
            let result = policy_stamp(p).and_then(|s| {
                self.quote.install(
                    s,
                    u16::try_from(p.value).map_err(|_| DomainError::Range)?,
                    now,
                )
            });
            self.offer_receipt = receipt(
                p,
                if result.is_ok() {
                    DOMAIN_PENDING
                } else {
                    DOMAIN_REJECTED
                },
                0,
                Some(ObjectKey {
                    id: OFFER_SERVICE_ID,
                    generation: 1,
                }),
            );
            if result.is_ok() {
                self.offer = p;
                self.quote_stop.installed(p.version);
            }
        }
        // Process after the current offer, so replaying that same wire cannot
        // reopen publication. Outstanding quote promises keep their own TTL.
        self.quote_stop.apply(input.quote_stop, boot, self.offer.version, now);
        if self.quote_stop.stopped() && self.offer_receipt.outcome == DOMAIN_PENDING
            && self.offer_receipt.version != 0
        {
            self.offer_receipt.outcome = DOMAIN_REJECTED;
        }
        if self.offer.version != 0
            && self.offer_receipt.outcome == DOMAIN_PENDING
            && now >= self.offer.installed_until_ns
        {
            self.offer_receipt = receipt(
                self.offer,
                DOMAIN_EXPIRED,
                0,
                Some(ObjectKey {
                    id: OFFER_SERVICE_ID,
                    generation: 1,
                }),
            );
        }
        let p = input.placement;
        if p.version == 0 || p == self.placement {
            return;
        }
        let target = ObjectKey {
            id: input.placement_request_id,
            generation: input.placement_request_generation,
        };
        let result = (|| {
            accept_placement_policy(self.placement, p, now)?;
            if self.placement.version == p.version {
                return Err(DomainError::Conflict);
            }
            let choice = match p.value {
                0 => PlacementChoice::Local,
                1 => PlacementChoice::Peer,
                2 => PlacementChoice::Defer,
                _ => return Err(DomainError::Range),
            };
            self.queue.choose(
                ApplyId {
                    boot_epoch: boot,
                    controller_epoch: p.controller_epoch,
                    plan_seq: p.plan_seq,
                    action_index: p.action_index as u16,
                    target,
                },
                choice,
                now,
            )
        })();
        self.placement_receipt = receipt(
            p,
            match result {
                Ok(PlacementStatus::Deferred) => DOMAIN_APPLIED,
                Ok(_) => DOMAIN_UNKNOWN,
                Err(_) => DOMAIN_REJECTED,
            },
            p.value,
            Some(target),
        );
        if result.is_ok() {
            self.placement = p;
        }
    }
    fn update_receipt(&mut self) {
        if self.placement_receipt.version == self.placement.version
            && matches!(
                self.placement_receipt.outcome,
                DOMAIN_PENDING | DOMAIN_UNKNOWN
            )
        {
            let key = ObjectKey {
                id: self.placement_receipt.request_id,
                generation: self.placement_receipt.request_generation,
            };
            if let Ok(PlacementStatus::Complete(outcome)) = self.queue.status(key) {
                self.placement_receipt.outcome = if matches!(outcome, PlacementOutcome::Rejected(_))
                {
                    DOMAIN_REJECTED
                } else {
                    DOMAIN_APPLIED
                };
            }
        }
        self.payloads.retain(|p| {
            !matches!(
                self.queue.status(p.request.key),
                Ok(PlacementStatus::Complete(_))
            )
        });
    }
}
fn node_key(node: [u8; 32]) -> ObjectKey {
    ObjectKey {
        id: u64::from_le_bytes(node[..8].try_into().unwrap()).max(1),
        generation: 1,
    }
}
fn contract_id(intent: PlacementIntent, cluster: [u8; 32], local: [u8; 32]) -> [u8; 16] {
    let mut bytes = b"CX-PLACEMENT-v2".to_vec();
    bytes.extend_from_slice(&cluster);
    bytes.extend_from_slice(&local);
    bytes.extend_from_slice(&intent.request.key.id.to_le_bytes());
    bytes.extend_from_slice(&intent.request.key.generation.to_le_bytes());
    bytes.extend_from_slice(&intent.request.payload_hash);
    bytes.extend_from_slice(&intent.request.package_hash);
    ring::digest::digest(&ring::digest::SHA256, &bytes).as_ref()[..16]
        .try_into()
        .unwrap()
}
fn contract_key(id: [u8; 16]) -> ObjectKey {
    ObjectKey {
        id: u64::from_le_bytes(id[..8].try_into().unwrap()).max(1),
        generation: u64::from_le_bytes(id[8..].try_into().unwrap()).max(1),
    }
}
fn local_result(bytes: &[u8]) -> PlacementAdmission {
    if bytes.len() != 24 {
        return PlacementAdmission::Unknown;
    }
    let n = |at| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    match n(0) {
        1 if n(8) != 0 && n(16) != 0 => PlacementAdmission::Admitted(ObjectKey {
            id: n(8),
            generation: n(16),
        }),
        2 => PlacementAdmission::Rejected(DomainError::Again),
        _ => PlacementAdmission::Unknown,
    }
}
struct Backend<'a> {
    driver: &'a mut Driver,
    payloads: &'a [Payload],
    peer: Option<PeerQuote>,
    now_ns: u64,
}
impl Backend<'_> {
    fn input(&self, intent: PlacementIntent) -> Option<&[u8]> {
        self.payloads
            .iter()
            .find(|p| p.request == intent.request)
            .map(|p| p.bytes.as_slice())
    }
    fn record(&self, intent: PlacementIntent) -> Result<Vec<u8>, DomainError> {
        journal::encode(&Record::Intent(
            intent,
            self.input(intent).ok_or(DomainError::NotFound)?.to_vec(),
        ))
    }
    fn query_local(&mut self, intent: PlacementIntent) -> PlacementAdmission {
        let mut query = intent.request.key.id.to_le_bytes().to_vec();
        query.extend_from_slice(&intent.request.key.generation.to_le_bytes());
        query.extend_from_slice(&intent.request.payload_hash);
        let mut response = [0; 24];
        match broker::request(OP_TASK, &query, &mut response, 0, [12, 0, 0]) {
            Ok((n, _)) => local_result(&response[..n.min(24)]),
            _ => PlacementAdmission::Unknown,
        }
    }
}
impl PlacementBackend for Backend<'_> {
    fn persist_intent(&mut self, intent: PlacementIntent) -> PlacementDurability {
        if intent.choice == PlacementChoice::Peer {
            let mut binding = intent.request.key.id.to_le_bytes().to_vec();
            binding.extend_from_slice(&intent.request.key.generation.to_le_bytes());
            binding.extend_from_slice(&contract_id(intent, self.driver.engine.cluster(), self.driver.engine.local));
            binding.extend_from_slice(&intent.request.payload_hash); binding.extend_from_slice(&intent.request.package_hash);
            match broker::request(OP_TASK, &binding, &mut [], 0, [30, 0, 0]) {
                Ok((0, _)) | Err(NOT_FOUND) => {},
                // No journal append or external task admission has happened.
                // Retry this same immutable intent after the signed bind ack.
                _ => return PlacementDurability::NotCommitted,
            }
        }
        let Ok(bytes) = self.record(intent) else {
            return PlacementDurability::NotCommitted;
        };
        match write_record(0, &bytes) {
            Ok(()) => PlacementDurability::Committed,
            Err(REJECTED) => PlacementDurability::NotCommitted,
            _ => PlacementDurability::Unknown,
        }
    }
    fn intent_status(&mut self, intent: PlacementIntent) -> PlacementDurability {
        let Ok(expected) = self.record(intent) else {
            return PlacementDurability::Unknown;
        };
        // This exceptional path only reconciles a lost durable-write reply; it
        // never re-appends an intent or guesses that a missing record is safe.
        for ordinal in 2..=32768 {
            match read_record(ordinal) {
                Ok(Some(bytes)) if bytes == expected => return PlacementDurability::Committed,
                Ok(Some(_)) => {}
                _ => break,
            }
        }
        PlacementDurability::Unknown
    }
    fn local_admit(&mut self, intent: PlacementIntent) -> PlacementAdmission {
        let Some(input) = self.input(intent) else {
            return PlacementAdmission::Rejected(DomainError::NotFound);
        };
        let Some(deadline) = intent
            .decided_ns
            .checked_div(1_000_000)
            .and_then(|n| n.checked_add(60000))
        else {
            return PlacementAdmission::Rejected(DomainError::Overflow);
        };
        let mut request = intent.request.key.id.to_le_bytes().to_vec();
        request.extend_from_slice(&intent.request.key.generation.to_le_bytes());
        for n in [
            deadline,
            u64::from(intent.request.cpu_milli),
            u64::from(intent.request.memory_pages),
        ] {
            request.extend_from_slice(&n.to_le_bytes());
        }
        request.extend_from_slice(&intent.request.payload_hash);
        request.extend_from_slice(&intent.request.package_hash);
        request.extend_from_slice(&(input.len() as u64).to_le_bytes());
        request.extend_from_slice(input);
        let mut response = [0; 24];
        match broker::request(OP_TASK, &request, &mut response, 0, [11, 0, 0]) {
            Ok((n, _)) => local_result(&response[..n.min(24)]),
            Err(AGAIN) => PlacementAdmission::Retry,
            Err(REJECTED) => PlacementAdmission::Rejected(DomainError::Again),
            _ => PlacementAdmission::Unknown,
        }
    }
    fn peer_ready(&self, request: PlacementRequest) -> bool {
        self.driver.active
            && self.driver.engine.ready()
            && request.peer == Some(node_key(self.driver.engine.peer))
            && self.peer.is_some_and(|p| {
                p.wire.status == 0
                    && p.wire.owner_boot == self.driver.peer_boot
                    && p.expires_ms > self.now_ns / 1_000_000
                    && p.wire.cpu_milli >= request.cpu_milli
                    && p.wire.memory_pages >= request.memory_pages
                    && p.wire.package_hash == request.package_hash
                    && p.wire.isa == request.isa
                    && p.wire.abi == request.abi
            })
    }
    fn peer_prepare(&mut self, intent: PlacementIntent) -> PlacementAdmission {
        if !self.peer_ready(intent.request) || self.driver.engine.contracts.iter().any(|c| c.remote)
        {
            return PlacementAdmission::Rejected(DomainError::NotReady);
        }
        let Some(input) = self.input(intent).map(<[u8]>::to_vec) else {
            return PlacementAdmission::Rejected(DomainError::NotFound);
        };
        let quote = self.peer.unwrap().wire;
        let terms = Terms {
            id: contract_id(
                intent,
                self.driver.engine.cluster(),
                self.driver.engine.local,
            ),
            cpu_milli: intent.request.cpu_milli,
            memory_pages: intent.request.memory_pages,
            runtime_ms: 60000,
            package_hash: intent.request.package_hash,
            input_hash: intent.request.payload_hash,
        };
        let hash = self.driver.engine.request_hash_for(
            &terms,
            self.driver.engine.local,
            self.driver.engine.peer,
        );
        let effect = match self.driver.engine.record_request(terms, hash) {
            Ok(e) => e,
            Err(_) => return PlacementAdmission::Rejected(DomainError::Conflict),
        };
        if persist(&mut self.driver.engine, effect).is_err() {
            return PlacementAdmission::Unknown;
        }
        self.driver.terms = Some(terms);
        self.driver.contract_hash = hash;
        self.driver.outgoing_input = input;
        let mut body = terms_bytes(terms);
        body.extend_from_slice(&hash);
        body.extend_from_slice(&quote.owner_boot.to_le_bytes());
        body.extend_from_slice(&quote.offer_seq.to_le_bytes());
        let _ = self.driver.send(17, body, None);
        PlacementAdmission::Unknown
    }
    fn reconcile(&mut self, intent: PlacementIntent) -> Option<PlacementOutcome> {
        match intent.choice {
            PlacementChoice::Local => match self.query_local(intent) {
                PlacementAdmission::Admitted(k) => Some(PlacementOutcome::Local(k)),
                PlacementAdmission::Rejected(e) => Some(PlacementOutcome::Rejected(e)),
                PlacementAdmission::Retry | PlacementAdmission::Unknown => None,
            },
            PlacementChoice::Peer => {
                let id = contract_id(
                    intent,
                    self.driver.engine.cluster(),
                    self.driver.engine.local,
                );
                let started = self
                    .driver
                    .native_started
                    .iter()
                    .any(|key| key.contract == id)
                    || self.driver.engine.results.iter().any(|r| {
                        r.received
                            && r.key.contract == id
                            && matches!(r.state, TaskState::Done | TaskState::Failed)
                    });
                started.then_some(PlacementOutcome::Peer {
                    node: intent.request.peer?,
                    contract: contract_key(id),
                })
            }
            PlacementChoice::Defer => None,
        }
    }
    fn persist_receipt(
        &mut self,
        intent: PlacementIntent,
        outcome: PlacementOutcome,
    ) -> PlacementDurability {
        let Ok(bytes) = journal::encode(&Record::Receipt(intent, outcome)) else {
            return PlacementDurability::Unknown;
        };
        match write_record(0, &bytes) {
            Ok(()) => PlacementDurability::Committed,
            Err(REJECTED) => PlacementDurability::NotCommitted,
            _ => PlacementDurability::Unknown,
        }
    }
}
impl Driver {
    pub(super) fn queued_class(&self, reserved: bool) -> Result<(usize, usize), ()> {
        let mut at = 0;
        let mut bytes = 0;
        let mut count = 0;
        while at < self.output.len() {
            let header = Header::decode(self.output.get(at..at + 96).ok_or(())?).map_err(|_| ())?;
            let end = at.checked_add(96 + header.body_len as usize).ok_or(())?;
            if end > self.output.len() {
                return Err(());
            }
            if end > self.sent
                && cyxia_prototype_cluster::domain_ingress::reserved_rpc(header.kind) == reserved
            {
                bytes += end - at;
                count += 1;
            }
            at = end;
        }
        Ok((bytes, count))
    }
    pub(super) fn compact_complete_frames(&mut self) -> Result<(), ()> {
        let mut at = 0;
        while at < self.sent {
            let header = Header::decode(self.output.get(at..at + 96).ok_or(())?).map_err(|_| ())?;
            let end = at.checked_add(96 + header.body_len as usize).ok_or(())?;
            if end > self.sent {
                break;
            }
            at = end;
        }
        if at != 0 {
            self.output.drain(..at);
            self.sent -= at;
        }
        Ok(())
    }
    pub fn new_native(
        boot: u64,
        uuid: [u8; 16],
        local: [u8; 32],
        peer: [u8; 32],
        signer: IdentitySigner,
        peer_public: [u8; 32],
        queue: &'static mut PlacementQueue,
    ) -> Result<Self, ()> {
        Self::construct(
            boot,
            uuid,
            local,
            peer,
            signer,
            peer_public,
            Some(NativeDomains::new(queue)),
        )
    }
    pub(super) fn schema(&self) -> [u8; 32] {
        self.engine.crypto.sha256(if self.native.is_some() {
            b"CX-RPC-native-schema-2"
        } else {
            b"CX-RPC-native-schema-1"
        })
    }
    /// Asynchronous admission of one registered pure-vector request. No model
    /// inference or resource grant occurs in this hot path.
    pub fn submit_placement(
        &mut self,
        key: ObjectKey,
        input: &[u8],
        now_ns: u64,
    ) -> Result<PlacementStatus, DomainError> {
        if input.is_empty() || input.len() > journal::MAX_INPUT || !input.len().is_multiple_of(8) {
            return Err(DomainError::Range);
        }
        let hash = self.engine.crypto.sha256(input);
        let package = package_hash().map_err(|_| DomainError::Io)?;
        let native = self.native.as_mut().ok_or(DomainError::Unsupported)?;
        let request = PlacementRequest {
            key,
            payload_hash: hash,
            package_hash: package,
            cpu_milli: 100,
            memory_pages: 16,
            isa: 183,
            abi: 1,
            peer: Some(node_key(self.engine.peer)),
        };
        if let Some(old) = native.payloads.iter().find(|p| p.request.key == key) {
            if old.request != request || old.bytes != input {
                return Err(DomainError::Conflict);
            }
        } else if native.payloads.len() >= 32 {
            return Err(DomainError::Capacity);
        }
        let result = native.queue.submit(request, now_ns)?;
        if !matches!(result, PlacementStatus::Complete(_))
            && !native.payloads.iter().any(|p| p.request.key == key)
        {
            native.payloads.push(Payload {
                request,
                bytes: input.to_vec(),
            });
        }
        Ok(result)
    }
    pub fn domain_tick(&mut self, now_ns: u64) -> Result<(), ()> {
        if self.native.is_none() {
            return Ok(());
        }
        self.application_tick(now_ns)?;
        let now_ns = broker::clock_ns().max(now_ns);
        if self.engine.local < self.engine.peer
            && !self.done
            && self.native.as_ref().unwrap().queue.retained_count() == 0
        {
            let key = ObjectKey {
                id: 1,
                generation: self.engine.boot,
            };
            self.submit_placement(key, &task_input(), now_ns)
                .map_err(|_| ())?;
            self.done = true;
        }
        let mut native = self.native.take().unwrap();
        native.install(broker::domains(), self.engine.boot, now_ns);
        let result = {
            let mut backend = Backend {
                driver: self,
                payloads: &native.payloads,
                peer: native.peer,
                now_ns,
            };
            native.queue.poll(now_ns, 4, &mut backend)
        };
        native.update_receipt();
        let status = native.publish_application_status();
        self.native = Some(native);
        status?;
        result.map(|_| ()).map_err(|_| ())
    }
    pub fn domain_feedback(&self, now_ns: u64) -> DomainFeedback {
        let mut f = DomainFeedback::default();
        let Some(n) = self.native.as_ref() else {
            return f;
        };
        f.offer = n.offer_receipt;
        f.quote_stop = n.quote_stop.receipt();
        f.quotes_stopped = u64::from(n.quote_stop.stopped());
        f.placement = n.placement_receipt;
        f.pending_placements = n.queue.pending_count() as u64;
        f.placement_fallbacks = n.queue.fallbacks;
        let peer = n.peer.filter(|p| {
            p.expires_ms > now_ns / 1_000_000 && p.wire.status == 0 && self.engine.ready()
        });
        if let Some(p) = peer {
            f.peer_cpu_milli = p.wire.cpu_milli as u64;
            f.peer_memory_pages = p.wire.memory_pages as u64;
        }
        for index in 0..32 {
            if let Some(request) = n.queue.waiting(index) {
                let waiting = PendingPlacementWire {
                    request_id: request.key.id,
                    request_generation: request.key.generation,
                    queued_us: n.queue.waiting_age_ns(index, now_ns).unwrap_or(0) / 1000,
                    cpu_milli: request.cpu_milli as u64,
                    memory_pages: request.memory_pages as u64,
                    peer_ready: u64::from(peer.is_some_and(|p| {
                        p.wire.cpu_milli >= request.cpu_milli
                            && p.wire.memory_pages >= request.memory_pages
                            && p.wire.package_hash == request.package_hash
                            && p.wire.isa == request.isa
                            && p.wire.abi == request.abi
                    })),
                };
                f.waiting[index] = waiting;
            }
        }
        f.waiting_request_id = f.waiting[0].request_id;
        f.waiting_request_generation = f.waiting[0].request_generation;
        if let Some(p) = n.peer.filter(|p| {
            now_ns / 1_000_000 >= p.received_ms && now_ns / 1_000_000 - p.received_ms <= 100
        }) {
            f.measurement_valid |= 4;
            f.cluster = [
                p.rtt_us,
                f.peer_cpu_milli,
                peer.map_or(0, |p| p.wire.memory_ratio as u64),
                f.waiting[0].queued_us,
            ];
        }
        f.measurement_ms = now_ns / 1_000_000;
        f
    }
    pub fn queued_frames(&self) -> usize {
        // The first frame may have a prefix already encrypted. Count its
        // retained frame plus every complete subsequent header, not bytes/MTU.
        let mut at = 0;
        let mut count = 0;
        while at < self.output.len() {
            if self.output.len() - at < 96 {
                return 0;
            }
            let Ok(h) = Header::decode(&self.output[at..at + 96]) else {
                return 0;
            };
            let end = at + 96 + h.body_len as usize;
            if end > self.output.len() {
                return 0;
            }
            if end > self.sent {
                count += 1;
            }
            at = end;
        }
        count
    }
    pub(super) fn native_quote_request(&mut self, now: u64) -> Result<(), ()> {
        let n = self.native.as_ref().ok_or(())?;
        if !self.engine.ready()
            || now.saturating_sub(n.last_quote_ms) < 50
            || n.quote_inflight
                .is_some_and(|(_, started)| now.saturating_sub(started) < 1000)
        {
            return Ok(());
        }
        self.send(16, Vec::new(), None)?;
        let mut id = [0; 16];
        id[..8].copy_from_slice(&self.engine.boot.to_le_bytes());
        id[8..].copy_from_slice(&self.request.to_le_bytes());
        let n = self.native.as_mut().unwrap();
        n.quote_inflight = Some((id, now));
        n.last_quote_ms = now;
        Ok(())
    }
    pub(super) fn native_quote_reply(&mut self, h: Header, b: &[u8], now: u64) -> Result<(), ()> {
        let q = QuoteWire::decode(b).map_err(|_| ())?;
        if q.node != self.engine.peer || q.owner_boot != self.peer_boot {
            return Err(());
        }
        let n = self.native.as_mut().ok_or(())?;
        let Some((id, start)) = n.quote_inflight else {
            return Err(());
        };
        if id != h.request || now < start {
            return Err(());
        }
        n.quote_inflight = None;
        n.peer = Some(PeerQuote {
            wire: q,
            expires_ms: now
                .checked_add((q.remaining_ms as u64).saturating_sub(now - start))
                .ok_or(())?,
            received_ms: now,
            rtt_us: (now - start).checked_mul(1000).ok_or(())?,
        });
        Ok(())
    }
    pub(super) fn native_quote_response(&mut self, h: Header, _now: u64) -> Result<(), ()> {
        let package_hash = package_hash()?;
        let mut native = self.native.take().ok_or(())?;
        let mut bytes = [0; 32];
        let capacity = match broker::request(OP_TASK, &[], &mut bytes, 0, [10, 0, 0]) {
            Ok((32, _)) => {
                let n = |at| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
                QuoteCapacity {
                    cpu_milli: u16::try_from(n(0)).unwrap_or(0),
                    memory_pages: u32::try_from(n(8)).unwrap_or(0),
                    core_generation: n(16),
                    ledger_generation: n(24),
                    ready: self.engine.ready(),
                }
            }
            _ => QuoteCapacity {
                cpu_milli: 0,
                memory_pages: 0,
                core_generation: 0,
                ledger_generation: 0,
                ready: false,
            },
        };
        let now_ns = broker::clock_ns();
        let slot = native
            .issued
            .iter()
            .position(|q| q.is_none_or(|q| q.quote.expires_ns <= now_ns));
        let Some(next) = native.next_offer.checked_add(1) else {
            self.native = Some(native);
            return Err(());
        };
        struct Publisher<'a> {
            driver: &'a mut Driver,
            capacity: QuoteCapacity,
            reply: [u8; 16],
            seq: u64,
            now_ns: u64,
            package: [u8; 32],
        }
        impl QuoteBackend for Publisher<'_> {
            fn capacity(&self) -> QuoteCapacity {
                self.capacity
            }
            fn publish(&mut self, q: CpuQuote) -> Result<(), DomainError> {
                let remaining =
                    (q.expires_ns.saturating_sub(self.now_ns) / 1_000_000).min(2000) as u32;
                if remaining == 0 {
                    return Err(DomainError::Expired);
                }
                let wire = QuoteWire {
                    status: 0,
                    isa: 183,
                    abi: 1,
                    node: self.driver.engine.local,
                    owner_boot: self.driver.engine.boot,
                    offer_seq: self.seq,
                    remaining_ms: remaining,
                    cpu_milli: q.cpu_milli,
                    // The native phase10 pool is physically bounded to sixteen pages.
                    memory_ratio: ((u64::from(q.memory_pages) * 1000) / 16).min(1000) as u16,
                    memory_pages: q.memory_pages,
                    package_hash: self.package,
                    core_generation: q.core_generation,
                    ledger_generation: q.ledger_generation,
                };
                self.driver
                    .send(0x8010, wire.encode().to_vec(), Some(self.reply))
                    .map_err(|_| DomainError::Io)
            }
        }
        let candidate = if native.quote_stop.stopped() {
            Err(DomainError::Busy)
        } else if slot.is_some() {
            native.next_offer = next;
            native.quote.publish(
                now_ns,
                &mut Publisher {
                    driver: self,
                    capacity,
                    reply: h.request,
                    seq: next,
                    now_ns,
                    package: package_hash,
                },
            )
        } else {
            Err(DomainError::Capacity)
        };
        let result = match candidate {
            Ok(quote) => {
                native.issued[slot.unwrap()] = Some(IssuedQuote { seq: next, quote });
                if native.offer_receipt.outcome == DOMAIN_PENDING
                    && native.offer_receipt.version == quote.policy_version
                {
                    native.offer_receipt = receipt(
                        native.offer,
                        DOMAIN_APPLIED,
                        quote.cpu_milli as u64,
                        Some(ObjectKey {
                            id: OFFER_SERVICE_ID,
                            generation: 1,
                        }),
                    );
                }
                Ok(())
            }
            Err(DomainError::Io) => Err(()),
            Err(error) => {
                let negative = QuoteWire {
                    status: if error == DomainError::Capacity { 2 } else { 1 },
                    isa: 183,
                    abi: 1,
                    node: self.engine.local,
                    owner_boot: self.engine.boot,
                    offer_seq: 0,
                    remaining_ms: 0,
                    cpu_milli: 0,
                    memory_ratio: 0,
                    memory_pages: 0,
                    package_hash,
                    core_generation: capacity.core_generation,
                    ledger_generation: capacity.ledger_generation,
                };
                self.send(0x8010, negative.encode().to_vec(), Some(h.request))
            }
        };
        self.native = Some(native);
        result
    }
    pub(super) fn native_validate_prepare(
        &self,
        terms: Terms,
        offer_seq: u64,
        now_ns: u64,
    ) -> Result<(), ()> {
        let n = self.native.as_ref().ok_or(())?;
        let offer = n
            .issued
            .iter()
            .flatten()
            .find(|q| q.seq == offer_seq && q.quote.expires_ns > now_ns)
            .ok_or(())?;
        if !self.engine.ready()
            || terms.cpu_milli > offer.quote.cpu_milli
            || terms.memory_pages > offer.quote.memory_pages
        {
            return Err(());
        }
        Ok(())
    }
    pub(super) fn native_started_reply(&mut self, b: &[u8]) -> Result<(), ()> {
        let mut reader = Reader::new(b);
        let key = read_key(&mut reader)?;
        reader.end()?;
        if Some(key) != self.task_key || !self.committed {
            return Err(());
        }
        if !self.native_started.contains(&key) {
            // A persisted terminal result already certifies custody. Retire
            // only those entries, never a STARTED/unknown obligation.
            self.native_started.retain(|old| !self.engine.results.iter().any(|r|
                r.received && r.key == *old && r.state != TaskState::Started));
            if self.native_started.len() >= 32 {
                return Err(());
            }
            self.native_started.push(key);
        }
        Ok(())
    }
}
