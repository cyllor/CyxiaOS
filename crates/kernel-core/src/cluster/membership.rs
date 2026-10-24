//! Two-voter native formation, proof and explicit activation handshake.
//! Persist each phase BEFORE exposing bytes that a node is allowed to sign.
//! Even enabled membership is not a resource grant. No timeout creates a new
//! ClusterID, shrinks the voter set, or turns an isolated node into standalone.
use super::{
    Digest, Error, Incarnation, NodeId, ObjectId, Result, Scope, Signature,
    auth::{Crypto, PROTOCOL, Peer},
    codec::{Bytes, Reader},
    storage::{self, Key, Store},
};
const KIND: u16 = 1;
const STORAGE_VERSION: u16 = 2;
/// No tombstone eviction: exhausted history requires an explicit reviewed migration.
pub const MAX_FORMATIONS: usize = 16;
#[derive(Clone, Copy)]
struct Binding {
    formation: Digest,
    digest: Digest,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Member {
    pub identity: Incarnation,
    pub native_digest: Digest,
    pub isa: u16,
    pub abi: u32,
    pub failure_domain: ObjectId,
}
impl Member {
    fn from_peer(peer: Peer) -> Self {
        let c = peer.claims();
        Self {
            identity: c.identity,
            native_digest: peer.digest(),
            isa: c.isa,
            abi: c.abi,
            failure_domain: c.failure_domain,
        }
    }
    fn write(self, b: &mut Bytes) -> Result<()> {
        b.incarnation(self.identity)?;
        b.put(&self.native_digest)?;
        b.u16(self.isa)?;
        b.u32(self.abi)?;
        b.put(&self.failure_domain.0)
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let m = Self {
            identity: r.incarnation()?,
            native_digest: r.get()?,
            isa: r.u16()?,
            abi: r.u32()?,
            failure_domain: ObjectId(r.get()?),
        };
        if !m.identity.valid()
            || m.native_digest == [0; 32]
            || m.isa == 0
            || m.abi == 0
            || !m.failure_domain.valid()
        {
            return Err(Error::Corrupt);
        }
        Ok(m)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    cluster: ObjectId,
    epoch: u64,
    formation: Digest,
    digest: Digest,
    capabilities: Digest,
    members: [Member; 2],
    nonces: [Digest; 2],
}
impl Config {
    pub fn new(
        crypto: &impl Crypto,
        cluster: ObjectId,
        epoch: u64,
        peers: [Peer; 2],
        nonces: [Digest; 2],
        capabilities: Digest,
    ) -> Result<Self> {
        if !cluster.valid()
            || epoch == 0
            || capabilities == [0; 32]
            || nonces.contains(&[0; 32])
            || nonces[0] == nonces[1]
        {
            return Err(Error::Invalid);
        }
        let mut members = peers.map(Member::from_peer);
        let mut nonces = nonces;
        if members[0].identity.node == members[1].identity.node {
            return Err(Error::Conflict);
        }
        if members[0].identity.node > members[1].identity.node {
            members.swap(0, 1);
            nonces.swap(0, 1);
        }
        let mut c = Self {
            cluster,
            epoch,
            formation: [0; 32],
            digest: [0; 32],
            capabilities,
            members,
            nonces,
        };
        c.formation = c.formation_hash(crypto)?;
        c.digest = crypto.sha256(c.canonical_without_digest()?.as_slice());
        Ok(c)
    }
    pub fn cluster(self) -> ObjectId {
        self.cluster
    }
    pub fn epoch(self) -> u64 {
        self.epoch
    }
    pub fn digest(self) -> Digest {
        self.digest
    }
    pub fn formation(self) -> Digest {
        self.formation
    }
    pub fn members(self) -> [Member; 2] {
        self.members
    }
    pub fn member(self, node: NodeId) -> Result<Member> {
        self.members
            .into_iter()
            .find(|m| m.identity.node == node)
            .ok_or(Error::WrongOwner)
    }
    fn formation_hash(self, crypto: &impl Crypto) -> Result<Digest> {
        let mut b = Bytes::new();
        b.put(b"CYXIA/FORMATION/v1\0")?;
        b.u16(PROTOCOL)?;
        for (m, n) in self.members.iter().zip(self.nonces) {
            b.put(&m.identity.node.0)?;
            b.put(&n)?;
        }
        Ok(crypto.sha256(b.as_slice()))
    }
    fn canonical_without_digest(self) -> Result<Bytes> {
        let mut b = Bytes::new();
        b.put(b"CYXIA/CONFIG/v1\0")?;
        b.u16(PROTOCOL)?;
        b.put(&self.cluster.0)?;
        b.u64(self.epoch)?;
        b.put(&self.formation)?;
        b.put(&self.capabilities)?;
        for (m, n) in self.members.iter().zip(self.nonces) {
            m.write(&mut b)?;
            b.put(&n)?;
        }
        Ok(b)
    }
    fn write(self, b: &mut Bytes) -> Result<()> {
        b.put(&self.cluster.0)?;
        b.u64(self.epoch)?;
        b.put(&self.formation)?;
        b.put(&self.digest)?;
        b.put(&self.capabilities)?;
        for (m, n) in self.members.iter().zip(self.nonces) {
            m.write(b)?;
            b.put(&n)?;
        }
        Ok(())
    }
    fn read(r: &mut Reader<'_>, crypto: &impl Crypto) -> Result<Self> {
        let cluster = ObjectId(r.get()?);
        let epoch = r.u64()?;
        let formation = r.get()?;
        let digest = r.get()?;
        let capabilities = r.get()?;
        let a = Member::read(r)?;
        let na = r.get()?;
        let b = Member::read(r)?;
        let nb = r.get()?;
        let c = Self {
            cluster,
            epoch,
            formation,
            digest,
            capabilities,
            members: [a, b],
            nonces: [na, nb],
        };
        if !cluster.valid()
            || epoch == 0
            || capabilities == [0; 32]
            || na == [0; 32]
            || nb == [0; 32]
            || na == nb
            || a.identity.node >= b.identity.node
            || c.formation_hash(crypto)? != formation
            || crypto.sha256(c.canonical_without_digest()?.as_slice()) != digest
        {
            return Err(Error::Corrupt);
        }
        Ok(c)
    }
    pub fn scope(self, activation_epoch: u64) -> Scope {
        Scope {
            cluster: self.cluster,
            config_epoch: self.epoch,
            config_digest: self.digest,
            activation_epoch,
        }
    }
    fn peers_match(self, peers: [Peer; 2]) -> bool {
        let mut ms = peers.map(Member::from_peer);
        if ms[0].identity.node > ms[1].identity.node {
            ms.swap(0, 1);
        }
        ms == self.members
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Phase {
    Prepared = 1,
    Proved = 2,
    ActivationReady = 3,
    ActiveMember = 4,
    Active = 5,
    Isolated = 6,
}
impl Phase {
    fn read(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::Prepared),
            2 => Ok(Self::Proved),
            3 => Ok(Self::ActivationReady),
            4 => Ok(Self::ActiveMember),
            5 => Ok(Self::Active),
            6 => Ok(Self::Isolated),
            _ => Err(Error::Corrupt),
        }
    }
}
#[derive(Clone, Copy)]
struct State {
    config: Config,
    phase: Phase,
    activation: u64,
    confirms: Option<[Signature; 2]>,
    bindings: [Option<Binding>; MAX_FORMATIONS],
}
pub struct Membership {
    local: Incarnation,
    state: Option<State>,
    revision: u64,
    poisoned: bool,
    /// Never recovered as true. A restart requires renewed peer authentication
    /// and a higher activation epoch even if the machine BootEpoch is unchanged.
    authenticated: bool,
    enabled: bool,
    recovered: bool,
}
impl Membership {
    pub fn open(store: &mut impl Store, crypto: &impl Crypto, local: Incarnation) -> Result<Self> {
        if !local.valid() {
            return Err(Error::Invalid);
        }
        let key = Key {
            kind: KIND,
            id: local.node.0,
        };
        let (revision, state) = if let Some((rev, b)) = storage::load(store, key)? {
            let mut r = Reader::new(b.as_slice());
            storage::read_header_version(&mut r, KIND, STORAGE_VERSION)?;
            if NodeId(r.get()?) != local.node {
                return Err(Error::Corrupt);
            }
            let config = Config::read(&mut r, crypto)?;
            config.member(local.node)?;
            let phase = Phase::read(r.u8()?)?;
            let activation = r.u64()?;
            let confirms = match r.u8()? {
                0 => None,
                1 => Some([r.get()?, r.get()?]),
                _ => return Err(Error::Corrupt),
            };
            let count = r.u16()? as usize;
            if count == 0 || count > MAX_FORMATIONS {
                return Err(Error::Corrupt);
            }
            let mut bindings: [Option<Binding>; MAX_FORMATIONS] = [None; MAX_FORMATIONS];
            for i in 0..count {
                let binding = Binding {
                    formation: r.get()?,
                    digest: r.get()?,
                };
                if binding.formation == [0; 32]
                    || binding.digest == [0; 32]
                    || bindings[..i]
                        .iter()
                        .flatten()
                        .any(|b| b.formation == binding.formation)
                {
                    return Err(Error::Corrupt);
                }
                bindings[i] = Some(binding);
            }
            if !bindings
                .iter()
                .flatten()
                .any(|b| b.formation == config.formation && b.digest == config.digest)
            {
                return Err(Error::Corrupt);
            }
            r.end()?;
            if matches!(
                phase,
                Phase::Proved | Phase::ActivationReady | Phase::ActiveMember | Phase::Active
            ) && confirms.is_none()
            {
                return Err(Error::Corrupt);
            }
            if matches!(
                phase,
                Phase::ActivationReady | Phase::ActiveMember | Phase::Active
            ) && activation == 0
            {
                return Err(Error::Corrupt);
            }
            if let Some(s) = confirms {
                verify_pair(crypto, config, confirm_bytes(config)?.as_slice(), &s)?;
            }
            (
                rev,
                Some(State {
                    config,
                    phase,
                    activation,
                    confirms,
                    bindings,
                }),
            )
        } else {
            (0, None)
        };
        Ok(Self {
            local,
            state,
            revision,
            poisoned: false,
            authenticated: false,
            enabled: false,
            recovered: revision != 0,
        })
    }
    pub fn local(&self) -> Incarnation {
        self.local
    }
    pub fn config(&self) -> Option<Config> {
        self.state.map(|s| s.config)
    }
    pub fn phase(&self) -> Option<Phase> {
        self.state.map(|s| s.phase)
    }
    pub fn activation_epoch(&self) -> u64 {
        self.state.map_or(0, |s| s.activation)
    }
    pub fn needs_reconcile(&self) -> bool {
        self.poisoned || (!self.enabled && self.state.is_some())
    }
    fn ready(&self) -> Result<State> {
        if self.poisoned {
            return Err(Error::Reconcile);
        }
        let s = self.state.ok_or(Error::NotReady)?;
        if !self.authenticated || s.config.member(self.local.node)?.identity != self.local {
            return Err(Error::Authentication);
        }
        Ok(s)
    }
    fn persist(&mut self, store: &mut impl Store, next: State) -> Result<()> {
        let mut b = Bytes::new();
        storage::header_version(&mut b, KIND, STORAGE_VERSION)?;
        b.put(&self.local.node.0)?;
        next.config.write(&mut b)?;
        b.u8(next.phase as u8)?;
        b.u64(next.activation)?;
        if let Some(s) = next.confirms {
            b.u8(1)?;
            b.put(&s[0])?;
            b.put(&s[1])?;
        } else {
            b.u8(0)?;
        }
        b.u16(next.bindings.iter().flatten().count() as u16)?;
        for binding in next.bindings.iter().flatten() {
            b.put(&binding.formation)?;
            b.put(&binding.digest)?;
        }
        storage::save(
            store,
            Key {
                kind: KIND,
                id: self.local.node.0,
            },
            &mut self.revision,
            &mut self.poisoned,
            &b,
        )?;
        self.state = Some(next);
        Ok(())
    }
    pub fn prepare(
        &mut self,
        store: &mut impl Store,
        config: Config,
        peers: [Peer; 2],
    ) -> Result<Bytes> {
        if self.poisoned {
            return Err(Error::Reconcile);
        }
        if !config.peers_match(peers) || config.member(self.local.node)?.identity != self.local {
            return Err(Error::Authentication);
        }
        let mut bindings = self.state.map_or([None; MAX_FORMATIONS], |s| s.bindings);
        if let Some(bound) = bindings
            .iter()
            .flatten()
            .find(|b| b.formation == config.formation)
        {
            if bound.digest != config.digest {
                return Err(Error::Conflict);
            }
        } else {
            let free = bindings
                .iter_mut()
                .find(|b| b.is_none())
                .ok_or(Error::Capacity)?;
            *free = Some(Binding {
                formation: config.formation,
                digest: config.digest,
            });
        }
        if let Some(old) = self.state {
            if old.config == config {
                self.authenticated = true;
                return confirm_bytes(config);
            }
            // Never replace a still-pending signed intention implicitly. An
            // explicit durable isolation/reconciliation boundary is mandatory.
            if old.phase != Phase::Isolated {
                return Err(Error::Busy);
            }
            // Reconfiguration here is ONLY same two voters, same cluster, next
            // epoch. Membership replacement/leave requires a separate protocol.
            if self.enabled
                || old.config.cluster != config.cluster
                || old.config.epoch.checked_add(1) != Some(config.epoch)
                || old.config.members.map(|m| m.identity.node)
                    != config.members.map(|m| m.identity.node)
            {
                return Err(Error::Conflict);
            }
            if old
                .config
                .members
                .iter()
                .zip(config.members)
                .any(|(a, b)| b.identity.boot < a.identity.boot)
            {
                return Err(Error::Stale);
            }
        }
        self.enabled = false;
        self.persist(
            store,
            State {
                config,
                phase: Phase::Prepared,
                activation: 0,
                confirms: None,
                bindings,
            },
        )?;
        self.authenticated = true;
        self.recovered = false;
        confirm_bytes(config)
    }
    pub fn prove(
        &mut self,
        store: &mut impl Store,
        crypto: &impl Crypto,
        signatures: [Signature; 2],
    ) -> Result<Digest> {
        let mut s = self.ready()?;
        verify_pair(
            crypto,
            s.config,
            confirm_bytes(s.config)?.as_slice(),
            &signatures,
        )?;
        if let Some(old) = s.confirms {
            if old != signatures {
                return Err(Error::Conflict);
            }
            return proof_digest(crypto, s.config, old);
        }
        if s.phase != Phase::Prepared {
            return Err(Error::NotReady);
        }
        s.confirms = Some(signatures);
        s.phase = Phase::Proved;
        self.persist(store, s)?;
        proof_digest(crypto, s.config, signatures)
    }
    /// Persist readiness before the local signer signs this exact message.
    pub fn begin_activation(
        &mut self,
        store: &mut impl Store,
        crypto: &impl Crypto,
        epoch: u64,
    ) -> Result<Bytes> {
        let mut s = self.ready()?;
        let sigs = s.confirms.ok_or(Error::NotReady)?;
        if self.recovered && epoch <= s.activation {
            return Err(Error::Stale);
        }
        if epoch == s.activation && s.phase == Phase::ActivationReady {
            return activation_bytes(crypto, s.config, sigs, epoch, 0);
        }
        if epoch == 0 || epoch <= s.activation {
            return Err(Error::Stale);
        }
        self.enabled = false;
        s.activation = epoch;
        s.phase = Phase::ActivationReady;
        self.persist(store, s)?;
        self.recovered = false;
        activation_bytes(crypto, s.config, sigs, epoch, 0)
    }
    /// Both READY signatures are needed. Persist ACTIVE_MEMBER before signing
    /// its acknowledgement; this local phase still cannot issue any grants.
    pub fn commit_activation(
        &mut self,
        store: &mut impl Store,
        crypto: &impl Crypto,
        votes: [Signature; 2],
    ) -> Result<Bytes> {
        let mut s = self.ready()?;
        let sigs = s.confirms.ok_or(Error::NotReady)?;
        if !matches!(
            s.phase,
            Phase::ActivationReady | Phase::ActiveMember | Phase::Active
        ) {
            return Err(Error::NotReady);
        }
        verify_pair(
            crypto,
            s.config,
            activation_bytes(crypto, s.config, sigs, s.activation, 0)?.as_slice(),
            &votes,
        )?;
        if s.phase == Phase::ActivationReady {
            s.phase = Phase::ActiveMember;
            self.persist(store, s)?;
        }
        activation_bytes(crypto, s.config, sigs, s.activation, 1)
    }
    pub fn enable(
        &mut self,
        store: &mut impl Store,
        crypto: &impl Crypto,
        acks: [Signature; 2],
    ) -> Result<()> {
        let mut s = self.ready()?;
        let sigs = s.confirms.ok_or(Error::NotReady)?;
        if !matches!(s.phase, Phase::ActiveMember | Phase::Active) {
            return Err(Error::NotReady);
        }
        // A recovered Active snapshot may not replay its old acks to re-enable.
        if self.recovered || (s.phase == Phase::Active && !self.enabled) {
            return Err(Error::Reconcile);
        }
        verify_pair(
            crypto,
            s.config,
            activation_bytes(crypto, s.config, sigs, s.activation, 1)?.as_slice(),
            &acks,
        )?;
        if s.phase != Phase::Active {
            s.phase = Phase::Active;
            self.persist(store, s)?;
        }
        self.enabled = true;
        Ok(())
    }
    pub fn isolate(&mut self, store: &mut impl Store) -> Result<()> {
        self.enabled = false;
        self.authenticated = false;
        if self.poisoned {
            return Err(Error::Reconcile);
        }
        if let Some(mut s) = self.state
            && s.phase != Phase::Isolated
        {
            s.phase = Phase::Isolated;
            self.persist(store, s)?;
        }
        Ok(())
    }
    pub fn active(&self) -> Result<Active<'_>> {
        let s = self.ready()?;
        if !self.enabled || s.phase != Phase::Active {
            return Err(Error::NotReady);
        }
        Ok(Active { membership: self })
    }
}
/// A live borrowed authority view. It cannot be fabricated from a wire Scope or
/// retained while mutably isolating/reconfiguring its Membership in safe Rust.
pub struct Active<'a> {
    membership: &'a Membership,
}
impl Active<'_> {
    pub fn scope(&self) -> Scope {
        let s = self.membership.state.expect("active view");
        s.config.scope(s.activation)
    }
    pub fn local(&self) -> Incarnation {
        self.membership.local
    }
    pub fn config(&self) -> Config {
        self.membership.state.expect("active view").config
    }
    pub fn member(&self, node: NodeId) -> Result<Member> {
        self.config().member(node)
    }
}
pub fn confirm_bytes(config: Config) -> Result<Bytes> {
    let mut b = Bytes::new();
    b.put(b"CYXIA/PREPARED-CONFIRM/v1\0")?;
    config.write(&mut b)?;
    Ok(b)
}
pub fn proof_digest(
    crypto: &impl Crypto,
    config: Config,
    signatures: [Signature; 2],
) -> Result<Digest> {
    let mut b = Bytes::new();
    b.put(b"CYXIA/COMMIT-PROOF/v1\0")?;
    config.write(&mut b)?;
    b.put(&signatures[0])?;
    b.put(&signatures[1])?;
    Ok(crypto.sha256(b.as_slice()))
}
fn activation_bytes(
    crypto: &impl Crypto,
    config: Config,
    signatures: [Signature; 2],
    epoch: u64,
    stage: u8,
) -> Result<Bytes> {
    let mut b = Bytes::new();
    b.put(b"CYXIA/ACTIVATION/v1\0")?;
    b.u8(stage)?;
    b.scope(config.scope(epoch))?;
    b.put(&proof_digest(crypto, config, signatures)?)?;
    for m in config.members {
        b.incarnation(m.identity)?;
    }
    Ok(b)
}
pub(crate) fn verify_pair(
    crypto: &impl Crypto,
    config: Config,
    bytes: &[u8],
    signatures: &[Signature; 2],
) -> Result<()> {
    for (m, s) in config.members.iter().zip(signatures) {
        if !crypto.verify(m.identity.node, bytes, s) {
            return Err(Error::Authentication);
        }
    }
    Ok(())
}
