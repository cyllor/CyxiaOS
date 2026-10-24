//! Bounded replicated-write acknowledgement gate, NOT a replication transport.
//! A replica signs only after storing the actual payload and metadata durably.
//! Both fixed native voters (2/2) and the required failure domains must attest
//! the SAME bytes/version/scope before the coordinator persists a commit result.
use super::{
    Digest, Error, Incarnation, ObjectId, Result, Scope, Signature,
    auth::Crypto,
    codec::{Bytes, Reader},
    endpoint::{Endpoint, Permit},
    membership::{Active, Config},
    storage::{self, Key, Store},
};
const REPLICA: u16 = 5;
const COMMIT: u16 = 6;
pub const MAX_DATA: usize = 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Write {
    pub scope: Scope,
    pub resource: ObjectId,
    pub operation: ObjectId,
    pub version: u64,
    pub data_digest: Digest,
}
impl Write {
    fn valid(self) -> bool {
        self.scope.valid()
            && self.resource.valid()
            && self.operation.valid()
            && self.version != 0
            && self.data_digest != [0; 32]
    }
    fn write(self, b: &mut Bytes) -> Result<()> {
        b.scope(self.scope)?;
        b.put(&self.resource.0)?;
        b.put(&self.operation.0)?;
        b.u64(self.version)?;
        b.put(&self.data_digest)
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let w = Self {
            scope: r.scope()?,
            resource: ObjectId(r.get()?),
            operation: ObjectId(r.get()?),
            version: r.u64()?,
            data_digest: r.get()?,
        };
        if !w.valid() {
            return Err(Error::Corrupt);
        }
        Ok(w)
    }
}
fn key(kind: u16, resource: ObjectId) -> Key {
    let mut id = [0; 32];
    id[..16].copy_from_slice(&resource.0);
    Key { kind, id }
}
pub fn ack_bytes(write: Write, replica: Incarnation) -> Result<Bytes> {
    if !write.valid() || !replica.valid() {
        return Err(Error::Invalid);
    }
    let mut b = Bytes::new();
    b.put(b"CYXIA/DURABLE-REPLICA/v1\0")?;
    write.write(&mut b)?;
    b.incarnation(replica)?;
    Ok(b)
}
/// Return signable bytes, never a fabricated signature. On ambiguous failure a
/// retry reloads the durable snapshot and verifies it, instead of assuming that
/// the first attempt failed. Immutable per-version payloads are retained; no
/// uncommitted overwrite can erase the bytes covered by an older durable ACK.
#[allow(clippy::too_many_arguments)]
pub fn persist_replica<const O: usize>(
    store: &mut impl Store,
    crypto: &impl Crypto,
    active: &Active<'_>,
    endpoint: &Endpoint<O>,
    permit: &Permit,
    write: Write,
    payload: &[u8],
    now: u64,
) -> Result<Bytes> {
    if !write.valid()
        || write.scope != active.scope()
        || payload.len() > MAX_DATA
        || crypto.sha256(payload) != write.data_digest
    {
        return Err(Error::Invalid);
    }
    if !endpoint.owns(permit) || permit.token().resource != write.resource {
        return Err(Error::WrongOwner);
    }
    endpoint.check(permit.token(), active, permit.token().consumer, now)?;
    let mut identity = Bytes::new();
    identity.put(b"CYXIA/REPLICA-SLOT/v1\0")?;
    identity.put(&write.scope.cluster.0)?;
    identity.put(&write.resource.0)?;
    identity.u64(write.version)?;
    let record_key = Key {
        kind: REPLICA,
        id: crypto.sha256(identity.as_slice()),
    };
    let mut revision = 0;
    if let Some((_rev, b)) = storage::load(store, record_key)? {
        let mut r = Reader::new(b.as_slice());
        storage::read_header(&mut r, REPLICA)?;
        if r.get::<32>()? != active.local().node.0 {
            return Err(Error::Corrupt);
        }
        let old = Write::read(&mut r)?;
        let len = r.u16()? as usize;
        if len > MAX_DATA {
            return Err(Error::Corrupt);
        }
        let old_data = r.slice(len)?;
        r.end()?;
        if crypto.sha256(old_data) != old.data_digest {
            return Err(Error::Corrupt);
        }
        if old == write && old_data == payload {
            return ack_bytes(write, active.local());
        }
        return Err(Error::Conflict);
    }
    let mut b = Bytes::new();
    storage::header(&mut b, REPLICA)?;
    b.put(&active.local().node.0)?;
    write.write(&mut b)?;
    b.u16(payload.len() as u16)?;
    b.put(payload)?;
    let mut poisoned = false;
    storage::save(store, record_key, &mut revision, &mut poisoned, &b)?;
    ack_bytes(write, active.local())
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurableAck {
    pub replica: Incarnation,
    pub signature: Signature,
}
pub struct Tracker {
    write: Write,
    config: Config,
    acks: [Option<Signature>; 2],
    min_domains: u8,
}
pub struct Committed {
    write: Write,
    store_revision: u64,
}
impl Committed {
    pub fn write(&self) -> Write {
        self.write
    }
    pub fn store_revision(&self) -> u64 {
        self.store_revision
    }
}
impl Tracker {
    pub fn new(active: &Active<'_>, write: Write, min_failure_domains: u8) -> Result<Self> {
        if !write.valid()
            || write.scope != active.scope()
            || !(1..=2).contains(&min_failure_domains)
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            write,
            config: active.config(),
            acks: [None; 2],
            min_domains: min_failure_domains,
        })
    }
    pub fn add(
        &mut self,
        crypto: &impl Crypto,
        active: &Active<'_>,
        ack: DurableAck,
    ) -> Result<bool> {
        if active.scope() != self.write.scope || active.config() != self.config {
            return Err(Error::Stale);
        }
        let ms = self.config.members();
        let i = ms
            .iter()
            .position(|m| m.identity == ack.replica)
            .ok_or(Error::WrongOwner)?;
        if !crypto.verify(
            ack.replica.node,
            ack_bytes(self.write, ack.replica)?.as_slice(),
            &ack.signature,
        ) {
            return Err(Error::Authentication);
        }
        if let Some(previous) = self.acks[i] {
            return if previous == ack.signature {
                Ok(false)
            } else {
                Err(Error::Conflict)
            };
        }
        self.acks[i] = Some(ack.signature);
        Ok(true)
    }
    pub fn acknowledgements(&self) -> usize {
        self.acks.iter().flatten().count()
    }
    pub fn finalize(&self, store: &mut impl Store, active: &Active<'_>) -> Result<Committed> {
        if active.scope() != self.write.scope || active.config() != self.config {
            return Err(Error::Stale);
        }
        if self.acknowledgements() != 2 {
            return Err(Error::NotReady);
        }
        let ms = self.config.members();
        if self.min_domains == 2 && ms[0].failure_domain == ms[1].failure_domain {
            return Err(Error::Capacity);
        }
        let k = key(COMMIT, self.write.resource);
        let mut revision = 0;
        if let Some((rev, b)) = storage::load(store, k)? {
            revision = rev;
            let mut r = Reader::new(b.as_slice());
            storage::read_header(&mut r, COMMIT)?;
            let old = Write::read(&mut r)?;
            let _old_sigs: [Signature; 2] = [r.get()?, r.get()?];
            r.end()?;
            if old == self.write {
                return Ok(Committed {
                    write: self.write,
                    store_revision: revision,
                });
            }
            if old.scope.cluster != self.write.scope.cluster
                || old.version.checked_add(1) != Some(self.write.version)
                || old.operation == self.write.operation
            {
                return Err(Error::Stale);
            }
        } else if self.write.version != 1 {
            return Err(Error::Stale);
        }
        let mut b = Bytes::new();
        storage::header(&mut b, COMMIT)?;
        self.write.write(&mut b)?;
        for signature in self.acks {
            b.put(&signature.ok_or(Error::NotReady)?)?;
        }
        let mut poisoned = false;
        storage::save(store, k, &mut revision, &mut poisoned, &b)?;
        Ok(Committed {
            write: self.write,
            store_revision: revision,
        })
    }
}
