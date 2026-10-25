//! Versioned durable placement records. Restoring an intent only permits a
//! query of its old execution key; it never authorizes another admission.
use alloc::vec::Vec;
use cyxia_prototype::domains::{ApplyId, Error, ObjectKey, platform::*};
pub const MAGIC: &[u8; 5] = b"CXDP2";
pub const MAX_INPUT: usize = 3984;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    Intent(PlacementIntent, Vec<u8>),
    Receipt(PlacementIntent, PlacementOutcome),
}
fn key(out: &mut Vec<u8>, key: ObjectKey) {
    out.extend_from_slice(&key.id.to_le_bytes());
    out.extend_from_slice(&key.generation.to_le_bytes());
}
fn intent(out: &mut Vec<u8>, i: PlacementIntent) {
    key(out, i.request.key);
    out.extend_from_slice(&i.request.payload_hash);
    out.extend_from_slice(&i.request.package_hash);
    out.extend_from_slice(&i.request.cpu_milli.to_le_bytes());
    out.extend_from_slice(&i.request.memory_pages.to_le_bytes());
    out.extend_from_slice(&i.request.isa.to_le_bytes());
    out.extend_from_slice(&i.request.abi.to_le_bytes());
    out.push(u8::from(i.request.peer.is_some()));
    key(out, i.request.peer.unwrap_or_default());
    out.push(match i.choice {
        PlacementChoice::Local => 0,
        PlacementChoice::Peer => 1,
        PlacementChoice::Defer => 2,
    });
    out.push(u8::from(i.apply.is_some()));
    let a = i.apply.unwrap_or_default();
    for v in [a.boot_epoch, a.controller_epoch, a.plan_seq] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&a.action_index.to_le_bytes());
    key(out, a.target);
    out.extend_from_slice(&i.decided_ns.to_le_bytes());
}
fn error_code(e: Error) -> u16 {
    match e {
        Error::Format => 1,
        Error::Auth => 2,
        Error::Schema => 3,
        Error::Stale => 4,
        Error::Capacity => 5,
        Error::Budget => 6,
        Error::Conflict => 7,
        Error::Expired => 8,
        Error::Unsupported => 9,
        Error::Busy => 10,
        Error::Again => 11,
        Error::NotFound => 12,
        Error::Exists => 13,
        Error::NotDirectory => 14,
        Error::IsDirectory => 15,
        Error::NotEmpty => 16,
        Error::Range => 17,
        Error::Io => 18,
        Error::Overflow => 19,
        Error::NotReady => 20,
    }
}
fn error(code: u16) -> Result<Error, Error> {
    Ok(match code {
        1 => Error::Format,
        2 => Error::Auth,
        3 => Error::Schema,
        4 => Error::Stale,
        5 => Error::Capacity,
        6 => Error::Budget,
        7 => Error::Conflict,
        8 => Error::Expired,
        9 => Error::Unsupported,
        10 => Error::Busy,
        11 => Error::Again,
        12 => Error::NotFound,
        13 => Error::Exists,
        14 => Error::NotDirectory,
        15 => Error::IsDirectory,
        16 => Error::NotEmpty,
        17 => Error::Range,
        18 => Error::Io,
        19 => Error::Overflow,
        20 => Error::NotReady,
        _ => return Err(Error::Format),
    })
}
pub fn encode(record: &Record) -> Result<Vec<u8>, Error> {
    let mut out = MAGIC.to_vec();
    match record {
        Record::Intent(i, input) => {
            if input.is_empty() || input.len() > MAX_INPUT || !input.len().is_multiple_of(8) {
                return Err(Error::Range);
            }
            out.push(0);
            intent(&mut out, *i);
            out.extend_from_slice(&(input.len() as u16).to_le_bytes());
            out.extend_from_slice(input);
        }
        Record::Receipt(i, o) => {
            out.push(1);
            intent(&mut out, *i);
            match *o {
                PlacementOutcome::Local(k) => {
                    out.push(0);
                    key(&mut out, k);
                }
                PlacementOutcome::Peer { node, contract } => {
                    out.push(1);
                    key(&mut out, node);
                    key(&mut out, contract);
                }
                PlacementOutcome::Rejected(e) => {
                    out.push(2);
                    out.extend_from_slice(&error_code(e).to_le_bytes());
                }
            }
        }
    }
    Ok(out)
}
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(n).ok_or(Error::Overflow)?;
        let b = self.bytes.get(self.at..end).ok_or(Error::Format)?;
        self.at = end;
        Ok(b)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    fn key(&mut self) -> Result<ObjectKey, Error> {
        Ok(ObjectKey {
            id: self.u64()?,
            generation: self.u64()?,
        })
    }
    fn intent(&mut self) -> Result<PlacementIntent, Error> {
        let key = self.key()?;
        let payload_hash = self.array()?;
        let package_hash = self.array()?;
        let cpu_milli = self.u16()?;
        let memory_pages = self.u32()?;
        let isa = self.u16()?;
        let abi = self.u16()?;
        let peer_flag = self.byte()?;
        let peer = self.key()?;
        let peer = match peer_flag {
            0 if peer == ObjectKey::default() => None,
            1 if peer.id != 0 && peer.generation != 0 => Some(peer),
            _ => return Err(Error::Format),
        };
        let choice = match self.byte()? {
            0 => PlacementChoice::Local,
            1 => PlacementChoice::Peer,
            _ => return Err(Error::Format),
        };
        let apply_flag = self.byte()?;
        let apply = ApplyId {
            boot_epoch: self.u64()?,
            controller_epoch: self.u64()?,
            plan_seq: self.u64()?,
            action_index: self.u16()?,
            target: self.key()?,
        };
        let apply = match apply_flag {
            0 if apply == ApplyId::default() => None,
            1 if apply.boot_epoch != 0
                && apply.controller_epoch != 0
                && apply.plan_seq != 0
                && apply.target == key =>
            {
                Some(apply)
            }
            _ => return Err(Error::Format),
        };
        let decided_ns = self.u64()?;
        if key.id == 0
            || key.generation == 0
            || !(1..=900).contains(&cpu_milli)
            || memory_pages == 0
            || isa == 0
            || abi == 0
            || (choice == PlacementChoice::Peer && peer.is_none())
        {
            return Err(Error::Format);
        }
        Ok(PlacementIntent {
            request: PlacementRequest {
                key,
                payload_hash,
                package_hash,
                cpu_milli,
                memory_pages,
                isa,
                abi,
                peer,
            },
            choice,
            apply,
            decided_ns,
        })
    }
}
pub fn decode(bytes: &[u8]) -> Result<Record, Error> {
    let mut r = Reader { bytes, at: 0 };
    if r.take(5)? != MAGIC {
        return Err(Error::Format);
    }
    let kind = r.byte()?;
    let intent = r.intent()?;
    let record = match kind {
        0 => {
            let n = r.u16()? as usize;
            if n == 0 || n > MAX_INPUT || !n.is_multiple_of(8) {
                return Err(Error::Range);
            }
            let input = r.take(n)?.to_vec();
            if ring::digest::digest(&ring::digest::SHA256, &input).as_ref()
                != intent.request.payload_hash
            {
                return Err(Error::Auth);
            }
            Record::Intent(intent, input)
        }
        1 => {
            let outcome = match r.byte()? {
                0 => PlacementOutcome::Local(r.key()?),
                1 => PlacementOutcome::Peer {
                    node: r.key()?,
                    contract: r.key()?,
                },
                2 => PlacementOutcome::Rejected(error(r.u16()?)?),
                _ => return Err(Error::Format),
            };
            match outcome {
                PlacementOutcome::Local(k)
                    if intent.choice == PlacementChoice::Local
                        && k.id != 0
                        && k.generation != 0 => {}
                PlacementOutcome::Peer { node, contract }
                    if intent.choice == PlacementChoice::Peer
                        && intent.request.peer == Some(node)
                        && contract.id != 0
                        && contract.generation != 0 => {}
                PlacementOutcome::Rejected(_) => {}
                _ => return Err(Error::Format),
            };
            Record::Receipt(intent, outcome)
        }
        _ => return Err(Error::Format),
    };
    if r.at != bytes.len() {
        return Err(Error::Format);
    }
    Ok(record)
}

/// Network quote v2: explicit negative replies carry no positive resource
/// promise. Identity, remaining lifetime, capability and capacity generations
/// are authenticated by the surrounding current TLS/RPC session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuoteWire {
    pub status: u16,
    pub isa: u16,
    pub abi: u16,
    pub node: [u8; 32],
    pub owner_boot: u64,
    pub offer_seq: u64,
    pub remaining_ms: u32,
    pub cpu_milli: u16,
    pub memory_ratio: u16,
    pub memory_pages: u32,
    pub package_hash: [u8; 32],
    pub core_generation: u64,
    pub ledger_generation: u64,
}
impl QuoteWire {
    pub const BYTES: usize = 116;
    pub fn encode(self) -> [u8; Self::BYTES] {
        let mut b = [0; Self::BYTES];
        b[..2].copy_from_slice(&self.status.to_le_bytes());
        b[2..4].copy_from_slice(&self.isa.to_le_bytes());
        b[4..6].copy_from_slice(&self.abi.to_le_bytes());
        b[8..40].copy_from_slice(&self.node);
        b[40..48].copy_from_slice(&self.owner_boot.to_le_bytes());
        b[48..56].copy_from_slice(&self.offer_seq.to_le_bytes());
        b[56..60].copy_from_slice(&self.remaining_ms.to_le_bytes());
        b[60..62].copy_from_slice(&self.cpu_milli.to_le_bytes());
        b[62..64].copy_from_slice(&self.memory_ratio.to_le_bytes());
        b[64..68].copy_from_slice(&self.memory_pages.to_le_bytes());
        b[68..100].copy_from_slice(&self.package_hash);
        b[100..108].copy_from_slice(&self.core_generation.to_le_bytes());
        b[108..116].copy_from_slice(&self.ledger_generation.to_le_bytes());
        b
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != Self::BYTES {
            return Err(Error::Format);
        }
        let mut r = Reader { bytes, at: 0 };
        let status = r.u16()?;
        let isa = r.u16()?;
        let abi = r.u16()?;
        if r.u16()? != 0 {
            return Err(Error::Format);
        }
        let q = Self {
            status,
            isa,
            abi,
            node: r.array()?,
            owner_boot: r.u64()?,
            offer_seq: r.u64()?,
            remaining_ms: r.u32()?,
            cpu_milli: r.u16()?,
            memory_ratio: r.u16()?,
            memory_pages: r.u32()?,
            package_hash: r.array()?,
            core_generation: r.u64()?,
            ledger_generation: r.u64()?,
        };
        if q.status > 2
            || q.owner_boot == 0
            || q.node == [0; 32]
            || q.isa == 0
            || q.abi == 0
            || q.remaining_ms > 2000
            || q.cpu_milli > 4000
            || q.memory_ratio > 1000
            || (q.status == 0
                && (q.remaining_ms == 0
                    || q.offer_seq == 0
                    || q.cpu_milli == 0
                    || q.memory_pages == 0
                    || q.core_generation == 0
                    || q.ledger_generation == 0))
            || (q.status != 0
                && (q.remaining_ms != 0
                    || q.cpu_milli != 0
                    || q.memory_pages != 0
                    || q.offer_seq != 0
                    || q.memory_ratio != 0))
        {
            return Err(Error::Format);
        }
        Ok(q)
    }
}
