//! Native identity verification. Discovery is untrusted and never admission.
//! The trusted adapter must verify pairing/trust and native measured-boot
//! evidence, not merely accept an OS name or signed self-asserted capability bit.
use super::{Digest, Error, Incarnation, NodeId, ObjectId, Result, Signature, codec::Bytes};
pub const PROTOCOL: u16 = 1;
pub const CYXIA_OS: u64 = 0x4359_5849_414f_5331;
pub const REQUIRED_FEATURES: u64 = 0b1111; // isolated cores, local AI, telemetry, resource contract
pub const KNOWN_FEATURES: u64 = REQUIRED_FEATURES;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeClaims {
    pub identity: Incarnation,
    pub os: u64,
    pub protocol: u16,
    pub abi: u32,
    pub isa: u16,
    pub measurement: Digest,
    pub failure_domain: ObjectId,
    /// Physical core masks, not sibling logical threads from the same core.
    pub control_physical: u64,
    pub business_physical: u64,
    pub features: u64,
}
impl NativeClaims {
    pub fn validate(self) -> Result<()> {
        if !self.identity.valid()
            || self.measurement == [0; 32]
            || !self.failure_domain.valid()
            || self.abi == 0
            || self.isa == 0
        {
            return Err(Error::Invalid);
        }
        if self.protocol != PROTOCOL {
            return Err(Error::Version);
        }
        if self.os != CYXIA_OS
            || self.control_physical == 0
            || self.business_physical == 0
            || self.control_physical & self.business_physical != 0
            || self.features & REQUIRED_FEATURES != REQUIRED_FEATURES
            || self.features & !KNOWN_FEATURES != 0
        {
            return Err(Error::NativeRequired);
        }
        Ok(())
    }
    pub fn canonical(self) -> Result<Bytes> {
        self.validate()?;
        let mut b = Bytes::new();
        b.put(b"CYXIA/NATIVE/v1\0")?;
        b.incarnation(self.identity)?;
        b.u64(self.os)?;
        b.u16(self.protocol)?;
        b.u32(self.abi)?;
        b.u16(self.isa)?;
        b.put(&self.measurement)?;
        b.put(&self.failure_domain.0)?;
        b.u64(self.control_physical)?;
        b.u64(self.business_physical)?;
        b.u64(self.features)?;
        Ok(b)
    }
}
/// SHA-256 and strict signature verification are supplied by the reviewed
/// crypto provider. This crate deliberately ships no weak hash/crypto fallback.
pub trait Crypto {
    fn sha256(&self, bytes: &[u8]) -> Digest;
    fn verify(&self, key: NodeId, bytes: &[u8], signature: &Signature) -> bool;
    /// Must authenticate the boot evidence and authorized pairing policy.
    fn authorize_native(&self, claims: &NativeClaims) -> bool;
}
pub struct Challenge {
    audience: NodeId,
    nonce: Digest,
    created: u64,
    deadline: u64,
    used: bool,
}
impl Challenge {
    /// nonce must come from the trusted CSPRNG. Time is local to the verifier.
    pub fn new(audience: NodeId, nonce: Digest, now: u64, deadline: u64) -> Result<Self> {
        if !audience.valid() || nonce == [0; 32] || deadline <= now {
            return Err(Error::Invalid);
        }
        Ok(Self {
            audience,
            nonce,
            created: now,
            deadline,
            used: false,
        })
    }
    pub fn signing_bytes(&self, claims: NativeClaims) -> Result<Bytes> {
        let mut b = Bytes::new();
        b.put(b"CYXIA/NATIVE-CHALLENGE/v1\0")?;
        b.put(&self.audience.0)?;
        b.put(&self.nonce)?;
        b.put(claims.canonical()?.as_slice())?;
        Ok(b)
    }
    pub fn authenticate(
        &mut self,
        crypto: &impl Crypto,
        claims: NativeClaims,
        signature: &Signature,
        now: u64,
    ) -> Result<Peer> {
        if self.used {
            return Err(Error::Replay);
        }
        if now < self.created {
            return Err(Error::Clock);
        }
        if now >= self.deadline {
            return Err(Error::Expired);
        }
        claims.validate()?;
        if !crypto.authorize_native(&claims)
            || !crypto.verify(
                claims.identity.node,
                self.signing_bytes(claims)?.as_slice(),
                signature,
            )
        {
            return Err(Error::Authentication);
        }
        self.used = true;
        Ok(Peer {
            claims,
            digest: crypto.sha256(claims.canonical()?.as_slice()),
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peer {
    claims: NativeClaims,
    digest: Digest,
}
impl Peer {
    pub fn claims(self) -> NativeClaims {
        self.claims
    }
    pub fn digest(self) -> Digest {
        self.digest
    }
}
