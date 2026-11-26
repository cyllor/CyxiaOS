//! Bounded recovery-class SecurityAudit v2 encoding and custody for the three stopped-writer handoffs.
use cyxia_kernel_core::control_plane::control_rpc_v1::{Caller, Error};
use cyxia_kernel_core::security::recovery_proof_v2::{RECOVERY_PROOF_BYTES, RecoveryProofV2};
use sha2::{Digest, Sha256};

pub(super) const WORKERS: usize = 3;
pub(super) const AUDIT_BYTES: usize = 128;

/// Encode the recovery-slot RECONCILE for CPU0's actual transfer of a stopped CPU's
/// protected accumulator. Source and object identities are CPU slots with
/// their protected writer generations. The event only attests this transfer.
pub(super) fn reconcile_record(
    boot: u64,
    owner: &RecoveryProofV2,
    proof: &RecoveryProofV2,
) -> Option<[u8; AUDIT_BYTES]> {
    if boot == 0
        || owner.boot_epoch != boot
        || owner.cpu_generation == 0
        || owner.cpu_id != 0
        || proof.boot_epoch != owner.boot_epoch
        || !(1..=WORKERS as u32).contains(&proof.cpu_id)
        || proof.cpu_generation != 2
        || proof.total_count == 0
    {
        return None;
    }
    let mut encoded = [0; RECOVERY_PROOF_BYTES];
    proof.encode(&mut encoded);
    let mut r = [0; AUDIT_BYTES];
    r[..4].copy_from_slice(&0x43594155u32.to_le_bytes());
    for (at, value) in [
        (4, 2u16),
        (6, 128),
        (24, 10),
        (26, 1),
        (28, 3),
        (30, u16::MAX),
    ] {
        r[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    for (at, value) in [
        (8, proof.boot_epoch),
        (16, u64::from(proof.cpu_id)), // CPU0 took workers in ascending slot order.
        (32, u64::from(owner.cpu_id)),
        (40, owner.cpu_generation),
        (48, u64::from(proof.cpu_id)),
        (56, proof.cpu_generation),
    ] {
        r[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    r[64..96].copy_from_slice(&Sha256::digest(encoded));
    let mut digest = Sha256::new();
    digest.update(b"CYX/AUDIT/v2");
    digest.update(&r[..96]);
    r[96..].copy_from_slice(&digest.finalize());
    Some(r)
}

#[derive(Clone, Copy)]
struct Slot {
    bytes: [u8; AUDIT_BYTES],
    delivered_to: Option<Caller>,
}

pub(super) struct Custody {
    slots: [Option<Slot>; WORKERS],
    pub(super) released: u64,
}

impl Custody {
    pub(super) const fn empty() -> Self {
        Self {
            slots: [None; WORKERS],
            released: 0,
        }
    }

    pub(super) fn from_handoffs(
        boot: u64,
        proofs: &[RecoveryProofV2; WORKERS + 1],
    ) -> Option<Self> {
        let mut custody = Self::empty();
        for (i, proof) in proofs[1..].iter().enumerate() {
            if proof.cpu_id as usize != i + 1 {
                return None;
            }
            custody.slots[i] = Some(Slot {
                bytes: reconcile_record(boot, &proofs[0], proof)?,
                delivered_to: None,
            });
        }
        Some(custody)
    }

    pub(super) fn read(&self, after: u64) -> [u8; 144] {
        let mut payload = [0; 144];
        if let Some((i, slot)) = self.slots.iter().enumerate().find_map(|(i, slot)| {
            slot.as_ref()
                .filter(|_| i as u64 + 1 > after)
                .map(|s| (i, s))
        }) {
            payload[..2].copy_from_slice(&1u16.to_le_bytes());
            payload[8..16].copy_from_slice(&(i as u64 + 1).to_le_bytes());
            payload[16..].copy_from_slice(&slot.bytes);
        }
        payload
    }

    fn index(seq: u64) -> Result<usize, Error> {
        if !(1..=WORKERS as u64).contains(&seq) {
            return Err(Error::Stale);
        }
        Ok(seq as usize - 1)
    }

    // Called only after successful copy and readback of the entire reply to this caller.
    pub(super) fn delivered(
        &mut self,
        caller: Caller,
        seq: u64,
        record: &[u8],
    ) -> Result<(), Error> {
        let slot = self.slots[Self::index(seq)?].as_mut().ok_or(Error::Stale)?;
        if record != slot.bytes || slot.delivered_to.is_some_and(|owner| owner != caller) {
            return Err(Error::Conflict);
        }
        slot.delivered_to = Some(caller);
        Ok(())
    }

    pub(super) fn check_ack(
        &self,
        caller: Caller,
        seq: u64,
        digest: &[u8],
    ) -> Result<usize, Error> {
        let i = Self::index(seq)?;
        let slot = self.slots[i].as_ref().ok_or(Error::Stale)?;
        if slot.delivered_to != Some(caller) {
            return Err(Error::Auth);
        }
        if slot.bytes[96..] != *digest {
            return Err(Error::Conflict);
        }
        Ok(i)
    }

    pub(super) fn release(&mut self, caller: Caller, seq: u64, digest: &[u8]) -> Result<(), Error> {
        let i = self.check_ack(caller, seq, digest)?;
        self.slots[i] = None;
        self.released += 1;
        Ok(())
    }
}
