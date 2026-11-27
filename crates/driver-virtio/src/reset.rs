//! SEC-D ResetProof v1 for a terminal reset of a one-shot MMIO owner.

pub const RESET_PROOF_BYTES: usize = 64;
pub(crate) const RESET_DEADLINE_NS: u64 = 100_000_000;
pub(crate) const RESET_POLL_LIMIT: usize = 1 << 20;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum DeviceState {
    Live,
    Failed,
    RecoveryFenced,
    ResetAttempted,
}

/// Created only after the old queue has stopped publishing and the driver's
/// ordered MMIO reads confirm a protocol reset. This is a DMA cessation
/// witness for a conforming device. Block operation results have their own
/// independent completion and durability evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResetProof {
    boot_epoch: u64,
    device_id: u32,
    queue_id: u16,
    observed_local_ns: u64,
}

impl ResetProof {
    pub(crate) fn for_first_generation(
        boot_epoch: u64,
        device_id: u32,
        queue_id: u16,
        observed_local_ns: u64,
    ) -> Self {
        Self {
            boot_epoch,
            device_id,
            queue_id,
            observed_local_ns,
        }
    }

    pub fn encode(self) -> [u8; RESET_PROOF_BYTES] {
        let mut wire = [0; RESET_PROOF_BYTES];
        wire[0..4].copy_from_slice(&0x4359_5250u32.to_le_bytes());
        wire[4..6].copy_from_slice(&1u16.to_le_bytes());
        wire[6..8].copy_from_slice(&(RESET_PROOF_BYTES as u16).to_le_bytes());
        wire[8..16].copy_from_slice(&self.boot_epoch.to_le_bytes());
        wire[16..20].copy_from_slice(&self.device_id.to_le_bytes());
        wire[20..22].copy_from_slice(&self.queue_id.to_le_bytes());
        // This owner registers the first device and queue generation once.
        // The generation is terminal after reset, so reset_seq is also one.
        for at in [24, 32, 40] {
            wire[at..at + 8].copy_from_slice(&1u64.to_le_bytes());
        }
        wire[56..64].copy_from_slice(&self.observed_local_ns.to_le_bytes());
        wire
    }
}
