//! D6 ProtectionStore wire layout. Mount validates matching durable records,
//! and the current boot still needs separate authority to open writes.

use super::{
    Error, SNAPSHOT_SLOTS, SUPER_BYTES, UnifiedSystemKind, crc32c_zeroed, decode_envelope_header,
    encode_object_envelope, le16, le64, put16, put32, put64,
};

const PAYLOAD_VERSION: u16 = 1;
const PAYLOAD_BYTES: u16 = 168;
const USED_BYTES: usize = 208;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestorePhase {
    Idle = 0,
    Prepared = 1,
    RestoredFrozen = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectionRecord {
    pub fs_uuid: [u8; 16],
    pub object_generation: u64,
    pub protection_generation: u64,
    pub live_view_epoch: u64,
    pub online_age_ns: u64,
    pub retention_deadlines: [u64; SNAPSHOT_SLOTS as usize],
    pub writes_open: bool,
    pub restore_phase: RestorePhase,
    pub cleanup_frozen: bool,
    pub reopen_proof_digest: [u8; 32],
    pub restore_obligation_digest: [u8; 32],
}

impl ProtectionRecord {
    fn validate(&self) -> Result<(), Error> {
        let idle = self.restore_phase == RestorePhase::Idle;
        if self.protection_generation == 0
            || self.live_view_epoch == 0
            || idle != (self.restore_obligation_digest == [0; 32])
            || self.writes_open != (self.reopen_proof_digest != [0; 32])
            || self.writes_open && !idle
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        let envelope = decode_envelope_header(UnifiedSystemKind::SnapshotProtection, raw)?;
        if le16(raw, 40)? != PAYLOAD_VERSION
            || le16(raw, 42)? != PAYLOAD_BYTES
            || raw[44..48] != [0; 4]
            || raw[136] > 1
            || raw[138] > 1
            || raw[139..144] != [0; 5]
            || raw[USED_BYTES..].iter().any(|&value| value != 0)
        {
            return Err(Error::Invalid);
        }
        let restore_phase = match raw[137] {
            0 => RestorePhase::Idle,
            1 => RestorePhase::Prepared,
            2 => RestorePhase::RestoredFrozen,
            _ => return Err(Error::Invalid),
        };
        let mut retention_deadlines = [0; SNAPSHOT_SLOTS as usize];
        for (i, deadline) in retention_deadlines.iter_mut().enumerate() {
            *deadline = le64(raw, 72 + i * 8)?;
        }
        let record = Self {
            fs_uuid: envelope.fs_uuid,
            object_generation: envelope.generation,
            protection_generation: le64(raw, 48)?,
            live_view_epoch: le64(raw, 56)?,
            online_age_ns: le64(raw, 64)?,
            retention_deadlines,
            writes_open: raw[136] == 1,
            restore_phase,
            cleanup_frozen: raw[138] == 1,
            reopen_proof_digest: raw[144..176].try_into().unwrap(),
            restore_obligation_digest: raw[176..208].try_into().unwrap(),
        };
        record.validate()?;
        Ok(record)
    }

    pub fn encode(&self, raw: &mut [u8; SUPER_BYTES]) -> Result<(), Error> {
        self.validate()?;
        encode_object_envelope(
            UnifiedSystemKind::SnapshotProtection,
            self.fs_uuid,
            self.object_generation,
            raw,
        )?;
        put16(raw, 40, PAYLOAD_VERSION);
        put16(raw, 42, PAYLOAD_BYTES);
        put64(raw, 48, self.protection_generation);
        put64(raw, 56, self.live_view_epoch);
        put64(raw, 64, self.online_age_ns);
        for (i, deadline) in self.retention_deadlines.iter().enumerate() {
            put64(raw, 72 + i * 8, *deadline);
        }
        raw[136] = u8::from(self.writes_open);
        raw[137] = self.restore_phase as u8;
        raw[138] = u8::from(self.cleanup_frozen);
        raw[144..176].copy_from_slice(&self.reopen_proof_digest);
        raw[176..208].copy_from_slice(&self.restore_obligation_digest);
        let crc = crc32c_zeroed(raw, 32)?;
        put32(raw, 32, crc);
        Ok(())
    }
}
