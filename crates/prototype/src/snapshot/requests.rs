use super::codec::*;
use super::*;
use crate::{
    journal::TransactionKey,
    storage::{self, BLOCK_SIZE},
};

pub(super) const RECORDS: usize = 64;
pub(super) const HEADER_CRC: usize = 508;
pub(super) const WATERMARK_FIRST: usize = 512;
pub(super) const WATERMARK_SIZE: usize = 128;
pub(super) const EMPTY_TRANSACTION: TransactionKey = TransactionKey {
    fs_uuid: [0; 16],
    log_epoch: 0,
    txid: 0,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestRecord {
    pub state: RequestState,
    pub operation: u16,
    pub key: FileReqKey,
    pub request_digest: [u8; 32],
    pub snapshot_key: SnapshotKey,
    pub old_live_view_epoch: u64,
    pub new_live_view_epoch: u64,
    pub transaction: TransactionKey,
    pub result_code: i32,
    pub restore_mode: RestoreMode,
    pub result_digest: [u8; 32],
    pub result_payload_len: u32,
    pub result_payload: [u8; 128],
}
impl RequestRecord {
    pub const FREE: Self = Self {
        state: RequestState::Free,
        operation: 0,
        key: FileReqKey::ZERO,
        request_digest: [0; 32],
        snapshot_key: SnapshotKey::ZERO,
        old_live_view_epoch: 0,
        new_live_view_epoch: 0,
        transaction: EMPTY_TRANSACTION,
        result_code: 0,
        restore_mode: RestoreMode::None,
        result_digest: [0; 32],
        result_payload_len: 0,
        result_payload: [0; 128],
    };
    pub(super) fn pending(
        request: Request,
        operation: u16,
        digest: [u8; 32],
        payload: &[u8],
    ) -> Self {
        let mut v = Self {
            state: RequestState::Pending,
            operation,
            key: request.key,
            request_digest: digest,
            old_live_view_epoch: request.expected_live_view_epoch,
            ..Self::FREE
        };
        v.result_payload_len = payload.len() as u32;
        v.result_payload[..payload.len()].copy_from_slice(payload);
        v
    }
    pub fn payload(&self) -> &[u8] {
        &self.result_payload[..self.result_payload_len as usize]
    }
    fn validate(self) -> Result<(), storage::Error> {
        if self.state == RequestState::Free {
            if self != Self::FREE {
                return Err(storage::Error::Reserved);
            }
            return Ok(());
        }
        self.key.validate()?;
        if !matches!(
            self.operation,
            OP_CREATE
                | OP_EXTEND
                | OP_DELETE
                | OP_RESTORE
                | OP_FREEZE_SET
                | OP_FREEZE_CLEAR
                | OP_OPEN_WRITES
        ) {
            return Err(storage::Error::Payload);
        }
        if self.result_payload_len > 128 {
            return Err(storage::Error::Length);
        }
        zeros(&self.result_payload[self.result_payload_len as usize..])?;
        if !self.snapshot_key.is_zero() {
            self.snapshot_key.validate()?;
            if self.snapshot_key.fs_uuid != self.key.fs_uuid {
                return Err(storage::Error::Identity);
            }
        }
        if self.transaction != EMPTY_TRANSACTION
            && (self.transaction.fs_uuid != self.key.fs_uuid
                || self.transaction.log_epoch == 0
                || self.transaction.txid == 0)
        {
            return Err(storage::Error::Identity);
        }
        if self.state == RequestState::Done && self.transaction == EMPTY_TRANSACTION {
            return Err(storage::Error::Identity);
        }
        if !self.state.terminal() && self.result_digest != [0; 32] {
            return Err(storage::Error::Reserved);
        }
        Ok(())
    }
    fn encode_fields(&self, b: &mut [u8]) {
        b.fill(0);
        put32(b, 0, 0x4359_4652);
        put16(b, 4, 1);
        put16(b, 6, 512);
        put32(b, 8, self.state as u32);
        put16(b, 12, self.operation);
        self.key.encode(&mut b[16..52]).unwrap();
        b[52..84].copy_from_slice(&self.request_digest);
        self.snapshot_key.encode(&mut b[88..128]).unwrap();
        put64(b, 128, self.old_live_view_epoch);
        put64(b, 136, self.new_live_view_epoch);
        b[144..160].copy_from_slice(&self.transaction.fs_uuid);
        put64(b, 160, self.transaction.log_epoch);
        put64(b, 168, self.transaction.txid);
        put32(b, 176, self.result_code as u32);
        put32(b, 180, self.restore_mode as u32);
        b[184..216].copy_from_slice(&self.result_digest);
        put32(b, 216, self.result_payload_len);
        b[220..348].copy_from_slice(&self.result_payload);
    }
    pub(super) fn seal_result(&mut self) {
        self.result_digest = [0; 32];
        if self.state.terminal() {
            let mut bytes = [0; 512];
            self.encode_fields(&mut bytes);
            self.result_digest = hash(&bytes);
        }
    }
    pub fn encode(&self, b: &mut [u8]) -> Result<(), storage::Error> {
        len(b, 512)?;
        self.validate()?;
        if self.state.terminal() {
            let mut expected = *self;
            expected.seal_result();
            if expected.result_digest != self.result_digest {
                return Err(storage::Error::Checksum);
            }
        }
        self.encode_fields(b);
        seal(b, 508);
        Ok(())
    }
    pub fn decode(b: &[u8]) -> Result<Self, storage::Error> {
        header(b, 512, 0x4359_4652, 1, 512, 508)?;
        zeros(&b[14..16])?;
        zeros(&b[84..88])?;
        zeros(&b[348..508])?;
        let v = Self {
            state: RequestState::try_from(u32_at(b, 8))?,
            operation: u16_at(b, 12),
            key: FileReqKey::decode(&b[16..52])?,
            request_digest: b[52..84].try_into().unwrap(),
            snapshot_key: SnapshotKey::decode(&b[88..128])?,
            old_live_view_epoch: u64_at(b, 128),
            new_live_view_epoch: u64_at(b, 136),
            transaction: TransactionKey {
                fs_uuid: b[144..160].try_into().unwrap(),
                log_epoch: u64_at(b, 160),
                txid: u64_at(b, 168),
            },
            result_code: u32_at(b, 176) as i32,
            restore_mode: RestoreMode::try_from(u32_at(b, 180))?,
            result_digest: b[184..216].try_into().unwrap(),
            result_payload_len: u32_at(b, 216),
            result_payload: b[220..348].try_into().unwrap(),
        };
        v.validate()?;
        if v.state.terminal() {
            let mut expected = v;
            expected.seal_result();
            if expected.result_digest != v.result_digest {
                return Err(storage::Error::Checksum);
            }
        }
        Ok(v)
    }
}

/// Frozen v1 extension: page 0 holds a 512-byte object header followed by sixteen
/// 128-byte principal entries; pages 1..=8 hold eight request records each.
/// Pages 9..=15 remain zero recovery reserve. Header CRC covers all of page 0.
pub fn format_request_block(
    index: u32,
    fs_uuid: [u8; 16],
    output: &mut [u8; BLOCK_SIZE],
) -> Result<(), storage::Error> {
    if index >= 16 {
        return Err(storage::Error::Range);
    }
    if fs_uuid == [0; 16] {
        return Err(storage::Error::Identity);
    }
    output.fill(0);
    if index == 0 {
        put32(output, 0, 0x4359_5251);
        put16(output, 4, 1);
        put16(output, 6, 512);
        output[8..24].copy_from_slice(&fs_uuid);
        for (o, v) in [(24, 64), (28, 512), (32, 16), (36, 128), (40, 1), (44, 512)] {
            put32(output, o, v);
        }
        for i in 0..16 {
            Watermark {
                client_slot: i as u32,
                client_generation: 1,
                highest_accepted_seq: 0,
            }
            .encode(&mut output[512 + i * 128..512 + (i + 1) * 128])?;
        }
        seal(output, HEADER_CRC);
    } else if index <= 8 {
        for i in 0..8 {
            RequestRecord::FREE.encode(&mut output[i * 512..(i + 1) * 512])?;
        }
    }
    Ok(())
}
#[derive(Clone, Copy, Debug)]
pub(super) struct Watermark {
    pub client_slot: u32,
    pub client_generation: u64,
    pub highest_accepted_seq: u64,
}
impl Watermark {
    pub fn encode(self, b: &mut [u8]) -> Result<(), storage::Error> {
        len(b, 128)?;
        if self.client_slot >= 16 || self.client_generation == 0 {
            return Err(storage::Error::Identity);
        }
        b.fill(0);
        put32(b, 0, 0x4359_574d);
        put16(b, 4, 1);
        put16(b, 6, 128);
        put32(b, 8, self.client_slot);
        put64(b, 16, self.client_generation);
        put64(b, 24, self.highest_accepted_seq);
        seal(b, 124);
        Ok(())
    }
    pub fn decode(b: &[u8], slot: usize) -> Result<Self, storage::Error> {
        header(b, 128, 0x4359_574d, 1, 128, 124)?;
        zeros(&b[12..16])?;
        zeros(&b[32..124])?;
        let v = Self {
            client_slot: u32_at(b, 8),
            client_generation: u64_at(b, 16),
            highest_accepted_seq: u64_at(b, 24),
        };
        if v.client_slot != slot as u32 || v.client_generation == 0 {
            return Err(storage::Error::Identity);
        }
        Ok(v)
    }
}
pub(super) fn validate_header(b: &[u8], uuid: [u8; 16]) -> Result<(), storage::Error> {
    header(b, BLOCK_SIZE, 0x4359_5251, 1, 512, HEADER_CRC)?;
    if b[8..24] != uuid
        || u32_at(b, 24) != 64
        || u32_at(b, 28) != 512
        || u32_at(b, 32) != 16
        || u32_at(b, 36) != 128
        || u32_at(b, 40) != 1
        || u32_at(b, 44) != 512
    {
        return Err(storage::Error::Layout);
    }
    zeros(&b[48..508])?;
    zeros(&b[2560..])?;
    for i in 0..16 {
        watermark(b, i)?;
    }
    Ok(())
}
pub(super) fn watermark(b: &[u8], slot: usize) -> Result<Watermark, storage::Error> {
    Watermark::decode(
        &b[WATERMARK_FIRST + slot * WATERMARK_SIZE..WATERMARK_FIRST + (slot + 1) * WATERMARK_SIZE],
        slot,
    )
}
pub(super) fn update_watermark(b: &mut [u8], value: Watermark) -> Result<(), storage::Error> {
    let slot = value.client_slot as usize;
    value.encode(&mut b[512 + slot * 128..512 + (slot + 1) * 128])?;
    seal(b, HEADER_CRC);
    Ok(())
}
pub(super) fn record_page(index: usize) -> u32 {
    storage::SNAPSHOT_REQUEST_START + 1 + (index / 8) as u32
}
pub(super) fn record_range(index: usize) -> core::ops::Range<usize> {
    let offset = (index % 8) * 512;
    offset..offset + 512
}
pub(super) fn partition(slot: u32) -> core::ops::Range<usize> {
    match slot {
        0..=13 => 0..48,
        14 => 48..56,
        _ => 56..64,
    }
}
pub(super) fn belongs(index: usize, slot: u32) -> bool {
    partition(slot).contains(&index)
}
