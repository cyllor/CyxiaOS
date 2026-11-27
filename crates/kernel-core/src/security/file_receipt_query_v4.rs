//! FILE_QUERY_RESULT for a mounted volume's committed receipt/index image.
//! The native caller supplies the authenticated mount, confirmed boot and
//! caller identity. The joint scanner and CRCs check structural consistency.

use super::{
    Error,
    file_index_v0199::{FileStreamIndexV4, GROUP_COUNT, SecurityStateStoreV2},
    file_media_v0199::{FileReceiptV4, RECEIPT_BYTES, local_request_id},
    file_receipt_store_v0199::scan_receipts_with_index,
    file_service_v4::{REPLY_HEADER, REPLY_MAGIC, REPLY_VERSION, Request},
    offline_config_v1::VerifiedOfflineConfig,
};

pub const FILE_QUERY_RESULT: u16 = 11;
pub const RECEIPT_KEY_BYTES: usize = 56;
const RECEIPT_KEY_OFFSET: usize = 8;
const BOUND: u16 = 2;
const UNKNOWN: u16 = 5;
const E_TIMEOUT: i32 = -6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiptKey {
    pub fs_uuid: [u8; 16],
    pub issued_boot_epoch: u64,
    pub group_id: u32,
    pub group_generation: u32,
    pub stream_slot: u64,
    pub stream_generation: u64,
    pub request_seq: u64,
}

impl ReceiptKey {
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != RECEIPT_KEY_BYTES {
            return Err(Error::Invalid);
        }
        let key = Self {
            fs_uuid: field(bytes, 0),
            issued_boot_epoch: u64::from_le_bytes(field(bytes, 16)),
            group_id: u32::from_le_bytes(field(bytes, 24)),
            group_generation: u32::from_le_bytes(field(bytes, 28)),
            stream_slot: u64::from_le_bytes(field(bytes, 32)),
            stream_generation: u64::from_le_bytes(field(bytes, 40)),
            request_seq: u64::from_le_bytes(field(bytes, 48)),
        };
        if key.fs_uuid == [0; 16]
            || key.issued_boot_epoch == 0
            || key.group_generation == 0
            || !(1..=u64::from(u32::MAX)).contains(&key.stream_generation)
            || key.request_id().is_none()
        {
            return Err(Error::Invalid);
        }
        Ok(key)
    }

    /// Return the canonical local ID projected from the group, stream and sequence.
    pub const fn request_id(&self) -> Option<u64> {
        local_request_id(self.group_id, self.stream_slot, self.request_seq)
    }
}

/// Facts supplied by the native caller after checking the live holder's
/// FILE_RECEIPT_QUERY qualification and current FILE_SERVICE IPC_SEND right.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiptQueryCaller {
    /// Persistent principal ID from the authenticated volume manifest.
    pub principal_id: u64,
    pub boot_epoch: u64,
    /// Current FILE_SERVICE instance generation.
    pub service_generation: u64,
}

pub struct MountedReceiptQuery<'a> {
    receipts: &'a [u8],
    fs_uuid: [u8; 16],
    boot_epoch: u64,
    principals: [u64; GROUP_COUNT],
}

impl<'a> MountedReceiptQuery<'a> {
    /// The native mount owner must supply the complete committed receipt,
    /// index and security images from one stable mounted state, together
    /// with the independently authenticated, already committed config.
    /// CRCs cannot establish principal identity or substitute for actual
    /// redo, FLUSH and recovery evidence.
    pub fn new(
        receipts: &'a [u8],
        index_block: &[u8],
        config: &VerifiedOfflineConfig<'_>,
        security: &SecurityStateStoreV2,
    ) -> Result<Self, Error> {
        config.check_committed(security)?;
        Self::from_principals(
            receipts,
            index_block,
            security.fs_uuid,
            security.last_boot_epoch,
            config.principals().map(|principal| principal.id),
        )
    }

    fn from_principals(
        receipts: &'a [u8],
        index_block: &[u8],
        fs_uuid: [u8; 16],
        boot_epoch: u64,
        principals: [u64; GROUP_COUNT],
    ) -> Result<Self, Error> {
        if boot_epoch == 0 {
            return Err(Error::Invalid);
        }
        scan_receipts_with_index(receipts, index_block, fs_uuid)?;
        let index = FileStreamIndexV4::decode(index_block)?;
        if index
            .groups
            .iter()
            .any(|group| group.boot_epoch > boot_epoch)
        {
            return Err(Error::Invalid);
        }
        if index.groups.map(|group| group.manifest_principal_id) != principals {
            return Err(Error::Unauthorized);
        }
        Ok(Self {
            receipts,
            fs_uuid,
            boot_epoch,
            principals,
        })
    }

    /// Read one exact receipt for the authenticated current holder. The caller
    /// supplies a frozen request frame and uses a view of the current mounted
    /// state for the duration of the query. On success, copy one Reply v3
    /// header. The reply buffer is untouched on error.
    pub fn serve(
        &self,
        caller: ReceiptQueryCaller,
        selector: u64,
        frame: &[u8],
        reply: &mut [u8],
    ) -> Result<usize, Error> {
        if caller.principal_id == 0 || caller.boot_epoch == 0 || caller.service_generation == 0 {
            return Err(Error::Unauthorized);
        }
        if caller.boot_epoch != self.boot_epoch {
            return Err(Error::Stale);
        }
        let request = Request::decode(frame, selector)?;
        if request.op != FILE_QUERY_RESULT {
            return Err(Error::Invalid);
        }
        let key = ReceiptKey::decode(request.payload)?;
        if key.request_id() != Some(request.request_id) {
            return Err(Error::Invalid);
        }
        if key.fs_uuid != self.fs_uuid
            || self.principals[key.group_id as usize] != caller.principal_id
        {
            return Err(Error::Unauthorized);
        }
        if key.issued_boot_epoch > self.boot_epoch {
            return Err(Error::Stale);
        }

        let raw = self
            .receipts
            .chunks_exact(RECEIPT_BYTES)
            .find(|raw| {
                &raw[RECEIPT_KEY_OFFSET..RECEIPT_KEY_OFFSET + RECEIPT_KEY_BYTES] == request.payload
            })
            .ok_or(Error::Stale)?;
        let receipt = FileReceiptV4::decode(raw)?;
        if receipt.owner_principal_id != caller.principal_id {
            return Err(Error::Unauthorized);
        }
        reply
            .get_mut(..REPLY_HEADER)
            .ok_or(Error::Capacity)?
            .copy_from_slice(&encode_receipt_reply(caller, receipt));
        Ok(REPLY_HEADER)
    }
}

/// Encode the committed receipt for a native query or operation completion.
/// The mounted owner supplies the already-authorized and validated receipt.
pub fn encode_receipt_reply(
    caller: ReceiptQueryCaller,
    receipt: FileReceiptV4,
) -> [u8; REPLY_HEADER] {
    // A prior boot cannot finish an admission with its old frozen pages.
    // Keep the on-disk BOUND record and reply with uncertainty until the
    // recovery owner reconciles it and durably proves a terminal outcome.
    let status = if receipt.status == BOUND && receipt.issued_boot_epoch < caller.boot_epoch {
        UNKNOWN
    } else {
        receipt.status
    };
    let result = if status == UNKNOWN && receipt.result == 0 {
        E_TIMEOUT
    } else {
        receipt.result
    };
    let mut wire = [0; REPLY_HEADER];
    wire[..4].copy_from_slice(&REPLY_MAGIC.to_le_bytes());
    wire[4..6].copy_from_slice(&REPLY_VERSION.to_le_bytes());
    wire[6..8].copy_from_slice(&(REPLY_HEADER as u16).to_le_bytes());
    wire[8..16].copy_from_slice(&receipt.request_id.to_le_bytes());
    wire[16..24].copy_from_slice(&caller.service_generation.to_le_bytes());
    wire[24..26].copy_from_slice(&status.to_le_bytes());
    wire[28..32].copy_from_slice(&result.to_le_bytes());
    wire[32..36].copy_from_slice(&receipt.completed_prefix.to_le_bytes());
    wire[40..48].copy_from_slice(&receipt.commit_lsn.to_le_bytes());
    wire[48..56].copy_from_slice(&receipt.log_epoch.to_le_bytes());
    wire[56..64].copy_from_slice(&receipt.txid.to_le_bytes());
    wire[80..112].copy_from_slice(&receipt.output_digest);
    wire[112..120].copy_from_slice(&receipt.request_id.to_le_bytes());
    wire[120..128].copy_from_slice(&receipt.write_seq.to_le_bytes());
    wire
}

fn field<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    bytes[offset..offset + N].try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{
        file_index_v0199::{BLOCK_BYTES, GroupIndex, STREAM_COUNT, STREAMS_PER_GROUP, StreamIndex},
        file_receipt_store_v0199::RECEIPT_STORE_BYTES,
        file_service_v4::{REQUEST_HEADER, Reply},
    };

    const UUID: [u8; 16] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
        0x2f,
    ];
    const KEY: ReceiptKey = ReceiptKey {
        fs_uuid: UUID,
        issued_boot_epoch: 7,
        group_id: 2,
        group_generation: 0x0103,
        stream_slot: 5,
        stream_generation: 0x0001_0203,
        request_seq: 0x0123,
    };
    const REQUEST_ID: u64 = 0x03a0_0000_0000_0123;
    const CALLER: ReceiptQueryCaller = ReceiptQueryCaller {
        principal_id: 102,
        boot_epoch: 10,
        service_generation: 0x15,
    };
    const RECEIPT_SLOT: usize = 21;
    const STREAM_POSITION: usize =
        KEY.group_id as usize * STREAMS_PER_GROUP + KEY.stream_slot as usize;

    #[rustfmt::skip]
    const QUERY: [u8; REQUEST_HEADER + RECEIPT_KEY_BYTES] = [
        0x51, 0x46, 0x59, 0x43, 0x04, 0x00, 0x20, 0x00,
        0x0b, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00,
        0x23, 0x01, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x03,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00,
        0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x23, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[rustfmt::skip]
    const PARTIAL_REPLY: [u8; REPLY_HEADER] = [
        0x52, 0x46, 0x59, 0x43, 0x03, 0x00, 0x80, 0x00,
        0x23, 0x01, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x03,
        0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff,
        0x45, 0x23, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x06, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x03, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
        0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
        0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
        0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
        0x23, 0x01, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x03,
        0x0b, 0x0a, 0x09, 0x08, 0x00, 0x00, 0x00, 0x00,
    ];

    fn mounted_image(status: u16, result: i32) -> ([u8; RECEIPT_STORE_BYTES], [u8; BLOCK_BYTES]) {
        let receipt = FileReceiptV4 {
            fs_uuid: KEY.fs_uuid,
            issued_boot_epoch: KEY.issued_boot_epoch,
            group_id: KEY.group_id,
            group_generation: KEY.group_generation,
            stream_slot: KEY.stream_slot,
            stream_generation: KEY.stream_generation,
            request_seq: KEY.request_seq,
            log_epoch: 11,
            txid: 0x0102_0304,
            commit_lsn: 0x0007_0605,
            write_seq: 0x0809_0a0b,
            status,
            result,
            completed_prefix: 0x0001_2345,
            operation_digest: [0x41; 32],
            output_digest: [0x31; 32],
            request_id: REQUEST_ID,
            owner_principal_id: CALLER.principal_id,
        };
        let mut receipts = [0; RECEIPT_STORE_BYTES];
        let at = RECEIPT_SLOT * RECEIPT_BYTES;
        receipts[at..at + RECEIPT_BYTES].copy_from_slice(&receipt.encode().unwrap());

        let mut index = FileStreamIndexV4 {
            fs_uuid: UUID,
            global_request_id_hi: 0,
            generation: 4,
            groups: core::array::from_fn(|group| GroupIndex {
                generation: 0,
                flags: 0,
                boot_epoch: 0,
                manifest_principal_id: 100 + group as u64,
            }),
            streams: [StreamIndex {
                generation: 0,
                flags: 0,
                issued_hi: 0,
                retired_through: 0,
            }; STREAM_COUNT],
        };
        index.groups[KEY.group_id as usize] = GroupIndex {
            generation: KEY.group_generation + 1,
            flags: 1,
            boot_epoch: CALLER.boot_epoch,
            manifest_principal_id: CALLER.principal_id,
        };
        index.streams[STREAM_POSITION] = StreamIndex {
            generation: KEY.stream_generation as u32,
            flags: 1,
            issued_hi: KEY.request_seq,
            retired_through: KEY.request_seq - 1,
        };
        let mut block = [0; BLOCK_BYTES];
        index.encode_into(&mut block).unwrap();
        (receipts, block)
    }

    fn mounted_view<'a>(
        receipts: &'a [u8],
        index: &[u8],
        fs_uuid: [u8; 16],
        boot_epoch: u64,
    ) -> Result<MountedReceiptQuery<'a>, Error> {
        MountedReceiptQuery::from_principals(
            receipts,
            index,
            fs_uuid,
            boot_epoch,
            core::array::from_fn(|group| 100 + group as u64),
        )
    }

    #[test]
    fn query_rejects_consistent_but_unauthenticated_principal_rebinding() {
        let (mut receipts, index) = mounted_image(4, -16);
        let mut changed = FileStreamIndexV4::decode(&index).unwrap();
        changed.groups[KEY.group_id as usize].manifest_principal_id = 999;
        let at = RECEIPT_SLOT * RECEIPT_BYTES;
        let mut receipt = FileReceiptV4::decode(&receipts[at..at + RECEIPT_BYTES]).unwrap();
        receipt.owner_principal_id = 999;
        receipts[at..at + RECEIPT_BYTES].copy_from_slice(&receipt.encode().unwrap());
        let mut block = [0; BLOCK_BYTES];
        changed.encode_into(&mut block).unwrap();

        // Both media records have valid CRCs and agree with one another.
        // They still cannot replace a principal from the authenticated config.
        assert!(scan_receipts_with_index(&receipts, &block, UUID).is_ok());
        assert_eq!(
            mounted_view(&receipts, &block, UUID, CALLER.boot_epoch).err(),
            Some(Error::Unauthorized)
        );
    }

    #[test]
    fn public_query_requires_committed_signed_manifest() {
        use crate::security::offline_config_v1::CatalogBindings;
        use ed25519_dalek::{Signer, SigningKey};
        use sha2::{Digest, Sha256};

        const LABEL: &[u8] = b"CYX/OFFLINE/v1";
        let mut wire = [0u8; 577];
        wire[..4].copy_from_slice(&0x4359_4f46u32.to_le_bytes());
        wire[4..6].copy_from_slice(&1u16.to_le_bytes());
        wire[6..8].copy_from_slice(&256u16.to_le_bytes());
        wire[8..12].copy_from_slice(&577u32.to_le_bytes());
        wire[12..16].copy_from_slice(&257u32.to_le_bytes());
        wire[16..32].copy_from_slice(&UUID);
        for (at, value) in [(32, 7u64), (40, 3), (48, 4), (56, 5)] {
            wire[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        wire[64..96].fill(2);
        wire[96..128].fill(3);
        wire[128..160].fill(4);
        for group in 0..GROUP_COUNT {
            let at = 256 + group * 16;
            wire[at..at + 8].copy_from_slice(&(100 + group as u64).to_le_bytes());
            wire[at + 8..at + 16].copy_from_slice(&1u64.to_le_bytes());
        }
        wire[512] = 42;
        let payload_hash = Sha256::digest(&wire[256..513]);
        wire[160..192].copy_from_slice(&payload_hash);
        // Host-only test key; never part of a boot trust catalog.
        let signer = SigningKey::from_bytes(&[0x37; 32]);
        let mut message = [0u8; LABEL.len() + 513];
        message[..LABEL.len()].copy_from_slice(LABEL);
        message[LABEL.len()..].copy_from_slice(&wire[..513]);
        wire[513..].copy_from_slice(&signer.sign(&message).to_bytes());
        let catalog = CatalogBindings {
            rule_generation: 3,
            security_generation: 4,
            key_generation: 5,
            rule_hash: [2; 32],
            security_hash: [3; 32],
            key_manifest_hash: [4; 32],
        };
        let mut scratch = [0u8; LABEL.len() + 513];
        let config = VerifiedOfflineConfig::verify(
            &wire,
            &signer.verifying_key().to_bytes(),
            catalog,
            &mut scratch,
            |_, _, payload| {
                if payload == [42] {
                    Ok(())
                } else {
                    Err(Error::Invalid)
                }
            },
        )
        .unwrap();
        let mut security = SecurityStateStoreV2 {
            fs_uuid: UUID,
            state_generation: 1,
            rule_min_generation: 3,
            security_min_generation: 4,
            key_generation: 5,
            isolated_service_bitmap: 0,
            last_boot_epoch: CALLER.boot_epoch,
            offline_config_generation: 7,
            offline_config_hash: config.digest(),
            service_generations: [1; 16],
        };
        let (receipts, index) = mounted_image(4, -16);
        let view = MountedReceiptQuery::new(&receipts, &index, &config, &security).unwrap();
        let mut reply = [0; REPLY_HEADER];
        assert_eq!(view.serve(CALLER, 0, &QUERY, &mut reply), Ok(REPLY_HEADER));
        assert_eq!(reply, PARTIAL_REPLY);

        security.offline_config_hash = [0x99; 32];
        assert_eq!(
            MountedReceiptQuery::new(&receipts, &index, &config, &security).err(),
            Some(Error::Conflict)
        );
        security.offline_config_hash = config.digest();
        security.last_boot_epoch = 0;
        assert_eq!(
            MountedReceiptQuery::new(&receipts, &index, &config, &security).err(),
            Some(Error::Invalid)
        );
    }

    #[test]
    fn literal_query_retains_prior_boot_and_group_generation() {
        let key = ReceiptKey::decode(&QUERY[REQUEST_HEADER..]).unwrap();
        assert_eq!(key, KEY);
        assert_eq!(key.request_id(), Some(REQUEST_ID));
        let (receipts, index) = mounted_image(4, -16);
        let view = mounted_view(&receipts, &index, UUID, CALLER.boot_epoch).unwrap();
        let mut reply = [0xa5; REPLY_HEADER + 2];
        assert_eq!(view.serve(CALLER, 0, &QUERY, &mut reply), Ok(REPLY_HEADER));
        assert_eq!(&reply[..REPLY_HEADER], &PARTIAL_REPLY);
        assert_eq!(&reply[REPLY_HEADER..], &[0xa5; 2]);
        let decoded = Reply::decode(&PARTIAL_REPLY).unwrap();
        assert!(decoded.output.is_empty());
        assert_eq!(decoded.new_cap_selector, 0);
    }

    #[test]
    fn receipt_key_rejects_noncanonical_size_and_identity() {
        let mut key: [u8; RECEIPT_KEY_BYTES] = QUERY[REQUEST_HEADER..].try_into().unwrap();
        let canonical = key;
        assert!(ReceiptKey::decode(&QUERY[REQUEST_HEADER - 1..]).is_err());
        assert!(ReceiptKey::decode(&QUERY[REQUEST_HEADER + 1..]).is_err());
        for range in [0..16, 16..24, 28..32, 40..48, 48..56] {
            key = canonical;
            key[range].fill(0);
            assert_eq!(ReceiptKey::decode(&key), Err(Error::Invalid));
        }
        for (offset, value) in [(24, 16), (32, 8), (44, 1), (54, 0x20)] {
            key = canonical;
            key[offset] = value;
            assert_eq!(ReceiptKey::decode(&key), Err(Error::Invalid));
        }
    }

    #[test]
    fn query_rejects_foreign_missing_and_changed_keys_without_copyout() {
        let (receipts, index) = mounted_image(4, -16);
        let view = mounted_view(&receipts, &index, UUID, CALLER.boot_epoch).unwrap();
        let mut reply = [0xa5; REPLY_HEADER];
        let mut refused = |caller, selector, request: &[u8], capacity, error| {
            assert_eq!(
                view.serve(caller, selector, request, &mut reply[..capacity]),
                Err(error)
            );
            assert_eq!(reply, [0xa5; REPLY_HEADER]);
        };

        let foreign = ReceiptQueryCaller {
            principal_id: 103,
            ..CALLER
        };
        refused(foreign, 0, &QUERY, REPLY_HEADER, Error::Unauthorized);
        let prior_boot = ReceiptQueryCaller {
            boot_epoch: 9,
            ..CALLER
        };
        refused(prior_boot, 0, &QUERY, REPLY_HEADER, Error::Stale);
        refused(CALLER, 1, &QUERY, REPLY_HEADER, Error::Unauthorized);
        refused(CALLER, 0, &QUERY, REPLY_HEADER - 1, Error::Capacity);

        for (offset, value, error) in [
            (8, 13, Error::Invalid),
            (16, 0x24, Error::Invalid),
            (REQUEST_HEADER, 0x99, Error::Unauthorized),
            (REQUEST_HEADER + 16, 6, Error::Stale),
            (REQUEST_HEADER + 16, 11, Error::Stale),
            (REQUEST_HEADER + 28, 2, Error::Stale),
            (REQUEST_HEADER + 40, 2, Error::Stale),
        ] {
            let mut query = QUERY;
            query[offset] = value;
            refused(CALLER, 0, &query, REPLY_HEADER, error);
        }
        let mut missing = QUERY;
        missing[16] = 0x24;
        missing[REQUEST_HEADER + 48] = 0x24;
        refused(CALLER, 0, &missing, REPLY_HEADER, Error::Stale);
        refused(foreign, 0, &missing, REPLY_HEADER, Error::Unauthorized);
    }

    #[test]
    fn mounted_query_rejects_torn_receipt_or_mismatched_index() {
        let (mut receipts, index) = mounted_image(4, -16);
        let mut newer_index = FileStreamIndexV4::decode(&index).unwrap();
        newer_index.generation += 1;
        newer_index.streams[STREAM_POSITION].issued_hi += 1;
        let mut newer_block = [0; BLOCK_BYTES];
        newer_index.encode_into(&mut newer_block).unwrap();

        for (data, index_block, fs_uuid, boot_epoch) in [
            (
                &receipts[..RECEIPT_STORE_BYTES - 1],
                &index[..],
                UUID,
                CALLER.boot_epoch,
            ),
            (
                &receipts[..],
                &index[..BLOCK_BYTES - 1],
                UUID,
                CALLER.boot_epoch,
            ),
            (&receipts[..], &newer_block[..], UUID, CALLER.boot_epoch),
            (&receipts[..], &index[..], [0x44; 16], CALLER.boot_epoch),
            (&receipts[..], &index[..], UUID, CALLER.boot_epoch - 1),
        ] {
            assert_eq!(
                mounted_view(data, index_block, fs_uuid, boot_epoch).err(),
                Some(Error::Invalid)
            );
        }
        receipts[BLOCK_BYTES..2 * BLOCK_BYTES].fill(0);
        assert_eq!(
            mounted_view(&receipts, &index, UUID, CALLER.boot_epoch).err(),
            Some(Error::Invalid)
        );
    }

    #[test]
    fn unknown_receipt_reply_preserves_proven_evidence() {
        for (stored, expected) in [(0, E_TIMEOUT), (-4, -4)] {
            let (receipts, index) = mounted_image(UNKNOWN, stored);
            let view = mounted_view(&receipts, &index, UUID, CALLER.boot_epoch).unwrap();
            let mut reply = [0; REPLY_HEADER];
            view.serve(CALLER, 0, &QUERY, &mut reply).unwrap();
            let decoded = Reply::decode(&reply).unwrap();
            assert_eq!((decoded.state, decoded.result), (UNKNOWN, expected));
            assert_eq!(decoded.completed_prefix, 0x0001_2345);
            assert_eq!(decoded.result_digest, [0x31; 32]);
            assert_eq!(decoded.receipt_ref, REQUEST_ID);
        }
    }

    #[test]
    fn earlier_boot_bound_receipt_requires_reconciliation() {
        let (receipts, index) = mounted_image(2, 0);
        let view = mounted_view(&receipts, &index, UUID, CALLER.boot_epoch).unwrap();
        let mut reply = [0; REPLY_HEADER];
        view.serve(CALLER, 0, &QUERY, &mut reply).unwrap();
        let decoded = Reply::decode(&reply).unwrap();
        assert_eq!((decoded.state, decoded.result), (UNKNOWN, E_TIMEOUT));
        assert_eq!(decoded.completed_prefix, 0x0001_2345);
        assert_eq!(decoded.commit_lsn, 0x0007_0605);
        assert_eq!(decoded.receipt_ref, REQUEST_ID);
    }
}
