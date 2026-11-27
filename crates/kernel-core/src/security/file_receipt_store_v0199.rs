//! V0.19.9 128 x 192-byte receipt store over exactly six 4096-byte blocks.
//!
//! Receipt records straddle home-block boundaries. A native redo transaction
//! updating one such record MUST atomically include both home blocks and the
//! FileStreamIndex, plus any necessary file/inode/bitmap updates; a per-record
//! CRC alone is not a persistence transaction. This read-only verifier
//! identifies malformed/torn receipts and the exact home-block closure.
//! Only real COMMIT + device FLUSH evidence may authorize DONE.
use super::{
    Error,
    file_index_v0199::{FileStreamIndexV4, GROUP_COUNT, STREAM_COUNT, STREAMS_PER_GROUP},
    file_media_v0199::FileReceiptV4,
};

mod reconcile;
pub use reconcile::{
    ReceiptDisposition, ReceiptRecoveryJob, ReceiptRecoveryOutcome, ReceiptRecoveryWorkspace,
    reconcile_receipt,
};

pub const RECEIPTS: usize = 128;
pub const RECEIPT_BYTES: usize = 192;
pub const BLOCK_BYTES: usize = 4096;
pub const RECEIPT_HOME_BLOCKS: usize = 6;
pub const RECEIPT_STORE_BYTES: usize = RECEIPT_HOME_BLOCKS * BLOCK_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiptHome {
    /// Index into the six-block receipt store (not disk LBA).
    pub first: usize,
    pub second: Option<usize>,
}
pub const fn receipt_home(index: usize) -> Option<ReceiptHome> {
    if index >= RECEIPTS {
        return None;
    }
    let offset = index * RECEIPT_BYTES;
    let first = offset / BLOCK_BYTES;
    let crosses = offset % BLOCK_BYTES + RECEIPT_BYTES > BLOCK_BYTES;
    Some(ReceiptHome {
        first,
        second: if crosses { Some(first + 1) } else { None },
    })
}
/// Exact bounded unique home blocks required for one receipt plus the index.
/// Caller is responsible for mapping relative homes to actual native LBAs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HomeClosure {
    pub receipt: ReceiptHome,
    /// If the receipt crosses blocks, the second home is compulsory.
    pub receipt_block_count: usize,
    pub requires_stream_index_block: bool,
}
pub const fn home_closure(index: usize) -> Option<HomeClosure> {
    match receipt_home(index) {
        Some(home) => Some(HomeClosure {
            receipt: home,
            receipt_block_count: if home.second.is_some() { 2 } else { 1 },
            requires_stream_index_block: true,
        }),
        None => None,
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiptStoreSummary {
    pub occupied: usize,
    pub unresolved: usize,
    pub across_block: usize,
}
/// Uses a stable, already copied six-block native storage snapshot; never
/// interprets a partially copied buffer as a clean receipt store.
pub fn scan_receipts(
    data: &[u8],
    expected_fs_uuid: [u8; 16],
) -> Result<ReceiptStoreSummary, Error> {
    scan_receipts_inner(data, expected_fs_uuid, None)
}

/// Validate a complete, stable, jointly copied receipt/index image before
/// writable recovery. This is a read-only consistency check, NOT authorization
/// to mount or a substitute for verified redo, FLUSH, and commit ordering.
/// Old group generations remain queryable by full key and permanent principal;
/// a stream with retained records must not have been reused.
pub fn scan_receipts_with_index(
    data: &[u8],
    index_block: &[u8],
    expected_fs_uuid: [u8; 16],
) -> Result<ReceiptStoreSummary, Error> {
    let index = FileStreamIndexV4::decode(index_block)?;
    if index.fs_uuid != expected_fs_uuid {
        return Err(Error::Invalid);
    }
    scan_receipts_inner(data, expected_fs_uuid, Some(&index))
}

fn scan_receipts_inner(
    data: &[u8],
    expected_fs_uuid: [u8; 16],
    index: Option<&FileStreamIndexV4>,
) -> Result<ReceiptStoreSummary, Error> {
    if data.len() != RECEIPT_STORE_BYTES || expected_fs_uuid == [0; 16] {
        return Err(Error::Invalid);
    }
    let mut summary = ReceiptStoreSummary {
        occupied: 0,
        unresolved: 0,
        across_block: 0,
    };
    let mut stream_counts = [0u8; STREAM_COUNT];
    let mut inflight = [false; STREAM_COUNT];
    let mut group_counts = [0u8; GROUP_COUNT];
    let mut request_ids = [0u64; RECEIPTS];
    for slot in 0..RECEIPTS {
        let at = slot * RECEIPT_BYTES;
        let raw = &data[at..at + RECEIPT_BYTES];
        if raw.iter().all(|byte| *byte == 0) {
            continue; // explicitly unallocated slot
        }
        let record = FileReceiptV4::decode(raw)?;
        if record.fs_uuid != expected_fs_uuid {
            return Err(Error::Invalid);
        }
        // Decode enforces the canonical, injective local ID of
        // (group, stream, sequence). Equal full keys therefore imply equal
        // IDs, and IDs must also be unique across retained generations.
        request_ids[summary.occupied] = record.request_id;
        if let Some(index) = index {
            let group_at = record.group_id as usize;
            let stream_at = group_at * STREAMS_PER_GROUP + record.stream_slot as usize;
            let group = &index.groups[group_at];
            let stream = &index.streams[stream_at];
            if group.flags == 0
                || stream.flags == 0
                || record.owner_principal_id != group.manifest_principal_id
                || record.group_generation > group.generation
                || record.issued_boot_epoch > group.boot_epoch
                || (record.group_generation == group.generation
                    && record.issued_boot_epoch != group.boot_epoch)
                || record.stream_generation != u64::from(stream.generation)
                || record.request_seq <= stream.retired_through
                || record.request_seq > stream.issued_hi
            {
                return Err(Error::Invalid);
            }
            stream_counts[stream_at] = stream_counts[stream_at]
                .checked_add(1)
                .ok_or(Error::Invalid)?;
            group_counts[group_at] = group_counts[group_at]
                .checked_add(1)
                .ok_or(Error::Invalid)?;
            if usize::from(group_counts[group_at]) > STREAMS_PER_GROUP {
                return Err(Error::Invalid);
            }
            // UNKNOWN may still own the original execution. It is not a
            // terminal predecessor and cannot coexist with a second inflight
            // request in the same stream.
            if matches!(record.status, 1 | 2 | 5) {
                if inflight[stream_at] || record.request_seq != stream.issued_hi {
                    return Err(Error::Invalid);
                }
                inflight[stream_at] = true;
            }
        }
        summary.occupied += 1;
        if matches!(record.status, 1 | 2 | 5) {
            summary.unresolved += 1;
        }
        if receipt_home(slot).ok_or(Error::Invalid)?.second.is_some() {
            summary.across_block += 1;
        }
    }
    // All keys here are fully decoded. Sort only the occupied prefix;
    // the original receipt slots, CRCs and index image remain untouched.
    let keys = &mut request_ids[..summary.occupied];
    keys.sort_unstable();
    if keys.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(Error::Invalid);
    }
    if let Some(index) = index {
        // Distinct in-range request IDs plus exact cardinality proves every
        // unretired sequence is present; never iterate a corrupt u64 range.
        for (at, stream) in index.streams.iter().enumerate() {
            if stream.issued_hi - stream.retired_through != u64::from(stream_counts[at]) {
                return Err(Error::Invalid);
            }
        }
    }
    Ok(summary)
}

/// Exact bounded single-receipt retirement projection. A successful
/// structural check does not itself ACK a request or prove media FLUSH.
/// The serialized native file owner must authenticate the actual principal,
/// the exact terminal receipt, current mounted transaction and durable
/// after-images of all required homes. No unrelated receipt/index mutation
/// is admitted by this deliberately narrow retirement path.
#[allow(clippy::too_many_arguments)]
pub fn verify_single_ack_transition(
    before: &[u8],
    after: &[u8],
    old_index: &[u8],
    new_index: &[u8],
    uuid: [u8; 16],
    slot: usize,
    principal: u64,
    actual_receipt_homes: &[usize],
    includes_index: bool,
    verify_commit: impl FnOnce(&FileReceiptV4, HomeClosure) -> Result<(), Error>,
) -> Result<(), Error> {
    let closure = home_closure(slot).ok_or(Error::Invalid)?;
    if !includes_index
        || actual_receipt_homes.len() != closure.receipt_block_count
        || actual_receipt_homes.first() != Some(&closure.receipt.first)
        || closure
            .receipt
            .second
            .is_some_and(|h| actual_receipt_homes.get(1) != Some(&h))
    {
        return Err(Error::Conflict);
    }
    scan_receipts_with_index(before, old_index, uuid)?;
    scan_receipts_with_index(after, new_index, uuid)?;
    let at = slot * RECEIPT_BYTES;
    let r = FileReceiptV4::decode(&before[at..at + RECEIPT_BYTES])?;
    if principal == 0 || r.owner_principal_id != principal {
        return Err(Error::Unauthorized);
    }
    if !matches!(r.status, 3 | 4 | 6) {
        return Err(Error::Busy);
    }
    if after[at..at + RECEIPT_BYTES].iter().any(|&v| v != 0)
        || before[..at] != after[..at]
        || before[at + RECEIPT_BYTES..] != after[at + RECEIPT_BYTES..]
    {
        return Err(Error::Conflict);
    }
    let mut expected = FileStreamIndexV4::decode(old_index)?;
    let stream =
        &mut expected.streams[r.group_id as usize * STREAMS_PER_GROUP + r.stream_slot as usize];
    if stream.retired_through.checked_add(1) != Some(r.request_seq) {
        return Err(Error::Conflict);
    }
    stream.retired_through = r.request_seq;
    expected.generation = expected.generation.checked_add(1).ok_or(Error::Exhausted)?;
    if FileStreamIndexV4::decode(new_index)? != expected {
        return Err(Error::Conflict);
    }
    verify_commit(&r, closure)
}

/// Actual baseline-v1 journal proof for a single ACK. Map all six logical
/// receipt blocks and the index through the independently authenticated
/// current file inode/extent owner. Require ALL affected after-images in
/// one complete transaction, with no unrelated home. No writer runs here.
#[allow(clippy::too_many_arguments)]
pub fn verify_single_ack_redo(
    before: &[u8],
    after: &[u8],
    old_index: &[u8],
    new_index: &[u8],
    superblock_raw: &[u8],
    receipt_homes: [u32; RECEIPT_HOME_BLOCKS],
    index_home: u32,
    slot: usize,
    principal: u64,
    first: u32,
    begin: &[u8],
    redos: &[&[u8]],
    commit: &[u8],
    txid: u64,
    commit_lsn: u64,
    verify_native: impl FnOnce(
        &FileReceiptV4,
        [u32; RECEIPT_HOME_BLOCKS],
        u32,
        u64,
        u64,
    ) -> Result<(), Error>,
) -> Result<(), Error> {
    use super::file_media_v0199::{BLOCK_COUNT, DATA_START, SuperblockV1, verify_state_redo_v1};
    let sb = SuperblockV1::decode(superblock_raw)?;
    if !(DATA_START..BLOCK_COUNT).contains(&index_home) {
        return Err(Error::Invalid);
    }
    for (i, &home) in receipt_homes.iter().enumerate() {
        if !(DATA_START..BLOCK_COUNT).contains(&home)
            || home == index_home
            || receipt_homes[..i].contains(&home)
        {
            return Err(Error::Conflict);
        }
    }
    let closure = home_closure(slot).ok_or(Error::Invalid)?;
    let logical = [
        closure.receipt.first,
        closure.receipt.second.unwrap_or(closure.receipt.first),
    ];
    let n = closure.receipt_block_count;
    if redos.len() != n + 1 {
        return Err(Error::Conflict);
    }
    verify_single_ack_transition(
        before,
        after,
        old_index,
        new_index,
        sb.fs_uuid,
        slot,
        principal,
        &logical[..n],
        true,
        |r, _| {
            for &i in &logical[..n] {
                let image = &after[i * BLOCK_BYTES..(i + 1) * BLOCK_BYTES];
                verify_state_redo_v1(
                    sb,
                    first,
                    u64::from(receipt_homes[i]),
                    begin,
                    redos,
                    commit,
                    image,
                    txid,
                    commit_lsn,
                )?;
            }
            verify_state_redo_v1(
                sb,
                first,
                u64::from(index_home),
                begin,
                redos,
                commit,
                new_index,
                txid,
                commit_lsn,
            )?;
            // Mandatory proof of current mapping, exact complete COMMIT and
            // actual device FLUSH; matching bytes alone are not durable proof.
            verify_native(r, receipt_homes, index_home, txid, commit_lsn)
        },
    )
}

#[cfg(test)]
mod tests {
    use super::super::file_media_v0199::{crc32c_zeroed, local_request_id};
    use super::*;

    fn receipt(id: u64, seq: u64) -> [u8; RECEIPT_BYTES] {
        let mut b = [0u8; RECEIPT_BYTES];
        b[0..4].copy_from_slice(&0x4359_5243u32.to_le_bytes());
        b[4..6].copy_from_slice(&4u16.to_le_bytes());
        b[6..8].copy_from_slice(&(RECEIPT_BYTES as u16).to_le_bytes());
        b[8..24].copy_from_slice(&[1u8; 16]);
        b[24..32].copy_from_slice(&1u64.to_le_bytes());
        b[36..40].copy_from_slice(&1u32.to_le_bytes());
        b[48..56].copy_from_slice(&1u64.to_le_bytes());
        b[56..64].copy_from_slice(&seq.to_le_bytes());
        b[96..98].copy_from_slice(&1u16.to_le_bytes());
        b[172..180].copy_from_slice(&id.to_le_bytes());
        b[180..188].copy_from_slice(&2u64.to_le_bytes());
        let crc = crc32c_zeroed(&b, 188).unwrap();
        b[188..192].copy_from_slice(&crc.to_le_bytes());
        b
    }
    #[test]
    fn every_cross_block_receipt_requires_both_home_blocks_and_index() {
        let across = [21, 42, 85, 106];
        let mut found = 0;
        for i in 0..RECEIPTS {
            let closure = home_closure(i).unwrap();
            assert!(closure.requires_stream_index_block);
            assert!(closure.receipt.first < RECEIPT_HOME_BLOCKS);
            if let Some(other) = closure.receipt.second {
                found += 1;
                assert_eq!(other, closure.receipt.first + 1);
                assert!(across.contains(&i));
                assert_eq!(closure.receipt_block_count, 2);
            } else {
                assert_eq!(closure.receipt_block_count, 1);
            }
        }
        assert_eq!(found, 4);
        assert_eq!(home_closure(RECEIPTS), None);
    }
    #[test]
    fn clean_store_and_frozen_cross_block_receipts_are_decoded_as_one_record() {
        let mut data = [0u8; RECEIPT_STORE_BYTES];
        assert_eq!(scan_receipts(&data, [1; 16]).unwrap().occupied, 0);
        for (index, seq) in [(21usize, 1u64), (42, 2), (85, 3), (106, 4)] {
            let at = index * RECEIPT_BYTES;
            data[at..at + RECEIPT_BYTES]
                .copy_from_slice(&receipt(local_request_id(0, 0, seq).unwrap(), seq));
        }
        let result = scan_receipts(&data, [1; 16]).unwrap();
        assert_eq!(result.occupied, 4);
        assert_eq!(result.unresolved, 4);
        assert_eq!(result.across_block, 4);
        assert!(scan_receipts(&data, [2; 16]).is_err());
        // Simulate second-home tearing at a straddling record; CRC must fail.
        let torn = 21 * RECEIPT_BYTES + RECEIPT_BYTES - 1;
        data[torn] ^= 1;
        assert!(scan_receipts(&data, [1; 16]).is_err());
    }
    #[test]
    fn conflicting_receipt_keys_and_short_staging_are_rejected() {
        let mut data = [0u8; RECEIPT_STORE_BYTES];
        data[..RECEIPT_BYTES].copy_from_slice(&receipt(local_request_id(0, 0, 1).unwrap(), 1));
        let at = RECEIPT_BYTES;
        data[at..at + RECEIPT_BYTES]
            .copy_from_slice(&receipt(local_request_id(0, 0, 1).unwrap(), 2));
        assert!(scan_receipts(&data, [1; 16]).is_err()); // inconsistent local ID
        data[at..at + RECEIPT_BYTES]
            .copy_from_slice(&receipt(local_request_id(0, 0, 1).unwrap(), 1));
        assert!(scan_receipts(&data, [1; 16]).is_err()); // duplicate canonical full stream key
        data[at..at + RECEIPT_BYTES]
            .copy_from_slice(&receipt(local_request_id(0, 0, 2).unwrap(), 2));
        assert!(scan_receipts(&data, [1; 16]).is_ok());
        assert!(scan_receipts(&data[..RECEIPT_STORE_BYTES - 1], [1; 16]).is_err());
    }
    #[test]
    fn full_store_rejects_duplicate_local_id_across_different_generations() {
        let mut data = [0u8; RECEIPT_STORE_BYTES];
        for (slot, raw) in data.chunks_exact_mut(RECEIPT_BYTES).enumerate() {
            let seq = (RECEIPTS - slot) as u64;
            raw.copy_from_slice(&receipt(local_request_id(0, 0, seq).unwrap(), seq));
        }
        let expected = ReceiptStoreSummary {
            occupied: RECEIPTS,
            unresolved: RECEIPTS,
            across_block: 4,
        };
        assert_eq!(scan_receipts(&data, [1; 16]), Ok(expected));
        let mut duplicate = receipt(local_request_id(0, 0, 1).unwrap(), 1);
        duplicate[24..32].copy_from_slice(&2u64.to_le_bytes());
        duplicate[36..40].copy_from_slice(&2u32.to_le_bytes());
        duplicate[48..56].copy_from_slice(&2u64.to_le_bytes());
        reseal(&mut duplicate);
        assert!(FileReceiptV4::decode(&duplicate).is_ok());
        data[..RECEIPT_BYTES].copy_from_slice(&duplicate);
        assert_eq!(scan_receipts(&data, [1; 16]), Err(Error::Invalid));
        let seq = RECEIPTS as u64;
        data[..RECEIPT_BYTES].copy_from_slice(&receipt(local_request_id(0, 0, seq).unwrap(), seq));
        assert_eq!(scan_receipts(&data, [1; 16]), Ok(expected));
        data[RECEIPT_STORE_BYTES - 1] ^= 1;
        assert_eq!(scan_receipts(&data, [1; 16]), Err(Error::Invalid));
    }

    fn strict_index(issued: u64, retired: u64) -> [u8; BLOCK_BYTES] {
        use super::super::file_index_v0199::{
            CRC_OFFSET, INDEX_HEADER, INDEX_MAGIC, INDEX_VERSION, STREAM_BASE,
        };
        let mut b = [0; BLOCK_BYTES];
        b[0..4].copy_from_slice(&INDEX_MAGIC.to_le_bytes());
        b[4..6].copy_from_slice(&INDEX_VERSION.to_le_bytes());
        b[6..8].copy_from_slice(&(INDEX_HEADER as u16).to_le_bytes());
        b[8..24].copy_from_slice(&[1; 16]);
        b[32..40].copy_from_slice(&1u64.to_le_bytes());
        for group in 0..GROUP_COUNT {
            let at = INDEX_HEADER + group * 24;
            b[at + 16..at + 24].copy_from_slice(&(group as u64 + 2).to_le_bytes());
        }
        b[64..68].copy_from_slice(&1u32.to_le_bytes());
        b[68..72].copy_from_slice(&1u32.to_le_bytes());
        b[72..80].copy_from_slice(&1u64.to_le_bytes());
        b[STREAM_BASE..STREAM_BASE + 4].copy_from_slice(&1u32.to_le_bytes());
        b[STREAM_BASE + 4..STREAM_BASE + 8].copy_from_slice(&1u32.to_le_bytes());
        b[STREAM_BASE + 8..STREAM_BASE + 16].copy_from_slice(&issued.to_le_bytes());
        b[STREAM_BASE + 16..STREAM_BASE + 24].copy_from_slice(&retired.to_le_bytes());
        let crc = crc32c_zeroed(&b, CRC_OFFSET).unwrap();
        b[CRC_OFFSET..].copy_from_slice(&crc.to_le_bytes());
        b
    }
    fn reseal(raw: &mut [u8]) {
        let crc = crc32c_zeroed(raw, 188).unwrap();
        raw[188..192].copy_from_slice(&crc.to_le_bytes());
    }
    #[test]
    fn exact_ack_redo_requires_all_three_actual_home_images() {
        use super::super::file_index_v0199::CRC_OFFSET;
        use sha2::{Digest, Sha256};
        fn p16(b: &mut [u8], i: usize, v: u16) {
            b[i..i + 2].copy_from_slice(&v.to_le_bytes());
        }
        fn p32(b: &mut [u8], i: usize, v: u32) {
            b[i..i + 4].copy_from_slice(&v.to_le_bytes());
        }
        fn p64(b: &mut [u8], i: usize, v: u64) {
            b[i..i + 8].copy_from_slice(&v.to_le_bytes());
        }
        fn seal(b: &mut [u8], kind: u16, n: usize, lsn: u64) {
            p32(b, 0, 0x43594c47);
            p16(b, 4, 1);
            p16(b, 6, kind);
            p32(b, 8, n as u32);
            p64(b, 16, 1);
            p64(b, 24, lsn);
            p64(b, 32, 1);
            let crc = cyxia_prototype::storage::crc32c(&b[64..n]);
            p32(b, 12, crc);
            let crc = crc32c_zeroed(&b[..64], 56).unwrap();
            p32(b, 56, crc);
        }
        let mut sb = [0; BLOCK_BYTES];
        p32(&mut sb, 0, 0x43594653);
        p16(&mut sb, 4, 1);
        p16(&mut sb, 6, 80);
        p32(&mut sb, 8, 4096);
        p32(&mut sb, 12, 131072);
        sb[16..32].fill(1);
        p64(&mut sb, 32, 1);
        p64(&mut sb, 48, 1);
        for (at, v) in [(56, 4098), (60, 4102), (64, 4118), (68, 256)] {
            p32(&mut sb, at, v);
        }
        let crc = crc32c_zeroed(&sb, 76).unwrap();
        p32(&mut sb, 76, crc);
        let mut before = [0u8; RECEIPT_STORE_BYTES];
        let at = 21 * RECEIPT_BYTES;
        let mut raw = receipt((1u64 << 56) | 2, 2);
        p16(&mut raw, 96, 3);
        raw[108] = 1;
        reseal(&mut raw);
        before[at..at + RECEIPT_BYTES].copy_from_slice(&raw);
        let old = strict_index(2, 1);
        let mut new = strict_index(2, 2);
        p64(&mut new, 32, 2);
        let crc = crc32c_zeroed(&new, CRC_OFFSET).unwrap();
        p32(&mut new, CRC_OFFSET, crc);
        let after = [0u8; RECEIPT_STORE_BYTES];
        let homes = [7000, 7001, 7002, 7003, 7004, 7005];
        let mut begin = [0; 4096];
        p32(&mut begin, 64, 3);
        p64(&mut begin, 72, 12288);
        seal(&mut begin, 1, 80, 1);
        let redos: [[u8; 8192]; 3] = core::array::from_fn(|i| {
            let mut b = [0; 8192];
            p64(&mut b, 40, u64::from(if i == 2 { 7010 } else { homes[i] }));
            p32(&mut b, 48, i as u32);
            p32(&mut b, 52, 3);
            if i == 2 {
                b[64..4160].copy_from_slice(&new);
            }
            seal(&mut b, 2, 4160, 2 + i as u64);
            b
        });
        let mut commit = [0; 4096];
        p64(&mut commit, 64, 1);
        p64(&mut commit, 72, 1);
        p64(&mut commit, 80, 4);
        p32(&mut commit, 88, 3);
        let mut h = Sha256::new();
        for b in &redos {
            h.update(&b[40..48]);
            h.update(&b[64..4160]);
        }
        commit[96..128].copy_from_slice(&h.finalize());
        seal(&mut commit, 3, 128, 5);
        let refs: [&[u8]; 3] = [&redos[0], &redos[1], &redos[2]];
        assert_eq!(
            verify_single_ack_redo(
                &before,
                &after,
                &old,
                &new,
                &sb,
                homes,
                7010,
                21,
                2,
                2,
                &begin,
                &refs[..2],
                &commit,
                1,
                5,
                |_, _, _, _, _| panic!()
            ),
            Err(Error::Conflict)
        );
        let bad = [7000, 7006, 7002, 7003, 7004, 7005];
        assert_eq!(
            verify_single_ack_redo(
                &before,
                &after,
                &old,
                &new,
                &sb,
                bad,
                7010,
                21,
                2,
                2,
                &begin,
                &refs,
                &commit,
                1,
                5,
                |_, _, _, _, _| panic!()
            ),
            Err(Error::Conflict)
        );
        assert_eq!(
            verify_single_ack_redo(
                &before,
                &after,
                &old,
                &new,
                &sb,
                homes,
                7010,
                21,
                2,
                2,
                &begin,
                &refs,
                &commit,
                1,
                5,
                |_, _, _, _, _| Err(Error::Unknown)
            ),
            Err(Error::Unknown)
        );
        verify_single_ack_redo(
            &before,
            &after,
            &old,
            &new,
            &sb,
            homes,
            7010,
            21,
            2,
            2,
            &begin,
            &refs,
            &commit,
            1,
            5,
            |r, map, index, t, l| {
                assert_eq!(r.request_seq, 2);
                assert_eq!((map, index, t, l), (homes, 7010, 1, 5));
                Ok(())
            },
        )
        .unwrap();
    }
    #[test]
    fn exact_cross_home_ack_requires_terminal_principal_and_only_one_watermark() {
        use super::super::file_index_v0199::CRC_OFFSET;
        let mut before = [0u8; RECEIPT_STORE_BYTES];
        let at = 21 * RECEIPT_BYTES;
        let mut raw = receipt((1u64 << 56) | 2, 2);
        raw[96..98].copy_from_slice(&3u16.to_le_bytes());
        raw[108] = 1;
        reseal(&mut raw);
        before[at..at + RECEIPT_BYTES].copy_from_slice(&raw);
        let old = strict_index(2, 1);
        let mut new = strict_index(2, 2);
        new[32..40].copy_from_slice(&2u64.to_le_bytes());
        let crc = crc32c_zeroed(&new, CRC_OFFSET).unwrap();
        new[CRC_OFFSET..].copy_from_slice(&crc.to_le_bytes());
        let after = [0u8; RECEIPT_STORE_BYTES];
        assert_eq!(
            verify_single_ack_transition(
                &before,
                &after,
                &old,
                &new,
                [1; 16],
                21,
                2,
                &[0],
                true,
                |_, _| panic!()
            ),
            Err(Error::Conflict)
        );
        assert_eq!(
            verify_single_ack_transition(
                &before,
                &after,
                &old,
                &new,
                [1; 16],
                21,
                3,
                &[0, 1],
                true,
                |_, _| panic!()
            ),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            verify_single_ack_transition(
                &before,
                &after,
                &old,
                &new,
                [1; 16],
                21,
                2,
                &[0, 1],
                true,
                |_, _| Err(Error::Unknown)
            ),
            Err(Error::Unknown)
        );
        verify_single_ack_transition(
            &before,
            &after,
            &old,
            &new,
            [1; 16],
            21,
            2,
            &[0, 1],
            true,
            |r, c| {
                assert_eq!(r.request_seq, 2);
                assert_eq!(c.receipt_block_count, 2);
                Ok(())
            },
        )
        .unwrap();
        raw[96..98].copy_from_slice(&5u16.to_le_bytes());
        reseal(&mut raw);
        before[at..at + RECEIPT_BYTES].copy_from_slice(&raw);
        assert_eq!(
            verify_single_ack_transition(
                &before,
                &after,
                &old,
                &new,
                [1; 16],
                21,
                2,
                &[0, 1],
                true,
                |_, _| panic!()
            ),
            Err(Error::Busy)
        );
    }
    #[test]
    fn joint_receipt_index_rejects_gap_retired_or_forged_identity() {
        let mut data = [0u8; RECEIPT_STORE_BYTES];
        let at = 21 * RECEIPT_BYTES;
        let raw = receipt((1u64 << 56) | 2, 2);
        data[at..at + RECEIPT_BYTES].copy_from_slice(&raw);
        let index = strict_index(2, 1);
        assert_eq!(
            scan_receipts_with_index(&data, &index, [1; 16])
                .unwrap()
                .across_block,
            1
        );
        assert!(scan_receipts_with_index(&data, &strict_index(3, 1), [1; 16]).is_err());
        assert!(scan_receipts_with_index(&data, &strict_index(2, 2), [1; 16]).is_err());
        assert!(
            scan_receipts_with_index(&data, &strict_index((1u64 << 53) - 1, 0), [1; 16]).is_err()
        );
        for (offset, value) in [(172usize, 9u8), (180, 3), (48, 2), (36, 2), (24, 2)] {
            data[at..at + RECEIPT_BYTES].copy_from_slice(&raw);
            data[at + offset] = value;
            reseal(&mut data[at..at + RECEIPT_BYTES]);
            assert!(
                scan_receipts_with_index(&data, &index, [1; 16]).is_err(),
                "offset {offset}"
            );
        }
        data[at..at + RECEIPT_BYTES].copy_from_slice(&raw);
        data[..RECEIPT_BYTES].copy_from_slice(&receipt((1u64 << 56) | 1, 1));
        assert!(scan_receipts_with_index(&data, &strict_index(2, 0), [1; 16]).is_err());
        // UNKNOWN is unresolved even if its binding digest is present.
        data[96..98].copy_from_slice(&5u16.to_le_bytes());
        data[108] = 1;
        reseal(&mut data[..RECEIPT_BYTES]);
        assert!(scan_receipts_with_index(&data, &strict_index(2, 0), [1; 16]).is_err());
        // A bound, proven terminal predecessor can coexist with one pending.
        data[96..98].copy_from_slice(&3u16.to_le_bytes());
        data[108] = 1;
        reseal(&mut data[..RECEIPT_BYTES]);
        assert_eq!(
            scan_receipts_with_index(&data, &strict_index(2, 0), [1; 16])
                .unwrap()
                .occupied,
            2
        );
        data[96..98].copy_from_slice(&5u16.to_le_bytes());
        reseal(&mut data[..RECEIPT_BYTES]);
        data[at + 96..at + 98].copy_from_slice(&3u16.to_le_bytes());
        data[at + 108] = 1;
        reseal(&mut data[at..at + RECEIPT_BYTES]);
        assert!(scan_receipts_with_index(&data, &strict_index(2, 0), [1; 16]).is_err());
    }
}
