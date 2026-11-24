//! V0.19.9 128 x 192-byte receipt store over exactly six 4096-byte blocks.
//!
//! Receipt records straddle home-block boundaries. A native redo transaction
//! updating one such record MUST atomically include both home blocks and the
//! FileStreamIndex, plus any necessary file/inode/bitmap updates; a per-record
//! CRC alone is not a persistence transaction. This read-only verifier
//! identifies malformed/torn receipts and the exact home-block closure.
//! Only real COMMIT + device FLUSH evidence may authorize DONE.
use super::{Error, file_media_v0199::FileReceiptV4, file_index_v0199::{FileStreamIndexV4, GROUP_COUNT, STREAM_COUNT, STREAMS_PER_GROUP}};

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
    if index >= RECEIPTS { return None; }
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
    let mut summary=ReceiptStoreSummary {
        occupied:0, unresolved:0, across_block:0,
    };
    let mut stream_counts = [0u8; STREAM_COUNT];
    let mut inflight = [false; STREAM_COUNT];
    let mut group_counts = [0u8; GROUP_COUNT];
    for slot in 0..RECEIPTS {
        let at=slot*RECEIPT_BYTES;
        let raw=&data[at..at+RECEIPT_BYTES];
        if raw.iter().all(|byte|*byte==0) {
            continue; // explicitly unallocated slot
        }
        let record=FileReceiptV4::decode(raw)?;
        if record.fs_uuid!=expected_fs_uuid {
            return Err(Error::Invalid);
        }
        // Earlier records were either all-zero or fully decoded, including
        // their CRC. Rechecking their canonical LE identity bytes avoids
        // O(N^2) repeated CRC work without allocating a second receipt table.
        for previous in 0..slot {
            let offset=previous*RECEIPT_BYTES;
            let earlier=&data[offset..offset+RECEIPT_BYTES];
            if earlier[172..180] == [0; 8] { continue; }
            if earlier[172..180] == raw[172..180] || earlier[8..64] == raw[8..64] {
                return Err(Error::Invalid);
            }
        }
        if let Some(index) = index {
            let group_at = record.group_id as usize;
            let stream_at = group_at * STREAMS_PER_GROUP + record.stream_slot as usize;
            let group = &index.groups[group_at];
            let stream = &index.streams[stream_at];
            let expected_id = ((u64::from(record.group_id) + 1) << 56)
                | (record.stream_slot << 53) | record.request_seq;
            if record.request_id != expected_id
                || group.flags == 0 || stream.flags == 0
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
            stream_counts[stream_at] = stream_counts[stream_at].checked_add(1).ok_or(Error::Invalid)?;
            group_counts[group_at] = group_counts[group_at].checked_add(1).ok_or(Error::Invalid)?;
            if usize::from(group_counts[group_at]) > STREAMS_PER_GROUP {
                return Err(Error::Invalid);
            }
            if matches!(record.status, 1 | 2) {
                if inflight[stream_at] { return Err(Error::Invalid); }
                inflight[stream_at] = true;
            }
        }
        summary.occupied+=1;
        if matches!(record.status,1|2|5) {
            summary.unresolved+=1;
        }
        if receipt_home(slot).ok_or(Error::Invalid)?.second.is_some() {
            summary.across_block+=1;
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::file_media_v0199::crc32c_zeroed;

    fn receipt(id:u64,seq:u64)->[u8;RECEIPT_BYTES]{
        let mut b=[0u8;RECEIPT_BYTES];
        b[0..4].copy_from_slice(&0x4359_5243u32.to_le_bytes());
        b[4..6].copy_from_slice(&4u16.to_le_bytes());
        b[6..8].copy_from_slice(&(RECEIPT_BYTES as u16).to_le_bytes());
        b[8..24].copy_from_slice(&[1u8;16]);
        b[24..32].copy_from_slice(&1u64.to_le_bytes());
        b[36..40].copy_from_slice(&1u32.to_le_bytes());
        b[48..56].copy_from_slice(&1u64.to_le_bytes());
        b[56..64].copy_from_slice(&seq.to_le_bytes());
        b[96..98].copy_from_slice(&1u16.to_le_bytes());
        b[172..180].copy_from_slice(&id.to_le_bytes());
        b[180..188].copy_from_slice(&2u64.to_le_bytes());
        let crc=crc32c_zeroed(&b,188).unwrap();
        b[188..192].copy_from_slice(&crc.to_le_bytes());
        b
    }
    #[test]
    fn every_cross_block_receipt_requires_both_home_blocks_and_index(){
        let across=[21,42,85,106];
        let mut found=0;
        for i in 0..RECEIPTS {
            let closure=home_closure(i).unwrap();
            assert!(closure.requires_stream_index_block);
            assert!(closure.receipt.first<RECEIPT_HOME_BLOCKS);
            if let Some(other)=closure.receipt.second {
                found+=1;
                assert_eq!(other,closure.receipt.first+1);
                assert!(across.contains(&i));
                assert_eq!(closure.receipt_block_count,2);
            }else{
                assert_eq!(closure.receipt_block_count,1);
            }
        }
        assert_eq!(found,4);
        assert_eq!(home_closure(RECEIPTS),None);
    }
    #[test]
    fn clean_store_and_frozen_cross_block_receipts_are_decoded_as_one_record(){
        let mut data=[0u8;RECEIPT_STORE_BYTES];
        assert_eq!(scan_receipts(&data,[1;16]).unwrap().occupied,0);
        for (index,seq) in [(21usize,1u64),(42,2),(85,3),(106,4)] {
            let at=index*RECEIPT_BYTES;
            data[at..at+RECEIPT_BYTES].copy_from_slice(&receipt(seq,seq));
        }
        let result=scan_receipts(&data,[1;16]).unwrap();
        assert_eq!(result.occupied,4);
        assert_eq!(result.unresolved,4);
        assert_eq!(result.across_block,4);
        assert!(scan_receipts(&data,[2;16]).is_err());
        // Simulate second-home tearing at a straddling record; CRC must fail.
        let torn=21*RECEIPT_BYTES+RECEIPT_BYTES-1;
        data[torn]^=1;
        assert!(scan_receipts(&data,[1;16]).is_err());
    }
    #[test]
    fn conflicting_receipt_keys_and_short_staging_are_rejected(){
        let mut data=[0u8;RECEIPT_STORE_BYTES];
        data[..RECEIPT_BYTES].copy_from_slice(&receipt(7,1));
        let at=RECEIPT_BYTES;
        data[at..at+RECEIPT_BYTES].copy_from_slice(&receipt(7,2));
        assert!(scan_receipts(&data,[1;16]).is_err()); // duplicate local ID
        data[at..at+RECEIPT_BYTES].copy_from_slice(&receipt(8,1));
        assert!(scan_receipts(&data,[1;16]).is_err()); // duplicate full stream key
        data[at..at+RECEIPT_BYTES].copy_from_slice(&receipt(8,2));
        assert!(scan_receipts(&data,[1;16]).is_ok());
        assert!(scan_receipts(&data[..RECEIPT_STORE_BYTES-1],[1;16]).is_err());
    }
    fn strict_index(issued: u64, retired: u64) -> [u8; BLOCK_BYTES] {
        use super::super::file_index_v0199::{INDEX_MAGIC, INDEX_VERSION, INDEX_HEADER, STREAM_BASE, CRC_OFFSET};
        let mut b = [0; BLOCK_BYTES];
        b[0..4].copy_from_slice(&INDEX_MAGIC.to_le_bytes());
        b[4..6].copy_from_slice(&INDEX_VERSION.to_le_bytes());
        b[6..8].copy_from_slice(&(INDEX_HEADER as u16).to_le_bytes());
        b[8..24].copy_from_slice(&[1;16]);
        b[32..40].copy_from_slice(&1u64.to_le_bytes());
        for group in 0..GROUP_COUNT {
            let at=INDEX_HEADER+group*24;
            b[at+16..at+24].copy_from_slice(&(group as u64+2).to_le_bytes());
        }
        b[64..68].copy_from_slice(&1u32.to_le_bytes());
        b[68..72].copy_from_slice(&1u32.to_le_bytes());
        b[72..80].copy_from_slice(&1u64.to_le_bytes());
        b[STREAM_BASE..STREAM_BASE+4].copy_from_slice(&1u32.to_le_bytes());
        b[STREAM_BASE+4..STREAM_BASE+8].copy_from_slice(&1u32.to_le_bytes());
        b[STREAM_BASE+8..STREAM_BASE+16].copy_from_slice(&issued.to_le_bytes());
        b[STREAM_BASE+16..STREAM_BASE+24].copy_from_slice(&retired.to_le_bytes());
        let crc=crc32c_zeroed(&b,CRC_OFFSET).unwrap();
        b[CRC_OFFSET..].copy_from_slice(&crc.to_le_bytes());
        b
    }
    fn reseal(raw: &mut [u8]) {
        let crc=crc32c_zeroed(raw,188).unwrap();
        raw[188..192].copy_from_slice(&crc.to_le_bytes());
    }
    #[test]
    fn joint_receipt_index_rejects_gap_retired_or_forged_identity() {
        let mut data=[0u8;RECEIPT_STORE_BYTES];
        let at=21*RECEIPT_BYTES;
        let raw=receipt((1u64<<56)|2,2);
        data[at..at+RECEIPT_BYTES].copy_from_slice(&raw);
        let index=strict_index(2,1);
        assert_eq!(scan_receipts_with_index(&data,&index,[1;16]).unwrap().across_block,1);
        assert!(scan_receipts_with_index(&data,&strict_index(3,1),[1;16]).is_err());
        assert!(scan_receipts_with_index(&data,&strict_index(2,2),[1;16]).is_err());
        assert!(scan_receipts_with_index(&data,&strict_index((1u64<<53)-1,0),[1;16]).is_err());
        for (offset,value) in [(172usize,9u8),(180,3),(48,2),(36,2),(24,2)] {
            data[at..at+RECEIPT_BYTES].copy_from_slice(&raw);
            data[at+offset]=value;
            reseal(&mut data[at..at+RECEIPT_BYTES]);
            assert!(scan_receipts_with_index(&data,&index,[1;16]).is_err(),"offset {offset}");
        }
        data[at..at+RECEIPT_BYTES].copy_from_slice(&raw);
        data[..RECEIPT_BYTES].copy_from_slice(&receipt((1u64<<56)|1,1));
        assert!(scan_receipts_with_index(&data,&strict_index(2,0),[1;16]).is_err());
        // A bound, proven terminal predecessor can coexist with one pending.
        data[96..98].copy_from_slice(&3u16.to_le_bytes());
        data[108]=1;
        reseal(&mut data[..RECEIPT_BYTES]);
        assert_eq!(scan_receipts_with_index(&data,&strict_index(2,0),[1;16]).unwrap().occupied,2);
    }

}
