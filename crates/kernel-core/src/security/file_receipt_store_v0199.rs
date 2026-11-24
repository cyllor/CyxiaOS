//! V0.19.9 128 x 192-byte receipt store over exactly six 4096-byte blocks.
//!
//! Receipt records straddle home-block boundaries. A native redo transaction
//! updating one such record MUST atomically include both home blocks and the
//! FileStreamIndex, plus any necessary file/inode/bitmap updates; a per-record
//! CRC alone is not a persistence transaction. This read-only verifier
//! identifies malformed/torn receipts and the exact home-block closure.
//! Only real COMMIT + device FLUSH evidence may authorize DONE.
use super::{Error, file_media_v0199::FileReceiptV4};

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
    if data.len() != RECEIPT_STORE_BYTES || expected_fs_uuid == [0; 16] {
        return Err(Error::Invalid);
    }
    let mut summary=ReceiptStoreSummary {
        occupied:0, unresolved:0, across_block:0,
    };
    for index in 0..RECEIPTS {
        let at=index*RECEIPT_BYTES;
        let raw=&data[at..at+RECEIPT_BYTES];
        if raw.iter().all(|byte|*byte==0) {
            continue; // explicitly unallocated slot
        }
        let record=FileReceiptV4::decode(raw)?;
        if record.fs_uuid!=expected_fs_uuid {
            return Err(Error::Invalid);
        }
        // A full receipt key must be unique among all retained slots. A
        // duplicate could otherwise give two different terminal results.
        for previous in 0..index {
            let offset=previous*RECEIPT_BYTES;
            let earlier=&data[offset..offset+RECEIPT_BYTES];
            if earlier.iter().all(|byte|*byte==0) { continue; }
            let old=FileReceiptV4::decode(earlier)?;
            if old.request_id == record.request_id
                || (old.issued_boot_epoch == record.issued_boot_epoch
                    && old.group_id == record.group_id
                    && old.group_generation == record.group_generation
                    && old.stream_slot == record.stream_slot
                    && old.stream_generation == record.stream_generation
                    && old.request_seq == record.request_seq)
            {
                return Err(Error::Invalid);
            }
        }
        summary.occupied+=1;
        if matches!(record.status,1|2|5) {
            summary.unresolved+=1;
        }
        if receipt_home(index).ok_or(Error::Invalid)?.second.is_some() {
            summary.across_block+=1;
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
}
