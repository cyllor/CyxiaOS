//! Bounded error provenance, independent of the ordinary 200-event prefix.
pub const MAGIC: u64 = 0x4359584558495431;
pub const WORDS: usize = 80;
pub const RECORD_WORDS: usize = 24;

pub fn valid_record(r: &[u64; RECORD_WORDS], boot: u64, generation: u64, connection: u64) -> bool {
    r[0] == 1
        && boot != 0
        && r[1] == boot
        && generation != 0
        && r[2] == generation
        && r[3] != 0
        && r[3] <= connection
        && (1..=16).contains(&r[5])
        && matches!(r[6], 0 | 0x1001..=0x100b | 0x2001..=0x2014 | 0x3000..=0x3005
            | 0x4000..=0x4005 | 0x4101 | 0x5001..=0x500b)
        && (1..=8).contains(&r[7])
        && r[8] <= 3
        && r[9] <= 15
        && (r[10] <= r[4] || r[6] == 0x1004)
        && r[12] <= u16::MAX as u64
        && r[16] <= 65536
        && r[17] <= u16::MAX as u64
        && r[23] == 0
}

/// Whole-boot scope: first unauthenticated, first authenticated, latest
/// authenticated. Counts include omitted exits and every service generation;
/// no slot is a complete event archive. Caller publishes with a seqlock.
pub fn retain(
    bank: &mut [u64; WORDS],
    record: &[u64; RECORD_WORDS],
    boot: u64,
    generation: u64,
    connection: u64,
) -> bool {
    if !valid_record(record, boot, generation, connection)
        || bank[0] & 1 != 0
        || (bank[0] != 0 && (bank[1] != MAGIC || bank[2] != 1 || bank[6] > generation))
    {
        return false;
    }
    let authenticated = record[9] & 1 != 0;
    let count_index = if authenticated { 4 } else { 3 };
    let Some(count) = bank[count_index].checked_add(1) else {
        return false;
    };
    let Some(sequence) = bank[0].checked_add(2) else {
        return false;
    };
    if bank[0] == 0 {
        bank[5] = generation;
    }
    bank[1] = MAGIC;
    bank[2] = 1;
    bank[6] = generation;
    if count == 1 {
        let slot = if authenticated { 32 } else { 8 };
        bank[slot..slot + RECORD_WORDS].copy_from_slice(record);
    }
    if authenticated {
        bank[56..80].copy_from_slice(record);
    }
    bank[count_index] = count;
    bank[0] = sequence;
    true
}
