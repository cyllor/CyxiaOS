//! M1 wire v1: magic/version/cpu/length/session/sequence/payload/CRC32, LE.
use crate::ContractError;
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0xedb88320 } else { 0 };
        }
    }
    !crc
}
pub fn encode(
    session: u64,
    sequence: u64,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, ContractError> {
    if session == 0 || sequence == 0 || payload.len() > 96 || out.len() < 28 + payload.len() {
        return Err(ContractError::Invalid);
    }
    let n = 24 + payload.len();
    out[..4].copy_from_slice(b"CYX1");
    out[4] = 1;
    out[5] = 0;
    out[6..8].copy_from_slice(&(payload.len() as u16).to_le_bytes());
    out[8..16].copy_from_slice(&session.to_le_bytes());
    out[16..24].copy_from_slice(&sequence.to_le_bytes());
    out[24..n].copy_from_slice(payload);
    let crc = crc32(&out[..n]);
    out[n..n + 4].copy_from_slice(&crc.to_le_bytes());
    Ok(n + 4)
}
