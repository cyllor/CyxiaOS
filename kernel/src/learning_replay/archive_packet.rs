//! Exact bounded copies of retained signed peer packets. The archive header
//! stores the signed length; only the following block padding is zero.
use cyxia_prototype::domains::Error;

pub(super) const CHUNK: usize = 256;

pub(super) fn padded(bytes: usize) -> Result<usize, Error> {
    if bytes > cyxia_peer_billing::PACKET_BYTES {
        return Err(Error::Capacity);
    }
    Ok(bytes.div_ceil(CHUNK) * CHUNK)
}

pub(super) fn chunk(
    bytes: usize,
    offset: usize,
    out: &mut [u8; CHUNK],
    copy: impl FnOnce(usize, &mut [u8]) -> Result<usize, Error>,
) -> Result<usize, Error> {
    if !offset.is_multiple_of(CHUNK) || offset >= padded(bytes)? {
        return Err(Error::Range);
    }
    let expected = bytes.saturating_sub(offset).min(CHUNK);
    out.fill(0);
    if copy(offset, out)? != expected {
        return Err(Error::Stale);
    }
    out[expected..].fill(0);
    Ok(CHUNK)
}
