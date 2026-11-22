//! Native EL0 helper for the separate FileServiceSchemaV2 transport.
//! Authorities are supplied by the protected root; this helper cannot mint
//! history or recovery permissions from an ordinary file capability.
use super::{Capability, snapshot as wire};
#[path = "../shared/calls.rs"]
mod calls;

pub struct Reply<'a> {
    pub operation: u16,
    pub status: i32,
    pub state: u32,
    pub payload: &'a [u8],
}
pub fn invoke<'a>(
    authority: Capability,
    request: &wire::RequestBuffer,
    response: &'a mut [u8; wire::MAX_RESPONSE],
) -> Result<Reply<'a>, i64> {
    if authority.id == 0
        || authority.generation == 0
        || u64::from(wire::u32_at(request.as_bytes(), 52)) != authority.id
    {
        return Err(-13);
    }
    response.fill(0);
    let result = unsafe {
        calls::call::<0x45>(
            [
                authority.id,
                request.as_bytes().as_ptr() as u64,
                authority.generation,
                response.as_mut_ptr() as u64,
                response.len() as u64,
            ],
            wire::SERVICE_CALL,
        )
    };
    let code = result[0] as i64;
    let length = usize::try_from(result[1]).map_err(|_| -22i64)?;
    if length < wire::RESPONSE_HEADER_BYTES
        || length > response.len()
        || wire::u32_at(response, 0) != wire::MAGIC
        || wire::u16_at(response, 4) != wire::VERSION
        || wire::u16_at(response, 6) != wire::RESPONSE_HEADER_BYTES as u16
        || wire::u16_at(response, 8) != wire::u16_at(request.as_bytes(), 8)
        || wire::u16_at(response, 10) != 0
        || wire::u32_at(response, 12) as usize != length
        || i64::from(wire::u32_at(response, 16) as i32) != code
        || wire::u32_at(response, 24) as usize != length - wire::RESPONSE_HEADER_BYTES
        || wire::u32_at(response, 28) != 0
    {
        return Err(if code < 0 { code } else { -22 });
    }
    Ok(Reply {
        operation: wire::u16_at(response, 8),
        status: code as i32,
        state: wire::u32_at(response, 20),
        payload: &response[wire::RESPONSE_HEADER_BYTES..length],
    })
}
