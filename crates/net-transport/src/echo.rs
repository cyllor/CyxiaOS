//! SEC-N05/06: exact bounded little-endian read-only Echo framing.
//! No capability, policy, resource request or remote execution op exists.
//! Parse only authenticated TLS plaintext after Session::accept_local_echo.
#![forbid(unsafe_code)]
pub const HEADER_BYTES: usize = 16;
pub const MAX_PAYLOAD: usize = 4096;
pub const MAX_FRAME: usize = HEADER_BYTES + MAX_PAYLOAD;
pub const VERSION: u16 = 1;
pub const READONLY_ECHO: u16 = 1;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Version,
    Opcode,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request<'a> {
    id: u64,
    payload: &'a [u8],
}
impl<'a> Request<'a> {
    pub const fn id(&self) -> u64 {
        self.id
    }
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }
    /// Writes an exact response using caller-owned bounded memory. A short
    /// output is rejected before changing a byte; no hidden staging/queue.
    pub fn encode_reply(self, out: &mut [u8]) -> Result<usize, Error> {
        let len = HEADER_BYTES + self.payload.len();
        if len > MAX_FRAME || out.len() < len {
            return Err(Error::Length);
        }
        out[..2].copy_from_slice(&VERSION.to_le_bytes());
        out[2..4].copy_from_slice(&READONLY_ECHO.to_le_bytes());
        out[4..8].copy_from_slice(&(self.payload.len() as u32).to_le_bytes());
        out[8..16].copy_from_slice(&self.id.to_le_bytes());
        out[16..len].copy_from_slice(self.payload);
        Ok(len)
    }
}
/// Inspect the first frame in a TLS byte stream. A TCP/TLS record may
/// contain a prefix of a frame or several complete frames; neither is an
/// invalid protocol message by itself. The exact-only public parse_request
/// remains strict and is called on precisely the returned prefix.
// Consumed only by the tls-gated admission ledger; dead in the smoltcp-only
// EL1 (sec-n-native) closure, which never compiles admission.
#[allow(dead_code)]
pub(crate) fn next_frame_len(input: &[u8]) -> Result<Option<usize>, Error> {
    if input.len() < HEADER_BYTES {
        return Ok(None);
    }
    let version = u16::from_le_bytes([input[0], input[1]]);
    if version != VERSION {
        return Err(Error::Version);
    }
    let opcode = u16::from_le_bytes([input[2], input[3]]);
    if opcode != READONLY_ECHO {
        return Err(Error::Opcode);
    }
    let payload_len =
        u32::from_le_bytes(input[4..8].try_into().map_err(|_| Error::Length)?) as usize;
    if payload_len > MAX_PAYLOAD {
        return Err(Error::Length);
    }
    let frame_len = HEADER_BYTES.checked_add(payload_len).ok_or(Error::Length)?;
    if input.len() < frame_len {
        return Ok(None);
    }
    Ok(Some(frame_len))
}
pub fn parse_request(input: &[u8]) -> Result<Request<'_>, Error> {
    if input.len() < HEADER_BYTES || input.len() > MAX_FRAME {
        return Err(Error::Length);
    }
    let version = u16::from_le_bytes([input[0], input[1]]);
    if version != VERSION {
        return Err(Error::Version);
    }
    let opcode = u16::from_le_bytes([input[2], input[3]]);
    if opcode != READONLY_ECHO {
        return Err(Error::Opcode);
    }
    let payload_len =
        u32::from_le_bytes(input[4..8].try_into().map_err(|_| Error::Length)?) as usize;
    let total = HEADER_BYTES.checked_add(payload_len).ok_or(Error::Length)?;
    if payload_len > MAX_PAYLOAD || input.len() != total {
        return Err(Error::Length);
    }
    let id = u64::from_le_bytes(input[8..16].try_into().map_err(|_| Error::Length)?);
    Ok(Request {
        id,
        payload: &input[HEADER_BYTES..],
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn packet(body: &[u8]) -> [u8; 20] {
        assert!(body.len() <= 4);
        let mut out = [0; 20];
        out[..2].copy_from_slice(&1u16.to_le_bytes());
        out[2..4].copy_from_slice(&1u16.to_le_bytes());
        out[4..8].copy_from_slice(&(body.len() as u32).to_le_bytes());
        out[8..16].copy_from_slice(&0x1234u64.to_le_bytes());
        out[16..16 + body.len()].copy_from_slice(body);
        out
    }
    #[test]
    fn sec_n05_exact_length_and_round_trip() {
        let packet = packet(&[1, 2, 3, 4]);
        let input = parse_request(&packet).unwrap();
        assert_eq!(input.id(), 0x1234);
        assert_eq!(input.payload(), [1, 2, 3, 4]);
        let mut out = [0u8; MAX_FRAME];
        assert_eq!(input.encode_reply(&mut out).unwrap(), 20);
        assert_eq!(&out[..20], &packet);
    }
    #[test]
    fn v019_sec_n05_fragmented_and_coalesced_stream_requires_exact_prefix() {
        let first = packet(&[1, 2, 3, 4]);
        let second = packet(&[5, 6, 7, 8]);
        for bytes in 0..first.len() {
            assert_eq!(next_frame_len(&first[..bytes]), Ok(None));
        }
        assert_eq!(next_frame_len(&first), Ok(Some(20)));
        let mut stream = [0u8; 40];
        stream[..20].copy_from_slice(&first);
        stream[20..].copy_from_slice(&second);
        assert_eq!(next_frame_len(&stream), Ok(Some(20)));
        assert_eq!(parse_request(&stream), Err(Error::Length));
        assert_eq!(
            parse_request(&stream[..20]).unwrap().payload(),
            &[1, 2, 3, 4]
        );
        assert_eq!(
            parse_request(&stream[20..]).unwrap().payload(),
            &[5, 6, 7, 8]
        );
    }
    #[test]
    fn v019_sec_n05_invalid_header_is_rejected_before_waiting_for_body() {
        let mut frame = packet(&[1, 2, 3, 4]);
        frame[2] = 19;
        assert_eq!(next_frame_len(&frame[..16]), Err(Error::Opcode));
        frame[2] = 1;
        frame[4..8].copy_from_slice(&4097u32.to_le_bytes());
        assert_eq!(next_frame_len(&frame[..16]), Err(Error::Length));
    }
    #[test]
    fn sec_n05_no_tail_or_truncation() {
        let packet = packet(&[1, 2, 3, 4]);
        assert_eq!(parse_request(&packet[..19]), Err(Error::Length));
        let mut extended = [0u8; 21];
        extended[..20].copy_from_slice(&packet);
        assert_eq!(parse_request(&extended), Err(Error::Length));
    }
    #[test]
    fn sec_n06_no_task_or_resource_opcode() {
        let mut packet = packet(&[1, 2, 3, 4]);
        for op in [0, 2, 16, 19, 65, 80, u16::MAX] {
            packet[2..4].copy_from_slice(&op.to_le_bytes());
            assert_eq!(parse_request(&packet), Err(Error::Opcode));
        }
    }
    #[test]
    fn sec_n05_oversize_and_bad_version() {
        let mut packet = packet(&[1, 2, 3, 4]);
        packet[4..8].copy_from_slice(&4097u32.to_le_bytes());
        assert_eq!(parse_request(&packet), Err(Error::Length));
        packet[4..8].copy_from_slice(&4u32.to_le_bytes());
        packet[..2].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(parse_request(&packet), Err(Error::Version));
    }
    #[test]
    fn sec_n05_short_output_never_mutates() {
        let packet = packet(&[1, 2, 3, 4]);
        let request = parse_request(&packet).unwrap();
        let mut short = [0xaau8; 19];
        assert_eq!(request.encode_reply(&mut short), Err(Error::Length));
        assert_eq!(short, [0xaa; 19]);
    }
}
