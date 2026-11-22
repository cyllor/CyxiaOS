//! FileServiceSchemaV2. This module has no kernel dependencies and is shared
//! verbatim with native EL0 clients. All integers are little endian.
pub const SERVICE_CALL: u64 = 0x50;
pub const MAGIC: u32 = 0x43594632;
pub const VERSION: u16 = 2;
pub const HEADER_BYTES: usize = 64;
pub const MAX_REQUEST: usize = 1024;
pub const RESPONSE_HEADER_BYTES: usize = 32;
pub const MAX_RESPONSE: usize = 2048;
pub const KEY_BYTES: usize = 40;
pub const REQUEST_KEY_BYTES: usize = 36;
pub const STATUS_BYTES: usize = 48;
pub const SUMMARY_BYTES: usize = 128;
pub const SNAP_CREATE: u16 = 0x20;
pub const SNAP_EXTEND: u16 = 0x21;
pub const SNAP_DELETE: u16 = 0x22;
pub const SNAP_RESTORE: u16 = 0x23;
pub const SNAP_LIST: u16 = 0x24;
pub const SNAP_QUERY: u16 = 0x25;
pub const SNAP_OPEN: u16 = 0x26;
pub const FREEZE_SET: u16 = 0x27;
pub const FREEZE_CLEAR: u16 = 0x28;
pub const OPEN_WRITES: u16 = 0x29;
pub const QUERY_REQUEST: u16 = 0x2a;
pub const ACK_REQUEST: u16 = 0x2b;

// These are independent capabilities, never additions to the ordinary v1
// ALL_RIGHTS mask. Only a protected kernel root may mint such authorities.
pub const RIGHT_CREATE: u16 = 1;
pub const RIGHT_LIST: u16 = 2;
pub const RIGHT_HISTORY_READ: u16 = 4;
pub const RIGHT_EXTEND: u16 = 8;
pub const RIGHT_DELETE_EXPIRED: u16 = 16;
pub const RIGHT_RESTORE: u16 = 32;
pub const RIGHT_PROTECTION: u16 = 64;
pub const KNOWN_RIGHTS: u16 = 127;
pub const RECOVERY_RIGHTS: u16 = RIGHT_RESTORE | RIGHT_PROTECTION;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireError {
    Version,
    Format,
    Range,
    Unsupported,
}
impl WireError {
    pub const fn errno(self) -> i32 {
        match self {
            Self::Version => -93,
            Self::Format => -22,
            Self::Range => -34,
            Self::Unsupported => -38,
        }
    }
}
pub fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}
pub fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
pub fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
pub fn put_u16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
pub fn put_u32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
pub fn put_u64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
pub fn request_key_valid(bytes: &[u8], allow_zero: bool) -> bool {
    bytes.len() == REQUEST_KEY_BYTES
        && ((allow_zero && zero(bytes))
            || (!zero(&bytes[..16])
                && u32_at(bytes, 16) < 16
                && u64_at(bytes, 20) != 0
                && u64_at(bytes, 28) != 0))
}
pub fn snapshot_key_valid(bytes: &[u8]) -> bool {
    bytes.len() == KEY_BYTES
        && !zero(&bytes[..16])
        && u64_at(bytes, 16) != 0
        && u32_at(bytes, 24) < 8
        && u32_at(bytes, 28) == 0
        && u64_at(bytes, 32) != 0
}
/// Canonical absolute paths make prefix comparisons component-aware. Reject
/// dot components instead of normalizing an untrusted path after authority.
pub fn canonical_path(bytes: &[u8]) -> bool {
    if bytes.is_empty() || bytes.len() > 512 || bytes[0] != b'/' {
        return false;
    }
    if core::str::from_utf8(bytes).is_err() || bytes.contains(&0) {
        return false;
    }
    bytes.len() == 1
        || bytes[1..]
            .split(|byte| *byte == b'/')
            .all(|part| !part.is_empty() && part.len() <= 63 && part != b"." && part != b"..")
}
pub fn within_prefix(path: &[u8], prefix: &[u8]) -> bool {
    canonical_path(path)
        && canonical_path(prefix)
        && (prefix == b"/"
            || path == prefix
            || (path.starts_with(prefix) && path.get(prefix.len()) == Some(&b'/')))
}
pub const fn persistent(operation: u16) -> bool {
    matches!(
        operation,
        SNAP_CREATE
            | SNAP_EXTEND
            | SNAP_DELETE
            | SNAP_RESTORE
            | FREEZE_SET
            | FREEZE_CLEAR
            | OPEN_WRITES
    )
}
pub const fn required_right(operation: u16) -> Option<u16> {
    Some(match operation {
        SNAP_CREATE => RIGHT_CREATE,
        SNAP_EXTEND => RIGHT_EXTEND,
        SNAP_DELETE => RIGHT_DELETE_EXPIRED,
        SNAP_RESTORE => RIGHT_RESTORE,
        SNAP_LIST | SNAP_QUERY => RIGHT_LIST,
        SNAP_OPEN => RIGHT_HISTORY_READ,
        FREEZE_SET | FREEZE_CLEAR | OPEN_WRITES => RIGHT_PROTECTION,
        QUERY_REQUEST | ACK_REQUEST => 0,
        _ => return None,
    })
}
pub const fn response_bound(operation: u16) -> usize {
    RESPONSE_HEADER_BYTES
        + match operation {
            SNAP_CREATE => 72,
            SNAP_EXTEND => 64,
            SNAP_DELETE => 56,
            SNAP_RESTORE => 96,
            SNAP_LIST => STATUS_BYTES + 8 * SUMMARY_BYTES,
            SNAP_QUERY => STATUS_BYTES + SUMMARY_BYTES,
            SNAP_OPEN => 8,
            FREEZE_SET | FREEZE_CLEAR | OPEN_WRITES => 16,
            QUERY_REQUEST => 512,
            _ => 0,
        }
}
pub fn request_length(header: &[u8]) -> Result<usize, WireError> {
    if header.len() < HEADER_BYTES || u32_at(header, 0) != MAGIC {
        return Err(WireError::Format);
    }
    if u16_at(header, 4) != VERSION {
        return Err(WireError::Version);
    }
    if u16_at(header, 6) != HEADER_BYTES as u16 || u16_at(header, 10) != 0 {
        return Err(WireError::Format);
    }
    let length = u32_at(header, 12) as usize;
    if !(HEADER_BYTES..=MAX_REQUEST).contains(&length) {
        return Err(WireError::Range);
    }
    Ok(length)
}
#[derive(Clone, Copy)]
pub struct Request<'a> {
    pub operation: u16,
    pub request_key: &'a [u8],
    pub cap_index: u32,
    pub expected_live_view_epoch: u64,
    pub payload: &'a [u8],
}
impl<'a> Request<'a> {
    pub fn decode(bytes: &'a [u8]) -> Result<Self, WireError> {
        if request_length(bytes)? != bytes.len() {
            return Err(WireError::Format);
        }
        let operation = u16_at(bytes, 8);
        required_right(operation).ok_or(WireError::Unsupported)?;
        let key = &bytes[16..52];
        if if persistent(operation) {
            !request_key_valid(key, false)
        } else {
            !zero(key)
        } {
            return Err(WireError::Format);
        }
        let epoch = u64_at(bytes, 56);
        if matches!(operation, SNAP_CREATE | SNAP_RESTORE | OPEN_WRITES) != (epoch != 0) {
            return Err(WireError::Format);
        }
        let payload = &bytes[HEADER_BYTES..];
        let valid = match operation {
            SNAP_CREATE => {
                payload.len() == 16
                    && u64_at(payload, 0) != 0
                    && matches!(u32_at(payload, 8), 1 | 2)
                    && u32_at(payload, 12) == 1
            }
            SNAP_EXTEND => {
                payload.len() == 48
                    && snapshot_key_valid(&payload[..40])
                    && u64_at(payload, 40) != 0
            }
            SNAP_DELETE | SNAP_QUERY => snapshot_key_valid(payload),
            SNAP_RESTORE => {
                payload.len() == 48
                    && snapshot_key_valid(&payload[..40])
                    && matches!(u32_at(payload, 40), 1 | 2)
                    && u32_at(payload, 44) == 0
            }
            SNAP_LIST => payload.is_empty(),
            SNAP_OPEN => {
                payload.len() >= 48
                    && snapshot_key_valid(&payload[..40])
                    && u16_at(payload, 42) == 0
                    && u32_at(payload, 44) == 0
                    && usize::from(u16_at(payload, 40)) == payload.len() - 48
                    && canonical_path(&payload[48..])
            }
            FREEZE_SET => {
                payload.len() == 16 && u64_at(payload, 0) != 0 && u32_at(payload, 12) == 0
            }
            FREEZE_CLEAR => payload.len() == 8 && u64_at(payload, 0) != 0,
            OPEN_WRITES => {
                payload.len() == 48
                    && u64_at(payload, 0) != 0
                    && request_key_valid(&payload[8..44], true)
                    && u32_at(payload, 44) == 0
            }
            QUERY_REQUEST => request_key_valid(payload, false),
            ACK_REQUEST => {
                payload.len() == 68
                    && request_key_valid(&payload[..36], false)
                    && !zero(&payload[36..])
            }
            _ => false,
        };
        if !valid {
            return Err(WireError::Format);
        }
        Ok(Self {
            operation,
            request_key: key,
            cap_index: u32_at(bytes, 52),
            expected_live_view_epoch: epoch,
            payload,
        })
    }
}

#[derive(Clone, Copy)]
pub struct RequestBuffer {
    pub bytes: [u8; MAX_REQUEST],
    pub len: usize,
}
impl RequestBuffer {
    pub fn new(operation: u16, cap_index: u32, key: [u8; 36], epoch: u64) -> Self {
        let mut bytes = [0; MAX_REQUEST];
        put_u32(&mut bytes, 0, MAGIC);
        put_u16(&mut bytes, 4, VERSION);
        put_u16(&mut bytes, 6, HEADER_BYTES as u16);
        put_u16(&mut bytes, 8, operation);
        put_u32(&mut bytes, 12, HEADER_BYTES as u32);
        bytes[16..52].copy_from_slice(&key);
        put_u32(&mut bytes, 52, cap_index);
        put_u64(&mut bytes, 56, epoch);
        Self {
            bytes,
            len: HEADER_BYTES,
        }
    }
    pub fn set_payload(&mut self, payload: &[u8]) -> Result<(), WireError> {
        let length = HEADER_BYTES
            .checked_add(payload.len())
            .ok_or(WireError::Range)?;
        if length > MAX_REQUEST {
            return Err(WireError::Range);
        }
        self.bytes[HEADER_BYTES..].fill(0);
        self.bytes[HEADER_BYTES..length].copy_from_slice(payload);
        self.len = length;
        put_u32(&mut self.bytes, 12, length as u32);
        Ok(())
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
pub fn response_header(
    out: &mut [u8],
    operation: u16,
    status: i32,
    state: u32,
    payload_len: usize,
) -> Result<usize, WireError> {
    let length = RESPONSE_HEADER_BYTES
        .checked_add(payload_len)
        .ok_or(WireError::Range)?;
    if length > MAX_RESPONSE || out.len() < length {
        return Err(WireError::Range);
    }
    out[..RESPONSE_HEADER_BYTES].fill(0);
    put_u32(out, 0, MAGIC);
    put_u16(out, 4, VERSION);
    put_u16(out, 6, RESPONSE_HEADER_BYTES as u16);
    put_u16(out, 8, operation);
    put_u32(out, 12, length as u32);
    put_u32(out, 16, status as u32);
    put_u32(out, 20, state);
    put_u32(out, 24, payload_len as u32);
    Ok(length)
}
