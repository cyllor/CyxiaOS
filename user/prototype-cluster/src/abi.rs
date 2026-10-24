//! Shared fixed-address broker ABI. No field is a guest pointer.
pub const SHARED_VA: u64 = 0x0200_0000;
pub const SHARED_BYTES: usize = 16384;
pub const STACK_TOP: u64 = 0x01ff_0000;
pub const STACK_BYTES: usize = 128 * 1024;
pub const SVC: u16 = 0x43;
pub const MAGIC: u64 = 0x4359_5843_4c53_3031;
pub const VERSION: u64 = 1;
pub const PAYLOAD: usize = 4096;
pub const OK: u64 = 0;
pub const AGAIN: u64 = 1;
pub const EOF: u64 = 2;
pub const FAILED: u64 = 3;
pub const NOT_FOUND: u64 = 4;
/// Pre-I/O capacity rejection; no durable write was attempted.
pub const REJECTED: u64 = 5;
pub const OP_ENTROPY: u64 = 1;
pub const OP_TIME: u64 = 2;
pub const OP_POLL: u64 = 3;
pub const OP_READ: u64 = 4;
pub const OP_WRITE: u64 = 5;
pub const OP_CLOSE: u64 = 6;
pub const OP_STORE_GET: u64 = 7;
pub const OP_STORE_PUT: u64 = 8;
pub const OP_STORE_FLUSH: u64 = 9;
pub const OP_TASK: u64 = 10;
pub const OP_TRACE: u64 = 11;
pub const OP_YIELD: u64 = 12;
/// POLL value: 0 disconnected, 1 connected. Epoch changes on every connection.
/// STORE offset selects a record chunk; arg0 record key; arg1 total record
/// bytes. PUT arg2 transaction phase: 0 stage,1 commit after complete staging.
/// GET/PUT offsets and total record sizes are bounded by MAX_RECORD.
pub const MAX_RECORD: u64 = 1024 * 1024;
#[repr(C, align(4096))]
pub struct Shared {
    pub magic: u64,
    pub version: u64,
    pub sequence: u64,
    pub op: u64,
    pub status: u64,
    pub len: u64,
    pub offset: u64,
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub monotonic_ms: u64,
    pub unix_seconds: u64,
    pub boot_epoch: u64,
    pub connection_epoch: u64,
    pub uuid: [u8; 16],
    pub local_node: [u8; 32],
    pub peer_node: [u8; 32],
    pub payload: [u8; PAYLOAD],
}
pub fn valid_request(op: u64, len: u64, offset: u64) -> bool {
    if len > PAYLOAD as u64 {
        return false;
    }
    match op {
        OP_ENTROPY | OP_READ | OP_WRITE | OP_TRACE | OP_TASK => offset == 0,
        OP_STORE_GET | OP_STORE_PUT => offset.checked_add(len).is_some_and(|n| n <= MAX_RECORD),
        OP_TIME | OP_POLL | OP_CLOSE | OP_STORE_FLUSH | OP_YIELD => len == 0 && offset == 0,
        _ => false,
    }
}
const _: () = assert!(core::mem::size_of::<Shared>() <= SHARED_BYTES);
