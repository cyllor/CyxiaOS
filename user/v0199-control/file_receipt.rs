//! Shared native FSYNC receipt checks and the cold-reopen client.
#[cfg(file_receipt_query_probe)]
use super::{call, clock, put16, put32, put64, reject_startup, yield_now};
#[cfg(not(file_receipt_query_probe))]
use super::{put32, put64};

pub(super) const ENDPOINT: u64 = 0x4649_4c45_0000_0011;
pub(super) const ID: u64 = 0x0100_0000_0000_0001;
pub(super) const EAGAIN: i64 = -13;
#[cfg(file_receipt_query_probe)]
const ESTALE: i64 = -4;

pub(super) fn receipt_key() -> [u8; 56] {
    let mut key = [0; 56];
    key[..16].copy_from_slice(b"CYX-FSYNC-TEST!!");
    put64(&mut key, 16, 1);
    put32(&mut key, 28, 1);
    put64(&mut key, 40, 1);
    put64(&mut key, 48, 1);
    key
}

#[cfg(file_receipt_query_probe)]
fn request() -> [u8; 88] {
    let mut wire = [0; 88];
    put32(&mut wire, 0, 0x4359_4651);
    put16(&mut wire, 4, 4);
    put16(&mut wire, 6, 32);
    put16(&mut wire, 8, 11);
    put32(&mut wire, 12, 56);
    put64(&mut wire, 16, ID);
    wire[32..].copy_from_slice(&receipt_key());
    wire
}

#[cfg(file_receipt_query_probe)]
fn query(request: &[u8; 88], reply: &mut [u8; 128]) -> i64 {
    call(
        0x50,
        [
            ENDPOINT,
            request.as_ptr() as u64,
            request.len() as u64,
            0,
            reply.as_mut_ptr() as u64,
            reply.len() as u64,
        ],
    )
}

fn field(reply: &[u8; 128], at: usize) -> u64 {
    u64::from_le_bytes(reply[at..at + 8].try_into().unwrap())
}

fn receipt_identity(reply: &[u8; 128]) -> bool {
    reply[..8] == [0x52, 0x46, 0x59, 0x43, 3, 0, 128, 0]
        && field(reply, 8) == ID
        && field(reply, 16) == 1
        && field(reply, 48) == 1
        && field(reply, 64) == 0
        && field(reply, 72) == 0
        && field(reply, 112) == ID
}

pub(super) fn receipt_is_committed(reply: &[u8; 128]) -> bool {
    let field = |at| field(reply, at);
    receipt_identity(reply)
        && field(24) == 3
        && match field(40) {
            19 => field(32) == 29 && field(120) == 7,
            21 => (29..=4096).contains(&field(32)) && field(120) > 0,
            _ => false,
        }
        && field(56) == 4
        && reply[80..112] != [0; 32]
}

#[cfg(file_receipt_query_probe)]
fn receipt_is_unknown(reply: &[u8; 128]) -> bool {
    receipt_identity(reply)
        && reply[24..28] == [5, 0, 0, 0]
        && i32::from_le_bytes(reply[28..32].try_into().unwrap()) == -6
        && field(reply, 32) == 0
        && field(reply, 40) == 14
        && field(reply, 56) == 3
        && reply[80..112] == [0; 32]
        && field(reply, 120) > 0
}

#[cfg(file_receipt_query_probe)]
pub(super) fn run() -> ! {
    if clock() < 0 {
        reject_startup();
    }
    let wire = request();
    let mut reply = [0xa5; 128];
    loop {
        match query(&wire, &mut reply) {
            0 if receipt_is_committed(&reply) || receipt_is_unknown(&reply) => break,
            EAGAIN if reply == [0xa5; 128] => yield_now(),
            _ => reject_startup(),
        }
    }
    yield_now();
    let mut reply = [0xa5; 128];
    if query(&wire, &mut reply) != ESTALE || reply != [0xa5; 128] {
        reject_startup();
    }
    loop {
        yield_now();
    }
}
