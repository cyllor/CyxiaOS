//! Native fixture client for the prior boot's FSYNC receipt.
use super::{call, clock, put16, put32, put64, reject_startup, yield_now};

const ENDPOINT: u64 = 0x4649_4c45_0000_0011;
const ID: u64 = 0x0100_0000_0000_0001;
const EAGAIN: i64 = -13;
const ESTALE: i64 = -4;
const FSYNC_RESULT_DIGEST: [u8; 32] = [
    0x5d, 0xc3, 0x8e, 0xe0, 0xd6, 0xb0, 0x13, 0xc1, 0xda, 0xcf, 0x94, 0xfe, 0x88, 0x5b, 0xde, 0x18,
    0x6a, 0xdd, 0xfd, 0x5b, 0x96, 0xde, 0x59, 0xe7, 0xaa, 0x5d, 0x59, 0x83, 0xee, 0xe9, 0x5f, 0x9c,
];

fn request() -> [u8; 88] {
    let mut wire = [0; 88];
    put32(&mut wire, 0, 0x4359_4651);
    put16(&mut wire, 4, 4);
    put16(&mut wire, 6, 32);
    put16(&mut wire, 8, 11);
    put32(&mut wire, 12, 56);
    put64(&mut wire, 16, ID);
    wire[32..48].copy_from_slice(b"CYX-FSYNC-TEST!!");
    put64(&mut wire, 48, 1);
    put32(&mut wire, 60, 1);
    put64(&mut wire, 72, 1);
    put64(&mut wire, 80, 1);
    wire
}

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

fn receipt_is_expected(reply: &[u8; 128]) -> bool {
    let field = |at| u64::from_le_bytes(reply[at..at + 8].try_into().unwrap());
    reply[..8] == [0x52, 0x46, 0x59, 0x43, 3, 0, 128, 0]
        && field(8) == ID
        && field(16) == 1
        && field(24) == 3
        && field(32) == 29
        && matches!(field(40), 19 | 21)
        && field(48) == 1
        && field(56) == 4
        && field(64) == 0
        && field(72) == 0
        && reply[80..112] == FSYNC_RESULT_DIGEST
        && field(112) == ID
        && field(120) == 7
}

pub(super) fn run() -> ! {
    if clock() < 0 {
        reject_startup();
    }
    let wire = request();
    let mut reply = [0xa5; 128];
    loop {
        match query(&wire, &mut reply) {
            0 if receipt_is_expected(&reply) => break,
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
