//! Ordinary native client of the signed scratch file.
use super::{
    call, clock,
    file_receipt::{EAGAIN, ENDPOINT, ID, receipt_is_committed, receipt_key},
    put16, put32, put64, reject_startup, yield_now,
};

const ROOT: u64 = 0x4649_4c45_0000_0001;
const FILE: &[u8; 10] = b"readme.txt";
const CONTENTS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/fsync-client-content.bin"));
const RESULT_DIGEST: &[u8; 32] =
    include_bytes!(concat!(env!("OUT_DIR"), "/fsync-client-digest.bin"));
const REPLY_MAGIC: [u8; 8] = [0x52, 0x46, 0x59, 0x43, 3, 0, 128, 0];
const WRITE_HEADER: usize = 44;
const MAX_WRITE: usize = 128 - WRITE_HEADER;
const COMMIT_LSN: u64 = if CONTENTS.len() > 4096 { 23 } else { 21 };

fn header<const BYTES: usize>(op: u16, id: u64) -> [u8; BYTES] {
    let mut wire = [0; BYTES];
    put32(&mut wire, 0, 0x4359_4651);
    put16(&mut wire, 4, 4);
    put16(&mut wire, 6, 32);
    put16(&mut wire, 8, op);
    put32(&mut wire, 12, (BYTES - 32) as u32);
    put64(&mut wire, 16, id);
    wire
}

fn service<const BYTES: usize>(wire: &[u8], selector: u64) -> [u8; BYTES] {
    let mut reply = [0xa5; BYTES];
    loop {
        match call(
            0x50,
            [
                ENDPOINT,
                wire.as_ptr() as u64,
                wire.len() as u64,
                selector,
                reply.as_mut_ptr() as u64,
                reply.len() as u64,
            ],
        ) {
            0 => return reply,
            EAGAIN if reply == [0xa5; BYTES] => yield_now(),
            _ => reject_startup(),
        }
    }
}

fn field(reply: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(reply[offset..offset + 8].try_into().unwrap())
}

fn accepted_volatile(reply: &[u8; 128], id: u64) -> bool {
    reply[..8] == REPLY_MAGIC
        && field(reply, 8) == id
        && field(reply, 16) == 1
        && field(reply, 24) == 0
        && field(reply, 32) == 0
        && field(reply, 40) == 0
        && field(reply, 112) == 0
}

fn acknowledge(reply: &[u8; 128]) {
    let id = field(reply, 8);
    let boot = field(reply, 16);
    let mut ack = header::<88>(15, id);
    put64(&mut ack, 32, boot);
    put64(&mut ack, 40, boot);
    put64(&mut ack, 48, id);
    ack[56..].copy_from_slice(&reply[80..112]);
    let released = service::<128>(&ack, 0);
    if !accepted_volatile(&released, id) || released[80..112] != reply[80..112] {
        reject_startup();
    }
}

pub(super) fn run() {
    if clock() < 0 {
        reject_startup();
    }
    let mut open = header::<52>(2, 1);
    put16(&mut open, 32, FILE.len() as u16);
    open[34..44].copy_from_slice(FILE);
    put32(&mut open, 44, 0x2300);
    let opened = service::<128>(&open, ROOT);
    let handle = field(&opened, 64);
    if !accepted_volatile(&opened, 1) || handle == 0 || field(&opened, 72) != 1 {
        reject_startup();
    }
    acknowledge(&opened);

    let chunks = CONTENTS.len().div_ceil(MAX_WRITE);
    let write_count = chunks.max(7);
    for index in 0..write_count {
        let start = (index % chunks) * MAX_WRITE;
        let data = &CONTENTS[start..(start + MAX_WRITE).min(CONTENTS.len())];
        let sequence = index as u64 + 1;
        let mut write = header::<128>(4, sequence + 1);
        put32(&mut write, 12, (12 + data.len()) as u32);
        put64(&mut write, 32, start as u64);
        put32(&mut write, 40, data.len() as u32);
        let write = &mut write[..WRITE_HEADER + data.len()];
        write[WRITE_HEADER..].copy_from_slice(data);
        let reply = service::<128>(write, handle);
        if !accepted_volatile(&reply, sequence + 1) || field(&reply, 120) != sequence {
            reject_startup();
        }
        acknowledge(&reply);
    }

    let mut alloc = header::<48>(10, 0);
    put64(&mut alloc, 40, 1);
    let allocated = service::<184>(&alloc, 0);
    if allocated[..8] != REPLY_MAGIC
        || field(&allocated, 8) != ID
        || field(&allocated, 16) != 1
        || field(&allocated, 24) != 1
        || field(&allocated, 32) != 56 << 32
        || allocated[128..] != receipt_key()
    {
        reject_startup();
    }

    let mut fsync = header::<40>(5, field(&allocated, 8));
    put64(&mut fsync, 32, write_count as u64);
    let reply = service::<128>(&fsync, handle);
    if !receipt_is_committed(&reply)
        || reply[80..112] != *RESULT_DIGEST
        || field(&reply, 40) != COMMIT_LSN
        || field(&reply, 32) != CONTENTS.len() as u64
        || field(&reply, 120) != write_count as u64
        || service::<128>(&fsync, handle) != reply
    {
        reject_startup();
    }
    yield_now();
}
