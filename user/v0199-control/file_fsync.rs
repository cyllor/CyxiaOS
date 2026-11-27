//! Ordinary native client of the signed scratch file.
use super::{
    call, clock,
    file_receipt::{EAGAIN, ENDPOINT, ID, receipt_is_expected, receipt_key},
    put16, put32, put64, reject_startup, yield_now,
};

const ROOT: u64 = 0x4649_4c45_0000_0001;
const FILE: &[u8; 10] = b"readme.txt";
const CONTENTS: &[u8; 29] = b"CyxiaOS V0.20 durable fsync!\n";
const REPLY_MAGIC: [u8; 8] = [0x52, 0x46, 0x59, 0x43, 3, 0, 128, 0];

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

    let mut write_seq = 0;
    for seq in 1..=7 {
        let mut write = header::<73>(4, seq + 1);
        put32(&mut write, 40, CONTENTS.len() as u32);
        write[44..].copy_from_slice(CONTENTS);
        let reply = service::<128>(&write, handle);
        write_seq = field(&reply, 120);
        if !accepted_volatile(&reply, seq + 1) || write_seq != seq {
            reject_startup();
        }
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
    put64(&mut fsync, 32, write_seq);
    let reply = service::<128>(&fsync, handle);
    if !receipt_is_expected(&reply)
        || field(&reply, 40) != 21
        || service::<128>(&fsync, handle) != reply
    {
        reject_startup();
    }
    yield_now();
}
