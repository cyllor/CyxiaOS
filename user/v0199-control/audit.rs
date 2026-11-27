//! The staged Supervisor receives one boot selector and its registered generation.
//! All read and ACK requests use the existing ControlRPC v1 envelope.
#[cfg(target_os = "none")]
use super::{call, clock, put16, put32, put64, reject_startup, yield_now};
#[path = "audit_hash.rs"]
mod audit_hash;

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

#[cfg(target_os = "none")]
fn header(op: u16, seq: u64, generation: u64, cursor: u64) -> [u8; 96] {
    let mut req = [0u8; 96];
    put32(&mut req, 0, 0x43594351);
    put16(&mut req, 4, 1);
    put16(&mut req, 6, 48);
    put16(&mut req, 8, op);
    put32(&mut req, 12, if op == 1 { 16 } else { 48 });
    put64(&mut req, 16, seq);
    put64(&mut req, 24, seq - 1);
    put64(&mut req, 32, generation);
    put64(&mut req, 48, generation);
    put64(&mut req, 56, cursor);
    req
}

#[cfg(target_os = "none")]
fn transact(cap: u64, req: &mut [u8], reply: &mut [u8]) {
    loop {
        if u64_at(req, 40) == 0 {
            let now = clock();
            if now < 0 {
                reject_startup();
            }
            put64(req, 40, (now as u64).saturating_add(400_000_000));
        }
        let result = call(
            0x50,
            [
                cap,
                req.as_ptr() as u64,
                req.len() as u64,
                0,
                reply.as_mut_ptr() as u64,
                reply.len() as u64,
            ],
        );
        match result {
            0 => return,
            -13 => yield_now(), // EAGAIN: preserve the complete original frame.
            -6 => {
                // The live handler returns E_TIMEOUT only on a new, unadmitted request.
                put64(req, 40, 0);
                yield_now();
            }
            _ => reject_startup(),
        }
    }
}

pub(super) fn valid_reply(wire: &[u8], op: u16, request_seq: u64, generation: u64) -> bool {
    let len = if op == 1 { 192 } else { 48 };
    wire.len() == len
        && wire[..8] == [0x52, 0x43, 0x59, 0x43, 1, 0, 48, 0]
        && wire[8..10] == op.to_le_bytes()
        && wire[10..16] == [1, 0, 0, 0, 0, 0]
        && u64_at(wire, 16) == request_seq
        && u64_at(wire, 24) == generation
        && u64_at(wire, 32) == generation
        && u64_at(wire, 40) == (len - 48) as u64
}

pub(super) fn read_record(wire: &[u8; 192], boot: u64, after: u64) -> Option<(u64, [u8; 32])> {
    if wire[48..56] != [1, 0, 0, 0, 0, 0, 0, 0] {
        return None;
    }
    let seq = u64_at(wire, 56);
    let r: &[u8; 128] = wire[64..].try_into().ok()?;
    if seq != after.checked_add(1)?
        || r[..8] != [0x55, 0x41, 0x59, 0x43, 2, 0, 128, 0]
        || u64_at(r, 8) != boot
        || u64_at(r, 16) != seq
        || r[24..32] != [10, 0, 1, 0, 3, 0, 255, 255]
        || u64_at(r, 32) != 0
        || u64_at(r, 40) != 1
        || !(1..=3).contains(&seq)
        || u64_at(r, 48) != seq
        || u64_at(r, 56) != 2
        || r[64..96].iter().all(|&b| b == 0)
    {
        return None;
    }
    let digest = audit_hash::record_digest(r);
    (digest == r[96..]).then_some((seq, digest))
}

#[cfg(target_os = "none")]
pub(super) fn run(cap: u64, boot: u64, generation: u64) -> ! {
    let mut seq = 1;
    let mut cursor = 0;
    loop {
        let mut req = header(1, seq, generation, cursor);
        let mut wire = [0u8; 192];
        transact(cap, &mut req[..64], &mut wire);
        if !valid_reply(&wire, 1, seq, generation) {
            reject_startup();
        }
        if wire[48..].iter().all(|&b| b == 0) {
            if seq == 7 && cursor == 3 {
                cursor = 0;
                seq += 1;
                continue;
            }
            if seq == 8 && cursor == 0 {
                #[cfg(file_read_probe)]
                super::file_read::probe_supervisor();
                #[cfg(file_receipt_query_probe)]
                super::file_receipt::run();
                #[cfg(all(not(file_receipt_query_probe), snapshot_catalog_probe))]
                super::catalog::probe_supervisor();
                #[cfg(not(any(file_receipt_query_probe, snapshot_catalog_probe)))]
                loop {
                    yield_now();
                }
            }
            reject_startup();
        }
        let Some((next, digest)) = read_record(&wire, boot, cursor) else {
            reject_startup();
        };
        if seq == 1 {
            let mut replay = [0u8; 192];
            transact(cap, &mut req[..64], &mut replay);
            if wire != replay {
                reject_startup();
            }
        }
        seq += 1;
        let mut ack = header(2, seq, generation, next);
        ack[64..].copy_from_slice(&digest);
        let mut ack_reply = [0u8; 48];
        transact(cap, &mut ack, &mut ack_reply);
        if !valid_reply(&ack_reply, 2, seq, generation) {
            reject_startup();
        }
        cursor = next;
        seq += 1;
    }
}
