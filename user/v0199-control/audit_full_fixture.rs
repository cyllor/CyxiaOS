#![no_std]
#![no_main]
//! Test-only signed Supervisor for a full durable audit carrier.

use core::{arch::asm, ptr::addr_of_mut};

mod audit_hash;

const MAGIC: u64 = 0x4359_5841_5546_554c;
const FIRST_SELECTOR: u64 = 0xc007;
const REPLACEMENT_SELECTOR: u64 = 0xc008;
const FIXTURE_EPOCH: u64 = 2;
const E_AUTH: i64 = -1;
const E_STALE: i64 = -4;
const E_TIMEOUT: i64 = -6;
const E_AGAIN: i64 = -13;
const READ: u16 = 1;
const ACK: u16 = 2;
const TRANSPORT_ACK: u16 = 12;
const LEASE: u64 = 400_000_000;
const PAUSE_NS: u64 = 3_000_000_000;
const RECORDS: usize = 9;
const HEADER_WORDS: usize = 16;

#[used]
#[unsafe(link_section = ".rodata.role")]
static ROLE_NOTE: [u8; 8] = [b'C', b'Y', b'R', b'3', 11, 3, 0, 0];

// Independently observed through the fixture's private data page. Only
// exact 128-byte returned audit records are copied into the record array.
#[used]
#[unsafe(link_section = ".role_probe")]
static mut PROBE: [u64; HEADER_WORDS + 16 * RECORDS] = [0; HEADER_WORDS + 16 * RECORDS];

fn observe(slot: usize, value: u64) {
    // SAFETY: only this EL0 thread writes its in-bounds private probe words.
    unsafe {
        addr_of_mut!(PROBE)
            .cast::<u64>()
            .add(slot)
            .write_volatile(value);
    }
}

#[inline(always)]
fn svc(operation: u64, args: [u64; 6]) -> i64 {
    let [mut x0, x1, x2, x3, x4, x5] = args;
    // SAFETY: ABI3 retains x1–x30 and uses this process's private spans.
    unsafe {
        asm!("svc #0", inlateout("x0") x0, in("x1") x1, in("x2") x2, in("x3") x3,
             in("x4") x4, in("x5") x5, in("x8") operation, options(nostack));
    }
    x0 as i64
}

fn fail(code: u64) -> ! {
    observe(15, code);
    svc(1, [code, 0, 0, 0, 0, 0]);
    loop {
        core::hint::spin_loop();
    }
}

fn check(yes: bool, code: u64) {
    if !yes {
        fail(code);
    }
}

fn clock() -> u64 {
    let result = svc(4, [0; 6]);
    check(result > 0, 1);
    result as u64
}

fn yield_now() {
    check(svc(2, [0; 6]) == 0, 2);
}

fn pause() {
    let until = clock() + PAUSE_NS;
    while clock() < until {
        yield_now();
    }
}

fn get64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

const fn from_hex(value: &str) -> [u8; 32] {
    let mut output = [0; 32];
    let bytes = value.as_bytes();
    assert!(bytes.len() == 64);
    let mut i = 0;
    while i < 64 {
        let digit = match bytes[i] {
            b'0'..=b'9' => bytes[i] - b'0',
            b'a'..=b'f' => bytes[i] - b'a' + 10,
            _ => panic!(),
        };
        output[i / 2] = (output[i / 2] << 4) | digit;
        i += 1;
    }
    output
}

const FIRST_DIGEST: [u8; 32] = from_hex(env!("CYX_AUDIT_FIXTURE_FIRST_DIGEST"));

fn request(op: u16, seq: u64, generation: u64, cursor: u64) -> [u8; 96] {
    let mut wire = [0; 96];
    let payload = match op {
        READ => 16u32,
        ACK => 48,
        _ => 0,
    };
    wire[..8].copy_from_slice(&[0x51, 0x43, 0x59, 0x43, 1, 0, 48, 0]);
    wire[8..10].copy_from_slice(&op.to_le_bytes());
    wire[12..16].copy_from_slice(&payload.to_le_bytes());
    for (at, value) in [
        (16, seq),
        (24, if op == TRANSPORT_ACK { seq } else { seq - 1 }),
        (32, generation),
        (40, clock() + LEASE),
        (48, generation),
        (56, cursor),
    ] {
        wire[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    wire
}

fn call(cap: u64, req: &[u8], reply: &mut [u8]) -> i64 {
    svc(
        0x50,
        [
            cap,
            req.as_ptr() as u64,
            req.len() as u64,
            0,
            reply.as_mut_ptr() as u64,
            reply.len() as u64,
        ],
    )
}

fn transact(cap: u64, req: &mut [u8], reply: &mut [u8], limit: u64) {
    loop {
        let status = call(cap, req, reply);
        if status == 0 {
            return;
        }
        observe(14, status as u64);
        let now = clock();
        check(matches!(status, E_AGAIN | E_TIMEOUT) && now < limit, 3);
        if status == E_TIMEOUT {
            req[40..48].copy_from_slice(&(now + LEASE).to_le_bytes());
        }
        yield_now();
    }
}

fn done(reply: &[u8], op: u16, seq: u64, generation: u64) -> bool {
    reply[..8] == [0x52, 0x43, 0x59, 0x43, 1, 0, 48, 0]
        && reply[8..10] == op.to_le_bytes()
        && reply[10..16] == [1, 0, 0, 0, 0, 0]
        && get64(reply, 16) == seq
        && get64(reply, 24) == generation
        && get64(reply, 32) == generation
        && get64(reply, 40) == (reply.len() - 48) as u64
}

fn read_record(cap: u64, rpc_seq: u64, generation: u64, audit_seq: u64, limit: u64) -> [u8; 32] {
    let mut req = request(READ, rpc_seq, generation, audit_seq - 1);
    let mut reply = [0xa5; 192];
    transact(cap, &mut req[..64], &mut reply, limit);
    check(done(&reply, READ, rpc_seq, generation), 4);
    let record: &[u8; 128] = reply[64..].try_into().unwrap();
    let digest = audit_hash::record_digest(record);
    check(
        reply[48..56] == [1, 0, 0, 0, 0, 0, 0, 0]
            && get64(&reply, 56) == audit_seq
            && get64(record, 16) == audit_seq
            && record[96..] == digest,
        5,
    );
    for i in 0..16 {
        observe(
            HEADER_WORDS + (audit_seq as usize - 1) * 16 + i,
            get64(record, i * 8),
        );
    }
    observe(11, audit_seq);
    digest
}

fn expect_old_denials(cap: u64, epoch: u64, generation: u64) {
    let (old_cap, old_generation) = if epoch == FIXTURE_EPOCH {
        ((epoch << 16) | FIRST_SELECTOR, generation - 1)
    } else {
        (((epoch - 1) << 16) | REPLACEMENT_SELECTOR, generation)
    };
    let mut reply = [0xa5; 192];
    let req = request(READ, 1, old_generation, 0);
    let result = call(old_cap, &req[..64], &mut reply);
    observe(6, result as u64);
    check(result == E_AUTH && reply == [0xa5; 192], 6);
    let req = request(READ, 1, generation - 1, 0);
    let result = call(cap, &req[..64], &mut reply);
    observe(7, result as u64);
    check(result == E_STALE && reply == [0xa5; 192], 7);

    let mut reply = [0xa5; 48];
    let mut req = request(ACK, 1, old_generation, 1);
    req[64..].copy_from_slice(&FIRST_DIGEST);
    let result = call(old_cap, &req, &mut reply);
    observe(8, result as u64);
    check(result == E_AUTH && reply == [0xa5; 48], 8);
    let mut req = request(ACK, 1, generation - 1, 1);
    req[64..].copy_from_slice(&FIRST_DIGEST);
    let result = call(cap, &req, &mut reply);
    observe(9, result as u64);
    check(result == E_STALE && reply == [0xa5; 48], 9);
    let mut req = request(ACK, 1, generation, 1);
    req[64..].copy_from_slice(&FIRST_DIGEST);
    let result = call(cap, &req, &mut reply);
    observe(10, result as u64);
    check(result == E_AUTH && reply == [0xa5; 48], 10);
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
extern "C" fn _start(args: u64, len: u64) -> ! {
    check(
        args != 0 && args.is_multiple_of(16) && matches!(len, 24 | 32),
        11,
    );
    let words = args as *const u64;
    // SAFETY: the loader installed these aligned initial stack words.
    let cap = unsafe { words.read_volatile() };
    let generation = unsafe { words.add(2).read_volatile() };
    let epoch = cap >> 16;
    check(
        matches!(
            (epoch, generation, cap & 0xffff),
            (FIXTURE_EPOCH, 1, FIRST_SELECTOR)
                | (FIXTURE_EPOCH, 2, REPLACEMENT_SELECTOR)
                | (3, 2, FIRST_SELECTOR)
        ),
        12,
    );
    observe(0, MAGIC);
    observe(1, epoch);
    observe(2, generation);
    observe(3, cap);
    observe(4, 1);
    let start = clock();
    observe(5, start);
    let limit = start + 40_000_000_000;
    if generation == 1 {
        check(
            read_record(cap, 1, generation, 1, limit) == FIRST_DIGEST,
            13,
        );
        observe(4, 2);
        // No ACK is sent. The private guard triggers the real stopped-role
        // fault path after the original consumer has received the old head.
        pause();
        // SAFETY: this disposable signed fixture deliberately accesses its
        // own unmapped stack guard to model a stopped audit consumer.
        unsafe {
            asm!("ldr xzr, [{guard}]", guard = in(reg) 0x2_f000u64, options(nostack));
        }
        fail(14);
    }

    expect_old_denials(cap, epoch, generation);
    observe(4, 3);
    // Give the observer a stable pre-ACK cut for cold recovery.
    pause();
    for i in 0..RECORDS as u64 {
        let audit_seq = i + 1;
        let rpc_seq = 2 * i + 1;
        let digest = read_record(cap, rpc_seq, generation, audit_seq, limit);
        if i == 0 {
            check(digest == FIRST_DIGEST, 16);
        }
        let mut req = request(ACK, rpc_seq + 1, generation, audit_seq);
        req[64..].copy_from_slice(&digest);
        let mut reply = [0xa5; 48];
        transact(cap, &mut req, &mut reply, limit);
        check(done(&reply, ACK, rpc_seq + 1, generation), 17);
        observe(12, audit_seq);
    }
    let rpc_seq = (2 * RECORDS) as u64 + 1;
    let mut req = request(READ, rpc_seq, generation, 0);
    let mut reply = [0xa5; 192];
    transact(cap, &mut req[..64], &mut reply, limit);
    check(
        done(&reply, READ, rpc_seq, generation) && reply[48..] == [0; 144],
        18,
    );
    let req = request(TRANSPORT_ACK, rpc_seq, generation, 0);
    let mut reply = [0xa5; 48];
    check(
        call(cap, &req[..48], &mut reply) == 0 && done(&reply, TRANSPORT_ACK, rpc_seq, generation),
        19,
    );
    observe(14, 0);
    observe(4, 4);
    loop {
        yield_now();
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    fail(255)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, len: usize) -> *mut u8 {
    for index in 0..len {
        // SAFETY: checked nonoverlapping spans are supplied by the compiler.
        unsafe {
            dst.add(index)
                .write_volatile(src.add(index).read_volatile());
        }
    }
    dst
}

#[unsafe(no_mangle)]
unsafe extern "C" fn memset(dst: *mut u8, value: i32, len: usize) -> *mut u8 {
    for index in 0..len {
        // SAFETY: the compiler supplies a writable span of length len.
        unsafe {
            dst.add(index).write_volatile(value as u8);
        }
    }
    dst
}

#[unsafe(no_mangle)]
unsafe extern "C" fn memcmp(lhs: *const u8, rhs: *const u8, len: usize) -> i32 {
    for index in 0..len {
        // SAFETY: the compiler supplies two readable spans of length len.
        let left = unsafe { lhs.add(index).read_volatile() };
        let right = unsafe { rhs.add(index).read_volatile() };
        if left != right {
            return i32::from(left) - i32::from(right);
        }
    }
    0
}

#[unsafe(no_mangle)]
unsafe extern "C" fn bcmp(lhs: *const u8, rhs: *const u8, len: usize) -> i32 {
    // SAFETY: the compiler's span contract matches memcmp.
    unsafe { memcmp(lhs, rhs, len) }
}
