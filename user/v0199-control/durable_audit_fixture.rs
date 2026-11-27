#![no_std]
#![no_main]
//! Opt-in Supervisor package for the signed native recovery acceptance run.
//! Compile separately and sign its exact ELF as role 11 in the test roster.

use core::arch::asm;

mod audit_hash;

const AUDIT_READ: u16 = 1;
const AUDIT_ACK: u16 = 2;
const TRANSPORT_ACK: u16 = 12;
const HEADER_BYTES: usize = 48;
const READ_BYTES: usize = 64;
const ACK_BYTES: usize = 96;
const AUDIT_REPLY_BYTES: usize = 192;
const E_AUTH: i64 = -1;
const E_STALE: i64 = -4;
const E_CONFLICT: i64 = -5;
const E_TIMEOUT: i64 = -6;
const E_AGAIN: i64 = -13;
// A request built at the end of a role turn may first trap next window.
const RPC_LEASE_NS: u64 = 400_000_000;
const COHORT_NS: u64 = 2_600_000_000;
const TEST_TIMEOUT_NS: u64 = 5_000_000_000;

#[used]
#[unsafe(link_section = ".rodata.role")]
static ROLE_NOTE: [u8; 8] = [b'C', b'Y', b'R', b'3', 11, 3, 0, 0];

#[inline(always)]
fn call(operation: u64, args: [u64; 6]) -> i64 {
    let [mut x0, x1, x2, x3, x4, x5] = args;
    // This is the same frozen native ABI used by the other signed roles.
    unsafe {
        asm!("svc #0", inlateout("x0") x0, in("x1") x1, in("x2") x2,
            in("x3") x3, in("x4") x4, in("x5") x5, in("x8") operation, options(nostack));
    }
    x0 as i64
}

fn clock() -> u64 {
    let now = call(4, [0; 6]);
    check(now >= 0, -20);
    now as u64
}

fn yield_now() {
    let _ = call(2, [0; 6]);
}

fn leave(status: i32) -> ! {
    let _ = call(1, [i64::from(status) as u64, 0, 0, 0, 0, 0]);
    loop {
        yield_now();
    }
}

fn check(condition: bool, status: i32) {
    if !condition {
        leave(status);
    }
}

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn get64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn request(op: u16, seq: u64, generation: u64, cursor: u64) -> [u8; ACK_BYTES] {
    let mut bytes = [0; ACK_BYTES];
    put32(&mut bytes, 0, 0x4359_4351);
    put16(&mut bytes, 4, 1);
    put16(&mut bytes, 6, HEADER_BYTES as u16);
    put16(&mut bytes, 8, op);
    let (payload, ack) = match op {
        AUDIT_READ => (16, seq - 1),
        AUDIT_ACK => (48, seq - 1),
        TRANSPORT_ACK => (0, seq),
        _ => leave(-21),
    };
    put32(&mut bytes, 12, payload);
    put64(&mut bytes, 16, seq);
    put64(&mut bytes, 24, ack);
    put64(&mut bytes, 32, generation);
    put64(&mut bytes, 40, clock().saturating_add(RPC_LEASE_NS));
    put64(&mut bytes, 48, generation);
    put64(&mut bytes, 56, cursor);
    bytes
}

fn service(selector: u64, request: &[u8], reply: &mut [u8]) -> i64 {
    call(
        0x50,
        [
            selector,
            request.as_ptr() as u64,
            request.len() as u64,
            0,
            reply.as_mut_ptr() as u64,
            reply.len() as u64,
        ],
    )
}

fn transact(selector: u64, request: &mut [u8], reply: &mut [u8], until: u64) {
    loop {
        let result = service(selector, request, reply);
        if result == 0 {
            return;
        }
        let now = clock();
        check(now < until && matches!(result, E_AGAIN | E_TIMEOUT), -22);
        if result == E_TIMEOUT {
            // Only a request rejected before admission can expire here.
            put64(request, 40, now.saturating_add(RPC_LEASE_NS));
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
        && get64(reply, 40) == (reply.len() - HEADER_BYTES) as u64
}

fn validate_record(reply: &[u8; AUDIT_REPLY_BYTES]) -> (u64, [u8; 32]) {
    check(reply[48..56] == [1, 0, 0, 0, 0, 0, 0, 0], -23);
    let seq = get64(reply, 56);
    let record: &[u8; 128] = reply[64..].try_into().unwrap();
    check(
        seq != 0
            && record[..8] == [0x55, 0x41, 0x59, 0x43, 2, 0, 128, 0]
            && get64(record, 8) != 0
            && get64(record, 16) == seq
            && record[24..26] == 10u16.to_le_bytes()
            && record[64..96].iter().any(|&byte| byte != 0),
        -24,
    );
    let digest = audit_hash::record_digest(record);
    check(digest == record[96..], -25);
    (seq, digest)
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
extern "C" fn _start(args: u64, len: u64) -> ! {
    check(args != 0 && args.is_multiple_of(16) && len == 24, -26);
    // SAFETY: The loader has checked this aligned private launch payload and
    // our entry has verified its exact ABI size before reading it.
    let (selector, generation) = unsafe {
        let ptr = args as *const u64;
        (
            u64::from_le(ptr.read_volatile()),
            u64::from_le(ptr.add(2).read_volatile()),
        )
    };
    check(
        selector != 0 && generation != 0 && generation != u64::MAX,
        -27,
    );
    let start = clock();
    let until = start.saturating_add(TEST_TIMEOUT_NS);
    let mut read_reply = [0x5a; AUDIT_REPLY_BYTES];
    let mut seq = 1;
    let read = request(AUDIT_READ, seq, generation, 0);
    check(
        service(selector ^ 1, &read[..READ_BYTES], &mut read_reply) == E_AUTH,
        -28,
    );
    let stale = request(AUDIT_READ, seq, generation + 1, 0);
    check(
        service(selector, &stale[..READ_BYTES], &mut read_reply) == E_STALE,
        -29,
    );
    check(read_reply.iter().all(|&byte| byte == 0x5a), -30);

    let (audit_seq, digest) = loop {
        let mut read = request(AUDIT_READ, seq, generation, 0);
        transact(selector, &mut read[..READ_BYTES], &mut read_reply, until);
        check(done(&read_reply, AUDIT_READ, seq, generation), -31);
        if read_reply[HEADER_BYTES..].iter().any(|&byte| byte != 0) {
            let mut replay = [0; AUDIT_REPLY_BYTES];
            check(
                service(selector, &read[..READ_BYTES], &mut replay) == 0,
                -32,
            );
            check(replay == read_reply, -33);
            break validate_record(&read_reply);
        }
        check(clock() < until, -34);
        seq += 1;
        yield_now();
    };

    seq += 1;
    let mut ack = request(AUDIT_ACK, seq, generation, audit_seq);
    ack[64..].copy_from_slice(&digest);
    let mut corrupt = ack;
    corrupt[64] ^= 1;
    let mut ack_reply = [0x5a; HEADER_BYTES];
    check(
        service(selector, &corrupt, &mut ack_reply) == E_CONFLICT,
        -35,
    );
    check(ack_reply.iter().all(|&byte| byte == 0x5a), -36);
    transact(selector, &mut ack, &mut ack_reply, until);
    check(done(&ack_reply, AUDIT_ACK, seq, generation), -37);
    let mut replay = [0; HEADER_BYTES];
    check(
        service(selector, &ack, &mut replay) == 0 && replay == ack_reply,
        -38,
    );

    let retire = request(TRANSPORT_ACK, seq, generation, 0);
    check(
        service(selector, &retire[..HEADER_BYTES], &mut ack_reply) == 0,
        -39,
    );
    check(done(&ack_reply, TRANSPORT_ACK, seq, generation), -40);
    check(service(selector, &ack, &mut replay) == E_STALE, -41);

    seq += 1;
    let mut scan = request(AUDIT_READ, seq, generation, 0);
    transact(selector, &mut scan[..READ_BYTES], &mut read_reply, until);
    check(done(&read_reply, AUDIT_READ, seq, generation), -42);
    if read_reply[HEADER_BYTES..].iter().any(|&byte| byte != 0) {
        check(validate_record(&read_reply).0 > audit_seq, -43);
    }
    while clock() < start.saturating_add(COHORT_NS) {
        yield_now();
    }
    leave(0);
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    leave(-44);
}

#[unsafe(no_mangle)]
unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, len: usize) -> *mut u8 {
    for offset in 0..len {
        // SAFETY: The compiler supplies valid nonoverlapping spans.
        unsafe {
            dst.add(offset)
                .write_volatile(src.add(offset).read_volatile())
        };
    }
    dst
}

#[unsafe(no_mangle)]
unsafe extern "C" fn memset(dst: *mut u8, byte: i32, len: usize) -> *mut u8 {
    for offset in 0..len {
        // SAFETY: The compiler supplies a writable span.
        unsafe { dst.add(offset).write_volatile(byte as u8) };
    }
    dst
}

#[unsafe(no_mangle)]
unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, len: usize) -> i32 {
    for offset in 0..len {
        // SAFETY: The compiler supplies readable spans.
        let (left, right) =
            unsafe { (a.add(offset).read_volatile(), b.add(offset).read_volatile()) };
        if left != right {
            return i32::from(left) - i32::from(right);
        }
    }
    0
}

#[unsafe(no_mangle)]
unsafe extern "C" fn bcmp(a: *const u8, b: *const u8, len: usize) -> i32 {
    // SAFETY: bcmp takes the same readable span arguments as memcmp.
    unsafe { memcmp(a, b, len) }
}
