#![no_std]
#![no_main]
//! Signed EL0 fixtures for in-place CPU0 role recovery.

use core::{arch::asm, ptr::addr_of_mut};

#[cfg(control_role = "11")]
mod audit_hash;

#[cfg(control_role = "6")]
const ROLE: u8 = 6;
#[cfg(control_role = "7")]
const ROLE: u8 = 7;
#[cfg(control_role = "11")]
const ROLE: u8 = 11;
const MAGIC: u64 = 0x4359_5852_4543_5600 | ROLE as u64;
const E_AUTH: i64 = -1;
const E_STALE: i64 = -4;
const E_AGAIN: i64 = -13;
const FIRST_SELECTOR: u64 = match ROLE {
    6 => 0xc000,
    7 => 0xc001,
    _ => 0xc007,
};

#[used]
#[unsafe(link_section = ".rodata.role")]
static ROLE_NOTE: [u8; 8] = [b'C', b'Y', b'R', b'3', ROLE, 3, 0, 0];

// The host observes this page through the linked private role backing. It
// carries no authority and is zero when the verified image starts again.
#[used]
#[unsafe(link_section = ".role_probe")]
static mut PROBE: [u64; 16] = [0; 16];

fn observe(slot: usize, value: u64) {
    // SAFETY: only this EL0 thread writes these in-bounds evidence words.
    unsafe {
        addr_of_mut!(PROBE)
            .cast::<u64>()
            .add(slot)
            .write_volatile(value)
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

fn leave(status: u64) -> ! {
    svc(1, [status, 0, 0, 0, 0, 0]);
    loop {
        core::hint::spin_loop();
    }
}

fn check(yes: bool, code: u64) {
    if !yes {
        observe(15, code);
        leave(code);
    }
}

fn yield_now() {
    check(svc(2, [0; 6]) == 0, 1);
}

fn clock() -> u64 {
    let now = svc(4, [0; 6]);
    check(now > 0, 2);
    now as u64
}

fn get64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

#[cfg(any(control_role = "6", control_role = "7"))]
fn snapshot(cap: u64, reply: &mut [u8; 264]) -> i64 {
    svc(0x40, [cap, 1, 0x100, reply.as_mut_ptr() as u64, 264, 0])
}

#[cfg(any(control_role = "6", control_role = "7"))]
fn brain(cap: u64, epoch: u64, generation: u64, start: u64) -> ! {
    let mut reply = [0xa5; 264];
    if generation == 2 {
        let result = snapshot((epoch << 16) | FIRST_SELECTOR, &mut reply);
        observe(13, result as u64);
        check(matches!(result, E_AUTH | E_STALE), 3);
        check(reply == [0xa5; 264], 4);
    }
    loop {
        let result = snapshot(cap, &mut reply);
        if result == 0 {
            break;
        }
        check(
            matches!(result, E_AGAIN | E_STALE | -10) && clock() - start < 2_000_000_000,
            5,
        );
        yield_now();
    }
    check(get64(&reply, 16) == epoch && get64(&reply, 40) == 0x100, 6);
    observe(5, get64(&reply, 8));
    observe(4, 1);
    if generation == 1 {
        let delay = if ROLE == 6 {
            1_300_000_000
        } else {
            4_400_000_000
        };
        while clock() - start < delay {
            yield_now();
        }
        observe(7, clock());
        observe(4, 2);
        #[cfg(control_role = "6")]
        // The package deliberately reads its own unmapped stack guard.
        // This produces an attributed EL0 data abort on the real vector.
        unsafe {
            asm!("ldr xzr, [{guard}]", guard = in(reg) 0x0002_f000u64, options(nostack));
        }
        #[cfg(control_role = "6")]
        check(false, 7);
        leave(0);
    }
    observe(7, clock());
    observe(4, 3);
    loop {
        yield_now();
    }
}

#[cfg(control_role = "11")]
mod supervisor {
    use super::*;

    const READ: u16 = 1;
    const ACK: u16 = 2;
    const TRANSPORT_ACK: u16 = 12;
    const LEASE: u64 = 400_000_000;

    fn request(op: u16, seq: u64, generation: u64, cursor: u64, until: u64) -> [u8; 96] {
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
            (40, until),
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
                break;
            }
            let now = clock();
            check(matches!(status, E_AGAIN | -6) && now < limit, 8);
            if status == -6 {
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

    pub(super) fn run(cap: u64, epoch: u64, generation: u64, start: u64) -> ! {
        let old_cap = (epoch << 16) | FIRST_SELECTOR;
        let limit = start + 8_000_000_000;
        let mut seq = 1;
        let mut reply = [0xa5; 192];
        if generation == 2 {
            let req = request(READ, seq, 1, 0, clock() + LEASE);
            let old_cap_status = call(old_cap, &req[..64], &mut reply);
            let old_generation_status = call(cap, &req[..64], &mut reply);
            observe(13, old_cap_status as u64);
            check(
                old_cap_status == E_AUTH
                    && old_generation_status == E_STALE
                    && reply == [0xa5; 192],
                9,
            );
        }
        let (audit_seq, digest) = loop {
            let mut req = request(READ, seq, generation, 0, clock() + LEASE);
            transact(cap, &mut req[..64], &mut reply, limit);
            check(done(&reply, READ, seq, generation), 10);
            if reply[48..].iter().any(|&byte| byte != 0) {
                let record: &[u8; 128] = reply[64..].try_into().unwrap();
                let audit_seq = get64(&reply, 56);
                let digest = audit_hash::record_digest(record);
                check(
                    reply[48..56] == [1, 0, 0, 0, 0, 0, 0, 0]
                        && get64(record, 8) == epoch
                        && get64(record, 16) == audit_seq
                        && audit_seq != 0
                        && digest == record[96..],
                    11,
                );
                break (audit_seq, digest);
            }
            seq += 1;
            check(clock() < limit, 12);
            yield_now();
        };
        observe(8, audit_seq);
        for i in 0..4 {
            observe(9 + i, get64(&digest, i * 8));
        }
        observe(7, clock());
        observe(4, 2);
        if generation == 1 {
            // The earlier consumer received a real record and leaves no ACK.
            // Keep the witness page live long enough for independent QMP readback.
            let leave_after = (start + 7_600_000_000).max(clock() + 900_000_000);
            while clock() < leave_after {
                yield_now();
            }
            leave(0);
        }
        seq += 1;
        let mut old = request(ACK, seq, 1, audit_seq, clock() + LEASE);
        old[64..].copy_from_slice(&digest);
        let mut ack_reply = [0xa5; 48];
        let retired = call(old_cap, &old, &mut ack_reply);
        let stale = call(cap, &old, &mut ack_reply);
        observe(14, retired as u64);
        check(
            retired == E_AUTH && stale == E_STALE && ack_reply == [0xa5; 48],
            13,
        );
        let mut ack = request(ACK, seq, generation, audit_seq, clock() + LEASE);
        ack[64..].copy_from_slice(&digest);
        transact(cap, &mut ack, &mut ack_reply, limit);
        check(done(&ack_reply, ACK, seq, generation), 14);
        observe(4, 3);
        let retire = request(TRANSPORT_ACK, seq, generation, 0, clock() + LEASE);
        check(call(cap, &retire[..48], &mut ack_reply) == 0, 15);
        check(done(&ack_reply, TRANSPORT_ACK, seq, generation), 16);
        let mut req = request(READ, seq + 1, generation, 0, clock() + LEASE);
        transact(cap, &mut req[..64], &mut reply, limit);
        check(
            done(&reply, READ, seq + 1, generation)
                && (reply[48..].iter().all(|&b| b == 0) || get64(&reply, 56) > audit_seq),
            17,
        );
        observe(4, 4);
        loop {
            yield_now();
        }
    }
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
extern "C" fn _start(args: u64, len: u64) -> ! {
    check(
        args != 0 && args.is_multiple_of(16) && matches!(len, 24 | 32),
        18,
    );
    // SAFETY: the loader installed these aligned initial stack words.
    let params = args as *const u64;
    let cap = u64::from_le(unsafe { params.read_volatile() });
    let generation = u64::from_le(unsafe { params.add(2).read_volatile() });
    let epoch = cap >> 16;
    check(epoch != 0 && matches!(generation, 1 | 2), 19);
    check((cap & 0xffff == FIRST_SELECTOR) == (generation == 1), 20);
    for i in 0..16 {
        // SAFETY: verify the fresh image page before storing probe results.
        let prior = unsafe { addr_of_mut!(PROBE).cast::<u64>().add(i).read_volatile() };
        check(prior == 0, 21);
    }
    observe(0, MAGIC);
    observe(1, epoch);
    observe(2, generation);
    observe(3, cap);
    let start = clock();
    observe(6, start);
    #[cfg(any(control_role = "6", control_role = "7"))]
    brain(cap, epoch, generation, start);
    #[cfg(control_role = "11")]
    supervisor::run(cap, epoch, generation, start)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    observe(15, 255);
    leave(255);
}

#[unsafe(no_mangle)]
unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, len: usize) -> *mut u8 {
    for index in 0..len {
        // SAFETY: the compiler supplies these checked, nonoverlapping spans.
        unsafe {
            dst.add(index)
                .write_volatile(src.add(index).read_volatile())
        };
    }
    dst
}

#[unsafe(no_mangle)]
unsafe extern "C" fn memset(dst: *mut u8, value: i32, len: usize) -> *mut u8 {
    for index in 0..len {
        // SAFETY: the compiler supplies a writable span of length len.
        unsafe { dst.add(index).write_volatile(value as u8) };
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
    // SAFETY: the compiler's span contract is identical to memcmp.
    unsafe { memcmp(lhs, rhs, len) }
}
