#![no_std]
#![no_main]
//! External signed controller and publisher probes for the native D01 path.
//! The guest writes only its private evidence page. EL1 revalidates all inputs.

use core::{arch::asm, ptr::addr_of_mut};

mod audit_hash;

#[cfg(control_role = "2")]
const ROLE: u8 = 2;
#[cfg(control_role = "8")]
const ROLE: u8 = 8;
#[cfg(control_role = "2")]
const E_AUTH: i64 = -1;
const E_STALE: i64 = -4;
const E_CONFLICT: i64 = -5;
const E_EXPIRED: i64 = -7;
const E_BUSY: i64 = -10;
const E_AGAIN: i64 = -13;
#[cfg(control_role = "2")]
const TARGET: u64 = 0x100;
const RECORD_BYTES: usize = 256;
const PLAN_BYTES: usize = 212;
const WINDOW_NS: u64 = 100_000_000;
const MAGIC: u64 = 0x4359_5853_434f_4e00 | ROLE as u64;
const PROBE_WORDS: usize = if cfg!(sec_ps_recovery) { 12 } else { 8 };
const WEIGHT: u16 = 2;
const SELECTED: u16 = WEIGHT - 1;
const RETRY_LIMIT: u64 = if cfg!(sec_ps_recovery) { 80 } else { 20 };

#[used]
#[unsafe(link_section = ".rodata.role")]
static NOTE: [u8; 8] = [b'C', b'Y', b'R', b'3', ROLE, 3, 0, 0];

#[used]
#[unsafe(link_section = ".role_probe")]
static mut PROBE: [u64; PROBE_WORDS] = [0; PROBE_WORDS];

fn observe(slot: usize, value: u64) {
    // SAFETY: Only this EL0 thread writes the in-bounds diagnostic slots.
    unsafe {
        addr_of_mut!(PROBE)
            .cast::<u64>()
            .add(slot)
            .write_volatile(value)
    };
}

#[inline(always)]
fn svc(no: u64, args: [u64; 6]) -> i64 {
    let [mut x0, x1, x2, x3, x4, x5] = args;
    // SAFETY: ABI3 retains x1–x30. The stack holding user buffers remains
    // stable during the call. The assembly has a memory clobber.
    unsafe {
        asm!("svc #0", inlateout("x0") x0, in("x1") x1, in("x2") x2,
             in("x3") x3, in("x4") x4, in("x5") x5, in("x8") no, options(nostack));
    }
    x0 as i64
}

fn check(value: bool, code: u64) {
    if !value {
        observe(7, code);
        svc(1, [code, 0, 0, 0, 0, 0]);
        loop {
            core::hint::spin_loop();
        }
    }
}

fn yield_now() {
    check(svc(2, [0; 6]) == 0, 3);
}

#[cfg(any(control_role = "8", sec_ps_recovery))]
fn clock() -> u64 {
    let now = svc(4, [0; 6]);
    check(now > 0, 4);
    now as u64
}

fn get64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

fn get16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}

fn put<const N: usize>(bytes: &mut [u8], at: usize, value: [u8; N]) {
    bytes[at..at + N].copy_from_slice(&value);
}

fn service(cap: u64, input: &[u8], output: &mut [u8]) -> i64 {
    svc(
        0x50,
        [
            cap,
            input.as_ptr() as u64,
            input.len() as u64,
            0,
            output.as_mut_ptr() as u64,
            output.len() as u64,
        ],
    )
}

fn publish(wire: &[u8; PLAN_BYTES], record: &[u8; RECORD_BYTES]) -> i64 {
    svc(
        0x41,
        [
            wire.as_ptr() as u64,
            PLAN_BYTES as u64,
            record.as_ptr() as u64,
            1,
            0,
            0,
        ],
    )
}

fn plan_key(boot: u64, seq: u64) -> [u8; 24] {
    let mut key = [0; 24];
    for (at, v) in [(0, boot), (8, 1u64), (16, seq)] {
        put(&mut key, at, v.to_le_bytes());
    }
    key
}

fn query(key: &[u8; 24], reply: &mut [u8; 64]) -> i64 {
    svc(
        0x42,
        [key.as_ptr() as u64, 24, reply.as_mut_ptr() as u64, 64, 0, 0],
    )
}

fn plan(record: &[u8; RECORD_BYTES], sampled: u64, base: u64) -> [u8; PLAN_BYTES] {
    let mut wire = [0; PLAN_BYTES];
    put(&mut wire, 0, 0x4359_4c31u32.to_le_bytes());
    put(&mut wire, 4, 2u16.to_le_bytes());
    put(&mut wire, 6, 64u16.to_le_bytes());
    put(&mut wire, 8, (PLAN_BYTES as u32).to_le_bytes());
    put(&mut wire, 12, 1u16.to_le_bytes());
    put(&mut wire, 24, base.to_le_bytes());
    put(&mut wire, 64, 0x4359_5031u32.to_le_bytes());
    put(&mut wire, 68, 2u16.to_le_bytes());
    put(&mut wire, 70, 144u16.to_le_bytes());
    put(&mut wire, 72, 1u16.to_le_bytes());
    put(&mut wire, 74, 1u16.to_le_bytes());
    put(&mut wire, 76, 4u32.to_le_bytes());
    for (to, from) in [
        (16, 32),
        (40, 16),
        (48, 40),
        (80, 16),
        (88, 24),
        (96, 40),
        (104, 48),
        (112, 56),
        (120, 64),
        (128, 72),
        (136, 144),
    ] {
        put(&mut wire, to, get64(record, from).to_le_bytes());
    }
    put(&mut wire, 56, (sampled + 10_000_000_000).to_le_bytes());
    wire[176..208].copy_from_slice(&record[224..256]);
    put(&mut wire, 208, SELECTED.to_le_bytes());
    put(&mut wire, 210, WEIGHT.to_le_bytes());
    wire
}

#[cfg(control_role = "2")]
const fn hex(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    assert!(b.len() == 64);
    let mut out = [0; 32];
    let mut i = 0;
    while i < b.len() {
        let digit = match b[i] {
            b'0'..=b'9' => b[i] - b'0',
            b'a'..=b'f' => b[i] - b'a' + 10,
            _ => panic!("expected a lowercase digest"),
        };
        out[i / 2] |= digit << if i % 2 == 0 { 4 } else { 0 };
        i += 1;
    }
    out
}

#[cfg(control_role = "2")]
fn candidate_digest(mut snapshot: [u8; 264], base: u64) -> [u8; 32] {
    const CONFIG: [u8; 32] = hex(env!("CYX_CONTROL_CATALOG_DIGEST_HEX"));
    snapshot[72 + 6 * 16 + 2..72 + 7 * 16].fill(0);
    let label = b"CYX/REGISTERED-CANDIDATES/v0199";
    let mut bytes = [0; 408];
    bytes[..31].copy_from_slice(label);
    bytes[31..63].copy_from_slice(&CONFIG);
    bytes[63..327].copy_from_slice(&snapshot);
    let mut at = 328;
    // Fields 1..4 are native D01 measurements. Fields 5, 6 and 7 are
    // the live weight ordinal, absent usage and healthy business layout.
    for i in 0..4 {
        let present = snapshot[72 + (8 + i) * 16 + 2];
        let value = get64(&snapshot, 72 + (8 + i) * 16 + 8);
        bytes[at] = present;
        put(&mut bytes, at + 1, value.to_le_bytes());
        at += 9;
    }
    bytes[at] = 1;
    bytes[at + 1] = u8::from(base != 0);
    bytes[at + 18] = 1;
    bytes[at + 19] = 1;
    if base == 0 {
        put(&mut bytes, 391, 2u16.to_le_bytes());
        bytes[393..403].copy_from_slice(&[0, 0, 2, 1, 0, 1, 0, 2, 2, 0]);
        audit_hash::sha256(&bytes[..403])
    } else {
        // Recovery rounds occur after the one-window weight hold. Weight
        // 4 is now a legal adjacent candidate but outside this signed rule.
        put(&mut bytes, 391, 3u16.to_le_bytes());
        bytes[393..].copy_from_slice(&[0, 0, 2, 1, 0, 1, 0, 2, 2, 0, 2, 0, 2, 4, 0]);
        audit_hash::sha256(&bytes)
    }
}

#[cfg(control_role = "2")]
fn controller(cap: u64, boot: u64, base: u64) -> u64 {
    let mut snapshot = [0; 264];
    let mut record = [0; RECORD_BYTES];
    let mut output = [0; 8];
    let mut wire;
    let mut retries = 0;
    let mut retired_seq = 0;
    'attempt: loop {
        let ret = svc(0x40, [cap, 1, TARGET, snapshot.as_mut_ptr() as u64, 264, 0]);
        if matches!(ret, E_BUSY | E_AGAIN | E_STALE) {
            retries += 1;
            check(retries < RETRY_LIMIT, 10);
            yield_now();
            continue;
        }
        check(ret == 0, 11);
        let sampled = get64(&snapshot, 56);
        check(
            get64(&snapshot, 16) == boot
                && get64(&snapshot, 40) == TARGET
                && get64(&snapshot, 48) == boot
                && get16(&snapshot, 64) == 1,
            12,
        );
        let seq = sampled / WINDOW_NS;
        if seq <= retired_seq {
            retries += 1;
            check(retries < RETRY_LIMIT, 13);
            yield_now();
            continue;
        }
        let mut r = [0; RECORD_BYTES];
        put(&mut r, 0, 0x4359_4431u32.to_le_bytes());
        put(&mut r, 4, 3u16.to_le_bytes());
        put(&mut r, 6, (RECORD_BYTES as u16).to_le_bytes());
        for (at, value) in [
            (8, boot),
            (16, 1),
            (24, seq),
            (32, seq),
            (40, get64(&snapshot, 8)),
            (48, TARGET),
            (56, boot),
            (64, get64(&snapshot, 24)),
            (72, get64(&snapshot, 32)),
            (80, 9),
            (144, sampled + WINDOW_NS),
        ] {
            put(&mut r, at, value.to_le_bytes());
        }
        put(&mut r, 88, 1u32.to_le_bytes());
        for (at, v) in [
            (94, 1u16),
            (96, 1),
            (102, SELECTED),
            (104, u16::MAX),
            (156, SELECTED),
        ] {
            put(&mut r, at, v.to_le_bytes());
        }
        put(&mut r, 108, 3u32.to_le_bytes());
        put(&mut r, 152, 3u32.to_le_bytes());
        put(&mut r, 160, hex(env!("CYX_CONTROL_RULE_HASH_HEX")));
        put(&mut r, 224, candidate_digest(snapshot, base));
        wire = plan(&r, sampled, base);
        put(&mut r, 192, audit_hash::sha256(&wire));
        let result = service(cap, &r, &mut output);
        observe(5, result as u64);
        if matches!(result, E_BUSY | E_AGAIN | E_STALE | E_EXPIRED) {
            retries += 1;
            check(retries < RETRY_LIMIT, 13);
            yield_now();
            continue;
        }
        check(result == 0 && output == seq.to_le_bytes(), 14);
        record.copy_from_slice(&r);
        observe(1, 3);
        observe(3, get64(&snapshot, 8));
        observe(6, seq);
        // Make the remaining Decision credit available to the Publisher.
        yield_now();
        let key = plan_key(boot, seq);
        let mut reply = [0; 64];
        loop {
            let status = query(&key, &mut reply);
            if status == E_STALE {
                retired_seq = seq;
                retries += 1;
                check(retries < RETRY_LIMIT, 19);
                continue 'attempt;
            }
            check(status == 0, 20);
            let state = get16(&reply, 32);
            if state == 4 || (!cfg!(sec_ps_recovery) && matches!(state, 2..=3)) {
                break;
            }
            check(matches!(state, 1..=3), 35);
            yield_now();
        }
        break;
    }

    let mut stale = record;
    put(&mut stale, 56, (boot + 1).to_le_bytes());
    check(service(cap, &stale, &mut output) == E_STALE, 15);
    check(publish(&wire, &record) == E_AUTH, 16);
    let mut changed = record;
    changed[192] ^= 1;
    check(service(cap, &changed, &mut output) == E_CONFLICT, 18);
    // Retry in a later window: accepting an already applied decision is a
    // read of the original immutable registration.
    yield_now();
    check(
        service(cap, &record, &mut output) == 0 && output == record[24..32],
        17,
    );
    observe(1, 31);
    get64(&record, 32)
}

#[cfg(control_role = "8")]
fn publisher(cap: u64, boot: u64, base: u64, seq: &mut u64) -> u64 {
    let mut retries = 0;
    let mut response = [0; 304];
    let (wire, record) = 'attempt: loop {
        let now = clock();
        let decision_seq = now / WINDOW_NS;
        let mut request = [0; 72];
        put(&mut request, 0, 0x4359_4351u32.to_le_bytes());
        put(&mut request, 4, 1u16.to_le_bytes());
        put(&mut request, 6, 48u16.to_le_bytes());
        put(&mut request, 8, 9u16.to_le_bytes());
        put(&mut request, 12, 24u32.to_le_bytes());
        for (at, value) in [
            (16, *seq),
            (24, *seq - 1),
            (32, 1),
            (40, now + WINDOW_NS),
            (48, boot),
            (56, 1),
            (64, decision_seq),
        ] {
            put(&mut request, at, value.to_le_bytes());
        }
        let result = service(cap, &request, &mut response);
        check(result == 0, 21);
        check(
            get16(&response, 10) == 1 && get64(&response, 16) == *seq,
            22,
        );
        let raw_result = i32::from_le_bytes(response[12..16].try_into().unwrap()) as i64;
        *seq += 1;
        if raw_result == E_STALE {
            retries += 1;
            check(retries < RETRY_LIMIT, 23);
            yield_now();
            continue;
        }
        check(raw_result == 0, 24);
        let record: [u8; RECORD_BYTES] = response[48..].try_into().unwrap();
        let sampled = get64(&record, 144) - WINDOW_NS;
        let wire = plan(&record, sampled, base);
        let mut attempts = 0;
        loop {
            let result = publish(&wire, &record);
            if matches!(result, E_BUSY | E_AGAIN) && attempts < 2 {
                attempts += 1;
                continue;
            }
            observe(5, result as u64);
            if matches!(result, E_STALE | E_EXPIRED | E_BUSY | E_AGAIN) {
                retries += 1;
                check(retries < RETRY_LIMIT, 26);
                yield_now();
                continue 'attempt;
            }
            check(result == 0, 26);
            break;
        }
        break (wire, record);
    };
    observe(1, 3);
    let plan_seq = get64(&record, 32);
    observe(6, plan_seq);
    check(audit_hash::sha256(&wire) == record[192..224], 25);
    let key = plan_key(boot, plan_seq);
    let mut reply = [0; 64];
    let until = clock() + 2_000_000_000;
    loop {
        check(query(&key, &mut reply) == 0, 27);
        let state = get16(&reply, 32);
        if state == 4 {
            check(
                reply[..24] == key
                    && get64(&reply, 24) == base + 1
                    && reply[36..40] == [0; 4]
                    && get16(&reply, 40) == 1
                    && get16(&reply, 42) == 1,
                28,
            );
            observe(3, get64(&reply, 24));
            observe(4, u64::from(state));
            break;
        }
        check(matches!(state, 2 | 3) && clock() < until, 29);
        yield_now();
    }
    check(publish(&wire, &record) == 0, 30);
    let mut forged = wire;
    put(&mut forged, 210, (3 - WEIGHT).to_le_bytes());
    check(publish(&forged, &record) == E_CONFLICT, 31);
    let mut stale = key;
    put(
        &mut stale,
        0,
        if boot > 1 { boot - 1 } else { boot + 1 }.to_le_bytes(),
    );
    check(query(&stale, &mut reply) == E_STALE, 32);
    put(&mut stale, 0, boot.to_le_bytes());
    put(&mut stale, 8, 2u64.to_le_bytes());
    check(query(&stale, &mut reply) == E_STALE, 33);
    check(
        query(&key, &mut reply) == 0 && get64(&reply, 24) == base + 1,
        34,
    );
    observe(1, 63);
    plan_seq
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
extern "C" fn _start(args: u64, len: u64) -> ! {
    check(
        args != 0 && args.is_multiple_of(16) && matches!(len, 24 | 32),
        1,
    );
    // SAFETY: Exact aligned boot argument span in the role's private stack.
    let cap = unsafe { (args as *const u64).read_volatile() };
    let boot = cap >> 16;
    check(
        boot != 0 && cap & 0xffff == if ROLE == 2 { 0xc002 } else { 0xc003 },
        2,
    );
    observe(0, MAGIC);
    observe(2, boot);
    #[cfg(control_role = "8")]
    let mut rpc_seq = 1;
    #[cfg(sec_ps_recovery)]
    {
        let start = clock();
        for (round, delay) in [0, 2_200_000_000, 5_300_000_000, 10_400_000_000]
            .into_iter()
            .enumerate()
        {
            while clock() - start < delay {
                yield_now();
            }
            #[cfg(control_role = "2")]
            let plan = controller(cap, boot, round as u64);
            #[cfg(control_role = "8")]
            let plan = publisher(cap, boot, round as u64, &mut rpc_seq);
            observe(8 + round, plan);
        }
    }
    #[cfg(all(control_role = "2", not(sec_ps_recovery)))]
    controller(cap, boot, 0);
    #[cfg(all(control_role = "8", not(sec_ps_recovery)))]
    publisher(cap, boot, 0, &mut rpc_seq);
    loop {
        yield_now();
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    check(false, 255);
    loop {
        core::hint::spin_loop();
    }
}
