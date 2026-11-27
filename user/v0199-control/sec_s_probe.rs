#![no_std]
#![no_main]
//! External signed-roster acceptance packages for Operations and Security.
//! The ordinary startup roster continues to use main.rs.

use core::{arch::asm, ptr::addr_of_mut};

#[cfg(control_role = "6")]
const ROLE: u64 = 6;
#[cfg(control_role = "7")]
const ROLE: u64 = 7;

const STACK_GUARD: u64 = 0x0002_f000;
#[cfg(control_role = "7")]
const STACK_END: u64 = 0x0003_8000;
const TASK_CAP_BASE: u64 = 0x100;
#[cfg(control_role = "6")]
const SEND: u64 = 0x201;
#[cfg(control_role = "7")]
const RECEIVE: u64 = 0x301;
const E_AUTH: i64 = -1;
const E_FORMAT: i64 = -2;
const E_STALE: i64 = -4;
#[cfg(control_role = "6")]
const E_CONFLICT: i64 = -5;
const E_TIMEOUT: i64 = -6;
#[cfg(control_role = "7")]
const E_BUSY: i64 = -10;
#[cfg(control_role = "6")]
const E_UNSUPPORTED: i64 = -11;
const EFAULT: i64 = -12;
const EAGAIN: i64 = -13;
const MAGIC: u64 = 0x4359_5345_5343_5052;
const FRAME: &[u8; 4] = b"SECS";
#[cfg(control_role = "7")]
const FRAME_BYTES: usize = 552;
const VECTOR_MAGIC: u32 = 0x4359_5656;
const VECTOR_HEADER: usize = 16;
const VECTOR_ITEM: usize = 28;
const VECTOR_RESULT: usize = 64;
const CHECK_IPC: u64 = 1 << 0;
const CHECK_TASK: u64 = 1 << 1;
const CHECK_VECTOR: u64 = 1 << 2;
const CHECK_REVOKE: u64 = 1 << 3;
const CHECK_DENIALS: u64 = 1 << 4;
#[cfg(control_role = "6")]
const CHECK_ROLE_STOP: u64 = 1 << 5;

#[used]
#[unsafe(link_section = ".rodata.role")]
static ROLE_NOTE: [u8; 8] = [b'C', b'Y', b'R', b'3', ROLE as u8, 3, 0, 0];

// QMP may read the stopped guest's private RW page at image offset 0xf000.
// This page is ordinary EL0 memory and never supplies authority to EL1.
#[used]
#[unsafe(link_section = ".role_probe")]
static mut PROBE: [u64; 8] = [0; 8];

fn observe(slot: usize, value: u64) {
    // SAFETY: all call sites use slots 0..8. Only this EL0 thread writes.
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
    // SAFETY: AArch64 ABI3 saves x1–x30. The SVC may access the exact
    // specified caller stack ranges, so this assembly has a memory clobber.
    unsafe {
        asm!("svc #0", inlateout("x0") x0, in("x1") x1, in("x2") x2,
             in("x3") x3, in("x4") x4, in("x5") x5, in("x8") no, options(nostack));
    }
    x0 as i64
}

fn reject(code: u64) -> ! {
    observe(7, code);
    svc(1, [code, 0, 0, 0, 0, 0]);
    loop {
        core::hint::spin_loop();
    }
}

fn check(ok: bool, code: u64) {
    if !ok {
        reject(code);
    }
}

fn clock() -> u64 {
    let result = svc(4, [0; 6]);
    check(result >= 0, 1);
    result as u64
}

fn yield_now() {
    check(svc(2, [0; 6]) == 0, 2);
}

fn sleep(now: u64) {
    check(
        svc(3, [now.saturating_add(1_000_000), 0, 0, 0, 0, 0]) == 0,
        3,
    );
}

#[cfg(control_role = "6")]
fn probe_ipc(epoch: u64) {
    let cap = (epoch << 32) | SEND;
    let mut frame = *FRAME;
    let address = core::hint::black_box(frame.as_mut_ptr()) as u64;
    let args = [cap, address, frame.len() as u64, 1, 0, 1];
    check(svc(0x30, [cap, STACK_GUARD, 4, 1, 0, 1]) == EFAULT, 10);
    check(svc(0x30, args) == 0, 11);
    check(svc(0x30, args) == 0, 12);
    frame[0] ^= 1;
    core::hint::black_box(&mut frame);
    check(svc(0x30, args) == E_CONFLICT, 13);
    check(svc(0x30, [cap, address, 4, 2, 0, 1]) == EAGAIN, 14);
    check(
        svc(0x30, [cap, address, 4, 2, u64::MAX, 0]) == E_UNSUPPORTED,
        15,
    );
}

#[cfg(control_role = "7")]
fn probe_ipc(epoch: u64) {
    let cap = (epoch << 32) | RECEIVE;
    let mut reply = [0xa5; FRAME_BYTES];
    let address = reply.as_mut_ptr() as u64;
    let len = reply.len() as u64;
    check(svc(0x30, [cap, address, 4, 1, 0, 1]) == E_AUTH, 20);
    check(svc(0x31, [cap, STACK_END - 8, len, 0, 1, 1]) == EFAULT, 21);
    let args = [cap, address, len, 0, 1, 1];
    let mut result = svc(0x31, args);
    while result == EAGAIN {
        yield_now();
        result = svc(0x31, args);
    }
    check(result == 44, 22);
    let sender_generation = u64_at(&reply, 8);
    check(
        u64_at(&reply, 0) == 6
            && sender_generation != 0
            && u64_at(&reply, 16) == 1
            && u64_at(&reply, 24) == epoch
            && u64_at(&reply, 32) == 4
            && &reply[40..44] == FRAME
            && reply[44] == 0xa5,
        23,
    );
    observe(6, sender_generation);
    let snapshot = reply;
    reply.fill(0xa5);
    check(svc(0x31, args) == 44 && reply == snapshot, 24);
    check(svc(0x31, [cap, address, len, 0, 1, 2]) == E_BUSY, 25);
    let ack = [cap, 0, 0, 0, 2, 1];
    check(svc(0x31, ack) == 0 && svc(0x31, ack) == 0, 26);
    check(svc(0x31, args) == E_STALE, 27);
    check(svc(0x31, [cap, address, len, 0, 1, 3]) == EAGAIN, 28);
    check(svc(0x31, [cap, address, len, 0, 1, 2]) == EAGAIN, 29);
}

fn probe_ungranted_calls() {
    // The register shapes are valid, but they do not convey authority. Any
    // premature pointer validation would observe the caller's unmapped page.
    let source = STACK_GUARD;
    let output = STACK_GUARD + 512;
    for (number, arguments) in [
        (0x10, [1, source, 32, output, 48, 0]),
        (0x13, [1, 1, 1, output, 48, 0]),
        (0x20, [0, 4096, 0, 0, output, 32]),
        (0x21, [1, 1, source, 1, 1, 0]),
        (0x22, [1, source, 4096, 1, 0, 0]),
        (0x40, [1, 1, 0, output, 264, 0]),
        (0x41, [source, 64, output, 1, 0, 0]),
        (0x42, [source, 24, output, 64, 0, 0]),
        (0x43, [1, source, 96, 0, 0, 0]),
        (0x50, [1, source, 48, 0, output, 48]),
    ] {
        check(svc(number, arguments) == E_AUTH, 200 + number);
    }
}

fn probe_task(epoch: u64, generation: u64, cap: u64, other: u64) -> [u8; 48] {
    let mut reply = [0xa5; 64];
    let address = reply.as_mut_ptr() as u64;
    let len = reply.len() as u64;
    check(
        svc(0x11, [other, generation, address, len, 0, 0]) == E_AUTH,
        100,
    );
    check(
        svc(0x11, [other, generation, address, len, 1, 0]) == E_AUTH
            && svc(0x11, [cap, generation, address, len, 1, 0]) == E_FORMAT,
        107,
    );
    check(
        svc(0x11, [cap, generation + 1, address, len, 0, 0]) == E_STALE,
        101,
    );
    let previous = ((epoch - 1) << 32) | (cap & 0xffff_ffff);
    check(
        svc(0x11, [previous, generation, address, len, 0, 0]) == E_STALE,
        102,
    );
    check(
        svc(0x11, [cap, generation, STACK_GUARD, len, 0, 0]) == EFAULT,
        103,
    );
    check(reply == [0xa5; 64], 104);
    check(svc(0x11, [cap, generation, address, len, 0, 0]) == 0, 105);

    let mut expected = [0; 48];
    expected[..8].copy_from_slice(&cap.to_le_bytes());
    expected[8..16].copy_from_slice(&generation.to_le_bytes());
    expected[16..20].copy_from_slice(&0xffffu32.to_le_bytes());
    expected[20..22].copy_from_slice(&4u16.to_le_bytes());
    check(reply[..48] == expected && reply[48..] == [0xa5; 16], 106);
    expected
}

fn probe_vector(cap: u64, generation: u64, task: &[u8; 48]) {
    let mut input = [0; VECTOR_HEADER + 3 * VECTOR_ITEM];
    let input_len = input.len() as u32;
    input[..4].copy_from_slice(&VECTOR_MAGIC.to_le_bytes());
    input[4..6].copy_from_slice(&2u16.to_le_bytes());
    input[6..8].copy_from_slice(&(VECTOR_HEADER as u16).to_le_bytes());
    input[8..10].copy_from_slice(&3u16.to_le_bytes());
    input[12..16].copy_from_slice(&input_len.to_le_bytes());
    for (at, row) in input[VECTOR_HEADER..]
        .chunks_exact_mut(VECTOR_ITEM)
        .enumerate()
    {
        let (op, version, tag) = [
            (2u16, generation, 11u64),
            (1, generation, 12),
            (2, generation + 1, 13),
        ][at];
        row[..2].copy_from_slice(&op.to_le_bytes());
        row[4..12].copy_from_slice(&cap.to_le_bytes());
        row[12..20].copy_from_slice(&version.to_le_bytes());
        row[20..28].copy_from_slice(&tag.to_le_bytes());
    }
    let mut reply = [0xa5; VECTOR_HEADER + 3 * VECTOR_RESULT];
    let mut args = [
        input.as_ptr() as u64,
        input.len() as u64,
        reply.as_mut_ptr() as u64,
        reply.len() as u64,
        clock().saturating_add(500_000_000),
        0,
    ];
    input[10] = 1;
    core::hint::black_box(&mut input);
    check(svc(0x32, args) == E_FORMAT && reply[0] == 0xa5, 110);
    input[10] = 0;
    core::hint::black_box(&mut input);
    let deadline = args[4];
    args[4] = 1;
    check(svc(0x32, args) == 0 && i32_at(&reply, 24) == E_TIMEOUT, 111);
    args[4] = deadline;
    check(svc(0x32, args) == 0, 112);
    check(
        reply[..12] == input[..12] && i32_at(&reply, 12) == reply.len() as i64,
        113,
    );
    for (at, row) in reply[VECTOR_HEADER..]
        .chunks_exact(VECTOR_RESULT)
        .enumerate()
    {
        let (expected_tag, result) = [(11, 0), (12, E_AUTH), (13, E_STALE)][at];
        check(
            u64_at(row, 0) == expected_tag && i32_at(row, 8) == result,
            114 + at as u64,
        );
        if at == 0 {
            check(i32_at(row, 12) == 2 && &row[16..] == task, 117);
        } else {
            check(row[12..] == [0; 52], 118);
        }
    }
}

fn probe_revoke(epoch: u64, generation: u64, cap: u64, other: u64) {
    let revoke = [cap, epoch, 1, 0, 0, 0];
    check(svc(0x12, [other, epoch, 1, 0, 0, 0]) == E_AUTH, 120);
    check(svc(0x12, [cap, epoch + 1, 1, 0, 0, 0]) == E_STALE, 121);
    check(svc(0x12, revoke) == 0 && svc(0x12, revoke) == 0, 122);
    check(svc(0x12, [cap, epoch, 2, 0, 0, 0]) == E_STALE, 123);
    let mut reply = [0xa5; 48];
    let args = [cap, generation, reply.as_mut_ptr() as u64, 48, 0, 0];
    check(svc(0x11, args) == E_STALE && reply == [0xa5; 48], 124);
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

fn i32_at(bytes: &[u8], at: usize) -> i64 {
    i64::from(i32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()))
}

fn compute(mut value: u64) -> u64 {
    // SAFETY: touches only caller registers. The role returns to the
    // measured scheduler with Clock between bounded blocks of work.
    unsafe {
        asm!(
            "1:",
            "eor {value}, {value}, {value}, ror #11",
            "add {value}, {value}, #1",
            "subs {count}, {count}, #1",
            "b.ne 1b",
            value = inout(reg) value,
            count = inout(reg) 65_536u64 => _,
            options(nomem, nostack),
        );
    }
    value
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
extern "C" fn _start(address: u64, length: u64) -> ! {
    check(
        length == 32 && address != 0 && address.is_multiple_of(16),
        4,
    );
    let args = address as *const u64;
    // SAFETY: these are the two authenticated startup words on our stack.
    let generation = u64::from_le(unsafe { args.add(2).read_volatile() });
    let epoch = u64::from_le(unsafe { args.add(3).read_volatile() });
    check(
        generation > 0 && (2..=u64::from(u32::MAX)).contains(&epoch),
        5,
    );
    observe(0, MAGIC);
    observe(1, ROLE);
    observe(2, epoch);
    observe(3, generation);

    let start = clock();
    sleep(start);
    yield_now();
    let mut value = ROLE;
    let mut blocks = 0u64;
    // Keep both roles continuously runnable through the sealed PMU prefix.
    while clock().saturating_sub(start) < 1_350_000_000 {
        value = core::hint::black_box(compute(value));
        blocks += 1;
        observe(5, blocks);
    }

    let role_index = ROLE - 6;
    let cap = (epoch << 32) | (TASK_CAP_BASE + role_index);
    let other = (epoch << 32) | (TASK_CAP_BASE + (role_index ^ 1));
    let mut checks = 0;
    probe_ipc(epoch);
    checks |= CHECK_IPC;
    let task = probe_task(epoch, generation, cap, other);
    checks |= CHECK_TASK;
    probe_vector(cap, generation, &task);
    checks |= CHECK_VECTOR;
    probe_revoke(epoch, generation, cap, other);
    checks |= CHECK_REVOKE;
    probe_ungranted_calls();
    checks |= CHECK_DENIALS;
    observe(4, checks);

    loop {
        value = core::hint::black_box(compute(value));
        blocks += 1;
        observe(5, blocks);
        let now = clock();
        #[cfg(control_role = "6")]
        if epoch == 2 && now.saturating_sub(start) >= 2_200_000_000 {
            observe(4, checks | CHECK_ROLE_STOP);
            // SAFETY: the fixture intentionally triggers a routine lower-EL
            // translation fault on its own unmapped stack guard.
            unsafe { asm!("ldr xzr, [{guard}]", guard = in(reg) STACK_GUARD, options(nostack)) };
            reject(125);
        }
        if blocks.is_multiple_of(8) {
            sleep(now);
        } else if blocks % 8 == 4 {
            yield_now();
        }
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    reject(127)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, len: usize) -> *mut u8 {
    for at in 0..len {
        unsafe { dst.add(at).write_volatile(src.add(at).read_volatile()) };
    }
    dst
}

#[unsafe(no_mangle)]
unsafe extern "C" fn memset(dst: *mut u8, value: i32, len: usize) -> *mut u8 {
    for at in 0..len {
        unsafe { dst.add(at).write_volatile(value as u8) };
    }
    dst
}

#[unsafe(no_mangle)]
unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, len: usize) -> i32 {
    for at in 0..len {
        let left = unsafe { a.add(at).read_volatile() };
        let right = unsafe { b.add(at).read_volatile() };
        if left != right {
            return i32::from(left) - i32::from(right);
        }
    }
    0
}

#[unsafe(no_mangle)]
unsafe extern "C" fn bcmp(a: *const u8, b: *const u8, len: usize) -> i32 {
    unsafe { memcmp(a, b, len) }
}
