//! Normal signed CPU3 reader and role12 service for the mounted file proof.
#![no_std]
#![no_main]

mod audit_hash;
#[cfg(cyxia_fixture_write)]
mod file_owner_write_fixture;
use audit_hash::sha256;
use core::{arch::asm, panic::PanicInfo};

#[cfg(not(cyxia_fixture_write))]
const READ_CASES: u64 = 6;
#[cfg(not(cyxia_fixture_write))]
const WINDOW_NS: u64 = 100_000_000;

fn svc(number: u64, args: [u64; 6]) -> i64 {
    let [mut result, x1, x2, x3, x4, x5] = args;
    unsafe {
        asm!("svc #0", inlateout("x0") result, in("x1") x1, in("x2") x2, in("x3") x3,
             in("x4") x4, in("x5") x5, in("x8") number, options(nostack));
    }
    result as i64
}

fn call(endpoint: u64, selector: u64, input: &[u8], output: &mut [u8]) -> i64 {
    svc(
        0x50,
        [
            endpoint,
            input.as_ptr() as u64,
            input.len() as u64,
            selector,
            output.as_mut_ptr() as u64,
            output.len() as u64,
        ],
    )
}

fn check(condition: bool, code: u64) {
    if !condition {
        exit(code);
    }
}

fn exit(code: u64) -> ! {
    svc(1, [code, 0, 0, 0, 0, 0]);
    idle();
}

fn pause() {
    svc(2, [0; 6]);
}

fn idle() -> ! {
    loop {
        pause();
    }
}

fn clock() -> u64 {
    let now = svc(4, [0; 6]);
    check(now > 0, 30);
    now as u64
}

fn sleep_until(deadline: u64) {
    check(svc(3, [deadline, 0, 0, 0, 0, 0]) == 0, 31);
}

fn get(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

fn put(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn file_header(frame: &mut [u8], op: u16, id: u64) {
    let n = (frame.len() - 32) as u32;
    frame[..8].copy_from_slice(&0x0020_0004_4359_4651u64.to_le_bytes());
    frame[8..10].copy_from_slice(&op.to_le_bytes());
    frame[12..16].copy_from_slice(&n.to_le_bytes());
    put(frame, 16, id);
}

#[cfg(not(cyxia_fixture_write))]
fn reader(epoch: u64, endpoint: u64, cap: u64) -> ! {
    let mut read = [0; 44];
    let mut reply = [0; 384];
    for id in 1..=READ_CASES {
        if id != 1 {
            // Exercise separate dispatch windows with ordinary B3 work
            // between reads. Leave ample time after the alignment boundary
            // for the actual file IPC turns and reply retirement.
            let next = (clock() / WINDOW_NS + 1) * WINDOW_NS;
            sleep_until(next + 5_000_000);
        }
        file_header(&mut read, 3, id);
        put(&mut read, 32, id - 1);
        read[40..44].copy_from_slice(&8u32.to_le_bytes());
        let result = loop {
            let code = call(endpoint, cap, &read, &mut reply);
            if code != -13 {
                break code;
            }
            pause();
        };
        check(
            result == 0
                && get(&reply, 8) == id
                && get(&reply, 16) != 0
                && reply[36..40] == 8u32.to_le_bytes()
                && get(&reply, 72) == 1
                && reply[128..136]
                    == b"live checkpoint bytes\n"[(id - 1) as usize..(id + 7) as usize],
            11,
        );
        let mut replay = [0; 384];
        check(
            call(endpoint, cap, &read, &mut replay) == 0 && reply == replay,
            12,
        );
        let mut query = [0; 56];
        file_header(&mut query, 14, id);
        put(&mut query, 32, epoch);
        put(&mut query, 40, get(&reply, 16));
        put(&mut query, 48, id);
        let expected: [u8; 32] = reply[80..112].try_into().unwrap();
        let mut summary = [0; 128];
        check(
            call(endpoint, 0, &query, &mut summary) == 0
                && summary[36..40] == [0; 4]
                && summary[80..112] == expected,
            13,
        );
        let mut ack = [0; 88];
        file_header(&mut ack, 15, id);
        ack[32..56].copy_from_slice(&query[32..]);
        ack[56..88].copy_from_slice(&expected);
        loop {
            let code = call(endpoint, 0, &ack, &mut summary);
            if code != -13 {
                check(code == 0, 14);
                break;
            }
            pause();
        }
        let mut duplicate = [0; 128];
        check(
            call(endpoint, 0, &ack, &mut duplicate) == 0 && summary == duplicate,
            15,
        );
        check(call(endpoint, cap, &read, &mut reply) == -4, 16);
    }
    idle()
}

#[cfg(not(cyxia_fixture_write))]
fn service(epoch: u64, generation: u64, endpoint: u64) -> ! {
    let work = (epoch << 16) | 0xf201;
    for seq in 1..=READ_CASES {
        let mut message = [0; 552];
        let used = loop {
            let result = svc(0x31, [work, message.as_mut_ptr() as u64, 552, 0, 1, seq]);
            if result != -13 {
                break result;
            }
            sleep_until(clock() + 1_000_000);
        };
        check(
            used == 128
                && get(&message, 16) == seq
                && get(&message, 24) == epoch
                && get(&message, 112) == generation,
            21,
        );
        let request = &message[40..84];
        let context = get(request, 24);
        let mut admit = [0; 128];
        put(&mut admit, 0, 0x0080_0003_4359_5646);
        for (index, word) in [
            context,
            get(&message, 88),
            get(&message, 96),
            1 << 8,
            get(request, 16),
            seq,
            get(&message, 104),
        ]
        .into_iter()
        .enumerate()
        {
            put(&mut admit, 8 + index * 8, word);
        }
        let mut original = [0; 44];
        original.copy_from_slice(request);
        original[24..32].fill(0);
        let mut material = [0; 145];
        material[..17].copy_from_slice(b"CYX/FILE-ADMIT/v3");
        put(&mut material, 17, epoch);
        put(&mut material, 25, context);
        material[33..65].copy_from_slice(&sha256(&original));
        material[65..145].copy_from_slice(&admit[16..96]);
        let operation = sha256(&material);
        admit[96..128].copy_from_slice(&operation);
        let mut ack = [0; 48];
        check(
            call(endpoint, 0, &admit, &mut ack) == 0
                && ack[16..18] == [1, 0]
                && get(&ack, 32) != 0
                && get(&ack, 40) != 0,
            22,
        );
        let mut duplicate = [0; 48];
        check(
            call(endpoint, 0, &admit, &mut duplicate) == 0 && ack == duplicate,
            23,
        );
        let admission = get(&ack, 32);

        let mut completion = [0; 56];
        put(&mut completion, 0, 0x0038_0001_4359_4643);
        put(&mut completion, 8, admission);
        put(&mut completion, 16, 3);
        let mut done = [0; 8];
        check(call(endpoint, 0, &completion, &mut done) == 0, 24);

        let mut reply = [0; 136];
        put(&mut reply, 0, 0x0080_0003_4359_4652);
        put(&mut reply, 8, seq);
        put(&mut reply, 16, generation);
        reply[36..40].copy_from_slice(&8u32.to_le_bytes());
        put(&mut reply, 72, get(&message, 96));
        reply[128..136].copy_from_slice(&message[120..128]);
        let mut evidence = [0; 111];
        evidence[..23].copy_from_slice(b"CYX/FILE-READ-EFFECT/v1");
        put(&mut evidence, 23, epoch);
        put(&mut evidence, 31, generation);
        put(&mut evidence, 39, admission);
        evidence[47..79].copy_from_slice(&operation);
        evidence[79..111].copy_from_slice(&sha256(&reply));
        put(&mut completion, 16, 1);
        completion[24..56].copy_from_slice(&sha256(&evidence));
        check(
            call(endpoint, 0, &completion, &mut done) == 0 && done == [0; 8],
            25,
        );
        check(call(endpoint, 0, &completion, &mut done) == 0, 26);
        check(svc(0x31, [work, 0, 0, 0, 2, seq]) == 0, 27);
    }
    sleep_until(clock() + 200_000_000);
    exit(0)
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
extern "C" fn _start(args: *const u64, len: usize) -> ! {
    if len == 0 {
        idle();
    }
    check(len == 24, 1);
    // SAFETY: the native loader placed these three aligned words on this stack.
    let [epoch, x1, x2] = unsafe { args.cast::<[u64; 3]>().read_volatile() };
    #[cfg(cyxia_fixture_write)]
    use file_owner_write_fixture::{reader, service};
    if x1 & 0xffff == 0xf210 {
        reader(epoch, x1, x2)
    } else {
        service(epoch, x1, x2)
    }
}

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    exit(99)
}
