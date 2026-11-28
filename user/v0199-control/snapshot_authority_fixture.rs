//! Signed Supervisor fixture for protected snapshot admission and settlement.
#![no_std]
#![no_main]

use core::{arch::asm, panic::PanicInfo};

const VOLUME: &[u8; 16] = include_bytes!(env!("CYX_SNAPSHOT_AUTHORITY_TEST_VOLUME"));
const RECOVERY_GENERATION: &[u8; 8] =
    include_bytes!(env!("CYX_SNAPSHOT_AUTHORITY_TEST_PRINCIPAL_GENERATION"));

fn svc(number: u64, args: [u64; 6]) -> i64 {
    let [mut result, x1, x2, x3, x4, x5] = args;
    unsafe {
        asm!("svc #0", inlateout("x0") result, in("x1") x1, in("x2") x2, in("x3") x3,
             in("x4") x4, in("x5") x5, in("x8") number, options(nostack));
    }
    result as i64
}

fn stop(code: u64) -> ! {
    svc(1, [code, 0, 0, 0, 0, 0]);
    loop {
        core::hint::spin_loop();
    }
}

fn call(endpoint: u64, selector: u64, input: &[u8], output: &mut [u8]) -> i64 {
    // Preserve the signed resident's ordinary per-window lifecycle while the
    // probe drives one request in a turn.
    svc(4, [0; 6]);
    let result = svc(
        0x50,
        [
            endpoint,
            input.as_ptr() as u64,
            input.len() as u64,
            selector,
            output.as_mut_ptr() as u64,
            output.len() as u64,
        ],
    );
    svc(0x50, [0; 6]);
    svc(2, [0; 6]);
    result
}

fn header(wire: &mut [u8], op: u16) {
    let payload = (wire.len() - 32) as u32;
    wire[..8].copy_from_slice(&0x0020_0004_4359_4651u64.to_le_bytes());
    wire[8..10].copy_from_slice(&op.to_le_bytes());
    wire[12..16].copy_from_slice(&payload.to_le_bytes());
    wire[16..24].copy_from_slice(&1u64.to_le_bytes());
    wire[32..48].copy_from_slice(VOLUME);
    wire[48..52].copy_from_slice(&15u32.to_le_bytes());
    wire[52..60].copy_from_slice(RECOVERY_GENERATION);
    wire[60..68].copy_from_slice(&1u64.to_le_bytes());
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
extern "C" fn _start(args: *const u64, len: usize) -> ! {
    if args.is_null() || len != 24 {
        stop(1);
    }
    // EL1 has copied the three words to this role's owned stack.
    let [control, endpoint, generation] = unsafe { args.cast::<[u64; 3]>().read_volatile() };
    if endpoint & 0xffff != 0x5301 || generation == 0 || generation > u64::MAX >> 16 {
        stop(2);
    }
    let selector = (generation << 16) | 0x5302;
    let mut freeze = [0; 84];
    header(&mut freeze, 0x27);
    freeze[68..76].copy_from_slice(&1u64.to_le_bytes());
    freeze[76..80].copy_from_slice(&1u32.to_le_bytes());
    let mut reply = [0xa5; 224];
    if call(endpoint, selector ^ (1 << 16), &freeze, &mut reply) != -4 {
        stop(3);
    }
    if call(endpoint ^ (1 << 16), selector, &freeze, &mut reply) != -4 {
        stop(4);
    }
    freeze[32] ^= 1;
    if call(endpoint, selector, &freeze, &mut reply) != -1 {
        stop(5);
    }
    freeze[32] ^= 1;
    freeze[52] ^= 2;
    if call(endpoint, selector, &freeze, &mut reply) != -1 {
        stop(6);
    }
    freeze[52] ^= 2;
    let mut restore = [0; 124];
    header(&mut restore, 0x23);
    restore[68..76].copy_from_slice(&1u64.to_le_bytes());
    restore[76..92].copy_from_slice(VOLUME);
    restore[92..100].copy_from_slice(&1u64.to_le_bytes());
    restore[108..116].copy_from_slice(&1u64.to_le_bytes());
    restore[116..120].copy_from_slice(&1u32.to_le_bytes());
    if call(endpoint, selector, &restore, &mut reply) != -1 {
        stop(7);
    }
    if call(endpoint, selector, &freeze, &mut reply) != -13 || reply != [0xa5; 224] {
        stop(8);
    }
    let mut completed = false;
    for _ in 0..16 {
        match call(endpoint, selector, &freeze, &mut reply) {
            -13 if reply == [0xa5; 224] => continue,
            144 => {
                completed = true;
                break;
            }
            _ => stop(10),
        }
    }
    if !completed
        || reply[..8] != 0x0080_0003_4359_4652u64.to_le_bytes()
        || reply[8..16] != 1u64.to_le_bytes()
        || reply[24..32] != 3u64.to_le_bytes()
        || reply[40..48] != 12u64.to_le_bytes()
        || reply[48..56] != 1u64.to_le_bytes()
        || reply[56..64] != 3u64.to_le_bytes()
        || reply[80..112] == [0; 32]
        || reply[128..136] != 2u64.to_le_bytes()
        || reply[136..140] != 1u32.to_le_bytes()
        || reply[140..144] != 1u32.to_le_bytes()
        || reply[144..] != [0xa5; 80]
    {
        stop(11);
    }
    let terminal = reply;
    reply.fill(0xa5);
    if call(endpoint, selector, &freeze, &mut reply) != 144 || reply != terminal {
        stop(12);
    }
    loop {
        svc(4, [0; 6]);
        // Same unprovisioned legacy control endpoint used by the stock role.
        svc(0x50, [control, 0, 0, 0, 0, 0]);
        svc(2, [0; 6]);
    }
}

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    stop(9)
}
