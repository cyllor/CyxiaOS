#![no_std]
#![no_main]

use core::{arch::asm, panic::PanicInfo};

fn svc(number: u64, args: [u64; 6]) -> i64 {
    let [mut result, x1, x2, x3, x4, x5] = args;
    unsafe {
        asm!("svc #0", inlateout("x0") result, in("x1") x1, in("x2") x2, in("x3") x3,
             in("x4") x4, in("x5") x5, in("x8") number, options(nostack));
    }
    result as i64
}

#[cfg(not(any(file_owner_fault_peer, file_owner_idle_supervisor)))]
fn auth(cap: u64, input: &[u64], reply: &mut [u64]) -> i64 {
    svc(
        0x50,
        [
            cap,
            input.as_ptr() as u64,
            size_of_val(input) as u64,
            0,
            reply.as_mut_ptr() as u64,
            size_of_val(reply) as u64,
        ],
    )
}

fn exit(status: u64) -> ! {
    svc(1, [status, 0, 0, 0, 0, 0]);
    loop {
        core::hint::spin_loop()
    }
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
#[cfg(not(any(file_owner_fault_peer, file_owner_idle_supervisor)))]
extern "C" fn _start(args: *const u64, len: usize) -> ! {
    if len != 24 {
        exit(1);
    }
    // The kernel copied these aligned words onto our private startup stack.
    let [epoch, generation, selector] = unsafe { args.cast::<[u64; 3]>().read_volatile() };
    if epoch == 0 || generation == 0 || selector >> 16 != epoch {
        exit(2);
    }
    let mut reply = [0xa5a5_a5a5_a5a5_a5a5; 6];
    let admit: [u64; 16] = [
        0x0080_0003_4359_5646,
        9,
        2,
        1,
        0x100,
        1,
        1,
        1,
        0,
        0,
        0,
        0,
        1,
        1,
        1,
        1,
    ];
    if auth(selector ^ (1 << 16), &admit, &mut reply) != -1 {
        exit(3);
    }
    if auth(selector, &admit[..6], &mut reply) != -3 {
        exit(4);
    }
    if auth(selector, &admit, &mut reply[..1]) != -12 {
        exit(5);
    }
    if auth(selector, &admit, &mut reply) != -4 {
        exit(6);
    }
    let complete = [0x0038_0001_4359_4643, 9, 3, 0, 0, 0, 0];
    if auth(selector, &complete, &mut reply) != -4 {
        exit(7);
    }
    if reply != [0xa5a5_a5a5_a5a5_a5a5; 6] {
        exit(8);
    }

    let now = svc(4, [0; 6]);
    if now <= 0 {
        exit(9);
    }
    let wake = now as u64 + 10_000_000;
    if svc(3, [wake, 0, 0, 0, 0, 0]) != 0 || svc(4, [0; 6]) < wake as i64 {
        exit(10);
    }
    #[cfg(file_owner_fault)]
    // Exercise the native EL0 fault retirement and stopped-writer handoff.
    unsafe {
        asm!("brk #0", options(nostack));
    }
    exit(0)
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
#[cfg(file_owner_fault_peer)]
extern "C" fn _start(_: *const u64, _: usize) -> ! {
    let now = svc(4, [0; 6]);
    if now <= 0 {
        exit(12);
    }
    // Once the regular business task exits, CPU0 can consume CPU3's proof.
    let wake = now as u64 + 1_200_000_000;
    let status = svc(3, [wake, 0, 0, 0, 0, 0]) != 0 || svc(4, [0; 6]) < wake as i64;
    exit(u64::from(status));
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
#[cfg(file_owner_idle_supervisor)]
extern "C" fn _start(_: *const u64, _: usize) -> ! {
    loop {
        svc(3, [u64::MAX, 0, 0, 0, 0, 0]);
    }
}

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    exit(11)
}
