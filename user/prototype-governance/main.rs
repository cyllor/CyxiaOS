#![no_std]
#![no_main]
//! Independent, restartable EL0 governance command producer. It receives only
//! a canonical read-only observation and cannot authorize or apply its command.
#[path = "src/decision.rs"]
mod decision;
use core::arch::asm;
use cyxia_prototype::learning::coordinator_wire::{COMMAND_BYTES, SNAPSHOT_BYTES};

const INPUT: u64 = 0x100000;
const OUTPUT: u64 = 0x101000;

fn abort(code: u64) -> ! {
    unsafe {
        asm!("svc #0x563", in("x0") code, options(nostack));
    }
    loop {
        core::hint::spin_loop();
    }
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
extern "C" fn _start(mode: u64, input_len: u64, output_len: u64) -> ! {
    match mode {
        1 => unsafe {
            asm!("str xzr, [{}]", in(reg) INPUT, options(nostack));
            abort(1)
        },
        2 => unsafe {
            asm!("str xzr, [{}]", in(reg) 0x80000u64, options(nostack));
            abort(2)
        },
        3 => unsafe {
            asm!("ldr x9, [{}]", in(reg) 0x30000u64, out("x9") _, options(nostack));
            abort(3)
        },
        4 => loop {
            core::hint::spin_loop();
        },
        0 => {}
        _ => abort(5),
    }
    if input_len as usize != SNAPSHOT_BYTES || output_len as usize != COMMAND_BYTES {
        abort(6)
    }
    let input = unsafe { core::slice::from_raw_parts(INPUT as *const u8, SNAPSHOT_BYTES) };
    let output = unsafe { core::slice::from_raw_parts_mut(OUTPUT as *mut u8, COMMAND_BYTES) };
    match decision::run(input, output) {
        Ok(COMMAND_BYTES) => unsafe {
            asm!(
                "svc #0x562",
                in("x0") OUTPUT,
                in("x1") COMMAND_BYTES as u64,
                options(nostack)
            );
        },
        Ok(_) => abort(7),
        Err(error) => abort(0x100 + error as u64),
    }
    abort(8)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    abort(0xffff)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    for i in 0..n {
        unsafe {
            dst.add(i).write_volatile(src.add(i).read_volatile());
        }
    }
    dst
}

#[unsafe(no_mangle)]
unsafe extern "C" fn memset(dst: *mut u8, value: i32, n: usize) -> *mut u8 {
    for i in 0..n {
        unsafe {
            dst.add(i).write_volatile(value as u8);
        }
    }
    dst
}

#[unsafe(no_mangle)]
unsafe extern "C" fn memmove(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if (dst as usize) < src as usize {
        for i in 0..n {
            unsafe {
                dst.add(i).write_volatile(src.add(i).read_volatile());
            }
        }
    } else {
        for i in (0..n).rev() {
            unsafe {
                dst.add(i).write_volatile(src.add(i).read_volatile());
            }
        }
    }
    dst
}
