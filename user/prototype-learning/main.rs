#![no_std]
#![no_main]
//! Independent, restartable learning/validation arithmetic. Neither this role
//! nor its protection/operator probes can create trusted replay labels.
#[path = "src/compute.rs"]
mod compute;
use core::arch::asm;
const INPUT: u64 = 0x100000;
const INPUT_BYTES: usize = 512 * 1024;
const OUTPUT: u64 = 0x180000;
const OUTPUT_BYTES: usize = 16 * 1024;
fn yield_step(completed: u64) {
    unsafe {
        asm!("svc #0x551",in("x0")completed,options(nostack));
    }
}
fn abort(code: u64) -> ! {
    unsafe {
        asm!("svc #0x553",in("x0")code,options(nostack));
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
            asm!("str xzr, [{}]",in(reg)INPUT,options(nostack));
            abort(1)
        },
        2 => unsafe {
            asm!("str xzr, [{}]",in(reg)0x80000u64,options(nostack));
            abort(2)
        },
        3 => unsafe {
            asm!("str xzr, [{}]",in(reg)0x1f0000u64,options(nostack));
            abort(3)
        },
        4 => unsafe {
            asm!("ldr x9, [{}]",in(reg)0x30000u64,out("x9")_,options(nostack));
            abort(4)
        },
        5 => loop {
            core::hint::spin_loop();
        },
        0 | 0x10 => {}
        _ => abort(6),
    }
    if output_len == 0 || output_len > OUTPUT_BYTES as u64 {
        abort(10)
    }
    let output = unsafe { core::slice::from_raw_parts_mut(OUTPUT as *mut u8, output_len as usize) };
    let result = if mode == 0x10 {
        compute::selftest(output, yield_step)
    } else {
        if input_len == 0 || input_len as usize > INPUT_BYTES {
            abort(7)
        }
        let input = unsafe { core::slice::from_raw_parts(INPUT as *const u8, input_len as usize) };
        compute::run(input, output, yield_step)
    };
    match result {
        Ok(len) if len <= OUTPUT_BYTES => unsafe {
            asm!("svc #0x552",in("x0")OUTPUT,in("x1")len as u64,options(nostack));
        },
        Ok(_) => abort(8),
        Err(error) => abort(0x100 + error as u64),
    }
    abort(9)
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
