#![no_std]
#![no_main]
//! Independent, restartable learning/validation arithmetic. Neither this role
//! nor its protection/operator probes can create trusted replay labels.
#[path = "src/compute.rs"]
mod compute;
#[path = "../shared/calls.rs"]
mod calls;
const INPUT: u64 = 0x100000;
const INPUT_BYTES: usize = 512 * 1024;
const OUTPUT: u64 = 0x180000;
const OUTPUT_BYTES: usize = 16 * 1024;
fn yield_step(completed: u64) {
    unsafe {
        let _ = calls::call::<0x551>([completed, 0, 0, 0, 0], 0);
    }
}
fn abort(code: u64) -> ! {
    unsafe {
        let _ = calls::call::<0x553>([code, 0, 0, 0, 0], 0);
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
            (INPUT as *mut u64).write_volatile(0);
            abort(1)
        },
        2 => unsafe {
            (0x80000u64 as *mut u64).write_volatile(0);
            abort(2)
        },
        3 => unsafe {
            (0x1f0000u64 as *mut u64).write_volatile(0);
            abort(3)
        },
        4 => unsafe {
            core::hint::black_box((0x30000u64 as *const u64).read_volatile());
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
            let _ = calls::call::<0x552>([OUTPUT, len as u64, 0, 0, 0], 0);
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
