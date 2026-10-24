#![no_std]
#![no_main]
//! Standalone EL0 binary. Only copied snapshot input and result SVC are allowed.
//! No EL1 model call, host RPC, allocator, filesystem, socket or hidden fallback.
#[path = "../../crates/control-model/src/abi.rs"]
mod abi;
#[path = "../../crates/control-model/src/model.rs"]
mod model;
use abi::*;
use core::arch::asm;
#[used]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".cyxia.model")]
static CONTROL_MODEL: [u8; 52] = *include_bytes!("../../ports/control-service/core-head.bin");
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
#[allow(unreachable_code, unused_variables)]
extern "C" fn _start() -> ! {
    loop {
        // Only this process maps OUTPUT writable. INPUT is read-only at EL0.
        let words =
            core::array::from_fn(|i| unsafe { (INPUT_VA as *const u64).add(i).read_volatile() });
        #[cfg(service_fault = "hang")]
        loop {
            core::hint::spin_loop();
        }
        #[cfg(service_fault = "snapshot-write")]
        unsafe {
            asm!("str xzr, [{}]",in(reg)INPUT_VA,options(nostack));
        }
        #[cfg(service_fault = "model-write")]
        unsafe {
            asm!("strb wzr, [{}]",in(reg)CONTROL_MODEL.as_ptr(),options(nostack));
        }
        let result = Input::decode(words)
            .and_then(|input| model::infer_with(&input, core::hint::black_box(&CONTROL_MODEL)))
            .unwrap_or_else(|_| abort());
        #[allow(unused_mut)]
        let mut out = result.encode();
        #[cfg(service_fault = "bad-mask")]
        {
            out[5] = 255;
        }
        for (i, value) in out.into_iter().enumerate() {
            unsafe {
                (OUTPUT_VA as *mut u64).add(i).write_volatile(value);
            }
        }
        unsafe {
            asm!("svc #0x431",in("x0") OUTPUT_VA,in("x1") (OUTPUT_WORDS*8) as u64, options(nostack));
        }
    }
}
fn abort() -> ! {
    unsafe {
        asm!("svc #0x432", options(nostack));
    }
    loop {
        core::hint::spin_loop();
    }
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    abort()
}
// Compiler-emitted fixed-size copies must not require a host libc. Volatile
// loops prevent recursive lowering back to these symbols; inputs are private.
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
unsafe extern "C" fn memset(dst: *mut u8, v: i32, n: usize) -> *mut u8 {
    for i in 0..n {
        unsafe {
            dst.add(i).write_volatile(v as u8);
        }
    }
    dst
}
