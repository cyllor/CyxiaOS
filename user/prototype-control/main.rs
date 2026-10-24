#![no_std]
#![no_main]
//! Synthetic engineering fixtures, executed by EL0 using the exact model kernel.
mod abi;
#[path = "../../crates/prototype/src/model.rs"]
mod model;
use abi::*;
use core::arch::asm;
#[used]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".cyxia.model")]
static PROTOTYPE_MODELS: [u8; model::MODEL_BYTES * MODELS] =
    *include_bytes!("../../ports/prototype/models.bin");
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
extern "C" fn _start(mode: u64) -> ! {
    // Explicit negative accesses must fault. Reaching the abort SVC fails them.
    match mode {
        1 => unsafe {
            asm!("str xzr, [{}]",in(reg)INPUT_VA,options(nostack));
            abort()
        },
        2 => unsafe {
            asm!("strb wzr, [{}]",in(reg)MODEL_VA,options(nostack));
            abort()
        },
        3 => unsafe {
            asm!("str xzr, [{}]",in(reg)0xb0000u64,options(nostack));
            abort()
        },
        4 => unsafe {
            asm!("ldr x9, [{}]",in(reg)0x30000u64,out("x9") _,options(nostack));
            abort()
        },
        5 => loop {
            core::hint::spin_loop();
        },
        0 => (),
        _ => abort(),
    }
    let words: [u64; INPUT_WORDS] =
        core::array::from_fn(|i| unsafe { (INPUT_VA as *const u64).add(i).read_volatile() });
    let count = words[3] as usize;
    let m = words[2] as usize;
    if words[0] != INPUT_MAGIC
        || words[1] != 1
        || m >= MODELS
        || !(1..=4).contains(&count)
        || words[4] == 0
        || words[5..8] != [0; 3]
    {
        abort();
    }
    let mut candidates = [[0i16; 64]; 4];
    for (i, input) in candidates.iter_mut().enumerate() {
        for (j, value) in input.iter_mut().enumerate() {
            *value = (words[8 + i * 16 + j / 4] >> ((j % 4) * 16)) as i16;
        }
    }
    let package = core::hint::black_box(&PROTOTYPE_MODELS);
    let network =
        model::Model::parse(&package[m * model::MODEL_BYTES..(m + 1) * model::MODEL_BYTES])
            .unwrap_or_else(|_| abort());
    let selected = network
        .select(&candidates[..count])
        .unwrap_or_else(|_| abort());
    let mut out = [0u64; OUTPUT_WORDS];
    out[..8].copy_from_slice(&[
        OUTPUT_MAGIC,
        1,
        words[4],
        selected as u64,
        count as u64,
        m as u64,
        0,
        0,
    ]);
    for (i, input) in candidates.iter().enumerate().take(count) {
        let trace = network.trace(input);
        for (j, v) in trace
            .hidden1
            .into_iter()
            .chain(trace.hidden2)
            .chain([trace.output])
            .enumerate()
        {
            out[8 + i * 14 + j / 4] |= u64::from(v as u16) << ((j % 4) * 16);
        }
    }
    for (i, v) in out.into_iter().enumerate() {
        unsafe {
            (OUTPUT_VA as *mut u64).add(i).write_volatile(v);
        }
    }
    unsafe {
        asm!("svc #0x531",in("x0") OUTPUT_VA,in("x1") (OUTPUT_WORDS*8) as u64,options(nostack));
    }
    abort()
}
fn abort() -> ! {
    unsafe {
        asm!("svc #0x532", options(nostack));
    }
    loop {
        core::hint::spin_loop();
    }
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    abort()
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
unsafe extern "C" fn memset(dst: *mut u8, v: i32, n: usize) -> *mut u8 {
    for i in 0..n {
        unsafe {
            dst.add(i).write_volatile(v as u8);
        }
    }
    dst
}
