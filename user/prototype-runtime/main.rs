#![no_std]
#![no_main]
//! Restartable isolated controller; each invocation evaluates a live snapshot.
mod abi;
#[path = "../../crates/prototype/src/domains/types.rs"]
mod domains;
#[path = "../../crates/prototype/src/features.rs"]
mod features;
#[path = "../../crates/prototype/src/model.rs"]
mod model;
mod native;
#[path = "../../crates/prototype/src/policy_wire.rs"]
mod policy_wire;
use abi::*;
use core::arch::asm;
#[used]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".cyxia.model")]
static RUNTIME_MODEL: [u8; MODEL_BYTES] = model_bytes();
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
extern "C" fn _start(mode: u64) -> ! {
    match mode {
        1 => unsafe {
            asm!("str xzr, [{}]", in(reg) INPUT_VA, options(nostack));
            abort()
        },
        2 => unsafe {
            asm!("str xzr, [{}]", in(reg) MODEL_VA, options(nostack));
            abort()
        },
        3 => unsafe {
            asm!("str xzr, [{}]", in(reg) 0xb0000u64, options(nostack));
            abort()
        },
        4 => unsafe {
            asm!("ldr x9, [{}]", in(reg) 0x30000u64, out("x9") _, options(nostack));
            abort()
        },
        5 => loop {
            core::hint::spin_loop();
        },
        0 => (),
        _ => abort(),
    }
    if unsafe { ((INPUT_VA as *const u64).add(1)).read_volatile() } == native::ABI {
        let input: [u64; native::INPUT_WORDS] =
            core::array::from_fn(|i| unsafe { (INPUT_VA as *const u64).add(i).read_volatile() });
        let mut output = [0u64; native::OUTPUT_WORDS];
        let model =
            model::Model::parse(core::hint::black_box(&RUNTIME_MODEL)).unwrap_or_else(|_| abort());
        native::evaluate(&input, &model, &mut output).unwrap_or_else(|_| abort());
        for (i, value) in output.into_iter().enumerate() {
            unsafe {
                (OUTPUT_VA as *mut u64).add(i).write_volatile(value);
            }
        }
        unsafe {
            asm!("svc #0x541", in("x0") OUTPUT_VA, in("x1") 512u64, options(nostack));
        }
        abort()
    }
    let input: [u64; INPUT_WORDS] =
        core::array::from_fn(|i| unsafe { (INPUT_VA as *const u64).add(i).read_volatile() });
    if input[0] != INPUT_MAGIC
        || ![1, 2].contains(&input[1])
        || input[2] == 0
        || input[3] == 0
        || input[6] == 0
        || input[7] == 0
        || input[14] == 0
        || (input[1] == 1 && input[15] != 0)
    {
        abort();
    }
    let candidates = candidates([input[10], input[11]]);
    let model =
        model::Model::parse(core::hint::black_box(&RUNTIME_MODEL)).unwrap_or_else(|_| abort());
    let mut known = [0i16; 64];
    known[0] = 64;
    if model.score(&known) != 64 || model.score(&[0i16; 64]) != 0 {
        abort();
    }
    let selected = model.select(&candidates).unwrap_or_else(|_| abort());
    let core_options = core_candidates(input[15]);
    let core_selected = model.select(&core_options).unwrap_or_else(|_| abort());
    let dynamic = input[1] == 2;
    let output = [
        OUTPUT_MAGIC,
        input[1],
        input[2],
        input[3],
        selected as u64
            | if dynamic {
                (if core_selected == 0 { 2 } else { 6 }) << 8
            } else {
                0
            },
        model.score(if dynamic {
            &core_options[0]
        } else {
            &candidates[0]
        }) as u16 as u64,
        model.score(if dynamic {
            &core_options[1]
        } else {
            &candidates[1]
        }) as u16 as u64,
        input[14],
    ];
    for (i, value) in output.into_iter().enumerate() {
        unsafe {
            (OUTPUT_VA as *mut u64).add(i).write_volatile(value);
        }
    }
    unsafe {
        asm!("svc #0x541", in("x0") OUTPUT_VA,
        in("x1") (OUTPUT_WORDS * 8) as u64, options(nostack));
    }
    abort()
}
fn abort() -> ! {
    unsafe {
        asm!("svc #0x542", options(nostack));
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
unsafe extern "C" fn memset(dst: *mut u8, value: i32, n: usize) -> *mut u8 {
    for i in 0..n {
        unsafe {
            dst.add(i).write_volatile(value as u8);
        }
    }
    dst
}
