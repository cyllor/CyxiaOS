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
#[path = "../../crates/prototype/src/boot_model.rs"]
#[allow(dead_code)]
mod boot_model;
#[path = "../../crates/prototype/src/policy_wire.rs"]
mod policy_wire;
use abi::*;
#[path = "../shared/calls.rs"]
mod calls;
#[used]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".cyxia.model")]
static RUNTIME_MODEL: [u8; MODEL_BYTES] = model_bytes();
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
extern "C" fn _start(mode: u64) -> ! {
    match mode {
        1 => unsafe {
            (INPUT_VA as *mut u64).write_volatile(0);
            abort()
        },
        2 => unsafe {
            (MODEL_VA as *mut u64).write_volatile(0);
            abort()
        },
        3 => unsafe {
            (0xb0000u64 as *mut u64).write_volatile(0);
            abort()
        },
        4 => unsafe {
            core::hint::black_box((0x30000u64 as *const u64).read_volatile());
            abort()
        },
        5 => loop {
            core::hint::spin_loop();
        },
        6 | 7 => {
            // This runs as an isolated EL0 control role before any new proposal
            // or authenticated network service. Fault mode corrupts only this
            // invocation's private candidate copy, never the active bank.
            let mut bytes = core::hint::black_box(domain_model_bytes());
            if mode == 7 {
                bytes[MODEL_BYTES - 4] ^= 1;
            }
            let passed = boot_model::check(core::hint::black_box(&bytes));
            unsafe {
                let _ = calls::call::<0x543>([boot_model::OUTPUT_MAGIC, u64::from(passed), boot_model::CASES as u64, 0, 0], 0);
            }
            abort()
        }
        0 => (),
        _ => abort(),
    }
    if unsafe { ((INPUT_VA as *const u64).add(1)).read_volatile() } == native::ABI {
        // EL1 owns all three page mappings for the complete invocation: input
        // and model are immutable, and output was cleared before it became
        // writable here.  Borrow the protected pages in place so the bounded
        // model does not spend its 2 ms execution budget on redundant 4 KiB
        // volatile copies and a second output memset.
        let input = unsafe { &*(INPUT_VA as *const [u64; native::INPUT_WORDS]) };
        let parameters = unsafe { core::slice::from_raw_parts(MODEL_VA as *const u8, MODEL_BYTES) };
        let output = unsafe { &mut *(OUTPUT_VA as *mut [u64; native::OUTPUT_WORDS]) };
        let model = model::Model::parse(parameters).unwrap_or_else(|_| abort());
        native::evaluate_precleared(input, &model, output).unwrap_or_else(|_| abort());
        unsafe {
            let _ = calls::call::<0x541>([OUTPUT_VA, (native::OUTPUT_WORDS * 8) as u64, 0, 0, 0], 0);
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
        let _ = calls::call::<0x541>([OUTPUT_VA, (OUTPUT_WORDS * 8) as u64, 0, 0, 0], 0);
    }
    abort()
}
fn abort() -> ! {
    unsafe {
        let _ = calls::call::<0x542>([0, 0, 0, 0, 0], 0);
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
