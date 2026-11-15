//! Compile for each admitted user target; execution belongs to native tests.
#![no_std]
#![no_main]
#[path = "shared/calls.rs"]
mod calls;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn exercise_calls(args: *const u64) -> u64 {
    let args = unsafe { core::ptr::read(args.cast::<[u64; 5]>()) };
    (unsafe { calls::call::<0x45>(args, 19) })[0]
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop { core::hint::spin_loop() }
}
