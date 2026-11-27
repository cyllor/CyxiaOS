//! Fixture identity holder in a separate EL0 address space.
#![no_std]
#![no_main]

#[path = "../../shared/calls.rs"]
mod calls;

use core::alloc::{GlobalAlloc, Layout};
use cyxia_contracts::tls_signer::{Request, WIRE_BYTES, certificate_verify_message};
use ring::{
    digest::{SHA256, digest},
    signature::{Ed25519KeyPair, KeyPair},
};

const MAILBOX: *mut [u8; WIRE_BYTES] = cyxia_local_echo::abi::SHARED_VA as *mut _;

struct NoHeap;

// SAFETY: this allocator never returns a pointer. The Ed25519 path uses its
// private stack, and an unexpected allocation fails through the panic gate.
unsafe impl GlobalAlloc for NoHeap {
    unsafe fn alloc(&self, _: Layout) -> *mut u8 {
        core::ptr::null_mut()
    }
    unsafe fn dealloc(&self, _: *mut u8, _: Layout) {}
}

#[global_allocator]
static ALLOCATOR: NoHeap = NoHeap;

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
extern "C" fn _start(pin0: u64, pin1: u64, pin2: u64, pin3: u64) -> ! {
    // SAFETY: this page is simultaneously mapped only to the EL1 owner and
    // this EL0 context. EL1 initializes it before each entry.
    let wire = unsafe { MAILBOX.read_volatile() };
    let mut expected_pin = [0; 32];
    for (part, word) in expected_pin
        .chunks_exact_mut(8)
        .zip([pin0, pin1, pin2, pin3])
    {
        part.copy_from_slice(&word.to_le_bytes());
    }
    let reply = Request::decode(&wire).and_then(|request| {
        let key = Ed25519KeyPair::from_pkcs8_maybe_unchecked(include_bytes!(concat!(
            env!("OUT_DIR"),
            "/key.der"
        )))
        .ok()?;
        if digest(&SHA256, key.public_key().as_ref()).as_ref() != expected_pin {
            return None;
        }
        let signature = key.sign(&certificate_verify_message(&request.transcript_hash));
        Some(request.encode_reply(signature.as_ref().try_into().ok()?))
    });
    if let Some(reply) = reply {
        unsafe { MAILBOX.write_volatile(reply) };
        calls::release_shared();
        stop(1)
    }
    stop(0)
}

fn stop(success: u64) -> ! {
    // SAFETY: only the isolated signer trampoline recognizes this return gate.
    unsafe { calls::call::<0x44>([success, 0, 0, 0, 0], 0) };
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    stop(0)
}
