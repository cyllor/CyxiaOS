//! A bounded EL0 receive parser. Entry registers contain only public link
//! configuration. The mailbox is read-only and belongs to this address space.
#![no_std]
#![no_main]

use core::alloc::{GlobalAlloc, Layout};
use cyxia_contracts::net_ingress::{FRAME_VA, RETURN_SVC};
use cyxia_net_transport::{device::MTU, ingress::eligible};

struct NoHeap;

// SAFETY: no allocation is available in this process. On unexpected allocation
// failure the panic path stops the parser; it has no recovery capability.
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
extern "C" fn _start(len: usize, mac: u64, local: u32, peer: u32, port: u16) -> ! {
    let accepted = if len <= MTU {
        // SAFETY: EL1 maps one read-only page at FRAME_VA and keeps the same
        // frame staged for this complete synchronous entry. MTU fits one page.
        let frame = unsafe { core::slice::from_raw_parts(FRAME_VA as *const u8, len) };
        eligible(
            frame,
            mac.to_le_bytes()[..6].try_into().unwrap(),
            local.to_be_bytes(),
            peer.to_be_bytes(),
            port,
        )
    } else {
        false
    };
    stop(u64::from(accepted))
}

fn stop(verdict: u64) -> ! {
    // SAFETY: the kernel decodes only this immediate on the parser's
    // synchronous return. No other endpoint is dispatched from this root.
    unsafe {
        core::arch::asm!("svc #{svc}", "2: b 2b", svc = const RETURN_SVC,
                         in("x0") verdict, options(nostack, noreturn));
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    stop(2)
}
