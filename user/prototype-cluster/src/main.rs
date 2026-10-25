#![no_std]
#![no_main]
extern crate alloc;
mod broker;
mod driver;
mod runtime;
use core::{
    alloc::{GlobalAlloc, Layout},
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};
use cyxia_prototype::domains::platform::PlacementQueue;
use cyxia_prototype_cluster::arena::{Arena, HEAP_BYTES};
const ALLOC_BYTES: usize = HEAP_BYTES - cyxia_prototype_cluster::abi::PLACEMENT_STORAGE_BYTES;
#[repr(C, align(4096))]
struct PlacementStorage(PlacementQueue);
static mut PLACEMENTS: PlacementStorage = PlacementStorage(PlacementQueue::new());
static PLACEMENTS_TAKEN: AtomicBool = AtomicBool::new(false);
pub(crate) fn placement_queue() -> &'static mut PlacementQueue {
    assert!(!PLACEMENTS_TAKEN.swap(true, Ordering::AcqRel));
    unsafe { &mut (*core::ptr::addr_of_mut!(PLACEMENTS)).0 }
}
#[repr(C, align(4096))]
struct Heap([u8; ALLOC_BYTES]);
static mut HEAP: Heap = Heap([0; ALLOC_BYTES]);
struct Allocator {
    lock: AtomicBool,
    arena: UnsafeCell<Arena>,
}
unsafe impl Sync for Allocator {}
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        while self.lock.swap(true, Ordering::Acquire) {
            core::hint::spin_loop();
        }
        let out = unsafe { (&mut *self.arena.get()).allocate(layout.size(), layout.align()) };
        self.lock.store(false, Ordering::Release);
        out.unwrap_or(0) as *mut u8
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        while self.lock.swap(true, Ordering::Acquire) {
            core::hint::spin_loop();
        }
        unsafe {
            core::ptr::write_bytes(ptr, 0, layout.size());
            (&mut *self.arena.get()).release(ptr as usize, layout.size());
        }
        self.lock.store(false, Ordering::Release);
    }
}
#[global_allocator]
static ALLOCATOR: Allocator = Allocator {
    lock: AtomicBool::new(false),
    arena: UnsafeCell::new(Arena::new(0, 0)),
};
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
extern "C" fn _start() -> ! {
    unsafe {
        *ALLOCATOR.arena.get() = Arena::new(core::ptr::addr_of_mut!(HEAP) as usize, ALLOC_BYTES);
    }
    broker::trace(1);
    runtime::run()
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    broker::fatal(0xff)
}
fn random(bytes: &mut [u8]) -> Result<(), getrandom::Error> {
    broker::entropy(bytes).map_err(|_| {
        getrandom::Error::from(core::num::NonZeroU32::new(getrandom::Error::CUSTOM_START).unwrap())
    })
}
getrandom::register_custom_getrandom!(random);
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
unsafe extern "C" fn memmove(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if (dst as usize) <= src as usize {
        unsafe {
            memcpy(dst, src, n);
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
unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    for i in 0..n {
        let (x, y) = unsafe { (a.add(i).read_volatile(), b.add(i).read_volatile()) };
        if x != y {
            return x as i32 - y as i32;
        }
    }
    0
}
