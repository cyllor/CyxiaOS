//! SEC-N local-echo guest loader + SVC 0x43 broker, shared by the V0.19.9
//! deployment fixture (`v0199_sec_n_fixture.rs`, mock `LoopbackPort`) and the
//! V0.20 production boot (`production/net.rs`, real VirtIO-net TCP stream).
//!
//! Extracted verbatim from the fixture (wave 11 Task 5); the only change is that
//! `broker` / `run_until_park` are generic over `cyxia_net_transport::device::Port`.
//! It loads the cross-compiled `user/local-echo` EL0 image into its own private
//! TTBR0 address space and services the guest's restricted SVC 0x43 broker
//! (ENTROPY/TIME/POLL/READ/WRITE/CLOSE/YIELD) from a caller-supplied port.
//!
//! UNSAFE BOUNDARY REGISTRATION (baseline 安 0.6 SEC-BUF). Global invariant: the
//! callers assert cpu::slot()==0 and every function here executes synchronously
//! in that single CPU0 turn loop; no IRQ handler, DMA or secondary CPU touches
//! these statics. The EL0 entry mechanism (user::enter_immutable) is
//! arch-aarch64's registered boundary; this module only calls it.
//! * GUEST_FRAMES / GUEST_LEAVES / GUEST_MID / GUEST_ROOT / SHARED / GUEST_STACK
//!   (static mut): CPU0-only. GUEST_FRAMES code/rodata pages are written once at
//!   load then sealed RO through the boot direct-map (break-before-make + TLBI);
//!   bss/stack/shared pages are writable only by CPU0 between phases. Every &mut
//!   is created and consumed within one synchronous CPU0 call; no aliasing.
//!   Under v020-production they live in the dedicated `.bss.sec_n` link section
//!   (aarch64.ld places it before every other .bss input, outside the wave-11
//!   FrameMeta window); they are NOT FrameMeta-registered this wave (open item).
//! * Broker state (CONN_EPOCH, CONNECTED, STALL_AFTER_POLL, POLL_COUNT, OP_COUNTS,
//!   CLOSE_SEEN, YIELD_RUN, ENTROPY_STATE, QUIESCENCE_REFUSED, HANDSHAKE_POLLS,
//!   POLLED_CONNECTED, LEASE_COUNTED, INFERRED_LEASES, RELAYED_BYTES)
//!   (static mut): CPU0-only, read/written only by the functions below and the
//!   by-value accessors; no reference escapes.
//! * load_guest()/map_page()/seal_page()/sync_code(): raw addr_of! arithmetic over
//!   the static frame pool and the boot ram_l3 direct-map, bounded by FRAME_CAP and
//!   the RAM size; the ELF is parsed from an immutable embedded copy. NOT a
//!   production VA walker or a general page-table publisher.
//! * broker(): reads/writes only the dedicated SHARED page (the guest's registered
//!   0x02000000 broker page) through its checked high-half alias; it never walks the
//!   guest code/data pages and never trusts guest bytes as kernel pointers.
//! * asm!("dsb/tlbi/ic"): bounded TLB/cache maintenance; options(nostack).
use super::*;
use cyxia_net_transport::device::{self, Port};

// Trusted monotonic clocks from the EL1 architectural timer (the same source the
// pinned Board uses).
pub(crate) fn now_ms() -> u64 {
    timer::ticks() / (timer::frequency() / 1000).max(1)
}
fn now_ns() -> u64 {
    ((u128::from(timer::ticks()) * 1_000_000_000) / u128::from(timer::frequency().max(1)))
        .min(u128::from(u64::MAX)) as u64
}

// The real cross-compiled EL0 Echo guest. Built by tools/verify_v0199_sec_n.py
// (cargo build --release -p cyxia-local-echo --features guest --target
// aarch64-unknown-none) with the fixed test identity below BEFORE this kernel
// feature is compiled. The default kernel build never embeds it.
pub(crate) static GUEST_ELF: &[u8] =
    include_bytes!("../../../../target/aarch64-unknown-none/release/cyxia-local-echo");

// ---- guest broker ABI (mirrors user/local-echo/src/abi.rs + lib.rs) ----
const SHARED_VA: u64 = 0x0200_0000;
const SVC_MAGIC: u64 = 0x4359_5843_4c53_3031;
const SVC_VERSION: u64 = 4;
const PAYLOAD: usize = 4096;
const ST_OK: u64 = 0;
const ST_AGAIN: u64 = 1;
const ST_FAILED: u64 = 3;
pub(crate) const OP_ENTROPY: u64 = 1;
const OP_TIME: u64 = 2;
pub(crate) const OP_POLL: u64 = 3;
const OP_READ: u64 = 4;
pub(crate) const OP_WRITE: u64 = 5;
pub(crate) const OP_CLOSE: u64 = 6;
pub(crate) const OP_YIELD: u64 = 12;
const DIRECT_TLS_CIPHERTEXT: u64 = 1;
// Shared-page field offsets (exact protected layout, see abi.rs const asserts).
const OFF_MAGIC: u64 = 0;
const OFF_VERSION: u64 = 8;
const OFF_OP: u64 = 24;
const OFF_STATUS: u64 = 32;
const OFF_LEN: u64 = 40;
const OFF_ARG0: u64 = 56;
const OFF_MONOTONIC_MS: u64 = 80;
const OFF_UNIX_SECONDS: u64 = 88;
const OFF_BOOT_EPOCH: u64 = 96;
const OFF_SERVICE_GEN: u64 = 104;
const OFF_CONN_EPOCH: u64 = 112;
const OFF_LOCAL_NODE: u64 = 136;
const OFF_PEER_NODE: u64 = 168;
const OFF_PEER_IPV4: u64 = 440;
const OFF_PAYLOAD: u64 = 2696;
const OFF_MONOTONIC_NS: u64 = 6792;

// Fixed test identity. The Echo guest is a passive TLS SERVER, and Pairing::server
// requires local > peer (the smaller NodeID is the dialing client). So the guest is
// built with the LARGER node b: LOCAL_NODE = node_id(b-test-cert.der) (the guest's
// own cert/key), PEER_NODE = node_id(a-test-cert.der) provisioned as peer.pin (the
// pinned client). These are CI type-check material, never production credentials.
pub(crate) const LOCAL_NODE: [u8; 32] = [
    0xff, 0xff, 0xae, 0x14, 0x28, 0x63, 0xc3, 0x2a, 0xa1, 0xa2, 0x10, 0xc5, 0x41, 0xa2, 0x68, 0x5f,
    0x3f, 0x59, 0x0e, 0x10, 0x9e, 0x15, 0xd2, 0x5e, 0x0d, 0xfc, 0xd5, 0xad, 0x6d, 0x69, 0xb0, 0xdd,
];
const PEER_NODE: [u8; 32] = [
    0xc0, 0x4a, 0xfa, 0x5e, 0xe9, 0x08, 0xe7, 0x7e, 0x04, 0x9a, 0x4b, 0xbf, 0xde, 0x03, 0x2f, 0xf0,
    0x97, 0xeb, 0x54, 0xca, 0xf3, 0xbc, 0x14, 0x77, 0x6a, 0xcd, 0xee, 0x22, 0x07, 0x4b, 0x06, 0xc7,
];
pub(crate) const SOURCE_IP: u32 = 0x0A00_0202; // 10.0.2.2, trusted native owner observation.
const BOOT_EPOCH: u64 = 1;
const SERVICE_GEN: u64 = 1;
const UNIX_SECONDS: u64 = 1_700_000_000; // fixed: no time-based handshake timeout.

// ---- private address-space layout ----
const PAGE: usize = 4096;
pub(crate) const FRAME_CAP: usize = 3072; // 12 MiB backing pool (guest image is ~9 MiB).
pub(crate) const IMAGE_BASE_VA: u64 = 0x0100_0000;
const STACK_VA: u64 = 0x01f0_0000;
const STACK_PAGES: usize = 64; // 256 KiB guarded guest stack.
const SHARED_PAGES: usize = 4; // 16 KiB broker page region.
const FIRST_MID: usize = 8; // 0x01000000 >> 21
const LAST_MID: usize = 16; // 0x02000000 >> 21
const MID_COUNT: usize = LAST_MID - FIRST_MID + 1;
const GUEST_ASID: u8 = 0x40; // distinct from probes 0x80..0x83 / roles 0x90..0x9f.

#[repr(C, align(4096))]
struct Frames([Page; FRAME_CAP]);
#[cfg_attr(feature = "v020-production", unsafe(link_section = ".bss.sec_n"))]
static mut GUEST_FRAMES: Frames = Frames([const { Page::ZERO }; FRAME_CAP]);
#[cfg_attr(feature = "v020-production", unsafe(link_section = ".bss.sec_n"))]
static mut GUEST_LEAVES: [Page; MID_COUNT] = [const { Page::ZERO }; MID_COUNT];
#[cfg_attr(feature = "v020-production", unsafe(link_section = ".bss.sec_n"))]
static mut GUEST_MID: Page = Page::ZERO;
#[cfg_attr(feature = "v020-production", unsafe(link_section = ".bss.sec_n"))]
static mut GUEST_ROOT: Page = Page::ZERO;
#[cfg_attr(feature = "v020-production", unsafe(link_section = ".bss.sec_n"))]
static mut SHARED: [Page; SHARED_PAGES] = [const { Page::ZERO }; SHARED_PAGES];
#[cfg_attr(feature = "v020-production", unsafe(link_section = ".bss.sec_n"))]
static mut GUEST_STACK: [Page; STACK_PAGES] = [const { Page::ZERO }; STACK_PAGES];

// CPU0-only broker/accounting state.
static mut CONN_EPOCH: u64 = 1;
static mut CONNECTED: bool = false;
static mut STALL_AFTER_POLL: u64 = 0; // 0 = never bump; else bump after N polls.
static mut POLL_COUNT: u64 = 0;
static mut OP_COUNTS: [u64; 16] = [0; 16];
static mut CLOSE_SEEN: bool = false;
static mut YIELD_RUN: u64 = 0;
static mut ENTROPY_STATE: u64 = 0;
static mut QUIESCENCE_REFUSED: u64 = 0;
static mut HANDSHAKE_POLLS: u64 = 0;
// Production accounting (inert for the mock-port fixture, which never reads it).
static mut POLLED_CONNECTED: bool = false;
static mut LEASE_COUNTED: bool = false;
static mut INFERRED_LEASES: u64 = 0;
static mut RELAYED_BYTES: u64 = 0;

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}
fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

// ---- boot direct-map helpers (mirror v0199_control_bringup) ----
fn high_leaf(pa: u64) -> *mut u64 {
    assert!(pa % PAGE as u64 == 0 && pa >= cyxia_platform_virt::RAM_BASE);
    let offset = (pa - cyxia_platform_virt::RAM_BASE) / PAGE as u64;
    assert!(offset < cyxia_platform_virt::RAM_MIB * 1024 * 1024 / PAGE as u64);
    unsafe {
        ((core::ptr::addr_of!(ram_l3) as u64 + super::super::HIGH) as *mut u64).add(offset as usize)
    }
}
fn tlbi() {
    unsafe {
        core::arch::asm!(
            "dsb ishst",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            options(nostack)
        );
    }
}
fn seal_page(pa: u64) {
    let leaf = high_leaf(pa);
    let old = unsafe { core::ptr::read_volatile(leaf) };
    assert_eq!(old, pa | 0x0060_0000_0000_0703);
    unsafe {
        core::ptr::write_volatile(leaf, 0);
    }
    tlbi();
    unsafe {
        core::ptr::write_volatile(leaf, old | (1 << 7));
    }
    tlbi();
}
fn sync_code(addr: u64, bytes: usize) {
    let ctr: u64;
    unsafe {
        core::arch::asm!("mrs {}, ctr_el0", out(reg) ctr, options(nomem, nostack));
    }
    let line = 4usize << ((ctr >> 16) & 15);
    for off in (0..bytes).step_by(line) {
        unsafe {
            core::arch::asm!("dc cvau, {}", in(reg) addr + off as u64, options(nostack));
        }
    }
    unsafe {
        core::arch::asm!("dsb ish", "ic ialluis", "dsb ish", "isb", options(nostack));
    }
}
fn frame_ptr(index: usize) -> *mut u8 {
    assert!(index < FRAME_CAP);
    unsafe {
        core::ptr::addr_of_mut!(GUEST_FRAMES.0)
            .cast::<Page>()
            .add(index)
            .cast::<u8>()
    }
}
fn map_page(va: u64, pa: u64, write: bool, execute: bool) {
    let mid = (va >> 21) as usize;
    assert!(
        (FIRST_MID..=LAST_MID).contains(&mid),
        "guest VA outside fixture leaves"
    );
    let leaf = unsafe {
        core::ptr::addr_of_mut!(GUEST_LEAVES)
            .cast::<Page>()
            .add(mid - FIRST_MID)
    };
    let entry = ((va >> 12) & 511) as usize;
    let desc = mmu::encode_user_leaf(PhysAddr(pa), write, execute).unwrap();
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*leaf).0[entry]), desc);
    }
}

/// Parsed guest image layout (CPU0-only).
pub(crate) struct Layout {
    pub(crate) entry: u64,
    bss_first: usize,
    bss_end: usize,
    pub(crate) used_frames: usize,
}

/// Parse the embedded ET_EXEC ELF and stage it into the private frame pool, then
/// publish the user page table. Minimal bounded parser: the production PIE
/// admission contract (pie_image_v0199) deliberately rejects ET_EXEC, so this
/// loader parses the fixed-address guest directly and never grants capabilities.
pub(crate) fn load_guest() -> Layout {
    let b = GUEST_ELF;
    assert!(b.len() >= 64 && &b[0..4] == b"\x7fELF" && b[4] == 2 && b[5] == 1 && b[6] == 1);
    assert_eq!(le16(b, 16), 2, "guest must be ET_EXEC fixed-address");
    assert_eq!(le16(b, 18), 183, "guest must be AArch64");
    let entry = le64(b, 24);
    let ph_off = le64(b, 32) as usize;
    let ph_num = le16(b, 56) as usize;
    assert!(ph_num > 0 && ph_num <= 16 && ph_off + ph_num * 56 <= b.len());
    // First pass: bound the total VA span and locate the writable (bss) segment.
    let mut max_end = 0u64;
    let mut bss_first = FRAME_CAP;
    let mut bss_end = 0usize;
    for i in 0..ph_num {
        let at = ph_off + i * 56;
        if le32(b, at) != 1 {
            continue; // PT_LOAD only
        }
        let va = le64(b, at + 16);
        let mem = le64(b, at + 40);
        let flags = le32(b, at + 4);
        assert!(va >= IMAGE_BASE_VA && va % PAGE as u64 == 0 && mem > 0);
        let end = va.checked_add(mem).unwrap();
        max_end = max_end.max(end);
        let first = ((va - IMAGE_BASE_VA) / PAGE as u64) as usize;
        let last = end.div_ceil(PAGE as u64) as usize - (IMAGE_BASE_VA / PAGE as u64) as usize;
        assert!(last <= FRAME_CAP, "guest image exceeds fixture frame pool");
        if flags & 2 != 0 {
            // Writable segment: this guest's only RW LOAD is the zero-file bss.
            assert_eq!(le64(b, at + 32), 0, "fixture expects bss-only RW LOAD");
            bss_first = bss_first.min(first);
            bss_end = bss_end.max(last);
        }
    }
    let used_frames = (max_end.div_ceil(PAGE as u64) - IMAGE_BASE_VA / PAGE as u64) as usize;
    assert!(used_frames <= FRAME_CAP && bss_end <= used_frames);
    // Second pass: copy file bytes into the VA-indexed frames and map each page.
    for i in 0..ph_num {
        let at = ph_off + i * 56;
        if le32(b, at) != 1 {
            continue;
        }
        let flags = le32(b, at + 4);
        let off = le64(b, at + 8) as usize;
        let va = le64(b, at + 16);
        let file = le64(b, at + 32) as usize;
        let mem = le64(b, at + 40) as usize;
        assert!(off + file <= b.len() && file <= mem);
        let write = flags & 2 != 0;
        let execute = flags & 1 != 0;
        assert!(!(write && execute), "W^X guest segment");
        let first = ((va - IMAGE_BASE_VA) / PAGE as u64) as usize;
        let pages = mem.div_ceil(PAGE);
        // Copy file bytes (bss has file == 0 and stays zero).
        if file != 0 {
            let dst = unsafe { core::slice::from_raw_parts_mut(frame_ptr(first), file) };
            dst.copy_from_slice(&b[off..off + file]);
        }
        for p in 0..pages {
            let index = first + p;
            let pa = phys(frame_ptr(index) as u64);
            if !write {
                // Seal the kernel direct-map alias RO/RX before publishing the
                // user leaf; no writable alias of guest code/rodata remains.
                seal_page(pa);
                if execute {
                    sync_code(frame_ptr(index) as u64, PAGE);
                }
            }
            map_page(va + p as u64 * PAGE as u64, pa, write, execute);
        }
    }
    // Shared broker page (RW, never executable).
    for p in 0..SHARED_PAGES {
        let pa = phys(unsafe { core::ptr::addr_of_mut!(SHARED).cast::<Page>().add(p) as u64 });
        map_page(SHARED_VA + p as u64 * PAGE as u64, pa, true, false);
    }
    // Guarded guest stack (RW). Pages below STACK_VA stay unmapped as a guard.
    for p in 0..STACK_PAGES {
        let pa = phys(unsafe { core::ptr::addr_of_mut!(GUEST_STACK).cast::<Page>().add(p) as u64 });
        map_page(STACK_VA + p as u64 * PAGE as u64, pa, true, false);
    }
    // Publish root -> mid -> leaves.
    unsafe {
        let mid_pa = phys(core::ptr::addr_of!(GUEST_MID) as u64);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(GUEST_ROOT.0[0]), mid_pa | 3);
        for i in 0..MID_COUNT {
            let leaf_pa = phys(core::ptr::addr_of!(GUEST_LEAVES).cast::<Page>().add(i) as u64);
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(GUEST_MID.0[FIRST_MID + i]),
                leaf_pa | 3,
            );
        }
    }
    tlbi();
    Layout {
        entry,
        bss_first,
        bss_end,
        used_frames,
    }
}

fn shared_ptr() -> *mut u8 {
    core::ptr::addr_of_mut!(SHARED).cast::<u8>()
}
fn shared_read(off: u64) -> u64 {
    unsafe { core::ptr::read_volatile(shared_ptr().add(off as usize).cast::<u64>()) }
}
fn shared_write(off: u64, value: u64) {
    unsafe { core::ptr::write_volatile(shared_ptr().add(off as usize).cast::<u64>(), value) }
}
fn shared_bytes(off: u64, out: &mut [u8]) {
    for (i, b) in out.iter_mut().enumerate() {
        *b = unsafe { core::ptr::read_volatile(shared_ptr().add(off as usize + i)) };
    }
}
fn shared_put(off: u64, bytes: &[u8]) {
    for (i, b) in bytes.iter().enumerate() {
        unsafe { core::ptr::write_volatile(shared_ptr().add(off as usize + i), *b) };
    }
}

/// Stage the protected shared page before a fresh guest run. `local` is the
/// kernel-local node pin presented to the guest (wrong value => identity negative).
pub(crate) fn stage_shared(local: [u8; 32], connected: bool, conn_epoch: u64) {
    let p = shared_ptr();
    unsafe { core::ptr::write_bytes(p, 0, SHARED_PAGES * PAGE) };
    shared_write(OFF_MAGIC, SVC_MAGIC);
    shared_write(OFF_VERSION, SVC_VERSION);
    shared_write(OFF_BOOT_EPOCH, BOOT_EPOCH);
    shared_write(OFF_SERVICE_GEN, SERVICE_GEN);
    shared_write(OFF_UNIX_SECONDS, UNIX_SECONDS);
    shared_write(OFF_MONOTONIC_MS, now_ms());
    shared_write(OFF_MONOTONIC_NS, now_ns());
    shared_put(OFF_LOCAL_NODE, &local);
    shared_put(OFF_PEER_NODE, &PEER_NODE);
    shared_write(OFF_CONN_EPOCH, conn_epoch);
    shared_write(OFF_PEER_IPV4, u64::from(SOURCE_IP));
    unsafe {
        CONN_EPOCH = conn_epoch;
        CONNECTED = connected;
        POLL_COUNT = 0;
        CLOSE_SEEN = false;
        YIELD_RUN = 0;
        OP_COUNTS = [0; 16];
        HANDSHAKE_POLLS = 0;
        POLLED_CONNECTED = false;
        LEASE_COUNTED = false;
        INFERRED_LEASES = 0;
        RELAYED_BYTES = 0;
    }
}

/// Re-zero the guest bss + stack between phases so each phase is a fresh guest
/// (allocator, NEXT_SESSION atomic and stack state reset). Code/rodata stay sealed.
pub(crate) fn reset_guest_data(layout: &Layout) {
    for i in layout.bss_first..layout.bss_end {
        unsafe { core::ptr::write_bytes(frame_ptr(i), 0, PAGE) };
    }
    unsafe {
        core::ptr::write_bytes(
            core::ptr::addr_of_mut!(GUEST_STACK).cast::<u8>(),
            0,
            STACK_PAGES * PAGE,
        );
    }
}

fn fresh_context(layout: &Layout) -> user::Context {
    let mut ctx = user::Context::empty();
    ctx.pc = layout.entry;
    ctx.sp = STACK_VA + (STACK_PAGES * PAGE) as u64;
    ctx
}

/// Independent kernel-side broker allowlist (mirrors the guest broker_surface).
fn allowed(op: u64, len: u64, arg0: u64) -> bool {
    if len > PAYLOAD as u64 {
        return false;
    }
    match op {
        OP_ENTROPY | OP_READ => arg0 == 0,
        OP_WRITE => arg0 == DIRECT_TLS_CIPHERTEXT && len != 0,
        OP_TIME | OP_POLL | OP_CLOSE | OP_YIELD => len == 0 && arg0 == 0,
        _ => false,
    }
}

/// Deterministic fixture PRNG (NOT a production CSPRNG). Sufficient only because
/// no real cryptographic session completes on top of it.
pub(crate) fn fixture_entropy(out: &mut [u8]) {
    let mut state = unsafe { ENTROPY_STATE };
    if state == 0 {
        state = timer::ticks() | 1;
    }
    for chunk in out.chunks_mut(8) {
        // xorshift64*
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let v = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
        for (i, b) in chunk.iter_mut().enumerate() {
            *b = (v >> (i * 8)) as u8;
        }
    }
    unsafe { ENTROPY_STATE = state };
}

/// Service one SVC 0x43 broker request from the shared page. The kernel never
/// touches sequence/magic/version/epoch/generation (the guest re-validates them).
pub(crate) fn broker<P: Port>(port: &mut P) {
    let op = shared_read(OFF_OP);
    let len = shared_read(OFF_LEN);
    let arg0 = shared_read(OFF_ARG0);
    if op < 16 {
        unsafe { OP_COUNTS[op as usize] += 1 };
    }
    if op == OP_YIELD {
        unsafe { YIELD_RUN += 1 };
    } else {
        unsafe { YIELD_RUN = 0 };
    }
    if op == OP_CLOSE {
        unsafe { CLOSE_SEEN = true };
        // The device boundary cannot certify TX quiescence: finish/retirement is
        // refused (fail-closed). Record the refusal; no credit is released.
        if !port.tx_quiescent() {
            unsafe { QUIESCENCE_REFUSED += 1 };
        }
    }
    if !allowed(op, len, arg0) {
        shared_write(OFF_STATUS, ST_FAILED);
        shared_write(OFF_LEN, 0);
        return;
    }
    match op {
        OP_ENTROPY => broker_entropy(len),
        OP_TIME => {
            shared_write(OFF_MONOTONIC_MS, now_ms());
            shared_write(OFF_MONOTONIC_NS, now_ns());
            shared_write(OFF_UNIX_SECONDS, UNIX_SECONDS);
            reply(0, ST_OK);
        }
        OP_POLL => broker_poll(),
        OP_READ => broker_read(port, len),
        OP_WRITE => broker_write(port, len),
        OP_CLOSE => {
            unsafe { CONNECTED = false };
            reply(0, ST_OK);
        }
        OP_YIELD => reply(0, ST_OK),
        _ => {
            shared_write(OFF_STATUS, ST_FAILED);
            shared_write(OFF_LEN, 0);
        }
    }
}

fn reply(len: u64, status: u64) {
    shared_write(OFF_LEN, len);
    shared_write(OFF_STATUS, status);
}

fn broker_entropy(len: u64) {
    // INFERRED lease: the guest calls Admission::begin_ns right after a connected
    // POLL and parks (CLOSE, no ENTROPY) if it fails; only a granted lease reaches
    // Pairing::server, whose rustls session is the first ENTROPY requester. So the
    // first ENTROPY after a connected POLL is counted as one issued lease. The
    // guest does not report its Admission count; this is a broker-trace inference.
    unsafe {
        if POLLED_CONNECTED && !LEASE_COUNTED {
            LEASE_COUNTED = true;
            INFERRED_LEASES += 1;
        }
    }
    let n = len as usize;
    let mut buf = [0u8; PAYLOAD];
    fixture_entropy(&mut buf[..n]);
    shared_put(OFF_PAYLOAD, &buf[..n]);
    reply(n as u64, ST_OK);
}

fn broker_poll() {
    unsafe {
        POLL_COUNT += 1;
        if CONNECTED {
            HANDSHAKE_POLLS += 1;
        }
        // Stale-generation negative: bump the connection epoch after N
        // polls so the guest's generation-bound socket fails closed.
        if STALL_AFTER_POLL != 0 && POLL_COUNT >= STALL_AFTER_POLL {
            CONN_EPOCH += 1;
        }
    }
    let (connected, epoch) = unsafe { (CONNECTED, CONN_EPOCH) };
    unsafe { POLLED_CONNECTED |= connected };
    shared_write(OFF_CONN_EPOCH, epoch);
    shared_write(OFF_PEER_IPV4, u64::from(SOURCE_IP));
    shared_write(OFF_ARG0, u64::from(connected));
    reply(0, ST_OK);
}

/// Bounded ingress via the port. A port with nothing to deliver answers AGAIN.
fn broker_read<P: Port>(port: &mut P, len: u64) {
    let mut frame = [0u8; device::MTU];
    match port.receive(&mut frame) {
        Ok(Some(n)) if n <= len as usize => {
            shared_put(OFF_PAYLOAD, &frame[..n]);
            unsafe { RELAYED_BYTES += n as u64 };
            reply(n as u64, ST_OK);
        }
        _ => reply(0, ST_AGAIN),
    }
}

fn broker_write<P: Port>(port: &mut P, len: u64) {
    let n = len as usize;
    let mut buf = [0u8; PAYLOAD];
    shared_bytes(OFF_PAYLOAD, &mut buf[..n]);
    match port.send(&buf[..n]) {
        Ok(()) => reply(n as u64, ST_OK),
        Err(_) => reply(0, ST_AGAIN),
    }
}

/// One bounded EL0 entry. Returns the trapped context kind/esr. Mirrors smp.rs
/// execute() but uses the immutable-root entry (no per-SVC global TLBI) because the
/// guest page-table descriptors never change while it runs.
fn step(ctx: &mut user::Context, root: u64) {
    let quantum = (timer::frequency() / 1000).max(1);
    unsafe {
        timer::arm(timer::ticks().saturating_add(quantum));
        user::enter_immutable(ctx, root, GUEST_ASID);
        cpu::disable_timer();
    }
}

/// Run the guest until it parks (CLOSE then a sustained YIELD run) or a bounded
/// SVC budget is spent. Returns the number of SVC dispatches performed.
pub(crate) fn run_until_park<P: Port>(layout: &Layout, port: &mut P, budget: u64) -> u64 {
    let root = phys(core::ptr::addr_of!(GUEST_ROOT) as u64);
    let mut ctx = fresh_context(layout);
    let mut dispatched = 0u64;
    for _ in 0..budget {
        step(&mut ctx, root);
        if ctx.kind == 9 {
            continue; // private PPI preemption; resume.
        }
        if ctx.kind != 8 || ctx.esr >> 26 != 0x15 {
            fatal(900); // unexpected EL0 fault (not an SVC).
        }
        let iss = ctx.esr & 0xffff;
        if iss != 0x43 {
            fatal(901); // only SVC 0x43 is admitted for this guest.
        }
        broker(port);
        dispatched += 1;
        // ELR already points past the trapped SVC; resume with no register return
        // (the broker ABI carries results in the shared page, not x0).
        let parked = unsafe { CLOSE_SEEN && YIELD_RUN >= 64 };
        if parked {
            return dispatched;
        }
    }
    fatal(902); // guest never parked within the bounded budget.
}

// ---- by-value broker state accessors (no reference to a static escapes) ----
/// Leases inferred from the broker trace (see `broker_entropy`), not reported
/// by the guest.
#[cfg(feature = "v020-production")]
pub(crate) fn inferred_leases() -> u64 {
    unsafe { INFERRED_LEASES }
}
/// Ingress bytes delivered to the guest through SVC 0x43 READ.
#[cfg(feature = "v020-production")]
pub(crate) fn relayed_bytes() -> u64 {
    unsafe { RELAYED_BYTES }
}
#[cfg(feature = "v0199-sec-n-selftest")]
pub(crate) fn op_counts() -> [u64; 16] {
    unsafe { OP_COUNTS }
}
#[cfg(feature = "v0199-sec-n-selftest")]
pub(crate) fn op_count(op: u64) -> u64 {
    op_counts()[op as usize]
}
#[cfg(feature = "v0199-sec-n-selftest")]
pub(crate) fn close_seen() -> bool {
    unsafe { CLOSE_SEEN }
}
#[cfg(feature = "v0199-sec-n-selftest")]
pub(crate) fn conn_epoch() -> u64 {
    unsafe { CONN_EPOCH }
}
#[cfg(feature = "v0199-sec-n-selftest")]
pub(crate) fn quiescence_refused() -> u64 {
    unsafe { QUIESCENCE_REFUSED }
}
#[cfg(feature = "v0199-sec-n-selftest")]
pub(crate) fn set_stall_after_poll(polls: u64) {
    unsafe { STALL_AFTER_POLL = polls };
}
