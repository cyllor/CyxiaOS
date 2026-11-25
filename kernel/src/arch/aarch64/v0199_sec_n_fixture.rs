//! V0.19.9 SEC-N native Echo *deployment* fixture (fixture scope, NOT production).
//!
//! This is the gated boot-dispatch that wave-7/wave-8 left OPEN: it actually
//! loads the cross-compiled `user/local-echo` EL0 image into its own private
//! TTBR0 address space, reconciles the protected boot identity, and services the
//! guest's restricted SVC 0x43 broker (ENTROPY/TIME/POLL/READ/WRITE/CLOSE/YIELD)
//! from a bounded kernel-owned port. The guest itself runs the REAL authoritative
//! `cyxia_net_transport::admission::Admission` ledger and a REAL rustls TLS 1.3
//! passive-server session; the EL1 kernel stays `aarch64-unknown-none-softfloat`
//! and never compiles rustls/ring (the `tls` feature is EL0-only by design).
//!
//! HONEST SCOPE / GAP DOCUMENTATION (read before trusting any word below):
//! * The socket side is a bounded TRAIT-LEVEL mock [`Port`] (a loopback stub that
//!   accepts egress and never delivers ingress ciphertext), NOT a real VirtIO-net
//!   device. The broker simulates the TCP connection generation/state so the guest
//!   reaches its real Admission + TLS handshake, then stalls ingress. Real
//!   `driver-virtio::net` MMIO/IRQ/DMA custody, a real smoltcp `Tcp` endpoint and a
//!   real pinned TLS peer are the REMAINING device gap. Because there is no real
//!   peer, the positive authenticated Echo turn and the evidence-gated
//!   `finish_session` retirement are NOT exercised here and are NOT claimed.
//! * What IS proven natively on CPU0 EL0 traps:
//!     - the real guest ELF is loaded (own TTBR0/identity) and executes;
//!     - boot-identity reconciliation fails closed on a wrong local node pin;
//!     - a real `Admission::begin_ns` pending lease is created and then released
//!       via `reject` when the bounded 8192-turn handshake budget is exhausted
//!       (stalled peer), after which the guest `begin_restart` + parks;
//!     - a stale connection generation fails closed mid-handshake;
//!     - the device boundary refuses to certify TX quiescence (fail-closed
//!       `Port::tx_quiescent == false`), so no `finish`/credit retirement can be
//!       authorized — matching the guest's hardcoded-false `BrokerSocket`.
//! * The fixture entropy source is a deterministic fixture PRNG, NOT a production
//!   platform CSPRNG; it is sufficient only because no real cryptographic session
//!   completes here.
//! * production_deployment=false, real_device_wiring=false,
//!   tls_echo_turn_verified=false, finish_retirement_verified=false.
//!
//! UNSAFE BOUNDARY REGISTRATION (baseline 安 0.6 SEC-BUF). Global invariant: run()
//! asserts cpu::slot()==0 and the whole chain executes synchronously in that single
//! CPU0 turn loop; no IRQ handler, DMA or secondary CPU touches these statics. The
//! EL0 entry mechanism (user::enter_immutable) is arch-aarch64's registered
//! boundary; this module only calls it.
//! * GUEST_FRAMES / GUEST_LEAVES / GUEST_MID / GUEST_ROOT / SHARED / GUEST_STACK
//!   (static mut): CPU0-only. GUEST_FRAMES code/rodata pages are written once at
//!   load then sealed RO through the boot direct-map (break-before-make + TLBI);
//!   bss/stack/shared pages are writable only by CPU0 between phases. Every &mut
//!   is created and consumed within one synchronous CPU0 call; no aliasing.
//! * load_guest()/map_page()/seal_page()/sync_code(): raw addr_of! arithmetic over
//!   the static frame pool and the boot ram_l3 direct-map, bounded by FRAME_CAP and
//!   the RAM size; the ELF is parsed from an immutable embedded copy. NOT a
//!   production VA walker or a general page-table publisher.
//! * broker(): reads/writes only the dedicated SHARED page (the guest's registered
//!   0x02000000 broker page) through its checked high-half alias; it never walks the
//!   guest code/data pages and never trusts guest bytes as kernel pointers.
//! * asm!("dsb/tlbi/ic"): bounded TLB/cache maintenance; options(nostack).
//! * SMP_EVIDENCE shared reference: a static of AtomicU64; atomic interior
//!   mutability, completion seal stored last with Release.
use super::*;
use cyxia_net_transport::device::{self, Port};
use sha2::{Digest, Sha256};

// Trusted monotonic clocks from the EL1 architectural timer (the same source the
// pinned Board uses). The mock port needs no VirtIO Platform handle.
fn now_ms() -> u64 {
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
static GUEST_ELF: &[u8] =
    include_bytes!("../../../../target/aarch64-unknown-none/release/cyxia-local-echo");

// ---- guest broker ABI (mirrors user/local-echo/src/abi.rs + lib.rs) ----
const SHARED_VA: u64 = 0x0200_0000;
const SVC_MAGIC: u64 = 0x4359_5843_4c53_3031;
const SVC_VERSION: u64 = 4;
const PAYLOAD: usize = 4096;
const ST_OK: u64 = 0;
const ST_AGAIN: u64 = 1;
const ST_EOF: u64 = 2;
const ST_FAILED: u64 = 3;
const OP_ENTROPY: u64 = 1;
const OP_TIME: u64 = 2;
const OP_POLL: u64 = 3;
const OP_READ: u64 = 4;
const OP_WRITE: u64 = 5;
const OP_CLOSE: u64 = 6;
const OP_YIELD: u64 = 12;
const DIRECT_TLS_CIPHERTEXT: u64 = 1;
// Shared-page field offsets (exact protected layout, see abi.rs const asserts).
const OFF_MAGIC: u64 = 0;
const OFF_VERSION: u64 = 8;
const OFF_SEQUENCE: u64 = 16;
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
const LOCAL_NODE: [u8; 32] = [
    0xff, 0xff, 0xae, 0x14, 0x28, 0x63, 0xc3, 0x2a, 0xa1, 0xa2, 0x10, 0xc5, 0x41, 0xa2, 0x68, 0x5f,
    0x3f, 0x59, 0x0e, 0x10, 0x9e, 0x15, 0xd2, 0x5e, 0x0d, 0xfc, 0xd5, 0xad, 0x6d, 0x69, 0xb0, 0xdd,
];
const PEER_NODE: [u8; 32] = [
    0xc0, 0x4a, 0xfa, 0x5e, 0xe9, 0x08, 0xe7, 0x7e, 0x04, 0x9a, 0x4b, 0xbf, 0xde, 0x03, 0x2f, 0xf0,
    0x97, 0xeb, 0x54, 0xca, 0xf3, 0xbc, 0x14, 0x77, 0x6a, 0xcd, 0xee, 0x22, 0x07, 0x4b, 0x06, 0xc7,
];
const SOURCE_IP: u32 = 0x0A00_0202; // 10.0.2.2, trusted native owner observation.
const BOOT_EPOCH: u64 = 1;
const SERVICE_GEN: u64 = 1;
const UNIX_SECONDS: u64 = 1_700_000_000; // fixed: no time-based handshake timeout.

// ---- private address-space layout ----
const PAGE: usize = 4096;
const FRAME_CAP: usize = 3072; // 12 MiB backing pool (guest image is ~9 MiB).
const IMAGE_BASE_VA: u64 = 0x0100_0000;
const STACK_VA: u64 = 0x01f0_0000;
const STACK_PAGES: usize = 64; // 256 KiB guarded guest stack.
const SHARED_PAGES: usize = 4; // 16 KiB broker page region.
const FIRST_MID: usize = 8; // 0x01000000 >> 21
const LAST_MID: usize = 16; // 0x02000000 >> 21
const MID_COUNT: usize = LAST_MID - FIRST_MID + 1;
const GUEST_ASID: u8 = 0x40; // distinct from probes 0x80..0x83 / roles 0x90..0x9f.
const MAGIC: u64 = 0x4359_5853_4543_4e31; // "CYXSECN1"

#[repr(C, align(4096))]
struct Frames([Page; FRAME_CAP]);
static mut GUEST_FRAMES: Frames = Frames([const { Page::ZERO }; FRAME_CAP]);
static mut GUEST_LEAVES: [Page; MID_COUNT] = [const { Page::ZERO }; MID_COUNT];
static mut GUEST_MID: Page = Page::ZERO;
static mut GUEST_ROOT: Page = Page::ZERO;
static mut SHARED: [Page; SHARED_PAGES] = [const { Page::ZERO }; SHARED_PAGES];
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
static mut TX_BYTES: u64 = 0;
static mut QUIESCENCE_REFUSED: u64 = 0;
static mut HANDSHAKE_POLLS: u64 = 0;

/// Bounded trait-level loopback port. It accepts egress into a bounded counter and
/// never delivers ingress ciphertext (stall), and it can NEVER certify TX
/// quiescence (fail-closed default). This is the documented mock device boundary;
/// real VirtIO-net DMA/used-ring custody is the remaining gap.
struct LoopbackPort;
impl Port for LoopbackPort {
    fn send(&mut self, frame: &[u8]) -> Result<(), device::Error> {
        if frame.len() > device::MTU {
            return Err(device::Error::Frame);
        }
        unsafe {
            TX_BYTES += frame.len() as u64;
        }
        Ok(())
    }
    fn receive(&mut self, _frame: &mut [u8; device::MTU]) -> Result<Option<usize>, device::Error> {
        Ok(None) // bounded stall: no ingress ciphertext is ever manufactured.
    }
    fn tx_quiescent(&self) -> bool {
        false // fail-closed: an unknown/mock port cannot certify DMA cessation.
    }
}

fn sha(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}
fn lo(d: &[u8; 32]) -> u64 {
    u64::from_le_bytes(d[..8].try_into().unwrap())
}
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
struct Layout {
    entry: u64,
    bss_first: usize,
    bss_end: usize,
    used_frames: usize,
}

/// Parse the embedded ET_EXEC ELF and stage it into the private frame pool, then
/// publish the user page table. Minimal bounded parser: the production PIE
/// admission contract (pie_image_v0199) deliberately rejects ET_EXEC, so this
/// fixture parses the fixed-address guest directly and never grants capabilities.
fn load_guest() -> Layout {
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
fn stage_shared(local: [u8; 32], connected: bool, conn_epoch: u64) {
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
        TX_BYTES = 0;
        HANDSHAKE_POLLS = 0;
    }
}

/// Re-zero the guest bss + stack between phases so each phase is a fresh guest
/// (allocator, NEXT_SESSION atomic and stack state reset). Code/rodata stay sealed.
fn reset_guest_data(layout: &Layout) {
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
/// no real cryptographic session completes in this mock-port fixture.
fn fixture_entropy(out: &mut [u8]) {
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
fn broker(port: &mut LoopbackPort) {
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
        OP_ENTROPY => {
            let n = len as usize;
            let mut buf = [0u8; PAYLOAD];
            fixture_entropy(&mut buf[..n]);
            shared_put(OFF_PAYLOAD, &buf[..n]);
            shared_write(OFF_LEN, n as u64);
            shared_write(OFF_STATUS, ST_OK);
        }
        OP_TIME => {
            shared_write(OFF_MONOTONIC_MS, now_ms());
            shared_write(OFF_MONOTONIC_NS, now_ns());
            shared_write(OFF_UNIX_SECONDS, UNIX_SECONDS);
            shared_write(OFF_LEN, 0);
            shared_write(OFF_STATUS, ST_OK);
        }
        OP_POLL => {
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
            shared_write(OFF_CONN_EPOCH, epoch);
            shared_write(OFF_PEER_IPV4, u64::from(SOURCE_IP));
            shared_write(OFF_ARG0, u64::from(connected));
            shared_write(OFF_LEN, 0);
            shared_write(OFF_STATUS, ST_OK);
        }
        OP_READ => {
            // Bounded ingress via the trait-level port. The mock never delivers
            // ciphertext, so the guest handshake stalls (budget-exhaustion path).
            let mut frame = [0u8; device::MTU];
            match port.receive(&mut frame) {
                Ok(Some(n)) if n <= len as usize => {
                    shared_put(OFF_PAYLOAD, &frame[..n]);
                    shared_write(OFF_LEN, n as u64);
                    shared_write(OFF_STATUS, ST_OK);
                }
                _ => {
                    shared_write(OFF_LEN, 0);
                    shared_write(OFF_STATUS, ST_AGAIN);
                }
            }
        }
        OP_WRITE => {
            let n = len as usize;
            let mut buf = [0u8; PAYLOAD];
            shared_bytes(OFF_PAYLOAD, &mut buf[..n]);
            match port.send(&buf[..n]) {
                Ok(()) => {
                    shared_write(OFF_LEN, n as u64);
                    shared_write(OFF_STATUS, ST_OK);
                }
                Err(_) => {
                    shared_write(OFF_LEN, 0);
                    shared_write(OFF_STATUS, ST_AGAIN);
                }
            }
        }
        OP_CLOSE => {
            unsafe { CONNECTED = false };
            shared_write(OFF_LEN, 0);
            shared_write(OFF_STATUS, ST_OK);
        }
        OP_YIELD => {
            shared_write(OFF_LEN, 0);
            shared_write(OFF_STATUS, ST_OK);
        }
        _ => {
            shared_write(OFF_STATUS, ST_FAILED);
            shared_write(OFF_LEN, 0);
        }
    }
}

/// One bounded EL0 entry. Returns the trapped context kind/esr. Mirrors smp.rs
/// execute() but uses the immutable-root entry (no per-SVC global TLBI) because the
/// guest page-table descriptors never change during the fixture.
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
fn run_until_park(layout: &Layout, port: &mut LoopbackPort, budget: u64) -> u64 {
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

fn op_count(op: u64) -> u64 {
    unsafe { OP_COUNTS[op as usize] }
}

pub(super) fn run(info: &BootInfo) -> ! {
    assert_eq!(
        cpu::slot(),
        0,
        "only boot CPU0 owns the SEC-N deployment fixture"
    );
    assert_eq!(ONLINE.load(Ordering::Acquire), 15);
    let _ = info;
    report("V0199_SEC_N_STAGE", 1, GUEST_ELF.len() as u64, 0);
    let image_digest = sha(GUEST_ELF);

    // Load the real guest ELF into its own private TTBR0 (own identity space).
    let layout = load_guest();
    assert!(layout.entry >= IMAGE_BASE_VA && layout.used_frames <= FRAME_CAP);
    report(
        "V0199_SEC_N_LOAD",
        layout.entry,
        layout.used_frames as u64,
        lo(&image_digest),
    );

    // Wait for bounded business progress on CPU1-3, then enable the CPU0 PPI.
    wait(|| (1..REQUIRED).all(|slot| PROGRESS[slot * 2].load(Ordering::Acquire) >= 2));
    gic()
        .enable(TIMER_IRQ.load(Ordering::Acquire) as u32)
        .expect("CPU0 timer PPI");

    let mut port = LoopbackPort;

    // (1) NEGATIVE: wrong kernel-local node pin => the guest fails closed at the
    // boot-identity reconciliation (CLOSE + park), never admitting a connection.
    reset_guest_data(&layout);
    stage_shared([0u8; 32], true, 1); // wrong local node, valid page identity.
    unsafe { STALL_AFTER_POLL = 0 };
    let d1 = run_until_park(&layout, &mut port, 4096);
    assert!(unsafe { CLOSE_SEEN }, "identity mismatch must park (CLOSE)");
    assert_eq!(
        op_count(OP_POLL),
        0,
        "identity mismatch must never poll a connection"
    );
    assert_eq!(
        op_count(OP_ENTROPY),
        0,
        "identity mismatch must never reach TLS"
    );
    report(
        "V0199_SEC_N_NEG_IDENTITY",
        d1,
        op_count(OP_CLOSE),
        op_count(OP_POLL),
    );
    let c1 = unsafe { OP_COUNTS }; // snapshot before the next phase resets counters.

    // (2) NEGATIVE: real Admission begin_ns + real TLS session, but the stalled
    // mock port exhausts the bounded 8192-turn handshake budget => reject +
    // begin_restart + park. This exercises the REAL authoritative ledger lease.
    reset_guest_data(&layout);
    stage_shared(LOCAL_NODE, true, 1);
    unsafe { STALL_AFTER_POLL = 0 };
    let d2 = run_until_park(&layout, &mut port, 200_000);
    assert!(unsafe { CLOSE_SEEN }, "budget exhaustion must park (CLOSE)");
    assert!(
        op_count(OP_POLL) >= 8192,
        "handshake must spend the bounded turn budget"
    );
    assert!(
        op_count(OP_ENTROPY) > 0,
        "a real TLS session must have requested entropy"
    );
    assert_eq!(
        op_count(OP_WRITE),
        0,
        "a passive server sends nothing before ClientHello"
    );
    report(
        "V0199_SEC_N_NEG_BUDGET",
        d2,
        op_count(OP_POLL),
        op_count(OP_ENTROPY),
    );
    let c2 = unsafe { OP_COUNTS };
    let tx2 = unsafe { TX_BYTES };

    // (3) NEGATIVE: stale connection generation mid-handshake => the guest's
    // generation-bound socket fails closed well before the turn budget.
    reset_guest_data(&layout);
    stage_shared(LOCAL_NODE, true, 1);
    unsafe { STALL_AFTER_POLL = 200 };
    let d3 = run_until_park(&layout, &mut port, 200_000);
    assert!(unsafe { CLOSE_SEEN }, "stale generation must park (CLOSE)");
    assert!(
        op_count(OP_POLL) < 8192,
        "stale generation must abort before the budget"
    );
    assert!(
        op_count(OP_POLL) >= 200,
        "stale generation must be observed mid-handshake"
    );
    report("V0199_SEC_N_NEG_STALE", d3, op_count(OP_POLL), unsafe {
        CONN_EPOCH
    });
    let c3 = unsafe { OP_COUNTS };
    let epoch3 = unsafe { CONN_EPOCH };

    // (4) NEGATIVE: finish without quiescence. The device boundary refuses to
    // certify TX quiescence (fail-closed default), so no finish/credit retirement
    // can be authorized. Assert the refusal was actually observed at CLOSE.
    assert!(
        !port.tx_quiescent(),
        "mock port must never certify TX quiescence"
    );
    assert!(
        unsafe { QUIESCENCE_REFUSED } >= 3,
        "every CLOSE must refuse quiescence"
    );
    report(
        "V0199_SEC_N_NEG_FINISH",
        unsafe { QUIESCENCE_REFUSED },
        unsafe { TX_BYTES },
        0,
    );

    // Business CPUs kept running; deterministic cleanup.
    for slot in 1..REQUIRED {
        assert!(PROGRESS[slot * 2].load(Ordering::Acquire) >= 2);
        assert_eq!(PROGRESS[slot * 2 + 1].load(Ordering::Acquire), 0);
    }
    for gate in GATES.iter().take(REQUIRED).skip(1) {
        close_gate(gate);
    }
    wait(|| (1..REQUIRED).all(|slot| GATES[slot].quiescent()));
    QUIT.store(true, Ordering::Release);
    wait(|| STOPPED.load(Ordering::Acquire) == 14);
    check_failures();
    for slot in 1..REQUIRED {
        report(
            "V0199_SEC_N_BUSINESS",
            slot as u64,
            PROGRESS[slot * 2].load(Ordering::Acquire),
            IRQS[slot].load(Ordering::Acquire),
        );
    }

    // QMP-readable evidence page.
    let words = unsafe { &*core::ptr::addr_of!(SMP_EVIDENCE) };
    for w in words.words.iter() {
        w.store(0, Ordering::Relaxed);
    }
    let summary = [
        MAGIC,
        1,
        0, // completion seal set last
        15,
        1,
        14,
        GUEST_ELF.len() as u64,
        layout.entry,
        layout.used_frames as u64,
        lo(&image_digest),
        d1,
        d2,
        d3,
        unsafe { QUIESCENCE_REFUSED },
        4, // four fail-closed negatives
        0, // tls_echo_turn_verified = false (mock port, no real peer)
    ];
    for (i, v) in summary.into_iter().enumerate() {
        words.words[i].store(v, Ordering::Relaxed);
    }
    // Per-negative rows: [dispatches, polls, entropy, close, yield_run, tx, epoch, 0].
    let rows: [[u64; 8]; 3] = [
        [
            d1,
            c1[OP_POLL as usize],
            c1[OP_ENTROPY as usize],
            c1[OP_CLOSE as usize],
            c1[OP_YIELD as usize],
            0,
            1,
            0,
        ],
        [
            d2,
            c2[OP_POLL as usize],
            c2[OP_ENTROPY as usize],
            c2[OP_CLOSE as usize],
            c2[OP_YIELD as usize],
            tx2,
            1,
            0,
        ],
        [
            d3,
            c3[OP_POLL as usize],
            c3[OP_ENTROPY as usize],
            c3[OP_CLOSE as usize],
            c3[OP_YIELD as usize],
            0,
            epoch3,
            0,
        ],
    ];
    for (r, row) in rows.into_iter().enumerate() {
        for (c, v) in row.into_iter().enumerate() {
            words.words[16 + r * 8 + c].store(v, Ordering::Relaxed);
        }
    }
    for slot in 1..REQUIRED {
        let at = 48 + (slot - 1) * 4;
        for (off, v) in [
            AFFINITIES[slot].load(Ordering::Acquire),
            PROGRESS[slot * 2].load(Ordering::Acquire),
            PROGRESS[slot * 2 + 1].load(Ordering::Acquire),
            IRQS[slot].load(Ordering::Acquire),
        ]
        .into_iter()
        .enumerate()
        {
            words.words[at + off].store(v, Ordering::Relaxed);
        }
    }
    words.words[2].store(1, Ordering::Release);
    // Framed UART payloads are bounded to 96 bytes (transport::encode); keep both
    // markers within that bound or they are silently dropped.
    super::super::log(b"V0199_SEC_N_SCOPE production=false device=false echo_turn=false finish=false mock_port=true\n");
    super::super::log(b"V0199_SEC_N_FIXTURE_PASS cpus=4 deploy=el0-echo negatives=identity,budget,stale,quiescence\n");
    super::super::halt()
}
