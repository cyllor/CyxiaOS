//! SEC-N local-echo guest loader + SVC 0x43 broker, shared by the V0.19.9
//! deployment fixture (`v0199_sec_n_fixture.rs`, mock `LoopbackPort`) and the
//! V0.20 production boot (`production/net.rs`, real VirtIO-net TCP stream).
//!
//! The broker serves both fixture and production transports through
//! `cyxia_net_transport::device::Port`.
//! It loads the cross-compiled `user/local-echo` EL0 image into its own private
//! TTBR0 address space and services the guest's restricted SVC 0x43 broker
//! (ENTROPY/TIME/POLL/READ/WRITE/CLOSE/YIELD/ADMISSION_GRANTED) from a caller-supplied port.
//! The authenticated production stream also supplies POLL_NORMAL_CLOSE and
//! ADMISSION_RETIRED, both bound to the grant and polled generation.
//!
//! UNSAFE BOUNDARY REGISTRATION (baseline 安 0.6 SEC-BUF). Global invariant: the
//! callers assert cpu::slot()==0 and every function here executes synchronously
//! in that single CPU0 turn loop; no IRQ handler, DMA or secondary CPU touches
//! these statics. The EL0 entry mechanism (user::enter_immutable) is
//! arch-aarch64's registered boundary; this module only calls it.
//! * GUEST address space (static mut): CPU0-only. Its code/rodata is written once at
//!   load then sealed RO through the boot direct-map (break-before-make + TLBI);
//!   bss/stack/shared pages are writable only by CPU0 between phases. Every &mut
//!   is created and consumed within one synchronous CPU0 call; no aliasing.
//!   After the authenticated relay returns, CPU0 invalidates this stopped
//!   root and wipes writable pages. No page is returned to a frame allocator.
//!   Under v020-production they live in the dedicated `.bss.sec_n` link section
//!   covered by the production FrameMeta Arena registration for that pinned
//!   section. Device descriptor custody is tracked separately by its driver.
//! * Broker state (CONN_EPOCH, CONNECTED, STALL_AFTER_POLL, POLL_COUNT, OP_COUNTS,
//!   CLOSE_SEEN, YIELD_RUN, ENTROPY_STATE, QUIESCENCE_REFUSED, HANDSHAKE_POLLS,
//!   CONN_SOURCE, POLLED_EPOCH, ADMISSION_RECEIPT, RELAYED_BYTES,
//!   STREAM_CLOSED, RETIREMENT, TLS_WINDOW, TLS_AUTHENTICATED_EPOCH,
//!   EMPTY_ACTIVE_READ)
//!   (static mut): CPU0-only, read/written only by the functions below and the
//!   by-value accessors; no reference escapes.
//! * load_guest()/map_page()/seal_page()/sync_code(): raw addr_of! arithmetic over
//!   the static frame pool and the boot ram_l3 direct-map, bounded by FRAME_CAP and
//!   the RAM size; the ELF is parsed from an immutable embedded copy. NOT a
//!   production VA walker or a general page-table publisher.
//! * broker(): reads/writes only the dedicated SHARED page (the guest's registered
//!   0x02000000 broker page) through its checked high-half alias; it never walks the
//!   guest code/data pages and never trusts guest bytes as kernel pointers.
//! * ACTIVE_POLL_TIMER joins the CPU0 foreground wait to its banked PPI
//!   handler. Only that IRQ, while enabled by the waiter, may rearm it.
//! * asm!("dsb/tlbi/ic"): bounded TLB/cache maintenance; options(nostack).
#[path = "sec_n_broker/receipt.rs"]
mod receipt;
#[cfg(feature = "v020-production-authenticated-net")]
#[path = "sec_n_broker/signer.rs"]
pub(super) mod signer;

use super::*;
#[cfg(feature = "v020-production-authenticated-net")]
use cyxia_kernel_core::security::network::tls_deadline::{Limit, Phase, TlsWindow};
use cyxia_net_transport::device::{self, Port};

// Trusted monotonic clocks from the EL1 architectural timer (the same source the
// pinned Board uses).
pub(crate) fn now_ms() -> u64 {
    timer::ticks() / (timer::frequency() / 1000).max(1)
}
pub(crate) fn now_ns() -> u64 {
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
const ST_EOF: u64 = 2;
const ST_FAILED: u64 = 3;
pub(crate) const OP_ENTROPY: u64 = 1;
const OP_TIME: u64 = 2;
pub(crate) const OP_POLL: u64 = 3;
const OP_READ: u64 = 4;
pub(crate) const OP_WRITE: u64 = 5;
pub(crate) const OP_CLOSE: u64 = 6;
pub(crate) const OP_YIELD: u64 = 12;
const OP_ADMISSION_GRANTED: u64 = 0x100;
#[cfg(feature = "v020-production-authenticated-net")]
const OP_POLL_NORMAL_CLOSE: u64 = 0x101;
#[cfg(feature = "v020-production-authenticated-net")]
const OP_ADMISSION_RETIRED: u64 = 0x102;
#[cfg(feature = "v020-production-authenticated-net")]
const OP_TLS_CERTIFICATE_VERIFY: u64 = 0x103;
#[cfg(feature = "v020-production-authenticated-net")]
const OP_TLS_AUTHENTICATED: u64 = 0x104;

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
#[cfg(feature = "v0199-sec-n-selftest")]
pub(crate) const SOURCE_IP: u32 = 0x0A00_0202; // 10.0.2.2, trusted native owner observation.
const UNIX_SECONDS: u64 = 1_700_000_000; // fixed: no time-based handshake timeout.

/// Input from the trusted owner, never from the Verifier's shared page.
#[derive(Clone, Copy)]
pub(crate) struct BootIdentity {
    pub(crate) boot_epoch: u64,
    verifier_generation: u64,
    #[cfg(feature = "v020-production-authenticated-net")]
    key_generation: u64,
}

impl BootIdentity {
    #[cfg(any(
        feature = "v0199-sec-n-selftest",
        not(feature = "v020-production-media-signed")
    ))]
    pub(crate) const FIXTURE: Self = Self {
        boot_epoch: 1,
        verifier_generation: 1,
        #[cfg(feature = "v020-production-authenticated-net")]
        key_generation: 1,
    };

    #[cfg(feature = "v020-production-media-signed")]
    pub(crate) fn from_signed_scratch(
        state: &cyxia_kernel_core::security::file_index_v0199::SecurityStateStoreV2,
        config: &cyxia_kernel_core::security::offline_config_v1::VerifiedOfflineConfig<'_>,
        installation: cyxia_kernel_core::security::network::TlsInstallation,
    ) -> Option<Self> {
        Some(Self {
            boot_epoch: installation.authorize(config, state).ok()?,
            verifier_generation: installation.verifier_generation,
            #[cfg(feature = "v020-production-authenticated-net")]
            key_generation: installation.key_generation,
        })
    }
}

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
struct AddressSpace<const FRAMES: usize, const STACK: usize> {
    frames: [Page; FRAMES],
    leaves: [Page; MID_COUNT],
    mid: Page,
    root: Page,
    shared: [Page; SHARED_PAGES],
    stack: [Page; STACK],
}

impl<const FRAMES: usize, const STACK: usize> AddressSpace<FRAMES, STACK> {
    const ZERO: Self = Self {
        frames: [const { Page::ZERO }; FRAMES],
        leaves: [const { Page::ZERO }; MID_COUNT],
        mid: Page::ZERO,
        root: Page::ZERO,
        shared: [const { Page::ZERO }; SHARED_PAGES],
        stack: [const { Page::ZERO }; STACK],
    };

    /// Caller supplies one boot-pinned address space owned by CPU0.
    unsafe fn memory(space: *mut Self) -> Memory {
        unsafe {
            Memory {
                frames: core::ptr::addr_of_mut!((*space).frames).cast(),
                frame_count: FRAMES,
                leaves: core::ptr::addr_of_mut!((*space).leaves).cast(),
                mid: core::ptr::addr_of_mut!((*space).mid),
                root: core::ptr::addr_of_mut!((*space).root),
                shared: core::ptr::addr_of_mut!((*space).shared).cast(),
                stack: core::ptr::addr_of_mut!((*space).stack).cast(),
                stack_pages: STACK,
            }
        }
    }
}

struct Memory {
    frames: *mut Page,
    frame_count: usize,
    leaves: *mut Page,
    mid: *mut Page,
    root: *mut Page,
    shared: *mut Page,
    stack: *mut Page,
    stack_pages: usize,
}

#[cfg_attr(feature = "v020-production", unsafe(link_section = ".bss.sec_n"))]
#[cfg_attr(
    feature = "v020-production-authenticated-net",
    unsafe(export_name = "V020_SEC_N_VERIFIER_SPACE")
)]
static mut GUEST: AddressSpace<FRAME_CAP, STACK_PAGES> = AddressSpace::ZERO;

fn guest_memory() -> Memory {
    // SAFETY: the CPU0 broker is the sole owner of the pinned guest address space.
    unsafe { AddressSpace::memory(core::ptr::addr_of_mut!(GUEST)) }
}

// CPU0-only broker/accounting state.
static mut CONN_EPOCH: u64 = 1;
static mut CONNECTED: bool = false;
static mut STALL_AFTER_POLL: u64 = 0; // 0 = never bump; else bump after N polls.
static mut POLL_COUNT: u64 = 0;
static mut OP_COUNTS: [u64; 16] = [0; 16];
static mut CLOSE_SEEN: bool = false;
static mut YIELD_RUN: u64 = 0;
#[cfg(any(
    feature = "v0199-sec-n-selftest",
    not(feature = "v020-production-authenticated-net")
))]
static mut ENTROPY_STATE: u64 = 0;
static mut QUIESCENCE_REFUSED: u64 = 0;
static mut HANDSHAKE_POLLS: u64 = 0;
// Production accounting (inert for the mock-port fixture, which never reads it).
static mut CONN_SOURCE: u32 = 0;
static mut POLLED_EPOCH: u64 = 0;
static mut ADMISSION_RECEIPT: Option<(u64, u32)> = None;
static mut RELAYED_BYTES: u64 = 0;
static mut STREAM_CLOSED: u64 = 0;
// CPU0 only, reset when a stream is staged. The staged grant binds these
// states to the same socket generation and source throughout the relay.
#[cfg(feature = "v020-production-authenticated-net")]
#[derive(Clone, Copy, Eq, PartialEq)]
enum Retirement {
    Open,
    Closing,
    Quiescent,
    Retired,
}
#[cfg(feature = "v020-production-authenticated-net")]
static mut RETIREMENT: Retirement = Retirement::Open;
#[cfg(feature = "v020-production-authenticated-net")]
static mut TLS_WINDOW: Option<TlsWindow> = None;
#[cfg(feature = "v020-production-authenticated-net")]
static mut TLS_AUTHENTICATED_EPOCH: u64 = 0;
#[cfg(feature = "v020-production-authenticated-net")]
static mut EMPTY_ACTIVE_READ: bool = false;
#[cfg(feature = "v020-production-authenticated-net")]
static ACTIVE_POLL_TIMER: AtomicU64 = AtomicU64::new(0);

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
    assert!(pa.is_multiple_of(PAGE as u64) && pa >= cyxia_platform_virt::RAM_BASE);
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
impl Memory {
    fn frame_ptr(&self, index: usize) -> *mut u8 {
        assert!(index < self.frame_count);
        unsafe { self.frames.add(index).cast() }
    }

    fn map_page(&self, va: u64, pa: u64, write: bool, execute: bool) {
        let mid = (va >> 21) as usize;
        assert!(
            (FIRST_MID..=LAST_MID).contains(&mid),
            "guest VA outside fixture leaves"
        );
        let leaf = unsafe { self.leaves.add(mid - FIRST_MID) };
        let entry = ((va >> 12) & 511) as usize;
        let desc = mmu::encode_user_leaf(PhysAddr(pa), write, execute).unwrap();
        unsafe {
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*leaf).0[entry]), desc);
        }
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
    load_image(GUEST_ELF, &guest_memory())
}

fn load_image(b: &[u8], memory: &Memory) -> Layout {
    assert!(b.len() >= 64 && &b[0..4] == b"\x7fELF" && b[4] == 2 && b[5] == 1 && b[6] == 1);
    assert_eq!(le16(b, 16), 2, "guest must be ET_EXEC fixed-address");
    assert_eq!(le16(b, 18), 183, "guest must be AArch64");
    let entry = le64(b, 24);
    let ph_off = le64(b, 32) as usize;
    let ph_num = le16(b, 56) as usize;
    assert!(ph_num > 0 && ph_num <= 16 && ph_off + ph_num * 56 <= b.len());
    // First pass: bound the total VA span and locate the writable (bss) segment.
    let mut max_end = 0u64;
    let mut bss_first = memory.frame_count;
    let mut bss_end = 0usize;
    for i in 0..ph_num {
        let at = ph_off + i * 56;
        if le32(b, at) != 1 {
            continue; // PT_LOAD only
        }
        let va = le64(b, at + 16);
        let mem = le64(b, at + 40);
        let flags = le32(b, at + 4);
        assert!(va >= IMAGE_BASE_VA && va.is_multiple_of(PAGE as u64) && mem > 0);
        let end = va.checked_add(mem).unwrap();
        max_end = max_end.max(end);
        let first = ((va - IMAGE_BASE_VA) / PAGE as u64) as usize;
        let last = end.div_ceil(PAGE as u64) as usize - (IMAGE_BASE_VA / PAGE as u64) as usize;
        assert!(
            last <= memory.frame_count,
            "guest image exceeds fixture frame pool"
        );
        if flags & 2 != 0 {
            // Writable segment: this guest's only RW LOAD is the zero-file bss.
            assert_eq!(le64(b, at + 32), 0, "fixture expects bss-only RW LOAD");
            assert_eq!(bss_end, 0, "fixture expects a single writable LOAD");
            bss_first = first;
            bss_end = last;
        }
    }
    let used_frames = (max_end.div_ceil(PAGE as u64) - IMAGE_BASE_VA / PAGE as u64) as usize;
    assert!(used_frames <= memory.frame_count && bss_end <= used_frames);
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
            let dst = unsafe { core::slice::from_raw_parts_mut(memory.frame_ptr(first), file) };
            dst.copy_from_slice(&b[off..off + file]);
        }
        for p in 0..pages {
            let index = first + p;
            let address = memory.frame_ptr(index) as u64;
            let pa = phys(address);
            if !write {
                // Seal the kernel direct-map alias RO/RX before publishing the
                // user leaf; no writable alias of guest code/rodata remains.
                seal_page(pa);
                if execute {
                    sync_code(address, PAGE);
                }
            }
            memory.map_page(va + p as u64 * PAGE as u64, pa, write, execute);
        }
    }
    // Shared broker page (RW, never executable).
    for p in 0..SHARED_PAGES {
        let pa = phys(unsafe { memory.shared.add(p) as u64 });
        memory.map_page(SHARED_VA + p as u64 * PAGE as u64, pa, true, false);
    }
    // Guarded guest stack (RW). Pages below STACK_VA stay unmapped as a guard.
    for p in 0..memory.stack_pages {
        let pa = phys(unsafe { memory.stack.add(p) as u64 });
        memory.map_page(STACK_VA + p as u64 * PAGE as u64, pa, true, false);
    }
    // Publish root -> mid -> leaves.
    unsafe {
        let mid_pa = phys(memory.mid as u64);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*memory.root).0[0]), mid_pa | 3);
        for i in 0..MID_COUNT {
            let leaf_pa = phys(memory.leaves.add(i) as u64);
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!((*memory.mid).0[FIRST_MID + i]),
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
    guest_memory().shared.cast()
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
#[cfg(feature = "v0199-sec-n-selftest")]
pub(crate) fn stage_shared(local: [u8; 32], connected: bool, conn_epoch: u64) {
    stage_connection(
        BootIdentity::FIXTURE,
        local,
        connected,
        conn_epoch,
        SOURCE_IP,
        now_ns(),
    );
}

pub(crate) fn stage_connection(
    identity: BootIdentity,
    local: [u8; 32],
    connected: bool,
    conn_epoch: u64,
    source: u32,
    accepted_ns: u64,
) {
    let p = shared_ptr();
    unsafe { core::ptr::write_bytes(p, 0, SHARED_PAGES * PAGE) };
    shared_write(OFF_MAGIC, SVC_MAGIC);
    shared_write(OFF_VERSION, SVC_VERSION);
    shared_write(OFF_BOOT_EPOCH, identity.boot_epoch);
    shared_write(OFF_SERVICE_GEN, identity.verifier_generation);
    shared_write(OFF_UNIX_SECONDS, UNIX_SECONDS);
    shared_write(OFF_MONOTONIC_MS, now_ms());
    shared_write(OFF_MONOTONIC_NS, accepted_ns);
    shared_put(OFF_LOCAL_NODE, &local);
    shared_put(OFF_PEER_NODE, &PEER_NODE);
    shared_write(OFF_CONN_EPOCH, conn_epoch);
    shared_write(OFF_PEER_IPV4, u64::from(source));
    unsafe {
        CONN_EPOCH = conn_epoch;
        CONNECTED = connected;
        POLL_COUNT = 0;
        CLOSE_SEEN = false;
        YIELD_RUN = 0;
        OP_COUNTS = [0; 16];
        HANDSHAKE_POLLS = 0;
        CONN_SOURCE = source;
        POLLED_EPOCH = 0;
        ADMISSION_RECEIPT = None;
        RELAYED_BYTES = 0;
        STREAM_CLOSED = 0;
        #[cfg(feature = "v020-production-authenticated-net")]
        {
            RETIREMENT = Retirement::Open;
            TLS_AUTHENTICATED_EPOCH = 0;
            EMPTY_ACTIVE_READ = false;
            TLS_WINDOW = if connected {
                TlsWindow::new(Phase::Pending, accepted_ns)
            } else {
                None
            };
        }
    }
}

/// Re-zero the guest bss + stack between phases so each phase is a fresh guest
/// (allocator, NEXT_SESSION atomic and stack state reset). Code/rodata stay sealed.
pub(crate) fn reset_guest_data(layout: &Layout) {
    let memory = guest_memory();
    for i in layout.bss_first..layout.bss_end {
        unsafe { core::ptr::write_bytes(memory.frame_ptr(i), 0, PAGE) };
    }
    unsafe {
        core::ptr::write_bytes(memory.stack.cast::<u8>(), 0, STACK_PAGES * PAGE);
    }
}

/// Called by the sole relay owner on every terminal return from the guest.
/// Preserve completion evidence while dropping live broker authority.
#[cfg(feature = "v020-production-authenticated-net")]
pub(crate) fn discard_guest_session(layout: &Layout, boot_epoch: u64) {
    let memory = guest_memory();
    // SAFETY: the synchronous EL0 entry has returned. No other actor or
    // device accesses this private root, image, stack or broker mailbox.
    let conn_epoch = unsafe {
        CONNECTED = false;
        POLLED_EPOCH = 0;
        TLS_WINDOW = None;
        TLS_AUTHENTICATED_EPOCH = 0;
        EMPTY_ACTIVE_READ = false;
        core::ptr::addr_of_mut!((*memory.root).0[0]).write_volatile(0);
        CONN_EPOCH
    };
    tlbi();
    // The loader admits one BSS-only writable LOAD. Volatile page writes
    // cover its exact extent and every private stack and shared page.
    unsafe {
        for i in layout.bss_first..layout.bss_end {
            memory.frames.add(i).write_volatile(Page::ZERO);
        }
        for i in 0..memory.stack_pages {
            memory.stack.add(i).write_volatile(Page::ZERO);
        }
        for i in 0..SHARED_PAGES {
            memory.shared.add(i).write_volatile(Page::ZERO);
        }
        core::arch::asm!("dsb ishst", options(nostack));
    }
    let pages = layout.bss_end.saturating_sub(layout.bss_first) + memory.stack_pages + SHARED_PAGES;
    report(
        "V020_SEC_N_VERIFIER_DISCARDED",
        boot_epoch,
        conn_epoch,
        pages as u64,
    );
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
        #[cfg(feature = "v020-production-authenticated-net")]
        OP_POLL_NORMAL_CLOSE | OP_ADMISSION_RETIRED | OP_TLS_AUTHENTICATED => {
            len == receipt::WIRE_BYTES as u64 && arg0 == 0
        }
        #[cfg(feature = "v020-production-authenticated-net")]
        OP_TLS_CERTIFICATE_VERIFY => {
            len == cyxia_contracts::tls_signer::SIGNATURE_BYTES as u64 && arg0 == 0
        }
        OP_ADMISSION_GRANTED => len == receipt::WIRE_BYTES as u64 && arg0 == 0,
        OP_WRITE => arg0 == DIRECT_TLS_CIPHERTEXT && len != 0,
        OP_TIME | OP_POLL | OP_CLOSE | OP_YIELD => len == 0 && arg0 == 0,
        _ => false,
    }
}

type ClosePoll<P> = fn(&mut P) -> Result<bool, device::Error>;

pub(crate) type EntropyFill<'a> = dyn FnMut(&mut [u8]) -> bool + 'a;

/// Non-authenticated fixture entropy. The authenticated mode has no fallback.
#[cfg(any(
    feature = "v0199-sec-n-selftest",
    not(feature = "v020-production-authenticated-net")
))]
pub(crate) fn fixture_entropy(out: &mut [u8]) -> bool {
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
    true
}

/// Service one SVC 0x43 broker request from the shared page. The kernel never
/// touches sequence/magic/version/epoch/generation (the guest re-validates them).
fn broker<P: Port>(
    port: &mut P,
    entropy: &mut EntropyFill<'_>,
    close_poll: Option<ClosePoll<P>>,
    #[cfg(feature = "v020-production-authenticated-net")] signer: Option<&mut signer::Signer>,
) {
    let op = shared_read(OFF_OP);
    let len = shared_read(OFF_LEN);
    let arg0 = shared_read(OFF_ARG0);
    if !allowed(op, len, arg0) {
        return reply(0, ST_FAILED);
    }
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
        // CLOSE parks the guest. The normal-retirement operations independently
        // verify the TCP/driver witness and record the guest ledger receipt.
        if !port.tx_quiescent() {
            unsafe { QUIESCENCE_REFUSED += 1 };
        }
    }
    match op {
        OP_ENTROPY => broker_entropy(len, entropy),
        OP_TIME => {
            shared_write(OFF_MONOTONIC_MS, now_ms());
            shared_write(OFF_MONOTONIC_NS, now_ns());
            shared_write(OFF_UNIX_SECONDS, UNIX_SECONDS);
            reply(0, ST_OK);
        }
        OP_POLL => broker_poll(close_poll.is_some()),
        #[cfg(feature = "v020-production-authenticated-net")]
        OP_POLL_NORMAL_CLOSE | OP_ADMISSION_RETIRED => broker_normal_close(port, close_poll, op),
        #[cfg(feature = "v020-production-authenticated-net")]
        OP_TLS_CERTIFICATE_VERIFY => broker_certificate_verify(signer),
        #[cfg(feature = "v020-production-authenticated-net")]
        OP_TLS_AUTHENTICATED => broker_tls_authenticated(signer),
        #[cfg(feature = "v020-production-authenticated-net")]
        OP_READ | OP_WRITE if unsafe { RETIREMENT } != Retirement::Open => reply(0, ST_FAILED),
        OP_ADMISSION_GRANTED => broker_admission_granted(),
        OP_READ | OP_WRITE if !unsafe { CONNECTED } => reply(0, ST_EOF),
        OP_READ => broker_read(
            port,
            len,
            #[cfg(feature = "v020-production-authenticated-net")]
            signer.is_some(),
        ),
        OP_WRITE => broker_write(port, len),
        OP_CLOSE => {
            unsafe { CONNECTED = false };
            reply(0, ST_OK);
        }
        OP_YIELD => {
            #[cfg(feature = "v020-production-authenticated-net")]
            if signer.is_some() {
                wait_after_empty_read();
            }
            reply(0, ST_OK);
        }
        _ => {
            shared_write(OFF_STATUS, ST_FAILED);
            shared_write(OFF_LEN, 0);
        }
    }
}

#[cfg(feature = "v020-production-authenticated-net")]
fn broker_certificate_verify(signer: Option<&mut signer::Signer>) {
    let (connected, epoch, source, grant, state, deadline_ns) = unsafe {
        (
            CONNECTED,
            CONN_EPOCH,
            CONN_SOURCE,
            ADMISSION_RECEIPT,
            RETIREMENT,
            TLS_WINDOW.map_or(0, |window| window.deadline().0),
        )
    };
    if !connected
        || grant != Some((epoch, source))
        || state != Retirement::Open
        || unsafe { TLS_AUTHENTICATED_EPOCH } != 0
    {
        return reply(0, ST_FAILED);
    }
    let mut transcript = [0; cyxia_contracts::tls_signer::TRANSCRIPT_BYTES];
    shared_bytes(OFF_PAYLOAD, &mut transcript);
    match signer.and_then(|signer| signer.certificate_verify(epoch, deadline_ns, transcript)) {
        Some(signature) => {
            shared_put(OFF_PAYLOAD, &signature);
            shared_write(OFF_ARG0, 0);
            reply(signature.len() as u64, ST_OK);
        }
        None => reply(0, ST_FAILED),
    }
}

#[cfg(feature = "v020-production-authenticated-net")]
fn broker_tls_authenticated(signer: Option<&mut signer::Signer>) {
    let mut wire = [0u8; receipt::WIRE_BYTES];
    shared_bytes(OFF_PAYLOAD, &mut wire);
    let (connected, epoch, polled, source, grant, state, authenticated, expires) = unsafe {
        (
            CONNECTED,
            CONN_EPOCH,
            POLLED_EPOCH,
            CONN_SOURCE,
            ADMISSION_RECEIPT,
            RETIREMENT,
            TLS_AUTHENTICATED_EPOCH,
            TLS_WINDOW.map_or(0, |window| window.deadline().0),
        )
    };
    let authenticated_ns = now_ns();
    if state != Retirement::Open
        || authenticated_ns >= expires
        || grant != Some((epoch, source))
        || !signer.is_some_and(|signer| signer.issued_for(epoch))
        || receipt::validate(&wire, connected, epoch, polled, source, authenticated != 0) != grant
    {
        return reply(0, ST_FAILED);
    }
    let Some(window) = TlsWindow::new(Phase::Active, authenticated_ns) else {
        return reply(0, ST_FAILED);
    };
    // The sealed TLS verifier has confirmed client CertificateVerify and
    // Finished. Only this transition starts the active connection's lifetime.
    unsafe {
        TLS_WINDOW = Some(window);
        TLS_AUTHENTICATED_EPOCH = epoch;
    };
    report(
        "V020_SEC_N_VERIFIER_AUTHENTICATED",
        epoch,
        u64::from(source),
        1,
    );
    reply(0, ST_OK);
}

fn reply(len: u64, status: u64) {
    shared_write(OFF_LEN, len);
    shared_write(OFF_STATUS, status);
}

/// Witness one successful guest grant for the staged connection. Only the
/// sealed guest runs in this address space; network bytes cannot dispatch an SVC.
fn broker_admission_granted() {
    let mut receipt = [0u8; receipt::WIRE_BYTES];
    shared_bytes(OFF_PAYLOAD, &mut receipt);
    // Snapshot protected state by value. The shared page is guest-writable.
    let (connected, epoch, polled_epoch, source, prior) = unsafe {
        (
            CONNECTED,
            CONN_EPOCH,
            POLLED_EPOCH,
            CONN_SOURCE,
            ADMISSION_RECEIPT,
        )
    };
    let Some(grant) = receipt::validate(
        &receipt,
        connected,
        epoch,
        polled_epoch,
        source,
        prior.is_some(),
    ) else {
        return reply(0, ST_FAILED);
    };
    unsafe { ADMISSION_RECEIPT = Some(grant) };
    reply(0, ST_OK);
}

#[cfg(feature = "v020-production-authenticated-net")]
fn broker_normal_close<P: Port>(port: &mut P, close_poll: Option<ClosePoll<P>>, op: u64) {
    let Some(poll) = close_poll else {
        return reply(0, ST_FAILED);
    };
    let mut wire = [0; receipt::WIRE_BYTES];
    shared_bytes(OFF_PAYLOAD, &mut wire);
    let (connected, epoch, polled, source, grant, state) = unsafe {
        (
            CONNECTED,
            CONN_EPOCH,
            POLLED_EPOCH,
            CONN_SOURCE,
            ADMISSION_RECEIPT,
            RETIREMENT,
        )
    };
    let identity = receipt::validate(&wire, connected, epoch, polled, source, false);
    if identity.is_none() || identity != grant || unsafe { TLS_AUTHENTICATED_EPOCH } != epoch {
        return reply(0, ST_FAILED);
    }
    match (op, state) {
        (OP_POLL_NORMAL_CLOSE, Retirement::Open | Retirement::Closing) => {
            unsafe { RETIREMENT = Retirement::Closing };
            match poll(port) {
                Ok(true) => {
                    unsafe { RETIREMENT = Retirement::Quiescent };
                    reply(0, ST_OK)
                }
                Ok(false) => reply(0, ST_AGAIN),
                Err(_) => disconnect(),
            }
        }
        (OP_ADMISSION_RETIRED, Retirement::Quiescent) => {
            unsafe { RETIREMENT = Retirement::Retired };
            reply(0, ST_OK)
        }
        _ => reply(0, ST_FAILED),
    }
}

fn broker_entropy(len: u64, fill: &mut EntropyFill<'_>) {
    let n = len as usize;
    let mut buf = [0u8; PAYLOAD];
    if !fill(&mut buf[..n]) {
        return reply(0, ST_FAILED);
    }
    shared_put(OFF_PAYLOAD, &buf[..n]);
    reply(n as u64, ST_OK);
}

fn broker_poll(normal_close: bool) {
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
    let (connected, epoch, source) = unsafe { (CONNECTED, CONN_EPOCH, CONN_SOURCE) };
    unsafe { POLLED_EPOCH = if connected { epoch } else { 0 } };
    shared_write(OFF_CONN_EPOCH, epoch);
    shared_write(OFF_PEER_IPV4, u64::from(source));
    shared_write(
        OFF_ARG0,
        u64::from(connected) | (u64::from(normal_close && connected) << 1),
    );
    reply(0, ST_OK);
}

/// Bounded ingress via the port. A port with nothing to deliver answers AGAIN.
/// Length-aware: the port is asked for at most the guest's `len`, so a stream
/// port never dequeues bytes the guest cannot take. A port that still returns
/// more (a frame port) or fails ends the connection; bytes are never dropped
/// silently.
fn broker_read<P: Port>(
    port: &mut P,
    len: u64,
    #[cfg(feature = "v020-production-authenticated-net")] authenticated_profile: bool,
) {
    let limit = len as usize;
    if limit == 0 {
        return reply(0, ST_AGAIN); // nothing deliverable: dequeue nothing.
    }
    let mut frame = [0u8; device::MTU];
    match port.receive_up_to(&mut frame, limit) {
        Ok(Some(n)) if n != 0 && n <= limit && n <= frame.len() => {
            #[cfg(feature = "v020-production-authenticated-net")]
            if authenticated_profile {
                let Some(mut window) = (unsafe { TLS_WINDOW }) else {
                    return reply(0, ST_FAILED);
                };
                // The device poll may finish after the timer boundary. Never
                // publish late input or renew an already expired window.
                if !window.record_read(now_ns()) {
                    return reply(0, ST_FAILED);
                }
                unsafe {
                    TLS_WINDOW = Some(window);
                    EMPTY_ACTIVE_READ = false;
                };
            }
            shared_put(OFF_PAYLOAD, &frame[..n]);
            unsafe { RELAYED_BYTES += n as u64 };
            reply(n as u64, ST_OK);
        }
        Ok(None | Some(0)) | Err(device::Error::WouldBlock) => {
            #[cfg(feature = "v020-production-authenticated-net")]
            unsafe {
                EMPTY_ACTIVE_READ = authenticated_profile && TLS_AUTHENTICATED_EPOCH != 0;
            };
            reply(0, ST_AGAIN);
        }
        Ok(Some(_)) | Err(device::Error::Device | device::Error::Frame) => disconnect(),
    }
}

fn broker_write<P: Port>(port: &mut P, len: u64) {
    #[cfg(feature = "v020-production-authenticated-net")]
    unsafe {
        EMPTY_ACTIVE_READ = false;
    };
    let n = len as usize;
    let mut buf = [0u8; PAYLOAD];
    shared_bytes(OFF_PAYLOAD, &mut buf[..n]);
    match port.send(&buf[..n]) {
        Ok(()) => reply(n as u64, ST_OK),
        Err(device::Error::WouldBlock | device::Error::Frame) => reply(0, ST_AGAIN),
        Err(device::Error::Device) => disconnect(),
    }
}

#[cfg(feature = "v020-production-authenticated-net")]
pub(crate) fn admits_next_transmit() -> bool {
    // The same CPU0 foreground owns both the TCP turn and this snapshot.
    let (connected, retirement, window) = unsafe { (CONNECTED, RETIREMENT, TLS_WINDOW) };
    connected
        && retirement == Retirement::Open
        && window.is_some_and(|window| window.admits_io_at(now_ns()))
}

/// The port reported a closed/reset/failed stream: the connection is over.
/// POLL now answers disconnected and this request answers EOF, so the guest's
/// generation-bound socket sees Closed and parks instead of spinning on AGAIN.
fn disconnect() {
    unsafe {
        CONNECTED = false;
        STREAM_CLOSED += 1;
    }
    reply(0, ST_EOF);
}

/// Called only for CPU0's banked timer PPI from the current-EL IRQ vector.
#[cfg(feature = "v020-production-authenticated-net")]
pub(super) fn rearm_active_poll_timer() -> bool {
    let period = ACTIVE_POLL_TIMER.load(Ordering::Acquire);
    if period != 0 {
        // A periodic wake prevents an IRQ just before WFI from stranding the
        // foreground. The waiter disarms it before returning to EL0.
        unsafe { timer::arm(timer::ticks().saturating_add(period)) };
        true
    } else {
        false
    }
}

#[cfg(feature = "v020-production-authenticated-net")]
fn wait_after_empty_read() {
    let wait = unsafe {
        let wait = EMPTY_ACTIVE_READ && CONNECTED && RETIREMENT == Retirement::Open;
        EMPTY_ACTIVE_READ = false;
        wait.then_some(TLS_WINDOW).flatten()
    };
    let Some(window) = wait else {
        return;
    };
    // Keep recent traffic responsive. After a full quiet second, use a
    // slower idle cadence so empty polls cannot consume the relay call
    // budget during a normally sparse session before its lifetime ends.
    let quiet_ns = now_ns().saturating_sub(window.last_read_ns());
    let period = (timer::frequency() / if quiet_ns < 1_000_000_000 { 500 } else { 100 }).max(1);
    let wake = timer::ticks()
        .saturating_add(period)
        .min(ticks_at_ns(window.deadline().0));
    if timer::ticks() >= wake {
        return;
    }
    // SAFETY: CPU0 owns the registered banked timer between stopped EL0
    // entries. IRQs run on the registered IRQ stack; restore the caller's
    // IRQ mask and remove the wake source before the next entry.
    unsafe {
        let daif: u64;
        core::arch::asm!(
            "mrs {}, daif", "msr daifset, #2", "isb",
            out(reg) daif, options(nostack, preserves_flags)
        );
        ACTIVE_POLL_TIMER.store(period, Ordering::Release);
        timer::arm(wake);
        timer::enable_irqs();
        timer::idle();
        core::arch::asm!("msr daifset, #2", "isb", options(nostack, preserves_flags));
        cpu::disable_timer();
        ACTIVE_POLL_TIMER.store(0, Ordering::Release);
        if daif & (1 << 7) == 0 {
            timer::enable_irqs();
        }
    }
}

/// One bounded EL0 entry. Returns the trapped context kind/esr. Mirrors smp.rs
/// execute() but uses the immutable-root entry (no per-SVC global TLBI) because the
/// guest page-table descriptors never change while it runs.
fn step(ctx: &mut user::Context, root: u64, asid: u8, latest_tick: u64) {
    let quantum = (timer::frequency() / 1000).max(1);
    unsafe {
        timer::arm(timer::ticks().saturating_add(quantum).min(latest_tick));
        user::enter_immutable(ctx, root, asid);
        cpu::disable_timer();
    }
}

#[cfg(feature = "v020-production-authenticated-net")]
fn ticks_at_ns(ns: u64) -> u64 {
    (u128::from(ns) * u128::from(timer::frequency()))
        .div_ceil(1_000_000_000)
        .min(u128::from(u64::MAX)) as u64
}

#[cfg(feature = "v020-production-authenticated-net")]
fn tls_timeout(window: TlsWindow, observed_ns: u64, dispatched: u64) -> GuestStop {
    let (expires_ns, limit) = window.deadline();
    let code = match (window.phase(), limit) {
        (Phase::Pending, Limit::Lifetime) => 903,
        (Phase::Pending, Limit::Idle) => 904,
        (Phase::Active, Limit::Lifetime) => 905,
        (Phase::Active, Limit::Idle) => 906,
    };
    report(
        match window.phase() {
            Phase::Pending => "V020_SEC_N_PENDING_TIMEOUT",
            Phase::Active => "V020_SEC_N_ACTIVE_TIMEOUT",
        },
        code,
        expires_ns - window.start_ns(),
        observed_ns - window.start_ns(),
    );
    GuestStop { code, dispatched }
}

/// Why a bounded guest run ended without parking.
#[derive(Clone, Copy)]
pub(crate) struct GuestStop {
    /// 900 unexpected EL0 fault, 901 non-0x43 SVC, 902 SVC budget exhausted,
    /// 903 TLS handshake lifetime, 904 pending input idle,
    /// 905 active TLS lifetime, 906 active input idle.
    pub(crate) code: u64,
    /// SVC dispatches performed before the stop (read by production only; the
    /// fixture halts on `code`).
    #[cfg_attr(not(feature = "v020-production"), allow(dead_code))]
    pub(crate) dispatched: u64,
}

/// Run the guest until it parks (CLOSE then a sustained YIELD run) or fails
/// closed. Fixture semantics: any stop is fatal with its code (production uses
/// `try_run_until_park` and never halts on a guest stop).
#[cfg(feature = "v0199-sec-n-selftest")]
pub(crate) fn run_until_park<P: Port>(layout: &Layout, port: &mut P, budget: u64) -> u64 {
    match try_run_until_park(layout, port, &mut fixture_entropy, budget) {
        Ok(dispatched) => dispatched,
        Err(stop) => fatal(stop.code),
    }
}

/// Run the guest until it parks or a bounded SVC budget is spent, returning the
/// stop instead of halting the boot. Returns the number of SVC dispatches.
#[cfg(any(
    feature = "v0199-sec-n-selftest",
    not(feature = "v020-production-authenticated-net")
))]
pub(crate) fn try_run_until_park<P: Port>(
    layout: &Layout,
    port: &mut P,
    entropy: &mut EntropyFill<'_>,
    budget: u64,
) -> Result<u64, GuestStop> {
    run_guest(
        layout,
        port,
        entropy,
        budget,
        None,
        #[cfg(feature = "v020-production-authenticated-net")]
        None,
    )
}

pub(crate) fn run_guest<P: Port>(
    layout: &Layout,
    port: &mut P,
    entropy: &mut EntropyFill<'_>,
    budget: u64,
    close_poll: Option<ClosePoll<P>>,
    #[cfg(feature = "v020-production-authenticated-net")] mut signer: Option<&mut signer::Signer>,
) -> Result<u64, GuestStop> {
    struct SavedContext(user::Context);
    impl Drop for SavedContext {
        fn drop(&mut self) {
            // SAFETY: EL0 has returned and the owner still has exclusive
            // access to the saved context, even on a terminal error.
            unsafe { core::ptr::write_volatile(&mut self.0, user::Context::empty()) };
        }
    }

    let root = phys(guest_memory().root as u64);
    let mut saved = SavedContext(fresh_context(layout));
    let ctx = &mut saved.0;
    let mut dispatched = 0u64;
    let stop = |code, dispatched| Err(GuestStop { code, dispatched });
    for _ in 0..budget {
        #[cfg(feature = "v020-production-authenticated-net")]
        let (window, latest_tick) =
            if signer.is_some() && unsafe { !CLOSE_SEEN && RETIREMENT == Retirement::Open } {
                let Some(window) = (unsafe { TLS_WINDOW }) else {
                    return stop(903, dispatched);
                };
                let now = now_ns();
                let deadline_ns = window.deadline().0;
                if now >= deadline_ns {
                    return Err(tls_timeout(window, now, dispatched));
                }
                (Some(window), ticks_at_ns(deadline_ns))
            } else {
                (None, u64::MAX)
            };
        #[cfg(not(feature = "v020-production-authenticated-net"))]
        let latest_tick = u64::MAX;
        step(ctx, root, GUEST_ASID, latest_tick);
        if ctx.kind == 9 {
            continue; // private PPI preemption; resume.
        }
        if ctx.kind != 8 || ctx.esr >> 26 != 0x15 {
            return stop(900, dispatched); // unexpected EL0 fault (not an SVC).
        }
        let iss = ctx.esr & 0xffff;
        if iss != 0x43 {
            return stop(901, dispatched); // only SVC 0x43 is admitted for this guest.
        }
        #[cfg(feature = "v020-production-authenticated-net")]
        if let Some(window) = window
            && timer::ticks() >= latest_tick
        {
            return Err(tls_timeout(window, now_ns(), dispatched));
        }
        broker(
            port,
            entropy,
            close_poll,
            #[cfg(feature = "v020-production-authenticated-net")]
            signer.as_deref_mut(),
        );
        dispatched += 1;
        // ELR already points past the trapped SVC; resume with no register return
        // (the broker ABI carries results in the shared page, not x0).
        let parked = unsafe { CLOSE_SEEN && YIELD_RUN >= 64 };
        if parked {
            return Ok(dispatched);
        }
    }
    stop(902, dispatched) // guest never parked within the bounded budget.
}

// ---- by-value broker state accessors (no reference to a static escapes) ----
/// The accepted receipt for this one-shot guest connection.
#[cfg(feature = "v020-production")]
pub(crate) fn admission_receipt() -> Option<(u64, u32)> {
    unsafe { ADMISSION_RECEIPT }
}
#[cfg(feature = "v020-production-authenticated-net")]
pub(crate) fn retired() -> bool {
    unsafe { RETIREMENT == Retirement::Retired }
}
/// Ingress bytes delivered to the guest through SVC 0x43 READ.
#[cfg(feature = "v020-production")]
pub(crate) fn relayed_bytes() -> u64 {
    unsafe { RELAYED_BYTES }
}
/// Closed/reset/failed stream events surfaced to the guest as EOF.
#[cfg(feature = "v020-production")]
pub(crate) fn stream_closed() -> u64 {
    unsafe { STREAM_CLOSED }
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
