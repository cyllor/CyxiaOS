//! One native runtime: CPU0 mechanism broker, isolated EL0 TLS/member service,
//! concurrent local-model control and independently scheduled business cores.
use crate::virtio_platform::Board;
use core::{
    fmt::Write,
    sync::atomic::{AtomicU64, Ordering},
};
use cyxia_arch_aarch64::{cpu, mmu, timer, user};
use cyxia_cluster_transport::{
    device::VirtioPort,
    tcp::{BUFFER_SIZE, Config, Storage, Tcp},
};
use cyxia_contracts::{BootInfo, PhysAddr};
use cyxia_driver_virtio::{Platform, QueueMemory, Transport, net::Net};
use cyxia_kernel_core::control_plane::service_image::{BASE, Image, LIMIT};
#[path = "../../user/prototype-cluster/src/abi.rs"]
mod abi;
const ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/cluster-service.elf"));
const LOCAL: &[u8; 32] = include_bytes!(concat!(env!("OUT_DIR"), "/local.pin32"));
const PEER: &[u8; 32] = include_bytes!(concat!(env!("OUT_DIR"), "/peer.pin32"));
const UNIX: u64 = include!(concat!(env!("OUT_DIR"), "/cluster-unix.rs"));
#[repr(C, align(4096))]
struct Page([u64; 512]);
#[repr(C, align(4096))]
struct Bytes<const N: usize>([u8; N]);
static mut ROOT: Page = Page([0; 512]);
static mut MIDDLE: Page = Page([0; 512]);
static mut LEAVES: [Page; 9] = [const { Page([0; 512]) }; 9];
static mut PRIVATE: Bytes<{ (LIMIT - BASE) as usize }> = Bytes([0; (LIMIT - BASE) as usize]);
static mut STACK: Bytes<{ abi::STACK_BYTES }> = Bytes([0; abi::STACK_BYTES]);
static mut SHARED: Bytes<{ abi::SHARED_BYTES }> = Bytes([0; abi::SHARED_BYTES]);
static mut RX: QueueMemory = QueueMemory::zeroed();
static mut TX: QueueMemory = QueueMemory::zeroed();
static mut TCP_RX: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];
static mut TCP_TX: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];
static mut SOCKET: [Storage<'static>; 1] = [Storage::EMPTY];
#[repr(C, align(4096))]
pub struct Evidence {
    words: [AtomicU64; 512],
}
#[used]
#[unsafe(no_mangle)]
pub static UNIFIED_EVIDENCE: Evidence = Evidence {
    words: [const { AtomicU64::new(0) }; 512],
};
fn line(args: core::fmt::Arguments<'_>) {
    struct Text {
        bytes: [u8; 256],
        n: usize,
    }
    impl Write for Text {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let end = self.n.checked_add(s.len()).ok_or(core::fmt::Error)?;
            self.bytes
                .get_mut(self.n..end)
                .ok_or(core::fmt::Error)?
                .copy_from_slice(s.as_bytes());
            self.n = end;
            Ok(())
        }
    }
    let mut t = Text {
        bytes: [0; 256],
        n: 0,
    };
    t.write_fmt(args).expect("bounded trace");
    crate::log(&t.bytes[..t.n]);
}
fn fail(code: u64) -> ! {
    UNIFIED_EVIDENCE.words[15].store(code, Ordering::Release);
    line(format_args!("UNIFIED_FAIL code={code}\n"));
    crate::halt()
}
fn isolate(coordinator: &mut crate::smp::prototype_runtime::Coordinator, code: u64) -> ! {
    crate::unified_task::transport(false);
    UNIFIED_EVIDENCE.words[15].store(code, Ordering::Release);
    line(format_args!(
        "UNIFIED_ISOLATED code={code} local_control_continues\n"
    ));
    loop {
        coordinator.poll();
        core::hint::spin_loop();
    }
}
fn phys(address: u64) -> u64 {
    address.checked_sub(crate::HIGH).expect("kernel pointer")
}
fn shared() -> *mut abi::Shared {
    core::ptr::addr_of_mut!(SHARED).cast()
}
/// Called once on CPU0 before entering the service. Static backing is private to
/// this root; no physical frames from other processes or device MMIO are mapped.
unsafe fn load() -> user::Context {
    let image = Image::parse(ELF).expect("validated cluster ELF");
    unsafe {
        let root = core::ptr::addr_of_mut!(ROOT);
        let mid = core::ptr::addr_of_mut!(MIDDLE);
        (*root).0[0] = phys(mid as u64) | 3;
        for (slot, index) in [8, 9, 10, 11, 12, 13, 14, 15, 16].into_iter().enumerate() {
            let leaf = core::ptr::addr_of_mut!(LEAVES).cast::<Page>().add(slot);
            (*mid).0[index] = phys(leaf as u64) | 3;
        }
        let backing = core::ptr::addr_of_mut!(PRIVATE).cast::<u8>();
        for s in &image.segments[..image.count] {
            let at = (s.address - BASE) as usize;
            core::ptr::copy_nonoverlapping(
                image.bytes.as_ptr().add(s.offset),
                backing.add(at),
                s.file_size,
            );
            core::ptr::write_bytes(
                backing.add(at + s.file_size),
                0,
                s.memory_size - s.file_size,
            );
            for page in (0..s.memory_size).step_by(4096) {
                map(
                    s.address + page as u64,
                    backing.add(at + page) as u64,
                    s.writable,
                    s.executable,
                );
            }
            for offset in (0..s.memory_size).step_by(64) {
                core::arch::asm!("dc cvau, {}",in(reg)backing.add(at+offset),options(nostack));
            }
        }
        let stack = core::ptr::addr_of_mut!(STACK).cast::<u8>();
        for page in (0..abi::STACK_BYTES).step_by(4096) {
            map(
                abi::STACK_TOP - abi::STACK_BYTES as u64 + page as u64,
                stack.add(page) as u64,
                true,
                false,
            );
        }
        let shared = core::ptr::addr_of_mut!(SHARED).cast::<u8>();
        for page in (0..abi::SHARED_BYTES).step_by(4096) {
            map(
                abi::SHARED_VA + page as u64,
                shared.add(page) as u64,
                true,
                false,
            );
        }
        core::arch::asm!("dsb ish", "ic ialluis", "dsb ish", "isb", options(nostack));
    }
    let mut ctx = user::Context::empty();
    ctx.pc = image.entry;
    ctx.sp = abi::STACK_TOP;
    ctx
}
unsafe fn map(va: u64, address: u64, writable: bool, executable: bool) {
    let slot = match va >> 21 {
        8..=14 => (va >> 21) as usize - 8,
        15 => 7,
        16 => 8,
        _ => panic!("private mapping bound"),
    };
    unsafe {
        let leaf = &mut *core::ptr::addr_of_mut!(LEAVES).cast::<Page>().add(slot);
        let entry = &mut leaf.0[((va >> 12) & 511) as usize];
        assert_eq!(*entry, 0, "no aliases");
        *entry = mmu::encode_user_leaf(PhysAddr(phys(address)), writable, executable).unwrap();
    }
}
fn attach(info: &BootInfo) -> Net {
    let mut selected = None;
    for resource in info.virtio.get(..info.virtio_count).expect("DTB count") {
        if resource.base.0 < 0x0a000000
            || resource
                .base
                .0
                .checked_add(resource.len)
                .is_none_or(|end| end > 0x0a200000)
        {
            continue;
        }
        // SAFETY: uniquely CPU0-owned mapped DTB Device range.
        let Ok(t) = (unsafe {
            Transport::attach(
                (crate::HIGH + resource.base.0) as usize,
                resource.len as usize,
            )
        }) else {
            continue;
        };
        if t.device_id() == 1 {
            if selected.is_some() {
                fail(1)
            }
            selected = Some(t);
        }
    }
    // SAFETY: one lifetime owner, pinned DMA pages, never recycled on errors.
    unsafe {
        Net::initialize(
            selected.unwrap_or_else(|| fail(2)),
            &mut *core::ptr::addr_of_mut!(RX),
            &mut *core::ptr::addr_of_mut!(TX),
            &Board,
        )
    }
    .unwrap_or_else(|_| fail(3))
}

pub fn run(info: &BootInfo) -> ! {
    assert_eq!(cpu::slot(), 0);
    let boot = crate::prototype_storage::boot(info);
    crate::entropy::init(info);
    crate::unified_store::init();
    crate::unified_task::init();
    let mut coordinator = crate::smp::prototype_runtime::Coordinator::new(boot);
    let mut context = unsafe { load() };
    unsafe {
        let p = &mut *shared();
        p.magic = abi::MAGIC;
        p.version = abi::VERSION;
        p.boot_epoch = boot.epoch;
        p.uuid = boot.filesystem;
        p.local_node = *LOCAL;
        p.peer_node = *PEER;
    }
    crate::smp::enable_service_timer();
    UNIFIED_EVIDENCE.words[1].store(boot.epoch, Ordering::Relaxed);
    UNIFIED_EVIDENCE.words[0].store(0x435958554e493031, Ordering::Release);
    let mut net = attach(info);
    let node = net.mac()[5];
    if !(1..=2).contains(&node) || net.mac() != [2, 0, 0, 0, 0, node] || LOCAL == PEER {
        fail(6)
    }
    crate::smp::prototype_runtime::register_broker_devices();
    let initiator = LOCAL < PEER;
    let mut config = Config {
        mac: net.mac(),
        local: [10, 42, 0, node],
        peer: [10, 42, 0, 3 - node],
        prefix_len: 24,
        local_port: if initiator { 40001 } else { 8443 },
        peer_port: if initiator { 8443 } else { 40001 },
        random_seed: 1, // Replaced by fresh guest entropy before every TCP construction.
    };
    line(format_args!(
        "UNIFIED_START node={node} boot={} initiator={} EL0_TLS\n",
        boot.epoch, initiator as u8
    ));
    let mut sequence = 0u64;
    let mut connection_epoch = 0u64;
    let mut entropy_failed = false;
    loop {
        // The prior socket borrow has ended; discard its state and use fresh
        // guest entropy for every TCP generation (including retries).
        let mut fresh = [0; 8];
        if !entropy_failed
            && crate::entropy::fill_progress(&mut fresh, &mut || coordinator.poll()).is_err()
        {
            entropy_failed = true;
            crate::unified_task::transport(false);
            UNIFIED_EVIDENCE.words[15].store(4, Ordering::Release);
            crate::log(b"UNIFIED_ISOLATED code=4 local_control_and_custody_continue\n");
        }
        config.random_seed = u64::from_le_bytes(fresh);
        if !entropy_failed && config.random_seed == 0 {
            continue;
        }
        unsafe {
            (*core::ptr::addr_of_mut!(SOCKET))[0] = Storage::EMPTY;
        }
        let mut tcp = if entropy_failed {
            None
        } else {
            Some(
                unsafe {
                    Tcp::new(
                        VirtioPort {
                            net: &mut net,
                            platform: &Board,
                        },
                        config,
                        Board.now_ms(),
                        &mut *core::ptr::addr_of_mut!(TCP_RX),
                        &mut *core::ptr::addr_of_mut!(TCP_TX),
                        &mut *core::ptr::addr_of_mut!(SOCKET),
                    )
                }
                .unwrap_or_else(|_| fail(7)),
            )
        };
        if let Some(tcp) = tcp.as_mut() {
            if initiator {
                tcp.connect()
            } else {
                tcp.listen()
            }
            .unwrap_or_else(|_| fail(8));
        }
        let mut was_connected = false;
        let connecting_since = Board.now_ms();
        loop {
            coordinator.poll();
            let now = Board.now_ms();
            let state = tcp
                .as_mut()
                .map(|tcp| tcp.poll(now))
                .unwrap_or(Ok(cyxia_cluster_transport::tcp::State::Closed));
            let connected = matches!(state, Ok(cyxia_cluster_transport::tcp::State::Established));
            crate::unified_task::transport(connected);
            if !entropy_failed
                && matches!(state, Ok(cyxia_cluster_transport::tcp::State::Closed))
                && now.saturating_sub(connecting_since) > 1000
            {
                break;
            }
            if connected && !was_connected {
                connection_epoch = connection_epoch.checked_add(1).unwrap_or_else(|| fail(10));
            }
            was_connected = connected;
            unsafe {
                let p = &mut *shared();
                p.monotonic_ms = now;
                p.unix_seconds = UNIX.checked_add(now / 1000).unwrap_or_else(|| fail(14));
                p.connection_epoch = connection_epoch;
                p.boot_epoch = boot.epoch;
                p.uuid = boot.filesystem;
                p.local_node = *LOCAL;
                p.peer_node = *PEER;
                timer::arm(timer::ticks() + timer::frequency() / 1000);
                user::enter(&mut context, phys(core::ptr::addr_of!(ROOT) as u64));
                cpu::disable_timer();
            }
            UNIFIED_EVIDENCE.words[2].fetch_add(1, Ordering::Relaxed);
            if context.kind == 9 {
                UNIFIED_EVIDENCE.words[3].fetch_add(1, Ordering::Relaxed);
                continue;
            }
            if context.kind != 8
                || context.esr >> 26 != 0x15
                || context.esr & 0xffff != u64::from(abi::SVC)
            {
                line(format_args!(
                    "UNIFIED_EL0_FAULT kind={} esr={} far={} pc={}\n",
                    context.kind, context.esr, context.far, context.pc
                ));
                isolate(&mut coordinator, 11)
            }
            let now = Board.now_ms();
            let p = unsafe { &mut *shared() };
            if p.magic != abi::MAGIC
                || p.version != abi::VERSION
                || p.sequence != sequence.checked_add(1).unwrap_or_else(|| fail(12))
                || !abi::valid_request(p.op, p.len, p.offset)
            {
                fail(13)
            }
            sequence = p.sequence;
            let len = p.len as usize;
            p.status = abi::OK;
            match p.op {
                abi::OP_ENTROPY => {
                    if entropy_failed
                        || crate::entropy::fill_progress(&mut p.payload[..len], &mut || {
                            coordinator.poll()
                        })
                        .is_err()
                    {
                        p.payload[..len].fill(0);
                        p.status = abi::FAILED;
                    }
                }
                abi::OP_TIME | abi::OP_YIELD => {
                    p.len = 0;
                }
                abi::OP_POLL => {
                    p.len = 0;
                    p.arg0 = u64::from(connected);
                }
                abi::OP_READ => match tcp
                    .as_mut()
                    .map(|tcp| tcp.receive_tls(&mut p.payload[..len]))
                    .unwrap_or(Err(cyxia_cluster_transport::tcp::Error::Closed))
                {
                    Ok(n) => {
                        p.len = n as u64;
                        UNIFIED_EVIDENCE.words[5].fetch_add(n as u64, Ordering::Relaxed);
                    }
                    Err(cyxia_cluster_transport::tcp::Error::WouldBlock) => p.status = abi::AGAIN,
                    Err(_) => p.status = abi::EOF,
                },
                abi::OP_WRITE => match tcp
                    .as_mut()
                    .map(|tcp| tcp.send_tls(&p.payload[..len]))
                    .unwrap_or(Err(cyxia_cluster_transport::tcp::Error::Closed))
                {
                    Ok(n) => {
                        p.len = n as u64;
                        UNIFIED_EVIDENCE.words[4].fetch_add(n as u64, Ordering::Relaxed);
                    }
                    Err(cyxia_cluster_transport::tcp::Error::WouldBlock) => p.status = abi::AGAIN,
                    Err(_) => p.status = abi::EOF,
                },
                abi::OP_STORE_GET | abi::OP_STORE_PUT => {
                    let (status, n, value) = crate::unified_store::request(
                        p.op == abi::OP_STORE_PUT,
                        p.arg0,
                        p.arg1,
                        p.arg2,
                        p.offset,
                        &mut p.payload,
                        len,
                        &mut || coordinator.poll(),
                    );
                    p.status = status;
                    p.len = n as u64;
                    p.arg0 = value;
                    if status == abi::OK && p.op == abi::OP_STORE_PUT {
                        UNIFIED_EVIDENCE.words[7].fetch_add(1, Ordering::Release);
                    }
                }
                abi::OP_STORE_FLUSH => {
                    p.len = 0;
                } // each accepted PUT already includes COMMIT→FLUSH
                abi::OP_TASK => {
                    let (status, n, value) = crate::unified_task::request(
                        p.arg0,
                        p.arg1,
                        p.arg2,
                        &mut p.payload,
                        len,
                        now,
                        connected,
                        connection_epoch,
                    );
                    p.status = status;
                    p.len = n as u64;
                    p.arg0 = value;
                    let (starts, finishes) = crate::unified_task::counts();
                    let (debits, ticks, max) = crate::unified_task::budget();
                    UNIFIED_EVIDENCE.words[10].store(debits, Ordering::Relaxed);
                    UNIFIED_EVIDENCE.words[11].store(ticks, Ordering::Relaxed);
                    UNIFIED_EVIDENCE.words[12].store(max, Ordering::Release);
                    UNIFIED_EVIDENCE.words[8].store(starts, Ordering::Relaxed);
                    UNIFIED_EVIDENCE.words[9].store(finishes, Ordering::Release);
                }
                abi::OP_CLOSE => {
                    p.len = 0;
                    crate::unified_task::transport(false);
                    if let Some(tcp) = tcp.as_mut() {
                        tcp.close(Board.now_ms());
                        break;
                    }
                }
                abi::OP_TRACE => {
                    let n = UNIFIED_EVIDENCE.words[6].fetch_add(1, Ordering::Relaxed) as usize;
                    if n < 200 {
                        UNIFIED_EVIDENCE.words[32 + n * 2].store(p.arg0, Ordering::Relaxed);
                        UNIFIED_EVIDENCE.words[33 + n * 2].store(now, Ordering::Release);
                    }
                    line(format_args!(
                        "UNIFIED_SERVICE event={} arg1={} arg2={} ms={}\n",
                        p.arg0, p.arg1, p.arg2, now
                    ));
                    p.len = 0;
                }
                _ => {
                    p.status = abi::FAILED;
                }
            }
        }
    }
}
