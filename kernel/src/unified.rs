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
    tcp::{BUFFER_SIZE, Config, Error as TcpError, State as TcpState, Storage, Tcp, reconnect_due},
};
use cyxia_contracts::{BootInfo, PhysAddr};
use cyxia_driver_virtio::{
    Platform, Transport, net::BatchedNet as Net, queue::BatchMemory as QueueMemory,
};
use cyxia_kernel_core::control_plane::service_image::{BASE, Image, LIMIT};
use cyxia_prototype::domains::Error;
#[path = "../../user/prototype-cluster/src/abi.rs"]
pub(crate) mod abi;
const ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/cluster-service.elf"));
const LOCAL: &[u8; 32] = include_bytes!(concat!(env!("OUT_DIR"), "/local.pin32"));
const PEER: &[u8; 32] = include_bytes!(concat!(env!("OUT_DIR"), "/peer.pin32"));
const UNIX: u64 = include!(concat!(env!("OUT_DIR"), "/cluster-unix.rs"));
const SELFTEST: bool = include!(concat!(env!("OUT_DIR"), "/domain-selftest.rs"));
type NativeTcp<'a> = Tcp<'static, VirtioPort<'a, Board, Net>>;
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
    let mut offline = None;
    loop {
        coordinator.poll();
        let _ = crate::domain_platform::poll(Board.now_ns());
        crate::domain_tasks::service(Board.now_ns(), &mut || coordinator.poll());
        let _ = service_work(coordinator, &mut offline, 0, |advance| {
            crate::domain_services::service(Board.now_ns(), advance)
        });
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
            selected = Some((t, resource.base.0, resource.irq));
        }
    }
    // SAFETY: one lifetime owner, pinned DMA pages, never recycled on errors.
    let (transport, id, irq) = selected.unwrap_or_else(|| fail(2));
    let mut net = unsafe {
        Net::initialize(
            transport,
            &mut *core::ptr::addr_of_mut!(RX),
            &mut *core::ptr::addr_of_mut!(TX),
            &Board,
        )
    }
    .unwrap_or_else(|_| fail(3));
    crate::domain_storage::register_notify_device(
        crate::domain_storage::NET_NOTIFY,
        id,
        net.capacity(),
        irq,
    )
    .unwrap_or_else(|_| fail(23));
    net.set_notify_hooks(
        crate::domain_storage::net_notify_command,
        crate::domain_storage::net_notify_feedback,
    );
    net.set_completion_interrupts(true, &Board);
    crate::domain_platform::enable_device_irq(irq).unwrap_or_else(|_| fail(24));
    net
}

fn startup<T>(stage: u64, mut action: impl FnMut() -> Result<T, Error>) -> T {
    UNIFIED_EVIDENCE.words[24].store(stage, Ordering::Release);
    let until = Board.now_ms().saturating_add(5000);
    loop {
        match action() {
            Ok(value) => {
                UNIFIED_EVIDENCE.words[25].store(0, Ordering::Release);
                return value;
            }
            Err(error) => {
                UNIFIED_EVIDENCE.words[25].store(error as u64 + 1, Ordering::Release);
                if !matches!(error, Error::Busy | Error::Again | Error::NotReady)
                    || Board.now_ms() >= until
                {
                    fail(100 + stage);
                }
                core::hint::spin_loop();
            }
        }
    }
}

fn drain_network(tcp: &mut NativeTcp<'_>, epoch: u64) {
    if epoch == 0 {
        return;
    }
    // The queue still owns each prefix until this exact, all-or-nothing TCP
    // enqueue succeeds. One FIFO head is handled in this CPU reservation;
    // further heads retain custody for later independently measured turns.
    let _ = crate::domain_tasks::network_drain(epoch, Board.now_ns(), &mut |bytes| {
        tcp.send_exact(bytes).map_err(|e| match e {
            TcpError::WouldBlock => Error::Again,
            _ => Error::Io,
        })?;
        UNIFIED_EVIDENCE.words[4].fetch_add(bytes.len() as u64, Ordering::Relaxed);
        UNIFIED_EVIDENCE.words[26].fetch_add(1, Ordering::Relaxed);
        UNIFIED_EVIDENCE.words[27].fetch_add(bytes.len() as u64, Ordering::Release);
        Ok(())
    });
}

fn mechanism_progress(coordinator: &mut crate::smp::prototype_runtime::Coordinator) {
    coordinator.poll();
    let _ = crate::domain_platform::poll(Board.now_ns());
}

fn resume_network_service(coordinator: &mut crate::smp::prototype_runtime::Coordinator) -> u64 {
    loop {
        if crate::domain_tasks::begin_service_segment().is_some()
            && crate::domain_tasks::revalidate_service_segment()
        {
            return timer::cpu_ticks();
        }
        mechanism_progress(coordinator);
    }
}

fn network_turn(
    coordinator: &mut crate::smp::prototype_runtime::Coordinator,
    tcp: &mut Option<NativeTcp<'_>>,
    epoch: u64,
) -> Result<TcpState, TcpError> {
    let Some(link) = tcp.as_mut() else {
        crate::unified_task::transport(false);
        return Ok(TcpState::Closed);
    };
    let Some(_) = crate::domain_tasks::begin_service_segment() else {
        return link.state();
    };
    if !crate::domain_tasks::revalidate_service_segment() {
        return link.state();
    }
    let mut started = timer::cpu_ticks();
    let mut network_stage = 40u64;
    UNIFIED_EVIDENCE.words[30].store(network_stage, Ordering::Release);
    let mut checkpoint = || {
        finish_service(started);
        mechanism_progress(coordinator);
        started = resume_network_service(coordinator);
        network_stage = network_stage.saturating_add(1);
        UNIFIED_EVIDENCE.words[30].store(network_stage, Ordering::Release);
    };
    let state = link.poll_with_checkpoints(Board.now_ms(), &mut checkpoint);
    if matches!(state, Ok(TcpState::Established)) && epoch != 0 {
        // Socket polling and IPC dequeue are separate bounded owners. The
        // callback runs with no socket/device or task lock held.
        checkpoint();
        drain_network(link, epoch);
    }
    drop(checkpoint);
    finish_service(started);
    let connected = matches!(state, Ok(TcpState::Established));
    crate::unified_task::transport(connected && epoch != 0);
    state
}

fn progress(
    coordinator: &mut crate::smp::prototype_runtime::Coordinator,
    tcp: &mut Option<NativeTcp<'_>>,
    epoch: u64,
) {
    mechanism_progress(coordinator);
    let _ = network_turn(coordinator, tcp, epoch);
}

fn finish_service(started: u64) {
    let actual_ns = timer::cpu_elapsed_ns(started);
    let finished_ns = Board.now_ns();
    match crate::domain_tasks::complete_service(actual_ns, finished_ns) {
        Ok(()) | Err(Error::Budget) => {}
        Err(_) => fail(30),
    }
}

/// A synchronous operation retains its own journal/DMA obligation while CPU
/// credit is released at every bounded progress point. Time spent advancing
/// another owner or waiting for a later budget window is not charged as its CPU.
fn service_work<R>(
    coordinator: &mut crate::smp::prototype_runtime::Coordinator,
    tcp: &mut Option<NativeTcp<'_>>,
    epoch: u64,
    work: impl FnOnce(&mut dyn FnMut()) -> R,
) -> R {
    let mut started = service_start(coordinator, tcp, epoch);
    let mut advance = || {
        finish_service(started);
        progress(coordinator, tcp, epoch);
        started = service_start(coordinator, tcp, epoch);
    };
    let result = work(&mut advance);
    drop(advance);
    finish_service(started);
    result
}

fn service_start(
    coordinator: &mut crate::smp::prototype_runtime::Coordinator,
    tcp: &mut Option<NativeTcp<'_>>,
    epoch: u64,
) -> u64 {
    loop {
        if crate::domain_tasks::begin_service_segment().is_some()
            && crate::domain_tasks::revalidate_service_segment()
        {
            return timer::cpu_ticks();
        }
        progress(coordinator, tcp, epoch);
    }
}

fn update_probe() {
    if SELFTEST
        && UNIFIED_EVIDENCE.words[19].load(Ordering::Acquire) == 0
        && let Ok(Some(code)) = crate::domain_tasks::probe_status()
    {
        UNIFIED_EVIDENCE.words[20].store(code, Ordering::Relaxed);
        UNIFIED_EVIDENCE.words[21].store(Board.now_ns(), Ordering::Relaxed);
        UNIFIED_EVIDENCE.words[19].store(1, Ordering::Release);
    }
}

fn close_network(epoch: u64, coordinator: &mut crate::smp::prototype_runtime::Coordinator) {
    if epoch == 0 {
        return;
    }
    crate::domain_network::bind_network(epoch, None).unwrap_or_else(|_| fail(31));
    loop {
        match crate::domain_tasks::close_network(epoch) {
            Ok(()) => return,
            Err(Error::Busy | Error::Again) => coordinator.poll(),
            Err(_) => fail(32),
        }
    }
}

pub fn run(info: &BootInfo) -> ! {
    assert_eq!(cpu::slot(), 0);
    // Register the DTB's physical sources before any driver enables a queue.
    startup(1, || crate::domain_platform::init(info));
    UNIFIED_EVIDENCE.words[24].store(2, Ordering::Release);
    let boot = crate::prototype_storage::boot(info);
    crate::storage_fault_capture::init(boot);
    crate::a02_capture::init_boot(boot.epoch);
    crate::entropy::init(info);
    startup(3, crate::domain_tasks::init);
    startup(4, crate::domain_storage::init);
    startup(5, || {
        crate::domain_tasks::set_file_service(
            crate::domain_storage::validate_file_object,
            crate::domain_storage::stat_file_object,
        )
    });
    startup(6, || {
        crate::domain_tasks::set_cache_loader(crate::domain_storage::read_cache_page)
    });
    crate::unified_store::init();
    crate::unified_task::init(boot.epoch, *PEER);
    startup(7, || crate::domain_control::init(boot.epoch));
    startup(8, crate::domain_services::init);
    let mut net = attach(info);
    startup(9, crate::prototype_storage::enable_block_interrupts);
    // An unavailable or poisoned RNG leaves the service offline; it never
    // substitutes a deterministic seed or releases the existing DMA backing.
    match crate::entropy::enable_interrupts() {
        Ok(()) | Err(Error::NotReady) => {}
        Err(_) => fail(33),
    }
    startup(10, crate::domain_tasks::register_control);
    startup(11, crate::domain_storage::register_control);
    startup(12, crate::domain_platform::register_control);
    startup(13, crate::domain_network::register_control);
    startup(14, crate::domain_services::register_control);
    let mut coordinator = crate::smp::prototype_runtime::Coordinator::new(boot);
    crate::smp::prototype_runtime::register_broker_devices();
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
    if crate::storage_fault_capture::PROFILE {
        if crate::storage_fault_capture::mode() != 3 {
            startup(15, || crate::domain_tasks::start_storage_client(1));
        }
        startup(15, || crate::domain_tasks::start_storage_client(2));
    } else if SELFTEST {
        let key = startup(15, crate::domain_tasks::start_probe_client);
        UNIFIED_EVIDENCE.words[16].store(1, Ordering::Relaxed);
        UNIFIED_EVIDENCE.words[17].store(key.id, Ordering::Relaxed);
        UNIFIED_EVIDENCE.words[18].store(key.generation, Ordering::Release);
    }
    unsafe {
        cpu::disable_timer();
    }
    crate::smp::enable_service_timer();
    UNIFIED_EVIDENCE.words[1].store(boot.epoch, Ordering::Relaxed);
    UNIFIED_EVIDENCE.words[24].store(16, Ordering::Relaxed);
    UNIFIED_EVIDENCE.words[0].store(0x435958554e493031, Ordering::Release);
    let node = net.mac()[5];
    if !(1..=2).contains(&node) || net.mac() != [2, 0, 0, 0, 0, node] || LOCAL == PEER {
        fail(6)
    }
    let initiator = LOCAL < PEER;
    let mut config = Config {
        mac: net.mac(),
        local: [10, 42, 0, node],
        peer: [10, 42, 0, 3 - node],
        prefix_len: 24,
        local_port: if initiator { 40001 } else { 8443 },
        peer_port: if initiator { 8443 } else { 40001 },
        random_seed: 1, // Always replaced by real fresh guest entropy below.
    };
    line(format_args!(
        "UNIFIED_START node={node} boot={} initiator={} EL0_TLS\n",
        boot.epoch, initiator as u8
    ));
    let mut sequence = 0u64;
    let mut connection_epoch = 0u64;
    let mut entropy_failed = false;
    let mut refresh_input = true;
    let mut learning_install_stage = 0u8;
    loop {
        // Only TCP state is reconstructed. The NIC and all DMA buffers retain
        // their original owner for the entire boot, including poisoned queues.
        let mut fresh = [0; 8];
        if !entropy_failed
            && crate::entropy::fill_progress(&mut fresh, &mut || {
                coordinator.poll();
                let _ = crate::domain_platform::poll(Board.now_ns());
            })
            .is_err()
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
        if let Some(link) = tcp.as_mut() {
            (if initiator {
                link.connect()
            } else {
                link.listen()
            })
            .unwrap_or_else(|_| fail(8));
        }
        let mut stream_epoch = 0;
        let mut terminal_since = None;
        loop {
            coordinator.poll();
            if learning_install_stage < 4 {
                match crate::domain_tasks::service_segment(|| match learning_install_stage {
                    0 => {
                        UNIFIED_EVIDENCE.words[30].store(1, Ordering::Release);
                        crate::smp::prototype_runtime::install_learning_capture_storage(
                            *LOCAL, boot.epoch,
                        )
                    }
                    1 => {
                        UNIFIED_EVIDENCE.words[30].store(1, Ordering::Release);
                        crate::smp::prototype_runtime::install_learning_history_storage(
                            *LOCAL, boot.epoch,
                        )
                    }
                    2 => {
                        UNIFIED_EVIDENCE.words[30].store(2, Ordering::Release);
                        crate::peer_replay::init(boot.epoch)
                    }
                    3 => {
                        UNIFIED_EVIDENCE.words[30].store(3, Ordering::Release);
                        crate::learning_replay::init()
                    }
                    _ => Ok(()),
                }) {
                    Some(Ok(())) => {
                        learning_install_stage += 1;
                        if learning_install_stage == 4 {
                            UNIFIED_EVIDENCE.words[28].store(1, Ordering::Release);
                        }
                    }
                    None | Some(Err(Error::Busy | Error::Again | Error::NotReady)) => {}
                    Some(Err(error)) => {
                        UNIFIED_EVIDENCE.words[29].store(error as u64 + 1, Ordering::Release);
                        fail(37);
                    }
                }
            }
            let _ = crate::domain_platform::poll(Board.now_ns());
            let state = network_turn(&mut coordinator, &mut tcp, stream_epoch);
            let now = Board.now_ms();
            let connected = matches!(state, Ok(TcpState::Established));
            if connected && stream_epoch == 0 {
                let next = connection_epoch.checked_add(1).unwrap_or_else(|| fail(10));
                match crate::domain_tasks::open_network(next) {
                    Ok(key) => {
                        match crate::domain_network::bind_network(next, Some(key)) {
                            Ok(()) => {}
                            Err(Error::Busy | Error::Again) => continue,
                            Err(_) => fail(34),
                        }
                        stream_epoch = next;
                        connection_epoch = next;
                    }
                    Err(Error::Busy | Error::Again) => continue,
                    Err(_) => fail(35),
                }
            }
            crate::unified_task::transport(connected && stream_epoch != 0);
            if reconnect_due(state, 1000, !entropy_failed) {
                let since = *terminal_since.get_or_insert(now);
                if reconnect_due(state, now.saturating_sub(since), !entropy_failed) {
                    break;
                }
            } else {
                terminal_since = None;
            }

            // These pumps own their own bounded CPU segments. Their progress
            // callback advances mechanisms only, so no active file/owner is
            // recursively borrowed and no waiting wall time becomes CPU usage.
            crate::domain_tasks::service(Board.now_ns(), &mut || {
                progress(&mut coordinator, &mut tcp, stream_epoch)
            });
            let _ = service_work(&mut coordinator, &mut tcp, stream_epoch, |advance| {
                UNIFIED_EVIDENCE.words[30].store(5, Ordering::Release);
                crate::domain_services::service(Board.now_ns(), advance)
            });
            update_probe();
            coordinator.poll();
            let Some(_credit) = crate::domain_tasks::begin_service(Board.now_ns()) else {
                core::hint::spin_loop();
                continue;
            };
            let entered = timer::cpu_ticks();
            UNIFIED_EVIDENCE.words[30].store(6, Ordering::Release);
            unsafe {
                if refresh_input {
                    // An IRQ can interrupt an EL0 structure copy. Keep input
                    // immutable until the next broker SVC boundary so a copy
                    // cannot combine fields from two policy publications.
                    let p = &mut *shared();
                    let now = Board.now_ms();
                    p.monotonic_ms = now;
                    p.unix_seconds = UNIX.checked_add(now / 1000).unwrap_or_else(|| fail(14));
                    p.connection_epoch = connection_epoch;
                    p.boot_epoch = boot.epoch;
                    p.uuid = boot.filesystem;
                    p.local_node = *LOCAL;
                    p.peer_node = *PEER;
                    crate::domain_network::prepare(p);
                    p.domains.peer_ipv4 = u64::from(u32::from_be_bytes(config.peer));
                    let observation = tcp
                        .as_ref()
                        .map(|link| link.observation())
                        .unwrap_or_default();
                    let depth = if stream_epoch == 0 {
                        Ok(0)
                    } else {
                        crate::domain_tasks::network_pending(stream_epoch)
                    };
                    p.domains.network_valid = if depth.is_ok() { observation.valid } else { 0 };
                    p.domains.network_sample_ms = observation.sample_ms;
                    p.domains.network_rtt_us = observation.rtt_us;
                    p.domains.network_retrans_milli = observation.retrans_milli;
                    p.domains.network_queued_bytes = observation.queued_bytes;
                    p.domains.network_queue_depth = depth.unwrap_or(0) as u64;
                    p.domains.network_active = observation.active;
                    refresh_input = false;
                }
                if !crate::domain_tasks::revalidate_builtin(0) {
                    refresh_input = true;
                    continue;
                }
                let slice = crate::domain_tasks::active_slice_ticks(0).unwrap_or_else(|| fail(36));
                let hard =
                    timer::ticks().saturating_add(slice.min((timer::frequency() / 1000).max(1)));
                crate::smp::enter_service(
                    &mut context,
                    phys(core::ptr::addr_of!(ROOT) as u64),
                    crate::domain_platform::next_deadline_ticks(hard),
                    crate::a02_capture::Task {
                        id: 0xffff_ffff_ffff_fef1,
                        generation: 1,
                        role: 1,
                        affinity: 1,
                    },
                    true,
                );
            }
            UNIFIED_EVIDENCE.words[2].fetch_add(1, Ordering::Relaxed);
            // Feedback is accepted only at a completed, unchanged even
            // publication sequence; an IRQ may interrupt the EL0 writer.
            unsafe {
                crate::domain_network::observe(&*shared());
            }
            finish_service(entered);
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
                drop(tcp);
                close_network(stream_epoch, &mut coordinator);
                isolate(&mut coordinator, 11)
            }
            let now = Board.now_ms();
            let p = unsafe { &mut *shared() };
            if p.magic != abi::MAGIC
                || p.version != abi::VERSION
                || p.sequence != sequence.checked_add(1).unwrap_or_else(|| fail(12))
                || !abi::valid_request(p.op, p.len, p.offset)
                || (p.op == abi::OP_WRITE && p.arg0 > 1)
            {
                fail(13)
            }
            sequence = p.sequence;
            refresh_input = true;
            let len = p.len as usize;
            p.status = abi::OK;
            match p.op {
                abi::OP_ENTROPY => {
                    if entropy_failed
                        || service_work(&mut coordinator, &mut tcp, stream_epoch, |advance| {
                            crate::entropy::fill_progress(&mut p.payload[..len], advance)
                        })
                        .is_err()
                    {
                        p.payload[..len].fill(0);
                        p.status = abi::FAILED;
                    }
                }
                abi::OP_TIME | abi::OP_YIELD => p.len = 0,
                abi::OP_POLL => {
                    p.len = 0;
                    p.arg0 = u64::from(
                        matches!(
                            network_turn(&mut coordinator, &mut tcp, stream_epoch),
                            Ok(TcpState::Established)
                        ) && stream_epoch != 0,
                    );
                }
                abi::OP_READ => {
                    let started = service_start(&mut coordinator, &mut tcp, stream_epoch);
                    match tcp
                        .as_mut()
                        .map(|link| link.receive_tls(&mut p.payload[..len]))
                        .unwrap_or(Err(TcpError::Closed))
                    {
                        Ok(n) => {
                            p.len = n as u64;
                            UNIFIED_EVIDENCE.words[5].fetch_add(n as u64, Ordering::Relaxed);
                        }
                        Err(TcpError::WouldBlock) => p.status = abi::AGAIN,
                        Err(_) => p.status = abi::EOF,
                    }
                    finish_service(started);
                }
                abi::OP_WRITE => {
                    let started = service_start(&mut coordinator, &mut tcp, stream_epoch);
                    if stream_epoch == 0 || tcp.is_none() {
                        p.status = abi::EOF;
                    } else if p.arg0 == 0 {
                        // The endpoint owner first holds a real cancellable
                        // D05 cell, then waits for its root-confirmed receipt
                        // and checks D10 dependencies before enqueueing that
                        // same grant. A rejected retry owns no accepted bytes.
                        // Equal-prefix retries reuse its original grant/ID,
                        // even though this SVC sequence has advanced.
                        let result = crate::domain_tasks::network_write(
                            stream_epoch,
                            sequence,
                            &p.payload[..len],
                        );
                        match result {
                            Ok(n) => p.len = n as u64,
                            Err(
                                Error::Busy
                                | Error::Again
                                | Error::Capacity
                                | Error::Budget
                                | Error::NotReady
                                | Error::Conflict,
                            ) => p.status = abi::AGAIN,
                            Err(_) => p.status = abi::EOF,
                        }
                    } else {
                        // Record encryption assigns a strict stream order.
                        // Reserved ciphertext must never bypass an earlier
                        // ordinary ciphertext prefix still owned by IPC.
                        let link = tcp.as_mut().unwrap();
                        drain_network(link, stream_epoch);
                        match crate::domain_tasks::network_pending(stream_epoch) {
                            Ok(0) => match link.send_tls(&p.payload[..len]) {
                                Ok(n) => {
                                    p.len = n as u64;
                                    UNIFIED_EVIDENCE.words[4]
                                        .fetch_add(n as u64, Ordering::Relaxed);
                                }
                                Err(TcpError::WouldBlock) => p.status = abi::AGAIN,
                                Err(_) => p.status = abi::EOF,
                            },
                            Ok(_) | Err(Error::Busy | Error::Again) => p.status = abi::AGAIN,
                            Err(_) => p.status = abi::EOF,
                        }
                    }
                    finish_service(started);
                }
                abi::OP_STORE_GET | abi::OP_STORE_PUT => {
                    let (status, n, value) =
                        service_work(&mut coordinator, &mut tcp, stream_epoch, |advance| {
                            crate::unified_store::request(
                                p.op == abi::OP_STORE_PUT,
                                p.arg0,
                                p.arg1,
                                p.arg2,
                                p.offset,
                                &mut p.payload,
                                len,
                                advance,
                            )
                        });
                    p.status = status;
                    p.len = n as u64;
                    p.arg0 = value;
                    if status == abi::OK && p.op == abi::OP_STORE_PUT {
                        UNIFIED_EVIDENCE.words[7].fetch_add(1, Ordering::Release);
                    }
                }
                abi::OP_STORE_FLUSH => p.len = 0, // PUT already committed and FLUSHed.
                abi::OP_TASK => {
                    let _ = network_turn(&mut coordinator, &mut tcp, stream_epoch);
                    let started = service_start(&mut coordinator, &mut tcp, stream_epoch);
                    // Waiting for the full mechanism credit may advance a
                    // socket or a contract deadline. Revalidate at admission,
                    // never using the earlier SVC capture time/connectivity.
                    let live = tcp
                        .as_ref()
                        .is_some_and(|link| link.state() == Ok(TcpState::Established))
                        && stream_epoch != 0;
                    let (status, n, value) = crate::unified_task::request(
                        p.arg0,
                        p.arg1,
                        p.arg2,
                        &mut p.payload,
                        len,
                        Board.now_ms(),
                        live,
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
                    finish_service(started);
                }
                abi::OP_CLOSE => {
                    let started = service_start(&mut coordinator, &mut tcp, stream_epoch);
                    p.len = 0;
                    crate::unified_task::transport(false);
                    if let Some(link) = tcp.as_mut() {
                        link.close(Board.now_ms());
                    }
                    terminal_since.get_or_insert(Board.now_ms());
                    finish_service(started);
                }
                abi::OP_TRACE => {
                    let started = service_start(&mut coordinator, &mut tcp, stream_epoch);
                    if p.arg0 & abi::TRACE_FATAL_BIT != 0 {
                        let code = (p.arg0 & !abi::TRACE_FATAL_BIT).max(1);
                        let _ = UNIFIED_EVIDENCE.words[15].compare_exchange(
                            0,
                            code,
                            Ordering::Release,
                            Ordering::Relaxed,
                        );
                    }
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
                    finish_service(started);
                }
                _ => p.status = abi::FAILED,
            }
        }
        crate::unified_task::transport(false);
        // End the socket and NIC mutable borrow before discarding IPC prefixes;
        // otherwise a new connection could receive an old stream's bytes.
        drop(tcp);
        close_network(stream_epoch, &mut coordinator);
    }
}
