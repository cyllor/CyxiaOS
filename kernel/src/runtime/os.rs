//! Long-running OS service composition on the actual PC board.
//! Shared Shell, resource policy, filesystem, checkpoint and graphics code have
//! one implementation. This entry has no acceptance timeout or A03 campaign.
use core::fmt::Write;
use cyxia_platform_pc::PcBootInfo;
use cyxia_platform_pc::boot::{BootPoolPlan, PoolSize};

static mut SHELL: cyxia_shell::Shell = cyxia_shell::Shell::new();
static mut BOOT_MEMORY: Option<PcBootInfo> = None;

fn plan_user_memory(info: &PcBootInfo) -> BootPoolPlan<4> {
    const MIB: u64 = 1024 * 1024;
    use crate::address_space::{TABLE_BYTES_PER_PROCESS, TABLE_POOL_BYTES};
    let heap = crate::user_heap::RESERVED_BYTES;
    #[cfg(feature = "ported")]
    let exec = crate::exec_memory::RESERVED_BYTES;
    #[cfg(not(feature = "ported"))]
    let exec = 0;
    #[cfg(all(feature = "ported", feature = "large-memory"))]
    let shared = crate::shared_memory::RESERVED_BYTES;
    #[cfg(not(all(feature = "ported", feature = "large-memory")))]
    let shared = 0;
    let (pools, minimum, keep_free) = if cfg!(feature = "cosmic-session") {
        // Keep the measured desktop working sets inside the compact envelope.
        let tables = 24 * TABLE_BYTES_PER_PROCESS;
        ([
            PoolSize::bounded(tables, TABLE_POOL_BYTES, TABLE_BYTES_PER_PROCESS),
            PoolSize::bounded(224 * MIB, heap, MIB),
            PoolSize::bounded(240 * MIB, exec, MIB),
            PoolSize::bounded(12 * MIB, shared, MIB),
        ], tables + (224 + 240 + 12) * MIB, 96 * MIB)
    } else {
        ([TABLE_POOL_BYTES, heap, exec, shared].map(PoolSize::fixed),
            TABLE_POOL_BYTES + heap + exec + shared, 0)
    };
    info.plan_pools(pools, keep_free).unwrap_or_else(|error| {
        panic!("boot memory {error:?}: usable_bytes={} minimum_pool_bytes={minimum} system_reserve_bytes={keep_free}",
            info.free_ram_bytes());
    })
}
/// Actual discovered RAM, including reserved pools, for the CPU0 system snapshot.
pub fn memory_bytes() -> u64 {
    assert_eq!(crate::machine::runtime::cpu_slot(), 0);
    let info = unsafe { (&*core::ptr::addr_of!(BOOT_MEMORY)).as_ref() }
        .expect("OS boot memory initialized");
    info.ram_regions().iter().map(|region| region.len).sum()
}
struct Output;
impl Write for Output {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        crate::try_log(text.as_bytes()).map_err(|_| core::fmt::Error)
    }
}
struct SystemIo;
impl cyxia_ai_runtime::DeviceIo for SystemIo {
    fn uart_write(&mut self, bytes: &[u8]) -> Result<usize, cyxia_ai_runtime::IoError> {
        crate::try_log(bytes).map_err(cyxia_ai_runtime::IoError::from)?;
        Ok(bytes.len())
    }
    fn timer_read(&mut self) -> Result<u64, cyxia_ai_runtime::IoError> {
        Ok(crate::machine::runtime::now_ns())
    }
}

pub fn run(info: &PcBootInfo) -> ! {
    assert_eq!(crate::machine::runtime::cpu_slot(), 0);
    crate::log(b"CYXIA_OS_BOOT architecture=x86_64 profile=os-runtime\n");
    let mut out = Output;
    let plan = plan_user_memory(info);
    let [tables, anonymous, _exec, _shared] = plan.ranges;
    unsafe { core::ptr::addr_of_mut!(BOOT_MEMORY).write(Some(plan.memory)); }
    let objects = crate::user::capacity::configure(plan.percent).expect("boot object limits");
    let _ = writeln!(out, "USER_OBJECT_PROFILE name={} fds={} ofds={} epolls_per_owner={} epolls={} inotify_per_owner={} inotify_instances={}",
        objects.name, objects.fds_per_process, objects.open_descriptions,
        objects.epolls_per_owner, objects.epoll_instances,
        objects.inotify_per_owner, objects.inotify_instances);
    let ram_bytes: u64 = info.ram_regions().iter().map(|r| r.len).sum();
    let _ = writeln!(out, "RAM_DISCOVERED bytes={ram_bytes}");
    for range in plan.ranges.into_iter().filter(|r| r.len != 0) {
        let _ = writeln!(out, "USER_MEMORY_POOL start={:#x} end={:#x} bytes={} backing=BOOTSTRAP",
            range.start.0, range.start.0 + range.len, range.len);
    }
    crate::address_space::init_pc(tables).expect("private user page-table pool");
    crate::user_heap::init_pc(anonymous).expect("user heap pool");
    let _ = writeln!(out, "PROCESS_MEMORY_READY table_base={:#x} table_bytes={} foreground_cpu=0",
                     tables.start.0, tables.len);
    #[cfg(feature = "ported")]
    {
        crate::exec_memory::init_pc(_exec).expect("user executable pool");
        #[cfg(feature = "large-memory")]
        crate::shared_memory::init_pc(_shared, crate::user::capacity::scale(cyxia_posix::shared_memory::OBJECTS, 40, plan.percent))
            .expect("user shared memory pool");
        let profile = crate::exec_memory::PROFILE;
        let layout = profile.layout();
        let _ = writeln!(out, "USER_IMAGE_PROFILE name={} image_base={:#x} image_end={:#x} stack_base={:#x} stack_pages={} exec_pages={} heap_base={:#x} heap_pages={} reserved_exec_bytes={}",
            profile.name(), layout.image_base, layout.image_end, layout.stack_base,
            layout.stack_pages, layout.exec_pool_pages, cyxia_posix::vm::BASE,
            cyxia_posix::vm::PAGE_COUNT, _exec.len);
    }
    let mut devices = unsafe { crate::devices::Devices::discover() }
        .expect("PC PCI discovery");
    let _ = writeln!(out, "PCI_READY virtio={} completion=polling", devices.count());
    crate::clock::init();
    crate::entropy::init_transport(devices.take(4).expect("RNG PCI resources"));
    crate::storage::init_transports(devices.take(2).expect("block PCI resources"));
    #[cfg(feature = "graphics")]
    {
        let display = devices.take(16).expect("GPU PCI resources");
        let keyboard = devices.take(18).expect("input PCI resources");
        let pointer = devices.take(18).expect("input PCI resources");
        crate::graphics::init_transports([display, keyboard, pointer].into_iter().flatten());
    }
    crate::machine::runtime::release_aps(crate::machine::dispatch::worker).expect("OS CPU release");
    let shell = unsafe { &mut *core::ptr::addr_of_mut!(SHELL) };
    shell.runtime_mut().bind_devices(true, true).expect("OS console and timer");
    while crate::storage::recovering() {
        crate::storage::poll(shell, &mut out);
        idle();
    }
    let cpus = crate::machine::runtime::online_cpus().count_ones();
    #[cfg(feature = "graphics")]
    let scanout = crate::graphics::scanout_bytes();
    #[cfg(not(feature = "graphics"))]
    let scanout = 0;
    let _ = writeln!(out, "SYSTEM_CAPACITY schema=1 cpus={} dispatch_aps={} ram_bytes={} free_bytes={} budget_percent={} process_slots={} threads={} threads_per_process={} block_sectors={} scanout_bytes={} ip_sockets=0 process_grant_pages={}",
        cpus, cpus - 1, ram_bytes, plan.free_bytes, plan.percent, crate::address_space::process_slots(),
        crate::user::capacity::thread_limit(), crate::user::capacity::per_process_thread_limit(),
        crate::storage::capacity_sectors(), scanout, cyxia_posix::usermem::POOL_PAGES);
    #[cfg(feature = "full-os")]
    {
        cyxia_posix::runtime_directory::reset_at_boot(shell.fs_mut())
            .expect("private session runtime directory after recovery");
        #[cfg(feature = "cosmic-session")]
        cyxia_posix::runtime_directory::prepare_cosmic(shell.fs_mut())
            .expect("COSMIC config and state watch roots after recovery");
        crate::log(b"SESSION_RUNTIME_READY path=/run/user/0 mode=0700 uid=0\n");
    }
    shell.banner(&mut out).expect("OS console");
    let mut io = SystemIo;
    loop {
        crate::machine::flush_logs(1024).expect("OS console drain");
        for _ in 0..64 {
            // Do not start another verbose command while the previous output
            // is backpressured. A full production process listing fits the
            // reserved 128 KiB stream queue; user memory grants are unrelated.
            if crate::machine::log_pending() > 4096 { break; }
            match crate::machine::try_read() {
                Ok(Some(byte)) => shell.input(byte, &mut out).expect("OS console"),
                Ok(None) => break,
                Err(_) => { shell.input_error(); break; }
            }
        }
        let now = crate::machine::runtime::now_ns() / 1_000_000;
        shell.runtime_mut().tick(now, &mut io).expect("resource service");
        crate::storage::poll(shell, &mut out);
        #[cfg(feature = "graphics")]
        crate::graphics::poll();
        crate::user::poll(shell, &mut out);
        crate::ai::poll(shell, &mut out);
        crate::machine::flush_logs(1024).expect("OS console drain");
        idle();
    }
}
fn idle() {
    crate::machine::runtime::idle_until_while(
        crate::machine::runtime::now_ns().checked_add(1_000_000).expect("clock horizon"),
        || !crate::user::runnable(),
    ).expect("OS deadline");
}
