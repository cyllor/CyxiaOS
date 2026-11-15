//! Long-running OS service composition on the actual PC board.
//! Shared Shell, resource policy, filesystem, checkpoint and graphics code have
//! one implementation. This entry has no acceptance timeout or A03 campaign.
use core::fmt::Write;
use cyxia_platform_pc::PcBootInfo;

static mut SHELL: cyxia_shell::Shell = cyxia_shell::Shell::new();
static mut BOOT_MEMORY: Option<PcBootInfo> = None;

/// CPU0 foreground reserves boot-backed physical pools before publishing them.
/// The recorded exclusions include firmware, loader, kernel and previous pools.
pub fn reserve_pool(bytes: u64) -> Result<cyxia_contracts::PhysAddr, cyxia_posix::Errno> {
    use cyxia_posix::Errno;
    if crate::machine::runtime::cpu_slot() != 0 { return Err(Errno::Perm); }
    let memory = unsafe { (&mut *core::ptr::addr_of_mut!(BOOT_MEMORY)).as_mut() }
        .ok_or(Errno::Nodev)?;
    memory.reserve_pool(bytes, 0x10_0000).map(|r| r.start).map_err(|_| Errno::Nomem)
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
    unsafe { core::ptr::addr_of_mut!(BOOT_MEMORY).write(Some(*info)); }
    crate::log(b"CYXIA_OS_BOOT architecture=x86_64 profile=os-runtime\n");
    let mut out = Output;
    let ram_bytes: u64 = info.ram_regions().iter().map(|r| r.len).sum();
    let _ = writeln!(out, "RAM_DISCOVERED bytes={ram_bytes}");
    let tables = crate::address_space::init_pc().expect("private user page-table pool");
    crate::user_heap::init_pc().expect("user heap pool");
    let _ = writeln!(out, "PROCESS_MEMORY_READY table_base={:#x} table_bytes={} foreground_cpu=0",
                     tables.0, crate::address_space::TABLE_POOL_BYTES);
    #[cfg(feature = "ported")]
    {
        crate::exec_memory::init_pc().expect("user executable pool");
        crate::shared_memory::init_pc().expect("user shared memory pool");
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
    shell.banner(&mut out).expect("OS console");
    let mut io = SystemIo;
    loop {
        for _ in 0..64 {
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
        idle();
    }
}
fn idle() {
    crate::machine::runtime::idle_until(
        crate::machine::runtime::now_ns().checked_add(1_000_000).expect("clock horizon")
    ).expect("OS deadline");
}
