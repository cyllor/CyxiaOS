//! Formal PC CPU backend. OS policy enters through crate::os; no fixture worker.
use super::*;
use arch::{
    apic::LocalApic,
    space::{Error, KERNEL_BASE, KernelMappings},
};
use core::sync::atomic::AtomicBool;

core::arch::global_asm!(
    include_str!("../../../../crates/arch-x86_64/src/entry_runtime.S"),
    options(att_syntax)
);
const RAM: u64 = 1 << 30;
const TIMER: u8 = 239;
const WAKE: u8 = 240;
const TLB: u8 = 241;
#[repr(C, align(4096))]
struct Stacks {
    guard: [u8; 4096],
    kernel: [u8; 65536],
    trap_guard: [u8; 4096],
    trap: [u8; 32768],
    ist_guard: [u8; 4096],
    ist: [u8; 16384],
}
impl Stacks {
    const EMPTY: Self = Self {
        guard: [0; 4096],
        kernel: [0; 65536],
        trap_guard: [0; 4096],
        trap: [0; 32768],
        ist_guard: [0; 4096],
        ist: [0; 16384],
    };
}
static mut STACKS: [Stacks; 3] = [const { Stacks::EMPTY }; 3];
static APIC_IDS: [AtomicU64; 4] = [const { AtomicU64::new(256) }; 4];
static LAPIC: AtomicU64 = AtomicU64::new(0);
static HPET: AtomicU64 = AtomicU64::new(0);
static HPET_PERIOD: AtomicU64 = AtomicU64::new(0);
static TIMER_HZ: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
static ONLINE: AtomicU64 = AtomicU64::new(0);
static ENTRY: AtomicU64 = AtomicU64::new(0);
static KERNEL_ROOT: AtomicU64 = AtomicU64::new(0);
static mut KERNEL_MAPPINGS: Option<KernelMappings> = None;
static BSP_ID: AtomicU64 = AtomicU64::new(256);
static FAILURE: AtomicU64 = AtomicU64::new(0);
static IRQ_HANDLER: AtomicU64 = AtomicU64::new(0);
static TLB_EPOCH: AtomicU64 = AtomicU64::new(0);
static TLB_ACK: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
static TLB_GATE: AtomicBool = AtomicBool::new(false);
static SEALED: [AtomicU64; 4096] = [const { AtomicU64::new(0) }; 4096];
// Three 20-bit counts: all user mappings, writable aliases, executable aliases.
static USER_ALIASES: [AtomicU64; 262144] = [const { AtomicU64::new(0) }; 262144];
static ALIAS_GATE: AtomicBool = AtomicBool::new(false);
struct AliasGuard;
impl Drop for AliasGuard {
    fn drop(&mut self) {
        ALIAS_GATE.store(false, Ordering::Release);
    }
}
fn alias_guard() -> Result<AliasGuard, Error> {
    ALIAS_GATE
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| Error::Active)?;
    Ok(AliasGuard)
}
unsafe extern "C" {
    static __kernel_phys_start: u8;
    static __kernel_phys_end: u8;
    static __text_start: u8;
    static __text_end: u8;
    static __rodata_start: u8;
    static __rodata_end: u8;
    static __stack_guard_start: u8;
    static __stack_guard_end: u8;
    static __stack_top: u8;
    static __trap_stack_guard: u8;
    static __trap_stack_top: u8;
    static __df_stack_guard: u8;
    static __df_stack_top: u8;
}
fn pa(pointer: u64) -> u64 {
    pointer
        .checked_sub(KERNEL_BASE)
        .expect("kernel physical pointer")
}
pub fn kernel_phys(address: usize, length: usize) -> Result<u64, Error> {
    let physical = (address as u64)
        .checked_sub(KERNEL_BASE)
        .ok_or(Error::Address)?;
    if length == 0
        || physical == 0
        || physical
            .checked_add(length as u64)
            .is_none_or(|end| end > RAM)
    {
        return Err(Error::Address);
    }
    Ok(physical)
}
pub fn kernel_va(physical: u64, length: usize) -> Result<usize, Error> {
    if length == 0
        || physical == 0
        || physical
            .checked_add(length as u64)
            .is_none_or(|end| end > RAM)
    {
        return Err(Error::Address);
    }
    Ok((KERNEL_BASE + physical) as usize)
}
pub fn map_device(base: u64, length: u64) -> Result<usize, Error> {
    if length == 0 || base < 0xc0000000 || base.checked_add(length).is_none_or(|end| end > 1 << 32)
    {
        return Err(Error::Address);
    }
    Ok((KERNEL_BASE + base) as usize)
}
pub fn kernel_mappings() -> &'static KernelMappings {
    unsafe { (&*core::ptr::addr_of!(KERNEL_MAPPINGS)).as_ref() }.expect("kernel mappings ready")
}
pub fn cpu_slot() -> usize {
    arch::user::cpu_slot()
}
pub fn online_cpus() -> u64 {
    ONLINE.load(Ordering::Acquire)
}
fn local_apic() -> LocalApic {
    unsafe { LocalApic::attach(KERNEL_BASE + LAPIC.load(Ordering::Acquire)) }
}
fn lapic_write(register: u64, value: u32) {
    unsafe {
        core::ptr::write_volatile(
            (KERNEL_BASE + LAPIC.load(Ordering::Acquire) + register) as *mut u32,
            value,
        );
    }
}
fn lapic_read(register: u64) -> u32 {
    unsafe {
        core::ptr::read_volatile(
            (KERNEL_BASE + LAPIC.load(Ordering::Acquire) + register) as *const u32,
        )
    }
}
pub fn now_ns() -> u64 {
    let base = HPET.load(Ordering::Acquire);
    let period = HPET_PERIOD.load(Ordering::Acquire);
    assert!(base != 0 && period != 0, "monotonic clock unavailable");
    let counter = unsafe { core::ptr::read_volatile((KERNEL_BASE + base + 0xf0) as *const u64) };
    u64::try_from(u128::from(counter) * u128::from(period) / 1_000_000).expect("monotonic overflow")
}
pub fn monotonic_resolution_ns() -> u64 {
    let period = HPET_PERIOD.load(Ordering::Acquire);
    assert!(period > 0, "monotonic clock unavailable");
    period.div_ceil(1_000_000)
}
pub fn arm_deadline(deadline_ns: u64) -> Result<(), Error> {
    let hz = TIMER_HZ
        .get(cpu_slot())
        .ok_or(Error::Address)?
        .load(Ordering::Acquire);
    if hz == 0 || deadline_ns == 0 {
        return Err(Error::Unsupported);
    }
    let delta = deadline_ns.saturating_sub(now_ns());
    let count = (u128::from(delta) * u128::from(hz))
        .div_ceil(1_000_000_000)
        .clamp(1, u32::MAX as u128) as u32;
    lapic_write(0x320, u32::from(TIMER));
    lapic_write(0x380, count);
    Ok(())
}
#[unsafe(no_mangle)]
extern "C" fn x86_runtime_arm_deadline(deadline: u64) -> u64 {
    u64::from(arm_deadline(deadline).is_err())
}
pub fn cancel_timer() {
    lapic_write(0x380, 0);
}
pub fn wake(slot: usize) -> Result<(), Error> {
    let id = APIC_IDS
        .get(slot)
        .ok_or(Error::Address)?
        .load(Ordering::Acquire);
    if id >= 255 || ONLINE.load(Ordering::Acquire) & (1 << slot) == 0 {
        return Err(Error::Identity);
    }
    local_apic()
        .send_fixed(id as u8, WAKE)
        .map_err(|_| Error::Timeout)
}
pub fn register_irq(handler: fn(u8) -> bool) -> Result<(), Error> {
    IRQ_HANDLER
        .compare_exchange(
            0,
            handler as usize as u64,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .map(|_| ())
        .map_err(|_| Error::Conflict)
}
pub fn release_aps(entry: extern "C" fn(usize) -> !) -> Result<(), Error> {
    if cpu_slot() != 0 || online_cpus() != 15 {
        return Err(Error::Identity);
    }
    ENTRY
        .compare_exchange(
            0,
            entry as usize as u64,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .map_err(|_| Error::Conflict)?;
    for slot in 1..4 {
        wake(slot)?;
    }
    Ok(())
}
pub fn idle() {
    // An unconditional idle is appropriate only when the caller has no work
    // predicate. A scheduler should use idle_while to close its wake race.
    arch::cpu::disable_interrupts();
    unsafe {
        arch::cpu::enable_and_wait();
    }
}
/// Check the local scheduler's sleep predicate with IF clear. A remote producer
/// publishes its queue entry before sending WAKE; a pending IRQ then wakes the
/// indivisible STI/HLT sequence instead of disappearing before HLT.
pub fn idle_while(should_sleep: impl FnOnce() -> bool) {
    arch::cpu::disable_interrupts();
    if should_sleep() {
        unsafe {
            arch::cpu::enable_and_wait();
        }
    } else {
        unsafe {
            arch::cpu::enable_interrupts();
        }
    }
}
/// Atomically arm the one-shot wake and enter an interruptible idle. Arming with
/// IF already enabled and later executing HLT can consume the only timer IRQ
/// between those operations and sleep forever.
pub fn idle_until(deadline_ns: u64) -> Result<(), Error> {
    arch::cpu::disable_interrupts();
    if deadline_ns <= now_ns() {
        unsafe {
            arch::cpu::enable_interrupts();
        }
        return Ok(());
    }
    if let Err(error) = arm_deadline(deadline_ns) {
        unsafe {
            arch::cpu::enable_interrupts();
        }
        return Err(error);
    }
    unsafe {
        arch::cpu::enable_and_wait();
    }
    Ok(())
}
pub fn failure() -> u64 {
    FAILURE.load(Ordering::Acquire)
}
pub(super) fn panic_on_ap() -> bool {
    let bsp = BSP_ID.load(Ordering::Relaxed);
    if bsp >= 255 || arch::apic::initial_id().unwrap_or(255) as u64 == bsp {
        return false;
    }
    FAILURE.store(1, Ordering::Release);
    true
}

fn initialize_clock() {
    let base = KERNEL_BASE + HPET.load(Ordering::Acquire);
    let capabilities = unsafe { core::ptr::read_volatile(base as *const u64) };
    let period = capabilities >> 32;
    assert!(
        capabilities & (1 << 13) != 0 && (1..=100_000_000).contains(&period),
        "HPET 64bit clock"
    );
    unsafe {
        let config = (base + 0x10) as *mut u64;
        let old = config.read_volatile();
        config.write_volatile(old & !3);
        core::ptr::write_volatile((base + 0xf0) as *mut u64, 0);
        config.write_volatile((old & !3) | 1);
    }
    HPET_PERIOD.store(period, Ordering::Release);
}
fn initialize_timer(slot: usize) {
    lapic_write(0x320, (1 << 16) | u32::from(TIMER));
    lapic_write(0x3e0, 3);
    lapic_write(0x380, u32::MAX);
    let start = now_ns();
    let target = start + 10_000_000;
    for _ in 0..100_000_000 {
        if now_ns() >= target {
            break;
        }
        core::hint::spin_loop();
    }
    let elapsed = now_ns().checked_sub(start).expect("HPET monotonic");
    let ticks = u32::MAX - lapic_read(0x390);
    lapic_write(0x380, 0);
    assert!(elapsed >= 10_000_000 && ticks > 0, "APIC timer calibration");
    let hz = (u128::from(ticks) * 1_000_000_000 / u128::from(elapsed)) as u64;
    assert!(hz > 0);
    TIMER_HZ[slot].store(hz, Ordering::Release);
    lapic_write(0x320, u32::from(TIMER));
}
fn wait_for(mut predicate: impl FnMut() -> bool) {
    let end = now_ns().checked_add(2_000_000_000).unwrap();
    while !predicate() {
        assert_eq!(failure(), 0, "AP failure");
        assert_eq!(arch::ap_boot::error(), 0, "AP bootstrap");
        assert!(now_ns() < end, "AP deadline");
        core::hint::spin_loop();
    }
}
fn stack(slot: usize) -> (u64, u64, u64) {
    if slot == 0 {
        return (
            core::ptr::addr_of!(__stack_top) as u64,
            core::ptr::addr_of!(__trap_stack_top) as u64,
            core::ptr::addr_of!(__df_stack_top) as u64,
        );
    }
    let stacks = unsafe { core::ptr::addr_of!(STACKS).cast::<Stacks>().add(slot - 1) };
    unsafe {
        (
            core::ptr::addr_of!((*stacks).kernel) as u64 + 65536,
            core::ptr::addr_of!((*stacks).trap) as u64 + 32768,
            core::ptr::addr_of!((*stacks).ist) as u64 + 16384,
        )
    }
}
fn guard_ranges() -> [(u64, u64); 12] {
    let mut out = [(0, 0); 12];
    for (index, address) in [
        core::ptr::addr_of!(__stack_guard_start) as u64,
        core::ptr::addr_of!(__trap_stack_guard) as u64,
        core::ptr::addr_of!(__df_stack_guard) as u64,
    ]
    .into_iter()
    .enumerate()
    {
        out[index] = (pa(address), pa(address) + 4096);
    }
    for slot in 1..4 {
        let stacks = unsafe { core::ptr::addr_of!(STACKS).cast::<Stacks>().add(slot - 1) };
        let addresses = unsafe {
            [
                core::ptr::addr_of!((*stacks).guard) as u64,
                core::ptr::addr_of!((*stacks).trap_guard) as u64,
                core::ptr::addr_of!((*stacks).ist_guard) as u64,
            ]
        };
        for (index, address) in addresses.into_iter().enumerate() {
            out[slot * 3 + index] = (pa(address), pa(address) + 4096);
        }
    }
    out
}
unsafe fn physical(address: u64, length: usize) -> &'static [u8] {
    assert!(
        address >= 4096
            && length > 0
            && address
                .checked_add(length as u64)
                .is_some_and(|end| end <= RAM),
        "firmware bounds"
    );
    unsafe { core::slice::from_raw_parts((KERNEL_BASE + address) as *const u8, length) }
}
unsafe fn table(address: u64) -> &'static [u8] {
    let h = unsafe { physical(address, 36) };
    let length = u32::from_le_bytes(h[4..8].try_into().unwrap()) as usize;
    assert!((36..=pc::acpi::MAX_TABLE_BYTES).contains(&length));
    unsafe { physical(address, length) }
}
unsafe fn firmware() -> pc::acpi::CpuTopology {
    let ebda =
        (unsafe { core::ptr::read_unaligned((KERNEL_BASE + 0x40e) as *const u16) } as u64) << 4;
    let mut root = None;
    for (start, end) in [
        (ebda, ebda.saturating_add(1024).min(0xa0000)),
        (0xe0000, 0x100000),
    ] {
        if start < 4096 || start >= end {
            continue;
        }
        for address in (((start + 15) & !15)..end.saturating_sub(35)).step_by(16) {
            let prefix = unsafe { physical(address, 36) };
            if &prefix[..8] != b"RSD PTR " {
                continue;
            }
            let length = if prefix[15] >= 2 {
                u32::from_le_bytes(prefix[20..24].try_into().unwrap()) as usize
            } else {
                20
            };
            if !(20..=4096).contains(&length) || address + length as u64 > end {
                continue;
            }
            if let Ok(value) = pc::acpi::parse_rsdp(unsafe { physical(address, length) }) {
                root = Some(value);
                break;
            }
        }
        if root.is_some() {
            break;
        }
    }
    let root = root.expect("ACPI RSDP");
    let bytes = unsafe { table(root.address) };
    let entries = pc::acpi::parse_root(bytes).expect("ACPI root");
    let mut topology = None;
    let mut hpet = None;
    for i in 0..entries.len() {
        let bytes = unsafe { table(entries.get(i).unwrap()) };
        match &bytes[..4] {
            b"APIC" => {
                assert!(topology.is_none());
                topology = Some(
                    pc::acpi::parse_madt(bytes, BSP_ID.load(Ordering::Relaxed) as u8)
                        .expect("MADT"),
                );
            }
            b"HPET" => {
                assert!(
                    hpet.is_none()
                        && bytes.len() >= 56
                        && bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b)) == 0
                );
                assert_eq!(bytes[40], 0, "HPET memory GAS");
                hpet = Some(u64::from_le_bytes(bytes[44..52].try_into().unwrap()));
            }
            _ => {}
        }
    }
    let hpet = hpet.expect("HPET absent");
    map_device(hpet, 4096).expect("HPET MMIO");
    HPET.store(hpet, Ordering::Release);
    let topology = topology.expect("MADT absent");
    assert_eq!(topology.count, 4);
    topology
}

#[unsafe(no_mangle)]
extern "C" fn x86_runtime_boot_entry(magic: u32, info_pa: u32) -> ! {
    arch::cpu::disable_interrupts();
    unsafe {
        super::console::init();
    }
    BSP_ID.store(
        arch::apic::initial_id().expect("APIC") as u64,
        Ordering::Relaxed,
    );
    let info_address = u64::from(info_pa);
    let header = unsafe { physical(info_address, pc::MB_INFO_BYTES) };
    let (map_address, map_len) =
        pc::memory_map_location_with_limit(header, RAM).expect("Multiboot map");
    let map = unsafe { physical(map_address, map_len) };
    let info = pc::parse_multiboot_with_limit(
        magic,
        header,
        info_address,
        map,
        map_address,
        core::ptr::addr_of!(__kernel_phys_start) as u64,
        core::ptr::addr_of!(__kernel_phys_end) as u64,
        RAM,
    )
    .expect("PC boot");
    let topology = unsafe { firmware() };
    assert!(
        info.ram_regions()
            .iter()
            .any(|r| r.start.0 <= 0x7000 && 0x9000 <= r.start.0 + r.len),
        "AP low RAM"
    );
    assert!(
        !(0x7000..0x9000).contains(&info_address)
            && !(map_address < 0x9000 && 0x7000 < map_address + map_len as u64)
    );
    unsafe {
        arch::ap_boot::copy_trampoline();
    }
    let guards = guard_ranges();
    let root = unsafe {
        arch::kernel_space::install(arch::kernel_space::KernelLayout {
            text: (
                pa(core::ptr::addr_of!(__text_start) as u64),
                pa(core::ptr::addr_of!(__text_end) as u64),
            ),
            rodata: (
                pa(core::ptr::addr_of!(__rodata_start) as u64),
                pa(core::ptr::addr_of!(__rodata_end) as u64),
            ),
            guards: &guards,
            ram_bytes: RAM,
        })
    }
    .expect("high kernel tables");
    unsafe {
        core::ptr::addr_of_mut!(KERNEL_MAPPINGS).write(Some(
            arch::kernel_space::mappings(RAM).expect("kernel mappings"),
        ));
    }
    KERNEL_ROOT.store(root, Ordering::Release);
    LAPIC.store(topology.lapic_base, Ordering::Release);
    for (slot, &id) in topology.apic_ids.iter().enumerate() {
        APIC_IDS[slot].store(id as u64, Ordering::Relaxed);
    }
    let (_, trap, ist) = stack(0);
    unsafe {
        arch::interrupts::init_cpu(0, trap, ist);
        arch::user::init_runtime_cpu(0, root, trap).expect("BSP process backend");
        pc::hardware::mask_all_irqs();
        LocalApic::init_mapped(topology.lapic_base, KERNEL_BASE + topology.lapic_base)
            .expect("BSP LAPIC");
    }
    initialize_clock();
    initialize_timer(0);
    ONLINE.store(1, Ordering::Release);
    for slot in 1..4 {
        unsafe {
            arch::ap_boot::prepare(arch::ap_boot::Mailbox {
                root,
                stack: stack(slot).0,
                entry: x86_runtime_secondary as *const () as u64,
                slot: slot as u64,
                apic_id: topology.apic_ids[slot] as u64,
                generation: 1,
                error: 0,
            });
        }
        let apic = local_apic();
        apic.send_init(topology.apic_ids[slot]).unwrap();
        unsafe { pc::hardware::delay_us(10000) }.unwrap();
        apic.send_init_deassert(topology.apic_ids[slot]).unwrap();
        apic.send_startup(topology.apic_ids[slot], 0x7000).unwrap();
        unsafe { pc::hardware::delay_us(200) }.unwrap();
        apic.send_startup(topology.apic_ids[slot], 0x7000).unwrap();
        wait_for(|| ONLINE.load(Ordering::Acquire) & (1 << slot) != 0);
    }
    log(b"X86_OS_CPU_READY\n");
    crate::os::run(&info)
}
#[unsafe(no_mangle)]
extern "C" fn x86_runtime_secondary(slot: usize, generation: u64) -> ! {
    arch::cpu::disable_interrupts();
    assert!(slot > 0 && slot < 4 && generation == 1);
    assert_eq!(
        arch::apic::initial_id().unwrap() as u64,
        APIC_IDS[slot].load(Ordering::Acquire)
    );
    let root = KERNEL_ROOT.load(Ordering::Acquire);
    let (_, trap, ist) = stack(slot);
    unsafe {
        arch::interrupts::init_cpu(slot, trap, ist);
        arch::user::init_runtime_cpu(slot, root, trap).unwrap();
        LocalApic::init_mapped(
            LAPIC.load(Ordering::Acquire),
            KERNEL_BASE + LAPIC.load(Ordering::Relaxed),
        )
        .unwrap();
    }
    initialize_timer(slot);
    ONLINE.fetch_or(1 << slot, Ordering::Release);
    loop {
        arch::cpu::disable_interrupts();
        let entry = ENTRY.load(Ordering::Acquire);
        if entry != 0 {
            let entry: extern "C" fn(usize) -> ! = unsafe { core::mem::transmute(entry as usize) };
            entry(slot);
        }
        unsafe {
            arch::cpu::enable_and_wait();
        }
    }
}

#[unsafe(no_mangle)]
extern "C" fn x86_trap(frame: &mut TrapFrame) -> u64 {
    let mut preempt = None;
    if let Some(interrupt) = frame.local_interrupt() {
        match frame.vector {
            239 => cancel_timer(),
            241 => {
                arch::trap::flush_tlb_request(&TLB_EPOCH, &TLB_ACK[cpu_slot()], || unsafe {
                    let root = arch::cpu::read_cr3();
                    core::arch::asm!("mov cr3,{}",in(reg)root,options(nostack));
                });
            }
            _ => {}
        }
        if interrupt.eoi {
            local_apic().eoi();
        }
        preempt = Some(interrupt.preemption);
    } else {
        match frame.vector {
            vector if vector >= 32 && vector != 128 && vector != 256 => {
                let handler = IRQ_HANDLER.load(Ordering::Acquire);
                assert!(handler != 0, "unregistered IRQ");
                let handler: fn(u8) -> bool = unsafe { core::mem::transmute(handler as usize) };
                assert!(handler(vector as u8), "unhandled IRQ");
                local_apic().eoi();
                preempt = Some(arch::user::PreemptReason::Wake);
            }
            _ => {}
        }
    }
    if frame.from_user() {
        arch::user::capture(frame, preempt).expect("user trap capture");
        1
    } else if preempt.is_some() {
        0
    } else {
        panic!(
            "kernel trap {} at {:x} cr2 {:x}",
            frame.vector,
            frame.rip,
            arch::cpu::read_cr2()
        );
    }
}

pub fn synchronize_tlb() -> Result<(), Error> {
    if TLB_GATE
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(Error::Active);
    }
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            TLB_GATE.store(false, Ordering::Release);
        }
    }
    let _guard = Guard;
    let epoch = TLB_EPOCH.fetch_add(1, Ordering::AcqRel) + 1;
    let slot = cpu_slot();
    let root = arch::cpu::read_cr3();
    unsafe {
        core::arch::asm!("mov cr3,{}",in(reg)root,options(nostack));
    }
    TLB_ACK[slot].store(epoch, Ordering::Release);
    let online = online_cpus();
    for cpu in 0..4 {
        if cpu != slot && online & (1 << cpu) != 0 {
            local_apic()
                .send_fixed(APIC_IDS[cpu].load(Ordering::Relaxed) as u8, TLB)
                .map_err(|_| Error::Timeout)?;
        }
    }
    let end = now_ns().checked_add(100_000_000).ok_or(Error::Timeout)?;
    while (0..4)
        .any(|cpu| online & (1 << cpu) != 0 && TLB_ACK[cpu].load(Ordering::Acquire) != epoch)
    {
        if now_ns() >= end {
            return Err(Error::Timeout);
        }
        core::hint::spin_loop();
    }
    Ok(())
}
#[unsafe(no_mangle)]
extern "C" fn x86_runtime_code_sealed(physical: u64) -> bool {
    physical < RAM
        && SEALED[(physical / 4096 / 64) as usize].load(Ordering::Acquire)
            & (1 << (physical / 4096 % 64))
            != 0
}
pub fn is_user_code_sealed(physical: u64) -> bool {
    x86_runtime_code_sealed(physical)
}
#[unsafe(no_mangle)]
extern "C" fn x86_runtime_mapping_change(physical: u64, old: u64, new: u64) -> bool {
    if physical >= RAM || physical % 4096 != 0 {
        return false;
    }
    let Ok(_guard) = alias_guard() else {
        return false;
    };
    let sealed = x86_runtime_code_sealed(physical);
    if new & 4 != 0 && !sealed || new & 2 != 0 && sealed {
        return false;
    }
    let counter = &USER_ALIASES[(physical / 4096) as usize];
    let value = counter.load(Ordering::Acquire);
    let mut updated = 0;
    for (flag, shift) in [(1, 0), (2, 20), (4, 40)] {
        let current = (value >> shift) & 0xfffff;
        let Some(next) = current
            .checked_sub(u64::from(old & flag != 0))
            .and_then(|v| v.checked_add(u64::from(new & flag != 0)))
        else {
            return false;
        };
        if next > 0xfffff {
            return false;
        }
        updated |= next << shift;
    }
    counter.store(updated, Ordering::Release);
    true
}
/// Caller has exclusive allocation ownership and has stopped every context and
/// device/reference that could mutate these frames. A timeout keeps them pinned.
pub unsafe fn seal_user_code(physical: u64, length: usize) -> Result<(), Error> {
    if length == 0
        || physical % 4096 != 0
        || length % 4096 != 0
        || physical < pa(core::ptr::addr_of!(__rodata_end) as u64)
        || physical
            .checked_add(length as u64)
            .is_none_or(|end| end > RAM)
    {
        return Err(Error::Address);
    }
    let _guard = alias_guard()?;
    for page in (physical..physical + length as u64).step_by(4096) {
        if (USER_ALIASES[(page / 4096) as usize].load(Ordering::Acquire) >> 20) & 0xfffff != 0 {
            return Err(Error::Permissions);
        }
    }
    for page in (physical..physical + length as u64).step_by(4096) {
        unsafe {
            arch::kernel_space::set_direct_permissions(page, false)?;
        }
    }
    synchronize_tlb()?;
    for page in (physical..physical + length as u64).step_by(4096) {
        SEALED[(page / 4096 / 64) as usize].fetch_or(1 << (page / 4096 % 64), Ordering::Release);
    }
    Ok(())
}
/// # Safety
/// All process mappings/contexts, shared loans and DMA owners of these frames
/// were retired, and the caller retains custody until this flush completes.
pub unsafe fn unseal_user_code(physical: u64, length: usize) -> Result<(), Error> {
    if length == 0
        || physical % 4096 != 0
        || length % 4096 != 0
        || physical
            .checked_add(length as u64)
            .is_none_or(|end| end > RAM)
    {
        return Err(Error::Address);
    }
    let _guard = alias_guard()?;
    for page in (physical..physical + length as u64).step_by(4096) {
        if USER_ALIASES[(page / 4096) as usize].load(Ordering::Acquire) != 0 {
            return Err(Error::Active);
        }
    }
    for page in (physical..physical + length as u64).step_by(4096) {
        if !x86_runtime_code_sealed(page) {
            return Err(Error::Permissions);
        }
        SEALED[(page / 4096 / 64) as usize]
            .fetch_and(!(1 << (page / 4096 % 64)), Ordering::Release);
    }
    synchronize_tlb()?;
    for page in (physical..physical + length as u64).step_by(4096) {
        unsafe {
            arch::kernel_space::set_direct_permissions(page, true)?;
        }
    }
    synchronize_tlb()
}
