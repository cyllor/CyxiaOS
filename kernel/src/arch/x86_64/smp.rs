//! Four-CPU mechanism validation. No production task/ownership claims are made.
use super::*;
use arch::apic::LocalApic;
use core::sync::atomic::AtomicBool;
use pc::acpi::CpuTopology;

const CPUS: usize = 4;
const WORK_VECTOR: u8 = 240;
const STOP_VECTOR: u8 = 241;
const WAIT_STEPS: usize = 2000;
const PAGE: u64 = 4096;

#[repr(C, align(4096))]
struct Stacks {
    kernel_guard: [u8; 4096],
    kernel: [u8; 65536],
    trap_guard: [u8; 4096],
    trap: [u8; 32768],
    ist_guard: [u8; 4096],
    ist: [u8; 16384],
}
impl Stacks {
    const EMPTY: Self = Self {
        kernel_guard: [0; 4096],
        kernel: [0; 65536],
        trap_guard: [0; 4096],
        trap: [0; 32768],
        ist_guard: [0; 4096],
        ist: [0; 16384],
    };
}
static mut STACKS: [Stacks; 3] = [const { Stacks::EMPTY }; 3];

#[derive(Clone, Copy)]
struct StackLayout {
    kernel_guard: u64,
    kernel_top: u64,
    trap_guard: u64,
    trap_top: u64,
    ist_guard: u64,
    ist_top: u64,
}
impl StackLayout {
    const EMPTY: Self = Self {
        kernel_guard: 0,
        kernel_top: 0,
        trap_guard: 0,
        trap_top: 0,
        ist_guard: 0,
        ist_top: 0,
    };
}
static mut STACK_LAYOUTS: [StackLayout; CPUS] = [StackLayout::EMPTY; CPUS];
static mut SNAPSHOTS: [arch::interrupts::Snapshot; CPUS] = [arch::interrupts::Snapshot {
    gdt: 0,
    idt: 0,
    tss: 0,
    rsp0: 0,
    ist: 0,
}; CPUS];

struct State {
    request: AtomicU64,
    ack: AtomicU64,
    progress: AtomicU64,
    online: AtomicU64,
    ipi: AtomicU64,
    error: AtomicU64,
}
impl State {
    const fn new() -> Self {
        Self {
            request: AtomicU64::new(1),
            ack: AtomicU64::new(0),
            progress: AtomicU64::new(0),
            online: AtomicU64::new(0),
            ipi: AtomicU64::new(0),
            error: AtomicU64::new(0),
        }
    }
}
static STATES: [State; CPUS] = [const { State::new() }; CPUS];
static READY: AtomicBool = AtomicBool::new(false);
static BSP_ID: AtomicU64 = AtomicU64::new(256);
static APIC_IDS: [AtomicU64; CPUS] = [const { AtomicU64::new(256) }; CPUS];
static LAPIC_BASE: AtomicU64 = AtomicU64::new(0);
static FAILURE: AtomicU64 = AtomicU64::new(0);

// Frozen by BSP only after all APs acknowledge final park generation 6.
#[unsafe(no_mangle)]
pub static mut X86_SMP_EVIDENCE: [u64; 128] = [0; 128];

unsafe extern "C" {
    static __stack_top: u8;
    static __trap_stack_guard: u8;
    static __df_stack_guard: u8;
    static __df_stack_top: u8;
}

fn overlap(a: u64, a_end: u64, b: u64, b_end: u64) -> bool {
    a < b_end && b < a_end
}
unsafe fn physical(address: u64, length: usize) -> &'static [u8] {
    assert!(
        address >= PAGE
            && length > 0
            && address
                .checked_add(length as u64)
                .is_some_and(|end| end <= pc::MAX_PHYSICAL_MEMORY),
        "ACPI physical bounds"
    );
    unsafe { core::slice::from_raw_parts(address as *const u8, length) }
}
unsafe fn table(address: u64) -> &'static [u8] {
    let header = unsafe { physical(address, 36) };
    let length = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;
    assert!(
        (36..=pc::acpi::MAX_TABLE_BYTES).contains(&length),
        "ACPI table length"
    );
    unsafe { physical(address, length) }
}

/// Called before final page tables remove the BIOS data area in page zero.
pub unsafe fn prepare(
    info: &pc::PcBootInfo,
    header_address: u64,
    map_address: u64,
    map_len: usize,
) -> CpuTopology {
    let bsp = arch::apic::initial_id().expect("BSP APIC capability");
    BSP_ID.store(bsp as u64, Ordering::Relaxed);
    let ebda = (unsafe { core::ptr::read_unaligned(0x40e as *const u16) } as u64) << 4;
    let mut root = None;
    let ebda_end = ebda.checked_add(1024).expect("EBDA overflow");
    let ranges = if (PAGE..0xa0000).contains(&ebda) && ebda_end <= 0xa0000 {
        [(ebda, ebda_end), (0xe0000, 0x100000)]
    } else {
        [(0xe0000, 0x100000), (0, 0)]
    };
    for (start, end) in ranges {
        let mut address = (start + 15) & !15;
        while address + 20 <= end {
            let bytes = unsafe { physical(address, 20) };
            if &bytes[..8] == b"RSD PTR " {
                let length = if bytes[15] >= 2 {
                    if address + 36 > end {
                        address += 16;
                        continue;
                    }
                    let extended = unsafe { physical(address, 36) };
                    u32::from_le_bytes(extended[20..24].try_into().unwrap()) as usize
                } else {
                    20
                };
                if (20..=4096).contains(&length) && address + length as u64 <= end {
                    if let Ok(pointer) = pc::acpi::parse_rsdp(unsafe { physical(address, length) })
                    {
                        root = Some(pointer);
                        break;
                    }
                }
            }
            address += 16;
        }
        if root.is_some() {
            break;
        }
    }
    let root = root.expect("ACPI RSDP absent");
    let root_bytes = unsafe { table(root.address) };
    assert_eq!(
        &root_bytes[..4],
        if root.xsdt { b"XSDT" } else { b"RSDT" },
        "ACPI root kind"
    );
    let entries = pc::acpi::parse_root(root_bytes).expect("ACPI root");
    let mut topology = None;
    for i in 0..entries.len() {
        let bytes = unsafe { table(entries.get(i).unwrap()) };
        if &bytes[..4] == b"APIC" {
            assert!(topology.is_none(), "duplicate MADT");
            topology = Some(pc::acpi::parse_madt(bytes, bsp).expect("MADT topology"));
        }
    }
    let topology = topology.expect("MADT absent");
    assert_eq!(topology.count, CPUS, "four enabled CPUs required");
    let low = arch::ap_boot::TRAMPOLINE_PHYSICAL;
    let end = arch::ap_boot::MAILBOX_PHYSICAL + PAGE;
    assert!(
        info.ram_regions()
            .iter()
            .any(|r| r.start.0 <= low && end <= r.start.0 + r.len),
        "AP conventional RAM"
    );
    assert!(
        !overlap(
            low,
            end,
            header_address,
            header_address + pc::MB_INFO_BYTES as u64
        ) && !overlap(low, end, map_address, map_address + map_len as u64)
            && !(ebda != 0 && overlap(low, end, ebda, ebda_end)),
        "AP loader/EBDA collision"
    );
    // The memory parser reserves the entire low MiB from frame allocation.
    unsafe {
        arch::ap_boot::copy_trampoline();
    }
    let layouts = core::ptr::addr_of_mut!(STACK_LAYOUTS).cast::<StackLayout>();
    unsafe {
        layouts.write(StackLayout {
            kernel_guard: core::ptr::addr_of!(__stack_guard_start) as u64,
            kernel_top: core::ptr::addr_of!(__stack_top) as u64,
            trap_guard: core::ptr::addr_of!(__trap_stack_guard) as u64,
            trap_top: core::ptr::addr_of!(__trap_stack_top) as u64,
            ist_guard: core::ptr::addr_of!(__df_stack_guard) as u64,
            ist_top: core::ptr::addr_of!(__df_stack_top) as u64,
        });
        let stacks = core::ptr::addr_of!(STACKS).cast::<Stacks>();
        for slot in 1..CPUS {
            let stack = stacks.add(slot - 1);
            layouts.add(slot).write(StackLayout {
                kernel_guard: core::ptr::addr_of!((*stack).kernel_guard) as u64,
                kernel_top: core::ptr::addr_of!((*stack).kernel) as u64 + 65536,
                trap_guard: core::ptr::addr_of!((*stack).trap_guard) as u64,
                trap_top: core::ptr::addr_of!((*stack).trap) as u64 + 32768,
                ist_guard: core::ptr::addr_of!((*stack).ist_guard) as u64,
                ist_top: core::ptr::addr_of!((*stack).ist) as u64 + 16384,
            });
        }
    }
    for (slot, &id) in topology.apic_ids.iter().enumerate() {
        APIC_IDS[slot].store(id as u64, Ordering::Relaxed);
    }
    LAPIC_BASE.store(topology.lapic_base, Ordering::Relaxed);
    READY.store(true, Ordering::Release);
    topology
}

pub fn guards() -> [(u64, u64); 11] {
    let mut guards = [(0, 0); 11];
    let layouts = unsafe { *core::ptr::addr_of!(STACK_LAYOUTS) };
    guards[0] = (layouts[0].trap_guard, layouts[0].trap_guard + PAGE);
    guards[1] = (layouts[0].ist_guard, layouts[0].ist_guard + PAGE);
    for slot in 1..CPUS {
        let start = 2 + (slot - 1) * 3;
        for (index, guard) in [
            layouts[slot].kernel_guard,
            layouts[slot].trap_guard,
            layouts[slot].ist_guard,
        ]
        .into_iter()
        .enumerate()
        {
            guards[start + index] = (guard, guard + PAGE);
        }
    }
    guards
}
fn slot() -> usize {
    let id = arch::apic::initial_id().unwrap_or(255) as u64;
    APIC_IDS
        .iter()
        .position(|value| value.load(Ordering::Relaxed) == id)
        .unwrap_or(CPUS)
}
fn apic() -> LocalApic {
    // CPU-local registers were initialized before this helper is called.
    unsafe { LocalApic::attach(LAPIC_BASE.load(Ordering::Acquire)) }
}
/// AP fatal paths never borrow the BSP-owned serial device.
pub fn panic_on_ap() -> bool {
    let id = arch::apic::initial_id().unwrap_or(255) as u64;
    if id == BSP_ID.load(Ordering::Relaxed) || !READY.load(Ordering::Acquire) {
        return false;
    }
    let slot = slot();
    if slot < CPUS {
        STATES[slot].error.store(1, Ordering::Release);
    }
    FAILURE.store(1, Ordering::Release);
    true
}
pub fn on_ipi() {
    let slot = slot();
    if slot == 0 || slot >= CPUS {
        FAILURE.store(2, Ordering::Release);
        arch::cpu::halt();
    }
    STATES[slot].ipi.fetch_add(1, Ordering::Release);
    apic().eoi();
}

#[unsafe(no_mangle)]
extern "C" fn x86_secondary_entry(slot: usize, generation: u64) -> ! {
    arch::cpu::disable_interrupts();
    assert!(READY.load(Ordering::Acquire));
    assert!(slot > 0 && slot < CPUS && generation == 1);
    assert_eq!(
        APIC_IDS[slot].load(Ordering::Relaxed),
        arch::apic::initial_id().unwrap() as u64
    );
    let layout = unsafe {
        core::ptr::addr_of!(STACK_LAYOUTS)
            .cast::<StackLayout>()
            .add(slot)
            .read()
    };
    let rsp: u64;
    unsafe {
        core::arch::asm!("mov {},rsp",out(reg)rsp,options(nomem,nostack));
    }
    assert!(rsp > layout.kernel_guard + PAGE && rsp <= layout.kernel_top);
    unsafe {
        arch::interrupts::init_cpu(slot, layout.trap_top, layout.ist_top);
    }
    let controller = unsafe { LocalApic::init(LAPIC_BASE.load(Ordering::Relaxed)) }.unwrap();
    assert_eq!(
        controller.id() as u64,
        APIC_IDS[slot].load(Ordering::Relaxed)
    );
    unsafe {
        core::ptr::addr_of_mut!(SNAPSHOTS)
            .cast::<arch::interrupts::Snapshot>()
            .add(slot)
            .write(arch::interrupts::snapshot(slot));
    }
    let state = &STATES[slot];
    state.ack.store(generation, Ordering::Relaxed);
    state.online.store(generation, Ordering::Release);
    let mut current = generation;
    loop {
        arch::cpu::disable_interrupts();
        let requested = state.request.load(Ordering::Acquire);
        if requested != current {
            assert_eq!(requested, current + 1, "AP command generation");
            current = requested;
            // Scheduler safe point: this mechanism owns no user/DMA/RCU work;
            // local device sources are masked and no old work survives here.
            // In production this ACK must follow the corresponding real drain.
            state.ack.store(current, Ordering::Release);
        }
        if current & 1 == 0 {
            unsafe {
                arch::cpu::enable_and_wait();
            }
        } else {
            unsafe {
                arch::cpu::enable_interrupts();
            }
            state.progress.fetch_add(1, Ordering::Release);
            core::hint::spin_loop();
        }
    }
}

fn wait_for(mut predicate: impl FnMut() -> bool) {
    for _ in 0..WAIT_STEPS {
        assert_eq!(FAILURE.load(Ordering::Acquire), 0, "AP failure");
        assert_eq!(arch::ap_boot::error(), 0, "AP bootstrap failure");
        if predicate() {
            return;
        }
        unsafe { pc::hardware::delay_us(1000) }.expect("AP wait clock");
    }
    panic!("AP synchronization timeout");
}
fn command(controller: LocalApic, slot: usize, generation: u64) {
    let state = &STATES[slot];
    assert_ne!(
        state.ack.load(Ordering::Acquire),
        generation,
        "stale ACK must not match"
    );
    let previous_ipi = state.ipi.load(Ordering::Acquire);
    state.request.store(generation, Ordering::Release);
    controller
        .send_fixed(
            APIC_IDS[slot].load(Ordering::Relaxed) as u8,
            if generation & 1 == 0 {
                STOP_VECTOR
            } else {
                WORK_VECTOR
            },
        )
        .expect("AP command IPI");
    wait_for(|| {
        state.ack.load(Ordering::Acquire) == generation
            && state.ipi.load(Ordering::Acquire) > previous_ipi
    });
}

pub fn run(topology: CpuTopology) {
    log(b"SMP_DISCOVERY_OK");
    unsafe {
        pc::hardware::mask_all_irqs();
    }
    let controller = unsafe { LocalApic::init(topology.lapic_base) }.expect("BSP xAPIC");
    assert_eq!(controller.id(), topology.apic_ids[0]);
    let mut evidence = [0u64; 128];
    evidence[..10].copy_from_slice(&[
        0x003731565f504d53,
        1,
        128,
        4,
        topology.lapic_base,
        arch::ap_boot::TRAMPOLINE_PHYSICAL,
        arch::ap_boot::MAILBOX_PHYSICAL,
        2,
        0,
        topology.apic_ids[0] as u64,
    ]);
    unsafe {
        core::ptr::addr_of_mut!(SNAPSHOTS)
            .cast::<arch::interrupts::Snapshot>()
            .write(arch::interrupts::snapshot(0));
    }
    STATES[0].online.store(1, Ordering::Release);
    for slot in 1..CPUS {
        let layout = unsafe {
            core::ptr::addr_of!(STACK_LAYOUTS)
                .cast::<StackLayout>()
                .add(slot)
                .read()
        };
        unsafe {
            arch::ap_boot::prepare(arch::ap_boot::Mailbox {
                root: arch::cpu::read_cr3(),
                stack: layout.kernel_top,
                entry: x86_secondary_entry as *const () as u64,
                slot: slot as u64,
                apic_id: topology.apic_ids[slot] as u64,
                generation: 1,
                error: 0,
            });
        }
        controller
            .send_init(topology.apic_ids[slot])
            .expect("INIT assert");
        unsafe { pc::hardware::delay_us(10000) }.expect("INIT delay");
        controller
            .send_init_deassert(topology.apic_ids[slot])
            .expect("INIT deassert");
        controller
            .send_startup(topology.apic_ids[slot], arch::ap_boot::TRAMPOLINE_PHYSICAL)
            .expect("SIPI1");
        unsafe { pc::hardware::delay_us(200) }.expect("SIPI delay");
        controller
            .send_startup(topology.apic_ids[slot], arch::ap_boot::TRAMPOLINE_PHYSICAL)
            .expect("SIPI2");
        wait_for(|| STATES[slot].online.load(Ordering::Acquire) == 1);
    }
    log(b"SMP_AP_ONLINE_OK");
    for slot in 1..CPUS {
        let before = STATES[slot].ipi.load(Ordering::Acquire);
        controller
            .send_fixed(topology.apic_ids[slot], WORK_VECTOR)
            .expect("ping IPI");
        wait_for(|| {
            STATES[slot].ipi.load(Ordering::Acquire) > before
                && STATES[slot].progress.load(Ordering::Acquire) > 0
        });
    }
    log(b"SMP_IPI_OK");
    for slot in 1..CPUS {
        let state = &STATES[slot];
        let at = 16 + slot * 28;
        for (stop, resume, start) in [(2, 3, 14), (4, 5, 20)] {
            command(controller, slot, stop);
            let progress = state.progress.load(Ordering::Acquire);
            unsafe { pc::hardware::delay_us(2000) }.expect("stop observation");
            let frozen = state.progress.load(Ordering::Acquire);
            assert!(progress > 0);
            assert_eq!(progress, frozen, "stopped AP made progress");
            evidence[at + start..at + start + 4].copy_from_slice(&[
                stop,
                state.ack.load(Ordering::Acquire),
                progress,
                frozen,
            ]);
            command(controller, slot, resume);
            wait_for(|| state.progress.load(Ordering::Acquire) > frozen);
            evidence[at + start + 4] = resume;
            evidence[at + start + 5] = state.progress.load(Ordering::Acquire);
        }
        command(controller, slot, 6); // freeze evidence after the two accepted rounds.
    }
    log(b"SMP_STOP_RESUME_OK");
    for slot in 0..CPUS {
        let at = 16 + slot * 28;
        let snapshot = unsafe {
            core::ptr::addr_of!(SNAPSHOTS)
                .cast::<arch::interrupts::Snapshot>()
                .add(slot)
                .read()
        };
        let layout = unsafe {
            core::ptr::addr_of!(STACK_LAYOUTS)
                .cast::<StackLayout>()
                .add(slot)
                .read()
        };
        evidence[at..at + 14].copy_from_slice(&[
            slot as u64,
            topology.apic_ids[slot] as u64,
            snapshot.gdt,
            snapshot.idt,
            snapshot.tss,
            snapshot.rsp0,
            snapshot.ist,
            layout.kernel_guard + PAGE,
            layout.kernel_top,
            layout.kernel_guard,
            layout.trap_guard,
            layout.ist_guard,
            STATES[slot].online.load(Ordering::Acquire),
            STATES[slot].ipi.load(Ordering::Acquire),
        ]);
        evidence[at + 26] = STATES[slot].error.load(Ordering::Acquire);
        if slot > 0 {
            assert_eq!(STATES[slot].ack.load(Ordering::Acquire), 6);
            assert!(evidence[at + 13] >= 6);
        }
    }
    unsafe {
        core::ptr::addr_of_mut!(X86_SMP_EVIDENCE).write(evidence);
    }
    use core::fmt::Write;
    for (index, word) in evidence.iter().enumerate() {
        let mut line = EvidenceLine {
            bytes: [0; 64],
            len: 0,
        };
        // Existing BSP markers are one record per transport frame without LF.
        // Keep the entire stream in that form so records cannot concatenate
        // when the independent decoder selects its legacy framing path.
        write!(&mut line, "SMP_V17 {index} {word:016x}").unwrap();
        log(&line.bytes[..line.len]);
    }
    log(b"SMP_V17_OK");
}
struct EvidenceLine {
    bytes: [u8; 64],
    len: usize,
}
impl core::fmt::Write for EvidenceLine {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        let end = self.len.checked_add(text.len()).ok_or(core::fmt::Error)?;
        if end > self.bytes.len() {
            return Err(core::fmt::Error);
        }
        self.bytes[self.len..end].copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}
