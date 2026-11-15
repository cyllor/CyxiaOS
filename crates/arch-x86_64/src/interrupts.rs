//! Per-CPU exception tables with private TSS stack switching and double-fault IST.
use crate::descriptors::{Gate, KERNEL_DATA, TSS_SELECTOR, tss_descriptor};
pub use crate::trap::TrapFrame;

core::arch::global_asm!(include_str!("trap_stubs.S"), options(att_syntax));
#[cfg(not(feature = "runtime"))]
core::arch::global_asm!(include_str!("traps.S"), options(att_syntax));
#[cfg(feature = "runtime")]
core::arch::global_asm!(include_str!("runtime_traps.S"), options(att_syntax));

#[repr(C, packed)]
struct DescriptorPointer {
    limit: u16,
    base: u64,
}
#[repr(C, packed)]
struct Tss {
    reserved0: u32,
    rsp: [u64; 3],
    reserved1: u64,
    ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    iomap: u16,
}
pub const MAX_CPUS: usize = 4;
#[repr(C, align(16))]
struct Tables {
    tss: Tss,
    gdt: [u64; 7],
    idt: [Gate; 256],
}
impl Tables {
    const EMPTY: Self = Self {
        tss: Tss {
            reserved0: 0,
            rsp: [0; 3],
            reserved1: 0,
            ist: [0; 7],
            reserved2: 0,
            reserved3: 0,
            iomap: 104,
        },
        gdt: [0; 7],
        idt: [Gate::EMPTY; 256],
    };
}
static mut TABLES: [Tables; MAX_CPUS] = [const { Tables::EMPTY }; MAX_CPUS];

#[derive(Clone, Copy)]
pub struct Snapshot {
    pub gdt: u64,
    pub idt: u64,
    pub tss: u64,
    pub rsp0: u64,
    pub ist: u64,
}
/// Read the actual local table registers and the selected private TSS.
pub fn snapshot(slot: usize) -> Snapshot {
    assert!(slot < MAX_CPUS);
    let mut gdtr = DescriptorPointer { limit: 0, base: 0 };
    let mut idtr = DescriptorPointer { limit: 0, base: 0 };
    let selector: u16;
    unsafe {
        core::arch::asm!("sgdt [{}]", "sidt [{}]", "str {selector:x}",
        in(reg) &mut gdtr,in(reg) &mut idtr,selector=out(reg)selector,options(nostack));
    }
    assert_eq!(selector, TSS_SELECTOR);
    let tables = core::ptr::addr_of!(TABLES).cast::<Tables>();
    let tss = unsafe { core::ptr::addr_of!((*tables.add(slot)).tss) };
    let actual_gdt = gdtr.base;
    let actual_idt = idtr.base;
    assert_eq!(
        actual_gdt,
        unsafe { core::ptr::addr_of!((*tables.add(slot)).gdt) } as u64
    );
    assert_eq!(
        actual_idt,
        unsafe { core::ptr::addr_of!((*tables.add(slot)).idt) } as u64
    );
    Snapshot {
        gdt: gdtr.base,
        idt: idtr.base,
        tss: tss as u64,
        rsp0: unsafe {
            core::ptr::addr_of!((*tss).rsp)
                .cast::<u64>()
                .read_unaligned()
        },
        ist: unsafe {
            core::ptr::addr_of!((*tss).ist)
                .cast::<u64>()
                .read_unaligned()
        },
    }
}
unsafe extern "C" {
    static x86_isr_table: [u64; 48];
    fn x86_isr_128();
    fn x86_isr_239();
    fn x86_isr_240();
    fn x86_isr_241();
    fn x86_isr_255();
}

/// # Safety
/// This CPU exclusively owns `slot`, initialized exactly once, interrupts
/// disabled, no live user contexts. `kernel_stack_top`
/// must be the aligned top of a reserved supervisor RW/NX stack with room for
/// trap handlers, distinct from the suspended kernel caller's stack. All tables
/// and the double-fault stack must remain mapped.
pub unsafe fn init_cpu(slot: usize, kernel_stack_top: u64, double_fault_top: u64) {
    assert!(slot < MAX_CPUS);
    assert!(double_fault_top > 4096 && double_fault_top.is_multiple_of(16));
    assert!(kernel_stack_top > 4096 && kernel_stack_top.is_multiple_of(16));
    assert_eq!(core::mem::size_of::<TrapFrame>(), 176);
    assert_eq!(core::mem::size_of::<Tss>(), 104);
    let tables = core::ptr::addr_of_mut!(TABLES).cast::<Tables>();
    let (tss, gdt, idt) = unsafe {
        let cpu = tables.add(slot);
        (
            core::ptr::addr_of_mut!((*cpu).tss),
            core::ptr::addr_of_mut!((*cpu).gdt),
            core::ptr::addr_of_mut!((*cpu).idt),
        )
    };
    let [low, high] = tss_descriptor(tss as u64, core::mem::size_of::<Tss>() as u32 - 1).unwrap();
    unsafe {
        tss.write(Tss {
            reserved0: 0,
            rsp: [kernel_stack_top, 0, 0],
            reserved1: 0,
            ist: [double_fault_top, 0, 0, 0, 0, 0, 0],
            reserved2: 0,
            reserved3: 0,
            iomap: core::mem::size_of::<Tss>() as u16,
        });
        gdt.write([
            0,
            0x00af_9a00_0000_ffff,
            0x00cf_9200_0000_ffff,
            0x00cf_f200_0000_ffff,
            0x00af_fa00_0000_ffff,
            low,
            high,
        ]);
        for (vector, gate) in (&mut *idt).iter_mut().enumerate() {
            let address = if vector < 48 {
                x86_isr_table[vector]
            } else if vector == 128 {
                x86_isr_128 as *const () as u64
            } else if vector == 239 {
                x86_isr_239 as *const () as u64
            } else if vector == 240 {
                x86_isr_240 as *const () as u64
            } else if vector == 241 {
                x86_isr_241 as *const () as u64
            } else {
                x86_isr_255 as *const () as u64
            };
            *gate = Gate::interrupt(
                address,
                if vector == 128 { 3 } else { 0 },
                if vector == 8 { 1 } else { 0 },
            )
            .unwrap();
        }
        let gdtr = DescriptorPointer {
            limit: (core::mem::size_of::<[u64; 7]>() - 1) as u16,
            base: gdt as u64,
        };
        let idtr = DescriptorPointer {
            limit: (core::mem::size_of::<[Gate; 256]>() - 1) as u16,
            base: idt as u64,
        };
        core::arch::asm!(
            "lgdt [{gdtr}]",
            "push 8",
            "lea rax, [rip + 2f]",
            "push rax",
            "retfq",
            "2:",
            "mov ax, {data:x}",
            "mov ds, ax", "mov es, ax", "mov ss, ax",
            "xor eax, eax", "mov fs, ax", "mov gs, ax",
            "mov ax, {tss:x}", "ltr ax",
            "lidt [{idtr}]",
            gdtr = in(reg) &gdtr, idtr = in(reg) &idtr,
            data = in(reg) KERNEL_DATA, tss = in(reg) TSS_SELECTOR,
            out("rax") _,
        );
    }
}
