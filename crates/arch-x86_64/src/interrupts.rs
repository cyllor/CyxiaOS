//! BSP exception entry with TSS stack switching and a dedicated double-fault IST.
use crate::descriptors::{Gate, KERNEL_DATA, TSS_SELECTOR, tss_descriptor};
pub use crate::trap::TrapFrame;

core::arch::global_asm!(include_str!("traps.S"), options(att_syntax));

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
#[repr(C, align(16))]
struct Stack([u8; 16384]);
static mut DOUBLE_FAULT_STACK: Stack = Stack([0; 16384]);
static mut TSS: Tss = Tss {
    reserved0: 0,
    rsp: [0; 3],
    reserved1: 0,
    ist: [0; 7],
    reserved2: 0,
    reserved3: 0,
    iomap: core::mem::size_of::<Tss>() as u16,
};
static mut GDT: [u64; 7] = [0; 7];
static mut IDT: [Gate; 256] = [Gate::EMPTY; 256];
unsafe extern "C" {
    static x86_isr_table: [u64; 48];
    fn x86_isr_128();
    fn x86_isr_255();
}

/// # Safety
/// BSP-only, interrupts disabled, no live user contexts. `kernel_stack_top`
/// must be the aligned top of a reserved supervisor RW/NX stack with room for
/// trap handlers, distinct from the suspended kernel caller's stack. All tables
/// and the double-fault stack must remain mapped.
pub unsafe fn init(kernel_stack_top: u64) {
    assert!(kernel_stack_top > 4096 && kernel_stack_top.is_multiple_of(16));
    assert_eq!(core::mem::size_of::<TrapFrame>(), 176);
    assert_eq!(core::mem::size_of::<Tss>(), 104);
    let tss = core::ptr::addr_of_mut!(TSS);
    let gdt = core::ptr::addr_of_mut!(GDT);
    let idt = core::ptr::addr_of_mut!(IDT);
    let double_fault_top = core::ptr::addr_of!(DOUBLE_FAULT_STACK) as u64 + 16384;
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
