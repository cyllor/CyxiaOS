// QEMU PC composition root: CPU mechanisms, board devices, and shared policy.
// This bounded BSP port does not advertise the ARM unified-runtime contract.
use arch::interrupts::TrapFrame;
use core::sync::atomic::{AtomicU64, Ordering};
use cyxia_arch_x86_64 as arch;
use cyxia_platform_pc as pc;

use crate::selftest;
core::arch::global_asm!(
    include_str!("../../../../crates/arch-x86_64/src/entry.S"),
    options(att_syntax)
);
core::arch::global_asm!(
    ".section .text.probes,\"ax\"
     .global x86_probe_read, x86_read_fault, x86_read_resume
     x86_probe_read:
     x86_read_fault: movq (%rdi), %rax
     x86_read_resume: ret
     .global x86_probe_write, x86_write_fault, x86_write_resume
     x86_probe_write:
     x86_write_fault: movb $0, (%rdi)
     x86_write_resume: ret
     .global x86_probe_execute, x86_execute_resume
     x86_probe_execute: call *%rdi
     ret
     x86_execute_resume: addq $8, %rsp
     ret",
    options(att_syntax)
);

unsafe extern "C" {
    static __kernel_start: u8;
    static __kernel_end: u8;
    static __text_start: u8;
    static __text_end: u8;
    static __rodata_start: u8;
    static __rodata_end: u8;
    static __user_text_start: u8;
    static __user_text_end: u8;
    static __user_stack_start: u8;
    static __user_stack_end: u8;
    static __stack_guard_start: u8;
    static __stack_guard_end: u8;
    static __trap_stack_top: u8;
    fn x86_probe_read(address: u64);
    fn x86_read_fault();
    fn x86_read_resume();
    fn x86_probe_write(address: u64);
    fn x86_write_fault();
    fn x86_write_resume();
    fn x86_probe_execute(address: u64);
    fn x86_execute_resume();
}

static TICKS: AtomicU64 = AtomicU64::new(0);
static BREAKPOINTS: AtomicU64 = AtomicU64::new(0);
static EXPECTED_IP: AtomicU64 = AtomicU64::new(0);
static EXPECTED_ADDRESS: AtomicU64 = AtomicU64::new(0);
static EXPECTED_ERROR: AtomicU64 = AtomicU64::new(0);
static RESUME_IP: AtomicU64 = AtomicU64::new(0);
static FAULTS: AtomicU64 = AtomicU64::new(0);
static USER_CALLS: AtomicU64 = AtomicU64::new(0);
static USER_FAULTS: AtomicU64 = AtomicU64::new(0);
static USER_PROBE: AtomicU64 = AtomicU64::new(0);

#[repr(C, align(4096))]
struct NxPage([u8; 4096]);
static mut NX_PROBE: NxPage = NxPage([0xc3; 4096]);

mod boot;
mod checks;
mod console;
use console::{exit, log};
