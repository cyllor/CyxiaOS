//! Pinned per-CPU process transitions. GS is kernel-private while at CPL0.
use super::context::*;
use crate::{space::AddressSpace, trap::TrapFrame};
use core::sync::atomic::{AtomicBool, Ordering};
#[repr(C, align(64))]
struct Local {
    active: *mut Context,
    kernel_rsp: u64,
    trap_top: u64,
    user_rsp: u64,
    kernel_root: u64,
    kernel_fs: u64,
    slot: u64,
    reserved: u64,
    kernel_fx: super::context::FxState,
}
impl Local {
    const EMPTY: Self = Self {
        active: core::ptr::null_mut(),
        kernel_rsp: 0,
        trap_top: 0,
        user_rsp: 0,
        kernel_root: 0,
        kernel_fs: 0,
        slot: 0,
        reserved: 0,
        kernel_fx: super::context::FxState::empty(),
    };
}
static mut LOCALS: [Local; 4] = [const { Local::EMPTY }; 4];
static READY: [AtomicBool; 4] = [const { AtomicBool::new(false) }; 4];
unsafe extern "C" {
    fn x86_context_enter(context: *mut core::ffi::c_void, root: u64);
    fn x86_runtime_syscall();
    fn x86_runtime_arm_deadline(deadline: u64) -> u64;
}
pub unsafe fn write_msr(index: u32, value: u64) {
    unsafe {
        core::arch::asm!("wrmsr",in("ecx")index,in("eax")value as u32,in("edx")(value>>32) as u32,options(nostack));
    }
}
pub unsafe fn read_msr(index: u32) -> u64 {
    let a: u32;
    let d: u32;
    unsafe {
        core::arch::asm!("rdmsr",in("ecx")index,out("eax")a,out("edx")d,options(nostack));
    }
    a as u64 | (d as u64) << 32
}
pub fn cpu_slot() -> usize {
    let slot: u64;
    unsafe {
        core::arch::asm!("mov {},gs:[48]",out(reg)slot,options(nostack,readonly));
    }
    slot as usize
}
/// # Safety
/// This registered CPU exclusively owns slot, valid guarded stacks/descriptors
/// are installed, IF clear, kernel_root mapped, no live user context.
pub unsafe fn init_runtime_cpu(slot: usize, kernel_root: u64, trap_top: u64) -> Result<(), Error> {
    let basic = core::arch::x86_64::__cpuid(1);
    let extended = core::arch::x86_64::__cpuid(0x80000001);
    if basic.edx & ((1 << 24) | (1 << 26)) != ((1 << 24) | (1 << 26))
        || extended.edx & (1 << 11) == 0
    {
        return Err(Error::Unsupported);
    }
    if slot >= 4 || kernel_root % 4096 != 0 || trap_top % 16 != 0 {
        return Err(Error::Address);
    }
    let local = unsafe { core::ptr::addr_of_mut!(LOCALS).cast::<Local>().add(slot) };
    unsafe {
        local.write(Local {
            slot: slot as u64,
            kernel_root,
            trap_top,
            ..Local::EMPTY
        });
    }
    // XSAVE/AVX, FSGSBASE, PKRU and supervisor extensions are not enabled. The
    // saved FX bank therefore covers every user-enabled FP/SIMD register.
    let mut cr4: u64;
    unsafe {
        core::arch::asm!("mov {},cr4",out(reg)cr4,options(nostack));
    }
    cr4 &= !((1 << 18) | (1 << 16) | (1 << 22));
    cr4 |= (1 << 9) | (1 << 10);
    unsafe {
        core::arch::asm!("mov cr4,{}",in(reg)cr4,options(nostack));
        write_msr(0xc0000101, local as u64);
        write_msr(0xc0000102, 0);
        let efer = read_msr(0xc0000080);
        // Fast FXSAVE/FXRSTOR omits XMM at CPL0 on supporting CPUs. All enabled
        // XMM state belongs to the entered process, so this mode is forbidden.
        write_msr(0xc0000080, (efer & !(1 << 14)) | 1);
        write_msr(0xc0000081, (8u64 << 32) | (0x13u64 << 48));
        write_msr(0xc0000082, x86_runtime_syscall as *const () as u64);
        write_msr(
            0xc0000084,
            (1 << 9) | (1 << 10) | (1 << 8) | (1 << 14) | (1 << 18),
        );
    }
    READY[slot].store(true, Ordering::Release);
    Ok(())
}
/// # Safety
/// Context/tables pinned, exclusive process ownership, no nested entry; every
/// mapped frame belongs to this process or an admitted shared object. RX frames
/// have no writable aliases, and all previous revocations completed.
pub unsafe fn resume(
    context: &mut Context,
    space: &AddressSpace<'_>,
    deadline_ns: u64,
) -> Result<UserExit, Error> {
    let slot = cpu_slot();
    if slot >= 4 || !READY[slot].load(Ordering::Acquire) {
        return Err(Error::NotReady);
    }
    let entry = space.translate(context.pc()).ok_or(Error::Mapping)?;
    // musl's detached-thread tail unmaps its own stack/TLS before SYS_exit.
    // IRET restores RSP without accessing that memory. Keep its user-range
    // guard (a noncanonical RSP could fault in CPL0), and let ordinary CPL3
    // memory accesses enforce page permissions when a stack is actually used.
    user_address(context.sp())?;
    if !entry.permissions.executable || entry.permissions.writable {
        return Err(Error::Mapping);
    }
    let flags: u64;
    unsafe {
        core::arch::asm!("pushfq","pop {}","cli",out(reg)flags);
    }
    struct RestoreIf(u64);
    impl Drop for RestoreIf {
        fn drop(&mut self) {
            if self.0 & (1 << 9) != 0 {
                unsafe {
                    core::arch::asm!("sti", options(nostack));
                }
            }
        }
    }
    let _restore = RestoreIf(flags);
    let local = unsafe { core::ptr::addr_of_mut!(LOCALS).cast::<Local>().add(slot) };
    if !unsafe { core::ptr::addr_of!((*local).active).read() }.is_null() {
        return Err(Error::Active);
    }
    if unsafe { x86_runtime_arm_deadline(deadline_ns) } != 0 {
        return Err(Error::Clock);
    }
    context.flags = (context.flags & 0x240cd5) | 0x202;
    context.exit = None;
    space.enter_cpu(slot).map_err(|_| Error::Mapping)?;
    unsafe {
        core::ptr::addr_of_mut!((*local).active).write(core::ptr::from_mut(context));
    }
    unsafe {
        x86_context_enter(core::ptr::from_mut(context).cast(), space.root_phys());
    }
    unsafe {
        core::ptr::addr_of_mut!((*local).active).write(core::ptr::null_mut());
    }
    space.leave_cpu(slot);
    context.exit.ok_or(Error::NotReady)
}
/// Called after assembly saved user FX/TLS and restored the kernel FP bank.
pub fn capture(frame: &TrapFrame, preempt: Option<PreemptReason>) -> Result<(), Error> {
    if !frame.from_user() {
        return Err(Error::Argument);
    }
    let slot = cpu_slot();
    if slot >= 4 {
        return Err(Error::Address);
    }
    let pointer = unsafe { (*core::ptr::addr_of!(LOCALS).cast::<Local>().add(slot)).active };
    if pointer.is_null() {
        return Err(Error::NotReady);
    }
    let context = unsafe { &mut *pointer };
    unsafe {
        core::ptr::copy_nonoverlapping(
            core::ptr::from_ref(frame).cast::<u64>(),
            context.registers.as_mut_ptr(),
            15,
        );
    }
    context.instruction = frame.rip;
    context.stack = frame.rsp;
    context.flags = frame.rflags;
    let exit = if let Some(reason) = preempt {
        UserExit::Preempted(reason)
    } else if frame.vector == 128 || frame.vector == 256 {
        if (frame.vector == 256) != (context.personality == UserAbi::Linux64) {
            context.exit = Some(UserExit::Fault(UserFault {
                vector: frame.vector as u16,
                error: frame.error,
                address: frame.rip,
                instruction: frame.rip,
                access: Access::Execute,
                reason: FaultReason::GeneralProtection,
            }));
            return Ok(());
        }
        context.syscall_pc = frame.rip.checked_sub(2).ok_or(Error::Address)?;
        UserExit::Syscall(Syscall {
            abi: context.personality,
            number: frame.rax,
            operation: if context.personality == UserAbi::CyxiaNative {
                frame.r9
            } else {
                frame.rax
            },
            args: [
                frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9,
            ],
        })
    } else {
        let address = if frame.vector == 14 {
            crate::cpu::read_cr2()
        } else {
            frame.rip
        };
        UserExit::Fault(UserFault {
            vector: frame.vector as u16,
            error: frame.error,
            address,
            instruction: frame.rip,
            access: if frame.error & (1 << 4) != 0 {
                Access::Execute
            } else if frame.error & 2 != 0 {
                Access::Write
            } else {
                Access::Read
            },
            reason: match frame.vector {
                14 if frame.error & 1 == 0 => FaultReason::NotPresent,
                14 => FaultReason::Permission,
                6 => FaultReason::InvalidInstruction,
                0 | 16 | 19 => FaultReason::Arithmetic,
                _ => FaultReason::GeneralProtection,
            },
        })
    };
    context.exit = Some(exit);
    Ok(())
}

const _: () = {
    assert!(core::mem::offset_of!(Context, fx) == 160);
    assert!(core::mem::offset_of!(Context, instruction) == 120);
    assert!(core::mem::offset_of!(Context, fs_base) == 144);
    assert!(core::mem::offset_of!(Local, kernel_fx) == 64);
};
