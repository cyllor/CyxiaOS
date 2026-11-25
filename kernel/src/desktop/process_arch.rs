//! CPU-owned process context and normalized exit; policy never decodes ARM ESR.
use cyxia_posix::{Errno, ImageAbi};
#[cfg(target_arch = "aarch64")]
pub const IMAGE_ABI: ImageAbi = ImageAbi::Aarch64;
#[cfg(target_arch = "x86_64")]
pub const IMAGE_ABI: ImageAbi = ImageAbi::X86_64;
#[cfg(target_arch = "aarch64")]
pub const MACHINE: &str = "aarch64";
#[cfg(target_arch = "x86_64")]
pub const MACHINE: &str = "x86_64";
#[cfg(target_arch = "aarch64")]
pub const INSTRUCTION_ALIGNMENT: usize = 4;
#[cfg(target_arch = "x86_64")]
pub const INSTRUCTION_ALIGNMENT: usize = 1;
#[derive(Clone, Copy)]
pub enum Exit {
    Syscall,
    Preempted,
    Fault {
        address: u64,
        instruction: u64,
        signal: u32,
        diagnostic: u64,
        vector: Option<u16>,
        code: i32,
    },
}
#[cfg(target_arch = "aarch64")]
type RawContext = cyxia_arch_aarch64::user::Context;
#[cfg(target_arch = "x86_64")]
type RawContext = cyxia_arch_x86_64::user::Context;
pub struct Context {
    raw: RawContext,
    number: u64,
    args: [u64; 6],
    retry_pc: Option<u64>,
    #[cfg(target_arch = "x86_64")]
    fault: cyxia_posix::signal_x86_64::FaultState,
    // AP records only; CPU0 consumes after the complete user phase is drained.
    #[cfg(target_arch = "x86_64")]
    entry_error: Option<cyxia_arch_x86_64::user::Error>,
}
impl Context {
    pub const fn empty() -> Self {
        Self {
            raw: RawContext::empty(),
            number: 0,
            args: [0; 6],
            retry_pc: None,
            #[cfg(target_arch = "x86_64")]
            fault: cyxia_posix::signal_x86_64::FaultState::EMPTY,
            #[cfg(target_arch = "x86_64")]
            entry_error: None,
        }
    }
    pub fn initialize(entry: u64, sp: u64, linux: bool) -> Result<Self, Errno> {
        let mut context = Self::empty();
        #[cfg(target_arch = "aarch64")]
        {
            context.raw.pc = entry;
            context.raw.sp = sp;
            let _ = linux;
        }
        #[cfg(target_arch = "x86_64")]
        {
            use cyxia_arch_x86_64::user::UserAbi;
            context
                .raw
                .initialize(
                    entry,
                    sp,
                    if linux {
                        UserAbi::Linux64
                    } else {
                        UserAbi::NativeOs
                    },
                )
                .map_err(|_| Errno::Inval)?;
        }
        Ok(context)
    }
    /// CPU0 only, after every user worker and root has been retired.
    #[cfg(target_arch = "x86_64")]
    pub fn trace_entry_failure(&mut self, pid: u32, tid: u32, errno: Errno) {
        let error = self.entry_error.take();
        trace_entry_error(
            "complete_exit",
            pid,
            tid,
            format_args!(
                "resume_error={error:?} errno={errno:?} pc={:#x} sp={:#x}",
                self.pc(),
                self.sp(),
            ),
        );
    }
    pub fn pc(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.raw.pc
        }
        #[cfg(target_arch = "x86_64")]
        {
            self.raw.pc()
        }
    }
    pub fn sp(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.raw.sp
        }
        #[cfg(target_arch = "x86_64")]
        {
            self.raw.sp()
        }
    }
    pub fn set_sp(&mut self, value: u64) -> Result<(), Errno> {
        #[cfg(target_arch = "aarch64")]
        {
            self.raw.sp = value;
            Ok(())
        }
        #[cfg(target_arch = "x86_64")]
        {
            self.raw.set_sp(value).map_err(|_| Errno::Inval)
        }
    }
    pub fn argument(&self, index: usize) -> u64 {
        assert!(index < 6);
        #[cfg(target_arch = "aarch64")]
        {
            self.raw.regs[index]
        }
        #[cfg(target_arch = "x86_64")]
        {
            self.raw.argument(index).unwrap()
        }
    }
    pub fn arguments(&self) -> [u64; 6] {
        core::array::from_fn(|i| self.argument(i))
    }
    pub fn set_argument(&mut self, index: usize, value: u64) {
        #[cfg(target_arch = "aarch64")]
        {
            self.raw.regs[index] = value;
        }
        #[cfg(target_arch = "x86_64")]
        {
            self.raw
                .set_argument(index, value)
                .expect("six process arguments");
        }
    }
    pub fn syscall_number(&self) -> u64 {
        self.number
    }
    pub fn result(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.raw.regs[0]
        }
        #[cfg(target_arch = "x86_64")]
        {
            self.raw.result()
        }
    }
    pub fn set_result(&mut self, value: u64) {
        // A blocked x86 call must retry with its number in RAX, not its FD.
        #[cfg(target_arch = "x86_64")]
        if self.retry_pc.is_some() {
            return;
        }
        #[cfg(target_arch = "aarch64")]
        {
            self.raw.regs[0] = value;
        }
        #[cfg(target_arch = "x86_64")]
        {
            self.raw.set_result(value);
        }
    }
    pub fn tls(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.raw.tpidr_el0
        }
        #[cfg(target_arch = "x86_64")]
        {
            self.raw.tls()
        }
    }
    pub fn set_tls(&mut self, value: u64) -> Result<(), Errno> {
        if value >= 0x0000_8000_0000_0000 {
            return Err(Errno::Inval);
        }
        #[cfg(target_arch = "aarch64")]
        {
            self.raw.tpidr_el0 = value;
            Ok(())
        }
        #[cfg(target_arch = "x86_64")]
        {
            self.raw.set_tls(value).map_err(|_| Errno::Inval)
        }
    }
    pub fn restart_syscall(&mut self) -> Result<(), Errno> {
        self.retry_pc = Some(self.pc());
        #[cfg(target_arch = "aarch64")]
        {
            self.raw.pc = self.raw.pc.checked_sub(4).ok_or(Errno::Fault)?;
            self.raw.regs[..6].copy_from_slice(&self.args);
        }
        #[cfg(target_arch = "x86_64")]
        self.raw.restart_syscall().map_err(|_| Errno::Fault)?;
        Ok(())
    }
    pub fn cancel_restart(&mut self) -> Result<(), Errno> {
        if let Some(pc) = self.retry_pc.take() {
            #[cfg(target_arch = "aarch64")]
            {
                self.raw.pc = pc;
            }
            #[cfg(target_arch = "x86_64")]
            self.raw.set_pc(pc).map_err(|_| Errno::Fault)?;
        }
        Ok(())
    }
    pub fn clone_for_thread(&self, sp: u64, tls: u64) -> Result<Self, Errno> {
        #[cfg(target_arch = "aarch64")]
        let raw = RawContext {
            regs: self.raw.regs,
            pc: self.raw.pc,
            status: self.raw.status,
            sp,
            esr: 0,
            far: 0,
            kind: 0,
            tpidr_el0: tls,
            simd: self.raw.simd,
            fpcr: self.raw.fpcr,
            fpsr: self.raw.fpsr,
        };
        #[cfg(target_arch = "x86_64")]
        let raw = self
            .raw
            .clone_for_thread(sp, tls)
            .map_err(|_| Errno::Inval)?;
        let mut child = Self {
            raw,
            number: self.number,
            args: self.args,
            retry_pc: None,
            #[cfg(target_arch = "x86_64")]
            fault: self.fault,
            #[cfg(target_arch = "x86_64")]
            entry_error: None,
        };
        child.set_result(0);
        Ok(child)
    }
}
pub fn now_ns() -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        cyxia_kernel_core::time::ticks_to_ns(
            cyxia_arch_aarch64::timer::ticks(),
            cyxia_arch_aarch64::timer::frequency(),
        )
        .unwrap()
        .0
    }
    #[cfg(target_arch = "x86_64")]
    {
        crate::machine::runtime::now_ns()
    }
}
pub fn resolution_ns() -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        1_000_000_000u64.div_ceil(cyxia_arch_aarch64::timer::frequency())
    }
    #[cfg(target_arch = "x86_64")]
    {
        crate::machine::runtime::monotonic_resolution_ns()
    }
}
#[cfg(target_arch = "aarch64")]
pub unsafe fn enter(context: &mut Context, root: u64, _deadline: u64) -> Result<Exit, Errno> {
    unsafe {
        cyxia_arch_aarch64::user::enter(&mut context.raw, root);
    }
    context.retry_pc = None;
    if context.raw.kind == 9 {
        return Ok(Exit::Preempted);
    }
    if context.raw.esr >> 26 == 0x15 && context.raw.esr & 0xffff == 0 {
        context.number = context.raw.regs[8];
        context.args = context.arguments();
        return Ok(Exit::Syscall);
    }
    Ok(Exit::Fault {
        address: context.raw.far,
        instruction: context.raw.pc,
        signal: if matches!(context.raw.esr >> 26, 0x20 | 0x24) {
            11
        } else {
            4
        },
        diagnostic: context.raw.esr,
        vector: None,
        code: 1, // Preserve historical Arm signal policy and ESR path.
    })
}
#[cfg(target_arch = "x86_64")]
pub unsafe fn enter(
    context: &mut Context,
    root: &cyxia_arch_x86_64::space::AddressSpace<'_>,
    deadline: u64,
) -> Result<Exit, Errno> {
    use cyxia_arch_x86_64::user::UserExit;
    context.entry_error = None;
    let exit = unsafe { cyxia_arch_x86_64::user::resume(&mut context.raw, root, deadline) }
        .map_err(|error| {
            // No printing on an AP. Existing ownership/drain carries this home.
            context.entry_error = Some(error);
            Errno::Io
        })?;
    // A timer may preempt the rewound SYSCALL before it executes. Keep its
    // return PC until an actual exit consumes it, including signal delivery.
    if !matches!(exit, UserExit::Preempted(_)) {
        context.retry_pc = None;
    }
    Ok(match exit {
        UserExit::Syscall(call) => {
            context.number = call.number;
            context.args = call.args;
            Exit::Syscall
        }
        UserExit::Preempted(_) => Exit::Preempted,
        UserExit::Fault(fault) => {
            context
                .fault
                .capture(fault.vector, fault.error, fault.address);
            let (signal, code) = cyxia_posix::signal_x86_64::fault_signal(
                fault.vector,
                fault.error,
                &context.raw.signal_state().fxsave,
            );
            Exit::Fault {
                address: fault.address,
                instruction: fault.instruction,
                signal,
                diagnostic: fault.error,
                vector: Some(fault.vector),
                code,
            }
        }
    })
}
/// Finish a nonblocking Linux clock syscall in the AP's owned job. Decline
/// complex outputs so CPU0 applies the ordinary copy and errno policy.
///
/// # Safety
/// The caller owns this stopped context and its matching root. The CPU0
/// service owner and other workers cannot access its private backing.
#[cfg(all(
    target_arch = "x86_64",
    feature = "cosmic-session",
    not(feature = "abi-trace")
))]
pub(crate) unsafe fn complete_ap_clock(
    context: &mut Context,
    root: &cyxia_arch_x86_64::space::AddressSpace<'_>,
    deadline: u64,
) -> bool {
    use cyxia_arch_x86_64::{space::PAGE_BYTES, user::UserAbi};
    use cyxia_posix::linux_abi::{CLOCK_MONOTONIC, X86_64_CLOCK_GETTIME, encode_timespec};

    let Some(call) = context.raw.syscall() else {
        return false;
    };
    if call.abi != UserAbi::Linux64
        || call.number != X86_64_CLOCK_GETTIME
        || call.args[0] != CLOCK_MONOTONIC
    {
        return false;
    }
    const LAYOUT: cyxia_contracts::user_layout::ImageLayout = crate::exec_memory::PROFILE.layout();
    const BYTES: usize = 16;
    let address = call.args[1];
    // Only the private image, initial stack and anonymous heap are eligible.
    // A single-page output delegates cross-page validation to CPU0.
    let private = (LAYOUT.image_base..LAYOUT.image_end).contains(&address)
        || (LAYOUT.stack_base..LAYOUT.stack_base + LAYOUT.stack_pages as u64 * PAGE_BYTES)
            .contains(&address)
        || (cyxia_posix::vm::BASE..cyxia_posix::vm::END).contains(&address);
    if !private || address % PAGE_BYTES > PAGE_BYTES - BYTES as u64 {
        return false;
    }
    debug_assert_eq!(root.resident_cpus(), 0);
    let Some(mapping) = root.translate(address) else {
        return false;
    };
    if !mapping.permissions.writable || mapping.permissions.executable {
        return false;
    }
    let Ok(output) = crate::machine::runtime::kernel_va(mapping.physical, BYTES) else {
        return false;
    };
    let ns = now_ns();
    if ns >= deadline {
        return false;
    }
    // The admitted writable private mapping pins a complete 16-byte span.
    unsafe {
        core::ptr::copy_nonoverlapping(encode_timespec(ns).as_ptr(), output as *mut u8, BYTES)
    };
    context.set_result(0);
    true
}

pub fn make_writable(address: u64, length: usize) -> Result<(), Errno> {
    #[cfg(target_arch = "aarch64")]
    {
        let _ = (address, length);
        Ok(())
    }
    #[cfg(target_arch = "x86_64")]
    {
        let physical = address.checked_sub(crate::HIGH).ok_or(Errno::Fault)?;
        for page in
            (physical..physical.checked_add(length as u64).ok_or(Errno::Fault)?).step_by(4096)
        {
            // A failed seal/unseal may have changed a PTE without completing its
            // fence. Only StableWritable permits zeroing or backing reuse.
            if !crate::machine::runtime::is_user_code_writable(page) {
                unsafe { crate::machine::runtime::unseal_user_code(page, 4096) }
                    .map_err(|_| Errno::Io)?;
            }
        }
        Ok(())
    }
}
pub fn publish_code(address: u64, length: usize) -> Result<(), Errno> {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let ctr: u64;
        core::arch::asm!("mrs {}, ctr_el0",out(reg)ctr);
        let line = 4u64 << ((ctr >> 16) & 15);
        let mut at = address & !(line - 1);
        while at < address + length as u64 {
            core::arch::asm!("dc cvau, {}",in(reg)at);
            at += line;
        }
        core::arch::asm!("dsb ish", "ic iallu", "dsb ish", "isb");
        Ok(())
    }
    #[cfg(target_arch = "x86_64")]
    {
        unsafe extern "C" {
            fn x86_runtime_code_sealed(physical: u64) -> bool;
        }
        let physical = address.checked_sub(crate::HIGH).ok_or(Errno::Fault)?;
        let end = physical.checked_add(length as u64).ok_or(Errno::Fault)?;
        if (physical..end)
            .step_by(4096)
            .any(|page| !unsafe { x86_runtime_code_sealed(page) })
        {
            unsafe { crate::machine::runtime::seal_user_code(physical, length) }.map_err(
                |error| {
                    trace_entry_error(
                        "publish_code",
                        0,
                        0,
                        format_args!(
                            "error={error:?} va={address:#x} pa={physical:#x} bytes={length}",
                        ),
                    );
                    Errno::Io
                },
            )?;
        }
        Ok(())
    }
}

#[cfg(target_arch = "aarch64")]
pub const LINUX_YIELD_NUMBER: u64 = 124;
#[cfg(target_arch = "x86_64")]
pub const LINUX_YIELD_NUMBER: u64 = 24;

#[cfg(target_arch = "aarch64")]
pub const KERNEL_DESCRIPTION: &str = "native ARM kernel";
#[cfg(target_arch = "x86_64")]
pub const KERNEL_DESCRIPTION: &str = "native x86 kernel";

#[cfg(all(feature = "ported", target_arch = "aarch64"))]
pub const SIGNAL_FRAME_BYTES: usize = cyxia_posix::signal::FRAME_BYTES;
#[cfg(all(feature = "ported", target_arch = "x86_64"))]
pub const SIGNAL_FRAME_BYTES: usize = cyxia_posix::signal_x86_64::FRAME_BYTES;
#[cfg(feature = "ported")]
pub fn signal_frame_address(
    stack: cyxia_posix::signal::AltStack,
    sp: u64,
    on_stack: bool,
) -> Result<u64, Errno> {
    #[cfg(target_arch = "aarch64")]
    {
        stack.frame_address(sp, on_stack)
    }
    #[cfg(target_arch = "x86_64")]
    {
        cyxia_posix::signal_x86_64::frame_address(stack, sp, on_stack)
    }
}
#[cfg(feature = "ported")]
impl Context {
    pub fn signal_return_address(&self) -> Result<u64, Errno> {
        #[cfg(target_arch = "aarch64")]
        {
            Ok(self.sp())
        }
        #[cfg(target_arch = "x86_64")]
        {
            self.sp().checked_sub(8).ok_or(Errno::Fault)
        }
    }
    pub fn encode_signal_frame(
        &self,
        out: &mut [u8; SIGNAL_FRAME_BYTES],
        address: u64,
        mask: u64,
        signal: u32,
        info: cyxia_posix::signal::Info,
        stack: cyxia_posix::signal::AltStack,
        restorer: u64,
        restart: bool,
    ) -> Result<(), Errno> {
        #[cfg(target_arch = "aarch64")]
        {
            let mut state = cyxia_posix::signal::FrameState {
                regs: self.raw.regs,
                sp: self.raw.sp,
                pc: self.raw.pc,
                pstate: self.raw.status,
                fault_address: self.raw.far,
                simd: self.raw.simd,
                fpcr: self.raw.fpcr as u32,
                fpsr: self.raw.fpsr as u32,
            };
            if let Some(pc) = self.retry_pc {
                state.pc = pc;
                state.regs[0] = (-(Errno::Intr as i64)) as u64;
            }
            cyxia_posix::signal::encode_frame(out, &state, mask, signal, info)?;
            cyxia_posix::signal::set_frame_stack(out, stack, self.sp());
            let _ = (address, restorer, restart);
            Ok(())
        }
        #[cfg(target_arch = "x86_64")]
        {
            let cpu = self.raw.signal_state();
            let mut state = cyxia_posix::signal_x86_64::FrameState {
                registers: cpu.registers,
                pc: cpu.pc,
                sp: cpu.sp,
                flags: cpu.status,
                fault: self.fault,
                fxsave: cpu.fxsave,
            };
            if let Some(pc) = self.retry_pc.filter(|_| !restart) {
                state.pc = pc;
                state.registers[14] = (-(Errno::Intr as i64)) as u64;
            }
            cyxia_posix::signal_x86_64::encode_frame(
                out,
                address,
                &state,
                mask,
                signal,
                info,
                stack,
                restorer,
                [
                    cyxia_arch_x86_64::descriptors::USER_CODE,
                    cyxia_arch_x86_64::descriptors::USER_DATA,
                ],
            )
        }
    }
    pub fn signal_handler(
        &mut self,
        action: cyxia_posix::signal::Action,
        address: u64,
        signal: u32,
    ) -> Result<(), Errno> {
        use cyxia_posix::signal::SA_SIGINFO;
        self.retry_pc = None;
        #[cfg(target_arch = "aarch64")]
        {
            self.raw.regs[0] = u64::from(signal);
            self.raw.regs[1] = if action.flags & SA_SIGINFO != 0 {
                address
            } else {
                0
            };
            self.raw.regs[2] = if action.flags & SA_SIGINFO != 0 {
                address + cyxia_posix::signal::UCONTEXT_OFFSET as u64
            } else {
                0
            };
            self.raw.regs[29] = address + cyxia_posix::signal::RT_FRAME_BYTES as u64;
            self.raw.regs[30] = action.restorer;
            self.raw.pc = action.handler;
            self.raw.sp = address;
            self.raw.status &= 0xf0000000;
            self.raw.kind = 0;
            self.raw.esr = 0;
            Ok(())
        }
        #[cfg(target_arch = "x86_64")]
        {
            let mut state = self.raw.signal_state();
            state.pc = action.handler;
            state.sp = address;
            state.registers[8] = u64::from(signal);
            state.registers[9] = if action.flags & SA_SIGINFO != 0 {
                address + cyxia_posix::signal_x86_64::SIGINFO_OFFSET as u64
            } else {
                0
            };
            state.registers[11] = if action.flags & SA_SIGINFO != 0 {
                address + cyxia_posix::signal_x86_64::UCONTEXT_OFFSET as u64
            } else {
                0
            };
            state.status = (state.status & !((1 << 8) | (1 << 10) | (1 << 16))) | 0x202;
            self.raw
                .restore_signal_state(state)
                .map_err(|_| Errno::Fault)
        }
    }
    pub fn restore_signal_frame(
        &self,
        bytes: &[u8; SIGNAL_FRAME_BYTES],
        address: u64,
        tls: u64,
    ) -> Result<(Self, u64, cyxia_posix::signal::AltStack), Errno> {
        #[cfg(target_arch = "aarch64")]
        {
            let (state, mask) = cyxia_posix::signal::decode_frame(bytes)?;
            let stack = cyxia_posix::signal::frame_stack(bytes)?;
            let context = Self {
                raw: RawContext {
                    regs: state.regs,
                    pc: state.pc,
                    status: state.pstate,
                    sp: state.sp,
                    far: state.fault_address,
                    tpidr_el0: tls,
                    simd: state.simd,
                    fpcr: u64::from(state.fpcr),
                    fpsr: u64::from(state.fpsr),
                    ..RawContext::empty()
                },
                number: 0,
                args: [0; 6],
                retry_pc: None,
            };
            let _ = address;
            Ok((context, mask, stack))
        }
        #[cfg(target_arch = "x86_64")]
        {
            let (state, mask, stack) = cyxia_posix::signal_x86_64::decode_frame(
                bytes,
                address,
                [
                    cyxia_arch_x86_64::descriptors::USER_CODE,
                    cyxia_arch_x86_64::descriptors::USER_DATA,
                ],
            )?;
            let mut raw = self.raw.clone();
            let previous = self.raw.signal_state();
            raw.restore_signal_state(cyxia_arch_x86_64::user::X86SignalState {
                registers: state.registers,
                pc: state.pc,
                sp: state.sp,
                status: state.flags,
                fs_base: tls,
                gs_base: previous.gs_base,
                fxsave: state.fxsave,
            })
            .map_err(|_| Errno::Fault)?;
            Ok((
                Self {
                    raw,
                    number: 0,
                    args: [0; 6],
                    retry_pc: None,
                    fault: self.fault,
                    entry_error: None,
                },
                mask,
                stack,
            ))
        }
    }
}

/// Emit diagnostics only after CPU0 has drained every user worker.
pub fn trace_fault(exit: Exit) {
    #[cfg(target_arch = "x86_64")]
    if let Exit::Fault {
        address,
        instruction,
        diagnostic,
        vector: Some(vector),
        ..
    } = exit
    {
        log_x86_fault(vector, diagnostic, address, instruction);
    }
    #[cfg(target_arch = "aarch64")]
    let _ = exit;
}

#[cfg(target_arch = "x86_64")]
fn log_x86_fault(vector: u16, error: u64, address: u64, instruction: u64) {
    use core::fmt::Write;
    struct Line {
        bytes: [u8; 192],
        len: usize,
    }
    impl core::fmt::Write for Line {
        fn write_str(&mut self, text: &str) -> core::fmt::Result {
            let end = self.len.checked_add(text.len()).ok_or(core::fmt::Error)?;
            self.bytes
                .get_mut(self.len..end)
                .ok_or(core::fmt::Error)?
                .copy_from_slice(text.as_bytes());
            self.len = end;
            Ok(())
        }
    }
    let mut line = Line {
        bytes: [0; 192],
        len: 0,
    };
    writeln!(line,"USER_FAULT vector={vector} error={error:#x} address={address:#x} instruction={instruction:#x}").expect("bounded hardware fault trace");
    crate::log(&line.bytes[..line.len]);
}

/// Failure-only, bounded CPU0 output; fixed stages and finite error enums only.
/// Never call while an AP user phase owns a context/root. Zero PID/TID means
/// unavailable here; the enclosing prepare diagnostic supplies that identity.
#[cfg(target_arch = "x86_64")]
pub fn trace_entry_error(
    stage: &'static str,
    pid: u32,
    tid: u32,
    detail: core::fmt::Arguments<'_>,
) {
    use core::fmt::Write;
    struct Line {
        bytes: [u8; 384],
        len: usize,
    }
    impl core::fmt::Write for Line {
        fn write_str(&mut self, text: &str) -> core::fmt::Result {
            let end = self.len.checked_add(text.len()).ok_or(core::fmt::Error)?;
            self.bytes
                .get_mut(self.len..end)
                .ok_or(core::fmt::Error)?
                .copy_from_slice(text.as_bytes());
            self.len = end;
            Ok(())
        }
    }
    let mut line = Line {
        bytes: [0; 384],
        len: 0,
    };
    writeln!(
        line,
        "USER_ENTRY_ERROR stage={stage} pid={pid} tid={tid} {detail}"
    )
    .expect("bounded user entry diagnostic");
    crate::log(&line.bytes[..line.len]);
}
