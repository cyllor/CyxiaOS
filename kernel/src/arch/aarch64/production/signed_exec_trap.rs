//! Restricted AArch64 execution for signed EL0 tasks on their owning cores.
//! Only a stopped, authenticated context may be changed here.
use core::arch::asm;
use cyxia_arch_aarch64::user;
use cyxia_kernel_core::security::process::{
    SavedEl0Frame, TrapDecision, TrapKind, TrapSource, decide_trap, resume_frame,
};

// UCT, nTWI and nTWE must be zero to trap CTR_EL0, WFI and WFE at EL0.
const TRAPPING_BITS: u64 = (1 << 15) | (1 << 16) | (1 << 18);

pub(super) enum Return {
    Timer,
    Yield,
    Emulated,
    Syscall,
    TerminateTask,
    FailStop,
}

#[derive(Clone, Copy)]
pub(super) struct Execution {
    ctr: u64,
}

impl Execution {
    /// Configure and read back this CPU before entering any signed task.
    pub(super) fn configure() -> Option<Self> {
        let sctlr: u64;
        let ctr: u64;
        // SAFETY: executed in EL1 on the task's registered owner CPU.
        unsafe {
            asm!(
                "mrs {sctlr}, sctlr_el1",
                "mrs {ctr}, ctr_el0",
                sctlr = out(reg) sctlr,
                ctr = out(reg) ctr,
                options(nomem, nostack, preserves_flags),
            );
        }
        let observed: u64;
        // SAFETY: only the three EL0 execution controls above can change.
        unsafe {
            asm!(
                "msr sctlr_el1, {required}",
                "isb",
                "mrs {observed}, sctlr_el1",
                required = in(reg) sctlr & !TRAPPING_BITS,
                observed = out(reg) observed,
                options(nostack, preserves_flags),
            );
        }
        (observed & TRAPPING_BITS == 0).then_some(Self { ctr })
    }

    pub(super) fn handle_return(self, ctx: &mut user::Context) -> Return {
        if ctx.status & 0x1f != 0 {
            return Return::FailStop;
        }
        match ctx.kind {
            9 => return Return::Timer,
            8 => {}
            _ => return Return::FailStop,
        }
        let decision = decide_trap(
            TrapSource::LowerElAarch64,
            TrapKind::Sync,
            ctx.esr,
            ctx.pc,
            self.ctr,
        );
        let outcome = match decision {
            TrapDecision::Syscall => return Return::Syscall,
            TrapDecision::Yield { .. } => Return::Yield,
            TrapDecision::EmulateCtr { .. } => Return::Emulated,
            TrapDecision::TerminateTask => return Return::TerminateTask,
            TrapDecision::FailStop | TrapDecision::IrqProtocol => return Return::FailStop,
        };
        if !ctx.pc.is_multiple_of(4) {
            return Return::FailStop;
        }
        let frame = SavedEl0Frame {
            x: ctx.regs,
            sp_el0: ctx.sp,
            elr: ctx.pc,
            spsr: ctx.status,
        };
        let Ok(resumed) = resume_frame(frame, decision) else {
            return Return::FailStop;
        };
        ctx.regs = resumed.x;
        ctx.pc = resumed.elr;
        ctx.status = resumed.spsr;
        outcome
    }
}
