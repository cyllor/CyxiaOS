//! SEC-P: bounded spawn idempotency, local CPU admission and exit fencing.
//! A VerifiedSpawn is built only from the protected task/package registry.
use super::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Request {
    pub id: u64,
    pub caller: u64,
    pub group: u8,
    pub package: [u8; 32],
    pub cpu: u8,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedSpawn {
    owner: u64,
    group: u8,
    package: [u8; 32],
    business: u64,
    healthy: u64,
    draining: u64,
    suspect: u64,
}
impl VerifiedSpawn {
    /// Only the privileged registry adapter may turn a capability and live
    /// ledger observation into this value; AI fields cannot construct one.
    /// Both registry constructors share the single V0.20 fixed CPU0 boundary.
    #[allow(dead_code)] // Constructed by the native authority adapter once integrated.
    pub(crate) const fn from_registry(
        owner: u64,
        group: u8,
        package: [u8; 32],
        business: u64,
        healthy: u64,
        draining: u64,
        suspect: u64,
    ) -> Self {
        Self {
            owner,
            group,
            package,
            business,
            healthy,
            draining,
            suspect,
        }
    }
    /// Retained constructor name for the V0.19.9 protected registry adapter;
    /// identical to from_registry now that CPU0 is the only control core.
    #[allow(dead_code)]
    pub(crate) const fn from_registry_v0199(
        owner: u64,
        group: u8,
        package: [u8; 32],
        business: u64,
        healthy: u64,
        draining: u64,
        suspect: u64,
    ) -> Self {
        Self {
            owner,
            group,
            package,
            business,
            healthy,
            draining,
            suspect,
        }
    }
    fn permits(&self, request: Request) -> bool {
        let cpu = 1u64.checked_shl(request.cpu as u32).unwrap_or(0);
        self.owner != 0
            && self.owner == request.caller
            && self.group == request.group
            && self.package == request.package
            && cpu != 0
            // Standalone SEC-P ledger shares the same V0.20 native role
            // boundary as authorize_business_core: CPU0 is the only control
            // CPU and may not be an ordinary business CPU; CPU1-3 are business.
            && crate::control_plane::cpu0_v0199::permits_business(
                u16::from(request.cpu), self.business, self.healthy, self.draining, self.suspect,
            )
    }
}

/// Gate for the actual native business-core placement. A snapshot is supplied
/// by the protected scheduler/ownership adapter, never by the AI or a task.
/// It is checked again at creation publication; it does not reserve a CPU.
pub fn authorize_business_core(
    cpu: u16,
    core_generation: u64,
    business_mask: u64,
    healthy_mask: u64,
    draining_mask: u64,
    quarantined_mask: u64,
) -> Result<(), Error> {
    // V0.20 native four-core layout: CPU0 is the only control CPU and can never
    // run ordinary business; CPU1-3 are the business cores. A damaged mask that
    // claims CPU0 (or any core outside CPU1-3) is healthy business fails closed.
    if cpu == 0 {
        return Err(Error::Unauthorized);
    }
    authorize_business_core_v0199(
        cpu,
        core_generation,
        business_mask,
        healthy_mask,
        draining_mask,
        quarantined_mask,
    )
}

/// V0.19.9 native placement gate; the single authoritative CPU0 business
/// boundary that authorize_business_core now delegates to. Recheck at publication.
pub fn authorize_business_core_v0199(
    cpu: u16,
    core_generation: u64,
    business_mask: u64,
    healthy_mask: u64,
    draining_mask: u64,
    quarantined_mask: u64,
) -> Result<(), Error> {
    if core_generation == 0
        || !crate::control_plane::cpu0_v0199::permits_business(
            cpu,
            business_mask,
            healthy_mask,
            draining_mask,
            quarantined_mask,
        )
    {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ticket {
    pub slot: u16,
    pub generation: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Reserved,
    Runnable,
    Exiting,
    Reapable,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Row {
    request: Request,
    ticket: Ticket,
    state: State,
    references: u16,
    tlb_pending: u64,
    dma_pins: u16,
}
/// Bounded ledger of request receipts. Terminal records are deliberately
/// retained, so a repeated request ID cannot create a second task.
pub struct SpawnLedger<const N: usize> {
    rows: [Option<Row>; N],
}
impl<const N: usize> Default for SpawnLedger<N> {
    fn default() -> Self {
        Self::new()
    }
}
impl<const N: usize> SpawnLedger<N> {
    pub const fn new() -> Self {
        Self { rows: [None; N] }
    }
    pub fn admit(&mut self, request: Request, authority: VerifiedSpawn) -> Result<Ticket, Error> {
        if request.id == 0 || request.caller == 0 || request.group >= 16 {
            return Err(Error::Invalid);
        }
        if let Some(row) = self
            .rows
            .iter()
            .flatten()
            .find(|r| r.request.id == request.id)
        {
            if row.request != request {
                return Err(Error::Conflict);
            }
            // Matching an old id is not authorization to see or reuse its receipt.
            if !authority.permits(request) {
                return Err(Error::Unauthorized);
            }
            return Ok(row.ticket);
        }
        if !authority.permits(request) {
            return Err(Error::Unauthorized);
        }
        let at = self
            .rows
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let slot = u16::try_from(at).map_err(|_| Error::Capacity)?;
        let ticket = Ticket {
            slot,
            generation: 1,
        };
        self.rows[at] = Some(Row {
            request,
            ticket,
            state: State::Reserved,
            references: 0,
            tlb_pending: 0,
            dma_pins: 0,
        });
        Ok(ticket)
    }
    fn row_mut(&mut self, ticket: Ticket) -> Result<&mut Row, Error> {
        let row = self
            .rows
            .get_mut(ticket.slot as usize)
            .and_then(Option::as_mut)
            .ok_or(Error::Stale)?;
        if row.ticket != ticket {
            return Err(Error::Stale);
        }
        Ok(row)
    }
    pub fn state(&self, ticket: Ticket) -> Result<State, Error> {
        let row = self
            .rows
            .get(ticket.slot as usize)
            .and_then(Option::as_ref)
            .ok_or(Error::Stale)?;
        if row.ticket != ticket {
            return Err(Error::Stale);
        }
        Ok(row.state)
    }
    pub fn publish_runnable(
        &mut self,
        ticket: Ticket,
        authority: VerifiedSpawn,
    ) -> Result<(), Error> {
        let row = self.row_mut(ticket)?;
        if row.state != State::Reserved {
            return Err(Error::Busy);
        }
        if !authority.permits(row.request) {
            return Err(Error::Unauthorized);
        }
        row.state = State::Runnable;
        Ok(())
    }
    pub fn hold_ref(&mut self, ticket: Ticket) -> Result<(), Error> {
        let row = self.row_mut(ticket)?;
        if row.state != State::Runnable {
            return Err(Error::Busy);
        }
        row.references = row.references.checked_add(1).ok_or(Error::Exhausted)?;
        Ok(())
    }
    pub fn end_ref(&mut self, ticket: Ticket) -> Result<(), Error> {
        let row = self.row_mut(ticket)?;
        row.references = row.references.checked_sub(1).ok_or(Error::Invalid)?;
        Ok(())
    }
    pub fn begin_exit(
        &mut self,
        ticket: Ticket,
        tlb_pending: u64,
        dma_pins: u16,
    ) -> Result<(), Error> {
        let row = self.row_mut(ticket)?;
        if row.state != State::Runnable && row.state != State::Reserved {
            return Err(Error::Busy);
        }
        row.state = State::Exiting;
        row.tlb_pending = tlb_pending;
        row.dma_pins = dma_pins;
        Ok(())
    }
    pub fn ack_tlb(&mut self, ticket: Ticket, cpu: u8) -> Result<(), Error> {
        let row = self.row_mut(ticket)?;
        if row.state != State::Exiting {
            return Err(Error::Busy);
        }
        let bit = 1u64.checked_shl(cpu as u32).ok_or(Error::Invalid)?;
        if row.tlb_pending & bit == 0 {
            return Err(Error::Stale);
        }
        row.tlb_pending &= !bit;
        Ok(())
    }
    pub fn dma_done(&mut self, ticket: Ticket) -> Result<(), Error> {
        let row = self.row_mut(ticket)?;
        if row.state != State::Exiting {
            return Err(Error::Busy);
        }
        row.dma_pins = row.dma_pins.checked_sub(1).ok_or(Error::Invalid)?;
        Ok(())
    }
    pub fn mark_reapable(&mut self, ticket: Ticket) -> Result<(), Error> {
        let row = self.row_mut(ticket)?;
        if row.state != State::Exiting {
            return Err(Error::Busy);
        }
        if row.references != 0 || row.tlb_pending != 0 || row.dma_pins != 0 {
            return Err(Error::Busy);
        }
        row.state = State::Reapable;
        Ok(())
    }
}

// ===========================================================================
// SEC-P11 — EL0 WFI/WFE/CTR_EL0/AArch32 execution-trap contract.
//
// Baseline (docs/design/baselines/v0.19.9-implementation-spec.txt):
//   * SEC-P11 acceptance row, L8745–8751: "WFI/WFE、CTR_EL0 及 AArch32 向量 →
//     合法陷入 ELR+4、yield/只读模拟；AArch32 拒绝；保存帧不泄漏".
//   * SEC-P10, L8724–8733: attributable synchronous faults end the current
//     task while preserving in-flight obligations; restricted instructions
//     cannot alter privileged state; unattributable SError is never faked as
//     a task error.
//   * 主§2.1.1, L449–458: EL0 CTR_EL0 access trapped by UCT=0 is emulated by
//     EL1 as a read-only value with ELR advanced (not a general illegal
//     instruction exit); lower-EL AArch32 vectors offer no continuation path
//     and enter controlled fail-stop/isolation with ESR evidence preserved.
//   * 主§2.2.1 SCTLR_EL1 baseline, L535: nTWI=0/nTWE=0/UCT=0 trap the EL0
//     WFI/WFE/CTR restricted paths.
//   * 16-vector dispatch matrix, L696–840: lower-EL AArch64 sync = SVC64 →
//     syscall, WFI/WFE confirmed → ELR+4 + yield, CTR_EL0 → read-only emulate
//     + ELR+4, other sync attributed by ESR/FAR; lower-EL AArch32 (all four
//     kinds) and current-EL/SP_EL0 (all four kinds) → controlled fail-stop.
//   * SEC-S implementation contract, L10515–10523: EL0 AArch32 rejected;
//     before ERET force SPSR.M[4:0]=0 and PSTATE.SS=0, restore every saved
//     EL0 GPR except the x0 return value; kernel temporaries never return to
//     user; WFI/WFE confirmed → saved ELR checked+4 + bounded yield, no
//     repeat trap.
//
// CONTRACT-ONLY host model. The native EL1 vector wiring (exceptions.rs /
// ERET stub) is a later step; nothing here touches hardware. The ESR_EL1 bit
// layouts below are ARMv8-A architectural encodings (ARM DDI 0487, ESR_EL1
// EC/IL/ISS), NOT invented protocol bytes: the baseline fixes the *policy*,
// the architecture fixes the *syndrome layout*. Unspecified details are
// marked inline (frozen CTR value, fault attribution, WFxT absence).
// ===========================================================================

/// The four exception-vector source classes of the 主§2.2.1 16-vector matrix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrapSource {
    CurrentElSpEl0,
    CurrentElSpElx,
    LowerElAarch64,
    LowerElAarch32,
}

/// The four exception kinds of the matrix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrapKind {
    Sync,
    Irq,
    Fiq,
    SError,
}

// ESR_EL1 architectural fields (ARM DDI 0487). EC = bits[31:26], IL = bit[25],
// ISS = bits[24:0]. The SVC64 value mirrors the encoding already gated by
// security::syscall_v3::decode_aarch64_svc_v3 (0x5600_0000).
const ESR_EC_SHIFT: u32 = 26;
const ESR_IL: u64 = 1 << 25;
const ESR_ISS_MASK: u64 = (1 << 25) - 1;
const EC_UNKNOWN: u64 = 0x00;
const EC_WFI_WFE: u64 = 0x01;
const EC_SVC64: u64 = 0x15;
const EC_MSR_MRS: u64 = 0x18;
// Lower-EL AArch64 synchronous fault classes attributable to the task once the
// native adapter verifies ESR/FAR (主§2.1.1). Same-EL abort ECs (0x21/0x25)
// are deliberately excluded: from a lower-EL source they are unconfirmed.
const EC_INSTR_ABORT_LOWER: u64 = 0x20;
const EC_PC_ALIGNMENT: u64 = 0x22;
const EC_DATA_ABORT_LOWER: u64 = 0x24;
const EC_SP_ALIGNMENT: u64 = 0x26;
const EC_BRK_AARCH64: u64 = 0x3C;
/// EC=0x15, IL=1, ISS immediate=0, RES0 — identical to syscall_v3's SVC64 gate.
const ESR_SVC64: u64 = (EC_SVC64 << ESR_EC_SHIFT) | ESR_IL;

/// Classification of a lower-EL AArch64 *synchronous* syndrome. Pure function
/// of the saved ESR_EL1; `Unconfirmed` is the fail-closed bucket for anything
/// the contract cannot positively identify.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum El0SyncClass {
    /// SVC64 → the existing ABI v3 preflight (security::syscall_v3).
    Svc64,
    /// Confirmed trapped WFI (wfe=false) or WFE (wfe=true).
    Wfx { wfe: bool },
    /// Confirmed trapped MRS read of CTR_EL0 into GPR `rt` (0..=30).
    CtrEl0Read { rt: u8 },
    /// Known EL0 synchronous fault class; the native adapter MUST verify
    /// ESR/FAR attribution before the terminate-task policy is applied
    /// (主§2.1.1). Unattributable faults escalate to fail-stop, not here.
    Fault,
    /// Unknown reason, illegal execution state, malformed/reserved ISS, or
    /// any syndrome the contract cannot confirm → fail closed.
    Unconfirmed,
}

/// Pure ESR classification for the lower-EL AArch64 synchronous vector.
pub fn classify_el0_sync(esr: u64) -> El0SyncClass {
    let ec = esr >> ESR_EC_SHIFT;
    let il = esr & ESR_IL != 0;
    let iss = esr & ESR_ISS_MASK;
    // Every confirmed instruction trap here is a 32-bit AArch64 instruction.
    if !il {
        return El0SyncClass::Unconfirmed;
    }
    match ec {
        EC_SVC64 if esr == ESR_SVC64 => El0SyncClass::Svc64,
        EC_WFI_WFE => {
            // ISS TI[1:0]: 0b00=WFI, 0b01=WFE; all other ISS bits RES0.
            // A53 is ARMv8.0: FEAT_WFxT (WFET/WFIT, extended ISS) does not
            // exist, so any nonzero upper ISS or reserved TI is unconfirmed.
            if iss & !0b11 != 0 {
                return El0SyncClass::Unconfirmed;
            }
            match iss & 0b11 {
                0b00 => El0SyncClass::Wfx { wfe: false },
                0b01 => El0SyncClass::Wfx { wfe: true },
                _ => El0SyncClass::Unconfirmed,
            }
        }
        EC_MSR_MRS => {
            // ISS for EC=0x18 (ARM DDI 0487): Op0[21:20], Op2[19:17],
            // Op1[16:14], CRn[13:10], Rt[9:5], CRm[4:1], Direction[0]
            // (1=MRS read, 0=MSR write). CTR_EL0 = op0=3,op1=3,CRn=0,CRm=0,
            // op2=1. Only a *read* of exactly CTR_EL0 is emulated; the fixed
            // field mask/value below exclude Rt, which selects the target GPR.
            const CTR_FIXED_MASK: u64 = 0x003F_FC1F;
            const CTR_READ_VALUE: u64 = 0x0032_C001;
            if iss & CTR_FIXED_MASK != CTR_READ_VALUE {
                return El0SyncClass::Unconfirmed;
            }
            let rt = ((iss >> 5) & 0x1F) as u8;
            // Rt=31 (XZR) is not a writable destination → fail closed.
            if rt > 30 {
                return El0SyncClass::Unconfirmed;
            }
            El0SyncClass::CtrEl0Read { rt }
        }
        EC_INSTR_ABORT_LOWER | EC_PC_ALIGNMENT | EC_DATA_ABORT_LOWER | EC_SP_ALIGNMENT
        | EC_BRK_AARCH64 => El0SyncClass::Fault,
        // EC=0x00 "Unknown reason" is explicitly fail-closed, never a benign
        // yield; any other unrecognised EC falls through to the same bucket.
        EC_UNKNOWN => El0SyncClass::Unconfirmed,
        _ => El0SyncClass::Unconfirmed,
    }
}

/// Policy outcome of an exception vector. Pure decision; the native handler
/// installs it. `FailStop` means controlled global safe-stop / reliable
/// isolation with ESR evidence preserved — never a return to the EL0 task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrapDecision {
    /// SVC64: dispatch to the ABI v3 preflight; only x0 may later change.
    Syscall,
    /// Confirmed WFI/WFE: resume at checked ELR+4 and perform a bounded yield.
    /// The strict forward advance is what guarantees "no repeat trap".
    Yield { resume_elr: u64 },
    /// Confirmed CTR_EL0 read: write the frozen read-only `value` into saved
    /// GPR `rt`, resume at checked ELR+4. No privileged state changes.
    EmulateCtr { resume_elr: u64, rt: u8, value: u64 },
    /// Attributable EL0 synchronous fault: task → EXITING, in-flight
    /// obligations preserved (SEC-P10). No resume to EL0.
    TerminateTask,
    /// AArch32 / current-EL SP_EL0 / SError / unconfirmed syndrome / ELR
    /// overflow: controlled fail-stop or reliable isolation. No resume.
    FailStop,
    /// Lower-EL AArch64 IRQ/FIQ and current-EL SP_ELx IRQ: the GIC/FIQ
    /// protocol (SEC-D), not a P11 execution trap. No EL0 task termination.
    IrqProtocol,
}

/// Pure policy decision over the 16-vector matrix. `frozen_ctr` is the
/// platform-supplied read-only CTR_EL0 value (UNSPECIFIED in the baseline —
/// 主§2.2.1 fixes the register baseline, not the emulated value; the trusted
/// platform adapter supplies it, and it is used only for a confirmed CTR read).
pub fn decide_trap(
    source: TrapSource,
    kind: TrapKind,
    esr: u64,
    elr: u64,
    frozen_ctr: u64,
) -> TrapDecision {
    // Forbidden vector classes fail closed for EVERY kind (matrix L696–840).
    match source {
        // Lower-EL AArch32 offers no continuation path for any kind.
        TrapSource::LowerElAarch32 => return TrapDecision::FailStop,
        // Current EL with SP_EL0 is uniformly forbidden.
        TrapSource::CurrentElSpEl0 => return TrapDecision::FailStop,
        _ => {}
    }
    // SError is asynchronous and never attributed to the current task by
    // default; isolate first (SEC-P10 / matrix). Fail closed in the model.
    if kind == TrapKind::SError {
        return TrapDecision::FailStop;
    }
    match (source, kind) {
        (TrapSource::LowerElAarch64, TrapKind::Sync) => match classify_el0_sync(esr) {
            El0SyncClass::Svc64 => TrapDecision::Syscall,
            El0SyncClass::Wfx { .. } => match elr.checked_add(4) {
                Some(resume_elr) => TrapDecision::Yield { resume_elr },
                // checked+4 overflow must never wrap into a re-trap.
                None => TrapDecision::FailStop,
            },
            El0SyncClass::CtrEl0Read { rt } => match elr.checked_add(4) {
                Some(resume_elr) => TrapDecision::EmulateCtr {
                    resume_elr,
                    rt,
                    value: frozen_ctr,
                },
                None => TrapDecision::FailStop,
            },
            El0SyncClass::Fault => TrapDecision::TerminateTask,
            El0SyncClass::Unconfirmed => TrapDecision::FailStop,
        },
        // EL1 SP_ELx sync: scratch/SP-guard/emergency is native; fail closed.
        (TrapSource::CurrentElSpElx, TrapKind::Sync) => TrapDecision::FailStop,
        // FIQ delivery is not enabled in the prototype; arrival → controlled stop.
        (_, TrapKind::Fiq) => TrapDecision::FailStop,
        // Legitimate IRQ paths follow the GIC protocol, not an execution trap.
        (TrapSource::LowerElAarch64, TrapKind::Irq) => TrapDecision::IrqProtocol,
        (TrapSource::CurrentElSpElx, TrapKind::Irq) => TrapDecision::IrqProtocol,
        // Remaining combinations are covered above; fail closed rather than
        // fall through to a default empty stub (SEC-S contract L10515).
        _ => TrapDecision::FailStop,
    }
}

/// Minimal saved EL0 context for the no-leak contract (主§2.2 / SEC-S contract
/// L10517–10519). x[0..31] are the saved EL0 GPRs (x30=LR), sp_el0 the user
/// stack, elr the resume PC, spsr the saved PSTATE. The native frame also
/// carries FP/SIMD and TPIDR_EL0; those are restored verbatim by the native
/// stub and are never written by this contract, so they are not modeled here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SavedEl0Frame {
    pub x: [u64; 31],
    pub sp_el0: u64,
    pub elr: u64,
    pub spsr: u64,
}

// SPSR/PSTATE bits sanitized before any ERET to EL0 (SEC-S contract L10517):
// M[4:0]=0b00000 (AArch64 EL0t) and SS (bit 21)=0.
const SPSR_M_MASK: u64 = 0x1F;
const SPSR_SS: u64 = 1 << 21;

/// Apply a resumable trap decision to the saved frame, enforcing the no-leak
/// rule: ONLY the designated fields may change (elr for Yield; elr + x[rt] for
/// CTR emulation). Every other GPR and sp_el0 is restored verbatim; kernel
/// temporaries are never written back. For Syscall the GPRs are restored
/// verbatim and the ABI dispatch owns the sole x0 result and the resume PC.
/// SPSR is sanitized (M[4:0]=0, SS=0) before return. Non-resumable decisions
/// (TerminateTask/FailStop/IrqProtocol) have no ERET-to-EL0 path and are
/// rejected.
pub fn resume_frame(frame: SavedEl0Frame, decision: TrapDecision) -> Result<SavedEl0Frame, Error> {
    let mut out = frame;
    match decision {
        TrapDecision::Yield { resume_elr } => {
            // The decision must carry the checked ELR+4 of THIS frame; a
            // mismatch means the handler would resume at the wrong PC.
            if resume_elr != frame.elr.checked_add(4).ok_or(Error::Invalid)? {
                return Err(Error::Invalid);
            }
            out.elr = resume_elr;
        }
        TrapDecision::EmulateCtr {
            resume_elr,
            rt,
            value,
        } => {
            if rt > 30 || resume_elr != frame.elr.checked_add(4).ok_or(Error::Invalid)? {
                return Err(Error::Invalid);
            }
            out.x[rt as usize] = value;
            out.elr = resume_elr;
        }
        TrapDecision::Syscall => {
            // Registers restored verbatim; the ABI dispatch writes only x0
            // afterwards. No kernel temporary is carried back here.
        }
        TrapDecision::TerminateTask | TrapDecision::FailStop | TrapDecision::IrqProtocol => {
            return Err(Error::Invalid);
        }
    }
    // Force AArch64 EL0t and clear software step before ERET.
    out.spsr &= !(SPSR_M_MASK | SPSR_SS);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn req(id: u64) -> Request {
        Request {
            id,
            caller: 7,
            group: 2,
            package: [5; 32],
            cpu: 2,
        }
    }
    fn cap() -> VerifiedSpawn {
        VerifiedSpawn::from_registry(7, 2, [5; 32], 0b1110, 0b1110, 0, 0)
    }
    #[test]
    fn sec_p01_unauthorized_package_and_caller() {
        let mut ledger = SpawnLedger::<2>::new();
        let mut input = req(1);
        input.package = [9; 32];
        assert_eq!(ledger.admit(input, cap()), Err(Error::Unauthorized));
        input = req(1);
        input.caller = 8;
        assert_eq!(ledger.admit(input, cap()), Err(Error::Unauthorized));
        assert_eq!(ledger.rows.iter().flatten().count(), 0);
    }
    #[test]
    fn sec_p02_idempotent_retries_and_conflict() {
        let mut l = SpawnLedger::<2>::new();
        let t = l.admit(req(1), cap()).unwrap();
        for _ in 0..100 {
            assert_eq!(l.admit(req(1), cap()), Ok(t));
        }
        let revoked = VerifiedSpawn::from_registry(7, 2, [9; 32], 0b1110, 0b1110, 0, 0);
        assert_eq!(l.admit(req(1), revoked), Err(Error::Unauthorized));
        let mut conflict = req(1);
        conflict.package = [4; 32];
        assert_eq!(l.admit(conflict, cap()), Err(Error::Conflict));
    }
    #[test]
    fn sec_p03_capacity_and_no_hidden_slot() {
        let mut l = SpawnLedger::<1>::new();
        l.admit(req(1), cap()).unwrap();
        assert_eq!(l.admit(req(2), cap()), Err(Error::Capacity));
    }
    #[test]
    fn sec_p04_stale_ticket_fails() {
        let mut l = SpawnLedger::<2>::new();
        let t = l.admit(req(1), cap()).unwrap();
        assert_eq!(l.state(Ticket { generation: 2, ..t }), Err(Error::Stale));
    }
    #[test]
    fn sec_p05_exit_waits_for_refs_and_tlb() {
        let mut l = SpawnLedger::<1>::new();
        let t = l.admit(req(1), cap()).unwrap();
        l.publish_runnable(t, cap()).unwrap();
        l.hold_ref(t).unwrap();
        l.begin_exit(t, 1 << 2, 0).unwrap();
        assert_eq!(l.mark_reapable(t), Err(Error::Busy));
        l.end_ref(t).unwrap();
        l.ack_tlb(t, 2).unwrap();
        l.mark_reapable(t).unwrap();
    }
    #[test]
    fn sec_p06_no_control_or_draining_cpu() {
        let mut l = SpawnLedger::<1>::new();
        let denied = VerifiedSpawn::from_registry(7, 2, [5; 32], 0b0001, 0b1111, 0, 0);
        assert_eq!(l.admit(req(1), denied), Err(Error::Unauthorized));
        let draining = VerifiedSpawn::from_registry(7, 2, [5; 32], 0b1110, 0b1111, 1 << 2, 0);
        assert_eq!(l.admit(req(1), draining), Err(Error::Unauthorized));
    }
    #[test]
    fn v020_sec_p06_bad_registry_cannot_make_cpu0_business() {
        let mut l = SpawnLedger::<2>::new();
        let misclassified = VerifiedSpawn::from_registry(7, 2, [5; 32], u64::MAX, u64::MAX, 0, 0);
        // CPU0 is the control core; even an all-ones mask cannot make it business.
        let mut input = req(1);
        input.cpu = 0;
        assert_eq!(l.admit(input, misclassified), Err(Error::Unauthorized));
        // A business mask with bits outside CPU1-3 fails closed on every core.
        assert_eq!(l.admit(req(7), misclassified), Err(Error::Unauthorized));
        assert_eq!(l.rows.iter().flatten().count(), 0);
        // CPU1 is now legal business with a correct CPU1-3 mask.
        let good = VerifiedSpawn::from_registry(7, 2, [5; 32], 0b1110, 0b1110, 0, 0);
        let mut cpu1 = req(2);
        cpu1.cpu = 1;
        assert!(l.admit(cpu1, good).is_ok());
    }
    #[test]
    fn v0199_business_placement_and_spawn_use_fixed_cpu0_boundary() {
        let mut ledger = SpawnLedger::<3>::new();
        let authority = VerifiedSpawn::from_registry_v0199(7, 2, [5; 32], 0b1110, 0b1111, 0, 0);
        for cpu in 1..=3 {
            let mut input = req(u64::from(cpu));
            input.cpu = cpu;
            let ticket = ledger.admit(input, authority).unwrap();
            ledger.publish_runnable(ticket, authority).unwrap();
        }
        for cpu in [0, 4, 63, 64, u16::MAX] {
            assert_eq!(
                authorize_business_core_v0199(cpu, 1, u64::MAX, u64::MAX, 0, 0),
                Err(Error::Unauthorized)
            );
        }
        assert_eq!(
            authorize_business_core_v0199(1, 1, 0b1110, 0b1111, 0, 0),
            Ok(())
        );
        assert_eq!(
            authorize_business_core_v0199(1, 0, 0b1110, 0b1111, 0, 0),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            authorize_business_core_v0199(1, 1, 0b1110, 0b1111, 2, 0),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            authorize_business_core_v0199(1, 1, 0b1110, 0b1111, 0, 2),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            authorize_business_core_v0199(1, 1, 0b1111, 0b1111, 0, 0),
            Err(Error::Unauthorized)
        );
    }
    #[test]
    fn sec_p07_exiting_cannot_take_new_references() {
        let mut l = SpawnLedger::<1>::new();
        let t = l.admit(req(1), cap()).unwrap();
        l.publish_runnable(t, cap()).unwrap();
        l.begin_exit(t, 0, 0).unwrap();
        assert_eq!(l.hold_ref(t), Err(Error::Busy));
    }
    #[test]
    fn native_business_core_guard_refuses_draining_quarantine_and_wrong_generation() {
        assert_eq!(authorize_business_core(2, 1, 0b1100, 0b1100, 0, 0), Ok(()));
        assert_eq!(
            authorize_business_core(2, 0, 0b1100, 0b1100, 0, 0),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            authorize_business_core(2, 1, 0b1100, 0b1100, 0b0100, 0),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            authorize_business_core(2, 1, 0b1100, 0b1100, 0, 0b0100),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            authorize_business_core(1, 1, 0b1100, 0b1100, 0, 0),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            authorize_business_core(64, 1, u64::MAX, u64::MAX, 0, 0),
            Err(Error::Unauthorized)
        );
    }
    #[test]
    fn v020_sec_p06_protected_cpu0_misclassification_fails_closed() {
        assert_eq!(
            authorize_business_core(0, 1, u64::MAX, u64::MAX, 0, 0),
            Err(Error::Unauthorized)
        );
        // A misclassified all-ones business mask fails closed even for CPU1.
        assert_eq!(
            authorize_business_core(1, 1, u64::MAX, u64::MAX, 0, 0),
            Err(Error::Unauthorized)
        );
        // CPU1-3 are legal business with a correct CPU1-3 mask.
        assert_eq!(authorize_business_core(1, 1, 0b1110, 0b1110, 0, 0), Ok(()));
        assert_eq!(authorize_business_core(2, 1, 0b1100, 0b1100, 0, 0), Ok(()));
        assert_eq!(authorize_business_core(3, 1, 0b1110, 0b1110, 0, 0), Ok(()));
    }
    #[test]
    fn sec_p08_no_ai_required_for_local_admission() {
        let mut l = SpawnLedger::<1>::new();
        let t = l.admit(req(1), cap()).unwrap();
        l.publish_runnable(t, cap()).unwrap();
        assert_eq!(l.state(t), Ok(State::Runnable));
    }

    // ---- SEC-P11: WFI/WFE/CTR_EL0/AArch32 execution-trap contract ----
    fn frame(elr: u64) -> SavedEl0Frame {
        let mut x = [0u64; 31];
        for (i, v) in x.iter_mut().enumerate() {
            *v = 0xDEAD_0000_0000_0000u64 | i as u64; // distinct sentinels
        }
        // Dirty SPSR: nonzero M[4:0], SS set, DAIF frozen bits present.
        SavedEl0Frame {
            x,
            sp_el0: 0x5050_5050,
            elr,
            spsr: SPSR_M_MASK | SPSR_SS | 0x3C0,
        }
    }
    fn esr_wfx(wfe: bool) -> u64 {
        (EC_WFI_WFE << ESR_EC_SHIFT) | ESR_IL | u64::from(wfe)
    }
    fn esr_ctr_read(rt: u64) -> u64 {
        (EC_MSR_MRS << ESR_EC_SHIFT) | ESR_IL | 0x0032_C001 | (rt << 5)
    }
    #[test]
    fn sec_p11_wfi_wfe_confirmed_elr_plus4_and_yield() {
        for wfe in [false, true] {
            let esr = esr_wfx(wfe);
            assert_eq!(classify_el0_sync(esr), El0SyncClass::Wfx { wfe });
            let f = frame(0x1000);
            let d = decide_trap(TrapSource::LowerElAarch64, TrapKind::Sync, esr, f.elr, 0);
            assert_eq!(d, TrapDecision::Yield { resume_elr: 0x1004 });
            let out = resume_frame(f, d).unwrap();
            assert_eq!(out.elr, 0x1004);
            assert_eq!(out.x, f.x); // a yield touches no GPR
            assert_eq!(out.sp_el0, f.sp_el0);
            assert_eq!(out.spsr & (SPSR_M_MASK | SPSR_SS), 0); // sanitized
        }
    }
    #[test]
    fn sec_p11_wfi_elr_overflow_fails_closed() {
        for elr in [u64::MAX - 3, u64::MAX - 1, u64::MAX] {
            let d = decide_trap(
                TrapSource::LowerElAarch64,
                TrapKind::Sync,
                esr_wfx(false),
                elr,
                0,
            );
            assert_eq!(d, TrapDecision::FailStop);
        }
        // checked+4 that does not overflow still yields.
        let d = decide_trap(
            TrapSource::LowerElAarch64,
            TrapKind::Sync,
            esr_wfx(false),
            u64::MAX - 4,
            0,
        );
        assert_eq!(
            d,
            TrapDecision::Yield {
                resume_elr: u64::MAX
            }
        );
    }
    #[test]
    fn sec_p11_unconfirmed_wfx_syndrome_fails_closed() {
        let base = (EC_WFI_WFE << ESR_EC_SHIFT) | ESR_IL;
        // Reserved TI values, a WFxT-style upper ISS bit, and IL=0.
        for bad in [base | 0b10, base | 0b11, base | (1 << 2), base & !ESR_IL] {
            assert_eq!(classify_el0_sync(bad), El0SyncClass::Unconfirmed);
            assert_eq!(
                decide_trap(TrapSource::LowerElAarch64, TrapKind::Sync, bad, 0x1000, 0),
                TrapDecision::FailStop
            );
        }
    }
    #[test]
    fn sec_p11_ctr_el0_readonly_emulation_no_privileged_change() {
        let frozen = 0x0000_0000_8000_0000u64; // platform-supplied read-only value
        let esr = esr_ctr_read(5);
        assert_eq!(classify_el0_sync(esr), El0SyncClass::CtrEl0Read { rt: 5 });
        let f = frame(0x2000);
        let d = decide_trap(
            TrapSource::LowerElAarch64,
            TrapKind::Sync,
            esr,
            f.elr,
            frozen,
        );
        assert_eq!(
            d,
            TrapDecision::EmulateCtr {
                resume_elr: 0x2004,
                rt: 5,
                value: frozen
            }
        );
        let out = resume_frame(f, d).unwrap();
        assert_eq!(out.elr, 0x2004);
        assert_eq!(out.x[5], frozen);
        for i in 0..31 {
            if i != 5 {
                assert_eq!(out.x[i], f.x[i]);
            }
        }
        assert_eq!(out.sp_el0, f.sp_el0);
        assert_eq!(out.spsr & (SPSR_M_MASK | SPSR_SS), 0);
    }
    #[test]
    fn sec_p11_ctr_write_wrong_reg_or_xzr_fails_closed() {
        // MSR (write, Direction=0) is not emulated.
        let write = (EC_MSR_MRS << ESR_EC_SHIFT) | ESR_IL | 0x0032_C000;
        assert_eq!(classify_el0_sync(write), El0SyncClass::Unconfirmed);
        // A different system register (MIDR_EL1 op0=3,op1=0,CRn=0,CRm=0,op2=0).
        let midr = (EC_MSR_MRS << ESR_EC_SHIFT) | ESR_IL | (3 << 20) | 1;
        assert_eq!(classify_el0_sync(midr), El0SyncClass::Unconfirmed);
        // Rt=31 (XZR) fails closed.
        assert_eq!(
            classify_el0_sync(esr_ctr_read(31)),
            El0SyncClass::Unconfirmed
        );
        for bad in [write, midr, esr_ctr_read(31)] {
            assert_eq!(
                decide_trap(TrapSource::LowerElAarch64, TrapKind::Sync, bad, 0x1000, 0),
                TrapDecision::FailStop
            );
        }
    }
    #[test]
    fn sec_p11_aarch32_every_vector_fails_stop_no_continuation() {
        for kind in [
            TrapKind::Sync,
            TrapKind::Irq,
            TrapKind::Fiq,
            TrapKind::SError,
        ] {
            let d = decide_trap(TrapSource::LowerElAarch32, kind, esr_wfx(false), 0x1000, 0);
            assert_eq!(d, TrapDecision::FailStop);
            // No return to the EL0 task is possible.
            assert!(resume_frame(frame(0x1000), d).is_err());
        }
    }
    #[test]
    fn sec_p11_forbidden_vectors_and_serror_fail_stop() {
        for kind in [
            TrapKind::Sync,
            TrapKind::Irq,
            TrapKind::Fiq,
            TrapKind::SError,
        ] {
            assert_eq!(
                decide_trap(TrapSource::CurrentElSpEl0, kind, 0, 0, 0),
                TrapDecision::FailStop
            );
        }
        for src in [TrapSource::CurrentElSpElx, TrapSource::LowerElAarch64] {
            assert_eq!(
                decide_trap(src, TrapKind::SError, 0, 0, 0),
                TrapDecision::FailStop
            );
        }
        // EL1 SP_ELx synchronous faults fail closed (emergency/SP-guard is native).
        assert_eq!(
            decide_trap(TrapSource::CurrentElSpElx, TrapKind::Sync, 0, 0, 0),
            TrapDecision::FailStop
        );
    }
    #[test]
    fn sec_p11_saved_frame_no_kernel_temporary_leak() {
        let f = frame(0x3000);
        let yield_out = resume_frame(f, TrapDecision::Yield { resume_elr: 0x3004 }).unwrap();
        assert_eq!(yield_out.spsr & (SPSR_M_MASK | SPSR_SS), 0);
        assert_eq!(yield_out.x, f.x);
        assert_eq!(yield_out.sp_el0, f.sp_el0);
        let ctr_out = resume_frame(
            f,
            TrapDecision::EmulateCtr {
                resume_elr: 0x3004,
                rt: 9,
                value: 7,
            },
        )
        .unwrap();
        assert_eq!(ctr_out.x[9], 7);
        for i in 0..31 {
            if i != 9 {
                assert_eq!(ctr_out.x[i], f.x[i]);
            }
        }
        assert_eq!(ctr_out.sp_el0, f.sp_el0);
        // Syscall path restores GPRs verbatim; x0/resume PC are ABI-owned.
        let svc_out = resume_frame(f, TrapDecision::Syscall).unwrap();
        assert_eq!(svc_out.x, f.x);
        assert_eq!(svc_out.sp_el0, f.sp_el0);
        assert_eq!(svc_out.spsr & (SPSR_M_MASK | SPSR_SS), 0);
        // A decision whose resume_elr does not match this frame is rejected.
        assert!(resume_frame(f, TrapDecision::Yield { resume_elr: 0x9999 }).is_err());
    }
    #[test]
    fn sec_p11_svc64_routes_to_syscall_and_faults_terminate() {
        assert_eq!(classify_el0_sync(ESR_SVC64), El0SyncClass::Svc64);
        assert_eq!(
            decide_trap(
                TrapSource::LowerElAarch64,
                TrapKind::Sync,
                ESR_SVC64,
                0x1000,
                0
            ),
            TrapDecision::Syscall
        );
        // Attributable EL0 data abort → task termination (native verifies ESR/FAR).
        let abort = (EC_DATA_ABORT_LOWER << ESR_EC_SHIFT) | ESR_IL;
        assert_eq!(classify_el0_sync(abort), El0SyncClass::Fault);
        assert_eq!(
            decide_trap(TrapSource::LowerElAarch64, TrapKind::Sync, abort, 0x1000, 0),
            TrapDecision::TerminateTask
        );
        assert!(resume_frame(frame(0x1000), TrapDecision::TerminateTask).is_err());
        // Unknown syndrome → fail closed, never a benign yield.
        let unknown = (EC_UNKNOWN << ESR_EC_SHIFT) | ESR_IL;
        assert_eq!(classify_el0_sync(unknown), El0SyncClass::Unconfirmed);
        assert_eq!(
            decide_trap(
                TrapSource::LowerElAarch64,
                TrapKind::Sync,
                unknown,
                0x1000,
                0
            ),
            TrapDecision::FailStop
        );
    }
    #[test]
    fn sec_p11_no_retrap_strict_forward_progress() {
        let f = frame(0x4000);
        let d = decide_trap(
            TrapSource::LowerElAarch64,
            TrapKind::Sync,
            esr_wfx(false),
            f.elr,
            0,
        );
        let out = resume_frame(f, d).unwrap();
        // ELR strictly advances past the trapping instruction (no repeat trap).
        assert!(out.elr > f.elr);
        assert_eq!(out.elr, f.elr + 4);
        // Resuming at the next instruction (a SVC) is a different decision,
        // so the handler cannot loop re-trapping the same WFI.
        let next = decide_trap(
            TrapSource::LowerElAarch64,
            TrapKind::Sync,
            ESR_SVC64,
            out.elr,
            0,
        );
        assert_eq!(next, TrapDecision::Syscall);
    }
}
