//! SEC-M: bounded mapping checks and non-forgetting TLB/DMA retirement.
//! This is not a hardware PTE flusher or a replacement for the platform ledger.
use super::Error;

pub const PAGE_SIZE: u64 = 4096;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameKind {
    User,
    Kernel,
    Control,
    Recovery,
    Device,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Frame {
    pub owner: u64,
    pub generation: u64,
    pub kind: FrameKind,
    pub zeroed: bool,
    /// Any writable/executable alias of the same physical frame must count.
    pub writable_alias: bool,
    pub executable_alias: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}
/// An EL1 registry-owned shared-memory permission, not a caller boolean.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SharedGrant {
    owner: u64,
    grantee: u64,
    frame_generation: u64,
}
impl SharedGrant {
    #[allow(dead_code)]
    pub(crate) const fn from_registry(owner: u64, grantee: u64, frame_generation: u64) -> Self {
        Self {
            owner,
            grantee,
            frame_generation,
        }
    }
}
pub fn authorize_mapping(
    frame: Frame,
    caller: u64,
    rights: Permissions,
    shared: Option<SharedGrant>,
) -> Result<(), Error> {
    if caller == 0 || frame.owner == 0 || frame.generation == 0 || frame.kind != FrameKind::User {
        return Err(Error::Unauthorized);
    }
    if frame.owner != caller
        && !shared.is_some_and(|g| {
            g.owner == frame.owner && g.grantee == caller && g.frame_generation == frame.generation
        })
    {
        return Err(Error::Unauthorized);
    }
    if !frame.zeroed {
        return Err(Error::Busy);
    }
    if (rights.write && (rights.execute || frame.executable_alias))
        || (rights.execute && frame.writable_alias)
    {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
pub fn checked_user_span(
    base: u64,
    length: usize,
    window_base: u64,
    window_end: u64,
) -> Result<(u64, u64), Error> {
    if length == 0 || window_base >= window_end {
        return Err(Error::Invalid);
    }
    let length = u64::try_from(length).map_err(|_| Error::Invalid)?;
    let end = base.checked_add(length).ok_or(Error::Invalid)?;
    if base < window_base || end > window_end {
        return Err(Error::Unauthorized);
    }
    Ok((base, end))
}

/// The privileged mapper may only publish ordinary data/progress pool frames,
/// never the initial protected page-table or executable loader frame prefix.
/// The native memory ledger remains responsible for owner, pin and zero proofs.
pub fn authorize_data_frame_slot(
    frame: usize,
    protected_prefix_pages: usize,
    physical_pool_pages: usize,
) -> Result<(), Error> {
    if protected_prefix_pages == 0 || protected_prefix_pages >= physical_pool_pages {
        return Err(Error::Invalid);
    }
    if frame < protected_prefix_pages || frame >= physical_pool_pages {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Shootdown {
    pub request_id: u64,
    pub generation: u64,
    targets: u64,
    acknowledged: u64,
    references: u16,
    pins: u16,
    dma_inflight: u16,
    revoked: bool,
}
impl Shootdown {
    pub fn begin(
        request_id: u64,
        generation: u64,
        targets: u64,
        references: u16,
        pins: u16,
        dma_inflight: u16,
    ) -> Result<Self, Error> {
        if request_id == 0 || generation == 0 {
            return Err(Error::Invalid);
        }
        Ok(Self {
            request_id,
            generation,
            targets,
            acknowledged: 0,
            references,
            pins,
            dma_inflight,
            revoked: false,
        })
    }
    /// Native adapter must revoke page-table access and execute the required
    /// barrier BEFORE acknowledging that revocation here.
    pub fn revoke_pte(&mut self) {
        self.revoked = true;
    }
    /// A CPU's actual generation and architectural TLB completion are evidence,
    /// not an AI assertion or a message payload.
    pub fn acknowledge(&mut self, request_id: u64, generation: u64, cpu: u8) -> Result<(), Error> {
        if !self.revoked || request_id != self.request_id || generation != self.generation {
            return Err(Error::Stale);
        }
        let bit = 1u64.checked_shl(cpu as u32).ok_or(Error::Invalid)?;
        if self.targets & bit == 0 {
            return Err(Error::Unauthorized);
        }
        self.acknowledged |= bit;
        Ok(())
    }
    pub fn release_reference(&mut self) -> Result<(), Error> {
        self.references = self.references.checked_sub(1).ok_or(Error::Invalid)?;
        Ok(())
    }
    pub fn release_pin(&mut self) -> Result<(), Error> {
        if self.dma_inflight != 0 {
            return Err(Error::Busy);
        }
        self.pins = self.pins.checked_sub(1).ok_or(Error::Invalid)?;
        Ok(())
    }
    pub fn complete_dma(&mut self) -> Result<(), Error> {
        self.dma_inflight = self.dma_inflight.checked_sub(1).ok_or(Error::Invalid)?;
        Ok(())
    }
    pub fn may_reuse(&self) -> bool {
        self.revoked
            && (self.acknowledged & self.targets) == self.targets
            && self.references == 0
            && self.pins == 0
            && self.dma_inflight == 0
    }
}

// ---------------------------------------------------------------------------
// SEC-M11 — A53 no-PAN copy window contract.
//
// Baseline: 主§2.2.1 (软件 PAN / TTBR0-TTBR1 discipline), 安§3 core flows 2/4,
// SEC-M 实施契约 and acceptance SEC-M11 ("A53 无 PAN 下 EL1 误解引用用户 VA …
// 非 copy 窗口不可访问；临时映射回收后不可再访问；无悬空映射"), plus the
// closing 安§3 note that empty-TTBR0/ASID/TLB isolation + protected TTBR1
// temporary-window copies are required and "仅 EPD0 或仅依靠 Rust 不构成充分
// 保护". Proof categories: STATIC_EL1 + ARCH_A53 (+ MODEL_CHECK).
//
// The locked cortex-a53 target has no hardware PAN, so EL1 may only touch
// user memory through a verified, pinned, per-CPU TTBR1 temporary window
// while the software-PAN context holds (empty TTBR0 root, TTBR1 ASID 0,
// DAIF masked). Outside the window — TLB hot or cold, nested exception or
// not — user VA is inaccessible, and after teardown it stays inaccessible.
//
// CONTRACT ONLY: bounded pure rules modeling that discipline. The actual
// TTBR/ASID switches with ISB, DAIF sequencing, VMA/PTE/owner walks, frame
// pinning and the local TLBI/DSB/ISB on teardown are native arch gates to be
// implemented and proven later; nothing here enforces them in hardware and
// no wire bytes are defined.
// ---------------------------------------------------------------------------

/// Frozen prototype CPU count (主§13.7: 4 CPU EL1/IRQ/应急栈, 160 KiB usable).
/// Per-CPU contracts below bind to `cpu < MAX_CPUS`.
pub const MAX_CPUS: u8 = 4;

/// Contract bound for one per-CPU TTBR1 copy window. The baseline fixes the
/// window discipline (单 CPU 专属、不可跨调度, 主§13.2 fixmap) but no page
/// count; this small bounded cap keeps the temporary mapping auditable.
/// A contract limit, not a wire format.
pub const COPY_WINDOW_MAX_PAGES: u64 = 16;

/// Contract alignment for a copy span base. The baseline fixes 4 KiB page
/// alignment for mapped regions (安§3 flow 1) and 16 B for SP, but no copy
/// granularity; the contract conservatively requires natural 8-byte word
/// alignment. Byte-tail handling inside a verified span belongs to the
/// native adapter.
pub const COPY_SPAN_ALIGN: u64 = 8;

/// Evidence of the 主§2.2.1 software-PAN sequence when a copy window opens.
/// All three steps are mandatory; `epd0` alone never suffices ("EPD0 单独不
/// 构成 PAN"). Between the TTBR1-ASID-0 and empty-TTBR0 steps no user VA may
/// be accessed and DAIF stays masked; nested entries never restore the user
/// TTBR.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SoftwarePanContext {
    /// TTBR0_EL1 switched to the empty root, followed by ISB.
    pub ttbr0_empty_root: bool,
    /// TTBR1 ASID switched to kernel-reserved 0, followed by ISB.
    pub ttbr1_asid_zero: bool,
    /// DAIF masked across the switch and the whole copy.
    pub daif_masked: bool,
    /// EPD0 state, recorded for audit only; never a substitute for the
    /// three steps above.
    pub epd0: bool,
}

impl SoftwarePanContext {
    pub const fn sufficient(self) -> bool {
        self.ttbr0_empty_root && self.ttbr1_asid_zero && self.daif_masked
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CopyWindowState {
    /// No live temporary mapping; user VA is inaccessible from EL1.
    Closed,
    /// Verified pinned TTBR1 window; only in-window spans may be copied.
    Open,
    /// Teardown started: access already fail-closed, pin still held until
    /// local invalidation completes.
    Invalidating,
}

/// One per-CPU TTBR1 temporary copy window (SEC-M11). Value semantics: a
/// retired window can never authorize again, and a reopened window carries
/// a fresh generation, so stale references fail closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CopyWindow {
    cpu: u8,
    state: CopyWindowState,
    base: u64,
    end: u64,
    owner: u64,
    generation: u64,
    user_asid: u8,
    pinned: bool,
}

impl CopyWindow {
    /// Open a window over a verified user range. Rejects unless the full
    /// software-PAN context holds, the range is page-aligned, non-empty,
    /// bounded and overflow-free, owner/generation are live, and the user
    /// ASID is in 1..=255 (ASID 0 is kernel-reserved, 主§2.2.1).
    pub fn open(
        cpu: u8,
        window_base: u64,
        window_end: u64,
        owner: u64,
        generation: u64,
        user_asid: u8,
        pan: SoftwarePanContext,
    ) -> Result<Self, Error> {
        if cpu >= MAX_CPUS {
            return Err(Error::Invalid);
        }
        if !pan.sufficient() {
            return Err(Error::Unauthorized);
        }
        if owner == 0 || generation == 0 || user_asid == 0 {
            return Err(Error::Unauthorized);
        }
        if window_base >= window_end
            || !window_base.is_multiple_of(PAGE_SIZE)
            || !window_end.is_multiple_of(PAGE_SIZE)
        {
            return Err(Error::Invalid);
        }
        let pages = (window_end - window_base) / PAGE_SIZE;
        if pages > COPY_WINDOW_MAX_PAGES {
            return Err(Error::Invalid);
        }
        Ok(Self {
            cpu,
            state: CopyWindowState::Open,
            base: window_base,
            end: window_end,
            owner,
            generation,
            user_asid,
            pinned: true,
        })
    }

    /// Authorize one copy span. Fail-closed: only an Open window on the
    /// executing CPU, for the verified owner at the verified generation,
    /// over an aligned in-window span with overflow-free bounds. A stale
    /// generation (concurrent unmap/remap, SEC-M05) is `Stale`, never a
    /// copy; faults only affect this syscall and leak no kernel data.
    pub fn authorize_copy(
        &self,
        cpu: u8,
        caller: u64,
        frame_owner: u64,
        frame_generation: u64,
        base: u64,
        length: usize,
    ) -> Result<(u64, u64), Error> {
        if self.state != CopyWindowState::Open || cpu != self.cpu {
            return Err(Error::Unauthorized);
        }
        if caller == 0 || caller != self.owner || frame_owner != self.owner {
            return Err(Error::Unauthorized);
        }
        if frame_generation != self.generation {
            return Err(Error::Stale);
        }
        if !base.is_multiple_of(COPY_SPAN_ALIGN) {
            return Err(Error::Invalid);
        }
        checked_user_span(base, length, self.base, self.end)
    }

    /// Begin teardown: copies stop being authorized immediately, but the
    /// pin is retained until local invalidation is proven complete
    /// ("撤窗完成本地失效再解除 pin", 主§2.2.1).
    pub fn begin_teardown(&mut self) -> Result<(), Error> {
        if self.state != CopyWindowState::Open {
            return Err(Error::Busy);
        }
        self.state = CopyWindowState::Invalidating;
        Ok(())
    }

    /// Complete teardown. `local_invalidation_done` must be real native
    /// evidence (this CPU's TLBI + DSB/ISB); without it the pin stays held
    /// and the window remains Invalidating. With it the pin is released and
    /// the window is Closed: no dangling access is possible afterwards.
    pub fn finish_teardown(&mut self, local_invalidation_done: bool) -> Result<(), Error> {
        if self.state != CopyWindowState::Invalidating {
            return Err(Error::Busy);
        }
        if !local_invalidation_done {
            return Err(Error::Busy);
        }
        self.pinned = false;
        self.state = CopyWindowState::Closed;
        Ok(())
    }

    /// No path in this contract restores the user TTBR0 at EL1 — nested
    /// exception entries included (主§2.2.1 "嵌套入口不恢复用户 TTBR").
    pub const fn user_ttbr_restored(&self) -> bool {
        false
    }

    pub const fn state(&self) -> CopyWindowState {
        self.state
    }

    pub const fn pinned(&self) -> bool {
        self.pinned
    }
}

// ---------------------------------------------------------------------------
// SEC-M12 — SP_ELx guard fault / emergency stack contract.
//
// Baseline: 主§13.2 (每 CPU 16 KiB 执行栈 / 16 KiB IRQ 栈 / 8 KiB 应急栈, each
// with an independent 4 KiB unmapped guard; 4 KiB entry scratch; SP must be
// in a registered stack, 16 B aligned, with 512 B fixed entry-frame
// headroom; guard/越界/非法 SP 组/栈帧不足 → load emergency SP, close
// admission, fail-stop; no normal IRQ nesting; recoverable sync nesting at
// most 1 layer with independent saved frames; scratch transfer must complete
// before any recoverable nesting; second fatal fault = minimal stop flag +
// WFE; unprovable stop = UNKNOWN), the EL1 16-vector matrix (当前 EL/SP_EL0
// uniformly prohibited → emergency + SMP safe stop; SP_ELx sync must not
// call Rust first), SEC-M 实施契约 and acceptance SEC-M12 / SEC-M10.
// Proof categories: STATIC_EL1 + ARCH_A53 (+ RUNTIME_QEMU).
//
// CONTRACT ONLY: bounded pure classification and state rules. Reading the
// real SP/SPSel, the unmapped guard PTEs, DAIF masking, the entry-scratch
// assembly sequence and loading the emergency SP are native arch gates to
// be implemented and proven later (G1 per-instruction/static stack-depth
// proof); nothing here enforces them in hardware and no wire bytes are
// defined.
// ---------------------------------------------------------------------------

pub const EXEC_STACK_BYTES: u64 = 16 * 1024;
pub const IRQ_STACK_BYTES: u64 = 16 * 1024;
pub const EMERGENCY_STACK_BYTES: u64 = 8 * 1024;
/// Each stack has its own independent unmapped 4 KiB guard below it.
pub const STACK_GUARD_BYTES: u64 = PAGE_SIZE;
/// Fixed entry-frame headroom that must remain below SP (主§13.2).
pub const ENTRY_FRAME_BYTES: u64 = 512;
/// SP must be 16-byte aligned (主§13.2 entry check).
pub const SP_ALIGNMENT: u64 = 16;
/// One 4 KiB globally trusted entry scratch page per CPU (主§13.2).
pub const ENTRY_SCRATCH_BYTES: u64 = PAGE_SIZE;
/// Recoverable synchronous nesting: at most one layer; the third entry
/// stops (主§13.2 "二层使用独立帧，第三层停机").
pub const MAX_RECOVERABLE_SYNC_NESTING: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StackKind {
    Exec,
    Irq,
    Emergency,
}

impl StackKind {
    pub const fn bytes(self) -> u64 {
        match self {
            Self::Exec => EXEC_STACK_BYTES,
            Self::Irq => IRQ_STACK_BYTES,
            Self::Emergency => EMERGENCY_STACK_BYTES,
        }
    }
}

/// A registered per-CPU stack. `base` is the low address of usable stack
/// space; the unmapped guard occupies `[base - STACK_GUARD_BYTES, base)`.
/// SP grows down from `base + len`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StackSlot {
    pub kind: StackKind,
    pub base: u64,
    pub len: u64,
}

impl StackSlot {
    fn guard_base(self) -> Option<u64> {
        self.base.checked_sub(STACK_GUARD_BYTES)
    }

    fn top(self) -> Option<u64> {
        self.base.checked_add(self.len)
    }

    /// Full reserved range including the guard: `[guard_base, top)`.
    fn reserved(self) -> Option<(u64, u64)> {
        Some((self.guard_base()?, self.top()?))
    }

    fn overlaps(self, other: StackSlot) -> Result<bool, Error> {
        let (a0, a1) = self.reserved().ok_or(Error::Invalid)?;
        let (b0, b1) = other.reserved().ok_or(Error::Invalid)?;
        Ok(a0 < b1 && b0 < a1)
    }
}

/// The frozen per-CPU EL1 stack layout (执行 / IRQ / 应急).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuStacks {
    pub exec: StackSlot,
    pub irq: StackSlot,
    pub emergency: StackSlot,
}

impl CpuStacks {
    /// Register the layout. Sizes are fixed by the baseline (16/16/8 KiB),
    /// never caller-chosen. Bases must be page-aligned with room for the
    /// guard below, and the three reserved ranges (stack + guard) must be
    /// pairwise disjoint so a guard fault can never contaminate a
    /// neighbouring stack or the control plane (SEC-M10 无相邻污染).
    pub fn register(exec_base: u64, irq_base: u64, emergency_base: u64) -> Result<Self, Error> {
        let stacks = Self {
            exec: StackSlot {
                kind: StackKind::Exec,
                base: exec_base,
                len: EXEC_STACK_BYTES,
            },
            irq: StackSlot {
                kind: StackKind::Irq,
                base: irq_base,
                len: IRQ_STACK_BYTES,
            },
            emergency: StackSlot {
                kind: StackKind::Emergency,
                base: emergency_base,
                len: EMERGENCY_STACK_BYTES,
            },
        };
        for s in [stacks.exec, stacks.irq, stacks.emergency] {
            if s.base % PAGE_SIZE != 0 || s.reserved().is_none() {
                return Err(Error::Invalid);
            }
        }
        if stacks.exec.overlaps(stacks.irq)?
            || stacks.exec.overlaps(stacks.emergency)?
            || stacks.irq.overlaps(stacks.emergency)?
        {
            return Err(Error::Conflict);
        }
        Ok(stacks)
    }

    pub const fn slot(&self, kind: StackKind) -> StackSlot {
        match kind {
            StackKind::Exec => self.exec,
            StackKind::Irq => self.irq,
            StackKind::Emergency => self.emergency,
        }
    }

    /// Usable EL1 stack bytes per CPU: 16 + 16 + 8 = 40 KiB; 4 CPUs account
    /// for the baseline's 160 KiB (主§13.7). Guards reserve extra on top.
    pub const fn usable_bytes_per_cpu() -> u64 {
        EXEC_STACK_BYTES + IRQ_STACK_BYTES + EMERGENCY_STACK_BYTES
    }
}

/// Entry-time classification of the original SP, checked before any Rust
/// call and without touching the faulted stack (主§13.2 entry scratch).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpCheck {
    Ok,
    /// SP landed in the unmapped guard page below a registered stack.
    GuardFault,
    /// SP below the guard or above the registered stack top.
    OutOfBounds,
    /// EL1 entry using SP_EL0 (SPSel=0): uniformly prohibited by the vector
    /// matrix for every exception type; also used when the emergency stack
    /// is presented as a normal entry target, which it never is.
    IllegalSpGroup,
    /// SP not 16-byte aligned.
    Misaligned,
    /// Less than the fixed 512 B entry-frame headroom above the stack base.
    InsufficientFrame,
}

impl SpCheck {
    pub const fn is_fatal(self) -> bool {
        !matches!(self, Self::Ok)
    }
}

/// Classify the original SP at exception entry. `expected` is the registered
/// stack the entry should be on (Exec for synchronous thread exceptions, Irq
/// for interrupts); `sp_sel` is 1 when the entry uses SP_ELx as required for
/// all normal EL1 threads (SPSel=1). Any fatal class routes to the emergency
/// stack, never to a frame push on the faulted stack.
pub fn classify_entry_sp(stacks: &CpuStacks, expected: StackKind, sp: u64, sp_sel: u8) -> SpCheck {
    if sp_sel != 1 {
        return SpCheck::IllegalSpGroup;
    }
    let slot = match expected {
        StackKind::Exec => stacks.exec,
        StackKind::Irq => stacks.irq,
        StackKind::Emergency => return SpCheck::IllegalSpGroup,
    };
    let (guard_base, top) = match slot.reserved() {
        Some(r) => r,
        None => return SpCheck::OutOfBounds,
    };
    if sp >= guard_base && sp < slot.base {
        return SpCheck::GuardFault;
    }
    if sp < slot.base || sp > top {
        return SpCheck::OutOfBounds;
    }
    if !sp.is_multiple_of(SP_ALIGNMENT) {
        return SpCheck::Misaligned;
    }
    if sp - slot.base < ENTRY_FRAME_BYTES {
        return SpCheck::InsufficientFrame;
    }
    SpCheck::Ok
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryDisposition {
    /// SP check passed and the entry scratch is trustworthy: switch/push the
    /// corresponding exec or IRQ stack.
    NormalStack,
    /// Fatal SP fault with trustworthy scratch: load the per-CPU 8 KiB
    /// emergency SP, close admission, record fail-stop. Never push frames on
    /// the faulted stack and never call Rust first.
    EmergencyFailStop,
    /// Entry page/registers corrupted so stopping cannot be evidenced:
    /// report UNKNOWN; do not claim fail-stop was achieved.
    Unknown,
}

/// Vector-entry decision combining the SP check with entry-scratch integrity
/// (主§13.2: 入口页/寄存器自身损坏无法证明停止则 UNKNOWN).
pub const fn entry_disposition(check: SpCheck, scratch_intact: bool) -> EntryDisposition {
    if !scratch_intact {
        return EntryDisposition::Unknown;
    }
    if check.is_fatal() {
        EntryDisposition::EmergencyFailStop
    } else {
        EntryDisposition::NormalStack
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmergencyState {
    Idle,
    /// First fatal fault taken; minimal fail-stop recorded on the emergency
    /// stack, new admission closed.
    FailStop,
    /// Second fatal fault: minimal stop flag + WFE only; terminal.
    Halted,
    /// Stopping could not be evidenced; no fail-stop claim.
    Unknown,
}

/// Per-CPU emergency-stack switch state (SEC-M12). Terminal by design: the
/// baseline routes guard faults to 分级 fail-stop / SMP 停机, not recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmergencyStack {
    cpu: u8,
    state: EmergencyState,
    admission_closed: bool,
}

impl EmergencyStack {
    pub fn new(cpu: u8) -> Result<Self, Error> {
        if cpu >= MAX_CPUS {
            return Err(Error::Invalid);
        }
        Ok(Self {
            cpu,
            state: EmergencyState::Idle,
            admission_closed: false,
        })
    }

    /// First fatal SP fault: switch to the emergency stack. Returns the
    /// emergency SP offset (top of the 8 KiB emergency stack); the native
    /// gate adds the registered base. `stop_provable` must be real evidence
    /// that the minimal fail-stop record can complete; without it the
    /// outcome is UNKNOWN, not a claimed fail-stop.
    pub fn enter(&mut self, check: SpCheck, stop_provable: bool) -> Result<u64, Error> {
        if !check.is_fatal() {
            return Err(Error::Invalid);
        }
        if self.state != EmergencyState::Idle {
            return Err(Error::Busy);
        }
        if !stop_provable {
            self.state = EmergencyState::Unknown;
            return Err(Error::Unknown);
        }
        self.state = EmergencyState::FailStop;
        self.admission_closed = true;
        Ok(EMERGENCY_STACK_BYTES)
    }

    /// A second fatal exception while on the emergency stack does only the
    /// minimal stop flag + WFE. No recursive calls, no further frames;
    /// repeating it changes nothing.
    pub fn second_fault(&mut self) -> Result<(), Error> {
        match self.state {
            EmergencyState::FailStop => {
                self.state = EmergencyState::Halted;
                Ok(())
            }
            EmergencyState::Halted => Ok(()),
            _ => Err(Error::Invalid),
        }
    }

    /// The faulted stack is never written again once a guard fault is taken
    /// ("不得在故障栈压帧").
    pub const fn faulted_stack_writable(&self) -> bool {
        false
    }

    /// The emergency stack never makes recursive calls ("应急栈不再递归调用").
    pub const fn may_recurse(&self) -> bool {
        false
    }

    pub const fn admission_closed(&self) -> bool {
        self.admission_closed
    }

    pub const fn state(&self) -> EmergencyState {
        self.state
    }

    pub const fn cpu(&self) -> u8 {
        self.cpu
    }
}

/// A saved-frame region on a verified exec/IRQ stack or a preallocated task
/// object. Frames for nested entries must be independent and disjoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameSlot {
    pub base: u64,
    pub len: u64,
}

impl FrameSlot {
    fn end(self) -> Option<u64> {
        self.base.checked_add(self.len)
    }

    fn validate(self) -> Result<(), Error> {
        if self.len < ENTRY_FRAME_BYTES
            || !self.base.is_multiple_of(SP_ALIGNMENT)
            || self.end().is_none()
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}

/// True when two frame regions cannot overwrite each other (checked bounds).
pub fn frames_disjoint(a: FrameSlot, b: FrameSlot) -> Result<bool, Error> {
    let ae = a.end().ok_or(Error::Invalid)?;
    let be = b.end().ok_or(Error::Invalid)?;
    Ok(a.base >= be || b.base >= ae)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScratchState {
    /// scratch_free published; no entry in progress.
    Free,
    /// Minimal entry save in progress (DAIF masked, no faulted-stack writes).
    Saving,
    /// Full saved frame (incl. exception-level state) sits in scratch.
    Saved,
    /// Frame transferred to a verified stack/task object and scratch_free
    /// published. Only now may recoverable sync nesting be considered.
    Transferred,
}

/// Per-CPU entry scratch lifecycle (主§13.2): minimal save first, transfer
/// the full frame before any recoverable nesting, one independent nested
/// frame at most, third entry stops.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntryScratch {
    state: ScratchState,
    depth: u8,
    outer_frame: Option<FrameSlot>,
    nested_frame: Option<FrameSlot>,
}

impl Default for EntryScratch {
    fn default() -> Self {
        Self::new()
    }
}

impl EntryScratch {
    pub const fn new() -> Self {
        Self {
            state: ScratchState::Free,
            depth: 0,
            outer_frame: None,
            nested_frame: None,
        }
    }

    pub const fn state(&self) -> ScratchState {
        self.state
    }

    pub const fn depth(&self) -> u8 {
        self.depth
    }

    /// Begin the minimal entry save into the trusted scratch page.
    pub fn begin_save(&mut self) -> Result<(), Error> {
        if self.state != ScratchState::Free {
            return Err(Error::Busy);
        }
        self.state = ScratchState::Saving;
        Ok(())
    }

    /// Complete the full save. The frame must fit the 4 KiB scratch page and
    /// be at least the fixed 512 B entry frame.
    pub fn complete_save(&mut self, frame_len: u64) -> Result<(), Error> {
        if self.state != ScratchState::Saving {
            return Err(Error::Busy);
        }
        if !(ENTRY_FRAME_BYTES..=ENTRY_SCRATCH_BYTES).contains(&frame_len) {
            return Err(Error::Invalid);
        }
        self.state = ScratchState::Saved;
        Ok(())
    }

    /// Before the transfer completes, any synchronous exception or SError is
    /// fatal: no normal recursion is entered ("转存前同步异常/SError 为致命").
    pub const fn fault_before_transfer_is_fatal(&self) -> bool {
        matches!(self.state, ScratchState::Saving | ScratchState::Saved)
    }

    /// Transfer the full saved frame to a verified exec/IRQ stack or a
    /// preallocated task object and publish scratch_free. The destination
    /// frame must be aligned, bounded and overflow-free.
    pub fn transfer(&mut self, dest: FrameSlot) -> Result<(), Error> {
        if self.state != ScratchState::Saved {
            return Err(Error::Busy);
        }
        dest.validate()?;
        self.outer_frame = Some(dest);
        self.state = ScratchState::Transferred;
        Ok(())
    }

    /// Admit one recoverable synchronous nesting layer. Requires scratch_free
    /// published (transfer complete), depth below the one-layer limit, and an
    /// independent frame disjoint from the outer saved frame ("允许一层时两帧
    /// 不互相覆盖"). The third entry must stop (`Exhausted` routes to the
    /// emergency/fail-stop path).
    pub fn begin_nested(&mut self, frame: FrameSlot) -> Result<(), Error> {
        if self.state != ScratchState::Transferred {
            return Err(Error::Unauthorized);
        }
        if self.depth >= MAX_RECOVERABLE_SYNC_NESTING {
            return Err(Error::Exhausted);
        }
        frame.validate()?;
        let outer = self.outer_frame.ok_or(Error::Invalid)?;
        if !frames_disjoint(outer, frame)? {
            return Err(Error::Conflict);
        }
        self.nested_frame = Some(frame);
        self.depth += 1;
        Ok(())
    }

    /// Retire the nested layer; the outer frame remains authoritative.
    pub fn end_nested(&mut self) -> Result<(), Error> {
        if self.depth == 0 || self.nested_frame.is_none() {
            return Err(Error::Invalid);
        }
        self.nested_frame = None;
        self.depth -= 1;
        Ok(())
    }

    /// Entry exit: scratch returns to Free for the next entry.
    pub fn retire(&mut self) -> Result<(), Error> {
        if self.state != ScratchState::Transferred || self.depth != 0 {
            return Err(Error::Busy);
        }
        self.outer_frame = None;
        self.state = ScratchState::Free;
        Ok(())
    }

    /// Normal IRQ nesting on the IRQ stack is never allowed ("IRQ 栈不允许
    /// 普通 IRQ 嵌套").
    pub const fn irq_nesting_allowed() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn user() -> Frame {
        Frame {
            owner: 7,
            generation: 3,
            kind: FrameKind::User,
            zeroed: true,
            writable_alias: false,
            executable_alias: false,
        }
    }
    fn data() -> Permissions {
        Permissions {
            read: true,
            write: true,
            execute: false,
        }
    }
    #[test]
    fn sec_m01_never_map_private_kernel_or_control_frames() {
        let mut f = user();
        f.kind = FrameKind::Control;
        assert_eq!(
            authorize_mapping(f, 7, data(), None),
            Err(Error::Unauthorized)
        );
        f.kind = FrameKind::User;
        assert_eq!(
            authorize_mapping(f, 8, data(), None),
            Err(Error::Unauthorized)
        );
    }
    #[test]
    fn sec_m02_wx_and_aliases_rejected() {
        let f = user();
        assert_eq!(
            authorize_mapping(
                f,
                7,
                Permissions {
                    execute: true,
                    ..data()
                },
                None
            ),
            Err(Error::Unauthorized)
        );
        let mut alias = user();
        alias.executable_alias = true;
        assert_eq!(
            authorize_mapping(alias, 7, data(), None),
            Err(Error::Unauthorized)
        );
    }
    #[test]
    fn sec_m03_unzeroed_user_frame_cannot_be_published() {
        let mut f = user();
        f.zeroed = false;
        assert_eq!(authorize_mapping(f, 7, data(), None), Err(Error::Busy));
    }
    #[test]
    fn sec_m04_missing_tlb_ack_retains_frame() {
        let mut s = Shootdown::begin(1, 2, 0b110, 0, 0, 0).unwrap();
        s.revoke_pte();
        s.acknowledge(1, 2, 1).unwrap();
        assert!(!s.may_reuse());
        s.acknowledge(1, 2, 2).unwrap();
        assert!(s.may_reuse());
    }
    #[test]
    fn sec_m05_checked_user_copy_range() {
        assert_eq!(
            checked_user_span(u64::MAX, 2, 1, u64::MAX),
            Err(Error::Invalid)
        );
        assert_eq!(checked_user_span(5, 4, 8, 12), Err(Error::Unauthorized));
        assert_eq!(checked_user_span(8, 4, 8, 12), Ok((8, 12)));
    }
    #[test]
    fn sec_m06_dma_and_pin_survive_cpu_unmap() {
        let mut s = Shootdown::begin(1, 2, 1, 0, 1, 1).unwrap();
        s.revoke_pte();
        s.acknowledge(1, 2, 0).unwrap();
        assert!(!s.may_reuse());
        assert_eq!(s.release_pin(), Err(Error::Busy));
        s.complete_dma().unwrap();
        s.release_pin().unwrap();
        assert!(s.may_reuse());
    }
    #[test]
    fn sec_m07_no_reuse_before_all_references_release() {
        let mut s = Shootdown::begin(1, 2, 0, 1, 0, 0).unwrap();
        s.revoke_pte();
        assert!(!s.may_reuse());
        s.release_reference().unwrap();
        assert!(s.may_reuse());
    }
    #[test]
    fn native_frame_pool_guard_blocks_tables_loader_and_overflow() {
        assert_eq!(authorize_data_frame_slot(17, 16, 256), Ok(()));
        assert_eq!(
            authorize_data_frame_slot(15, 16, 256),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            authorize_data_frame_slot(256, 16, 256),
            Err(Error::Unauthorized)
        );
        assert_eq!(authorize_data_frame_slot(17, 256, 256), Err(Error::Invalid));
    }
    #[test]
    fn v019_sec_m01_zero_owner_cannot_be_shared_into_el0() {
        let frame = Frame { owner: 0, ..user() };
        let forged = SharedGrant::from_registry(0, 7, frame.generation);
        assert_eq!(
            authorize_mapping(frame, 7, data(), Some(forged)),
            Err(Error::Unauthorized)
        );
    }
    #[test]
    fn sec_m08_stale_tlb_generation_not_an_ack() {
        let mut s = Shootdown::begin(1, 2, 1, 0, 0, 0).unwrap();
        s.revoke_pte();
        assert_eq!(s.acknowledge(1, 1, 0), Err(Error::Stale));
        assert!(!s.may_reuse());
    }

    // --- SEC-M11: A53 no-PAN copy window contract -------------------------

    fn pan() -> SoftwarePanContext {
        SoftwarePanContext {
            ttbr0_empty_root: true,
            ttbr1_asid_zero: true,
            daif_masked: true,
            epd0: true,
        }
    }
    fn window() -> CopyWindow {
        CopyWindow::open(0, 0x1000, 0x3000, 7, 3, 1, pan()).unwrap()
    }

    #[test]
    fn sec_m11_software_pan_required_epd0_alone_insufficient() {
        let epd0_only = SoftwarePanContext {
            ttbr0_empty_root: false,
            ttbr1_asid_zero: false,
            daif_masked: false,
            epd0: true,
        };
        assert!(!epd0_only.sufficient());
        assert_eq!(
            CopyWindow::open(0, 0x1000, 0x3000, 7, 3, 1, epd0_only),
            Err(Error::Unauthorized)
        );
        for missing in [
            SoftwarePanContext {
                ttbr0_empty_root: false,
                ..pan()
            },
            SoftwarePanContext {
                ttbr1_asid_zero: false,
                ..pan()
            },
            SoftwarePanContext {
                daif_masked: false,
                ..pan()
            },
        ] {
            assert_eq!(
                CopyWindow::open(0, 0x1000, 0x3000, 7, 3, 1, missing),
                Err(Error::Unauthorized)
            );
        }
        assert!(pan().sufficient());
        assert_eq!(window().state(), CopyWindowState::Open);
    }

    #[test]
    fn sec_m11_window_range_page_aligned_bounded_overflow_free() {
        // Misaligned or empty/inverted ranges.
        assert_eq!(
            CopyWindow::open(0, 0x1001, 0x3000, 7, 3, 1, pan()),
            Err(Error::Invalid)
        );
        assert_eq!(
            CopyWindow::open(0, 0x1000, 0x2001, 7, 3, 1, pan()),
            Err(Error::Invalid)
        );
        assert_eq!(
            CopyWindow::open(0, 0x2000, 0x2000, 7, 3, 1, pan()),
            Err(Error::Invalid)
        );
        assert_eq!(
            CopyWindow::open(0, 0x3000, 0x2000, 7, 3, 1, pan()),
            Err(Error::Invalid)
        );
        // Bounded page count: 16 pages ok, 17 rejected.
        assert!(CopyWindow::open(0, 0x1000, 0x11000, 7, 3, 1, pan()).is_ok());
        assert_eq!(
            CopyWindow::open(0, 0x1000, 0x12000, 7, 3, 1, pan()),
            Err(Error::Invalid)
        );
        // Frozen CPU count and live identity/ASID rules.
        assert_eq!(
            CopyWindow::open(MAX_CPUS, 0x1000, 0x3000, 7, 3, 1, pan()),
            Err(Error::Invalid)
        );
        assert_eq!(
            CopyWindow::open(0, 0x1000, 0x3000, 0, 3, 1, pan()),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            CopyWindow::open(0, 0x1000, 0x3000, 7, 0, 1, pan()),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            CopyWindow::open(0, 0x1000, 0x3000, 7, 3, 0, pan()),
            Err(Error::Unauthorized)
        );
    }

    #[test]
    fn sec_m11_out_of_window_copy_fail_closed() {
        let w = window();
        // Below the window, crossing the end, and at/after the end.
        assert_eq!(
            w.authorize_copy(0, 7, 7, 3, 0x0ff8, 8),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            w.authorize_copy(0, 7, 7, 3, 0x2ff8, 16),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            w.authorize_copy(0, 7, 7, 3, 0x3000, 8),
            Err(Error::Unauthorized)
        );
        // Overflow-free bounds and non-empty spans.
        assert_eq!(
            w.authorize_copy(0, 7, 7, 3, u64::MAX - 7, 16),
            Err(Error::Invalid)
        );
        assert_eq!(w.authorize_copy(0, 7, 7, 3, 0x1000, 0), Err(Error::Invalid));
        // In-window copy is authorized with exact bounds.
        assert_eq!(
            w.authorize_copy(0, 7, 7, 3, 0x1000, 8),
            Ok((0x1000, 0x1008))
        );
        assert_eq!(
            w.authorize_copy(0, 7, 7, 3, 0x2ff8, 8),
            Ok((0x2ff8, 0x3000))
        );
    }

    #[test]
    fn sec_m11_owner_generation_and_cpu_binding() {
        let w = window();
        assert_eq!(
            w.authorize_copy(0, 8, 7, 3, 0x1000, 8),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            w.authorize_copy(0, 7, 8, 3, 0x1000, 8),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            w.authorize_copy(0, 0, 7, 3, 0x1000, 8),
            Err(Error::Unauthorized)
        );
        // Concurrent unmap/remap: stale generation is never a copy.
        assert_eq!(w.authorize_copy(0, 7, 7, 4, 0x1000, 8), Err(Error::Stale));
        // Per-CPU exclusive: another CPU cannot use this window.
        assert_eq!(
            w.authorize_copy(1, 7, 7, 3, 0x1000, 8),
            Err(Error::Unauthorized)
        );
    }

    #[test]
    fn sec_m11_copy_span_alignment() {
        let w = window();
        assert_eq!(w.authorize_copy(0, 7, 7, 3, 0x1004, 8), Err(Error::Invalid));
        assert_eq!(
            w.authorize_copy(0, 7, 7, 3, 0x1008, 8),
            Ok((0x1008, 0x1010))
        );
    }

    #[test]
    fn sec_m11_teardown_invalidation_before_unpin_no_dangling() {
        let mut w = window();
        w.begin_teardown().unwrap();
        assert_eq!(w.state(), CopyWindowState::Invalidating);
        assert!(w.pinned());
        // Access is already fail-closed during teardown.
        assert_eq!(
            w.authorize_copy(0, 7, 7, 3, 0x1000, 8),
            Err(Error::Unauthorized)
        );
        // Without local invalidation evidence the pin stays held.
        assert_eq!(w.finish_teardown(false), Err(Error::Busy));
        assert!(w.pinned());
        assert_eq!(w.state(), CopyWindowState::Invalidating);
        // With evidence: unpin and close; no dangling access afterwards.
        w.finish_teardown(true).unwrap();
        assert!(!w.pinned());
        assert_eq!(w.state(), CopyWindowState::Closed);
        assert_eq!(
            w.authorize_copy(0, 7, 7, 3, 0x1000, 8),
            Err(Error::Unauthorized)
        );
        assert_eq!(w.begin_teardown(), Err(Error::Busy));
        assert_eq!(w.finish_teardown(true), Err(Error::Busy));
    }

    #[test]
    fn sec_m11_nested_entry_never_restores_user_ttbr() {
        let mut w = window();
        // No contract path restores the user TTBR, in any state.
        assert!(!w.user_ttbr_restored());
        // A nested exception does not change the window; out-of-window user
        // VA stays inaccessible whether the TLB entry is hot or cold.
        let before = w.state();
        assert_eq!(
            w.authorize_copy(0, 7, 7, 3, 0x4000, 8),
            Err(Error::Unauthorized)
        );
        assert_eq!(w.state(), before);
        w.begin_teardown().unwrap();
        assert!(!w.user_ttbr_restored());
        w.finish_teardown(true).unwrap();
        assert!(!w.user_ttbr_restored());
        // A retired window cannot serve a newer generation: reopening binds
        // a fresh generation and the old reference fails closed.
        let old = window();
        let _new = CopyWindow::open(0, 0x1000, 0x3000, 7, 4, 1, pan()).unwrap();
        assert_eq!(old.authorize_copy(0, 7, 7, 4, 0x1000, 8), Err(Error::Stale));
    }

    // --- SEC-M12: SP_ELx guard fault / emergency stack contract -----------

    fn stacks() -> CpuStacks {
        CpuStacks::register(0x10_0000, 0x20_0000, 0x30_0000).unwrap()
    }
    fn saved_scratch() -> EntryScratch {
        let mut s = EntryScratch::new();
        s.begin_save().unwrap();
        s.complete_save(ENTRY_FRAME_BYTES).unwrap();
        s
    }
    fn transferred_scratch() -> EntryScratch {
        let mut s = saved_scratch();
        s.transfer(FrameSlot {
            base: 0x10_0000,
            len: ENTRY_FRAME_BYTES,
        })
        .unwrap();
        s
    }

    #[test]
    fn sec_m12_frozen_layout_disjoint_guards() {
        let s = stacks();
        assert_eq!(s.exec.len, EXEC_STACK_BYTES);
        assert_eq!(s.irq.len, IRQ_STACK_BYTES);
        assert_eq!(s.emergency.len, EMERGENCY_STACK_BYTES);
        assert_eq!(
            CpuStacks::usable_bytes_per_cpu() * u64::from(MAX_CPUS),
            160 * 1024
        );
        // Overlapping reserved ranges (stack or guard) are rejected.
        assert_eq!(
            CpuStacks::register(0x10_0000, 0x10_3000, 0x30_0000),
            Err(Error::Conflict)
        );
        // Adjacent stacks without guard room contaminate each other.
        assert_eq!(
            CpuStacks::register(0x10_0000, 0x10_4000, 0x30_0000),
            Err(Error::Conflict)
        );
        // Page alignment and guard underflow.
        assert_eq!(
            CpuStacks::register(0x10_0800, 0x20_0000, 0x30_0000),
            Err(Error::Invalid)
        );
        assert_eq!(
            CpuStacks::register(0, 0x20_0000, 0x30_0000),
            Err(Error::Invalid)
        );
        assert_eq!(
            CpuStacks::register(u64::MAX - 0x3000, 0x20_0000, 0x30_0000),
            Err(Error::Invalid)
        );
    }

    #[test]
    fn sec_m12_sp_guard_and_entry_classification() {
        let s = stacks();
        // Exec stack: base 0x10_0000, top 0x10_4000, guard [0xFF000, 0x10_0000).
        assert_eq!(
            classify_entry_sp(&s, StackKind::Exec, 0x10_3f00, 1),
            SpCheck::Ok
        );
        assert_eq!(
            classify_entry_sp(&s, StackKind::Exec, 0x10_4000, 1),
            SpCheck::Ok
        );
        assert_eq!(
            classify_entry_sp(&s, StackKind::Exec, 0x10_0200, 1),
            SpCheck::Ok
        );
        assert_eq!(
            classify_entry_sp(&s, StackKind::Exec, 0xff800, 1),
            SpCheck::GuardFault
        );
        assert_eq!(
            classify_entry_sp(&s, StackKind::Exec, 0xfe000, 1),
            SpCheck::OutOfBounds
        );
        assert_eq!(
            classify_entry_sp(&s, StackKind::Exec, 0x10_4008, 1),
            SpCheck::OutOfBounds
        );
        // SP_EL0 at EL1 is uniformly prohibited, even with an in-range SP.
        assert_eq!(
            classify_entry_sp(&s, StackKind::Exec, 0x10_3f00, 0),
            SpCheck::IllegalSpGroup
        );
        assert_eq!(
            classify_entry_sp(&s, StackKind::Emergency, 0x30_1f00, 1),
            SpCheck::IllegalSpGroup
        );
        assert_eq!(
            classify_entry_sp(&s, StackKind::Exec, 0x10_3f08, 1),
            SpCheck::Misaligned
        );
        // 512 B fixed entry-frame headroom boundary.
        assert_eq!(
            classify_entry_sp(&s, StackKind::Exec, 0x10_0100, 1),
            SpCheck::InsufficientFrame
        );
        assert_eq!(
            classify_entry_sp(&s, StackKind::Exec, 0x10_0200, 1),
            SpCheck::Ok
        );
        // IRQ entries are checked against the IRQ stack, not the exec stack.
        assert_eq!(
            classify_entry_sp(&s, StackKind::Irq, 0x20_3f00, 1),
            SpCheck::Ok
        );
        assert_eq!(
            classify_entry_sp(&s, StackKind::Irq, 0x10_3f00, 1),
            SpCheck::OutOfBounds
        );
        assert!(!SpCheck::Ok.is_fatal());
        for fatal in [
            SpCheck::GuardFault,
            SpCheck::OutOfBounds,
            SpCheck::IllegalSpGroup,
            SpCheck::Misaligned,
            SpCheck::InsufficientFrame,
        ] {
            assert!(fatal.is_fatal());
        }
    }

    #[test]
    fn sec_m12_entry_disposition_emergency_or_unknown() {
        assert_eq!(
            entry_disposition(SpCheck::Ok, true),
            EntryDisposition::NormalStack
        );
        assert_eq!(
            entry_disposition(SpCheck::GuardFault, true),
            EntryDisposition::EmergencyFailStop
        );
        assert_eq!(
            entry_disposition(SpCheck::InsufficientFrame, true),
            EntryDisposition::EmergencyFailStop
        );
        // Corrupted entry scratch/registers: stopping cannot be evidenced.
        assert_eq!(
            entry_disposition(SpCheck::Ok, false),
            EntryDisposition::Unknown
        );
        assert_eq!(
            entry_disposition(SpCheck::GuardFault, false),
            EntryDisposition::Unknown
        );
    }

    #[test]
    fn sec_m12_emergency_switch_closes_admission_no_faulted_frames() {
        assert_eq!(EmergencyStack::new(MAX_CPUS), Err(Error::Invalid));
        let mut e = EmergencyStack::new(0).unwrap();
        assert_eq!(e.state(), EmergencyState::Idle);
        assert!(!e.admission_closed());
        // A passing SP check never enters the emergency path.
        assert_eq!(e.enter(SpCheck::Ok, true), Err(Error::Invalid));
        // First fatal fault: emergency SP = top of the 8 KiB emergency stack.
        assert_eq!(
            e.enter(SpCheck::GuardFault, true),
            Ok(EMERGENCY_STACK_BYTES)
        );
        assert_eq!(e.state(), EmergencyState::FailStop);
        assert!(e.admission_closed());
        assert!(!e.faulted_stack_writable());
        assert!(!e.may_recurse());
        assert_eq!(e.cpu(), 0);
        // No second first-entry; the faulted stack is never reused.
        assert_eq!(e.enter(SpCheck::OutOfBounds, true), Err(Error::Busy));
        // Unprovable stop is UNKNOWN, not a claimed fail-stop.
        let mut u = EmergencyStack::new(1).unwrap();
        assert_eq!(u.enter(SpCheck::GuardFault, false), Err(Error::Unknown));
        assert_eq!(u.state(), EmergencyState::Unknown);
        assert!(!u.admission_closed());
        assert_eq!(u.enter(SpCheck::GuardFault, true), Err(Error::Busy));
    }

    #[test]
    fn sec_m12_second_fault_minimal_stop_flag_only() {
        let mut e = EmergencyStack::new(2).unwrap();
        assert_eq!(e.second_fault(), Err(Error::Invalid));
        e.enter(SpCheck::Misaligned, true).unwrap();
        e.second_fault().unwrap();
        assert_eq!(e.state(), EmergencyState::Halted);
        // Repeating the second fault only re-asserts the stop flag; no
        // recursion, no frames, terminal state.
        e.second_fault().unwrap();
        assert_eq!(e.state(), EmergencyState::Halted);
        assert!(!e.may_recurse());
        assert!(!e.faulted_stack_writable());
        let mut u = EmergencyStack::new(3).unwrap();
        u.enter(SpCheck::GuardFault, false).unwrap_err();
        assert_eq!(u.second_fault(), Err(Error::Invalid));
    }

    #[test]
    fn sec_m12_scratch_transfer_gates_nesting() {
        let mut s = EntryScratch::new();
        assert_eq!(s.state(), ScratchState::Free);
        assert!(!s.fault_before_transfer_is_fatal());
        // Recoverable nesting is refused before the transfer completes.
        assert_eq!(
            s.begin_nested(FrameSlot {
                base: 0x10_0200,
                len: ENTRY_FRAME_BYTES
            }),
            Err(Error::Unauthorized)
        );
        s.begin_save().unwrap();
        assert!(s.fault_before_transfer_is_fatal());
        assert_eq!(s.begin_save(), Err(Error::Busy));
        // Frame must fit the 4 KiB scratch and cover the 512 B entry frame.
        assert_eq!(s.complete_save(ENTRY_FRAME_BYTES - 1), Err(Error::Invalid));
        assert_eq!(
            s.complete_save(ENTRY_SCRATCH_BYTES + 1),
            Err(Error::Invalid)
        );
        s.complete_save(ENTRY_SCRATCH_BYTES).unwrap();
        assert!(s.fault_before_transfer_is_fatal());
        assert_eq!(
            s.begin_nested(FrameSlot {
                base: 0x10_0200,
                len: ENTRY_FRAME_BYTES
            }),
            Err(Error::Unauthorized)
        );
        // Destination frame must be aligned, bounded, overflow-free.
        assert_eq!(
            s.transfer(FrameSlot {
                base: 0x10_0008,
                len: ENTRY_FRAME_BYTES
            }),
            Err(Error::Invalid)
        );
        assert_eq!(
            s.transfer(FrameSlot {
                base: u64::MAX - 0x100,
                len: ENTRY_FRAME_BYTES
            }),
            Err(Error::Invalid)
        );
        s.transfer(FrameSlot {
            base: 0x10_0000,
            len: ENTRY_FRAME_BYTES,
        })
        .unwrap();
        assert_eq!(s.state(), ScratchState::Transferred);
        assert!(!s.fault_before_transfer_is_fatal());
        assert_eq!(
            s.transfer(FrameSlot {
                base: 0x10_0000,
                len: ENTRY_FRAME_BYTES
            }),
            Err(Error::Busy)
        );
    }

    #[test]
    fn sec_m12_one_nesting_layer_independent_disjoint_frames() {
        let mut s = transferred_scratch();
        let outer = FrameSlot {
            base: 0x10_0000,
            len: ENTRY_FRAME_BYTES,
        };
        // Overlapping nested frame would overwrite the outer saved frame.
        assert_eq!(
            s.begin_nested(FrameSlot {
                base: 0x10_0100,
                len: ENTRY_FRAME_BYTES
            }),
            Err(Error::Conflict)
        );
        assert_eq!(s.depth(), 0);
        // One independent layer is admitted.
        let nested = FrameSlot {
            base: 0x10_0200,
            len: ENTRY_FRAME_BYTES,
        };
        assert_eq!(frames_disjoint(outer, nested), Ok(true));
        s.begin_nested(nested).unwrap();
        assert_eq!(s.depth(), 1);
        // The third entry must stop.
        assert_eq!(
            s.begin_nested(FrameSlot {
                base: 0x10_0400,
                len: ENTRY_FRAME_BYTES
            }),
            Err(Error::Exhausted)
        );
        assert_eq!(s.depth(), 1);
        s.end_nested().unwrap();
        assert_eq!(s.depth(), 0);
        assert_eq!(s.end_nested(), Err(Error::Invalid));
        // Entry exit returns the scratch to Free for the next entry.
        assert_eq!(s.retire(), Ok(()));
        assert_eq!(s.state(), ScratchState::Free);
        s.begin_save().unwrap();
        // Adjacent frames are disjoint; overlap and overflow are detected.
        assert_eq!(
            frames_disjoint(
                outer,
                FrameSlot {
                    base: 0x10_0200,
                    len: ENTRY_FRAME_BYTES
                }
            ),
            Ok(true)
        );
        assert_eq!(
            frames_disjoint(
                outer,
                FrameSlot {
                    base: 0x10_0100,
                    len: ENTRY_FRAME_BYTES
                }
            ),
            Ok(false)
        );
        assert_eq!(
            frames_disjoint(
                outer,
                FrameSlot {
                    base: u64::MAX - 0x100,
                    len: ENTRY_FRAME_BYTES
                }
            ),
            Err(Error::Invalid)
        );
    }

    #[test]
    fn sec_m12_irq_nesting_forbidden() {
        assert!(!EntryScratch::irq_nesting_allowed());
        // Even a fully transferred scratch never admits normal IRQ nesting.
        let s = transferred_scratch();
        assert_eq!(s.state(), ScratchState::Transferred);
        assert!(!EntryScratch::irq_nesting_allowed());
    }
}
