//! V0.19.9 advice-chain native E2E *fixture* (fixture scope, NOT production).
//!
//! This exercises the full causal chain on real CPU0 EL0 traps:
//!   EL0 AdviceEnvelope v1 --SVC 0x50--> EL1 supervisor copyin/verify
//!     -> fixed::Pair::submit_operations_wire + EvidenceLedger::record
//!     -> RuleProfile v2 review (review_with_rule_profile)
//!     -> DecisionRecord v3 + AdviceDisposition v1 + PlanV2 (trusted EL1)
//!     --SVC 0x50 register--> SvcV3Bridge::register_assisted_one
//!     --SVC 0x41 publish--> SvcV3Bridge::publish_assisted_one (unique accept)
//!     -> claim_apply_work -> fixture executor effect -> ApplyReport v1
//!     -> settle_verified_apply_reports_with_feedback (supervisor terminal).
//!
//! HONEST SCOPE / GAP DOCUMENTATION:
//! * The advice INTAKE (0x50 carrying a 152-byte envelope) has no dedicated
//!   SvcV3Bridge method; the bridge only exposes register/publish/read
//!   endpoints. The fixture's EL1 glue therefore authenticates the caller and
//!   calls fixed::Pair::submit_operations_wire + EvidenceLedger::record
//!   directly. That is exactly what a production supervisor adapter must do;
//!   it is NOT a fake chain, but it is glue rather than a bridge entry point.
//! * The REGISTER (0x50, 496B) and PUBLISH (0x41) endpoints ARE driven through
//!   real EL0 SVC traps into SvcV3Bridge. The DecisionRecord/Disposition/Plan
//!   bytes are trusted EL1 artifacts (never model output); EL1 stages them into
//!   the controller/publisher private page and the EL0 carrier traps them
//!   across the boundary. The deterministic decision-construction logic runs in
//!   EL1 fixture glue, not in an independent EL0 controller binary.
//! * The executor is a bounded fixture "device": a private EL1-owned target
//!   page whose word is written by the apply step and independently re-read by
//!   the terminal verify_native callback. It is NOT a real driver/peripheral.
//! * The wrong-CPU negative is exercised at the EL1 bridge boundary (caller.cpu
//!   = 1) because every real trap here runs on CPU0; it is labelled as such.
//! * Feedback custody uses a no-op retain (as the kernel-core settlement test
//!   helper does); the bounded FeedbackInbox is NOT instantiated. The causal
//!   label is derived from the registered decision, and the gate independently
//!   re-validates the exact CausalPair during settlement.
//! * production_wiring=false: the production in-vector syscall dispatcher is
//!   still NOT wired. This fixture dispatches in the CPU0 turn loop after
//!   user::enter returns the authenticated trapped context.
//!
//! The large kernel-core guards (EvidenceLedger, RegisteredDecisionGate) live
//! in static control storage, never on the bounded EL1 stack.
//!
//! UNSAFE BOUNDARY REGISTRATION (baseline 安 0.6 SEC-BUF: minimal trusted
//! boundaries registered individually). Global invariant for every site
//! below: run() asserts cpu::slot()==0 and the whole chain executes
//! synchronously in that single CPU0 turn loop; no IRQ handler, DMA or
//! secondary CPU touches these statics or the advice spaces (index >= C*2).
//! The EL0 entry mechanism itself (execute/user::enter) is smp.rs's
//! registered boundary; this module only calls it.
//! * LEDGER/GATE (static mut MaybeUninit) via ledger_ptr()/gate_ptr():
//!   init_control_guards() ptr::write-initializes each exactly once at the
//!   start of run(), before any dispatch (ptr::write never drops the
//!   uninitialized placeholder). Every later &mut/&* is created and consumed
//!   within one synchronous CPU0 call, so no two live references alias.
//!   Bounded: one ledger + one gate in static storage, never the EL1 stack.
//! * MANIFEST_MEMBERS (static mut): written once by run() (write_volatile)
//!   before the first EL0 turn; dispatch reads it (read_volatile) at
//!   role_index = space - FIRST_ADVICE_SPACE, which is < ROLE_COUNT because
//!   copy_address() rejects space >= PRIVATE_SPACES. CPU0-only, no aliasing.
//! * EXEC_TARGET (static mut): the bounded fixture executor "device"; the
//!   apply step writes word 0 (write_volatile) and the settlement callback
//!   independently re-reads it (read_volatile), both on CPU0 in the same
//!   synchronous loop. One page, one word, no other owner.
//! * copy_address()/read_word()/read_bytes()/write_bytes(): raw addr_of!
//!   arithmetic over ROOTS/MIDDLES/LEAVES/DATA_PAGES/USER_STACKS is bounded
//!   by space < PRIVATE_SPACES and page/offset masks; the descriptor chain
//!   is re-read volatile and checked against this fixture's own tables, and
//!   mmu::checked_user_leaf_span validates the full span before any
//!   high-half alias is dereferenced. Only the three statically registered
//!   pages of the stopped context are reachable; NOT a production VA walker.
//! * Advice-space CODE leaf remap + manifest root/data reads in run():
//!   LEAVES/ROOTS/DATA_PAGES .add(space) stays inside the eight
//!   advice-exclusive spaces (PRIVATE_SPACES == FIRST_ADVICE_SPACE +
//!   ADVICE_SPACES is asserted); CPU0 is the sole writer, secondaries never
//!   use these spaces, and dsb/tlbi/isb publishes the remap before EL0 entry.
//! * asm!("dsb ishst","tlbi vmalle1is","dsb ish","isb"): bounded TLB
//!   maintenance after the leaf update; options(nostack), no memory operands.
//! * SMP_EVIDENCE shared reference: a static of AtomicU64; all mutation is
//!   atomic interior mutability and the completion seal is stored last with
//!   Release.
use super::*;
use core::mem::MaybeUninit;
use cyxia_kernel_core::control_plane::{
    Epochs, Identity,
    advice_disposition_v1::{AdviceDispositionV1, DISPOSITION_BYTES},
    advice_envelope_v1::{ADVICE_BYTES, AdviceEnvelopeV1, TrustedAdviceScope},
    advice_ledger_v0199::EvidenceLedger,
    apply_report_v1::{
        ActionStatus, ApplyReportV1, BoundReport, ExecutorBindingV1, ReportOrigin,
        TrustedApplyScope,
    },
    apply_work_v1::ApplyWorkV1,
    cpu0_v0199 as profile,
    decision_record_v3::{DECISION_BYTES, DecisionRecordV3, DecisionSource},
    feedback_v0199::CausalPair,
    fixed::{ChoiceSource, Pair},
    plan_wire_v2::PlanV2,
    registered_gate_v3::{
        AssistedScope, FrozenAction, Publication, RegisteredDecisionGate, Registration,
        TrustedRegistrationScope,
    },
    role_manifest_v0199::{
        DECISION_REGISTER, NativeRole, NativeRoleManifest, PUBLISH_PLAN, PrivateRegion, ROLE_COUNT,
        ROLES, Role, SEND_ADVICE,
    },
    rule_profile_v2::Profile,
    svc_bridge_v3::{FrozenNativePlan, SvcV3Bridge, VerifiedNativeCaller},
};
use cyxia_kernel_core::security::syscall_v3::decode_aarch64_svc_v3;
use sha2::{Digest, Sha256};

const FIRST_ADVICE_SPACE: usize = C * 2;
const ADVICE_SPACES: usize = ROLE_COUNT;
// Fixture capability table (EL1-owned; never read from EL0 bytes).
const ADVICE_CAP: u64 = 66;
const DECISION_CAP: u64 = 77;
const PUBLISHER_CAP: u64 = 88;
const OPS: Identity = Identity {
    id: 6,
    generation: 1,
};
const SEC: Identity = Identity {
    id: 7,
    generation: 1,
};
const CTRL: Identity = Identity {
    id: 2,
    generation: 1,
};
const PUB: Identity = Identity {
    id: 8,
    generation: 1,
};
const SUPER: Identity = Identity {
    id: 11,
    generation: 1,
};
const TARGET: Identity = Identity {
    id: 17,
    generation: 1,
};
const BOOT: u64 = 1;
const CTRL_EPOCH: u64 = 2;
const ADVISOR_EPOCH: u64 = 1;
const RULES_GEN: u64 = 7;
const MODEL_GEN: u64 = 9;
const LEDGER_GEN: u64 = 5;
const CORE_GEN: u64 = 6;
const SNAPSHOT_SEQ: u64 = 3;
const SAMPLED_NS: u64 = 100;
const NOW_NS: u64 = 150;
const EXPIRES_NS: u64 = 200;
const PLAN_SEQ: u64 = 1;
const DECISION_SEQ: u64 = 4;
const PLAN_VERSION: u64 = 7;
const EXEC_GEN: u64 = 9;
const COMPLETED_NS: u64 = 180;
const SETTLE_NS: u64 = 200;
const INSTALLED_NS: u64 = SAMPLED_NS + 10_000_000_000;
// Private DATA page layout (EL0 VA = DATA + offset).
const ENVELOPE_OFF: u64 = 64;
// Clear of every staged payload (register rec||disp ends at 560, publish
// sidecar at 576); EL0 records its observed x0 return here.
const OBSERVED_OFF: u64 = 768;
const REG_OUT_OFF: u64 = 640;
const PUB_SIDECAR_OFF: u64 = 320;
// Distinct QMP evidence marker ("CYXAE199").
const MAGIC: u64 = 0x4359_4145_3139_3939;
// CPU0-only acceptance counter for the unique native publish callback.
static ACCEPT_COUNT: AtomicU64 = AtomicU64::new(0);
// Bounded fixture executor "device": one EL1-owned target word.
#[repr(C, align(4096))]
struct ExecTarget(Page);
static mut EXEC_TARGET: ExecTarget = ExecTarget(Page::ZERO);
// Large control-plane guards in static storage (never the bounded EL1 stack).
static mut LEDGER: MaybeUninit<EvidenceLedger> = MaybeUninit::uninit();
static mut GATE: MaybeUninit<RegisteredDecisionGate<'static>> = MaybeUninit::uninit();
// The validated eight-role manifest snapshot (CPU0-only).
static mut MANIFEST_MEMBERS: [NativeRole; ROLE_COUNT] = [NativeRole {
    role: Role::Operations,
    actor: Identity {
        id: 0,
        generation: 0,
    },
    ttbr0_root: 0,
    private_rw: PrivateRegion { base: 0, bytes: 0 },
    caps: 0,
    control_ns_per_100ms: 0,
    cpu_mask: 0,
    thread_count: 0,
    endpoint_id: 0,
}; ROLE_COUNT];

fn ledger_ptr() -> *mut EvidenceLedger {
    core::ptr::addr_of_mut!(LEDGER).cast()
}
fn gate_ptr() -> *mut RegisteredDecisionGate<'static> {
    core::ptr::addr_of_mut!(GATE).cast()
}
fn sha(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}
fn lo(d: &[u8; 32]) -> u64 {
    u64::from_le_bytes(d[..8].try_into().unwrap())
}

// Verified fixture copyin/out adapter (identical contract to the role fixture):
// only the three statically registered pages of this stopped context may be
// accessed, through their checked high-half aliases. NOT a production VA walker.
fn copy_address(space: usize, va: u64, bytes: usize, write: bool) -> Option<(u64, u64)> {
    if space >= PRIVATE_SPACES {
        return None;
    }
    let page = va & !4095;
    let offset = va & 4095;
    let (root, mid, leaf, base) = unsafe {
        let root = core::ptr::addr_of!(ROOTS).cast::<Page>().add(space);
        let mid = core::ptr::addr_of!(MIDDLES).cast::<Page>().add(space);
        let leaf = core::ptr::addr_of!(LEAVES).cast::<Page>().add(space);
        let base = match page {
            CODE => core::ptr::addr_of!(v0199_advice_user_start) as u64,
            DATA => core::ptr::addr_of!(DATA_PAGES).cast::<Page>().add(space) as u64,
            STACK => core::ptr::addr_of!(USER_STACKS).cast::<Page>().add(space) as u64,
            _ => return None,
        };
        (root, mid, leaf, base)
    };
    let root_desc = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*root).0[0])) };
    let mid_desc = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*mid).0[0])) };
    if root_desc != (phys(mid as u64) | 3) || mid_desc != (phys(leaf as u64) | 3) {
        return None;
    }
    let desc =
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*leaf).0[(page / 4096) as usize])) };
    let pa = mmu::checked_user_leaf_span(desc, PhysAddr(phys(base)), offset, bytes, write).ok()?;
    Some((base.checked_add(offset)?, pa.0))
}
fn read_word(space: usize, off: u64) -> u64 {
    let (src, _) = copy_address(space, DATA + off, 8, false).expect("fixture read span");
    unsafe { core::ptr::read_volatile(src as *const u64) }
}
fn read_bytes(space: usize, off: u64, out: &mut [u8]) {
    let (src, _) = copy_address(space, DATA + off, out.len(), false).expect("fixture copyin span");
    for (i, b) in out.iter_mut().enumerate() {
        *b = unsafe { core::ptr::read_volatile((src + i as u64) as *const u8) };
    }
}
fn write_bytes(space: usize, off: u64, bytes: &[u8]) {
    let (dst, _) =
        copy_address(space, DATA + off, bytes.len(), true).expect("fixture copyout span");
    for (i, b) in bytes.iter().enumerate() {
        unsafe { core::ptr::write_volatile((dst + i as u64) as *mut u8, *b) };
    }
}

// ---- canonical wire builders (mirror the kernel-core host-test layouts) ----
fn rule_bytes() -> [u8; 80] {
    let mut b = [0u8; 80];
    b[0..4].copy_from_slice(&0x4359_5255u32.to_le_bytes());
    b[4..6].copy_from_slice(&2u16.to_le_bytes());
    b[6..8].copy_from_slice(&32u16.to_le_bytes());
    b[8..16].copy_from_slice(&RULES_GEN.to_le_bytes());
    b[16..20].copy_from_slice(&1u32.to_le_bytes());
    b[20..24].copy_from_slice(&80u32.to_le_bytes());
    b[32..36].copy_from_slice(&1u32.to_le_bytes()); // rule id 1
    b[36..38].copy_from_slice(&1u16.to_le_bytes()); // D01
    b[38..40].copy_from_slice(&1u16.to_le_bytes()); // kind 1
    b[40..48].copy_from_slice(&TARGET.id.to_le_bytes());
    b[48..50].copy_from_slice(&1u16.to_le_bytes()); // choice_policy = 1 (AI assist)
    b[52..54].copy_from_slice(&2u16.to_le_bytes()); // two legal values
    b[56..60].copy_from_slice(&48u32.to_le_bytes());
    b[64..66].copy_from_slice(&2u16.to_le_bytes()); // ordinal 2, rank 0 (fallback)
    b[72..74].copy_from_slice(&4u16.to_le_bytes()); // ordinal 4, rank 1 (advice)
    b[74..76].copy_from_slice(&1u16.to_le_bytes());
    b
}
fn advice_expected() -> [u8; ADVICE_BYTES] {
    let mut a = [0u8; ADVICE_BYTES];
    a[0..4].copy_from_slice(&0x4359_4131u32.to_le_bytes());
    a[4..6].copy_from_slice(&1u16.to_le_bytes());
    a[6..8].copy_from_slice(&(ADVICE_BYTES as u16).to_le_bytes());
    for (at, v) in [
        (8, ADVISOR_EPOCH),
        (16, 1),
        (24, SNAPSHOT_SEQ),
        (32, TARGET.id),
        (40, TARGET.generation),
        (48, LEDGER_GEN),
        (56, CORE_GEN),
        (64, EXPIRES_NS),
        (72, MODEL_GEN),
    ] {
        a[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }
    for (at, v) in [(80, 1u16), (82, 1), (84, 1), (86, 2)] {
        a[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }
    a[88..120].fill(3);
    a[120..152].fill(1);
    a
}
fn plan_bytes() -> [u8; 212] {
    let mut b = [0u8; 212];
    b[0..4].copy_from_slice(&0x4359_4c31u32.to_le_bytes());
    b[4..6].copy_from_slice(&2u16.to_le_bytes());
    b[6..8].copy_from_slice(&64u16.to_le_bytes());
    b[8..12].copy_from_slice(&212u32.to_le_bytes());
    b[12..14].copy_from_slice(&1u16.to_le_bytes()); // action count
    b[14..16].copy_from_slice(&1u16.to_le_bytes()); // flags = 1 (model active)
    b[16..24].copy_from_slice(&PLAN_SEQ.to_le_bytes());
    b[32..40].copy_from_slice(&MODEL_GEN.to_le_bytes());
    b[40..48].copy_from_slice(&CTRL_EPOCH.to_le_bytes());
    b[48..56].copy_from_slice(&SNAPSHOT_SEQ.to_le_bytes());
    b[56..64].copy_from_slice(&INSTALLED_NS.to_le_bytes());
    let h = 64;
    b[h..h + 4].copy_from_slice(&0x4359_5031u32.to_le_bytes());
    b[h + 4..h + 6].copy_from_slice(&2u16.to_le_bytes());
    b[h + 6..h + 8].copy_from_slice(&144u16.to_le_bytes());
    b[h + 8..h + 10].copy_from_slice(&1u16.to_le_bytes()); // D01
    b[h + 10..h + 12].copy_from_slice(&1u16.to_le_bytes()); // kind 1
    b[h + 12..h + 16].copy_from_slice(&4u32.to_le_bytes()); // payload len
    for (at, v) in [
        (16, CTRL_EPOCH),
        (24, DECISION_SEQ),
        (32, SNAPSHOT_SEQ),
        (40, TARGET.id),
        (48, TARGET.generation),
        (56, LEDGER_GEN),
        (64, CORE_GEN),
        (72, EXPIRES_NS),
    ] {
        b[h + at..h + at + 8].copy_from_slice(&v.to_le_bytes());
    }
    b[h + 80..h + 112].fill(3); // model_hash
    b[h + 112..h + 144].fill(1); // candidate_set_hash
    b[h + 144..h + 146].copy_from_slice(&1u16.to_le_bytes()); // candidate_index = 1
    b[h + 146..h + 148].copy_from_slice(&[4u8, 0]); // D01 GroupWeight(4)
    b
}
fn decision_bytes(plan: &[u8], rules: &[u8]) -> [u8; DECISION_BYTES] {
    let mut b = [0u8; DECISION_BYTES];
    b[0..4].copy_from_slice(&0x4359_4431u32.to_le_bytes());
    b[4..6].copy_from_slice(&3u16.to_le_bytes());
    b[6..8].copy_from_slice(&(DECISION_BYTES as u16).to_le_bytes());
    for (at, v) in [
        (8, BOOT),
        (16, CTRL_EPOCH),
        (24, DECISION_SEQ),
        (32, PLAN_SEQ),
        (40, SNAPSHOT_SEQ),
        (48, TARGET.id),
        (56, TARGET.generation),
        (64, LEDGER_GEN),
        (72, CORE_GEN),
        (80, RULES_GEN),
        (144, EXPIRES_NS),
    ] {
        b[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }
    b[88..92].copy_from_slice(&1u32.to_le_bytes()); // rule id
    b[94..96].copy_from_slice(&1u16.to_le_bytes()); // domain D01
    b[96..98].copy_from_slice(&1u16.to_le_bytes()); // action kind
    b[98] = 2; // mode ASSISTED
    b[99] = 1; // source AI_ASSISTED
    b[100] = 1; // disposition ADOPTED
    b[101] = 1; // advice present
    b[102..104].copy_from_slice(&1u16.to_le_bytes()); // selected_index
    b[104..106].copy_from_slice(&1u16.to_le_bytes()); // recommended_index
    b[108..112].copy_from_slice(&8u32.to_le_bytes()); // reason 8 (adopted)
    b[112..120].copy_from_slice(&ADVISOR_EPOCH.to_le_bytes());
    b[120..128].copy_from_slice(&1u64.to_le_bytes()); // advice_seq
    b[128..136].copy_from_slice(&MODEL_GEN.to_le_bytes());
    b[152..156].copy_from_slice(&3u32.to_le_bytes()); // allowed_mask 0b11
    b[156..158].copy_from_slice(&0u16.to_le_bytes()); // fallback_index
    b[158..160].copy_from_slice(&1u16.to_le_bytes()); // choice_policy
    b[160..192].copy_from_slice(&sha(rules));
    b[192..224].copy_from_slice(&sha(plan));
    b[224..256].fill(1); // candidate_set_hash
    b
}
fn disposition_bytes(advice: &[u8], rec: &[u8], rules: &[u8]) -> [u8; DISPOSITION_BYTES] {
    let mut b = [0u8; DISPOSITION_BYTES];
    b[0..4].copy_from_slice(&0x4359_4144u32.to_le_bytes());
    b[4..6].copy_from_slice(&1u16.to_le_bytes());
    b[6..8].copy_from_slice(&(DISPOSITION_BYTES as u16).to_le_bytes());
    for (at, v) in [
        (8, BOOT),
        (16, ADVISOR_EPOCH),
        (24, 1),
        (32, SNAPSHOT_SEQ),
        (40, CTRL_EPOCH),
        (48, DECISION_SEQ),
        (56, TARGET.id),
        (64, TARGET.generation),
        (72, MODEL_GEN),
        (80, NOW_NS),
    ] {
        b[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }
    for (at, v) in [
        (88, 1u16),
        (90, 1),
        (92, 1),  // state ADOPTED
        (94, 0),  // reason 0
        (100, 0), // fallback_index
        (102, 1), // recommended_index
        (104, 1), // selected_index
        (106, 1), // choice_policy
    ] {
        b[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }
    b[96..100].copy_from_slice(&3u32.to_le_bytes()); // allowed_mask
    b[112..144].fill(1); // candidate_set_hash
    b[144..176].copy_from_slice(&sha(advice));
    b[176..208].copy_from_slice(&sha(rec));
    b[208..240].copy_from_slice(&sha(rules));
    b
}
fn report_bytes() -> [u8; 98] {
    let mut b = [0u8; 98];
    for (at, v) in [
        (0, BOOT),
        (8, CTRL_EPOCH),
        (16, PLAN_SEQ),
        (32, TARGET.id),
        (40, TARGET.generation),
        (48, EXEC_GEN),
        (56, PLAN_VERSION),
        (72, COMPLETED_NS),
    ] {
        b[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }
    b[26..28].copy_from_slice(&1u16.to_le_bytes()); // domain D01
    b[28..30].copy_from_slice(&1u16.to_le_bytes()); // state APPLIED
    b[68..72].copy_from_slice(&2u32.to_le_bytes()); // action len
    b[96..98].copy_from_slice(&[4u8, 0]); // exact action payload
    b
}
fn binding() -> ExecutorBindingV1 {
    ExecutorBindingV1 {
        domain: 1,
        role: 1,
        active: true,
        target: TARGET,
        executor_generation: EXEC_GEN,
        holder: Identity {
            id: 0,
            generation: 0,
        },
        endpoint_cap_id: 0,
    }
}

/// Immutable trusted artifacts borrowed by the dispatch glue.
struct Bundle<'a> {
    plan: &'a [u8],
    rec: &'a [u8; DECISION_BYTES],
    profile: &'a Profile<'a>,
    local: &'a FrozenAction<'a>,
    ctx: TrustedRegistrationScope,
    scope: &'a AssistedScope<'a>,
}

/// Small CPU0-owned state; the large guards live in static storage.
struct Fixture {
    pair: Pair,
    advice_wire: [u8; ADVICE_BYTES],
}
impl Fixture {
    fn new() -> Self {
        Self {
            pair: Pair::new(OPS, SEC).expect("distinct operations/security brains"),
            advice_wire: [0; ADVICE_BYTES],
        }
    }

    /// EL1 trap adapter: authenticate the caller from its registered address
    /// space (never from user bytes), checked copyin, then dispatch. Returns a
    /// fixture outcome code (1 accepted/recorded, 2 exact retry/replay, 0 denied).
    fn dispatch(&mut self, space: usize, esr: u64, regs: &[u64; 31], b: &Bundle<'_>) -> u64 {
        let role_index = space - FIRST_ADVICE_SPACE;
        let member = unsafe {
            core::ptr::read_volatile(
                core::ptr::addr_of!(MANIFEST_MEMBERS)
                    .cast::<NativeRole>()
                    .add(role_index),
            )
        };
        let call = match decode_aarch64_svc_v3(3, esr, regs) {
            Ok(c) => c,
            Err(_) => return 0,
        };
        let args = call.args;
        let cpu = cpu::slot();
        match regs[8] {
            0x50 if args[2] == ADVICE_BYTES as u64 => {
                // Advice intake glue (no SvcV3Bridge submit entry exists). The
                // outcome is returned to EL0 in x0 by the turn loop.
                if cpu != 0
                    || member.caps & SEND_ADVICE != SEND_ADVICE
                    || args[0] != ADVICE_CAP
                    || args[3] != 0
                {
                    return 0;
                }
                let mut copy = [0u8; ADVICE_BYTES];
                if copy_address(space, args[1], ADVICE_BYTES, false).is_none() {
                    return 0;
                }
                read_bytes(space, args[1] & 4095, &mut copy);
                let trusted = trusted_scope();
                let ledger = unsafe { &mut *ledger_ptr() };
                let ok = self
                    .pair
                    .submit_operations_wire(member.actor, &copy, &trusted)
                    .is_ok()
                    && ledger.record(OPS, &copy, &trusted).is_ok();
                if ok {
                    self.advice_wire = copy;
                }
                u64::from(ok)
            }
            0x50 if args[2] == (DECISION_BYTES + DISPOSITION_BYTES) as u64 => {
                // REGISTER via the real SvcV3Bridge 0x50 endpoint.
                if cpu != 0
                    || member.caps & DECISION_REGISTER != DECISION_REGISTER
                    || args[0] != DECISION_CAP
                {
                    return 0;
                }
                let mut copy = [0u8; DECISION_BYTES + DISPOSITION_BYTES];
                if copy_address(space, args[1], copy.len(), false).is_none() {
                    return 0;
                }
                read_bytes(space, args[1] & 4095, &mut copy);
                let caller = VerifiedNativeCaller {
                    identity: member.actor,
                    package_abi: 3,
                    endpoint_cap: DECISION_CAP,
                    cpu,
                };
                let frozen = FrozenNativePlan {
                    bytes: b.plan,
                    sidecars: core::slice::from_ref(b.rec),
                    rules: b.profile,
                    actions: core::slice::from_ref(b.local),
                    context: b.ctx,
                };
                let mut bridge = SvcV3Bridge {
                    gate: unsafe { &mut *gate_ptr() },
                    decision_endpoint_cap: DECISION_CAP,
                    publisher_cap: PUBLISHER_CAP,
                };
                let ledger = unsafe { &mut *ledger_ptr() };
                match bridge.register_assisted_one(caller, args, &copy, &frozen, b.scope, ledger) {
                    Ok(Registration::Frozen) => 1,
                    Ok(Registration::ExactRetry) => 2,
                    Err(_) => 0,
                }
            }
            0x41 => {
                // PUBLISH via the real SvcV3Bridge 0x41 endpoint.
                if cpu != 0 || member.caps & PUBLISH_PLAN != PUBLISH_PLAN {
                    return 0;
                }
                let plan_len = args[1] as usize;
                let mut plan_copy = [0u8; 212];
                let mut side_copy = [0u8; DECISION_BYTES];
                if plan_len != plan_copy.len()
                    || copy_address(space, args[0], plan_len, false).is_none()
                    || copy_address(space, args[2], DECISION_BYTES, false).is_none()
                {
                    return 0;
                }
                read_bytes(space, args[0] & 4095, &mut plan_copy);
                read_bytes(space, args[2] & 4095, &mut side_copy);
                let caller = VerifiedNativeCaller {
                    identity: member.actor,
                    package_abi: 3,
                    endpoint_cap: PUBLISHER_CAP,
                    cpu,
                };
                let frozen = FrozenNativePlan {
                    bytes: b.plan,
                    sidecars: core::slice::from_ref(b.rec),
                    rules: b.profile,
                    actions: core::slice::from_ref(b.local),
                    context: b.ctx,
                };
                let mut bridge = SvcV3Bridge {
                    gate: unsafe { &mut *gate_ptr() },
                    decision_endpoint_cap: DECISION_CAP,
                    publisher_cap: PUBLISHER_CAP,
                };
                match bridge.publish_assisted_one(
                    caller,
                    args,
                    &plan_copy,
                    core::slice::from_ref(&side_copy),
                    &frozen,
                    b.scope,
                    || {
                        ACCEPT_COUNT.fetch_add(1, Ordering::Relaxed);
                        Ok(())
                    },
                ) {
                    Ok(Publication::AdapterAccepted) => 1,
                    Ok(Publication::ReplayNoEffect) => 2,
                    Err(_) => 0,
                }
            }
            _ => 0,
        }
    }

    /// Shared bounded execute loop: dispatch the main SVC, deliver the outcome
    /// in x0 (canonical syscall return), resume past the SVC, finish on yield.
    fn execute_loop(
        &mut self,
        ctx: &mut user::Context,
        space: usize,
        b: &Bundle<'_>,
    ) -> (u64, u64, u64) {
        let mut main = (0u64, 0u64, 0u64);
        let mut trapped = false;
        for _ in 0..64 {
            execute(ctx, space);
            if ctx.kind == 9 {
                continue; // private PPI preemption; restore and resume
            }
            if ctx.kind != 8 || ctx.esr >> 26 != 0x15 {
                fatal(300);
            }
            let iss = ctx.esr & 0xffff;
            if iss == 4 {
                trapped = true;
                break; // bounded yield
            }
            if iss == 3 {
                fatal(310); // EL0 cookie mismatch
            }
            if iss != 0 {
                fatal(320);
            }
            let regs = ctx.regs;
            let outcome = self.dispatch(space, ctx.esr, &regs, b);
            main = (ctx.esr, regs[8], outcome);
            ctx.regs[0] = outcome; // EL1 syscall return value
            // ELR_EL1 already points past the trapped SVC instruction; resume
            // there with the return value installed in x0.
        }
        if !trapped {
            fatal(330);
        }
        main
    }

    /// Advice turn: EL0 constructs the envelope (mode 1/2/3) and submits.
    fn turn(&mut self, space: usize, mode: u64, b: &Bundle<'_>) -> (u64, u64, u64) {
        let mut ctx = context(space);
        ctx.regs[7] = mode; // mode selector (x7 is not a syscall argument)
        self.execute_loop(&mut ctx, space, b)
    }

    /// Carrier turn: EL1 pre-sets the syscall number/arguments in the context;
    /// EL0 traps the trusted REGISTER (0x50) / PUBLISH (0x41) payload bytes.
    fn carrier(
        &mut self,
        space: usize,
        x8: u64,
        args: [u64; 6],
        b: &Bundle<'_>,
    ) -> (u64, u64, u64) {
        let mut ctx = context(space);
        ctx.regs[8] = x8;
        ctx.regs[..6].copy_from_slice(&args);
        ctx.regs[7] = 4; // carrier mode (set after args; x7 is not an argument)
        self.execute_loop(&mut ctx, space, b)
    }
}

fn epochs() -> Epochs {
    Epochs {
        boot: BOOT,
        controller: CTRL_EPOCH,
        model: MODEL_GEN,
        resources: LEDGER_GEN,
        cores: CORE_GEN,
    }
}
fn trusted_scope() -> TrustedAdviceScope<'static> {
    TrustedAdviceScope {
        epochs: epochs(),
        advisor_epoch: ADVISOR_EPOCH,
        snapshot_seq: SNAPSHOT_SEQ,
        domain: 1,
        target: TARGET,
        sampled_ns: SAMPLED_NS,
        now_ns: NOW_NS,
        action_kind: 1,
        candidates: &[2, 4],
        model_hash: [3; 32],
        candidate_set_hash: [1; 32],
    }
}

/// Construct the large guards directly into static control storage. Kept in a
/// lean helper so the by-value constructor temporary fits the bounded EL1 stack.
fn init_control_guards() {
    let ledger = EvidenceLedger::new(OPS, CTRL, SUPER, BOOT, ADVISOR_EPOCH).expect("causal ledger");
    unsafe { core::ptr::write(ledger_ptr(), ledger) };
    let gate = RegisteredDecisionGate::new_with_terminal_owner(CTRL, PUB, SUPER, BOOT, CTRL_EPOCH)
        .expect("registered decision gate");
    unsafe { core::ptr::write(gate_ptr(), gate) };
}

pub(super) fn run() -> ! {
    assert_eq!(
        cpu::slot(),
        0,
        "only boot CPU0 owns the advice-chain fixture"
    );
    assert_eq!(PRIVATE_SPACES, FIRST_ADVICE_SPACE + ADVICE_SPACES);
    assert_eq!(ONLINE.load(Ordering::Acquire), profile::ONLINE);
    report("V0199_ADVICE_STAGE", 1, 0, 0);
    init_control_guards();

    let fixed_limits = Limits {
        resource_epoch: 1,
        min_control_cores: 1,
        min_control_capacity: 1,
        min_business_capacity: 3,
        committed_business_capacity: 3,
        protected_control: profile::CONTROL_MASK,
        protected_business: profile::BUSINESS_MASK,
        cooldown_ticks: 0,
    };
    let ownership = Ownership::<REQUIRED>::new_v0199_cpu0(
        profile::ONLINE,
        [1; REQUIRED],
        core::array::from_fn(|i| 1 << i),
        fixed_limits,
    )
    .expect("fixed CPU0 control ownership");
    let snapshot = ownership.snapshot();
    profile::validate_snapshot(snapshot).expect("single CPU0 + three business cores");
    report("V0199_ADVICE_STAGE", 2, snapshot.control, snapshot.business);

    // Map the fixture EL0 advisor program into each advice space's CODE leaf.
    let code = core::ptr::addr_of!(v0199_advice_user_start) as u64;
    let code_end = core::ptr::addr_of!(v0199_advice_user_end) as u64;
    assert!(code.is_multiple_of(4096) && code_end - code <= 4096);
    for index in 0..ADVICE_SPACES {
        let space = FIRST_ADVICE_SPACE + index;
        let leaf = unsafe { core::ptr::addr_of_mut!(LEAVES).cast::<Page>().add(space) };
        unsafe {
            (*leaf).0[(CODE / 4096) as usize] =
                mmu::encode_user_leaf(PhysAddr(phys(code)), false, true).unwrap();
        }
    }
    unsafe {
        core::arch::asm!(
            "dsb ishst",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            options(nostack)
        );
    }

    // Eight distinct EL1-owned TTBR0/private-page manifest entries (role style).
    let members = core::array::from_fn(|index| {
        let space = FIRST_ADVICE_SPACE + index;
        let root = unsafe { core::ptr::addr_of!(ROOTS).cast::<Page>().add(space) as u64 };
        let data = unsafe { core::ptr::addr_of!(DATA_PAGES).cast::<Page>().add(space) as u64 };
        NativeRole {
            role: ROLES[index],
            actor: Identity {
                id: ROLES[index].id() as u64,
                generation: 1,
            },
            ttbr0_root: phys(root),
            private_rw: PrivateRegion {
                base: phys(data),
                bytes: 4096,
            },
            caps: ROLES[index].allowed_caps(),
            control_ns_per_100ms: 2_000_000,
            cpu_mask: profile::CONTROL_MASK,
            thread_count: 1,
            endpoint_id: 0xC000 + index as u64,
        }
    });
    let manifest = NativeRoleManifest {
        online_mask: profile::ONLINE,
        members,
        other_protected_pool_bytes: 5 * 1024 * 1024,
        other_control_ns_per_100ms: 45_000_000,
    };
    manifest
        .validate()
        .expect("eight distinct native TTBR/role/cap entries");
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(MANIFEST_MEMBERS), members);
    }
    report(
        "V0199_ADVICE_STAGE",
        3,
        manifest.members[0].ttbr0_root,
        manifest.members[0].private_rw.base,
    );

    wait(|| (1..REQUIRED).all(|slot| PROGRESS[slot * 2].load(Ordering::Acquire) >= 2));
    gic()
        .enable(TIMER_IRQ.load(Ordering::Acquire) as u32)
        .expect("CPU0 timer PPI");
    report(
        "V0199_ADVICE_STAGE",
        4,
        PROGRESS[2].load(Ordering::Acquire),
        PROGRESS[4].load(Ordering::Acquire),
    );

    // Trusted frozen artifacts (EL1-owned; the advice bytes are proven equal to
    // the actual EL0-constructed envelope after the positive submit turn).
    let rules = rule_bytes();
    let profile = Profile::parse(&rules).expect("RuleProfile v2");
    let candidates = [2u16, 4];
    let payload = [4u8, 0];
    let local = FrozenAction {
        domain_id: 1,
        target: TARGET,
        candidate_set_hash: [1; 32],
        static_ordinals: &candidates,
        raw_fields: [None; 7],
        action_payload: &payload,
    };
    let trusted = trusted_scope();
    let scope = AssistedScope {
        advice: &trusted,
        assisted_mode: true,
        offline_model_authorized: true,
    };
    let ctx = TrustedRegistrationScope {
        boot_epoch: BOOT,
        controller_epoch: CTRL_EPOCH,
        rules_generation: RULES_GEN,
        rules_hash: sha(&rules),
        base_plan_version: 0,
        ledger_generation: LEDGER_GEN,
        core_generation: CORE_GEN,
        snapshot_seq: SNAPSHOT_SEQ,
        sampled_ns: SAMPLED_NS,
        now_ns: NOW_NS,
    };
    let advice = advice_expected();
    let plan = plan_bytes();
    let rec = decision_bytes(&plan, &rules);
    let disp = disposition_bytes(&advice, &rec, &rules);
    let bundle = Bundle {
        plan: &plan,
        rec: &rec,
        profile: &profile,
        local: &local,
        ctx,
        scope: &scope,
    };
    let mut fx = Fixture::new();

    let ops_space = FIRST_ADVICE_SPACE; // Operations (role 6)
    let sec_space = FIRST_ADVICE_SPACE + 1; // Security (role 7)
    let ctrl_space = FIRST_ADVICE_SPACE + 2; // Controller (role 2)
    let pub_space = FIRST_ADVICE_SPACE + 3; // Publisher (role 8)

    // (1) POSITIVE: EL0 operations advisor constructs the envelope and submits.
    let (esr, x8, outcome) = fx.turn(ops_space, 1, &bundle);
    assert_eq!(
        (esr, x8, outcome),
        (0x5600_0000, 0x50, 1),
        "advice submit must be recorded"
    );
    assert_eq!(
        fx.advice_wire, advice,
        "EL0-constructed envelope must equal the trusted expectation"
    );
    assert_eq!(unsafe { (&*ledger_ptr()).pending() }, 1);
    // Prove the causal pair links the ACTUAL EL0 bytes, not a separate copy.
    AdviceDispositionV1::decode(&disp)
        .unwrap()
        .matches_decision_pair(BOOT, &fx.advice_wire, &rec)
        .expect("disposition links real EL0 advice + decision");
    assert_eq!(
        read_word(ops_space, OBSERVED_OFF),
        1,
        "EL0 must observe the x0 return receipt"
    );
    report("V0199_ADVICE_SUBMIT", OPS.id, esr, outcome);

    // (2) Independent RuleProfile review adopts the advice candidate (4 != fallback 2).
    let review = fx
        .pair
        .review_with_rule_profile(
            &profile,
            RULES_GEN,
            trusted.review_scope(),
            [None; 7],
            &candidates,
            true,
        )
        .expect("rule profile review");
    assert_eq!(review.source, ChoiceSource::OperationsAdvice);
    assert_eq!(review.candidate, 4);
    report(
        "V0199_ADVICE_REVIEW",
        review.candidate as u64,
        review.source as u64,
        0,
    );

    // (3) NEGATIVES: wrong identity (security space), illegal domain, forged cap.
    let pending_before = unsafe { (&*ledger_ptr()).pending() };
    let sec = fx.turn(sec_space, 1, &bundle);
    assert_eq!(sec.2, 0, "security role lacks SEND_ADVICE");
    let illegal = fx.turn(ops_space, 2, &bundle);
    assert_eq!(illegal.2, 0, "illegal domain must never be recorded");
    let forged = fx.turn(ops_space, 3, &bundle);
    assert_eq!(forged.2, 0, "forged cap must be rejected");
    assert_eq!(
        unsafe { (&*ledger_ptr()).pending() },
        pending_before,
        "no negative advice may enter the ledger"
    );
    assert_eq!(read_word(ops_space, OBSERVED_OFF), 0);
    report("V0199_ADVICE_NEG", sec.2, illegal.2, forged.2);

    // (4) NEGATIVE: wrong CPU at the EL1 bridge boundary (every real trap is CPU0).
    let mut recdisp = [0u8; DECISION_BYTES + DISPOSITION_BYTES];
    recdisp[..DECISION_BYTES].copy_from_slice(&rec);
    recdisp[DECISION_BYTES..].copy_from_slice(&disp);
    {
        let caller = VerifiedNativeCaller {
            identity: CTRL,
            package_abi: 3,
            endpoint_cap: DECISION_CAP,
            cpu: 1,
        };
        let frozen = FrozenNativePlan {
            bytes: &plan,
            sidecars: core::slice::from_ref(&rec),
            rules: &profile,
            actions: core::slice::from_ref(&local),
            context: ctx,
        };
        let mut bridge = SvcV3Bridge {
            gate: unsafe { &mut *gate_ptr() },
            decision_endpoint_cap: DECISION_CAP,
            publisher_cap: PUBLISHER_CAP,
        };
        let args = [
            DECISION_CAP,
            DATA + ENVELOPE_OFF,
            recdisp.len() as u64,
            0,
            DATA + REG_OUT_OFF,
            8,
        ];
        let ledger = unsafe { &mut *ledger_ptr() };
        assert!(
            bridge
                .register_assisted_one(caller, args, &recdisp, &frozen, &scope, ledger)
                .is_err(),
            "wrong CPU must be denied"
        );
    }
    assert!(
        !unsafe { (&*gate_ptr()).has_unpublished() },
        "wrong-CPU register must not freeze a plan"
    );
    report("V0199_ADVICE_WRONG_CPU", 1, 0, 0);

    // (5) REGISTER via real EL0 SVC 0x50 (controller carries trusted rec||disp).
    // EL1 stages the trusted payload (read back by EL1 copyin); the syscall
    // arguments are delivered in registers, never via EL1-staged EL0 loads.
    write_bytes(ctrl_space, ENVELOPE_OFF, &recdisp);
    let reg_args = [
        DECISION_CAP,
        DATA + ENVELOPE_OFF,
        recdisp.len() as u64,
        0,
        DATA + REG_OUT_OFF,
        8,
    ];
    let reg = fx.carrier(ctrl_space, 0x50, reg_args, &bundle);
    assert_eq!((reg.1, reg.2), (0x50, 1), "register must freeze");
    assert!(unsafe { (&*gate_ptr()).has_unpublished() });
    assert_eq!(read_word(ctrl_space, OBSERVED_OFF), 1);
    report("V0199_ADVICE_REGISTER", CTRL.id, reg.0, reg.2);
    // Exact retry is idempotent (no second frozen plan).
    let reg_retry = fx.carrier(ctrl_space, 0x50, reg_args, &bundle);
    assert_eq!(reg_retry.2, 2, "exact register retry");
    report("V0199_ADVICE_REGISTER_RETRY", CTRL.id, reg_retry.2, 0);

    // (6) PUBLISH via real EL0 SVC 0x41 (publisher carries trusted plan+sidecar).
    write_bytes(pub_space, ENVELOPE_OFF, &plan);
    write_bytes(pub_space, PUB_SIDECAR_OFF, &rec);
    let pub_args = [
        DATA + ENVELOPE_OFF,
        plan.len() as u64,
        DATA + PUB_SIDECAR_OFF,
        1,
        0,
        0,
    ];
    let pub_result = fx.carrier(pub_space, 0x41, pub_args, &bundle);
    assert_eq!(
        (pub_result.1, pub_result.2),
        (0x41, 1),
        "publish must be adapter-accepted"
    );
    assert_eq!(unsafe { (&*gate_ptr()).published_count() }, 1);
    assert_eq!(
        ACCEPT_COUNT.load(Ordering::Relaxed),
        1,
        "unique native accept"
    );
    report("V0199_ADVICE_PUBLISH", PUB.id, pub_result.0, pub_result.2);
    // NEGATIVE: operations role may not publish.
    write_bytes(ops_space, ENVELOPE_OFF, &plan);
    write_bytes(ops_space, PUB_SIDECAR_OFF, &rec);
    let bad_pub = fx.carrier(ops_space, 0x41, pub_args, &bundle);
    assert_eq!(bad_pub.2, 0, "non-publisher must be denied");
    assert_eq!(unsafe { (&*gate_ptr()).published_count() }, 1);
    assert_eq!(ACCEPT_COUNT.load(Ordering::Relaxed), 1);
    report("V0199_ADVICE_BAD_PUBLISH", OPS.id, bad_pub.2, 0);
    // Replay publish has no second effect.
    let pub_replay = fx.carrier(pub_space, 0x41, pub_args, &bundle);
    assert_eq!(pub_replay.2, 2, "replay publish no effect");
    assert_eq!(
        ACCEPT_COUNT.load(Ordering::Relaxed),
        1,
        "replay must not re-accept"
    );
    report(
        "V0199_ADVICE_PUBLISH_REPLAY",
        PUB.id,
        pub_replay.2,
        ACCEPT_COUNT.load(Ordering::Relaxed),
    );

    // (7) Executor: claim work, apply the D01 GroupWeight(4) to the fixture target.
    let claim_scope = TrustedApplyScope {
        boot_epoch: BOOT,
        plan_version: PLAN_VERSION,
        now_ns: NOW_NS,
    };
    let frame = unsafe { &mut *gate_ptr() }
        .claim_apply_work(
            &plan,
            0,
            claim_scope,
            binding(),
            ReportOrigin::Kernel,
            |_| Ok(()),
        )
        .expect("claim apply work");
    let work = ApplyWorkV1::decode(frame.bytes()).expect("apply work");
    assert_eq!(work.payload, &[4, 0]);
    // Real bounded fixture effect: write the adopted value to the target word.
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(EXEC_TARGET.0.0[0]), 4);
    }
    let report_wire = report_bytes();
    let parsed_report = ApplyReportV1::decode(&report_wire).expect("apply report");
    assert_eq!(parsed_report.state, ActionStatus::Applied);
    assert!(work.matches_report(parsed_report));
    report("V0199_ADVICE_APPLY", PLAN_SEQ, COMPLETED_NS, 4);

    // (8) Supervisor terminal settlement with the exact causal sidecar. Feedback
    // custody uses a no-op retain (the bounded inbox is not instantiated); the
    // gate still independently re-validates the exact CausalPair.
    let bound = [BoundReport {
        bytes: &report_wire,
        origin: ReportOrigin::Kernel,
    }];
    let pair = CausalPair {
        advice: &fx.advice_wire,
        disposition: &disp,
    };
    let settle_scope = TrustedApplyScope {
        boot_epoch: BOOT,
        plan_version: PLAN_VERSION,
        now_ns: SETTLE_NS,
    };
    let summary = unsafe { &mut *gate_ptr() }
        .settle_verified_apply_reports_with_feedback(
            SUPER,
            &plan,
            &bound,
            &[binding()],
            settle_scope,
            Some(pair),
            |_, r| {
                // Independent native effect proof: re-read the fixture target.
                let actual =
                    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(EXEC_TARGET.0.0[0])) };
                if r.state == ActionStatus::Applied && actual == 4 {
                    Ok(())
                } else {
                    Err(Error::Denied)
                }
            },
            |_| Ok(()),
        )
        .expect("terminal settlement");
    assert_eq!(summary.plan_seq, PLAN_SEQ);
    assert_eq!(summary.action_count, 1);
    assert_eq!(
        unsafe { (&*gate_ptr()).published_count() },
        0,
        "terminal releases the obligation"
    );
    let terminal = unsafe { (&*gate_ptr()).terminal_summary(SUPER, PLAN_SEQ) }
        .unwrap()
        .expect("terminal summary");
    assert_eq!(terminal.plan_seq, PLAN_SEQ);
    // Causal label derived from the registered decision (adopted != fallback).
    let causal_label: u64 = if rec[102..104] == rec[156..158] { 1 } else { 2 };
    assert_eq!(causal_label, 2, "adopted candidate differs from fallback");
    report(
        "V0199_ADVICE_SETTLE",
        summary.plan_seq,
        summary.action_count as u64,
        causal_label,
    );

    // (9) Full causal-chain linkage assertions.
    let adv = AdviceEnvelopeV1::decode(&fx.advice_wire).unwrap();
    let d = AdviceDispositionV1::decode(&disp).unwrap();
    let r = DecisionRecordV3::decode(&rec).unwrap();
    let p = PlanV2::decode(&plan).unwrap();
    assert_eq!(adv.advice_seq, d.advice_seq);
    assert_eq!(d.advice_seq, r.advice_seq);
    assert_eq!(d.decision_seq, r.decision_seq);
    assert_eq!(r.plan_seq, p.header.plan_seq);
    assert_eq!(p.header.plan_seq, parsed_report.key.plan_seq);
    assert_eq!(parsed_report.key.plan_seq, summary.plan_seq);
    assert_eq!(d.advice_digest, sha(&fx.advice_wire));
    assert_eq!(d.decision_digest, sha(&rec));
    assert_eq!(r.plan_digest, sha(&plan));
    assert_eq!(d.state, 1);
    assert_eq!(r.source, DecisionSource::AiAssisted);
    report(
        "V0199_ADVICE_CHAIN",
        adv.advice_seq,
        r.plan_seq,
        summary.plan_seq,
    );

    // (10) Business CPUs kept running; deterministic cleanup.
    for slot in 1..REQUIRED {
        assert!(PROGRESS[slot * 2].load(Ordering::Acquire) >= 2);
        assert_eq!(PROGRESS[slot * 2 + 1].load(Ordering::Acquire), 0);
    }
    for gate in GATES.iter().take(REQUIRED).skip(1) {
        close_gate(gate);
    }
    wait(|| (1..REQUIRED).all(|slot| GATES[slot].quiescent()));
    QUIT.store(true, Ordering::Release);
    wait(|| STOPPED.load(Ordering::Acquire) == 14);
    check_failures();
    for slot in 1..REQUIRED {
        report(
            "V0199_ADVICE_BUSINESS",
            slot as u64,
            PROGRESS[slot * 2].load(Ordering::Acquire),
            IRQS[slot].load(Ordering::Acquire),
        );
    }

    // (11) QMP-readable evidence page.
    let words = unsafe { &*core::ptr::addr_of!(SMP_EVIDENCE) };
    for w in words.words.iter() {
        w.store(0, Ordering::Relaxed);
    }
    let summary_words = [
        MAGIC,
        1,
        0, // completion seal set last
        15,
        1,
        14,
        adv.advice_seq,
        r.plan_seq,
        r.decision_seq,
        d.state as u64,
        r.selected_index as u64,
        r.fallback_index as u64,
        causal_label,
        ACCEPT_COUNT.load(Ordering::Relaxed),
        summary.action_count as u64,
        5, // five rejected negatives
    ];
    for (i, v) in summary_words.into_iter().enumerate() {
        words.words[i].store(v, Ordering::Relaxed);
    }
    let rows: [[u64; 8]; 5] = [
        [
            OPS.id,
            esr,
            x8,
            outcome,
            unsafe { (&*ledger_ptr()).pending() } as u64,
            adv.advice_seq,
            lo(&d.advice_digest),
            0,
        ],
        [
            CTRL.id,
            reg.0,
            reg.1,
            reg.2,
            1,
            r.decision_seq,
            lo(&d.decision_digest),
            0,
        ],
        [
            PUB.id,
            pub_result.0,
            pub_result.1,
            pub_result.2,
            1,
            ACCEPT_COUNT.load(Ordering::Relaxed),
            lo(&r.plan_digest),
            0,
        ],
        [
            summary.plan_seq,
            summary.action_count as u64,
            1,
            causal_label,
            parsed_report.state as u64,
            COMPLETED_NS,
            lo(&summary.evidence_digest),
            0,
        ],
        [
            sec.2,
            illegal.2,
            forged.2,
            1,
            bad_pub.2,
            reg_retry.2,
            pub_replay.2,
            pending_before as u64,
        ],
    ];
    for (r_i, row_data) in rows.into_iter().enumerate() {
        for (c_i, v) in row_data.into_iter().enumerate() {
            words.words[16 + r_i * 8 + c_i].store(v, Ordering::Relaxed);
        }
    }
    for slot in 1..REQUIRED {
        let at = 64 + (slot - 1) * 4;
        for (off, v) in [
            AFFINITIES[slot].load(Ordering::Acquire),
            PROGRESS[slot * 2].load(Ordering::Acquire),
            PROGRESS[slot * 2 + 1].load(Ordering::Acquire),
            IRQS[slot].load(Ordering::Acquire),
        ]
        .into_iter()
        .enumerate()
        {
            words.words[at + off].store(v, Ordering::Relaxed);
        }
    }
    words.words[2].store(1, Ordering::Release);
    super::super::log(b"V0199_ADVICE_E2E_SCOPE production_wiring=false real_services=false fixture_executor=true\n");
    super::super::log(
        b"V0199_ADVICE_E2E_FIXTURE_PASS cpus=4 chain=advice-disposition-plan-receipt\n",
    );
    super::super::halt()
}
