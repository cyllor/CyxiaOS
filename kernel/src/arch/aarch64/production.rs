//! V0.20 native diagnostics for the boot and in-vector SVC mechanism.
//!
//! This elevates the proven advice-e2e SvcV3Bridge dispatch OUT of the fixture
//! turn loop and INTO the production exception-vector path. The opt-in
//! `v020-production-diagnostic` feature selects this entry. The exception
//! vector routes its EL0 sync ABI-v3 SVCs (0x40/0x41/0x50) to
//! [`exception`], which dispatches them in-vector and returns straight to EL0.
//!
//! What is genuinely production-wired here:
//! * The SMP bring-up reuses smp.rs's proven secondary-start path verbatim
//!   (same statics, init_memory, cpu::start, GATES). No second mechanism.
//! * The eight ABI3 PIE role packages are loaded through the existing build
//!   catalog (kernel/build/v0199_roles.rs) and the kernel-core VerifiedRolePackage
//!   loader, exactly like v0199_control_bringup. Their snapshot (0x40) and
//!   supervisor audit (0x50 op1) SVCs are dispatched IN-VECTOR.
//! * The advice causal chain (AdviceEnvelope v1 -> 0x50 intake -> RuleProfile
//!   review -> DecisionRecord/Disposition -> 0x50 register -> 0x41 publish ->
//!   claim_apply_work -> ApplyReport -> supervisor terminal) runs through the
//!   SAME kernel-core bridge APIs the advice-e2e fixture uses, but every EL0
//!   0x50/0x41 trap is serviced in the exception vector, not a turn loop.
//! * Wave 11 adds permanent FrameMeta registration, the in-memory recovery
//!   gate and stopped-writer handoff, diagnostic critical-section metering,
//!   and real VirtIO TCP delivery plus the guest Admission receipt at 0x43.
//!
//! HONEST SCOPE / REMAINING GAPS (do NOT read this as full production authority):
//! * production_skeleton=true, full_authority=false, real_models=false.
//! * The live boot epoch is volatile (BOOT=1). The opt-in media path allocates
//!   a separate staged epoch on its scratch disk. Checkpoint facts for the
//!   live publish gate are staged in memory; durable audit has no media binding.
//! * The executor is a bounded fixture target word on one EL1-owned page.
//!   The live-control feature serves its D01 observation and a volatile audit
//!   record once ready. Immutable disk snapshots and durable audit are open.
//! * No real model is active; the decision artifacts are trusted EL1 fixtures.
//! * Policy-lock timing is diagnostic. Role budget metering
//!   (role_budget_v0199 PMU ledger) and service restart remain open; turns use
//!   a fixed iteration cap and private timer backstop.
//!
//! UNSAFE BOUNDARY REGISTRATION (baseline SEC-BUF: minimal trusted boundaries).
//! Global invariant: run() asserts cpu::slot()==0 for the control plane; the
//! whole advice chain and PIE role turns execute synchronously on CPU0. No IRQ
//! handler, DMA or secondary CPU touches these statics or the advice spaces
//! (index >= C*2). Secondary CPUs only run the smp business fixture; their EL0
//! faults write only their own per-CPU recovery accumulator in recovery.rs
//! (registered there), never any static listed here. The DMA users are the
//! SEC-N VirtIO-net device driven by net.rs and, ONLY under the opt-in
//! v020-production-media-staging feature, the scratch VirtIO-blk device driven
//! by media_staging.rs, both synchronously on CPU0 after the business CPUs
//! stopped; their pools/queues/workspaces are registered in net_device.rs /
//! production/net.rs / sec_n_broker.rs / scratch_blk.rs /
//! production/media_staging*.rs, never listed here.
//! * LEDGER/GATE (static mut MaybeUninit) via ledger_ptr()/gate_ptr():
//!   ptr::write-initialized once in init_control_guards() before any dispatch.
//!   Every later &mut/&* is created and consumed within one synchronous CPU0
//!   call (the in-vector dispatcher or the run() settlement), never aliasing.
//! * PLAN_POOL: the one CPU0 boot claim transfers its exclusive borrow into
//!   the decision gate. The FrameMeta scanner takes only the base address.
//! * TRUSTED_* byte artifacts + ADVICE_WIRE (static mut): written once by run()
//!   before the first EL0 turn; the dispatcher reads them on CPU0 only.
//! * MANIFEST_MEMBERS / PIE_MEMBERS (static mut): written once by run() before
//!   dispatch; read volatile by the dispatcher at a bounded role index.
//! * VECTOR_CALLER (per-CPU atomic): the turn loop publishes the registered
//!   caller index BEFORE user::enter and clears it AFTER return; the in-vector
//!   dispatcher reads it to authenticate the caller from EL1 state, never from
//!   EL0 bytes. Only CPU0 enters production roles.
//! * EXEC_TARGET: bounded D01 executor root. CPU0 prepares exact registered
//!   work, installs the version and weight inside the measured target lock,
//!   and re-reads the atomic root for terminal/observation verification.
//! * copy_address()/read_bytes()/write_bytes(): bounded raw addr_of! arithmetic
//!   over the advice spaces, re-checked against this profile's own tables and
//!   mmu::checked_user_leaf_span before any high-half alias is dereferenced.
//! * PIE backing/tables (static mut): CPU0 is the sole loader; seal_page does
//!   real break-before-make on the high-half direct map before publishing the
//!   low user mapping. No writable alias of executable code remains.

use super::super::ExceptionFrame;
use super::*;
use core::mem::MaybeUninit;
use cyxia_kernel_core::control_plane::{
    Epochs, Error, Identity,
    advice_disposition_v1::{AdviceDispositionV1, DISPOSITION_BYTES},
    advice_envelope_v1::{ADVICE_BYTES, AdviceEnvelopeV1, TrustedAdviceScope},
    advice_ledger_v0199::EvidenceLedger,
    apply_report_v1::{
        ActionStatus, ApplyReportV1, BoundReport, ExecutorBindingV1, MAX_APPLY_REPORT_BYTES,
        ReportOrigin,
        TrustedApplyScope,
    },
    apply_work_v1::ApplyWorkV1,
    cpu0_v0199 as profile,
    decision_record_v3::{DECISION_BYTES, DecisionRecordV3, DecisionSource},
    feedback_v0199::CausalPair,
    fixed::{ChoiceSource, Pair},
    plan_wire_v2::PlanV2,
    registered_gate_v3::{
        AssistedScope, FrozenAction, MAX_PUBLISHED_PLANS, Publication, PublishedPlanPool,
        RegisteredDecisionGate, Registration, TrustedRegistrationScope,
    },
    role_manifest_v0199::{
        DECISION_REGISTER, NativeRole, NativeRoleManifest, PUBLISH_PLAN, PrivateRegion, ROLE_COUNT,
        ROLES, Role, SEND_ADVICE,
    },
    rule_profile_v2::Profile,
    svc_bridge_v3::{FrozenNativePlan, SvcV3Bridge, VerifiedNativeCaller},
};
use cyxia_kernel_core::security::{
    syscall::Syscall,
    syscall_v3::{ABI_VERSION, decode_aarch64_svc_v3, preflight_errno},
};
use sha2::{Digest, Sha256};

#[cfg(any(
    feature = "v020-production-snapshot-catalog",
    feature = "v020-production-file-read",
    feature = "v020-production-fsync-scratch"
))]
#[path = "production/copy_window.rs"]
mod copy_window;
#[path = "production/evidence.rs"]
mod evidence;
#[cfg(feature = "v020-production-fsync-scratch")]
#[cfg_attr(feature = "v020-production-media-reopen", allow(dead_code))]
#[path = "production/file_durable.rs"]
mod file_durable;
#[cfg(feature = "v020-production-file-read")]
#[path = "production/file_read.rs"]
mod file_read;
#[cfg(all(
    feature = "v020-production-fsync-scratch",
    feature = "v020-production-media-reopen"
))]
#[path = "production/file_receipt.rs"]
mod file_receipt;
#[path = "production/frames.rs"]
mod frames;
#[cfg(feature = "v020-production-media-staging")]
#[path = "production/media_staging.rs"]
mod media_staging;
#[path = "production/meter.rs"]
mod meter;
use meter::ExecTarget;
#[path = "production/net.rs"]
mod net;
#[path = "production/role_loader.rs"]
mod role_loader;
#[cfg(feature = "v020-production-frame-pool")]
use role_loader::high_leaf;
#[cfg(cyxia_signed_resident)]
use role_loader::ns_from_ticks;
use role_loader::{
    BACKING, Backing, COPY, COPY_BUFFER, CopyBuffer, PIE_CAP, TABLES, Tables, load_role_with_identity,
    now_ns, pie_context, role_asid, root_pa, stack_span, tlbi, trapped_ttbr0,
};
#[cfg(feature = "v020-production-live-control")]
#[path = "production/observations.rs"]
mod observations;
#[path = "production/recovery.rs"]
pub(crate) mod recovery;
#[cfg(feature = "v020-production-signed-resident")]
#[path = "production/resident.rs"]
mod resident;
#[cfg(feature = "v020-production-signed-resident")]
#[path = "production/signed_resident.rs"]
mod signed_resident;
#[cfg(feature = "v020-production-snapshot-catalog")]
#[path = "production/snapshot_catalog.rs"]
mod snapshot_catalog;

#[cfg(all(
    feature = "v020-production-signed-resident",
    any(
        feature = "v020-production-authenticated-net",
        feature = "v020-production-live-control",
        feature = "v020-production-fsync-scratch"
    )
))]
compile_error!("The signed resident fixture requires the empty scratch authorization profile");

#[cfg(feature = "v020-production-signed-resident")]
pub(super) fn timer_deadline() -> u64 {
    resident::timer_deadline()
}

// The advice EL0 advisor/carrier program is the SAME proven bounded program the
// advice-e2e fixture uses (constructs the envelope at EL0, records the x0 return,
// yields with SVC #4). Reusing it keeps the causal chain identical; only the
// dispatch location (vector vs turn loop) differs.
core::arch::global_asm!(include_str!("v0199_advice_user.S"));
unsafe extern "C" {
    static v0199_advice_user_start: u8;
    static v0199_advice_user_end: u8;
}

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
// STAGED boot epoch (volatile). NOT a durable BootEpoch; see module scope.
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
// Private DATA page layout (EL0 VA = DATA + offset), identical to advice-e2e.
const ENVELOPE_OFF: u64 = 64;
const OBSERVED_OFF: u64 = 768;
const REG_OUT_OFF: u64 = 640;
const PUB_SIDECAR_OFF: u64 = 320;
// Distinct QMP evidence marker ("CYXPRD10").
const MAGIC: u64 = 0x4359_5052_4431_3030;
// In-vector syscall return codes for the fail-closed PIE bootstrap subset.
const E_AUTH: i64 = -1;
const E_FORMAT: i64 = -2;
const EFAULT: i64 = -12;
const EAGAIN: i64 = -13;
// VECTOR_CALLER encoding: [0, ROLE_COUNT) = PIE role index;
// [ROLE_COUNT, 2*ROLE_COUNT) = advice role index; NONE = no registered caller.
const CALLER_NONE: u64 = u64::MAX;
const ADVICE_CALLER_BASE: u64 = ROLE_COUNT as u64;

// CPU0-only acceptance counter for the unique native publish callback.
static ACCEPT_COUNT: AtomicU64 = AtomicU64::new(0);
// Per-CPU registered in-vector caller (see VECTOR_CALLER boundary note).
static VECTOR_CALLER: [AtomicU64; C] = [const { AtomicU64::new(CALLER_NONE) }; C];
// In-vector dispatch evidence, recorded by the dispatcher for the run() seal.
static SVC_ESR: [AtomicU64; 2 * ROLE_COUNT] = [const { AtomicU64::new(0) }; 2 * ROLE_COUNT];
static SVC_X8: [AtomicU64; 2 * ROLE_COUNT] = [const { AtomicU64::new(0) }; 2 * ROLE_COUNT];
static SVC_OUT: [AtomicU64; 2 * ROLE_COUNT] = [const { AtomicU64::new(0) }; 2 * ROLE_COUNT];
// PIE role progress counters (clocks/yields in the turn loop; role_calls in-vector).
static PIE_CLOCKS: [AtomicU64; ROLE_COUNT] = [const { AtomicU64::new(0) }; ROLE_COUNT];
static PIE_YIELDS: [AtomicU64; ROLE_COUNT] = [const { AtomicU64::new(0) }; ROLE_COUNT];
static PIE_ROLE_CALLS: [AtomicU64; ROLE_COUNT] = [const { AtomicU64::new(0) }; ROLE_COUNT];
static EXEC_TARGET: ExecTarget = ExecTarget::new();
// Large control-plane guards in static storage (never the bounded EL1 stack).
static mut LEDGER: MaybeUninit<EvidenceLedger> = MaybeUninit::uninit();
static mut GATE: MaybeUninit<RegisteredDecisionGate<'static>> = MaybeUninit::uninit();
#[repr(C, align(4096))]
struct PlanPoolMemory(PublishedPlanPool);
const PLAN_POOL_BYTES: usize = core::mem::size_of::<PlanPoolMemory>();
static mut PLAN_POOL: PlanPoolMemory = PlanPoolMemory(PublishedPlanPool::new());
static PLAN_POOL_CLAIMED: AtomicBool = AtomicBool::new(false);
// Persistent operations/security intake pair (matches the advice-e2e Fixture.pair).
static mut PAIR: MaybeUninit<Pair> = MaybeUninit::uninit();
// Trusted EL1 decision artifacts (written once by run() before dispatch).
static mut TRUSTED_RULES: [u8; 80] = [0; 80];
static mut TRUSTED_PLAN: [u8; 212] = [0; 212];
static mut TRUSTED_REC: [u8; DECISION_BYTES] = [0; DECISION_BYTES];
static mut TRUSTED_DISP: [u8; DISPOSITION_BYTES] = [0; DISPOSITION_BYTES];
// The actual EL0-constructed envelope, captured by the in-vector intake.
static mut ADVICE_WIRE: [u8; ADVICE_BYTES] = [0; ADVICE_BYTES];
static ADVICE_RECORDED: AtomicBool = AtomicBool::new(false);
// Validated eight-role advice manifest snapshot (CPU0-only).
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
// PIE role manifest members + issued snapshot/audit cap selectors (CPU0-only).
static mut PIE_MEMBERS: [NativeRole; ROLE_COUNT] = [NativeRole {
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
fn pair_ptr() -> *mut Pair {
    core::ptr::addr_of_mut!(PAIR).cast()
}
fn sha(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}
fn lo(d: &[u8; 32]) -> u64 {
    u64::from_le_bytes(d[..8].try_into().unwrap())
}

// ---- advice-space checked copyin/out (identical contract to advice-e2e) ----
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
    let (src, _) = copy_address(space, DATA + off, 8, false).expect("production read span");
    unsafe { core::ptr::read_volatile(src as *const u64) }
}
fn read_bytes(space: usize, off: u64, out: &mut [u8]) {
    let (src, _) =
        copy_address(space, DATA + off, out.len(), false).expect("production copyin span");
    for (i, b) in out.iter_mut().enumerate() {
        *b = unsafe { core::ptr::read_volatile((src + i as u64) as *const u8) };
    }
}
fn write_bytes(space: usize, off: u64, bytes: &[u8]) {
    let (dst, _) =
        copy_address(space, DATA + off, bytes.len(), true).expect("production copyout span");
    for (i, b) in bytes.iter().enumerate() {
        unsafe { core::ptr::write_volatile((dst + i as u64) as *mut u8, *b) };
    }
}

// ---- canonical wire builders (mirror the advice-e2e / kernel-core layouts) ----
fn rule_bytes() -> [u8; 80] {
    let mut b = [0u8; 80];
    b[0..4].copy_from_slice(&0x4359_5255u32.to_le_bytes());
    b[4..6].copy_from_slice(&2u16.to_le_bytes());
    b[6..8].copy_from_slice(&32u16.to_le_bytes());
    b[8..16].copy_from_slice(&RULES_GEN.to_le_bytes());
    b[16..20].copy_from_slice(&1u32.to_le_bytes());
    b[20..24].copy_from_slice(&80u32.to_le_bytes());
    b[32..36].copy_from_slice(&1u32.to_le_bytes());
    b[36..38].copy_from_slice(&1u16.to_le_bytes());
    b[38..40].copy_from_slice(&1u16.to_le_bytes());
    b[40..48].copy_from_slice(&TARGET.id.to_le_bytes());
    b[48..50].copy_from_slice(&1u16.to_le_bytes());
    b[52..54].copy_from_slice(&2u16.to_le_bytes());
    b[56..60].copy_from_slice(&48u32.to_le_bytes());
    b[64..66].copy_from_slice(&2u16.to_le_bytes());
    b[72..74].copy_from_slice(&4u16.to_le_bytes());
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
    b[12..14].copy_from_slice(&1u16.to_le_bytes());
    b[14..16].copy_from_slice(&1u16.to_le_bytes());
    b[16..24].copy_from_slice(&PLAN_SEQ.to_le_bytes());
    b[32..40].copy_from_slice(&MODEL_GEN.to_le_bytes());
    b[40..48].copy_from_slice(&CTRL_EPOCH.to_le_bytes());
    b[48..56].copy_from_slice(&SNAPSHOT_SEQ.to_le_bytes());
    b[56..64].copy_from_slice(&INSTALLED_NS.to_le_bytes());
    let h = 64;
    b[h..h + 4].copy_from_slice(&0x4359_5031u32.to_le_bytes());
    b[h + 4..h + 6].copy_from_slice(&2u16.to_le_bytes());
    b[h + 6..h + 8].copy_from_slice(&144u16.to_le_bytes());
    b[h + 8..h + 10].copy_from_slice(&1u16.to_le_bytes());
    b[h + 10..h + 12].copy_from_slice(&1u16.to_le_bytes());
    b[h + 12..h + 16].copy_from_slice(&4u32.to_le_bytes());
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
    b[h + 80..h + 112].fill(3);
    b[h + 112..h + 144].fill(1);
    b[h + 144..h + 146].copy_from_slice(&1u16.to_le_bytes());
    b[h + 146..h + 148].copy_from_slice(&[4u8, 0]);
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
    b[88..92].copy_from_slice(&1u32.to_le_bytes());
    b[94..96].copy_from_slice(&1u16.to_le_bytes());
    b[96..98].copy_from_slice(&1u16.to_le_bytes());
    b[98] = 2;
    b[99] = 1;
    b[100] = 1;
    b[101] = 1;
    b[102..104].copy_from_slice(&1u16.to_le_bytes());
    b[104..106].copy_from_slice(&1u16.to_le_bytes());
    b[108..112].copy_from_slice(&8u32.to_le_bytes());
    b[112..120].copy_from_slice(&ADVISOR_EPOCH.to_le_bytes());
    b[120..128].copy_from_slice(&1u64.to_le_bytes());
    b[128..136].copy_from_slice(&MODEL_GEN.to_le_bytes());
    b[152..156].copy_from_slice(&3u32.to_le_bytes());
    b[156..158].copy_from_slice(&0u16.to_le_bytes());
    b[158..160].copy_from_slice(&1u16.to_le_bytes());
    b[160..192].copy_from_slice(&sha(rules));
    b[192..224].copy_from_slice(&sha(plan));
    b[224..256].fill(1);
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
        (92, 1),
        (94, 0),
        (100, 0),
        (102, 1),
        (104, 1),
        (106, 1),
    ] {
        b[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }
    b[96..100].copy_from_slice(&3u32.to_le_bytes());
    b[112..144].fill(1);
    b[144..176].copy_from_slice(&sha(advice));
    b[176..208].copy_from_slice(&sha(rec));
    b[208..240].copy_from_slice(&sha(rules));
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
fn init_control_guards() {
    let ledger = EvidenceLedger::new(OPS, CTRL, SUPER, BOOT, ADVISOR_EPOCH).expect("causal ledger");
    unsafe { core::ptr::write(ledger_ptr(), ledger) };
    assert!(!PLAN_POOL_CLAIMED.swap(true, Ordering::AcqRel));
    // SAFETY: CPU0 claims this storage once before running any EL0 carrier.
    // The resulting gate exclusively owns the borrow until boot terminates.
    let pool = unsafe { &mut *core::ptr::addr_of_mut!(PLAN_POOL.0) };
    let gate = RegisteredDecisionGate::with_pool(CTRL, PUB, SUPER, BOOT, CTRL_EPOCH, pool)
        .expect("registered decision gate with protected plan storage");
    unsafe { core::ptr::write(gate_ptr(), gate) };
    report(
        "V020_PLAN_POOL",
        MAX_PUBLISHED_PLANS as u64,
        1,
        PLAN_POOL_BYTES as u64,
    );
    let pair = Pair::new(OPS, SEC).expect("distinct operations/security brains");
    unsafe { core::ptr::write(pair_ptr(), pair) };
}

/// Snapshot/audit cap selector issued to a PIE role (diagnostic, EL1-owned).
fn pie_cap_selector(index: usize) -> u64 {
    match ROLES[index] {
        Role::Operations | Role::Security | Role::DeterministicController | Role::Supervisor => {
            0x1000 + index as u64 * 0x100 + 1
        }
        _ => 0,
    }
}
fn load_role(index: usize) -> NativeRole {
    #[cfg(feature = "v020-production-live-control")]
    let target_selector = observations::selector(ROLES[index]);
    #[cfg(not(feature = "v020-production-live-control"))]
    let target_selector = 0;
    load_role_with_identity(index, 1, pie_cap_selector(index), target_selector)
}

// ---- in-vector production dispatch ----
/// Authenticate the trapped caller from EL1 registered state (never EL0 bytes)
/// and dispatch the ABI-v3 production subset. Returns Some(outcome) when the
/// trap was serviced in-vector (EL0 resumes with x0=outcome); None lets the
/// exception fall through to the proven smp capture path (clock/yield/sleep,
/// timer IRQ, faults, secondary CPUs).
fn svc_dispatch(f: &mut ExceptionFrame) -> Option<u64> {
    let slot = cpu::slot();
    if slot != 0 {
        return None;
    }
    let caller = VECTOR_CALLER[slot].load(Ordering::Acquire);
    if caller == CALLER_NONE {
        return None;
    }
    if caller >= SVC_OUT.len() as u64 {
        return Some(E_AUTH as u64);
    }
    if caller >= ADVICE_CALLER_BASE && f.esr & 0xffff == 4 {
        // The linked advice diagnostic uses SVC #4 only to return to its
        // bounded owner. An ABI3 PIE task uses the SVC #0 lifecycle entry.
        return None;
    }
    let x8 = f.regs[8];
    let call = match decode_aarch64_svc_v3(ABI_VERSION, f.esr, &f.regs) {
        Ok(call) => call,
        Err(error) => {
            // A failed ABI check can report a refusal for the recognized endpoint.
            #[cfg(any(
                feature = "v020-production-snapshot-catalog",
                feature = "v020-production-file-read",
                feature = "v020-production-fsync-scratch"
            ))]
            if f.esr == 0x5600_0000 && caller < ROLE_COUNT as u64 && x8 == 0x50 {
                let index = caller as usize;
                if let Some(outcome) =
                    reject_service_preflight(index, f.regs[..6].try_into().unwrap())
                {
                    return Some(outcome);
                }
            }
            return Some(preflight_errno(error) as u64);
        }
    };
    match call.operation {
        Syscall::ReadSnapshot | Syscall::SubmitPlan | Syscall::ServiceCall => {}
        Syscall::Clock | Syscall::Yield | Syscall::Sleep if caller < ADVICE_CALLER_BASE => {
            return None;
        }
        _ => return Some(E_AUTH as u64),
    }
    let outcome = if caller < ADVICE_CALLER_BASE {
        pie_dispatch(caller as usize, x8, call.args, f)
    } else {
        advice_dispatch((caller - ADVICE_CALLER_BASE) as usize, x8, call.args, f)
    };
    let idx = caller as usize;
    SVC_ESR[idx].store(f.esr, Ordering::Relaxed);
    SVC_X8[idx].store(x8, Ordering::Relaxed);
    SVC_OUT[idx].store(outcome, Ordering::Relaxed);
    Some(outcome)
}
fn pie_member(index: usize) -> NativeRole {
    unsafe {
        core::ptr::read_volatile(
            core::ptr::addr_of!(PIE_MEMBERS)
                .cast::<NativeRole>()
                .add(index),
        )
    }
}

#[cfg(any(
    feature = "v020-production-snapshot-catalog",
    feature = "v020-production-file-read",
    feature = "v020-production-fsync-scratch"
))]
fn reject_service_preflight(index: usize, args: [u64; 6]) -> Option<u64> {
    match args[0] {
        #[cfg(feature = "v020-production-snapshot-catalog")]
        cyxia_kernel_core::security::snapshot_list_v4::LIST_ENDPOINT => Some(
            snapshot_catalog::reject_preflight(index, pie_member(index), args),
        ),
        #[cfg(feature = "v020-production-file-read")]
        cyxia_kernel_core::security::file_read_v4::ENDPOINT => {
            Some(file_read::reject_preflight(index, pie_member(index), args))
        }
        #[cfg(all(
            not(feature = "v020-production-file-read"),
            feature = "v020-production-fsync-scratch",
            feature = "v020-production-media-reopen"
        ))]
        cyxia_kernel_core::security::file_read_v4::ENDPOINT => Some(
            file_receipt::reject_preflight(index, pie_member(index), args),
        ),
        #[cfg(all(
            not(feature = "v020-production-file-read"),
            feature = "v020-production-fsync-scratch",
            not(feature = "v020-production-media-reopen")
        ))]
        cyxia_kernel_core::security::file_read_v4::ENDPOINT => Some(
            file_durable::reject_preflight(index, pie_member(index), args),
        ),
        _ => None,
    }
}

fn registered_pie_cap(index: usize, member: NativeRole) -> Option<u64> {
    if ROLES.get(index) != Some(&member.role)
        || member != pie_member(index)
        || member.ttbr0_root != root_pa(index)
    {
        return None;
    }
    let cap = PIE_CAP[index].load(Ordering::Acquire);
    (cap != 0 && cap == pie_cap_selector(index)).then_some(cap)
}

fn trapped_pie_cap(index: usize, member: NativeRole) -> Result<u64, i64> {
    if cpu::slot() != 0 || VECTOR_CALLER[0].load(Ordering::Acquire) != index as u64 {
        return Err(E_AUTH);
    }
    let cap = registered_pie_cap(index, member).ok_or(E_AUTH)?;
    if trapped_ttbr0() != (member.ttbr0_root | (u64::from(role_asid(index)) << 48)) {
        return Err(E_AUTH);
    }
    Ok(cap)
}

#[cfg(any(
    feature = "v020-production-snapshot-catalog",
    feature = "v020-production-file-read",
    feature = "v020-production-fsync-scratch"
))]
fn wait_for_role_yield(
    index: usize,
    ctx: &mut user::Context,
    until: u64,
    failure: u64,
    done: impl Fn() -> bool,
) {
    loop {
        if ctx.kind == 8
            && decode_aarch64_svc_v3(ABI_VERSION, ctx.esr, &ctx.regs)
                .is_ok_and(|call| call.operation == Syscall::Yield)
            && done()
        {
            return;
        }
        if timer::ticks() >= until {
            fatal(failure);
        }
        pie_turn(index, ctx);
    }
}

/// In-vector snapshot/audit and optional catalogue requests share the
/// protected PIE membership. Clock, yield and sleep use the turn loop.
fn pie_dispatch(index: usize, x8: u64, args: [u64; 6], _f: &ExceptionFrame) -> u64 {
    if index >= ROLE_COUNT {
        return E_AUTH as u64;
    }
    let member = pie_member(index);
    // Authenticate the live CPU, task and TTBR0 for every PIE endpoint, not
    // only the optional file and snapshot services.
    let cap = match trapped_pie_cap(index, member) {
        Ok(cap) => cap,
        Err(error) => return error as u64,
    };
    match x8 {
        0x40 => {
            // ReadSnapshot: cap + domain + writable reply span, then EAGAIN.
            let domain_ok = match member.role {
                Role::Security => args[1] == 12,
                Role::Operations | Role::DeterministicController => args[1] == 1,
                _ => false,
            };
            if cap == 0 || args[0] != cap || !domain_ok || args[4] < 264 {
                return E_AUTH as u64;
            }
            if usize::try_from(args[4])
                .ok()
                .and_then(|len| stack_span(index, args[3], len, true))
                .is_none()
            {
                return EFAULT as u64;
            }
            PIE_ROLE_CALLS[index].fetch_add(1, Ordering::Relaxed);
            #[cfg(feature = "v020-production-live-control")]
            if let Some(outcome) = observations::snapshot(index, member, args) {
                return outcome;
            }
            #[cfg(feature = "v020-production-media-staging")]
            {
                media_staging::snapshot_0x40()
            }
            #[cfg(not(feature = "v020-production-media-staging"))]
            {
                EAGAIN as u64
            }
        }
        #[cfg(feature = "v020-production-snapshot-catalog")]
        0x50 if args[0] == cyxia_kernel_core::security::snapshot_list_v4::LIST_ENDPOINT => {
            snapshot_catalog::dispatch(index, member, args)
        }
        #[cfg(feature = "v020-production-file-read")]
        0x50 if args[0] == cyxia_kernel_core::security::file_read_v4::ENDPOINT => {
            file_read::dispatch(index, member, args)
        }
        #[cfg(all(
            feature = "v020-production-fsync-scratch",
            feature = "v020-production-media-reopen"
        ))]
        0x50 if args[0] == cyxia_kernel_core::security::file_read_v4::ENDPOINT => {
            let result = file_receipt::dispatch(index, member, args);
            if result == EAGAIN as u64 {
                PIE_ROLE_CALLS[index].fetch_add(1, Ordering::Relaxed);
            }
            result
        }
        #[cfg(all(
            feature = "v020-production-fsync-scratch",
            not(feature = "v020-production-media-reopen")
        ))]
        0x50 if args[0] == cyxia_kernel_core::security::file_read_v4::ENDPOINT => {
            let result = file_durable::dispatch(index, member, args);
            if result == EAGAIN as u64 {
                PIE_ROLE_CALLS[index].fetch_add(1, Ordering::Relaxed);
            }
            result
        }
        0x50 if args[2] == 64
            || (cfg!(feature = "v020-production-live-control") && args[2] == 96) =>
        {
            // Live Supervisor audit accepts the frozen READ and ACK wire sizes.
            if member.role != Role::Supervisor || cap == 0 || args[0] != cap || args[3] != 0 {
                return E_AUTH as u64;
            }
            if stack_span(index, args[1], args[2] as usize, false).is_none()
                || usize::try_from(args[5])
                    .ok()
                    .and_then(|len| stack_span(index, args[4], len, true))
                    .is_none()
            {
                return EFAULT as u64;
            }
            PIE_ROLE_CALLS[index].fetch_add(1, Ordering::Relaxed);
            #[cfg(feature = "v020-production-live-control")]
            {
                observations::audit(index, member, args)
            }
            #[cfg(not(feature = "v020-production-live-control"))]
            {
                EAGAIN as u64
            }
        }
        _ => E_FORMAT as u64,
    }
}
/// Advice-chain bridge dispatch — the SAME kernel-core APIs the advice-e2e
/// fixture calls, now serviced in the exception vector.
fn advice_dispatch(role_index: usize, x8: u64, args: [u64; 6], _f: &ExceptionFrame) -> u64 {
    let space = FIRST_ADVICE_SPACE + role_index;
    let member = unsafe {
        core::ptr::read_volatile(
            core::ptr::addr_of!(MANIFEST_MEMBERS)
                .cast::<NativeRole>()
                .add(role_index),
        )
    };
    let cpu = cpu::slot();
    let expected = member.ttbr0_root | (u64::from(user::dynamic_asid()) << 48);
    if cpu != 0 || member.ttbr0_root == 0 || trapped_ttbr0() != expected {
        return E_AUTH as u64;
    }
    match x8 {
        0x50 if args[2] == ADVICE_BYTES as u64 => {
            // Advice intake glue (no SvcV3Bridge submit entry exists).
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
            let pair = unsafe { &mut *pair_ptr() };
            let ok = pair
                .submit_operations_wire(member.actor, &copy, &trusted)
                .is_ok()
                && ledger.record(OPS, &copy, &trusted).is_ok();
            if ok {
                unsafe {
                    core::ptr::write_volatile(core::ptr::addr_of_mut!(ADVICE_WIRE), copy);
                }
                ADVICE_RECORDED.store(true, Ordering::Release);
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
            with_bundle(|frozen, scope| {
                let mut bridge = SvcV3Bridge {
                    gate: unsafe { &mut *gate_ptr() },
                    decision_endpoint_cap: DECISION_CAP,
                    publisher_cap: PUBLISHER_CAP,
                };
                let ledger = unsafe { &mut *ledger_ptr() };
                match meter::metered(|| {
                    bridge.register_assisted_one(caller, args, &copy, frozen, scope, ledger)
                }) {
                    Ok(Registration::Frozen) => 1,
                    Ok(Registration::ExactRetry) => 2,
                    Err(_) => 0,
                }
            })
        }
        0x41 => {
            // PUBLISH via the real SvcV3Bridge 0x41 endpoint.
            if cpu != 0 || member.caps & PUBLISH_PLAN != PUBLISH_PLAN {
                return 0;
            }
            if !recovery::publish_allowed() {
                return E_AUTH as u64;
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
            with_bundle(|frozen, scope| {
                let mut bridge = SvcV3Bridge {
                    gate: unsafe { &mut *gate_ptr() },
                    decision_endpoint_cap: DECISION_CAP,
                    publisher_cap: PUBLISHER_CAP,
                };
                match meter::metered(|| {
                    bridge.publish_assisted_one(
                        caller,
                        args,
                        &plan_copy,
                        core::slice::from_ref(&side_copy),
                        frozen,
                        scope,
                        || {
                            ACCEPT_COUNT.fetch_add(1, Ordering::Relaxed);
                            Ok(())
                        },
                    )
                }) {
                    Ok(Publication::AdapterAccepted) => 1,
                    Ok(Publication::ReplayNoEffect) => 2,
                    Err(_) => 0,
                }
            })
        }
        _ => 0,
    }
}
/// Reconstruct the immutable trusted bundle from the EL1-owned static artifacts
/// and invoke `f` synchronously within this frame. The byte artifacts are
/// 'static (static storage); the parsed Profile/FrozenAction/scope are borrow
/// locals that live exactly as long as the synchronous bridge call. No lifetime
/// is extended past its frame (no transmute).
fn with_bundle(f: impl FnOnce(&FrozenNativePlan<'_>, &AssistedScope<'_>) -> u64) -> u64 {
    let rules = unsafe { &*core::ptr::addr_of!(TRUSTED_RULES) };
    let plan = unsafe { &*core::ptr::addr_of!(TRUSTED_PLAN) };
    let rec = unsafe { &*core::ptr::addr_of!(TRUSTED_REC) };
    let profile = Profile::parse(rules).expect("RuleProfile v2");
    let candidates: &[u16] = &[2, 4];
    let payload: &[u8] = &[4, 0];
    let local = FrozenAction {
        domain_id: 1,
        target: TARGET,
        candidate_set_hash: [1; 32],
        static_ordinals: candidates,
        candidate_payloads: &[&[2, 0], payload],
        raw_fields: [None; 7],
        action_payload: payload,
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
        rules_hash: sha(rules),
        base_plan_version: 0,
        ledger_generation: LEDGER_GEN,
        core_generation: CORE_GEN,
        snapshot_seq: SNAPSHOT_SEQ,
        sampled_ns: SAMPLED_NS,
        now_ns: NOW_NS,
    };
    let frozen = FrozenNativePlan {
        bytes: plan,
        sidecars: core::slice::from_ref(rec),
        rules: &profile,
        actions: core::slice::from_ref(&local),
        context: ctx,
    };
    f(&frozen, &scope)
}

/// Production exception entry: dispatch the ABI-v3 production subset in-vector,
/// fall through to the proven smp path for everything else.
pub(crate) fn exception(f: &mut ExceptionFrame, kind: u64) {
    #[cfg(feature = "v020-production-signed-resident")]
    signed_resident::verify_captured_role(f, kind);
    if !cfg!(feature = "v020-production-signed-resident")
        && kind == 8
        && f.spsr & 0x1f == 0
        && f.esr >> 26 == 0x15
        && let Some(outcome) = svc_dispatch(f)
    {
        f.regs[0] = outcome;
        // ELR_EL1 already points past the trapped SVC; SPSR stays EL0t.
        return;
    }
    super::exception(f, kind);
}

// ---- bounded turn loops ----
fn enter_advice(ctx: &mut user::Context, space: usize) {
    let role_index = space - FIRST_ADVICE_SPACE;
    VECTOR_CALLER[0].store(ADVICE_CALLER_BASE + role_index as u64, Ordering::Release);
    execute(ctx, space);
    VECTOR_CALLER[0].store(CALLER_NONE, Ordering::Release);
}
/// Advice turn: SVCs are serviced in-vector; the loop only observes the bounded
/// yield (SVC #4) and private-timer preemptions.
fn advice_turn(space: usize, mode: u64) {
    let mut ctx = context(space);
    ctx.regs[7] = mode;
    for _ in 0..64 {
        enter_advice(&mut ctx, space);
        if ctx.kind == 9 {
            continue;
        }
        if ctx.kind == 8 && ctx.esr >> 26 == 0x15 && ctx.esr & 0xffff == 4 {
            return;
        }
        fatal(300);
    }
    fatal(330);
}
/// Carrier turn: EL1 pre-sets x8/x0..x5; EL0 traps the trusted payload in-vector.
fn advice_carrier(space: usize, x8: u64, args: [u64; 6]) {
    let mut ctx = context(space);
    ctx.regs[8] = x8;
    ctx.regs[..6].copy_from_slice(&args);
    ctx.regs[7] = 4;
    for _ in 0..64 {
        enter_advice(&mut ctx, space);
        if ctx.kind == 9 {
            continue;
        }
        if ctx.kind == 8 && ctx.esr >> 26 == 0x15 && ctx.esr & 0xffff == 4 {
            return;
        }
        fatal(300);
    }
    fatal(330);
}
/// One bounded PIE role turn. Clock/yield/sleep are handled here (capture path);
/// snapshot/audit were already serviced in-vector.
fn pie_turn(index: usize, ctx: &mut user::Context) {
    VECTOR_CALLER[0].store(index as u64, Ordering::Release);
    let quantum = (timer::frequency() / 1000).max(1);
    unsafe {
        timer::arm(timer::ticks().saturating_add(quantum));
        user::enter_pinned_until_retired(ctx, root_pa(index), role_asid(index));
        cpu::disable_timer();
    }
    VECTOR_CALLER[0].store(CALLER_NONE, Ordering::Release);
    if ctx.kind == 9 {
        return; // private PPI preemption; resume next turn
    }
    if ctx.kind != 8 || ctx.esr >> 26 != 0x15 {
        fatal(600 + index as u64);
    }
    let call = match decode_aarch64_svc_v3(ABI_VERSION, ctx.esr, &ctx.regs) {
        Ok(call) => call,
        Err(error) => {
            ctx.regs[0] = preflight_errno(error) as u64;
            return;
        }
    };
    let result = match call.operation {
        Syscall::Clock => {
            PIE_CLOCKS[index].fetch_add(1, Ordering::Relaxed);
            i64::try_from(now_ns()).unwrap_or(0)
        }
        Syscall::Yield => {
            PIE_YIELDS[index].fetch_add(1, Ordering::Relaxed);
            0
        }
        Syscall::Sleep => {
            PIE_YIELDS[index].fetch_add(1, Ordering::Relaxed);
            0
        }
        _ => E_AUTH,
    };
    ctx.regs[0] = result as u64;
}

pub(crate) fn run(info: &BootInfo) -> ! {
    #[cfg(feature = "v020-production-signed-resident")]
    if cfg!(feature = "v020-production-signed-resident") {
        signed_resident::run(info);
    }
    assert_eq!(
        cpu::slot(),
        0,
        "only boot CPU0 owns the production control plane"
    );
    frames::register_or_fatal();
    #[cfg(feature = "v020-production-frame-pool")]
    let reserved_info = {
        let mut reserved = *info;
        frames::prove_pool_or_fatal(&mut reserved);
        reserved
    };
    #[cfg(feature = "v020-production-frame-pool")]
    let info = &reserved_info;
    recovery::init_or_fatal();
    bring_up_production(info);
    for gate in GATES.iter().take(REQUIRED).skip(1) {
        gate.open(Token {
            generation: 1,
            plane: Plane::Business,
        })
        .unwrap();
    }
    assert_eq!(PRIVATE_SPACES, FIRST_ADVICE_SPACE + ADVICE_SPACES);
    report("V020_PROD_STAGE", 1, 0, 0);
    init_control_guards();
    gic()
        .enable(TIMER_IRQ.load(Ordering::Acquire) as u32)
        .expect("CPU0 timer PPI");

    // ---- Phase 1: load + run the eight ABI3 PIE role packages ----
    let pie_members: [NativeRole; ROLE_COUNT] = core::array::from_fn(load_role);
    let other_protected_pool_bytes =
        core::mem::size_of::<[Tables; ROLE_COUNT]>() + COPY + PLAN_POOL_BYTES + 1024 * 1024;
    #[cfg(feature = "v020-production-live-control")]
    let other_protected_pool_bytes = other_protected_pool_bytes + observations::protected_bytes();
    #[cfg(feature = "v020-production-snapshot-catalog")]
    let other_protected_pool_bytes =
        other_protected_pool_bytes + snapshot_catalog::protected_bytes();
    #[cfg(feature = "v020-production-file-read")]
    let other_protected_pool_bytes = other_protected_pool_bytes + file_read::protected_bytes();
    #[cfg(all(
        feature = "v020-production-fsync-scratch",
        not(feature = "v020-production-media-reopen")
    ))]
    let other_protected_pool_bytes = other_protected_pool_bytes + file_durable::protected_bytes();
    #[cfg(all(
        feature = "v020-production-fsync-scratch",
        feature = "v020-production-media-reopen"
    ))]
    let other_protected_pool_bytes = other_protected_pool_bytes + file_receipt::protected_bytes();
    let pie_manifest = NativeRoleManifest {
        online_mask: profile::ONLINE,
        members: pie_members,
        other_protected_pool_bytes,
        other_control_ns_per_100ms: 10_000_000,
    };
    pie_manifest
        .validate()
        .expect("eight distinct native PIE TTBR/role/cap entries");
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(PIE_MEMBERS), pie_members);
    }
    report(
        "V020_PROD_PIE_LOAD",
        ROLE_COUNT as u64,
        pie_members[0].ttbr0_root,
        0,
    );
    let mut pie_ctx: [user::Context; ROLE_COUNT] = core::array::from_fn(pie_context);
    // Bounded round-robin: every role clocks; snapshot/audit roles service their
    // role-specific SVC in-vector (EAGAIN), sleep roles yield.
    let until = timer::ticks()
        .checked_add(timer::frequency() * 5)
        .expect("deadline");
    loop {
        let done = (0..ROLE_COUNT).all(|i| {
            PIE_CLOCKS[i].load(Ordering::Acquire) >= 1
                && (PIE_ROLE_CALLS[i].load(Ordering::Acquire) >= 1
                    || PIE_YIELDS[i].load(Ordering::Acquire) >= 1)
        });
        if done {
            break;
        }
        if timer::ticks() >= until {
            fatal(650);
        }
        for (i, ctx) in pie_ctx.iter_mut().enumerate().take(ROLE_COUNT) {
            pie_turn(i, ctx);
        }
    }
    // Both sinks record this same startup phase, before later native file
    // turns reuse the role's syscall outcome and progress counters.
    let pie_startup: [[u64; 6]; ROLE_COUNT] = core::array::from_fn(|i| {
        [
            pie_members[i].ttbr0_root,
            PIE_CLOCKS[i].load(Ordering::Acquire),
            PIE_ROLE_CALLS[i].load(Ordering::Acquire),
            PIE_YIELDS[i].load(Ordering::Acquire),
            lo(&role_loader::image_digest(i)),
            SVC_OUT[i].load(Ordering::Acquire),
        ]
    });
    for (i, row) in pie_startup.iter().enumerate() {
        report(
            "V020_PROD_PIE_ROLE",
            u64::from(ROLES[i].id()),
            row[1],
            row[2],
        );
    }
    report("V020_PROD_STAGE", 2, ROLE_COUNT as u64, 0);

    // ---- Phase 2: in-vector advice causal chain ----
    // Map the advisor/carrier EL0 program into each advice space's CODE leaf.
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
    tlbi();
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
        other_protected_pool_bytes: 5 * 1024 * 1024 + PLAN_POOL_BYTES,
        other_control_ns_per_100ms: 45_000_000,
    };
    manifest
        .validate()
        .expect("eight distinct native advice TTBR/role/cap entries");
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(MANIFEST_MEMBERS), members);
    }
    // Trusted EL1 artifacts (written once before any dispatch).
    let rules = rule_bytes();
    let plan = plan_bytes();
    let rec = decision_bytes(&plan, &rules);
    let advice = advice_expected();
    let disp = disposition_bytes(&advice, &rec, &rules);
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(TRUSTED_RULES), rules);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(TRUSTED_PLAN), plan);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(TRUSTED_REC), rec);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(TRUSTED_DISP), disp);
    }
    report(
        "V020_PROD_STAGE",
        3,
        members[0].ttbr0_root,
        members[0].private_rw.base,
    );
    wait(|| (1..REQUIRED).all(|slot| PROGRESS[slot * 2].load(Ordering::Acquire) >= 2));

    let ops_space = FIRST_ADVICE_SPACE;
    let sec_space = FIRST_ADVICE_SPACE + 1;
    let ctrl_space = FIRST_ADVICE_SPACE + 2;
    let pub_space = FIRST_ADVICE_SPACE + 3;

    // (1) POSITIVE: EL0 operations advisor constructs + submits (in-vector 0x50).
    advice_turn(ops_space, 1);
    assert!(
        ADVICE_RECORDED.load(Ordering::Acquire),
        "advice submit must be recorded"
    );
    let advice_wire = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ADVICE_WIRE)) };
    assert_eq!(
        advice_wire, advice,
        "EL0-constructed envelope must equal the trusted expectation"
    );
    assert_eq!(unsafe { (&*ledger_ptr()).pending() }, 1);
    AdviceDispositionV1::decode(&disp)
        .unwrap()
        .matches_decision_pair(BOOT, &advice_wire, &rec)
        .expect("disposition links real EL0 advice + decision");
    assert_eq!(
        read_word(ops_space, OBSERVED_OFF),
        1,
        "EL0 must observe the x0 return receipt"
    );
    let submit = (
        SVC_ESR[ROLE_COUNT].load(Ordering::Relaxed),
        SVC_X8[ROLE_COUNT].load(Ordering::Relaxed),
        SVC_OUT[ROLE_COUNT].load(Ordering::Relaxed),
    );
    assert_eq!(
        submit,
        (0x5600_0000, 0x50, 1),
        "in-vector advice submit evidence"
    );
    report("V020_PROD_SUBMIT", OPS.id, submit.0, submit.2);

    // (2) Independent RuleProfile review adopts the advice candidate.
    let pair = unsafe { &*pair_ptr() };
    let profile = Profile::parse(&rules).expect("RuleProfile v2");
    let candidates = [2u16, 4];
    let trusted = trusted_scope();
    let review = pair
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
        "V020_PROD_REVIEW",
        review.candidate as u64,
        review.source as u64,
        0,
    );

    // (3) NEGATIVES: wrong identity, illegal domain, forged cap (all in-vector).
    let pending_before = unsafe { (&*ledger_ptr()).pending() };
    advice_turn(sec_space, 1);
    let sec_out = SVC_OUT[ROLE_COUNT + 1].load(Ordering::Relaxed);
    advice_turn(ops_space, 2);
    let illegal_out = SVC_OUT[ROLE_COUNT].load(Ordering::Relaxed);
    advice_turn(ops_space, 3);
    let forged_out = SVC_OUT[ROLE_COUNT].load(Ordering::Relaxed);
    assert_eq!(
        (sec_out, illegal_out, forged_out),
        (0, 0, 0),
        "negatives must be rejected"
    );
    assert_eq!(
        unsafe { (&*ledger_ptr()).pending() },
        pending_before,
        "no negative advice may enter the ledger"
    );
    assert_eq!(read_word(ops_space, OBSERVED_OFF), 0);
    report("V020_PROD_NEG", sec_out, illegal_out, forged_out);

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
        let args = [
            DECISION_CAP,
            DATA + ENVELOPE_OFF,
            recdisp.len() as u64,
            0,
            DATA + REG_OUT_OFF,
            8,
        ];
        let denied = with_bundle(|frozen, scope| {
            let mut bridge = SvcV3Bridge {
                gate: unsafe { &mut *gate_ptr() },
                decision_endpoint_cap: DECISION_CAP,
                publisher_cap: PUBLISHER_CAP,
            };
            let ledger = unsafe { &mut *ledger_ptr() };
            u64::from(
                bridge
                    .register_assisted_one(caller, args, &recdisp, frozen, scope, ledger)
                    .is_err(),
            )
        });
        assert_eq!(denied, 1, "wrong CPU must be denied");
    }
    assert!(
        !unsafe { (&*gate_ptr()).has_unpublished() },
        "wrong-CPU register must not freeze a plan"
    );
    report("V020_PROD_WRONG_CPU", 1, 0, 0);

    // (5) REGISTER via real in-vector EL0 SVC 0x50 (controller carrier).
    write_bytes(ctrl_space, ENVELOPE_OFF, &recdisp);
    let reg_args = [
        DECISION_CAP,
        DATA + ENVELOPE_OFF,
        recdisp.len() as u64,
        0,
        DATA + REG_OUT_OFF,
        8,
    ];
    advice_carrier(ctrl_space, 0x50, reg_args);
    let reg = (
        SVC_ESR[ROLE_COUNT + 2].load(Ordering::Relaxed),
        SVC_X8[ROLE_COUNT + 2].load(Ordering::Relaxed),
        SVC_OUT[ROLE_COUNT + 2].load(Ordering::Relaxed),
    );
    assert_eq!((reg.1, reg.2), (0x50, 1), "register must freeze");
    assert!(unsafe { (&*gate_ptr()).has_unpublished() });
    assert_eq!(read_word(ctrl_space, OBSERVED_OFF), 1);
    report("V020_PROD_REGISTER", CTRL.id, reg.0, reg.2);
    advice_carrier(ctrl_space, 0x50, reg_args);
    let reg_retry = SVC_OUT[ROLE_COUNT + 2].load(Ordering::Relaxed);
    assert_eq!(reg_retry, 2, "exact register retry");
    report("V020_PROD_REGISTER_RETRY", CTRL.id, reg_retry, 0);

    // (6) PUBLISH via real in-vector EL0 SVC 0x41 (publisher carrier).
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
    advice_carrier(pub_space, 0x41, pub_args);
    let pub_result = (
        SVC_ESR[ROLE_COUNT + 3].load(Ordering::Relaxed),
        SVC_X8[ROLE_COUNT + 3].load(Ordering::Relaxed),
        SVC_OUT[ROLE_COUNT + 3].load(Ordering::Relaxed),
    );
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
    report("V020_PROD_PUBLISH", PUB.id, pub_result.0, pub_result.2);
    // NEGATIVE: operations role may not publish.
    write_bytes(ops_space, ENVELOPE_OFF, &plan);
    write_bytes(ops_space, PUB_SIDECAR_OFF, &rec);
    advice_carrier(ops_space, 0x41, pub_args);
    let bad_pub = SVC_OUT[ROLE_COUNT].load(Ordering::Relaxed);
    assert_eq!(bad_pub, 0, "non-publisher must be denied");
    assert_eq!(unsafe { (&*gate_ptr()).published_count() }, 1);
    assert_eq!(ACCEPT_COUNT.load(Ordering::Relaxed), 1);
    report("V020_PROD_BAD_PUBLISH", OPS.id, bad_pub, 0);
    advice_carrier(pub_space, 0x41, pub_args);
    let pub_replay = SVC_OUT[ROLE_COUNT + 3].load(Ordering::Relaxed);
    assert_eq!(pub_replay, 2, "replay publish no effect");
    assert_eq!(
        ACCEPT_COUNT.load(Ordering::Relaxed),
        1,
        "replay must not re-accept"
    );
    report(
        "V020_PROD_PUBLISH_REPLAY",
        PUB.id,
        pub_replay,
        ACCEPT_COUNT.load(Ordering::Relaxed),
    );

    // RECOVERY probe while the plan is published (count 1), before settlement.
    recovery::publish_probe(pub_space, pub_args);

    // (7) Executor: claim work, apply to the fixture target, ApplyReport.
    let claim_scope = TrustedApplyScope {
        boot_epoch: BOOT,
        plan_version: PLAN_VERSION,
        now_ns: NOW_NS,
    };
    let mut prepared = None;
    let frame = unsafe { &mut *gate_ptr() }
        .claim_apply_work(
            &plan,
            0,
            claim_scope,
            binding(),
            ReportOrigin::Kernel,
            |work| {
                prepared = Some(EXEC_TARGET.prepare(work)?);
                Ok(())
            },
        )
        .expect("claim apply work");
    let work = ApplyWorkV1::decode(frame.bytes()).expect("apply work");
    let target_lock = EXEC_TARGET
        .commit(prepared.expect("reserved target install"))
        .expect("D01 install without waiting");
    let fault = match target_lock {
        Some(sample) => {
            let t = sample.timing;
            report(
                "V020_SEC_S_TARGET_LOCK",
                t.work_ns,
                t.overhead_ns,
                t.total_ns,
            );
            u64::from(t.exceeded())
        }
        None => 8, // unmeasured; close new work while retaining the installed root
    };
    let weight = EXEC_TARGET
        .installed_weight(work.plan_version)
        .expect("installed target version");
    if fault != 0 {
        // SAFETY: synchronous CPU0 owns the gate. The retained exact claim
        // remains available for terminal settlement after fencing new work.
        let gate = unsafe { &mut *gate_ptr() };
        gate.fence(SUPER).expect("meter fault closes publication");
        assert!(matches!(EXEC_TARGET.prepare(&work), Err(Error::NotReady)));
        assert_eq!(
            gate.claim_apply_work(
                &plan,
                0,
                claim_scope,
                binding(),
                ReportOrigin::Kernel,
                |_| Err(Error::Denied),
            )
            .err(),
            Some(Error::NotReady),
            "budget fault closes the native claim entry before another effect"
        );
    }
    report(
        "V020_SEC_S_TARGET_INSTALL",
        work.plan_version,
        u64::from(weight),
        fault,
    );
    let action = weight.to_le_bytes();
    let mut report_buffer = [0; MAX_APPLY_REPORT_BYTES];
    let report_len = ApplyReportV1 {
        key: work.key,
        action_index: work.action_index,
        domain_id: work.domain,
        state: ActionStatus::Applied,
        target: work.target,
        executor_generation: work.executor_generation,
        plan_version: work.plan_version,
        result: 0,
        completed_ns: COMPLETED_NS,
        action: &action,
    }
    .encode(&mut report_buffer)
    .expect("encode installed target result");
    let report_wire = &report_buffer[..report_len];
    let parsed_report = ApplyReportV1::decode(report_wire).expect("apply report");
    assert_eq!(parsed_report.state, ActionStatus::Applied);
    assert!(work.matches_report(parsed_report));
    report("V020_PROD_APPLY", PLAN_SEQ, COMPLETED_NS, u64::from(weight));

    // (8) Supervisor terminal settlement with the exact causal sidecar.
    let bound = [BoundReport {
        bytes: report_wire,
        origin: ReportOrigin::Kernel,
    }];
    let pair = CausalPair {
        advice: &advice_wire,
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
                if r.state == ActionStatus::Applied
                    && EXEC_TARGET
                        .installed_weight(r.plan_version)
                        .is_some_and(|actual| actual.to_le_bytes() == r.action)
                {
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
    let causal_label: u64 = if rec[102..104] == rec[156..158] { 1 } else { 2 };
    assert_eq!(causal_label, 2, "adopted candidate differs from fallback");
    report(
        "V020_PROD_SETTLE",
        summary.plan_seq,
        summary.action_count as u64,
        causal_label,
    );

    // (9) Full causal-chain linkage assertions.
    let adv = AdviceEnvelopeV1::decode(&advice_wire).unwrap();
    let d = AdviceDispositionV1::decode(&disp).unwrap();
    let r = DecisionRecordV3::decode(&rec).unwrap();
    let p = PlanV2::decode(&plan).unwrap();
    assert_eq!(adv.advice_seq, d.advice_seq);
    assert_eq!(d.advice_seq, r.advice_seq);
    assert_eq!(d.decision_seq, r.decision_seq);
    assert_eq!(r.plan_seq, p.header.plan_seq);
    assert_eq!(p.header.plan_seq, parsed_report.key.plan_seq);
    assert_eq!(parsed_report.key.plan_seq, summary.plan_seq);
    assert_eq!(d.advice_digest, sha(&advice_wire));
    assert_eq!(d.decision_digest, sha(&rec));
    assert_eq!(r.plan_digest, sha(&plan));
    assert_eq!(d.state, 1);
    assert_eq!(r.source, DecisionSource::AiAssisted);
    report(
        "V020_PROD_CHAIN",
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
    recovery::takeover_stopped();
    check_failures();
    for slot in 1..REQUIRED {
        report(
            "V020_PROD_BUSINESS",
            slot as u64,
            PROGRESS[slot * 2].load(Ordering::Acquire),
            IRQS[slot].load(Ordering::Acquire),
        );
    }

    // With no signed media, this is the standalone network fixture identity.
    #[cfg(not(feature = "v020-production-media-signed"))]
    let net_outcome = net::serve(info, super::sec_n_broker::BootIdentity::FIXTURE);
    // Opt-in G-B media staging on a throw-away scratch VirtIO-blk disk.
    #[cfg(feature = "v020-production-media-staging")]
    let staging_outcome = media_staging::stage(
        info,
        #[cfg(all(
            feature = "v020-production-fsync-scratch",
            not(feature = "v020-production-signed-resident")
        ))]
        if cfg!(feature = "v020-production-media-reopen") {
            None
        } else {
            Some(
                file_durable::Client::new(&mut pie_ctx, &pie_manifest)
                    .expect("scratch file client"),
            )
        },
    );
    // The signed scratch profile binds diagnostics to the same durable boot
    // as the mount. No listener or device ownership starts on mount refusal.
    #[cfg(feature = "v020-production-media-signed")]
    let net_outcome = match staging_outcome.network_boot() {
        Some(identity) => net::serve(info, identity),
        None => net::NetOutcome::default(),
    };

    // (11) QMP-readable evidence page.
    let words = unsafe { &*core::ptr::addr_of!(SMP_EVIDENCE) };
    for w in words.words.iter() {
        w.store(0, Ordering::Relaxed);
    }
    let summary_words = [
        MAGIC,
        1,
        0,
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
        5,
    ];
    for (i, v) in summary_words.into_iter().enumerate() {
        words.words[i].store(v, Ordering::Relaxed);
    }
    let rows: [[u64; 8]; 5] = [
        [
            OPS.id,
            submit.0,
            submit.1,
            submit.2,
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
            sec_out,
            illegal_out,
            forged_out,
            1,
            bad_pub,
            reg_retry,
            pub_replay,
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
    // PIE role evidence: distinct TTBR roots + image hashes + in-vector calls.
    for (i, row) in pie_startup.into_iter().enumerate() {
        let at = 80 + i * 6;
        for (field, value) in row.into_iter().enumerate() {
            words.words[at + field].store(value, Ordering::Relaxed);
        }
    }
    // Wave 11 segment (words 128..160): magic + staged boot epoch; later wave-11
    // tasks fill their own rows through evidence::put before this seal.
    evidence::put(evidence::W11_BASE, evidence::W11_MAGIC);
    evidence::put(evidence::W11_STAGED_BOOT_EPOCH, 1);
    frames::publish();
    recovery::publish();
    meter::publish();
    if let Some(sample) = target_lock {
        sample.publish();
    }
    net::publish(&net_outcome);
    #[cfg(feature = "v020-production-media-staging")]
    media_staging::publish(&staging_outcome);
    #[cfg(feature = "v020-production-live-control")]
    observations::drive(&mut pie_ctx, &pie_manifest);
    #[cfg(feature = "v020-production-file-read")]
    if staging_outcome.services_ready()
        && let Some(view) = staging_outcome.file_read
    {
        file_read::drive(&mut pie_ctx, &pie_manifest, view);
    }
    #[cfg(all(
        feature = "v020-production-fsync-scratch",
        feature = "v020-production-media-reopen"
    ))]
    if staging_outcome.services_ready()
        && let Some(view) = staging_outcome.file_receipts
    {
        file_receipt::drive(&mut pie_ctx, &pie_manifest, view);
    }
    #[cfg(any(
        feature = "v020-production-file-read",
        feature = "v020-production-fsync-scratch"
    ))]
    {
        let (reads, writes, closed) = copy_window::closed_counts();
        report(
            "V020_SEC_M_FILE_COPY_WINDOW",
            reads,
            writes,
            u64::from(closed),
        );
    }
    #[cfg(feature = "v020-production-snapshot-catalog")]
    if staging_outcome.services_ready()
        && let Some(view) = staging_outcome.snapshot_catalog
    {
        snapshot_catalog::drive(&mut pie_ctx, &pie_manifest, view);
    }
    words.words[2].store(1, Ordering::Release);
    // Framed UART payloads are capped at 96 bytes; keep the scope marker short.
    // in_vector_dispatch / staged_boot_epoch / fixture_executor are proven by the
    // ESR evidence and the summary.json metadata respectively.
    super::super::log(
        b"V020_PROD_SCOPE production_skeleton=true full_authority=false real_models=false\n",
    );
    evidence::log_completion();
    super::super::log(
        b"V020_PRODUCTION_SKELETON_PASS cpus=4 roles=8 chain=advice-disposition-plan-receipt\n",
    );
    super::super::halt()
}
