//! V0.19.9 RecoveryProof v2 + RECOVERY_REQUIRED contract layer.
//!
//! Contract-only model of the baseline recovery evidence rules; native EL1
//! wiring (audit-slot fallback, per-CPU preallocated accumulators, consumer
//! takeover, mount integration) is a LATER deliverable and is deliberately
//! NOT faked here. Nothing in this module mounts a volume, allocates a
//! BootEpoch or authorizes a write by itself.
//!
//! Baseline citations (docs/design/baselines/v0.19.9-implementation-spec.txt):
//! * 安§0.9 (~L7411-7470): RecoveryProof v2 fixed 256B layout, the
//!   `CYX/RECOVERY/v2` chain rule, per-CPU single writer, saturating sticky
//!   counters, and "仅证明审计降级摘要，不能替代 COMMIT、ResetProof 或 TLB ACK".
//! * Digest-label registry (~L8318): `RecoveryProof.v2 /
//!   audit.recovery_digest_label = CYX/RECOVERY/v2` (ASCII, 安§0.9 / SEC-S11).
//! * SEC-I09 (~L6619), SEC-S11 (~L10682), DEC-05 (~L11253): full audit slots
//!   never block CAP_REVOKE / isolation / necessary completion; they fall
//!   back to the per-CPU accumulator + AUDIT_DEGRADED; no keys/plaintext.
//! * Protected-pool budget (~L6025): 9 KiB = 8192B audit slots + 4×256B
//!   emergency accumulators.
//! * §9.5 (~L3976-4030) and §9.7 (~L4620): RECOVERY_REQUIRED entry rules
//!   (invalid/single copy, same-generation different content, unprovable
//!   relation, higher-generation log), protected read-only-only allowance,
//!   no online recovery promise, exit only via evidence-based rebuild and
//!   re-acceptance.
//! * A10 (~L5001-5013), SEC-F05 (~L9003), SEC-F09 (~L9039), SEC-D05
//!   (~L10222), J05 (~L10995): B-side judgments must surface
//!   RECOVERY_REQUIRED/EIO; A/B judged separately; B's refusal is not A's
//!   data-recovery proof; device reset is not durable-success proof.
//! * Frozen errno table (~L10779-10810): 16 codes, EIO = -16.
//!   RECOVERY_REQUIRED is a STATE, not a 17th errno; the DENY reason-index
//!   mapping 1..16 stays intact. "UNKNOWN 是状态，不是未执行" (~L10771).
//! * 安§7.1 (~L10825): file persistence truth only from log evidence, device
//!   DMA end only from completion/reliable-reset proof, TLB only from ACK;
//!   no group may substitute another service's silence for release evidence.
//! * V0.19.10 candidate §5 (docs/design/v0.19.10-immutable-snapshots.md):
//!   after recovery the write gate stays closed; only a deterministic open
//!   path with real completion proof, current protection generation and
//!   independent authority may reopen; no model/auto-restart open; a
//!   persistent-request ACK does not lift a remaining protection gate.
//!
//! Documented unspecified details (G1 freeze candidates, NOT baseline wire
//! bytes): the numeric state codes of `RecoveryState` are internal only (no
//! wire encoding is invented); the per-counter event-kind mapping and the
//! freeze-after-saturation reading of "饱和后不伪造逐事件证明" are conservative
//! contract choices documented at their definitions; nonzero
//! boot_epoch/cpu_generation at accumulator construction is a binding
//! hygiene rule, not an explicit baseline sentence.

use super::Error;
use crate::control_plane::Identity;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// (a) RECOVERY_REQUIRED state
// ---------------------------------------------------------------------------

/// Frozen baseline errno (安§7.5 table): device/media error. The recovery
/// state surfaces to ordinary callers as EIO; no new errno is introduced.
pub const EIO: i32 = -16;

/// Protected recovery knowledge states. Internal model only — the baseline
/// fixes no numeric wire code for these states, so none is invented here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryState {
    /// Dual checkpoint relation and committed chain provable (A10-A side).
    /// Ordinary admission/capability checks still apply elsewhere.
    Verified,
    /// Uncertain completion (timeout/reset/power loss at a commit boundary).
    /// UNKNOWN is a state, not "not executed"; never a success claim.
    Unknown,
    /// §9.5/§9.7: protected read-only diagnostics/mirror export only.
    RecoveryRequired,
}

/// Acceptance-matrix symbol (A10-B / SEC-F05 / SEC-F09 / SEC-D05 / J05).
/// RECOVERY_REQUIRED is a protected state, not an errno value.
pub const RECOVERY_REQUIRED: RecoveryState = RecoveryState::RecoveryRequired;

/// Verified facts about the two superblocks, supplied by the native owner
/// AFTER independent format/UUID/CRC verification (§9.5 mount precondition).
/// This layer does not re-parse media; `recovery_v1` / `file_media_v0199`
/// own the raw byte checks. All-false means "nothing proven".
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CheckpointPairFacts {
    /// First superblock passed independent format/UUID/CRC verification.
    pub first_valid: bool,
    /// Second superblock passed independent format/UUID/CRC verification.
    pub second_valid: bool,
    /// Both copies carry the same FS UUID (one filesystem, one pair).
    pub same_fs_uuid: bool,
    /// Same generation AND same content: legal only as the fresh-image
    /// initial pair ("新镜像两份初值完全相同").
    pub identical_initial_pair: bool,
    /// Same generation but different content: never a legal checkpoint pair.
    pub same_generation_different_content: bool,
    /// Alternating checkpoints prove generation adjacency, log_epoch
    /// adjacency and monotone checkpoint_lsn; or the identical initial pair.
    pub relation_provable: bool,
    /// §9.4: any verifiable log record with log_epoch above the selected
    /// superblock. Corrupt/unparsable evidence never proves absence.
    pub higher_generation_log: bool,
}

/// Deterministic §9.5 base-point classification. Only a fully qualified pair
/// selects the highest generation; every other case is RECOVERY_REQUIRED.
/// A `Verified` result is a candidate base point, NOT a mount: the full
/// committed-chain/structure validation of §9.5 steps 2-5 still applies.
pub const fn classify_checkpoint_pair(f: &CheckpointPairFacts) -> RecoveryState {
    if !f.first_valid
        || !f.second_valid
        || !f.same_fs_uuid
        || f.same_generation_different_content
        || !f.relation_provable
        || f.higher_generation_log
    {
        RECOVERY_REQUIRED
    } else {
        RecoveryState::Verified
    }
}

/// Operations whose allowance the recovery state controls (§9.5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryOperation {
    /// Protected read-only diagnostic (authorized recovery/diagnostic role).
    ProtectedReadOnlyDiagnostic,
    /// Protected read-only mirror export.
    ProtectedMirrorExport,
    OrdinaryFileRead,
    OrdinaryFileWrite,
    AllocateBootEpoch,
    DurableSuccessReply,
    DiskModification,
    RemountWritable,
}

/// §9.5: RECOVERY_REQUIRED allows only protected read-only diagnostics and
/// mirror export — no ordinary file service, no BootEpoch allocation, no
/// durable success, no disk modification. Documented extension: UNKNOWN
/// keeps the same read-only set (v0.19.10 §2 "保持冻结、只读或 UNKNOWN");
/// the baseline explicitly fixes the allowance only for RECOVERY_REQUIRED.
pub const fn recovery_operation_allowed(state: RecoveryState, op: RecoveryOperation) -> bool {
    match state {
        RecoveryState::Verified => true,
        RecoveryState::Unknown | RecoveryState::RecoveryRequired => matches!(
            op,
            RecoveryOperation::ProtectedReadOnlyDiagnostic
                | RecoveryOperation::ProtectedMirrorExport
        ),
    }
}

/// External refusal result for ordinary operations while the gate is not
/// Verified: baseline surfaces RECOVERY_REQUIRED/EIO (A10-B, SEC-F05/F09/
/// D05, J05). `None` means this layer issues no refusal; success (0) is
/// only ever issued by the real completion path, never by a classifier.
pub const fn refusal_errno(state: RecoveryState) -> Option<i32> {
    match state {
        RecoveryState::Verified => None,
        RecoveryState::Unknown | RecoveryState::RecoveryRequired => Some(EIO),
    }
}

// ---------------------------------------------------------------------------
// (b) RecoveryProof v2 — exact baseline 256B layout (安§0.9)
// ---------------------------------------------------------------------------

pub const RECOVERY_PROOF_MAGIC: u32 = 0x4359_5241;
pub const RECOVERY_PROOF_VERSION: u16 = 2;
pub const RECOVERY_PROOF_BYTES: usize = 256;
/// ASCII domain separator, exact bytes (digest-label registry, SEC-S11).
pub const RECOVERY_DOMAIN: &[u8] = b"CYX/RECOVERY/v2";
/// flags bit0: sticky counter overflow.
pub const FLAG_OVERFLOW: u32 = 1 << 0;
/// flags bit1: audit degraded (AUDIT_DEGRADED fallback accumulator).
pub const FLAG_DEGRADED: u32 = 1 << 1;
/// 4×256B emergency accumulators inside the 9 KiB SecurityAudit+RecoveryProof
/// protected pool (8192B audit slots + 1024B accumulators).
pub const ACCUMULATOR_COUNT: usize = 4;

const _: () = assert!(RECOVERY_PROOF_BYTES == 256);
const _: () = assert!(8192 + ACCUMULATOR_COUNT * RECOVERY_PROOF_BYTES == 9 * 1024);

/// RecoveryProof v2 per-CPU emergency accumulator image. Binds the operation
/// digest (`last_event_digest`), the authoritative evidence chain
/// (`chain_digest` over protected audit evidence) and the generations
/// (`boot_epoch`, `cpu_generation`, `last_object_generation`). It proves ONLY
/// the audit-degraded summary: it can never substitute COMMIT, ResetProof or
/// TLB ACK (安§0.9), and it records no keys/plaintext (SEC-I09).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryProofV2 {
    /// offset 8
    pub boot_epoch: u64,
    /// offset 16
    pub cpu_id: u32,
    /// offset 20; only bit0 (overflow) / bit1 (degraded) are defined.
    pub flags: u32,
    /// offset 24
    pub cpu_generation: u64,
    /// offset 32
    pub last_event_id: u64,
    /// offset 40; saturates, never wraps.
    pub total_count: u64,
    /// offset 48; saturates, never wraps.
    pub unknown_count: u64,
    /// offset 56
    pub last_failure_code: u32,
    /// offset 64; saturates, never wraps.
    pub revoke_count: u64,
    /// offset 72; saturates, never wraps.
    pub recovery_count: u64,
    /// offset 80
    pub last_object_id: u64,
    /// offset 88
    pub last_object_generation: u64,
    /// offset 96, 32B
    pub last_event_digest: [u8; 32],
    /// offset 128, 32B; all-zero before the first recorded event.
    pub chain_digest: [u8; 32],
}

impl RecoveryProofV2 {
    /// Canonical little-endian encoding. Reserved word at 60 and bytes
    /// 160..255 are zero; magic/version/length are the frozen constants.
    pub fn encode(&self, out: &mut [u8; RECOVERY_PROOF_BYTES]) {
        out.fill(0);
        out[0..4].copy_from_slice(&RECOVERY_PROOF_MAGIC.to_le_bytes());
        out[4..6].copy_from_slice(&RECOVERY_PROOF_VERSION.to_le_bytes());
        out[6..8].copy_from_slice(&(RECOVERY_PROOF_BYTES as u16).to_le_bytes());
        out[8..16].copy_from_slice(&self.boot_epoch.to_le_bytes());
        out[16..20].copy_from_slice(&self.cpu_id.to_le_bytes());
        out[20..24].copy_from_slice(&self.flags.to_le_bytes());
        out[24..32].copy_from_slice(&self.cpu_generation.to_le_bytes());
        out[32..40].copy_from_slice(&self.last_event_id.to_le_bytes());
        out[40..48].copy_from_slice(&self.total_count.to_le_bytes());
        out[48..56].copy_from_slice(&self.unknown_count.to_le_bytes());
        out[56..60].copy_from_slice(&self.last_failure_code.to_le_bytes());
        // 60..64 reserved = 0
        out[64..72].copy_from_slice(&self.revoke_count.to_le_bytes());
        out[72..80].copy_from_slice(&self.recovery_count.to_le_bytes());
        out[80..88].copy_from_slice(&self.last_object_id.to_le_bytes());
        out[88..96].copy_from_slice(&self.last_object_generation.to_le_bytes());
        out[96..128].copy_from_slice(&self.last_event_digest);
        out[128..160].copy_from_slice(&self.chain_digest);
        // 160..256 reserved = 0
    }

    /// Strict decode: exact 256 bytes, frozen magic/version/length, only
    /// defined flag bits, zero reserved word and tail. Schema rejections
    /// surface as [`Error::Invalid`] here (native boundary: E_FORMAT -2 /
    /// E_SCHEMA -3 per the frozen errno table).
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() != RECOVERY_PROOF_BYTES {
            return Err(Error::Invalid);
        }
        let le16 = |at: usize| u16::from_le_bytes([b[at], b[at + 1]]);
        let le32 = |at: usize| u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
        let le64 = |at: usize| {
            u64::from_le_bytes([
                b[at],
                b[at + 1],
                b[at + 2],
                b[at + 3],
                b[at + 4],
                b[at + 5],
                b[at + 6],
                b[at + 7],
            ])
        };
        if le32(0) != RECOVERY_PROOF_MAGIC
            || le16(4) != RECOVERY_PROOF_VERSION
            || le16(6) as usize != RECOVERY_PROOF_BYTES
            || le32(20) & !(FLAG_OVERFLOW | FLAG_DEGRADED) != 0
            || le32(60) != 0
            || b[160..].iter().any(|&v| v != 0)
        {
            return Err(Error::Invalid);
        }
        let mut last_event_digest = [0u8; 32];
        last_event_digest.copy_from_slice(&b[96..128]);
        let mut chain_digest = [0u8; 32];
        chain_digest.copy_from_slice(&b[128..160]);
        Ok(Self {
            boot_epoch: le64(8),
            cpu_id: le32(16),
            flags: le32(20),
            cpu_generation: le64(24),
            last_event_id: le64(32),
            total_count: le64(40),
            unknown_count: le64(48),
            last_failure_code: le32(56),
            revoke_count: le64(64),
            recovery_count: le64(72),
            last_object_id: le64(80),
            last_object_generation: le64(88),
            last_event_digest,
            chain_digest,
        })
    }

    /// Exact baseline chain step:
    /// `SHA256("CYX/RECOVERY/v2" || old_chain || last_event_digest ||
    /// LE64(total_count))`. The initial chain is all-zero by definition,
    /// not a hash output.
    pub fn chain_step(
        old_chain: &[u8; 32],
        last_event_digest: &[u8; 32],
        total_count: u64,
    ) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(RECOVERY_DOMAIN);
        h.update(old_chain);
        h.update(last_event_digest);
        h.update(total_count.to_le_bytes());
        h.finalize().into()
    }

    /// True for the defined initial image: no event recorded yet, chain
    /// all-zero. `verify_chain_from` does not apply to the initial image.
    pub fn is_initial(&self) -> bool {
        self.total_count == 0
            && self.last_event_id == 0
            && self.last_event_digest == [0; 32]
            && self.chain_digest == [0; 32]
    }

    /// Re-derive the chain from the predecessor chain. A standalone decoder
    /// cannot verify the chain without `old_chain`; the native audit
    /// recovery role holds it.
    pub fn verify_chain_from(&self, old_chain: &[u8; 32]) -> bool {
        Self::chain_step(old_chain, &self.last_event_digest, self.total_count) == self.chain_digest
    }
}

/// Event kinds feeding the degraded counters. Documented contract mapping
/// (baseline fixes the counter names, not a per-event increment table; G1
/// freezes the exact mapping): CAP_REVOKE (event_type 2, including the
/// emergency recovery-slot revoke) → revoke_count; recovery-class events
/// (CRITICAL_RECOVERY_START/STOP/RECONCILE, class 3) → recovery_count;
/// unclassifiable/unknown-reason events → unknown_count; every recorded
/// event → total_count. No keys/plaintext are ever recorded (SEC-I09).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DegradedEventKind {
    CapRevoke,
    Recovery,
    Unknown,
    OtherCritical,
}

/// One degraded-audit event, already verified by the protected sender path
/// (real EL1 sender, seq, object generation and digest — 安§0.9). The
/// accumulator never accepts a business self-filled reason table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DegradedEvent {
    pub kind: DegradedEventKind,
    pub event_id: u64,
    pub event_digest: [u8; 32],
    pub object_id: u64,
    pub object_generation: u64,
    pub failure_code: u32,
}

/// Per-CPU single-writer emergency accumulator (安§0.9). Native wiring must
/// place it in preallocated memory and use it only after the authorization
/// gate was atomically closed and group/recovery slots were tried first.
/// Counters saturate with sticky overflow and never wrap; after saturation
/// the summary is frozen — no further per-event proof is fabricated
/// ("饱和后不伪造逐事件证明", conservative reading documented in the header).
#[derive(Debug)]
pub struct RecoveryAccumulator {
    proof: RecoveryProofV2,
}

impl RecoveryAccumulator {
    /// Fresh accumulator for one CPU writer. Zero boot_epoch or
    /// cpu_generation cannot bind evidence to a real boot/writer (documented
    /// binding-hygiene rule; the baseline fixes no explicit nonzero sentence).
    pub fn new(boot_epoch: u64, cpu_id: u32, cpu_generation: u64) -> Result<Self, Error> {
        if boot_epoch == 0 || cpu_generation == 0 {
            return Err(Error::Invalid);
        }
        Ok(Self {
            proof: RecoveryProofV2 {
                boot_epoch,
                cpu_id,
                flags: 0,
                cpu_generation,
                last_event_id: 0,
                total_count: 0,
                unknown_count: 0,
                last_failure_code: 0,
                revoke_count: 0,
                recovery_count: 0,
                last_object_id: 0,
                last_object_generation: 0,
                last_event_digest: [0; 32],
                chain_digest: [0; 32],
            },
        })
    }

    /// Reconstruct the volatile accumulator from its canonical decoded
    /// image (e.g. EL1 takeover readback). Schema validation already
    /// happened in [`RecoveryProofV2::decode`].
    pub fn from_decoded(proof: RecoveryProofV2) -> Self {
        Self { proof }
    }

    pub fn proof(&self) -> &RecoveryProofV2 {
        &self.proof
    }

    /// Record one verified degraded event. Audit-seq discipline applies to
    /// event_id (EL1-only increase, no wrap; same-key same-digest repeat is
    /// idempotent, same-key different-digest is rejected — 安§0.9). Once
    /// overflow is sticky the frozen summary is returned unchanged.
    pub fn record(&mut self, ev: &DegradedEvent) -> Result<(), Error> {
        let p = &mut self.proof;
        if p.flags & FLAG_OVERFLOW != 0 {
            return Ok(());
        }
        // Seq 0 is never a real event; the initial last_event_id is 0.
        if ev.event_id == 0 {
            return Err(Error::Invalid);
        }
        if ev.event_id < p.last_event_id {
            return Err(Error::Stale);
        }
        if ev.event_id == p.last_event_id {
            return if ev.event_digest == p.last_event_digest {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        // Strict increase means no wrap: past u64::MAX no successor exists,
        // so every later id is stale or a same-key repeat handled above.
        let total = p.total_count.saturating_add(1);
        let (revoke, recovery, unknown) = match ev.kind {
            DegradedEventKind::CapRevoke => (
                p.revoke_count.saturating_add(1),
                p.recovery_count,
                p.unknown_count,
            ),
            DegradedEventKind::Recovery => (
                p.revoke_count,
                p.recovery_count.saturating_add(1),
                p.unknown_count,
            ),
            DegradedEventKind::Unknown => (
                p.revoke_count,
                p.recovery_count,
                p.unknown_count.saturating_add(1),
            ),
            DegradedEventKind::OtherCritical => (p.revoke_count, p.recovery_count, p.unknown_count),
        };
        p.total_count = total;
        p.revoke_count = revoke;
        p.recovery_count = recovery;
        p.unknown_count = unknown;
        p.last_event_id = ev.event_id;
        p.last_event_digest = ev.event_digest;
        p.last_object_id = ev.object_id;
        p.last_object_generation = ev.object_generation;
        p.last_failure_code = ev.failure_code;
        p.chain_digest = RecoveryProofV2::chain_step(&p.chain_digest, &ev.event_digest, total);
        // Any event landing here means audit slots were unavailable.
        p.flags |= FLAG_DEGRADED;
        if total == u64::MAX || revoke == u64::MAX || recovery == u64::MAX || unknown == u64::MAX {
            p.flags |= FLAG_OVERFLOW;
        }
        Ok(())
    }

    /// Issue a successor writer/consumer generation after the native takeover
    /// verified the old generation, closed old read/ACK rights and confirmed
    /// the read watermark (those duties are native EL1, out of scope here).
    /// Accumulated unconfirmed evidence is retained, never overwritten;
    /// generations strictly increase and never wrap.
    pub fn takeover(&mut self, new_cpu_generation: u64) -> Result<(), Error> {
        // Strict increase also rules out wrap: at u64::MAX no successor
        // exists, so every candidate is stale.
        if new_cpu_generation <= self.proof.cpu_generation {
            return Err(Error::Stale);
        }
        self.proof.cpu_generation = new_cpu_generation;
        Ok(())
    }
}

/// What a proof artifact is allowed to stand for. 安§0.9: RecoveryProof v2
/// proves only the audit-degraded summary; 安§7.1: each domain's truth comes
/// only from its own evidence (file persistence = log evidence, device DMA
/// end = completion/reliable-reset proof, TLB = ACK). A service self-report
/// or a bare device reset is never durable-success proof (A10-B, SEC-D05).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionAuthority {
    /// Verified BEGIN/REDO/COMMIT chain + FLUSH evidence (file domain).
    CommitChain,
    /// Reliable device reset/completion proof (device domain only).
    ResetProof,
    /// TLB invalidation ACK (memory domain only).
    TlbAck,
    /// Audit-degraded summary only — substitutes nothing.
    RecoveryProofV2,
    /// The service's own claim — never authoritative.
    ServiceSelfReport,
    /// Device reset observed without durable proof — not success.
    DeviceReset,
}

/// Whether the artifact is real completion evidence in ITS OWN domain.
/// Only [`CompletionAuthority::CommitChain`] can support durable file
/// success or a write-gate reopen; the gate enforces that separately.
pub const fn may_substitute_completion(a: CompletionAuthority) -> bool {
    matches!(
        a,
        CompletionAuthority::CommitChain
            | CompletionAuthority::ResetProof
            | CompletionAuthority::TlbAck
    )
}

// ---------------------------------------------------------------------------
// (c) Recovery gate — only a deterministic path with real completion proof
//     re-opens writes (§9.5 exit rule + V0.19.10 candidate §5)
// ---------------------------------------------------------------------------

/// Real completion evidence for the deterministic reopen path. Every field
/// is a fact the native recovery owner must prove from actual media; a
/// model, an automatic restart or the failed service itself cannot supply
/// them. All-false/zero means "no evidence" and keeps the gate closed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReopenEvidence {
    /// Rebuilt dual checkpoint re-passes §9.5 independent verification and
    /// relation checks (offline rebuild + re-acceptance).
    pub rebuilt_pair: CheckpointPairFacts,
    /// Full committed chain (BEGIN/all REDO/COMMIT, all checksums) verified
    /// for the selected generation (§9.5 step 3).
    pub committed_chain_verified: bool,
    /// Post-replay home FLUSH confirmed (§9.5 step 5).
    pub home_flush_confirmed: bool,
    /// New noncurrent superblock written, FLUSHed and read back identical
    /// (§9.5 step 5; readback is not a substitute for FLUSH — both).
    pub checkpoint_readback_verified: bool,
    /// Digest binding the recovery operation (redo/afterimage chain).
    /// Zero digest = no operation bound = no evidence.
    pub operation_digest: [u8; 32],
    /// Current protection generation. Never rolls back (V0.19.10 §5);
    /// BootEpoch is likewise never rolled back or re-allocated here.
    pub protection_generation: u64,
}

/// Protected recovery write gate. RECOVERY_REQUIRED is a monotonic latch:
/// the baseline promises no online recovery (§9.5/§9.7), so the ONLY return
/// to Verified is [`RecoveryGate::reopen`] with full real evidence and the
/// independent deterministic authority. A/B are judged separately: raising
/// the B-side refusal produces no A-side data-recovery proof (A10).
#[derive(Debug)]
pub struct RecoveryGate {
    state: RecoveryState,
    reopen_authority: Identity,
    boot_epoch: u64,
    protection_generation: u64,
}

impl RecoveryGate {
    /// Mount preflight: the initial state is the deterministic §9.5
    /// classification of the verified pair facts. The reopen authority is
    /// an EL1-verified independent identity, never the failed service,
    /// a model role or an ordinary FileCap.
    pub fn new(
        boot_epoch: u64,
        protection_generation: u64,
        reopen_authority: Identity,
        initial: &CheckpointPairFacts,
    ) -> Result<Self, Error> {
        if boot_epoch == 0 || protection_generation == 0 || !reopen_authority.valid() {
            return Err(Error::Invalid);
        }
        Ok(Self {
            state: classify_checkpoint_pair(initial),
            reopen_authority,
            boot_epoch,
            protection_generation,
        })
    }

    pub fn state(&self) -> RecoveryState {
        self.state
    }

    pub fn boot_epoch(&self) -> u64 {
        self.boot_epoch
    }

    pub fn protection_generation(&self) -> u64 {
        self.protection_generation
    }

    /// Recovery-gate allowance only; ordinary admission/capability checks
    /// still apply on top. Never true in UNKNOWN or RECOVERY_REQUIRED.
    pub fn may_write(&self) -> bool {
        self.state == RecoveryState::Verified
    }

    /// Raise the B-side refusal when the pair facts demand it. Monotonic:
    /// once RECOVERY_REQUIRED, no later "good facts" report returns the gate
    /// to Verified online — only the evidenced reopen path can.
    pub fn raise(&mut self, facts: &CheckpointPairFacts) -> RecoveryState {
        if classify_checkpoint_pair(facts) == RECOVERY_REQUIRED {
            self.state = RECOVERY_REQUIRED;
        }
        self.state
    }

    /// Uncertain completion (timeout/reset/power loss): Verified → Unknown.
    /// Never downgrades RECOVERY_REQUIRED and never claims success.
    pub fn mark_unknown(&mut self) -> RecoveryState {
        if self.state == RecoveryState::Verified {
            self.state = RecoveryState::Unknown;
        }
        self.state
    }

    /// Confirming a persistent request result does NOT lift a remaining
    /// protection gate (V0.19.10 §5). Returns the unchanged state.
    pub fn ack_persistent_request(&self) -> RecoveryState {
        self.state
    }

    /// The only deterministic open-writes path (§9.5 exit + V0.19.10 §5):
    /// independent authority + real commit-chain completion proof + rebuilt
    /// re-accepted pair + non-rollback protection generation. Self-reported
    /// claims, bare device resets, RecoveryProof v2 summaries, ResetProof and
    /// TLB ACKs are all rejected for write reopen. Without evidence the gate
    /// keeps UNKNOWN/RECOVERY_REQUIRED and returns an error.
    pub fn reopen(
        &mut self,
        actor: Identity,
        completion: CompletionAuthority,
        evidence: &ReopenEvidence,
    ) -> Result<(), Error> {
        if actor != self.reopen_authority {
            return Err(Error::Unauthorized);
        }
        if self.state == RecoveryState::Verified {
            return Err(Error::Busy);
        }
        if completion != CompletionAuthority::CommitChain {
            return Err(Error::Invalid);
        }
        if classify_checkpoint_pair(&evidence.rebuilt_pair) != RecoveryState::Verified
            || !evidence.committed_chain_verified
            || !evidence.home_flush_confirmed
            || !evidence.checkpoint_readback_verified
            || evidence.operation_digest == [0; 32]
        {
            // Missing evidence: keep the current closed state, no success.
            return Err(Error::Unknown);
        }
        if evidence.protection_generation < self.protection_generation {
            return Err(Error::Conflict);
        }
        self.protection_generation = evidence.protection_generation;
        self.state = RecoveryState::Verified;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// (d) Production recovery decision authority — native-owner skeleton for T1.
// ---------------------------------------------------------------------------

/// Snapshot of the protected recovery decision for the production path.
/// `may_write` and `allocate_boot_epoch_allowed` are recovery-gate allowance
/// only; ordinary admission/capability checks still apply on top. A non-Verified
/// state surfaces to ordinary callers as the frozen EIO, never a new errno.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryDecision {
    pub state: RecoveryState,
    pub may_write: bool,
    pub refusal_errno: Option<i32>,
    pub allocate_boot_epoch_allowed: bool,
}

/// Production recovery decision surface: the monotonic write gate plus the
/// four preallocated per-CPU degraded-audit accumulators (the 1 KiB
/// accumulator portion of the 9 KiB SecurityAudit+RecoveryProof protected
/// pool). Serialized EL1 recovery owner only. Never mounts a volume, never
/// allocates a BootEpoch, never authorizes a write by itself.
///
/// # Integration contract — how T1's production recovery path calls this
/// 1. Independently verify both superblocks (format/UUID/CRC) and the pair
///    relation; build [`CheckpointPairFacts`] from real media, never a model.
/// 2. [`RecoveryAuthority::new`]`(boot_epoch, protection_generation,
///    reopen_authority, &facts)` — the initial state is the deterministic §9.5
///    classification. `reopen_authority` is the EL1-verified independent
///    recovery identity, never the failed service or an ordinary FileCap.
/// 3. [`RecoveryAuthority::decision`] gives the production allowance snapshot;
///    on RECOVERY_REQUIRED/UNKNOWN deny ordinary ops with `refusal_errno`
///    (EIO) and allow only protected read-only diagnostics/mirror export.
/// 4. Feed later verified pair facts via [`RecoveryAuthority::observe_pair`]
///    (monotonic latch) and uncertain completion via `observe_unknown`.
/// 5. While audit slots are unavailable, record verified degraded events with
///    [`RecoveryAuthority::record_degraded`] (AUDIT_DEGRADED). Their summaries
///    (`degraded_proof`) are audit evidence ONLY and can never reopen writes.
/// 6. The ONLY return to Verified is [`RecoveryAuthority::reopen`] with the
///    independent authority + `CompletionAuthority::CommitChain` + full real
///    [`ReopenEvidence`] (rebuilt re-accepted pair, committed chain, FLUSH,
///    readback, nonzero operation digest, non-rollback protection generation).
///    Without evidence the gate stays closed and an error is returned.
///
/// Skeleton model: the accumulators are owned here and routed by CPU index
/// (0..ACCUMULATOR_COUNT). Native wiring must place them in the protected pool,
/// pin each to its CPU single writer, and use them only after the authorization
/// gate was atomically closed and group/recovery slots were tried first.
///
/// Honest scope: native-authority API skeleton. Actual audit-slot fallback,
/// per-CPU preallocation and mount integration are exercised by T1's QEMU
/// production boot / a later wave; host tests below are not native evidence.
#[derive(Debug)]
pub struct RecoveryAuthority {
    gate: RecoveryGate,
    degraded: [RecoveryAccumulator; ACCUMULATOR_COUNT],
}
const _: () = assert!(ACCUMULATOR_COUNT == 4);
impl RecoveryAuthority {
    /// Mount preflight: initial state is the deterministic §9.5 classification
    /// of the verified pair facts. Also constructs the four initial per-CPU
    /// degraded accumulators bound to this boot epoch (writer generation 1).
    pub fn new(
        boot_epoch: u64,
        protection_generation: u64,
        reopen_authority: Identity,
        initial: &CheckpointPairFacts,
    ) -> Result<Self, Error> {
        let gate = RecoveryGate::new(boot_epoch, protection_generation, reopen_authority, initial)?;
        // gate::new already rejected boot_epoch == 0; writer generation 1 is
        // nonzero, so these constructions cannot fail.
        let degraded = [
            RecoveryAccumulator::new(boot_epoch, 0, 1)?,
            RecoveryAccumulator::new(boot_epoch, 1, 1)?,
            RecoveryAccumulator::new(boot_epoch, 2, 1)?,
            RecoveryAccumulator::new(boot_epoch, 3, 1)?,
        ];
        Ok(Self { gate, degraded })
    }

    pub fn state(&self) -> RecoveryState {
        self.gate.state()
    }
    pub fn boot_epoch(&self) -> u64 {
        self.gate.boot_epoch()
    }
    pub fn protection_generation(&self) -> u64 {
        self.gate.protection_generation()
    }

    /// Classify a freshly verified checkpoint pair and latch the gate.
    /// Monotonic: once RECOVERY_REQUIRED, later "good facts" never return the
    /// gate to Verified online. Returns the resulting state.
    pub fn observe_pair(&mut self, facts: &CheckpointPairFacts) -> RecoveryState {
        self.gate.raise(facts)
    }

    /// Uncertain completion (timeout/reset/power loss): Verified → Unknown.
    /// Never downgrades RECOVERY_REQUIRED and never claims success.
    pub fn observe_unknown(&mut self) -> RecoveryState {
        self.gate.mark_unknown()
    }

    /// The current production decision snapshot.
    pub fn decision(&self) -> RecoveryDecision {
        let state = self.gate.state();
        RecoveryDecision {
            state,
            may_write: self.gate.may_write(),
            refusal_errno: refusal_errno(state),
            allocate_boot_epoch_allowed: recovery_operation_allowed(
                state,
                RecoveryOperation::AllocateBootEpoch,
            ),
        }
    }

    /// Confirming a persistent request result does NOT lift a remaining
    /// protection gate (V0.19.10 §5). Returns the unchanged state.
    pub fn ack_persistent_request(&self) -> RecoveryState {
        self.gate.ack_persistent_request()
    }

    /// The only deterministic open-writes path. Delegates to the gate:
    /// independent authority + CommitChain + full real evidence + non-rollback
    /// protection generation. Returns the new state on success; on any
    /// missing/invalid evidence the gate stays closed and an error is returned.
    pub fn reopen(
        &mut self,
        actor: Identity,
        completion: CompletionAuthority,
        evidence: &ReopenEvidence,
    ) -> Result<RecoveryState, Error> {
        self.gate.reopen(actor, completion, evidence)?;
        Ok(self.gate.state())
    }

    fn slot(&self, cpu: u32) -> Result<usize, Error> {
        let i = cpu as usize;
        if i >= ACCUMULATOR_COUNT {
            return Err(Error::Invalid);
        }
        Ok(i)
    }

    /// Record one verified degraded-audit event into the CPU's emergency
    /// accumulator (AUDIT_DEGRADED fallback). Audit-seq discipline and
    /// saturating sticky counters apply. This is audit evidence only.
    pub fn record_degraded(&mut self, cpu: u32, ev: &DegradedEvent) -> Result<(), Error> {
        let i = self.slot(cpu)?;
        self.degraded[i].record(ev)
    }

    /// The CPU's current audit-degraded summary. Never completion evidence and
    /// never a write-reopen authority (安§0.9 / 安§7.1).
    pub fn degraded_proof(&self, cpu: u32) -> Result<RecoveryProofV2, Error> {
        let i = self.slot(cpu)?;
        Ok(*self.degraded[i].proof())
    }

    /// Issue a successor writer generation for one CPU accumulator after the
    /// native takeover verified the old generation. Accumulated unconfirmed
    /// evidence is retained; generations strictly increase and never wrap.
    pub fn takeover_degraded(&mut self, cpu: u32, new_cpu_generation: u64) -> Result<(), Error> {
        let i = self.slot(cpu)?;
        self.degraded[i].takeover(new_cpu_generation)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn hex(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    // Independent golden vectors (python hashlib, not this code):
    // H("CYX/RECOVERY/v2" || 0^32 || 0xAB^32 || LE64(1))
    const CHAIN_1: &str = "8268289772f6825fdb7396e0352e5b2d42fa3055bea4345a1958f29f6e0423b0";
    // H("CYX/RECOVERY/v2" || CHAIN_1 || 0xCD^32 || LE64(2))
    const CHAIN_2: &str = "e93b9c1e911f50d88fa8c455cdeaddaff51db944eeef601a7b6e5b3f37a83b76";
    // H("CYX/RECOVERY/v2" || CHAIN_2 || 0x01^32 || LE64(u64::MAX))
    const CHAIN_SAT: &str = "6948845b58c7a72f2b4f22919a6449071187a9935596c8f861261798fa6a5b50";

    fn good_pair() -> CheckpointPairFacts {
        CheckpointPairFacts {
            first_valid: true,
            second_valid: true,
            same_fs_uuid: true,
            identical_initial_pair: false,
            same_generation_different_content: false,
            relation_provable: true,
            higher_generation_log: false,
        }
    }

    fn event(id: u64, kind: DegradedEventKind, fill: u8) -> DegradedEvent {
        DegradedEvent {
            kind,
            event_id: id,
            event_digest: [fill; 32],
            object_id: 77,
            object_generation: 9,
            failure_code: 16,
        }
    }

    fn authority() -> Identity {
        Identity {
            id: 4,
            generation: 1,
        }
    }

    fn full_evidence(protection: u64) -> ReopenEvidence {
        ReopenEvidence {
            rebuilt_pair: good_pair(),
            committed_chain_verified: true,
            home_flush_confirmed: true,
            checkpoint_readback_verified: true,
            operation_digest: [0x5A; 32],
            protection_generation: protection,
        }
    }

    #[test]
    fn constants_match_baseline() {
        assert_eq!(RECOVERY_PROOF_MAGIC, 0x4359_5241);
        assert_eq!(RECOVERY_PROOF_VERSION, 2);
        assert_eq!(RECOVERY_PROOF_BYTES, 256);
        assert_eq!(RECOVERY_DOMAIN, b"CYX/RECOVERY/v2");
        assert_eq!(RECOVERY_DOMAIN.len(), 15);
        assert_eq!((FLAG_OVERFLOW, FLAG_DEGRADED), (1, 2));
        assert_eq!(EIO, -16);
        assert_eq!(ACCUMULATOR_COUNT, 4);
        assert_eq!(8192 + ACCUMULATOR_COUNT * RECOVERY_PROOF_BYTES, 9 * 1024);
        assert_eq!(RECOVERY_REQUIRED, RecoveryState::RecoveryRequired);
    }

    #[test]
    fn encode_places_fields_at_exact_offsets() {
        let p = RecoveryProofV2 {
            boot_epoch: 0x1122_3344_5566_7788,
            cpu_id: 3,
            flags: FLAG_OVERFLOW | FLAG_DEGRADED,
            cpu_generation: 0x99AA_BBCC_DDEE_FF00,
            last_event_id: 42,
            total_count: 43,
            unknown_count: 44,
            last_failure_code: 16,
            revoke_count: 45,
            recovery_count: 46,
            last_object_id: 77,
            last_object_generation: 9,
            last_event_digest: [0xAB; 32],
            chain_digest: [0xCD; 32],
        };
        let mut b = [0xFFu8; 256];
        p.encode(&mut b);
        assert_eq!(&b[0..4], &0x4359_5241u32.to_le_bytes());
        assert_eq!(&b[4..6], &2u16.to_le_bytes());
        assert_eq!(&b[6..8], &256u16.to_le_bytes());
        assert_eq!(&b[8..16], &p.boot_epoch.to_le_bytes());
        assert_eq!(&b[16..20], &3u32.to_le_bytes());
        assert_eq!(&b[20..24], &3u32.to_le_bytes());
        assert_eq!(&b[24..32], &p.cpu_generation.to_le_bytes());
        assert_eq!(&b[32..40], &42u64.to_le_bytes());
        assert_eq!(&b[40..48], &43u64.to_le_bytes());
        assert_eq!(&b[48..56], &44u64.to_le_bytes());
        assert_eq!(&b[56..60], &16u32.to_le_bytes());
        assert_eq!(&b[60..64], &[0; 4]);
        assert_eq!(&b[64..72], &45u64.to_le_bytes());
        assert_eq!(&b[72..80], &46u64.to_le_bytes());
        assert_eq!(&b[80..88], &77u64.to_le_bytes());
        assert_eq!(&b[88..96], &9u64.to_le_bytes());
        assert_eq!(&b[96..128], &[0xAB; 32]);
        assert_eq!(&b[128..160], &[0xCD; 32]);
        assert!(b[160..].iter().all(|&v| v == 0));
    }

    #[test]
    fn encode_decode_roundtrip() {
        let mut a = RecoveryAccumulator::new(7, 2, 5).unwrap();
        a.record(&event(1, DegradedEventKind::CapRevoke, 0xAB))
            .unwrap();
        a.record(&event(2, DegradedEventKind::Recovery, 0xCD))
            .unwrap();
        let mut b = [0u8; 256];
        a.proof().encode(&mut b);
        assert_eq!(RecoveryProofV2::decode(&b).unwrap(), *a.proof());
    }

    #[test]
    fn decode_rejects_wrong_length() {
        let mut a = RecoveryAccumulator::new(7, 0, 1).unwrap();
        a.record(&event(1, DegradedEventKind::OtherCritical, 1))
            .unwrap();
        let mut b = [0u8; 256];
        a.proof().encode(&mut b);
        assert_eq!(RecoveryProofV2::decode(&b[..255]), Err(Error::Invalid));
        assert_eq!(RecoveryProofV2::decode(&b[..0]), Err(Error::Invalid));
        let mut long = [0u8; 257];
        long[..256].copy_from_slice(&b);
        assert_eq!(RecoveryProofV2::decode(&long), Err(Error::Invalid));
    }

    #[test]
    fn decode_rejects_wrong_magic_version_len() {
        let mut a = RecoveryAccumulator::new(7, 0, 1).unwrap();
        a.record(&event(1, DegradedEventKind::OtherCritical, 1))
            .unwrap();
        let mut b = [0u8; 256];
        a.proof().encode(&mut b);
        let mut bad = b;
        bad[0] ^= 1;
        assert_eq!(RecoveryProofV2::decode(&bad), Err(Error::Invalid));
        for v in [1u16, 3] {
            bad = b;
            bad[4..6].copy_from_slice(&v.to_le_bytes());
            assert_eq!(RecoveryProofV2::decode(&bad), Err(Error::Invalid));
        }
        for l in [128u16, 512] {
            bad = b;
            bad[6..8].copy_from_slice(&l.to_le_bytes());
            assert_eq!(RecoveryProofV2::decode(&bad), Err(Error::Invalid));
        }
    }

    #[test]
    fn decode_rejects_unknown_flags_and_reserved() {
        let mut a = RecoveryAccumulator::new(7, 0, 1).unwrap();
        a.record(&event(1, DegradedEventKind::OtherCritical, 1))
            .unwrap();
        let mut b = [0u8; 256];
        a.proof().encode(&mut b);
        for bit in [4u32, 0x8000_0000] {
            let mut bad = b;
            bad[20..24].copy_from_slice(&(FLAG_DEGRADED | bit).to_le_bytes());
            assert_eq!(RecoveryProofV2::decode(&bad), Err(Error::Invalid));
        }
        let mut bad = b;
        bad[60] = 1;
        assert_eq!(RecoveryProofV2::decode(&bad), Err(Error::Invalid));
        for at in [160usize, 255] {
            bad = b;
            bad[at] = 1;
            assert_eq!(RecoveryProofV2::decode(&bad), Err(Error::Invalid));
        }
    }

    #[test]
    fn initial_accumulator_is_valid_and_initial() {
        let a = RecoveryAccumulator::new(7, 0, 1).unwrap();
        assert!(a.proof().is_initial());
        assert_eq!(a.proof().flags, 0);
        let mut b = [0u8; 256];
        a.proof().encode(&mut b);
        assert!(RecoveryProofV2::decode(&b).unwrap().is_initial());
        // The initial all-zero chain is defined, not a hash output.
        assert!(!a.proof().verify_chain_from(&[0; 32]));
        assert_eq!(
            RecoveryAccumulator::new(0, 0, 1).unwrap_err(),
            Error::Invalid
        );
        assert_eq!(
            RecoveryAccumulator::new(7, 0, 0).unwrap_err(),
            Error::Invalid
        );
    }

    #[test]
    fn chain_steps_match_independent_golden_vectors() {
        let c1 = RecoveryProofV2::chain_step(&[0; 32], &[0xAB; 32], 1);
        assert_eq!(c1, hex(CHAIN_1));
        let c2 = RecoveryProofV2::chain_step(&c1, &[0xCD; 32], 2);
        assert_eq!(c2, hex(CHAIN_2));
        let c3 = RecoveryProofV2::chain_step(&c2, &[0x01; 32], u64::MAX);
        assert_eq!(c3, hex(CHAIN_SAT));
    }

    #[test]
    fn chain_order_and_endianness_are_exact() {
        let c1 = RecoveryProofV2::chain_step(&[0; 32], &[0xAB; 32], 1);
        // Swapping old_chain/event_digest or hashing BE64 must differ.
        let swapped = RecoveryProofV2::chain_step(&[0xAB; 32], &[0; 32], 1);
        assert_ne!(c1, swapped);
        let mut h = Sha256::new();
        h.update(RECOVERY_DOMAIN);
        h.update([0; 32]);
        h.update([0xAB; 32]);
        h.update(1u64.to_be_bytes());
        let be: [u8; 32] = h.finalize().into();
        assert_ne!(c1, be);
    }

    #[test]
    fn record_binds_digest_generation_and_chain() {
        let mut a = RecoveryAccumulator::new(7, 2, 5).unwrap();
        a.record(&event(1, DegradedEventKind::CapRevoke, 0xAB))
            .unwrap();
        let p = a.proof();
        assert_eq!(p.total_count, 1);
        assert_eq!(p.revoke_count, 1);
        assert_eq!((p.recovery_count, p.unknown_count), (0, 0));
        assert_eq!(p.last_event_id, 1);
        assert_eq!(p.last_event_digest, [0xAB; 32]);
        assert_eq!((p.last_object_id, p.last_object_generation), (77, 9));
        assert_eq!(p.last_failure_code, 16);
        assert_eq!(p.flags, FLAG_DEGRADED);
        assert_eq!(p.chain_digest, hex(CHAIN_1));
        assert!(p.verify_chain_from(&[0; 32]));
        assert!(!p.is_initial());
        a.record(&event(2, DegradedEventKind::Recovery, 0xCD))
            .unwrap();
        let p = a.proof();
        assert_eq!((p.total_count, p.revoke_count, p.recovery_count), (2, 1, 1));
        assert_eq!(p.chain_digest, hex(CHAIN_2));
        assert!(p.verify_chain_from(&hex(CHAIN_1)));
        assert!(!p.verify_chain_from(&[0; 32]));
    }

    #[test]
    fn unknown_and_other_kinds_map_to_counters() {
        let mut a = RecoveryAccumulator::new(7, 0, 1).unwrap();
        a.record(&event(1, DegradedEventKind::Unknown, 1)).unwrap();
        a.record(&event(2, DegradedEventKind::OtherCritical, 2))
            .unwrap();
        let p = a.proof();
        assert_eq!((p.total_count, p.unknown_count), (2, 1));
        assert_eq!((p.revoke_count, p.recovery_count), (0, 0));
    }

    #[test]
    fn event_id_discipline_no_wrap_dedup_conflict() {
        let mut a = RecoveryAccumulator::new(7, 0, 1).unwrap();
        assert_eq!(
            a.record(&event(0, DegradedEventKind::CapRevoke, 1)),
            Err(Error::Invalid)
        );
        a.record(&event(5, DegradedEventKind::CapRevoke, 1))
            .unwrap();
        assert_eq!(
            a.record(&event(4, DegradedEventKind::CapRevoke, 1)),
            Err(Error::Stale)
        );
        // Same key + same digest: idempotent, no double count.
        a.record(&event(5, DegradedEventKind::CapRevoke, 1))
            .unwrap();
        assert_eq!(a.proof().total_count, 1);
        // Same key + different digest: rejected.
        assert_eq!(
            a.record(&event(5, DegradedEventKind::CapRevoke, 2)),
            Err(Error::Conflict)
        );
        assert_eq!(a.proof().total_count, 1);
        a.record(&event(u64::MAX, DegradedEventKind::CapRevoke, 3))
            .unwrap();
        assert_eq!(
            a.record(&event(u64::MAX, DegradedEventKind::CapRevoke, 4)),
            Err(Error::Conflict)
        );
        // No successor exists past u64::MAX; nothing wraps.
        assert_eq!(
            a.record(&event(6, DegradedEventKind::CapRevoke, 4)),
            Err(Error::Stale)
        );
    }

    #[test]
    fn counters_saturate_sticky_overflow_never_wrap() {
        let mut p = RecoveryAccumulator::new(7, 0, 1).unwrap().proof;
        p.total_count = u64::MAX - 1;
        p.revoke_count = u64::MAX - 1;
        let mut a = RecoveryAccumulator::from_decoded(p);
        a.record(&event(1, DegradedEventKind::CapRevoke, 1))
            .unwrap();
        let p = a.proof();
        assert_eq!(p.total_count, u64::MAX);
        assert_eq!(p.revoke_count, u64::MAX);
        assert_eq!(p.flags & FLAG_OVERFLOW, FLAG_OVERFLOW);
        assert_eq!(p.flags & FLAG_DEGRADED, FLAG_DEGRADED);
        // Saturation step still hashes LE64(u64::MAX) — golden vector.
        let mut prev = RecoveryAccumulator::new(7, 0, 1).unwrap();
        prev.record(&event(1, DegradedEventKind::CapRevoke, 0xAB))
            .unwrap();
        prev.record(&event(2, DegradedEventKind::Recovery, 0xCD))
            .unwrap();
        let mut q = prev.proof;
        q.total_count = u64::MAX;
        q.flags |= FLAG_OVERFLOW;
        let mut sat = RecoveryAccumulator::from_decoded(q);
        // Frozen summary: no fabricated per-event proof after saturation.
        let before = *sat.proof();
        sat.record(&event(3, DegradedEventKind::Unknown, 0x01))
            .unwrap();
        assert_eq!(*sat.proof(), before);
        assert_eq!(
            RecoveryProofV2::chain_step(&hex(CHAIN_2), &[0x01; 32], u64::MAX),
            hex(CHAIN_SAT)
        );
    }

    #[test]
    fn takeover_requires_strictly_newer_generation_and_keeps_evidence() {
        let mut a = RecoveryAccumulator::new(7, 0, 5).unwrap();
        a.record(&event(1, DegradedEventKind::CapRevoke, 1))
            .unwrap();
        let before = *a.proof();
        assert_eq!(a.takeover(5), Err(Error::Stale));
        assert_eq!(a.takeover(4), Err(Error::Stale));
        a.takeover(6).unwrap();
        assert_eq!(a.proof().cpu_generation, 6);
        assert_eq!(a.proof().total_count, before.total_count);
        assert_eq!(a.proof().chain_digest, before.chain_digest);
        let mut max = RecoveryAccumulator::from_decoded(RecoveryProofV2 {
            cpu_generation: u64::MAX,
            ..*a.proof()
        });
        assert_eq!(max.takeover(u64::MAX), Err(Error::Stale));
        assert_eq!(max.takeover(1), Err(Error::Stale));
    }

    #[test]
    fn valid_pair_and_fresh_image_classify_verified() {
        assert_eq!(
            classify_checkpoint_pair(&good_pair()),
            RecoveryState::Verified
        );
        let fresh = CheckpointPairFacts {
            identical_initial_pair: true,
            ..good_pair()
        };
        assert_eq!(classify_checkpoint_pair(&fresh), RecoveryState::Verified);
    }

    #[test]
    fn single_invalid_copy_enters_recovery_required() {
        for (first, second) in [(false, true), (true, false), (false, false)] {
            let f = CheckpointPairFacts {
                first_valid: first,
                second_valid: second,
                ..good_pair()
            };
            assert_eq!(classify_checkpoint_pair(&f), RECOVERY_REQUIRED);
        }
    }

    #[test]
    fn same_generation_different_content_enters_recovery_required() {
        let f = CheckpointPairFacts {
            same_generation_different_content: true,
            ..good_pair()
        };
        assert_eq!(classify_checkpoint_pair(&f), RECOVERY_REQUIRED);
    }

    #[test]
    fn unprovable_relation_or_uuid_mismatch_enters_recovery_required() {
        let f = CheckpointPairFacts {
            relation_provable: false,
            ..good_pair()
        };
        assert_eq!(classify_checkpoint_pair(&f), RECOVERY_REQUIRED);
        let f = CheckpointPairFacts {
            same_fs_uuid: false,
            ..good_pair()
        };
        assert_eq!(classify_checkpoint_pair(&f), RECOVERY_REQUIRED);
        // Nothing proven at all is never Verified.
        assert_eq!(
            classify_checkpoint_pair(&CheckpointPairFacts::default()),
            RECOVERY_REQUIRED
        );
    }

    #[test]
    fn higher_generation_log_enters_recovery_required() {
        let f = CheckpointPairFacts {
            higher_generation_log: true,
            ..good_pair()
        };
        assert_eq!(classify_checkpoint_pair(&f), RECOVERY_REQUIRED);
    }

    #[test]
    fn recovery_required_allows_only_protected_readonly() {
        let protected = [
            RecoveryOperation::ProtectedReadOnlyDiagnostic,
            RecoveryOperation::ProtectedMirrorExport,
        ];
        let denied = [
            RecoveryOperation::OrdinaryFileRead,
            RecoveryOperation::OrdinaryFileWrite,
            RecoveryOperation::AllocateBootEpoch,
            RecoveryOperation::DurableSuccessReply,
            RecoveryOperation::DiskModification,
            RecoveryOperation::RemountWritable,
        ];
        for op in protected {
            assert!(recovery_operation_allowed(RECOVERY_REQUIRED, op));
            assert!(recovery_operation_allowed(RecoveryState::Unknown, op));
            assert!(recovery_operation_allowed(RecoveryState::Verified, op));
        }
        for op in denied {
            assert!(!recovery_operation_allowed(RECOVERY_REQUIRED, op));
            assert!(!recovery_operation_allowed(RecoveryState::Unknown, op));
            assert!(recovery_operation_allowed(RecoveryState::Verified, op));
        }
    }

    #[test]
    fn refusal_errno_is_frozen_eio_not_a_new_code() {
        assert_eq!(refusal_errno(RECOVERY_REQUIRED), Some(-16));
        assert_eq!(refusal_errno(RecoveryState::Unknown), Some(-16));
        assert_eq!(refusal_errno(RecoveryState::Verified), None);
    }

    #[test]
    fn completion_authority_table() {
        assert!(may_substitute_completion(CompletionAuthority::CommitChain));
        assert!(may_substitute_completion(CompletionAuthority::ResetProof));
        assert!(may_substitute_completion(CompletionAuthority::TlbAck));
        assert!(!may_substitute_completion(
            CompletionAuthority::RecoveryProofV2
        ));
        assert!(!may_substitute_completion(
            CompletionAuthority::ServiceSelfReport
        ));
        assert!(!may_substitute_completion(CompletionAuthority::DeviceReset));
    }

    #[test]
    fn gate_new_starts_from_classified_facts() {
        let g = RecoveryGate::new(7, 3, authority(), &good_pair()).unwrap();
        assert_eq!(g.state(), RecoveryState::Verified);
        assert!(g.may_write());
        let bad = CheckpointPairFacts {
            higher_generation_log: true,
            ..good_pair()
        };
        let g = RecoveryGate::new(7, 3, authority(), &bad).unwrap();
        assert_eq!(g.state(), RECOVERY_REQUIRED);
        assert!(!g.may_write());
        assert_eq!(
            RecoveryGate::new(0, 3, authority(), &good_pair()).unwrap_err(),
            Error::Invalid
        );
        assert_eq!(
            RecoveryGate::new(7, 0, authority(), &good_pair()).unwrap_err(),
            Error::Invalid
        );
        assert_eq!(
            RecoveryGate::new(
                7,
                3,
                Identity {
                    id: 0,
                    generation: 1
                },
                &good_pair()
            )
            .unwrap_err(),
            Error::Invalid
        );
    }

    #[test]
    fn raise_latches_recovery_required_no_online_return() {
        let mut g = RecoveryGate::new(7, 3, authority(), &good_pair()).unwrap();
        let bad = CheckpointPairFacts {
            first_valid: false,
            ..good_pair()
        };
        assert_eq!(g.raise(&bad), RECOVERY_REQUIRED);
        assert!(!g.may_write());
        // Later "good facts" reports cannot recover online (§9.5/§9.7).
        assert_eq!(g.raise(&good_pair()), RECOVERY_REQUIRED);
        assert!(!g.may_write());
    }

    #[test]
    fn mark_unknown_never_downgrades_recovery_required() {
        let mut g = RecoveryGate::new(7, 3, authority(), &good_pair()).unwrap();
        assert_eq!(g.mark_unknown(), RecoveryState::Unknown);
        assert!(!g.may_write());
        assert_eq!(g.mark_unknown(), RecoveryState::Unknown);
        let bad = CheckpointPairFacts {
            relation_provable: false,
            ..good_pair()
        };
        g.raise(&bad);
        assert_eq!(g.mark_unknown(), RECOVERY_REQUIRED);
    }

    #[test]
    fn reopen_requires_independent_authority() {
        let mut g = RecoveryGate::new(7, 3, authority(), &good_pair()).unwrap();
        g.mark_unknown();
        let stranger = Identity {
            id: 99,
            generation: 1,
        };
        assert_eq!(
            g.reopen(
                stranger,
                CompletionAuthority::CommitChain,
                &full_evidence(3)
            ),
            Err(Error::Unauthorized)
        );
        assert_eq!(g.state(), RecoveryState::Unknown);
        // Same id, wrong generation is not the verified authority either.
        let stale = Identity {
            id: 4,
            generation: 2,
        };
        assert_eq!(
            g.reopen(stale, CompletionAuthority::CommitChain, &full_evidence(3)),
            Err(Error::Unauthorized)
        );
    }

    #[test]
    fn reopen_rejects_self_report_reset_and_audit_summary() {
        for fake in [
            CompletionAuthority::ServiceSelfReport,
            CompletionAuthority::DeviceReset,
            CompletionAuthority::RecoveryProofV2,
            CompletionAuthority::ResetProof,
            CompletionAuthority::TlbAck,
        ] {
            let mut g = RecoveryGate::new(7, 3, authority(), &good_pair()).unwrap();
            g.raise(&CheckpointPairFacts {
                second_valid: false,
                ..good_pair()
            });
            assert_eq!(
                g.reopen(authority(), fake, &full_evidence(3)),
                Err(Error::Invalid)
            );
            assert_eq!(g.state(), RECOVERY_REQUIRED);
            assert!(!g.may_write());
        }
    }

    #[test]
    fn reopen_without_evidence_keeps_closed_state() {
        let base = full_evidence(3);
        let variants = [
            ReopenEvidence {
                committed_chain_verified: false,
                ..base
            },
            ReopenEvidence {
                home_flush_confirmed: false,
                ..base
            },
            ReopenEvidence {
                checkpoint_readback_verified: false,
                ..base
            },
            ReopenEvidence {
                operation_digest: [0; 32],
                ..base
            },
            ReopenEvidence {
                rebuilt_pair: CheckpointPairFacts::default(),
                ..base
            },
            ReopenEvidence::default(),
        ];
        for ev in variants {
            let mut g = RecoveryGate::new(7, 3, authority(), &good_pair()).unwrap();
            g.mark_unknown();
            assert_eq!(
                g.reopen(authority(), CompletionAuthority::CommitChain, &ev),
                Err(Error::Unknown)
            );
            assert_eq!(g.state(), RecoveryState::Unknown);
            let mut g = RecoveryGate::new(7, 3, authority(), &good_pair()).unwrap();
            g.raise(&CheckpointPairFacts {
                higher_generation_log: true,
                ..good_pair()
            });
            assert_eq!(
                g.reopen(authority(), CompletionAuthority::CommitChain, &ev),
                Err(Error::Unknown)
            );
            assert_eq!(g.state(), RECOVERY_REQUIRED);
        }
    }

    #[test]
    fn reopen_rejects_protection_generation_rollback() {
        let mut g = RecoveryGate::new(7, 5, authority(), &good_pair()).unwrap();
        g.mark_unknown();
        assert_eq!(
            g.reopen(
                authority(),
                CompletionAuthority::CommitChain,
                &full_evidence(4)
            ),
            Err(Error::Conflict)
        );
        assert_eq!(g.state(), RecoveryState::Unknown);
        assert_eq!(g.protection_generation(), 5);
    }

    #[test]
    fn reopen_with_real_proof_opens_writes() {
        let mut g = RecoveryGate::new(7, 3, authority(), &good_pair()).unwrap();
        g.raise(&CheckpointPairFacts {
            same_generation_different_content: true,
            ..good_pair()
        });
        assert_eq!(g.state(), RECOVERY_REQUIRED);
        g.reopen(
            authority(),
            CompletionAuthority::CommitChain,
            &full_evidence(4),
        )
        .unwrap();
        assert_eq!(g.state(), RecoveryState::Verified);
        assert!(g.may_write());
        assert_eq!(g.protection_generation(), 4);
        assert_eq!(g.boot_epoch(), 7);
        // Already open: nothing to reopen.
        assert_eq!(
            g.reopen(
                authority(),
                CompletionAuthority::CommitChain,
                &full_evidence(4)
            ),
            Err(Error::Busy)
        );
    }

    #[test]
    fn ack_persistent_request_never_opens_gate() {
        let mut g = RecoveryGate::new(7, 3, authority(), &good_pair()).unwrap();
        g.raise(&CheckpointPairFacts {
            first_valid: false,
            ..good_pair()
        });
        assert_eq!(g.ack_persistent_request(), RECOVERY_REQUIRED);
        assert!(!g.may_write());
        g.mark_unknown();
        assert_eq!(g.ack_persistent_request(), RECOVERY_REQUIRED);
    }

    #[test]
    fn b_side_refusal_is_not_a_side_recovery_proof() {
        // A10: A/B judged separately. The B-side refusal (RECOVERY_REQUIRED)
        // carries no completion digest and cannot stand in for A-side data
        // recovery; reopening still demands the full real evidence.
        let mut g = RecoveryGate::new(7, 3, authority(), &good_pair()).unwrap();
        let refusal = g.raise(&CheckpointPairFacts {
            second_valid: false,
            ..good_pair()
        });
        assert_eq!(refusal, RECOVERY_REQUIRED);
        assert_eq!(refusal_errno(refusal), Some(EIO));
        assert!(!g.may_write());
        assert_eq!(
            g.reopen(
                authority(),
                CompletionAuthority::CommitChain,
                &ReopenEvidence::default()
            ),
            Err(Error::Unknown)
        );
        assert_eq!(g.state(), RECOVERY_REQUIRED);
        // Only the evidenced deterministic path opens; the refusal itself
        // never produced a CommitChain authority.
        assert!(!may_substitute_completion(
            CompletionAuthority::RecoveryProofV2
        ));
        g.reopen(
            authority(),
            CompletionAuthority::CommitChain,
            &full_evidence(3),
        )
        .unwrap();
        assert!(g.may_write());
    }

    // ---- Production recovery decision authority (native-owner skeleton) ----
    // Host tests only; actual audit-slot fallback / per-CPU preallocation /
    // mount integration are exercised by T1's QEMU boot or a later wave.

    #[test]
    fn production_recovery_decision_fail_closed_without_evidence() {
        let mut ra = RecoveryAuthority::new(7, 3, authority(), &good_pair()).unwrap();
        let d = ra.decision();
        assert_eq!(d.state, RecoveryState::Verified);
        assert!(d.may_write);
        assert_eq!(d.refusal_errno, None);
        assert!(d.allocate_boot_epoch_allowed);
        // Classify a bad pair -> RECOVERY_REQUIRED latch.
        let bad = CheckpointPairFacts {
            higher_generation_log: true,
            ..good_pair()
        };
        assert_eq!(ra.observe_pair(&bad), RECOVERY_REQUIRED);
        let d = ra.decision();
        assert_eq!(d.state, RECOVERY_REQUIRED);
        assert!(!d.may_write);
        assert_eq!(d.refusal_errno, Some(EIO));
        assert!(!d.allocate_boot_epoch_allowed);
        // No evidence -> stays closed, no success claim.
        assert_eq!(
            ra.reopen(
                authority(),
                CompletionAuthority::CommitChain,
                &ReopenEvidence::default()
            ),
            Err(Error::Unknown)
        );
        assert_eq!(ra.state(), RECOVERY_REQUIRED);
        // Later "good facts" never recover online.
        assert_eq!(ra.observe_pair(&good_pair()), RECOVERY_REQUIRED);
        // Only full real evidence reopens.
        assert_eq!(
            ra.reopen(
                authority(),
                CompletionAuthority::CommitChain,
                &full_evidence(4)
            ),
            Ok(RecoveryState::Verified)
        );
        assert!(ra.decision().may_write);
        assert_eq!(ra.protection_generation(), 4);
        assert_eq!(ra.boot_epoch(), 7);
    }

    #[test]
    fn production_recovery_degraded_summary_never_reopens() {
        let mut ra = RecoveryAuthority::new(7, 3, authority(), &good_pair()).unwrap();
        ra.observe_pair(&CheckpointPairFacts {
            first_valid: false,
            ..good_pair()
        });
        assert_eq!(ra.state(), RECOVERY_REQUIRED);
        // Record degraded audit events on CPU0 and CPU3.
        ra.record_degraded(0, &event(1, DegradedEventKind::CapRevoke, 0xAB))
            .unwrap();
        ra.record_degraded(3, &event(1, DegradedEventKind::Recovery, 0xCD))
            .unwrap();
        let p0 = ra.degraded_proof(0).unwrap();
        assert_eq!(p0.flags & FLAG_DEGRADED, FLAG_DEGRADED);
        assert_eq!(p0.total_count, 1);
        assert_eq!(p0.revoke_count, 1);
        assert!(p0.verify_chain_from(&[0; 32]));
        assert_eq!(p0.boot_epoch, 7);
        assert_eq!(p0.cpu_id, 0);
        // Out-of-range CPU index is rejected.
        assert_eq!(
            ra.record_degraded(
                ACCUMULATOR_COUNT as u32,
                &event(2, DegradedEventKind::Unknown, 1)
            ),
            Err(Error::Invalid)
        );
        assert_eq!(
            ra.degraded_proof(ACCUMULATOR_COUNT as u32),
            Err(Error::Invalid)
        );
        // The audit-degraded summary is NOT completion evidence: reopen refused.
        assert_eq!(
            ra.reopen(
                authority(),
                CompletionAuthority::RecoveryProofV2,
                &full_evidence(3)
            ),
            Err(Error::Invalid)
        );
        assert_eq!(ra.state(), RECOVERY_REQUIRED);
        assert!(!may_substitute_completion(
            CompletionAuthority::RecoveryProofV2
        ));
        // Only real CommitChain evidence opens.
        ra.reopen(
            authority(),
            CompletionAuthority::CommitChain,
            &full_evidence(3),
        )
        .unwrap();
        assert!(ra.decision().may_write);
    }

    #[test]
    fn production_recovery_unknown_latch_and_degraded_takeover() {
        let mut ra = RecoveryAuthority::new(7, 3, authority(), &good_pair()).unwrap();
        assert_eq!(ra.observe_unknown(), RecoveryState::Unknown);
        let d = ra.decision();
        assert!(!d.may_write);
        assert_eq!(d.refusal_errno, Some(EIO));
        assert!(!d.allocate_boot_epoch_allowed);
        // Acknowledging a persistent request never opens the gate.
        assert_eq!(ra.ack_persistent_request(), RecoveryState::Unknown);
        // Degraded takeover retains evidence; strictly newer generation only.
        ra.record_degraded(1, &event(1, DegradedEventKind::CapRevoke, 1))
            .unwrap();
        let before = ra.degraded_proof(1).unwrap();
        assert_eq!(ra.takeover_degraded(1, 1), Err(Error::Stale));
        ra.takeover_degraded(1, 2).unwrap();
        let after = ra.degraded_proof(1).unwrap();
        assert_eq!(after.cpu_generation, 2);
        assert_eq!(after.total_count, before.total_count);
        assert_eq!(after.chain_digest, before.chain_digest);
        // Reopen from Unknown with real evidence.
        ra.reopen(
            authority(),
            CompletionAuthority::CommitChain,
            &full_evidence(3),
        )
        .unwrap();
        assert_eq!(ra.state(), RecoveryState::Verified);
    }

    #[test]
    fn production_recovery_authority_validates_bindings() {
        assert_eq!(
            RecoveryAuthority::new(0, 3, authority(), &good_pair()).unwrap_err(),
            Error::Invalid
        );
        assert_eq!(
            RecoveryAuthority::new(7, 0, authority(), &good_pair()).unwrap_err(),
            Error::Invalid
        );
        assert_eq!(
            RecoveryAuthority::new(
                7,
                3,
                Identity {
                    id: 0,
                    generation: 1
                },
                &good_pair()
            )
            .unwrap_err(),
            Error::Invalid
        );
        // Initial degraded accumulators are initial and bound to the boot epoch.
        let ra = RecoveryAuthority::new(7, 3, authority(), &good_pair()).unwrap();
        for cpu in 0..ACCUMULATOR_COUNT as u32 {
            let p = ra.degraded_proof(cpu).unwrap();
            assert!(p.is_initial());
            assert_eq!(p.boot_epoch, 7);
            assert_eq!(p.cpu_id, cpu);
        }
    }
}
