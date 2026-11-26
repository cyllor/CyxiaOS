//! V0.19.9 EL1 AuthContext FILE_AUTH ADMIT v3 / COMPLETE v1 contract layer.
//!
//! Byte-level contracts and pure state rules from the V0.19.9 baseline
//! (internal 0x50, FILE_AUTH op1 ADMIT v3 / op2 COMPLETE v1; there is NO
//! op3 PREPARE). This module is the *contract layer only*: it strictly
//! decodes/encodes the frozen frames, computes the binding digests and
//! models the idempotency, three-step linearization and terminal-state
//! rules. Native EL1 AuthContext wiring, the authoritative object/ACL/cap
//! version cross-checks, ancestor-revocation lookup, resource/completion
//! credit accounting and real redo/device completion evidence are a LATER
//! release gate and are deliberately NOT faked here. Nothing in this
//! module authorizes a file operation by itself; the file-service TCB
//! owns semantic truth of frozen data and completion evidence.
//!
//! Error mapping at the native boundary (baseline errno table): schema
//! rejections (magic/version/length/reserved, old 48B ADMIT frames)
//! surface as [`Error::Invalid`] here and map to E_SCHEMA (-3);
//! [`Error::Conflict`] maps to E_CONFLICT (-5), [`Error::Stale`] to
//! E_STALE (-4) and [`Error::Unauthorized`] to E_AUTH (-1). Endpoint
//! qualification (role12, protected recovery successor) is supplied by
//! the verified EL1 caller, never self-reported in a frame body.
//!
//! UNKNOWN reading: a recorded *terminal* completion never regresses and
//! only an identical (state, evidence digest) repeat is idempotent; while
//! the admission is UNKNOWN, repeated UNKNOWN reports only reconcile and
//! evidence may be updated multiple times, never releasing the gate,
//! reference or in-flight credit.
use super::Error;
use super::file_service_v4;

pub const ADMIT_REQUEST_MAGIC: u32 = 0x4359_5646;
pub const ADMIT_REQUEST_VERSION: u16 = 3;
pub const ADMIT_REQUEST_BYTES: usize = 128;
pub const ADMIT_REPLY_MAGIC: u32 = 0x4359_5652;
pub const ADMIT_REPLY_VERSION: u16 = 3;
pub const ADMIT_REPLY_BYTES: usize = 48;
pub const COMPLETE_REQUEST_MAGIC: u32 = 0x4359_4643;
pub const COMPLETE_REQUEST_VERSION: u16 = 1;
pub const COMPLETE_REQUEST_BYTES: usize = 56;
pub const COMPLETE_REPLY_BYTES: usize = 8;

/// FILE_AUTH static endpoint ops. There is no op3 PREPARE: PREPARED state
/// exists only inside the trusted file service, never as an EL1 op.
pub const FILE_AUTH_ADMIT: u16 = 1;
pub const FILE_AUTH_COMPLETE: u16 = 2;

/// role12 FILE_SERVICE is the only ADMIT caller; COMPLETE additionally
/// allows a protected recovery successor verified by EL1 takeover records.
pub const FILE_SERVICE_ROLE: u64 = 12;

/// Domain separator of the ADMIT binding digest (ASCII, exact bytes).
pub const OPERATION_DOMAIN: &[u8] = b"CYX/FILE-ADMIT/v3";
/// auth_context_id offset inside a FileServiceRequest v4 user frame; the
/// binding digest hashes that 8-byte field as zero.
pub const USER_FRAME_AUTH_CONTEXT_OFFSET: usize = 24;

/// Baseline errno values carried by COMPLETE replies (native boundary).
pub const E_AUTH: i32 = -1;
pub const E_SCHEMA: i32 = -3;
pub const E_STALE: i32 = -4;
pub const E_CONFLICT: i32 = -5;

fn le16(b: &[u8], at: usize) -> Result<u16, Error> {
    let s = b.get(at..at + 2).ok_or(Error::Invalid)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}
fn le32(b: &[u8], at: usize) -> Result<u32, Error> {
    let s = b.get(at..at + 4).ok_or(Error::Invalid)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn le64(b: &[u8], at: usize) -> Result<u64, Error> {
    let s = b.get(at..at + 8).ok_or(Error::Invalid)?;
    Ok(u64::from_le_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}
fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Deny = 0,
    Admitted = 1,
    Revoked = 2,
    Stale = 3,
    Retry = 4,
}
impl Verdict {
    pub const fn from_u16(v: u16) -> Option<Self> {
        match v {
            0 => Some(Self::Deny),
            1 => Some(Self::Admitted),
            2 => Some(Self::Revoked),
            3 => Some(Self::Stale),
            4 => Some(Self::Retry),
            _ => None,
        }
    }
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
    /// Only ADMITTED atomically registers an in-flight reference;
    /// DENY/REVOKED/STALE/RETRY register nothing.
    pub const fn registers_inflight(self) -> bool {
        matches!(self, Self::Admitted)
    }
    /// No irreversible user-visible effect may exist before ADMITTED.
    pub const fn irreversible_effects_allowed(self) -> bool {
        matches!(self, Self::Admitted)
    }
}

/// COMPLETE terminal_state wire values (baseline table). UNKNOWN is a
/// non-terminal knowledge state, not "not executed".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalState {
    Done = 1,
    Partial = 2,
    Unknown = 3,
    NoEffect = 4,
}
impl TerminalState {
    pub const fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::Done),
            2 => Some(Self::Partial),
            3 => Some(Self::Unknown),
            4 => Some(Self::NoEffect),
            _ => None,
        }
    }
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Unknown)
    }
    /// Persistent receipt status projection: DONE→3, PARTIAL→4,
    /// NO_EFFECT→6 CANCELLED, UNKNOWN→5 (or keep 2 BOUND when the
    /// persistent record cannot be written). PARTIAL never maps to
    /// NO_EFFECT and an unproven effect never maps to CANCELLED.
    pub const fn receipt_status(self, persistent_writable: bool) -> u16 {
        match self {
            Self::Done => 3,
            Self::Partial => 4,
            Self::NoEffect => 6,
            Self::Unknown => {
                if persistent_writable {
                    5
                } else {
                    2
                }
            }
        }
    }
}

/// ADMIT v3 request, 128B little-endian. The frozen proposal produced by
/// trusted role12 in step ①: target/ACL generations, object-local
/// prepared_version and data digest. Freezing is NOT admission and has
/// no user-visible side effects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmitRequestV3 {
    pub auth_context_id: u64,
    pub target_id: u64,
    pub target_generation: u64,
    pub required_rights: u64,
    pub request_seq: u64,
    pub prepared_version: u64,
    pub acl_generation: u64,
    pub frozen_data_digest: [u8; 32],
    pub operation_digest: [u8; 32],
}
impl AdmitRequestV3 {
    /// Exact-length decode. Any other length — including the old 48B
    /// ADMIT frame — is a schema rejection (native E_SCHEMA).
    pub fn decode(frame: &[u8]) -> Result<Self, Error> {
        if frame.len() != ADMIT_REQUEST_BYTES
            || le32(frame, 0)? != ADMIT_REQUEST_MAGIC
            || le16(frame, 4)? != ADMIT_REQUEST_VERSION
            || le16(frame, 6)? != ADMIT_REQUEST_BYTES as u16
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            auth_context_id: le64(frame, 8)?,
            target_id: le64(frame, 16)?,
            target_generation: le64(frame, 24)?,
            required_rights: le64(frame, 32)?,
            request_seq: le64(frame, 40)?,
            prepared_version: le64(frame, 48)?,
            acl_generation: le64(frame, 56)?,
            frozen_data_digest: frame[64..96].try_into().map_err(|_| Error::Invalid)?,
            operation_digest: frame[96..128].try_into().map_err(|_| Error::Invalid)?,
        })
    }
    pub fn encode(&self, out: &mut [u8; ADMIT_REQUEST_BYTES]) {
        out.fill(0);
        put32(out, 0, ADMIT_REQUEST_MAGIC);
        put16(out, 4, ADMIT_REQUEST_VERSION);
        put16(out, 6, ADMIT_REQUEST_BYTES as u16);
        put64(out, 8, self.auth_context_id);
        put64(out, 16, self.target_id);
        put64(out, 24, self.target_generation);
        put64(out, 32, self.required_rights);
        put64(out, 40, self.request_seq);
        put64(out, 48, self.prepared_version);
        put64(out, 56, self.acl_generation);
        out[64..96].copy_from_slice(&self.frozen_data_digest);
        out[96..128].copy_from_slice(&self.operation_digest);
    }
}

/// ADMIT v3 reply, 48B. When verdict != ADMITTED the admission_id and
/// accepted_local_ns fields are zero on the wire; an ADMITTED reply must
/// carry a real (non-zero) admission_id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmitReplyV3 {
    pub auth_context_id: u64,
    pub verdict: Verdict,
    pub deny_generation: u64,
    pub admission_id: u64,
    pub accepted_local_ns: u64,
}
impl AdmitReplyV3 {
    pub fn decode(frame: &[u8]) -> Result<Self, Error> {
        if frame.len() != ADMIT_REPLY_BYTES
            || le32(frame, 0)? != ADMIT_REPLY_MAGIC
            || le16(frame, 4)? != ADMIT_REPLY_VERSION
            || le16(frame, 6)? != ADMIT_REPLY_BYTES as u16
            || frame[18..24].iter().any(|v| *v != 0)
        {
            return Err(Error::Invalid);
        }
        let verdict = Verdict::from_u16(le16(frame, 16)?).ok_or(Error::Invalid)?;
        let admission_id = le64(frame, 32)?;
        let accepted_local_ns = le64(frame, 40)?;
        if verdict != Verdict::Admitted {
            if admission_id != 0 || accepted_local_ns != 0 {
                return Err(Error::Invalid);
            }
        } else if admission_id == 0 {
            return Err(Error::Invalid);
        }
        Ok(Self {
            auth_context_id: le64(frame, 8)?,
            verdict,
            deny_generation: le64(frame, 24)?,
            admission_id,
            accepted_local_ns,
        })
    }
    pub fn encode(&self, out: &mut [u8; ADMIT_REPLY_BYTES]) -> Result<(), Error> {
        if self.verdict != Verdict::Admitted {
            if self.admission_id != 0 || self.accepted_local_ns != 0 {
                return Err(Error::Invalid);
            }
        } else if self.admission_id == 0 {
            return Err(Error::Invalid);
        }
        out.fill(0);
        put32(out, 0, ADMIT_REPLY_MAGIC);
        put16(out, 4, ADMIT_REPLY_VERSION);
        put16(out, 6, ADMIT_REPLY_BYTES as u16);
        put64(out, 8, self.auth_context_id);
        put16(out, 16, self.verdict.as_u16());
        put64(out, 24, self.deny_generation);
        put64(out, 32, self.admission_id);
        put64(out, 40, self.accepted_local_ns);
        Ok(())
    }
}

/// COMPLETE v1 request, 56B. Binds a real admission; terminal claims
/// require a non-zero authoritative evidence digest — without evidence
/// the admission only keeps UNKNOWN. Self-reported service claims never
/// substitute for redo/device completion proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompleteRequestV1 {
    pub admission_id: u64,
    pub terminal_state: TerminalState,
    pub evidence_digest: [u8; 32],
}
impl CompleteRequestV1 {
    pub fn decode(frame: &[u8]) -> Result<Self, Error> {
        if frame.len() != COMPLETE_REQUEST_BYTES
            || le32(frame, 0)? != COMPLETE_REQUEST_MAGIC
            || le16(frame, 4)? != COMPLETE_REQUEST_VERSION
            || le16(frame, 6)? != COMPLETE_REQUEST_BYTES as u16
            || frame[18..24].iter().any(|v| *v != 0)
        {
            return Err(Error::Invalid);
        }
        let admission_id = le64(frame, 8)?;
        let terminal_state = TerminalState::from_u16(le16(frame, 16)?).ok_or(Error::Invalid)?;
        let evidence_digest: [u8; 32] = frame[24..56].try_into().map_err(|_| Error::Invalid)?;
        if admission_id == 0 || (terminal_state.is_terminal() && evidence_digest == [0; 32]) {
            return Err(Error::Invalid);
        }
        Ok(Self {
            admission_id,
            terminal_state,
            evidence_digest,
        })
    }
    pub fn encode(&self, out: &mut [u8; COMPLETE_REQUEST_BYTES]) -> Result<(), Error> {
        if self.admission_id == 0
            || (self.terminal_state.is_terminal() && self.evidence_digest == [0; 32])
        {
            return Err(Error::Invalid);
        }
        out.fill(0);
        put32(out, 0, COMPLETE_REQUEST_MAGIC);
        put16(out, 4, COMPLETE_REQUEST_VERSION);
        put16(out, 6, COMPLETE_REQUEST_BYTES as u16);
        put64(out, 8, self.admission_id);
        put16(out, 16, self.terminal_state.as_u16());
        out[24..56].copy_from_slice(&self.evidence_digest);
        Ok(())
    }
}

/// COMPLETE v1 reply, 8B: result:i32 + reserved:u32=0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompleteReplyV1 {
    pub result: i32,
}
impl CompleteReplyV1 {
    pub fn decode(frame: &[u8]) -> Result<Self, Error> {
        if frame.len() != COMPLETE_REPLY_BYTES || le32(frame, 4)? != 0 {
            return Err(Error::Invalid);
        }
        Ok(Self {
            result: le32(frame, 0)? as i32,
        })
    }
    pub fn encode(&self, out: &mut [u8; COMPLETE_REPLY_BYTES]) {
        put32(out, 0, self.result as u32);
        put32(out, 4, 0);
    }
}

/// 0x50 FILE_AUTH op discrimination by subprotocol magic/version/len on
/// the copied-in frame, never by a self-reported op field. Old 48B ADMIT
/// frames and any unknown schema are rejected (native E_SCHEMA).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileAuthOp {
    AdmitV3,
    CompleteV1,
}
pub fn discriminate_op(frame: &[u8]) -> Result<FileAuthOp, Error> {
    if frame.len() < 8 {
        return Err(Error::Invalid);
    }
    let magic = le32(frame, 0)?;
    let ver = le16(frame, 4)?;
    let len = le16(frame, 6)?;
    if magic == ADMIT_REQUEST_MAGIC
        && ver == ADMIT_REQUEST_VERSION
        && len == ADMIT_REQUEST_BYTES as u16
        && frame.len() == ADMIT_REQUEST_BYTES
    {
        return Ok(FileAuthOp::AdmitV3);
    }
    if magic == COMPLETE_REQUEST_MAGIC
        && ver == COMPLETE_REQUEST_VERSION
        && len == COMPLETE_REQUEST_BYTES as u16
        && frame.len() == COMPLETE_REQUEST_BYTES
    {
        return Ok(FileAuthOp::CompleteV1);
    }
    Err(Error::Invalid)
}

/// ADMIT is role12-only. The caller role is an EL1-verified fact, not a
/// frame field; endpoint qualification is never gained by body self-report.
pub const fn admit_role_gate(caller_role: u64) -> Result<(), Error> {
    if caller_role != FILE_SERVICE_ROLE {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
/// COMPLETE allows role12 or a protected recovery successor. The successor
/// flag must come from EL1's verified shutdown/takeover record. A recovery
/// successor may only reconcile old obligations — it can never issue new
/// work through an old admission (ADMIT stays role12-only above).
pub const fn complete_role_gate(
    caller_role: u64,
    protected_recovery_successor: bool,
) -> Result<(), Error> {
    if caller_role != FILE_SERVICE_ROLE && !protected_recovery_successor {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

/// SHA256 of the actual frozen data / FSYNC snapshot bytes; all-zero when
/// there is no data. This hashes only the bytes presented — the semantic
/// truth of the snapshot belongs to the file-service TCB.
pub fn frozen_data_digest(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    if data.is_empty() {
        return [0; 32];
    }
    sha2::Sha256::digest(data).into()
}

/// operation_digest = SHA256( ASCII "CYX/FILE-ADMIT/v3" || LE64(boot_epoch)
/// || LE64(auth_context_id) || SHA256(original full user request frame with
/// its auth_context_id field zeroed) || request[16..96] ).
///
/// The original frame must be a FileServiceRequest v4 frame; its 8-byte
/// auth_context_id field at offset 24 is hashed as zero regardless of the
/// bytes presented. The proposal window is the canonical encoding of the
/// decoded ADMIT request bytes 16..96 (six u64 fields + frozen data digest).
/// EL1 recomputes this binding from the protected original AuthContext and
/// compares against its authoritative object/ACL versions — that native
/// cross-check is a later gate, not performed here.
pub fn operation_digest(
    boot_epoch: u64,
    original_user_frame: &[u8],
    request: &AdmitRequestV3,
) -> Result<[u8; 32], Error> {
    use sha2::{Digest, Sha256};
    let header = file_service_v4::REQUEST_HEADER;
    if original_user_frame.len() < header
        || le32(original_user_frame, 0)? != file_service_v4::REQUEST_MAGIC
        || le16(original_user_frame, 4)? != file_service_v4::REQUEST_VERSION
        || le16(original_user_frame, 6)? != header as u16
    {
        return Err(Error::Invalid);
    }
    let payload_len =
        usize::try_from(le32(original_user_frame, 12)?).map_err(|_| Error::Invalid)?;
    if header.checked_add(payload_len) != Some(original_user_frame.len()) {
        return Err(Error::Invalid);
    }
    let at = USER_FRAME_AUTH_CONTEXT_OFFSET;
    let mut inner = Sha256::new();
    inner.update(&original_user_frame[..at]);
    inner.update([0u8; 8]);
    inner.update(&original_user_frame[at + 8..]);
    let inner_digest: [u8; 32] = inner.finalize().into();
    let mut proposal = [0u8; ADMIT_REQUEST_BYTES];
    request.encode(&mut proposal);
    let mut outer = Sha256::new();
    outer.update(OPERATION_DOMAIN);
    outer.update(boot_epoch.to_le_bytes());
    outer.update(request.auth_context_id.to_le_bytes());
    outer.update(inner_digest);
    outer.update(&proposal[16..96]);
    Ok(outer.finalize().into())
}

/// Object-local prepared_version advance: strictly monotonic, never wraps.
/// None at u64::MAX means the object can never prepare another version.
pub const fn next_prepared_version(current: u64) -> Option<u64> {
    current.checked_add(1)
}

/// A registered step-② admission: EL1 atomically recorded the admission_id,
/// the frozen binding digest and the in-flight reference under the exact
/// (AuthContext, request_seq) key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisteredAdmission {
    pub auth_context_id: u64,
    pub request_seq: u64,
    pub operation_digest: [u8; 32],
    pub admission_id: u64,
    pub accepted_local_ns: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmitDecision {
    /// No prior registration under this key: EL1 may run the full step-②
    /// authority checks and atomically register a fresh admission.
    Fresh,
    /// Same key and same proposal digest: return the original ADMIT.
    Replay {
        admission_id: u64,
        accepted_local_ns: u64,
    },
}

/// ADMIT idempotency/conflict rule: same AuthContext + request_seq +
/// proposal digest returns the original ADMIT; a different digest under
/// the same key is E_CONFLICT. STALE/RETRY/REVOKED outcomes register no
/// in-flight reference (see [`Verdict::registers_inflight`]). The prior
/// record must have been looked up by the exact key; a mismatched record
/// is a caller bug. Zero key components cannot identify a request.
pub fn admit_idempotency(
    request: &AdmitRequestV3,
    prior: Option<&RegisteredAdmission>,
) -> Result<AdmitDecision, Error> {
    if request.auth_context_id == 0 || request.request_seq == 0 {
        return Err(Error::Invalid);
    }
    let Some(p) = prior else {
        return Ok(AdmitDecision::Fresh);
    };
    if p.auth_context_id != request.auth_context_id
        || p.request_seq != request.request_seq
        || p.admission_id == 0
    {
        return Err(Error::Invalid);
    }
    if p.operation_digest == request.operation_digest {
        Ok(AdmitDecision::Replay {
            admission_id: p.admission_id,
            accepted_local_ns: p.accepted_local_ns,
        })
    } else {
        Err(Error::Conflict)
    }
}

/// Step-③ outcome for an ALREADY ADMITTED proposal. The service re-verifies
/// its local prepared_version against the frozen object version admitted by
/// EL1 and executes per the original admission. A frozen local version is
/// NOT an admission: callers must hold a real ADMITTED verdict and a
/// registered admission before any irreversible user effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepThree {
    /// Local version matches the frozen admission: execute per admission.
    Execute,
    /// Mismatch with provable zero request effect: COMPLETE NO_EFFECT.
    CompleteNoEffect,
    /// Mismatch without proof: keep UNKNOWN, retaining gate/reference.
    KeepUnknown,
}
pub const fn reverify_execution(
    local_prepared_version: u64,
    frozen_prepared_version: u64,
    provable_no_effect: bool,
) -> StepThree {
    if local_prepared_version == frozen_prepared_version {
        StepThree::Execute
    } else if provable_no_effect {
        StepThree::CompleteNoEffect
    } else {
        StepThree::KeepUnknown
    }
}

/// Protected completion state of one admission. UNKNOWN is non-terminal:
/// it retains the gate, the reference and the in-flight credit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Completion {
    /// ADMITTED and in-flight; no completion report recorded yet.
    InFlight,
    /// Non-terminal UNKNOWN with the latest reconciled evidence digest.
    Unknown { evidence_digest: [u8; 32] },
    /// Irreversible terminal publication (Done/Partial/NoEffect only).
    Terminal {
        state: TerminalState,
        evidence_digest: [u8; 32],
    },
}
impl Completion {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Terminal { .. })
    }
    /// Only a verified terminal publication may release the reference;
    /// UNKNOWN and in-flight admissions never release. For durable
    /// operations the trusted file service must FIRST persist the receipt
    /// terminal state with real transaction evidence, then EL1 publishes
    /// object/ACL generations and releases — that ordering is native.
    pub const fn releases_reference(self) -> bool {
        self.is_terminal()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompleteOutcome {
    /// Same admission, same terminal state, same evidence digest: return
    /// the original result without any state change.
    Idempotent,
    /// Repeated or evidence-updated UNKNOWN: reconciliation only; gate,
    /// reference and in-flight credit are retained.
    UnknownRetained { evidence_digest: [u8; 32] },
    /// Advance to a terminal publication. Durable ordering obligation:
    /// receipt terminal state + real transaction evidence persisted first.
    Terminal {
        state: TerminalState,
        evidence_digest: [u8; 32],
    },
}

/// COMPLETE state machine: ADMITTED→UNKNOWN (evidence may be updated
/// multiple times)→DONE/PARTIAL/NO_EFFECT, or ADMITTED directly to a
/// terminal state. Any terminal state is irreversible: only an identical
/// (state, evidence digest) repeat is idempotent, anything else is
/// E_CONFLICT. A terminal claim without evidence is rejected so the
/// admission keeps UNKNOWN; an unproven effect never maps to CANCELLED.
///
/// The caller must already have bound the REAL admission, its binding
/// operation digest and authoritative evidence (native gate); this pure
/// function models only the state rules and never trusts self-report.
pub fn complete_transition(
    current: Completion,
    report: &CompleteRequestV1,
) -> Result<CompleteOutcome, Error> {
    if report.admission_id == 0 {
        return Err(Error::Invalid);
    }
    if !report.terminal_state.is_terminal() {
        // UNKNOWN: reconcile or update evidence; never regress a terminal
        // publication and never release.
        if current.is_terminal() {
            return Err(Error::Conflict);
        }
        return Ok(CompleteOutcome::UnknownRetained {
            evidence_digest: report.evidence_digest,
        });
    }
    if report.evidence_digest == [0; 32] {
        return Err(Error::Invalid);
    }
    match current {
        Completion::Terminal {
            state,
            evidence_digest,
        } => {
            if state == report.terminal_state && evidence_digest == report.evidence_digest {
                Ok(CompleteOutcome::Idempotent)
            } else {
                Err(Error::Conflict)
            }
        }
        Completion::InFlight | Completion::Unknown { .. } => Ok(CompleteOutcome::Terminal {
            state: report.terminal_state,
            evidence_digest: report.evidence_digest,
        }),
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use sha2::{Digest, Sha256};
    use std::vec;
    use std::vec::Vec;

    fn request() -> AdmitRequestV3 {
        AdmitRequestV3 {
            auth_context_id: 0x1122_3344_5566_7788,
            target_id: 42,
            target_generation: 7,
            required_rights: 0b1011,
            request_seq: 9,
            prepared_version: 3,
            acl_generation: 5,
            frozen_data_digest: [0xa5; 32],
            operation_digest: [0x5a; 32],
        }
    }
    fn admit_frame() -> [u8; ADMIT_REQUEST_BYTES] {
        let mut b = [0u8; ADMIT_REQUEST_BYTES];
        request().encode(&mut b);
        b
    }
    fn reply(verdict: Verdict) -> AdmitReplyV3 {
        AdmitReplyV3 {
            auth_context_id: 0x1122_3344_5566_7788,
            verdict,
            deny_generation: 12,
            admission_id: if verdict == Verdict::Admitted { 77 } else { 0 },
            accepted_local_ns: if verdict == Verdict::Admitted {
                1_000
            } else {
                0
            },
        }
    }
    fn complete(state: TerminalState, evidence: [u8; 32]) -> CompleteRequestV1 {
        CompleteRequestV1 {
            admission_id: 77,
            terminal_state: state,
            evidence_digest: evidence,
        }
    }
    /// Minimal valid FileServiceRequest v4 user frame (op6, 4B payload).
    fn user_frame() -> Vec<u8> {
        let mut b = vec![0u8; file_service_v4::REQUEST_HEADER + 4];
        b[0..4].copy_from_slice(&file_service_v4::REQUEST_MAGIC.to_le_bytes());
        b[4..6].copy_from_slice(&file_service_v4::REQUEST_VERSION.to_le_bytes());
        b[6..8].copy_from_slice(&(file_service_v4::REQUEST_HEADER as u16).to_le_bytes());
        b[8..10].copy_from_slice(&6u16.to_le_bytes());
        b[12..16].copy_from_slice(&4u32.to_le_bytes());
        b[16..24].copy_from_slice(&4u64.to_le_bytes());
        b
    }

    #[test]
    fn admit_v3_golden_layout_and_round_trip() {
        let b = admit_frame();
        assert_eq!(le32(&b, 0).unwrap(), 0x4359_5646);
        assert_eq!(le16(&b, 4).unwrap(), 3);
        assert_eq!(le16(&b, 6).unwrap(), 128);
        assert_eq!(le64(&b, 8).unwrap(), 0x1122_3344_5566_7788);
        assert_eq!(le64(&b, 16).unwrap(), 42);
        assert_eq!(le64(&b, 24).unwrap(), 7);
        assert_eq!(le64(&b, 32).unwrap(), 0b1011);
        assert_eq!(le64(&b, 40).unwrap(), 9);
        assert_eq!(le64(&b, 48).unwrap(), 3);
        assert_eq!(le64(&b, 56).unwrap(), 5);
        assert_eq!(&b[64..96], &[0xa5; 32]);
        assert_eq!(&b[96..128], &[0x5a; 32]);
        assert_eq!(AdmitRequestV3::decode(&b).unwrap(), request());

        let mut r = [0u8; ADMIT_REPLY_BYTES];
        reply(Verdict::Admitted).encode(&mut r).unwrap();
        assert_eq!(le32(&r, 0).unwrap(), 0x4359_5652);
        assert_eq!(le16(&r, 4).unwrap(), 3);
        assert_eq!(le16(&r, 6).unwrap(), 48);
        assert_eq!(le16(&r, 16).unwrap(), 1);
        assert_eq!(&r[18..24], &[0; 6]);
        assert_eq!(le64(&r, 24).unwrap(), 12);
        assert_eq!(le64(&r, 32).unwrap(), 77);
        assert_eq!(le64(&r, 40).unwrap(), 1_000);
        assert_eq!(AdmitReplyV3::decode(&r).unwrap(), reply(Verdict::Admitted));

        let mut c = [0u8; COMPLETE_REQUEST_BYTES];
        complete(TerminalState::Done, [0x3c; 32])
            .encode(&mut c)
            .unwrap();
        assert_eq!(le32(&c, 0).unwrap(), 0x4359_4643);
        assert_eq!(le16(&c, 4).unwrap(), 1);
        assert_eq!(le16(&c, 6).unwrap(), 56);
        assert_eq!(le64(&c, 8).unwrap(), 77);
        assert_eq!(le16(&c, 16).unwrap(), 1);
        assert_eq!(&c[18..24], &[0; 6]);
        assert_eq!(&c[24..56], &[0x3c; 32]);
        assert_eq!(
            CompleteRequestV1::decode(&c).unwrap(),
            complete(TerminalState::Done, [0x3c; 32])
        );

        let mut p = [0u8; COMPLETE_REPLY_BYTES];
        CompleteReplyV1 { result: E_CONFLICT }.encode(&mut p);
        assert_eq!(&p[4..8], &[0; 4]);
        assert_eq!(CompleteReplyV1::decode(&p).unwrap().result, -5);
        CompleteReplyV1 { result: 0 }.encode(&mut p);
        assert_eq!(CompleteReplyV1::decode(&p).unwrap().result, 0);
    }

    #[test]
    fn admit_v3_rejects_wrong_magic_version_length_and_tails() {
        let good = admit_frame();
        assert!(AdmitRequestV3::decode(&good).is_ok());
        let mut b = good;
        b[0] ^= 1;
        assert_eq!(AdmitRequestV3::decode(&b), Err(Error::Invalid));
        for v in [0u16, 2, 4] {
            let mut b = good;
            put16(&mut b, 4, v);
            assert_eq!(AdmitRequestV3::decode(&b), Err(Error::Invalid));
        }
        for len in [0u16, 48, 127, 129] {
            let mut b = good;
            put16(&mut b, 6, len);
            assert_eq!(AdmitRequestV3::decode(&b), Err(Error::Invalid));
        }
        assert!(AdmitRequestV3::decode(&good[..127]).is_err());
        assert!(AdmitRequestV3::decode(&good[..0]).is_err());
        let mut trailing = vec![0u8; 129];
        trailing[..128].copy_from_slice(&good);
        assert!(AdmitRequestV3::decode(&trailing).is_err());
        // Reply schema gate.
        let mut r = [0u8; ADMIT_REPLY_BYTES];
        reply(Verdict::Admitted).encode(&mut r).unwrap();
        let mut b = r;
        b[0] ^= 1;
        assert!(AdmitReplyV3::decode(&b).is_err());
        let mut b = r;
        put16(&mut b, 4, 2);
        assert!(AdmitReplyV3::decode(&b).is_err());
        let mut b = r;
        put16(&mut b, 6, 47);
        assert!(AdmitReplyV3::decode(&b).is_err());
        assert!(AdmitReplyV3::decode(&r[..47]).is_err());
        let mut b = r;
        b[18] = 1;
        assert!(AdmitReplyV3::decode(&b).is_err());
        let mut b = r;
        put16(&mut b, 16, 5);
        assert!(AdmitReplyV3::decode(&b).is_err());
    }

    #[test]
    fn old_48b_admit_frame_is_schema_rejected_and_no_prepare_op() {
        // Old 48B ADMIT shape: same magic family, len=48. Must be E_SCHEMA
        // (Error::Invalid at this layer), never reinterpreted as v3.
        let mut old = [0u8; 48];
        put32(&mut old, 0, ADMIT_REQUEST_MAGIC);
        put16(&mut old, 4, 2);
        put16(&mut old, 6, 48);
        assert_eq!(AdmitRequestV3::decode(&old), Err(Error::Invalid));
        assert_eq!(discriminate_op(&old), Err(Error::Invalid));
        put16(&mut old, 4, 3);
        assert_eq!(AdmitRequestV3::decode(&old), Err(Error::Invalid));
        assert_eq!(discriminate_op(&old), Err(Error::Invalid));
        assert_eq!(discriminate_op(&admit_frame()), Ok(FileAuthOp::AdmitV3));
        let mut c = [0u8; COMPLETE_REQUEST_BYTES];
        complete(TerminalState::Unknown, [0; 32])
            .encode(&mut c)
            .unwrap();
        assert_eq!(discriminate_op(&c), Ok(FileAuthOp::CompleteV1));
        let mut unknown = admit_frame();
        put32(&mut unknown, 0, 0x4359_0000);
        assert_eq!(discriminate_op(&unknown), Err(Error::Invalid));
        assert_eq!(discriminate_op(&[0u8; 7]), Err(Error::Invalid));
        // Static op table: only ADMIT=1 and COMPLETE=2 exist; no PREPARE.
        assert_eq!((FILE_AUTH_ADMIT, FILE_AUTH_COMPLETE), (1, 2));
    }

    #[test]
    fn non_admitted_reply_zeroes_tail_and_admitted_needs_real_id() {
        for verdict in [
            Verdict::Deny,
            Verdict::Revoked,
            Verdict::Stale,
            Verdict::Retry,
        ] {
            assert!(!verdict.registers_inflight());
            assert!(!verdict.irreversible_effects_allowed());
            let mut r = reply(verdict);
            let mut b = [0u8; ADMIT_REPLY_BYTES];
            r.encode(&mut b).unwrap();
            assert_eq!(le64(&b, 32).unwrap(), 0);
            assert_eq!(le64(&b, 40).unwrap(), 0);
            assert_eq!(AdmitReplyV3::decode(&b).unwrap().verdict, verdict);
            // deny_generation remains meaningful on non-ADMITTED replies.
            assert_eq!(le64(&b, 24).unwrap(), 12);
            // A non-zero tail on the wire is rejected, not normalized.
            let mut bad = b;
            put64(&mut bad, 32, 1);
            assert!(AdmitReplyV3::decode(&bad).is_err());
            let mut bad = b;
            put64(&mut bad, 40, 1);
            assert!(AdmitReplyV3::decode(&bad).is_err());
            // Encoding an inconsistent struct fails instead of silently zeroing.
            r.admission_id = 1;
            assert!(r.encode(&mut b).is_err());
            r.admission_id = 0;
            r.accepted_local_ns = 1;
            assert!(r.encode(&mut b).is_err());
        }
        assert!(Verdict::Admitted.registers_inflight());
        assert!(Verdict::Admitted.irreversible_effects_allowed());
        let mut b = [0u8; ADMIT_REPLY_BYTES];
        assert!(reply(Verdict::Admitted).encode(&mut b).is_ok());
        let mut zero_id = reply(Verdict::Admitted);
        zero_id.admission_id = 0;
        assert!(zero_id.encode(&mut b).is_err());
        put64(&mut b, 32, 0);
        // Rebuild a valid ADMITTED wire then zero the id: decode rejects.
        reply(Verdict::Admitted).encode(&mut b).unwrap();
        put64(&mut b, 32, 0);
        assert!(AdmitReplyV3::decode(&b).is_err());
        for v in 0u16..=4 {
            assert_eq!(Verdict::from_u16(v).unwrap().as_u16(), v);
        }
        assert!(Verdict::from_u16(5).is_none());
    }

    #[test]
    fn operation_digest_matches_baseline_formula_vector() {
        let boot_epoch = 0x0102_0304_0506_0708u64;
        let mut original = user_frame();
        // Even a non-zero auth_context field must be hashed as zero.
        original[24..32].copy_from_slice(&0xdead_beefu64.to_le_bytes());
        let req = request();
        let got = operation_digest(boot_epoch, &original, &req).unwrap();

        let mut zeroed = original.clone();
        zeroed[24..32].fill(0);
        let inner: [u8; 32] = Sha256::digest(&zeroed).into();
        let frame = admit_frame();
        let mut expected = Sha256::new();
        expected.update(b"CYX/FILE-ADMIT/v3");
        expected.update(boot_epoch.to_le_bytes());
        expected.update(req.auth_context_id.to_le_bytes());
        expected.update(inner);
        expected.update(&frame[16..96]);
        let expected: [u8; 32] = expected.finalize().into();
        assert_eq!(got, expected);

        // The zeroing is independent of the presented field bytes.
        let mut clean = user_frame();
        clean[24..32].fill(0);
        assert_eq!(operation_digest(boot_epoch, &clean, &req).unwrap(), got);
        // Every binding input changes the digest.
        assert_ne!(
            operation_digest(boot_epoch + 1, &original, &req).unwrap(),
            got
        );
        let mut other_ctx = req;
        other_ctx.auth_context_id += 1;
        assert_ne!(
            operation_digest(boot_epoch, &original, &other_ctx).unwrap(),
            got
        );
        let mut other_seq = req;
        other_seq.request_seq += 1;
        assert_ne!(
            operation_digest(boot_epoch, &original, &other_seq).unwrap(),
            got
        );
        let mut other_data = req;
        other_data.frozen_data_digest[0] ^= 1;
        assert_ne!(
            operation_digest(boot_epoch, &original, &other_data).unwrap(),
            got
        );
        let mut other_frame = original.clone();
        other_frame[32] ^= 1;
        assert_ne!(
            operation_digest(boot_epoch, &other_frame, &req).unwrap(),
            got
        );
        // Malformed original frames are rejected, not hashed blindly.
        assert!(operation_digest(boot_epoch, &original[..31], &req).is_err());
        let mut bad = original.clone();
        bad[0] ^= 1;
        assert!(operation_digest(boot_epoch, &bad, &req).is_err());
        let mut bad = original.clone();
        put16(&mut bad, 4, 3);
        assert!(operation_digest(boot_epoch, &bad, &req).is_err());
        let mut bad = original.clone();
        put32(&mut bad, 12, 5);
        assert!(operation_digest(boot_epoch, &bad, &req).is_err());
        let mut trailing = original.clone();
        trailing.push(0);
        assert!(operation_digest(boot_epoch, &trailing, &req).is_err());
    }

    #[test]
    fn frozen_data_digest_zero_when_empty_and_sha256_otherwise() {
        assert_eq!(frozen_data_digest(&[]), [0; 32]);
        let data = b"frozen snapshot bytes";
        let expected: [u8; 32] = Sha256::digest(data).into();
        assert_eq!(frozen_data_digest(data), expected);
        assert_ne!(frozen_data_digest(data), [0; 32]);
    }

    #[test]
    fn idempotency_and_conflict_matrix() {
        // The registered binding digest is the recomputed operation_digest;
        // EL1's native recomputation feeds that value into this contract.
        let mut req = request();
        req.operation_digest = operation_digest(7, &user_frame(), &req).unwrap();
        let prior = RegisteredAdmission {
            auth_context_id: req.auth_context_id,
            request_seq: req.request_seq,
            operation_digest: req.operation_digest,
            admission_id: 77,
            accepted_local_ns: 1_000,
        };
        // No prior registration: fresh admission path.
        assert_eq!(admit_idempotency(&req, None), Ok(AdmitDecision::Fresh));
        // Same key + same proposal digest: original ADMIT returned.
        assert_eq!(
            admit_idempotency(&req, Some(&prior)),
            Ok(AdmitDecision::Replay {
                admission_id: 77,
                accepted_local_ns: 1_000
            })
        );
        // Same key, different digest: E_CONFLICT.
        let mut changed = req;
        changed.operation_digest[0] ^= 1;
        assert_eq!(
            admit_idempotency(&changed, Some(&prior)),
            Err(Error::Conflict)
        );
        // A changed proposal recomputes to a different binding digest.
        let mut changed = req;
        changed.prepared_version += 1;
        changed.operation_digest = operation_digest(7, &user_frame(), &changed).unwrap();
        assert_ne!(changed.operation_digest, req.operation_digest);
        assert_eq!(
            admit_idempotency(&changed, Some(&prior)),
            Err(Error::Conflict)
        );
        // This layer keys on the carried proposal digest only; recomputing
        // the binding against changed fields is the native EL1 gate, so an
        // unchanged carried digest still replays at this layer.
        let mut stale_binding = req;
        stale_binding.prepared_version += 1;
        assert_eq!(
            admit_idempotency(&stale_binding, Some(&prior)),
            Ok(AdmitDecision::Replay {
                admission_id: 77,
                accepted_local_ns: 1_000
            })
        );
        // Different request_seq is a different key: fresh, not conflict.
        let mut next = req;
        next.request_seq += 1;
        assert_eq!(admit_idempotency(&next, None), Ok(AdmitDecision::Fresh));
        // A prior record under another key is a caller lookup bug.
        let mut other_key = prior;
        other_key.request_seq += 1;
        assert_eq!(
            admit_idempotency(&req, Some(&other_key)),
            Err(Error::Invalid)
        );
        let mut other_ctx = prior;
        other_ctx.auth_context_id += 1;
        assert_eq!(
            admit_idempotency(&req, Some(&other_ctx)),
            Err(Error::Invalid)
        );
        let mut no_id = prior;
        no_id.admission_id = 0;
        assert_eq!(admit_idempotency(&req, Some(&no_id)), Err(Error::Invalid));
        // Zero key components cannot identify a request.
        let mut zero = req;
        zero.auth_context_id = 0;
        assert_eq!(admit_idempotency(&zero, None), Err(Error::Invalid));
        let mut zero = req;
        zero.request_seq = 0;
        assert_eq!(admit_idempotency(&zero, None), Err(Error::Invalid));
    }

    #[test]
    fn prepared_version_monotonic_never_wraps_and_step_three_rules() {
        assert_eq!(next_prepared_version(0), Some(1));
        assert_eq!(next_prepared_version(u64::MAX - 1), Some(u64::MAX));
        assert_eq!(next_prepared_version(u64::MAX), None);
        // Step ③: match executes per the original admission; mismatch with
        // provable no-effect completes NO_EFFECT; otherwise keep UNKNOWN.
        assert_eq!(reverify_execution(3, 3, false), StepThree::Execute);
        assert_eq!(reverify_execution(4, 3, true), StepThree::CompleteNoEffect);
        assert_eq!(reverify_execution(4, 3, false), StepThree::KeepUnknown);
        assert_eq!(reverify_execution(2, 3, true), StepThree::CompleteNoEffect);
    }

    #[test]
    fn complete_decode_rejects_unknown_enum_reserved_and_bad_frames() {
        let mut b = [0u8; COMPLETE_REQUEST_BYTES];
        complete(TerminalState::Done, [1; 32])
            .encode(&mut b)
            .unwrap();
        assert!(CompleteRequestV1::decode(&b).is_ok());
        for state in [0u16, 5, 7, 0xffff] {
            let mut bad = b;
            put16(&mut bad, 16, state);
            assert_eq!(CompleteRequestV1::decode(&bad), Err(Error::Invalid));
        }
        let mut bad = b;
        bad[18] = 1;
        assert!(CompleteRequestV1::decode(&bad).is_err());
        let mut bad = b;
        bad[0] ^= 1;
        assert!(CompleteRequestV1::decode(&bad).is_err());
        let mut bad = b;
        put16(&mut bad, 4, 2);
        assert!(CompleteRequestV1::decode(&bad).is_err());
        let mut bad = b;
        put16(&mut bad, 6, 55);
        assert!(CompleteRequestV1::decode(&bad).is_err());
        assert!(CompleteRequestV1::decode(&b[..55]).is_err());
        let mut trailing = vec![0u8; 57];
        trailing[..56].copy_from_slice(&b);
        assert!(CompleteRequestV1::decode(&trailing).is_err());
        let mut bad = b;
        put64(&mut bad, 8, 0);
        assert!(CompleteRequestV1::decode(&bad).is_err());
        // Terminal claims without evidence are rejected (keep UNKNOWN);
        // UNKNOWN itself may carry no evidence yet.
        for state in [
            TerminalState::Done,
            TerminalState::Partial,
            TerminalState::NoEffect,
        ] {
            let mut bad = b;
            put16(&mut bad, 16, state.as_u16());
            bad[24..56].fill(0);
            assert!(CompleteRequestV1::decode(&bad).is_err());
            assert!(complete(state, [0; 32]).encode(&mut bad).is_err());
        }
        let mut u = [0u8; COMPLETE_REQUEST_BYTES];
        complete(TerminalState::Unknown, [0; 32])
            .encode(&mut u)
            .unwrap();
        assert_eq!(
            CompleteRequestV1::decode(&u).unwrap().terminal_state,
            TerminalState::Unknown
        );
        // Reply reserved must be zero; length exact.
        let mut p = [0u8; COMPLETE_REPLY_BYTES];
        CompleteReplyV1 { result: 0 }.encode(&mut p);
        p[4] = 1;
        assert!(CompleteReplyV1::decode(&p).is_err());
        assert!(CompleteReplyV1::decode(&p[..7]).is_err());
        let mut long = [0u8; 9];
        long[..8].copy_from_slice(&{
            let mut q = [0u8; 8];
            CompleteReplyV1 { result: 0 }.encode(&mut q);
            q
        });
        assert!(CompleteReplyV1::decode(&long).is_err());
    }

    #[test]
    fn complete_state_machine_idempotency_conflict_and_unknown_retention() {
        let evidence = [0x77; 32];
        let done = complete(TerminalState::Done, evidence);
        // ADMITTED directly to a terminal state with real evidence.
        let out = complete_transition(Completion::InFlight, &done).unwrap();
        assert_eq!(
            out,
            CompleteOutcome::Terminal {
                state: TerminalState::Done,
                evidence_digest: evidence
            }
        );
        let terminal = Completion::Terminal {
            state: TerminalState::Done,
            evidence_digest: evidence,
        };
        assert!(terminal.releases_reference());
        // Identical repeat: idempotent original result.
        assert_eq!(
            complete_transition(terminal, &done),
            Ok(CompleteOutcome::Idempotent)
        );
        // Different digest or different terminal state: E_CONFLICT.
        let mut other = done;
        other.evidence_digest[0] ^= 1;
        assert_eq!(complete_transition(terminal, &other), Err(Error::Conflict));
        let partial = complete(TerminalState::Partial, evidence);
        assert_eq!(
            complete_transition(terminal, &partial),
            Err(Error::Conflict)
        );
        let no_effect = complete(TerminalState::NoEffect, evidence);
        assert_eq!(
            complete_transition(terminal, &no_effect),
            Err(Error::Conflict)
        );
        // Terminal never regresses to UNKNOWN.
        let unknown = complete(TerminalState::Unknown, evidence);
        assert_eq!(
            complete_transition(terminal, &unknown),
            Err(Error::Conflict)
        );
        // ADMITTED → UNKNOWN retains gate/reference; repeated UNKNOWN only
        // reconciles; evidence may be updated while UNKNOWN, never releases.
        let out = complete_transition(Completion::InFlight, &unknown).unwrap();
        assert_eq!(
            out,
            CompleteOutcome::UnknownRetained {
                evidence_digest: evidence
            }
        );
        let unknown_state = Completion::Unknown {
            evidence_digest: evidence,
        };
        assert!(!unknown_state.releases_reference());
        assert!(!Completion::InFlight.releases_reference());
        assert_eq!(
            complete_transition(unknown_state, &unknown),
            Ok(CompleteOutcome::UnknownRetained {
                evidence_digest: evidence
            })
        );
        let mut updated = unknown;
        updated.evidence_digest = [0x88; 32];
        assert_eq!(
            complete_transition(unknown_state, &updated),
            Ok(CompleteOutcome::UnknownRetained {
                evidence_digest: [0x88; 32]
            })
        );
        // UNKNOWN → terminal with authoritative evidence.
        assert_eq!(
            complete_transition(unknown_state, &done),
            Ok(CompleteOutcome::Terminal {
                state: TerminalState::Done,
                evidence_digest: evidence
            })
        );
        // Terminal claims without evidence keep UNKNOWN (rejected here).
        let mut unproven = done;
        unproven.evidence_digest = [0; 32];
        assert_eq!(
            complete_transition(unknown_state, &unproven),
            Err(Error::Invalid)
        );
        assert_eq!(
            complete_transition(Completion::InFlight, &unproven),
            Err(Error::Invalid)
        );
        // UNKNOWN with zero evidence is a legal reconciliation report.
        let bare = complete(TerminalState::Unknown, [0; 32]);
        assert_eq!(
            complete_transition(Completion::InFlight, &bare),
            Ok(CompleteOutcome::UnknownRetained {
                evidence_digest: [0; 32]
            })
        );
        // A zero admission id can never bind a real admission.
        let mut zero = done;
        zero.admission_id = 0;
        assert_eq!(
            complete_transition(Completion::InFlight, &zero),
            Err(Error::Invalid)
        );
    }

    #[test]
    fn terminal_receipt_status_projection_and_no_false_cancel() {
        assert_eq!(TerminalState::Done.receipt_status(true), 3);
        assert_eq!(TerminalState::Partial.receipt_status(true), 4);
        assert_eq!(TerminalState::NoEffect.receipt_status(true), 6);
        assert_eq!(TerminalState::Unknown.receipt_status(true), 5);
        // Cannot persist the record: keep BOUND and query UNKNOWN.
        assert_eq!(TerminalState::Unknown.receipt_status(false), 2);
        // PARTIAL never maps to NO_EFFECT/CANCELLED.
        assert_ne!(TerminalState::Partial.receipt_status(true), 6);
        assert!(TerminalState::Done.is_terminal());
        assert!(TerminalState::Partial.is_terminal());
        assert!(TerminalState::NoEffect.is_terminal());
        assert!(!TerminalState::Unknown.is_terminal());
        for v in 1u16..=4 {
            assert_eq!(TerminalState::from_u16(v).unwrap().as_u16(), v);
        }
        for v in [0u16, 5, 7] {
            assert!(TerminalState::from_u16(v).is_none());
        }
    }

    #[test]
    fn role_gates_use_verified_caller_not_body_self_report() {
        assert_eq!(admit_role_gate(FILE_SERVICE_ROLE), Ok(()));
        for role in [0u64, 1, 2, 11, 13, 15] {
            assert_eq!(admit_role_gate(role), Err(Error::Unauthorized));
        }
        assert_eq!(complete_role_gate(FILE_SERVICE_ROLE, false), Ok(()));
        // Protected recovery successor may reconcile old obligations only.
        assert_eq!(complete_role_gate(9, true), Ok(()));
        assert_eq!(complete_role_gate(9, false), Err(Error::Unauthorized));
        // Recovery never gains ADMIT (new work) qualification.
        assert_eq!(admit_role_gate(9), Err(Error::Unauthorized));
    }
}
