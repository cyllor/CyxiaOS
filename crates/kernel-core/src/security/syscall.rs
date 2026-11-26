//! SEC-S: ABI-v1 syscall admission, stable bounded copy and read-only vector.
//! The real trap handler must call these *after* verifying EL0 identity and
//! *before* dispatch. This module does not dereference user pointers.
use super::Error;

pub const MAX_VECTOR: usize = 16;
pub const ITEM_BYTES: usize = 28;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Syscall {
    Exit,
    Yield,
    Sleep,
    Clock,
    Spawn,
    QueryTask,
    RevokeCap,
    Join,
    ReserveVm,
    MapOwned,
    Unmap,
    IpcSend,
    IpcRecv,
    SubmitReadVector,
    ReadSnapshot,
    SubmitPlan,
    QueryPlan,
    ReportResult,
    ServiceCall,
}
pub fn decode_syscall(no: u64) -> Result<Syscall, Error> {
    use Syscall::*;
    Ok(match no {
        0x01 => Exit,
        0x02 => Yield,
        0x03 => Sleep,
        0x04 => Clock,
        0x10 => Spawn,
        0x11 => QueryTask,
        0x12 => RevokeCap,
        0x13 => Join,
        0x20 => ReserveVm,
        0x21 => MapOwned,
        0x22 => Unmap,
        0x30 => IpcSend,
        0x31 => IpcRecv,
        0x32 => SubmitReadVector,
        0x40 => ReadSnapshot,
        0x41 => SubmitPlan,
        0x42 => QueryPlan,
        0x43 => ReportResult,
        0x50 => ServiceCall,
        _ => return Err(Error::Invalid),
    })
}
pub fn user_copy_span(
    address: u64,
    bytes: usize,
    user_start: u64,
    user_end: u64,
    max_bytes: usize,
) -> Result<(u64, u64), Error> {
    if bytes == 0 || bytes > max_bytes || user_start >= user_end {
        return Err(Error::Invalid);
    }
    let len = u64::try_from(bytes).map_err(|_| Error::Invalid)?;
    let end = address.checked_add(len).ok_or(Error::Invalid)?;
    if address < user_start || end > user_end {
        return Err(Error::Unauthorized);
    }
    Ok((address, end))
}
/// Immediate copy into an exclusively owned bounded buffer; callers must
/// use this copy for parsing and never reread mutable EL0 input after checks.
pub struct StableCopy<const N: usize> {
    data: [u8; N],
    len: usize,
}
impl<const N: usize> StableCopy<N> {
    pub fn from_validated(source: &[u8]) -> Result<Self, Error> {
        if source.len() > N {
            return Err(Error::Capacity);
        }
        let mut data = [0; N];
        data[..source.len()].copy_from_slice(source);
        Ok(Self {
            data,
            len: source.len(),
        })
    }
    pub fn bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadOperation {
    pub op: u16,
    pub flags: u16,
    pub capability: u64,
    pub generation: u64,
    pub tag: u64,
}
pub const FILE_STAT_BY_CAP: u16 = 1;
pub const TASK_QUERY_BY_CAP: u16 = 2;
/// Format-only preflight for a frozen, copied readonly vector. This is a
/// fixed-cost validator without extra stack buffers; the trusted caller
/// supplies a stable snapshot, not a live EL0 pointer.
/// Capability validity and object generations are *per-item* failures and
/// MUST NOT reject the whole vector or roll back unrelated completed items.
pub fn validate_readonly_batch(
    count: usize,
    item: impl Fn(usize) -> (u16, u16, u64),
) -> Result<(), Error> {
    if count == 0 || count > MAX_VECTOR {
        return Err(Error::Invalid);
    }
    for at in 0..count {
        let (op, flags, tag) = item(at);
        if flags != 0 || !matches!(op, FILE_STAT_BY_CAP | TASK_QUERY_BY_CAP) {
            return Err(Error::Invalid);
        }
        for earlier in 0..at {
            if item(earlier).2 == tag {
                return Err(Error::Invalid);
            }
        }
    }
    Ok(())
}
/// The model-facing typed adapter uses the same format gate as the native
/// vector decoder, without treating a missing/stale cap as a global error.
pub fn validate_vector(items: &[ReadOperation]) -> Result<(), Error> {
    validate_readonly_batch(items.len(), |at| {
        let item = &items[at];
        (item.op, item.flags, item.tag)
    })
}

/// Construct only from EL1 protected identity. Neither AI scores nor a
/// network message can supply publisher or executor authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedRole {
    identity: u64,
    generation: u64,
}
impl ProtectedRole {
    #[allow(dead_code)] // Constructed by the native authority adapter once integrated.
    pub(crate) const fn from_kernel(identity: u64, generation: u64) -> Self {
        Self {
            identity,
            generation,
        }
    }
}
pub fn can_publish(caller: ProtectedRole, publisher: ProtectedRole) -> Result<(), Error> {
    if caller.identity == 0 || caller.generation == 0 || caller != publisher {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
/// V0.20 fixed native publisher gate. A matching EL1 identity is not
/// sufficient if the caller runs on a business CPU (CPU1-3), or if the control
/// mask was silently expanded beyond the single CPU0 control core by an
/// obsolete CoreSet decision.
pub fn can_publish_fixed(
    caller: ProtectedRole,
    publisher: ProtectedRole,
    executing_cpu: usize,
    control_mask: u64,
) -> Result<(), Error> {
    can_publish(caller, publisher)?;
    if executing_cpu != crate::control_plane::fixed::CONTROL_CPU
        || control_mask != crate::control_plane::fixed::CONTROL_MASK
    {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
/// V0.19.9 CPU0 single-controller publication gate, independent from the
/// legacy CPU1/Cpu0-broker path. A protected EL1 task identity is still
/// required; neither a model packet nor a role number authorizes publishing.
pub fn can_publish_cpu0_v0199(
    caller: ProtectedRole,
    publisher: ProtectedRole,
    executing_cpu: usize,
    control_mask: u64,
) -> Result<(), Error> {
    can_publish(caller, publisher)?;
    if executing_cpu != crate::control_plane::cpu0_v0199::CONTROL_CPU
        || control_mask != crate::control_plane::cpu0_v0199::CONTROL_MASK
    {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
pub fn can_report_completion(
    caller: ProtectedRole,
    executor: ProtectedRole,
    reported_generation: u64,
) -> Result<(), Error> {
    can_publish(caller, executor)?;
    if reported_generation != executor.generation {
        return Err(Error::Stale);
    }
    Ok(())
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptState {
    Accepted,
    Committed,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Receipt {
    request_id: u64,
    digest: [u8; 32],
    state: ReceiptState,
    output_fault: bool,
}
pub struct ReceiptTable<const N: usize> {
    rows: [Option<Receipt>; N],
}
impl<const N: usize> ReceiptTable<N> {
    pub const fn new() -> Self {
        Self { rows: [None; N] }
    }
    pub fn submit(&mut self, id: u64, digest: [u8; 32]) -> Result<ReceiptState, Error> {
        if id == 0 {
            return Err(Error::Invalid);
        }
        if let Some(r) = self.rows.iter().flatten().find(|r| r.request_id == id) {
            return if r.digest == digest {
                Ok(r.state)
            } else {
                Err(Error::Conflict)
            };
        }
        let at = self
            .rows
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        self.rows[at] = Some(Receipt {
            request_id: id,
            digest,
            state: ReceiptState::Accepted,
            output_fault: false,
        });
        Ok(ReceiptState::Accepted)
    }
    fn row(&mut self, id: u64) -> Result<&mut Receipt, Error> {
        self.rows
            .iter_mut()
            .flatten()
            .find(|r| r.request_id == id)
            .ok_or(Error::Stale)
    }
    pub fn committed(&mut self, id: u64) -> Result<(), Error> {
        let r = self.row(id)?;
        if r.state != ReceiptState::Accepted {
            return Err(Error::Busy);
        }
        r.state = ReceiptState::Committed;
        Ok(())
    }
    pub fn uncertain(&mut self, id: u64) -> Result<(), Error> {
        let r = self.row(id)?;
        if r.state == ReceiptState::Accepted {
            r.state = ReceiptState::Unknown;
        }
        Ok(())
    }
    pub fn output_copy_failed(&mut self, id: u64) -> Result<(), Error> {
        self.row(id)?.output_fault = true;
        Ok(())
    }
    pub fn query(&mut self, id: u64) -> Result<(ReceiptState, bool), Error> {
        let r = self.row(id)?;
        Ok((r.state, r.output_fault))
    }
}
impl<const N: usize> Default for ReceiptTable<N> {
    fn default() -> Self {
        Self::new()
    }
}
// ===========================================================================
// SEC-S10 — query indistinguishability (response equivalence).
//
// Baseline (docs/design/baselines/v0.19.9-implementation-spec.txt):
//   * SEC-S10 acceptance row, L10660–10668: cross-privilege task_query/file
//     queries against the same absent object and a real unauthorized object
//     must "对外返回相同拒绝错误，非授权侧无法凭结果确认其他对象存在".
//   * SEC-S implementation contract, L10529–10530: "不存在与无权访问均报
//     E_AUTH，不承诺常量时延不可探测（防止把本版错误码统一误称为完整侧信道防护）".
//   * Unified error table, L10769–10777: unauthorized or non-self absent
//     objects uniformly E_AUTH(-1); ONLY the real holder's old generation gets
//     E_STALE(-4); "错误分类先验证 holder，不承诺常量时延".
//   * 主§2.2, L672–674: unauthorized and absent objects both return E_AUTH to
//     a non-authorized caller; strict constant time of the two rejection paths
//     is NOT promised.
//   * SEC-P implementation contract, L8632: an unauthorized service call
//     returns the same E_AUTH whether or not the object exists.
//   * 安§0.7, L6697+: holder_id/generation are the EL1 lookup keys.
//
// CONTRACT-ONLY host model of the holder-first classification rule. The
// protected EL1 registry adapter supplies the real ObjectObservation; AI or
// network input cannot. Error mapping: Unauthorized↔E_AUTH(-1),
// Stale↔E_STALE(-4), Invalid↔E_FORMAT(-2).
//
// HONEST SCOPE: the baseline guarantees identical *external rejection*
// (response equivalence), NOT constant time. L10529 and L674 explicitly
// disclaim strict constant-time / full side-channel protection. This model
// asserts NO timing property; a timing oracle is out of scope for this
// version and must not be claimed as defended.
// ===========================================================================

/// Real object state supplied ONLY by the protected EL1 registry adapter.
/// `Present` carries the true holder identity/generation and current object
/// generation; a non-holder caller must never learn any of these fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectObservation {
    Absent,
    Present {
        holder: u64,
        holder_generation: u64,
        object_generation: u64,
    },
}

/// Holder-first query classification (SEC-S10 / error table L10771). The rule
/// is identical for task_query (0x11 / TASK_QUERY_BY_CAP) and file stat
/// (FILE_STAT_BY_CAP), and by the SEC-P contract (L8632) for any object query
/// (snapshot/telemetry lookups included). Format validation runs BEFORE this
/// rule (validate_readonly_batch / decode_v3) and is existence-independent.
///
/// Every non-holder outcome — absent object, real-but-unauthorized object, or
/// invalid caller identity — collapses to the single external E_AUTH
/// (Unauthorized). Only the verified holder of the current generation may
/// proceed (Ok); only the verified holder requesting an old generation learns
/// E_STALE (Stale). A non-holder NEVER receives Stale, which would otherwise
/// leak both existence and generation.
pub fn query_admission(
    caller: u64,
    caller_generation: u64,
    requested_generation: u64,
    observation: ObjectObservation,
) -> Result<(), Error> {
    // Invalid identity is indistinguishable from unauthorized: same E_AUTH.
    if caller == 0 || caller_generation == 0 {
        return Err(Error::Unauthorized);
    }
    match observation {
        ObjectObservation::Absent => Err(Error::Unauthorized),
        ObjectObservation::Present {
            holder,
            holder_generation,
            object_generation,
        } => {
            // Verify holder FIRST; a non-holder gets E_AUTH regardless of the
            // object's real generation (no existence/generation oracle).
            if holder != caller || holder_generation != caller_generation {
                return Err(Error::Unauthorized);
            }
            if requested_generation != object_generation {
                return Err(Error::Stale);
            }
            Ok(())
        }
    }
}

/// S10 response-equivalence rule as a checkable pure predicate: the external
/// replies for two observations are indistinguishable to this caller iff they
/// are equal. For a non-holder caller, `Absent` and any real unauthorized
/// `Present` MUST be indistinguishable (no existence oracle). This compares
/// responses only; it asserts nothing about timing (see HONEST SCOPE above).
pub fn query_replies_indistinguishable(
    caller: u64,
    caller_generation: u64,
    requested_generation: u64,
    a: ObjectObservation,
    b: ObjectObservation,
) -> bool {
    query_admission(caller, caller_generation, requested_generation, a)
        == query_admission(caller, caller_generation, requested_generation, b)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn item(tag: u64) -> ReadOperation {
        ReadOperation {
            op: FILE_STAT_BY_CAP,
            flags: 0,
            capability: 7,
            generation: 1,
            tag,
        }
    }
    fn role(id: u64) -> ProtectedRole {
        ProtectedRole::from_kernel(id, 1)
    }
    #[test]
    fn sec_s01_unknown_syscall_and_overflow_rejected() {
        assert_eq!(decode_syscall(0x51), Err(Error::Invalid));
        assert_eq!(decode_syscall(0x41), Ok(Syscall::SubmitPlan));
        assert_eq!(
            user_copy_span(u64::MAX, 8, 1, u64::MAX, 8),
            Err(Error::Invalid)
        );
    }
    // The post-copy write is deliberate scaffolding: the test proves the
    // frozen copy ignores later input mutation, so the assignment must stay.
    #[allow(unused_assignments)]
    #[test]
    fn sec_s02_user_input_frozen_once() {
        let mut input = [1, 2, 3];
        let copy = StableCopy::<16>::from_validated(&input).unwrap();
        input[0] = 99;
        assert_eq!(copy.bytes(), &[1, 2, 3]);
    }
    #[test]
    fn sec_s03_output_fault_does_not_redo_commit() {
        let mut t = ReceiptTable::<1>::new();
        t.submit(1, [2; 32]).unwrap();
        t.committed(1).unwrap();
        t.output_copy_failed(1).unwrap();
        assert_eq!(t.query(1), Ok((ReceiptState::Committed, true)));
        assert_eq!(t.submit(1, [2; 32]), Ok(ReceiptState::Committed));
    }
    #[test]
    fn sec_s04_only_publisher_can_submit_plan() {
        assert_eq!(can_publish(role(1), role(2)), Err(Error::Unauthorized));
        assert_eq!(can_publish(role(2), role(2)), Ok(()));
    }
    #[test]
    fn v020_sec_s04_fixed_publisher_cannot_run_on_business_cpu() {
        assert_eq!(can_publish_fixed(role(2), role(2), 0, 0b0001), Ok(()));
        assert_eq!(
            can_publish_fixed(role(2), role(2), 1, 0b0001),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            can_publish_fixed(role(2), role(2), 2, 0b0001),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            can_publish_fixed(role(2), role(2), 3, 0b0001),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            can_publish_fixed(role(2), role(2), 0, 0b0011),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            can_publish_fixed(role(1), role(2), 0, 0b0001),
            Err(Error::Unauthorized)
        );
    }
    #[test]
    fn v0199_cpu0_publisher_rejects_all_business_cores() {
        assert_eq!(can_publish_cpu0_v0199(role(8), role(8), 0, 1), Ok(()));
        for cpu in 1..=3 {
            assert_eq!(
                can_publish_cpu0_v0199(role(8), role(8), cpu, 1),
                Err(Error::Unauthorized)
            );
        }
        assert_eq!(
            can_publish_cpu0_v0199(role(8), role(8), 0, 0b11),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            can_publish_cpu0_v0199(role(7), role(8), 0, 1),
            Err(Error::Unauthorized)
        );
    }
    #[test]
    fn sec_s05_old_executor_generation_cannot_report() {
        assert_eq!(
            can_report_completion(role(2), role(2), 2),
            Err(Error::Stale)
        );
        assert_eq!(can_report_completion(role(2), role(2), 1), Ok(()));
    }
    #[test]
    fn sec_s06_vector_format_invalid_is_whole_vector_failure() {
        let mut ops = [item(1), item(2)];
        ops[1].tag = 1;
        assert_eq!(validate_vector(&ops), Err(Error::Invalid));
        ops[1].tag = 2;
        ops[1].op = 99;
        assert_eq!(validate_vector(&ops), Err(Error::Invalid));
    }
    #[test]
    fn sec_s07_vector_tags_stable_and_single_item_does_not_cancel_peer() {
        let ops = [
            ReadOperation {
                capability: 0,
                generation: 0,
                ..item(1)
            },
            ReadOperation {
                op: TASK_QUERY_BY_CAP,
                ..item(2)
            },
        ];
        // This is structurally legal: the first item's missing cap is an
        // authorization error for that item, not an all-vector format error.
        validate_vector(&ops).unwrap();
        assert_eq!(
            validate_readonly_batch(2, |at| { (ops[at].op, ops[at].flags, ops[at].tag) }),
            Ok(())
        );
        let results = [Err(Error::Stale), Ok(5u64)];
        assert!(results[0].is_err());
        assert_eq!(results[1], Ok(5));
        assert_eq!(ops[1].tag, 2);
    }
    #[test]
    fn sec_s08_full_receipt_credit_causes_precommit_backpressure() {
        let mut t = ReceiptTable::<1>::new();
        t.submit(1, [2; 32]).unwrap();
        assert_eq!(t.submit(2, [3; 32]), Err(Error::Capacity));
        t.uncertain(1).unwrap();
        assert_eq!(t.submit(1, [2; 32]), Ok(ReceiptState::Unknown));
    }

    // ---- SEC-S10: query indistinguishability (response equivalence) ----
    fn present(holder: u64, holder_gen: u64, obj_gen: u64) -> ObjectObservation {
        ObjectObservation::Present {
            holder,
            holder_generation: holder_gen,
            object_generation: obj_gen,
        }
    }
    #[test]
    fn sec_s10_absent_and_unauthorized_present_identical() {
        // Caller 7 (gen 1) is not the holder (9) of the real object.
        for req_gen in [0, 1, 2, 99, u64::MAX] {
            let absent = query_admission(7, 1, req_gen, ObjectObservation::Absent);
            let unauth = query_admission(7, 1, req_gen, present(9, 1, 2));
            assert_eq!(absent, Err(Error::Unauthorized));
            assert_eq!(absent, unauth);
            assert!(query_replies_indistinguishable(
                7,
                1,
                req_gen,
                ObjectObservation::Absent,
                present(9, 1, 2)
            ));
        }
    }
    #[test]
    fn sec_s10_non_holder_never_learns_stale() {
        // Requesting the OLD generation of a real object must still be E_AUTH
        // for a non-holder (Stale would leak existence + generation).
        assert_eq!(
            query_admission(7, 1, 1, present(9, 1, 2)),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            query_admission(7, 1, 2, present(9, 1, 2)),
            Err(Error::Unauthorized)
        );
        // Wrong holder generation is also E_AUTH, not Stale.
        assert_eq!(
            query_admission(9, 2, 1, present(9, 1, 2)),
            Err(Error::Unauthorized)
        );
        // The REAL holder requesting an old generation is the only Stale case.
        assert_eq!(
            query_admission(9, 1, 1, present(9, 1, 2)),
            Err(Error::Stale)
        );
    }
    #[test]
    fn sec_s10_holder_current_generation_allowed() {
        assert_eq!(query_admission(9, 1, 2, present(9, 1, 2)), Ok(()));
    }
    #[test]
    fn sec_s10_invalid_identity_same_rejection_as_absent() {
        for (caller, caller_gen) in [(0, 1), (7, 0), (0, 0)] {
            let r = query_admission(caller, caller_gen, 2, present(9, 1, 2));
            assert_eq!(r, Err(Error::Unauthorized));
            assert_eq!(
                r,
                query_admission(caller, caller_gen, 2, ObjectObservation::Absent)
            );
        }
    }
    #[test]
    fn sec_s10_task_query_and_file_stat_share_the_rule() {
        // Both registered readonly query ops feed the same admission rule and
        // produce identical external rejections for a non-holder.
        let ops = [
            ReadOperation {
                op: TASK_QUERY_BY_CAP,
                flags: 0,
                capability: 7,
                generation: 1,
                tag: 1,
            },
            ReadOperation {
                op: FILE_STAT_BY_CAP,
                flags: 0,
                capability: 7,
                generation: 1,
                tag: 2,
            },
        ];
        validate_vector(&ops).unwrap(); // format gate is existence-independent
        let mut replies = [Err(Error::Unauthorized); 2];
        for (i, op) in ops.iter().enumerate() {
            replies[i] = query_admission(op.capability, op.generation, 2, present(9, 1, 2));
            assert_eq!(
                replies[i],
                query_admission(op.capability, op.generation, 2, ObjectObservation::Absent)
            );
        }
        assert_eq!(replies[0], replies[1]);
    }
    #[test]
    fn sec_s10_format_gate_is_existence_independent() {
        // A malformed op is rejected by the format preflight identically
        // whether the object is absent or present (no existence-dependent error).
        let bad = [ReadOperation {
            op: 99,
            flags: 0,
            capability: 7,
            generation: 1,
            tag: 1,
        }];
        assert_eq!(validate_vector(&bad), Err(Error::Invalid));
        for obs in [ObjectObservation::Absent, present(9, 1, 2)] {
            assert_eq!(query_admission(7, 1, 2, obs), Err(Error::Unauthorized));
        }
    }
    #[test]
    fn sec_s10_no_existence_oracle_over_generation_sweep() {
        // A fixed non-holder caller sweeping requested generations cannot
        // distinguish absent from any real unauthorized object.
        let real = present(9, 1, 2);
        for req_gen in 0..64u64 {
            assert!(query_replies_indistinguishable(
                7,
                1,
                req_gen,
                ObjectObservation::Absent,
                real
            ));
            assert_eq!(
                query_admission(7, 1, req_gen, real),
                Err(Error::Unauthorized)
            );
        }
        // Two different real objects, both unauthorized to caller 7, are also
        // indistinguishable from each other and from absent.
        let other = present(10, 3, 7);
        assert!(query_replies_indistinguishable(7, 1, 2, real, other));
        assert!(query_replies_indistinguishable(
            7,
            1,
            2,
            ObjectObservation::Absent,
            other
        ));
    }
    #[test]
    fn sec_s10_equivalence_is_response_only_not_timing() {
        // Records the honest scope: the contract asserts identical external
        // responses (E_AUTH), NOT constant time. Baseline L10529/L674 disclaim
        // strict constant-time / full side-channel protection; no timing
        // property is claimed or tested here.
        assert!(query_replies_indistinguishable(
            7,
            1,
            2,
            ObjectObservation::Absent,
            present(9, 1, 2)
        ));
        assert_eq!(
            query_admission(7, 1, 2, ObjectObservation::Absent),
            Err(Error::Unauthorized)
        );
    }
}
