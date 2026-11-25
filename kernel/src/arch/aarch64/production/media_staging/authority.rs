//! Staging durable BootEpoch (spec Q3=(a)) and the EL1 FILE_AUTH admission
//! flow, both driven on the freshly formatted scratch volume.
//!
//! BootEpoch, against the integration contract in kernel-core
//! `boot_epoch_v1.rs` (BootEpochAuthority):
//! * Step 1 is only PARTIALLY satisfied: both superblocks, the (empty) redo
//!   chain and the mounted-volume identity are verified on real media, but
//!   there is NO signed offline config. `open` therefore goes through the
//!   paired-store gate with a STAGED `verify_recovered` (committed state must
//!   equal the frozen-mount evidence), never `recovered_for_startup`.
//!   `confirmed_config_boot` is never called and no control root is issued.
//! * Steps 2..6 run for real: committed homes read from disk, an EMPTY
//!   six-block log extent (2..8, zeroed by the formatter) with txid=1 /
//!   commit_lsn=4, paired BEGIN/REDO/COMMIT append with ordered FLUSH and
//!   independent device readback, `confirm_boot_from_redo`.
//! * Step 7: a second allocation in the same boot must be `Conflict`.
//! The epoch is durable only on this throw-away scratch image; it is evidence
//! that the path runs, not a production persistence claim.
//!
//! Admission: `run_admission_flow` with a fixed EL1 fixture input (v4 CLOSE
//! frame, role12, ADMITTED authority facts). No EL0 file service exists; the
//! native authority cross-checks are the documented later gate.
//!
//! UNSAFE BOUNDARY: PAIR (static mut BootPairRedo, `.bss.sec_n`, NOT
//! FrameMeta-registered; the contract's "progress pool" is not provisioned in
//! this lane): one `&mut` inside the one-shot CPU0 `stage` call.
use super::Disk;
use super::volume::{BOOT_HOME, SECURITY_HOME};
use cyxia_kernel_core::control_plane::role_manifest_v0199::ROLES;
use cyxia_kernel_core::security::{
    Error as SecurityError,
    boot_epoch_v1::{BootEpochAuthority, BootEpochTx, BootPairRedo},
    durable_role_epoch_v0199::SlotBinding,
    epoch_redo_v0199::EpochBlockIo,
    file_admission_flow_v1::{AdmissionFlowInput, FlowOutcome, run_admission_flow},
    file_auth_context_v1::{AdmissionLedgerV1, AuthContextIssuerV1, AuthorityFacts},
    file_auth_v3::{AdmitRequestV3, CompleteOutcome, FILE_SERVICE_ROLE, TerminalState, Verdict},
    file_index_v0199::{BLOCK_BYTES, SecurityStateStoreV2},
    file_service_v4::{REQUEST_HEADER, REQUEST_MAGIC, REQUEST_VERSION},
};

const FIRST_LOG_BLOCK: u32 = 2;
const BOOT_TXID: u64 = 1;
const BOOT_COMMIT_LSN: u64 = 4;
const EVIDENCE: [u8; 32] = [0x3c; 32];

#[cfg_attr(feature = "v020-production", unsafe(link_section = ".bss.sec_n"))]
static mut PAIR: BootPairRedo = BootPairRedo::new();

/// Allocate and durably confirm boot epoch 1 on the scratch volume. Returns
/// the authority's `confirmed_epoch`; any failure is returned (fail-closed).
pub(super) fn boot_epoch(
    disk: &mut Disk,
    mounted: &SecurityStateStoreV2,
) -> Result<u64, SecurityError> {
    let mut state = [0; BLOCK_BYTES];
    let mut boot = [0; BLOCK_BYTES];
    let mut sb_raw = [0; BLOCK_BYTES];
    disk.read(SECURITY_HOME, &mut state)?;
    disk.read(BOOT_HOME, &mut boot)?;
    disk.read(0, &mut sb_raw)?;
    let slots = core::array::from_fn(|i| SlotBinding {
        role: ROLES[i],
        slot: i as u8,
    });
    // STAGED verification: frozen-mount identity only; no signed config.
    let mut authority = BootEpochAuthority::open(&state, &boot, slots, |s| {
        if s == mounted {
            Ok(())
        } else {
            Err(SecurityError::Conflict)
        }
    })?;
    if authority.confirmed_epoch().is_some() {
        return Err(SecurityError::Conflict);
    }
    let tx = BootEpochTx {
        superblock_raw: &sb_raw,
        first_log_block: FIRST_LOG_BLOCK,
        state_home: SECURITY_HOME,
        boot_home: BOOT_HOME,
        txid: BOOT_TXID,
        commit_lsn: BOOT_COMMIT_LSN,
    };
    // SAFETY: one-shot CPU0 call (module header); the borrow ends on return.
    let pair = unsafe { &mut *core::ptr::addr_of_mut!(PAIR) };
    let grant = authority.allocate(disk, pair, tx)?;
    let confirmed = authority.confirmed_epoch().ok_or(SecurityError::Conflict)?;
    if confirmed != grant.epoch() || confirmed == 0 {
        return Err(SecurityError::Conflict);
    }
    // One boot epoch per boot: a retry must be fenced before any I/O.
    if authority.allocate(disk, pair, tx).err() != Some(SecurityError::Conflict) {
        return Err(SecurityError::Conflict);
    }
    Ok(confirmed)
}

fn user_frame(auth_context_id: u64) -> [u8; REQUEST_HEADER + 4] {
    // FileServiceRequest v4, op6 CLOSE, 4-byte payload.
    let mut b = [0; REQUEST_HEADER + 4];
    b[0..4].copy_from_slice(&REQUEST_MAGIC.to_le_bytes());
    b[4..6].copy_from_slice(&REQUEST_VERSION.to_le_bytes());
    b[6..8].copy_from_slice(&(REQUEST_HEADER as u16).to_le_bytes());
    b[8..10].copy_from_slice(&6u16.to_le_bytes());
    b[12..16].copy_from_slice(&4u32.to_le_bytes());
    b[16..24].copy_from_slice(&4u64.to_le_bytes());
    b[24..32].copy_from_slice(&auth_context_id.to_le_bytes());
    b
}

fn input(frame: &[u8]) -> AdmissionFlowInput<'_> {
    AdmissionFlowInput {
        principal: 1,
        role: FILE_SERVICE_ROLE,
        user_frame: frame,
        cap_selector: 1,
        proposal: AdmitRequestV3 {
            auth_context_id: 0,
            target_id: 42,
            target_generation: 7,
            required_rights: 0b1011,
            request_seq: 1,
            prepared_version: 0,
            acl_generation: 1,
            frozen_data_digest: [0; 32],
            operation_digest: [0; 32],
        },
        current_prepared_version: 2,
        data: b"staging",
        facts: AuthorityFacts {
            current_generation: 1,
            verdict: Verdict::Admitted,
            deny_generation: 0,
            accepted_local_ns: 1_000,
        },
        local_prepared_version: 3,
        provable_no_effect: false,
        terminal_state: TerminalState::Done,
        evidence_digest: EVIDENCE,
    }
}

/// Fresh FILE_AUTH flow under the confirmed epoch reaches a terminal DONE with
/// the reference released, AND a self-reported nonzero auth_context_id frame
/// is rejected with nothing registered.
pub(super) fn admission_flow(boot_epoch: u64) -> Result<(), SecurityError> {
    // Negative on its own issuer/ledger: encapsulation still consumes a
    // context id and advances the holder generation, which would make the
    // positive run's authority facts stale if both shared one issuer.
    let mut issuer = AuthContextIssuerV1::new(boot_epoch)?;
    let mut ledger = AdmissionLedgerV1::new(boot_epoch)?;
    let forged = user_frame(0xdead_beef);
    if run_admission_flow(&mut issuer, &mut ledger, &input(&forged)).is_ok() || ledger.len() != 0 {
        return Err(SecurityError::Conflict);
    }
    let mut issuer = AuthContextIssuerV1::new(boot_epoch)?;
    let mut ledger = AdmissionLedgerV1::new(boot_epoch)?;
    let frame = user_frame(0);
    let done = CompleteOutcome::Terminal {
        state: TerminalState::Done,
        evidence_digest: EVIDENCE,
    };
    match run_admission_flow(&mut issuer, &mut ledger, &input(&frame))? {
        FlowOutcome::Completed { completion, .. }
            if completion == done && ledger.len() == 1 && ledger.inflight_count() == 0 =>
        {
            Ok(())
        }
        _ => Err(SecurityError::Conflict),
    }
}
