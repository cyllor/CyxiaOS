//! Staging durable BootEpoch (spec Q3=(a)) and the EL1 FILE_AUTH admission
//! flow on a fresh or replayed dedicated scratch volume.
//!
//! BootEpoch, against the integration contract in kernel-core
//! `boot_epoch_v1.rs` (BootEpochAuthority):
//! * Both lanes verify the checkpoint, redo and mounted-volume identity.
//!   The signed scratch lane also checks its signed test policy before replay,
//!   opens the signed startup gate and rechecks the committed config after
//!   the paired append. This boot owner issues only the scratch epoch.
//! * Steps 2..6 run for real: committed homes read from disk, an EMPTY
//!   six-block log extent (2..8) with the next txid / commit LSN,
//!   paired BEGIN/REDO/COMMIT append with ordered FLUSH and
//!   independent device readback, `confirm_boot_from_redo`.
//! * Step 7: a second allocation in the same boot must be `Conflict`.
//!
//! The epoch is durable only on this throw-away scratch image; it is evidence
//! that the path runs, not a production persistence claim.
//!
//! Admission: `run_admission_flow` with a fixed EL1 fixture input (v4 CLOSE
//! frame, role12, ADMITTED authority facts). No EL0 file service exists; the
//! native authority cross-checks are the documented later gate.
//!
//! UNSAFE BOUNDARY: PAIR is a static BootPairRedo in the FrameMeta
//! `.bss.sec_n` Arena. CPU0 creates one `&mut` in the one-shot `stage`
//! call. The production progress pool remains a separate integration.
use super::Disk;
use super::volume::{self, BOOT_HOME, FIRST_LOG_BLOCK, SECURITY_HOME};
use cyxia_kernel_core::control_plane::role_manifest_v0199::ROLES;
use cyxia_kernel_core::security::{
    Error as SecurityError,
    boot_epoch_v1::{BootEpochAuthority, BootEpochTx, BootPairRedo},
    durable_role_epoch_v0199::SlotBinding,
    epoch_redo_v0199::EpochBlockIo,
    file_index_v0199::{BLOCK_BYTES, SecurityStateStoreV2},
    file_media_v0199::SuperblockV1,
};
// This file is also compiled directly by kernel-core integration tests.
// Keep the diagnostic helpers available there without enabling them in a
// default non-diagnostic kernel.
#[cfg(any(test, feature = "v020-production-diagnostic"))]
use cyxia_kernel_core::security::{
    file_admission_flow_v1::{AdmissionFlowInput, FlowOutcome, run_admission_flow},
    file_auth_context_v1::{AdmissionLedgerV1, AuthContextIssuerV1, AuthorityFacts},
    file_auth_v3::{
        AdmitRequestV3, CompleteOutcome, FILE_SERVICE_ROLE, StepThree, TerminalState, Verdict,
    },
    file_service_v4::{REQUEST_HEADER, REQUEST_MAGIC, REQUEST_VERSION},
};

pub(super) const BOOT_LOG_BLOCKS: u32 = 6;
#[cfg(any(test, feature = "v020-production-diagnostic"))]
const EVIDENCE: [u8; 32] = [0x3c; 32];

#[cfg_attr(target_os = "none", unsafe(link_section = ".bss.sec_n"))]
static mut PAIR: BootPairRedo = BootPairRedo::new();

/// Read and verify the sole transaction this staging owner could have left.
pub(super) fn verify_previous_pair(
    disk: &mut Disk,
    sb: SuperblockV1,
    config: volume::Config<'_>,
) -> Result<u64, SecurityError> {
    Ok(verified_pair_state(disk, sb, config)?.last_boot_epoch)
}

/// Re-read the exact paired transaction from the actual device. Return its
/// verified state image, not a synthetic next epoch or an unflushed home.
pub(super) fn verified_pair_state(
    disk: &mut Disk,
    sb: SuperblockV1,
    config: volume::Config<'_>,
) -> Result<SecurityStateStoreV2, SecurityError> {
    // SAFETY: synchronous, non-overlapping use of this CPU0-owned workspace.
    let pair = unsafe { &mut *core::ptr::addr_of_mut!(PAIR) };
    pair.read(disk, FIRST_LOG_BLOCK)?;
    let state = pair.verify(
        sb,
        FIRST_LOG_BLOCK,
        SECURITY_HOME,
        BOOT_HOME,
        sb.generation,
        sb.checkpoint_lsn
            .checked_add(4)
            .ok_or(SecurityError::Exhausted)?,
    )?;
    if let Some(config) = config {
        config.check_committed(&state)?;
    }
    if state != volume::expected_state(sb.generation, config)? {
        return Err(SecurityError::Conflict);
    }
    Ok(state)
}

/// Allocate and durably confirm the next epoch on the scratch volume. Returns
/// the authority's `confirmed_epoch`; any failure is returned (fail-closed).
#[allow(dead_code)] // The signed resident build retains the authority instead.
pub(super) fn boot_epoch(
    disk: &mut Disk,
    checkpoint: SuperblockV1,
    mounted: &SecurityStateStoreV2,
    config: volume::Config<'_>,
) -> Result<u64, SecurityError> {
    boot_epoch_owner(disk, checkpoint, mounted, config).map(|(epoch, _)| epoch)
}

pub(super) fn boot_epoch_owner(
    disk: &mut Disk,
    checkpoint: SuperblockV1,
    mounted: &SecurityStateStoreV2,
    config: volume::Config<'_>,
) -> Result<(u64, BootEpochAuthority), SecurityError> {
    let mut state = [0; BLOCK_BYTES];
    let mut boot = [0; BLOCK_BYTES];
    let mut sb_raw = [0; BLOCK_BYTES];
    disk.read(SECURITY_HOME, &mut state)?;
    disk.read(BOOT_HOME, &mut boot)?;
    if volume::read_checkpoint(disk, &mut sb_raw)? != checkpoint {
        return Err(SecurityError::Conflict);
    }
    let next = mounted
        .last_boot_epoch
        .checked_add(1)
        .ok_or(SecurityError::Exhausted)?;
    if next != checkpoint.generation {
        return Err(SecurityError::Conflict);
    }
    let slots = core::array::from_fn(|i| SlotBinding {
        role: ROLES[i],
        slot: i as u8,
    });
    let verify_mounted = |s: &SecurityStateStoreV2| {
        if s == mounted {
            Ok(())
        } else {
            Err(SecurityError::Conflict)
        }
    };
    let mut authority = match config {
        Some(verified) => {
            BootEpochAuthority::open_for_startup(&state, &boot, slots, verified, verify_mounted)?
        }
        None => BootEpochAuthority::open(&state, &boot, slots, verify_mounted)?,
    };
    if authority.confirmed_epoch().is_some() {
        return Err(SecurityError::Conflict);
    }
    let tx = BootEpochTx {
        superblock_raw: &sb_raw,
        first_log_block: FIRST_LOG_BLOCK,
        state_home: SECURITY_HOME,
        boot_home: BOOT_HOME,
        txid: next,
        commit_lsn: checkpoint
            .checkpoint_lsn
            .checked_add(4)
            .ok_or(SecurityError::Exhausted)?,
    };
    // SAFETY: one-shot CPU0 call (module header); the borrow ends on return.
    let pair = unsafe { &mut *core::ptr::addr_of_mut!(PAIR) };
    let confirmed = match config {
        Some(verified) => {
            let binding = authority.allocate_for_startup(disk, pair, tx, verified)?;
            // allocate replaced the workspace images with device readback.
            // Verify the signed startup identity before exposing its epoch.
            binding.verify_state(&SecurityStateStoreV2::decode(pair.state_image())?)?;
            binding.epoch()
        }
        None => authority.allocate(disk, pair, tx)?.epoch(),
    };
    if authority.confirmed_epoch() != Some(confirmed) || confirmed != next {
        return Err(SecurityError::Conflict);
    }
    // One boot epoch per boot: a retry must be fenced before any I/O.
    let before_retry = (disk.reads, disk.writes, disk.flushes);
    if authority.allocate(disk, pair, tx).err() != Some(SecurityError::Conflict)
        || (disk.reads, disk.writes, disk.flushes) != before_retry
    {
        return Err(SecurityError::Conflict);
    }
    Ok((confirmed, authority))
}

#[cfg(any(test, feature = "v020-production-diagnostic"))]
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

#[cfg(any(test, feature = "v020-production-diagnostic"))]
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
#[cfg(any(test, feature = "v020-production-diagnostic"))]
pub(super) fn admission_flow(boot_epoch: u64) -> Result<(), SecurityError> {
    // Negative on its own issuer/ledger: encapsulation still consumes a
    // context id and advances the holder generation, which would make the
    // positive run's authority facts stale if both shared one issuer.
    let mut issuer = AuthContextIssuerV1::new(boot_epoch)?;
    let mut ledger = AdmissionLedgerV1::new(boot_epoch)?;
    let forged = user_frame(0xdead_beef);
    if run_admission_flow(&mut issuer, &mut ledger, &input(&forged)) != Err(SecurityError::Invalid)
        || !ledger.is_empty()
    {
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
        FlowOutcome::Completed {
            step_three: StepThree::Execute,
            completion,
            ..
        } if completion == done && ledger.len() == 1 && ledger.inflight_count() == 0 => Ok(()),
        _ => Err(SecurityError::Conflict),
    }
}
