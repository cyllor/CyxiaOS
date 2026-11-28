//! Frozen BootEpochStore v1 (§9.6) and atomic two-home startup redo.
//! The independently authenticated file owner supplies exact inode/extent
//! locations and exclusive transaction space. A single state block is not
//! a complete startup grant. Diagnostic media never become production
//! credentials merely because their CRC/FLUSH checks pass.
use super::{
    Error,
    durable_role_epoch_v0199::{
        Change, CommitEvidence, ConfirmedBootPolicy, DurableEpochGate, Outcome, PreparedEpoch,
        RedoPlacement, SlotBinding, StopEvidence,
    },
    epoch_redo_v0199::{EpochBlockIo, OneStateRedo, ServiceRestartAppend},
    file_index_v0199::SecurityStateStoreV2,
    file_media_v0199::{
        BLOCK_COUNT, DATA_START, SUPER_BYTES as BLOCK, SuperblockV1, crc32c_payload, crc32c_zeroed,
        verify_state_redo_v1,
    },
};
use crate::control_plane::role_manifest_v0199::ROLE_COUNT;
use sha2::{Digest, Sha256};
fn p16(b: &mut [u8], i: usize, v: u16) {
    b[i..i + 2].copy_from_slice(&v.to_le_bytes());
}
fn p32(b: &mut [u8], i: usize, v: u32) {
    b[i..i + 4].copy_from_slice(&v.to_le_bytes());
}
fn p64(b: &mut [u8], i: usize, v: u64) {
    b[i..i + 8].copy_from_slice(&v.to_le_bytes());
}
fn u32at(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(b[i..i + 4].try_into().unwrap())
}
fn u64at(b: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(b[i..i + 8].try_into().unwrap())
}
fn hash(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootEpochStoreV1 {
    pub fs_uuid: [u8; 16],
    pub boot_epoch: u64,
}
impl BootEpochStoreV1 {
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() != BLOCK
            || u32at(b, 0) != 0x43594245
            || b[4..6] != 1u16.to_le_bytes()
            || b[6..8] != 40u16.to_le_bytes()
            || u32at(b, 36) != 0
            || b[40..].iter().any(|&v| v != 0)
            || u32at(b, 32) != crc32c_zeroed(b, 32)?
        {
            return Err(Error::Invalid);
        }
        let v = Self {
            fs_uuid: b[8..24].try_into().unwrap(),
            boot_epoch: u64at(b, 24),
        };
        if v.fs_uuid == [0; 16] {
            return Err(Error::Invalid);
        }
        Ok(v)
    }
    pub fn encode(self) -> Result<[u8; BLOCK], Error> {
        if self.fs_uuid == [0; 16] {
            return Err(Error::Invalid);
        }
        let mut b = [0; BLOCK];
        p32(&mut b, 0, 0x43594245);
        p16(&mut b, 4, 1);
        p16(&mut b, 6, 40);
        b[8..24].copy_from_slice(&self.fs_uuid);
        p64(&mut b, 24, self.boot_epoch);
        let c = crc32c_zeroed(&b, 32)?;
        p32(&mut b, 32, c);
        Ok(b)
    }
    pub fn matches(self, state: &SecurityStateStoreV2) -> bool {
        self.fs_uuid == state.fs_uuid && self.boot_epoch == state.last_boot_epoch
    }
}
fn seal(b: &mut [u8], kind: u16, len: usize, txid: u64, epoch: u64, lsn: u64) -> Result<(), Error> {
    p32(b, 0, 0x43594c47);
    p16(b, 4, 1);
    p16(b, 6, kind);
    p32(b, 8, len as u32);
    p64(b, 16, txid);
    p64(b, 24, lsn);
    p64(b, 32, epoch);
    let c = crc32c_payload(&b[64..len]);
    p32(b, 12, c);
    let c = crc32c_zeroed(&b[..64], 56)?;
    p32(b, 56, c);
    Ok(())
}
/// Both canonical afterimages in one exact committed v1 transaction.
/// General log validation is shared with service-generation updates.
// Stable wide boot-pair verification API; regrouping arguments would change the public contract.
#[allow(clippy::too_many_arguments)]
pub fn verify_boot_pair(
    sb: SuperblockV1,
    first: u32,
    state_home: u32,
    boot_home: u32,
    begin: &[u8],
    redos: &[&[u8]],
    commit: &[u8],
    expected_state: &[u8],
    expected_boot: &[u8],
    txid: u64,
    commit_lsn: u64,
) -> Result<SecurityStateStoreV2, Error> {
    if redos.len() != 2
        || state_home == boot_home
        || !(DATA_START..BLOCK_COUNT).contains(&boot_home)
    {
        return Err(Error::Invalid);
    }
    let state = SecurityStateStoreV2::decode(expected_state)?;
    let boot = BootEpochStoreV1::decode(expected_boot)?;
    if !boot.matches(&state) || state.fs_uuid != sb.fs_uuid {
        return Err(Error::Conflict);
    }
    verify_state_redo_v1(
        sb,
        first,
        u64::from(state_home),
        begin,
        redos,
        commit,
        expected_state,
        txid,
        commit_lsn,
    )?;
    verify_state_redo_v1(
        sb,
        first,
        u64::from(boot_home),
        begin,
        redos,
        commit,
        expected_boot,
        txid,
        commit_lsn,
    )?;
    Ok(state)
}
/// 24 KiB explicitly preallocated progress workspace; no stack-sized copy
/// of the whole transaction. Ordered records occupy six log blocks.
pub struct BootPairRedo {
    pub begin: [u8; BLOCK],
    pub state_redo: [u8; 2 * BLOCK],
    pub boot_redo: [u8; 2 * BLOCK],
    pub commit: [u8; BLOCK],
}
impl Default for BootPairRedo {
    fn default() -> Self {
        Self::new()
    }
}
impl BootPairRedo {
    pub const fn new() -> Self {
        Self {
            begin: [0; BLOCK],
            state_redo: [0; 2 * BLOCK],
            boot_redo: [0; 2 * BLOCK],
            commit: [0; BLOCK],
        }
    }
    fn extent(first: u32) -> Result<(), Error> {
        if !(2..=4092).contains(&first) {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    pub fn read(&mut self, io: &mut impl EpochBlockIo, first: u32) -> Result<(), Error> {
        Self::extent(first)?;
        io.read(first, &mut self.begin)?;
        for (i, raw) in [&mut self.state_redo, &mut self.boot_redo]
            .into_iter()
            .enumerate()
        {
            let (a, b) = raw.split_at_mut(BLOCK);
            io.read(first + 1 + 2 * i as u32, a.try_into().unwrap())?;
            io.read(first + 2 + 2 * i as u32, b.try_into().unwrap())?;
        }
        io.read(first + 5, &mut self.commit)?;
        Ok(())
    }
    pub fn blank(&self) -> bool {
        self.begin
            .iter()
            .chain(self.state_redo.iter())
            .chain(self.boot_redo.iter())
            .chain(self.commit.iter())
            .all(|&v| v == 0)
    }

    fn prepared_blocks(&self) -> [&[u8; BLOCK]; 5] {
        [
            &self.begin,
            self.state_redo.first_chunk().unwrap(),
            self.state_redo.last_chunk().unwrap(),
            self.boot_redo.first_chunk().unwrap(),
            self.boot_redo.last_chunk().unwrap(),
        ]
    }

    fn encode_recovery_pair(
        &mut self,
        sb: SuperblockV1,
        first: u32,
        homes: [u32; 2],
        state: SecurityStateStoreV2,
    ) -> Result<(), Error> {
        Self::extent(first)?;
        if homes[0] == homes[1]
            || homes
                .iter()
                .any(|home| !(DATA_START..BLOCK_COUNT).contains(home))
            || state.fs_uuid != sb.fs_uuid
            || state.last_boot_epoch != sb.generation
        {
            return Err(Error::Conflict);
        }
        let boot = BootEpochStoreV1 {
            fs_uuid: state.fs_uuid,
            boot_epoch: state.last_boot_epoch,
        };
        self.encode(
            sb,
            homes[0],
            homes[1],
            state.last_boot_epoch,
            sb.checkpoint_lsn.checked_add(4).ok_or(Error::Exhausted)?,
            &state.encode()?,
            &boot.encode()?,
        )
    }

    /// Identify the materialized blocks of an exact preparation with an empty
    /// COMMIT block. Recovery must separately validate both old homes and the
    /// absence of later records under exclusive, reset-complete device ownership.
    pub fn verify_uncommitted_prefix(
        &mut self,
        io: &mut impl EpochBlockIo,
        sb: SuperblockV1,
        first: u32,
        homes: [u32; 2],
        expected_state: SecurityStateStoreV2,
    ) -> Result<u8, Error> {
        self.encode_recovery_pair(sb, first, homes, expected_state)?;
        let mut raw = [0; BLOCK];
        io.read(first + 5, &mut raw)?;
        if raw != [0; BLOCK] {
            return Err(Error::Conflict);
        }
        let mut present = 0;
        let mut missing = false;
        for (offset, expected) in self.prepared_blocks().into_iter().enumerate() {
            io.read(first + offset as u32, &mut raw)?;
            if raw == [0; BLOCK] {
                // A continuation may be canonically zero even after its write.
                missing |= expected != &[0; BLOCK];
            } else if missing || raw != *expected {
                return Err(Error::Conflict);
            } else {
                present |= 1 << offset;
            }
        }
        if present == 0 {
            return Err(Error::Conflict);
        }
        Ok(present)
    }

    /// With the successor checkpoint selected, recognize only zero blocks
    /// and exact blocks from its previously committed boot-only transaction.
    /// The caller must verify the selected checkpoint and all mounted homes
    /// before retiring this extent. This check never writes to the device.
    pub fn verify_checkpointed_residue(
        &mut self,
        io: &mut impl EpochBlockIo,
        prior: SuperblockV1,
        first: u32,
        homes: [u32; 2],
        state: SecurityStateStoreV2,
    ) -> Result<(), Error> {
        self.encode_recovery_pair(prior, first, homes, state)?;
        let mut raw = [0; BLOCK];
        let records = self.prepared_blocks().into_iter().chain([&self.commit]);
        for (offset, expected) in records.enumerate() {
            io.read(first + offset as u32, &mut raw)?;
            if raw != [0; BLOCK] && raw != *expected {
                return Err(Error::Conflict);
            }
        }
        Ok(())
    }
    pub fn state_image(&self) -> &[u8; BLOCK] {
        self.state_redo[64..4160].try_into().unwrap()
    }
    pub fn boot_image(&self) -> &[u8; BLOCK] {
        self.boot_redo[64..4160].try_into().unwrap()
    }
    pub fn verify(
        &self,
        sb: SuperblockV1,
        first: u32,
        state_home: u32,
        boot_home: u32,
        txid: u64,
        lsn: u64,
    ) -> Result<SecurityStateStoreV2, Error> {
        // Canonical encoder writes state then boot. Reject a reordered
        // otherwise valid chain for this exact startup transaction.
        verify_boot_pair(
            sb,
            first,
            state_home,
            boot_home,
            &self.begin,
            &[&self.state_redo, &self.boot_redo],
            &self.commit,
            self.state_image(),
            self.boot_image(),
            txid,
            lsn,
        )
    }
    // Stable wide boot-pair encoding API; regrouping arguments would change the public contract.
    #[allow(clippy::too_many_arguments)]
    fn encode(
        &mut self,
        sb: SuperblockV1,
        state_home: u32,
        boot_home: u32,
        txid: u64,
        lsn: u64,
        state: &[u8; BLOCK],
        boot: &[u8; BLOCK],
    ) -> Result<(), Error> {
        let start = lsn.checked_sub(3).ok_or(Error::Invalid)?;
        if start <= sb.checkpoint_lsn || txid == 0 {
            return Err(Error::Invalid);
        }
        self.begin.fill(0);
        p32(&mut self.begin, 64, 2);
        p64(&mut self.begin, 72, 8192);
        seal(&mut self.begin, 1, 80, txid, sb.log_epoch, start)?;
        let mut digest = Sha256::new();
        for (i, (home, raw, image)) in [
            (state_home, &mut self.state_redo, state),
            (boot_home, &mut self.boot_redo, boot),
        ]
        .into_iter()
        .enumerate()
        {
            raw.fill(0);
            p64(raw, 40, u64::from(home));
            p32(raw, 48, i as u32);
            p32(raw, 52, 2);
            raw[64..4160].copy_from_slice(image);
            digest.update(u64::from(home).to_le_bytes());
            digest.update(image);
            seal(raw, 2, 4160, txid, sb.log_epoch, start + 1 + i as u64)?;
        }
        self.commit.fill(0);
        p64(&mut self.commit, 64, txid);
        p64(&mut self.commit, 72, start);
        p64(&mut self.commit, 80, lsn - 1);
        p32(&mut self.commit, 88, 2);
        self.commit[96..128].copy_from_slice(&digest.finalize());
        seal(&mut self.commit, 3, 128, txid, sb.log_epoch, lsn)?;
        Ok(())
    }
    /// Append once to the authenticated owner's reserved, empty six-block extent.
    #[allow(clippy::too_many_arguments)]
    pub fn append_once(
        &mut self,
        io: &mut impl EpochBlockIo,
        gate: &mut DurableEpochGate,
        sb: SuperblockV1,
        first: u32,
        state_home: u32,
        boot_home: u32,
        txid: u64,
        lsn: u64,
        ticket: PreparedEpoch,
        verify_reserved_extent: impl FnOnce(&RedoPlacement) -> Result<(), Error>,
    ) -> Result<BootPairCommit, Error> {
        let state = gate.after_image(ticket)?;
        gate.claim_redo_once(
            ticket,
            RedoPlacement {
                fs_uuid: sb.fs_uuid,
                log_epoch: sb.log_epoch,
                first,
                state_home,
                boot_home: Some(boot_home),
                txid,
                commit_lsn: lsn,
            },
            verify_reserved_extent,
        )?;
        self.append(
            io, sb, first, state_home, boot_home, txid, lsn, ticket, &state,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn append(
        &mut self,
        io: &mut impl EpochBlockIo,
        sb: SuperblockV1,
        first: u32,
        state_home: u32,
        boot_home: u32,
        txid: u64,
        lsn: u64,
        ticket: PreparedEpoch,
        state: &[u8; BLOCK],
    ) -> Result<BootPairCommit, Error> {
        let decoded = SecurityStateStoreV2::decode(state)?;
        if !ticket.change.allocates_boot()
            || ticket.fs_uuid != sb.fs_uuid
            || decoded.fs_uuid != sb.fs_uuid
            || decoded.state_generation != ticket.new_state_generation
            || decoded.last_boot_epoch != ticket.target_boot_epoch
            || ticket.old_state_generation.checked_add(1) != Some(ticket.new_state_generation)
            || ticket.target_boot_epoch == 0
            || hash(state) != ticket.after_digest
        {
            return Err(Error::Conflict);
        }
        let boot = BootEpochStoreV1 {
            fs_uuid: sb.fs_uuid,
            boot_epoch: ticket.target_boot_epoch,
        }
        .encode()?;
        self.read(io, first)?;
        if !self.blank() {
            return Err(Error::Conflict);
        }
        self.encode(sb, state_home, boot_home, txid, lsn, state, &boot)?;
        self.verify(sb, first, state_home, boot_home, txid, lsn)?;
        for (offset, raw) in self.prepared_blocks().into_iter().enumerate() {
            io.write(first + offset as u32, raw)
                .map_err(|_| Error::Unknown)?;
        }
        io.flush().map_err(|_| Error::Unknown)?;
        io.write(first + 5, &self.commit)
            .map_err(|_| Error::Unknown)?;
        io.flush().map_err(|_| Error::Unknown)?;
        self.read(io, first).map_err(|_| Error::Unknown)?;
        self.verify(sb, first, state_home, boot_home, txid, lsn)
            .map_err(|_| Error::Unknown)?;
        if self.state_image() != state || self.boot_image() != &boot {
            return Err(Error::Unknown);
        }
        Ok(BootPairCommit {
            ticket,
            receipt: CommitEvidence {
                fs_uuid: sb.fs_uuid,
                log_epoch: sb.log_epoch,
                txid,
                commit_lsn: lsn,
                after_digest: hash(state),
            },
            boot_digest: hash(&boot),
        })
    }
}
pub struct BootPairCommit {
    ticket: PreparedEpoch,
    receipt: CommitEvidence,
    boot_digest: [u8; 32],
}
impl BootPairCommit {
    pub fn receipt(&self) -> CommitEvidence {
        self.receipt
    }
    pub fn verifies(
        &self,
        ticket: &PreparedEpoch,
        receipt: &CommitEvidence,
        boot: &[u8],
    ) -> Result<(), Error> {
        if self.ticket != *ticket || self.receipt != *receipt || hash(boot) != self.boot_digest {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Production boot-epoch authority — native-owner skeleton for T1 integration.
// ---------------------------------------------------------------------------

/// Exclusive transaction space and authenticated layout for ONE boot-epoch
/// allocation, supplied by the native file owner. This layer never invents
/// log extents, home blocks or transaction ids; it only consumes facts the
/// authenticated owner proves from real media.
#[derive(Clone, Copy)]
pub struct BootEpochTx<'a> {
    /// Raw current superblock; must decode to a valid [`SuperblockV1`].
    pub superblock_raw: &'a [u8],
    /// First block of the reserved EMPTY six-block log extent.
    pub first_log_block: u32,
    /// Paired protected home blocks (state, boot): distinct, in the data range.
    pub state_home: u32,
    pub boot_home: u32,
    /// Exclusive nonzero transaction id and commit LSN for this allocation.
    pub txid: u64,
    pub commit_lsn: u64,
}

/// A confirmed production boot epoch. Constructed ONLY after the paired
/// state+boot transaction passed append, ordered FLUSH, independent device
/// readback and `confirm_boot_from_redo`. Its trust is no stronger than the
/// protected [`EpochBlockIo`] adapter; a host test double is not native
/// persistence evidence. It is not, by itself, a capability grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootEpochGrant {
    epoch: u64,
    receipt: CommitEvidence,
    boot_digest: [u8; 32],
}
impl BootEpochGrant {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn receipt(&self) -> CommitEvidence {
        self.receipt
    }
    pub fn boot_digest(&self) -> [u8; 32] {
        self.boot_digest
    }
}

/// The identity shared by the signed policy, confirmed BootEpoch and exact
/// committed security state. Service authorization also checks the deployed
/// catalog, role identity and live task.
#[derive(Debug, Eq, PartialEq)]
pub struct StartupEpochBinding {
    grant: BootEpochGrant,
    config_digest: [u8; 32],
}

impl StartupEpochBinding {
    pub fn epoch(&self) -> u64 {
        self.grant.epoch()
    }

    pub fn verify_state(&self, state: &SecurityStateStoreV2) -> Result<(), Error> {
        let receipt = self.grant.receipt();
        if state.fs_uuid != receipt.fs_uuid
            || state.last_boot_epoch != self.epoch()
            || state.offline_config_hash != self.config_digest
            || hash(&state.encode()?) != receipt.after_digest
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}

/// Durable monotonic boot-epoch authority for the production boot path.
/// Wraps the paired-home [`DurableEpochGate`] custody and the atomic
/// [`BootPairRedo`] transaction so the production boot owner can allocate and
/// commit a boot epoch with a single call instead of orchestrating six wide
/// entry points. Serialized EL1 owner only; not a mount, not a capability
/// issuer, and it never writes a raw home block (the journal owner's
/// checkpoint/replay does that).
///
/// # Integration contract — how T1's production boot calls this
/// 1. Independently verify both superblocks, the committed redo chain, the
///    signed offline config and the mounted-volume identity (native owner;
///    never EL0 or a model). Recover/replay to the latest committed pair.
/// 2. Read the two committed protected home images (state, boot).
/// 3. Use [`BootEpochAuthority::open_for_startup`] with the exact signed config.
///    The storage callback must establish the actual mounted volume identity
///    and recovered commit chain.
/// 4. Reserve an EMPTY six-block log extent and an exclusive nonzero
///    txid/commit_lsn; build a [`BootEpochTx`] from the authenticated layout.
/// 5. Place a [`BootPairRedo`] workspace in the preallocated progress pool.
/// 6. [`BootEpochAuthority::allocate`]`(&mut io, &mut pair, tx)` returns a
///    [`BootEpochGrant`] ONLY on full durable evidence. Use `grant.epoch()` as
///    the durable boot epoch. The signed startup owner uses
///    [`BootEpochAuthority::allocate_for_startup`] before clearing startup.
/// 7. Fail-closed: on `Error::Unknown` do NOT retry under this authority — the
///    pending transition is preserved, no epoch is published, and the claimed
///    extent fences retries with `Error::Conflict`. Cold-recover from durable
///    evidence instead; generation continuity then allocates the next epoch
///    exactly once. One boot epoch per boot: a second `allocate` after a
///    confirmed grant returns `Error::Conflict`.
///
/// Honest scope: this is the native-authority API skeleton. Actual disk
/// persistence is exercised by T1's QEMU production boot (or a later wave);
/// the host tests below use an [`EpochBlockIo`] double, not native media.
pub struct BootEpochAuthority {
    gate: DurableEpochGate,
}
pub(super) mod tls_policy;
pub use tls_policy::{TlsBootPolicy, TlsBootTransition};

impl BootEpochAuthority {
    /// Reopen from the two committed protected home images. `verify_recovered`
    /// must be the native owner's real startup verification; see the type-level
    /// integration contract. A mismatched state/boot pair is rejected.
    pub fn open(
        state_raw: &[u8],
        boot_raw: &[u8],
        slots: [SlotBinding; ROLE_COUNT],
        verify_recovered: impl FnOnce(&SecurityStateStoreV2) -> Result<(), Error>,
    ) -> Result<Self, Error> {
        Ok(Self {
            gate: DurableEpochGate::recovered_pair(state_raw, boot_raw, slots, verify_recovered)?,
        })
    }

    /// Open the paired authority only after the signed configuration agrees
    /// with the decoded home and the caller authenticates the mounted volume.
    pub fn open_for_startup(
        state_raw: &[u8],
        boot_raw: &[u8],
        slots: [SlotBinding; ROLE_COUNT],
        config: &super::offline_config_v1::VerifiedOfflineConfig<'_>,
        verify_volume: impl FnOnce(&SecurityStateStoreV2) -> Result<(), Error>,
    ) -> Result<Self, Error> {
        Ok(Self {
            gate: DurableEpochGate::recovered_for_startup(
                state_raw,
                boot_raw,
                slots,
                config,
                verify_volume,
            )?,
        })
    }

    /// Recheck the signed policy against the durably confirmed pair.
    pub fn confirmed_config_boot(
        &self,
        config: &super::offline_config_v1::VerifiedOfflineConfig<'_>,
    ) -> Result<u64, Error> {
        self.gate.confirmed_config_boot(config)
    }

    /// Borrow the current signed policy and confirmed epoch for capability
    /// checks. The native owner separately authenticates its live role and
    /// object registries.
    pub fn confirmed_boot_policy(
        &self,
        config: &super::offline_config_v1::VerifiedOfflineConfig<'_>,
    ) -> Result<ConfirmedBootPolicy<'_>, Error> {
        self.gate.confirmed_boot_policy(config)
    }

    pub fn confirmed_running_policy(
        &self,
        config: &super::offline_config_v1::VerifiedOfflineConfig<'_>,
    ) -> Result<ConfirmedBootPolicy<'_>, Error> {
        self.gate.confirmed_running_policy(config)
    }

    pub fn prepare_role_restart(
        &mut self,
        log: &mut OneStateRedo,
        superblock: SuperblockV1,
        placement: RedoPlacement,
        config: &super::offline_config_v1::VerifiedOfflineConfig<'_>,
        stop: StopEvidence,
        verify_stop: impl FnOnce(StopEvidence) -> Result<(), Error>,
    ) -> Result<ServiceRestartAppend, Error> {
        self.gate.confirmed_config_boot(config)?;
        log.prepare_restart(&mut self.gate, superblock, placement, stop, verify_stop)
    }

    pub fn step_role_restart(
        &mut self,
        io: &mut impl EpochBlockIo,
        log: &OneStateRedo,
        work: &mut ServiceRestartAppend,
        superblock_raw: &[u8; BLOCK],
        scratch: &mut [u8; BLOCK],
    ) -> Result<Option<Outcome>, Error> {
        log.step_restart(io, &mut self.gate, work, superblock_raw, scratch)
    }

    /// The confirmed boot epoch, if a paired transaction was fully confirmed
    /// and no newer transition fences it. `None` before confirmation and while
    /// an uncertain commit is pending.
    pub fn confirmed_epoch(&self) -> Option<u64> {
        self.gate.boot_epoch()
    }

    /// Verify the signed startup authority before attempting journal I/O,
    /// then bind the committed pair to the same policy after device readback.
    pub fn allocate_for_startup(
        &mut self,
        io: &mut impl EpochBlockIo,
        pair: &mut BootPairRedo,
        tx: BootEpochTx<'_>,
        config: &super::offline_config_v1::VerifiedOfflineConfig<'_>,
    ) -> Result<StartupEpochBinding, Error> {
        self.gate.verify_startup_config(config)?;
        let grant = self.allocate(io, pair, tx)?;
        self.bind_startup_grant(grant, config)
    }

    /// Change the TLS installation and allocate BootEpoch in the same
    /// paired redo append. The authenticated old config was opened from
    /// the actual mounted predecessor and no old role has run in this boot.
    pub fn allocate_tls_boot(
        &mut self,
        io: &mut impl EpochBlockIo,
        pair: &mut BootPairRedo,
        tx: BootEpochTx<'_>,
        transition: TlsBootTransition<'_>,
    ) -> Result<StartupEpochBinding, Error> {
        self.gate
            .verify_startup_config(transition.previous().config())?;
        let ticket = self.gate.prepare_tls_boot(transition)?;
        let grant = self.append_prepared(io, pair, tx, ticket)?;
        self.bind_startup_grant(grant, transition.current().config())
    }

    /// Apply the exact manifest state, including durable revocation,
    /// to an unchanged authorized boot. Opaque legacy catalogs grant
    /// no deployment TLS authority through this entry.
    pub fn allocate_with_tls_policy(
        &mut self,
        io: &mut impl EpochBlockIo,
        pair: &mut BootPairRedo,
        tx: BootEpochTx<'_>,
        policy: TlsBootPolicy<'_>,
    ) -> Result<StartupEpochBinding, Error> {
        self.gate.bind_tls_startup(policy)?;
        self.allocate_for_startup(io, pair, tx, policy.config())
    }

    fn bind_startup_grant(
        &self,
        grant: BootEpochGrant,
        config: &super::offline_config_v1::VerifiedOfflineConfig<'_>,
    ) -> Result<StartupEpochBinding, Error> {
        let policy = self.confirmed_boot_policy(config)?;
        if policy.boot_epoch() != grant.epoch() {
            return Err(Error::Conflict);
        }
        Ok(StartupEpochBinding {
            grant,
            config_digest: policy.config_digest(),
        })
    }

    /// Allocate and durably commit the next monotonic boot epoch in one call:
    /// prepare → exact after-image → paired BEGIN/REDO/COMMIT append with
    /// ordered FLUSH + independent readback → `confirm_boot_from_redo`.
    /// Returns a grant ONLY on full evidence; see the type-level fail-closed /
    /// no-retry rule for `Error::Unknown`.
    pub fn allocate(
        &mut self,
        io: &mut impl EpochBlockIo,
        pair: &mut BootPairRedo,
        tx: BootEpochTx<'_>,
    ) -> Result<BootEpochGrant, Error> {
        // One boot epoch per boot: once this boot has a confirmed epoch, a
        // further allocation is a conflict, never a second monotonic bump.
        if self.gate.boot_epoch().is_some() {
            return Err(Error::Conflict);
        }
        // Boot allocation never authorizes a service stop/restart.
        let ticket = self
            .gate
            .prepare(Change::AllocateBoot, |_| Err(Error::Unauthorized))?;
        self.append_prepared(io, pair, tx, ticket)
    }

    fn append_prepared(
        &mut self,
        io: &mut impl EpochBlockIo,
        pair: &mut BootPairRedo,
        tx: BootEpochTx<'_>,
        ticket: PreparedEpoch,
    ) -> Result<BootEpochGrant, Error> {
        let sb = SuperblockV1::decode(tx.superblock_raw)?;
        // The mounted-volume owner supplies the authenticated reservation in tx.
        // The append checks the empty extent against the device before writing.
        let proof = pair
            .append_once(
                io,
                &mut self.gate,
                sb,
                tx.first_log_block,
                tx.state_home,
                tx.boot_home,
                tx.txid,
                tx.commit_lsn,
                ticket,
                |placement| {
                    if placement.commit_lsn - 3 <= sb.checkpoint_lsn {
                        return Err(Error::Invalid);
                    }
                    Ok(())
                },
            )
            .map_err(|error| match error {
                Error::Busy => Error::Conflict,
                other => other,
            })?;
        let receipt = proof.receipt();
        let outcome = self.gate.confirm_boot_from_redo(
            ticket,
            receipt,
            pair.state_image(),
            pair.boot_image(),
            tx.superblock_raw,
            tx.first_log_block,
            tx.state_home,
            tx.boot_home,
            &pair.begin,
            &[&pair.state_redo, &pair.boot_redo],
            &pair.commit,
            |t, r, b| proof.verifies(t, r, b),
        )?;
        let epoch = match outcome {
            Outcome::Boot { epoch } => epoch,
            _ => return Err(Error::Conflict),
        };
        Ok(BootEpochGrant {
            epoch,
            receipt,
            boot_digest: hash(pair.boot_image()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paired_gate_requires_both_exact_committed_homes_and_keeps_unknown() {
        use super::super::durable_role_epoch_v0199::{DurableEpochGate, Outcome, SlotBinding};
        use crate::control_plane::role_manifest_v0199::ROLES;
        struct Disk {
            log: [[u8; BLOCK]; 6],
            writes: u32,
            flushes: u32,
            fail_second: bool,
        }
        impl EpochBlockIo for Disk {
            fn read(&mut self, b: u32, out: &mut [u8; BLOCK]) -> Result<(), Error> {
                *out = self.log[(b - 2) as usize];
                Ok(())
            }
            fn write(&mut self, b: u32, data: &[u8; BLOCK]) -> Result<(), Error> {
                self.log[(b - 2) as usize] = *data;
                self.writes += 1;
                Ok(())
            }
            fn flush(&mut self) -> Result<(), Error> {
                self.flushes += 1;
                if self.fail_second && self.flushes == 2 {
                    return Err(Error::Unknown);
                }
                Ok(())
            }
        }
        let state = SecurityStateStoreV2 {
            fs_uuid: [1; 16],
            state_generation: 1,
            rule_min_generation: 1,
            security_min_generation: 1,
            key_generation: 1,
            isolated_service_bitmap: 0,
            last_boot_epoch: 0,
            offline_config_generation: 1,
            offline_config_hash: [2; 32],
            service_generations: [1; 16],
        }
        .encode()
        .unwrap();
        let boot = BootEpochStoreV1 {
            fs_uuid: [1; 16],
            boot_epoch: 0,
        }
        .encode()
        .unwrap();
        let wrong = BootEpochStoreV1 {
            fs_uuid: [1; 16],
            boot_epoch: 1,
        }
        .encode()
        .unwrap();
        let slots = core::array::from_fn(|i| SlotBinding {
            role: ROLES[i],
            slot: i as u8,
        });
        assert!(matches!(
            DurableEpochGate::recovered_pair(&state, &wrong, slots, |_| panic!()),
            Err(Error::Conflict)
        ));
        let mut gate = DurableEpochGate::recovered_pair(&state, &boot, slots, |_| Ok(())).unwrap();
        let ticket = gate.prepare(Change::AllocateBoot, |_| panic!()).unwrap();
        let mut pair = BootPairRedo::new();
        let sb = SuperblockV1 {
            fs_uuid: [1; 16],
            generation: 1,
            checkpoint_lsn: 0,
            log_epoch: 1,
        };
        let mut disk = Disk {
            log: [[0; BLOCK]; 6],
            writes: 0,
            flushes: 0,
            fail_second: true,
        };
        assert!(matches!(
            pair.append_once(
                &mut disk,
                &mut gate,
                sb,
                2,
                7000,
                7002,
                1,
                4,
                ticket,
                |_| Ok(())
            ),
            Err(Error::Unknown)
        ));
        assert_eq!(gate.boot_epoch(), None);
        assert_eq!((disk.writes, disk.flushes), (6, 2));
        assert!(matches!(
            pair.append_once(
                &mut disk,
                &mut gate,
                sb,
                2,
                7000,
                7002,
                1,
                4,
                ticket,
                |_| panic!()
            ),
            Err(Error::Busy)
        ));
        // Separate successful native-owner fixture. Do not retry the
        // ambiguous transaction on another device under the old gate.
        let mut gate = DurableEpochGate::recovered_pair(&state, &boot, slots, |_| Ok(())).unwrap();
        let ticket = gate.prepare(Change::AllocateBoot, |_| panic!()).unwrap();
        let image = gate.after_image(ticket).unwrap();
        let mut disk = Disk {
            log: [[0; BLOCK]; 6],
            writes: 0,
            flushes: 0,
            fail_second: false,
        };
        let proof = pair
            .append_once(
                &mut disk,
                &mut gate,
                sb,
                2,
                7000,
                7002,
                1,
                4,
                ticket,
                |_| Ok(()),
            )
            .unwrap();
        let receipt = proof.receipt();
        assert_eq!(
            gate.confirm(ticket, receipt, &image, |_, _| panic!()),
            Err(Error::Unauthorized)
        );
        let mut super_raw = [0; BLOCK];
        p32(&mut super_raw, 0, 0x43594653);
        p16(&mut super_raw, 4, 1);
        p16(&mut super_raw, 6, 80);
        p32(&mut super_raw, 8, 4096);
        p32(&mut super_raw, 12, 131072);
        super_raw[16..32].fill(1);
        p64(&mut super_raw, 32, 1);
        p64(&mut super_raw, 48, 1);
        p32(&mut super_raw, 56, 4098);
        p32(&mut super_raw, 60, 4102);
        p32(&mut super_raw, 64, 4118);
        p32(&mut super_raw, 68, 256);
        let crc = crc32c_zeroed(&super_raw, 76).unwrap();
        p32(&mut super_raw, 76, crc);
        assert_eq!(
            gate.confirm_boot_from_redo(
                ticket,
                receipt,
                pair.state_image(),
                &boot,
                &super_raw,
                2,
                7000,
                7002,
                &pair.begin,
                &[&pair.state_redo, &pair.boot_redo],
                &pair.commit,
                |_, _, _| panic!()
            ),
            Err(Error::Conflict)
        );
        assert_eq!(
            gate.confirm_boot_from_redo(
                ticket,
                receipt,
                pair.state_image(),
                pair.boot_image(),
                &super_raw,
                2,
                7000,
                7002,
                &pair.begin,
                &[&pair.state_redo, &pair.boot_redo],
                &pair.commit,
                |t, r, b| proof.verifies(t, r, b)
            ),
            Ok(Outcome::Boot { epoch: 1 })
        );
        assert_eq!(gate.boot_epoch(), Some(1));
    }
    #[test]
    fn exact_boot_epoch_store_roundtrip_and_crc_reserved_rejection() {
        let s = BootEpochStoreV1 {
            fs_uuid: [1; 16],
            boot_epoch: 42,
        };
        let b = s.encode().unwrap();
        assert_eq!(BootEpochStoreV1::decode(&b), Ok(s));
        let mut bad = b;
        bad[24] ^= 1;
        assert!(BootEpochStoreV1::decode(&bad).is_err());
        let mut bad = b;
        bad[4095] = 1;
        let c = crc32c_zeroed(&bad, 32).unwrap();
        p32(&mut bad, 32, c);
        assert!(BootEpochStoreV1::decode(&bad).is_err());
    }

    // ---- Production boot-epoch authority (native-owner skeleton) ----
    // These host tests use an EpochBlockIo double, NOT native media. Actual
    // disk persistence is exercised by T1's QEMU production boot / later wave.
    use crate::control_plane::role_manifest_v0199::ROLES;

    struct ProdDisk {
        blocks: [[u8; BLOCK]; 16],
        flushes: u32,
        fail_second_flush: bool,
    }
    impl EpochBlockIo for ProdDisk {
        fn read(&mut self, b: u32, out: &mut [u8; BLOCK]) -> Result<(), Error> {
            *out = self.blocks[b as usize];
            Ok(())
        }
        fn write(&mut self, b: u32, data: &[u8; BLOCK]) -> Result<(), Error> {
            self.blocks[b as usize] = *data;
            Ok(())
        }
        fn flush(&mut self) -> Result<(), Error> {
            self.flushes += 1;
            if self.fail_second_flush && self.flushes == 2 {
                return Err(Error::Unknown);
            }
            Ok(())
        }
    }
    fn prod_disk(fail: bool) -> ProdDisk {
        ProdDisk {
            blocks: [[0; BLOCK]; 16],
            flushes: 0,
            fail_second_flush: fail,
        }
    }
    fn prod_slots() -> [SlotBinding; ROLE_COUNT] {
        core::array::from_fn(|i| SlotBinding {
            role: ROLES[i],
            slot: i as u8,
        })
    }
    fn prod_state(uuid: [u8; 16], generation: u64, epoch: u64) -> [u8; BLOCK] {
        SecurityStateStoreV2 {
            fs_uuid: uuid,
            state_generation: generation,
            rule_min_generation: 1,
            security_min_generation: 1,
            key_generation: 1,
            isolated_service_bitmap: 0,
            last_boot_epoch: epoch,
            offline_config_generation: 1,
            offline_config_hash: [2; 32],
            service_generations: [1; 16],
        }
        .encode()
        .unwrap()
    }
    fn prod_boot(uuid: [u8; 16], epoch: u64) -> [u8; BLOCK] {
        BootEpochStoreV1 {
            fs_uuid: uuid,
            boot_epoch: epoch,
        }
        .encode()
        .unwrap()
    }
    fn prod_sb_raw(uuid: [u8; 16]) -> [u8; BLOCK] {
        let mut b = [0; BLOCK];
        p32(&mut b, 0, 0x43594653);
        p16(&mut b, 4, 1);
        p16(&mut b, 6, 80);
        p32(&mut b, 8, 4096);
        p32(&mut b, 12, 131072);
        b[16..32].copy_from_slice(&uuid);
        p64(&mut b, 32, 1);
        p64(&mut b, 40, 0);
        p64(&mut b, 48, 1);
        p32(&mut b, 56, 4098);
        p32(&mut b, 60, 4102);
        p32(&mut b, 64, 4118);
        p32(&mut b, 68, 256);
        let crc = crc32c_zeroed(&b, 76).unwrap();
        p32(&mut b, 76, crc);
        b
    }
    fn prod_tx(sb_raw: &[u8], first: u32, txid: u64, lsn: u64) -> BootEpochTx<'_> {
        BootEpochTx {
            superblock_raw: sb_raw,
            first_log_block: first,
            state_home: 7000,
            boot_home: 7002,
            txid,
            commit_lsn: lsn,
        }
    }

    #[test]
    fn production_boot_epoch_monotonic_across_simulated_reboots() {
        let uuid = [1; 16];
        let state_raw = prod_state(uuid, 7, 5);
        let boot_raw = prod_boot(uuid, 5);
        let sb_raw = prod_sb_raw(uuid);
        let sb = SuperblockV1::decode(&sb_raw).unwrap();
        let mut disk = prod_disk(false);
        let mut auth =
            BootEpochAuthority::open(&state_raw, &boot_raw, prod_slots(), |_| Ok(())).unwrap();
        assert_eq!(auth.confirmed_epoch(), None);
        let mut pair = BootPairRedo::new();
        let g1 = auth
            .allocate(&mut disk, &mut pair, prod_tx(&sb_raw, 2, 1, 4))
            .unwrap();
        assert_eq!(g1.epoch(), 6);
        assert_eq!(auth.confirmed_epoch(), Some(6));
        assert_eq!(g1.receipt().txid, 1);
        assert_eq!(g1.receipt().commit_lsn, 4);
        assert_eq!(g1.boot_digest(), hash(pair.boot_image()));
        // One boot epoch per boot: a second allocation is refused.
        let mut pair_b = BootPairRedo::new();
        assert_eq!(
            auth.allocate(&mut disk, &mut pair_b, prod_tx(&sb_raw, 8, 3, 11)),
            Err(Error::Conflict)
        );

        // Simulate a cold reboot: recover the committed pair from durable log
        // evidence (the committed after-image IS the recovered state), then
        // reopen a fresh authority and allocate the next epoch exactly once.
        let mut rec = BootPairRedo::new();
        rec.read(&mut disk, 2).unwrap();
        let recovered = rec.verify(sb, 2, 7000, 7002, 1, 4).unwrap();
        assert_eq!(recovered.last_boot_epoch, 6);
        assert_eq!(recovered.state_generation, 8);
        let mut next = BootEpochAuthority::open(
            rec.state_image(),
            rec.boot_image(),
            prod_slots(),
            |_| Ok(()),
        )
        .unwrap();
        let mut pair2 = BootPairRedo::new();
        let g2 = next
            .allocate(&mut disk, &mut pair2, prod_tx(&sb_raw, 8, 3, 11))
            .unwrap();
        assert_eq!(g2.epoch(), 7);
        assert!(g2.epoch() > g1.epoch());
        // Generation continuity: state_generation advances, never rolls back.
        let mut rec2 = BootPairRedo::new();
        rec2.read(&mut disk, 8).unwrap();
        let recovered2 = rec2.verify(sb, 8, 7000, 7002, 3, 11).unwrap();
        assert_eq!(recovered2.last_boot_epoch, 7);
        assert_eq!(recovered2.state_generation, 9);
    }

    #[test]
    fn tls_boot_borrows_the_confirmed_signed_pair_and_exact_installation() {
        use super::super::{
            network::TlsInstallation,
            offline_config_v1::{CatalogBindings, VerifiedOfflineConfig},
        };

        const UUID: [u8; 16] = *b"CYX-W11-STAGING!";
        const WIRE: &[u8] = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/v020-signed-scratch/config.bin"
        ));
        const BOOT_KEY: [u8; 32] = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];
        let catalogue = CatalogBindings {
            rule_generation: 1,
            security_generation: 1,
            key_generation: 1,
            rule_hash: hash(b"scratch/test/rules/1"),
            security_hash: hash(b"scratch/test/security/1"),
            key_manifest_hash: hash(b"scratch/test/keys/1"),
        };
        let config = VerifiedOfflineConfig::verify(
            WIRE,
            &BOOT_KEY,
            catalogue,
            &mut [0; 1024],
            |_, _, lists| {
                if lists == [0; 12] {
                    Ok(())
                } else {
                    Err(Error::Unauthorized)
                }
            },
        )
        .unwrap();
        let mut state = SecurityStateStoreV2::decode(&prod_state(UUID, 7, 5)).unwrap();
        state.offline_config_hash = config.digest();
        let boot = prod_boot(UUID, 5);
        let sb = prod_sb_raw(UUID);
        let installation = TlsInstallation {
            verifier_generation: 1,
            signer_generation: 1,
            key_generation: 1,
            key_manifest_hash: catalogue.key_manifest_hash,
        };
        let authorize =
            |state: SecurityStateStoreV2, slots, installation: TlsInstallation, fail| {
                let mut owner = BootEpochAuthority::open_for_startup(
                    &state.encode()?,
                    &boot,
                    slots,
                    &config,
                    |mounted| {
                        assert_eq!(mounted, &state);
                        Ok(())
                    },
                )?;
                assert!(owner.confirmed_boot_policy(&config).is_err());
                let mut pair = BootPairRedo::new();
                let result = owner.allocate_for_startup(
                    &mut prod_disk(fail),
                    &mut pair,
                    prod_tx(&sb, 2, 1, 4),
                    &config,
                );
                if result.is_err() {
                    assert!(owner.confirmed_boot_policy(&config).is_err());
                }
                result?;
                let authority = installation.authorize(owner.confirmed_boot_policy(&config)?)?;
                Ok(authority.boot_epoch())
            };
        assert_eq!(authorize(state, prod_slots(), installation, false), Ok(6));
        assert_eq!(
            authorize(state, prod_slots(), installation, true),
            Err(Error::Unknown)
        );
        let mut overlapping = prod_slots();
        overlapping[0].slot = 12;
        assert_eq!(
            authorize(state, overlapping, installation, false),
            Err(Error::Conflict)
        );
        for slot in [12, 13] {
            let mut isolated = state;
            isolated.isolated_service_bitmap = 1 << slot;
            assert_eq!(
                authorize(isolated, prod_slots(), installation, false),
                Err(Error::Unauthorized)
            );
            let mut advanced = state;
            advanced.service_generations[slot] += 1;
            assert_eq!(
                authorize(advanced, prod_slots(), installation, false),
                Err(Error::Stale)
            );
        }
        let wrong_key = TlsInstallation {
            key_generation: 2,
            ..installation
        };
        assert_eq!(
            authorize(state, prod_slots(), wrong_key, false),
            Err(Error::Stale)
        );
        let wrong_catalogue = TlsInstallation {
            key_manifest_hash: [3; 32],
            ..installation
        };
        assert_eq!(
            authorize(state, prod_slots(), wrong_catalogue, false),
            Err(Error::Unauthorized)
        );
        let mut different_config = state;
        different_config.offline_config_hash = [9; 32];
        assert_eq!(
            authorize(different_config, prod_slots(), installation, false),
            Err(Error::Conflict)
        );
    }

    #[test]
    fn production_boot_epoch_fail_closed_on_uncertain_commit() {
        let uuid = [1; 16];
        let state_raw = prod_state(uuid, 7, 5);
        let boot_raw = prod_boot(uuid, 5);
        let sb_raw = prod_sb_raw(uuid);
        let mut disk = prod_disk(true);
        let mut auth =
            BootEpochAuthority::open(&state_raw, &boot_raw, prod_slots(), |_| Ok(())).unwrap();
        let mut pair = BootPairRedo::new();
        let tx = prod_tx(&sb_raw, 2, 1, 4);
        assert_eq!(auth.allocate(&mut disk, &mut pair, tx), Err(Error::Unknown));
        assert_eq!(auth.confirmed_epoch(), None);
        // The claim fences retry on both the original and a different extent.
        assert_eq!(
            auth.allocate(&mut disk, &mut pair, tx),
            Err(Error::Conflict)
        );
        assert_eq!(
            auth.allocate(&mut disk, &mut pair, prod_tx(&sb_raw, 8, 2, 8)),
            Err(Error::Conflict)
        );
        assert_eq!(disk.flushes, 2);
        assert!(disk.blocks[8..14].iter().flatten().all(|&byte| byte == 0));
        assert_eq!(auth.confirmed_epoch(), None);
        // The uncertain commit did not burn the epoch globally: a clean cold
        // recovery from the original committed image allocates epoch 6 once.
        let mut clean = prod_disk(false);
        let mut fresh =
            BootEpochAuthority::open(&state_raw, &boot_raw, prod_slots(), |_| Ok(())).unwrap();
        let mut p = BootPairRedo::new();
        let g = fresh.allocate(&mut clean, &mut p, tx).unwrap();
        assert_eq!(g.epoch(), 6);
    }

    #[test]
    fn production_boot_epoch_rejects_bad_layout_and_identity() {
        let uuid = [1; 16];
        let state_raw = prod_state(uuid, 7, 5);
        let boot_raw = prod_boot(uuid, 5);
        let sb_raw = prod_sb_raw(uuid);
        // Same home for state and boot is not a paired transaction.
        let mut disk = prod_disk(false);
        let mut auth =
            BootEpochAuthority::open(&state_raw, &boot_raw, prod_slots(), |_| Ok(())).unwrap();
        let mut pair = BootPairRedo::new();
        let same_home = BootEpochTx {
            state_home: 7000,
            boot_home: 7000,
            ..prod_tx(&sb_raw, 2, 1, 4)
        };
        assert!(auth.allocate(&mut disk, &mut pair, same_home).is_err());
        // Mismatched superblock UUID is a conflict, before any write.
        let mut auth =
            BootEpochAuthority::open(&state_raw, &boot_raw, prod_slots(), |_| Ok(())).unwrap();
        let other_sb = prod_sb_raw([9; 16]);
        assert!(
            auth.allocate(&mut disk, &mut pair, prod_tx(&other_sb, 2, 1, 4))
                .is_err()
        );
        // A non-empty (dirty) log extent is refused.
        let mut dirty = prod_disk(false);
        dirty.blocks[2][0] = 1;
        let mut auth =
            BootEpochAuthority::open(&state_raw, &boot_raw, prod_slots(), |_| Ok(())).unwrap();
        assert_eq!(
            auth.allocate(&mut dirty, &mut pair, prod_tx(&sb_raw, 2, 1, 4)),
            Err(Error::Conflict)
        );
        // Boot home outside the data range is rejected.
        let mut auth =
            BootEpochAuthority::open(&state_raw, &boot_raw, prod_slots(), |_| Ok(())).unwrap();
        let bad_home = BootEpochTx {
            boot_home: 100,
            ..prod_tx(&sb_raw, 2, 1, 4)
        };
        assert!(auth.allocate(&mut disk, &mut pair, bad_home).is_err());
    }
}
