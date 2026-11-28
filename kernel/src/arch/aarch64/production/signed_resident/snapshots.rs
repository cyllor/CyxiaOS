//! Protected D2 endpoint for the signed resident Supervisor.

use super::super::{E_AUTH, EFAULT, copy_window::VerifiedSpan};
use super::{
    ConfirmedBootPolicy, NativeRoleManifest, ROLE_COUNT, RoleRecovery, SignedCaller, Task,
    media_staging, registered_role_abi, report_recovery,
};
use cyxia_kernel_core::{
    control_plane::{Identity, control_rpc_v1::Error as RpcError, role_manifest_v0199::Role},
    security::{
        Error,
        file_media_unified_v1::{
            SNAP_CONTROL_CACHE_KIB, SNAP_MAX_REPLY_BYTES, SNAP_MAX_REQUEST_BYTES, SUPER_BYTES,
        },
        file_mount_v1::MountedSnapshots,
        file_service_v4::{REPLY_HEADER, REQUEST_HEADER},
        snapshot_protection_tx_v1::freeze_set,
        snapshot_request_store_v1::RequestRecord,
        snapshot_service_v4::{FILE_REQ_KEY_BYTES, Operation, SnapshotRequest, encode_reply},
        startup_catalog_v0199::snapshot_authority::SnapshotAuthority,
    },
};

const FREEZE_WIRE_BYTES: usize = REQUEST_HEADER + FILE_REQ_KEY_BYTES + 16;

struct QueuedFreeze {
    bytes: [u8; FREEZE_WIRE_BYTES],
    selector: u64,
    actor: Identity,
    root: u64,
    index: usize,
}

struct Completion {
    digest: [u8; 32],
    result: Result<RequestRecord, Error>,
}

pub(super) struct SnapshotEndpoint {
    grant: SnapshotAuthority,
    endpoint: u64,
    file_generation: u64,
    reported: bool,
    pending: Option<QueuedFreeze>,
    completion: Option<Completion>,
}

const _: () = assert!(
    core::mem::size_of::<SnapshotEndpoint>() + core::mem::size_of::<MountedSnapshots>()
        <= SNAP_CONTROL_CACHE_KIB as usize * 1024
);

impl SnapshotEndpoint {
    pub(super) fn bind(
        grant: SnapshotAuthority,
        policy: &ConfirmedBootPolicy<'_>,
    ) -> Result<Self, Error> {
        Ok(Self {
            endpoint: grant.protection_endpoint(policy)?,
            file_generation: policy.file_service_generation()?,
            grant,
            reported: false,
            pending: None,
            completion: None,
        })
    }

    pub(super) fn startup_endpoint(&self, role: Role) -> u64 {
        if role == Role::Supervisor {
            self.endpoint
        } else {
            0
        }
    }

    pub(super) fn recognizes(endpoint: u64) -> bool {
        SnapshotAuthority::is_protection_endpoint(endpoint)
    }

    pub(super) fn dispatch(
        &mut self,
        caller: &SignedCaller,
        call: [u64; 6],
        policy: &ConfirmedBootPolicy<'_>,
    ) -> i64 {
        self.admit(caller, call, policy)
            .unwrap_or_else(|error| error)
    }

    fn admit(
        &mut self,
        caller: &SignedCaller,
        [endpoint, src, len, selector, dst, cap]: [u64; 6],
        policy: &ConfirmedBootPolicy<'_>,
    ) -> Result<i64, i64> {
        if !Self::recognizes(endpoint)
            || caller.member.role != Role::Supervisor
            || !caller.registered()
        {
            return Err(E_AUTH);
        }
        if policy.file_service_generation() != Ok(self.file_generation) {
            return Err(RpcError::Stale as i64);
        }
        let len = usize::try_from(len).map_err(|_| RpcError::Format as i64)?;
        if !(REQUEST_HEADER..=SNAP_MAX_REQUEST_BYTES).contains(&len) {
            return Err(RpcError::Format as i64);
        }
        let cap = usize::try_from(cap).map_err(|_| EFAULT)?;
        if !(REPLY_HEADER..=SNAP_MAX_REPLY_BYTES).contains(&cap) {
            return Err(EFAULT);
        }
        let input = VerifiedSpan::verify_signed(caller, src, len, false)?;
        let output = VerifiedSpan::verify_signed(caller, dst, cap, true)?;
        let src_end = src.checked_add(len as u64).ok_or(EFAULT)?;
        let dst_end = dst.checked_add(cap as u64).ok_or(EFAULT)?;
        if src < dst_end && dst < src_end {
            return Err(EFAULT);
        }
        let mut wire = [0; SNAP_MAX_REQUEST_BYTES];
        input.copy_in(&mut wire[..len])?;
        let request =
            SnapshotRequest::decode(&wire[..len], selector).map_err(|error| error.errno())?;
        if cap < request.reply_bound() {
            return Err(EFAULT);
        }
        let (binding, _) = self
            .grant
            .authorize_protection(policy, caller.member.actor, endpoint, selector, &request)
            .map_err(errno)?;
        if !self.reported {
            self.reported = true;
            report_recovery(
                "V020_G1_SNAPSHOT_PROTECTION_AUTH",
                policy.boot_epoch(),
                binding.service_generation,
                u64::from(request.op),
            );
        }
        if !matches!(request.operation, Operation::FreezeSet { .. }) {
            return Err(RpcError::Again as i64);
        }
        let digest = request.digest().map_err(errno)?;
        if let Some(done) = self
            .completion
            .as_ref()
            .filter(|done| done.digest == digest)
        {
            match done.result {
                Ok(receipt) => {
                    let mut response = [0; REPLY_HEADER + 16];
                    let length = encode_reply(
                        &request,
                        &receipt.reply(binding.service_generation, false),
                        &mut response,
                    )
                    .map_err(errno)?;
                    if !output.copy_out_and_check(&response[..length])? {
                        return Err(EFAULT);
                    }
                    return Ok(length as i64);
                }
                Err(error) => {
                    self.completion = None;
                    return Err(errno(error));
                }
            }
        }
        if self.pending.is_none() {
            self.pending = Some(QueuedFreeze {
                bytes: wire[..len]
                    .try_into()
                    .map_err(|_| RpcError::Format as i64)?,
                selector,
                actor: caller.member.actor,
                root: caller.root_asid(),
                index: caller.index,
            });
        }
        Err(RpcError::Again as i64)
    }

    pub(super) fn pending(&self) -> bool {
        self.pending.is_some()
    }

    pub(super) fn advance(
        &mut self,
        boot: &mut media_staging::SignedResidentBoot,
        manifest: &NativeRoleManifest,
        tasks: &[Task; ROLE_COUNT],
        checkpoint: &mut dyn FnMut() -> Result<(), Error>,
    ) -> Result<(), Error> {
        let Some(call) = self.pending.take() else {
            return Ok(());
        };
        checkpoint()?;
        let member = manifest.members[call.index];
        if !matches!(tasks[call.index].recovery, RoleRecovery::Live)
            || member.actor != call.actor
            || registered_role_abi(call.index, member, call.root).is_none()
        {
            return Err(Error::Stale);
        }
        let request =
            SnapshotRequest::decode(&call.bytes, call.selector).map_err(|_| Error::Invalid)?;
        let digest = request.digest()?;
        let (binding, grant) = self.grant.authorize_protection(
            &boot.policy()?,
            call.actor,
            self.endpoint,
            call.selector,
            &request,
        )?;
        let result = boot.with_runtime_writer(checkpoint, |writer, mount, _| {
            let mut pages = [[0; SUPER_BYTES]; 2];
            freeze_set(writer, mount, binding, grant, &request, &mut pages, |_| {
                Ok(())
            })
        });
        if let Ok(record) = result
            && record.state.terminal()
        {
            report_recovery(
                "V020_G1_SNAPSHOT_PROTECTION_TERMINAL",
                binding.boot_epoch,
                record.key.request_seq,
                record.commit_lsn,
            );
        }
        self.completion = Some(Completion { digest, result });
        Ok(())
    }
}

fn errno(error: Error) -> i64 {
    (match error {
        Error::Invalid => RpcError::Format,
        Error::Unauthorized => RpcError::Auth,
        Error::Stale => RpcError::Stale,
        Error::Conflict => RpcError::Conflict,
        Error::Capacity => RpcError::NoSpace,
        Error::Busy | Error::Exhausted => RpcError::Again,
        Error::Unknown => RpcError::Io,
    }) as i64
}
