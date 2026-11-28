//! Detached D2 snapshot authority for a signed canonical unified volume.
//!
//! The recovery slot is shared durable request custody. RESTORE belongs to
//! the EL1 recovery owner, while PROTECTION belongs to the signed Supervisor.
//! Effect verification and write admission belong to the transaction owner.

use super::{
    Error, LifecyclePackageDigest, PinnedStartupCatalog, VerifiedOfflineConfig, file_volume,
    lifecycle_package_message, verify_startup_signature,
};
use crate::control_plane::{
    Identity,
    role_manifest_v0199::{ROLE_COUNT, Role},
};
use crate::security::{
    durable_role_epoch_v0199::ConfirmedBootPolicy,
    file_media_unified_v1::{SNAP_CAP_PROTECTION, SNAP_CAP_RESTORE, SnapshotEnrollment},
    file_mount_v1::MountEvidence,
    offline_config_v1::Principal,
    snapshot_service_v4::{CallBinding, RECOVERY_SLOT, SnapshotGrant, SnapshotRequest},
};
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = b"CYXSNA01";
const LABEL: &[u8] = b"CYX/STARTUP-SNAPSHOT-AUTHORITY/v1";
pub const BYTES: usize = 56;
const MESSAGE_BYTES: usize = LABEL.len() + 32 + 32 + BYTES;
const EL1: u64 = 1;
const EPOCH_STRIDE: u64 = 1 << 16;
const PROTECTION_ENDPOINT: u64 = 0x5301;
const PROTECTION_SELECTOR: u64 = 0x5302;
const RECOVERY_ENDPOINT: u64 = 0x5303;
const RECOVERY_SELECTOR: u64 = 0x5304;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotAuthority {
    config_digest: [u8; 32],
    volume: [u8; 16],
    recovery_principal: Principal,
}

impl SnapshotAuthority {
    pub fn verify(
        catalog: &PinnedStartupCatalog<'_>,
        config: &VerifiedOfflineConfig<'_>,
        roster: [LifecyclePackageDigest; ROLE_COUNT],
        file_volume: &[u8; file_volume::BYTES],
        wire: &[u8; BYTES],
        signature: &[u8; 64],
    ) -> Result<Self, Error> {
        if catalog.offline_config != config.wire() {
            return Err(Error::Conflict);
        }
        let config_digest = config.digest();
        verify_startup_signature(
            catalog.boot_public_key,
            signature,
            &message(config_digest, roster, file_volume, wire),
        )?;
        let volume = config.header().fs_uuid;
        let recovery_principal = config.principals()[RECOVERY_SLOT as usize];
        if *wire != encoding(volume, recovery_principal) || file_volume[8..24] != volume {
            return Err(Error::Unauthorized);
        }
        Ok(Self {
            config_digest,
            volume,
            recovery_principal,
        })
    }

    pub fn protection_endpoint(self, policy: &ConfirmedBootPolicy<'_>) -> Result<u64, Error> {
        self.check_policy(policy)?;
        tagged(policy.boot_epoch(), PROTECTION_ENDPOINT)
    }

    pub const fn is_protection_endpoint(endpoint: u64) -> bool {
        endpoint % EPOCH_STRIDE == PROTECTION_ENDPOINT
    }

    /// Narrow replay qualification. Live holder and generation checks are
    /// separate from validating historical redo under the same signed policy.
    pub fn replay_principal(self, config: &VerifiedOfflineConfig<'_>) -> Result<Principal, Error> {
        if config.digest() != self.config_digest
            || config.header().fs_uuid != self.volume
            || config.principals()[RECOVERY_SLOT as usize] != self.recovery_principal
        {
            return Err(Error::Stale);
        }
        Ok(self.recovery_principal)
    }

    /// Recheck the durable role and file service generation inside this
    /// syscall's paid turn, with the caller derived by the native trap owner.
    pub fn authorize_protection(
        self,
        policy: &ConfirmedBootPolicy<'_>,
        holder: Identity,
        endpoint: u64,
        selector: u64,
        request: &SnapshotRequest<'_>,
    ) -> Result<(CallBinding, SnapshotGrant), Error> {
        self.check_policy(policy)?;
        self.protection_grant(
            CallBinding {
                holder,
                boot_epoch: policy.boot_epoch(),
                service_generation: policy.file_service_generation()?,
                endpoint,
                selector,
                fs_uuid: self.volume,
            },
            policy.service_generation(Role::Supervisor)?,
            request,
        )
    }

    /// EL1 recovery holds the verified mounted state in the exclusive media
    /// owner. This entry is internal and is never selected by a user SVC.
    pub fn authorize_restore(
        self,
        policy: &ConfirmedBootPolicy<'_>,
        mount: &MountEvidence,
        request: &SnapshotRequest<'_>,
    ) -> Result<(CallBinding, SnapshotGrant), Error> {
        self.check_policy(policy)?;
        if mount.snapshot.is_none()
            || mount.boot.fs_uuid != self.volume
            || mount.boot.boot_epoch != policy.boot_epoch()
            || !mount.boot.matches(&mount.security)
            || !policy.matches_mounted_security(&mount.security)
        {
            return Err(Error::Stale);
        }
        let boot = policy.boot_epoch();
        self.authorize(
            CallBinding {
                holder: Identity {
                    id: EL1,
                    generation: boot,
                },
                boot_epoch: boot,
                service_generation: policy.file_service_generation()?,
                endpoint: tagged(boot, RECOVERY_ENDPOINT)?,
                selector: tagged(boot, RECOVERY_SELECTOR)?,
                fs_uuid: self.volume,
            },
            SNAP_CAP_RESTORE,
            request,
        )
    }

    fn check_policy(self, policy: &ConfirmedBootPolicy<'_>) -> Result<(), Error> {
        if policy.matches_config_digest(self.config_digest) {
            Ok(())
        } else {
            Err(Error::Stale)
        }
    }

    fn protection_grant(
        self,
        binding: CallBinding,
        holder_generation: u64,
        request: &SnapshotRequest<'_>,
    ) -> Result<(CallBinding, SnapshotGrant), Error> {
        if binding.holder.id != u64::from(Role::Supervisor.id())
            || binding.selector % EPOCH_STRIDE != PROTECTION_SELECTOR
        {
            return Err(Error::Unauthorized);
        }
        if binding.endpoint != tagged(binding.boot_epoch, PROTECTION_ENDPOINT)?
            || binding.holder.generation != holder_generation
            || binding.selector != tagged(holder_generation, PROTECTION_SELECTOR)?
        {
            return Err(Error::Stale);
        }
        self.authorize(binding, SNAP_CAP_PROTECTION, request)
    }

    fn authorize(
        self,
        binding: CallBinding,
        rights: u32,
        request: &SnapshotRequest<'_>,
    ) -> Result<(CallBinding, SnapshotGrant), Error> {
        let grant = SnapshotGrant {
            binding,
            enrollment: SnapshotEnrollment::RecoverySupervisor,
            capability_word: rights,
            principal: Some((RECOVERY_SLOT, self.recovery_principal.generation)),
            history_prefix_sha256: None,
        };
        request.verify_grant(binding, grant, &[])?;
        Ok((binding, grant))
    }
}

fn tagged(generation: u64, tag: u64) -> Result<u64, Error> {
    generation
        .checked_mul(EPOCH_STRIDE)
        .filter(|&value| value != 0)
        .map(|value| value | tag)
        .ok_or(Error::Exhausted)
}

fn encoding(volume: [u8; 16], principal: Principal) -> [u8; BYTES] {
    let mut wire = [0; BYTES];
    wire[..8].copy_from_slice(MAGIC);
    wire[8..24].copy_from_slice(&volume);
    wire[24..32].copy_from_slice(&principal.id.to_le_bytes());
    wire[32..40].copy_from_slice(&principal.generation.to_le_bytes());
    wire[40..42].copy_from_slice(&(RECOVERY_SLOT as u16).to_le_bytes());
    wire[42..44].copy_from_slice(&(EL1 as u16).to_le_bytes());
    wire[44..46].copy_from_slice(&Role::Supervisor.id().to_le_bytes());
    wire[48..52].copy_from_slice(&SNAP_CAP_RESTORE.to_le_bytes());
    wire[52..56].copy_from_slice(&SNAP_CAP_PROTECTION.to_le_bytes());
    wire
}

fn message(
    digest: [u8; 32],
    roster: [LifecyclePackageDigest; ROLE_COUNT],
    file_volume: &[u8; file_volume::BYTES],
    wire: &[u8; BYTES],
) -> [u8; MESSAGE_BYTES] {
    let mut out = [0; MESSAGE_BYTES];
    let (label, body) = out.split_at_mut(LABEL.len());
    let (config_and_roster, body) = body.split_at_mut(32);
    let (volume, contents) = body.split_at_mut(32);
    label.copy_from_slice(LABEL);
    config_and_roster.copy_from_slice(&Sha256::digest(lifecycle_package_message(digest, roster)));
    volume.copy_from_slice(&Sha256::digest(file_volume));
    contents.copy_from_slice(wire);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::role_manifest_v0199::ROLES;
    use crate::security::{
        file_media_unified_v1::{SNAP_OP_FREEZE_SET, SNAP_OP_RESTORE},
        offline_config_v1::CatalogBindings,
        snapshot_service_v4::{FileReqKey, SnapshotKey, encode_request},
    };
    use ed25519_dalek::{Signer, SigningKey};

    const CONFIG: &[u8] =
        include_bytes!("../../../../../tests/fixtures/v020-signed-scratch/config.bin");
    const TEST_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    #[test]
    fn signed_authority_binds_volume_roster_and_distinct_scopes() {
        let key = SigningKey::from_bytes(&TEST_SEED);
        let public = key.verifying_key().to_bytes();
        let assets = CatalogBindings {
            rule_generation: 1,
            security_generation: 1,
            key_generation: 1,
            rule_hash: Sha256::digest(b"scratch/test/rules/1").into(),
            security_hash: Sha256::digest(b"scratch/test/security/1").into(),
            key_manifest_hash: Sha256::digest(b"scratch/test/keys/1").into(),
        };
        let mut scratch = [0; 1024];
        let config =
            VerifiedOfflineConfig::verify(CONFIG, &public, assets, &mut scratch, |_, _, lists| {
                if lists == [0; 12] {
                    Ok(())
                } else {
                    Err(Error::Unauthorized)
                }
            })
            .unwrap();
        let catalog = PinnedStartupCatalog {
            boot_public_key: &public,
            offline_config: CONFIG,
            rules: &[],
            security_profile: &[0; 256],
            key_manifest: &[],
            key_generation: 1,
        };
        let roster = ROLES.map(|role| LifecyclePackageDigest {
            role: role.id(),
            image: [role.id() as u8; 32],
            relocations: [role.id() as u8 + 16; 32],
        });
        let uuid = config.header().fs_uuid;
        let principal = config.principals()[RECOVERY_SLOT as usize];
        let mut volume = [0; file_volume::BYTES];
        volume[..8].copy_from_slice(b"CYXFVOL1");
        volume[8..24].copy_from_slice(&uuid);
        let mut wire = encoding(uuid, principal);
        let sign = |wire: &[u8; BYTES]| {
            key.sign(&message(config.digest(), roster, &volume, wire))
                .to_bytes()
        };
        let signed = sign(&wire);
        let verified =
            SnapshotAuthority::verify(&catalog, &config, roster, &volume, &wire, &signed).unwrap();
        assert_eq!(verified.recovery_principal, principal);
        assert_eq!(verified.replay_principal(&config), Ok(principal));
        let revoked = SnapshotAuthority {
            config_digest: [0; 32],
            ..verified
        };
        assert_eq!(revoked.replay_principal(&config), Err(Error::Stale));
        let mut wrong_volume = volume;
        wrong_volume[40] = 1;
        assert_eq!(
            SnapshotAuthority::verify(&catalog, &config, roster, &wrong_volume, &wire, &signed),
            Err(Error::Unauthorized)
        );
        let mut wrong_roster = roster;
        wrong_roster[7].image[0] ^= 1;
        assert_eq!(
            SnapshotAuthority::verify(&catalog, &config, wrong_roster, &volume, &wire, &signed),
            Err(Error::Unauthorized)
        );
        for offset in [24, 32, 40, 42, 44, 46, 48, 52] {
            wire[offset] ^= 1;
            assert_eq!(
                SnapshotAuthority::verify(&catalog, &config, roster, &volume, &wire, &sign(&wire)),
                Err(Error::Unauthorized)
            );
            wire[offset] ^= 1;
        }
    }

    #[test]
    fn live_protection_binds_supervisor_boot_file_service_and_slot() {
        let uuid = [7; 16];
        let authority = SnapshotAuthority {
            config_digest: [2; 32],
            volume: uuid,
            recovery_principal: Principal {
                id: 16,
                generation: 33,
            },
        };
        let mut key = FileReqKey {
            fs_uuid: uuid,
            client_slot: RECOVERY_SLOT,
            client_generation: 33,
            request_seq: 1,
        };
        let mut wire = [0; 256];
        let binding = CallBinding {
            holder: Identity {
                id: 11,
                generation: 3,
            },
            boot_epoch: 6,
            service_generation: 12,
            endpoint: tagged(6, PROTECTION_ENDPOINT).unwrap(),
            selector: tagged(3, PROTECTION_SELECTOR).unwrap(),
            fs_uuid: uuid,
        };
        let mut freeze = [0; 16];
        freeze[..8].copy_from_slice(&1u64.to_le_bytes());
        freeze[8..12].copy_from_slice(&1u32.to_le_bytes());
        let len = encode_request(
            SNAP_OP_FREEZE_SET,
            1,
            Some(key),
            0,
            &freeze,
            binding.selector,
            &mut wire,
        )
        .unwrap();
        let request = SnapshotRequest::decode(&wire[..len], binding.selector).unwrap();
        let (_, grant) = authority.protection_grant(binding, 3, &request).unwrap();
        assert_eq!(grant.capability_word, SNAP_CAP_PROTECTION);
        assert_eq!(grant.binding.service_generation, 12);
        assert_eq!(grant.principal, Some((RECOVERY_SLOT, 33)));
        assert_eq!(
            authority.protection_grant(binding, 4, &request),
            Err(Error::Stale)
        );
        let old_endpoint = CallBinding {
            endpoint: tagged(5, PROTECTION_ENDPOINT).unwrap(),
            ..binding
        };
        assert_eq!(
            authority.protection_grant(old_endpoint, 3, &request),
            Err(Error::Stale)
        );
        let other_actor = CallBinding {
            holder: Identity {
                id: EL1,
                generation: 3,
            },
            ..binding
        };
        assert_eq!(
            authority.protection_grant(other_actor, 3, &request),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            authority.authorize(other_actor, SNAP_CAP_RESTORE, &request),
            Err(Error::Unauthorized)
        );

        key.client_generation -= 1;
        let len = encode_request(
            SNAP_OP_FREEZE_SET,
            1,
            Some(key),
            0,
            &freeze,
            binding.selector,
            &mut wire,
        )
        .unwrap();
        let request = SnapshotRequest::decode(&wire[..len], binding.selector).unwrap();
        assert_eq!(
            authority.protection_grant(binding, 3, &request),
            Err(Error::Unauthorized)
        );
        key.client_generation += 1;
        let mut restore = [0; 48];
        restore[..40].copy_from_slice(
            &SnapshotKey {
                fs_uuid: uuid,
                snapshot_id: 1,
                slot: 0,
                slot_generation: 1,
            }
            .encode()
            .unwrap(),
        );
        restore[40..44].copy_from_slice(&1u32.to_le_bytes());
        let len = encode_request(
            SNAP_OP_RESTORE,
            1,
            Some(key),
            2,
            &restore,
            binding.selector,
            &mut wire,
        )
        .unwrap();
        let request = SnapshotRequest::decode(&wire[..len], binding.selector).unwrap();
        assert_eq!(
            authority.protection_grant(binding, 3, &request),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            authority
                .authorize(other_actor, SNAP_CAP_RESTORE, &request)
                .unwrap()
                .1
                .capability_word,
            SNAP_CAP_RESTORE
        );
    }
}
