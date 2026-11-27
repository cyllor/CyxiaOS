//! Detached deployment grants for the exact verified lifecycle roster.
use super::{Error, LifecyclePackageDigest, lifecycle_package_message, verify_startup_signature};
use crate::control_plane::role_manifest_v0199::{ROLE_COUNT, ROLES};
use sha2::{Digest, Sha256};

pub const BYTES: usize = 88;
const MAGIC: &[u8; 8] = b"CYXSVC01";
const LABEL: &[u8] = b"CYX/STARTUP-ROLE-SERVICES/v1";
const MESSAGE_BYTES: usize = LABEL.len() + 32 + BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoleServices {
    control_caps: [u64; ROLE_COUNT],
    pub task_query_mask: u8,
    pub ipc_peers: [u8; ROLE_COUNT],
}

impl RoleServices {
    pub const NONE: Self = Self {
        control_caps: [0; ROLE_COUNT],
        task_query_mask: 0,
        ipc_peers: [0; ROLE_COUNT],
    };

    pub fn control_caps(self, index: usize) -> u64 {
        self.control_caps.get(index).copied().unwrap_or(0)
    }

    pub fn uses_objects(self, index: usize) -> bool {
        if index >= ROLE_COUNT {
            return false;
        }
        let bit = 1 << index;
        self.task_query_mask & bit != 0
            || self.ipc_peers[index] != 0
            || self.ipc_peers.iter().any(|mask| mask & bit != 0)
    }

    pub fn verify(
        wire: &[u8; BYTES],
        signature: &[u8; 64],
        public_key: &[u8; 32],
        config_digest: [u8; 32],
        roster: [LifecyclePackageDigest; ROLE_COUNT],
    ) -> Result<Self, Error> {
        verify_startup_signature(public_key, signature, &message(wire, config_digest, roster))?;
        if &wire[..8] != MAGIC || wire[81..] != [0; 7] {
            return Err(Error::Invalid);
        }
        let mut control_caps = [0; ROLE_COUNT];
        for ((caps, role), raw) in control_caps
            .iter_mut()
            .zip(ROLES)
            .zip(wire[8..72].chunks_exact(8))
        {
            *caps = u64::from_le_bytes(raw.try_into().unwrap());
            if *caps & !role.allowed_caps() != 0 {
                return Err(Error::Unauthorized);
            }
        }
        let ipc_peers: [u8; ROLE_COUNT] = wire[73..81].try_into().unwrap();
        if ipc_peers
            .iter()
            .enumerate()
            .any(|(index, mask)| mask & (1 << index) != 0)
            || ipc_peers.iter().map(|mask| mask.count_ones()).sum::<u32>() > ROLE_COUNT as u32
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            control_caps,
            task_query_mask: wire[72],
            ipc_peers,
        })
    }
}

fn message(
    wire: &[u8; BYTES],
    config_digest: [u8; 32],
    roster: [LifecyclePackageDigest; ROLE_COUNT],
) -> [u8; MESSAGE_BYTES] {
    let mut bytes = [0; MESSAGE_BYTES];
    let (label, body) = bytes.split_at_mut(LABEL.len());
    let (digest, grants) = body.split_at_mut(32);
    label.copy_from_slice(LABEL);
    digest.copy_from_slice(&Sha256::digest(lifecycle_package_message(
        config_digest,
        roster,
    )));
    grants.copy_from_slice(wire);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::role_manifest_v0199::{AUDIT_READ, PUBLISH_PLAN, SNAPSHOT};
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn verifies_exact_signed_authority_for_one_policy_and_roster() {
        let config = [31; 32];
        let packages = ROLES.map(|role| LifecyclePackageDigest {
            role: role.id(),
            image: [role.id() as u8; 32],
            relocations: [role.id() as u8 + 16; 32],
        });
        let key = SigningKey::from_bytes(&[15; 32]);
        let public = key.verifying_key().to_bytes();
        let mut wire = [0; BYTES];
        wire[..8].copy_from_slice(MAGIC);
        wire[8..16].copy_from_slice(&SNAPSHOT.to_le_bytes());
        wire[64..72].copy_from_slice(&AUDIT_READ.to_le_bytes());
        wire[72] = 1;
        wire[73] = 2;
        let signature = key.sign(&message(&wire, config, packages)).to_bytes();
        let grants = RoleServices::verify(&wire, &signature, &public, config, packages).unwrap();
        assert_eq!(grants.control_caps(0), SNAPSHOT);
        assert_eq!(grants.control_caps(7), AUDIT_READ);
        assert_eq!(grants.task_query_mask, 1);
        assert_eq!(grants.ipc_peers[0], 2);
        assert!(grants.uses_objects(0));
        assert!(grants.uses_objects(1));
        assert!(!grants.uses_objects(7));
        assert_eq!(
            RoleServices::verify(&wire, &signature, &public, [4; 32], packages),
            Err(Error::Unauthorized)
        );
        let mut different = packages;
        different[3].relocations[0] ^= 1;
        assert_eq!(
            RoleServices::verify(&wire, &signature, &public, config, different),
            Err(Error::Unauthorized)
        );
        wire[8..16].copy_from_slice(&PUBLISH_PLAN.to_le_bytes());
        let unauthorized = key.sign(&message(&wire, config, packages)).to_bytes();
        assert_eq!(
            RoleServices::verify(&wire, &unauthorized, &public, config, packages),
            Err(Error::Unauthorized)
        );
        wire[8..16].copy_from_slice(&SNAPSHOT.to_le_bytes());
        wire[73] = 1;
        let invalid = key.sign(&message(&wire, config, packages)).to_bytes();
        assert_eq!(
            RoleServices::verify(&wire, &invalid, &public, config, packages),
            Err(Error::Invalid)
        );
    }
}
