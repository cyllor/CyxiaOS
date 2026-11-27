//! Authenticate an offline envelope against independently pinned boot inputs.
//! This stage checks asset identity. Payload-list semantics, the actual
//! mounted state and the current BootEpoch are checked by their owners.

use super::{
    Error,
    offline_config_v1::{
        AuthenticatedEnvelope, CatalogBindings, ConfigHeader, Principal, VerifiedOfflineConfig,
    },
};
use crate::control_plane::{role_manifest_v0199::ROLES, rule_profile_v2::Profile};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

mod lifecycle_packages;
mod profile;

pub use lifecycle_packages::LifecyclePackageDigest;
use lifecycle_packages::lifecycle_package_message;

pub struct PinnedStartupCatalog<'a> {
    pub boot_public_key: &'a [u8; 32],
    pub offline_config: &'a [u8],
    pub rules: &'a [u8],
    pub security_profile: &'a [u8; profile::BYTES],
    pub key_manifest: &'a [u8],
    pub key_generation: u64,
}

impl<'a> PinnedStartupCatalog<'a> {
    /// Check the signed envelope, canonical RuleProfile and exact asset
    /// digests. The SecurityProfile header binds the same rules digest.
    /// This method returns only a verification result for startup diagnostics.
    pub fn authenticate(&self, scratch: &mut [u8]) -> Result<(), Error> {
        AuthenticatedEnvelope::verify(
            self.offline_config,
            self.boot_public_key,
            self.bindings()?,
            scratch,
        )?;
        Ok(())
    }

    /// Authenticate the same catalog and require the receiving owner to
    /// check its policy lists before handing any authority to a mount.
    pub fn verify_policy(
        &self,
        scratch: &mut [u8],
        verify_payload: impl FnOnce(&ConfigHeader, &[Principal; 16], &[u8]) -> Result<(), Error>,
    ) -> Result<VerifiedOfflineConfig<'a>, Error> {
        VerifiedOfflineConfig::verify(
            self.offline_config,
            self.boot_public_key,
            self.bindings()?,
            scratch,
            verify_payload,
        )
    }

    /// Qualify the exact ABI3 lifecycle roster for this authenticated catalog.
    /// The loader separately checks the actual ELF and relocation bytes.
    pub fn qualify_lifecycle_packages(
        &self,
        policy: &VerifiedOfflineConfig<'_>,
        packages: [LifecyclePackageDigest; ROLES.len()],
        signature: &[u8; 64],
    ) -> Result<(), Error> {
        if policy.wire() != self.offline_config
            || packages
                .iter()
                .zip(ROLES)
                .any(|(package, role)| package.role != role.id())
        {
            return Err(Error::Conflict);
        }
        verify_lifecycle_signature(self.boot_public_key, signature, policy.digest(), packages)
    }

    fn bindings(&self) -> Result<CatalogBindings, Error> {
        let rules = Profile::parse(self.rules).map_err(|_| Error::Invalid)?;
        let rule_hash: [u8; 32] = Sha256::digest(rules.canonical_bytes()).into();
        let security = self.security_profile;
        let security_generation = profile::generation(security, &rule_hash)?;
        if self.key_generation == 0 || self.key_manifest.is_empty() {
            return Err(Error::Invalid);
        }
        Ok(CatalogBindings {
            rule_generation: rules.generation,
            security_generation,
            key_generation: self.key_generation,
            rule_hash,
            security_hash: Sha256::digest(security).into(),
            key_manifest_hash: Sha256::digest(self.key_manifest).into(),
        })
    }
}

fn verify_lifecycle_signature(
    public_key: &[u8; 32],
    signature: &[u8; 64],
    config_digest: [u8; 32],
    packages: [LifecyclePackageDigest; ROLES.len()],
) -> Result<(), Error> {
    let message = lifecycle_package_message(config_digest, packages);
    VerifyingKey::from_bytes(public_key)
        .and_then(|key| key.verify_strict(&message, &Signature::from_bytes(signature)))
        .map_err(|_| Error::Unauthorized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::offline_config_v1::{SIGNATURE_LABEL, VerifiedOfflineConfig};
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn lifecycle_qualification_pins_the_config_and_each_package() {
        let config = [17; 32];
        let roles = [6u16, 7, 2, 8, 9, 3, 10, 11];
        let packages = roles.map(|role| LifecyclePackageDigest {
            role,
            image: [role as u8; 32],
            relocations: [role as u8 + 16; 32],
        });
        let mut message = b"CYX/STARTUP-LIFECYCLE-PACKAGES/v1".to_vec();
        message.extend_from_slice(&config);
        for role in roles {
            message.extend_from_slice(&role.to_le_bytes());
            message.extend_from_slice(&[role as u8; 32]);
            message.extend_from_slice(&[role as u8 + 16; 32]);
        }
        let signer = SigningKey::from_bytes(&[0x38; 32]);
        let signature = signer.sign(&message).to_bytes();
        let public_key = signer.verifying_key().to_bytes();
        let verify = |digest, packages| {
            verify_lifecycle_signature(&public_key, &signature, digest, packages)
        };
        assert_eq!(verify(config, packages), Ok(()));
        assert_eq!(verify([18; 32], packages), Err(Error::Unauthorized));

        let mut other_image = packages;
        other_image[4].image = [33; 32];
        assert_eq!(verify(config, other_image), Err(Error::Unauthorized));
        let mut other_relocations = packages;
        other_relocations[7].relocations = [34; 32];
        assert_eq!(verify(config, other_relocations), Err(Error::Unauthorized));
        let mut reordered = packages;
        reordered.swap(0, 1);
        assert_eq!(verify(config, reordered), Err(Error::Unauthorized));
    }

    #[test]
    fn signed_catalog_checks_independent_assets_before_payload_authorization() {
        let mut rules = [0; 80];
        rules[..32].copy_from_slice(&[
            0x55, 0x52, 0x59, 0x43, 2, 0, 32, 0, 7, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 80, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        rules[32..].copy_from_slice(&[
            1, 0, 0, 0, 1, 0, 1, 0, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 48, 0, 0, 0,
            0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 4, 0, 1, 0, 0, 0, 0, 0,
        ]);
        let rule_hash: [u8; 32] = Sha256::digest(rules).into();
        let security = profile::fixture(9, rule_hash);
        let keys = b"test-only key manifest bytes";
        let security_hash: [u8; 32] = Sha256::digest(security).into();
        let key_manifest_hash: [u8; 32] = Sha256::digest(keys).into();

        let mut wire = [0; 577];
        wire[..8].copy_from_slice(&[0x46, 0x4f, 0x59, 0x43, 1, 0, 0, 1]);
        wire[8..12].copy_from_slice(&577u32.to_le_bytes());
        wire[12..16].copy_from_slice(&257u32.to_le_bytes());
        wire[16..32].fill(1);
        wire[32] = 1;
        wire[40] = 7;
        wire[48] = 9;
        wire[56] = 2;
        wire[64..96].copy_from_slice(&rule_hash);
        wire[96..128].copy_from_slice(&security_hash);
        wire[128..160].copy_from_slice(&key_manifest_hash);
        for (i, principal) in wire[256..512].chunks_exact_mut(16).enumerate() {
            principal[0] = i as u8 + 1;
            principal[8] = 1;
        }
        wire[512] = 255; // The semantic verifier must still reject this list.
        let payload_hash = Sha256::digest(&wire[256..513]);
        wire[160..192].copy_from_slice(&payload_hash);
        let signer = SigningKey::from_bytes(&[0x37; 32]);
        let public_key = signer.verifying_key().to_bytes();
        let signed = [SIGNATURE_LABEL, &wire[..513]].concat();
        wire[513..].copy_from_slice(&signer.sign(&signed).to_bytes());

        let catalog = PinnedStartupCatalog {
            boot_public_key: &public_key,
            offline_config: &wire,
            rules: &rules,
            security_profile: &security,
            key_manifest: keys,
            key_generation: 2,
        };
        let mut scratch = [0; 1024];
        assert_eq!(catalog.authenticate(&mut scratch), Ok(()));
        assert!(matches!(
            catalog.verify_policy(&mut scratch, |_, _, _| Err(Error::Unauthorized)),
            Err(Error::Unauthorized)
        ));

        let mut widened = security;
        widened[118..120].copy_from_slice(&4000u16.to_le_bytes());
        let mut signed_widened = wire;
        signed_widened[96..128].copy_from_slice(&Sha256::digest(widened));
        let signed = [SIGNATURE_LABEL, &signed_widened[..513]].concat();
        signed_widened[513..].copy_from_slice(&signer.sign(&signed).to_bytes());
        let invalid_profile = PinnedStartupCatalog {
            security_profile: &widened,
            offline_config: &signed_widened,
            ..catalog
        };
        assert_eq!(
            invalid_profile.authenticate(&mut scratch),
            Err(Error::Invalid)
        );
        let invalid_key_manifest = PinnedStartupCatalog {
            key_manifest: b"other",
            ..catalog
        };
        assert_eq!(
            invalid_key_manifest.authenticate(&mut scratch),
            Err(Error::Conflict)
        );
        let mut tampered = wire;
        tampered[576] ^= 1;
        let invalid_signature = PinnedStartupCatalog {
            offline_config: &tampered,
            ..catalog
        };
        assert_eq!(
            invalid_signature.authenticate(&mut scratch),
            Err(Error::Unauthorized)
        );
        assert!(matches!(
            VerifiedOfflineConfig::verify(
                &wire,
                &public_key,
                CatalogBindings {
                    rule_generation: 7,
                    security_generation: 9,
                    key_generation: 2,
                    rule_hash,
                    security_hash,
                    key_manifest_hash,
                },
                &mut scratch,
                |_, _, _| Err(Error::Unauthorized),
            ),
            Err(Error::Unauthorized)
        ));
    }
}
