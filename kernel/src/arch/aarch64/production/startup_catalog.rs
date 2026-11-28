//! CPU0 boot owner for the immutable deployment catalog inputs. At this
//! stage we verify Ed25519 and the independently pinned asset identities.

#[cfg(cyxia_resident_net)]
use cyxia_kernel_core::security::network::deployment::ActiveDeployment;
#[cfg(cyxia_startup_catalog)]
use cyxia_kernel_core::security::network::deployment::KeyManifest;
#[cfg(cyxia_startup_catalog)]
use cyxia_kernel_core::security::offline_config_v1::MAX_SIGNED_BYTES;
#[cfg(cyxia_signed_resident)]
use cyxia_kernel_core::security::offline_config_v1::{
    ConfigHeader, Principal, VerifiedOfflineConfig,
};
#[cfg(cyxia_startup_catalog)]
use cyxia_kernel_core::security::recovery_proof_store::RecoveryLocator;
#[cfg(cyxia_startup_catalog)]
use cyxia_kernel_core::security::startup_catalog_v0199::file_volume::UnifiedFileVolume;
use cyxia_kernel_core::security::{Error, startup_catalog_v0199::PinnedStartupCatalog};

const CATALOG: PinnedStartupCatalog<'static> = PinnedStartupCatalog {
    boot_public_key: include_bytes!(concat!(
        env!("OUT_DIR"),
        "/startup-catalog/offline-ed25519-pubkey.bin"
    )),
    offline_config: include_bytes!(concat!(
        env!("OUT_DIR"),
        "/startup-catalog/offline-config.bin"
    )),
    rules: include_bytes!(concat!(
        env!("OUT_DIR"),
        "/startup-catalog/rule-profile.bin"
    )),
    security_profile: include_bytes!(concat!(
        env!("OUT_DIR"),
        "/startup-catalog/security-profile.bin"
    )),
    key_manifest: include_bytes!(concat!(
        env!("OUT_DIR"),
        "/startup-catalog/key-manifest.bin"
    )),
    key_generation: include!(concat!(
        env!("OUT_DIR"),
        "/startup-catalog/key-generation.rs"
    )),
};

#[cfg(cyxia_network_predecessor)]
const PREDECESSOR: PinnedStartupCatalog<'static> = PinnedStartupCatalog {
    boot_public_key: CATALOG.boot_public_key,
    offline_config: include_bytes!(concat!(
        env!("OUT_DIR"),
        "/startup-catalog/predecessor/offline-config.bin"
    )),
    rules: include_bytes!(concat!(
        env!("OUT_DIR"),
        "/startup-catalog/predecessor/rule-profile.bin"
    )),
    security_profile: include_bytes!(concat!(
        env!("OUT_DIR"),
        "/startup-catalog/predecessor/security-profile.bin"
    )),
    key_manifest: include_bytes!(concat!(
        env!("OUT_DIR"),
        "/startup-catalog/predecessor/key-manifest.bin"
    )),
    key_generation: include!(concat!(
        env!("OUT_DIR"),
        "/startup-catalog/predecessor/key-generation.rs"
    )),
};

#[cfg(cyxia_startup_catalog)]
#[derive(Clone, Copy)]
pub(super) enum NetworkDeployment {
    #[cfg(cyxia_resident_net)]
    Active(ActiveDeployment<'static>),
    Revoked(KeyManifest),
}

#[cfg(cyxia_startup_catalog)]
impl NetworkDeployment {
    pub(super) fn manifest(self) -> KeyManifest {
        match self {
            #[cfg(cyxia_resident_net)]
            Self::Active(active) => active.manifest(),
            Self::Revoked(manifest) => manifest,
        }
    }
}

#[cfg(cyxia_startup_catalog)]
pub(super) fn network(
    config: &VerifiedOfflineConfig<'_>,
    checkpoint: &mut impl FnMut() -> Result<(), Error>,
) -> Result<Option<NetworkDeployment>, Error> {
    if config.wire() != CATALOG.offline_config {
        return Err(Error::Conflict);
    }
    let Some(manifest) = KeyManifest::parse(CATALOG.key_manifest)? else {
        return Ok(None);
    };
    manifest.matches_config(config)?;
    if manifest.listener().is_none() {
        return Ok(Some(NetworkDeployment::Revoked(manifest)));
    }
    #[cfg(cyxia_resident_net)]
    {
        let active = manifest.qualify(
            config,
            CATALOG.boot_public_key,
            include_bytes!(concat!(
                env!("OUT_DIR"),
                "/startup-catalog/tls-packages.sig"
            )),
            [
                include_bytes!(concat!(
                    env!("OUT_DIR"),
                    "/startup-catalog/tls-verifier.elf"
                )),
                include_bytes!(concat!(env!("OUT_DIR"), "/startup-catalog/tls-signer.elf")),
                include_bytes!(concat!(env!("OUT_DIR"), "/startup-catalog/tls-ingress.elf")),
            ],
            checkpoint,
        )?;
        Ok(Some(NetworkDeployment::Active(active)))
    }
    #[cfg(not(cyxia_resident_net))]
    {
        let _ = checkpoint;
        Err(Error::Unauthorized)
    }
}

#[cfg(cyxia_startup_catalog)]
pub(super) fn previous_policy(
    scratch: &mut [u8],
    verify_payload: impl FnOnce(&ConfigHeader, &[Principal; 16], &[u8]) -> Result<(), Error>,
) -> Result<Option<(VerifiedOfflineConfig<'static>, Option<KeyManifest>)>, Error> {
    #[cfg(cyxia_network_predecessor)]
    {
        let config = PREDECESSOR.verify_policy(scratch, verify_payload)?;
        let manifest = KeyManifest::parse(PREDECESSOR.key_manifest)?;
        if let Some(manifest) = manifest {
            manifest.matches_config(&config)?;
        }
        Ok(Some((config, manifest)))
    }
    #[cfg(not(cyxia_network_predecessor))]
    {
        let _ = (scratch, verify_payload);
        Ok(None)
    }
}

/// Authorize the single carrier before the protected boot allocates an epoch.
/// A successor policy must explicitly authorize the same protected file.
#[cfg(cyxia_startup_catalog)]
pub(super) fn recovery_store(
    config: &VerifiedOfflineConfig<'_>,
    predecessor: Option<&VerifiedOfflineConfig<'_>>,
    checkpoint: &mut impl FnMut() -> Result<(), Error>,
) -> Result<Option<RecoveryLocator>, Error> {
    checkpoint()?;
    let current = RecoveryLocator::verify(
        config,
        CATALOG.boot_public_key,
        include_bytes!(concat!(
            env!("OUT_DIR"),
            "/startup-catalog/recovery-store.bin"
        )),
        include_bytes!(concat!(
            env!("OUT_DIR"),
            "/startup-catalog/recovery-store.sig"
        )),
    )?;
    #[cfg(cyxia_network_predecessor)]
    if let Some(predecessor) = predecessor {
        checkpoint()?;
        let previous = RecoveryLocator::verify(
            predecessor,
            PREDECESSOR.boot_public_key,
            include_bytes!(concat!(
                env!("OUT_DIR"),
                "/startup-catalog/predecessor/recovery-store.bin"
            )),
            include_bytes!(concat!(
                env!("OUT_DIR"),
                "/startup-catalog/predecessor/recovery-store.sig"
            )),
        )?;
        if previous.is_some_and(|prior| !current.is_some_and(|now| now.same_carrier(prior))) {
            return Err(Error::Conflict);
        }
    }
    #[cfg(not(cyxia_network_predecessor))]
    let _ = predecessor;
    checkpoint()?;
    Ok(current)
}

#[cfg(cyxia_startup_catalog)]
pub(super) fn file_volume(
    config: &VerifiedOfflineConfig<'_>,
    predecessor: Option<&VerifiedOfflineConfig<'_>>,
    checkpoint: &mut impl FnMut() -> Result<(), Error>,
) -> Result<Option<UnifiedFileVolume>, Error> {
    checkpoint()?;
    let current = UnifiedFileVolume::verify(
        config,
        CATALOG.boot_public_key,
        include_bytes!(concat!(env!("OUT_DIR"), "/startup-catalog/file-volume.bin")),
        include_bytes!(concat!(env!("OUT_DIR"), "/startup-catalog/file-volume.sig")),
    )?;
    #[cfg(cyxia_network_predecessor)]
    if let Some(config) = predecessor {
        checkpoint()?;
        let previous = UnifiedFileVolume::verify(
            config,
            PREDECESSOR.boot_public_key,
            include_bytes!(concat!(
                env!("OUT_DIR"),
                "/startup-catalog/predecessor/file-volume.bin"
            )),
            include_bytes!(concat!(
                env!("OUT_DIR"),
                "/startup-catalog/predecessor/file-volume.sig"
            )),
        )?;
        if previous != current {
            return Err(Error::Conflict);
        }
    }
    #[cfg(not(cyxia_network_predecessor))]
    let _ = predecessor;
    checkpoint()?;
    Ok(current)
}

#[cfg(cyxia_startup_catalog)]
static mut SIGNATURE_WORK: [u8; MAX_SIGNED_BYTES] = [0; MAX_SIGNED_BYTES];

/// Called once from the resident Cpu0 startup recovery reservation.
#[cfg(cyxia_startup_catalog)]
pub(super) fn authenticate() -> Result<(), Error> {
    // SAFETY: this boot has a single foreground owner, which calls once.
    // No secondary, exception hook, or DMA device uses this memory.
    let work = unsafe { &mut *core::ptr::addr_of_mut!(SIGNATURE_WORK) };
    CATALOG.authenticate(work)
}

/// The signed scratch owner supplies the existing scratch buffer and checks
/// its own accepted policy shape before the storage stage may start.
#[cfg(cyxia_signed_resident)]
pub(super) fn verify_policy(
    scratch: &mut [u8],
    verify_payload: impl FnOnce(&ConfigHeader, &[Principal; 16], &[u8]) -> Result<(), Error>,
) -> Result<VerifiedOfflineConfig<'static>, Error> {
    CATALOG.verify_policy(scratch, verify_payload)
}

#[cfg(cyxia_lifecycle_package_signature)]
pub(super) fn verify_lifecycle_packages(config: &VerifiedOfflineConfig<'_>) -> Result<(), Error> {
    CATALOG.qualify_lifecycle_packages(
        config,
        super::role_loader::lifecycle_package_digests(),
        include_bytes!(concat!(
            env!("OUT_DIR"),
            "/startup-catalog/lifecycle-packages.sig"
        )),
    )
}

#[cfg(all(cyxia_startup_catalog, not(cyxia_lifecycle_package_signature)))]
pub(super) fn verify_lifecycle_packages(_: &VerifiedOfflineConfig<'_>) -> Result<(), Error> {
    // First-pass builds can produce detached signing inputs and expose
    // read-only status. Missing package approval never opens the boot volume.
    Err(Error::Unauthorized)
}

#[cfg(cyxia_business_package)]
pub(super) fn qualify_business_package(
    config: &VerifiedOfflineConfig<'_>,
    package_digest: [u8; 32],
    signature: &[u8; 64],
) -> Result<(), Error> {
    CATALOG.qualify_business_package(config, package_digest, signature)
}

#[cfg(cyxia_file_owner_package)]
pub(super) fn qualify_file_owner(
    config: &VerifiedOfflineConfig<'_>,
    package_digest: [u8; 32],
    grant: &[u8; cyxia_kernel_core::security::startup_catalog_v0199::file_owner::BYTES],
    signature: &[u8; 64],
) -> Result<cyxia_kernel_core::security::startup_catalog_v0199::file_owner::FileOwnerGrant, Error> {
    cyxia_kernel_core::security::startup_catalog_v0199::file_owner::FileOwnerGrant::verify(
        &CATALOG,
        config,
        package_digest,
        grant,
        signature,
    )
}

#[cfg(cyxia_business_package)]
pub(super) fn control_rules(
    verified_config_wire: &[u8],
) -> Result<cyxia_kernel_core::control_plane::rule_profile_v2::Profile<'static>, Error> {
    if verified_config_wire != CATALOG.offline_config {
        return Err(Error::Conflict);
    }
    // The VerifiedOfflineConfig was authenticated against these exact
    // catalog bytes, including the SecurityProfile's RuleProfile binding.
    cyxia_kernel_core::control_plane::rule_profile_v2::Profile::parse(CATALOG.rules)
        .map_err(|_| Error::Invalid)
}

#[cfg(cyxia_business_task_services)]
pub(super) fn qualify_business_task_services(
    config: &VerifiedOfflineConfig<'_>,
    package_digest: [u8; 32],
    grants: &[u8; cyxia_kernel_core::security::startup_catalog_v0199::TASK_SERVICES_BYTES],
    signature: &[u8; 64],
) -> Result<(), Error> {
    CATALOG.qualify_business_task_services(config, package_digest, grants, signature)
}
