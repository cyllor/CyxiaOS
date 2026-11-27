//! CPU0 boot owner for the immutable deployment catalog inputs. At this
//! stage we verify Ed25519 and the independently pinned asset identities.

#[cfg(cyxia_startup_catalog)]
use cyxia_kernel_core::security::offline_config_v1::MAX_SIGNED_BYTES;
#[cfg(cyxia_signed_scratch_catalog)]
use cyxia_kernel_core::security::offline_config_v1::{
    ConfigHeader, Principal, VerifiedOfflineConfig,
};
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
#[cfg(cyxia_signed_scratch_catalog)]
pub(super) fn verify_policy(
    scratch: &mut [u8],
    verify_payload: impl FnOnce(&ConfigHeader, &[Principal; 16], &[u8]) -> Result<(), Error>,
) -> Result<VerifiedOfflineConfig<'static>, Error> {
    CATALOG.verify_policy(scratch, verify_payload)
}
