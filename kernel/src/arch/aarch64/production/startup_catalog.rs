//! CPU0 boot owner for the immutable deployment catalog inputs. At this
//! stage we verify Ed25519 and the independently pinned asset identities.

use cyxia_kernel_core::security::{
    Error, offline_config_v1::MAX_SIGNED_BYTES, startup_catalog_v0199::PinnedStartupCatalog,
};

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

static mut SIGNATURE_WORK: [u8; MAX_SIGNED_BYTES] = [0; MAX_SIGNED_BYTES];

/// Called once from the resident Cpu0 startup recovery reservation.
pub(super) fn authenticate() -> Result<(), Error> {
    // SAFETY: this boot has a single foreground owner, which calls once.
    // No secondary, exception hook, or DMA device uses this memory.
    let work = unsafe { &mut *core::ptr::addr_of_mut!(SIGNATURE_WORK) };
    CATALOG.authenticate(work)
}
