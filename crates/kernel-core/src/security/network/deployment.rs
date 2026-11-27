//! Public deployment identity carried by the offline-signed key manifest.
//! Its hash and key generation are bound by OfflineConfigEnvelope v1.
//! No network request can construct a qualified or boot-authorized deployment.
use super::{Error, TlsInstallation};
use crate::security::{
    durable_role_epoch_v0199::ConfirmedBootPolicy, offline_config_v1::VerifiedOfflineConfig,
};
use sha2::{Digest, Sha256};

pub const BYTES: usize = 184;
const MAGIC: &[u8; 8] = b"CYXNET01";
const PAGE: u64 = 4096;
const IMAGE_BASE: u64 = 0x0100_0000;
pub const VERIFIER_FRAMES: usize = 3072;
pub const SIGNER_FRAMES: usize = 64;
pub const INGRESS_FRAMES: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Listener {
    pub local_ipv4: [u8; 4],
    pub peer_ipv4: [u8; 4],
    pub prefix_len: u8,
    pub listen_port: u16,
    pub mac: [u8; 6],
    pub local_pin: [u8; 32],
    pub peer_pin: [u8; 32],
    pub ingress_digest: [u8; 32],
}

impl Listener {
    fn valid(self) -> bool {
        if !(1..=30).contains(&self.prefix_len)
            || self.listen_port == 0
            || self.mac == [0; 6]
            || self.mac[0] & 1 != 0
            || self.local_pin <= self.peer_pin
            || self.peer_pin == [0; 32]
            || self.ingress_digest == [0; 32]
            || self.local_ipv4 == self.peer_ipv4
        {
            return false;
        }
        let host_mask = u32::MAX >> self.prefix_len;
        let unicast = |octets: [u8; 4]| {
            let host = u32::from_be_bytes(octets) & host_mask;
            (1..224).contains(&octets[0]) && octets[0] != 127 && host != 0 && host != host_mask
        };
        unicast(self.local_ipv4)
            && unicast(self.peer_ipv4)
            && (u32::from_be_bytes(self.local_ipv4) ^ u32::from_be_bytes(self.peer_ipv4))
                & !host_mask
                == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyManifest {
    installation: TlsInstallation,
    predecessor_config: [u8; 32],
    listener: Option<Listener>,
}

impl KeyManifest {
    /// Older opaque catalogs carry no network authority. An unrecognized
    /// version of this manifest family is an invalid network catalog.
    pub fn parse(wire: &[u8]) -> Result<Option<Self>, Error> {
        if !wire.starts_with(b"CYXNET") {
            return Ok(None);
        }
        if wire.len() != BYTES || !wire.starts_with(MAGIC) || wire[82..88] != [0; 6] {
            return Err(Error::Invalid);
        }
        let generation = |at| u64::from_le_bytes(wire[at..at + 8].try_into().unwrap());
        let installation = TlsInstallation {
            key_generation: generation(8),
            verifier_generation: generation(16),
            signer_generation: generation(24),
            key_manifest_hash: Sha256::digest(wire).into(),
        };
        if [
            installation.key_generation,
            installation.verifier_generation,
            installation.signer_generation,
        ]
        .contains(&0)
        {
            return Err(Error::Invalid);
        }
        let predecessor_config = wire[32..64].try_into().unwrap();
        let listener = match wire[73] {
            1 => {
                let listener = Listener {
                    local_ipv4: wire[64..68].try_into().unwrap(),
                    peer_ipv4: wire[68..72].try_into().unwrap(),
                    prefix_len: wire[72],
                    listen_port: u16::from_le_bytes(wire[74..76].try_into().unwrap()),
                    mac: wire[76..82].try_into().unwrap(),
                    local_pin: wire[88..120].try_into().unwrap(),
                    peer_pin: wire[120..152].try_into().unwrap(),
                    ingress_digest: wire[152..184].try_into().unwrap(),
                };
                if !listener.valid() {
                    return Err(Error::Invalid);
                }
                Some(listener)
            }
            2 if predecessor_config != [0; 32]
                && wire[64..73].iter().chain(&wire[74..]).all(|&b| b == 0) =>
            {
                None
            }
            _ => return Err(Error::Invalid),
        };
        Ok(Some(Self {
            installation,
            predecessor_config,
            listener,
        }))
    }

    pub fn listener(self) -> Option<Listener> {
        self.listener
    }

    pub fn installation(self) -> TlsInstallation {
        self.installation
    }

    pub fn predecessor_config(self) -> [u8; 32] {
        self.predecessor_config
    }

    pub fn matches_config(self, config: &VerifiedOfflineConfig<'_>) -> Result<(), Error> {
        let signed = config.header();
        if signed.key_generation != self.installation.key_generation
            || signed.key_manifest_hash != self.installation.key_manifest_hash
        {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }

    /// Check all three local EL0 packages before the storage owner commits
    /// policy. The detached signature uses the existing TLS pair format.
    pub fn qualify<'a>(
        self,
        config: &VerifiedOfflineConfig<'_>,
        locked_public_key: &[u8; 32],
        signature: &[u8; 64],
        [verifier, signer, ingress]: [&'a [u8]; 3],
        checkpoint: &mut impl FnMut() -> Result<(), Error>,
    ) -> Result<ActiveDeployment<'a>, Error> {
        self.matches_config(config)?;
        let listener = self.listener.ok_or(Error::Unauthorized)?;
        check_image(verifier, VERIFIER_FRAMES)?;
        check_image(signer, SIGNER_FRAMES)?;
        check_image(ingress, INGRESS_FRAMES)?;
        let verifier_digest = hash_image(verifier, checkpoint)?;
        let signer_digest = hash_image(signer, checkpoint)?;
        if hash_image(ingress, checkpoint)? != listener.ingress_digest {
            return Err(Error::Unauthorized);
        }
        checkpoint()?;
        self.installation.qualify_package_hashes(
            locked_public_key,
            signature,
            verifier_digest,
            signer_digest,
        )?;
        Ok(ActiveDeployment {
            manifest: self,
            config_digest: config.digest(),
            verifier,
            signer,
            ingress,
        })
    }
}

#[derive(Clone, Copy)]
pub struct ActiveDeployment<'a> {
    manifest: KeyManifest,
    config_digest: [u8; 32],
    verifier: &'a [u8],
    signer: &'a [u8],
    ingress: &'a [u8],
}

impl<'a> ActiveDeployment<'a> {
    pub fn manifest(self) -> KeyManifest {
        self.manifest
    }

    /// The native startup owner holds this installation through the boot.
    /// Offline configuration changes run before the admission is issued.
    pub fn authorize(
        self,
        policy: ConfirmedBootPolicy<'_>,
    ) -> Result<AuthorizedNetwork<'a>, Error> {
        if !policy.matches_config_digest(self.config_digest) {
            return Err(Error::Conflict);
        }
        let confirmed = self.manifest.installation.authorize(policy)?;
        Ok(AuthorizedNetwork {
            active: self,
            boot_epoch: confirmed.boot_epoch(),
        })
    }
}

/// Sealed boot-only result for handoff of the package slices to their
/// resident CPU. The underlying installation cannot be updated online.
#[derive(Clone, Copy)]
pub struct AuthorizedNetwork<'a> {
    active: ActiveDeployment<'a>,
    boot_epoch: u64,
}

impl<'a> AuthorizedNetwork<'a> {
    pub fn boot_epoch(self) -> u64 {
        self.boot_epoch
    }

    pub fn installation(self) -> TlsInstallation {
        self.active.manifest.installation
    }

    pub fn listener(self) -> Listener {
        self.active.manifest.listener.expect("qualified listener")
    }

    pub fn verifier_image(self) -> &'a [u8] {
        self.active.verifier
    }

    pub fn signer_image(self) -> &'a [u8] {
        self.active.signer
    }

    pub fn ingress_image(self) -> &'a [u8] {
        self.active.ingress
    }
}

fn hash_image(
    image: &[u8],
    checkpoint: &mut impl FnMut() -> Result<(), Error>,
) -> Result<[u8; 32], Error> {
    let mut hash = Sha256::new();
    for chunk in image.chunks(PAGE as usize) {
        checkpoint()?;
        hash.update(chunk);
    }
    Ok(hash.finalize().into())
}

/// Check the exact, bounded ET_EXEC shape consumed by the native broker.
/// This is a fixed-address package format without runtime relocations.
fn check_image(image: &[u8], frames: usize) -> Result<(), Error> {
    if image.len() < 64
        || image[..7] != *b"\x7fELF\x02\x01\x01"
        || image[16..24] != [2, 0, 183, 0, 1, 0, 0, 0]
        || image[52..56] != [64, 0, 56, 0]
    {
        return Err(Error::Invalid);
    }
    let word = |offset| u64::from_le_bytes(image[offset..offset + 8].try_into().unwrap());
    let entry = word(24);
    let headers = usize::try_from(word(32)).map_err(|_| Error::Invalid)?;
    let count = usize::from(u16::from_le_bytes(image[56..58].try_into().unwrap()));
    if !(1..=16).contains(&count)
        || headers < 64
        || headers
            .checked_add(count * 56)
            .is_none_or(|n| n > image.len())
        || !entry.is_multiple_of(4)
    {
        return Err(Error::Invalid);
    }
    let mut occupied = [(0, 0); 16];
    let mut writable = false;
    let mut executable_entry = false;
    for index in 0..count {
        let header = headers + index * 56;
        let kind = u32::from_le_bytes(image[header..header + 4].try_into().unwrap());
        match kind {
            1 => (),
            // No dynamic interpreter, dynamic relocation data, or ELF TLS.
            2 | 3 | 7 => return Err(Error::Invalid),
            _ => continue,
        }
        let flags = u32::from_le_bytes(image[header + 4..header + 8].try_into().unwrap());
        let address = word(header + 16);
        let files = word(header + 32);
        let memory = word(header + 40);
        let end = address.checked_add(memory).ok_or(Error::Invalid)?;
        if !matches!(flags, 4..=6)
            || address < IMAGE_BASE
            || end > IMAGE_BASE + frames as u64 * PAGE
            || !address.is_multiple_of(PAGE)
            || memory == 0
            || files > memory
            || word(header + 8)
                .checked_add(files)
                .is_none_or(|n| n > image.len() as u64)
        {
            return Err(Error::Invalid);
        }
        if flags == 6 {
            if writable || files != 0 {
                return Err(Error::Invalid);
            }
            writable = true;
        }
        let boundary = end.div_ceil(PAGE) * PAGE;
        if occupied[..index]
            .iter()
            .any(|&(start, stop)| address < stop && start < boundary)
        {
            return Err(Error::Invalid);
        }
        occupied[index] = (address, boundary);
        executable_entry |= flags == 5 && (address..address + files).contains(&entry);
    }
    executable_entry.then_some(()).ok_or(Error::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::offline_config_v1::{CatalogBindings, SIGNATURE_LABEL};
    use ed25519_dalek::{Signer, SigningKey};

    fn manifest() -> [u8; BYTES] {
        let mut wire = [0; BYTES];
        wire[..8].copy_from_slice(b"CYXNET01");
        wire[8..16].copy_from_slice(&7u64.to_le_bytes());
        wire[16..24].copy_from_slice(&3u64.to_le_bytes());
        wire[24..32].copy_from_slice(&5u64.to_le_bytes());
        wire[64..68].copy_from_slice(&[10, 0, 2, 15]);
        wire[68..72].copy_from_slice(&[10, 0, 2, 2]);
        wire[72] = 24;
        wire[73] = 1;
        wire[74..76].copy_from_slice(&7u16.to_le_bytes());
        wire[76..82].copy_from_slice(&[0x52, 0x54, 0, 0x12, 0x34, 0x56]);
        wire[88..120].fill(200);
        wire[120..152].fill(100);
        wire[152..184].fill(5);
        wire
    }

    #[test]
    fn active_manifest_binds_network_identity_and_all_generations() {
        let wire = manifest();
        let record = KeyManifest::parse(&wire).unwrap().unwrap();
        let listener = record.listener().unwrap();
        assert_eq!(listener.local_ipv4, [10, 0, 2, 15]);
        assert_eq!(listener.peer_ipv4, [10, 0, 2, 2]);
        assert_eq!(listener.mac, [0x52, 0x54, 0, 0x12, 0x34, 0x56]);
        assert_eq!(record.installation().key_generation, 7);
        assert_eq!(record.installation().verifier_generation, 3);
        assert_eq!(record.installation().signer_generation, 5);
        assert_eq!(record.predecessor_config(), [0; 32]);
    }

    #[test]
    fn malformed_network_manifest_cannot_be_interpreted_as_legacy() {
        assert_eq!(KeyManifest::parse(b"legacy").unwrap(), None);
        for (at, value) in [
            (7, b'2'),
            (64, 224),
            (68, 11),
            (71, 255),
            (72, 0),
            (73, 0),
            (74, 0),
            (76, 0x53),
            (87, 1),
            (88, 10),
            (152, 0),
        ] {
            let mut wire = manifest();
            wire[at] = value;
            if at == 152 {
                wire[152..].fill(0);
            }
            assert_eq!(KeyManifest::parse(&wire), Err(Error::Invalid), "{at}");
        }
        assert_eq!(KeyManifest::parse(b"CYXNET"), Err(Error::Invalid));
    }

    #[test]
    fn revocation_names_a_predecessor_and_carries_no_listener() {
        let mut wire = manifest();
        wire[64..].fill(0);
        wire[73] = 2;
        assert_eq!(KeyManifest::parse(&wire), Err(Error::Invalid));
        wire[32..64].fill(7);
        let record = KeyManifest::parse(&wire).unwrap().unwrap();
        assert!(record.listener().is_none());
        assert_eq!(record.predecessor_config(), [7; 32]);
        wire[76] = 0x52;
        assert_eq!(KeyManifest::parse(&wire), Err(Error::Invalid));
    }

    fn executable() -> [u8; 124] {
        let mut elf = [0; 124];
        elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        elf[16..24].copy_from_slice(&[2, 0, 183, 0, 1, 0, 0, 0]);
        elf[24..32].copy_from_slice(&IMAGE_BASE.to_le_bytes());
        elf[32..40].copy_from_slice(&64u64.to_le_bytes());
        elf[52..58].copy_from_slice(&[64, 0, 56, 0, 1, 0]);
        elf[64..72].copy_from_slice(&[1, 0, 0, 0, 5, 0, 0, 0]);
        elf[72..80].copy_from_slice(&120u64.to_le_bytes());
        elf[80..88].copy_from_slice(&IMAGE_BASE.to_le_bytes());
        elf[96..104].copy_from_slice(&4u64.to_le_bytes());
        elf[104..112].copy_from_slice(&4u64.to_le_bytes());
        elf
    }

    #[test]
    fn image_validation_precedes_loading_signed_inputs() {
        let image = executable();
        assert_eq!(check_image(&image, SIGNER_FRAMES), Ok(()));
        for (at, value) in [
            (24, 4),
            (48, 1),
            (64, 3),
            (68, 7),
            (72, 123),
            (80, 1),
            (104, 2),
        ] {
            // ELF program entry uses its own fixed address. Offset 48 is
            // deliberately mutable e_flags and unused by the loader.
            let mut malformed = image;
            malformed[at] = value;
            let expected = if at == 48 {
                Ok(())
            } else {
                Err(Error::Invalid)
            };
            assert_eq!(check_image(&malformed, SIGNER_FRAMES), expected, "{at}");
        }
    }

    #[test]
    fn signed_catalog_qualifies_exact_role_images_and_stops_at_checkpoint_error() {
        let signer = SigningKey::from_bytes(&[7; 32]);
        let boot_key = signer.verifying_key().to_bytes();
        let mut wire = manifest();
        let role = executable();
        let role_digest = Sha256::digest(role);
        wire[152..184].copy_from_slice(&role_digest);
        let manifest = KeyManifest::parse(&wire).unwrap().unwrap();
        let signed_manifest_digest = manifest.installation().key_manifest_hash;
        let catalog = CatalogBindings {
            rule_generation: 1,
            security_generation: 1,
            key_generation: 7,
            rule_hash: [42; 32],
            security_hash: [43; 32],
            key_manifest_hash: signed_manifest_digest,
        };
        let mut config = [0; 588];
        config[..16]
            .copy_from_slice(&[0x46, 0x4f, 0x59, 0x43, 1, 0, 0, 1, 76, 2, 0, 0, 12, 1, 0, 0]);
        config[16..32].fill(1);
        config[32] = 1;
        config[40] = 1;
        config[48] = 1;
        config[56] = 7;
        config[64..96].copy_from_slice(&catalog.rule_hash);
        config[96..128].copy_from_slice(&catalog.security_hash);
        config[128..160].copy_from_slice(&signed_manifest_digest);
        for (index, principal) in config[256..512].chunks_exact_mut(16).enumerate() {
            principal[0] = index as u8 + 1;
            principal[8] = 1;
        }
        let payload_hash = Sha256::digest(&config[256..524]);
        config[160..192].copy_from_slice(&payload_hash);
        let config_message = [SIGNATURE_LABEL, &config[..524]].concat();
        config[524..].copy_from_slice(&signer.sign(&config_message).to_bytes());
        let config = VerifiedOfflineConfig::verify(
            &config,
            &boot_key,
            catalog,
            &mut [0; 1024],
            |_, _, _| Ok(()),
        )
        .unwrap();
        let packages_message = [
            b"CYX/TLS-PACKAGES/v1".as_slice(),
            &3u64.to_le_bytes(),
            &5u64.to_le_bytes(),
            &7u64.to_le_bytes(),
            &signed_manifest_digest,
            &role_digest,
            &role_digest,
        ]
        .concat();
        let signature = signer.sign(&packages_message).to_bytes();
        let mut checkpoints = 0;
        assert!(
            manifest
                .qualify(&config, &boot_key, &signature, [&role; 3], &mut || {
                    checkpoints += 1;
                    Ok(())
                })
                .is_ok()
        );
        assert_eq!(checkpoints, 4);
        assert_eq!(
            manifest
                .qualify(&config, &boot_key, &signature, [&role; 3], &mut || Err(
                    Error::Busy
                ))
                .err(),
            Some(Error::Busy)
        );
        let mut changed = role;
        changed[123] = 1;
        for images in [
            [&changed[..], &role, &role],
            [&role[..], &changed, &role],
            [&role[..], &role, &changed],
        ] {
            assert_eq!(
                manifest
                    .qualify(&config, &boot_key, &signature, images, &mut || Ok(()))
                    .err(),
                Some(Error::Unauthorized)
            );
        }
    }
}
