//! Code and key-generation qualification for the installed TLS role pair.
//! Boot trust and the current durable policy are supplied by the caller.
use super::{Error, TlsInstallation};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

const LABEL: &[u8] = b"CYX/TLS-PACKAGES/v1";
const MESSAGE_BYTES: usize = LABEL.len() + 3 * 8 + 3 * 32;

impl TlsInstallation {
    /// Check a detached offline signature over the exact verifier and signer
    /// image hashes, their role generations and their key catalogue identity.
    /// This grants no admission by itself. The mount owner also has to match
    /// this installation against the currently committed boot configuration.
    pub fn qualify_packages(
        &self,
        boot_key: &[u8; 32],
        signature: &[u8; 64],
        verifier: &[u8],
        signer: &[u8],
    ) -> Result<(), Error> {
        if [
            self.verifier_generation,
            self.signer_generation,
            self.key_generation,
        ]
        .contains(&0)
            || self.key_manifest_hash == [0; 32]
            || verifier.is_empty()
            || signer.is_empty()
        {
            return Err(Error::Invalid);
        }
        let mut message = [0; MESSAGE_BYTES];
        message[..LABEL.len()].copy_from_slice(LABEL);
        let fields = &mut message[LABEL.len()..];
        fields[..8].copy_from_slice(&self.verifier_generation.to_le_bytes());
        fields[8..16].copy_from_slice(&self.signer_generation.to_le_bytes());
        fields[16..24].copy_from_slice(&self.key_generation.to_le_bytes());
        fields[24..56].copy_from_slice(&self.key_manifest_hash);
        fields[56..88].copy_from_slice(&Sha256::digest(verifier));
        fields[88..120].copy_from_slice(&Sha256::digest(signer));
        VerifyingKey::from_bytes(boot_key)
            .and_then(|key| key.verify_strict(&message, &Signature::from_bytes(signature)))
            .map_err(|_| Error::Unauthorized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn package_qualification_matches_both_roles_and_committed_key_identity() {
        let installation = TlsInstallation {
            verifier_generation: 3,
            signer_generation: 4,
            key_generation: 5,
            key_manifest_hash: [6; 32],
        };
        let verifier = b"verifier build at generation 3";
        let signer = b"signer build at generation 4";
        let message = [
            b"CYX/TLS-PACKAGES/v1".as_slice(),
            &3u64.to_le_bytes(),
            &4u64.to_le_bytes(),
            &5u64.to_le_bytes(),
            &[6; 32],
            &Sha256::digest(verifier),
            &Sha256::digest(signer),
        ]
        .concat();
        let key = SigningKey::from_bytes(&[7; 32]);
        let signature = key.sign(&message).to_bytes();
        let boot_key = key.verifying_key().to_bytes();
        let verify = |installed: TlsInstallation, verifier: &[u8], signer: &[u8]| {
            installed.qualify_packages(&boot_key, &signature, verifier, signer)
        };
        assert_eq!(verify(installation, verifier, signer), Ok(()));
        assert_eq!(
            verify(installation, signer, verifier),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            verify(installation, verifier, b"previous signer build"),
            Err(Error::Unauthorized)
        );
        for newer in [
            TlsInstallation {
                key_generation: 6,
                ..installation
            },
            TlsInstallation {
                verifier_generation: 4,
                ..installation
            },
            TlsInstallation {
                signer_generation: 5,
                ..installation
            },
            TlsInstallation {
                key_manifest_hash: [7; 32],
                ..installation
            },
        ] {
            assert_eq!(verify(newer, verifier, signer), Err(Error::Unauthorized));
        }
    }
}
