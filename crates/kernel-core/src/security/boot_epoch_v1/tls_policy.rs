//! An offline TLS policy changes the existing boot pair, not the media layout.
use super::{Error, SecurityStateStoreV2};
use crate::control_plane::role_manifest_v0199::ROLE_COUNT;
use crate::security::{network::deployment::KeyManifest, offline_config_v1::VerifiedOfflineConfig};

pub(in crate::security) const TLS_VERIFIER_SLOT: usize = 12;
pub(in crate::security) const TLS_SIGNER_SLOT: usize = 13;
pub(in crate::security) const TLS_SLOTS: u64 = (1 << TLS_VERIFIER_SLOT) | (1 << TLS_SIGNER_SLOT);

/// An authenticated config and the parsed public key manifest it binds.
/// Older configs with an opaque manifest can be used as a predecessor.
#[derive(Clone, Copy)]
pub struct TlsBootPolicy<'a> {
    config: &'a VerifiedOfflineConfig<'a>,
    manifest: Option<KeyManifest>,
}

impl<'a> TlsBootPolicy<'a> {
    pub fn new(
        config: &'a VerifiedOfflineConfig<'a>,
        manifest: Option<KeyManifest>,
    ) -> Result<Self, Error> {
        if let Some(manifest) = manifest {
            manifest.matches_config(config)?;
        }
        Ok(Self { config, manifest })
    }

    pub fn config(self) -> &'a VerifiedOfflineConfig<'a> {
        self.config
    }

    pub fn listener_enabled(self) -> bool {
        self.manifest
            .is_some_and(|manifest| manifest.listener().is_some())
    }

    fn tls_generations(self) -> [u64; 2] {
        self.manifest.map_or([1; 2], |manifest| {
            let installation = manifest.installation();
            [
                installation.verifier_generation,
                installation.signer_generation,
            ]
        })
    }

    pub fn verify_committed(self, state: &SecurityStateStoreV2) -> Result<(), Error> {
        self.config.check_committed(state)?;
        let header = self.config.header();
        if state.rule_min_generation != header.rule_generation
            || state.security_min_generation != header.security_generation
            || [
                state.service_generations[TLS_VERIFIER_SLOT],
                state.service_generations[TLS_SIGNER_SLOT],
            ] != self.tls_generations()
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }

    pub fn resident_state(self, epoch: u64) -> Result<SecurityStateStoreV2, Error> {
        self.resident_state_with_roles(epoch, [1; ROLE_COUNT])
    }

    /// Native roster slots are fixed by the signed launch owner. Their
    /// generation advances contribute exactly one state transition per
    /// restart and leave the boot counter, TLS slots and config independent.
    pub fn resident_state_with_roles(
        self,
        epoch: u64,
        roles: [u64; ROLE_COUNT],
    ) -> Result<SecurityStateStoreV2, Error> {
        let header = self.config.header();
        let state_generation = roles.iter().try_fold(
            epoch.checked_add(1).ok_or(Error::Exhausted)?,
            |total, &generation| {
                total
                    .checked_add(generation.checked_sub(1).ok_or(Error::Stale)?)
                    .ok_or(Error::Exhausted)
            },
        )?;
        let mut service_generations = [1; 16];
        service_generations[..ROLE_COUNT].copy_from_slice(&roles);
        let [verifier, signer] = self.tls_generations();
        service_generations[TLS_VERIFIER_SLOT] = verifier;
        service_generations[TLS_SIGNER_SLOT] = signer;
        Ok(SecurityStateStoreV2 {
            fs_uuid: header.fs_uuid,
            state_generation,
            rule_min_generation: header.rule_generation,
            security_min_generation: header.security_generation,
            key_generation: header.key_generation,
            isolated_service_bitmap: 0,
            last_boot_epoch: epoch,
            offline_config_generation: header.generation,
            offline_config_hash: self.config.digest(),
            service_generations,
        })
    }

    pub fn verify_resident_state(
        self,
        state: &SecurityStateStoreV2,
        epoch: u64,
    ) -> Result<(), Error> {
        self.verify_committed(state)?;
        let roles = state.service_generations[..ROLE_COUNT].try_into().unwrap();
        if *state != self.resident_state_with_roles(epoch, roles)? {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}

/// An exact signed predecessor-to-successor edge. Both policies are verified
/// by the boot owner under the same locked trust root. No policy clearance,
/// principal migration or rule/profile replacement belongs to this update.
#[derive(Clone, Copy)]
pub struct TlsBootTransition<'a> {
    previous: TlsBootPolicy<'a>,
    current: TlsBootPolicy<'a>,
}

impl<'a> TlsBootTransition<'a> {
    pub fn new(previous: TlsBootPolicy<'a>, current: TlsBootPolicy<'a>) -> Result<Self, Error> {
        let before = previous.config.header();
        let after = current.config.header();
        let manifest = current.manifest.ok_or(Error::Unauthorized)?;
        if manifest.predecessor_config() != previous.config.digest()
            || before.fs_uuid != after.fs_uuid
            || after.generation <= before.generation
            || after.key_generation <= before.key_generation
        {
            return Err(Error::Stale);
        }
        if after.rule_generation != before.rule_generation
            || after.rule_hash != before.rule_hash
            || after.security_generation != before.security_generation
            || after.security_hash != before.security_hash
            || after.payload_hash != before.payload_hash
            || after.mode != 0
            || before.mode != after.mode
            || after.clear_isolation_bitmap != 0
            || before.clear_isolation_bitmap != 0
            || current.config.principals() != previous.config.principals()
            || previous
                .tls_generations()
                .into_iter()
                .zip(current.tls_generations())
                .any(|(before, after)| before.checked_add(1) != Some(after))
        {
            return Err(Error::Conflict);
        }
        if let Some(old_listener) = previous.manifest.and_then(KeyManifest::listener)
            && let Some(new_listener) = manifest.listener()
            && old_listener.local_pin == new_listener.local_pin
            && old_listener.peer_pin == new_listener.peer_pin
        {
            // Address or package changes alone do not rotate a credential.
            return Err(Error::Conflict);
        }
        Ok(Self { previous, current })
    }

    pub fn previous(self) -> TlsBootPolicy<'a> {
        self.previous
    }

    pub fn current(self) -> TlsBootPolicy<'a> {
        self.current
    }

    pub fn successor_state(
        self,
        old: &SecurityStateStoreV2,
    ) -> Result<SecurityStateStoreV2, Error> {
        self.previous.verify_committed(old)?;
        let header = self.current.config.header();
        let mut next = *old;
        next.state_generation = old
            .state_generation
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        next.last_boot_epoch = old.last_boot_epoch.checked_add(1).ok_or(Error::Exhausted)?;
        next.offline_config_generation = header.generation;
        next.offline_config_hash = self.current.config.digest();
        next.key_generation = header.key_generation;
        let [verifier, signer] = self.current.tls_generations();
        next.service_generations[TLS_VERIFIER_SLOT] = verifier;
        next.service_generations[TLS_SIGNER_SLOT] = signer;
        if !next.no_rollback_from(old) {
            return Err(Error::Conflict);
        }
        self.current.verify_committed(&next)?;
        Ok(next)
    }
}
