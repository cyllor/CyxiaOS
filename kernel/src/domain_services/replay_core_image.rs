//! Canonical working-state proof for a CoreSet replay's original configuration.
//! Monotonic receipt generations are bound by the root snapshot separately.
use cyxia_prototype::domains::{Action, Error, ObjectKey};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoreImage {
    pub target: ObjectKey,
    pub control: u64,
    pub business: u64,
    pub healthy: u64,
    pub draining: u64,
}
impl CoreImage {
    pub fn observed(
        target: ObjectKey,
        control: u64,
        business: u64,
        healthy: u64,
        draining: u64,
        pending: bool,
    ) -> Result<Self, Error> {
        if target.id == 0 || target.generation == 0 {
            return Err(Error::Stale);
        }
        if pending || draining != 0 {
            return Err(Error::Busy);
        }
        if !matches!(control, 2 | 6)
            || control & business != 0
            || control & healthy != control
            || business & healthy == 0
        {
            return Err(Error::NotReady);
        }
        Ok(Self {
            target,
            control,
            business,
            healthy,
            draining,
        })
    }
    /// The baseline keeps the original legal set. A candidate's closing action
    /// restores this same observed set, rather than silently choosing mask 2.
    pub fn baseline(self) -> Action {
        Action::ControlSet(self.control)
    }
    pub fn digest(self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"CYXIA_ORIGINAL_CORESET_IMAGE_1.3\0");
        for value in [
            self.target.id,
            self.target.generation,
            self.control,
            self.business,
            self.healthy,
            self.draining,
        ] {
            hash.update(value.to_le_bytes());
        }
        hash.finalize().into()
    }
    pub fn matches(self, actual: Self) -> Result<(), Error> {
        if self == actual {
            Ok(())
        } else {
            Err(Error::Conflict)
        }
    }
}
