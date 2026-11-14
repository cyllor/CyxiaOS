//! Actual IRQ route and legal ownership set for a deterministic replay reset.
use cyxia_prototype::domains::{Action, Error, ObjectKey};
use sha2::{Digest, Sha256};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IrqImage {
    pub target: ObjectKey,
    pub current: u16,
    pub hardware_allowed: u64,
    pub healthy_business: u64,
    pub draining: u64,
}
impl IrqImage {
    pub fn observed(
        target: ObjectKey,
        current: u16,
        hardware_allowed: u64,
        healthy_business: u64,
        draining: u64,
    ) -> Result<Self, Error> {
        if target.id == 0 || target.generation != 1 || current >= 64 {
            return Err(Error::Stale);
        }
        let allowed = hardware_allowed & healthy_business & !draining;
        if allowed == 0 || allowed & (1u64 << current) == 0 {
            return Err(Error::NotReady);
        }
        Ok(Self {
            target,
            current,
            hardware_allowed,
            healthy_business,
            draining,
        })
    }
    pub fn baseline(self) -> Action {
        Action::IrqTarget(
            (self.hardware_allowed & self.healthy_business & !self.draining).trailing_zeros()
                as u16,
        )
    }
    pub fn restored(self) -> Self {
        let Action::IrqTarget(current) = self.baseline() else {
            unreachable!()
        };
        Self { current, ..self }
    }
    pub fn digest(self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"CYXIA_ORIGINAL_IRQ_IMAGE_1.3\0");
        for value in [
            self.target.id,
            self.target.generation,
            u64::from(self.current),
            self.hardware_allowed,
            self.healthy_business,
            self.draining,
        ] {
            h.update(value.to_le_bytes());
        }
        h.finalize().into()
    }
    pub fn matches(self, actual: Self) -> Result<(), Error> {
        if self == actual {
            Ok(())
        } else {
            Err(Error::Conflict)
        }
    }
}
