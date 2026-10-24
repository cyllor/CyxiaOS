//! Bounded model learning and validation mechanisms. Untrained fixtures and
//! incomplete native measurements never become accepted training labels.
pub mod softfloat;
pub mod reward;

pub const FAMILIES: usize = 18;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Family { pub domain: u16, pub kind: u16 }
impl Family {
    pub fn index(self) -> Result<usize, Error> {
        match (self.domain, self.kind) {
            (1, 1) => Ok(0), (1, 2) => Ok(1),
            (2..=15, 1) => Ok(usize::from(self.domain)),
            (16, 1) => Ok(16), (16, 2) => Ok(17),
            _ => Err(Error::Schema),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayGroup {
    pub seed: u64,
    pub workload: [u8; 32],
    pub initial_image: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchemaBinding { pub version: u32, pub hash: [u8; 32] }
impl SchemaBinding {
    pub fn validate(self) -> Result<(), Error> {
        if self.version == 0 || self.hash == [0;32] { Err(Error::Schema) } else { Ok(()) }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Numeric,
    Model,
    Manifest,
    Schema,
    Untrained,
    FrozenLayers,
    DataIncomplete,
    Evidence,
    GroupOverlap,
    Capacity,
    Order,
    Validation,
    Stale,
    Conflict,
    Budget,
    Deadline,
    Unknown,
    State,
    NoChange,
}
impl From<softfloat::FloatError> for Error {
    fn from(_: softfloat::FloatError) -> Self { Self::Numeric }
}
