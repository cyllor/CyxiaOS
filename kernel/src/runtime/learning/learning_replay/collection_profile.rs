//! Collection schedule only. Full dataset and training gates stay in data.rs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum CollectionProfile {
    Full = 0,
    CoreSetOnePair = 1,
    CoreSetDataOnePair = 2,
}
impl CollectionProfile {
    pub const fn first_family(self) -> usize {
        match self {
            Self::Full => 0,
            Self::CoreSetOnePair | Self::CoreSetDataOnePair => 1,
        }
    }
    pub const fn focused(self) -> bool {
        !matches!(self, Self::Full)
    }
    pub const fn bounded(self) -> bool {
        matches!(self, Self::CoreSetDataOnePair)
    }
    pub fn pair_complete(self, verified: u64, archived: u64, paired: usize) -> bool {
        self == Self::CoreSetOnePair && verified == 2 && archived == 2 && paired == 1
    }
}
#[derive(Clone, Copy)]
pub struct ReleaseFacts {
    pub owner_clear: bool,
    pub work_quiescent: bool,
    pub pending_baseline: bool,
    pub witness_durable: bool,
    pub credit_settled: bool,
}
impl ReleaseFacts {
    pub fn complete(self) -> bool {
        self.owner_clear
            && self.work_quiescent
            && !self.pending_baseline
            && self.witness_durable
            && self.credit_settled
    }
}
