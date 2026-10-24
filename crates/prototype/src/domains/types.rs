pub const WINDOW_NS: u64 = 100_000_000;
pub const POLICY_NS: u64 = 10_000_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Format,
    Auth,
    Schema,
    Stale,
    Capacity,
    Budget,
    Conflict,
    Expired,
    Unsupported,
    Busy,
    Again,
    NotFound,
    Exists,
    NotDirectory,
    IsDirectory,
    NotEmpty,
    Range,
    Io,
    Overflow,
    NotReady,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct ObjectKey {
    pub id: u64,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ApplyId {
    pub boot_epoch: u64,
    pub controller_epoch: u64,
    pub plan_seq: u64,
    pub action_index: u16,
    pub target: ObjectKey,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PolicyStamp {
    pub version: u64,
    pub snapshot_ns: u64,
    pub installed_until_ns: u64,
}

impl PolicyStamp {
    pub fn new(version: u64, snapshot_ns: u64, now_ns: u64) -> Result<Self, Error> {
        if version == 0 {
            return Err(Error::Stale);
        }
        if now_ns < snapshot_ns {
            return Err(Error::Range);
        }
        if now_ns - snapshot_ns > WINDOW_NS {
            return Err(Error::Expired);
        }
        Ok(Self {
            version,
            snapshot_ns,
            installed_until_ns: snapshot_ns.checked_add(POLICY_NS).ok_or(Error::Overflow)?,
        })
    }

    pub fn live(self, now_ns: u64) -> bool {
        self.version != 0 && now_ns >= self.snapshot_ns && now_ns < self.installed_until_ns
    }

    /// Exact retry is idempotent, including after expiry. It never extends TTL.
    pub fn accepts(self, next: Self, now_ns: u64) -> Result<(), Error> {
        if next.version == 0 {
            return Err(Error::Stale);
        }
        if next.version == self.version {
            return if self == next {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        if next.version < self.version {
            return Err(Error::Stale);
        }
        if next != Self::new(next.version, next.snapshot_ns, now_ns)? {
            return Err(Error::Format);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    CpuWeight(u16),
    ControlSet(u64),
    SpawnTokens(u16),
    Cache { pages: u32, batch: u16 },
    Filesystem { readahead: u16, flush: u16 },
    Ipc { budget: u16, batch: u8 },
    IrqTarget(u16),
    SoftCoalesce(u16),
    ServiceBatch(u8),
    IoShare(u16),
    TxBatch(u8),
    NotifyBatch(u8),
    UnauthRate(u16),
    BackgroundBudget(u16),
    RecoveryRecipe(u16),
    ConsoleBatch(u16),
    OfferCpu(u16),
    Placement(u16),
}

impl Action {
    pub const fn domain(self) -> u16 {
        match self {
            Self::CpuWeight(_) | Self::ControlSet(_) => 1,
            Self::SpawnTokens(_) => 2,
            Self::Cache { .. } => 3,
            Self::Filesystem { .. } => 4,
            Self::Ipc { .. } => 5,
            Self::IrqTarget(_) => 6,
            Self::SoftCoalesce(_) => 7,
            Self::ServiceBatch(_) => 8,
            Self::IoShare(_) => 9,
            Self::TxBatch(_) => 10,
            Self::NotifyBatch(_) => 11,
            Self::UnauthRate(_) => 12,
            Self::BackgroundBudget(_) => 13,
            Self::RecoveryRecipe(_) => 14,
            Self::ConsoleBatch(_) => 15,
            Self::OfferCpu(_) | Self::Placement(_) => 16,
        }
    }
    pub const fn kind(self) -> u16 {
        match self {
            Self::ControlSet(_) | Self::Placement(_) => 2,
            _ => 1,
        }
    }
    pub const fn one_shot(self) -> bool {
        matches!(
            self,
            Self::ControlSet(_) | Self::RecoveryRecipe(_) | Self::Placement(_)
        )
    }
    pub const fn single_action(self) -> bool {
        matches!(self, Self::ControlSet(_) | Self::RecoveryRecipe(_))
    }
    pub fn validate(self) -> Result<(), Error> {
        let valid = match self {
            Self::CpuWeight(v) | Self::SpawnTokens(v) => [1, 2, 4, 8].contains(&v),
            Self::ControlSet(mask) => mask != 0 && mask & !15 == 0 && mask != 15,
            Self::Cache { pages, batch } => {
                [(64, 4), (256, 16), (1024, 32), (4096, 64)].contains(&(pages, batch))
            }
            Self::Filesystem { readahead, flush } => {
                [(0, 4), (2, 8), (8, 16), (16, 32)].contains(&(readahead, flush))
            }
            Self::Ipc { budget, batch } => {
                [(8, 1), (32, 4), (64, 8), (128, 16)].contains(&(budget, batch))
            }
            Self::IrqTarget(v) => v < 4,
            Self::SoftCoalesce(v) => [0, 50, 200, 1000].contains(&v),
            Self::ServiceBatch(v) | Self::NotifyBatch(v) => [1, 2, 4, 8].contains(&v),
            Self::IoShare(v) => [100, 250, 500, 750].contains(&v),
            Self::TxBatch(v) => [1, 4, 8, 16].contains(&v),
            Self::UnauthRate(v) => [4, 8, 16, 32].contains(&v),
            Self::BackgroundBudget(v) => [50, 100, 200, 400].contains(&v),
            Self::RecoveryRecipe(v) | Self::Placement(v) => v <= 2,
            Self::ConsoleBatch(v) => [1, 8, 32, 64].contains(&v),
            Self::OfferCpu(v) => [100, 250, 500, 1000].contains(&v),
        };
        if valid { Ok(()) } else { Err(Error::Range) }
    }

    /// Numeric schema order, independent of little-endian serialization.
    pub const fn order(self) -> (u16, u16, u64, u64) {
        let (a, b) = match self {
            Self::ControlSet(mask) => (mask, 0),
            Self::Cache { pages, batch } => (pages as u64, batch as u64),
            Self::Filesystem { readahead, flush } => (readahead as u64, flush as u64),
            Self::Ipc { budget, batch } => (budget as u64, batch as u64),
            Self::ServiceBatch(v) | Self::TxBatch(v) | Self::NotifyBatch(v) => (v as u64, 0),
            Self::CpuWeight(v)
            | Self::SpawnTokens(v)
            | Self::IrqTarget(v)
            | Self::SoftCoalesce(v)
            | Self::IoShare(v)
            | Self::UnauthRate(v)
            | Self::BackgroundBudget(v)
            | Self::RecoveryRecipe(v)
            | Self::ConsoleBatch(v)
            | Self::OfferCpu(v)
            | Self::Placement(v) => (v as u64, 0),
        };
        (self.domain(), self.kind(), a, b)
    }
}
