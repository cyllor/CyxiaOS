use crate::*;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetLimit(pub PageCount);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlanAllowance {
    pub plan: PlanId,
    pub limit: PageCount,
    pub expires: TimeNs,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PagePermissions {
    writable: bool,
    executable: bool,
}
impl PagePermissions {
    pub const fn new(writable: bool, executable: bool) -> Result<Self, ContractError> {
        if writable && executable {
            Err(ContractError::Invalid)
        } else {
            Ok(Self {
                writable,
                executable,
            })
        }
    }
    pub const fn writable(self) -> bool {
        self.writable
    }
    pub const fn executable(self) -> bool {
        self.executable
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionKind {
    Ram,
    Reserved,
    Device,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryRegion {
    pub start: PhysAddr,
    pub len: u64,
    pub kind: RegionKind,
}
impl MemoryRegion {
    pub const EMPTY: Self = Self {
        start: PhysAddr(0),
        len: 0,
        kind: RegionKind::Reserved,
    };
    pub fn end(self) -> Result<u64, ContractError> {
        self.start
            .0
            .checked_add(self.len)
            .ok_or(ContractError::Invalid)
    }
    pub fn overlaps(self, other: Self) -> bool {
        match (self.end(), other.end()) {
            (Ok(a), Ok(b)) => self.start.0 < b && other.start.0 < a,
            _ => true,
        }
    }
}
