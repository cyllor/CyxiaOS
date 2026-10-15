use crate::ContractError;
macro_rules! identity {
    ($name:ident,$ty:ty) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name($ty);
        impl $name {
            pub const fn new(value: $ty) -> Result<Self, ContractError> {
                if value == 0 {
                    Err(ContractError::Invalid)
                } else {
                    Ok(Self(value))
                }
            }
            pub const fn get(self) -> $ty {
                self.0
            }
        }
    };
}
identity!(TaskId, u32);
identity!(Generation, u64);
identity!(PlanId, u64);
identity!(GrantId, u64);
identity!(RedemptionId, u64);
impl Generation {
    pub fn next_checked(self) -> Result<Self, ContractError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(ContractError::Exhausted)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuId(pub u16);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysAddr(pub u64);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtAddr(pub u64);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageCount(pub u32);
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TimeNs(pub u64);
