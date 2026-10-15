#![no_std]
mod audit;
mod ids;
mod platform;
mod resource;
pub use audit::*;
pub use ids::*;
pub use platform::*;
pub use resource::*;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractError {
    Invalid,
    Exhausted,
    NotReady,
    Capacity,
}
