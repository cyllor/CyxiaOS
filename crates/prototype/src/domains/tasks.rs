//! Bounded task, VM, IPC and syscall executors. Callers serialize these objects
//! with their hardware/resource gates; backend callbacks perform real effects.
mod ipc;
mod memory;
mod scheduler;
mod service;
mod spawn;

pub use ipc::*;
pub use memory::*;
pub use scheduler::*;
pub use service::*;
pub use spawn::*;

use super::{Error, ObjectKey, PolicyStamp};
pub const MAX_GROUPS: usize = 16;
pub const MAX_THREADS: usize = 64;
pub const MAX_SPAWNS: usize = 64;
pub const MAX_ENDPOINTS: usize = 32;
pub const MAX_MESSAGES: usize = 128;
const UNSET: PolicyStamp = PolicyStamp {
    version: 0,
    snapshot_ns: 0,
    installed_until_ns: 0,
};
const EMPTY_KEY: ObjectKey = ObjectKey {
    id: 0,
    generation: 0,
};
fn valid_key(key: ObjectKey) -> Result<(), Error> {
    if key.id == 0 || key.generation == 0 {
        Err(Error::Auth)
    } else {
        Ok(())
    }
}
