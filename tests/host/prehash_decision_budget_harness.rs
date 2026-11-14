#![allow(dead_code)]
// Compile the unmodified production preparation module against narrow host
// type facades. This checks its real decision/retained CPU bounds, not native WCET.
extern crate self as cyxia_prototype;

pub mod domains {
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct ObjectKey {
        pub id: u64,
        pub generation: u64,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Error {
        Format, Auth, Schema, Stale, Capacity, Budget, Conflict, Expired,
        Unsupported, Busy, Again, NotReady, Range, Overflow,
    }
}
pub mod policy {
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct ModelBinding {
        pub generation: u64,
        pub model_hash: [u8; 32],
        pub schema_hash: [u8; 32],
    }
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct Snapshot {
        pub sequence: u64,
        pub taken_ns: u64,
        pub ledger_generation: u64,
        pub core_generation: u64,
    }
}

#[path = "../../kernel/src/runtime/control/domain_control/preparation.rs"]
mod preparation;
