//! Default AArch64 startup with a build-pinned external catalog. Admission
//! reopens an existing compatible volume and launches the verified roster.
//! An independently signed workload may run on the fixed business CPUs.

use super::*;
use crate::ExceptionFrame;
use cyxia_kernel_core::control_plane::{
    Error, Identity, cpu0_v0199 as profile,
    role_manifest_v0199::{NativeRole, NativeRoleManifest, ROLE_COUNT, ROLES, Role},
};

mod copy_window;
#[path = "frames.rs"]
pub(crate) mod frames;
#[path = "media_staging.rs"]
mod media_staging;
#[cfg(any(cyxia_business_package, cyxia_resident_net))]
mod net_entropy;
#[cfg(cyxia_resident_net)]
pub(super) mod net_resident;
#[cfg(cyxia_resident_net)]
pub(super) mod network_worker;
#[path = "recovery.rs"]
mod recovery;
#[path = "resident.rs"]
mod resident;
#[path = "role_loader.rs"]
mod role_loader;
#[cfg(cyxia_business_package)]
pub(super) mod signed_business;
mod signed_control;
#[cfg(cyxia_business_package)]
mod signed_d01;
#[path = "signed_resident.rs"]
mod signed_resident;
mod signed_syscalls;
#[path = "startup_catalog.rs"]
mod startup_catalog;

use role_loader::{
    BACKING, Backing, COPY, COPY_BUFFER, CopyBuffer, TABLES, Tables, load_role_with_identity,
    now_ns, ns_from_ticks, pie_context, role_asid, trapped_ttbr0,
};

const E_AUTH: i64 = -1;
const EFAULT: i64 = -12;

pub(crate) fn run(info: &BootInfo) -> ! {
    signed_resident::run(info)
}

pub(crate) fn exception(frame: &mut ExceptionFrame, kind: u64) {
    signed_resident::verify_captured_role(frame, kind);
    super::exception(frame, kind);
}

pub(super) fn timer_deadline() -> u64 {
    resident::timer_deadline()
}
