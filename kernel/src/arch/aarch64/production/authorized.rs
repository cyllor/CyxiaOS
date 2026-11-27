//! Default AArch64 startup with a build-pinned external catalog. The signed
//! SIM admission reopens an existing compatible volume and runs only its
//! authorized lifecycle roles. This owner has no diagnostic service bridge.

use super::*;
use crate::ExceptionFrame;
use cyxia_kernel_core::control_plane::{
    Error, Identity, cpu0_v0199 as profile,
    role_manifest_v0199::{NativeRole, NativeRoleManifest, ROLE_COUNT, ROLES, Role},
};

#[path = "frames.rs"]
mod frames;
#[path = "media_staging.rs"]
mod media_staging;
#[path = "recovery.rs"]
mod recovery;
#[path = "resident.rs"]
mod resident;
#[path = "role_loader.rs"]
mod role_loader;
#[path = "signed_resident.rs"]
mod signed_resident;
#[path = "startup_catalog.rs"]
mod startup_catalog;

use role_loader::{
    BACKING, Backing, COPY, COPY_BUFFER, CopyBuffer, TABLES, Tables, load_role_with_identity,
    now_ns, ns_from_ticks, pie_context, role_asid, trapped_ttbr0,
};

const E_AUTH: i64 = -1;

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
