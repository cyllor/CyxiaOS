//! Signed scratch policy. The resident may pin an external empty policy at
//! build time. The FSYNC profile pins its separate test volume and owner.
use super::volume::UUID;
use cyxia_kernel_core::security::{
    Error,
    offline_config_v1::{CatalogBindings, ConfigHeader, Principal, VerifiedOfflineConfig},
};

#[cfg(not(feature = "v020-production-fsync-scratch"))]
pub(super) const WIRE: &[u8] =
    include_bytes!("../../../../../../tests/fixtures/v020-signed-scratch/config.bin");
#[cfg(feature = "v020-production-fsync-scratch")]
pub(super) const WIRE: &[u8] =
    include_bytes!("../../../../../../tests/fixtures/v020-signed-scratch/fsync-config.bin");
#[cfg(not(feature = "v020-production-fsync-scratch"))]
pub(super) const PAYLOAD: &[u8] = &[0; 12];
#[cfg(feature = "v020-production-fsync-scratch")]
const PAYLOAD: &[u8] = b"CYX-SCRATCH-FSYNC/v1:inode=1,principal=1";
#[cfg(feature = "v020-production-fsync-scratch")]
const RECEIPT_QUERY_WIRE: &[u8] =
    include_bytes!("../../../../../../tests/fixtures/v020-signed-scratch/fsync-receipt-query.bin");
#[cfg(feature = "v020-production-fsync-scratch")]
const RECEIPT_QUERY_PAYLOAD: &[u8] = concat!(
    "CYX-SCRATCH-FILE-RECEIPT-QUERY/v1:",
    "fsync=e987d063b83bff1cf60b1d000845276f0172599f3e36eec4ff1abf4c6e6c14d1,",
    "principal=1,generation=1,holder_role=11,file_service=12,ipc_send=1",
)
.as_bytes();
#[cfg(feature = "v020-production-fsync-scratch")]
const RECEIPT_QUERY_DIGEST: [u8; 32] = [
    0xd0, 0x45, 0xb7, 0x17, 0x23, 0x81, 0xdd, 0xd1, 0x73, 0x0b, 0x9d, 0x44, 0x72, 0x29, 0x9d, 0x26,
    0x37, 0x81, 0x33, 0xbf, 0xa5, 0xb9, 0xb8, 0x29, 0x9e, 0xca, 0x39, 0x66, 0xba, 0x5a, 0x9d, 0x40,
];
#[cfg(feature = "v020-production-fsync-scratch")]
const FSYNC_CLIENT_WIRE: &[u8] =
    include_bytes!("../../../../../../tests/fixtures/v020-signed-scratch/fsync-client.bin");
#[cfg(feature = "v020-production-fsync-scratch")]
const FSYNC_CLIENT_PAYLOAD: &[u8] = concat!(
    "CYX-SCRATCH-FILE-FSYNC-CLIENT/v1:",
    "fsync=e987d063b83bff1cf60b1d000845276f0172599f3e36eec4ff1abf4c6e6c14d1,",
    "principal=1,generation=1,holder_role=11,file_service=12,ipc_send=1,",
    "inode=1,inode_generation=1,file_rights=0x2300",
)
.as_bytes();
#[cfg(feature = "v020-production-fsync-scratch")]
const FSYNC_CLIENT_DIGEST: [u8; 32] = [
    0xf7, 0xfb, 0x8f, 0xff, 0x89, 0x2c, 0xef, 0x54, 0x4f, 0xf5, 0xea, 0xba, 0x4b, 0xe8, 0xce, 0x7d,
    0x57, 0x76, 0x04, 0xca, 0x9d, 0xcd, 0x0f, 0x7a, 0xb0, 0xd4, 0x77, 0x9f, 0x3e, 0x97, 0x27, 0xef,
];
// RFC 8032 test vector 1, public verifying key.
const PUBLIC_KEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
#[cfg(not(feature = "v020-production-fsync-scratch"))]
const WIRE_DIGEST: [u8; 32] = [
    0xff, 0xff, 0x2c, 0x6b, 0x9f, 0xde, 0x3b, 0x53, 0x11, 0xc4, 0xdf, 0x1c, 0x87, 0x1f, 0xf6, 0xb3,
    0x83, 0x08, 0x17, 0xfd, 0x1d, 0x76, 0xe0, 0xa1, 0xfb, 0x4b, 0xc0, 0x7a, 0xaa, 0x36, 0x9b, 0xcf,
];
#[cfg(feature = "v020-production-fsync-scratch")]
const WIRE_DIGEST: [u8; 32] = [
    0xe9, 0x87, 0xd0, 0x63, 0xb8, 0x3b, 0xff, 0x1c, 0xf6, 0x0b, 0x1d, 0x00, 0x08, 0x45, 0x27, 0x6f,
    0x01, 0x72, 0x59, 0x9f, 0x3e, 0x36, 0xee, 0xc4, 0xff, 0x1a, 0xbf, 0x4c, 0x6e, 0x6c, 0x14, 0xd1,
];
const CATALOG: CatalogBindings = CatalogBindings {
    rule_generation: 1,
    security_generation: 1,
    key_generation: 1,
    rule_hash: [
        0xb8, 0xa1, 0xbf, 0x7f, 0x72, 0xa2, 0xee, 0xe8, 0x95, 0x05, 0xd7, 0x71, 0xa8, 0xce, 0x50,
        0x38, 0xf2, 0x8e, 0xa7, 0xcc, 0x59, 0x96, 0xb0, 0x28, 0x75, 0x5c, 0x79, 0x8d, 0x96, 0x32,
        0x7e, 0x4e,
    ],
    security_hash: [
        0x5f, 0xb0, 0x65, 0x1b, 0x6a, 0xf8, 0x9d, 0x50, 0x37, 0xd8, 0x62, 0x2a, 0x61, 0x92, 0x6d,
        0x72, 0xb1, 0x40, 0xe1, 0xb0, 0x51, 0x08, 0x62, 0xe3, 0x56, 0x5e, 0xb6, 0xcd, 0x81, 0x95,
        0xb1, 0xff,
    ],
    key_manifest_hash: [
        0xb0, 0x01, 0x79, 0xae, 0x6e, 0xd2, 0xc6, 0xad, 0x68, 0x4f, 0x29, 0x5f, 0x30, 0x83, 0x21,
        0x9c, 0x57, 0xa6, 0x75, 0x0b, 0x58, 0xd0, 0xf5, 0x55, 0x0d, 0x6f, 0x71, 0x68, 0x64, 0x66,
        0xf2, 0xa8,
    ],
};

/// Accept the pinned repository scratch fixture.
pub(super) fn verify<'a>(
    wire: &'a [u8],
    scratch: &mut [u8],
) -> Result<VerifiedOfflineConfig<'a>, Error> {
    verify_vector(wire, scratch, PAYLOAD, WIRE_DIGEST)
}

pub(super) fn verify_scratch_payload(
    header: &ConfigHeader,
    principals: &[Principal; 16],
    lists: &[u8],
    expected: &[u8],
) -> Result<(), Error> {
    if header.fs_uuid != UUID
        || header.generation != 1
        || header.rule_generation != 1
        || header.security_generation != 1
        || header.key_generation != 1
        || header.mode != 0
        || header.clear_isolation_bitmap != 0
        || lists != expected
        || principals
            .iter()
            .enumerate()
            .any(|(index, p)| p.id != index as u64 + 1 || p.generation != 1)
    {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

fn verify_vector<'a>(
    wire: &'a [u8],
    scratch: &mut [u8],
    payload: &[u8],
    digest: [u8; 32],
) -> Result<VerifiedOfflineConfig<'a>, Error> {
    let config = VerifiedOfflineConfig::verify(
        wire,
        &PUBLIC_KEY,
        CATALOG,
        scratch,
        |header, principals, lists| verify_scratch_payload(header, principals, lists, payload),
    )?;
    if config.digest() != digest {
        return Err(Error::Conflict);
    }
    Ok(config)
}

/// Explicit test-only FILE_RECEIPT_QUERY and IPC_SEND qualification for role 11
/// on this exact FSYNC policy. It neither changes the existing media policy
/// hash nor grants any authority over another volume or service.
#[cfg(feature = "v020-production-fsync-scratch")]
pub(super) fn receipt_query_principal(
    mounted: &VerifiedOfflineConfig<'_>,
    scratch: &mut [u8],
) -> Result<Principal, Error> {
    qualified_principal(
        mounted,
        scratch,
        RECEIPT_QUERY_WIRE,
        RECEIPT_QUERY_PAYLOAD,
        RECEIPT_QUERY_DIGEST,
    )
}

/// Bind the scratch OPEN/WRITE/FSYNC sender to the mounted test policy and
/// its exact inode/ACL scope. The existing media authorization is unchanged.
#[cfg(feature = "v020-production-fsync-scratch")]
pub(super) fn fsync_client_principal(
    mounted: &VerifiedOfflineConfig<'_>,
    scratch: &mut [u8],
) -> Result<Principal, Error> {
    qualified_principal(
        mounted,
        scratch,
        FSYNC_CLIENT_WIRE,
        FSYNC_CLIENT_PAYLOAD,
        FSYNC_CLIENT_DIGEST,
    )
}

#[cfg(feature = "v020-production-fsync-scratch")]
fn qualified_principal(
    mounted: &VerifiedOfflineConfig<'_>,
    scratch: &mut [u8],
    wire: &[u8],
    payload: &[u8],
    digest: [u8; 32],
) -> Result<Principal, Error> {
    let query = verify_vector(wire, scratch, payload, digest)?;
    if mounted.digest() != WIRE_DIGEST || mounted.principals() != query.principals() {
        return Err(Error::Unauthorized);
    }
    Ok(query.principals()[0])
}
