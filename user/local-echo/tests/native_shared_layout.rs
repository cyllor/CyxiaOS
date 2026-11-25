//! Exact host-side cross-check against the existing kernel-shared EL0 ABI.
//! This intentionally compiles the old layout only for tests; no cluster
//! engine or privilege-bearing RPC enters the native local Echo executable.
#[allow(dead_code)]
#[path = "../../prototype-cluster/src/abi.rs"]
mod original;
use core::mem::{offset_of, size_of};
use cyxia_local_echo::abi as limited;

#[test]
fn native_local_echo_shared_page_matches_kernel_broker_offsets() {
    assert_eq!(size_of::<limited::Shared>(), size_of::<original::Shared>());
    assert_eq!(
        size_of::<limited::DomainSourceView>(),
        size_of::<original::DomainInput>()
    );
    assert_eq!(
        offset_of!(limited::Shared, magic),
        offset_of!(original::Shared, magic)
    );
    assert_eq!(
        offset_of!(limited::Shared, sequence),
        offset_of!(original::Shared, sequence)
    );
    assert_eq!(
        offset_of!(limited::Shared, op),
        offset_of!(original::Shared, op)
    );
    assert_eq!(
        offset_of!(limited::Shared, status),
        offset_of!(original::Shared, status)
    );
    assert_eq!(
        offset_of!(limited::Shared, arg0),
        offset_of!(original::Shared, arg0)
    );
    assert_eq!(
        offset_of!(limited::Shared, boot_epoch),
        offset_of!(original::Shared, boot_epoch)
    );
    assert_eq!(
        offset_of!(limited::Shared, service_generation),
        offset_of!(original::Shared, service_generation)
    );
    assert_eq!(
        offset_of!(limited::Shared, connection_epoch),
        offset_of!(original::Shared, connection_epoch)
    );
    assert_eq!(
        offset_of!(limited::Shared, domains),
        offset_of!(original::Shared, domains)
    );
    assert_eq!(
        offset_of!(limited::Shared, domains) + offset_of!(limited::DomainSourceView, peer_ipv4),
        offset_of!(original::Shared, domains) + offset_of!(original::DomainInput, peer_ipv4)
    );
    assert_eq!(
        offset_of!(limited::Shared, payload),
        offset_of!(original::Shared, payload)
    );
    assert_eq!(
        offset_of!(limited::Shared, monotonic_ns),
        offset_of!(original::Shared, monotonic_ns)
    );
    assert_eq!(limited::MAGIC, original::MAGIC);
    assert_eq!(limited::VERSION, original::VERSION);
    assert_eq!(limited::SHARED_VA, original::SHARED_VA);
    assert_eq!(limited::PAYLOAD, original::PAYLOAD);
}
