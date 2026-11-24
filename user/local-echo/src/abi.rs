//! Standalone V0.19 read-only view of the existing native EL0 shared-page
//! broker layout (version 4). No cluster task or storage types are imported.
//! The reserved fields are never parsed as a remote protocol or authorization.
//!
//! This is an exact memory-layout compatibility adapter, NOT permission to
//! invoke the corresponding legacy service operations.
#![forbid(unsafe_code)]
pub const SHARED_VA:u64=0x0200_0000;
pub const SHARED_BYTES:usize=16_384;
pub const SVC:u16=0x43;
pub const MAGIC:u64=0x4359_5843_4c53_3031;
pub const VERSION:u64=4;
pub const PAYLOAD:usize=4096;
pub const OK:u64=0;
pub const AGAIN:u64=1;
pub const EOF:u64=2;
pub const FAILED:u64=3;
/// Original DomainInput is 4 policy wires, two placement counters, one
/// peer IPv4 observation and 17 trailing u64 values (incl. quote metadata).
#[repr(C)]
pub struct DomainSourceView {
    _prior:[u64;30],
    pub peer_ipv4:u64,
    _tail:[u64;17],
}
/// 4 receipts, 15 counters, 3 telemetry vectors, 2 TX counters, 32 old
/// placement rows, one quote-stop receipt and last counter = 264 u64.
/// Not interpreted or write-mapped by this read-only Echo guest.
pub const FEEDBACK_WORDS:usize=264;
#[repr(C,align(4096))]
pub struct Shared {
    pub magic:u64,
    pub version:u64,
    pub sequence:u64,
    pub op:u64,
    pub status:u64,
    pub len:u64,
    pub offset:u64,
    pub arg0:u64,
    pub arg1:u64,
    pub arg2:u64,
    pub monotonic_ms:u64,
    pub unix_seconds:u64,
    pub boot_epoch:u64,
    pub service_generation:u64,
    pub connection_epoch:u64,
    pub uuid:[u8;16],
    pub local_node:[u8;32],
    pub peer_node:[u8;32],
    pub domains:DomainSourceView,
    _feedback:[u64;FEEDBACK_WORDS],
    pub payload:[u8;PAYLOAD],
    pub monotonic_ns:u64,
    _feedback_sequence:u64,
}
pub fn valid_service_identity(page:&Shared,epoch:u64,generation:u64)->bool{
    epoch!=0 && generation!=0 && page.magic==MAGIC && page.version==VERSION
        && page.boot_epoch==epoch && page.service_generation==generation
}
const _:()={
    assert!(core::mem::size_of::<DomainSourceView>()==384);
    assert!(core::mem::offset_of!(DomainSourceView,peer_ipv4)==240);
    assert!(core::mem::offset_of!(Shared,domains)==200);
    assert!(core::mem::offset_of!(Shared,payload)==2696);
    assert!(core::mem::offset_of!(Shared,monotonic_ns)==6792);
    assert!(core::mem::size_of::<Shared>()==8192);
    assert!(core::mem::size_of::<Shared>()<=SHARED_BYTES);
};
#[cfg(test)]
mod tests{
    use super::*;
    #[test] fn guest_view_matches_existing_protected_shared_page_offsets(){
        assert_eq!(core::mem::size_of::<DomainSourceView>(),384);
        assert_eq!(core::mem::offset_of!(Shared,payload),2696);
        assert_eq!(core::mem::offset_of!(Shared,domains)+
            core::mem::offset_of!(DomainSourceView,peer_ipv4),440);
        assert_eq!(core::mem::size_of::<Shared>(),8192);
    }
}
