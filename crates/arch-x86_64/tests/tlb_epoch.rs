use cyxia_arch_x86_64::trap::flush_tlb_request;
use std::sync::atomic::{AtomicU64, Ordering};

// A CPU can be paused during an old flush while the initiator times out and
// publishes a retry. The old operation must not acknowledge that newer request.
#[test]
fn request_advanced_during_flush_requires_another_flush_before_acknowledgement() {
    let request = AtomicU64::new(17);
    let acknowledgement = AtomicU64::new(16);
    flush_tlb_request(&request, &acknowledgement, || {
        assert_eq!(acknowledgement.load(Ordering::Acquire), 16);
        request.store(18, Ordering::Release);
    });
    assert_eq!(request.load(Ordering::Acquire), 18);
    assert_eq!(acknowledgement.load(Ordering::Acquire), 17);

    flush_tlb_request(&request, &acknowledgement, || {
        assert_eq!(acknowledgement.load(Ordering::Acquire), 17);
    });
    assert_eq!(acknowledgement.load(Ordering::Acquire), 18);
}
