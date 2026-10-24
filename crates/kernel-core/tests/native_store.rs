//! Exercise the actual kernel broker against the real journal and a sparse
//! block device; this is not a duplicate implementation of its ordinal cache.
extern crate self as cyxia_arch_aarch64;
mod cpu {
    pub fn slot() -> usize {
        0
    }
}
mod prototype_storage {
    use cyxia_prototype::{
        boot::BootSession,
        journal::{BlockDevice, Journal},
    };
    use std::{cell::RefCell, collections::BTreeMap};
    pub struct Disk(BTreeMap<u32, [u8; 4096]>);
    impl BlockDevice for Disk {
        type Error = ();
        fn block_count(&self) -> u32 {
            131072
        }
        fn read_block(&mut self, n: u32, b: &mut [u8; 4096]) -> Result<(), ()> {
            *b = self.0.get(&n).copied().unwrap_or([0; 4096]);
            Ok(())
        }
        fn write_block(&mut self, n: u32, b: &[u8; 4096]) -> Result<(), ()> {
            self.0.insert(n, *b);
            Ok(())
        }
        fn flush(&mut self) -> Result<(), ()> {
            Ok(())
        }
    }
    thread_local! {static DEVICE:RefCell<(Journal,Disk,[u8;8192])>=RefCell::new((Journal::new(),Disk(BTreeMap::new()),[0;8192]));}
    pub fn with_journal<R>(f: impl FnOnce(&mut Journal, &mut Disk, &mut [u8; 8192]) -> R) -> R {
        DEVICE.with(|c| {
            let mut s = c.borrow_mut();
            let (j, d, b) = &mut *s;
            f(j, d, b)
        })
    }
    pub fn with_progress<R>(
        p: &mut dyn FnMut(),
        f: impl FnOnce(&mut Journal, &mut Disk, &mut [u8; 8192]) -> R,
    ) -> R {
        p();
        with_journal(f)
    }
    pub fn init() {
        with_journal(|j, d, s| {
            cyxia_prototype::journal::format(d, [9; 16], s).unwrap();
            j.mount(d, s).unwrap();
            BootSession::new()
                .allocate(j, d, s, &mut [[0; 4096]; 4])
                .unwrap();
        });
    }
}
#[path = "../../../kernel/src/unified_store.rs"]
mod store;
#[test]
fn missing_ordinal_cannot_relabel_the_last_scanned_record() {
    prototype_storage::init();
    store::init();
    let mut bytes = [0; 4096];
    let mut p = || {};
    bytes[..85].fill(9);
    bytes[..5].copy_from_slice(b"CXID1");
    assert_eq!(
        store::request(true, 0, 85, 1, 0, &mut bytes, 85, &mut p).0,
        0
    );
    bytes[..100].fill(7);
    assert_eq!(
        store::request(true, 1, 100, 1, 0, &mut bytes, 100, &mut p).0,
        0
    );
    assert_eq!(
        store::request(false, 1, 0, 0, 0, &mut bytes, 4096, &mut p),
        (0, 85, 85)
    );
    let first = bytes[..85].to_vec();
    assert_eq!(
        store::request(false, 3, 0, 0, 0, &mut bytes, 4096, &mut p).0,
        4
    );
    assert_eq!(
        store::request(false, 1, 0, 0, 0, &mut bytes, 4096, &mut p),
        (0, 85, 85)
    );
    assert_eq!(&bytes[..85], first);
    // Partial chunks cannot publish a record or acknowledge a mismatched total.
    bytes[..10].fill(4);
    assert_eq!(
        store::request(true, 2, 20, 0, 0, &mut bytes, 10, &mut p).0,
        0
    );
    assert_eq!(
        store::request(true, 2, 20, 1, 11, &mut bytes, 9, &mut p).0,
        3
    );
    assert_eq!(
        store::request(false, 3, 0, 0, 0, &mut bytes, 4096, &mut p).0,
        4
    );
    // Exhaust ordinary storage through the actual broker, then prove that a
    // deterministic no-space result keeps both reads and closing reserve live.
    let mut exhausted = false;
    for key in 10..600 {
        let total = cyxia_prototype::cluster::MAX_EFFECT;
        let mut status = 0;
        for offset in (0..total).step_by(4096) {
            let n = (total - offset).min(4096);
            bytes[..n].fill(0x77);
            status = store::request(
                true,
                key,
                total as u64,
                u64::from(offset + n == total),
                offset as u64,
                &mut bytes,
                n,
                &mut p,
            )
            .0;
            if status != 0 {
                break;
            }
        }
        if status == 5 {
            exhausted = true;
            break;
        }
        assert_eq!(status, 0);
    }
    assert!(
        exhausted,
        "ordinary quota must backpressure before closing reserve"
    );
    assert_eq!(
        store::request(false, 1, 0, 0, 0, &mut bytes, 4096, &mut p).0,
        0
    );
    // Fill the residual ordinary tail too, so a short new grant cannot slip
    // through unused ordinary space and masquerade as closing-reserve access.
    for key in 2000..4000 {
        bytes[..32].fill(0x77);
        let status = store::request(true, key, 32, 1, 0, &mut bytes, 32, &mut p).0;
        if status == 5 {
            break;
        }
        assert_eq!(status, 0);
    }
    bytes[..32].fill(0);
    bytes[..4].copy_from_slice(b"CXE1");
    bytes[12] = 10;
    bytes[31] = 3;
    assert_eq!(
        store::request(true, 4000, 32, 1, 0, &mut bytes, 32, &mut p).0,
        5,
        "a requester grant is not a closing record"
    );
    for tag in [5u8, 6, 7, 8, 9, 10, 12, 13] {
        bytes[..32].fill(0);
        bytes[..4].copy_from_slice(b"CXE1");
        bytes[12] = tag;
        bytes[31] = 5;
        assert_eq!(
            store::request(
                true,
                1000 + u64::from(tag),
                32,
                1,
                0,
                &mut bytes,
                32,
                &mut p
            )
            .0,
            0,
            "closing tag {tag}"
        );
    }
}
