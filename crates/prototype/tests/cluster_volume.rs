use cyxia_prototype::{
    boot::BootSession,
    cluster::volume::{Cursor, Volume, VolumeScratch},
    journal::{self, BlockDevice, Journal},
    storage::TOTAL_BLOCKS,
};
use std::collections::BTreeMap;
#[derive(Default)]
struct Disk {
    stable: BTreeMap<u32, Box<[u8; 4096]>>,
    pending: BTreeMap<u32, Box<[u8; 4096]>>,
    fail: bool,
}
impl BlockDevice for Disk {
    type Error = ();
    fn block_count(&self) -> u32 {
        TOTAL_BLOCKS
    }
    fn read_block(&mut self, n: u32, b: &mut [u8; 4096]) -> Result<(), ()> {
        if let Some(a) = self.pending.get(&n).or(self.stable.get(&n)) {
            *b = **a
        } else {
            b.fill(0)
        }
        Ok(())
    }
    fn write_block(&mut self, n: u32, b: &[u8; 4096]) -> Result<(), ()> {
        self.pending.insert(n, Box::new(*b));
        Ok(())
    }
    fn flush(&mut self) -> Result<(), ()> {
        if self.fail {
            return Err(());
        }
        self.stable.append(&mut self.pending);
        Ok(())
    }
}
#[test]
fn regular_file_events_survive_reboot_and_boot_counter_remains_strict() {
    let mut d = Disk::default();
    let mut s = [0; 8192];
    journal::format(&mut d, [7; 16], &mut s).unwrap();
    let mut j = Journal::new();
    j.mount(&mut d, &mut s).unwrap();
    BootSession::new()
        .allocate(&mut j, &mut d, &mut s, &mut [[0; 4096]; 4])
        .unwrap();
    let mut w: Box<VolumeScratch> = Box::new([[0; 4096]; 16]);
    let mut v = Volume::open(&mut j, &mut d, &mut s, &mut w).unwrap();
    v.append(&mut j, &mut d, &mut s, &mut w, b"one", false)
        .unwrap();
    v.append(&mut j, &mut d, &mut s, &mut w, &[42; 32768], false)
        .unwrap();
    d.pending.clear();
    let mut j = Journal::new();
    j.mount(&mut d, &mut s).unwrap();
    assert_eq!(
        BootSession::new()
            .allocate(&mut j, &mut d, &mut s, &mut [[0; 4096]; 4])
            .unwrap()
            .epoch,
        2
    );
    let v = Volume::open(&mut j, &mut d, &mut s, &mut w).unwrap();
    let mut c = Cursor::new();
    let mut out = [0; 33200];
    assert_eq!(
        v.next(&mut j, &mut d, &mut s, &mut w, &mut c, &mut out)
            .unwrap(),
        Some(3)
    );
    assert_eq!(&out[..3], b"one");
    assert_eq!(
        v.next(&mut j, &mut d, &mut s, &mut w, &mut c, &mut out)
            .unwrap(),
        Some(32768)
    );
    assert_eq!(&out[..32768], &[42; 32768]);
    assert_eq!(
        v.next(&mut j, &mut d, &mut s, &mut w, &mut c, &mut out)
            .unwrap(),
        None
    );
}
#[test]
fn failed_flush_loses_uncommitted_event_after_crash() {
    let mut d = Disk::default();
    let mut s = [0; 8192];
    journal::format(&mut d, [7; 16], &mut s).unwrap();
    let mut j = Journal::new();
    j.mount(&mut d, &mut s).unwrap();
    BootSession::new()
        .allocate(&mut j, &mut d, &mut s, &mut [[0; 4096]; 4])
        .unwrap();
    let mut w = Box::new([[0; 4096]; 16]);
    let mut v = Volume::open(&mut j, &mut d, &mut s, &mut w).unwrap();
    d.fail = true;
    assert!(
        v.append(&mut j, &mut d, &mut s, &mut w, b"lost", false)
            .is_err()
    );
    d.pending.clear();
    d.fail = false;
    let mut j = Journal::new();
    j.mount(&mut d, &mut s).unwrap();
    let v = Volume::open(&mut j, &mut d, &mut s, &mut w).unwrap();
    assert_eq!(
        v.next(
            &mut j,
            &mut d,
            &mut s,
            &mut w,
            &mut Cursor::new(),
            &mut [0; 33200]
        )
        .unwrap(),
        None
    );
}
