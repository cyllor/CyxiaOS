//! Correct host seam: production anonymous faults and production file-cache
//! replacement execute together. Hardware page-table/native proof is separate.
use cyxia_prototype::{
    domains::{
        Error, ObjectKey,
        filesystem::{FileSystem, OpenMode},
        tasks::{CacheHandle, Memory, MemoryBackend},
    },
    journal::{self, BlockDevice, Journal},
    storage::{BLOCK_SIZE, TOTAL_BLOCKS},
};
use std::collections::BTreeMap;
struct Pages {
    bytes: Vec<[u8; 4096]>,
    maps: BTreeMap<(u64, u64, u64), usize>,
}
impl MemoryBackend for Pages {
    fn zero(&mut self, f: usize) -> Result<(), Error> {
        self.bytes[f].fill(0);
        Ok(())
    }
    fn map(&mut self, k: ObjectKey, va: u64, f: usize, _: bool) -> Result<(), Error> {
        assert!(
            !self.maps.values().any(|old| *old == f),
            "two actual owners received one anonymous frame"
        );
        assert!(self.maps.insert((k.id, k.generation, va), f).is_none());
        Ok(())
    }
    fn revoke(&mut self, k: ObjectKey, va: u64, _: usize) -> Result<(), Error> {
        self.maps.remove(&(k.id, k.generation, va));
        Ok(())
    }
    fn load_cache(&mut self, _: ObjectKey, _: u64, _: usize) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn drop_cache(&mut self, _: CacheHandle) -> Result<(), Error> {
        Ok(())
    }
}
#[derive(Default)]
struct Disk(BTreeMap<u32, [u8; 4096]>);
impl BlockDevice for Disk {
    type Error = ();
    fn block_count(&self) -> u32 {
        TOTAL_BLOCKS
    }
    fn read_block(&mut self, b: u32, out: &mut [u8; BLOCK_SIZE]) -> Result<(), ()> {
        *out = self.0.get(&b).copied().unwrap_or([0; 4096]);
        Ok(())
    }
    fn write_block(&mut self, b: u32, input: &[u8; BLOCK_SIZE]) -> Result<(), ()> {
        self.0.insert(b, *input);
        Ok(())
    }
    fn flush(&mut self) -> Result<(), ()> {
        Ok(())
    }
}
#[test]
fn two_real_anonymous_owners_survive_real_clean_file_cache_replacement() {
    let mut m = Memory::<128, 32>::new();
    let mut backing = Pages {
        bytes: vec![[0xa5; 4096]; 128],
        maps: BTreeMap::new(),
    };
    let keys = [
        ObjectKey {
            id: 11,
            generation: 1,
        },
        ObjectKey {
            id: 12,
            generation: 2,
        },
    ];
    for (key_index, key) in keys.into_iter().enumerate() {
        m.register_owner(key, 16).unwrap();
        assert_eq!(m.owner_quota(key).unwrap(), 16);
        m.reserve(key, 0x60000, 4, true).unwrap();
        for page in 0..4 {
            let f = m
                .fault(key, 0x60000 + page * 4096, false, &mut backing)
                .unwrap();
            assert!(
                backing.bytes[f].iter().all(|b| *b == 0),
                "real fault did not zero reused backing"
            );
            backing.bytes[f].fill((key_index * 32 + page as usize + 1) as u8);
        }
    }
    let original = backing.bytes.clone();
    let mappings = backing.maps.clone();
    let mut disk = Disk::default();
    let mut scratch = [0; 8192];
    journal::format(&mut disk, [1; 16], &mut scratch).unwrap();
    let mut j = Journal::new();
    j.mount(&mut disk, &mut scratch).unwrap();
    cyxia_prototype::boot::BootSession::new()
        .allocate(&mut j, &mut disk, &mut scratch, &mut [[0; 4096]; 4])
        .unwrap();
    let mut fs = FileSystem::<64>::new();
    fs.mount(&mut j, &mut disk, &mut scratch).unwrap();
    fs.create("/anonymous-pressure", &mut j, &mut disk, &mut scratch)
        .unwrap();
    let h = fs
        .open(
            "/anonymous-pressure",
            OpenMode::ReadWrite,
            &mut j,
            &mut disk,
            &mut scratch,
        )
        .unwrap();
    for page in 0..65u64 {
        let bytes = [page as u8; 4096];
        fs.write(h, page * 4096, &bytes, &mut j, &mut disk, &mut scratch)
            .unwrap();
        fs.fsync(h, &mut j, &mut disk, &mut scratch).unwrap();
    }
    let before = fs.cache_evictions();
    let mut read = [0; 65536];
    for page in (0..65u64).step_by(16) {
        let pages = (65 - page).min(16) as usize;
        assert_eq!(
            fs.read(
                h,
                page * 4096,
                &mut read[..pages * 4096],
                0,
                &mut j,
                &mut disk,
                &mut scratch
            )
            .unwrap(),
            pages * 4096
        );
        for offset in 0..pages {
            assert_eq!(
                read[offset * 4096..(offset + 1) * 4096],
                [(page as usize + offset) as u8; 4096]
            );
        }
    }
    assert!(
        fs.cache_evictions() > before,
        "workload never actually replaced a clean cached page"
    );
    m.reclaim_step(128, 0, &mut backing).unwrap();
    assert_eq!(
        backing.maps, mappings,
        "cache pressure revoked anonymous mapping"
    );
    for key in keys {
        for page in 0..4 {
            let f = m.resident(key, 0x60000 + page * 4096).unwrap();
            assert_eq!(backing.bytes[f], original[f], "anonymous sentinel was lost");
        }
    }
}
