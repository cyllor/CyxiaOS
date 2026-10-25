//! Protected, bounded raw wire state. No operation or acceptance verdict lives here.
use core::sync::atomic::{AtomicU64, Ordering};

#[repr(C, align(4096))]
pub struct Capture {
    pub words: [AtomicU64; 24640],
}
impl Capture {
    pub const fn new() -> Self {
        Self {
            words: [const { AtomicU64::new(0) }; 24640],
        }
    }
    fn put(&self, at: usize, words: &[u64]) {
        for (slot, value) in self.words[at..].iter().zip(words) {
            slot.store(*value, Ordering::Relaxed);
        }
    }
    fn bytes(&self, at: usize, bytes: &[u8]) {
        for (slot, bytes) in self.words[at..].iter().zip(bytes.chunks_exact(8)) {
            slot.store(
                u64::from_le_bytes(bytes.try_into().unwrap()),
                Ordering::Relaxed,
            );
        }
    }
    pub fn begin(&self, config: &[u64; 64], epoch: u64, uuid: [u8; 16]) -> bool {
        if config[0] != 0x4359584131304346
            || config[1] != 1
            || !(1..=3).contains(&config[2])
            || config[3] != epoch
            || epoch == 0
            || config[4..6] == [0; 2]
            || config[6..18].chunks(4).any(|v| v == [0; 4])
            || config[20..].iter().any(|v| *v != 0)
            || config[18..20].iter().flat_map(|v| v.to_le_bytes()).ne(uuid)
        {
            return false;
        }
        self.put(0, &[0x4359584131305452, 1, 768, 0, 0, epoch, config[2]]);
        self.put(7, &config[4..6]);
        self.bytes(9, &uuid);
        self.put(15, &config[6..18]);
        true
    }
    pub fn owner(&self, role: usize, owner: [u64; 2]) -> bool {
        if !(1..=2).contains(&role)
            || owner.contains(&0)
            || (role == 1 && self.words[6].load(Ordering::Acquire) == 3)
        {
            return false;
        }
        let at = 11 + (role - 1) * 2;
        if self.words[at].load(Ordering::Acquire) != 0 {
            return false;
        }
        self.put(at, &owner);
        true
    }
    pub fn selected(&self, owner: [u64; 2]) -> bool {
        self.role(owner).is_some()
    }
    pub fn role(&self, owner: [u64; 2]) -> Option<usize> {
        if owner.contains(&0) {
            return None;
        }
        (0..2).find(|role| {
            let at = 11 + role * 2;
            self.words[at].load(Ordering::Acquire) == owner[0]
                && self.words[at + 1].load(Ordering::Acquire) == owner[1]
        })
    }
    pub fn fail(&self) {
        self.words[4].store(1, Ordering::Release);
    }
    /// Single CPU0 producer: complete the row before releasing its count.
    pub fn record(&self, metadata: [u64; 10], hash: [u8; 32], frame: &[u8; 640]) {
        if !self.selected([metadata[2], metadata[3]]) {
            return;
        }
        let count = self.words[3].load(Ordering::Acquire);
        if count >= 256 {
            self.fail();
            return;
        }
        let at = 64 + count as usize * 96;
        self.put(at, &[0x4359584131304556, count + 1]);
        self.put(at + 2, &metadata);
        self.bytes(at + 12, &hash);
        self.bytes(at + 16, frame);
        self.words[3].store(count + 1, Ordering::Release);
    }
}
