//! Fixed 64-byte allocation units; deallocation restores quota on reconnect.
const UNIT: usize = 64;
pub const HEAP_BYTES: usize = 8 * 1024 * 1024;
const WORDS: usize = HEAP_BYTES / UNIT / 64;
pub struct Arena {
    base: usize,
    units: usize,
    used: [u64; WORDS],
}
impl Arena {
    pub const fn new(base: usize, bytes: usize) -> Self {
        Self {
            base,
            units: if bytes > HEAP_BYTES {
                HEAP_BYTES / UNIT
            } else {
                bytes / UNIT
            },
            used: [0; WORDS],
        }
    }
    pub fn allocate(&mut self, size: usize, align: usize) -> Option<usize> {
        if align == 0 || !align.is_power_of_two() {
            return None;
        }
        let count = size.max(1).checked_add(UNIT - 1)? / UNIT;
        if count > self.units {
            return None;
        }
        let mut begin = 0;
        while begin + count <= self.units {
            let ptr = self.base.checked_add(begin * UNIT)?;
            if ptr & (align - 1) != 0 {
                begin += 1;
                continue;
            }
            let mut offset = 0;
            while offset < count
                && self.used[(begin + offset) / 64] & (1 << ((begin + offset) % 64)) == 0
            {
                offset += 1;
            }
            if offset == count {
                for i in begin..begin + count {
                    self.used[i / 64] |= 1 << (i % 64);
                }
                return Some(ptr);
            }
            begin += offset + 1;
        }
        None
    }
    pub fn release(&mut self, ptr: usize, size: usize) {
        let Some(offset) = ptr.checked_sub(self.base) else {
            return;
        };
        let Some(count) = size.max(1).checked_add(UNIT - 1).map(|n| n / UNIT) else {
            return;
        };
        let begin = offset / UNIT;
        if offset % UNIT != 0 || begin.checked_add(count).is_none_or(|end| end > self.units) {
            return;
        }
        for i in begin..begin + count {
            self.used[i / 64] &= !(1 << (i % 64));
        }
    }
}
