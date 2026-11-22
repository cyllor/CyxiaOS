use crate::open_description::{CAPACITY, Handle};
use core::num::NonZeroU16;

const _: () = assert!(CAPACITY <= u16::MAX as usize);

#[derive(Clone, Copy)]
struct Deadline {
    handle: Handle,
    time: u64,
}
impl Deadline {
    const EMPTY: Self = Self {
        handle: Handle { slot: 0, generation: 0 },
        time: 0,
    };
}

/// One heap entry per OFD with a future expiration. The reverse position
/// permits rearm, disarm and final close without a search or stale entries.
pub(crate) struct Deadlines {
    nodes: [Deadline; CAPACITY],
    positions: [Option<NonZeroU16>; CAPACITY],
    len: usize,
}
impl Deadlines {
    pub(crate) const fn new() -> Self {
        Self {
            nodes: [Deadline::EMPTY; CAPACITY],
            positions: [None; CAPACITY],
            len: 0,
        }
    }
    pub(super) fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub(crate) fn scheduled(&self, slot: usize) -> bool {
        self.positions[slot].is_some()
    }
    fn record_position(&mut self, index: usize) {
        self.positions[self.nodes[index].handle.slot] = NonZeroU16::new((index + 1) as u16);
    }
    fn swap(&mut self, left: usize, right: usize) {
        self.nodes.swap(left, right);
        self.record_position(left);
        self.record_position(right);
    }
    fn sift_up(&mut self, mut index: usize) {
        while index > 0 {
            let parent = (index - 1) / 2;
            if self.nodes[parent].time <= self.nodes[index].time {
                break;
            }
            self.swap(parent, index);
            index = parent;
        }
    }
    fn sift_down(&mut self, mut index: usize) {
        while 2 * index + 1 < self.len {
            let left = 2 * index + 1;
            let right = left + 1;
            let child = if right < self.len && self.nodes[right].time < self.nodes[left].time {
                right
            } else {
                left
            };
            if self.nodes[index].time <= self.nodes[child].time {
                break;
            }
            self.swap(index, child);
            index = child;
        }
    }
    pub(crate) fn remove(&mut self, slot: usize) {
        let Some(position) = self.positions[slot].take() else {
            return;
        };
        let index = usize::from(position.get() - 1);
        self.len -= 1;
        if index == self.len {
            return;
        }
        let previous = self.nodes[index].time;
        self.nodes[index] = self.nodes[self.len];
        self.record_position(index);
        if self.nodes[index].time < previous {
            self.sift_up(index);
        } else {
            self.sift_down(index);
        }
    }
    pub(super) fn set(&mut self, handle: Handle, time: Option<u64>) {
        self.remove(handle.slot);
        if let Some(time) = time {
            let index = self.len;
            self.len += 1;
            self.nodes[index] = Deadline { handle, time };
            self.record_position(index);
            self.sift_up(index);
        }
    }
    pub(super) fn pop_due(&mut self, now: u64) -> Option<Handle> {
        let head = self.nodes[0];
        if self.is_empty() || head.time > now {
            return None;
        }
        self.remove(head.handle.slot);
        Some(head.handle)
    }
}
