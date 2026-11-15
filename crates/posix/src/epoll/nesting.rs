//! Bounded epoll graph validation and readiness propagation. No backend calls
//! occur while this shared OFD table is borrowed.
use super::{Errno, IN, OPEN_MAX, Object};
use crate::open_description::{EPOLLS, Handle, Table};
// Linux permits five epoll instances in a path (four nesting edges).
const MAX_DEPTH: usize = 5;

pub(super) struct Topology {
    pub(super) order: [usize; EPOLLS],
    pub(super) count: usize,
    children: [usize; EPOLLS],
}
impl Topology {
    pub(super) fn reachable(&self, root: usize) -> usize {
        let mut reachable = 1 << root;
        for &index in self.order[..self.count].iter().rev() {
            if reachable & (1 << index) != 0 {
                reachable |= self.children[index];
            }
        }
        reachable
    }
}

impl Table {
    fn nested_index(&self, handle: Handle) -> Option<usize> {
        match self.entry(handle).ok()?.value?.object {
            Object::Epoll(index) => Some(index),
            _ => None,
        }
    }

    pub(in crate::epoll) fn epoll_topology(
        &self,
        extra: Option<(usize, usize)>,
    ) -> Result<Topology, Errno> {
        let mut topology = Topology {
            order: [0; EPOLLS],
            count: 0,
            children: [0; EPOLLS],
        };
        for (index, instance) in self.epolls.iter().enumerate().filter(|(_, e)| e.used) {
            // Disarmed watches remain graph edges: MOD must not resurrect a cycle.
            for watch in instance.watches.iter().flatten() {
                if let Some(child) = self.nested_index(watch.description) {
                    topology.children[index] |= 1 << child;
                }
            }
        }
        if let Some((parent, child)) = extra {
            topology.children[parent] |= 1 << child;
        }
        let mut done = 0usize;
        let mut depths = [0; EPOLLS];
        for _ in 0..EPOLLS {
            for (index, instance) in self.epolls.iter().enumerate() {
                if !instance.used
                    || done & (1 << index) != 0
                    || topology.children[index] & !done != 0
                {
                    continue;
                }
                depths[index] = 1 + depths
                    .iter()
                    .enumerate()
                    .filter(|(child, _)| topology.children[index] & (1 << child) != 0)
                    .map(|(_, depth)| *depth)
                    .max()
                    .unwrap_or(0);
                if depths[index] > MAX_DEPTH {
                    return Err(Errno::Loop);
                }
                topology.order[topology.count] = index;
                topology.count += 1;
                done |= 1 << index;
            }
        }
        if topology.count != self.epolls.iter().filter(|e| e.used).count() {
            return Err(Errno::Loop);
        }
        Ok(topology)
    }

    pub(in crate::epoll) fn observe_epoll(
        &mut self,
        index: usize,
        readiness: &mut [u32; OPEN_MAX],
    ) -> bool {
        let mut notified = false;
        for (slot, ready) in readiness.iter_mut().enumerate() {
            let Some(watch) = self.epolls[index].watches[slot] else {
                continue;
            };
            if let Some(child) = self.nested_index(watch.description) {
                *ready = u32::from(self.epolls[child].readable()) * IN;
            }
            notified |= self.epolls[index].watches[slot]
                .as_mut()
                .unwrap()
                .observe(*ready, 0);
        }
        notified
    }

    pub(crate) fn propagate_nested(&mut self, mut wakes: [bool; EPOLLS]) {
        let topology = self.epoll_topology(None).expect("validated epoll graph");
        for &index in &topology.order[..topology.count] {
            for slot in 0..OPEN_MAX {
                let Some(watch) = self.epolls[index].watches[slot] else {
                    continue;
                };
                let Some(child) = self.nested_index(watch.description) else {
                    continue;
                };
                let ready = u32::from(self.epolls[child].readable()) * IN;
                let notification = u32::from(wakes[child]) * IN;
                wakes[index] |= self.epolls[index].watches[slot]
                    .as_mut()
                    .unwrap()
                    .observe(ready, notification);
            }
        }
    }
}

const _: () = assert!(EPOLLS <= usize::BITS as usize);
