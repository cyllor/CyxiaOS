//! Bounded epoll graph validation and readiness propagation. No backend calls
//! occur while this shared OFD table is borrowed.
use super::{Errno, IN, OPEN_MAX, Object};
use crate::open_description::{EPOLLS, Handle, Table};
// Linux permits five epoll instances in a path (four nesting edges).
const MAX_DEPTH: usize = 5;

#[derive(Clone, Copy)]
pub(crate) struct Topology {
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
        #[cfg(test)]
        self.nested_lookups.set(self.nested_lookups.get() + 1);
        match self.entry(handle).ok()?.value?.object {
            Object::Epoll(index) => Some(index),
            _ => None,
        }
    }

    pub(in crate::epoll) fn epoll_topology(
        &self,
        extra: Option<(usize, usize)>,
    ) -> Result<Topology, Errno> {
        // Readiness, EDGE delivery and ONESHOT disarming do not change graph
        // edges. Keep their hot path independent of unrelated owners' watches.
        // A proposed ADD is validated separately and must never enter the cache.
        if extra.is_none()
            && let Some(topology) = self.epoll_topology.get()
        {
            return Ok(topology);
        }
        #[cfg(test)]
        self.topology_builds.set(self.topology_builds.get() + 1);
        let mut topology = Topology {
            order: [0; EPOLLS],
            count: 0,
            children: [0; EPOLLS],
        };
        for (index, instance) in self.epolls.iter().enumerate().filter(|(_, e)| e.used) {
            // Disarmed watches remain graph edges: MOD must not resurrect a cycle.
            for slot in instance.live_slots() {
                if let Some(watch) = instance.watches[slot].filter(|watch| watch.backend.is_none())
                    && let Some(child) = self.nested_index(watch.description)
                {
                    topology.children[index] |= 1 << child;
                }
            }
        }
        if let Some((parent, child)) = extra {
            topology.children[parent] |= 1 << child;
        }
        let mut done = 0usize;
        let mut depths = [0; EPOLLS];
        let wanted = self.epolls.iter().filter(|e| e.used).count();
        for _ in 0..EPOLLS {
            if topology.count == wanted {
                break;
            }
            let before = topology.count;
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
            if topology.count == before {
                return Err(Errno::Loop);
            }
        }
        if topology.count != self.epolls.iter().filter(|e| e.used).count() {
            return Err(Errno::Loop);
        }
        if extra.is_none() {
            self.epoll_topology.set(Some(topology));
        }
        Ok(topology)
    }

    pub(in crate::epoll) fn observe_epoll(
        &mut self,
        index: usize,
        readiness: &mut [u32; OPEN_MAX],
    ) -> bool {
        let was_readable = self.epolls[index].readable();
        let mut notified = false;
        for slot in self.epolls[index].live_slots() {
            let Some(watch) = self.epolls[index].watches[slot] else {
                continue;
            };
            let ready = &mut readiness[slot];
            if watch.backend.is_none()
                && let Some(child) = self.nested_index(watch.description)
            {
                *ready = u32::from(self.epolls[child].readable()) * IN;
            }
            notified |= self.epolls[index].observe_watch(slot, *ready, 0);
        }
        self.note_epoll_readability(index, was_readable);
        notified
    }

    pub(crate) fn propagate_nested(&mut self, mut wakes: usize) {
        let mut dirty = core::mem::take(&mut self.epoll_dirty) | wakes;
        if dirty == 0 {
            return;
        }
        let topology = self.epoll_topology(None).expect("validated epoll graph");
        // Child before parent, including when a child shared by multiple
        // parents remains readable and only contributes a new edge.
        for &child in &topology.order[..topology.count] {
            let bit = 1 << child;
            if dirty & bit == 0 {
                continue;
            }
            let handle = self.epolls[child]
                .description
                .expect("live epoll description");
            let ready = u32::from(self.epolls[child].readable()) * IN;
            let notification = u32::from(wakes & bit != 0) * IN;
            let parents = self.observe_description(handle, ready, notification);
            wakes |= parents;
            dirty |= parents | core::mem::take(&mut self.epoll_dirty);
        }
    }
}

const _: () = assert!(EPOLLS <= usize::BITS as usize);
