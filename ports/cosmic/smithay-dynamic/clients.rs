//! Bounded connection identities, independent of Wayland and fixture roles.
//! Slot reuse never reuses a connection ID or its generation. Actual protocol
//! ownership is checked in addition to the generational key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Key {
    pub slot: usize,
    pub generation: u32,
    pub id: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Peer {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Full,
    Exhausted,
    Peer,
    Stale,
    Owner,
    Bound,
}
#[derive(Debug)]
pub(crate) struct Entry<C> {
    pub key: Key,
    pub peer: Peer,
    owner: Option<C>,
}
pub(crate) struct Registry<C, const N: usize> {
    slots: [Option<Entry<C>>; N],
    generations: [u32; N],
    next_id: u32,
}
impl<C: PartialEq, const N: usize> Registry<C, N> {
    pub fn new() -> Self {
        Self {
            slots: std::array::from_fn(|_| None),
            generations: [0; N],
            next_id: 1,
        }
    }
    pub fn len(&self) -> usize {
        self.slots.iter().flatten().count()
    }
    pub fn reserve(&mut self, peer: Peer) -> Result<Key, Error> {
        if peer.pid <= 0 {
            return Err(Error::Peer);
        }
        let slot = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Full)?;
        let generation = self.generations[slot]
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        let next_id = self.next_id.checked_add(1).ok_or(Error::Exhausted)?;
        let key = Key {
            slot,
            generation,
            id: self.next_id,
        };
        self.slots[slot] = Some(Entry {
            key,
            peer,
            owner: None,
        });
        self.generations[slot] = generation;
        self.next_id = next_id;
        Ok(key)
    }
    fn entry(&self, key: Key) -> Result<&Entry<C>, Error> {
        self.slots
            .get(key.slot)
            .and_then(Option::as_ref)
            .filter(|entry| entry.key == key)
            .ok_or(Error::Stale)
    }
    pub fn bind(&mut self, key: Key, owner: C) -> Result<(), Error> {
        if self.entry(key)?.owner.is_some() {
            return Err(Error::Bound);
        }
        self.slots[key.slot].as_mut().ok_or(Error::Stale)?.owner = Some(owner);
        Ok(())
    }
    pub fn get(&self, key: Key, owner: &C) -> Result<&Entry<C>, Error> {
        let entry = self.entry(key)?;
        if entry.owner.as_ref() != Some(owner) {
            return Err(Error::Owner);
        }
        Ok(entry)
    }
    pub fn remove(&mut self, key: Key, owner: &C) -> Result<Entry<C>, Error> {
        self.get(key, owner)?;
        self.slots[key.slot].take().ok_or(Error::Stale)
    }
    /// Roll back a reserved slot if protocol registration fails. The monotonic
    /// identity remains consumed, so no observer can reuse its stale key.
    pub fn rollback(&mut self, key: Key) -> Result<(), Error> {
        if self.entry(key)?.owner.is_some() {
            return Err(Error::Bound);
        }
        self.slots[key.slot] = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn peer(pid: i32) -> Peer {
        Peer {
            pid,
            uid: 0,
            gid: 0,
        }
    }
    #[test]
    fn full_rejection_does_not_consume_identity_or_generation() {
        let mut registry = Registry::<u32, 2>::new();
        let a = registry.reserve(peer(2)).unwrap();
        registry.bind(a, 20).unwrap();
        let b = registry.reserve(peer(3)).unwrap();
        registry.bind(b, 30).unwrap();
        assert_eq!(registry.reserve(peer(4)), Err(Error::Full));
        assert_eq!(registry.len(), 2);
        registry.remove(b, &30).unwrap();
        let c = registry.reserve(peer(5)).unwrap();
        assert_eq!(
            a,
            Key {
                slot: 0,
                generation: 1,
                id: 1
            }
        );
        assert_eq!(
            b,
            Key {
                slot: 1,
                generation: 1,
                id: 2
            }
        );
        assert_eq!(
            c,
            Key {
                slot: 1,
                generation: 2,
                id: 3
            }
        );
        registry.bind(c, 50).unwrap();
        assert_eq!(registry.get(c, &50).unwrap().peer, peer(5));
    }
    #[test]
    fn slot_reuse_rejects_stale_key_even_with_new_owner() {
        let mut registry = Registry::<u32, 1>::new();
        let old = registry.reserve(peer(2)).unwrap();
        registry.bind(old, 20).unwrap();
        registry.remove(old, &20).unwrap();
        let new = registry.reserve(peer(5)).unwrap();
        registry.bind(new, 50).unwrap();
        assert_eq!(registry.get(old, &50).unwrap_err(), Error::Stale);
        assert_eq!(registry.remove(old, &50).unwrap_err(), Error::Stale);
        assert_eq!(registry.get(new, &20).unwrap_err(), Error::Owner);
        assert_eq!(registry.remove(new, &20).unwrap_err(), Error::Owner);
        assert_eq!(registry.get(new, &50).unwrap().key, new);
    }
    #[test]
    fn binding_and_rollback_are_single_owner_operations() {
        let mut registry = Registry::<u32, 1>::new();
        let failed = registry.reserve(peer(2)).unwrap();
        assert_eq!(registry.get(failed, &20).unwrap_err(), Error::Owner);
        registry.rollback(failed).unwrap();
        assert_eq!(registry.bind(failed, 20), Err(Error::Stale));
        let live = registry.reserve(peer(2)).unwrap();
        assert_eq!(live.id, 2);
        registry.bind(live, 20).unwrap();
        assert_eq!(registry.bind(live, 30), Err(Error::Bound));
        assert_eq!(registry.rollback(live), Err(Error::Bound));
        assert_eq!(registry.get(live, &20).unwrap().peer.pid, 2);
    }
    #[test]
    fn invalid_peer_zero_capacity_and_counter_exhaustion_are_atomic() {
        assert_eq!(Registry::<u32, 0>::new().reserve(peer(1)), Err(Error::Full));
        let mut registry = Registry::<u32, 1>::new();
        for pid in [0, -1] {
            assert_eq!(registry.reserve(peer(pid)), Err(Error::Peer));
        }
        assert_eq!(registry.len(), 0);
        registry.next_id = u32::MAX;
        assert_eq!(registry.reserve(peer(2)), Err(Error::Exhausted));
        assert_eq!(registry.len(), 0);
        assert_eq!(registry.generations, [0]);
        registry.next_id = 1;
        registry.generations[0] = u32::MAX;
        assert_eq!(registry.reserve(peer(2)), Err(Error::Exhausted));
        assert_eq!(registry.len(), 0);
        assert_eq!(registry.next_id, 1);
    }
    #[test]
    fn forged_slot_and_generation_cannot_address_another_connection() {
        let mut registry = Registry::<u32, 2>::new();
        let key = registry.reserve(peer(2)).unwrap();
        registry.bind(key, 20).unwrap();
        for forged in [
            Key { slot: 2, ..key },
            Key { id: 2, ..key },
            Key {
                generation: 2,
                ..key
            },
        ] {
            assert_eq!(registry.get(forged, &20).unwrap_err(), Error::Stale);
        }
        assert_eq!(registry.len(), 1);
    }
}
