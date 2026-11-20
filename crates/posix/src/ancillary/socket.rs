//! Bounded socket-reference cleanup. Backends are released without callbacks
//! into a borrowed socket pool; non-socket effects leave this borrow entirely.
use super::{MESSAGES, OpenDescriptions, REFERENCES, Ticket};
use crate::{
    Errno, Object, Released,
    open_description::{CAPACITY, Table},
    unix::{ENDPOINTS, Handle, UnixSockets},
};
use cyxia_ai_fs::FileSystem;

pub struct TicketBatch {
    tickets: [Option<Ticket>; MESSAGES],
    len: usize,
}

impl Default for TicketBatch {
    fn default() -> Self {
        Self::new()
    }
}

impl TicketBatch {
    pub const fn new() -> Self {
        Self {
            tickets: [None; MESSAGES],
            len: 0,
        }
    }
    pub fn push(&mut self, ticket: Ticket) {
        // A detached batch cannot contain more messages than the entire pool.
        assert!(self.len < MESSAGES);
        self.tickets[self.len] = Some(ticket);
        self.len += 1;
    }
    pub fn as_slice(&self) -> &[Option<Ticket>] {
        &self.tickets[..self.len]
    }
    fn pop(&mut self) -> Option<Ticket> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        self.tickets[self.len].take()
    }
}

pub struct Reclaimed {
    // At most REFERENCES transferred objects, plus one initiating release.
    pub external: [Option<Released>; REFERENCES + 1],
    pub messages: usize,
    pub references: usize,
    pub cancelled: usize,
    pub receipts: [Option<DiscardedMessage>; MESSAGES],
}

#[derive(Clone, Copy)]
pub struct DiscardedMessage {
    pub references: usize,
    pub cancelled: bool,
}

struct Work {
    sockets: [Option<(u32, u64)>; ENDPOINTS],
    len: usize,
    external_len: usize,
    result: Reclaimed,
}

impl Work {
    fn new() -> Self {
        Self {
            sockets: [None; ENDPOINTS],
            len: 0,
            external_len: 0,
            result: Reclaimed {
                external: [None; REFERENCES + 1],
                messages: 0,
                references: 0,
                cancelled: 0,
                receipts: [None; MESSAGES],
            },
        }
    }
    fn release(&mut self, released: Option<Released>) {
        match released {
            Some(Released::Socket { owner, handle }) => {
                assert!(self.len < ENDPOINTS);
                self.sockets[self.len] = Some((owner, handle));
                self.len += 1;
            }
            Some(effect) => {
                assert!(self.external_len < self.result.external.len());
                self.result.external[self.external_len] = Some(effect);
                self.external_len += 1;
            }
            None => {}
        }
    }
    fn socket(&mut self) -> Option<(u32, u64)> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        self.sockets[self.len].take()
    }
    fn discard(
        &mut self,
        objects: &OpenDescriptions,
        fs: &mut FileSystem,
        ticket: Ticket,
        cancelled: bool,
    ) -> Result<(), Errno> {
        assert!(self.result.messages < MESSAGES);
        let (effects, count) = objects.discard_rights(fs, ticket)?;
        self.result.receipts[self.result.messages] = Some(DiscardedMessage {
            references: count,
            cancelled,
        });
        self.result.messages += 1;
        self.result.references += count;
        self.result.cancelled += usize::from(cancelled);
        for effect in effects {
            self.release(effect);
        }
        Ok(())
    }
}

impl OpenDescriptions {
    /// CPU0 must serialize descriptor/pool mutations around this operation.
    /// No backend is called from a Unix close/shutdown callback or OFD borrow.
    pub fn reclaim_socket_rights(
        &self,
        fs: &mut FileSystem,
        sockets: &mut UnixSockets,
        released: Option<Released>,
        detached: &[Option<Ticket>],
        cancelled: bool,
    ) -> Result<Reclaimed, Errno> {
        let mut work = Work::new();
        let mut pending = TicketBatch::new();
        work.release(released);
        for ticket in detached.iter().flatten() {
            work.discard(self, fs, *ticket, cancelled)?;
        }
        loop {
            if let Some(ticket) = pending.pop() {
                work.discard(self, fs, ticket, false)?;
            } else if let Some((owner, raw)) = work.socket() {
                sockets.close_with(owner, Handle::from_raw(raw), &mut |ticket| {
                    pending.push(ticket)
                })?;
            } else {
                pending = self.unreachable_socket_tickets(sockets)?;
                if pending.as_slice().is_empty() {
                    break;
                }
            }
        }
        Ok(work.result)
    }

    fn unreachable_socket_tickets(&self, sockets: &mut UnixSockets) -> Result<TicketBatch, Errno> {
        let mut detached = TicketBatch::new();
        {
            let table = self.inner.borrow();
            if table
                .rights
                .iter()
                .all(|slot| slot.state == super::State::Free)
            {
                return Ok(detached);
            }
            let queues = sockets.rights_queues()?;
            // FD references and staged (not yet committed) ownership are roots.
            // In-flight ownership is reached only through a reachable queue.
            let mut reachable = core::array::from_fn::<_, CAPACITY, _>(|index| {
                let entry = &table.entries[index];
                entry.value.is_some() && entry.references > entry.inflight
            });
            for queue in queues.iter().flatten() {
                let slot = table
                    .rights
                    .get(queue.ticket.slot)
                    .filter(|slot| {
                        slot.generation == queue.ticket.generation
                            && slot.state != super::State::Free
                    })
                    .ok_or(Errno::Badf)?;
                for handle in &slot.handles[..slot.count] {
                    table.entry(*handle)?;
                }
            }
            loop {
                let mut changed = false;
                for queue in queues.iter().flatten() {
                    if !queue_reachable(&table, &reachable, queue.owner, queue.handle) {
                        continue;
                    }
                    let slot = &table.rights[queue.ticket.slot];
                    for handle in &slot.handles[..slot.count] {
                        changed |= !reachable[handle.slot];
                        reachable[handle.slot] = true;
                    }
                }
                if !changed {
                    break;
                }
            }
            for queue in queues.iter().flatten() {
                if !queue_reachable(&table, &reachable, queue.owner, queue.handle) {
                    detached.push(queue.ticket);
                }
            }
        }
        // End the OFD borrow before detaching, closing, or releasing anything.
        sockets.detach_rights(detached.as_slice());
        Ok(detached)
    }
}

fn queue_reachable(
    table: &Table,
    reachable: &[bool; CAPACITY],
    owner: u32,
    handle: Handle,
) -> bool {
    table.entries.iter().enumerate().any(|(index, entry)| {
        reachable[index]
            && entry.owner == owner
            && entry.value.is_some_and(
                |value| matches!(value.object, Object::Socket(raw) if raw == handle.raw()),
            )
    })
}
