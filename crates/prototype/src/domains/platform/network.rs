use crate::domains::{Action, Error, ObjectKey, PolicyStamp};

pub const CONNECTION_CAPACITY: usize = 16;
pub const RESERVED_TX_PER_TURN: usize = 4;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TxStep {
    pub sent: bool,
    pub still_ready: bool,
}

/// `reserved` services ACK/retransmission/authenticated recovery traffic using
/// its own credits. `send_ready` transfers one already-sendable ordinary work
/// item, never waits to fill a batch, and must retain unconfirmed bytes on error.
pub trait NetworkTx {
    fn reserved(&mut self) -> Result<TxStep, Error>;
    fn send_ready(&mut self, connection: ObjectKey) -> Result<TxStep, Error>;
}

#[derive(Clone, Copy)]
struct Connection {
    key: ObjectKey,
    ready: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TxRound {
    pub ordinary: u8,
    pub reserved: u8,
    pub policy_version: u64,
}

pub struct NetworkScheduler {
    connections: [Option<Connection>; CONNECTION_CAPACITY],
    stamp: PolicyStamp,
    batch: u8,
    cursor: usize,
    last_ns: u64,
    pub sent: u64,
    pub reserved_sent: u64,
}
impl Default for NetworkScheduler {
    fn default() -> Self {
        Self::new()
    }
}
impl NetworkScheduler {
    pub const fn new() -> Self {
        Self {
            connections: [None; CONNECTION_CAPACITY],
            stamp: PolicyStamp {
                version: 0,
                snapshot_ns: 0,
                installed_until_ns: 0,
            },
            batch: 4,
            cursor: 0,
            last_ns: 0,
            sent: 0,
            reserved_sent: 0,
        }
    }
    pub fn install(&mut self, stamp: PolicyStamp, batch: u8, now_ns: u64) -> Result<(), Error> {
        Action::TxBatch(batch).validate()?;
        if now_ns < self.last_ns {
            return Err(Error::Stale);
        }
        self.stamp.accepts(stamp, now_ns)?;
        if stamp.version == self.stamp.version && batch != self.batch {
            return Err(Error::Conflict);
        }
        self.stamp = stamp;
        self.batch = batch;
        self.last_ns = now_ns;
        Ok(())
    }
    pub fn register(&mut self, key: ObjectKey) -> Result<(), Error> {
        if key.generation == 0 {
            return Err(Error::Format);
        }
        if self
            .connections
            .iter()
            .flatten()
            .any(|c| c.key.id == key.id)
        {
            return Err(Error::Exists);
        }
        *self
            .connections
            .iter_mut()
            .find(|c| c.is_none())
            .ok_or(Error::Capacity)? = Some(Connection { key, ready: false });
        Ok(())
    }
    fn slot(&self, key: ObjectKey) -> Result<usize, Error> {
        let slot = self
            .connections
            .iter()
            .position(|c| c.is_some_and(|c| c.key.id == key.id))
            .ok_or(Error::NotFound)?;
        if self.connections[slot].unwrap().key != key {
            return Err(Error::Stale);
        }
        Ok(slot)
    }
    pub fn mark_ready(&mut self, key: ObjectKey) -> Result<(), Error> {
        let slot = self.slot(key)?;
        self.connections[slot].as_mut().unwrap().ready = true;
        Ok(())
    }
    /// The transport owner must first settle or transfer its pending bytes.
    pub fn unregister(&mut self, key: ObjectKey) -> Result<(), Error> {
        let slot = self.slot(key)?;
        if self.connections[slot].unwrap().ready {
            return Err(Error::Busy);
        }
        self.connections[slot] = None;
        Ok(())
    }
    /// Called only after the transport owner has closed the old session and
    /// retired its ciphertext. Policy leases/counters survive reconnection.
    pub fn retire_closed(&mut self, key: ObjectKey) -> Result<(), Error> {
        let slot = self.slot(key)?;
        self.connections[slot] = None;
        Ok(())
    }
    pub fn service<T: NetworkTx>(
        &mut self,
        now_ns: u64,
        transport: &mut T,
    ) -> Result<TxRound, Error> {
        if now_ns < self.last_ns {
            return Err(Error::Stale);
        }
        self.last_ns = now_ns;
        let live = self.stamp.live(now_ns);
        let batch = if live { self.batch } else { 4 };
        let mut round = TxRound {
            policy_version: if live { self.stamp.version } else { 0 },
            ..TxRound::default()
        };
        for _ in 0..RESERVED_TX_PER_TURN {
            let step = transport.reserved()?;
            if step.sent {
                round.reserved += 1;
                self.reserved_sent = self.reserved_sent.saturating_add(1);
            }
            if !step.sent || !step.still_ready {
                break;
            }
        }
        // At most batch * 16 inspections. A productive connection can be
        // revisited, but equal ready connections rotate fairly across turns.
        for _ in 0..batch {
            let mut found = None;
            for _ in 0..CONNECTION_CAPACITY {
                let slot = self.cursor;
                self.cursor = (self.cursor + 1) % CONNECTION_CAPACITY;
                if self.connections[slot].is_some_and(|c| c.ready) {
                    found = Some(slot);
                    break;
                }
            }
            let Some(slot) = found else {
                break;
            };
            let key = self.connections[slot].unwrap().key;
            let step = transport.send_ready(key)?;
            self.connections[slot].as_mut().unwrap().ready = step.still_ready;
            if step.sent {
                round.ordinary += 1;
                self.sent = self.sent.saturating_add(1);
            }
        }
        Ok(round)
    }
    pub fn ready_connections(&self) -> usize {
        self.connections
            .iter()
            .flatten()
            .filter(|c| c.ready)
            .count()
    }
}
